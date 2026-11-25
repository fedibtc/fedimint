//! Download of a signed session outcome from peers, with a shareable record
//! of why it keeps failing.
//!
//! A guardian that falls behind catches up only through this download, so
//! when it cannot, the failure kind is the fact that says which path fails.
//! [`ObservedFederationApi`] wraps the federation API for the download and
//! counts each failed peer request by its fixed
//! [`ServerError::failure_kind`]; [`FailureReport`] turns the counts into at
//! most one shareable event per [`REPORT_INTERVAL`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fedimint_api_client::api::{
    DynGlobalApi, DynModuleApi, IRawFederationApi, ServerError, ServerResult,
};
use fedimint_connectors::{DynGuaridianConnection, PeerStatus};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::time::now;
use fedimint_core::{PeerId, apply, async_trait_maybe_send};
use futures::stream::BoxStream;
use serde_json::Value;
use tracing::warn;

use crate::LOG_CONSENSUS;

/// The shortest time between two shareable failure events of one download.
pub(crate) const REPORT_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// Failures of one download since its last shareable event.
#[derive(Debug, Default)]
pub(crate) struct FailureReport {
    failures: BTreeMap<&'static str, u64>,
    reported_at: Option<std::time::SystemTime>,
}

/// What one shareable event says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FailureSummary {
    /// The kind most failures since the last event had.
    pub(crate) failure_kind: &'static str,
    /// All failures since the last event, this one included.
    pub(crate) failures: u64,
}

impl FailureReport {
    /// Count a failure of `kind` at `now`, and return what to report when an
    /// event is due: at the first failure, then once per interval.
    pub(crate) fn record(
        &mut self,
        kind: &'static str,
        now: std::time::SystemTime,
    ) -> Option<FailureSummary> {
        *self.failures.entry(kind).or_default() += 1;
        let due = self.reported_at.is_none_or(|reported_at| {
            now.duration_since(reported_at)
                .is_ok_and(|elapsed| elapsed >= REPORT_INTERVAL)
        });
        if !due {
            return None;
        }
        self.reported_at = Some(now);
        let failures = std::mem::take(&mut self.failures);
        let (failure_kind, _) = failures
            .iter()
            .max_by_key(|(kind, count)| (**count, std::cmp::Reverse(**kind)))
            .expect("this failure was just counted");
        Some(FailureSummary {
            failure_kind,
            failures: failures.values().sum(),
        })
    }
}

/// The federation API, recording each failed peer request of the download
/// of `session_index`'s outcome.
pub(crate) struct ObservedFederationApi {
    inner: DynGlobalApi,
    session_index: u64,
    report: Arc<Mutex<FailureReport>>,
}

impl ObservedFederationApi {
    pub(crate) fn new(inner: DynGlobalApi, session_index: u64) -> Self {
        Self {
            inner,
            session_index,
            report: Arc::default(),
        }
    }

    fn record(&self, error: &ServerError) {
        let summary = self
            .report
            .lock()
            .expect("failure report lock is never poisoned")
            .record(error.failure_kind(), now());
        if let Some(summary) = summary {
            warn!(
                target: LOG_CONSENSUS,
                safe_to_share = true,
                session_index = self.session_index,
                failure_kind = summary.failure_kind,
                failures = summary.failures,
                "Signed session outcome download is failing"
            );
        }
    }
}

impl fmt::Debug for ObservedFederationApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservedFederationApi")
            .field("session_index", &self.session_index)
            .finish_non_exhaustive()
    }
}

#[apply(async_trait_maybe_send!)]
impl IRawFederationApi for ObservedFederationApi {
    fn all_peers(&self) -> &BTreeSet<PeerId> {
        self.inner.all_peers()
    }

    fn self_peer(&self) -> Option<PeerId> {
        self.inner.self_peer()
    }

    fn with_module(&self, id: ModuleInstanceId) -> DynModuleApi {
        self.inner.with_module(id)
    }

    async fn request_raw(
        &self,
        peer_id: PeerId,
        method: &str,
        params: &ApiRequestErased,
    ) -> ServerResult<Value> {
        let result = self.inner.request_raw(peer_id, method, params).await;
        if let Err(error) = &result {
            self.record(error);
        }
        result
    }

    fn connection_status_stream(&self) -> BoxStream<'static, BTreeMap<PeerId, PeerStatus>> {
        self.inner.connection_status_stream()
    }

    async fn wait_for_initialized_connections(&self) {
        self.inner.wait_for_initialized_connections().await;
    }

    async fn get_peer_connection(&self, peer_id: PeerId) -> ServerResult<DynGuaridianConnection> {
        self.inner.get_peer_connection(peer_id).await
    }
}

#[cfg(test)]
mod tests;
