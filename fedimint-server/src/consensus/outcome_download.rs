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
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_000_000 + secs)
    }

    /// The first failure is reported at once; later ones only once per
    /// interval, with every failure in between counted and the most common
    /// kind named.
    #[test]
    fn failures_are_reported_once_per_interval_with_their_count() {
        let mut report = FailureReport::default();
        assert_eq!(
            report.record("no_address", at(0)),
            Some(FailureSummary {
                failure_kind: "no_address",
                failures: 1,
            })
        );
        for second in 1..300 {
            let kind = if second % 3 == 0 {
                "connect_timeout"
            } else {
                "no_address"
            };
            assert_eq!(report.record(kind, at(second)), None);
        }
        assert_eq!(
            report.record("connect_timeout", at(REPORT_INTERVAL.as_secs())),
            Some(FailureSummary {
                failure_kind: "no_address",
                failures: 300,
            })
        );
        assert_eq!(
            report.record("rejected", at(REPORT_INTERVAL.as_secs() + 1)),
            None
        );
    }

    #[test]
    fn a_tie_names_the_kind_first_in_order() {
        let mut report = FailureReport::default();
        report.record("rejected", at(0));
        report.record("transport", at(1));
        report.record("connect_timeout", at(2));
        report.record("transport", at(3));
        assert_eq!(
            report
                .record("connect_timeout", at(REPORT_INTERVAL.as_secs()))
                .map(|summary| summary.failure_kind),
            Some("connect_timeout")
        );
    }
}
