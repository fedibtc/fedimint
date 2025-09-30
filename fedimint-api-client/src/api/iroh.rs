use std::collections::{BTreeMap, BTreeSet};
use std::pin::Pin;
use std::str::FromStr;

use anyhow::Context;
use async_trait::async_trait;
use fedimint_core::PeerId;
use fedimint_core::envs::parse_kv_list_from_env;
use fedimint_core::iroh_prod::FM_DNS_PKARR_RELAY_PROD;
use fedimint_core::module::{
    ApiError, ApiMethod, ApiRequestErased, FEDIMINT_API_ALPN, IrohApiRequest,
};
use fedimint_core::util::{FmtCompact as _, SafeUrl};
use fedimint_logging::LOG_NET_IROH;
use futures::Future;
use futures::stream::{FuturesUnordered, StreamExt};
use iroh::discovery::pkarr::PkarrResolver;
use iroh::endpoint::Connection;
use iroh::{Endpoint, NodeAddr, NodeId, PublicKey};
use iroh_base::ticket::NodeTicket;
use serde_json::Value;
use tracing::{debug, trace, warn};
use url::Url;

use super::{DynClientConnection, IClientConnection, IClientConnector, PeerError, PeerResult};

#[derive(Debug, Clone)]
pub struct IrohConnector {
    node_ids: BTreeMap<PeerId, NodeId>,
    endpoint_stable: Endpoint,

    /// List of overrides to use when attempting to connect to given
    /// `NodeId`
    ///
    /// This is useful for testing, or forcing non-default network
    /// connectivity.
    pub connection_overrides: BTreeMap<NodeId, NodeAddr>,
}

impl IrohConnector {
    pub async fn new(
        peers: BTreeMap<PeerId, SafeUrl>,
        iroh_dns: Option<SafeUrl>,
    ) -> anyhow::Result<Self> {
        const FM_IROH_CONNECT_OVERRIDES_ENV: &str = "FM_IROH_CONNECT_OVERRIDES";
        warn!(target: LOG_NET_IROH, "Iroh support is experimental");
        let mut s = Self::new_no_overrides(peers, iroh_dns).await?;

        for (k, v) in parse_kv_list_from_env::<_, NodeTicket>(FM_IROH_CONNECT_OVERRIDES_ENV)? {
            s = s.with_connection_override(k, v.into());
        }

        Ok(s)
    }

    pub async fn new_no_overrides(
        peers: BTreeMap<PeerId, SafeUrl>,
        iroh_dns: Option<SafeUrl>,
    ) -> anyhow::Result<Self> {
        let iroh_dns_servers: Vec<_> = iroh_dns.map_or_else(
            || {
                FM_DNS_PKARR_RELAY_PROD
                    .into_iter()
                    .map(|url| Url::parse(url).expect("Hardcoded, can't fail"))
                    .collect()
            },
            |url| vec![url.to_unsafe()],
        );
        let node_ids = peers
            .into_iter()
            .map(|(peer, url)| {
                let host = url.host_str().context("Url is missing host")?;

                let node_id = PublicKey::from_str(host).context("Failed to parse node id")?;

                Ok((peer, node_id))
            })
            .collect::<anyhow::Result<BTreeMap<PeerId, NodeId>>>()?;

        let endpoint_stable = {
            let builder = Endpoint::builder();

            // As a client, we don't need to register on any relays
            let mut builder = builder.relay_mode(iroh::RelayMode::Disabled);

            for iroh_dns in iroh_dns_servers.clone() {
                builder = builder.add_discovery(move |_| Some(PkarrResolver::new(iroh_dns)));
            }

            // Only adding n0 discovery without the publisher didn't work
            let endpoint = builder.discovery_n0().bind().await?;
            debug!(
                target: LOG_NET_IROH,
                node_id = %endpoint.node_id(),
                node_id_pkarr = %z32::encode(endpoint.node_id().as_bytes()),
                "Iroh api client endpoint (stable)"
            );
            endpoint
        };

        Ok(Self {
            node_ids,
            endpoint_stable,
            connection_overrides: BTreeMap::new(),
        })
    }

    pub fn with_connection_override(mut self, node: NodeId, addr: NodeAddr) -> Self {
        self.connection_overrides.insert(node, addr);
        self
    }
}

#[async_trait]
impl IClientConnector for IrohConnector {
    fn peers(&self) -> BTreeSet<PeerId> {
        self.node_ids.keys().copied().collect()
    }

    async fn connect(&self, peer_id: PeerId) -> PeerResult<DynClientConnection> {
        let node_id = *self
            .node_ids
            .get(&peer_id)
            .ok_or(PeerError::InvalidPeerId { peer_id })?;

        let mut futures = FuturesUnordered::<
            Pin<Box<dyn Future<Output = PeerResult<DynClientConnection>> + Send>>,
        >::new();
        let connection_override = self.connection_overrides.get(&node_id).cloned();
        let endpoint_stable = self.endpoint_stable.clone();

        futures.push(Box::pin({
            let connection_override = connection_override.clone();
            async move {
                match connection_override {
                    Some(node_addr) => {
                        trace!(target: LOG_NET_IROH, %node_id, "Using a connectivity override for connection");
                        endpoint_stable
                            .connect(node_addr.clone(), FEDIMINT_API_ALPN)
                            .await
                    }
                    None => endpoint_stable.connect(node_id, FEDIMINT_API_ALPN).await,
                }.map_err(PeerError::Connection)
                .map(super::IClientConnection::into_dyn)
            }
        }));

        // Remember last error, so we have something to return if
        // neither connection works.
        let mut prev_err = None;

        // Loop until first success, or running out of connections.
        while let Some(result) = futures.next().await {
            match result {
                Ok(connection) => return Ok(connection),
                Err(err) => {
                    warn!(
                        target: LOG_NET_IROH,
                        err = %err.fmt_compact(),
                        "Join error in iroh connection task"
                    );
                    prev_err = Some(err);
                }
            }
        }

        Err(prev_err.unwrap_or_else(|| {
            PeerError::ServerError(anyhow::anyhow!("Both iroh connection attempts failed"))
        }))
    }
}

#[async_trait]
impl IClientConnection for Connection {
    async fn request(&self, method: ApiMethod, request: ApiRequestErased) -> PeerResult<Value> {
        let json = serde_json::to_vec(&IrohApiRequest { method, request })
            .expect("Serialization to vec can't fail");

        let (mut sink, mut stream) = self
            .open_bi()
            .await
            .map_err(|e| PeerError::Transport(e.into()))?;

        sink.write_all(&json)
            .await
            .map_err(|e| PeerError::Transport(e.into()))?;

        sink.finish().map_err(|e| PeerError::Transport(e.into()))?;

        let response = stream
            .read_to_end(1_000_000)
            .await
            .map_err(|e| PeerError::Transport(e.into()))?;

        // TODO: We should not be serializing Results on the wire
        let response = serde_json::from_slice::<Result<Value, ApiError>>(&response)
            .map_err(|e| PeerError::InvalidResponse(e.into()))?;

        response.map_err(|e| PeerError::InvalidResponse(anyhow::anyhow!("Api Error: {:?}", e)))
    }

    async fn await_disconnection(&self) {
        self.closed().await;
    }
}
