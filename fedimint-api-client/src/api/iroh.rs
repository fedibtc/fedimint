use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use fedimint_core::PeerId;
use fedimint_core::envs::parse_kv_list_from_env;
use fedimint_core::iroh_prod::FM_IROH_DNS_FEDIMINT_PROD;
use fedimint_core::module::{
    ApiError, ApiMethod, ApiRequestErased, FEDIMINT_API_ALPN, IrohApiRequest,
};
use fedimint_core::task::spawn;
use fedimint_core::util::SafeUrl;
use fedimint_logging::LOG_NET_IROH;
use iroh::discovery::pkarr::PkarrResolver;
use iroh::endpoint::Connection;
use iroh::{Endpoint, NodeAddr, NodeId, PublicKey};
use iroh_base::ticket::NodeTicket;
use serde_json::Value;
use tokio::sync::OnceCell;
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

    /// Connection pool for stable endpoint connections
    connections_stable: Arc<tokio::sync::Mutex<HashMap<NodeId, Arc<OnceCell<Connection>>>>>,
}

impl IrohConnector {
    #[cfg(not(target_family = "wasm"))]
    fn spawn_connection_monitoring_stable(endpoint: &Endpoint, node_id: NodeId) {
        if let Ok(mut conn_type_watcher) = endpoint.conn_type(node_id) {
            #[allow(clippy::let_underscore_future)]
            let _ = spawn("iroh connection (stable)", async move {
                if let Ok(conn_type) = conn_type_watcher.get() {
                    debug!(target: LOG_NET_IROH, %node_id, type = %conn_type, "Connection type (initial)");
                }
                while let Ok(event) = conn_type_watcher.updated().await {
                    debug!(target: LOG_NET_IROH, %node_id, type = %event, "Connection type (changed)");
                }
            });
        }
    }

    pub async fn new(
        peers: BTreeMap<PeerId, SafeUrl>,
        iroh_dns: Option<SafeUrl>,
        iroh_enable_dht: bool,
        _iroh_enable_next: bool,
    ) -> anyhow::Result<Self> {
        const FM_IROH_CONNECT_OVERRIDES_ENV: &str = "FM_IROH_CONNECT_OVERRIDES";
        warn!(target: LOG_NET_IROH, "Iroh support is experimental");
        let mut s =
            Self::new_no_overrides(peers, iroh_dns, iroh_enable_dht).await?;

        for (k, v) in parse_kv_list_from_env::<_, NodeTicket>(FM_IROH_CONNECT_OVERRIDES_ENV)? {
            s = s.with_connection_override(k, v.into());
        }

        Ok(s)
    }

    pub async fn new_no_overrides(
        peers: BTreeMap<PeerId, SafeUrl>,
        iroh_dns: Option<SafeUrl>,
        iroh_enable_dht: bool,
    ) -> anyhow::Result<Self> {
        let iroh_dns_servers: Vec<_> = iroh_dns.map_or_else(
            || {
                FM_IROH_DNS_FEDIMINT_PROD
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

        let mut builder = Endpoint::builder();

        for iroh_dns in iroh_dns_servers {
            builder = builder.add_discovery(|_| Some(PkarrResolver::new(iroh_dns)));
        }

        // As a client, we don't need to register on any relays
        let mut builder = builder.relay_mode(iroh::RelayMode::Disabled);

        #[cfg(not(target_family = "wasm"))]
        if iroh_enable_dht {
            builder = builder.discovery_dht();
        }

        // instead of `.discovery_n0`, which brings publisher we don't want
        {
            builder = builder.add_discovery(move |_| Some(PkarrResolver::n0_dns()));
        }

        let endpoint_stable = builder.bind().await?;
        debug!(
            target: LOG_NET_IROH,
            node_id = %endpoint_stable.node_id(),
            node_id_pkarr = %z32::encode(endpoint_stable.node_id().as_bytes()),
            "Iroh api client endpoint (stable)"
        );

        Ok(Self {
            node_ids,
            endpoint_stable,
            connection_overrides: BTreeMap::new(),
            connections_stable: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        })
    }

    pub fn with_connection_override(mut self, node: NodeId, addr: NodeAddr) -> Self {
        self.connection_overrides.insert(node, addr);
        self
    }

    async fn get_or_create_connection_stable(
        &self,
        node_id: NodeId,
        node_addr: Option<NodeAddr>,
    ) -> PeerResult<Connection> {
        let mut pool_lock = self.connections_stable.lock().await;

        let entry_arc = pool_lock
            .entry(node_id)
            .and_modify(|entry_arc| {
                // Check if existing connection is disconnected and remove it
                if let Some(existing_conn) = entry_arc.get()
                    && existing_conn.close_reason().is_some() {
                        trace!(target: LOG_NET_IROH, %node_id, "Existing stable connection is disconnected, removing from pool");
                        *entry_arc = Arc::new(OnceCell::new());
                    }
            })
            .or_insert_with(|| Arc::new(OnceCell::new()))
            .clone();

        // Drop the pool lock so other connections can work in parallel
        drop(pool_lock);

        let conn = entry_arc
            .get_or_try_init(|| async {
                trace!(target: LOG_NET_IROH, %node_id, "Creating new stable connection");
                let conn = match node_addr.clone() {
                    Some(node_addr) => {
                        trace!(target: LOG_NET_IROH, %node_id, "Using a connectivity override for connection");
                        let conn = self.endpoint_stable
                            .connect(node_addr.clone(), FEDIMINT_API_ALPN)
                            .await;

                        #[cfg(not(target_family = "wasm"))]
                        if conn.is_ok() {
                            Self::spawn_connection_monitoring_stable(&self.endpoint_stable, node_id);
                        }
                        conn
                    }
                    None => self.endpoint_stable.connect(node_id, FEDIMINT_API_ALPN).await,
                }.map_err(PeerError::Connection)?;

                Ok(conn)
            })
            .await?;

        trace!(target: LOG_NET_IROH, %node_id, "Using stable connection");
        Ok(conn.clone())
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

        let connection_override = self.connection_overrides.get(&node_id).cloned();

        self
            .get_or_create_connection_stable(node_id, connection_override)
            .await
            .map(super::IClientConnection::into_dyn)
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
