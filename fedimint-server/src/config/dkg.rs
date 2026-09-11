use std::collections::BTreeMap;

use anyhow::Context;
use async_trait::async_trait;
use bls12_381::{G1Projective, G2Projective, Scalar};
use fedimint_core::config::P2PMessage;
use fedimint_core::net::peers::Recipient;
use fedimint_core::{NumPeers, PeerId};
use fedimint_logging::LOG_NET_PEER_DKG;
use fedimint_server_core::config::PeerHandleOps;
use tracing::{error, info, warn};

use super::dkg_g1::run_dkg_g1;
use super::dkg_g2::run_dkg_g2;
use super::peer_handle::PeerHandle;

#[async_trait]
impl PeerHandleOps for PeerHandle<'_> {
    fn num_peers(&self) -> NumPeers {
        self.num_peers
    }

    async fn run_dkg_g1(&self) -> anyhow::Result<(Vec<G1Projective>, Scalar)> {
        info!(
            target: LOG_NET_PEER_DKG,
            safe_to_share = true,
            "Running distributed key generation for group G1..."
        );

        let result = run_dkg_g1(self.num_peers, self.identity, self.connections).await;
        if let Err(err) = &result {
            error!(
                target: LOG_NET_PEER_DKG,
                error = format_args!("{err:#}"),
                "G1 distributed key generation failed"
            );
            warn!(
                target: LOG_NET_PEER_DKG,
                safe_to_share = true,
                stage = "module_dkg_g1",
                failure_kind = "protocol_or_transport",
                "distributed key generation failed"
            );
        }
        result
    }

    async fn run_dkg_g2(&self) -> anyhow::Result<(Vec<G2Projective>, Scalar)> {
        info!(
            target: LOG_NET_PEER_DKG,
            safe_to_share = true,
            "Running distributed key generation for group G2..."
        );

        let result = run_dkg_g2(self.num_peers, self.identity, self.connections).await;
        if let Err(err) = &result {
            error!(
                target: LOG_NET_PEER_DKG,
                error = format_args!("{err:#}"),
                "G2 distributed key generation failed"
            );
            warn!(
                target: LOG_NET_PEER_DKG,
                safe_to_share = true,
                stage = "module_dkg_g2",
                failure_kind = "protocol_or_transport",
                "distributed key generation failed"
            );
        }
        result
    }

    async fn exchange_bytes(&self, bytes: Vec<u8>) -> anyhow::Result<BTreeMap<PeerId, Vec<u8>>> {
        info!(
            target: LOG_NET_PEER_DKG,
            safe_to_share = true,
            "Exchanging raw bytes..."
        );

        let mut peer_data: BTreeMap<PeerId, Vec<u8>> = BTreeMap::new();

        self.connections
            .send(Recipient::Everyone, P2PMessage::Encodable(bytes.clone()));

        peer_data.insert(self.identity, bytes);

        for peer in self.num_peers.peer_ids().filter(|p| *p != self.identity) {
            let message = match self
                .connections
                .receive_from_peer(peer)
                .await
                .context("Unexpected shutdown of p2p connections")
            {
                Ok(message) => message,
                Err(err) => {
                    error!(
                        target: LOG_NET_PEER_DKG,
                        peer_id = %peer,
                        error = format_args!("{err:#}"),
                        "byte exchange failed while receiving from peer"
                    );
                    warn!(
                        target: LOG_NET_PEER_DKG,
                        safe_to_share = true,
                        stage = "module_byte_exchange",
                        failure_kind = "connection_closed",
                        peer_id = %peer,
                        "distributed key generation failed"
                    );
                    return Err(err);
                }
            };

            match message {
                P2PMessage::Encodable(bytes) => {
                    peer_data.insert(peer, bytes);
                }
                message => {
                    error!(
                        target: LOG_NET_PEER_DKG,
                        peer_id = %peer,
                        received = ?message,
                        "byte exchange received an unexpected message"
                    );
                    warn!(
                        target: LOG_NET_PEER_DKG,
                        safe_to_share = true,
                        stage = "module_byte_exchange",
                        failure_kind = "unexpected_message",
                        peer_id = %peer,
                        "distributed key generation failed"
                    );
                    anyhow::bail!("Invalid message from {peer}: {message:?}");
                }
            }
        }

        Ok(peer_data)
    }
}
