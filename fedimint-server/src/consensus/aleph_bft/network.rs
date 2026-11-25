use std::sync::{Arc, Mutex};

use async_channel::Sender;
use bitcoin::hashes::{Hash, sha256};
use fedimint_core::PeerId;
use fedimint_core::config::P2PMessage;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::SerdeModuleEncoding;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::net::peers::{DynP2PConnections, Recipient};
use fedimint_core::secp256k1::schnorr;
use fedimint_core::session_outcome::SignedSessionOutcome;
use fedimint_core::util::FmtCompact as _;
use fedimint_logging::LOG_CONSENSUS;
use parity_scale_codec::{Decode, Encode, IoReader};
use tokio::sync::watch;
use tracing::{error, info, trace};

use super::super::db::SignedSessionOutcomeKey;
use super::super::peer_availability::PeerActivity;
use super::data_provider::{PendingBatches, UnitData};
use super::keychain::Keychain;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Hasher;

impl aleph_bft::Hasher for Hasher {
    type Hash = [u8; 32];

    fn hash(input: &[u8]) -> Self::Hash {
        input.consensus_hash::<sha256::Hash>().to_byte_array()
    }
}

pub type NetworkData = aleph_bft::NetworkData<
    Hasher,
    UnitData,
    <Keychain as aleph_bft::Keychain>::Signature,
    <Keychain as aleph_bft::MultiKeychain>::PartialMultisignature,
>;

/// The variant of [`P2PMessage::Default`] by which a guardian with a shutdown
/// due at the end of a session asks its peers to stop slowing down under Aleph
/// quiescence, so the session completes without the remaining rounds at their
/// idle pace. P2P messages travel bincode-encoded, so a variant unknown to
/// older peers would fail to decode; as `Default`, older peers decode and
/// ignore it. The index is far above upstream's variants, so it does not
/// collide with one they add.
pub const DRAIN_SESSION_VARIANT: u64 = 0xfed1_0000;

/// The request to drain `session_index`.
pub fn drain_session_message(session_index: u64) -> P2PMessage {
    P2PMessage::Default {
        variant: DRAIN_SESSION_VARIANT,
        bytes: session_index.consensus_encode_to_vec(),
    }
}

/// The session a drain request's payload names, if it decodes.
fn drain_session(bytes: &[u8]) -> Option<u64> {
    u64::consensus_decode_whole(bytes, &ModuleRegistry::default()).ok()
}

pub struct Network {
    connections: DynP2PConnections<P2PMessage>,
    peer_activity: Arc<Mutex<PeerActivity>>,
    signed_outcomes_sender: Sender<(PeerId, SignedSessionOutcome)>,
    signatures_sender: Sender<(PeerId, schnorr::Signature)>,
    pending_batches: PendingBatches,
    db: Database,
    session_index: u64,
    drain_sender: watch::Sender<bool>,
}

impl Network {
    pub fn new(
        connections: DynP2PConnections<P2PMessage>,
        peer_activity: Arc<Mutex<PeerActivity>>,
        signed_outcomes_sender: Sender<(PeerId, SignedSessionOutcome)>,
        signatures_sender: Sender<(PeerId, schnorr::Signature)>,
        pending_batches: PendingBatches,
        db: Database,
        session_index: u64,
        drain_sender: watch::Sender<bool>,
    ) -> Self {
        Self {
            connections,
            peer_activity,
            signed_outcomes_sender,
            signatures_sender,
            pending_batches,
            db,
            session_index,
            drain_sender,
        }
    }
}

#[async_trait::async_trait]
impl aleph_bft::Network<NetworkData> for Network {
    fn send(&self, network_data: NetworkData, recipient: aleph_bft::Recipient) {
        // convert from aleph_bft::Recipient to session::Recipient
        let recipient = match recipient {
            aleph_bft::Recipient::Node(node_index) => {
                // Aleph echoes back node indices taken from messages we received, so this
                // index may have been chosen by a peer and may not name a peer at all.
                let Some(peer_id) = super::to_peer_id(node_index) else {
                    trace!(
                        target: LOG_CONSENSUS,
                        ?node_index,
                        "Dropping Aleph BFT message addressed to an invalid node index"
                    );

                    return;
                };

                Recipient::Peer(peer_id)
            }
            aleph_bft::Recipient::Everyone => Recipient::Everyone,
        };

        self.connections
            .send(recipient, P2PMessage::Aleph(network_data.encode()));
    }

    async fn next_event(&mut self) -> Option<NetworkData> {
        loop {
            let (peer_id, message) = self.connections.receive().await?;

            match message {
                P2PMessage::Aleph(bytes) => {
                    self.peer_activity.lock().expect("poisoned").heard(
                        peer_id,
                        fedimint_core::time::duration_since_epoch().as_secs(),
                    );

                    match NetworkData::decode(&mut IoReader(bytes.as_slice())) {
                        Ok(network_data) => {
                            let units = network_data.carried_units();

                            // in order to bound the RAM consumption of a session we have to bound
                            // the size of an individual unit in memory
                            if units
                                .iter()
                                .filter_map(|unit| unit.data.as_ref())
                                .all(UnitData::is_valid)
                            {
                                // a quiescent data provider wakes up for our peers' batches
                                // with work
                                for unit in &units {
                                    self.pending_batches.heard(unit);
                                }

                                return Some(network_data);
                            }

                            error!(
                                target: LOG_CONSENSUS,
                                %peer_id,
                                "Received invalid unit data"
                            );
                        }
                        Err(err) => {
                            error!(
                                target: LOG_CONSENSUS,
                                %peer_id,
                                err = %err.fmt_compact(),
                                "Failed to decode Aleph BFT network data"
                            );
                        }
                    }
                }
                P2PMessage::SessionSignature(signature) => {
                    self.signatures_sender.try_send((peer_id, signature)).ok();
                }
                P2PMessage::SessionIndex(their_session) => {
                    if let Some(outcome) = self
                        .db
                        .begin_transaction_nc()
                        .await
                        .get_value(&SignedSessionOutcomeKey(their_session))
                        .await
                    {
                        self.connections.send(
                            Recipient::Peer(peer_id),
                            P2PMessage::SignedSessionOutcome(SerdeModuleEncoding::from(&outcome)),
                        );
                    }
                }
                P2PMessage::Default { variant, bytes } if variant == DRAIN_SESSION_VARIANT => {
                    // A request for another session, delayed or replayed, does nothing.
                    if drain_session(&bytes) == Some(self.session_index)
                        && !self.drain_sender.send_replace(true)
                    {
                        info!(
                            target: LOG_CONSENSUS,
                            %peer_id,
                            session_index = self.session_index,
                            "Peer asked to drain the session for its shutdown"
                        );
                    }
                }
                P2PMessage::SignedSessionOutcome(encoded_outcome) => {
                    match encoded_outcome.try_into_inner(&ModuleRegistry::default()) {
                        Ok(outcome) => {
                            self.signed_outcomes_sender
                                .try_send((peer_id, outcome))
                                .ok();
                        }
                        Err(err) => {
                            error!(
                                target: LOG_CONSENSUS,
                                %peer_id,
                                err = %err.fmt_compact(),
                                "Failed to decode SignedSessionOutcome"
                            );
                        }
                    }
                }
                message => {
                    error!(
                        target: LOG_CONSENSUS,
                        %peer_id,
                        ?message,
                        "Received unexpected p2p message variant"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use fedimint_core::config::P2PMessage;

    use super::{DRAIN_SESSION_VARIANT, drain_session, drain_session_message};

    /// P2P connections send bincode, which a peer of any release decodes into
    /// the same `P2PMessage`, with the drain request as `Default`.
    #[test]
    fn a_drain_request_survives_the_wire_and_names_its_session() {
        let bytes = bincode::serialize(&drain_session_message(9)).expect("encodes");
        let received: P2PMessage = bincode::deserialize(&bytes).expect("decodes");
        let P2PMessage::Default { variant, bytes } = received else {
            panic!("expected the default variant, got {received:?}");
        };
        assert_eq!(variant, DRAIN_SESSION_VARIANT);
        assert_eq!(drain_session(&bytes), Some(9));
        assert_eq!(drain_session(&[1, 2]), None);
    }
}
