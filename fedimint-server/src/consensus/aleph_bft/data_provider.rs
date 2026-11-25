use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Instant;

use aleph_bft::{CarriedUnit, Round};
use fedimint_core::config::ALEPH_BFT_UNIT_BYTE_LIMIT;
use fedimint_core::encoding::Encodable;
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::secp256k1::schnorr;
use fedimint_core::{PeerId, TransactionId};
use tokio::sync::watch;

use crate::LOG_CONSENSUS;
use crate::consensus::engine::ScheduledShutdown;

#[derive(
    Clone, Debug, PartialEq, Eq, Hash, parity_scale_codec::Encode, parity_scale_codec::Decode,
)]
pub enum UnitData {
    Batch(Vec<u8>),
    Signature([u8; 64]),
}

impl UnitData {
    // in order to bound the RAM consumption of a session we have to bound an
    // individual units size, hence the size of its attached unit data in memory
    pub fn is_valid(&self) -> bool {
        match self {
            UnitData::Signature(..) => true,
            UnitData::Batch(bytes) => bytes.len() <= ALEPH_BFT_UNIT_BYTE_LIMIT,
        }
    }
}

/// What keeps a quiescent [`DataProvider`] creating units in this session.
///
/// - The batches that, as far as we know, await ordering: the ones we attached
///   to our own units and the ones we received in our peers' units. A batch
///   which only one guardian has then gets ordered right away rather than once
///   every guardian has work of its own.
/// - The highest round of a peer unit we heard of. A provider parked on a round
///   that a peer already created a unit of creates its own. Otherwise a peer
///   one round ahead could wait for parents while everyone else is parked, and
///   work that reaches only that peer could not enter a unit.
///
/// The [`DataProvider`] counts our batches as it creates them, the
/// [`super::network::Network`] records our peers' units of this session as
/// they arrive, and the [`super::finalization_handler::FinalizationHandler`]
/// clears batches as they are ordered.
#[derive(Clone)]
pub struct PendingBatches {
    /// Peers keep rebroadcasting the last units of the session they just
    /// finished while we run the next one. Those units are no work of ours, and
    /// their high rounds would keep us awake for the whole session.
    session: u64,
    state: Arc<watch::Sender<PendingBatchesState>>,
}

#[derive(Debug, Default)]
pub struct PendingBatchesState {
    ours: usize,
    /// Our peers' unordered batches by the creator and round of their unit,
    /// since two guardians may attach equal batches to their units.
    peers: BTreeSet<(PeerId, Round)>,
    /// Aleph BFT rebroadcasts a guardian's latest unit until it creates the
    /// next one and sends units again in responses, so we remember which units
    /// were ordered in order to not take such a copy for new work.
    ordered: BTreeSet<(PeerId, Round)>,
    /// The highest round of a peer unit we heard of, with or without data.
    highest_peer_round: Option<Round>,
}

impl PendingBatchesState {
    /// Whether nothing keeps us from parking on our unit of `round`.
    fn idle_at(&self, round: Round) -> bool {
        self.ours == 0
            && self.peers.is_empty()
            && self
                .highest_peer_round
                .is_none_or(|highest| highest < round)
    }
}

impl PendingBatches {
    pub fn new(session: u64) -> Self {
        Self {
            session,
            state: Arc::new(watch::channel(PendingBatchesState::default()).0),
        }
    }

    fn created(&self) {
        self.state.send_if_modified(|state| {
            state.ours += 1;
            // only a peer's batch needs to wake a parked data provider
            false
        });
    }

    /// Record a unit of this session received from a peer: its round, and its
    /// batch if it has one. The unit is not verified yet, so a peer can keep us
    /// from going quiescent, but nothing else.
    pub fn heard(&self, unit: &CarriedUnit<UnitData>) {
        if unit.session != self.session {
            return;
        }

        // a peer can name any node index in a message it sends us
        let Some(creator) = super::to_peer_id(unit.creator) else {
            return;
        };

        let key = (creator, unit.round);
        let has_batch = matches!(unit.data, Some(UnitData::Batch(..)));

        self.state.send_if_modified(|state| {
            let ahead = state
                .highest_peer_round
                .is_none_or(|highest| highest < unit.round);

            if ahead {
                state.highest_peer_round = Some(unit.round);
            }

            let new_batch = has_batch && !state.ordered.contains(&key) && state.peers.insert(key);

            ahead || new_batch
        });
    }

    pub fn ordered(&self, creator: PeerId, round: Round, ours: bool, data: &UnitData) {
        if !matches!(data, UnitData::Batch(..)) {
            return;
        }

        self.state.send_if_modified(|state| {
            // Aleph BFT replays every unit of the current session from our backup on
            // a restart, thereby ordering batches we have not created in this
            // process. Hence we saturate at zero instead of underflowing.
            if ours {
                state.ours = state.ours.saturating_sub(1);
            }

            state.peers.remove(&(creator, round));
            state.ordered.insert((creator, round));

            // ordering never gives a parked data provider work
            false
        });
    }

    fn subscribe(&self) -> watch::Receiver<PendingBatchesState> {
        self.state.subscribe()
    }
}

pub struct DataProvider {
    mempool_item_receiver: async_channel::Receiver<ConsensusItem>,
    signature_receiver: watch::Receiver<Option<schnorr::Signature>>,
    submitted_transactions: BTreeSet<TransactionId>,
    leftover_item: Option<ConsensusItem>,
    timestamp_sender: async_channel::Sender<Instant>,
    is_recovery: bool,
    pending_batches: PendingBatches,
    pending_changes: watch::Receiver<PendingBatchesState>,
    park_deadline: Option<Instant>,
    quiescence: watch::Receiver<bool>,
    shutdown: watch::Receiver<Option<ScheduledShutdown>>,
}

impl DataProvider {
    pub fn new(
        mempool_item_receiver: async_channel::Receiver<ConsensusItem>,
        signature_receiver: watch::Receiver<Option<schnorr::Signature>>,
        timestamp_sender: async_channel::Sender<Instant>,
        is_recovery: bool,
        pending_batches: PendingBatches,
        park_deadline: Option<Instant>,
        shutdown: watch::Receiver<Option<ScheduledShutdown>>,
    ) -> Self {
        Self {
            mempool_item_receiver,
            signature_receiver,
            submitted_transactions: BTreeSet::new(),
            leftover_item: None,
            timestamp_sender,
            is_recovery,
            pending_changes: pending_batches.subscribe(),
            pending_batches,
            park_deadline,
            quiescence: fedimint_server_core::quiescence::subscribe(),
            shutdown,
        }
    }

    /// Whether an admin scheduled a shutdown at the end of this session. A
    /// guardian transfer or a coordinated upgrade then waits for the session
    /// to end, so we complete it as fast as without quiescence.
    fn shutdown_due(&mut self) -> bool {
        self.shutdown
            .borrow_and_update()
            .is_some_and(|scheduled| scheduled.session <= self.pending_batches.session)
    }

    /// Whether the item is not a transaction we already attached to a unit.
    fn is_new(&mut self, item: &ConsensusItem) -> bool {
        match item {
            ConsensusItem::Transaction(transaction) => {
                self.submitted_transactions.insert(transaction.tx_hash())
            }
            _ => true,
        }
    }
}

#[async_trait::async_trait]
impl aleph_bft::DataProvider<UnitData> for DataProvider {
    async fn get_data(&mut self, round: Round) -> Option<UnitData> {
        loop {
            // we only attach our signature as no more items can be ordered in this session
            if let Some(signature) = *self.signature_receiver.borrow() {
                return Some(UnitData::Signature(signature.serialize()));
            }

            // the length of a vector is encoded in at most 9 bytes
            let mut n_bytes = 9;
            let mut items = Vec::new();

            if let Some(item) = self.leftover_item.take() {
                let n_bytes_item = item.consensus_encode_to_vec().len();

                if n_bytes_item + n_bytes <= ALEPH_BFT_UNIT_BYTE_LIMIT {
                    n_bytes += n_bytes_item;
                    items.push(item);
                } else {
                    tracing::warn!(target: LOG_CONSENSUS, ?item, "Consensus item length is over BYTE_LIMIT");
                }
            }

            // we only drain the items which are available right away in order to not
            // delay the creation of our next unit
            while let Ok(item) = self.mempool_item_receiver.try_recv() {
                if !self.is_new(&item) {
                    continue;
                }

                let n_bytes_item = item.consensus_encode_to_vec().len();

                if n_bytes + n_bytes_item <= ALEPH_BFT_UNIT_BYTE_LIMIT {
                    n_bytes += n_bytes_item;
                    items.push(item);
                } else {
                    self.leftover_item = Some(item);
                    break;
                }
            }

            if !items.is_empty() {
                if !self.is_recovery {
                    self.timestamp_sender.send(Instant::now()).await.ok();
                }

                let bytes = items.consensus_encode_to_vec();

                assert!(bytes.len() <= ALEPH_BFT_UNIT_BYTE_LIMIT);

                self.pending_batches.created();

                return Some(UnitData::Batch(bytes));
            }

            // Without quiescence we create a unit every round, with or without data.
            // With it, as long as a batch of ours or of a peer still awaits ordering,
            // or a peer has created a unit of this round already, we keep creating
            // units without data such that the broadcast grows the dag and orders it.
            // Otherwise there is no work to be done and we go quiescent until an item
            // is submitted to us, a peer's batch or a unit of this round arrives, the
            // session ends, the park deadline passes, quiescence is turned off, or a
            // shutdown is scheduled at the end of this session.
            let park_deadline = self.park_deadline?;

            if !*self.quiescence.borrow_and_update()
                || Instant::now() >= park_deadline
                || !self.pending_changes.borrow_and_update().idle_at(round)
                || self.shutdown_due()
            {
                return None;
            }

            tokio::select! {
                item = self.mempool_item_receiver.recv() => {
                    match item {
                        Ok(item) => {
                            if self.is_new(&item) {
                                self.leftover_item = Some(item);
                            }
                        }
                        // the sender is dropped as the server shuts down, in which case
                        // we park instead of spinning on the closed channel
                        Err(..) => std::future::pending::<()>().await,
                    }
                }
                changed = self.signature_receiver.changed() => {
                    if changed.is_err() {
                        std::future::pending::<()>().await;
                    }
                }
                // The switch lives as long as the process.
                _ = self.quiescence.changed() => {}
                // We hold the sender ourselves.
                _ = self.pending_changes.changed() => {}
                changed = self.shutdown.changed() => {
                    if changed.is_err() {
                        std::future::pending::<()>().await;
                    }
                }
                () = tokio::time::sleep_until(park_deadline.into()) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use aleph_bft::DataProvider as _;
    use fedimint_core::encoding::Decodable as _;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::transaction::{Transaction, TransactionSignature};

    use super::*;
    use crate::consensus::engine::ShutdownRequest;

    const PARKED: Duration = Duration::from_millis(300);

    fn transaction(nonce: u8) -> ConsensusItem {
        ConsensusItem::Transaction(Transaction {
            inputs: vec![],
            outputs: vec![],
            nonce: [nonce; 8],
            signatures: TransactionSignature::NaiveMultisig(vec![]),
        })
    }

    fn batch_items(data: Option<UnitData>) -> Vec<ConsensusItem> {
        let Some(UnitData::Batch(bytes)) = data else {
            panic!("expected a batch, got {data:?}");
        };
        Vec::<ConsensusItem>::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .expect("a batch decodes")
    }

    fn batch(nonce: u8) -> UnitData {
        UnitData::Batch(vec![transaction(nonce)].consensus_encode_to_vec())
    }

    struct Harness {
        provider: DataProvider,
        /// The round of the unit the provider fills next; it advances when
        /// `get_data` returns, as AlephBFT's packer then moves on.
        round: Round,
        mempool: async_channel::Sender<ConsensusItem>,
        signature: watch::Sender<Option<schnorr::Signature>>,
        shutdown: watch::Sender<Option<ScheduledShutdown>>,
        batches: PendingBatches,
        _timestamps: async_channel::Receiver<Instant>,
    }

    fn harness(park_deadline: Option<Instant>) -> Harness {
        let (mempool, mempool_receiver) = async_channel::unbounded();
        let (signature, signature_receiver) = watch::channel(None);
        let (timestamp_sender, timestamps) = async_channel::unbounded();
        let (shutdown, shutdown_receiver) = watch::channel(None);
        let batches = PendingBatches::new(SESSION);
        Harness {
            provider: DataProvider::new(
                mempool_receiver,
                signature_receiver,
                timestamp_sender,
                false,
                batches.clone(),
                park_deadline,
                shutdown_receiver,
            ),
            round: 0,
            mempool,
            signature,
            shutdown,
            batches,
            _timestamps: timestamps,
        }
    }

    fn far_deadline() -> Instant {
        Instant::now() + Duration::from_secs(3600)
    }

    impl Harness {
        async fn get_data_within(&mut self, limit: Duration) -> Option<Option<UnitData>> {
            let data = tokio::time::timeout(limit, self.provider.get_data(self.round))
                .await
                .ok()?;
            self.round += 1;
            Some(data)
        }

        async fn parks(&mut self) -> bool {
            self.get_data_within(PARKED).await.is_none()
        }

        async fn returns(&mut self) -> Option<UnitData> {
            self.get_data_within(PARKED)
                .await
                .expect("get_data returns without parking")
        }

        /// Run `wake` shortly after `get_data` has parked, and return its
        /// result.
        async fn woken_by(&mut self, wake: impl FnOnce() + Send + 'static) -> Option<UnitData> {
            let waker = fedimint_core::runtime::spawn("data provider test waker", async move {
                fedimint_core::runtime::sleep(Duration::from_millis(100)).await;
                wake();
            });
            let data = self
                .get_data_within(PARKED * 3)
                .await
                .expect("the wake-up ends the park");
            waker.await.expect("the waker does not panic");
            data
        }
    }

    /// The session of the tests' pending batches.
    const SESSION: u64 = 7;

    fn unit(creator: u16, round: Round, data: UnitData) -> CarriedUnit<UnitData> {
        CarriedUnit {
            session: SESSION,
            creator: super::super::to_node_index(PeerId::from(creator)),
            round,
            data: Some(data),
        }
    }

    fn empty_unit(creator: u16, round: Round) -> CarriedUnit<UnitData> {
        CarriedUnit {
            session: SESSION,
            creator: super::super::to_node_index(PeerId::from(creator)),
            round,
            data: None,
        }
    }

    /// A round far above the ones the tests name, where only batches keep a
    /// provider awake.
    const LATE: Round = 1000;

    #[test]
    fn pending_batches_track_ours_and_unordered_peer_batches() {
        let us = PeerId::from(0);
        let peer = PeerId::from(1);
        let other_peer = PeerId::from(2);

        let batches = PendingBatches::new(SESSION);
        let mut changes = batches.subscribe();
        assert!(changes.borrow_and_update().idle_at(LATE));

        // Ordering a batch of ours replayed from the backup must not underflow.
        batches.ordered(us, 1, true, &batch(1));
        assert!(batches.subscribe().borrow().idle_at(LATE));

        // Our own batches count until ordered, without waking anyone.
        batches.created();
        batches.created();
        assert!(!changes.has_changed().expect("sender alive"));
        batches.ordered(us, 2, true, &batch(2));
        assert!(!changes.borrow().idle_at(LATE));
        batches.ordered(us, 3, true, &batch(3));
        assert!(changes.borrow().idle_at(LATE));

        // A peer's batch is pending from its arrival until it is ordered, and
        // its arrival wakes a parked provider.
        batches.heard(&unit(1, 4, batch(4)));
        assert!(changes.has_changed().expect("sender alive"));
        assert!(!changes.borrow_and_update().idle_at(LATE));

        // Another copy of the same unit is the same batch.
        batches.heard(&unit(1, 4, batch(4)));
        assert!(!changes.has_changed().expect("sender alive"));
        batches.ordered(peer, 4, false, &batch(4));
        assert!(changes.borrow().idle_at(LATE));

        // A rebroadcast of an ordered unit is no new work.
        batches.heard(&unit(1, 4, batch(4)));
        assert!(!changes.has_changed().expect("sender alive"));
        assert!(changes.borrow().idle_at(LATE));

        // Two peers' equal batches stay pending until both are ordered.
        batches.heard(&unit(1, 5, batch(5)));
        batches.heard(&unit(2, 5, batch(5)));
        assert!(!changes.borrow_and_update().idle_at(LATE));
        batches.ordered(peer, 5, false, &batch(5));
        assert!(!changes.borrow().idle_at(LATE));
        batches.ordered(other_peer, 5, false, &batch(5));
        assert!(changes.borrow().idle_at(LATE));

        // Units without a batch are no work, and units naming no possible peer
        // are ignored altogether.
        batches.heard(&unit(1, 5, UnitData::Signature([7; 64])));
        batches.heard(&CarriedUnit {
            session: SESSION,
            creator: aleph_bft::NodeIndex(usize::MAX),
            round: LATE,
            data: Some(batch(6)),
        });
        assert!(!changes.has_changed().expect("sender alive"));
        assert!(changes.borrow().idle_at(LATE));
    }

    #[test]
    fn a_peer_unit_keeps_us_awake_up_to_its_round() {
        let batches = PendingBatches::new(SESSION);
        let mut changes = batches.subscribe();
        assert!(changes.borrow_and_update().idle_at(0));

        // A peer created a unit of round 3, with or without data: we must create
        // ours of rounds up to 3, but may park on round 4.
        batches.heard(&empty_unit(1, 3));
        assert!(changes.has_changed().expect("sender alive"));
        let state = changes.borrow_and_update();
        assert!(!state.idle_at(2));
        assert!(!state.idle_at(3));
        assert!(state.idle_at(4));
        drop(state);

        // Units of rounds we know of already, such as rebroadcasts, wake no one.
        batches.heard(&empty_unit(2, 3));
        batches.heard(&empty_unit(1, 2));
        assert!(!changes.has_changed().expect("sender alive"));

        // A higher round wakes a parked provider.
        batches.heard(&unit(2, 4, UnitData::Signature([7; 64])));
        assert!(changes.has_changed().expect("sender alive"));
        assert!(!changes.borrow_and_update().idle_at(4));
        assert!(changes.borrow().idle_at(5));
    }

    #[test]
    fn units_of_another_session_are_no_work() {
        let batches = PendingBatches::new(SESSION);
        let mut changes = batches.subscribe();
        assert!(changes.borrow_and_update().idle_at(0));

        // Peers rebroadcast the last units of the session they just finished,
        // with rounds past the round limit, and may have attached a batch.
        for session in [SESSION - 1, SESSION + 1] {
            batches.heard(&CarriedUnit {
                session,
                ..empty_unit(1, 3610)
            });
            batches.heard(&CarriedUnit {
                session,
                ..unit(2, 3600, batch(1))
            });
        }
        assert!(!changes.has_changed().expect("sender alive"));
        assert!(changes.borrow().idle_at(1));

        // The same units of this session are work.
        batches.heard(&empty_unit(1, 3610));
        assert!(changes.has_changed().expect("sender alive"));
        assert!(!changes.borrow_and_update().idle_at(1));
    }

    // A single test, since the switch is a process global.
    #[tokio::test]
    async fn quiescence_parks_only_without_work_and_only_while_switched_on() {
        use fedimint_server_core::quiescence::set_enabled;

        set_enabled(false);

        // Off: a unit every round, with or without data.
        let mut h = harness(Some(far_deadline()));
        assert_eq!(h.returns().await, None);
        assert_eq!(h.returns().await, None);

        set_enabled(true);

        // On and idle: no unit until there is work.
        assert!(h.parks().await);

        // An item submitted while parked is attached at once.
        let mempool = h.mempool.clone();
        let ours = h
            .woken_by(move || {
                mempool.try_send(transaction(1)).expect("unbounded");
            })
            .await;
        assert_eq!(batch_items(ours.clone()), vec![transaction(1)]);

        // Units without data continue while our batch awaits ordering.
        assert_eq!(h.returns().await, None);
        assert_eq!(h.returns().await, None);

        // Once it is ordered, we park again.
        h.batches
            .ordered(PeerId::from(0), 2, true, ours.as_ref().expect("a batch"));
        assert!(h.parks().await);

        // A transaction we already attached does not wake us.
        h.mempool.try_send(transaction(1)).expect("unbounded");
        assert!(h.parks().await);

        // A peer's batch wakes us, and we create units until it is ordered. Its
        // unit is from an earlier round, so only its batch keeps us awake.
        let batches = h.batches.clone();
        let earlier = h.round - 1;
        let data = h
            .woken_by(move || {
                batches.heard(&unit(1, earlier, batch(2)));
            })
            .await;
        assert_eq!(data, None);
        assert_eq!(h.returns().await, None);
        h.batches
            .ordered(PeerId::from(1), earlier, false, &batch(2));
        assert!(h.parks().await);

        // Its rebroadcast does not wake us again.
        h.batches.heard(&unit(1, earlier, batch(2)));
        assert!(h.parks().await);

        // A peer that created a unit of the round we are parked on wakes us,
        // even without data: it may be waiting for our unit as a parent. We then
        // park on the next round, which no peer has reached yet.
        let batches = h.batches.clone();
        let parked_on = h.round;
        let data = h
            .woken_by(move || {
                batches.heard(&empty_unit(2, parked_on));
            })
            .await;
        assert_eq!(data, None);
        assert_eq!(h.round, parked_on + 1);
        assert!(h.parks().await);

        // A peer several rounds ahead keeps us creating units until we catch up.
        let ahead = h.round + 2;
        h.batches.heard(&empty_unit(3, ahead));
        assert_eq!(h.returns().await, None);
        assert_eq!(h.returns().await, None);
        assert_eq!(h.returns().await, None);
        assert_eq!(h.round, ahead + 1);
        assert!(h.parks().await);

        // Turning the switch off wakes a parked provider.
        let data = h
            .woken_by(|| {
                set_enabled(false);
            })
            .await;
        assert_eq!(data, None);
        assert_eq!(h.returns().await, None);

        // The session's signature wakes a parked provider.
        set_enabled(true);
        assert!(h.parks().await);
        let signature = schnorr::Signature::from_slice(&[7; 64]).expect("64 bytes");
        let signature_sender = h.signature.clone();
        let data = h
            .woken_by(move || {
                signature_sender.send_replace(Some(signature));
            })
            .await;
        assert_eq!(data, Some(UnitData::Signature(signature.serialize())));

        // A shutdown scheduled after a later session does not wake a parked
        // provider, but one at the end of this session does, and it then creates
        // units without parking so the session completes promptly.
        let mut h = harness(Some(far_deadline()));
        assert!(h.parks().await);
        h.shutdown.send_replace(Some(ScheduledShutdown {
            session: SESSION + 1,
            request: ShutdownRequest::AtSession,
        }));
        assert!(h.parks().await);
        let shutdown = h.shutdown.clone();
        let data = h
            .woken_by(move || {
                shutdown.send_replace(Some(ScheduledShutdown {
                    session: SESSION,
                    request: ShutdownRequest::AfterCurrentSession,
                }));
            })
            .await;
        assert_eq!(data, None);
        assert_eq!(h.returns().await, None);
        assert_eq!(h.returns().await, None);

        // A parked provider resumes creating units at its park deadline.
        let deadline = Instant::now() + Duration::from_millis(150);
        let mut h = harness(Some(deadline));
        let data = h
            .get_data_within(PARKED * 3)
            .await
            .expect("the deadline ends the park");
        assert_eq!(data, None);
        assert!(deadline <= Instant::now());
        assert_eq!(h.returns().await, None);

        // Without a park deadline, as in a session resumed from the backup, the
        // provider never parks.
        let mut h = harness(None);
        assert_eq!(h.returns().await, None);
        assert_eq!(h.returns().await, None);

        set_enabled(false);
    }
}
