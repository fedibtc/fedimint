use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aleph_bft::{CarriedUnit, Round};
use fedimint_core::config::ALEPH_BFT_UNIT_BYTE_LIMIT;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::module::registry::ModuleDecoderRegistry;
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

/// What keeps a quiescent [`DataProvider`] creating units at the normal pace in
/// this session: the batches that, as far as we know, await ordering and carry
/// work.
///
/// - Our own batches, from their creation until they are ordered.
/// - A peer's batch that carries a transaction, or an item that we have not
///   ordered from this peer yet in this session. A batch which only one
///   guardian has then gets ordered right away rather than at the idle pace.
///
/// A peer's batch of items that we already ordered from it does not speed us
/// up.
/// A guardian without the vote dedup of
/// [`fedimint_server_core::quiescence`] re-proposes its unchanged votes on
/// every poll, so nearly every unit it creates carries such a batch, and
/// speeding up for it would keep a federation at full speed while any of its
/// guardians runs an older build. Its votes that change still speed us up. Nor
/// does a peer unit without data, as such a guardian creates one every round.
///
/// The record of ordered items lives as long as the session. Bounding it by
/// the session bounds it by what the session outcome holds anyway, and the
/// only cost is that an older guardian's unchanged votes speed us up once at
/// the start of every session.
///
/// The [`DataProvider`] counts our batches as it creates them, the
/// [`super::network::Network`] records our peers' units of this session as
/// they arrive, and the [`super::finalization_handler::FinalizationHandler`]
/// clears batches and records their items as they are ordered.
#[derive(Clone)]
pub struct PendingBatches {
    /// Peers keep rebroadcasting the last units of the session they just
    /// finished while we run the next one. Those units are no work of ours.
    session: u64,
    /// The session outcome only takes items from units below this round, so a
    /// unit at or above it carries no work. Bounding the rounds we record also
    /// bounds the memory a peer can make us spend on units that AlephBFT has
    /// not verified yet, to what the broadcast itself may hold.
    rounds: Round,
    decoders: ModuleDecoderRegistry,
    state: Arc<watch::Sender<PendingBatchesState>>,
}

#[derive(Debug, Default)]
pub struct PendingBatchesState {
    ours: usize,
    /// Our peers' unordered batches that carry work, by the creator and round
    /// of their unit, since two guardians may attach equal batches to their
    /// units, with the items that make them work.
    peers: BTreeMap<(PeerId, Round), Vec<ConsensusItem>>,
    /// Aleph BFT rebroadcasts a guardian's latest unit until it creates the
    /// next one and sends units again in responses, so we remember which units
    /// were ordered in order to not take such a copy for new work.
    ordered: BTreeSet<(PeerId, Round)>,
    /// The items other than transactions of each peer's batches ordered in
    /// this session.
    ordered_items: BTreeMap<PeerId, HashSet<ConsensusItem>>,
}

impl PendingBatchesState {
    /// Whether nothing keeps us from slowing down.
    fn idle(&self) -> bool {
        self.ours == 0 && self.peers.is_empty()
    }

    /// The items of a peer's batch that are work: its transactions, and the
    /// items we have not ordered from this peer yet.
    fn work(&self, creator: PeerId, items: Vec<ConsensusItem>) -> Vec<ConsensusItem> {
        let ordered = self.ordered_items.get(&creator);

        items
            .into_iter()
            .filter(|item| {
                matches!(item, ConsensusItem::Transaction(..))
                    || ordered.is_none_or(|ordered| !ordered.contains(item))
            })
            .collect()
    }
}

impl PendingBatches {
    pub fn new(session: u64, rounds: Round, decoders: ModuleDecoderRegistry) -> Self {
        Self {
            session,
            rounds,
            decoders,
            state: Arc::new(watch::channel(PendingBatchesState::default()).0),
        }
    }

    pub(super) fn created(&self) {
        self.state.send_if_modified(|state| {
            state.ours += 1;
            // only a peer's batch needs to end a waiting data provider's wait
            false
        });
    }

    /// The items of a batch. A batch that does not decode is ordered and then
    /// discarded by every guardian, so we treat it as a single unknown item:
    /// it wakes us once, but its rebroadcasts do not.
    fn items(&self, bytes: &[u8]) -> Vec<ConsensusItem> {
        Vec::<ConsensusItem>::consensus_decode_whole(bytes, &self.decoders).unwrap_or_else(|_| {
            vec![ConsensusItem::Default {
                variant: u64::MAX,
                bytes: bytes.to_vec(),
            }]
        })
    }

    /// Record the batch of a unit of this session received from a peer, if it
    /// carries work. The unit is not verified yet, so a peer can keep us from
    /// going quiescent, but nothing else.
    pub fn heard(&self, unit: &CarriedUnit<UnitData>) {
        let Some(UnitData::Batch(bytes)) = &unit.data else {
            return;
        };

        if unit.session != self.session || unit.round >= self.rounds {
            return;
        }

        // a peer can name any node index in a message it sends us
        let Some(creator) = super::to_peer_id(unit.creator) else {
            return;
        };

        let key = (creator, unit.round);

        {
            let state = self.state.borrow();

            if state.ordered.contains(&key) || state.peers.contains_key(&key) {
                return;
            }
        }

        let items = self.items(bytes);

        self.state.send_if_modified(|state| {
            if state.ordered.contains(&key) || state.peers.contains_key(&key) {
                return false;
            }

            let work = state.work(creator, items);

            if work.is_empty() {
                return false;
            }

            state.peers.insert(key, work);

            true
        });
    }

    pub fn ordered(&self, creator: PeerId, round: Round, ours: bool, data: &UnitData) {
        let UnitData::Batch(bytes) = data else {
            return;
        };

        let items = (!ours).then(|| self.items(bytes));

        self.state.send_if_modified(|state| {
            // Aleph BFT replays every unit of the current session from our backup on
            // a restart, thereby ordering batches we have not created in this
            // process. Hence we saturate at zero instead of underflowing.
            if ours {
                state.ours = state.ours.saturating_sub(1);
            }

            state.peers.remove(&(creator, round));
            state.ordered.insert((creator, round));

            if let Some(items) = items {
                state.ordered_items.entry(creator).or_default().extend(
                    items
                        .into_iter()
                        .filter(|item| !matches!(item, ConsensusItem::Transaction(..))),
                );

                // A peer's later batches that repeat what is now ordered are no
                // work any more.
                let ordered = &state.ordered_items[&creator];

                state.peers.retain(|(peer, _), work| {
                    if *peer != creator {
                        return true;
                    }

                    work.retain(|item| {
                        matches!(item, ConsensusItem::Transaction(..)) || !ordered.contains(item)
                    });

                    !work.is_empty()
                });
            }

            // ordering never gives a waiting data provider work
            false
        });
    }

    fn subscribe(&self) -> watch::Receiver<PendingBatchesState> {
        self.state.subscribe()
    }

    #[cfg(test)]
    pub(super) fn idle(&self) -> bool {
        self.state.borrow().idle()
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
    /// When we last returned data or none, which the idle round delay counts
    /// from.
    last_unit: Instant,
    quiescence: watch::Receiver<Option<Duration>>,
    shutdown: watch::Receiver<Option<ScheduledShutdown>>,
    drain: watch::Receiver<bool>,
}

impl DataProvider {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mempool_item_receiver: async_channel::Receiver<ConsensusItem>,
        signature_receiver: watch::Receiver<Option<schnorr::Signature>>,
        timestamp_sender: async_channel::Sender<Instant>,
        is_recovery: bool,
        pending_batches: PendingBatches,
        shutdown: watch::Receiver<Option<ScheduledShutdown>>,
        drain: watch::Receiver<bool>,
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
            last_unit: Instant::now(),
            quiescence: fedimint_server_core::quiescence::subscribe(),
            shutdown,
            drain,
        }
    }

    /// Whether an admin scheduled a shutdown at the end of this session. We
    /// then stop slowing down, and the engine asks our peers to drain the
    /// session as well, since a round needs units from 2f+1 guardians.
    fn shutdown_due(&mut self) -> bool {
        self.shutdown
            .borrow_and_update()
            .is_some_and(|scheduled| scheduled.session <= self.pending_batches.session)
    }

    /// Return the data of our next unit, from whose creation we count the idle
    /// round delay.
    fn unit(&mut self, data: Option<UnitData>) -> Option<UnitData> {
        self.last_unit = Instant::now();
        data
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
    async fn get_data(&mut self) -> Option<UnitData> {
        loop {
            // we only attach our signature as no more items can be ordered in this session
            let signature = *self.signature_receiver.borrow();

            if let Some(signature) = signature {
                return self.unit(Some(UnitData::Signature(signature.serialize())));
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

                return self.unit(Some(UnitData::Batch(bytes)));
            }

            // Without quiescence we create a unit every round, with or without data,
            // after AlephBFT's round delay. With it, as long as a batch of ours or a
            // peer's batch with work still awaits ordering we do the same, such that the
            // broadcast grows the dag and orders it. Otherwise there is no work
            // to be done and we create our unit only once the idle round delay
            // has passed since our last one, or earlier once an item is
            // submitted to us, a peer's batch with work arrives, quiescence is
            // switched, a shutdown is scheduled at the end of this session, or
            // a peer asks us to drain this session for its own shutdown. We
            // never stop creating units, so a session still completes within
            // rounds times the idle round delay.
            let Some(idle_round_delay) = *self.quiescence.borrow_and_update() else {
                return self.unit(None);
            };

            if !self.pending_changes.borrow_and_update().idle()
                || self.shutdown_due()
                || *self.drain.borrow_and_update()
            {
                return self.unit(None);
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
                        // we wait instead of spinning on the closed channel
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
                changed = self.drain.changed() => {
                    if changed.is_err() {
                        std::future::pending::<()>().await;
                    }
                }
                () = tokio::time::sleep_until((self.last_unit + idle_round_delay).into()) => {
                    return self.unit(None);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use aleph_bft::DataProvider as _;
    use fedimint_core::transaction::{Transaction, TransactionSignature};

    use super::*;
    use crate::consensus::engine::ShutdownRequest;

    const WAITED: Duration = Duration::from_millis(300);

    /// An idle round delay far beyond any test's duration.
    const LONG: Option<Duration> = Some(Duration::from_secs(3600));

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

    struct Harness {
        provider: DataProvider,
        mempool: async_channel::Sender<ConsensusItem>,
        signature: watch::Sender<Option<schnorr::Signature>>,
        shutdown: watch::Sender<Option<ScheduledShutdown>>,
        drain: watch::Sender<bool>,
        batches: PendingBatches,
        _timestamps: async_channel::Receiver<Instant>,
    }

    fn harness() -> Harness {
        let (mempool, mempool_receiver) = async_channel::unbounded();
        let (signature, signature_receiver) = watch::channel(None);
        let (timestamp_sender, timestamps) = async_channel::unbounded();
        let (shutdown, shutdown_receiver) = watch::channel(None);
        let (drain, drain_receiver) = watch::channel(false);
        let batches = PendingBatches::new(SESSION, ROUNDS, ModuleDecoderRegistry::default());
        Harness {
            provider: DataProvider::new(
                mempool_receiver,
                signature_receiver,
                timestamp_sender,
                false,
                batches.clone(),
                shutdown_receiver,
                drain_receiver,
            ),
            mempool,
            signature,
            shutdown,
            drain,
            batches,
            _timestamps: timestamps,
        }
    }

    impl Harness {
        async fn get_data_within(&mut self, limit: Duration) -> Option<Option<UnitData>> {
            tokio::time::timeout(limit, self.provider.get_data())
                .await
                .ok()
        }

        async fn waits(&mut self) -> bool {
            self.get_data_within(WAITED).await.is_none()
        }

        async fn returns(&mut self) -> Option<UnitData> {
            self.get_data_within(WAITED)
                .await
                .expect("get_data returns without waiting")
        }

        /// Run `wake` shortly after `get_data` has started to wait, and return
        /// its result.
        async fn woken_by(&mut self, wake: impl FnOnce() + Send + 'static) -> Option<UnitData> {
            let waker = fedimint_core::runtime::spawn("data provider test waker", async move {
                fedimint_core::runtime::sleep(Duration::from_millis(100)).await;
                wake();
            });
            let data = self
                .get_data_within(WAITED * 3)
                .await
                .expect("the wake-up ends the wait");
            waker.await.expect("the waker does not panic");
            data
        }
    }

    /// The session the tests' providers run.
    const SESSION: u64 = 7;

    /// The rounds of the tests' sessions.
    const ROUNDS: Round = 3600;

    /// A vote as a guardian proposes it, `value` being what it votes for. Its
    /// variant is unknown, so it decodes without module decoders.
    fn vote(kind: u64, value: u8) -> ConsensusItem {
        ConsensusItem::Default {
            variant: 1000 + kind,
            bytes: vec![value],
        }
    }

    fn batch(items: &[ConsensusItem]) -> UnitData {
        UnitData::Batch(items.to_vec().consensus_encode_to_vec())
    }

    fn unit(creator: u16, round: Round, data: Option<UnitData>) -> CarriedUnit<UnitData> {
        CarriedUnit {
            session: SESSION,
            creator: aleph_bft::NodeIndex(creator.into()),
            round,
            data,
        }
    }

    fn pending() -> (PendingBatches, watch::Receiver<PendingBatchesState>) {
        let batches = PendingBatches::new(SESSION, ROUNDS, ModuleDecoderRegistry::default());
        let mut changes = batches.subscribe();
        assert!(changes.borrow_and_update().idle());
        (batches, changes)
    }

    #[test]
    fn our_batches_count_until_ordered_without_waking_anyone() {
        let (batches, mut changes) = pending();
        let us = PeerId::from(0);

        // Ordering a batch of ours replayed from the backup must not underflow.
        batches.ordered(us, 1, true, &batch(&[vote(1, 1)]));
        assert!(changes.borrow().idle());

        batches.created();
        batches.created();
        assert!(!changes.has_changed().expect("sender alive"));
        batches.ordered(us, 2, true, &batch(&[vote(1, 1)]));
        assert!(!changes.borrow().idle());
        batches.ordered(us, 3, true, &batch(&[vote(1, 2)]));
        assert!(changes.borrow_and_update().idle());

        // What we ordered from ourselves is no record of a peer's items.
        batches.heard(&unit(1, 4, Some(batch(&[vote(1, 2)]))));
        assert!(changes.has_changed().expect("sender alive"));
        assert!(!changes.borrow().idle());
    }

    #[test]
    fn a_peer_repeating_ordered_votes_wakes_no_one_but_a_changed_vote_does() {
        let (batches, mut changes) = pending();
        let old = PeerId::from(1);
        let votes = [vote(1, 100), vote(2, 7)];

        // A peer's first votes in the session are work until ordered.
        batches.heard(&unit(1, 4, Some(batch(&votes))));
        assert!(changes.has_changed().expect("sender alive"));
        assert!(!changes.borrow_and_update().idle());

        // Another copy of the same unit is the same batch.
        batches.heard(&unit(1, 4, Some(batch(&votes))));
        assert!(!changes.has_changed().expect("sender alive"));

        batches.ordered(old, 4, false, &batch(&votes));
        assert!(changes.borrow().idle());

        // A rebroadcast of the ordered unit is no new work.
        batches.heard(&unit(1, 4, Some(batch(&votes))));
        assert!(changes.borrow().idle());

        // The same votes re-proposed in later units, in any order or subset, are
        // no work either.
        batches.heard(&unit(1, 5, Some(batch(&votes))));
        batches.heard(&unit(1, 6, Some(batch(&[vote(2, 7), vote(1, 100)]))));
        batches.heard(&unit(1, 7, Some(batch(&[vote(2, 7)]))));
        assert!(!changes.has_changed().expect("sender alive"));
        assert!(changes.borrow().idle());

        // One changed vote among unchanged ones wakes us.
        batches.heard(&unit(1, 8, Some(batch(&[vote(1, 101), vote(2, 7)]))));
        assert!(changes.has_changed().expect("sender alive"));
        assert!(!changes.borrow_and_update().idle());
        batches.ordered(old, 8, false, &batch(&[vote(1, 101), vote(2, 7)]));
        assert!(changes.borrow().idle());

        // The record is per peer: another peer's equal votes are work.
        batches.heard(&unit(2, 8, Some(batch(&votes))));
        assert!(changes.has_changed().expect("sender alive"));
        assert!(!changes.borrow_and_update().idle());
    }

    #[test]
    fn transactions_always_wake() {
        let (batches, mut changes) = pending();
        let peer = PeerId::from(1);
        let items = [vote(1, 1), transaction(1)];

        batches.heard(&unit(1, 4, Some(batch(&items))));
        assert!(!changes.borrow_and_update().idle());
        batches.ordered(peer, 4, false, &batch(&items));
        assert!(changes.borrow().idle());

        // The same transaction in a later unit of the same peer is work again.
        batches.heard(&unit(1, 5, Some(batch(&items))));
        assert!(changes.has_changed().expect("sender alive"));
        assert!(!changes.borrow_and_update().idle());
    }

    #[test]
    fn ordering_a_peers_batch_clears_its_pending_repeats() {
        let (batches, mut changes) = pending();
        let old = PeerId::from(1);
        let votes = [vote(1, 100)];

        // A peer without quiescence attaches the same votes to its next units
        // before the first is ordered.
        batches.heard(&unit(1, 4, Some(batch(&votes))));
        batches.heard(&unit(1, 5, Some(batch(&votes))));
        batches.heard(&unit(1, 6, Some(batch(&[vote(1, 100), transaction(1)]))));
        batches.heard(&unit(2, 5, Some(batch(&votes))));
        assert!(!changes.borrow_and_update().idle());

        // Once the first is ordered, the repeats are no work, but the batch
        // with a transaction and the other peer's batch still are.
        batches.ordered(old, 4, false, &batch(&votes));
        let state = changes.borrow_and_update();
        assert_eq!(
            state.peers.keys().copied().collect::<Vec<_>>(),
            vec![(old, 6), (PeerId::from(2), 5)]
        );
        drop(state);

        batches.ordered(old, 6, false, &batch(&[vote(1, 100), transaction(1)]));
        batches.ordered(PeerId::from(2), 5, false, &batch(&votes));
        assert!(changes.borrow().idle());

        // An ordered repeat that we stopped waiting for is harmless.
        batches.ordered(old, 5, false, &batch(&votes));
        assert!(changes.borrow().idle());
    }

    #[test]
    fn units_past_the_last_round_of_the_session_are_no_work() {
        let (batches, mut changes) = pending();

        // The session outcome takes no items from these rounds, and a peer
        // could name any of them to make us hold its batches.
        for round in [ROUNDS, ROUNDS + 1, Round::MAX] {
            batches.heard(&unit(1, round, Some(batch(&[vote(1, 1)]))));
        }
        assert!(!changes.has_changed().expect("sender alive"));
        assert!(changes.borrow().idle());

        // The last round that is ordered still counts.
        batches.heard(&unit(1, ROUNDS - 1, Some(batch(&[vote(1, 1)]))));
        assert!(changes.has_changed().expect("sender alive"));
        assert!(!changes.borrow_and_update().idle());
    }

    #[test]
    fn units_without_work_of_this_session_are_ignored() {
        let (batches, mut changes) = pending();

        // A guardian without quiescence creates a unit every round. Those
        // units, however far ahead of ours, must not speed us up.
        batches.heard(&unit(1, 3, None));
        batches.heard(&unit(1, 500, None));
        batches.heard(&unit(2, 501, Some(UnitData::Signature([7; 64]))));

        // Units naming no possible peer are ignored.
        batches.heard(&CarriedUnit {
            session: SESSION,
            creator: aleph_bft::NodeIndex(usize::MAX),
            round: 6,
            data: Some(batch(&[vote(1, 1)])),
        });

        // Peers rebroadcast the last units of the session they just finished.
        for session in [SESSION - 1, SESSION + 1] {
            batches.heard(&CarriedUnit {
                session,
                ..unit(1, 3610, Some(batch(&[vote(1, 1)])))
            });
        }
        assert!(!changes.has_changed().expect("sender alive"));
        assert!(changes.borrow().idle());

        // A batch that does not decode wakes us once, and not again once
        // ordered.
        let garbage = UnitData::Batch(vec![0xff; 3]);
        batches.heard(&unit(3, 7, Some(garbage.clone())));
        assert!(!changes.borrow_and_update().idle());
        batches.ordered(PeerId::from(3), 7, false, &garbage);
        batches.heard(&unit(3, 8, Some(garbage)));
        assert!(changes.borrow().idle());
    }

    // A single test, since the switch is a process global.
    #[tokio::test]
    async fn quiescence_slows_down_only_without_work_and_only_while_switched_on() {
        use fedimint_server_core::quiescence::set_idle_round_delay;

        set_idle_round_delay(None);

        // Off: a unit every round, with or without data.
        let mut h = harness();
        assert_eq!(h.returns().await, None);
        assert_eq!(h.returns().await, None);

        set_idle_round_delay(LONG);

        // On and idle: no unit before the idle round delay.
        assert!(h.waits().await);

        // An item submitted while waiting is attached at once.
        let mempool = h.mempool.clone();
        let ours = h
            .woken_by(move || {
                mempool.try_send(transaction(1)).expect("unbounded");
            })
            .await;
        assert_eq!(batch_items(ours), vec![transaction(1)]);

        // Units without data continue at the normal pace while our batch awaits
        // ordering.
        assert_eq!(h.returns().await, None);
        assert_eq!(h.returns().await, None);

        // Once it is ordered, we wait again.
        h.batches
            .ordered(PeerId::from(0), 0, true, &batch(&[transaction(1)]));
        assert!(h.waits().await);

        // A transaction we already attached does not end the wait.
        h.mempool.try_send(transaction(1)).expect("unbounded");
        assert!(h.waits().await);

        // A peer's batch with work ends the wait, and we keep the normal pace
        // until it is ordered.
        let batches = h.batches.clone();
        let data = h
            .woken_by(move || {
                batches.heard(&unit(1, 3, Some(batch(&[vote(1, 1)]))));
            })
            .await;
        assert_eq!(data, None);
        assert_eq!(h.returns().await, None);
        h.batches
            .ordered(PeerId::from(1), 3, false, &batch(&[vote(1, 1)]));
        assert!(h.waits().await);

        // Its repeat in the peer's next units, and peer units without data, do
        // not.
        h.batches.heard(&unit(1, 4, Some(batch(&[vote(1, 1)]))));
        h.batches.heard(&unit(2, 100, None));
        assert!(h.waits().await);

        // Turning the switch off ends the wait.
        let data = h
            .woken_by(|| {
                set_idle_round_delay(None);
            })
            .await;
        assert_eq!(data, None);
        assert_eq!(h.returns().await, None);

        // A shorter delay applies at once, counted from our last unit: the first
        // unit after a long wait is due right away, the next one after the delay.
        set_idle_round_delay(LONG);
        assert!(h.waits().await);
        let data = h
            .woken_by(|| {
                set_idle_round_delay(Some(Duration::from_millis(50)));
            })
            .await;
        assert_eq!(data, None);
        let start = Instant::now();
        assert_eq!(h.returns().await, None);
        assert!(Duration::from_millis(50) <= start.elapsed());
        set_idle_round_delay(Some(Duration::from_millis(500)));
        let start = Instant::now();
        let data = h
            .get_data_within(WAITED * 3)
            .await
            .expect("the idle round delay ends the wait");
        assert_eq!(data, None);
        assert!(Duration::from_millis(500) <= start.elapsed());

        // The session's signature ends the wait.
        set_idle_round_delay(LONG);
        assert!(h.waits().await);
        let signature = schnorr::Signature::from_slice(&[7; 64]).expect("64 bytes");
        let signature_sender = h.signature.clone();
        let data = h
            .woken_by(move || {
                signature_sender.send_replace(Some(signature));
            })
            .await;
        assert_eq!(data, Some(UnitData::Signature(signature.serialize())));

        // A shutdown scheduled after a later session does not end the wait, but
        // one at the end of this session does, and we then create units at the
        // normal pace so the session completes promptly.
        let mut h = harness();
        assert!(h.waits().await);
        h.shutdown.send_replace(Some(ScheduledShutdown {
            session: SESSION + 1,
            request: ShutdownRequest::AtSession,
        }));
        assert!(h.waits().await);
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

        // So does a peer's request to drain this session.
        let mut h = harness();
        assert!(h.waits().await);
        let drain = h.drain.clone();
        let data = h
            .woken_by(move || {
                drain.send_replace(true);
            })
            .await;
        assert_eq!(data, None);
        assert_eq!(h.returns().await, None);
        assert_eq!(h.returns().await, None);

        set_idle_round_delay(None);
    }
}
