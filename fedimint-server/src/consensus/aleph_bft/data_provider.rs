use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use fedimint_core::TransactionId;
use fedimint_core::config::ALEPH_BFT_UNIT_BYTE_LIMIT;
use fedimint_core::encoding::Encodable;
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::secp256k1::schnorr;
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

/// The number of batches we have attached to our own units which have not been
/// ordered yet, shared between the [`DataProvider`] which creates them and the
/// [`super::finalization_handler::FinalizationHandler`] which observes them
/// being ordered.
///
/// Only our own batches keep a quiescent provider creating units at the normal
/// pace. A peer's batch or unit does not: a guardian without quiescence
/// re-proposes its votes every second and creates a unit every round, so it
/// would keep a federation at full speed while any of its guardians runs an
/// older build. The cost: an item that only one guardian has is ordered at the
/// idle pace of the others.
#[derive(Clone, Default)]
pub struct UnorderedBatches(Arc<AtomicUsize>);

impl UnorderedBatches {
    pub fn created(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    pub fn ordered(&self) {
        // Aleph BFT replays every unit of the current session from our backup on
        // a restart, thereby ordering batches we have not created in this
        // process. Hence we saturate at zero instead of underflowing.
        self.0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |batches| {
                Some(batches.saturating_sub(1))
            })
            .expect("The closure always returns Some");
    }

    pub fn is_empty(&self) -> bool {
        self.0.load(Ordering::Relaxed) == 0
    }
}

pub struct DataProvider {
    mempool_item_receiver: async_channel::Receiver<ConsensusItem>,
    signature_receiver: watch::Receiver<Option<schnorr::Signature>>,
    submitted_transactions: BTreeSet<TransactionId>,
    leftover_item: Option<ConsensusItem>,
    timestamp_sender: async_channel::Sender<Instant>,
    is_recovery: bool,
    unordered_batches: UnorderedBatches,
    session_index: u64,
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
        unordered_batches: UnorderedBatches,
        session_index: u64,
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
            unordered_batches,
            session_index,
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
            .is_some_and(|scheduled| scheduled.session <= self.session_index)
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

                self.unordered_batches.created();

                return self.unit(Some(UnitData::Batch(bytes)));
            }

            // Without quiescence we create a unit every round, with or without data,
            // after AlephBFT's round delay. With it, as long as a batch of ours still
            // awaits ordering we do the same, such that the broadcast grows the dag
            // and orders it. Otherwise there is no work to be done and we create our
            // unit only once the idle round delay has passed since our last one, or
            // earlier once an item is submitted to us, quiescence is switched, a
            // shutdown is scheduled at the end of this session, or a peer asks us to
            // drain this session for its own shutdown. We never stop creating units,
            // so a session still completes within rounds times the idle round delay.
            let Some(idle_round_delay) = *self.quiescence.borrow_and_update() else {
                return self.unit(None);
            };

            if !self.unordered_batches.is_empty()
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
    use fedimint_core::encoding::Decodable as _;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
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
        batches: UnorderedBatches,
        _timestamps: async_channel::Receiver<Instant>,
    }

    fn harness() -> Harness {
        let (mempool, mempool_receiver) = async_channel::unbounded();
        let (signature, signature_receiver) = watch::channel(None);
        let (timestamp_sender, timestamps) = async_channel::unbounded();
        let (shutdown, shutdown_receiver) = watch::channel(None);
        let (drain, drain_receiver) = watch::channel(false);
        let batches = UnorderedBatches::default();
        Harness {
            provider: DataProvider::new(
                mempool_receiver,
                signature_receiver,
                timestamp_sender,
                false,
                batches.clone(),
                SESSION,
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

    #[test]
    fn unordered_batches_count_ours_until_ordered() {
        let batches = UnorderedBatches::default();
        assert!(batches.is_empty());

        // Ordering a batch of ours replayed from the backup must not underflow.
        batches.ordered();
        assert!(batches.is_empty());

        batches.created();
        batches.created();
        batches.ordered();
        assert!(!batches.is_empty());
        batches.ordered();
        assert!(batches.is_empty());
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
        h.batches.ordered();
        assert!(h.waits().await);

        // A transaction we already attached does not end the wait.
        h.mempool.try_send(transaction(1)).expect("unbounded");
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
