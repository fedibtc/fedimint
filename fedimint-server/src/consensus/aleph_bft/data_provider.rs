use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use fedimint_core::TransactionId;
use fedimint_core::config::ALEPH_BFT_UNIT_BYTE_LIMIT;
use fedimint_core::encoding::Encodable;
use fedimint_core::secp256k1::schnorr;
use fedimint_core::session_outcome::ConsensusItem;
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
/// Only our own batches keep a quiescent provider creating units. A peer's
/// batch or unit does not wake us: a guardian without quiescence re-proposes
/// its votes every second and creates a unit every round, so such a wake would
/// keep a federation awake while any of its guardians runs an older build. The
/// cost: an item that only one guardian has waits until another guardian has
/// work of its own, such as its next unix time vote.
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
    park_deadline: Option<Instant>,
    quiescence: watch::Receiver<bool>,
    shutdown: watch::Receiver<Option<ScheduledShutdown>>,
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
            unordered_batches,
            session_index,
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
            .is_some_and(|scheduled| scheduled.session <= self.session_index)
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

                self.unordered_batches.created();

                return Some(UnitData::Batch(bytes));
            }

            // Without quiescence we create a unit every round, with or without data.
            // With it, as long as a batch of ours still awaits ordering, we keep
            // creating units without data such that the broadcast grows the dag and
            // orders it. Otherwise there is no work to be done and we go quiescent
            // until an item is submitted to us, the session ends, the park deadline
            // passes, quiescence is turned off, or a shutdown is scheduled at the end
            // of this session.
            let park_deadline = self.park_deadline?;

            if !*self.quiescence.borrow_and_update()
                || Instant::now() >= park_deadline
                || !self.unordered_batches.is_empty()
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

    struct Harness {
        provider: DataProvider,
        mempool: async_channel::Sender<ConsensusItem>,
        signature: watch::Sender<Option<schnorr::Signature>>,
        shutdown: watch::Sender<Option<ScheduledShutdown>>,
        batches: UnorderedBatches,
        _timestamps: async_channel::Receiver<Instant>,
    }

    fn harness(park_deadline: Option<Instant>) -> Harness {
        let (mempool, mempool_receiver) = async_channel::unbounded();
        let (signature, signature_receiver) = watch::channel(None);
        let (timestamp_sender, timestamps) = async_channel::unbounded();
        let (shutdown, shutdown_receiver) = watch::channel(None);
        let batches = UnorderedBatches::default();
        Harness {
            provider: DataProvider::new(
                mempool_receiver,
                signature_receiver,
                timestamp_sender,
                false,
                batches.clone(),
                SESSION,
                park_deadline,
                shutdown_receiver,
            ),
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
            tokio::time::timeout(limit, self.provider.get_data())
                .await
                .ok()
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
        assert_eq!(batch_items(ours), vec![transaction(1)]);

        // Units without data continue while our batch awaits ordering.
        assert_eq!(h.returns().await, None);
        assert_eq!(h.returns().await, None);

        // Once it is ordered, we park again.
        h.batches.ordered();
        assert!(h.parks().await);

        // A transaction we already attached does not wake us.
        h.mempool.try_send(transaction(1)).expect("unbounded");
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
