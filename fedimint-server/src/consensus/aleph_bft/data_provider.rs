use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use fedimint_core::TransactionId;
use fedimint_core::config::ALEPH_BFT_UNIT_BYTE_LIMIT;
use fedimint_core::encoding::Encodable;
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::secp256k1::schnorr;
use tokio::sync::watch;

use crate::LOG_CONSENSUS;

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

/// The batches we have attached to our own units which have not been ordered
/// yet, shared between the [`DataProvider`] which creates them, the
/// [`super::finalization_handler::FinalizationHandler`] which observes them
/// being ordered, and the session watchdog.
#[derive(Clone)]
pub struct UnorderedBatches(Arc<Mutex<UnorderedBatchesState>>);

struct UnorderedBatchesState {
    count: usize,
    /// When one of our batches was last ordered, or when we started waiting if
    /// none has been ordered since.
    last_progress: Instant,
}

impl Default for UnorderedBatches {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(UnorderedBatchesState {
            count: 0,
            last_progress: Instant::now(),
        })))
    }
}

impl UnorderedBatches {
    fn lock(&self) -> std::sync::MutexGuard<'_, UnorderedBatchesState> {
        self.0
            .lock()
            .expect("No code panics while holding the lock")
    }

    pub fn created(&self) {
        let mut state = self.lock();
        if state.count == 0 {
            // Waiting starts now, not when the previous batch was ordered.
            state.last_progress = Instant::now();
        }
        state.count += 1;
    }

    pub fn ordered(&self) {
        let mut state = self.lock();
        // Aleph BFT replays every unit of the current session from our backup on
        // a restart, thereby ordering batches we have not created in this
        // process. Hence we saturate at zero instead of underflowing.
        state.count = state.count.saturating_sub(1);
        state.last_progress = Instant::now();
    }

    pub fn is_empty(&self) -> bool {
        self.lock().count == 0
    }

    /// How long a batch of ours has been waiting without any of our batches
    /// being ordered, or `None` if none is waiting.
    pub fn stalled_for(&self) -> Option<std::time::Duration> {
        let state = self.lock();
        (state.count != 0).then(|| state.last_progress.elapsed())
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
    quiescence: watch::Receiver<bool>,
}

impl DataProvider {
    pub fn new(
        mempool_item_receiver: async_channel::Receiver<ConsensusItem>,
        signature_receiver: watch::Receiver<Option<schnorr::Signature>>,
        timestamp_sender: async_channel::Sender<Instant>,
        is_recovery: bool,
        unordered_batches: UnorderedBatches,
    ) -> Self {
        Self {
            mempool_item_receiver,
            signature_receiver,
            submitted_transactions: BTreeSet::new(),
            leftover_item: None,
            timestamp_sender,
            is_recovery,
            unordered_batches,
            quiescence: fedimint_server_core::quiescence::subscribe(),
        }
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
            // With it, as long as a batch of ours still awaits ordering we keep
            // creating units without data such that the broadcast grows the dag and
            // orders it, otherwise there is no work to be done and we go quiescent
            // until an item is submitted to us, the session ends, or quiescence is
            // turned off. A session we resumed from our backup after a restart may
            // hold batches of ours that we no longer count, so we never go quiescent
            // in it.
            if !*self.quiescence.borrow_and_update()
                || self.is_recovery
                || !self.unordered_batches.is_empty()
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
        batches: UnorderedBatches,
        _timestamps: async_channel::Receiver<Instant>,
    }

    fn harness(is_recovery: bool) -> Harness {
        let (mempool, mempool_receiver) = async_channel::unbounded();
        let (signature, signature_receiver) = watch::channel(None);
        let (timestamp_sender, timestamps) = async_channel::unbounded();
        let batches = UnorderedBatches::default();
        Harness {
            provider: DataProvider::new(
                mempool_receiver,
                signature_receiver,
                timestamp_sender,
                is_recovery,
                batches.clone(),
            ),
            mempool,
            signature,
            batches,
            _timestamps: timestamps,
        }
    }

    async fn parks(provider: &mut DataProvider) -> bool {
        tokio::time::timeout(PARKED, provider.get_data())
            .await
            .is_err()
    }

    async fn returns(provider: &mut DataProvider) -> Option<UnitData> {
        tokio::time::timeout(PARKED, provider.get_data())
            .await
            .expect("get_data returns without parking")
    }

    /// Run `wake` shortly after `get_data` has parked, and return its result.
    async fn woken_by(
        provider: &mut DataProvider,
        wake: impl FnOnce() + Send + 'static,
    ) -> Option<UnitData> {
        let waker = fedimint_core::runtime::spawn("data provider test waker", async move {
            fedimint_core::runtime::sleep(Duration::from_millis(100)).await;
            wake();
        });
        let data = tokio::time::timeout(PARKED * 3, provider.get_data())
            .await
            .expect("the wake-up ends the park");
        waker.await.expect("the waker does not panic");
        data
    }

    #[test]
    fn unordered_batches_track_the_wait_without_progress() {
        let batches = UnorderedBatches::default();
        assert!(batches.is_empty());
        assert_eq!(batches.stalled_for(), None);

        // Ordering a batch replayed from the backup must not underflow.
        batches.ordered();
        assert!(batches.is_empty());

        batches.created();
        batches.created();
        std::thread::sleep(Duration::from_millis(50));
        let waited = batches.stalled_for().expect("two batches wait");
        assert!(waited >= Duration::from_millis(50));

        // Progress on one batch restarts the clock while the other still waits.
        batches.ordered();
        assert!(!batches.is_empty());
        assert!(batches.stalled_for().expect("one batch waits") < waited);

        batches.ordered();
        assert!(batches.is_empty());
        assert_eq!(batches.stalled_for(), None);
    }

    // A single test, since the switch is a process global.
    #[tokio::test]
    async fn quiescence_parks_only_without_work_and_only_while_switched_on() {
        use fedimint_server_core::quiescence::set_enabled;

        set_enabled(false);

        // Off: a unit every round, with or without data.
        let mut h = harness(false);
        assert_eq!(returns(&mut h.provider).await, None);
        assert_eq!(returns(&mut h.provider).await, None);

        set_enabled(true);

        // On and idle: no unit until there is work.
        assert!(parks(&mut h.provider).await);

        // An item submitted while parked is attached at once.
        let mempool = h.mempool.clone();
        let data = woken_by(&mut h.provider, move || {
            mempool.try_send(transaction(1)).expect("unbounded");
        })
        .await;
        assert_eq!(batch_items(data), vec![transaction(1)]);

        // Units without data continue while our batch awaits ordering.
        assert_eq!(returns(&mut h.provider).await, None);
        assert_eq!(returns(&mut h.provider).await, None);

        // Once it is ordered, we park again.
        h.batches.ordered();
        assert!(parks(&mut h.provider).await);

        // A transaction we already attached does not wake us.
        h.mempool.try_send(transaction(1)).expect("unbounded");
        assert!(parks(&mut h.provider).await);

        // Turning the switch off wakes a parked provider.
        let data = woken_by(&mut h.provider, || {
            set_enabled(false);
        })
        .await;
        assert_eq!(data, None);
        assert_eq!(returns(&mut h.provider).await, None);

        // The session's signature wakes a parked provider.
        set_enabled(true);
        assert!(parks(&mut h.provider).await);
        let signature = schnorr::Signature::from_slice(&[7; 64]).expect("64 bytes");
        let signature_sender = h.signature.clone();
        let data = woken_by(&mut h.provider, move || {
            signature_sender.send_replace(Some(signature));
        })
        .await;
        assert_eq!(data, Some(UnitData::Signature(signature.serialize())));

        // A session resumed from the backup never parks.
        let mut recovered = harness(true);
        assert_eq!(returns(&mut recovered.provider).await, None);
        assert_eq!(returns(&mut recovered.provider).await, None);

        set_enabled(false);
    }
}
