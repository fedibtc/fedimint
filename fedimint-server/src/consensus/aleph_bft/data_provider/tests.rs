use std::time::Duration;

use aleph_bft::DataProvider as _;
use fedimint_core::encoding::Decodable as _;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::transaction::{Transaction, TransactionSignature};

use super::{
    ConsensusItem, DataProvider, Instant, ScheduledShutdown, UnitData, UnorderedBatches, schnorr,
    watch,
};
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
    drain: watch::Sender<bool>,
    parked: watch::Receiver<bool>,
    batches: UnorderedBatches,
    _timestamps: async_channel::Receiver<Instant>,
}

fn harness(park_deadline: Option<Instant>) -> Harness {
    let (mempool, mempool_receiver) = async_channel::unbounded();
    let (signature, signature_receiver) = watch::channel(None);
    let (timestamp_sender, timestamps) = async_channel::unbounded();
    let (shutdown, shutdown_receiver) = watch::channel(None);
    let (drain, drain_receiver) = watch::channel(false);
    let (parked_tx, parked) = watch::channel(false);
    let batches = UnorderedBatches::default();
    let now = Instant::now();
    let park_window = park_deadline.map(|deadline| (now, deadline.saturating_duration_since(now)));
    Harness {
        provider: DataProvider::new(
            mempool_receiver,
            signature_receiver,
            timestamp_sender,
            false,
            batches.clone(),
            SESSION,
            park_window,
            parked_tx,
            shutdown_receiver,
            drain_receiver,
        ),
        mempool,
        signature,
        shutdown,
        drain,
        parked,
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

    // A peer's request to drain this session wakes a parked provider, which
    // then creates units without parking.
    let mut h = harness(Some(far_deadline()));
    assert!(h.parks().await);
    let drain = h.drain.clone();
    let data = h
        .woken_by(move || {
            drain.send_replace(true);
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
    assert!(!*h.parked.borrow());

    // A policy override extends the park window past the default deadline, and
    // shortening it mid-park wakes the parked provider immediately.
    use fedimint_server_core::quiescence::set_park_duration;
    set_park_duration(Some(Duration::from_secs(3600)));
    let short_default = Instant::now() + Duration::from_millis(50);
    let mut h = harness(Some(short_default));
    assert!(h.parks().await);
    // Clearing back to a shorter duration wakes a parked provider promptly.
    let data = h
        .woken_by(|| {
            set_park_duration(Some(Duration::from_millis(10)));
        })
        .await;
    assert_eq!(data, None);
    assert!(!*h.parked.borrow());

    set_park_duration(None);
    set_enabled(false);
}
