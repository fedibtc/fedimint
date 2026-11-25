use aleph_bft::{FinalizationHandler as _, NodeIndex};
use fedimint_core::PeerId;

use super::FinalizationHandler;
use crate::consensus::aleph_bft::data_provider::{UnitData, UnorderedBatches};

#[test]
fn only_our_own_ordered_batch_counts_as_ordered() {
    let (sender, receiver) = async_channel::unbounded();
    let batches = UnorderedBatches::default();
    let mut handler = FinalizationHandler::new(sender, PeerId::from(1), batches.clone());

    batches.created();

    // a peer's batch, our signature and our unit without data leave our batch
    // unordered
    handler.unit_finalized(NodeIndex(0), 0, Some(UnitData::Batch(vec![])));
    handler.unit_finalized(NodeIndex(1), 1, Some(UnitData::Signature([0; 64])));
    handler.unit_finalized(NodeIndex(1), 2, None);
    assert!(!batches.is_empty());

    handler.unit_finalized(NodeIndex(1), 3, Some(UnitData::Batch(vec![])));
    assert!(batches.is_empty());

    // every unit is forwarded to the engine
    assert_eq!(receiver.len(), 4);
}
