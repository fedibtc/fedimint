use aleph_bft::{NodeIndex, Round};
use fedimint_core::PeerId;

use super::data_provider::{PendingBatches, UnitData};

pub struct OrderedUnit {
    pub creator: PeerId,
    pub round: Round,
    pub data: Option<UnitData>,
}

pub struct FinalizationHandler {
    sender: async_channel::Sender<OrderedUnit>,
    identity: PeerId,
    pending_batches: PendingBatches,
}

impl FinalizationHandler {
    pub fn new(
        sender: async_channel::Sender<OrderedUnit>,
        identity: PeerId,
        pending_batches: PendingBatches,
    ) -> Self {
        Self {
            sender,
            identity,
            pending_batches,
        }
    }
}

impl aleph_bft::FinalizationHandler<UnitData> for FinalizationHandler {
    fn data_finalized(&mut self, _data: UnitData) {
        unreachable!("This method is not called")
    }

    fn unit_finalized(&mut self, creator: NodeIndex, round: Round, data: Option<UnitData>) {
        // Skipping a finalized unit would make us compute a different session
        // outcome than our peers, so we must not swallow an invalid index here.
        // It is unreachable regardless: a unit is only finalized after its
        // signature was verified against our broadcast public key set, which
        // requires its creator to be one of our peers.
        let creator = super::to_peer_id(creator)
            .expect("Finalized units were verified against the broadcast public key set");

        // the data provider stops creating units as soon as all batches with work
        // have been ordered
        if let Some(data) = &data {
            self.pending_batches
                .ordered(creator, round, creator == self.identity, data);
        }

        // the channel is unbounded
        self.sender
            .try_send(OrderedUnit {
                creator,
                round,
                data,
            })
            .ok();
    }
}

#[cfg(test)]
mod tests {
    use aleph_bft::FinalizationHandler as _;
    use fedimint_core::module::registry::ModuleDecoderRegistry;

    use super::*;

    #[test]
    fn only_our_own_ordered_batch_counts_as_ours() {
        let (sender, receiver) = async_channel::unbounded();
        let batches = PendingBatches::new(0, 3600, ModuleDecoderRegistry::default());
        let mut handler = FinalizationHandler::new(sender, PeerId::from(1), batches.clone());

        batches.created();

        // a peer's batch, our signature and our unit without data leave our batch
        // unordered
        handler.unit_finalized(NodeIndex(0), 0, Some(UnitData::Batch(vec![0])));
        handler.unit_finalized(NodeIndex(1), 1, Some(UnitData::Signature([0; 64])));
        handler.unit_finalized(NodeIndex(1), 2, None);
        assert!(!batches.idle());

        handler.unit_finalized(NodeIndex(1), 3, Some(UnitData::Batch(vec![0])));
        assert!(batches.idle());

        // every unit is forwarded to the engine
        assert_eq!(receiver.len(), 4);
    }
}
