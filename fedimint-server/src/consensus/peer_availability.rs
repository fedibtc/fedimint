//! This guardian's view of its peers' availability.
//!
//! When a session completes we count the units each peer created in it from
//! the AlephBFT backup, which holds every unit added to our DAG, late or not.
//! A unit proves its creator ran this session and kept up with consensus, so
//! a slow peer counts while a frozen or offline one does not. The counts feed
//! exponential moving averages with the time constants in
//! [`PEER_AVAILABILITY_WINDOWS_SECS`] and each peer's last-seen time.

use std::collections::BTreeMap;
use std::io::{Error, Read, Write};

use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::peer_availability::{
    PEER_AVAILABILITY_WINDOWS_SECS, PeerAvailability, WindowAvailability,
};
use fedimint_core::{NumPeers, PeerId};
use parity_scale_codec::Decode;

/// Longest gap between two completed sessions that still counts as observed.
/// A longer gap means we were down or stalled ourselves, and our peers'
/// participation after it says nothing about the gap.
const MAX_OBSERVED_GAP_SECS: f64 = 600.0;

/// Moving averages of each peer's participation, one per window.
#[derive(Debug, Clone, Default, PartialEq, Encodable, Decodable)]
pub struct PeerAvailabilityState {
    updated_at_secs: u64,
    /// End of the last session in which each peer took part
    last_seen_secs: BTreeMap<PeerId, u64>,
    /// Per window: moving average of 1 over the time we observed
    coverage: Vec<Average>,
    /// Per window: moving average of each peer's participation
    participation: Vec<BTreeMap<PeerId, Average>>,
}

/// An `f64` stored by its bits, so the averages survive restarts exactly.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct Average(f64);

impl Encodable for Average {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        self.0.to_bits().consensus_encode(writer)
    }
}

impl Decodable for Average {
    fn consensus_decode_partial<R: Read>(
        reader: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(Self(f64::from_bits(u64::consensus_decode_partial(
            reader, modules,
        )?)))
    }
}

/// Returns each peer's participation in a session in `0.0..=1.0`: the share of
/// the session's rounds for which we hold a unit it created.
///
/// `units` are the encoded units of the AlephBFT backup. Each starts with the
/// unit's coordinates, its round and creator.
pub fn session_participation<'a>(
    units: impl IntoIterator<Item = &'a [u8]>,
    num_peers: NumPeers,
    rounds_per_session: u16,
) -> BTreeMap<PeerId, f64> {
    let mut counts: BTreeMap<PeerId, u32> = num_peers.peer_ids().map(|peer| (peer, 0)).collect();

    for mut unit in units {
        let Ok((round, creator)) = <(u16, aleph_bft::NodeIndex)>::decode(&mut unit) else {
            continue;
        };

        if round < rounds_per_session
            && let Some(count) =
                super::aleph_bft::to_peer_id(creator).and_then(|peer| counts.get_mut(&peer))
        {
            *count += 1;
        }
    }

    counts
        .into_iter()
        .map(|(peer, count)| {
            (
                peer,
                (f64::from(count) / f64::from(rounds_per_session)).min(1.0),
            )
        })
        .collect()
}

impl PeerAvailabilityState {
    /// Adds the participation of one completed session.
    pub fn update(&mut self, now_secs: u64, participation: &BTreeMap<PeerId, f64>) {
        for (peer, value) in participation {
            if 0.0 < *value {
                self.last_seen_secs.insert(*peer, now_secs);
            }
        }

        // The first session only starts the clock, since we do not know how
        // long it took
        if self.updated_at_secs == 0 {
            self.updated_at_secs = now_secs;
            return;
        }

        let elapsed = now_secs.saturating_sub(self.updated_at_secs) as f64;
        let observed = elapsed.min(MAX_OBSERVED_GAP_SECS);

        let windows = PEER_AVAILABILITY_WINDOWS_SECS.len();
        self.coverage.resize(windows, Average::default());
        self.participation.resize(windows, BTreeMap::new());

        for (window, window_secs) in PEER_AVAILABILITY_WINDOWS_SECS.iter().enumerate() {
            // Everything decays over the real elapsed time, but only the
            // observed part of it adds new weight
            let decay = (-elapsed / *window_secs as f64).exp();
            let gain = 1.0 - (-observed / *window_secs as f64).exp();

            self.coverage[window].0 = self.coverage[window].0 * decay + gain;

            for average in self.participation[window].values_mut() {
                average.0 *= decay;
            }

            for (peer, value) in participation {
                self.participation[window].entry(*peer).or_default().0 += gain * value;
            }
        }

        self.updated_at_secs = now_secs;
    }

    /// Returns the averages as seen at `now_secs`.
    pub fn report(&self, now_secs: u64) -> PeerAvailability {
        let elapsed = now_secs.saturating_sub(self.updated_at_secs) as f64;

        PeerAvailability {
            last_seen_secs: self.last_seen_secs.clone(),
            windows: PEER_AVAILABILITY_WINDOWS_SECS
                .iter()
                .zip(&self.coverage)
                .zip(&self.participation)
                .map(
                    |((window_secs, coverage), participation)| WindowAvailability {
                        window_secs: *window_secs,
                        // Time since the last session is unobserved, so coverage
                        // decays over it while the ratio below does not change
                        coverage_bps: to_bps(coverage.0 * (-elapsed / *window_secs as f64).exp()),
                        peers: participation
                            .iter()
                            .map(|(peer, average)| (*peer, to_bps(average.0 / coverage.0)))
                            .collect(),
                    },
                )
                .collect(),
        }
    }
}

fn to_bps(value: f64) -> u16 {
    (value * 10_000.0).round().clamp(0.0, 10_000.0) as u16
}

#[cfg(test)]
mod tests {
    use parity_scale_codec::Encode;

    use super::*;

    const SESSION_SECS: u64 = 180;
    const DAY: u64 = 86_400;

    fn unit(round: u16, creator: usize) -> Vec<u8> {
        // Coordinates, then bytes standing in for the rest of the unit
        let mut unit = (round, aleph_bft::NodeIndex(creator)).encode();
        unit.extend([0xab; 40]);
        unit
    }

    #[test]
    fn participation_counts_units_per_creator_within_the_session_rounds() {
        let units: Vec<Vec<u8>> = (0..10)
            .flat_map(|round| [unit(round, 0), unit(round, 2)])
            .chain((0..5).map(|round| unit(round, 1)))
            // Rounds past the session limit and unknown creators do not count
            .chain([unit(10, 1), unit(11, 1), unit(3, 7)])
            .collect();

        let participation =
            session_participation(units.iter().map(Vec::as_slice), NumPeers::from(4), 10);

        assert_eq!(
            participation,
            BTreeMap::from([
                (PeerId::from(0), 1.0),
                (PeerId::from(1), 0.5),
                (PeerId::from(2), 1.0),
                (PeerId::from(3), 0.0),
            ])
        );
    }

    fn run(state: &mut PeerAvailabilityState, from: u64, to: u64, peer_1_up: bool) {
        for now in (from..to).step_by(SESSION_SECS as usize) {
            let participation = BTreeMap::from([
                (PeerId::from(0), 1.0),
                (PeerId::from(1), if peer_1_up { 1.0 } else { 0.0 }),
            ]);
            state.update(now, &participation);
        }
    }

    #[test]
    fn week_window_forgets_faster_than_month_window() {
        let mut state = PeerAvailabilityState::default();
        // Peer 1 is up for 20 days, then down for the last day
        run(&mut state, 1, 20 * DAY, true);
        run(&mut state, 20 * DAY, 21 * DAY, false);

        let report = state.report(21 * DAY);
        let peer_1 = |window: usize| report.windows[window].peers[&PeerId::from(1)];

        // Week window: the last day weighs 1 - e^(-1/7) = 13%, against 20
        // days covering 1 - e^(-20/7) = 94%, so ~86% up
        assert!((8_550..=8_650).contains(&peer_1(0)), "{}", peer_1(0));
        // Month window covers 1 - e^(-21/30) = 0.503, of which the up days
        // weigh e^(-1/30) - e^(-21/30) = 0.471, so ~93.5% up
        assert!((9_300..=9_400).contains(&peer_1(1)), "{}", peer_1(1));
        assert_eq!(report.windows[0].peers[&PeerId::from(0)], 10_000);

        // Peer 1 was last seen in the last session of day 20
        let last_up = (1..20 * DAY).step_by(SESSION_SECS as usize).last().unwrap();
        assert_eq!(report.last_seen_secs[&PeerId::from(1)], last_up);
    }

    #[test]
    fn our_own_downtime_does_not_count_against_peers() {
        let mut state = PeerAvailabilityState::default();
        run(&mut state, 1, 2 * DAY, true);
        // We are down for two days. The first session after that misses
        // peer 1, which must count for at most one capped gap, not two days.
        run(&mut state, 4 * DAY, 4 * DAY + 1, false);
        run(&mut state, 4 * DAY + SESSION_SECS, 4 * DAY + 3_600, true);

        let report = state.report(4 * DAY + 3_600);

        // Counting the whole gap as down would give ~43% instead
        let peer_1 = report.windows[0].peers[&PeerId::from(1)];
        assert!((9_900..=9_970).contains(&peer_1), "{peer_1}");
        // We observed 2 days and an hour, decayed: ~19% of the week window
        let coverage = report.windows[0].coverage_bps;
        assert!((1_850..=2_000).contains(&coverage), "{coverage}");
    }

    #[test]
    fn coverage_decays_while_no_session_completes() {
        let mut state = PeerAvailabilityState::default();
        run(&mut state, 1, 10 * DAY, true);

        // 10 days cover 1 - e^(-10/7) = 76% of the week window
        let running = state.report(10 * DAY).windows[0].coverage_bps;
        assert!((7_550..=7_650).contains(&running), "{running}");
        // A day later without sessions it decays by e^(-1/7) to 66%
        let stalled = state.report(11 * DAY).windows[0].coverage_bps;
        assert!((6_550..=6_650).contains(&stalled), "{stalled}");
    }

    #[test]
    fn state_roundtrips_through_the_database_encoding() {
        let mut state = PeerAvailabilityState::default();
        run(&mut state, 1, DAY, true);

        let decoded = PeerAvailabilityState::consensus_decode_whole(
            &state.consensus_encode_to_vec(),
            &ModuleDecoderRegistry::default(),
        )
        .unwrap();

        assert_eq!(decoded, state);
    }
}
