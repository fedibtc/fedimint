//! This guardian's view of its peers' availability.
//!
//! A peer counts as available in a 10-second slot if it sent us any AlephBFT
//! message in it. Every running peer sends consensus traffic all the time,
//! including a slow one that lags behind and still runs an older session,
//! while an offline or frozen peer, or one whose consensus is stuck, sends
//! nothing. A slot in which we heard from fewer than `threshold - 1` peers
//! means we were down or cut off ourselves, so it does not count.
//!
//! [`PeerActivity`] counts slots in memory; each completed session folds them
//! into exponential moving averages with the time constants in
//! [`PEER_AVAILABILITY_WINDOWS_SECS`], persisted as [`PeerAvailabilityState`].

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Error, Read, Write};

use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::peer_availability::{
    PEER_AVAILABILITY_WINDOWS_SECS, PeerAvailability, WindowAvailability,
};
use fedimint_core::{NumPeers, PeerId};

const SLOT_SECS: u64 = 10;

/// Slots of consensus traffic per peer since the last [`PeerActivity::take`].
#[derive(Debug)]
pub struct PeerActivity {
    identity: PeerId,
    num_peers: NumPeers,
    slot: u64,
    heard_in_slot: BTreeSet<PeerId>,
    observed_slots: u32,
    active_slots: BTreeMap<PeerId, u32>,
    last_heard_secs: BTreeMap<PeerId, u64>,
}

/// What [`PeerActivity`] observed since it was last taken.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ObservedActivity {
    pub observed_secs: u64,
    /// Each peer's share of the observed slots in `0.0..=1.0`
    pub availability: BTreeMap<PeerId, f64>,
    pub last_heard_secs: BTreeMap<PeerId, u64>,
}

impl PeerActivity {
    pub fn new(identity: PeerId, num_peers: NumPeers) -> Self {
        Self {
            identity,
            num_peers,
            slot: 0,
            heard_in_slot: BTreeSet::new(),
            observed_slots: 0,
            active_slots: BTreeMap::new(),
            last_heard_secs: BTreeMap::new(),
        }
    }

    /// Records a consensus message from `peer`.
    pub fn heard(&mut self, peer: PeerId, now_secs: u64) {
        self.advance(now_secs);
        self.heard_in_slot.insert(peer);
        self.last_heard_secs.insert(peer, now_secs);
    }

    /// Returns the activity of the slots closed since the last call.
    pub fn take(&mut self, now_secs: u64) -> ObservedActivity {
        self.advance(now_secs);

        let observed_slots = std::mem::take(&mut self.observed_slots);
        let mut active_slots = std::mem::take(&mut self.active_slots);

        // We were up in every slot we observed
        active_slots.insert(self.identity, observed_slots);
        if 0 < observed_slots {
            self.last_heard_secs.insert(self.identity, now_secs);
        }

        ObservedActivity {
            observed_secs: u64::from(observed_slots) * SLOT_SECS,
            availability: self
                .num_peers
                .peer_ids()
                .filter(|_| 0 < observed_slots)
                .map(|peer| {
                    let active = active_slots.get(&peer).copied().unwrap_or(0);
                    (peer, f64::from(active) / f64::from(observed_slots))
                })
                .collect(),
            last_heard_secs: self.last_heard_secs.clone(),
        }
    }

    /// Closes the current slot once `now_secs` is past it. Slots in which
    /// nothing at all arrived are not observed.
    fn advance(&mut self, now_secs: u64) {
        let slot = now_secs / SLOT_SECS;
        if slot == self.slot {
            return;
        }

        // We never hear from ourselves
        if self.num_peers.threshold() - 1 <= self.heard_in_slot.len() {
            self.observed_slots += 1;
            for peer in &self.heard_in_slot {
                *self.active_slots.entry(*peer).or_default() += 1;
            }
        }

        self.heard_in_slot.clear();
        self.slot = slot;
    }
}

/// Moving averages of each peer's availability, one per window.
#[derive(Debug, Clone, Default, PartialEq, Encodable, Decodable)]
pub struct PeerAvailabilityState {
    updated_at_secs: u64,
    /// Last time each peer sent us a consensus message
    last_seen_secs: BTreeMap<PeerId, u64>,
    /// Per window: moving average of 1 over the time we observed
    coverage: Vec<Average>,
    /// Per window: moving average of each peer's availability
    availability: Vec<BTreeMap<PeerId, Average>>,
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

impl PeerAvailabilityState {
    /// Folds in the activity observed since the last update.
    pub fn update(&mut self, now_secs: u64, activity: &ObservedActivity) {
        for (peer, heard) in &activity.last_heard_secs {
            let last_seen = self.last_seen_secs.entry(*peer).or_default();
            *last_seen = (*last_seen).max(*heard);
        }

        // Everything decays over the real elapsed time, but only the observed
        // part of it adds new weight
        let elapsed = now_secs.saturating_sub(self.updated_at_secs) as f64;
        let observed = activity.observed_secs as f64;

        let windows = PEER_AVAILABILITY_WINDOWS_SECS.len();
        self.coverage.resize(windows, Average::default());
        self.availability.resize(windows, BTreeMap::new());

        for (window, window_secs) in PEER_AVAILABILITY_WINDOWS_SECS.iter().enumerate() {
            let decay = (-elapsed.max(observed) / *window_secs as f64).exp();
            let gain = 1.0 - (-observed / *window_secs as f64).exp();

            self.coverage[window].0 = self.coverage[window].0 * decay + gain;

            for average in self.availability[window].values_mut() {
                average.0 *= decay;
            }

            for (peer, value) in &activity.availability {
                self.availability[window].entry(*peer).or_default().0 += gain * value;
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
                .zip(&self.availability)
                .map(
                    |((window_secs, coverage), availability)| WindowAvailability {
                        window_secs: *window_secs,
                        // Time since the last update is unobserved, so coverage
                        // decays over it while the ratio below does not change
                        coverage_bps: to_bps(coverage.0 * (-elapsed / *window_secs as f64).exp()),
                        peers: availability
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
    use super::*;

    const DAY: u64 = 86_400;

    fn peer(id: u16) -> PeerId {
        PeerId::from(id)
    }

    #[test]
    fn counts_slots_per_peer_and_skips_slots_where_we_were_cut_off() {
        // We are peer 0 of 4: a slot needs messages from 2 other peers
        let mut activity = PeerActivity::new(peer(0), NumPeers::from(4));

        for slot in 0..10 {
            let now = 1_000 + slot * SLOT_SECS;
            activity.heard(peer(1), now);
            // Peer 2 only in the first half
            if slot < 5 {
                activity.heard(peer(2), now + 1);
            }
            activity.heard(peer(3), now + 9);
        }
        // 3 slots in which only peer 1 reached us: we were cut off
        for slot in 10..13 {
            activity.heard(peer(1), 1_000 + slot * SLOT_SECS);
        }

        let observed = activity.take(1_000 + 13 * SLOT_SECS);

        assert_eq!(observed.observed_secs, 10 * SLOT_SECS);
        assert_eq!(
            observed.availability,
            BTreeMap::from([
                (peer(0), 1.0),
                (peer(1), 1.0),
                (peer(2), 0.5),
                (peer(3), 1.0)
            ])
        );
        assert_eq!(observed.last_heard_secs[&peer(1)], 1_000 + 12 * SLOT_SECS);
        assert_eq!(
            observed.last_heard_secs[&peer(2)],
            1_000 + 4 * SLOT_SECS + 1
        );

        // Taking again starts from zero
        assert_eq!(activity.take(1_000 + 14 * SLOT_SECS).observed_secs, 0);
    }

    /// Updates `state` every 3 minutes from `from` to `to` with all observed
    /// time and peer 1 up or down.
    fn run(state: &mut PeerAvailabilityState, from: u64, to: u64, peer_1_up: bool) {
        for now in (from..to).step_by(180) {
            let activity = ObservedActivity {
                observed_secs: 180,
                availability: BTreeMap::from([
                    (peer(0), 1.0),
                    (peer(1), if peer_1_up { 1.0 } else { 0.0 }),
                ]),
                last_heard_secs: if peer_1_up {
                    BTreeMap::from([(peer(1), now)])
                } else {
                    BTreeMap::new()
                },
            };
            state.update(now, &activity);
        }
    }

    #[test]
    fn week_window_forgets_faster_than_month_window() {
        let mut state = PeerAvailabilityState::default();
        // Peer 1 is up for 20 days, then down for the last day
        run(&mut state, 180, 20 * DAY, true);
        run(&mut state, 20 * DAY, 21 * DAY, false);

        let report = state.report(21 * DAY);
        let peer_1 = |window: usize| report.windows[window].peers[&peer(1)];

        // Week window: the last day weighs 1 - e^(-1/7) = 13%, against 20
        // days covering 1 - e^(-20/7) = 94%, so ~86% up
        assert!((8_550..=8_650).contains(&peer_1(0)), "{}", peer_1(0));
        // Month window covers 1 - e^(-21/30) = 0.503, of which the up days
        // weigh e^(-1/30) - e^(-21/30) = 0.471, so ~93.5% up
        assert!((9_300..=9_400).contains(&peer_1(1)), "{}", peer_1(1));
        assert_eq!(report.windows[0].peers[&peer(0)], 10_000);

        // Peer 1 was last seen in the last update of day 20
        let last_up = (180..20 * DAY).step_by(180).last().unwrap();
        assert_eq!(report.last_seen_secs[&peer(1)], last_up);
    }

    #[test]
    fn unobserved_time_does_not_count_against_peers() {
        let mut state = PeerAvailabilityState::default();
        run(&mut state, 180, 2 * DAY, true);
        // We are down for two days: the next update has two days elapsed but
        // only 3 minutes observed, in which peer 1 is down
        run(&mut state, 4 * DAY, 4 * DAY + 1, false);
        run(&mut state, 4 * DAY + 180, 4 * DAY + 3_600, true);

        let report = state.report(4 * DAY + 3_600);

        // Only 3 minutes of the gap count as down: ~99.8%. Counting the
        // whole gap as down would give ~44% instead
        let peer_1 = report.windows[0].peers[&peer(1)];
        assert!((9_950..=9_995).contains(&peer_1), "{peer_1}");
        // We observed 2 days and an hour, decayed: ~19% of the week window
        let coverage = report.windows[0].coverage_bps;
        assert!((1_850..=2_000).contains(&coverage), "{coverage}");
    }

    #[test]
    fn coverage_decays_while_nothing_is_observed() {
        let mut state = PeerAvailabilityState::default();
        run(&mut state, 180, 10 * DAY, true);

        // 10 days cover 1 - e^(-10/7) = 76% of the week window
        let running = state.report(10 * DAY).windows[0].coverage_bps;
        assert!((7_550..=7_650).contains(&running), "{running}");
        // A day later without updates it decays by e^(-1/7) to 66%
        let stalled = state.report(11 * DAY).windows[0].coverage_bps;
        assert!((6_550..=6_650).contains(&stalled), "{stalled}");
    }

    #[test]
    fn state_roundtrips_through_the_database_encoding() {
        let mut state = PeerAvailabilityState::default();
        run(&mut state, 180, DAY, true);

        let decoded = PeerAvailabilityState::consensus_decode_whole(
            &state.consensus_encode_to_vec(),
            &ModuleDecoderRegistry::default(),
        )
        .unwrap();

        assert_eq!(decoded, state);
    }
}
