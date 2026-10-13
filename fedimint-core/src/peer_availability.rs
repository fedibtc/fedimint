//! Guardians' views of each other's availability.
//!
//! The public
//! [`PEER_AVAILABILITY_ENDPOINT`](crate::endpoint_constants::PEER_AVAILABILITY_ENDPOINT)
//! serves them.
//! Each guardian reports, per window, how much of the window it observed
//! itself (`coverage_bps`) and the fraction of that time each peer took part
//! in consensus. A single report is one guardian's opinion; clients combine
//! the reports with [`merge_peer_availability`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{NumPeers, PeerId};

/// Time constants of the availability windows in seconds: one day, one week
/// and 30 days.
pub const PEER_AVAILABILITY_WINDOWS_SECS: [u64; 3] = [86_400, 604_800, 2_592_000];

/// One guardian's view of its peers' availability.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerAvailability {
    /// One entry per window in [`PEER_AVAILABILITY_WINDOWS_SECS`]
    pub windows: Vec<WindowAvailability>,
}

/// One guardian's view of its peers' availability over one window.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowAvailability {
    /// Time constant of the moving average
    pub window_secs: u64,
    /// Share of the window this guardian observed itself, in basis points
    pub coverage_bps: u16,
    /// Share of the observed time each peer took part in consensus, in basis
    /// points
    pub peers: BTreeMap<PeerId, u16>,
}

/// Combines the reports of several guardians into one availability per window
/// and peer.
///
/// A peer's own report about itself is ignored, as are reports that cover
/// less than half of the best-covered report of the window. Of the remaining
/// reports the [`NumPeers::one_honest`]-th highest value is used: at least one
/// honest guardian saw the peer at least that available, and
/// [`NumPeers::max_evil`] lying guardians cannot move the value outside the
/// honest reports. A peer with fewer usable reports is omitted.
pub fn merge_peer_availability(
    reports: &BTreeMap<PeerId, PeerAvailability>,
    num_peers: NumPeers,
) -> Vec<BTreeMap<PeerId, u16>> {
    (0..PEER_AVAILABILITY_WINDOWS_SECS.len())
        .map(|window| {
            let windows: Vec<(PeerId, &WindowAvailability)> = reports
                .iter()
                .filter_map(|(reporter, report)| Some((*reporter, report.windows.get(window)?)))
                .collect();

            let max_coverage = windows
                .iter()
                .map(|(_, window)| window.coverage_bps)
                .max()
                .unwrap_or(0);

            num_peers
                .peer_ids()
                .filter_map(|peer| {
                    let mut values: Vec<u16> = windows
                        .iter()
                        .filter(|(reporter, window)| {
                            *reporter != peer
                                && 0 < window.coverage_bps
                                && max_coverage <= 2 * window.coverage_bps
                        })
                        .filter_map(|(_, window)| window.peers.get(&peer).copied())
                        .collect();

                    values.sort_unstable_by(|a, b| b.cmp(a));

                    Some((peer, *values.get(num_peers.one_honest() - 1)?))
                })
                .collect()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(coverage_bps: u16, peers: &[(u16, u16)]) -> PeerAvailability {
        PeerAvailability {
            windows: PEER_AVAILABILITY_WINDOWS_SECS
                .iter()
                .map(|window_secs| WindowAvailability {
                    window_secs: *window_secs,
                    coverage_bps,
                    peers: peers
                        .iter()
                        .map(|(peer, bps)| (PeerId::from(*peer), *bps))
                        .collect(),
                })
                .collect(),
        }
    }

    #[test]
    fn evil_reporters_cannot_move_the_result_outside_honest_reports() {
        // 10 peers tolerate 3 evil ones. Peer 0 is down half the time. Honest
        // peers 1..=6 report 4900..=5400 about it, evil peers 7..=9 claim 10000.
        let num_peers = NumPeers::from(10);
        let mut reports: BTreeMap<PeerId, PeerAvailability> = (1..=6)
            .map(|reporter| {
                (
                    PeerId::from(reporter),
                    report(10_000, &[(0, 4_800 + 100 * reporter)]),
                )
            })
            .collect();
        for evil in 7..=9 {
            reports.insert(PeerId::from(evil), report(10_000, &[(0, 10_000)]));
        }

        // Sorted: 10000 x3, 5400, 5300, ... so the 4th highest is honest 5400
        assert_eq!(
            merge_peer_availability(&reports, num_peers)[0][&PeerId::from(0)],
            5_400
        );

        // Evil peers claiming 0 instead cannot push it below the honest range
        for evil in 7..=9 {
            reports.insert(PeerId::from(evil), report(10_000, &[(0, 0)]));
        }
        assert_eq!(
            merge_peer_availability(&reports, num_peers)[0][&PeerId::from(0)],
            5_100
        );
    }

    #[test]
    fn ignores_self_reports_and_poorly_covered_reports() {
        let num_peers = NumPeers::from(4);
        let reports = BTreeMap::from([
            // Peer 0 claims to be perfect, which must not count
            (PeerId::from(0), report(10_000, &[(0, 10_000), (3, 10_000)])),
            (PeerId::from(1), report(10_000, &[(0, 2_000), (3, 9_000)])),
            (PeerId::from(2), report(10_000, &[(0, 3_000), (3, 8_000)])),
            // Peer 3 observed less than half of what the others did
            (PeerId::from(3), report(4_999, &[(0, 9_999)])),
        ]);

        let merged = merge_peer_availability(&reports, num_peers);

        // max_evil() is 1, so the 2nd highest usable report: 2000 from peers 1 and 2
        assert_eq!(merged[0][&PeerId::from(0)], 2_000);
        assert_eq!(merged[0][&PeerId::from(3)], 9_000);
        // Nobody reports on peer 1
        assert!(!merged[0].contains_key(&PeerId::from(1)));
    }
}
