//! Lets the guardians on one host sync their AlephBFT backups together.
//!
//! The backup writer syncs once per round, and on a copy-on-write filesystem
//! such as btrfs every sync costs a fixed amount of metadata writes, whatever
//! it stores. Concurrent syncs share that cost: the filesystem commits them
//! together. A host running many guardians therefore wears its disk far less
//! when their syncs happen at the same moment.
//!
//! Two mechanisms line them up, both active only when the host sets
//! [`FM_BACKUP_SYNC_COORDINATOR_ENV`]:
//!
//! - Every guardian ends its round wait on the host's grid: wall-clock
//!   multiples of the round delay, shifted by the host's phase
//!   ([`FM_BACKUP_SYNC_PHASE_US_ENV`]). The host's guardians then create their
//!   units, and need their syncs, at about the same time. Each host picks its
//!   own phase so that the peers of one federation, which sit on different
//!   hosts, do not all create their units at the same instant: that lockstep
//!   delays ordering by several rounds.
//! - Before each backup commit the writer asks the host's coordinator over a
//!   unix socket and commits when the coordinator answers. The coordinator
//!   answers every waiting guardian at once, when all of them are ready or
//!   after a short window.
//!
//! The coordinator only delays a commit; the unit is still synced before it
//! is sent. A guardian whose coordinator is missing or slow commits after at
//! most [`GATE_TIMEOUT`].

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fedimint_core::envs::{FM_BACKUP_SYNC_COORDINATOR_ENV, FM_BACKUP_SYNC_PHASE_US_ENV};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tracing::{debug, warn};

use crate::LOG_CONSENSUS;

/// The longest a commit waits for the coordinator before going ahead alone.
const GATE_TIMEOUT: Duration = Duration::from_millis(25);

/// Sent by the writer when its commit is ready, and by the coordinator when
/// the writer may commit.
const READY: u8 = b'r';
const GO: u8 = b'g';

/// The coordinator's socket, if the host runs one.
pub fn coordinator_socket() -> Option<PathBuf> {
    std::env::var_os(FM_BACKUP_SYNC_COORDINATOR_ENV).map(PathBuf::from)
}

/// The host's phase on the round grid, if the host set one.
pub fn round_phase() -> Option<Duration> {
    let value = std::env::var(FM_BACKUP_SYNC_PHASE_US_ENV).ok()?;
    match value.parse() {
        Ok(micros) => Some(Duration::from_micros(micros)),
        Err(error) => {
            warn!(target: LOG_CONSENSUS, %error, "Invalid backup sync phase; rounds stay unaligned");
            None
        }
    }
}

/// Shortens or extends `delay` so that it ends on the point of the grid
/// `k * period + phase` nearest to `now + delay`, or the next point when that
/// one has passed. Rounds keep their average length, and every guardian with
/// the same phase ends its wait at the same instant.
pub fn align_to_wall_clock(delay: Duration, period: Duration, phase: Duration) -> Duration {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the unix epoch");
    align(now, delay, period, phase)
}

/// [`align_to_wall_clock`] at the wall-clock time `now`.
fn align(now: Duration, delay: Duration, period: Duration, phase: Duration) -> Duration {
    let period = period.as_nanos();
    if delay.is_zero() || period == 0 {
        return delay;
    }
    let phase = phase.as_nanos() % period;
    let now = now.as_nanos();

    // Shift by a whole period first so the subtraction cannot underflow.
    let target = now + delay.as_nanos() + period - phase;
    let mut point = (target + period / 2) / period * period - period + phase;
    // A delay much shorter than the period can round to a point already
    // passed; the round then waits for the next one.
    if point <= now {
        point += period;
    }

    Duration::from_nanos(
        (point - now)
            .try_into()
            .expect("an aligned round delay fits in u64 nanoseconds"),
    )
}

/// The writer's connection to the host's coordinator.
pub struct SyncGate {
    path: PathBuf,
    stream: Option<UnixStream>,
}

impl SyncGate {
    pub fn new(path: PathBuf) -> Self {
        Self { path, stream: None }
    }

    /// Returns when the coordinator lets this guardian commit, or after
    /// [`GATE_TIMEOUT`]. Never fails: any problem only costs the batching.
    pub async fn wait(&mut self) {
        let result = tokio::time::timeout(GATE_TIMEOUT, async {
            if self.stream.is_none() {
                self.stream = Some(UnixStream::connect(&self.path).await?);
            }
            let stream = self.stream.as_mut().expect("connected above");
            stream.write_all(&[READY]).await?;
            let mut answer = [0; 1];
            stream.read_exact(&mut answer).await?;
            if answer[0] != GO {
                return Err(std::io::Error::other("unexpected coordinator answer"));
            }
            Ok(())
        })
        .await;

        if !matches!(result, Ok(Ok(()))) {
            // A late answer must not release a later commit, so start over
            // with a new connection.
            self.stream = None;
            debug!(target: LOG_CONSENSUS, ?result, "Committing backup without the sync coordinator");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::align;

    const fn ms(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }

    #[test]
    fn delay_ends_on_the_nearest_point_of_the_hosts_grid() {
        let period = ms(50);
        // (now, delay, phase) -> expected delay. `now` is wall-clock time; the
        // grid is 50 ms multiples plus the phase.
        for (now, delay, phase, expected) in [
            // On a phase-0 grid: 1_000_010 + 50 rounds down to 1_000_050.
            (ms(1_000_010), ms(50), ms(0), ms(40)),
            // 1_000_030 + 50 = 1_000_080 rounds up to 1_000_100.
            (ms(1_000_030), ms(50), ms(0), ms(70)),
            // The same instants on a 13 ms phase: points at ...013, ...063, ...113.
            (ms(1_000_010), ms(50), ms(13), ms(53)),
            (ms(1_000_030), ms(50), ms(13), ms(33)),
            // A phase of a whole period or more wraps.
            (ms(1_000_030), ms(50), ms(63), ms(33)),
            // A longer delay keeps its length up to the grid.
            (ms(1_000_010), ms(130), ms(0), ms(140)),
            // 1_000_049 + 1 lands on the point 1_000_050 itself.
            (ms(1_000_049), ms(1), ms(0), ms(1)),
            // The nearest point to 1_000_001 + 1 is 1_000_000, already past:
            // wait for 1_000_050.
            (ms(1_000_001), ms(1), ms(0), ms(49)),
        ] {
            assert_eq!(
                align(now, delay, period, phase),
                expected,
                "now {now:?}, delay {delay:?}, phase {phase:?}"
            );
        }
    }

    #[test]
    fn zero_delay_stays_zero() {
        assert_eq!(
            align(ms(1_000_017), Duration::ZERO, ms(50), ms(7)),
            Duration::ZERO
        );
    }
}
