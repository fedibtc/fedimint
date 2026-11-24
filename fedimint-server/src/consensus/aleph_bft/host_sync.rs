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
//! - Every guardian ends its round wait on the nearest wall-clock multiple of
//!   the round delay, so the host's guardians create their units, and need
//!   their syncs, at about the same time.
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

use fedimint_core::envs::FM_BACKUP_SYNC_COORDINATOR_ENV;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tracing::debug;

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

/// Shortens or extends `delay` so that it ends on the wall-clock multiple of
/// `period` nearest to `now + delay`. Rounds keep their average length, and
/// every guardian on the host ends its wait at the same instant.
pub fn align_to_wall_clock(delay: Duration, period: Duration) -> Duration {
    let period = period.as_nanos();
    if delay.is_zero() || period == 0 {
        return delay;
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_nanos();
    let target = now + delay.as_nanos();
    let boundary = (target + period / 2) / period * period;

    Duration::from_nanos(
        boundary
            .saturating_sub(now)
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
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::align_to_wall_clock;

    #[test]
    fn aligned_delay_ends_near_a_period_boundary() {
        let period = Duration::from_millis(50);
        for delay_ms in [1, 24, 26, 50, 75, 130] {
            let delay = Duration::from_millis(delay_ms);
            let start = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            let aligned = align_to_wall_clock(delay, period);
            let end = (start + aligned).as_nanos();
            let offset = end % period.as_nanos();
            let distance = offset.min(period.as_nanos() - offset);
            // `start` is read just before the function reads the clock.
            assert!(
                distance < 2_000_000,
                "{delay_ms} ms ends {distance} ns off a boundary"
            );
            let shift = aligned.as_nanos().abs_diff(delay.as_nanos());
            assert!(
                shift <= period.as_nanos() / 2 + 2_000_000,
                "{delay_ms} ms moved by {shift} ns"
            );
        }
    }

    #[test]
    fn zero_delay_stays_zero() {
        assert_eq!(
            align_to_wall_clock(Duration::ZERO, Duration::from_millis(50)),
            Duration::ZERO
        );
    }
}
