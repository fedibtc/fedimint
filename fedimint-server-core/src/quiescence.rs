//! Process-wide switch for Aleph quiescence.
//!
//! Upstream fedimint/fedimint#9043 stops a guardian from creating AlephBFT
//! units while it has nothing to order, and stops modules from re-proposing
//! votes that their peers already recorded. This fork instead slows a guardian
//! without work down to one unit per idle round delay, and ships both behind
//! one switch. The process driving `fedimintd` sets it at runtime through the
//! driven control channel's features (`fedimint_server::config::driven`); a
//! standalone `fedimintd` sets it once at start from
//! `FM_ALEPH_IDLE_ROUND_DELAY_MS`. The switch is the idle round delay, so
//! quiescence cannot be on without one. It is not persisted: without the
//! environment variable it starts off on every process start, so a restarted
//! guardian behaves exactly like one without the change until it is enabled
//! again.
//!
//! One `fedimintd` process runs one guardian, so the switch is a process
//! global: module consensus proposals have no other path to it. In-process
//! test federations share it.

use std::sync::LazyLock;
use std::time::Duration;

use tokio::sync::watch;

static SWITCH: LazyLock<watch::Sender<Option<Duration>>> = LazyLock::new(|| watch::channel(None).0);

/// Whether this guardian slows down while it has no work and modules propose
/// only votes their peers accept.
pub fn is_enabled() -> bool {
    SWITCH.borrow().is_some()
}

/// Turn quiescence on with the delay between our units while we have no
/// work, or off; returns the previous setting.
pub fn set_idle_round_delay(idle_round_delay: Option<Duration>) -> Option<Duration> {
    SWITCH.send_replace(idle_round_delay)
}

/// Observe changes, so a waiting data provider follows a new delay at once.
pub fn subscribe() -> watch::Receiver<Option<Duration>> {
    SWITCH.subscribe()
}
