//! Process-wide switch for Aleph quiescence.
//!
//! Upstream fedimint/fedimint#9043 stops a guardian from creating AlephBFT
//! units while it has nothing to order, and stops modules from re-proposing
//! votes that their peers already recorded. This fork ships both behind one
//! switch that the process driving `fedimintd` flips at runtime through the
//! driven control channel's features (`fedimint_server::config::driven`). It
//! starts off on every process start and is not persisted, so a restarted
//! guardian behaves exactly like one without the change until it is enabled
//! again.
//!
//! One `fedimintd` process runs one guardian, so the switch is a process
//! global: module consensus proposals have no other path to it. In-process
//! test federations share it.

use std::sync::LazyLock;
use std::time::Duration;

use tokio::sync::watch;

static SWITCH: LazyLock<watch::Sender<bool>> = LazyLock::new(|| watch::channel(false).0);
static PARK_DURATION: LazyLock<watch::Sender<Option<Duration>>> =
    LazyLock::new(|| watch::channel(None).0);

/// Whether this guardian creates units only when it has work and modules
/// propose only votes their peers accept.
pub fn is_enabled() -> bool {
    *SWITCH.borrow()
}

/// Turn quiescence on or off; returns the previous setting.
pub fn set_enabled(enabled: bool) -> bool {
    SWITCH.send_replace(enabled)
}

/// Observe changes, so a parked data provider resumes when it is turned off.
pub fn subscribe() -> watch::Receiver<bool> {
    SWITCH.subscribe()
}

/// Optional override for how long a quiescent session may park before draining
/// its remaining rounds. `None` falls back to `session_timeout / 2`.
pub fn park_duration() -> Option<Duration> {
    *PARK_DURATION.borrow()
}

/// Set or clear the quiescent park duration override; returns the previous
/// setting.
pub fn set_park_duration(duration: Option<Duration>) -> Option<Duration> {
    PARK_DURATION.send_replace(duration)
}

/// Observe park-duration changes so a parked data provider wakes promptly if
/// the configured park window is shortened.
pub fn subscribe_park_duration() -> watch::Receiver<Option<Duration>> {
    PARK_DURATION.subscribe()
}
