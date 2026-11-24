//! Process-wide switch for Aleph quiescence.
//!
//! Upstream fedimint/fedimint#9043 stops a guardian from creating AlephBFT
//! units while it has nothing to order, and stops modules from re-proposing
//! votes that their peers already recorded. This fork ships both behind one
//! switch that the operator flips at runtime through the
//! `set_aleph_quiescence` admin endpoint. It starts off on every process
//! start and is not persisted, so a restarted guardian behaves exactly like
//! one without the change until it is enabled again.
//!
//! One `fedimintd` process runs one guardian, so the switch is a process
//! global: module consensus proposals have no other path to it. In-process
//! test federations share it.

use std::sync::LazyLock;

use tokio::sync::watch;

static SWITCH: LazyLock<watch::Sender<bool>> = LazyLock::new(|| watch::channel(false).0);

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
