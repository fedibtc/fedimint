//! Fedi kill switch for the walletv2 block count vote delay of 0.13.
//!
//! Upstream 0.13 votes the walletv2 block count one block further behind the
//! bitcoin backend than 0.12 did (fedimint/fedimint#9308). With the switch on,
//! this guardian votes as 0.12 does, the finality delay behind its backend. A
//! vote only changes what this guardian proposes: every guardian processes
//! votes the same way, so guardians with the switch on and off agree on the
//! consensus block count.
//!
//! The process driving `fedimintd` sets it through
//! `fedimint_server::config::driven::Features`. It is off, the 0.13
//! behaviour, unless set.

use std::sync::atomic::{AtomicBool, Ordering};

static LEGACY: AtomicBool = AtomicBool::new(false);

/// Whether this guardian votes the block count the finality delay behind its
/// backend, as 0.12 does.
pub fn is_legacy() -> bool {
    LEGACY.load(Ordering::Relaxed)
}

/// Switch to 0.12's vote delay or back; returns the previous setting.
pub fn set_legacy(legacy: bool) -> bool {
    LEGACY.swap(legacy, Ordering::Relaxed)
}
