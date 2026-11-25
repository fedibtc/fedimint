use std::time::Duration;

use tokio::sync::watch;

use super::{ScheduledShutdown, SessionTimedOut, ShutdownRequest, active_timeout, due_shutdown};

#[test]
fn shutdown_takes_effect_at_the_first_boundary_at_or_after_its_session() {
    let at = |session| {
        Some(ScheduledShutdown {
            session,
            request: ShutdownRequest::AtSession,
        })
    };
    assert_eq!(due_shutdown(None, 0), None);
    assert_eq!(due_shutdown(at(5), 4), None);
    assert_eq!(due_shutdown(at(5), 5), Some(ShutdownRequest::AtSession));
    // Scheduled while session 5 was completing: the next boundary.
    assert_eq!(due_shutdown(at(5), 6), Some(ShutdownRequest::AtSession));
}

/// fedimintd names the exit reason by downcasting the error the
/// consensus loop returns, which callers may have wrapped in context.
#[test]
fn a_session_timeout_is_recognized_through_added_context() {
    let error: anyhow::Error = SessionTimedOut { session_index: 7 }.into();
    let wrapped = error.context("running consensus").context("server main");
    assert_eq!(
        wrapped.downcast_ref::<SessionTimedOut>(),
        Some(&SessionTimedOut { session_index: 7 })
    );
    assert!(
        anyhow::anyhow!("other failure")
            .downcast_ref::<SessionTimedOut>()
            .is_none()
    );
}

#[tokio::test(start_paused = true)]
async fn active_timeout_pauses_while_parked_and_fires_after_active_budget() {
    let (parked_tx, parked_rx) = watch::channel(false);
    let mut timeout = Box::pin(active_timeout(Duration::from_secs(60), parked_rx));

    // 20s active -> 40s remaining.
    assert!(
        tokio::time::timeout(Duration::from_secs(20), &mut timeout)
            .await
            .is_err()
    );

    // Park for 4 hours -> watchdog must NOT fire while parked.
    parked_tx.send_replace(true);
    assert!(
        tokio::time::timeout(Duration::from_secs(4 * 3600), &mut timeout)
            .await
            .is_err()
    );

    // Unpark: 39s active -> still 1s remaining.
    parked_tx.send_replace(false);
    assert!(
        tokio::time::timeout(Duration::from_secs(39), &mut timeout)
            .await
            .is_err()
    );

    // Next 2s active exhausts the 60s active budget and trips the watchdog.
    assert!(
        tokio::time::timeout(Duration::from_secs(2), &mut timeout)
            .await
            .is_ok()
    );
}
