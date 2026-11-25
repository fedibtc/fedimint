use super::{ScheduledShutdown, SessionTimedOut, ShutdownRequest, due_shutdown};

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
