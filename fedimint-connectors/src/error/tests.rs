use std::time::Duration;

use super::ServerError;
use crate::iroh::RequestTimedOut;

/// The kinds name the path that failed from typed sources, and from the
/// stable endpoint's own missing-address error, without passing any
/// error text on.
#[test]
fn failures_are_classified_by_their_typed_source() {
    let timed_out = ServerError::Transport(
        RequestTimedOut {
            method: "await_signed_session_outcome".to_owned(),
            timeout: Duration::from_secs(3600),
        }
        .into(),
    );
    assert_eq!(timed_out.failure_kind(), "request_timeout");
    assert_eq!(
        ServerError::Transport(anyhow::anyhow!("stream reset").into()).failure_kind(),
        "transport"
    );
    let handshake = ServerError::Connection(
        anyhow::Error::new(iroh::endpoint::ConnectionError::TimedOut)
            .context("failed connecting to remote endpoint")
            .into(),
    );
    assert_eq!(handshake.failure_kind(), "connect_timeout");
    let no_address = ServerError::Connection(
        anyhow::anyhow!("No addressing information for NodeId(abc), unable to connect").into(),
    );
    assert_eq!(no_address.failure_kind(), "no_address");
    assert_eq!(
        ServerError::Connection(anyhow::anyhow!("refused").into()).failure_kind(),
        "connect_failed"
    );
    assert_eq!(
        ServerError::InvalidResponse("bad".to_owned()).failure_kind(),
        "invalid_response"
    );
    assert_eq!(
        ServerError::ServerError("no".to_owned()).failure_kind(),
        "rejected"
    );
}
