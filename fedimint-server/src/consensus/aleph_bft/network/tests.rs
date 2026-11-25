use fedimint_core::config::P2PMessage;

use super::{DRAIN_SESSION_VARIANT, drain_session, drain_session_message};

/// P2P connections send bincode, which a peer of any release decodes into
/// the same `P2PMessage`, with the drain request as `Default`.
#[test]
fn a_drain_request_survives_the_wire_and_names_its_session() {
    let bytes = bincode::serialize(&drain_session_message(9)).expect("encodes");
    let received: P2PMessage = bincode::deserialize(&bytes).expect("decodes");
    let P2PMessage::Default { variant, bytes } = received else {
        panic!("expected the default variant, got {received:?}");
    };
    assert_eq!(variant, DRAIN_SESSION_VARIANT);
    assert_eq!(drain_session(&bytes), Some(9));
    assert_eq!(drain_session(&[1, 2]), None);
}
