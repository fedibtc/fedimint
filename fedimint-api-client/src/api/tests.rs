use std::collections::BTreeMap;
use std::str::FromStr as _;

use fedimint_core::config::FederationId;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::util::SafeUrl;
use fedimint_core::{NumPeersExt as _, PeerId};

#[test]
fn converts_invite_code() {
    let connect = InviteCode::new(
        "ws://test1".parse().unwrap(),
        PeerId::from(1),
        FederationId::dummy(),
        Some("api_secret".into()),
    );

    let bech32 = connect.to_string();
    let connect_parsed = InviteCode::from_str(&bech32).expect("parses");
    assert_eq!(connect, connect_parsed);

    let json = serde_json::to_string(&connect).unwrap();
    let connect_as_string: String = serde_json::from_str(&json).unwrap();
    assert_eq!(connect_as_string, bech32);
    let connect_parsed_json: InviteCode = serde_json::from_str(&json).unwrap();
    assert_eq!(connect_parsed_json, connect_parsed);
}

#[test]
fn creates_essential_guardians_invite_code() {
    let mut peer_to_url_map = BTreeMap::new();
    peer_to_url_map.insert(PeerId::from(0), "ws://test1".parse().expect("URL fail"));
    peer_to_url_map.insert(PeerId::from(1), "ws://test2".parse().expect("URL fail"));
    peer_to_url_map.insert(PeerId::from(2), "ws://test3".parse().expect("URL fail"));
    peer_to_url_map.insert(PeerId::from(3), "ws://test4".parse().expect("URL fail"));
    let max_size = peer_to_url_map.to_num_peers().max_evil() + 1;

    let code =
        InviteCode::new_with_essential_num_guardians(&peer_to_url_map, FederationId::dummy());

    assert_eq!(FederationId::dummy(), code.federation_id());

    let expected_map: BTreeMap<PeerId, SafeUrl> =
        peer_to_url_map.into_iter().take(max_size).collect();
    assert_eq!(expected_map, code.peers());
}

#[tokio::test]
async fn api_views_share_pools_without_sharing_peer_maps_or_authentication() {
    use std::sync::Arc;

    use fedimint_connectors::ConnectorRegistry;

    use super::{FederationApi, IRawFederationApi as _};

    let connectors = ConnectorRegistry::build_from_server_defaults()
        .bind()
        .await
        .unwrap();
    let url: SafeUrl = "ws://guardian.example/".parse().unwrap();
    let first = FederationApi::new(
        connectors.clone(),
        [(PeerId::from(0), url.clone())].into(),
        None,
        None,
    );
    let second = FederationApi::new(
        connectors.clone(),
        [(PeerId::from(7), url.clone())].into(),
        None,
        None,
    );
    assert!(Arc::ptr_eq(&first.connection_pool, &second.connection_pool));
    assert_ne!(first.all_peers(), second.all_peers());

    let mut pools = vec![first.connection_pool.clone()];
    for secret in ["", "secret-a", "secret-b"] {
        let api = FederationApi::new(
            connectors.clone(),
            [(PeerId::from(0), url.clone())].into(),
            None,
            Some(secret),
        );
        for pool in &pools {
            assert!(!Arc::ptr_eq(pool, &api.connection_pool));
        }
        pools.push(api.connection_pool);
    }

    let other_registry = ConnectorRegistry::build_from_server_defaults()
        .bind()
        .await
        .unwrap();
    let isolated = FederationApi::new(other_registry, [(PeerId::from(0), url)].into(), None, None);
    assert!(!Arc::ptr_eq(
        &first.connection_pool,
        &isolated.connection_pool
    ));
}
