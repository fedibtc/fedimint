use std::collections::{BTreeMap, BTreeSet};

use fedimint_core::PeerId;
use fedimint_core::encoding::Encodable;
use fedimint_core::module::ApiAuth;
use fedimint_core::secp256k1::{PublicKey, Secp256k1, SecretKey};
use fedimint_core::setup_code::{PeerEndpoints, PeerSetupCode};

use super::{ConfigGenParams, ServerConfig, dkg_consensus_code_version};

fn config(version: &str) -> ServerConfig {
    let identity = PeerId::from(0);
    let broadcast_secret_key =
        SecretKey::from_slice(&[1; 32]).expect("fixed secret key should be valid");
    let broadcast_public_key = PublicKey::from_secret_key(&Secp256k1::new(), &broadcast_secret_key);
    let peers = BTreeMap::from([(
        identity,
        PeerSetupCode {
            name: "peer-0".to_owned(),
            endpoints: PeerEndpoints::Tcp {
                api_url: "ws://127.0.0.1:8173".parse().expect("valid API URL"),
                p2p_url: "fedimint://127.0.0.1:8174".parse().expect("valid P2P URL"),
                cert: Vec::new(),
            },
            federation_name: None,
            disable_base_fees: None,
            enabled_modules: None,
            federation_size: None,
        },
    )]);
    let params = ConfigGenParams {
        identity,
        tls_key: None,
        iroh_api_sk: None,
        iroh_p2p_sk: None,
        api_auth: ApiAuth::new("test-password".to_owned()),
        peers,
        meta: BTreeMap::new(),
        disable_base_fees: false,
        enabled_modules: BTreeSet::new(),
        network: bitcoin::Network::Regtest,
    };

    ServerConfig::from(
        params,
        identity,
        BTreeMap::from([(identity, broadcast_public_key)]),
        broadcast_secret_key,
        BTreeMap::new(),
        version.to_owned(),
    )
}

#[test]
fn server_config_allows_patch_and_prerelease_skew() {
    let first = config("0.11.0-rc.1+fedi");
    let second = config("0.11.7+fedi");

    assert_eq!(first.consensus.code_version, "0.11+fedi");
    assert_eq!(first.consensus.code_version, second.consensus.code_version);
    assert_eq!(
        first.consensus.consensus_hash_sha256(),
        second.consensus.consensus_hash_sha256()
    );
}

#[test]
fn server_config_rejects_major_minor_and_vendor_skew_via_checksum() {
    let fedi = config("0.11.0+fedi").consensus;

    for incompatible in [
        config("1.11.0+fedi").consensus,
        config("0.12.0+fedi").consensus,
        config("0.11.0+other").consensus,
        config("0.11.0").consensus,
    ] {
        assert_ne!(fedi.code_version, incompatible.code_version);
        assert_ne!(
            fedi.consensus_hash_sha256(),
            incompatible.consensus_hash_sha256()
        );
    }
}

#[test]
fn consensus_code_version_preserves_opaque_test_values() {
    assert_eq!(
        dkg_consensus_code_version("test-version-hash".to_owned()),
        "test-version-hash"
    );
}
