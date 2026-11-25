use std::collections::{BTreeMap, BTreeSet};

use fedimint_core::{PeerId, secp256k1};
use rand::rngs::OsRng;

use super::{ConfigGenParams, ServerConfig};

fn server_config_with_code_version(code_version: &str) -> ServerConfig {
    let (broadcast_secret_key, _) = secp256k1::generate_keypair(&mut OsRng);

    ServerConfig::from(
        ConfigGenParams {
            identity: PeerId::from(0),
            tls_key: None,
            iroh_api_sk: None,
            iroh_p2p_sk: None,
            peers: BTreeMap::new(),
            meta: BTreeMap::new(),
            disable_base_fees: false,
            enabled_modules: BTreeSet::new(),
            network: bitcoin::Network::Regtest,
        },
        PeerId::from(0),
        BTreeMap::new(),
        broadcast_secret_key,
        BTreeMap::new(),
        code_version.to_owned(),
    )
}

#[test]
fn server_config_uses_dkg_compatibility_identity_as_consensus_code_version() {
    let patch_3 = server_config_with_code_version("1.2.3-alpha+fedi");
    let patch_4 = server_config_with_code_version("1.2.4+fedi");
    let upstream = server_config_with_code_version("1.2.4");
    let other_vendor = server_config_with_code_version("1.2.4+acme");
    let next_minor = server_config_with_code_version("1.3.0");

    assert_eq!(patch_3.consensus.code_version, "1.2+fedi");
    assert_eq!(
        patch_3.consensus.code_version,
        patch_4.consensus.code_version
    );
    assert_ne!(
        patch_3.consensus.code_version,
        upstream.consensus.code_version
    );
    assert_ne!(
        patch_3.consensus.code_version,
        other_vendor.consensus.code_version
    );
    assert_ne!(
        patch_3.consensus.code_version,
        next_minor.consensus.code_version
    );
}

#[test]
fn server_config_accepts_opaque_test_code_versions() {
    let config = server_config_with_code_version("fedimint-code-version");

    assert_eq!(config.consensus.code_version, "fedimint");
}

#[test]
fn legacy_encrypted_layout_still_reads_with_disk_password() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let config = server_config_with_code_version("0.13.0+fedi");
    let password = "test-seat-password";
    let salt = fedimint_aead::random_salt();
    super::io::plaintext_display_write(
        &password,
        &directory.path().join(super::io::PLAINTEXT_PASSWORD),
    )
    .expect("write legacy password");
    super::io::plaintext_display_write(&salt, &directory.path().join(super::io::SALT_FILE))
        .expect("write legacy salt");
    let key = fedimint_aead::get_encryption_key(password, &salt).expect("derive legacy key");
    for (name, value) in [
        (
            super::io::LOCAL_CONFIG,
            serde_json::to_vec(&config.local).unwrap(),
        ),
        (
            super::io::CONSENSUS_CONFIG,
            serde_json::to_vec(&config.consensus).unwrap(),
        ),
    ] {
        std::fs::write(
            directory
                .path()
                .join(name)
                .with_extension(super::io::JSON_EXT),
            value,
        )
        .expect("write legacy public config");
    }
    fedimint_aead::encrypted_write(
        serde_json::to_vec(&config.private).expect("serialize private config"),
        &key,
        directory
            .path()
            .join(super::io::PRIVATE_CONFIG)
            .with_extension(super::io::ENCRYPTED_EXT),
    )
    .expect("write legacy encrypted private config");
    assert!(!directory.path().join("private.json").exists());
    let restored =
        super::io::read_server_config(directory.path()).expect("read encrypted configuration");
    assert_eq!(
        serde_json::to_value(config).expect("serialize original"),
        serde_json::to_value(restored).expect("serialize restored"),
    );
    fedimint_core::util::write_overwrite(
        directory.path().join(super::io::PLAINTEXT_PASSWORD),
        "wrong",
    )
    .expect("replace test password");
    assert!(super::io::read_server_config(directory.path()).is_err());
    assert!(directory.path().join("private.encrypt").exists());
}
