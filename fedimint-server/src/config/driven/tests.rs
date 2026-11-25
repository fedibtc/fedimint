use std::net::{Ipv4Addr, SocketAddr};

use fedimint_core::setup_code::PeerSetupCode;
use tokio::io::AsyncWriteExt as _;

use super::{
    BTreeSet, ChildMessage, ChildState, ConfigGenSettings, DrivenDkgClient, DrivenDkgEvent,
    FEDIMINT_PREFIX, Features, MAX_FRAME_LEN, PROTOCOL_VERSION, ParentMessage, ParentPhase,
    PeerEndpoints, RunDkgParams, SALT_FILE, Serialize, base32, decode_prefixed,
    ensure_no_config_artifacts, fs, install_staging, prepare_staging, read_frame, staging_path,
    validate_run_dkg, write_frame,
};

fn settings() -> ConfigGenSettings {
    ConfigGenSettings {
        p2p_bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 8173)),
        api_bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 8174)),
        ui_bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 8175)),
        p2p_url: None,
        api_url: None,
        enable_iroh: true,
        iroh_dns: None,
        iroh_relays: vec![],
        network: bitcoin::Network::Regtest,
        available_modules: BTreeSet::new(),
        default_modules: BTreeSet::new(),
    }
}

fn valid_request() -> ParentMessage {
    let secrets: Vec<_> = (1_u8..=4)
        .map(|byte| {
            (
                iroh::SecretKey::from_bytes(&[byte; 32]),
                iroh::SecretKey::from_bytes(&[byte + 10; 32]),
            )
        })
        .collect();
    let codes: BTreeSet<_> = secrets
        .iter()
        .enumerate()
        .map(|(index, (api, p2p))| PeerSetupCode {
            name: format!("guardian-{index}"),
            endpoints: PeerEndpoints::Iroh {
                api_pk: api.public(),
                p2p_pk: p2p.public(),
            },
            federation_name: (index == 0).then(|| "test-fed".to_string()),
            disable_base_fees: None,
            enabled_modules: None,
            federation_size: (index == 0).then_some(4),
            network: bitcoin::Network::Regtest,
            fedimint_version: fedimint_core::version::DkgVersion::parse("0.13.0")
                .expect("valid version"),
        })
        .collect();
    let codes: Vec<_> = codes
        .iter()
        .map(|code| base32::encode_prefixed(FEDIMINT_PREFIX, code))
        .collect();
    let our_index = codes
        .iter()
        .position(|encoded| {
            let code: PeerSetupCode = decode_prefixed(FEDIMINT_PREFIX, encoded).unwrap();
            matches!(
                code.endpoints,
                PeerEndpoints::Iroh { api_pk, .. } if api_pk == secrets[0].0.public()
            )
        })
        .unwrap() as u16;

    ParentMessage::RunDkg {
        our_index,
        codes,
        iroh_api_sk: secrets[0].0.to_bytes(),
        iroh_p2p_sk: secrets[0].1.to_bytes(),
        tls_key: None,
        api_auth: "secret".to_string(),
        network: "regtest".to_string(),
    }
}

fn parent_params() -> RunDkgParams {
    RunDkgParams {
        our_index: 0,
        codes: vec!["code".to_string()],
        iroh_api_sk: [1; 32],
        iroh_p2p_sk: [2; 32],
        tls_key: None,
        api_auth: "secret".to_string(),
        network: "regtest".to_string(),
    }
}

async fn write_hello(stream: &mut tokio::io::DuplexStream, state: ChildState) {
    write_frame(
        stream,
        &ChildMessage::Hello {
            proto: PROTOCOL_VERSION,
            code_version: "test-version".to_string(),
            state,
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn parent_client_validates_happy_path_and_retirement() {
    let (parent, mut child) = tokio::io::duplex(4096);
    let child_task = fedimint_core::runtime::spawn("driven test child", async move {
        write_hello(&mut child, ChildState::NeedsParams).await;
        let _: ParentMessage = read_frame(&mut child).await.unwrap();
        write_frame(&mut child, &ChildMessage::DkgStarted {})
            .await
            .unwrap();
        write_frame(
            &mut child,
            &ChildMessage::ConfigPersisted {
                invite_code: "invite".to_string(),
                api_url: "wss://guardian.example".to_string(),
            },
        )
        .await
        .unwrap();
        write_frame(&mut child, &ChildMessage::ConsensusStarted {})
            .await
            .unwrap();
    });

    let mut client = DrivenDkgClient::connect(parent).await.unwrap();
    assert_eq!(client.code_version(), "test-version");
    assert_eq!(client.child_state(), &ChildState::NeedsParams);
    client.run_dkg(parent_params()).await.unwrap();
    assert_eq!(
        client.next_event().await.unwrap().unwrap(),
        DrivenDkgEvent::DkgStarted
    );
    assert_eq!(
        client.next_event().await.unwrap().unwrap(),
        DrivenDkgEvent::ConfigPersisted {
            invite_code: "invite".to_string(),
            api_url: "wss://guardian.example".to_string(),
        }
    );
    assert_eq!(
        client.next_event().await.unwrap().unwrap(),
        DrivenDkgEvent::ConsensusStarted
    );
    child_task.await.unwrap();
    assert!(client.next_event().await.is_none());
}

#[tokio::test]
async fn parent_client_accepts_already_configured_path() {
    let (parent, mut child) = tokio::io::duplex(1024);
    fedimint_core::runtime::spawn("driven test child", async move {
        write_hello(
            &mut child,
            ChildState::AlreadyConfigured {
                invite_code: "invite".to_string(),
            },
        )
        .await;
        write_frame(&mut child, &ChildMessage::ConsensusStarted {})
            .await
            .unwrap();
    });

    let mut client = DrivenDkgClient::connect(parent).await.unwrap();
    assert_eq!(
        client.child_state(),
        &ChildState::AlreadyConfigured {
            invite_code: "invite".to_string()
        }
    );
    assert!(client.run_dkg(parent_params()).await.is_err());
    assert_eq!(
        client.next_event().await.unwrap().unwrap(),
        DrivenDkgEvent::ConsensusStarted
    );
    assert!(client.next_event().await.is_none());
}

#[tokio::test]
async fn features_flow_only_after_consensus_starts() {
    let (parent, mut child) = tokio::io::duplex(1024);
    write_hello(&mut child, ChildState::NeedsParams).await;
    let client = DrivenDkgClient::connect(parent).await.unwrap();
    assert!(client.into_features().is_err());

    let (parent, mut child) = tokio::io::duplex(1024);
    write_hello(
        &mut child,
        ChildState::AlreadyConfigured {
            invite_code: "invite".to_string(),
        },
    )
    .await;
    write_frame(&mut child, &ChildMessage::ConsensusStarted {})
        .await
        .unwrap();
    let mut client = DrivenDkgClient::connect(parent).await.unwrap();
    client.next_event().await.unwrap().unwrap();
    let mut features = client.into_features().unwrap();
    features
        .set(&Features {
            aleph_quiescence: true,
            ..Features::default()
        })
        .await
        .unwrap();
    let read: Features = read_frame(&mut child).await.unwrap();
    assert!(read.aleph_quiescence);
}

#[test]
fn start_features_set_the_iroh_timeouts_and_frames_do_not() {
    use fedimint_core::net::iroh::{iroh_idle_timeout, iroh_keep_alive_interval};

    let legacy: Features =
        serde_json::from_str(r#"{"iroh_legacy_timeouts":true}"#).expect("valid features");
    assert!(!legacy.walletv2_legacy_vote_delay);

    legacy.apply_at_start();
    assert_eq!(iroh_idle_timeout(), std::time::Duration::from_secs(60));
    assert_eq!(
        iroh_keep_alive_interval(),
        std::time::Duration::from_secs(30)
    );

    Features::default().apply();
    assert_eq!(iroh_idle_timeout(), std::time::Duration::from_secs(60));

    Features::default().apply_at_start();
    assert_eq!(iroh_idle_timeout(), std::time::Duration::from_secs(5));
    assert_eq!(
        iroh_keep_alive_interval(),
        std::time::Duration::from_secs(1)
    );
}

#[test]
fn frames_switch_the_walletv2_vote_delay() {
    use fedimint_server_core::walletv2_vote_delay::is_legacy;

    Features {
        walletv2_legacy_vote_delay: true,
        ..Features::default()
    }
    .apply();
    assert!(is_legacy());

    Features::default().apply();
    assert!(!is_legacy());
}

#[tokio::test]
async fn features_missing_from_a_frame_are_off() {
    #[derive(Serialize)]
    struct Empty {}
    #[derive(Serialize)]
    struct Future {
        aleph_quiescence: bool,
        not_yet_known: u8,
    }
    let (mut parent, mut child) = tokio::io::duplex(1024);
    write_frame(&mut parent, &Empty {}).await.unwrap();
    write_frame(
        &mut parent,
        &Future {
            aleph_quiescence: true,
            not_yet_known: 1,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        read_frame::<_, Features>(&mut child).await.unwrap(),
        Features::default()
    );
    assert!(
        read_frame::<_, Features>(&mut child)
            .await
            .unwrap()
            .aleph_quiescence
    );
}

#[tokio::test]
async fn parent_client_reports_params_rejected_as_terminal() {
    let (parent, mut child) = tokio::io::duplex(1024);
    fedimint_core::runtime::spawn("driven test child", async move {
        write_hello(&mut child, ChildState::NeedsParams).await;
        let _: ParentMessage = read_frame(&mut child).await.unwrap();
        write_frame(
            &mut child,
            &ChildMessage::ParamsRejected {
                reason: "bad params".to_string(),
            },
        )
        .await
        .unwrap();
    });

    let mut client = DrivenDkgClient::connect(parent).await.unwrap();
    client.run_dkg(parent_params()).await.unwrap();
    assert_eq!(
        client.next_event().await.unwrap().unwrap(),
        DrivenDkgEvent::ParamsRejected {
            reason: "bad params".to_string()
        }
    );
    assert!(client.next_event().await.is_none());
}

#[tokio::test]
async fn parent_client_redacts_unexpected_message_fields() {
    let (parent, mut child) = tokio::io::duplex(1024);
    write_frame(
        &mut child,
        &ChildMessage::ConfigPersisted {
            invite_code: "secret-invite".to_string(),
            api_url: "wss://secret.example".to_string(),
        },
    )
    .await
    .unwrap();
    let mut client = DrivenDkgClient {
        stream: parent,
        code_version: "test".to_string(),
        child_state: ChildState::NeedsParams,
        phase: ParentPhase::AwaitingDkgStart,
    };

    let error = client.next_event().await.unwrap().unwrap_err().to_string();

    assert!(error.contains("ConfigPersisted"));
    assert!(!error.contains("secret-invite"));
    assert!(!error.contains("secret.example"));
}

#[tokio::test]
async fn parent_client_rejects_version_mismatch() {
    let (parent, mut child) = tokio::io::duplex(1024);
    fedimint_core::runtime::spawn("driven test child", async move {
        write_frame(
            &mut child,
            &ChildMessage::Hello {
                proto: PROTOCOL_VERSION + 1,
                code_version: "future".to_string(),
                state: ChildState::NeedsParams,
            },
        )
        .await
        .unwrap();
    });

    let error = DrivenDkgClient::connect(parent).await.unwrap_err();
    assert!(error.to_string().contains("version mismatch"));
}

#[tokio::test]
async fn parent_client_rejects_oversized_hello() {
    let (parent, mut child) = tokio::io::duplex(4);
    child
        .write_all(&(MAX_FRAME_LEN as u32 + 1).to_le_bytes())
        .await
        .unwrap();

    let error = DrivenDkgClient::connect(parent).await.unwrap_err();
    assert!(error.to_string().contains("child hello"));
}

#[tokio::test]
async fn parent_client_treats_eof_before_retirement_as_child_death() {
    for phase in [
        ParentPhase::NeedsRequest,
        ParentPhase::AwaitingDkgStart,
        ParentPhase::DkgRunning,
        ParentPhase::ConfigPersisted,
        ParentPhase::AwaitingConsensus,
    ] {
        let (parent, child) = tokio::io::duplex(64);
        drop(child);
        let mut client = DrivenDkgClient {
            stream: parent,
            code_version: "test".to_string(),
            child_state: ChildState::NeedsParams,
            phase,
        };
        let error = client.next_event().await.unwrap().unwrap_err();
        assert!(
            error.to_string().contains(&format!("during {phase:?}")),
            "{error:#}"
        );
        assert!(client.next_event().await.is_none());
    }

    let (parent, child) = tokio::io::duplex(64);
    drop(child);
    let error = DrivenDkgClient::connect(parent).await.unwrap_err();
    assert!(error.to_string().contains("child hello"));
}

#[tokio::test]
async fn framing_round_trip() {
    let message = ParentMessage::RunDkg {
        our_index: 1,
        codes: vec!["code-a".to_string(), "code-b".to_string()],
        iroh_api_sk: [1; 32],
        iroh_p2p_sk: [2; 32],
        tls_key: None,
        api_auth: "secret".to_string(),
        network: "regtest".to_string(),
    };
    let (mut writer, mut reader) = tokio::io::duplex(MAX_FRAME_LEN + 4);

    write_frame(&mut writer, &message).await.unwrap();

    let decoded: ParentMessage = read_frame(&mut reader).await.unwrap();
    assert_eq!(decoded, message);
}

#[tokio::test]
async fn oversized_frame_is_rejected_before_payload_read() {
    let (mut writer, mut reader) = tokio::io::duplex(4);
    writer
        .write_all(&(MAX_FRAME_LEN as u32 + 1).to_le_bytes())
        .await
        .unwrap();

    assert!(read_frame::<_, ParentMessage>(&mut reader).await.is_err());
}

#[test]
fn validation_rejects_noncanonical_order() {
    let ParentMessage::RunDkg {
        our_index,
        mut codes,
        iroh_api_sk,
        iroh_p2p_sk,
        tls_key,
        api_auth,
        network,
    } = valid_request();
    codes.swap(0, 1);

    let error = validate_run_dkg(
        ParentMessage::RunDkg {
            our_index,
            codes,
            iroh_api_sk,
            iroh_p2p_sk,
            tls_key,
            api_auth,
            network,
        },
        &settings(),
    )
    .unwrap_err();

    assert!(error.to_string().contains("canonical"));
}

#[test]
fn validation_rejects_bad_index() {
    let ParentMessage::RunDkg {
        codes,
        iroh_api_sk,
        iroh_p2p_sk,
        tls_key,
        api_auth,
        network,
        ..
    } = valid_request();

    let error = validate_run_dkg(
        ParentMessage::RunDkg {
            our_index: codes.len() as u16,
            codes,
            iroh_api_sk,
            iroh_p2p_sk,
            tls_key,
            api_auth,
            network,
        },
        &settings(),
    )
    .unwrap_err();

    assert!(error.to_string().contains("out of range"));
}

#[test]
fn validation_rejects_network_mismatch() {
    let ParentMessage::RunDkg {
        our_index,
        codes,
        iroh_api_sk,
        iroh_p2p_sk,
        tls_key,
        api_auth,
        ..
    } = valid_request();

    let error = validate_run_dkg(
        ParentMessage::RunDkg {
            our_index,
            codes,
            iroh_api_sk,
            iroh_p2p_sk,
            tls_key,
            api_auth,
            network: "bitcoin".to_string(),
        },
        &settings(),
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("does not match configured network")
    );
}

#[test]
fn validation_rejects_duplicate_codes() {
    let ParentMessage::RunDkg {
        our_index,
        mut codes,
        iroh_api_sk,
        iroh_p2p_sk,
        tls_key,
        api_auth,
        network,
    } = valid_request();
    codes[1] = codes[0].clone();

    let error = validate_run_dkg(
        ParentMessage::RunDkg {
            our_index,
            codes,
            iroh_api_sk,
            iroh_p2p_sk,
            tls_key,
            api_auth,
            network,
        },
        &settings(),
    )
    .unwrap_err();

    assert!(error.to_string().contains("duplicates"));
}

#[test]
fn staging_install_replaces_incomplete_state_atomically() {
    let parent = tempfile::tempdir().unwrap();
    let final_path = parent.path().join("fedimintd");
    fs::create_dir(&final_path).unwrap();
    fedimint_core::util::write_new(final_path.join("partial"), b"partial").unwrap();
    let stale_staging = staging_path(&final_path).unwrap();
    fs::create_dir(&stale_staging).unwrap();
    fedimint_core::util::write_new(stale_staging.join("stale"), b"stale").unwrap();

    let staging = prepare_staging(&final_path).unwrap();
    assert!(!final_path.exists());
    assert_eq!(fs::read_dir(&staging).unwrap().count(), 0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(&staging).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    fedimint_core::util::write_new(staging.join("complete"), b"complete").unwrap();

    install_staging(&staging, &final_path).unwrap();

    assert!(!staging.exists());
    assert_eq!(fs::read(final_path.join("complete")).unwrap(), b"complete");
}

#[test]
fn passwordless_config_artifacts_are_preserved_and_refused() {
    let parent = tempfile::tempdir().unwrap();
    let final_path = parent.path().join("fedimintd");
    fs::create_dir(&final_path).unwrap();
    fedimint_core::util::write_new(final_path.join(SALT_FILE), b"existing salt").unwrap();

    let error = ensure_no_config_artifacts(&final_path).unwrap_err();

    assert!(error.to_string().contains("non-disposable"));
    assert_eq!(
        fs::read(final_path.join(SALT_FILE)).unwrap(),
        b"existing salt"
    );
}
