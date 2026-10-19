use std::collections::BTreeMap;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fedimint_connectors::ConnectorRegistry;
use fedimint_core::PeerId;
use fedimint_core::config::{ClientConfig, FederationId, GlobalClientConfig, PeerUrl};
use fedimint_core::endpoint_constants::CLIENT_CONFIG_ENDPOINT;
use fedimint_core::envs::{FM_IN_DEVIMINT_ENV, is_running_in_test_env};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::CORE_CONSENSUS_VERSION;
use fedimint_core::util::backoff_util;
use jsonrpsee::RpcModule;
use jsonrpsee::server::ServerBuilder;
use jsonrpsee::types::ErrorObjectOwned;

use super::{client_config_download_backoff, download_from_invite_code};

// Each child gets its own environment, including a fresh fedimint-core
// (compiled as a dependency, without cfg(test)). Never mutate the test runner's
// environment.
#[test]
fn config_download_environment_policy() {
    for mode in ["production", "devimint", "nextest"] {
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args(["--exact", "tests::config_download_child", "--nocapture"])
            .env_remove(FM_IN_DEVIMINT_ENV)
            .env_remove("NEXTEST")
            .env("FM_CONFIG_DOWNLOAD_TEST_MODE", mode);
        match mode {
            "devimint" => {
                child.env(FM_IN_DEVIMINT_ENV, "1");
            }
            "nextest" => {
                child.env("NEXTEST", "1");
            }
            _ => {}
        }
        let output = child.output().unwrap();
        assert!(
            output.status.success(),
            "{mode}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("config-download checks completed"),
            "{mode}: child did not run the expected checks",
        );
    }
}

#[tokio::test]
async fn config_download_child() {
    let Ok(mode) = std::env::var("FM_CONFIG_DOWNLOAD_TEST_MODE") else {
        return;
    };
    let testing = mode != "production";
    assert_eq!(is_running_in_test_env(), testing);
    // Backon's Fibonacci threshold is applied before advancing the sequence;
    // jitter adds up to one minimum delay. These are not wall-clock RPC bounds.
    let production = [
        200, 200, 400, 600, 1000, 1600, 2600, 4200, 6800, 6800, 6800, 6800, 6800, 6800,
    ];
    let fast = [
        20, 20, 40, 60, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
    ];
    check_delays(backoff_util::aggressive_backoff(), &production, 200);
    check_delays(
        client_config_download_backoff(),
        if testing { &fast } else { &production },
        if testing { 20 } else { 200 },
    );

    download_with_failures(0).await;
    if testing {
        download_with_failures(3).await;
        download_with_failures(usize::MAX).await;
        // A stopped listener exercises transport failure as well as RPC errors.
        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", server.local_addr().unwrap())
            .parse()
            .unwrap();
        drop(server);
        let connectors = ConnectorRegistry::build_from_testing_defaults()
            .bind()
            .await
            .unwrap();
        let invite = InviteCode::new(url, PeerId::from(0), FederationId::dummy(), None);
        assert!(
            download_from_invite_code(&connectors, &invite)
                .await
                .is_err()
        );
    }
    println!("config-download checks completed");
}

fn check_delays(backoff: backoff_util::FibonacciBackoff, expected_ms: &[u64], jitter_ms: u64) {
    let delays: Vec<_> = backoff.collect();
    assert_eq!(delays.len(), 14);
    for (delay, expected) in delays.into_iter().zip(expected_ms) {
        assert!(Duration::from_millis(*expected) <= delay);
        assert!(delay <= Duration::from_millis(expected + jitter_ms));
    }
}

async fn download_with_failures(failures: usize) {
    let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", server.local_addr().unwrap())
        .parse()
        .unwrap();
    let config = ClientConfig {
        global: GlobalClientConfig {
            api_endpoints: [(
                PeerId::from(0),
                PeerUrl {
                    url,
                    name: "test".into(),
                },
            )]
            .into(),
            broadcast_public_keys: None,
            consensus_version: CORE_CONSENSUS_VERSION,
            meta: BTreeMap::default(),
        },
        modules: BTreeMap::default(),
    };
    let invite = InviteCode::new(
        config.global.api_endpoints[&PeerId::from(0)].url.clone(),
        PeerId::from(0),
        config.calculate_federation_id(),
        None,
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let mut rpc = RpcModule::new((config.clone(), calls.clone()));
    rpc.register_method(CLIENT_CONFIG_ENDPOINT, move |_, context, _| {
        if context.1.fetch_add(1, Ordering::SeqCst) < failures {
            Err(ErrorObjectOwned::owned(-32000, "Not ready", None::<()>))
        } else {
            Ok(context.0.clone())
        }
    })
    .unwrap();
    let handle = server.start(rpc);
    let connectors = ConnectorRegistry::build_from_testing_defaults()
        .bind()
        .await
        .unwrap();
    let result = download_from_invite_code(&connectors, &invite).await;
    if failures == usize::MAX {
        assert!(result.is_err());
        // Fourteen retries after the initial attempt.
        assert_eq!(calls.load(Ordering::SeqCst), 15);
    } else {
        assert_eq!(result.unwrap().0, config);
        // Successful download also verifies the config with the full peer set.
        assert_eq!(calls.load(Ordering::SeqCst), failures + 2);
    }
    handle.stop().unwrap();
    handle.stopped().await;
}
