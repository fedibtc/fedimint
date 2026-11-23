use std::future::Future as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Context;
use std::time::Duration;

use fedimint_core::module::{ApiMethod, ApiRequestErased};
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send};
use serde_json::Value;
use tokio::sync::watch;

use crate::{ConnectionPool, ConnectorRegistry, IConnection, IGuardianConnection, ServerResult};

#[derive(Debug)]
struct TestConnection {
    connected: watch::Sender<bool>,
}

#[apply(async_trait_maybe_send!)]
impl IConnection for TestConnection {
    async fn await_disconnection(&self) {
        self.connected
            .subscribe()
            .wait_for(|connected| !connected)
            .await
            .expect("test sender remains alive");
    }

    fn is_connected(&self) -> bool {
        *self.connected.borrow()
    }
}

#[apply(async_trait_maybe_send!)]
impl IGuardianConnection for TestConnection {
    async fn request(&self, _method: ApiMethod, _request: ApiRequestErased) -> ServerResult<Value> {
        Ok(Value::Null)
    }
}

// A parked mint recovery request must not block requests to other guardians.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn unpolled_request_does_not_block_the_pool() {
    let registry = ConnectorRegistry::build_from_server_defaults().bind().await;
    let pool = ConnectionPool::<dyn IGuardianConnection>::new(registry);
    let create = |_: SafeUrl, _: Option<String>, _: ConnectorRegistry| async {
        Ok(Arc::new(TestConnection {
            connected: watch::channel(true).0,
        }) as Arc<dyn IGuardianConnection>)
    };
    let urls: Vec<SafeUrl> = (0..8)
        .map(|i| format!("ws://guardian{i}.example/").parse().unwrap())
        .collect();
    for url in &urls {
        pool.get_or_create_connection(url, None, create)
            .await
            .unwrap();
    }

    let stop = Arc::new(AtomicBool::new(false));
    let others: Vec<_> = urls[1..]
        .iter()
        .map(|url| {
            let pool = pool.clone();
            let url = url.clone();
            let stop = stop.clone();
            tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    pool.get_or_create_connection(&url, None, create)
                        .await
                        .unwrap();
                }
            })
        })
        .collect();

    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut unpolled = Vec::new();
    let deadline = fedimint_core::time::now() + Duration::from_secs(2);
    while unpolled.is_empty() && fedimint_core::time::now() < deadline {
        let mut request = Box::pin(tokio::task::unconstrained(
            pool.get_or_create_connection(&urls[0], None, create),
        ));
        if request.as_mut().poll(&mut cx).is_pending() {
            unpolled.push(request);
        }
    }

    stop.store(true, Ordering::Relaxed);
    tokio::time::timeout(
        Duration::from_secs(5),
        pool.get_or_create_connection(&urls[1], None, create),
    )
    .await
    .expect("a request to another guardian finishes")
    .unwrap();
    for other in others {
        other.abort();
    }
}
