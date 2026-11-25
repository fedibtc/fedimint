use super::*;

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

#[tokio::test]
async fn shared_pool_single_flights_and_reconnects_by_full_url() {
    let registry = ConnectorRegistry::build_from_server_defaults().bind().await;
    let first_pool = registry.guardian_connection_pool(None);
    let second_pool = registry.guardian_connection_pool(None);
    let connections = Arc::new(Mutex::new(Vec::<Arc<TestConnection>>::new()));
    let create = {
        let connections = connections.clone();
        move |_: SafeUrl, _: Option<String>, _: ConnectorRegistry| {
            let connections = connections.clone();
            async move {
                let conn = Arc::new(TestConnection {
                    connected: watch::channel(true).0,
                });
                connections.lock().unwrap().push(conn.clone());
                tokio::task::yield_now().await;
                Ok(conn as Arc<dyn IGuardianConnection>)
            }
        }
    };
    let url: SafeUrl = "ws://guardian.example/".parse().unwrap();
    let (first, second) = tokio::join!(
        first_pool.get_or_create_connection(&url, None, create.clone()),
        second_pool.get_or_create_connection(&url, None, create.clone()),
    );
    let first = first.unwrap();
    assert!(Arc::ptr_eq(&first, &second.unwrap()));
    assert_eq!(connections.lock().unwrap().len(), 1);

    connections.lock().unwrap()[0].connected.send_replace(false);
    let (replacement, same_replacement) = tokio::join!(
        first_pool.get_or_create_connection(&url, None, create.clone()),
        second_pool.get_or_create_connection(&url, None, create.clone()),
    );
    let replacement = replacement.unwrap();
    assert!(!Arc::ptr_eq(&first, &replacement));
    assert!(Arc::ptr_eq(&replacement, &same_replacement.unwrap()));
    assert_eq!(connections.lock().unwrap().len(), 2);

    let other_url: SafeUrl = "ws://guardian.example/v1".parse().unwrap();
    let other = second_pool
        .get_or_create_connection(&other_url, None, create)
        .await
        .unwrap();
    assert!(!Arc::ptr_eq(&replacement, &other));
    assert_eq!(connections.lock().unwrap().len(), 3);

    for conn in connections.lock().unwrap().iter() {
        conn.connected.send_replace(false);
    }
}

#[tokio::test]
async fn guardian_pool_cache_is_weak_and_does_not_expose_secrets() {
    let registry = ConnectorRegistry::build_from_server_defaults().bind().await;
    let pool = registry.guardian_connection_pool(Some("private-test-secret"));
    let weak_pool = Arc::downgrade(&pool);
    assert!(!format!("{registry:?} {pool:?}").contains("private-test-secret"));
    drop(pool);
    assert!(weak_pool.upgrade().is_none());

    let replacement = registry.guardian_connection_pool(None);
    assert_eq!(registry.inner.guardian_pools.lock().unwrap().len(), 1);
    let weak_registry = Arc::downgrade(&registry.inner);
    drop(replacement);
    drop(registry);
    assert!(weak_registry.upgrade().is_none());
}

#[test]
fn connector_builder_equality_includes_routing_overrides() {
    let defaults = ConnectorRegistry::build_from_server_defaults();
    assert_eq!(defaults, defaults.clone());
    let overridden = defaults.clone().with_connection_override(
        "ws://guardian.example/".parse().unwrap(),
        "ws://override.example/".parse().unwrap(),
    );
    assert_ne!(defaults, overridden);
}
