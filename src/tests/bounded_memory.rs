use super::*;
use std::num::NonZeroUsize;
use time::Duration;

fn key(value: &str) -> AuthRateLimitKey {
    AuthRateLimitKey {
        flow: AuthRateLimitFlow::PasswordLogin,
        bucket: AuthRateLimitBucket::Principal,
        value_hash: value.into(),
    }
}
fn snapshot(
    key: AuthRateLimitKey,
    now: OffsetDateTime,
    expiry: OffsetDateTime,
) -> AuthRateLimitSnapshot {
    AuthRateLimitSnapshot {
        revision: Uuid::new_v4(),
        state: AuthRateLimitState {
            key,
            attempts: 1,
            first_attempt_at: now,
            last_attempt_at: now,
            backoff_until: None,
            locked_until: None,
            expires_at: expiry,
        },
    }
}
fn store(capacity: usize) -> (MemoryAuthRateLimitStore, FixedClock) {
    let clock = FixedClock::new(OffsetDateTime::UNIX_EPOCH);
    (
        MemoryAuthRateLimitStore::with_capacity_and_clock(
            NonZeroUsize::new(capacity).unwrap(),
            Arc::new(clock.clone()),
        ),
        clock,
    )
}

#[tokio::test]
async fn expired_unique_principals_are_reclaimed_by_reads_and_expired_inserts_fail_closed() {
    let (store, clock) = store(2);
    let first = key("expired-a");
    let second = key("expired-b");
    for key in [&first, &second] {
        assert!(
            store
                .compare_exchange_auth_rate_limit_state(
                    key,
                    None,
                    snapshot(
                        key.clone(),
                        clock.now(),
                        clock.now() + Duration::seconds(10)
                    )
                )
                .await
                .unwrap()
        );
    }
    clock.advance_seconds(10);
    assert!(
        store
            .find_auth_rate_limit_state(&key("unrelated-read"))
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.get(&first).is_none());
    assert!(store.get(&second).is_none());
    assert_eq!(store.purge_expired().unwrap(), 0);
    assert!(matches!(
        store
            .compare_exchange_auth_rate_limit_state(
                &first,
                None,
                snapshot(first.clone(), clock.now(), clock.now())
            )
            .await,
        Err(AuthError::Store(_))
    ));
    assert!(
        store
            .find_auth_rate_limit_state(&first)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .compare_exchange_auth_rate_limit_state(
                &first,
                None,
                snapshot(
                    first.clone(),
                    clock.now(),
                    clock.now() + Duration::seconds(10)
                )
            )
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn distinct_principal_flood_is_bounded_and_never_evicts_active_lockouts() {
    let (store, clock) = store(2);
    let locked_key = key("locked-principal");
    let mut locked = snapshot(
        locked_key.clone(),
        clock.now(),
        clock.now() + Duration::minutes(5),
    );
    locked.state.locked_until = Some(locked.state.expires_at);
    locked.state.attempts = 10;
    let locked_revision = locked.revision;
    assert!(
        store
            .compare_exchange_auth_rate_limit_state(&locked_key, None, locked)
            .await
            .unwrap()
    );
    let second = key("counter");
    let second_snapshot = snapshot(
        second.clone(),
        clock.now(),
        clock.now() + Duration::minutes(5),
    );
    let second_revision = second_snapshot.revision;
    assert!(
        store
            .compare_exchange_auth_rate_limit_state(&second, None, second_snapshot)
            .await
            .unwrap()
    );
    for n in 0..100 {
        let key = key(&format!("flood-{n}"));
        assert!(matches!(
            store
                .compare_exchange_auth_rate_limit_state(
                    &key,
                    None,
                    snapshot(key.clone(), clock.now(), clock.now() + Duration::minutes(5))
                )
                .await,
            Err(AuthError::AuthServiceUnavailable)
        ));
    }
    let locked = store
        .find_auth_rate_limit_state(&locked_key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(locked.revision, locked_revision);
    assert_eq!(locked.state.attempts, 10);
    let replacement = snapshot(
        second.clone(),
        clock.now(),
        clock.now() + Duration::minutes(10),
    );
    assert!(
        store
            .compare_exchange_auth_rate_limit_state(&second, Some(second_revision), replacement)
            .await
            .unwrap()
    );
    assert!(
        store
            .clear_auth_rate_limit_state(&locked_key, Some(locked_revision))
            .await
            .unwrap()
    );
    let admitted = key("after-clear");
    assert!(
        store
            .compare_exchange_auth_rate_limit_state(
                &admitted,
                None,
                snapshot(
                    admitted.clone(),
                    clock.now(),
                    clock.now() + Duration::minutes(5)
                )
            )
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn stale_expiry_and_cas_cannot_remove_or_replace_newer_state() {
    let (store, clock) = store(1);
    let key = key("same-principal");
    let first = snapshot(
        key.clone(),
        clock.now(),
        clock.now() + Duration::seconds(10),
    );
    let first_revision = first.revision;
    assert!(
        store
            .compare_exchange_auth_rate_limit_state(&key, None, first)
            .await
            .unwrap()
    );
    clock.advance_seconds(5);
    let second = snapshot(
        key.clone(),
        clock.now(),
        clock.now() + Duration::seconds(20),
    );
    let second_revision = second.revision;
    assert!(
        store
            .compare_exchange_auth_rate_limit_state(&key, Some(first_revision), second)
            .await
            .unwrap()
    );
    clock.advance_seconds(5);
    assert_eq!(store.purge_expired().unwrap(), 0);
    assert_eq!(
        store
            .find_auth_rate_limit_state(&key)
            .await
            .unwrap()
            .unwrap()
            .revision,
        second_revision
    );
    clock.advance_seconds(20);
    assert_eq!(store.purge_expired().unwrap(), 1);
    let third = snapshot(
        key.clone(),
        clock.now(),
        clock.now() + Duration::seconds(10),
    );
    let third_revision = third.revision;
    assert!(
        !store
            .compare_exchange_auth_rate_limit_state(&key, Some(first_revision), third.clone())
            .await
            .unwrap()
    );
    assert!(
        store
            .compare_exchange_auth_rate_limit_state(&key, None, third)
            .await
            .unwrap()
    );
    assert!(
        !store
            .clear_auth_rate_limit_state(&key, Some(second_revision))
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .find_auth_rate_limit_state(&key)
            .await
            .unwrap()
            .unwrap()
            .revision,
        third_revision
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_insertions_share_one_capacity_boundary() {
    let (store, clock) = store(1);
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let mut tasks = vec![];
    for name in ["first", "second"] {
        let store = store.clone();
        let barrier = barrier.clone();
        let now = clock.now();
        let key = key(name);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .compare_exchange_auth_rate_limit_state(
                    &key,
                    None,
                    snapshot(key.clone(), now, now + Duration::hours(1)),
                )
                .await
        }));
    }
    barrier.wait().await;
    let mut admitted = 0;
    let mut denied = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(true) => admitted += 1,
            Err(AuthError::AuthServiceUnavailable) => denied += 1,
            other => panic!("unexpected capacity result {other:?}"),
        }
    }
    assert_eq!((admitted, denied), (1, 1));
    clock.advance_seconds(3600);
    assert_eq!(store.purge_expired().unwrap(), 1);
}

#[tokio::test]
async fn capacity_failure_denies_request_admission_without_issuing_authority() {
    let (store, clock) = store(1);
    let refresh = MemoryRefreshTokenStore::default();
    let auth = AuthService::new_with_rate_limit_store_and_clock(
        AuthConfig::new(TEST_HS256_SECRET),
        Arc::new(MemoryUserStore::default()),
        Arc::new(refresh.clone()),
        Arc::new(store.clone()),
        Arc::new(clock.clone()),
    )
    .unwrap();
    let result = auth
        .should_process_login_code_request(
            "synthetic@example.invalid",
            ClientMetadata {
                ip_address: Some("192.0.2.1".into()),
                ..ClientMetadata::default()
            },
        )
        .await;
    assert!(matches!(result, Err(AuthError::AuthServiceUnavailable)));
    assert!(refresh.tokens_by_id.lock().unwrap().is_empty());
    clock.advance_seconds(24 * 3600);
    assert_eq!(
        store.purge_expired().unwrap(),
        1,
        "the safe over-count from the first bucket remains until expiry"
    );
}
