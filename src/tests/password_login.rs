//! One password-login contract reused by memory and SQL consumer stores.
use std::sync::{Arc, atomic::Ordering};

use argon2::password_hash::PasswordHash;
use async_graphql::ErrorExtensions;
use async_trait::async_trait;
use time::{Duration, OffsetDateTime};
use tokio::sync::{Barrier, Notify};
use uuid::Uuid;

use super::{MemoryRefreshTokenStore, MemoryUserStore, TEST_HS256_SECRET, stored_user};
use crate::prelude::*;

type Service = AuthService<MemoryUserStore, MemoryRefreshTokenStore>;

fn policy() -> AuthRateLimitPolicy {
    AuthRateLimitPolicy {
        enabled: true,
        window: Duration::minutes(15),
        backoff_after_attempts: 2,
        max_attempts_before_lockout: 3,
        base_backoff: Duration::seconds(10),
        max_backoff: Duration::seconds(20),
        lockout_duration: Duration::minutes(5),
        state_ttl: Duration::hours(1),
    }
}

fn service<S: AuthRateLimitStore + 'static>(
    store: Arc<S>,
    users: MemoryUserStore,
    refresh: MemoryRefreshTokenStore,
    clock: Arc<FixedClock>,
    policy: AuthRateLimitPolicy,
) -> Service {
    let mut config = AuthConfig::new(TEST_HS256_SECRET);
    config.rate_limits.credential = policy;
    AuthService::new_with_rate_limit_store_and_clock(
        config,
        Arc::new(users),
        Arc::new(refresh),
        store,
        clock,
    )
    .unwrap()
}

fn metadata() -> ClientMetadata {
    ClientMetadata {
        ip_address: Some("192.0.2.7".into()),
        ..Default::default()
    }
}

fn keys(auth: &Service, principal: &str) -> Vec<AuthRateLimitKey> {
    let keys = auth.rate_limit_keys(
        AuthRateLimitFlow::PasswordLogin,
        Some(principal),
        &metadata(),
    );
    assert_eq!(keys.len(), 2);
    keys
}

async fn assert_attempts<S: AuthRateLimitStore>(
    store: &S,
    keys: &[AuthRateLimitKey],
    attempts: u32,
) {
    for key in keys {
        assert_eq!(
            store
                .find_auth_rate_limit_state(key)
                .await
                .unwrap()
                .unwrap()
                .state
                .attempts,
            attempts
        );
    }
}

fn assert_no_authority(auth: &Service, refresh: &MemoryRefreshTokenStore) {
    assert_eq!(auth.token_work.load(Ordering::SeqCst), 0);
    assert!(refresh.tokens_by_id.lock().unwrap().is_empty());
    assert_eq!(*refresh.rotations.lock().unwrap(), 0);
}

/// The caller supplies a fresh consumer store for each invocation.
pub(super) async fn rejection_contract<S: AuthRateLimitStore + 'static>(store: Arc<S>) {
    // Equal policy, principal/client keys and injected clock for every case.
    for (case, disabled, password, code) in [
        ("unknown", false, "wrong", "INVALID_CREDENTIALS"),
        ("enabled", false, "wrong", "INVALID_CREDENTIALS"),
        ("disabled-wrong", true, "wrong", "USER_DISABLED"),
        ("disabled-correct", true, "correct", "USER_DISABLED"),
        ("disabled-corrupt-hash", true, "correct", "USER_DISABLED"),
    ] {
        let users = MemoryUserStore::default();
        let refresh = MemoryRefreshTokenStore::default();
        let start = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let clock = Arc::new(FixedClock::new(start));
        let auth = service(
            store.clone(),
            users.clone(),
            refresh.clone(),
            clock.clone(),
            policy(),
        );
        let principal = format!("{case}@example.com");
        let mut user = stored_user(&auth, case, &principal, "correct");
        let real_hash = user.password_hash.clone();
        if case != "unknown" {
            user.disabled = disabled;
            if case == "disabled-corrupt-hash" {
                user.password_hash = "corrupt".into();
            }
            users.insert(user);
        }
        let keys = keys(&auth, &principal);
        // Separate client keys between cases without changing configured controls.
        for key in &keys {
            let current = store.find_auth_rate_limit_state(key).await.unwrap();
            if let Some(current) = current {
                assert!(
                    store
                        .clear_auth_rate_limit_state(key, Some(current.revision))
                        .await
                        .unwrap()
                );
            }
        }
        for count in 1..=2 {
            let error = auth
                .login(&principal, password, metadata())
                .await
                .unwrap_err();
            assert_eq!(error.public_code(), code);
            assert_attempts(&*store, &keys, count).await;
        }
        let blocked = auth
            .login(&principal, password, metadata())
            .await
            .unwrap_err();
        assert!(matches!(blocked, AuthError::AuthThrottled { .. }));
        assert_eq!(blocked.public_code(), "RATE_LIMITED");
        let gql = blocked.extend();
        assert_eq!(
            gql.extensions.unwrap().get("retryAfterSeconds"),
            Some(&async_graphql::Value::from(10))
        );
        assert_attempts(&*store, &keys, 2).await;
        assert_eq!(auth.password_work.lock().unwrap().len(), 2);
        clock.advance_seconds(10);
        assert_eq!(
            auth.login(&principal, password, metadata())
                .await
                .unwrap_err()
                .public_code(),
            code
        );
        assert_attempts(&*store, &keys, 3).await;
        let locked = auth
            .login(&principal, "correct", metadata())
            .await
            .unwrap_err();
        assert!(matches!(locked, AuthError::AuthLocked { .. }));
        assert_eq!(locked.public_code(), "RATE_LIMITED");
        assert_eq!(
            locked.extend().extensions.unwrap().get("retryAfterSeconds"),
            Some(&async_graphql::Value::from(300))
        );
        assert_eq!(auth.password_work.lock().unwrap().len(), 3);
        assert_attempts(&*store, &keys, 3).await;
        assert_no_authority(&auth, &refresh);
        // Exactly one completed Argon2 verifier call per admitted attempt. The
        // dummy PHC has the same algorithm/version/work parameters as new hashes.
        for hash in auth.password_work.lock().unwrap().iter() {
            let actual = PasswordHash::new(hash).unwrap();
            let expected = PasswordHash::new(&real_hash).unwrap();
            assert_eq!(actual.algorithm, expected.algorithm);
            assert_eq!(actual.version, expected.version);
            assert_eq!(actual.params, expected.params);
        }
        clock.advance_seconds(policy().window.whole_seconds() - 10);
        assert_eq!(
            auth.login(&principal, password, metadata())
                .await
                .unwrap_err()
                .public_code(),
            code
        );
        for key in &keys {
            let state = store
                .find_auth_rate_limit_state(key)
                .await
                .unwrap()
                .unwrap()
                .state;
            assert_eq!(state.attempts, 1);
            assert_eq!(state.first_attempt_at, start + policy().window);
        }
    }
}

pub(super) async fn success_contract<S: AuthRateLimitStore + 'static>(store: Arc<S>) {
    let users = MemoryUserStore::default();
    let refresh = MemoryRefreshTokenStore::default();
    let clock = Arc::new(FixedClock::new(
        OffsetDateTime::from_unix_timestamp(1_800_001_000).unwrap(),
    ));
    let auth = service(
        store.clone(),
        users.clone(),
        refresh.clone(),
        clock,
        policy(),
    );
    let mut user = stored_user(&auth, "success", "success@example.com", "correct");
    user.disabled = true;
    users.insert(user.clone());
    assert_eq!(
        auth.login(&user.principal, "correct", metadata())
            .await
            .unwrap_err()
            .public_code(),
        "USER_DISABLED"
    );
    let keys = keys(&auth, &user.principal);
    assert_attempts(&*store, &keys, 1).await;
    assert_no_authority(&auth, &refresh);
    user.disabled = false;
    users.insert(user.clone());
    let payload = auth
        .login(&user.principal, "correct", metadata())
        .await
        .unwrap();
    for key in keys {
        assert!(
            store
                .find_auth_rate_limit_state(&key)
                .await
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(
        auth.authenticate_access_token(&payload.access_token)
            .unwrap()
            .user_id,
        user.id
    );
    assert_eq!(auth.token_work.load(Ordering::SeqCst), 1);
    assert_eq!(refresh.tokens_by_id.lock().unwrap().len(), 1);
}

/// Force all writers to observe absence before the first insert CAS.
/// Losing writers must reread/recalculate/retry against the new revision.
struct ContendedStore<S> {
    inner: Arc<S>,
    barrier: Barrier,
    first_writes: std::sync::atomic::AtomicUsize,
    conflicts: std::sync::atomic::AtomicUsize,
}

#[async_trait]
impl<S: AuthRateLimitStore> AuthRateLimitStore for ContendedStore<S> {
    async fn find_auth_rate_limit_state(
        &self,
        key: &AuthRateLimitKey,
    ) -> crate::AuthResult<Option<AuthRateLimitSnapshot>> {
        self.inner.find_auth_rate_limit_state(key).await
    }
    async fn compare_exchange_auth_rate_limit_state(
        &self,
        key: &AuthRateLimitKey,
        revision: Option<Uuid>,
        replacement: AuthRateLimitSnapshot,
    ) -> crate::AuthResult<bool> {
        if key.bucket == AuthRateLimitBucket::Principal
            && self.first_writes.fetch_add(1, Ordering::SeqCst) < 8
        {
            self.barrier.wait().await;
        }
        let result = self
            .inner
            .compare_exchange_auth_rate_limit_state(key, revision, replacement)
            .await?;
        if !result {
            self.conflicts.fetch_add(1, Ordering::SeqCst);
        }
        Ok(result)
    }
    async fn clear_auth_rate_limit_state(
        &self,
        key: &AuthRateLimitKey,
        revision: Option<Uuid>,
    ) -> crate::AuthResult<bool> {
        self.inner.clear_auth_rate_limit_state(key, revision).await
    }
}

pub(super) async fn concurrent_contract<S: AuthRateLimitStore + 'static>(store: Arc<S>) {
    const ATTEMPTS: usize = 8;
    for case in ["unknown", "enabled", "disabled"] {
        let store = Arc::new(ContendedStore {
            inner: store.clone(),
            barrier: Barrier::new(ATTEMPTS),
            first_writes: Default::default(),
            conflicts: Default::default(),
        });
        let users = MemoryUserStore::default();
        let refresh = MemoryRefreshTokenStore::default();
        let clock = Arc::new(FixedClock::new(
            OffsetDateTime::from_unix_timestamp(1_800_002_000).unwrap(),
        ));
        let mut policy = policy();
        policy.backoff_after_attempts = 100;
        policy.max_attempts_before_lockout = 200;
        let first = Arc::new(service(
            store.clone(),
            users.clone(),
            refresh.clone(),
            clock.clone(),
            policy.clone(),
        ));
        let second = Arc::new(service(
            store.clone(),
            users.clone(),
            refresh.clone(),
            clock,
            policy,
        ));
        let principal = format!("concurrent-{case}@example.com");
        if case != "unknown" {
            let mut user = stored_user(&first, case, &principal, "correct");
            user.disabled = case == "disabled";
            users.insert(user);
        }
        let keys = keys(&first, &principal);
        // Shared client counts are reset between independent scenarios.
        for key in &keys {
            if let Some(snapshot) = store.find_auth_rate_limit_state(key).await.unwrap() {
                assert!(
                    store
                        .clear_auth_rate_limit_state(key, Some(snapshot.revision))
                        .await
                        .unwrap()
                );
            }
        }
        let mut tasks = Vec::new();
        for index in 0..ATTEMPTS {
            let auth = if index % 2 == 0 {
                first.clone()
            } else {
                second.clone()
            };
            let principal = principal.clone();
            tasks.push(tokio::spawn(async move {
                auth.login(&principal, "wrong", metadata()).await
            }));
        }
        for task in tasks {
            let error = task.await.unwrap().unwrap_err();
            assert_eq!(
                error.public_code(),
                if case == "disabled" {
                    "USER_DISABLED"
                } else {
                    "INVALID_CREDENTIALS"
                }
            );
        }
        assert_attempts(&*store, &keys, ATTEMPTS as u32).await;
        assert!(store.conflicts.load(Ordering::SeqCst) >= ATTEMPTS - 1);
        assert_eq!(
            first.password_work.lock().unwrap().len() + second.password_work.lock().unwrap().len(),
            ATTEMPTS
        );
        assert_no_authority(&first, &refresh);
        assert_no_authority(&second, &refresh);
    }
}

struct PausedClearStore<S> {
    inner: Arc<S>,
    started: Notify,
    resume: Notify,
}
#[async_trait]
impl<S: AuthRateLimitStore> AuthRateLimitStore for PausedClearStore<S> {
    async fn find_auth_rate_limit_state(
        &self,
        key: &AuthRateLimitKey,
    ) -> crate::AuthResult<Option<AuthRateLimitSnapshot>> {
        self.inner.find_auth_rate_limit_state(key).await
    }
    async fn compare_exchange_auth_rate_limit_state(
        &self,
        key: &AuthRateLimitKey,
        revision: Option<Uuid>,
        replacement: AuthRateLimitSnapshot,
    ) -> crate::AuthResult<bool> {
        self.inner
            .compare_exchange_auth_rate_limit_state(key, revision, replacement)
            .await
    }
    async fn clear_auth_rate_limit_state(
        &self,
        key: &AuthRateLimitKey,
        revision: Option<Uuid>,
    ) -> crate::AuthResult<bool> {
        if key.bucket == AuthRateLimitBucket::Principal {
            self.started.notify_one();
            self.resume.notified().await;
        }
        self.inner.clear_auth_rate_limit_state(key, revision).await
    }
}

pub(super) async fn clear_order_contract<S: AuthRateLimitStore + 'static>(inner: Arc<S>) {
    let store = Arc::new(PausedClearStore {
        inner,
        started: Notify::new(),
        resume: Notify::new(),
    });
    let users = MemoryUserStore::default();
    let refresh = MemoryRefreshTokenStore::default();
    let clock = Arc::new(FixedClock::new(
        OffsetDateTime::from_unix_timestamp(1_800_003_000).unwrap(),
    ));
    let mut policy = policy();
    policy.backoff_after_attempts = 100;
    policy.max_attempts_before_lockout = 200;
    let first = Arc::new(service(
        store.clone(),
        users.clone(),
        refresh.clone(),
        clock.clone(),
        policy.clone(),
    ));
    let second = service(store.clone(), users.clone(), refresh.clone(), clock, policy);
    let user = stored_user(&first, "clear", "clear@example.com", "correct");
    users.insert(user.clone());
    assert_eq!(
        first
            .login(&user.principal, "wrong", metadata())
            .await
            .unwrap_err()
            .public_code(),
        "INVALID_CREDENTIALS"
    );
    let success = tokio::spawn({
        let auth = first.clone();
        let principal = user.principal.clone();
        async move { auth.login(&principal, "correct", metadata()).await }
    });
    store.started.notified().await;
    // Correct-password success must finish conditional clears before issuance.
    assert_no_authority(&first, &refresh);
    let mut disabled = stored_user(
        &second,
        "disabled-clear",
        "disabled-clear@example.com",
        "correct",
    );
    disabled.disabled = true;
    users.insert(disabled.clone());
    assert_eq!(
        second
            .login(&disabled.principal, "correct", metadata())
            .await
            .unwrap_err()
            .public_code(),
        "USER_DISABLED"
    );
    assert_no_authority(&second, &refresh);
    store.resume.notify_one();
    success.await.unwrap().unwrap();
    // The later disabled failure survives the stale shared-client clear.
    let enabled_keys = keys(&first, &user.principal);
    assert!(
        store
            .find_auth_rate_limit_state(&enabled_keys[0])
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .find_auth_rate_limit_state(&enabled_keys[1])
            .await
            .unwrap()
            .unwrap()
            .state
            .attempts,
        2
    );
    assert_eq!(
        store
            .find_auth_rate_limit_state(&keys(&second, &disabled.principal)[0])
            .await
            .unwrap()
            .unwrap()
            .state
            .attempts,
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_password_login_contract() {
    independent_buckets_contract(Arc::new(MemoryAuthRateLimitStore::default())).await;
    store_contract(Arc::new(MemoryAuthRateLimitStore::default())).await;
    rejection_contract(Arc::new(MemoryAuthRateLimitStore::default())).await;
    success_contract(Arc::new(MemoryAuthRateLimitStore::default())).await;
    concurrent_contract(Arc::new(MemoryAuthRateLimitStore::default())).await;
    clear_order_contract(Arc::new(MemoryAuthRateLimitStore::default())).await;
}

pub(super) async fn store_contract<S: AuthRateLimitStore + 'static>(store: Arc<S>) {
    let now = OffsetDateTime::from_unix_timestamp(1_800_004_000).unwrap();
    let auth = service(
        store.clone(),
        Default::default(),
        Default::default(),
        Arc::new(FixedClock::new(now)),
        policy(),
    );
    let keys = keys(&auth, "expired@example.com");
    for key in &keys {
        let snapshot = AuthRateLimitSnapshot {
            revision: Uuid::new_v4(),
            state: AuthRateLimitState {
                key: key.clone(),
                attempts: 42,
                first_attempt_at: now,
                last_attempt_at: now,
                backoff_until: Some(now + Duration::minutes(5)),
                locked_until: Some(now + Duration::minutes(10)),
                expires_at: now,
            },
        };
        let mut mismatched = snapshot.clone();
        mismatched.state.key.value_hash = "another-key".into();
        assert!(
            store
                .compare_exchange_auth_rate_limit_state(key, None, mismatched)
                .await
                .is_err()
        );
        assert!(
            store
                .find_auth_rate_limit_state(key)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .compare_exchange_auth_rate_limit_state(key, None, snapshot.clone())
                .await
                .unwrap()
        );
        let mut newer = snapshot.clone();
        newer.revision = Uuid::new_v4();
        assert!(
            !store
                .compare_exchange_auth_rate_limit_state(key, None, newer.clone())
                .await
                .unwrap()
        );
        assert!(!store.clear_auth_rate_limit_state(key, None).await.unwrap());
        assert!(
            store
                .compare_exchange_auth_rate_limit_state(key, Some(snapshot.revision), newer.clone())
                .await
                .unwrap()
        );
        assert!(
            !store
                .compare_exchange_auth_rate_limit_state(
                    key,
                    Some(snapshot.revision),
                    snapshot.clone()
                )
                .await
                .unwrap()
        );
        assert!(
            !store
                .clear_auth_rate_limit_state(key, Some(snapshot.revision))
                .await
                .unwrap()
        );
        assert_eq!(
            store.find_auth_rate_limit_state(key).await.unwrap(),
            Some(newer)
        );
    }
    assert_eq!(
        auth.login("expired@example.com", "wrong", metadata())
            .await
            .unwrap_err()
            .public_code(),
        "INVALID_CREDENTIALS"
    );
    for key in &keys {
        let snapshot = store
            .find_auth_rate_limit_state(key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.state.attempts, 1);
        assert_eq!(snapshot.state.first_attempt_at, now);
        assert_eq!(snapshot.state.expires_at, now + policy().state_ttl);
        assert!(snapshot.state.backoff_until.is_none());
        assert!(snapshot.state.locked_until.is_none());
        assert!(
            store
                .clear_auth_rate_limit_state(key, Some(snapshot.revision))
                .await
                .unwrap()
        );
        assert!(
            store
                .find_auth_rate_limit_state(key)
                .await
                .unwrap()
                .is_none()
        );
        let mut fresh = snapshot;
        fresh.revision = Uuid::new_v4();
        fresh.state.attempts = u32::MAX;
        assert!(
            store
                .compare_exchange_auth_rate_limit_state(key, None, fresh)
                .await
                .unwrap()
        );
    }
    assert_eq!(
        auth.login("expired@example.com", "wrong", metadata())
            .await
            .unwrap_err()
            .public_code(),
        "INVALID_CREDENTIALS"
    );
    for key in keys {
        let state = store
            .find_auth_rate_limit_state(&key)
            .await
            .unwrap()
            .unwrap()
            .state;
        assert_eq!(state.attempts, u32::MAX);
        assert_eq!(state.locked_until, Some(now + policy().lockout_duration));
    }
}

struct FailingRecordStore;
#[async_trait]
impl AuthRateLimitStore for FailingRecordStore {
    async fn find_auth_rate_limit_state(
        &self,
        _: &AuthRateLimitKey,
    ) -> crate::AuthResult<Option<AuthRateLimitSnapshot>> {
        Ok(None)
    }
    async fn compare_exchange_auth_rate_limit_state(
        &self,
        key: &AuthRateLimitKey,
        _: Option<Uuid>,
        _: AuthRateLimitSnapshot,
    ) -> crate::AuthResult<bool> {
        Err(AuthError::Store(format!(
            "private backend failure: {}",
            key.value_hash
        )))
    }
    async fn clear_auth_rate_limit_state(
        &self,
        _: &AuthRateLimitKey,
        _: Option<Uuid>,
    ) -> crate::AuthResult<bool> {
        panic!("rejections must not clear")
    }
}

#[tokio::test]
async fn rejection_store_errors_are_safe_and_issue_no_authority() {
    for case in ["unknown", "disabled", "enabled"] {
        let users = MemoryUserStore::default();
        let refresh = MemoryRefreshTokenStore::default();
        let auth = service(
            Arc::new(FailingRecordStore),
            users.clone(),
            refresh.clone(),
            Arc::new(FixedClock::new(OffsetDateTime::UNIX_EPOCH)),
            policy(),
        );
        let principal = "private@example.com";
        if case != "unknown" {
            let mut user = stored_user(&auth, case, principal, "correct");
            user.disabled = case == "disabled";
            users.insert(user);
        }
        let error = auth
            .login(principal, "private-password", metadata())
            .await
            .unwrap_err();
        assert_eq!(error.public_code(), "AUTH_SERVICE_UNAVAILABLE");
        assert_eq!(error.public_message(), "authentication service unavailable");
        let graphql = error.extend();
        assert_eq!(graphql.message, error.public_message());
        assert_eq!(
            graphql.extensions.unwrap().get("code"),
            Some(&async_graphql::Value::from("AUTH_SERVICE_UNAVAILABLE"))
        );
        assert!(
            error
                .internal_detail()
                .unwrap()
                .contains("private backend failure")
        );
        assert_eq!(auth.password_work.lock().unwrap().len(), 1);
        assert_no_authority(&auth, &refresh);
    }
}

#[tokio::test]
async fn disabled_work_and_public_error_are_preserved_without_rate_limits() {
    let users = MemoryUserStore::default();
    let refresh = MemoryRefreshTokenStore::default();
    let auth = service(
        Arc::new(MemoryAuthRateLimitStore::default()),
        users.clone(),
        refresh.clone(),
        Arc::new(FixedClock::new(OffsetDateTime::UNIX_EPOCH)),
        AuthRateLimitPolicy::disabled(),
    );
    let mut user = stored_user(&auth, "disabled", "disabled@example.com", "correct");
    user.disabled = true;
    users.insert(user.clone());
    for password in ["correct", "wrong"] {
        let error = auth
            .login(&user.principal, password, metadata())
            .await
            .unwrap_err();
        assert_eq!(error.public_code(), "USER_DISABLED");
        let graphql = error.extend();
        assert_eq!(graphql.message, "user is disabled");
        assert_eq!(
            graphql.extensions.unwrap().get("code"),
            Some(&async_graphql::Value::from("USER_DISABLED"))
        );
    }
    assert_eq!(auth.password_work.lock().unwrap().len(), 2);
    assert_no_authority(&auth, &refresh);
}

pub(super) async fn independent_buckets_contract<S: AuthRateLimitStore + 'static>(store: Arc<S>) {
    let users = MemoryUserStore::default();
    let refresh = MemoryRefreshTokenStore::default();
    let clock = Arc::new(FixedClock::new(
        OffsetDateTime::from_unix_timestamp(1_800_005_000).unwrap(),
    ));
    let auth = service(
        store.clone(),
        users.clone(),
        refresh.clone(),
        clock,
        policy(),
    );
    let mut disabled = stored_user(
        &auth,
        "bucket-disabled",
        "bucket-disabled@example.com",
        "correct",
    );
    disabled.disabled = true;
    users.insert(disabled.clone());
    users.insert(stored_user(
        &auth,
        "bucket-enabled",
        "bucket-enabled@example.com",
        "correct",
    ));
    assert_eq!(
        auth.login(&disabled.principal, "correct", metadata())
            .await
            .unwrap_err()
            .public_code(),
        "USER_DISABLED"
    );
    assert_eq!(
        auth.login("bucket-unknown@example.com", "wrong", metadata())
            .await
            .unwrap_err()
            .public_code(),
        "INVALID_CREDENTIALS"
    );
    // The shared client alone throttles a third, previously untouched principal.
    assert!(matches!(
        auth.login("bucket-enabled@example.com", "wrong", metadata())
            .await
            .unwrap_err(),
        AuthError::AuthThrottled { .. }
    ));
    assert_eq!(auth.password_work.lock().unwrap().len(), 2);
    let disabled_keys = keys(&auth, &disabled.principal);
    assert_eq!(
        store
            .find_auth_rate_limit_state(&disabled_keys[0])
            .await
            .unwrap()
            .unwrap()
            .state
            .attempts,
        1
    );
    assert_eq!(
        store
            .find_auth_rate_limit_state(&disabled_keys[1])
            .await
            .unwrap()
            .unwrap()
            .state
            .attempts,
        2
    );
    // A different client is admitted and activates principal-only backoff.
    let second_client = ClientMetadata {
        ip_address: Some("192.0.2.8".into()),
        ..Default::default()
    };
    assert_eq!(
        auth.login(&disabled.principal, "wrong", second_client)
            .await
            .unwrap_err()
            .public_code(),
        "USER_DISABLED"
    );
    let third_client = ClientMetadata {
        ip_address: Some("192.0.2.9".into()),
        ..Default::default()
    };
    assert!(matches!(
        auth.login(&disabled.principal, "correct", third_client)
            .await
            .unwrap_err(),
        AuthError::AuthThrottled { .. }
    ));
    assert_eq!(auth.password_work.lock().unwrap().len(), 3);
    assert_eq!(
        store
            .find_auth_rate_limit_state(&disabled_keys[0])
            .await
            .unwrap()
            .unwrap()
            .state
            .attempts,
        2
    );
    assert_no_authority(&auth, &refresh);
}
