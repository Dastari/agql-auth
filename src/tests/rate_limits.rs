use std::sync::Arc;

use async_trait::async_trait;
use data_encoding::BASE32_NOPAD;
use time::{Duration, OffsetDateTime};
use tokio::sync::{Barrier, Notify};
use uuid::Uuid;

use super::{
    MemoryLoginChallengeStore, MemoryPasswordResetStore, MemoryRefreshTokenStore, MemoryUserStore,
    TEST_HS256_SECRET, metadata, stored_user,
};
use crate::prelude::*;

#[derive(Clone, Default)]
struct BlockingClearRateLimitStore {
    inner: MemoryAuthRateLimitStore,
    clear_started: Arc<Notify>,
    continue_clear: Arc<Notify>,
}

#[async_trait]
impl AuthRateLimitStore for BlockingClearRateLimitStore {
    async fn find_auth_rate_limit_state(
        &self,
        key: &AuthRateLimitKey,
    ) -> crate::AuthResult<Option<AuthRateLimitSnapshot>> {
        self.inner.find_auth_rate_limit_state(key).await
    }

    async fn compare_exchange_auth_rate_limit_state(
        &self,
        key: &AuthRateLimitKey,
        expected_revision: Option<Uuid>,
        replacement: AuthRateLimitSnapshot,
    ) -> crate::AuthResult<bool> {
        self.inner
            .compare_exchange_auth_rate_limit_state(key, expected_revision, replacement)
            .await
    }

    async fn clear_auth_rate_limit_state(
        &self,
        key: &AuthRateLimitKey,
        expected_revision: Option<Uuid>,
    ) -> crate::AuthResult<bool> {
        self.clear_started.notify_one();
        self.continue_clear.notified().await;
        self.inner
            .clear_auth_rate_limit_state(key, expected_revision)
            .await
    }
}

#[tokio::test]
async fn password_login_locks_existing_and_missing_principals_without_distinguishing_them() {
    let user_store = MemoryUserStore::default();
    let refresh_store = MemoryRefreshTokenStore::default();
    let rate_store = Arc::new(MemoryAuthRateLimitStore::default());
    let auth = throttled_auth_service(
        user_store.clone(),
        refresh_store,
        rate_store,
        lockout_policy(),
    );
    user_store.insert(stored_user(
        &auth,
        "user-1",
        "alice@example.com",
        "password123",
    ));

    assert_password_login_sequence(&auth, "missing@example.com", "10.0.0.10").await;
    assert_password_login_sequence(&auth, "alice@example.com", "10.0.0.11").await;
}

#[tokio::test]
async fn password_login_rate_limits_by_client_across_principals_and_service_instances() {
    let user_store = MemoryUserStore::default();
    let refresh_store = MemoryRefreshTokenStore::default();
    let rate_store = Arc::new(MemoryAuthRateLimitStore::default());
    let auth = throttled_auth_service(
        user_store.clone(),
        refresh_store.clone(),
        rate_store.clone(),
        backoff_policy(),
    );
    user_store.insert(stored_user(
        &auth,
        "user-1",
        "alice@example.com",
        "password123",
    ));

    let first = auth
        .login("alice@example.com", "wrong", client_metadata("192.0.2.20"))
        .await
        .unwrap_err();
    assert!(matches!(first, AuthError::InvalidCredentials));

    let restarted_auth =
        throttled_auth_service(user_store, refresh_store, rate_store, backoff_policy());
    let second = restarted_auth
        .login("other@example.com", "wrong", client_metadata("192.0.2.20"))
        .await
        .unwrap_err();
    assert!(matches!(second, AuthError::AuthThrottled { .. }));
}

#[tokio::test]
async fn login_code_verification_locks_after_repeated_invalid_codes() {
    let auth = throttled_auth_service(
        MemoryUserStore::default(),
        MemoryRefreshTokenStore::default(),
        Arc::new(MemoryAuthRateLimitStore::default()),
        lockout_policy(),
    );
    let store = MemoryLoginChallengeStore::default();
    let issued = auth
        .create_login_challenge(&store, "alice@example.com", Default::default())
        .await
        .unwrap();

    for code in ["000000", "111111"] {
        let err = auth
            .verify_login_challenge_with_metadata(
                &store,
                issued.challenge_id,
                code,
                client_metadata("192.0.2.30"),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::InvalidLoginCode));
    }

    let locked = auth
        .verify_login_challenge_with_metadata(
            &store,
            issued.challenge_id,
            "222222",
            client_metadata("192.0.2.30"),
        )
        .await
        .unwrap_err();
    assert!(matches!(locked, AuthError::AuthLocked { .. }));
}

#[tokio::test]
async fn password_reset_token_consumption_locks_replay_attempts() {
    let auth = throttled_auth_service(
        MemoryUserStore::default(),
        MemoryRefreshTokenStore::default(),
        Arc::new(MemoryAuthRateLimitStore::default()),
        lockout_policy(),
    );
    let store = MemoryPasswordResetStore::default();
    let issued = auth
        .issue_password_reset_token_with_store(&store, "user-1", Duration::hours(1))
        .await
        .unwrap();

    auth.consume_password_reset_token_with_metadata(
        &store,
        &issued.token,
        client_metadata("192.0.2.40"),
    )
    .await
    .unwrap();

    for _ in 0..2 {
        let err = auth
            .consume_password_reset_token_with_metadata(
                &store,
                &issued.token,
                client_metadata("192.0.2.40"),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::PasswordResetTokenReplayed));
    }

    let locked = auth
        .consume_password_reset_token_with_metadata(
            &store,
            &issued.token,
            client_metadata("192.0.2.40"),
        )
        .await
        .unwrap_err();
    assert!(matches!(locked, AuthError::AuthLocked { .. }));
}

#[tokio::test]
async fn totp_verification_locks_after_repeated_invalid_codes() {
    let auth = throttled_auth_service(
        MemoryUserStore::default(),
        MemoryRefreshTokenStore::default(),
        Arc::new(MemoryAuthRateLimitStore::default()),
        lockout_policy(),
    );
    let secret = TotpSecret {
        raw_secret: b"12345678901234567890".to_vec(),
        base32_secret: BASE32_NOPAD.encode(b"12345678901234567890"),
    };
    let options = TotpOptions {
        digits: 8,
        period_seconds: 30,
        allowed_skew: 0,
    };
    let now = OffsetDateTime::from_unix_timestamp(59).unwrap();

    for code in ["00000000", "11111111"] {
        let err = auth
            .verify_totp_code_for_principal(
                "user-1",
                &secret.base32_secret,
                code,
                options.clone(),
                now,
                client_metadata("192.0.2.50"),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::InvalidTotpCode));
    }

    let locked = auth
        .verify_totp_code_for_principal(
            "user-1",
            &secret.base32_secret,
            "94287082",
            options,
            now,
            client_metadata("192.0.2.50"),
        )
        .await
        .unwrap_err();
    assert!(matches!(locked, AuthError::AuthLocked { .. }));
}

#[tokio::test]
async fn password_reset_requests_return_false_when_principal_is_locked() {
    let auth = request_throttled_auth_service(lockout_policy());

    assert!(
        auth.should_process_password_reset_request(
            "alice@example.com",
            client_metadata("192.0.2.60")
        )
        .await
        .unwrap()
    );
    assert!(
        auth.should_process_password_reset_request(
            "alice@example.com",
            client_metadata("192.0.2.61")
        )
        .await
        .unwrap()
    );

    let allowed = auth
        .should_process_password_reset_request("alice@example.com", client_metadata("192.0.2.62"))
        .await
        .unwrap();
    assert!(!allowed);
}

#[tokio::test]
async fn login_code_requests_return_false_when_client_is_throttled() {
    let auth = request_throttled_auth_service(backoff_policy());

    assert!(
        auth.should_process_login_code_request("alice@example.com", client_metadata("192.0.2.70"))
            .await
            .unwrap()
    );

    let allowed = auth
        .should_process_login_code_request("bob@example.com", client_metadata("192.0.2.70"))
        .await
        .unwrap();
    assert!(!allowed);
}

#[tokio::test]
async fn concurrent_request_attempts_across_two_services_lose_no_increments() {
    const ATTEMPTS: usize = 64;
    let store = Arc::new(MemoryAuthRateLimitStore::default());
    let clock = Arc::new(FixedClock::new(
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
    ));
    let policy = high_contention_policy();
    let first = Arc::new(request_service_with_clock(
        store.clone(),
        clock.clone(),
        policy.clone(),
    ));
    let second = Arc::new(request_service_with_clock(store.clone(), clock, policy));
    let barrier = Arc::new(Barrier::new(ATTEMPTS + 1));
    let mut tasks = Vec::with_capacity(ATTEMPTS);

    for index in 0..ATTEMPTS {
        let auth = if index % 2 == 0 {
            first.clone()
        } else {
            second.clone()
        };
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            auth.should_process_login_code_request(
                "alice@example.com",
                client_metadata("192.0.2.80"),
            )
            .await
        }));
    }

    barrier.wait().await;
    for task in tasks {
        assert!(task.await.unwrap().unwrap());
    }

    let keys = first.rate_limit_keys(
        AuthRateLimitFlow::LoginCodeRequest,
        Some("alice@example.com"),
        &client_metadata("192.0.2.80"),
    );
    assert_eq!(keys.len(), 2);
    for key in keys {
        assert_eq!(store.get(&key).unwrap().attempts, ATTEMPTS as u32);
    }
}

#[tokio::test]
async fn concurrent_request_admission_is_linearized_with_recording() {
    const REQUESTS: usize = 32;
    let store = Arc::new(MemoryAuthRateLimitStore::default());
    let clock = Arc::new(FixedClock::new(
        OffsetDateTime::from_unix_timestamp(1_800_000_100).unwrap(),
    ));
    let policy = backoff_policy();
    let first = Arc::new(request_service_with_clock(
        store.clone(),
        clock.clone(),
        policy.clone(),
    ));
    let second = Arc::new(request_service_with_clock(store.clone(), clock, policy));
    let barrier = Arc::new(Barrier::new(REQUESTS + 1));
    let mut tasks = Vec::with_capacity(REQUESTS);

    for index in 0..REQUESTS {
        let auth = if index % 2 == 0 {
            first.clone()
        } else {
            second.clone()
        };
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            auth.should_process_password_reset_request(
                "alice@example.com",
                ClientMetadata::default(),
            )
            .await
        }));
    }

    barrier.wait().await;
    let mut admitted = 0;
    for task in tasks {
        if task.await.unwrap().unwrap() {
            admitted += 1;
        }
    }
    assert_eq!(admitted, 1);

    let key = first
        .rate_limit_keys(
            AuthRateLimitFlow::PasswordResetRequest,
            Some("alice@example.com"),
            &ClientMetadata::default(),
        )
        .pop()
        .unwrap();
    assert_eq!(store.get(&key).unwrap().attempts, 1);
}

#[tokio::test]
async fn concurrent_credential_failures_across_two_services_lose_no_increments() {
    const ATTEMPTS: usize = 32;
    let store = Arc::new(MemoryAuthRateLimitStore::default());
    let clock = Arc::new(FixedClock::new(
        OffsetDateTime::from_unix_timestamp(1_800_000_200).unwrap(),
    ));
    let policy = high_contention_policy();
    let first = Arc::new(credential_service_with_clock(
        store.clone(),
        clock.clone(),
        policy.clone(),
    ));
    let second = Arc::new(credential_service_with_clock(store.clone(), clock, policy));
    let barrier = Arc::new(Barrier::new(ATTEMPTS + 1));
    let mut tasks = Vec::with_capacity(ATTEMPTS);

    for index in 0..ATTEMPTS {
        let auth = if index % 2 == 0 {
            first.clone()
        } else {
            second.clone()
        };
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            auth.verify_totp_code_for_principal(
                "user-atomic",
                &BASE32_NOPAD.encode(b"12345678901234567890"),
                "00000000",
                TotpOptions {
                    digits: 8,
                    period_seconds: 30,
                    allowed_skew: 0,
                },
                OffsetDateTime::from_unix_timestamp(59).unwrap(),
                ClientMetadata::default(),
            )
            .await
        }));
    }

    barrier.wait().await;
    for task in tasks {
        assert!(matches!(
            task.await.unwrap().unwrap_err(),
            AuthError::InvalidTotpCode
        ));
    }

    let key = first
        .rate_limit_keys(
            AuthRateLimitFlow::TotpVerification,
            Some("user-atomic"),
            &ClientMetadata::default(),
        )
        .pop()
        .unwrap();
    assert_eq!(store.get(&key).unwrap().attempts, ATTEMPTS as u32);
}

#[tokio::test]
async fn window_reset_and_clock_boundaries_use_the_injected_clock() {
    let store = Arc::new(MemoryAuthRateLimitStore::default());
    let start = OffsetDateTime::from_unix_timestamp(1_800_000_300).unwrap();
    let clock = Arc::new(FixedClock::new(start));
    let policy = high_contention_policy();
    let auth = request_service_with_clock(store.clone(), clock.clone(), policy.clone());
    let metadata = ClientMetadata::default();

    assert!(
        auth.should_process_login_code_request("alice@example.com", metadata.clone())
            .await
            .unwrap()
    );
    clock.advance_seconds(policy.window.whole_seconds());
    assert!(
        auth.should_process_login_code_request("alice@example.com", metadata.clone())
            .await
            .unwrap()
    );

    let key = auth
        .rate_limit_keys(
            AuthRateLimitFlow::LoginCodeRequest,
            Some("alice@example.com"),
            &metadata,
        )
        .pop()
        .unwrap();
    let state = store.get(&key).unwrap();
    assert_eq!(state.attempts, 1);
    assert_eq!(state.first_attempt_at, start + policy.window);
}

#[tokio::test]
async fn expired_snapshot_resets_atomically_without_unconditional_cleanup() {
    let store = Arc::new(MemoryAuthRateLimitStore::default());
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_350).unwrap();
    let clock = Arc::new(FixedClock::new(now));
    let policy = high_contention_policy();
    let auth = request_service_with_clock(store.clone(), clock, policy);
    let key = auth
        .rate_limit_keys(
            AuthRateLimitFlow::LoginCodeRequest,
            Some("alice@example.com"),
            &ClientMetadata::default(),
        )
        .pop()
        .unwrap();
    let expired = AuthRateLimitSnapshot {
        state: AuthRateLimitState {
            key: key.clone(),
            attempts: 42,
            first_attempt_at: now,
            last_attempt_at: now,
            backoff_until: Some(now + Duration::minutes(5)),
            locked_until: None,
            expires_at: now,
        },
        revision: Uuid::new_v4(),
    };
    assert!(
        store
            .compare_exchange_auth_rate_limit_state(&key, None, expired)
            .await
            .unwrap()
    );

    assert!(
        auth.should_process_login_code_request("alice@example.com", ClientMetadata::default(),)
            .await
            .unwrap()
    );
    let state = store.get(&key).unwrap();
    assert_eq!(state.attempts, 1);
    assert_eq!(state.first_attempt_at, now);
    assert!(state.backoff_until.is_none());
}

#[tokio::test]
async fn maximum_attempt_count_saturates_locked_and_time_overflow_fails_safely() {
    let store = Arc::new(MemoryAuthRateLimitStore::default());
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_400).unwrap();
    let clock = Arc::new(FixedClock::new(now));
    let mut policy = high_contention_policy();
    policy.backoff_after_attempts = u32::MAX;
    policy.max_attempts_before_lockout = u32::MAX;
    let auth = credential_service_with_clock(store.clone(), clock, policy.clone());
    let key = auth
        .rate_limit_keys(
            AuthRateLimitFlow::TotpVerification,
            Some("user-max"),
            &ClientMetadata::default(),
        )
        .pop()
        .unwrap();
    let initial = AuthRateLimitSnapshot {
        state: AuthRateLimitState {
            key: key.clone(),
            attempts: u32::MAX - 1,
            first_attempt_at: now,
            last_attempt_at: now,
            backoff_until: None,
            locked_until: None,
            expires_at: now + Duration::hours(1),
        },
        revision: Uuid::new_v4(),
    };
    assert!(
        store
            .compare_exchange_auth_rate_limit_state(&key, None, initial)
            .await
            .unwrap()
    );

    let error = auth
        .verify_totp_code_for_principal(
            "user-max",
            &BASE32_NOPAD.encode(b"12345678901234567890"),
            "00000000",
            TotpOptions {
                digits: 8,
                period_seconds: 30,
                allowed_skew: 0,
            },
            OffsetDateTime::from_unix_timestamp(59).unwrap(),
            ClientMetadata::default(),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, AuthError::InvalidTotpCode));
    let state = store.get(&key).unwrap();
    assert_eq!(state.attempts, u32::MAX);
    assert!(state.locked_until.is_some());

    let overflow_store = Arc::new(MemoryAuthRateLimitStore::default());
    let overflow_clock = Arc::new(FixedClock::new(
        OffsetDateTime::from_unix_timestamp(253_402_300_798).unwrap(),
    ));
    let overflow_auth =
        request_service_with_clock(overflow_store, overflow_clock, high_contention_policy());
    let error = overflow_auth
        .should_process_login_code_request("alice@example.com", ClientMetadata::default())
        .await
        .unwrap_err();
    assert!(matches!(error, AuthError::InvalidConfiguration(_)));
    assert_eq!(error.public_code(), "INVALID_CONFIGURATION");
}

#[tokio::test]
async fn stale_success_clear_cannot_erase_a_newer_failure() {
    let store = Arc::new(BlockingClearRateLimitStore::default());
    let clock = Arc::new(FixedClock::new(
        OffsetDateTime::from_unix_timestamp(1_800_000_500).unwrap(),
    ));
    let user_store = MemoryUserStore::default();
    let refresh_store = MemoryRefreshTokenStore::default();
    let policy = high_contention_policy();
    let first = Arc::new(service_with_clock(
        user_store.clone(),
        refresh_store.clone(),
        store.clone(),
        clock.clone(),
        policy.clone(),
        AuthRateLimitPolicy::disabled(),
    ));
    let second = Arc::new(service_with_clock(
        user_store.clone(),
        refresh_store,
        store.clone(),
        clock,
        policy,
        AuthRateLimitPolicy::disabled(),
    ));
    user_store.insert(stored_user(
        &first,
        "user-clear-race",
        "alice@example.com",
        "correct-password",
    ));

    assert!(matches!(
        first
            .login(
                "alice@example.com",
                "wrong-password",
                ClientMetadata::default(),
            )
            .await
            .unwrap_err(),
        AuthError::InvalidCredentials
    ));

    let successful = tokio::spawn({
        let first = first.clone();
        async move {
            first
                .login(
                    "alice@example.com",
                    "correct-password",
                    ClientMetadata::default(),
                )
                .await
        }
    });
    store.clear_started.notified().await;

    assert!(matches!(
        second
            .login(
                "alice@example.com",
                "wrong-password",
                ClientMetadata::default(),
            )
            .await
            .unwrap_err(),
        AuthError::InvalidCredentials
    ));
    store.continue_clear.notify_one();
    successful.await.unwrap().unwrap();

    let key = first
        .rate_limit_keys(
            AuthRateLimitFlow::PasswordLogin,
            Some("alice@example.com"),
            &ClientMetadata::default(),
        )
        .pop()
        .unwrap();
    assert_eq!(store.inner.get(&key).unwrap().attempts, 2);
}

#[tokio::test]
async fn memory_store_cas_contract_and_object_safety_are_locked() {
    let store = Arc::new(MemoryAuthRateLimitStore::default());
    let object_safe: Arc<dyn AuthRateLimitStore> = store.clone();
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_600).unwrap();
    let key = AuthRateLimitKey {
        flow: AuthRateLimitFlow::PasswordLogin,
        bucket: AuthRateLimitBucket::Principal,
        value_hash: "opaque-value-hash".to_string(),
    };
    let first_revision = Uuid::new_v4();
    let first = test_snapshot(key.clone(), first_revision, 1, now);
    let round_trip: AuthRateLimitSnapshot =
        serde_json::from_value(serde_json::to_value(&first).unwrap()).unwrap();
    assert_eq!(round_trip, first);
    assert!(
        object_safe
            .compare_exchange_auth_rate_limit_state(&key, None, first)
            .await
            .unwrap()
    );
    assert!(
        !object_safe
            .compare_exchange_auth_rate_limit_state(
                &key,
                None,
                test_snapshot(key.clone(), Uuid::new_v4(), 2, now),
            )
            .await
            .unwrap()
    );
    let second_revision = Uuid::new_v4();
    assert!(
        object_safe
            .compare_exchange_auth_rate_limit_state(
                &key,
                Some(first_revision),
                test_snapshot(key.clone(), second_revision, 2, now),
            )
            .await
            .unwrap()
    );
    assert!(
        !object_safe
            .clear_auth_rate_limit_state(&key, Some(first_revision))
            .await
            .unwrap()
    );
    assert!(
        object_safe
            .clear_auth_rate_limit_state(&key, Some(second_revision))
            .await
            .unwrap()
    );
    assert!(
        object_safe
            .find_auth_rate_limit_state(&key)
            .await
            .unwrap()
            .is_none()
    );

    let debug = format!("{key:?}");
    assert!(!debug.contains("opaque-value-hash"));
    let backend_error = AuthError::Store("backend included opaque-value-hash".to_string());
    assert!(!backend_error.public_message().contains("opaque-value-hash"));
    assert_eq!(backend_error.public_code(), "AUTH_SERVICE_UNAVAILABLE");
    assert_eq!(
        backend_error.internal_detail(),
        Some("backend included opaque-value-hash")
    );
}

async fn assert_password_login_sequence(
    auth: &AuthService<MemoryUserStore, MemoryRefreshTokenStore>,
    principal: &str,
    ip_address: &str,
) {
    for _ in 0..2 {
        let err = auth
            .login(principal, "wrong", client_metadata(ip_address))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::InvalidCredentials));
    }

    let locked = auth
        .login(principal, "wrong", client_metadata(ip_address))
        .await
        .unwrap_err();
    assert!(matches!(locked, AuthError::AuthLocked { .. }));
}

fn throttled_auth_service(
    user_store: MemoryUserStore,
    refresh_store: MemoryRefreshTokenStore,
    rate_store: Arc<MemoryAuthRateLimitStore>,
    credential_policy: AuthRateLimitPolicy,
) -> AuthService<MemoryUserStore, MemoryRefreshTokenStore> {
    let mut config = AuthConfig::new(TEST_HS256_SECRET);
    config.rate_limits.credential = credential_policy;
    AuthService::new_with_rate_limit_store(
        config,
        Arc::new(user_store),
        Arc::new(refresh_store),
        rate_store,
    )
    .unwrap()
}

fn request_throttled_auth_service(
    request_policy: AuthRateLimitPolicy,
) -> AuthService<MemoryUserStore, MemoryRefreshTokenStore> {
    let mut config = AuthConfig::new(TEST_HS256_SECRET);
    config.rate_limits.credential = AuthRateLimitPolicy::disabled();
    config.rate_limits.request = request_policy;
    AuthService::new_with_rate_limit_store(
        config,
        Arc::new(MemoryUserStore::default()),
        Arc::new(MemoryRefreshTokenStore::default()),
        Arc::new(MemoryAuthRateLimitStore::default()),
    )
    .unwrap()
}

fn request_service_with_clock(
    rate_store: Arc<MemoryAuthRateLimitStore>,
    clock: Arc<FixedClock>,
    request_policy: AuthRateLimitPolicy,
) -> AuthService<MemoryUserStore, MemoryRefreshTokenStore> {
    service_with_clock(
        MemoryUserStore::default(),
        MemoryRefreshTokenStore::default(),
        rate_store,
        clock,
        AuthRateLimitPolicy::disabled(),
        request_policy,
    )
}

fn credential_service_with_clock(
    rate_store: Arc<MemoryAuthRateLimitStore>,
    clock: Arc<FixedClock>,
    credential_policy: AuthRateLimitPolicy,
) -> AuthService<MemoryUserStore, MemoryRefreshTokenStore> {
    service_with_clock(
        MemoryUserStore::default(),
        MemoryRefreshTokenStore::default(),
        rate_store,
        clock,
        credential_policy,
        AuthRateLimitPolicy::disabled(),
    )
}

fn service_with_clock<S>(
    user_store: MemoryUserStore,
    refresh_store: MemoryRefreshTokenStore,
    rate_store: Arc<S>,
    clock: Arc<FixedClock>,
    credential_policy: AuthRateLimitPolicy,
    request_policy: AuthRateLimitPolicy,
) -> AuthService<MemoryUserStore, MemoryRefreshTokenStore>
where
    S: AuthRateLimitStore + 'static,
{
    let mut config = AuthConfig::new(TEST_HS256_SECRET);
    config.rate_limits.credential = credential_policy;
    config.rate_limits.request = request_policy;
    AuthService::new_with_rate_limit_store_and_clock(
        config,
        Arc::new(user_store),
        Arc::new(refresh_store),
        rate_store,
        clock,
    )
    .unwrap()
}

fn high_contention_policy() -> AuthRateLimitPolicy {
    AuthRateLimitPolicy {
        enabled: true,
        window: Duration::minutes(15),
        backoff_after_attempts: 1_000,
        max_attempts_before_lockout: 2_000,
        base_backoff: Duration::ZERO,
        max_backoff: Duration::ZERO,
        lockout_duration: Duration::minutes(5),
        state_ttl: Duration::hours(1),
    }
}

fn test_snapshot(
    key: AuthRateLimitKey,
    revision: Uuid,
    attempts: u32,
    now: OffsetDateTime,
) -> AuthRateLimitSnapshot {
    AuthRateLimitSnapshot {
        state: AuthRateLimitState {
            key,
            attempts,
            first_attempt_at: now,
            last_attempt_at: now,
            backoff_until: None,
            locked_until: None,
            expires_at: now + Duration::hours(1),
        },
        revision,
    }
}

fn lockout_policy() -> AuthRateLimitPolicy {
    AuthRateLimitPolicy {
        enabled: true,
        window: Duration::minutes(15),
        backoff_after_attempts: 1,
        max_attempts_before_lockout: 2,
        base_backoff: Duration::ZERO,
        max_backoff: Duration::ZERO,
        lockout_duration: Duration::minutes(5),
        state_ttl: Duration::hours(1),
    }
}

fn backoff_policy() -> AuthRateLimitPolicy {
    AuthRateLimitPolicy {
        enabled: true,
        window: Duration::minutes(15),
        backoff_after_attempts: 1,
        max_attempts_before_lockout: 10,
        base_backoff: Duration::minutes(1),
        max_backoff: Duration::minutes(10),
        lockout_duration: Duration::minutes(5),
        state_ttl: Duration::hours(1),
    }
}

fn client_metadata(ip_address: &str) -> ClientMetadata {
    ClientMetadata {
        ip_address: Some(ip_address.to_string()),
        ..metadata()
    }
}
