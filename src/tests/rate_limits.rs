use std::sync::Arc;

use data_encoding::BASE32_NOPAD;
use time::{Duration, OffsetDateTime};

use super::{
    MemoryLoginChallengeStore, MemoryPasswordResetStore, MemoryRefreshTokenStore, MemoryUserStore,
    TEST_HS256_SECRET, metadata, stored_user,
};
use crate::prelude::*;

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
