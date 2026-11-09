//! Password length cap, configurable Argon2 parameters and the rehash signal.
use std::sync::Arc;

use super::{MemoryRefreshTokenStore, MemoryUserStore, TEST_HS256_SECRET, metadata};
use crate::prelude::*;
use crate::{DEFAULT_MAX_PASSWORD_BYTES, MAX_PASSWORD_BYTES_LIMIT, PasswordHashingConfig};

type Service = AuthService<MemoryUserStore, MemoryRefreshTokenStore>;

/// Cheap parameters, so the tests stay fast in debug builds.
fn light() -> PasswordHashingConfig {
    PasswordHashingConfig {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
        ..PasswordHashingConfig::default()
    }
}

fn service(hashing: PasswordHashingConfig, users: &MemoryUserStore) -> Service {
    let mut config = AuthConfig::new(TEST_HS256_SECRET);
    config.password_hashing = hashing;
    AuthService::new(
        config,
        Arc::new(users.clone()),
        Arc::new(MemoryRefreshTokenStore::default()),
    )
    .unwrap()
}

fn user(auth: &Service, password: &str) -> StoredUser {
    StoredUser {
        id: "user-1".to_string(),
        principal: "alice@example.com".to_string(),
        password_hash: auth.hash_password(password).unwrap(),
        roles: vec![],
        scopes: vec![],
        disabled: false,
    }
}

#[test]
fn the_defaults_are_the_owasp_minimum_with_a_one_kib_cap() {
    let defaults = PasswordHashingConfig::default();
    assert_eq!(defaults.max_password_bytes, DEFAULT_MAX_PASSWORD_BYTES);
    assert_eq!(DEFAULT_MAX_PASSWORD_BYTES, 1024);
    assert_eq!(
        (
            defaults.memory_kib,
            defaults.iterations,
            defaults.parallelism
        ),
        (19_456, 2, 1)
    );
}

#[test]
fn hashing_refuses_a_password_over_the_cap_and_accepts_one_at_it() {
    let users = MemoryUserStore::default();
    let auth = service(
        PasswordHashingConfig {
            max_password_bytes: 16,
            ..light()
        },
        &users,
    );
    assert!(auth.hash_password(&"a".repeat(16)).is_ok());
    let error = auth.hash_password(&"a".repeat(17)).unwrap_err();
    assert!(matches!(error, AuthError::PasswordTooLong));
    assert_eq!(error.public_code(), "PASSWORD_TOO_LONG");
    // The cap is in bytes, not characters.
    assert!(matches!(
        auth.hash_password(&"é".repeat(9)),
        Err(AuthError::PasswordTooLong)
    ));
}

#[tokio::test]
async fn an_over_long_login_is_a_counted_wrong_password_without_argon_work() {
    let users = MemoryUserStore::default();
    let auth = service(
        PasswordHashingConfig {
            max_password_bytes: 16,
            ..light()
        },
        &users,
    );
    users.insert(user(&auth, "correct"));
    let long = "a".repeat(1 << 20);
    for (principal, user_id) in [
        ("alice@example.com", Some("user-1")),
        ("unknown@example.com", None),
    ] {
        auth.password_work.lock().unwrap().clear();
        assert!(matches!(
            auth.login(principal, &long, metadata()).await,
            Err(AuthError::InvalidCredentials)
        ));
        assert!(
            auth.password_work.lock().unwrap().is_empty(),
            "no Argon2 work for an over-long password"
        );
        // Known accounts are counted by user ID, unknown ones by principal.
        let keys = auth.password_login_rate_limit_keys(principal, user_id, &metadata());
        let principal_key = keys
            .iter()
            .find(|key| key.bucket == crate::AuthRateLimitBucket::Principal)
            .unwrap();
        assert!(
            auth.rate_limit_store
                .find_auth_rate_limit_state(principal_key)
                .await
                .unwrap()
                .is_some(),
            "the attempt counts as a credential failure"
        );
    }
    assert!(matches!(
        auth.verify_password(&long, &users_hash(&users)),
        Err(AuthError::InvalidCredentials)
    ));
    assert!(
        auth.login("alice@example.com", "correct", metadata())
            .await
            .is_ok()
    );
}

fn users_hash(users: &MemoryUserStore) -> String {
    futures_block_on(users.find_user_by_id("user-1"))
        .unwrap()
        .unwrap()
        .password_hash
}

fn futures_block_on<F: std::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => panic!("memory store is synchronous"),
    }
}

#[tokio::test]
async fn new_hashes_use_the_configured_parameters_and_unknown_users_match_their_cost() {
    let users = MemoryUserStore::default();
    let auth = service(light(), &users);
    let stored = user(&auth, "correct");
    assert!(
        stored.password_hash.contains("m=64,t=1,p=1"),
        "{}",
        stored.password_hash
    );
    users.insert(stored);
    assert!(
        auth.login("alice@example.com", "correct", metadata())
            .await
            .is_ok()
    );

    auth.password_work.lock().unwrap().clear();
    assert!(matches!(
        auth.login("unknown@example.com", "guess", metadata()).await,
        Err(AuthError::InvalidCredentials)
    ));
    let work = auth.password_work.lock().unwrap().clone();
    assert_eq!(work.len(), 1);
    assert!(
        work[0].contains("m=64,t=1,p=1"),
        "the dummy verification costs what a current user's does: {}",
        work[0]
    );
}

#[test]
fn the_rehash_signal_flags_other_parameters_and_unparseable_hashes() {
    let users = MemoryUserStore::default();
    let current = service(light(), &users);
    let stronger = service(
        PasswordHashingConfig {
            memory_kib: 128,
            ..light()
        },
        &users,
    );
    let hash = current.hash_password("secret").unwrap();
    assert!(!current.password_hash_needs_rehash(&hash));
    assert!(stronger.password_hash_needs_rehash(&hash));
    assert!(!stronger.password_hash_needs_rehash(&stronger.hash_password("secret").unwrap()));
    assert!(current.password_hash_needs_rehash("not a hash"));
    // Same costs, other variant.
    assert!(current.password_hash_needs_rehash(
        "$argon2i$v=19$m=64,t=1,p=1$YWdxbC1hdXRoLWR1bW15LXNsdA$8ClNuSX6M3l/dalOcz8a117s1wLv/AbzbJiKA7dS4Ak"
    ));
}

#[test]
fn invalid_hashing_configuration_is_refused() {
    for hashing in [
        PasswordHashingConfig {
            max_password_bytes: 0,
            ..light()
        },
        PasswordHashingConfig {
            max_password_bytes: MAX_PASSWORD_BYTES_LIMIT + 1,
            ..light()
        },
        PasswordHashingConfig {
            memory_kib: 0,
            ..light()
        },
        PasswordHashingConfig {
            iterations: 0,
            ..light()
        },
        PasswordHashingConfig {
            parallelism: 0,
            ..light()
        },
    ] {
        let mut config = AuthConfig::new(TEST_HS256_SECRET);
        config.password_hashing = hashing;
        assert!(matches!(
            AuthService::new(
                config,
                Arc::new(MemoryUserStore::default()),
                Arc::new(MemoryRefreshTokenStore::default()),
            ),
            Err(AuthError::InvalidConfiguration(_))
        ));
    }
}
