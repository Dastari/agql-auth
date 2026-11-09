//! Absolute session lifetime and user-wide refresh revocation.
use std::sync::Arc;

use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::refresh_reuse_grace::seed_record;
use super::{MemoryRefreshTokenStore, MemoryUserStore, TEST_HS256_SECRET, metadata, stored_user};
use crate::prelude::*;
use crate::util::hash_refresh_token;

const USER_ID: &str = "user-1";

struct Session {
    auth: AuthService<MemoryUserStore, MemoryRefreshTokenStore>,
    store: MemoryRefreshTokenStore,
    clock: FixedClock,
    login: OffsetDateTime,
}

/// A one-day refresh token in a session that may last at most two days.
fn session(max_session_lifetime: Option<Duration>, grace: bool) -> Session {
    let users = MemoryUserStore::default();
    users.insert(StoredUser {
        id: USER_ID.to_string(),
        principal: "alice@example.com".to_string(),
        password_hash: "unused".to_string(),
        roles: vec!["member".to_string(), "editor".to_string()],
        scopes: vec!["records.read".to_string(), "records.write".to_string()],
        disabled: false,
    });
    let store = MemoryRefreshTokenStore::default();
    let mut config = AuthConfig::new(TEST_HS256_SECRET);
    config.refresh_token_ttl = Duration::days(1);
    config.max_session_lifetime = max_session_lifetime;
    let login = OffsetDateTime::now_utc();
    let clock = FixedClock::new(login);
    let mut auth = AuthService::new(config, Arc::new(users), Arc::new(store.clone()))
        .unwrap()
        .with_refresh_rotation_clock(Arc::new(clock.clone()));
    if grace {
        auth = auth
            .with_refresh_reuse_grace(Duration::seconds(10))
            .unwrap();
    }
    Session {
        auth,
        store,
        clock,
        login,
    }
}

impl Session {
    async fn seed(&self, raw: &str, session_expires_at: Option<OffsetDateTime>) {
        let mut record = seed_record(raw, Uuid::new_v4(), Uuid::new_v4(), self.login);
        record.expires_at = self.login + Duration::days(1);
        record.session_expires_at = session_expires_at;
        self.store.insert_refresh_token(record).await.unwrap();
    }

    fn at(&self, hours: i64) {
        self.clock.set(self.login + Duration::hours(hours));
    }

    async fn refresh(&self, raw: &str) -> crate::AuthResult<AuthPayload> {
        self.auth.refresh(raw, metadata()).await
    }

    fn record(&self, raw: &str) -> StoredRefreshToken {
        self.store.get_by_hash(&hash_refresh_token(raw)).unwrap()
    }
}

#[tokio::test]
async fn rotation_never_extends_a_session_past_its_absolute_lifetime() {
    let s = session(Some(Duration::days(2)), false);
    let deadline = s.login + Duration::days(2);
    s.seed("seed", Some(deadline)).await;

    s.at(20);
    let second = s.refresh("seed").await.unwrap();
    assert_eq!(
        second.refresh_token_expires_at,
        s.login + Duration::hours(44)
    );
    assert_eq!(
        s.record(&second.refresh_token).session_expires_at,
        Some(deadline),
        "rotation carries the deadline unchanged"
    );

    s.at(40);
    let third = s.refresh(&second.refresh_token).await.unwrap();
    assert_eq!(third.refresh_token_expires_at, deadline);

    s.clock.set(deadline);
    assert!(matches!(
        s.refresh(&third.refresh_token).await,
        Err(AuthError::RefreshTokenExpired)
    ));
}

#[tokio::test]
async fn login_sets_the_absolute_deadline_from_the_configured_lifetime() {
    let users = MemoryUserStore::default();
    let store = MemoryRefreshTokenStore::default();
    let mut config = AuthConfig::new(TEST_HS256_SECRET);
    config.max_session_lifetime = Some(Duration::hours(12));
    let auth = AuthService::new(config, Arc::new(users.clone()), Arc::new(store.clone())).unwrap();
    users.insert(stored_user(
        &auth,
        USER_ID,
        "alice@example.com",
        "password123",
    ));

    let before = OffsetDateTime::now_utc();
    let payload = auth
        .login("alice@example.com", "password123", metadata())
        .await
        .unwrap();
    let after = OffsetDateTime::now_utc();
    let record = store
        .get_by_hash(&hash_refresh_token(&payload.refresh_token))
        .unwrap();
    let deadline = record.session_expires_at.unwrap();
    assert!(deadline >= before + Duration::hours(12) && deadline <= after + Duration::hours(12));
    assert_eq!(
        payload.refresh_token_expires_at, deadline,
        "a refresh token never outlives its session"
    );
}

#[test]
fn the_default_lifetime_is_bounded_and_zero_is_refused() {
    let config = AuthConfig::new(TEST_HS256_SECRET);
    assert_eq!(config.max_session_lifetime, Some(Duration::days(90)));

    for lifetime in [Duration::ZERO, Duration::seconds(-1)] {
        let mut config = AuthConfig::new(TEST_HS256_SECRET);
        config.max_session_lifetime = Some(lifetime);
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

/// A record without a persisted deadline, from before 0.27 or from a store
/// that does not persist the field, can be rotated but never extended.
#[tokio::test]
async fn a_record_without_a_deadline_is_not_extended_past_its_expiry() {
    let s = session(Some(Duration::days(2)), false);
    s.seed("legacy", None).await;

    s.at(20);
    let next = s.refresh("legacy").await.unwrap();
    assert_eq!(next.refresh_token_expires_at, s.login + Duration::days(1));
    assert_eq!(
        s.record(&next.refresh_token).session_expires_at,
        Some(s.login + Duration::days(1))
    );
}

#[tokio::test]
async fn without_a_lifetime_rotation_slides_and_a_recorded_deadline_still_holds() {
    let s = session(None, false);
    s.seed("sliding", None).await;
    s.at(20);
    let next = s.refresh("sliding").await.unwrap();
    assert_eq!(next.refresh_token_expires_at, s.login + Duration::hours(44));
    assert_eq!(s.record(&next.refresh_token).session_expires_at, None);

    let deadline = s.login + Duration::hours(30);
    s.seed("bounded", Some(deadline)).await;
    let next = s.refresh("bounded").await.unwrap();
    assert_eq!(next.refresh_token_expires_at, deadline);
}

#[tokio::test]
async fn a_grace_reuse_keeps_the_deadline() {
    let s = session(Some(Duration::days(2)), true);
    let deadline = s.login + Duration::hours(30);
    s.seed("seed", Some(deadline)).await;

    s.at(20);
    let _second = s.refresh("seed").await.unwrap();
    s.clock.advance_seconds(1);
    let reused = s.refresh("seed").await.unwrap();
    assert_eq!(reused.refresh_token_expires_at, deadline);
    assert_eq!(
        s.record(&reused.refresh_token).session_expires_at,
        Some(deadline)
    );
}

#[tokio::test]
async fn revoking_a_users_sessions_ends_every_family_of_that_user_only() {
    let s = session(Some(Duration::days(2)), false);
    s.seed("first", None).await;
    s.seed("second", None).await;
    let mut other = seed_record("other", Uuid::new_v4(), Uuid::new_v4(), s.login);
    other.user_id = "user-2".to_string();
    s.store.insert_refresh_token(other).await.unwrap();
    s.at(1);
    let rotated = s.refresh("second").await.unwrap();

    let revoked = s
        .auth
        .revoke_user_sessions(USER_ID, RefreshTokenRevocationReason::AdminRevoked)
        .await
        .unwrap();
    assert_eq!(revoked, 2, "the two live tokens of the user");

    for raw in ["first", rotated.refresh_token.as_str()] {
        assert!(s.record(raw).is_revoked());
        assert!(s.refresh(raw).await.is_err());
    }
    assert!(!s.record("other").is_revoked());
    assert_eq!(
        s.auth
            .revoke_user_sessions(USER_ID, RefreshTokenRevocationReason::AdminRevoked)
            .await
            .unwrap(),
        0
    );
}
