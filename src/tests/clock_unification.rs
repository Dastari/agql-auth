//! One injected clock governs every time decision of a service: issuance,
//! service-side validation, logout, revocation, purpose and reset tokens, and
//! API tokens. Before 0.27 these read the system clock while rotation used the
//! injected one.

use std::sync::Arc;

use time::{Duration, OffsetDateTime};

use super::{
    MemoryApiTokenStore, MemoryPasswordResetStore, MemoryRefreshTokenStore, MemoryUserStore,
    metadata, stored_user, test_auth_service,
};
use crate::prelude::*;
use crate::util::hash_refresh_token;

/// A fixed instant far from real time, so any system-clock read is visible.
fn epoch() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_000_000_000).unwrap()
}

fn service(
    clock: &FixedClock,
) -> (
    AuthService<MemoryUserStore, MemoryRefreshTokenStore>,
    MemoryRefreshTokenStore,
) {
    let users = MemoryUserStore::default();
    let refresh = MemoryRefreshTokenStore::default();
    // The 0.26 setter: it must now cover issuance and validation as well.
    let auth = test_auth_service(users.clone(), refresh.clone())
        .with_refresh_rotation_clock(Arc::new(clock.clone()));
    users.insert(stored_user(
        &auth,
        "user-1",
        "alice@example.com",
        "password123",
    ));
    (auth, refresh)
}

#[tokio::test]
async fn login_issues_and_validates_on_the_session_clock() {
    let clock = FixedClock::new(epoch());
    let (auth, refresh) = service(&clock);
    let payload = auth
        .login("alice@example.com", "password123", metadata())
        .await
        .unwrap();

    let header_claims: serde_json::Value = serde_json::from_slice(
        &base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            payload.access_token.split('.').nth(1).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(header_claims["iat"], epoch().unix_timestamp());

    // Valid at the injected instant although it is long past in real time.
    auth.authenticate_access_token(&payload.access_token)
        .expect("validation uses the session clock");
    let stored = refresh
        .find_refresh_token_by_hash(&hash_refresh_token(&payload.refresh_token))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.created_at, epoch());

    clock.advance_seconds(Duration::days(1).whole_seconds());
    assert!(matches!(
        auth.authenticate_access_token(&payload.access_token),
        Err(AuthError::AccessTokenExpired)
    ));

    auth.logout(&payload.refresh_token, true).await.unwrap();
    let revoked = refresh
        .find_refresh_token_by_hash(&hash_refresh_token(&payload.refresh_token))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(revoked.revoked_at, Some(clock.now()));
}

#[tokio::test]
async fn purpose_and_reset_tokens_use_the_session_clock() {
    let clock = FixedClock::new(epoch());
    let (auth, _refresh) = service(&clock);

    let purpose = auth
        .issue_purpose_token(PurposeTokenIssueRequest::new(
            "user-1",
            "capture_upload",
            "capture-clients",
            Duration::minutes(5),
        ))
        .unwrap();
    let resets = MemoryPasswordResetStore::default();
    let reset = auth
        .issue_password_reset_token_with_store(&resets, "user-1", Duration::minutes(5))
        .await
        .unwrap();

    auth.authenticate_purpose_token(
        &purpose.token,
        PurposeTokenValidation::new("capture_upload", "capture-clients"),
    )
    .expect("purpose token is valid at the injected instant");
    assert_eq!(
        auth.authenticate_password_reset_token(&reset.token)
            .unwrap()
            .issued_at,
        epoch()
    );

    clock.advance_seconds(Duration::minutes(6).whole_seconds());
    assert!(matches!(
        auth.authenticate_purpose_token(
            &purpose.token,
            PurposeTokenValidation::new("capture_upload", "capture-clients"),
        ),
        Err(AuthError::PurposeTokenExpired)
    ));
    assert!(matches!(
        auth.authenticate_password_reset_token(&reset.token),
        Err(AuthError::PasswordResetTokenExpired)
    ));
}

#[tokio::test]
async fn with_clock_sets_the_session_and_challenge_clocks() {
    let clock = FixedClock::new(epoch());
    let users = MemoryUserStore::default();
    let auth = test_auth_service(users.clone(), MemoryRefreshTokenStore::default())
        .with_clock(Arc::new(clock.clone()));
    users.insert(stored_user(
        &auth,
        "user-1",
        "alice@example.com",
        "password123",
    ));
    let payload = auth
        .login("alice@example.com", "password123", metadata())
        .await
        .unwrap();
    auth.authenticate_access_token(&payload.access_token)
        .unwrap();
    let challenges = super::MemoryLoginChallengeStore::default();
    let challenge = auth
        .create_login_challenge(&challenges, "user-1", LoginChallengeOptions::default())
        .await
        .unwrap();
    assert_eq!(
        challenge.expires_at,
        epoch() + LoginChallengeOptions::default().ttl
    );
}

#[tokio::test]
async fn api_tokens_use_the_injected_clock() {
    let clock = FixedClock::new(epoch());
    let service = ApiTokenService::new(Arc::new(MemoryApiTokenStore::default()))
        .with_clock(Arc::new(clock.clone()));
    let issued = service
        .issue_token(ApiTokenIssueRequest::new(
            "sync",
            "svc-sync",
            ApiTokenPrincipalKind::service(),
            Duration::days(1),
        ))
        .await
        .unwrap();
    assert_eq!(issued.expires_at, epoch() + Duration::days(1));
    service
        .authenticate_token(&issued.token, ClientMetadata::default())
        .await
        .expect("valid at the injected instant");

    clock.advance_seconds(Duration::days(2).whole_seconds());
    assert!(matches!(
        service
            .authenticate_token(&issued.token, ClientMetadata::default())
            .await,
        Err(AuthError::ApiTokenExpired)
    ));
}
