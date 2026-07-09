use std::sync::Arc;

use time::{Duration, OffsetDateTime};

use super::jwt_signing::RSA_PUBLIC_KEY_A;
use super::validator::rs256_config;
use super::{MemoryRefreshTokenStore, MemoryUserStore};
use crate::prelude::*;

#[tokio::test]
async fn issue_access_token_only_validates_without_refresh_row() {
    let refresh_store = MemoryRefreshTokenStore::default();
    let auth = AuthService::new(
        rs256_config(),
        Arc::new(MemoryUserStore::default()),
        Arc::new(refresh_store.clone()),
    )
    .unwrap();

    let grant = auth.issue_access_token_only(request(None)).await.unwrap();

    assert_eq!(grant.user.user_id, "device-user-1");
    assert_eq!(grant.user.roles, vec!["Device".to_string()]);
    assert_eq!(
        grant.user.scopes,
        vec!["devices.read".to_string(), "devices.write".to_string()]
    );
    assert!(
        refresh_store.tokens_by_id.lock().unwrap().is_empty(),
        "access-token-only must not insert refresh tokens"
    );

    let decoded = auth.authenticate_access_token(&grant.access_token).unwrap();
    assert_eq!(decoded, grant.user);

    let validator = AccessTokenValidator::builder()
        .issuer("agql-auth")
        .audience("agql-auth-clients")
        .rs256_public_pem(RSA_PUBLIC_KEY_A)
        .key_id("auth-key-1")
        .build()
        .unwrap();
    let validated = validator
        .authenticate_access_token(&grant.access_token)
        .unwrap();
    assert_eq!(validated, grant.user);
}

#[tokio::test]
async fn issue_access_token_only_respects_custom_ttl() {
    let auth = AuthService::new(
        rs256_config(),
        Arc::new(MemoryUserStore::default()),
        Arc::new(MemoryRefreshTokenStore::default()),
    )
    .unwrap();
    let before = OffsetDateTime::now_utc();

    let grant = auth
        .issue_access_token_only(request(Some(Duration::minutes(5))))
        .await
        .unwrap();

    let lower = before + Duration::minutes(5) - Duration::seconds(2);
    let upper = OffsetDateTime::now_utc() + Duration::minutes(5) + Duration::seconds(2);
    assert!(grant.access_token_expires_at >= lower);
    assert!(grant.access_token_expires_at <= upper);
}

#[tokio::test]
async fn issue_access_token_only_rejects_empty_subject_and_non_positive_ttl() {
    let auth = AuthService::new(
        rs256_config(),
        Arc::new(MemoryUserStore::default()),
        Arc::new(MemoryRefreshTokenStore::default()),
    )
    .unwrap();

    let mut empty_subject = request(None);
    empty_subject.user_id = " ".to_string();
    assert!(matches!(
        auth.issue_access_token_only(empty_subject)
            .await
            .unwrap_err(),
        AuthError::InvalidConfiguration(_)
    ));

    assert!(matches!(
        auth.issue_access_token_only(request(Some(Duration::ZERO)))
            .await
            .unwrap_err(),
        AuthError::InvalidConfiguration(_)
    ));
}

fn request(ttl: Option<Duration>) -> AccessTokenOnlyRequest {
    AccessTokenOnlyRequest {
        user_id: "device-user-1".to_string(),
        roles: vec!["Device".to_string()],
        scopes: vec!["devices.read".to_string(), "devices.write".to_string()],
        session: SessionContext::for_auth_method(AuthMethod::ServiceToken),
        ttl,
    }
}
