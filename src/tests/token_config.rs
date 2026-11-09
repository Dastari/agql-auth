use std::sync::Arc;

use time::{Duration, OffsetDateTime};

use super::{MemoryRefreshTokenStore, MemoryUserStore, TEST_HS256_SECRET, metadata};
use crate::prelude::*;

fn build(config: AuthConfig) -> AuthResult<AuthService<MemoryUserStore, MemoryRefreshTokenStore>> {
    AuthService::new(
        config,
        Arc::new(MemoryUserStore::default()),
        Arc::new(MemoryRefreshTokenStore::default()),
    )
}

use crate::AuthResult;

#[test]
fn access_token_ttl_may_not_exceed_the_configured_maximum() {
    let mut config = AuthConfig::new(TEST_HS256_SECRET);
    config.access_token_ttl = config.max_access_token_ttl + Duration::seconds(1);
    assert!(matches!(
        build(config.clone()),
        Err(AuthError::InvalidConfiguration(_))
    ));

    config.access_token_ttl = config.max_access_token_ttl;
    assert!(build(config).is_ok());
}

#[tokio::test]
async fn user_principal_exposes_its_access_token_expiry() {
    let auth = build(AuthConfig::new(TEST_HS256_SECRET)).unwrap();
    let payload = auth
        .issue_verified_user_session("user-1", vec![], AuthMethod::Password, metadata())
        .await
        .unwrap();
    let user = auth
        .authenticate_access_token(&payload.access_token)
        .unwrap();
    let expected =
        OffsetDateTime::from_unix_timestamp(payload.access_token_expires_at.unix_timestamp())
            .unwrap();
    assert_eq!(user.token_claims.expires_at, Some(expected));
    assert_eq!(AuthPrincipal::User(user).expires_at(), Some(expected));

    assert_eq!(
        AuthPrincipal::User(AuthUser {
            user_id: "u".into(),
            session_id: uuid::Uuid::new_v4(),
            roles: vec![],
            scopes: vec![],
            session: SessionContext::default(),
            token_claims: AccessTokenMetadata::default(),
        })
        .expires_at(),
        None
    );
}

#[test]
fn hs256_minimum_secret_length_is_enforced_on_every_path() {
    let short = "s".repeat(31);
    assert!(matches!(
        build(AuthConfig::new(short.clone())),
        Err(AuthError::InvalidConfiguration(_))
    ));
    assert!(matches!(
        crate::keys::StaticHs256Key::from_secret(&short, None),
        Err(AuthError::InvalidConfiguration(_))
    ));
    assert!(matches!(
        AccessTokenValidator::builder()
            .issuer("agql-auth")
            .audience("agql-auth-clients")
            .accept_hs256(true)
            .hs256_secret(short)
            .build(),
        Err(AuthError::InvalidConfiguration(_))
    ));
    let exact = "s".repeat(32);
    assert!(build(AuthConfig::new(exact.clone())).is_ok());
    assert!(crate::keys::StaticHs256Key::from_secret(&exact, None).is_ok());
}
