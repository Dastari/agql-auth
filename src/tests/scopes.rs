use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;
use time::OffsetDateTime;

use super::{
    MemoryRefreshTokenStore, MemoryUserStore, TEST_HS256_SECRET, metadata, stored_user,
    test_auth_service,
};
use crate::prelude::*;

#[derive(Serialize)]
struct LegacyAccessTokenClaims {
    sub: String,
    sid: String,
    roles: Vec<String>,
    ctx: SessionContext,
    iss: String,
    aud: String,
    exp: i64,
    iat: i64,
}

#[tokio::test]
async fn access_tokens_round_trip_scopes() {
    let auth = test_auth_service(Default::default(), Default::default());
    let payload = auth
        .issue_verified_user_session_with_scopes(
            "user-1",
            vec!["Operator".to_string()],
            vec![
                "global.admin".to_string(),
                "collection.collection-1.media.write".to_string(),
            ],
            AuthMethod::EmailCode,
            metadata(),
        )
        .await
        .unwrap();

    let decoded = auth
        .authenticate_access_token(&payload.access_token)
        .unwrap();
    assert_eq!(decoded.scopes, payload.user.scopes);
    assert!(decoded.has_scope("global.admin"));
    assert!(decoded.has_all_scopes(&["global.admin", "collection.collection-1.media.write"]));
    assert!(decoded.has_any_scope(&["audit.read", "global.admin"]));
}

#[test]
fn legacy_access_tokens_without_scopes_decode_to_empty_scopes() {
    let auth = test_auth_service(Default::default(), Default::default());
    let issued_at = OffsetDateTime::now_utc();
    let expires_at = issued_at + time::Duration::minutes(15);
    let session_id = uuid::Uuid::new_v4();
    let token = encode(
        &Header::new(Algorithm::HS256),
        &LegacyAccessTokenClaims {
            sub: "legacy-user".to_string(),
            sid: session_id.to_string(),
            roles: vec!["CatalogEditor".to_string()],
            ctx: SessionContext::for_auth_method(AuthMethod::Password),
            iss: "agql-auth".to_string(),
            aud: "agql-auth-clients".to_string(),
            exp: expires_at.unix_timestamp(),
            iat: issued_at.unix_timestamp(),
        },
        &EncodingKey::from_secret(TEST_HS256_SECRET.as_bytes()),
    )
    .unwrap();

    let decoded = auth.authenticate_access_token(&token).unwrap();
    assert_eq!(decoded.user_id, "legacy-user");
    assert_eq!(decoded.roles, vec!["CatalogEditor".to_string()]);
    assert!(decoded.scopes.is_empty());
}

#[tokio::test]
async fn scope_helpers_support_exact_matches_only() {
    let user_store = MemoryUserStore::default();
    let refresh_store = MemoryRefreshTokenStore::default();
    let auth = test_auth_service(user_store.clone(), refresh_store);
    user_store.insert(stored_user(
        &auth,
        "user-1",
        "alice@example.com",
        "password123",
    ));

    let payload = auth
        .login("alice@example.com", "password123", metadata())
        .await
        .unwrap();

    assert!(has_scope(&payload.user.scopes, "users.read"));
    assert!(has_any_scope(
        &payload.user.scopes,
        &["users.manage", "users.read"]
    ));
    assert!(has_all_scopes(
        &payload.user.scopes,
        &["users.read", "collection.collection-1.records.read"]
    ));
    assert!(!has_scope(&payload.user.scopes, "users"));
    assert!(!has_scope(
        &payload.user.scopes,
        "collection.*.records.read"
    ));
    assert!(!payload.user.has_any_scope(&["audit.read", "users.manage"]));
}
