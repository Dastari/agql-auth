use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;
use serde_json::{Value as JsonValue, json};
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
    let claims = decode_payload(&payload.access_token);
    assert_eq!(
        claims["scope"],
        "global.admin collection.collection-1.media.write"
    );
    assert!(claims.get("scopes").is_none());
    assert_eq!(decoded.scopes, payload.user.scopes);
    assert!(decoded.has_scope("global.admin"));
    assert!(decoded.has_all_scopes(&["global.admin", "collection.collection-1.media.write"]));
    assert!(decoded.has_any_scope(&["audit.read", "global.admin"]));
}

#[tokio::test]
async fn empty_scopes_omit_both_claim_shapes() {
    let auth = test_auth_service(Default::default(), Default::default());
    let payload = auth
        .issue_verified_user_session("user-1", Vec::new(), AuthMethod::Password, metadata())
        .await
        .unwrap();

    let claims = decode_payload(&payload.access_token);
    assert!(claims.get("scope").is_none());
    assert!(claims.get("scopes").is_none());
    assert!(
        auth.authenticate_access_token(&payload.access_token)
            .unwrap()
            .scopes
            .is_empty()
    );
}

#[tokio::test]
async fn legacy_issuance_is_explicit_and_cannot_reject_its_own_shape() {
    let config = AuthConfig::new(TEST_HS256_SECRET)
        .with_access_token_scope_claim_format(AccessTokenScopeClaimFormat::LegacyArray);
    let auth = test_auth_service_with_config(config);
    let payload = auth
        .issue_verified_user_session_with_scopes(
            "legacy-user",
            Vec::new(),
            vec!["records.read".to_string()],
            AuthMethod::Password,
            metadata(),
        )
        .await
        .unwrap();

    let claims = decode_payload(&payload.access_token);
    assert!(claims.get("scope").is_none());
    assert_eq!(claims["scopes"], json!(["records.read"]));
    assert_eq!(
        auth.authenticate_access_token(&payload.access_token)
            .unwrap()
            .scopes,
        vec!["records.read".to_string()]
    );

    let invalid = AuthConfig::new(TEST_HS256_SECRET)
        .with_access_token_scope_claim_format(AccessTokenScopeClaimFormat::LegacyArray)
        .with_legacy_scope_claims(LegacyScopeClaims::Reject);
    let error = AuthService::new(
        invalid,
        std::sync::Arc::new(MemoryUserStore::default()),
        std::sync::Arc::new(MemoryRefreshTokenStore::default()),
    )
    .err()
    .expect("incoherent scope migration configuration must fail");
    assert!(matches!(error, AuthError::InvalidConfiguration(_)));
}

#[test]
fn standard_and_legacy_validation_is_bounded_and_conflicts_fail_closed() {
    let accepting = test_auth_service(Default::default(), Default::default());
    let rejecting = test_auth_service_with_config(
        AuthConfig::new(TEST_HS256_SECRET).with_legacy_scope_claims(LegacyScopeClaims::Reject),
    );

    let standard = signed_access_token(json!({"scope": "records.read records.write"}));
    assert_eq!(
        accepting
            .authenticate_access_token(&standard)
            .unwrap()
            .scopes,
        vec!["records.read".to_string(), "records.write".to_string()]
    );

    let legacy = signed_access_token(json!({"scopes": ["records.read"]}));
    assert_eq!(
        accepting.authenticate_access_token(&legacy).unwrap().scopes,
        vec!["records.read".to_string()]
    );
    assert!(matches!(
        rejecting.authenticate_access_token(&legacy).unwrap_err(),
        AuthError::InvalidAccessToken
    ));
    let strict_resource_server = AccessTokenValidator::builder()
        .issuer("agql-auth")
        .audience("agql-auth-clients")
        .accept_hs256(true)
        .hs256_secret(TEST_HS256_SECRET)
        .legacy_scope_claims(LegacyScopeClaims::Reject)
        .build()
        .unwrap();
    assert_eq!(
        strict_resource_server
            .authenticate_access_token(&standard)
            .unwrap()
            .scopes,
        vec!["records.read".to_string(), "records.write".to_string()]
    );
    assert!(matches!(
        strict_resource_server
            .authenticate_access_token(&legacy)
            .unwrap_err(),
        AuthError::InvalidAccessToken
    ));

    let equivalent_dual = signed_access_token(json!({
        "scope": "records.write records.read",
        "scopes": ["records.read", "records.write"]
    }));
    assert_eq!(
        accepting
            .authenticate_access_token(&equivalent_dual)
            .unwrap()
            .scopes,
        vec!["records.write".to_string(), "records.read".to_string()]
    );
    assert!(matches!(
        rejecting
            .authenticate_access_token(&equivalent_dual)
            .unwrap_err(),
        AuthError::InvalidAccessToken
    ));

    let conflicting = signed_access_token(json!({
        "scope": "records.read",
        "scopes": ["records.write"]
    }));
    assert!(matches!(
        accepting
            .authenticate_access_token(&conflicting)
            .unwrap_err(),
        AuthError::InvalidAccessToken
    ));
}

#[tokio::test]
async fn malformed_scope_claims_and_unrepresentable_issued_scopes_fail_closed() {
    let auth = test_auth_service(Default::default(), Default::default());
    for claims in [
        json!({"scope": ""}),
        json!({"scope": "records.read  records.write"}),
        json!({"scope": "records.\"read"}),
        json!({"scope": ["records.read"]}),
        json!({"scopes": "records.read"}),
        json!({"scopes": ["records read"]}),
    ] {
        let token = signed_access_token(claims);
        assert!(matches!(
            auth.authenticate_access_token(&token).unwrap_err(),
            AuthError::InvalidAccessToken
        ));
    }
    for claims in [
        json!({"scope": "x".repeat(MAX_ACCESS_TOKEN_SCOPE_LENGTH + 1)}),
        json!({"scope": vec!["x"; MAX_ACCESS_TOKEN_SCOPES + 1].join(" ")}),
        json!({"scopes": vec!["x"; MAX_ACCESS_TOKEN_SCOPES + 1]}),
    ] {
        let token = signed_access_token(claims);
        assert!(matches!(
            auth.authenticate_access_token(&token).unwrap_err(),
            AuthError::InvalidAccessToken
        ));
    }

    let result = auth
        .issue_verified_user_session_with_scopes(
            "invalid-scope-user",
            Vec::new(),
            vec!["records read".to_string()],
            AuthMethod::Password,
            metadata(),
        )
        .await;
    assert!(matches!(result.unwrap_err(), AuthError::TokenCreation(_)));
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

fn test_auth_service_with_config(
    config: AuthConfig,
) -> AuthService<MemoryUserStore, MemoryRefreshTokenStore> {
    AuthService::new(
        config,
        std::sync::Arc::new(MemoryUserStore::default()),
        std::sync::Arc::new(MemoryRefreshTokenStore::default()),
    )
    .unwrap()
}

fn signed_access_token(extra: JsonValue) -> String {
    let issued_at = OffsetDateTime::now_utc();
    let mut claims = json!({
        "sub": "scope-user",
        "sid": uuid::Uuid::new_v4().to_string(),
        "roles": [],
        "ctx": SessionContext::for_auth_method(AuthMethod::Password),
        "iss": "agql-auth",
        "aud": "agql-auth-clients",
        "exp": (issued_at + time::Duration::minutes(15)).unix_timestamp(),
        "iat": issued_at.unix_timestamp(),
    });
    claims
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(TEST_HS256_SECRET.as_bytes()),
    )
    .unwrap()
}

fn decode_payload(token: &str) -> JsonValue {
    let payload = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}
