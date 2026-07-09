use std::sync::Arc;

use async_graphql::{Context, EmptyMutation, EmptySubscription, Object, Request, Schema};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value as JsonValue, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::jwt_signing::{RSA_PRIVATE_KEY_A, RSA_PUBLIC_KEY_A};
use super::{MemoryRefreshTokenStore, MemoryUserStore, TEST_HS256_SECRET, metadata};
use crate::prelude::*;

struct ValidatorQuery;

#[Object]
impl ValidatorQuery {
    async fn auth_subject(&self, ctx: &Context<'_>) -> String {
        auth_user_from_ctx_opt(ctx)
            .map(|user| user.user_id.clone())
            .unwrap_or_else(|| "none".to_string())
    }

    #[graphql(guard = "RequireScope::new(\"orders.items.read\")")]
    async fn guarded(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn rs256_valid_token_from_auth_service_validates_one_to_one() {
    let auth = auth_service(rs256_config());
    let payload = auth
        .issue_verified_user_session_with_scopes(
            "user-1",
            vec!["Operator".to_string()],
            vec!["orders.read".to_string()],
            AuthMethod::Password,
            metadata(),
        )
        .await
        .unwrap();
    let validator = rs256_validator().build().unwrap();

    let decoded = validator
        .authenticate_bearer(&format!("Bearer {}", payload.access_token))
        .unwrap();

    assert_eq!(decoded, payload.user);
    assert_eq!(
        validator
            .scope_matcher()
            .has_scope(&decoded.scopes, "orders.read"),
        true
    );
}

#[tokio::test]
async fn rs256_validator_rejects_wrong_audience_and_issuer() {
    let auth = auth_service(rs256_config());
    let payload = auth
        .issue_verified_user_session("user-1", vec![], AuthMethod::Password, metadata())
        .await
        .unwrap();

    let wrong_audience = rs256_validator()
        .audience("other-audience")
        .build()
        .unwrap();
    assert!(matches!(
        wrong_audience
            .authenticate_access_token(&payload.access_token)
            .unwrap_err(),
        AuthError::InvalidAccessToken
    ));

    let wrong_issuer = rs256_validator().issuer("other-issuer").build().unwrap();
    assert!(matches!(
        wrong_issuer
            .authenticate_access_token(&payload.access_token)
            .unwrap_err(),
        AuthError::InvalidAccessToken
    ));
}

#[tokio::test]
async fn rs256_validator_rejects_expired_and_wrong_purpose_tokens() {
    let mut config = rs256_config();
    config.access_token_ttl = Duration::seconds(-5);
    let auth = auth_service(config);
    let payload = auth
        .issue_verified_user_session("user-1", vec![], AuthMethod::Password, metadata())
        .await
        .unwrap();
    let validator = rs256_validator().build().unwrap();

    assert!(matches!(
        validator
            .authenticate_access_token(&payload.access_token)
            .unwrap_err(),
        AuthError::AccessTokenExpired
    ));

    let wrong_purpose = encode_rs256(access_claims_json(Some("password_reset")));
    assert!(matches!(
        validator
            .authenticate_access_token(&wrong_purpose)
            .unwrap_err(),
        AuthError::InvalidAccessToken
    ));
}

#[test]
fn validator_accepts_legacy_access_tokens_without_purpose() {
    let validator = rs256_validator().build().unwrap();
    let legacy = encode_rs256(access_claims_json(None));

    let decoded = validator.authenticate_access_token(&legacy).unwrap();

    assert_eq!(decoded.user_id, "user-1");
    assert_eq!(decoded.roles, vec!["Operator".to_string()]);
    assert_eq!(decoded.scopes, vec!["orders.read".to_string()]);
}

#[tokio::test]
async fn hs256_validator_requires_explicit_acceptance() {
    let err = match AccessTokenValidator::builder()
        .issuer("agql-auth")
        .audience("agql-auth-clients")
        .hs256_secret(TEST_HS256_SECRET)
        .build()
    {
        Ok(_) => panic!("HS256 should be rejected without accept_hs256(true)"),
        Err(err) => err,
    };
    assert!(matches!(err, AuthError::InvalidConfiguration(_)));

    let auth = auth_service(AuthConfig::new(TEST_HS256_SECRET));
    let payload = auth
        .issue_verified_user_session("user-1", vec![], AuthMethod::Password, metadata())
        .await
        .unwrap();
    let validator = AccessTokenValidator::builder()
        .issuer("agql-auth")
        .audience("agql-auth-clients")
        .accept_hs256(true)
        .hs256_secret(TEST_HS256_SECRET)
        .build()
        .unwrap();

    let decoded = validator
        .authenticate_access_token(&payload.access_token)
        .unwrap();
    assert_eq!(decoded.user_id, "user-1");
}

#[tokio::test]
async fn validator_injects_auth_runtime_and_rejects_bad_tokens() {
    let auth = auth_service(rs256_config());
    let payload = auth
        .issue_verified_user_session_with_scopes(
            "user-1",
            vec![],
            vec!["orders.*".to_string()],
            AuthMethod::Password,
            metadata(),
        )
        .await
        .unwrap();
    let validator = rs256_validator()
        .scope_matcher(Arc::new(HierarchicalScopeMatch::with_defaults()))
        .build()
        .unwrap();
    let schema = Schema::build(ValidatorQuery, EmptyMutation, EmptySubscription).finish();

    let missing = validator
        .inject_http_auth(Request::new("{ authSubject }"), None)
        .unwrap();
    let missing_response = schema.execute(missing).await;
    assert_eq!(
        missing_response.data.into_json().unwrap()["authSubject"],
        "none"
    );

    assert!(matches!(
        validator
            .inject_http_auth(Request::new("{ authSubject }"), Some("not-a-jwt"))
            .unwrap_err(),
        AuthError::InvalidAccessToken
    ));

    let request = validator
        .inject_http_auth(
            Request::new("{ authSubject guarded }"),
            Some(&format!("Bearer {}", payload.access_token)),
        )
        .unwrap();
    let response = schema.execute(request).await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(response.data.into_json().unwrap()["authSubject"], "user-1");
}

#[tokio::test]
async fn validator_supports_static_jwks_json() {
    let auth = auth_service(rs256_config());
    let payload = auth
        .issue_verified_user_session("user-1", vec![], AuthMethod::Password, metadata())
        .await
        .unwrap();
    let jwks = auth.jwks().unwrap().to_string();
    let validator = AccessTokenValidator::builder()
        .issuer("agql-auth")
        .audience("agql-auth-clients")
        .jwks_json(jwks)
        .key_id("auth-key-1")
        .build()
        .unwrap();

    let decoded = validator
        .authenticate_access_token(&payload.access_token)
        .unwrap();
    assert_eq!(decoded.user_id, "user-1");
}

#[tokio::test]
async fn validator_authenticates_connection_init_authorization_keys() {
    let auth = auth_service(rs256_config());
    let payload = auth
        .issue_verified_user_session("user-1", vec![], AuthMethod::Password, metadata())
        .await
        .unwrap();
    let validator = rs256_validator().build().unwrap();

    let decoded = validator
        .authenticate_connection_init_value(
            &json!({
                "WsAuthorization": format!("Bearer {}", payload.access_token),
            }),
            &["WsAuthorization", "Authorization"],
        )
        .unwrap();

    assert_eq!(decoded.user_id, "user-1");
}

fn auth_service(config: AuthConfig) -> AuthService<MemoryUserStore, MemoryRefreshTokenStore> {
    AuthService::new(
        config,
        Arc::new(MemoryUserStore::default()),
        Arc::new(MemoryRefreshTokenStore::default()),
    )
    .unwrap()
}

pub(super) fn rs256_config() -> AuthConfig {
    AuthConfig::with_rs256_pem(RSA_PRIVATE_KEY_A, RSA_PUBLIC_KEY_A, "auth-key-1")
}

fn rs256_validator() -> AccessTokenValidatorBuilder {
    AccessTokenValidator::builder()
        .issuer("agql-auth")
        .audience("agql-auth-clients")
        .rs256_public_pem(RSA_PUBLIC_KEY_A)
        .key_id("auth-key-1")
}

fn encode_rs256(claims: JsonValue) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("auth-key-1".to_string());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY_A.as_bytes()).unwrap(),
    )
    .unwrap()
}

fn access_claims_json(purpose: Option<&str>) -> JsonValue {
    let issued_at = OffsetDateTime::now_utc();
    let mut claims = json!({
        "typ": "access",
        "sub": "user-1",
        "sid": Uuid::new_v4().to_string(),
        "roles": ["Operator"],
        "scopes": ["orders.read"],
        "ctx": SessionContext::for_auth_method(AuthMethod::Password),
        "iss": "agql-auth",
        "aud": "agql-auth-clients",
        "exp": (issued_at + Duration::minutes(15)).unix_timestamp(),
        "iat": issued_at.unix_timestamp(),
    });
    if let Some(purpose) = purpose {
        claims["purpose"] = json!(purpose);
    }
    claims
}
