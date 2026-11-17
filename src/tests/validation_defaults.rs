use std::sync::Arc;

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value as JsonValue, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::jwt_signing::{RSA_PRIVATE_KEY_A, RSA_PUBLIC_KEY_A};
use super::{MemoryRefreshTokenStore, MemoryUserStore, metadata};
use crate::prelude::*;

fn issuer() -> AuthService<MemoryUserStore, MemoryRefreshTokenStore> {
    AuthService::new(
        AuthConfig::with_rs256_pem(RSA_PRIVATE_KEY_A, RSA_PUBLIC_KEY_A, "auth-key-1"),
        Arc::new(MemoryUserStore::default()),
        Arc::new(MemoryRefreshTokenStore::default()),
    )
    .unwrap()
}

fn default_validator() -> AccessTokenValidatorBuilder {
    AccessTokenValidator::builder()
        .issuer("agql-auth")
        .audience("agql-auth-clients")
        .rs256_public_pem(RSA_PUBLIC_KEY_A)
        .key_id("auth-key-1")
}

fn claims() -> JsonValue {
    let now = OffsetDateTime::now_utc();
    json!({
        "typ": "access",
        "purpose": "access_token",
        "sub": "user-1",
        "sid": Uuid::new_v4().to_string(),
        "roles": [],
        "scope": "orders.read",
        "ctx": SessionContext::for_auth_method(AuthMethod::Password),
        "iss": "agql-auth",
        "aud": "agql-auth-clients",
        "exp": (now + Duration::minutes(5)).unix_timestamp(),
        "iat": now.unix_timestamp(),
    })
}

fn sign(claims: &JsonValue) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("auth-key-1".to_string());
    encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY_A.as_bytes()).unwrap(),
    )
    .unwrap()
}

fn without(mut claims: JsonValue, names: &[&str]) -> JsonValue {
    for name in names {
        claims.as_object_mut().unwrap().remove(*name);
    }
    claims
}

// A 0.26 issuer already mints `typ`, `purpose` and the standard `scope`, so the
// tightened defaults accept every token it issues during a rolling upgrade.
#[tokio::test]
async fn current_issuer_tokens_pass_the_strict_defaults() {
    let auth = issuer();
    let payload = auth
        .issue_verified_user_session_with_scopes(
            "user-1",
            vec![],
            vec!["orders.read".to_string()],
            AuthMethod::Password,
            metadata(),
        )
        .await
        .unwrap();
    let claims: JsonValue = serde_json::from_slice(
        &base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            payload.access_token.split('.').nth(1).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(claims["typ"], "access");
    assert_eq!(claims["purpose"], "access_token");
    assert!(claims.get("scopes").is_none());

    let validator = default_validator().build().unwrap();
    let bearer = format!("Bearer {}", payload.access_token);
    assert_eq!(
        validator.authenticate_bearer(&bearer).unwrap().user_id,
        "user-1"
    );
    assert_eq!(auth.authenticate_bearer(&bearer).unwrap().user_id, "user-1");
}

#[test]
fn default_validator_rejects_tokens_without_typ_or_purpose() {
    let validator = default_validator().build().unwrap();
    for names in [&["typ"][..], &["purpose"][..], &["typ", "purpose"][..]] {
        let token = sign(&without(claims(), names));
        assert!(
            matches!(
                validator.authenticate_access_token(&token),
                Err(AuthError::InvalidAccessToken)
            ),
            "missing {names:?}"
        );
    }

    let legacy = default_validator()
        .purpose_policy(PurposePolicy::AccessTokenOrLegacy)
        .build()
        .unwrap();
    let token = sign(&without(claims(), &["typ", "purpose"]));
    assert_eq!(
        legacy.authenticate_access_token(&token).unwrap().user_id,
        "user-1"
    );
}

#[test]
fn issuer_rejects_its_own_key_signing_a_token_without_typ() {
    let auth = issuer();
    let token = sign(&without(claims(), &["typ"]));
    assert!(matches!(
        auth.authenticate_access_token(&token),
        Err(AuthError::InvalidAccessToken)
    ));
    let token = sign(&without(claims(), &["purpose"]));
    assert!(matches!(
        auth.authenticate_access_token(&token),
        Err(AuthError::InvalidAccessToken)
    ));
}

#[test]
fn default_validator_requires_the_bearer_scheme() {
    let token = sign(&claims());
    let validator = default_validator().build().unwrap();
    assert!(matches!(
        validator.authenticate_bearer(&token),
        Err(AuthError::InvalidBearerToken)
    ));
    assert_eq!(
        validator
            .authenticate_bearer(&format!("Bearer {token}"))
            .unwrap()
            .user_id,
        "user-1"
    );

    let raw = default_validator()
        .bearer_parse_mode(BearerParseMode::BearerOrRaw)
        .build()
        .unwrap();
    assert_eq!(raw.authenticate_bearer(&token).unwrap().user_id, "user-1");
}

#[test]
fn default_validator_and_issuer_reject_the_legacy_scopes_array() {
    let mut legacy = without(claims(), &["scope"]);
    legacy["scopes"] = json!(["orders.read"]);
    let token = sign(&legacy);

    let validator = default_validator().build().unwrap();
    assert!(matches!(
        validator.authenticate_access_token(&token),
        Err(AuthError::InvalidAccessToken)
    ));
    assert!(matches!(
        issuer().authenticate_access_token(&token),
        Err(AuthError::InvalidAccessToken)
    ));

    let migrating = default_validator()
        .legacy_scope_claims(LegacyScopeClaims::Accept)
        .build()
        .unwrap();
    assert_eq!(
        migrating.authenticate_access_token(&token).unwrap().scopes,
        ["orders.read"]
    );
    assert_eq!(
        AuthConfig::new("x").legacy_scope_claims,
        LegacyScopeClaims::Reject
    );
    assert_eq!(LegacyScopeClaims::default(), LegacyScopeClaims::Reject);
    assert_eq!(BearerParseMode::default(), BearerParseMode::RequireBearer);
    assert_eq!(PurposePolicy::default(), PurposePolicy::RequireAccessToken);
}

#[test]
fn legacy_scope_issuance_requires_an_explicit_legacy_validation_opt_in() {
    let config = AuthConfig::with_rs256_pem(RSA_PRIVATE_KEY_A, RSA_PUBLIC_KEY_A, "auth-key-1")
        .with_access_token_scope_claim_format(AccessTokenScopeClaimFormat::LegacyArray);
    assert!(matches!(
        AuthService::new(
            config.clone(),
            Arc::new(MemoryUserStore::default()),
            Arc::new(MemoryRefreshTokenStore::default()),
        ),
        Err(AuthError::InvalidConfiguration(_))
    ));
    assert!(
        AuthService::new(
            config.with_legacy_scope_claims(LegacyScopeClaims::Accept),
            Arc::new(MemoryUserStore::default()),
            Arc::new(MemoryRefreshTokenStore::default()),
        )
        .is_ok()
    );
}
