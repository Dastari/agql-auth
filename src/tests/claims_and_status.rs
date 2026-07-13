use std::sync::Arc;

use async_graphql::ErrorExtensions;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::jwt_signing::{RSA_PRIVATE_KEY_A, RSA_PUBLIC_KEY_A};
use super::validator::rs256_config;
use super::{MemoryRefreshTokenStore, MemoryUserStore};
use crate::prelude::*;

#[test]
fn access_token_only_grant_debug_redacts_token() {
    let grant = AccessTokenOnlyGrant {
        access_token: "super-secret-jwt".to_string(),
        access_token_expires_at: OffsetDateTime::now_utc(),
        user: AuthUser {
            user_id: "u1".to_string(),
            session_id: Uuid::new_v4(),
            roles: Vec::new(),
            scopes: Vec::new(),
            session: SessionContext::default(),
            token_claims: AccessTokenMetadata::default(),
        },
    };
    let debug = format!("{grant:?}");
    assert!(debug.contains("[redacted]"));
    assert!(!debug.contains("super-secret-jwt"));
}

#[test]
fn public_errors_do_not_leak_internal_details() {
    let err = AuthError::OidcDiscovery("https://idp.example/.well-known leaked".to_string());
    let gql = err.extend();
    assert_eq!(gql.message, "authentication service unavailable");
    assert_eq!(err.public_code(), "AUTH_SERVICE_UNAVAILABLE");
    assert!(err.internal_detail().unwrap().contains("idp.example"));
    assert!(!gql.message.contains("idp.example"));

    let store = AuthError::Store("postgres connection string leaked".to_string());
    assert_eq!(store.public_message(), "authentication service unavailable");
    assert_eq!(store.public_code(), "AUTH_SERVICE_UNAVAILABLE");
}

#[test]
fn claim_requirements_require_tenant_jti_and_cnf() {
    let requirements = ClaimRequirements::tenant_jti_and_cnf();
    let mut metadata = AccessTokenMetadata {
        jti: Some("jti-1".to_string()),
        tenant_id: Some("tenant-1".to_string()),
        cnf: Some(ConfirmationClaims {
            x5t_s256: Some("thumb".to_string()),
            jkt: None,
        }),
        ..AccessTokenMetadata::default()
    };
    assert!(requirements.validate(&metadata).is_ok());

    metadata.cnf = None;
    assert!(requirements.validate(&metadata).is_err());
}

#[tokio::test]
async fn validator_enforces_claim_requirements_and_nbf_with_test_clock() {
    let now = OffsetDateTime::now_utc();
    let clock = Arc::new(FixedClock::new(now));
    let validator = AccessTokenValidator::builder()
        .issuer("agql-auth")
        .audience("agql-auth-clients")
        .rs256_public_pem(RSA_PUBLIC_KEY_A)
        .key_id("auth-key-1")
        .claim_requirements(ClaimRequirements::tenant_and_jti())
        .clock(clock.clone())
        .leeway_seconds(5)
        .build()
        .unwrap();

    let no_nbf = encode_rs256(json!({
        "typ": "access",
        "purpose": "access_token",
        "sub": "user-1",
        "sid": Uuid::new_v4().to_string(),
        "roles": [],
        "scopes": [],
        "iss": "agql-auth",
        "aud": "agql-auth-clients",
        "exp": (now + Duration::minutes(15)).unix_timestamp(),
        "iat": now.unix_timestamp(),
        "jti": "jti-no-nbf",
        "tenant_id": "tenant-1",
    }));
    assert!(validator.authenticate_access_token(&no_nbf).is_ok());

    for nbf in [now - Duration::seconds(1), now] {
        let numeric_nbf = encode_rs256(json!({
            "typ": "access",
            "purpose": "access_token",
            "sub": "user-1",
            "sid": Uuid::new_v4().to_string(),
            "roles": [],
            "scopes": [],
            "iss": "agql-auth",
            "aud": "agql-auth-clients",
            "exp": (now + Duration::minutes(15)).unix_timestamp(),
            "iat": now.unix_timestamp(),
            "jti": "jti-numeric-nbf",
            "tenant_id": "tenant-1",
            "nbf": nbf.unix_timestamp(),
        }));
        assert!(validator.authenticate_access_token(&numeric_nbf).is_ok());
    }

    let missing_claims = encode_rs256(json!({
        "typ": "access",
        "purpose": "access_token",
        "sub": "user-1",
        "sid": Uuid::new_v4().to_string(),
        "roles": [],
        "scopes": [],
        "iss": "agql-auth",
        "aud": "agql-auth-clients",
        "exp": (now + Duration::minutes(15)).unix_timestamp(),
        "iat": now.unix_timestamp(),
    }));
    assert!(matches!(
        validator.authenticate_access_token(&missing_claims),
        Err(AuthError::InvalidAccessToken)
    ));

    let with_claims = encode_rs256(json!({
        "typ": "access",
        "purpose": "access_token",
        "sub": "user-1",
        "sid": Uuid::new_v4().to_string(),
        "roles": [],
        "scopes": [],
        "iss": "agql-auth",
        "aud": "agql-auth-clients",
        "exp": (now + Duration::minutes(15)).unix_timestamp(),
        "iat": now.unix_timestamp(),
        "jti": "jti-1",
        "tenant_id": "tenant-1",
        "nbf": (now + Duration::seconds(30)).unix_timestamp(),
    }));
    assert!(matches!(
        validator.authenticate_access_token(&with_claims),
        Err(AuthError::InvalidAccessToken)
    ));

    clock.advance_seconds(30);
    let user = validator.authenticate_access_token(&with_claims).unwrap();
    assert_eq!(user.token_claims.tenant_id.as_deref(), Some("tenant-1"));
    assert_eq!(user.token_claims.jti.as_deref(), Some("jti-1"));
}

#[test]
fn validator_rejects_basic_scheme_and_can_require_bearer() {
    let validator = AccessTokenValidator::builder()
        .issuer("agql-auth")
        .audience("agql-auth-clients")
        .rs256_public_pem(RSA_PUBLIC_KEY_A)
        .key_id("auth-key-1")
        .bearer_parse_mode(BearerParseMode::RequireBearer)
        .build()
        .unwrap();

    assert!(matches!(
        validator.authenticate_bearer("Basic dXNlcjpwYXNz"),
        Err(AuthError::InvalidBearerToken)
    ));
    assert!(matches!(
        validator.authenticate_bearer("raw-token-without-scheme"),
        Err(AuthError::InvalidBearerToken)
    ));
}

#[test]
fn validator_accepts_multi_audience_tokens() {
    let now = OffsetDateTime::now_utc();
    let token = encode_rs256(json!({
        "typ": "access",
        "purpose": "access_token",
        "sub": "user-1",
        "sid": Uuid::new_v4().to_string(),
        "roles": [],
        "scopes": [],
        "iss": "agql-auth",
        "aud": ["svc-a", "svc-b"],
        "exp": (now + Duration::minutes(15)).unix_timestamp(),
        "iat": now.unix_timestamp(),
        "jti": "jti-1",
    }));

    let validator = AccessTokenValidator::builder()
        .issuer("agql-auth")
        .audiences(["svc-b", "svc-c"])
        .rs256_public_pem(RSA_PUBLIC_KEY_A)
        .key_id("auth-key-1")
        .build()
        .unwrap();

    assert_eq!(
        validator.authenticate_access_token(&token).unwrap().user_id,
        "user-1"
    );

    let wrong = AccessTokenValidator::builder()
        .issuer("agql-auth")
        .audiences(["svc-c"])
        .rs256_public_pem(RSA_PUBLIC_KEY_A)
        .key_id("auth-key-1")
        .build()
        .unwrap();
    assert!(matches!(
        wrong.authenticate_access_token(&token),
        Err(AuthError::InvalidAccessToken)
    ));
}

#[test]
fn purpose_policy_can_reject_legacy_tokens() {
    let now = OffsetDateTime::now_utc();
    let legacy = encode_rs256(json!({
        "typ": "access",
        "sub": "user-1",
        "sid": Uuid::new_v4().to_string(),
        "roles": [],
        "scopes": [],
        "iss": "agql-auth",
        "aud": "agql-auth-clients",
        "exp": (now + Duration::minutes(15)).unix_timestamp(),
        "iat": now.unix_timestamp(),
    }));

    let strict = AccessTokenValidator::builder()
        .issuer("agql-auth")
        .audience("agql-auth-clients")
        .rs256_public_pem(RSA_PUBLIC_KEY_A)
        .key_id("auth-key-1")
        .purpose_policy(PurposePolicy::RequireAccessToken)
        .build()
        .unwrap();
    assert!(matches!(
        strict.authenticate_access_token(&legacy),
        Err(AuthError::InvalidAccessToken)
    ));
}

#[test]
fn rotating_jwks_supports_unknown_kid_cooldown_and_replace() {
    let jwks_a = AuthService::new(
        rs256_config(),
        Arc::new(MemoryUserStore::default()),
        Arc::new(MemoryRefreshTokenStore::default()),
    )
    .unwrap()
    .jwks()
    .unwrap()
    .to_string();

    let clock = Arc::new(FixedClock::new(OffsetDateTime::now_utc()));
    let set = RotatingJwksKeySet::with_clock(
        &jwks_a,
        KeyRefreshPolicy {
            cache_ttl: std::time::Duration::from_secs(60),
            unknown_kid_cooldown: std::time::Duration::from_secs(30),
            stale_policy: StaleKeyPolicy::UseStale,
        },
        clock.clone(),
    )
    .unwrap();

    assert!(set.begin_forced_refresh());
    assert!(!set.begin_forced_refresh());
    set.end_forced_refresh();
    clock.advance_seconds(31);
    assert!(set.should_force_refresh_for_unknown_kid());
    assert!(set.begin_forced_refresh());
    set.replace_jwks(&jwks_a).unwrap();
    assert!(set.resolve(Some("auth-key-1")).is_ok());
}

#[test]
fn reauthorization_deadline_uses_token_expiry_and_policy() {
    let now = OffsetDateTime::now_utc();
    let policy = ReauthorizationPolicy {
        min_interval: Duration::minutes(1),
        lifetime_fraction: 0.5,
        max_connection_ttl: Some(Duration::hours(1)),
        failure_mode: StatusCheckFailureMode::FailClosed,
    };
    let metadata = AccessTokenMetadata {
        expires_at: Some(now + Duration::minutes(10)),
        ..AccessTokenMetadata::default()
    };
    let deadline = policy.next_deadline(now, &metadata, now);
    assert!(deadline >= now + Duration::minutes(1));
    assert!(deadline <= now + Duration::minutes(5) + Duration::seconds(1));
}

#[tokio::test]
async fn issue_access_token_only_includes_jti_and_no_refresh() {
    let refresh_store = MemoryRefreshTokenStore::default();
    let auth = AuthService::new(
        rs256_config(),
        Arc::new(MemoryUserStore::default()),
        Arc::new(refresh_store.clone()),
    )
    .unwrap();

    let grant = auth
        .issue_access_token_only(
            AccessTokenOnlyRequest::new(
                "machine-1",
                vec!["Service".to_string()],
                vec!["jobs.run".to_string()],
                SessionContext::for_auth_method(AuthMethod::ServiceToken),
            )
            .with_tenant_id("tenant-9")
            .with_ttl(Duration::minutes(10)),
        )
        .await
        .unwrap();

    assert!(refresh_store.tokens_by_id.lock().unwrap().is_empty());
    assert!(grant.user.token_claims.jti.is_some());
    assert_eq!(
        grant.user.token_claims.tenant_id.as_deref(),
        Some("tenant-9")
    );
    assert_eq!(
        grant.user.token_claims.purpose.as_deref(),
        Some("access_token")
    );
}

fn encode_rs256(claims: serde_json::Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("auth-key-1".to_string());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY_A.as_bytes()).unwrap(),
    )
    .unwrap()
}
