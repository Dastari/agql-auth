use std::sync::Arc;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode};
use serde_json::{Value as JsonValue, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::jwt_signing::{
    RSA_PRIVATE_KEY_A, RSA_PRIVATE_KEY_B, RSA_PUBLIC_KEY_A, RSA_PUBLIC_KEY_B,
};
use super::{MemoryRefreshTokenStore, MemoryUserStore, TEST_HS256_SECRET, metadata};
use crate::keys::{ResolvedKey, StaticHs256Key};
use crate::prelude::*;

// Test-only P-256 key pair; it protects nothing.
const EC_PRIVATE_KEY_PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7bYpc0JgPBCQYTez
OsBZTT7Uwf+WuOej1wm30kwDJKmhRANCAASPPtIre2ytj5CLbErE5Tgeg+0S6YQd
3BXzapI9ApAS4ZhLSPhvaT5YUhxcOENuXu/XENWX6rc097YtIA/x4jmO
-----END PRIVATE KEY-----";
const EC_X: &str = "jz7SK3tsrY-Qi2xKxOU4HoPtEumEHdwV82qSPQKQEuE";
const EC_Y: &str = "mEtI-G9pPlhSHFw4Q25e79cQ1ZfqtzT3ti0gD_HiOY4";

fn service(config: AuthConfig) -> AuthService<MemoryUserStore, MemoryRefreshTokenStore> {
    AuthService::new(
        config,
        Arc::new(MemoryUserStore::default()),
        Arc::new(MemoryRefreshTokenStore::default()),
    )
    .unwrap()
}

fn issuer(
    private_pem: &str,
    public_pem: &str,
    kid: &str,
) -> AuthService<MemoryUserStore, MemoryRefreshTokenStore> {
    service(AuthConfig::with_rs256_pem(private_pem, public_pem, kid))
}

async fn access_token(auth: &AuthService<MemoryUserStore, MemoryRefreshTokenStore>) -> String {
    auth.issue_verified_user_session("user-1", vec![], AuthMethod::Password, metadata())
        .await
        .unwrap()
        .access_token
}

fn jwks_keys(auth: &AuthService<MemoryUserStore, MemoryRefreshTokenStore>) -> Vec<JsonValue> {
    auth.jwks().unwrap()["keys"].as_array().unwrap().clone()
}

fn merged_jwks(sets: &[&AuthService<MemoryUserStore, MemoryRefreshTokenStore>]) -> String {
    let keys = sets
        .iter()
        .flat_map(|auth| jwks_keys(auth))
        .collect::<Vec<_>>();
    json!({ "keys": keys }).to_string()
}

fn validator_builder() -> AccessTokenValidatorBuilder {
    AccessTokenValidator::builder()
        .issuer("agql-auth")
        .audience("agql-auth-clients")
}

fn access_claims() -> JsonValue {
    let now = OffsetDateTime::now_utc();
    json!({
        "typ": "access",
        "purpose": "access_token",
        "sub": "user-1",
        "sid": Uuid::new_v4().to_string(),
        "roles": [],
        "ctx": SessionContext::for_auth_method(AuthMethod::Password),
        "iss": "agql-auth",
        "aud": "agql-auth-clients",
        "exp": (now + Duration::minutes(5)).unix_timestamp(),
        "iat": now.unix_timestamp(),
    })
}

fn sign(header: Header, key: &EncodingKey) -> String {
    encode(&header, &access_claims(), key).unwrap()
}

fn header(alg: Algorithm, kid: Option<&str>) -> Header {
    let mut header = Header::new(alg);
    header.kid = kid.map(str::to_string);
    header
}

// AUTH-16: following docs/key-rotation.md with the default policy must not fail
// every token once the cache TTL passes.
#[test]
fn rotating_jwks_default_policy_keeps_the_documented_example_working() {
    let auth = issuer(RSA_PRIVATE_KEY_A, RSA_PUBLIC_KEY_A, "auth-key-1");
    let clock = FixedClock::new(OffsetDateTime::now_utc());
    let jwks = auth.jwks().unwrap().to_string();
    let rotating =
        RotatingJwksKeySet::with_clock(&jwks, KeyRefreshPolicy::default(), Arc::new(clock.clone()))
            .unwrap();

    clock.advance_seconds(301);
    assert!(rotating.resolve(Some("auth-key-1")).is_ok());
}

// AUTH-18: a static JWKS with the outgoing and incoming keys must accept both
// during the overlap, selected by the token `kid`.
#[tokio::test]
async fn static_jwks_accepts_every_published_kid_during_rotation_overlap() {
    let old = issuer(RSA_PRIVATE_KEY_A, RSA_PUBLIC_KEY_A, "auth-key-1");
    let new = issuer(RSA_PRIVATE_KEY_B, RSA_PUBLIC_KEY_B, "auth-key-2");
    let validator = validator_builder()
        .jwks_json(merged_jwks(&[&old, &new]))
        .build()
        .unwrap();

    for auth in [&old, &new] {
        let token = access_token(auth).await;
        assert_eq!(
            validator.authenticate_access_token(&token).unwrap().user_id,
            "user-1"
        );
    }

    let no_kid = sign(
        header(Algorithm::RS256, None),
        &EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY_A.as_bytes()).unwrap(),
    );
    assert!(matches!(
        validator.authenticate_access_token(&no_kid).unwrap_err(),
        AuthError::InvalidAccessToken
    ));
}

// AUTH-18: docs say a one-key JWKS requires the token `kid` when the JWK has one.
#[test]
fn single_key_jwks_with_kid_requires_the_token_kid() {
    let auth = issuer(RSA_PRIVATE_KEY_A, RSA_PUBLIC_KEY_A, "auth-key-1");
    let validator = validator_builder()
        .jwks_json(auth.jwks().unwrap().to_string())
        .build()
        .unwrap();
    let no_kid = sign(
        header(Algorithm::RS256, None),
        &EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY_A.as_bytes()).unwrap(),
    );
    assert!(matches!(
        validator.authenticate_access_token(&no_kid).unwrap_err(),
        AuthError::InvalidAccessToken
    ));
}

// AUTH-18: each JWK keeps its own algorithm instead of being labelled RS256.
#[test]
fn static_jwks_labels_each_key_with_its_own_algorithm() {
    let jwks = json!({
        "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "use": "sig",
            "kid": "ec-key-1",
            "x": EC_X,
            "y": EC_Y,
        }]
    })
    .to_string();
    let set = StaticJwksKeySet::from_jwks_json(&jwks).unwrap();
    assert_eq!(
        set.resolve(Some("ec-key-1")).unwrap().algorithm,
        Algorithm::ES256
    );

    let validator = validator_builder()
        .jwks_json(jwks)
        .allowed_algorithms([Algorithm::ES256])
        .build()
        .unwrap();
    let token = sign(
        header(Algorithm::ES256, Some("ec-key-1")),
        &EncodingKey::from_ec_pem(EC_PRIVATE_KEY_PKCS8.as_bytes()).unwrap(),
    );
    assert_eq!(
        validator.authenticate_access_token(&token).unwrap().user_id,
        "user-1"
    );
}

#[test]
fn static_jwks_rejects_symmetric_duplicate_and_unidentified_keys() {
    let rsa = issuer(RSA_PRIVATE_KEY_A, RSA_PUBLIC_KEY_A, "auth-key-1");
    let rsa_key = jwks_keys(&rsa)[0].clone();

    let symmetric = json!({ "keys": [{ "kty": "oct", "kid": "hmac", "k": "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3JldA" }] });
    let duplicate = json!({ "keys": [rsa_key.clone(), rsa_key.clone()] });
    let mut unnamed = rsa_key.clone();
    unnamed.as_object_mut().unwrap().remove("kid");
    let unidentified = json!({ "keys": [rsa_key, unnamed] });

    for document in [symmetric, duplicate, unidentified] {
        assert!(
            matches!(
                StaticJwksKeySet::from_jwks_json(&document.to_string()),
                Err(AuthError::InvalidConfiguration(_))
            ),
            "{document}"
        );
    }
}

struct FixedResolver(ResolvedKey);

impl std::fmt::Debug for FixedResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FixedResolver")
    }
}

impl AccessTokenKeyResolver for FixedResolver {
    fn resolve(&self, _kid: Option<&str>) -> AuthResult<ResolvedKey> {
        Ok(self.0.clone())
    }
}

use crate::AuthResult;

// AUTH-17: a resolver returning an HMAC key must not bypass accept_hs256.
#[test]
fn key_resolver_returning_hmac_keys_requires_accept_hs256() {
    let hs256 = Arc::new(StaticHs256Key::from_secret(TEST_HS256_SECRET, None).unwrap());
    let token = sign(
        header(Algorithm::HS256, None),
        &EncodingKey::from_secret(TEST_HS256_SECRET.as_bytes()),
    );
    match validator_builder().key_resolver(hs256.clone()).build() {
        Err(AuthError::InvalidConfiguration(_)) => {}
        Err(other) => panic!("unexpected error {other:?}"),
        Ok(validator) => panic!(
            "HS256 resolver accepted without accept_hs256: {:?}",
            validator
                .authenticate_access_token(&token)
                .map(|user| user.user_id)
        ),
    }

    let hs384 = Arc::new(FixedResolver(ResolvedKey {
        decoding_key: DecodingKey::from_secret(TEST_HS256_SECRET.as_bytes()),
        algorithm: Algorithm::HS384,
        kid: None,
    }));
    assert!(matches!(
        validator_builder()
            .key_resolver(hs384)
            .allowed_algorithms([Algorithm::HS384])
            .build(),
        Err(AuthError::InvalidConfiguration(_))
    ));

    // With the explicit opt-in the resolver works.
    let validator = validator_builder()
        .key_resolver(hs256)
        .accept_hs256(true)
        .build()
        .unwrap();
    assert_eq!(
        validator.authenticate_access_token(&token).unwrap().user_id,
        "user-1"
    );
}

// AUTH-17 sibling: a resolver that hands out an HMAC key for one kid at request
// time is refused even when the build-time probe saw an RSA key.
#[test]
fn key_resolver_switching_to_hmac_at_request_time_is_refused() {
    #[derive(Debug)]
    struct SwitchingResolver;
    impl AccessTokenKeyResolver for SwitchingResolver {
        fn resolve(&self, kid: Option<&str>) -> AuthResult<ResolvedKey> {
            Ok(match kid {
                Some("hmac") => ResolvedKey {
                    decoding_key: DecodingKey::from_secret(TEST_HS256_SECRET.as_bytes()),
                    algorithm: Algorithm::HS256,
                    kid: Some("hmac".into()),
                },
                _ => ResolvedKey {
                    decoding_key: DecodingKey::from_rsa_pem(RSA_PUBLIC_KEY_A.as_bytes()).unwrap(),
                    algorithm: Algorithm::RS256,
                    kid: kid.map(str::to_string),
                },
            })
        }
    }
    let validator = validator_builder()
        .key_resolver(Arc::new(SwitchingResolver))
        .allowed_algorithms([Algorithm::RS256])
        .build()
        .unwrap();
    let token = sign(
        header(Algorithm::HS256, Some("hmac")),
        &EncodingKey::from_secret(TEST_HS256_SECRET.as_bytes()),
    );
    assert!(validator.authenticate_access_token(&token).is_err());
}

// AUTH-16: the stale window is bounded; a refresh restores service.
#[test]
fn rotating_jwks_default_stale_window_is_bounded_and_refresh_recovers() {
    let auth = issuer(RSA_PRIVATE_KEY_A, RSA_PUBLIC_KEY_A, "auth-key-1");
    let clock = FixedClock::new(OffsetDateTime::now_utc());
    let jwks = auth.jwks().unwrap().to_string();
    let policy = KeyRefreshPolicy::default();
    assert_eq!(policy.stale_policy, StaleKeyPolicy::UseStale);
    let rotating =
        RotatingJwksKeySet::with_clock(&jwks, policy.clone(), Arc::new(clock.clone())).unwrap();
    assert!(!rotating.needs_refresh());

    clock.advance_seconds(policy.cache_ttl.as_secs() as i64);
    assert!(rotating.needs_refresh());
    assert!(rotating.resolve(Some("auth-key-1")).is_ok());

    clock.advance_seconds(policy.max_stale.as_secs() as i64);
    assert!(matches!(
        rotating.resolve(Some("auth-key-1")),
        Err(AuthError::AuthServiceUnavailable)
    ));

    rotating.replace_jwks(&jwks).unwrap();
    assert!(!rotating.needs_refresh());
    assert!(rotating.resolve(Some("auth-key-1")).is_ok());

    let strict = RotatingJwksKeySet::with_clock(
        &jwks,
        KeyRefreshPolicy {
            stale_policy: StaleKeyPolicy::Reject,
            ..KeyRefreshPolicy::default()
        },
        Arc::new(clock.clone()),
    )
    .unwrap();
    clock.advance_seconds(300);
    assert!(matches!(
        strict.resolve(Some("auth-key-1")),
        Err(AuthError::AuthServiceUnavailable)
    ));

    // Durations beyond the representable range saturate instead of wrapping.
    let unbounded = RotatingJwksKeySet::with_clock(
        &jwks,
        KeyRefreshPolicy {
            cache_ttl: std::time::Duration::MAX,
            ..KeyRefreshPolicy::default()
        },
        Arc::new(clock.clone()),
    )
    .unwrap();
    clock.advance_seconds(10_000_000);
    assert!(unbounded.resolve(Some("auth-key-1")).is_ok());
    assert!(!unbounded.needs_refresh());
}

#[test]
fn validator_key_ids_pin_a_set_of_kids() {
    let old = issuer(RSA_PRIVATE_KEY_A, RSA_PUBLIC_KEY_A, "auth-key-1");
    let new = issuer(RSA_PRIVATE_KEY_B, RSA_PUBLIC_KEY_B, "auth-key-2");
    let jwks = merged_jwks(&[&old, &new]);
    let pinned = validator_builder()
        .jwks_json(jwks.clone())
        .key_id("auth-key-2")
        .build()
        .unwrap();
    let old_token = sign(
        header(Algorithm::RS256, Some("auth-key-1")),
        &EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY_A.as_bytes()).unwrap(),
    );
    assert!(pinned.authenticate_access_token(&old_token).is_err());
    let both = validator_builder()
        .jwks_json(jwks.clone())
        .key_ids(["auth-key-1", "auth-key-2"])
        .build()
        .unwrap();
    assert!(both.authenticate_access_token(&old_token).is_ok());
    assert!(matches!(
        validator_builder()
            .jwks_json(jwks)
            .key_id("auth-key-9")
            .build(),
        Err(AuthError::InvalidConfiguration(_))
    ));
}

// AUTH-19: previous keys verify, are published, and never sign.
#[tokio::test]
async fn issuer_previous_verification_keys_allow_rotation_overlap() {
    let old = issuer(RSA_PRIVATE_KEY_A, RSA_PUBLIC_KEY_A, "auth-key-1");
    let old_token = access_token(&old).await;
    let old_purpose = old
        .issue_purpose_token(PurposeTokenIssueRequest::new(
            "user-1",
            "capture_upload",
            "capture-clients",
            Duration::minutes(5),
        ))
        .unwrap()
        .token;
    let reset_store = crate::tests::MemoryPasswordResetStore::default();
    let old_reset = old
        .issue_password_reset_token(&reset_store, "user-1")
        .await
        .unwrap()
        .token;

    let rotated = service(
        AuthConfig::with_rs256_pem(RSA_PRIVATE_KEY_B, RSA_PUBLIC_KEY_B, "auth-key-2")
            .with_previous_verification_key("auth-key-1", RSA_PUBLIC_KEY_A),
    );

    let kids = jwks_keys(&rotated)
        .iter()
        .map(|key| key["kid"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(kids, ["auth-key-2", "auth-key-1"]);

    assert_eq!(
        rotated
            .authenticate_access_token(&old_token)
            .unwrap()
            .user_id,
        "user-1"
    );
    rotated
        .authenticate_purpose_token(
            &old_purpose,
            PurposeTokenValidation::new("capture_upload", "capture-clients"),
        )
        .unwrap();
    assert_eq!(
        rotated
            .authenticate_password_reset_token(&old_reset)
            .unwrap()
            .user_id,
        "user-1"
    );
    let new_token = access_token(&rotated).await;
    assert_eq!(
        jsonwebtoken::decode_header(&new_token)
            .unwrap()
            .kid
            .as_deref(),
        Some("auth-key-2")
    );

    // A resource server fed the rotated JWKS accepts both generations.
    let validator = validator_builder()
        .jwks_json(rotated.jwks().unwrap().to_string())
        .build()
        .unwrap();
    assert!(validator.authenticate_access_token(&old_token).is_ok());
    assert!(validator.authenticate_access_token(&new_token).is_ok());

    // Without the previous key the cutover is hard.
    let cut_over = issuer(RSA_PRIVATE_KEY_B, RSA_PUBLIC_KEY_B, "auth-key-2");
    assert!(matches!(
        cut_over.authenticate_access_token(&old_token),
        Err(AuthError::InvalidAccessToken)
    ));

    // A previous kid with the wrong key still fails the signature check.
    let forged = sign(
        header(Algorithm::RS256, Some("auth-key-1")),
        &EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY_B.as_bytes()).unwrap(),
    );
    assert!(rotated.authenticate_access_token(&forged).is_err());
}

#[test]
fn previous_verification_keys_are_validated() {
    let build = |config: AuthConfig| {
        AuthService::new(
            config,
            Arc::new(MemoryUserStore::default()),
            Arc::new(MemoryRefreshTokenStore::default()),
        )
        .map(|_| ())
    };
    let rs256 = || AuthConfig::with_rs256_pem(RSA_PRIVATE_KEY_B, RSA_PUBLIC_KEY_B, "auth-key-2");
    for config in [
        rs256().with_previous_verification_key("auth-key-2", RSA_PUBLIC_KEY_A),
        rs256().with_previous_verification_key("", RSA_PUBLIC_KEY_A),
        rs256()
            .with_previous_verification_key("auth-key-1", RSA_PUBLIC_KEY_A)
            .with_previous_verification_key("auth-key-1", RSA_PUBLIC_KEY_A),
        rs256().with_previous_verification_key("auth-key-1", "not a pem"),
        AuthConfig::new(TEST_HS256_SECRET)
            .with_previous_verification_key("auth-key-1", RSA_PUBLIC_KEY_A),
    ] {
        assert!(matches!(
            build(config),
            Err(AuthError::InvalidConfiguration(_))
        ));
    }
    let mut too_many = rs256();
    for index in 0..=crate::MAX_PREVIOUS_VERIFICATION_KEYS {
        too_many =
            too_many.with_previous_verification_key(format!("old-{index}"), RSA_PUBLIC_KEY_A);
    }
    assert!(matches!(
        build(too_many),
        Err(AuthError::InvalidConfiguration(_))
    ));
}
