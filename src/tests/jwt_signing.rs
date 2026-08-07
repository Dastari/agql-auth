use std::sync::Arc;

use async_graphql::{EmptyMutation, EmptySubscription, Object, Schema};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header, decode_header, encode};
use serde_json::{Value as JsonValue, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::{MemoryRefreshTokenStore, MemoryUserStore, TEST_HS256_SECRET, metadata, stored_user};
use crate::prelude::*;

pub(super) const RSA_PRIVATE_KEY_A: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTL
UTv4l4sggh5/CYYi/cvI+SXVT9kPWSKXxJXBXd/4LkvcPuUakBoAkfh+eiFVMh2V
rUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8H
oGfG/AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBI
Mc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi+yUod+j8MtvIj812dkS4QMiRVN/
by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQIDAQABAoIBAHREk0I0O9DvECKd
WUpAmF3mY7oY9PNQiu44Yaf+AoSuyRpRUGTMIgc3u3eivOE8ALX0BmYUO5JtuRNZ
Dpvt4SAwqCnVUinIf6C+eH/wSurCpapSM0BAHp4aOA7igptyOMgMPYBHNA1e9A7j
E0dCxKWMl3DSWNyjQTk4zeRGEAEfbNjHrq6YCtjHSZSLmWiG80hnfnYos9hOr5Jn
LnyS7ZmFE/5P3XVrxLc/tQ5zum0R4cbrgzHiQP5RgfxGJaEi7XcgherCCOgurJSS
bYH29Gz8u5fFbS+Yg8s+OiCss3cs1rSgJ9/eHZuzGEdUZVARH6hVMjSuwvqVTFaE
8AgtleECgYEA+uLMn4kNqHlJS2A5uAnCkj90ZxEtNm3E8hAxUrhssktY5XSOAPBl
xyf5RuRGIImGtUVIr4HuJSa5TX48n3Vdt9MYCprO/iYl6moNRSPt5qowIIOJmIjY
2mqPDfDt/zw+fcDD3lmCJrFlzcnh0uea1CohxEbQnL3cypeLt+WbU6kCgYEAzSp1
9m1ajieFkqgoB0YTpt/OroDx38vvI5unInJlEeOjQ+oIAQdN2wpxBvTrRorMU6P0
7mFUbt1j+Co6CbNiw+X8HcCaqYLR5clbJOOWNR36PuzOpQLkfK8woupBxzW9B8gZ
mY8rB1mbJ+/WTPrEJy6YGmIEBkWylQ2VpW8O4O0CgYEApdbvvfFBlwD9YxbrcGz7
MeNCFbMz+MucqQntIKoKJ91ImPxvtc0y6e/Rhnv0oyNlaUOwJVu0yNgNG117w0g4
t/+Q38mvVC5xV7/cn7x9UMFk6MkqVir3dYGEqIl/OP1grY2Tq9HtB5iyG9L8NIam
QOLMyUqqMUILxdthHyFmiGkCgYEAn9+PjpjGMPHxL0gj8Q8VbzsFtou6b1deIRRA
2CHmSltltR1gYVTMwXxQeUhPMmgkMqUXzs4/WijgpthY44hK1TaZEKIuoxrS70nJ
4WQLf5a9k1065fDsFZD6yGjdGxvwEmlGMZgTwqV7t1I4X0Ilqhav5hcs5apYL7gn
PYPeRz0CgYALHCj/Ji8XSsDoF/MhVhnGdIs2P99NNdmo3R2Pv0CuZbDKMU559LJH
UvrKS8WkuWRDuKrz1W/EQKApFjDGpdqToZqriUFQzwy7mR3ayIiogzNtHcvbDHx8
oFnGY0OFksX/ye0/XGpy2SFxYRwGU98HPYeBvAQQrVjdkzfy7BmXQQ==
-----END RSA PRIVATE KEY-----"#;

pub(super) const RSA_PUBLIC_KEY_A: &str = r#"-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAyRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4
l4sggh5/CYYi/cvI+SXVT9kPWSKXxJXBXd/4LkvcPuUakBoAkfh+eiFVMh2VrUyW
yj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG
/AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4l
QzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi+yUod+j8MtvIj812dkS4QMiRVN/by2h
3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQIDAQAB
-----END RSA PUBLIC KEY-----"#;

pub(super) const RSA_PRIVATE_KEY_B: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw
kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr
m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi
NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV
3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2
QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs
kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go
amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM
+bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9
D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC
0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y
lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+
hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp
bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X
+jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B
BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC
2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx
QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz
5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9
Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0
NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j
8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma
3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K
y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB
jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=
-----END RSA PRIVATE KEY-----"#;

pub(super) const RSA_PUBLIC_KEY_B: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
MwIDAQAB
-----END PUBLIC KEY-----"#;

const OTHER_HS256_SECRET: &str = "different-test-secret-with-32-bytes";

struct GuardedQuery;

#[Object]
impl GuardedQuery {
    #[graphql(guard = "RequireAnyRole::new([\"CatalogEditor\"])")]
    async fn role_guarded(&self) -> bool {
        true
    }

    #[graphql(guard = "RequireScope::new(\"users.read\")")]
    async fn scope_guarded(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn hs256_auth_config_new_emits_standard_scope_claim() {
    let auth = auth_service(AuthConfig::new(TEST_HS256_SECRET));
    let payload = auth
        .issue_verified_user_session_with_scopes(
            "user-1",
            vec!["CatalogEditor".to_string()],
            vec!["users.read".to_string()],
            AuthMethod::Password,
            metadata(),
        )
        .await
        .unwrap();

    let header = decode_header(&payload.access_token).unwrap();
    assert_eq!(header.alg, Algorithm::HS256);
    assert!(header.kid.is_none());

    let claims = decode_payload(&payload.access_token);
    assert_claim_shape(&claims);
    assert_eq!(claims["sub"], "user-1");
    assert_eq!(claims["roles"], json!(["CatalogEditor"]));
    assert_eq!(claims["scope"], "users.read");
    assert!(claims.get("scopes").is_none());

    let decoded = auth
        .authenticate_access_token(&payload.access_token)
        .unwrap();
    assert_eq!(decoded.user_id, "user-1");
    assert!(matches!(auth.jwks(), Err(AuthError::JwksUnsupported)));
}

#[test]
fn hs256_rejects_secret_shorter_than_32_bytes() {
    let result = AuthService::new(
        AuthConfig::new("short-secret"),
        Arc::new(MemoryUserStore::default()),
        Arc::new(MemoryRefreshTokenStore::default()),
    );
    let err = match result {
        Ok(_) => panic!("short HS256 secret should fail construction"),
        Err(err) => err,
    };
    assert!(matches!(err, AuthError::InvalidConfiguration(_)));
}

#[test]
fn hs256_accepts_32_byte_secret() {
    let secret = "12345678901234567890123456789012";
    let result = AuthService::new(
        AuthConfig::new(secret),
        Arc::new(MemoryUserStore::default()),
        Arc::new(MemoryRefreshTokenStore::default()),
    );
    assert!(result.is_ok());
}

#[tokio::test]
async fn legacy_jwt_secret_field_no_longer_overrides_signing_config() {
    let mut config = AuthConfig::with_hs256_secret(TEST_HS256_SECRET);
    config.jwt_secret = OTHER_HS256_SECRET.to_string();
    let auth = auth_service(config);
    let payload = auth
        .issue_verified_user_session("user-1", vec![], AuthMethod::Password, metadata())
        .await
        .unwrap();

    let expected_secret_verifier = auth_service(AuthConfig::new(TEST_HS256_SECRET));
    expected_secret_verifier
        .authenticate_access_token(&payload.access_token)
        .unwrap();

    let legacy_field_verifier = auth_service(AuthConfig::new(OTHER_HS256_SECRET));
    assert!(matches!(
        legacy_field_verifier
            .authenticate_access_token(&payload.access_token)
            .unwrap_err(),
        AuthError::InvalidAccessToken
    ));
}

#[tokio::test]
async fn issued_access_tokens_include_purpose() {
    let auth = auth_service(AuthConfig::new(TEST_HS256_SECRET));
    let payload = auth
        .issue_verified_user_session("user-1", vec![], AuthMethod::Password, metadata())
        .await
        .unwrap();
    let claims = decode_payload(&payload.access_token);
    assert_eq!(claims["typ"], "access");
    assert_eq!(claims["purpose"], "access_token");
}

#[tokio::test]
async fn refreshable_access_token_omits_unset_optional_top_level_claims() {
    let auth = auth_service(rs256_config("auth-key-1"));
    let issued = auth
        .issue_verified_user_session_with_scopes(
            "user-1",
            vec!["Operator".to_string()],
            vec!["records.read".to_string()],
            AuthMethod::Password,
            metadata(),
        )
        .await
        .unwrap();

    let claims = decode_payload(&issued.access_token);
    assert_unset_access_claims_absent(
        &claims,
        &[
            "nbf",
            "tenant_id",
            "organization_id",
            "actor",
            "auth_time",
            "amr",
            "acr",
            "cnf",
            "resource_type",
            "resource_id",
            "correlation_id",
        ],
    );
    assert!(claims.get("session_family_id").is_some());
    assert!(!decode_payload_json(&issued.access_token).contains("\"nbf\":null"));
    auth.authenticate_access_token(&issued.access_token)
        .unwrap();

    let diagnostics = format!("{issued:?}");
    assert!(!diagnostics.contains(&issued.access_token));
    assert!(!diagnostics.contains(&issued.refresh_token));
    assert!(!diagnostics.contains(RSA_PRIVATE_KEY_A.lines().nth(1).unwrap()));
}

#[tokio::test]
async fn access_token_only_omits_unset_optional_top_level_claims() {
    let auth = auth_service(rs256_config("auth-key-1"));
    let grant = auth
        .issue_access_token_only(AccessTokenOnlyRequest::new(
            "machine-1",
            vec!["Worker".to_string()],
            vec!["jobs.run".to_string()],
            SessionContext::for_auth_method(AuthMethod::ServiceToken),
        ))
        .await
        .unwrap();

    let claims = decode_payload(&grant.access_token);
    assert_unset_access_claims_absent(
        &claims,
        &[
            "nbf",
            "tenant_id",
            "organization_id",
            "session_family_id",
            "actor",
            "auth_time",
            "amr",
            "acr",
            "cnf",
            "resource_type",
            "resource_id",
            "correlation_id",
        ],
    );
    assert!(!decode_payload_json(&grant.access_token).contains("\"nbf\":null"));
    auth.authenticate_access_token(&grant.access_token).unwrap();

    let diagnostics = format!("{grant:?}");
    assert!(!diagnostics.contains(&grant.access_token));
    assert!(!diagnostics.contains(RSA_PRIVATE_KEY_A.lines().nth(1).unwrap()));
}

#[tokio::test]
async fn populated_optional_access_token_metadata_serializes_and_round_trips() {
    let auth = auth_service(rs256_config("auth-key-1"));
    let authenticated_at = OffsetDateTime::from_unix_timestamp(1_700_000_123).unwrap();
    let assurance = SessionAssurance::new(
        authenticated_at,
        ["pwd", "otp"],
        Some("urn:example:loa:2".to_string()),
        Some("example-policy".to_string()),
        MfaAcceptance::Satisfied,
    )
    .unwrap();
    let actor = ActorIdentity {
        sub: "operator-1".to_string(),
        amr: vec!["hwk".to_string()],
    };
    let confirmation = ConfirmationClaims {
        x5t_s256: Some("certificate-thumbprint".to_string()),
        jkt: Some("jwk-thumbprint".to_string()),
    };
    let mut request = AccessTokenOnlyRequest::new(
        "user-1",
        vec!["Operator".to_string()],
        vec!["records.read".to_string()],
        SessionContext::for_auth_method(AuthMethod::Oidc).with_assurance(assurance.clone()),
    );
    request.tenant_id = Some("tenant-1".to_string());
    request.organization_id = Some("organization-1".to_string());
    request.session_family_id = Some("family-1".to_string());
    request.actor = Some(actor.clone());
    request.auth_time = Some(authenticated_at.unix_timestamp());
    request.amr = Some(vec!["pwd".to_string(), "otp".to_string()]);
    request.acr = Some("urn:example:loa:2".to_string());
    request.cnf = Some(confirmation.clone());
    request.resource_type = Some("record".to_string());
    request.resource_id = Some("record-1".to_string());
    request.correlation_id = Some("correlation-1".to_string());

    let grant = auth.issue_access_token_only(request).await.unwrap();
    let claims = decode_payload(&grant.access_token);
    assert_eq!(claims["tenant_id"], "tenant-1");
    assert_eq!(claims["organization_id"], "organization-1");
    assert_eq!(claims["session_family_id"], "family-1");
    assert_eq!(
        claims["actor"],
        json!({"sub": "operator-1", "amr": ["hwk"]})
    );
    assert_eq!(claims["auth_time"], authenticated_at.unix_timestamp());
    assert_eq!(claims["amr"], json!(["pwd", "otp"]));
    assert_eq!(claims["acr"], "urn:example:loa:2");
    assert_eq!(
        claims["cnf"],
        json!({"x5t#S256": "certificate-thumbprint", "jkt": "jwk-thumbprint"})
    );
    assert_eq!(claims["resource_type"], "record");
    assert_eq!(claims["resource_id"], "record-1");
    assert_eq!(claims["correlation_id"], "correlation-1");
    assert!(claims.get("nbf").is_none());

    let decoded = auth.authenticate_access_token(&grant.access_token).unwrap();
    assert_eq!(decoded.session.assurance, Some(assurance));
    assert_eq!(decoded.token_claims.tenant_id.as_deref(), Some("tenant-1"));
    assert_eq!(
        decoded.token_claims.organization_id.as_deref(),
        Some("organization-1")
    );
    assert_eq!(
        decoded.token_claims.session_family_id.as_deref(),
        Some("family-1")
    );
    assert_eq!(decoded.token_claims.actor, Some(actor));
    assert_eq!(
        decoded.token_claims.auth_time,
        Some(authenticated_at.unix_timestamp())
    );
    assert_eq!(
        decoded.token_claims.amr,
        Some(vec!["pwd".to_string(), "otp".to_string()])
    );
    assert_eq!(
        decoded.token_claims.acr.as_deref(),
        Some("urn:example:loa:2")
    );
    assert_eq!(decoded.token_claims.cnf, Some(confirmation));
    assert_eq!(
        decoded.token_claims.resource_type.as_deref(),
        Some("record")
    );
    assert_eq!(
        decoded.token_claims.resource_id.as_deref(),
        Some("record-1")
    );
    assert_eq!(
        decoded.token_claims.correlation_id.as_deref(),
        Some("correlation-1")
    );
}

#[test]
fn invalid_token_diagnostics_do_not_expose_raw_token_or_key_material() {
    let auth = auth_service(AuthConfig::new(TEST_HS256_SECRET));
    let raw_token = "raw-token-secret-marker";
    let error = auth.authenticate_access_token(raw_token).unwrap_err();
    let diagnostics = format!("{error:?} {error}");
    assert!(!diagnostics.contains(raw_token));
    assert!(!diagnostics.contains(TEST_HS256_SECRET));
    assert!(!diagnostics.contains(RSA_PRIVATE_KEY_A.lines().nth(1).unwrap()));
}

#[test]
fn purpose_tokens_validate_exact_purpose_and_audience() {
    let auth = auth_service(AuthConfig::new(TEST_HS256_SECRET));
    let session_id = Uuid::new_v4();
    let issued = auth
        .issue_purpose_token(
            PurposeTokenIssueRequest::new(
                "user-1",
                "capture_upload",
                "capture-upload-clients",
                Duration::minutes(15),
            )
            .with_session_id(session_id)
            .with_scopes(["collection.collection-1.records.create"])
            .with_claim("col", json!("collection-1"))
            .with_claim("acc", json!(null)),
        )
        .unwrap();

    let claims = decode_payload(&issued.token);
    assert_eq!(claims["typ"], "purpose_token");
    assert_eq!(claims["purpose"], "capture_upload");
    assert_eq!(claims["aud"], "capture-upload-clients");
    assert_eq!(claims["col"], "collection-1");

    let verified = auth
        .authenticate_purpose_token(
            &issued.token,
            PurposeTokenValidation::new("capture_upload", "capture-upload-clients"),
        )
        .unwrap();
    assert_eq!(verified.subject, "user-1");
    assert_eq!(verified.session_id, Some(session_id));
    assert_eq!(
        verified.scopes,
        vec!["collection.collection-1.records.create".to_string()]
    );
    assert_eq!(verified.claims["col"], json!("collection-1"));

    assert!(matches!(
        auth.authenticate_access_token(&issued.token).unwrap_err(),
        AuthError::InvalidAccessToken
    ));
    assert!(matches!(
        auth.authenticate_purpose_token(
            &issued.token,
            PurposeTokenValidation::new("access_token", "capture-upload-clients"),
        )
        .unwrap_err(),
        AuthError::InvalidPurposeToken
    ));
    assert!(matches!(
        auth.authenticate_purpose_token(
            &issued.token,
            PurposeTokenValidation::new("capture_upload", "other-audience"),
        )
        .unwrap_err(),
        AuthError::InvalidPurposeToken
    ));
}

#[test]
fn purpose_tokens_reject_reserved_custom_claims() {
    let auth = auth_service(AuthConfig::new(TEST_HS256_SECRET));
    let err = auth
        .issue_purpose_token(
            PurposeTokenIssueRequest::new(
                "user-1",
                "capture_upload",
                "capture-upload-clients",
                Duration::minutes(15),
            )
            .with_claim("aud", json!("other-audience")),
        )
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidConfiguration(_)));
}

#[test]
fn legacy_access_tokens_without_purpose_still_decode() {
    let auth = auth_service(AuthConfig::new(TEST_HS256_SECRET));
    let claims = access_token_claims_json(None);
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(TEST_HS256_SECRET.as_bytes()),
    )
    .unwrap();

    let decoded = auth.authenticate_access_token(&token).unwrap();
    assert_eq!(decoded.user_id, "user-1");
}

#[test]
fn access_token_rejects_wrong_purpose() {
    let auth = auth_service(AuthConfig::new(TEST_HS256_SECRET));
    let claims = access_token_claims_json(Some("password_reset"));
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(TEST_HS256_SECRET.as_bytes()),
    )
    .unwrap();

    let err = auth.authenticate_access_token(&token).unwrap_err();
    assert!(matches!(err, AuthError::InvalidAccessToken));
}

#[tokio::test]
async fn rs256_tokens_are_issued_and_validated_with_kid() {
    let auth = auth_service(rs256_config("auth-key-1"));
    let payload = auth
        .issue_verified_user_session_with_scopes(
            "user-1",
            vec!["CatalogEditor".to_string()],
            vec!["users.read".to_string()],
            AuthMethod::Password,
            metadata(),
        )
        .await
        .unwrap();

    let header = decode_header(&payload.access_token).unwrap();
    assert_eq!(header.alg, Algorithm::RS256);
    assert_eq!(header.kid.as_deref(), Some("auth-key-1"));

    let claims = decode_payload(&payload.access_token);
    assert_claim_shape(&claims);
    assert_eq!(claims["sub"], "user-1");
    assert_eq!(claims["roles"], json!(["CatalogEditor"]));
    assert_eq!(claims["scope"], "users.read");
    assert!(claims.get("scopes").is_none());

    let decoded = auth
        .authenticate_access_token(&payload.access_token)
        .unwrap();
    assert_eq!(decoded.user_id, "user-1");
    assert_eq!(decoded.roles, vec!["CatalogEditor".to_string()]);
    assert_eq!(decoded.scopes, vec!["users.read".to_string()]);
}

#[tokio::test]
async fn rs256_rejects_wrong_public_key() {
    let issuer = auth_service(rs256_config("auth-key-1"));
    let verifier = auth_service(rs256_config_with_keys(
        RSA_PRIVATE_KEY_B,
        RSA_PUBLIC_KEY_B,
        "auth-key-1",
    ));
    let payload = issuer
        .issue_verified_user_session("user-1", vec![], AuthMethod::Password, metadata())
        .await
        .unwrap();

    let err = verifier
        .authenticate_access_token(&payload.access_token)
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidAccessToken));
}

#[test]
fn rs256_rejects_mismatched_key_pair_at_construction() {
    let result = AuthService::new(
        rs256_config_with_keys(RSA_PRIVATE_KEY_A, RSA_PUBLIC_KEY_B, "auth-key-1"),
        Arc::new(MemoryUserStore::default()),
        Arc::new(MemoryRefreshTokenStore::default()),
    );
    let err = match result {
        Ok(_) => panic!("mismatched key pair should fail construction"),
        Err(err) => err,
    };
    assert!(matches!(err, AuthError::InvalidConfiguration(_)));
}

#[test]
fn rs256_requires_non_empty_kid() {
    let result = AuthService::new(
        rs256_config_with_keys(RSA_PRIVATE_KEY_A, RSA_PUBLIC_KEY_A, ""),
        Arc::new(MemoryUserStore::default()),
        Arc::new(MemoryRefreshTokenStore::default()),
    );
    let err = match result {
        Ok(_) => panic!("empty key id should fail construction"),
        Err(err) => err,
    };
    assert!(matches!(err, AuthError::InvalidConfiguration(_)));
}

#[tokio::test]
async fn rs256_rejects_wrong_issuer_and_audience() {
    let issuer = auth_service(rs256_config("auth-key-1"));
    let payload = issuer
        .issue_verified_user_session("user-1", vec![], AuthMethod::Password, metadata())
        .await
        .unwrap();

    let mut wrong_issuer_config = rs256_config("auth-key-1");
    wrong_issuer_config.issuer = "other-issuer".to_string();
    let wrong_issuer = auth_service(wrong_issuer_config);
    assert!(matches!(
        wrong_issuer
            .authenticate_access_token(&payload.access_token)
            .unwrap_err(),
        AuthError::InvalidAccessToken
    ));

    let mut wrong_audience_config = rs256_config("auth-key-1");
    wrong_audience_config.audience = "other-audience".to_string();
    let wrong_audience = auth_service(wrong_audience_config);
    assert!(matches!(
        wrong_audience
            .authenticate_access_token(&payload.access_token)
            .unwrap_err(),
        AuthError::InvalidAccessToken
    ));
}

#[tokio::test]
async fn rs256_rejects_expired_token() {
    let mut config = rs256_config("auth-key-1");
    config.access_token_ttl = Duration::seconds(-5);
    let auth = auth_service(config);
    let payload = auth
        .issue_verified_user_session("user-1", vec![], AuthMethod::Password, metadata())
        .await
        .unwrap();

    let err = auth
        .authenticate_access_token(&payload.access_token)
        .unwrap_err();
    assert!(matches!(err, AuthError::AccessTokenExpired));
}

#[tokio::test]
async fn rs256_rejects_algorithm_confusion_and_wrong_kid() {
    let auth = auth_service(rs256_config("auth-key-1"));
    let claims = json!({
        "sub": "user-1",
        "sid": Uuid::new_v4().to_string(),
        "roles": [],
        "scopes": [],
        "ctx": SessionContext::for_auth_method(AuthMethod::Password),
        "iss": "agql-auth",
        "aud": "agql-auth-clients",
        "exp": (OffsetDateTime::now_utc() + Duration::minutes(5)).unix_timestamp(),
        "iat": OffsetDateTime::now_utc().unix_timestamp(),
    });

    let hs_token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(TEST_HS256_SECRET.as_bytes()),
    )
    .unwrap();
    assert!(matches!(
        auth.authenticate_access_token(&hs_token).unwrap_err(),
        AuthError::InvalidAccessToken
    ));

    let mut wrong_kid_header = Header::new(Algorithm::RS256);
    wrong_kid_header.kid = Some("wrong-key".to_string());
    let wrong_kid_token = encode(
        &wrong_kid_header,
        &claims,
        &EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY_A.as_bytes()).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        auth.authenticate_access_token(&wrong_kid_token)
            .unwrap_err(),
        AuthError::InvalidAccessToken
    ));
}

#[test]
fn rs256_jwks_exports_public_key_only() {
    let auth = auth_service(rs256_config("auth-key-1"));
    let jwks = auth.jwks().unwrap();
    let keys = jwks["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    let key = &keys[0];
    assert_eq!(key["kty"], "RSA");
    assert_eq!(key["use"], "sig");
    assert_eq!(key["alg"], "RS256");
    assert_eq!(key["kid"], "auth-key-1");
    assert!(key["n"].as_str().is_some_and(|value| !value.is_empty()));
    assert!(key["e"].as_str().is_some_and(|value| !value.is_empty()));

    for private_field in ["d", "p", "q", "dp", "dq", "qi"] {
        assert!(key.get(private_field).is_none());
    }
    assert!(!jwks.to_string().contains("PRIVATE KEY"));
}

#[tokio::test]
async fn inject_http_auth_and_guards_work_with_rs256() {
    let user_store = MemoryUserStore::default();
    let refresh_store = MemoryRefreshTokenStore::default();
    let auth = AuthService::new(
        rs256_config("auth-key-1"),
        Arc::new(user_store.clone()),
        Arc::new(refresh_store),
    )
    .unwrap();
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

    let request = auth
        .inject_http_auth(
            async_graphql::Request::new("{ roleGuarded scopeGuarded }"),
            Some(&format!("Bearer {}", payload.access_token)),
        )
        .await
        .unwrap();
    let schema = Schema::build(GuardedQuery, EmptyMutation, EmptySubscription).finish();
    let response = schema.execute(request).await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
}

fn auth_service(config: AuthConfig) -> AuthService<MemoryUserStore, MemoryRefreshTokenStore> {
    AuthService::new(
        config,
        Arc::new(MemoryUserStore::default()),
        Arc::new(MemoryRefreshTokenStore::default()),
    )
    .unwrap()
}

fn rs256_config(key_id: &str) -> AuthConfig {
    rs256_config_with_keys(RSA_PRIVATE_KEY_A, RSA_PUBLIC_KEY_A, key_id)
}

fn rs256_config_with_keys(private_key_pem: &str, public_key_pem: &str, key_id: &str) -> AuthConfig {
    AuthConfig::with_rs256_pem(private_key_pem, public_key_pem, key_id)
}

fn decode_payload(token: &str) -> JsonValue {
    let payload = token.split('.').nth(1).unwrap();
    let bytes = URL_SAFE_NO_PAD.decode(payload).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn decode_payload_json(token: &str) -> String {
    let payload = token.split('.').nth(1).unwrap();
    let bytes = URL_SAFE_NO_PAD.decode(payload).unwrap();
    String::from_utf8(bytes).unwrap()
}

fn assert_unset_access_claims_absent(claims: &JsonValue, expected_absent: &[&str]) {
    let object = claims.as_object().unwrap();
    for key in expected_absent {
        assert!(
            !object.contains_key(*key),
            "unset optional claim must be absent: {key}"
        );
    }
    assert!(
        object.values().all(|value| !value.is_null()),
        "issued access tokens must not contain top-level null claims"
    );
}

fn assert_claim_shape(claims: &JsonValue) {
    for key in [
        "sub", "sid", "roles", "scope", "ctx", "iss", "aud", "exp", "iat",
    ] {
        assert!(claims.get(key).is_some(), "missing claim {key}");
    }
}

fn access_token_claims_json(purpose: Option<&str>) -> JsonValue {
    let issued_at = OffsetDateTime::now_utc();
    let mut claims = json!({
        "sub": "user-1",
        "sid": Uuid::new_v4().to_string(),
        "roles": [],
        "scopes": [],
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
