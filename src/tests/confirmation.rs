use std::sync::Arc;

use async_graphql::{EmptyMutation, EmptySubscription, Object, Request, Schema};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value as JsonValue, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::jwt_signing::{RSA_PRIVATE_KEY_A, RSA_PUBLIC_KEY_A};
use crate::prelude::*;

const THUMBPRINT: &str = "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2";

fn claims(cnf: Option<JsonValue>) -> JsonValue {
    let now = OffsetDateTime::now_utc();
    let mut claims = json!({
        "typ": "access",
        "purpose": "access_token",
        "jti": Uuid::new_v4().to_string(),
        "tenant_id": "tenant-1",
        "sub": "user-1",
        "sid": Uuid::new_v4().to_string(),
        "roles": [],
        "ctx": SessionContext::for_auth_method(AuthMethod::Password),
        "iss": "agql-auth",
        "aud": "agql-auth-clients",
        "exp": (now + Duration::minutes(5)).unix_timestamp(),
        "iat": now.unix_timestamp(),
    });
    if let Some(cnf) = cnf {
        claims["cnf"] = cnf;
    }
    claims
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

fn validator(requirements: ClaimRequirements) -> AccessTokenValidator {
    AccessTokenValidator::builder()
        .issuer("agql-auth")
        .audience("agql-auth-clients")
        .rs256_public_pem(RSA_PUBLIC_KEY_A)
        .key_id("auth-key-1")
        .claim_requirements(requirements)
        .build()
        .unwrap()
}

// `require_cnf` proves possession, not mere presence of a claim.
#[test]
fn tenant_jti_and_cnf_requires_the_presented_thumbprint() {
    let validator = validator(ClaimRequirements::tenant_jti_and_cnf());
    let bound = sign(&claims(Some(json!({ "x5t#S256": THUMBPRINT }))));

    // A stolen bound token replayed without the certificate fails.
    assert!(matches!(
        validator.authenticate_access_token(&bound),
        Err(AuthError::InvalidAccessToken)
    ));
    assert!(matches!(
        validator.authenticate_bearer_with_confirmation(
            &format!("Bearer {bound}"),
            &PresentedConfirmation::certificate_thumbprint("another-certificate"),
        ),
        Err(AuthError::InvalidAccessToken)
    ));
    assert!(matches!(
        validator.authenticate_access_token_with_confirmation(
            &bound,
            &PresentedConfirmation::jwk_thumbprint(THUMBPRINT),
        ),
        Err(AuthError::InvalidAccessToken)
    ));
    assert_eq!(
        validator
            .authenticate_bearer_with_confirmation(
                &format!("Bearer {bound}"),
                &PresentedConfirmation::certificate_thumbprint(THUMBPRINT),
            )
            .unwrap()
            .user_id,
        "user-1"
    );

    let unbound = sign(&claims(None));
    assert!(
        validator
            .authenticate_access_token_with_confirmation(
                &unbound,
                &PresentedConfirmation::certificate_thumbprint(THUMBPRINT),
            )
            .is_err()
    );
}

#[test]
fn confirmation_is_checked_whenever_material_is_presented() {
    let validator = validator(ClaimRequirements::none());
    let bound = sign(&claims(Some(json!({ "jkt": THUMBPRINT }))));
    assert!(
        validator
            .authenticate_access_token_with_confirmation(
                &bound,
                &PresentedConfirmation::jwk_thumbprint("other"),
            )
            .is_err()
    );
    assert!(
        validator
            .authenticate_access_token_with_confirmation(
                &bound,
                &PresentedConfirmation::jwk_thumbprint(THUMBPRINT),
            )
            .is_ok()
    );
    // An unbound token is fine when binding is not required.
    let unbound = sign(&claims(None));
    assert!(
        validator
            .authenticate_access_token_with_confirmation(
                &unbound,
                &PresentedConfirmation::jwk_thumbprint(THUMBPRINT),
            )
            .is_ok()
    );

    // A token bound to both methods needs both.
    let both = sign(&claims(Some(
        json!({ "x5t#S256": THUMBPRINT, "jkt": THUMBPRINT }),
    )));
    assert!(
        validator
            .authenticate_access_token_with_confirmation(
                &both,
                &PresentedConfirmation::certificate_thumbprint(THUMBPRINT),
            )
            .is_err()
    );
    assert!(
        validator
            .authenticate_access_token_with_confirmation(
                &both,
                &PresentedConfirmation::certificate_thumbprint(THUMBPRINT)
                    .with_jwk_thumbprint(THUMBPRINT),
            )
            .is_ok()
    );
}

#[tokio::test]
async fn injection_with_confirmation_checks_the_binding() {
    let validator = validator(ClaimRequirements::tenant_jti_and_cnf());
    let bound = format!(
        "Bearer {}",
        sign(&claims(Some(json!({ "x5t#S256": THUMBPRINT }))))
    );
    assert!(
        validator
            .inject_http_auth(Request::new("{ ok }"), Some(&bound))
            .is_err()
    );
    assert!(
        validator
            .inject_http_auth_with_confirmation(Request::new("{ ok }"), Some(&bound), None)
            .is_err()
    );
    let request = validator
        .inject_http_auth_with_confirmation(
            Request::new("{ ok }"),
            Some(&bound),
            Some(&PresentedConfirmation::certificate_thumbprint(THUMBPRINT)),
        )
        .unwrap();
    let schema = Schema::build(Query, EmptyMutation, EmptySubscription).finish();
    let response = schema.execute(request).await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
}

#[test]
fn metadata_confirmation_check_is_exact() {
    let metadata = AccessTokenMetadata {
        cnf: Some(ConfirmationClaims {
            x5t_s256: Some(THUMBPRINT.to_string()),
            jkt: None,
        }),
        ..AccessTokenMetadata::default()
    };
    assert!(
        metadata
            .verify_confirmation(&PresentedConfirmation::certificate_thumbprint(THUMBPRINT))
            .is_ok()
    );
    for near_miss in [&THUMBPRINT[1..], "", &format!("{THUMBPRINT}x")] {
        assert!(
            metadata
                .verify_confirmation(&PresentedConfirmation::certificate_thumbprint(near_miss))
                .is_err()
        );
    }
    assert!(
        AccessTokenMetadata::default()
            .verify_confirmation(&PresentedConfirmation::certificate_thumbprint(THUMBPRINT))
            .is_err()
    );
    let debug = format!(
        "{:?}",
        PresentedConfirmation::certificate_thumbprint(THUMBPRINT)
    );
    assert!(!debug.contains(THUMBPRINT));
}

struct Query;

#[Object]
impl Query {
    #[graphql(guard = "RequireAuth::new()")]
    async fn ok(&self) -> bool {
        true
    }
}

struct DelegatedQuery;

#[Object]
impl DelegatedQuery {
    #[graphql(guard = "RequireScope::new(\"orders.read\").allow_delegated()")]
    async fn scope(&self) -> bool {
        true
    }

    #[graphql(guard = "RequireAuth::new().allow_delegated()")]
    async fn auth(&self) -> bool {
        true
    }

    #[graphql(guard = "RequirePrincipalScope::new(\"orders.read\").allow_delegated()")]
    async fn principal_scope(&self) -> bool {
        true
    }

    #[graphql(guard = "RequireAllRoles::new([\"Editor\"]).allow_delegated()")]
    async fn all_roles(&self) -> bool {
        true
    }
}

// a guard may explicitly admit delegated tokens.
#[tokio::test]
async fn guards_admit_delegated_tokens_only_when_opted_in() {
    let schema = Schema::build(DelegatedQuery, EmptyMutation, EmptySubscription).finish();
    let user = AuthUser {
        user_id: "user-1".to_string(),
        session_id: Uuid::new_v4(),
        roles: vec!["Editor".to_string()],
        scopes: vec!["orders.read".to_string()],
        session: SessionContext::for_auth_method(AuthMethod::Password),
        token_claims: AccessTokenMetadata {
            grant_kind: Some(AccessTokenGrantKind::SessionBoundDelegation),
            actor: Some(ActorIdentity {
                sub: "agent".to_string(),
                amr: Vec::new(),
            }),
            ..AccessTokenMetadata::default()
        },
    };
    assert!(user.token_claims.is_delegated());
    let response = schema
        .execute(
            Request::new("{ scope auth principalScope allRoles }")
                .data(AuthPrincipal::User(user.clone()))
                .data(user)
                .data(AuthRuntime::new(Arc::new(ExactScopeMatch))),
        )
        .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
}
