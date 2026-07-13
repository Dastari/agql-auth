use async_trait::async_trait;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::prelude::*;

fn user_principal(jti: &str, scopes: &[&str]) -> AuthPrincipal {
    AuthPrincipal::User(AuthUser {
        user_id: "user-42".to_owned(),
        session_id: Uuid::from_u128(42),
        roles: vec!["editor".to_owned()],
        scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        session: SessionContext::default(),
        token_claims: AccessTokenMetadata {
            jti: Some(jti.to_owned()),
            tenant_id: Some("tenant-a".to_owned()),
            session_family_id: Some("family-a".to_owned()),
            resource_type: Some("project".to_owned()),
            resource_id: Some("project-7".to_owned()),
            correlation_id: Some("correlation-1".to_owned()),
            expires_at: Some(OffsetDateTime::UNIX_EPOCH + Duration::hours(1)),
            ..AccessTokenMetadata::default()
        },
    })
}

#[test]
fn principal_reference_contains_no_authority_snapshot_or_credential() {
    let reference = user_principal("safe-jti", &["records:read", "records:write"]).reference();
    let json = serde_json::to_string(&reference).expect("reference should serialize");

    assert!(json.contains("safe-jti"));
    assert!(!json.contains("records:read"));
    assert!(!json.contains("records:write"));
    assert!(!json.contains("editor"));
    assert!(!json.contains("bearer"));
}

#[test]
fn refreshed_user_token_can_rehydrate_same_session_with_current_scopes() {
    let reference = user_principal("old-jti", &["records:write"]).reference();
    let current = user_principal("new-jti", &["records:read"]);

    let resolved = ResolvedPrincipal::new(reference, current, OffsetDateTime::UNIX_EPOCH)
        .expect("same session and bindings should resolve after token refresh");

    assert_eq!(resolved.principal().scopes(), &["records:read"]);
}

#[test]
fn rehydration_rejects_changed_resource_binding() {
    let reference = user_principal("jti", &["records:read"]).reference();
    let mut changed = user_principal("jti-2", &["records:read"]);
    if let AuthPrincipal::User(user) = &mut changed {
        user.token_claims.resource_id = Some("project-8".to_owned());
    }

    let result = ResolvedPrincipal::new(reference, changed, OffsetDateTime::UNIX_EPOCH);
    assert!(matches!(result, Err(crate::AuthError::Forbidden)));
}

#[test]
fn purpose_bound_grant_requires_exact_boundary() {
    let now = OffsetDateTime::UNIX_EPOCH + Duration::minutes(10);
    let principal = user_principal("jti", &["records:read"]);
    let grant = PurposeBoundGrantReference {
        grant_id: Uuid::from_u128(7),
        subject: "user-42".to_owned(),
        audience: "external-model".to_owned(),
        resource_type: "project".to_owned(),
        resource_id: "project-7".to_owned(),
        action: "data_egress".to_owned(),
        purpose: "assistant_response".to_owned(),
        granted_at: now - Duration::minutes(1),
        expires_at: now + Duration::minutes(1),
        revoked_at: None,
        assurance_ref: Some("recent-mfa".to_owned()),
    };

    assert_eq!(
        grant.evaluate(
            &principal,
            "external-model",
            "project",
            "project-7",
            "data_egress",
            "assistant_response",
            now,
        ),
        PurposeGrantStatus::Active
    );
    assert_eq!(
        grant.evaluate(
            &principal,
            "external-model",
            "project",
            "project-7",
            "data_egress",
            "different-purpose",
            now,
        ),
        PurposeGrantStatus::PurposeMismatch
    );
}

struct StaticResolver {
    principal: AuthPrincipal,
}

#[async_trait]
impl CurrentPrincipalResolver for StaticResolver {
    async fn resolve(
        &self,
        reference: &PrincipalReference,
    ) -> crate::AuthResult<ResolvedPrincipal> {
        ResolvedPrincipal::new(
            reference.clone(),
            self.principal.clone(),
            OffsetDateTime::UNIX_EPOCH,
        )
    }
}

#[tokio::test]
async fn resolver_returns_current_authority_not_stored_scopes() {
    let old = user_principal("old-jti", &["records:write"]);
    let resolver = StaticResolver {
        principal: user_principal("new-jti", &["records:read"]),
    };

    let resolved = resolver
        .resolve(&old.reference())
        .await
        .expect("same durable identity should resolve");

    assert!(resolved.principal().has_scope("records:read"));
    assert!(!resolved.principal().has_scope("records:write"));
}

#[test]
fn authorization_invocation_does_not_replace_actor() {
    let principal = user_principal("jti", &["records:read"]);
    let decision = AuthorizationDecision::from_principal(
        &principal,
        "records:read",
        AuthorizationOutcome::Allow,
        AuthorizationReasonCode::Allowed,
        OffsetDateTime::UNIX_EPOCH,
    )
    .with_invocation(
        AuthorizationInvocation::new("internal_service").with_causation_id("tool-call-1"),
    );

    assert_eq!(decision.decision.principal_ref, "user-42");
    assert_eq!(decision.invocation.mechanism, "internal_service");
}
