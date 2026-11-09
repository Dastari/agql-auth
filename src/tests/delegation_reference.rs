use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::prelude::*;

fn parent() -> AuthUser {
    AuthUser {
        user_id: "user-1".into(),
        session_id: Uuid::from_u128(42),
        roles: vec!["Editor".into(), "Admin".into()],
        scopes: vec![
            "records.read".into(),
            "records.write".into(),
            "admin.all".into(),
        ],
        session: SessionContext::for_auth_method(AuthMethod::Oidc),
        token_claims: AccessTokenMetadata {
            jti: Some("parent-token".into()),
            tenant_id: Some("tenant-1".into()),
            session_family_id: Some(Uuid::from_u128(7).to_string()),
            grant_kind: Some(AccessTokenGrantKind::UserSession),
            session_version: Some("v1".into()),
            authorization_roles: vec!["catalog.editor".into(), "catalog.owner".into()],
            expires_at: Some(OffsetDateTime::now_utc() + Duration::hours(1)),
            ..AccessTokenMetadata::default()
        },
    }
}

fn delegated() -> AuthUser {
    let mut user = parent();
    user.roles = vec!["Editor".into()];
    user.scopes = vec!["records.read".into()];
    let claims = &mut user.token_claims;
    claims.jti = Some("delegated-token".into());
    claims.grant_kind = Some(AccessTokenGrantKind::SessionBoundDelegation);
    claims.authorization_roles = vec!["catalog.editor".into()];
    claims.actor = Some(ActorIdentity {
        sub: "tool-agent".into(),
        amr: vec!["service".into()],
    });
    claims.resource_type = Some("project".into());
    claims.resource_id = Some("project-1".into());
    claims.correlation_id = Some("call-1".into());
    claims.operation = Some(ExactOperationBinding::new("Approve", "sha256:op"));
    claims.expires_at = Some(OffsetDateTime::now_utc() + Duration::minutes(5));
    user
}

fn user_of(principal: &AuthPrincipal) -> &AuthUser {
    match principal {
        AuthPrincipal::User(user) => user,
        AuthPrincipal::ApiToken(_) => panic!("expected a user principal"),
    }
}

#[test]
fn resolved_delegation_never_exceeds_the_delegated_token() {
    let accepted = AuthPrincipal::User(delegated());
    // A job persists the reference and later resolves it to the parent session.
    let persisted = serde_json::to_string(&accepted.reference()).unwrap();
    let reference: PrincipalReference = serde_json::from_str(&persisted).unwrap();
    let resolved = ResolvedPrincipal::new(
        reference,
        AuthPrincipal::User(parent()),
        OffsetDateTime::now_utc(),
    )
    .unwrap();

    for principal in [resolved.principal().clone(), resolved.into_principal()] {
        let user = user_of(&principal);
        assert_eq!(user.roles, vec!["Editor".to_string()]);
        assert_eq!(user.scopes, vec!["records.read".to_string()]);
        assert_eq!(
            user.token_claims.authorization_roles,
            vec!["catalog.editor".to_string()]
        );
        assert!(user.is_session_bound_delegation());
        assert_eq!(user.token_claims.jti.as_deref(), Some("delegated-token"));
        assert_eq!(user.token_claims.resource_type.as_deref(), Some("project"));
        assert_eq!(user.token_claims.resource_id.as_deref(), Some("project-1"));
        assert_eq!(
            user.token_claims
                .actor
                .as_ref()
                .map(|actor| actor.sub.as_str()),
            Some("tool-agent")
        );
        assert_eq!(
            user.token_claims.operation,
            Some(ExactOperationBinding::new("Approve", "sha256:op"))
        );
        assert_eq!(
            user.token_claims.expires_at,
            accepted.reference().expires_at
        );
        assert!(user.require_session_management_eligible().is_err());
    }
}

#[test]
fn resolved_delegation_drops_grants_the_parent_lost() {
    let accepted = AuthPrincipal::User(delegated());
    let mut current = parent();
    current.scopes.retain(|scope| scope != "records.read");
    current.token_claims.authorization_roles.clear();
    let resolved = ResolvedPrincipal::new(
        accepted.reference(),
        AuthPrincipal::User(current),
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    let user = user_of(resolved.principal());
    assert_eq!(user.roles, vec!["Editor".to_string()]);
    assert!(user.scopes.is_empty());
    assert!(user.token_claims.authorization_roles.is_empty());
}

#[test]
fn delegation_reference_without_a_ceiling_cannot_be_resolved() {
    let mut reference = AuthPrincipal::User(delegated()).reference();
    assert!(reference.grant_ceiling.is_some());
    reference.grant_ceiling = None;
    assert!(matches!(
        ResolvedPrincipal::new(
            reference,
            AuthPrincipal::User(parent()),
            OffsetDateTime::now_utc()
        ),
        Err(AuthError::Forbidden)
    ));
    // Other kinds carry no ceiling.
    assert!(
        AuthPrincipal::User(parent())
            .reference()
            .grant_ceiling
            .is_none()
    );
}

#[test]
fn resolved_delegation_keeps_assurance_only_for_the_same_authentication() {
    let authenticated_at =
        OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp()).unwrap();
    let assured = |at: OffsetDateTime| {
        let mut user = parent();
        let assurance =
            SessionAssurance::new(at, ["pwd", "otp"], None, None, MfaAcceptance::Satisfied)
                .unwrap();
        user.token_claims.auth_time = Some(assurance.auth_time());
        user.token_claims.amr = Some(assurance.methods.clone());
        user.session.mfa.satisfied = true;
        user.session.assurance = Some(assurance);
        user
    };
    let mut token = delegated();
    token.token_claims.auth_time = Some(authenticated_at.unix_timestamp());
    let reference = AuthPrincipal::User(token).reference();

    let same = ResolvedPrincipal::new(
        reference.clone(),
        AuthPrincipal::User(assured(authenticated_at)),
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    assert!(user_of(same.principal()).session.assurance.is_some());

    // A later step-up on the parent is not authority the delegated token had.
    let stepped_up = ResolvedPrincipal::new(
        reference,
        AuthPrincipal::User(assured(authenticated_at + Duration::minutes(1))),
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    let user = user_of(stepped_up.principal());
    assert!(user.session.assurance.is_none());
    assert!(!user.session.mfa.satisfied);
    assert_eq!(user.token_claims.auth_time, None);
    assert_eq!(user.token_claims.amr, None);
}

struct ParentResolver(AuthUser);

#[async_trait::async_trait]
impl CurrentPrincipalResolver for ParentResolver {
    async fn resolve(
        &self,
        reference: &PrincipalReference,
    ) -> crate::AuthResult<ResolvedPrincipal> {
        ResolvedPrincipal::new(
            reference.clone(),
            AuthPrincipal::User(self.0.clone()),
            OffsetDateTime::now_utc(),
        )
    }
}

struct Active;

#[async_trait::async_trait]
impl TokenStatusChecker for Active {
    async fn check(&self, _: TokenStatusRequest<'_>) -> crate::AuthResult<TokenStatus> {
        Ok(TokenStatus::Active)
    }
}

#[tokio::test]
async fn sensitive_revalidation_of_a_delegation_still_narrows_to_the_token() {
    let accepted = AuthPrincipal::User(delegated());
    let narrowed = revalidate_sensitive_principal(
        &accepted,
        &ParentResolver(parent()),
        &Active,
        OffsetDateTime::now_utc(),
    )
    .await
    .unwrap();
    assert_eq!(narrowed, accepted);
}

#[tokio::test]
async fn resolved_delegation_cannot_prepare_a_further_delegation() {
    let resolved = ResolvedPrincipal::new(
        AuthPrincipal::User(delegated()).reference(),
        AuthPrincipal::User(parent()),
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    let auth = super::test_auth_service(Default::default(), Default::default());
    let binding = SessionBoundDelegationBinding::new(
        ActorIdentity {
            sub: "tool-agent".into(),
            amr: Vec::new(),
        },
        "project",
        "project-1",
        "call-2",
        ExactOperationBinding::new("Approve", "sha256:op"),
    );
    assert!(matches!(
        auth.prepare_session_bound_access_token_only(
            &resolved,
            vec!["Editor".into()],
            vec!["records.read".into()],
            binding,
        )
        .await,
        Err(AuthError::Forbidden)
    ));
}
