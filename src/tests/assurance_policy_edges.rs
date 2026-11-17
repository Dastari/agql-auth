use std::sync::Arc;

use async_trait::async_trait;
use time::{Duration, OffsetDateTime};

use super::{MemoryRefreshTokenStore, MemoryUserStore, metadata, stored_user, test_auth_service};
use crate::prelude::*;

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp()).unwrap()
}

fn assured_user(methods: &[&str], context: Option<&str>) -> AuthUser {
    let assurance = SessionAssurance::new(
        now(),
        methods.iter().copied(),
        Some("urn:example:loa:2".to_string()),
        context.map(str::to_string),
        MfaAcceptance::Satisfied,
    )
    .unwrap();
    AuthUser {
        user_id: "user-1".to_string(),
        session_id: uuid::Uuid::new_v4(),
        roles: vec![],
        scopes: vec![],
        session: SessionContext::for_auth_method(AuthMethod::Oidc)
            .with_assurance(assurance.clone()),
        token_claims: AccessTokenMetadata {
            auth_time: Some(assurance.auth_time()),
            amr: Some(assurance.methods.clone()),
            acr: assurance.acr.clone(),
            ..AccessTokenMetadata::default()
        },
    }
}

fn open_policy() -> RecentMfaPolicy {
    RecentMfaPolicy {
        maximum_age: Duration::minutes(5),
        clock_skew: Duration::seconds(30),
        allowed_amr: vec![],
        allowed_acr: vec![],
        match_mode: AssuranceMatchMode::All,
        required_amr: vec![],
        required_context: None,
    }
}

fn denial(policy: &RecentMfaPolicy, user: &AuthUser) -> Option<AssuranceDenialCode> {
    policy
        .evaluate(user, &FixedClock::new(now()))
        .err()
        .map(|denial| denial.code())
}

#[test]
fn accepted_mfa_without_any_method_never_satisfies_a_policy() {
    let user = assured_user(&[], None);
    assert_eq!(
        denial(&open_policy(), &user),
        Some(AssuranceDenialCode::AssuranceMethodNotAllowed)
    );
    assert_eq!(denial(&open_policy(), &assured_user(&["otp"], None)), None);
}

#[test]
fn amr_allowlists_are_normalized_like_session_methods() {
    let user = assured_user(&["otp"], None);
    let mut policy = open_policy();
    policy.allowed_amr = vec![" TOTP ".to_string(), "OTP".to_string()];
    assert_eq!(denial(&policy, &user), None);
    policy.allowed_amr = vec!["HWK".to_string()];
    assert_eq!(
        denial(&policy, &user),
        Some(AssuranceDenialCode::AssuranceMethodNotAllowed)
    );
    policy.allowed_amr = vec!["  ".to_string()];
    assert_eq!(
        denial(&policy, &user),
        Some(AssuranceDenialCode::AssurancePolicyError)
    );
}

struct CurrentGrant;

#[async_trait]
impl RefreshGrantAuthority for CurrentGrant {
    async fn current_grant(
        &self,
        token: &StoredRefreshToken,
        _: &StoredUser,
    ) -> crate::AuthResult<CurrentRefreshGrant> {
        Ok(CurrentRefreshGrant {
            roles: token.roles.clone(),
            scopes: token.scopes.clone(),
        })
    }
}

#[tokio::test]
async fn step_up_with_no_methods_is_refused_without_rotating() {
    let refresh_store = MemoryRefreshTokenStore::default();
    let users = MemoryUserStore::default();
    let auth = test_auth_service(users.clone(), refresh_store.clone())
        .with_refresh_grant_authority(Arc::new(CurrentGrant));
    users.insert(stored_user(&auth, "user-1", "user@example.test", "pw-123"));
    let session = auth
        .issue_verified_user_session("user-1", vec![], AuthMethod::Password, metadata())
        .await
        .unwrap();
    for methods in [vec![], vec!["  ".to_string()]] {
        let error = auth
            .step_up_session(
                &session.refresh_token,
                StepUpAuthentication {
                    methods,
                    acr: None,
                    context: None,
                },
                metadata(),
                &FixedClock::new(now()),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(error, AuthError::InvalidConfiguration(_)),
            "{error:?}"
        );
    }
    assert_eq!(*refresh_store.rotations.lock().unwrap(), 0);
    auth.refresh(&session.refresh_token, metadata())
        .await
        .unwrap();
}

#[test]
fn required_amr_demands_every_listed_method() {
    let mut policy = RecentMfaPolicy::new(Duration::minutes(5));
    policy.required_amr = vec!["PWD".to_string(), "hwk".to_string()];
    assert_eq!(
        denial(&policy, &assured_user(&["pwd", "hwk", "otp"], None)),
        None
    );
    for methods in [&["pwd"][..], &["hwk"], &["otp"]] {
        assert_eq!(
            denial(&policy, &assured_user(methods, None)),
            Some(AssuranceDenialCode::AssuranceMethodNotAllowed)
        );
    }
    // Required methods apply even when an Any allowlist already matched.
    policy.allowed_amr = vec!["otp".to_string()];
    policy.match_mode = AssuranceMatchMode::Any;
    assert_eq!(
        denial(&policy, &assured_user(&["otp", "pwd"], None)),
        Some(AssuranceDenialCode::AssuranceMethodNotAllowed)
    );
    policy.required_amr = vec![String::new()];
    assert_eq!(
        denial(&policy, &assured_user(&["otp"], None)),
        Some(AssuranceDenialCode::AssurancePolicyError)
    );
}

#[test]
fn required_context_keeps_provider_namespaces_apart() {
    let mut policy = RecentMfaPolicy::new(Duration::minutes(5));
    policy.allowed_acr = vec!["urn:example:loa:2".to_string()];
    policy.required_context = Some("idp-a".to_string());
    assert_eq!(
        denial(&policy, &assured_user(&["otp"], Some("idp-a"))),
        None
    );
    for context in [Some("idp-b"), Some("IDP-A"), None] {
        assert_eq!(
            denial(&policy, &assured_user(&["otp"], context)),
            Some(AssuranceDenialCode::AssuranceMethodNotAllowed)
        );
    }
    // Without a required context, the same ACR from any namespace matches.
    policy.required_context = None;
    assert_eq!(
        denial(&policy, &assured_user(&["otp"], Some("idp-b"))),
        None
    );
}
