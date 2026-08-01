use time::{Duration, OffsetDateTime};

use super::{MemoryRefreshTokenStore, MemoryUserStore, metadata, stored_user, test_auth_service};
use crate::prelude::*;
use crate::util::hash_refresh_token;

fn accepted(at: OffsetDateTime) -> SessionAssurance {
    SessionAssurance::new(
        at,
        ["  OTP ", "pwd", "otp"],
        Some("urn:example:loa:2".to_string()),
        Some("example-idp".to_string()),
        MfaAcceptance::Satisfied,
    )
    .unwrap()
}

fn policy(maximum_age: Duration) -> RecentMfaPolicy {
    RecentMfaPolicy {
        maximum_age,
        clock_skew: Duration::seconds(30),
        allowed_amr: vec!["otp".to_string()],
        allowed_acr: vec!["urn:example:loa:2".to_string()],
        match_mode: AssuranceMatchMode::All,
    }
}

fn user_with_assurance(assurance: SessionAssurance) -> AuthUser {
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

#[tokio::test]
async fn refreshable_issuance_and_multiple_rotations_preserve_exact_assurance() {
    let refresh_store = MemoryRefreshTokenStore::default();
    let user_store = MemoryUserStore::default();
    let auth = test_auth_service(user_store.clone(), refresh_store.clone());
    user_store.insert(stored_user(
        &auth,
        "user-1",
        "user@example.test",
        "password123",
    ));
    let authenticated_at = OffsetDateTime::from_unix_timestamp(1_700_000_123).unwrap();
    let assurance = accepted(authenticated_at);
    let session =
        SessionContext::for_auth_method(AuthMethod::Oidc).with_assurance(assurance.clone());
    let refreshable = RefreshableTokenMetadata {
        tenant_id: Some("tenant-1".to_string()),
        organization_id: Some("organization-1".to_string()),
        actor: Some(ActorIdentity {
            sub: "operator-1".to_string(),
            amr: vec!["hwk".to_string()],
        }),
        correlation_id: Some("correlation-1".to_string()),
    };

    let first = auth
        .issue_session_for_user_with_metadata(
            "user-1",
            vec!["member".to_string()],
            vec!["records.read".to_string()],
            session,
            refreshable.clone(),
            metadata(),
        )
        .await
        .unwrap();

    assert_eq!(first.user.session.assurance.as_ref(), Some(&assurance));
    assert!(first.user.session.mfa.satisfied);
    assert_eq!(first.user.token_claims.auth_time, Some(1_700_000_123));
    assert_eq!(
        first.user.token_claims.amr,
        Some(vec!["otp".to_string(), "pwd".to_string()])
    );
    assert_eq!(
        first.user.token_claims.acr.as_deref(),
        Some("urn:example:loa:2")
    );
    assert_eq!(
        first.user.token_claims.tenant_id.as_deref(),
        Some("tenant-1")
    );
    let decoded = auth.authenticate_access_token(&first.access_token).unwrap();
    assert_eq!(decoded.session.assurance, Some(assurance.clone()));
    assert_eq!(decoded.token_claims.auth_time, Some(1_700_000_123));

    let second = auth
        .refresh(&first.refresh_token, metadata())
        .await
        .unwrap();
    let third = auth
        .refresh(&second.refresh_token, metadata())
        .await
        .unwrap();
    for payload in [&second, &third] {
        assert_eq!(payload.user.session.assurance.as_ref(), Some(&assurance));
        assert_eq!(payload.user.token_claims.auth_time, Some(1_700_000_123));
        assert_eq!(payload.user.token_claims.amr, first.user.token_claims.amr);
        assert_eq!(payload.user.token_claims.acr, first.user.token_claims.acr);
        assert_eq!(payload.user.token_claims.tenant_id, refreshable.tenant_id);
        assert_eq!(payload.user.token_claims.actor, refreshable.actor);
    }
    let record = refresh_store
        .get_by_hash(&hash_refresh_token(&third.refresh_token))
        .unwrap();
    assert_eq!(record.session.assurance, Some(assurance));
    assert_eq!(record.refreshable_metadata, Some(refreshable));
    assert_ne!(
        third.user.token_claims.auth_time,
        Some(OffsetDateTime::now_utc().unix_timestamp())
    );
}

#[test]
fn legacy_refresh_record_deserializes_without_assurance_and_recent_mfa_fails_closed() {
    let sample = StoredRefreshToken {
        id: uuid::Uuid::new_v4(),
        user_id: "user-1".to_string(),
        session_id: uuid::Uuid::new_v4(),
        session_family_id: uuid::Uuid::new_v4(),
        scopes: vec![],
        session: SessionContext::default(),
        refreshable_metadata: None,
        token_hash: "hash-only".to_string(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        expires_at: OffsetDateTime::UNIX_EPOCH + Duration::days(1),
        last_used_at: None,
        revoked_at: None,
        replaced_by_token_id: None,
        user_agent: None,
        ip_address: None,
    };
    let mut raw = serde_json::to_value(sample).unwrap();
    raw.as_object_mut().unwrap().remove("refreshable_metadata");
    raw["session"].as_object_mut().unwrap().remove("assurance");
    let record: StoredRefreshToken = serde_json::from_value(raw).unwrap();
    assert!(record.session.assurance.is_none());
    assert!(record.refreshable_metadata.is_none());

    let user = AuthUser {
        user_id: record.user_id,
        session_id: record.session_id,
        roles: vec![],
        scopes: vec![],
        session: record.session,
        token_claims: AccessTokenMetadata::default(),
    };
    let clock = FixedClock::new(OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap());
    let denial = policy(Duration::minutes(5))
        .evaluate(&user, &clock)
        .unwrap_err();
    assert_eq!(denial.code(), AssuranceDenialCode::AssuranceRequired);
}

#[test]
fn recent_mfa_policy_covers_boundaries_missing_values_and_overflow() {
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
    let clock = FixedClock::new(now);
    let make_user = |assurance: SessionAssurance| AuthUser {
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
    };

    let exact = make_user(accepted(now - Duration::minutes(5)));
    assert!(
        policy(Duration::minutes(5))
            .evaluate(&exact, &clock)
            .is_ok()
    );
    let mut missing_auth_time = make_user(accepted(now));
    missing_auth_time.token_claims.auth_time = None;
    assert_eq!(
        policy(Duration::minutes(5))
            .evaluate(&missing_auth_time, &clock)
            .unwrap_err()
            .code(),
        AssuranceDenialCode::AssuranceRequired
    );
    let stale = make_user(accepted(now - Duration::minutes(5) - Duration::seconds(1)));
    assert_eq!(
        policy(Duration::minutes(5))
            .evaluate(&stale, &clock)
            .unwrap_err()
            .code(),
        AssuranceDenialCode::AuthenticationTooOld
    );
    let skew_edge = make_user(accepted(now + Duration::seconds(30)));
    assert!(
        policy(Duration::minutes(5))
            .evaluate(&skew_edge, &clock)
            .is_ok()
    );
    let future = make_user(accepted(now + Duration::seconds(31)));
    assert_eq!(
        policy(Duration::minutes(5))
            .evaluate(&future, &clock)
            .unwrap_err()
            .code(),
        AssuranceDenialCode::InvalidAuthenticationTime
    );

    let password_only =
        SessionAssurance::new(now, ["pwd"], None, None, MfaAcceptance::Unsatisfied).unwrap();
    assert_eq!(
        policy(Duration::minutes(5))
            .evaluate(&make_user(password_only), &clock)
            .unwrap_err()
            .code(),
        AssuranceDenialCode::MfaRequired
    );

    let no_amr_or_acr = SessionAssurance::new(
        now,
        Vec::<String>::new(),
        None,
        None,
        MfaAcceptance::Satisfied,
    )
    .unwrap();
    assert_eq!(
        policy(Duration::minutes(5))
            .evaluate(&make_user(no_amr_or_acr), &clock)
            .unwrap_err()
            .code(),
        AssuranceDenialCode::AssuranceMethodNotAllowed
    );

    let mut either = policy(Duration::minutes(5));
    either.match_mode = AssuranceMatchMode::Any;
    either.allowed_amr = vec!["not-present".to_string()];
    assert!(either.evaluate(&exact, &clock).is_ok());

    let overflow_clock =
        FixedClock::new(OffsetDateTime::from_unix_timestamp(253_402_300_799).unwrap());
    let denial = policy(Duration::minutes(5))
        .evaluate(&make_user(accepted(now)), &overflow_clock)
        .unwrap_err();
    assert_eq!(denial.code(), AssuranceDenialCode::AssurancePolicyError);
}

#[test]
fn requirement_evaluation_has_exact_boundaries_and_stable_denial_categories() {
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
    let clock = FixedClock::new(now);
    let policy_id = AssurancePolicyId::new("interactive.recent-auth").unwrap();
    let requirement = AssuranceRequirement::new(policy_id.clone());
    let mut policies = AssurancePolicySet::new();
    policies.insert(policy_id, policy(Duration::minutes(5)));

    let exact_time = now - Duration::minutes(5);
    let exact = user_with_assurance(accepted(exact_time));
    let evaluation = policies.evaluate(&requirement, Some(&exact), &clock);
    assert!(evaluation.is_satisfied());
    assert_eq!(evaluation.server_evaluation_time.get(), now);
    assert_eq!(evaluation.authenticated_at.unwrap().get(), exact_time);
    assert_eq!(evaluation.satisfied_until.unwrap().get(), now);
    assert_eq!(evaluation.state.graphql_extension_code(), None);

    clock.advance_seconds(1);
    let expired = policies.evaluate(&requirement, Some(&exact), &clock);
    assert_eq!(
        expired.state,
        AssuranceEvaluationState::StepUpRequired {
            denial_code: AssuranceDenialCode::AuthenticationTooOld,
        }
    );
    assert_eq!(
        expired.state.graphql_extension_code(),
        Some("STEP_UP_REQUIRED")
    );

    let unauthenticated = policies.evaluate(&requirement, None, &clock);
    assert_eq!(
        unauthenticated.state.graphql_extension_code(),
        Some("UNAUTHENTICATED")
    );

    let missing = AssuranceRequirement::new(AssurancePolicyId::new("missing").unwrap());
    let forbidden = policies.evaluate(&missing, Some(&exact), &clock);
    assert_eq!(
        forbidden.state,
        AssuranceEvaluationState::Forbidden {
            denial_code: AssuranceDenialCode::AssurancePolicyError,
        }
    );
    assert_eq!(forbidden.state.graphql_extension_code(), Some("FORBIDDEN"));
}

#[test]
fn missing_and_disallowed_evidence_are_machine_readable() {
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
    let clock = FixedClock::new(now);
    let requirement =
        AssuranceRequirement::new(AssurancePolicyId::new("interactive.recent-auth").unwrap());
    let missing = user_with_assurance(
        SessionAssurance::new(
            now,
            Vec::<String>::new(),
            None,
            Some("host-defined".to_string()),
            MfaAcceptance::Satisfied,
        )
        .unwrap(),
    );
    assert_eq!(
        policy(Duration::minutes(5))
            .evaluate_requirement(&requirement, Some(&missing), &clock)
            .state
            .denial_code(),
        Some(AssuranceDenialCode::AssuranceMethodNotAllowed)
    );

    let disallowed = user_with_assurance(
        SessionAssurance::new(
            now,
            ["pwd", "webauthn"],
            Some("host:a3".to_string()),
            Some("host-defined".to_string()),
            MfaAcceptance::Satisfied,
        )
        .unwrap(),
    );
    assert_eq!(
        policy(Duration::minutes(5))
            .evaluate_requirement(&requirement, Some(&disallowed), &clock)
            .state
            .denial_code(),
        Some(AssuranceDenialCode::AssuranceMethodNotAllowed)
    );
}

#[test]
fn safe_status_projection_contains_no_credentials_or_provider_payloads() {
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
    let assurance = SessionAssurance::new(
        now,
        ["pwd", "totp"],
        Some("provider-private-acr".to_string()),
        Some("provider-private-context".to_string()),
        MfaAcceptance::Satisfied,
    )
    .unwrap();
    let mut user = user_with_assurance(assurance);
    user.token_claims.additional.insert(
        "provider_payload".to_string(),
        serde_json::json!({
            "access_token": "raw-access-secret",
            "refresh_token": "raw-refresh-secret",
        }),
    );

    let encoded = serde_json::to_string(&SessionAssuranceStatus::from_user(Some(&user))).unwrap();
    assert!(encoded.contains("authenticated_at"));
    for forbidden in [
        "raw-access-secret",
        "raw-refresh-secret",
        "provider-private-acr",
        "provider-private-context",
        "provider_payload",
        "session_id",
        "totp",
        "methods",
    ] {
        assert!(!encoded.contains(forbidden), "status leaked {forbidden}");
    }

    assert_eq!(
        SessionAssuranceStatus::from_user(None),
        SessionAssuranceStatus {
            authenticated: false,
            authenticated_at: None,
            mfa_satisfied: false,
        }
    );
}

#[test]
fn policy_ids_are_portable_and_bounded() {
    assert_eq!(
        AssurancePolicyId::new("interactive/recent-auth:v1")
            .unwrap()
            .as_str(),
        "interactive/recent-auth:v1"
    );
    for invalid in ["", "spaces are not portable", "provider@policy"] {
        assert_eq!(
            AssurancePolicyId::new(invalid).unwrap_err(),
            AssurancePolicyIdError
        );
    }
}

#[tokio::test]
async fn genuine_step_up_changes_only_the_target_session_at_injected_time() {
    let refresh_store = MemoryRefreshTokenStore::default();
    let user_store = MemoryUserStore::default();
    let auth = test_auth_service(user_store.clone(), refresh_store);
    user_store.insert(stored_user(
        &auth,
        "user-1",
        "user@example.test",
        "password123",
    ));
    let first = auth
        .issue_verified_user_session("user-1", vec![], AuthMethod::Password, metadata())
        .await
        .unwrap();
    let unrelated = auth
        .issue_verified_user_session("user-1", vec![], AuthMethod::Password, metadata())
        .await
        .unwrap();
    let step_time = OffsetDateTime::from_unix_timestamp(1_700_000_555).unwrap();
    let clock = FixedClock::new(step_time);
    let stepped = auth
        .step_up_session(
            &first.refresh_token,
            StepUpAuthentication {
                methods: vec!["otp".to_string()],
                acr: Some("urn:example:loa:2".to_string()),
                context: Some("local-totp".to_string()),
            },
            metadata(),
            &clock,
        )
        .await
        .unwrap();
    assert_eq!(
        stepped
            .user
            .session
            .assurance
            .as_ref()
            .unwrap()
            .authenticated_at,
        step_time
    );
    assert!(stepped.user.session.mfa.satisfied);
    assert_eq!(
        stepped.user.token_claims.auth_time,
        Some(step_time.unix_timestamp())
    );

    let unrelated_refreshed = auth
        .refresh(&unrelated.refresh_token, metadata())
        .await
        .unwrap();
    assert!(unrelated_refreshed.user.session.assurance.is_none());
    assert!(!unrelated_refreshed.user.session.mfa.satisfied);
}

#[test]
fn denial_debug_and_public_surface_do_not_expose_internal_detail() {
    let user = AuthUser {
        user_id: "secret-user".to_string(),
        session_id: uuid::Uuid::new_v4(),
        roles: vec![],
        scopes: vec![],
        session: SessionContext::default(),
        token_claims: AccessTokenMetadata::default(),
    };
    let clock = FixedClock::new(OffsetDateTime::UNIX_EPOCH);
    let denial = policy(Duration::minutes(5))
        .evaluate(&user, &clock)
        .unwrap_err();
    assert_eq!(
        denial.public_message(),
        "additional authentication is required"
    );
    assert_eq!(denial.code().as_str(), "ASSURANCE_REQUIRED");
    assert!(denial.internal_detail().contains("missing"));
    let debug = format!("{denial:?}");
    assert!(!debug.contains(denial.internal_detail()));
    assert!(!debug.contains("secret-user"));
}
