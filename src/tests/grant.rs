use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_graphql::{Context, EmptyMutation, EmptySubscription, ErrorExtensions, Object, Schema};
use async_trait::async_trait;
use serde_json::json;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::jwt_signing::RSA_PUBLIC_KEY_A;
use super::validator::rs256_config;
use super::{MemoryRefreshTokenStore, MemoryUserStore};
use crate::prelude::*;

#[tokio::test]
async fn issue_access_token_only_validates_without_refresh_row() {
    let refresh_store = MemoryRefreshTokenStore::default();
    let auth = AuthService::new(
        rs256_config(),
        Arc::new(MemoryUserStore::default()),
        Arc::new(refresh_store.clone()),
    )
    .unwrap();

    let grant = auth.issue_access_token_only(request(None)).await.unwrap();

    assert_eq!(grant.user.user_id, "device-user-1");
    assert_eq!(grant.user.roles, vec!["Device".to_string()]);
    assert_eq!(
        grant.user.scopes,
        vec!["devices.read".to_string(), "devices.write".to_string()]
    );
    assert!(
        refresh_store.tokens_by_id.lock().unwrap().is_empty(),
        "access-token-only must not insert refresh tokens"
    );

    let decoded = auth.authenticate_access_token(&grant.access_token).unwrap();
    assert_eq!(decoded, grant.user);

    let validator = AccessTokenValidator::builder()
        .issuer("agql-auth")
        .audience("agql-auth-clients")
        .rs256_public_pem(RSA_PUBLIC_KEY_A)
        .key_id("auth-key-1")
        .build()
        .unwrap();
    let validated = validator
        .authenticate_access_token(&grant.access_token)
        .unwrap();
    assert_eq!(validated, grant.user);
}

#[tokio::test]
async fn issue_access_token_only_respects_custom_ttl() {
    let auth = AuthService::new(
        rs256_config(),
        Arc::new(MemoryUserStore::default()),
        Arc::new(MemoryRefreshTokenStore::default()),
    )
    .unwrap();
    let before = OffsetDateTime::now_utc();

    let grant = auth
        .issue_access_token_only(request(Some(Duration::minutes(5))))
        .await
        .unwrap();

    let lower = before + Duration::minutes(5) - Duration::seconds(2);
    let upper = OffsetDateTime::now_utc() + Duration::minutes(5) + Duration::seconds(2);
    assert!(grant.access_token_expires_at >= lower);
    assert!(grant.access_token_expires_at <= upper);
}

#[tokio::test]
async fn issue_access_token_only_rejects_empty_subject_and_non_positive_ttl() {
    let auth = AuthService::new(
        rs256_config(),
        Arc::new(MemoryUserStore::default()),
        Arc::new(MemoryRefreshTokenStore::default()),
    )
    .unwrap();

    let mut empty_subject = request(None);
    empty_subject.user_id = " ".to_string();
    assert!(matches!(
        auth.issue_access_token_only(empty_subject)
            .await
            .unwrap_err(),
        AuthError::InvalidConfiguration(_)
    ));

    assert!(matches!(
        auth.issue_access_token_only(request(Some(Duration::ZERO)))
            .await
            .unwrap_err(),
        AuthError::InvalidConfiguration(_)
    ));
}

#[tokio::test]
async fn session_bound_grant_preserves_active_session_and_current_assurance_without_new_row() {
    let refresh_store = MemoryRefreshTokenStore::default();
    let auth = AuthService::new(
        rs256_config(),
        Arc::new(MemoryUserStore::default()),
        Arc::new(refresh_store.clone()),
    )
    .unwrap();
    let now =
        OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp()).unwrap();
    let assurance = SessionAssurance::new(
        now,
        ["pwd", "otp"],
        Some("urn:example:loa:2".to_string()),
        Some("tool-policy".to_string()),
        MfaAcceptance::Satisfied,
    )
    .unwrap();
    let original = auth
        .issue_assured_user_session(
            "user-1",
            vec![
                "Editor".to_string(),
                "Auditor".to_string(),
                "Editor".to_string(),
            ],
            vec![
                "records.read".to_string(),
                "records.write".to_string(),
                "records.read".to_string(),
            ],
            AuthMethod::Oidc,
            assurance.clone(),
            RefreshableTokenMetadata {
                tenant_id: Some("tenant-1".to_string()),
                organization_id: Some("organization-1".to_string()),
                correlation_id: Some("login-correlation".to_string()),
                ..RefreshableTokenMetadata::default()
            },
            ClientMetadata::default(),
        )
        .await
        .unwrap();
    assert_eq!(refresh_store.tokens_by_id.lock().unwrap().len(), 1);
    assert_eq!(
        original.user.token_claims.grant_kind,
        Some(AccessTokenGrantKind::UserSession)
    );

    let active_sessions = ActiveSessionStore::new(
        original.user.clone(),
        "session-version-1",
        now + Duration::minutes(20),
        Some(now + Duration::minutes(10)),
        now,
    );
    let auth = auth.with_active_user_session_resolver(Arc::new(active_sessions.clone()));
    let verified = active_sessions.initial_resolution().unwrap();
    let original_reference = verified.reference().clone();
    let actor = ActorIdentity {
        sub: "fame-ai".to_string(),
        amr: vec!["service".to_string()],
    };
    let confirmation = ConfirmationClaims {
        x5t_s256: None,
        jkt: Some("tool-key-thumbprint".to_string()),
    };
    let binding = SessionBoundDelegationBinding::new(
        actor.clone(),
        "graphql_operation",
        "current_user_context",
        "tool-call-1",
        ExactOperationBinding::new("CurrentUserContext", "sha256:registered-operation"),
    );
    let request = auth
        .prepare_session_bound_access_token_only(
            &verified,
            vec!["Editor".to_string(), "Editor".to_string()],
            vec!["records.read".to_string(), "records.read".to_string()],
            binding,
        )
        .await
        .unwrap()
        .with_ttl(Duration::minutes(5))
        .with_confirmation(confirmation.clone())
        .with_claim("tool_policy", json!("registered-only"));

    let refresh_rows_before = refresh_rows(&refresh_store);
    let family_count_before = refresh_family_count(&refresh_store);
    let active_row_before = active_sessions.snapshot();

    let grant = auth
        .issue_session_bound_access_token_only(request.clone())
        .await
        .unwrap();
    let second = auth
        .issue_session_bound_access_token_only(request)
        .await
        .unwrap();

    assert_eq!(grant.user.user_id, original.user.user_id);
    assert_eq!(grant.user.session_id, original.user.session_id);
    assert_eq!(grant.user.roles, vec!["Editor".to_string()]);
    assert_eq!(grant.user.scopes, vec!["records.read".to_string()]);
    assert_eq!(grant.user.session.assurance.as_ref(), Some(&assurance));
    assert_eq!(
        grant.user.token_claims.session_family_id,
        original.user.token_claims.session_family_id
    );
    assert_eq!(
        grant.user.token_claims.grant_kind,
        Some(AccessTokenGrantKind::SessionBoundDelegation)
    );
    assert_eq!(
        grant.user.token_claims.session_version.as_deref(),
        Some("session-version-1")
    );
    assert_ne!(
        grant.user.token_claims.jti, second.user.token_claims.jti,
        "each delegated token needs a unique jti"
    );
    assert_eq!(refresh_store.tokens_by_id.lock().unwrap().len(), 1);
    assert_eq!(refresh_rows(&refresh_store), refresh_rows_before);
    assert_eq!(refresh_family_count(&refresh_store), family_count_before);
    assert_eq!(active_sessions.snapshot(), active_row_before);
    assert_eq!(active_sessions.reads.load(Ordering::Relaxed), 3);

    let decoded = auth.authenticate_access_token(&grant.access_token).unwrap();
    assert_eq!(decoded.session_id, original.user.session_id);
    assert_eq!(
        AuthPrincipal::User(decoded.clone())
            .reference()
            .session_id
            .as_deref(),
        original_reference.session_id.as_deref()
    );
    assert_eq!(decoded.token_claims.actor, Some(actor));
    assert_eq!(decoded.token_claims.cnf, Some(confirmation));
    assert_eq!(
        decoded.token_claims.resource_type.as_deref(),
        Some("graphql_operation")
    );
    assert_eq!(
        decoded.token_claims.resource_id.as_deref(),
        Some("current_user_context")
    );
    assert_eq!(
        decoded.token_claims.correlation_id.as_deref(),
        Some("tool-call-1")
    );
    assert_eq!(
        decoded.token_claims.operation,
        Some(ExactOperationBinding::new(
            "CurrentUserContext",
            "sha256:registered-operation"
        ))
    );
    assert_eq!(
        decoded.token_claims.additional["tool_policy"],
        json!("registered-only")
    );
    assert!(decoded.is_session_bound_delegation());
    assert!(matches!(
        decoded.require_session_management_eligible(),
        Err(AuthError::Forbidden)
    ));

    let validator = AccessTokenValidator::builder()
        .issuer("agql-auth")
        .audience("agql-auth-clients")
        .rs256_public_pem(RSA_PUBLIC_KEY_A)
        .key_id("auth-key-1")
        .claim_requirements(ClaimRequirements {
            require_jti: true,
            require_tenant_id: true,
            require_cnf: true,
            require_purpose: true,
            require_session_family_id: true,
            require_actor: true,
            require_resource_binding: true,
            require_correlation_id: true,
            required_grant_kind: Some(AccessTokenGrantKind::SessionBoundDelegation),
            require_session_version: true,
            require_operation_binding: true,
            ..ClaimRequirements::default()
        })
        .build()
        .unwrap();
    assert_eq!(
        validator
            .authenticate_access_token(&grant.access_token)
            .unwrap(),
        decoded
    );

    let mfa_policy = RecentMfaPolicy {
        maximum_age: Duration::minutes(5),
        clock_skew: Duration::seconds(30),
        allowed_amr: vec!["otp".to_string()],
        allowed_acr: vec!["urn:example:loa:2".to_string()],
        match_mode: AssuranceMatchMode::All,
    };
    mfa_policy
        .evaluate(&decoded, &FixedClock::new(now))
        .expect("delegation must preserve current session assurance");

    let diagnostics = format!("{grant:?}");
    assert!(diagnostics.contains("[redacted]"));
    assert!(!diagnostics.contains(&grant.access_token));
}

#[tokio::test]
async fn issuance_rereads_session_and_rejects_post_resolution_changes() {
    let now = OffsetDateTime::now_utc();

    let revoked = active_store(now);
    let auth = test_auth_service_with_resolver(rs256_config(), &revoked);
    let revoked_request = prepared_request(&auth, &revoked, ["Editor"], ["records.read"]).await;
    revoked.record.lock().unwrap().revoked = true;
    assert!(matches!(
        auth.issue_session_bound_access_token_only(revoked_request)
            .await,
        Err(AuthError::TokenRevoked)
    ));

    let expired = active_store(now);
    let auth = test_auth_service_with_resolver(rs256_config(), &expired);
    let expired_request = prepared_request(&auth, &expired, ["Editor"], ["records.read"]).await;
    expired.record.lock().unwrap().idle_expires_at = Some(now);
    assert!(matches!(
        auth.issue_session_bound_access_token_only(expired_request)
            .await,
        Err(AuthError::AccessTokenExpired)
    ));

    let changed_subject = active_store(now);
    let auth = test_auth_service_with_resolver(rs256_config(), &changed_subject);
    let subject_request =
        prepared_request(&auth, &changed_subject, ["Editor"], ["records.read"]).await;
    changed_subject.record.lock().unwrap().user.user_id = "unrelated-user".to_string();
    assert!(matches!(
        auth.issue_session_bound_access_token_only(subject_request)
            .await,
        Err(AuthError::Forbidden)
    ));

    let changed_session = active_store(now);
    let auth = test_auth_service_with_resolver(rs256_config(), &changed_session);
    let session_request =
        prepared_request(&auth, &changed_session, ["Editor"], ["records.read"]).await;
    changed_session.record.lock().unwrap().user.session_id = Uuid::new_v4();
    assert!(matches!(
        auth.issue_session_bound_access_token_only(session_request)
            .await,
        Err(AuthError::Forbidden)
    ));

    let changed_version = active_store(now);
    let auth = test_auth_service_with_resolver(rs256_config(), &changed_version);
    let version_request = auth
        .prepare_session_bound_access_token_only(
            &changed_version.initial_resolution().unwrap(),
            vec!["Editor".to_string()],
            vec!["records.read".to_string()],
            delegation_binding(),
        )
        .await
        .unwrap();
    changed_version.record.lock().unwrap().version = "session-version-2".to_string();
    assert!(matches!(
        auth.issue_session_bound_access_token_only(version_request)
            .await,
        Err(AuthError::Forbidden)
    ));

    let reduced_authority = active_store(now);
    let auth = test_auth_service_with_resolver(rs256_config(), &reduced_authority);
    let authority_request = prepared_request(
        &auth,
        &reduced_authority,
        ["Editor"],
        ["records.read", "records.write"],
    )
    .await;
    reduced_authority
        .record
        .lock()
        .unwrap()
        .user
        .scopes
        .retain(|scope| scope != "records.write");
    assert!(matches!(
        auth.issue_session_bound_access_token_only(authority_request)
            .await,
        Err(AuthError::Forbidden)
    ));

    let excessive_role = active_store(now);
    let auth = test_auth_service_with_resolver(rs256_config(), &excessive_role);
    assert!(matches!(
        auth.prepare_session_bound_access_token_only(
            &excessive_role.initial_resolution().unwrap(),
            vec!["Administrator".to_string()],
            vec!["records.read".to_string()],
            delegation_binding()
        )
        .await,
        Err(AuthError::Forbidden)
    ));

    let excessive_scope = active_store(now);
    let auth = test_auth_service_with_resolver(rs256_config(), &excessive_scope);
    assert!(matches!(
        auth.prepare_session_bound_access_token_only(
            &excessive_scope.initial_resolution().unwrap(),
            vec!["Editor".to_string()],
            vec!["records.delete".to_string()],
            delegation_binding()
        )
        .await,
        Err(AuthError::Forbidden)
    ));
}

#[tokio::test]
async fn session_bound_request_validates_ttl_reserved_and_security_bindings() {
    let sessions = active_store(OffsetDateTime::now_utc());
    let auth = test_auth_service_with_resolver(rs256_config(), &sessions);
    let unconfigured = test_auth_service_with_config(rs256_config());
    assert!(matches!(
        unconfigured
            .issue_session_bound_access_token_only(delegated_request(
                &sessions,
                ["Editor"],
                ["records.read"]
            ))
            .await,
        Err(AuthError::InvalidConfiguration(_))
    ));

    let unversioned = AuthPrincipal::User(verified_user());
    let unversioned = ResolvedPrincipal::new(
        unversioned.reference(),
        unversioned,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    let prepared = auth
        .prepare_session_bound_access_token_only(
            &unversioned,
            vec!["Editor".to_string()],
            vec!["records.read".to_string()],
            delegation_binding(),
        )
        .await
        .unwrap();
    assert_eq!(
        prepared.reference.session_version.as_deref(),
        Some("session-version-1")
    );

    for request in [
        delegated_request(&sessions, ["Editor"], ["records.read"]).with_ttl(Duration::ZERO),
        delegated_request(&sessions, ["Editor"], ["records.read"]).with_ttl(Duration::days(2)),
        delegated_request(&sessions, ["Editor"], ["records.read"])
            .with_claim("sid", json!(Uuid::new_v4())),
        request_with_binding(
            &sessions,
            SessionBoundDelegationBinding::new(
                ActorIdentity::default(),
                "graphql_operation",
                "current_user_context",
                "correlation-1",
                exact_operation(),
            ),
        ),
        delegated_request(&sessions, ["Editor"], ["records.read"])
            .with_confirmation(ConfirmationClaims::default()),
        request_with_binding(
            &sessions,
            SessionBoundDelegationBinding::new(
                actor(),
                "",
                "current_user_context",
                "correlation-1",
                exact_operation(),
            ),
        ),
        request_with_binding(
            &sessions,
            SessionBoundDelegationBinding::new(
                actor(),
                "graphql_operation",
                "current_user_context",
                " ",
                exact_operation(),
            ),
        ),
        request_with_binding(
            &sessions,
            SessionBoundDelegationBinding::new(
                actor(),
                "graphql_operation",
                "current_user_context",
                "correlation-1",
                ExactOperationBinding::new("", "hash"),
            ),
        ),
    ] {
        assert!(matches!(
            auth.issue_session_bound_access_token_only(request).await,
            Err(AuthError::InvalidConfiguration(_))
        ));
    }

    for alias in [
        "subject",
        "session_id",
        "tenantId",
        "role",
        "audience",
        "expires_at",
        "issued_at",
        "token_id",
        "act",
        "azp",
        "token_kind",
        "resource",
        "correlationId",
        "authentication_time",
        "operation_hash",
    ] {
        let request = delegated_request(&sessions, ["Editor"], ["records.read"])
            .with_claim(alias, json!("shadow"));
        assert!(matches!(
            auth.issue_session_bound_access_token_only(request).await,
            Err(AuthError::InvalidConfiguration(_))
        ));
    }
}

#[tokio::test]
async fn session_bound_scope_narrowing_uses_configured_authority_semantics() {
    let now = OffsetDateTime::now_utc();
    let sessions = active_store(now);
    sessions.record.lock().unwrap().user.scopes = vec!["records.*".to_string()];
    let request = delegated_request(&sessions, ["Editor"], ["records.read"]);

    let exact = test_auth_service_with_resolver(rs256_config(), &sessions);
    assert!(matches!(
        exact
            .issue_session_bound_access_token_only(request.clone())
            .await,
        Err(AuthError::Forbidden)
    ));

    let hierarchical = test_auth_service_with_resolver(rs256_config(), &sessions)
        .with_scope_matcher(Arc::new(HierarchicalScopeMatch::with_defaults()));
    let grant = hierarchical
        .issue_session_bound_access_token_only(request)
        .await
        .unwrap();
    assert_eq!(grant.user.scopes, vec!["records.read".to_string()]);
}

#[tokio::test]
async fn session_bound_delegation_cannot_replace_authoritative_security_bindings() {
    let now = OffsetDateTime::now_utc();
    let sessions = active_store(now);
    {
        let mut record = sessions.record.lock().unwrap();
        record.user.token_claims.actor = Some(ActorIdentity {
            sub: "original-actor".to_string(),
            amr: Vec::new(),
        });
        record.user.token_claims.cnf = Some(ConfirmationClaims {
            x5t_s256: None,
            jkt: Some("original-key".to_string()),
        });
        record.user.token_claims.resource_type = Some("project".to_string());
        record.user.token_claims.resource_id = Some("project-1".to_string());
    }
    let auth = test_auth_service_with_resolver(rs256_config(), &sessions);
    let request = delegated_request(&sessions, ["Editor"], ["records.read"]).with_confirmation(
        ConfirmationClaims {
            x5t_s256: None,
            jkt: Some("different-key".to_string()),
        },
    );
    assert!(matches!(
        auth.issue_session_bound_access_token_only(request).await,
        Err(AuthError::Forbidden)
    ));
}

#[tokio::test]
async fn delegated_expiry_is_clamped_to_request_ceiling_and_session_lifetime() {
    let now = OffsetDateTime::now_utc();

    let requested_sessions = active_store(now);
    let requested_auth = test_auth_service_with_resolver(
        rs256_config().with_max_session_bound_delegation_ttl(Duration::minutes(10)),
        &requested_sessions,
    );
    let requested = requested_auth
        .issue_session_bound_access_token_only(
            delegated_request(&requested_sessions, ["Editor"], ["records.read"])
                .with_ttl(Duration::seconds(30)),
        )
        .await
        .unwrap();
    assert_expiry_near(
        requested.access_token_expires_at,
        now + Duration::seconds(30),
    );

    let ceiling_sessions = active_store(now);
    let ceiling_auth = test_auth_service_with_resolver(
        rs256_config().with_max_session_bound_delegation_ttl(Duration::minutes(2)),
        &ceiling_sessions,
    );
    let ceiling = ceiling_auth
        .issue_session_bound_access_token_only(
            delegated_request(&ceiling_sessions, ["Editor"], ["records.read"])
                .with_ttl(Duration::minutes(5)),
        )
        .await
        .unwrap();
    assert_expiry_near(ceiling.access_token_expires_at, now + Duration::minutes(2));

    let lifetime_sessions = active_store(now);
    lifetime_sessions.record.lock().unwrap().idle_expires_at = Some(now + Duration::minutes(1));
    let lifetime_auth = test_auth_service_with_resolver(
        rs256_config().with_max_session_bound_delegation_ttl(Duration::minutes(10)),
        &lifetime_sessions,
    );
    let lifetime = lifetime_auth
        .issue_session_bound_access_token_only(
            delegated_request(&lifetime_sessions, ["Editor"], ["records.read"])
                .with_ttl(Duration::minutes(5)),
        )
        .await
        .unwrap();
    assert_expiry_near(lifetime.access_token_expires_at, now + Duration::minutes(1));
}

#[tokio::test]
async fn delegated_credentials_cannot_manage_or_chain_the_session() {
    let sessions = active_store(OffsetDateTime::now_utc());
    let auth = test_auth_service_with_resolver(rs256_config(), &sessions);
    let grant = auth
        .issue_session_bound_access_token_only(delegated_request(
            &sessions,
            ["Editor"],
            ["records.read"],
        ))
        .await
        .unwrap();
    let delegated = auth.authenticate_access_token(&grant.access_token).unwrap();
    assert!(matches!(
        delegated.require_session_management_eligible(),
        Err(AuthError::Forbidden)
    ));
    assert!(matches!(
        auth.authenticate_session_management_bearer(&grant.access_token),
        Err(AuthError::Forbidden)
    ));
    let delegated_principal = AuthPrincipal::User(delegated);
    let delegated_reference = delegated_principal.reference();
    let current_principal = AuthPrincipal::User(
        sessions
            .resolve_active_user_session(&delegated_reference)
            .await
            .unwrap()
            .user()
            .clone(),
    );
    let resolved = ResolvedPrincipal::new(
        delegated_reference,
        current_principal,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    assert!(matches!(
        auth.prepare_session_bound_access_token_only(
            &resolved,
            vec!["Editor".to_string()],
            vec!["records.read".to_string()],
            delegation_binding()
        )
        .await,
        Err(AuthError::Forbidden)
    ));

    let sessionless = auth.issue_access_token_only(request(None)).await.unwrap();
    assert_eq!(
        sessionless.user.token_claims.grant_kind,
        Some(AccessTokenGrantKind::Sessionless)
    );
    assert!(matches!(
        sessionless.user.require_session_management_eligible(),
        Err(AuthError::Forbidden)
    ));
    assert!(matches!(
        auth.authenticate_session_management_bearer(&sessionless.access_token),
        Err(AuthError::Forbidden)
    ));
}

#[tokio::test]
async fn signed_delegation_passes_middleware_current_session_and_protected_resolver() {
    let sessions = active_store(OffsetDateTime::now_utc());
    let auth = test_auth_service_with_resolver(rs256_config(), &sessions);
    let grant = auth
        .issue_session_bound_access_token_only(delegated_request(
            &sessions,
            ["Editor"],
            ["records.read"],
        ))
        .await
        .unwrap();
    let schema = Schema::build(DelegatedQuery, EmptyMutation, EmptySubscription)
        .data(sessions.clone())
        .finish();

    let request = auth
        .inject_http_auth(
            async_graphql::Request::new("{ currentUserContext }"),
            Some(&grant.access_token),
        )
        .await
        .unwrap();
    let response = schema.execute(request).await;
    assert!(response.errors.is_empty(), "{:#?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap()["currentUserContext"],
        json!("user-1")
    );

    sessions.record.lock().unwrap().revoked = true;
    let revoked_request = auth
        .inject_http_auth(
            async_graphql::Request::new("{ currentUserContext }"),
            Some(&grant.access_token),
        )
        .await
        .unwrap();
    let revoked = schema.execute(revoked_request).await;
    assert_eq!(revoked.errors.len(), 1);
    assert_eq!(revoked.errors[0].message, "token revoked");

    {
        let mut record = sessions.record.lock().unwrap();
        record.revoked = false;
        record.idle_expires_at = Some(record.verified_at);
    }
    let expired_request = auth
        .inject_http_auth(
            async_graphql::Request::new("{ currentUserContext }"),
            Some(&grant.access_token),
        )
        .await
        .unwrap();
    let expired = schema.execute(expired_request).await;
    assert_eq!(expired.errors.len(), 1);
    assert_eq!(expired.errors[0].message, "access token expired");
}

fn request(ttl: Option<Duration>) -> AccessTokenOnlyRequest {
    let mut request = AccessTokenOnlyRequest::new(
        "device-user-1",
        vec!["Device".to_string()],
        vec!["devices.read".to_string(), "devices.write".to_string()],
        SessionContext::for_auth_method(AuthMethod::ServiceToken),
    );
    request.ttl = ttl;
    request
}

fn verified_user() -> AuthUser {
    AuthUser {
        user_id: "user-1".to_string(),
        session_id: Uuid::from_u128(42),
        roles: vec!["Editor".to_string(), "Auditor".to_string()],
        scopes: vec!["records.read".to_string(), "records.write".to_string()],
        session: SessionContext::for_auth_method(AuthMethod::Oidc),
        token_claims: AccessTokenMetadata {
            tenant_id: Some("tenant-1".to_string()),
            session_family_id: Some(Uuid::from_u128(7).to_string()),
            ..AccessTokenMetadata::default()
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveSessionRecord {
    user: AuthUser,
    version: String,
    absolute_expires_at: OffsetDateTime,
    idle_expires_at: Option<OffsetDateTime>,
    verified_at: OffsetDateTime,
    revoked: bool,
    interactive_last_active_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
struct ActiveSessionStore {
    record: Arc<Mutex<ActiveSessionRecord>>,
    reads: Arc<AtomicU64>,
}

impl ActiveSessionStore {
    fn new(
        user: AuthUser,
        version: impl Into<String>,
        absolute_expires_at: OffsetDateTime,
        idle_expires_at: Option<OffsetDateTime>,
        verified_at: OffsetDateTime,
    ) -> Self {
        Self {
            record: Arc::new(Mutex::new(ActiveSessionRecord {
                user,
                version: version.into(),
                absolute_expires_at,
                idle_expires_at,
                verified_at,
                revoked: false,
                interactive_last_active_at: verified_at - Duration::minutes(1),
            })),
            reads: Arc::new(AtomicU64::new(0)),
        }
    }

    fn initial_resolution(&self) -> crate::AuthResult<ResolvedPrincipal> {
        let record = self.record.lock().unwrap();
        let mut user = record.user.clone();
        user.token_claims.session_version = Some(record.version.clone());
        user.token_claims.grant_kind = Some(AccessTokenGrantKind::UserSession);
        let principal = AuthPrincipal::User(user);
        ResolvedPrincipal::new(principal.reference(), principal, record.verified_at)
    }

    fn snapshot(&self) -> ActiveSessionRecord {
        self.record.lock().unwrap().clone()
    }
}

#[async_trait]
impl VerifiedActiveUserSessionResolver for ActiveSessionStore {
    async fn resolve_active_user_session(
        &self,
        reference: &PrincipalReference,
    ) -> crate::AuthResult<VerifiedActiveUserSession> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let record = self.record.lock().unwrap();
        if record.revoked {
            return Err(AuthError::TokenRevoked);
        }
        let mut user = record.user.clone();
        user.token_claims.session_version = Some(record.version.clone());
        user.token_claims.grant_kind = Some(AccessTokenGrantKind::UserSession);
        VerifiedActiveUserSession::from_authoritative_record(
            reference.clone(),
            user,
            record.version.clone(),
            record.absolute_expires_at,
            record.idle_expires_at,
            record.verified_at,
        )
    }
}

struct DelegatedQuery;

#[Object]
impl DelegatedQuery {
    async fn current_user_context(&self, ctx: &Context<'_>) -> async_graphql::Result<String> {
        let token_user = auth_user_from_ctx(ctx)?;
        let sessions = ctx.data::<ActiveSessionStore>()?;
        let current = sessions
            .resolve_active_user_session(&AuthPrincipal::User(token_user.clone()).reference())
            .await
            .map_err(|error| error.extend())?;
        let resolved = ResolvedPrincipal::new(
            AuthPrincipal::User(token_user.clone()).reference(),
            AuthPrincipal::User(current.user().clone()),
            current.verified_at(),
        )
        .map_err(|error| error.extend())?;
        if !token_user.has_scope("records.read")
            || token_user.token_claims.grant_kind
                != Some(AccessTokenGrantKind::SessionBoundDelegation)
            || token_user.token_claims.operation.as_ref() != Some(&exact_operation())
            || resolved.principal().subject() != token_user.user_id
        {
            return Err(AuthError::Forbidden.extend());
        }
        Ok(resolved.principal().subject().to_string())
    }
}

fn active_store(now: OffsetDateTime) -> ActiveSessionStore {
    ActiveSessionStore::new(
        verified_user(),
        "session-version-1",
        now + Duration::hours(1),
        Some(now + Duration::minutes(30)),
        now,
    )
}

fn delegated_request<const R: usize, const S: usize>(
    sessions: &ActiveSessionStore,
    roles: [&str; R],
    scopes: [&str; S],
) -> SessionBoundAccessTokenOnlyRequest {
    SessionBoundAccessTokenOnlyRequest::from_prepared_reference(
        sessions.initial_resolution().unwrap().reference().clone(),
        roles.into_iter().map(str::to_string).collect(),
        scopes.into_iter().map(str::to_string).collect(),
        delegation_binding(),
    )
}

async fn prepared_request<const R: usize, const S: usize>(
    auth: &AuthService<MemoryUserStore, MemoryRefreshTokenStore>,
    sessions: &ActiveSessionStore,
    roles: [&str; R],
    scopes: [&str; S],
) -> SessionBoundAccessTokenOnlyRequest {
    auth.prepare_session_bound_access_token_only(
        &sessions.initial_resolution().unwrap(),
        roles.into_iter().map(str::to_string).collect(),
        scopes.into_iter().map(str::to_string).collect(),
        delegation_binding(),
    )
    .await
    .unwrap()
}

fn request_with_binding(
    sessions: &ActiveSessionStore,
    binding: SessionBoundDelegationBinding,
) -> SessionBoundAccessTokenOnlyRequest {
    SessionBoundAccessTokenOnlyRequest::from_prepared_reference(
        sessions.initial_resolution().unwrap().reference().clone(),
        vec!["Editor".to_string()],
        vec!["records.read".to_string()],
        binding,
    )
}

fn delegation_binding() -> SessionBoundDelegationBinding {
    SessionBoundDelegationBinding::new(
        actor(),
        "graphql_operation",
        "current_user_context",
        "correlation-1",
        exact_operation(),
    )
}

fn exact_operation() -> ExactOperationBinding {
    ExactOperationBinding::new("CurrentUserContext", "sha256:registered-operation")
}

fn actor() -> ActorIdentity {
    ActorIdentity {
        sub: "fame-ai".to_string(),
        amr: vec!["service".to_string()],
    }
}

fn test_auth_service_with_config(
    config: AuthConfig,
) -> AuthService<MemoryUserStore, MemoryRefreshTokenStore> {
    AuthService::new(
        config,
        Arc::new(MemoryUserStore::default()),
        Arc::new(MemoryRefreshTokenStore::default()),
    )
    .unwrap()
}

fn test_auth_service_with_resolver(
    config: AuthConfig,
    sessions: &ActiveSessionStore,
) -> AuthService<MemoryUserStore, MemoryRefreshTokenStore> {
    test_auth_service_with_config(config)
        .with_active_user_session_resolver(Arc::new(sessions.clone()))
}

fn refresh_rows(refresh_store: &MemoryRefreshTokenStore) -> Vec<(Uuid, Uuid, Uuid, String)> {
    let mut rows = refresh_store
        .tokens_by_id
        .lock()
        .unwrap()
        .values()
        .map(|record| {
            (
                record.id,
                record.session_id,
                record.session_family_id,
                record.token_hash.clone(),
            )
        })
        .collect::<Vec<_>>();
    rows.sort_by_key(|row| row.0);
    rows
}

fn refresh_family_count(refresh_store: &MemoryRefreshTokenStore) -> usize {
    refresh_store
        .tokens_by_id
        .lock()
        .unwrap()
        .values()
        .map(|record| record.session_family_id)
        .collect::<HashSet<_>>()
        .len()
}

fn assert_expiry_near(actual: OffsetDateTime, expected: OffsetDateTime) {
    let difference = (actual - expected).whole_seconds().abs();
    assert!(difference <= 2, "expiry differed by {difference} seconds");
}
