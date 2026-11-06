use std::mem::{discriminant, size_of};
use std::sync::Weak;
use std::sync::atomic::AtomicBool;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::Value as JsonValue;

use super::super::jwt_signing::{RSA_PRIVATE_KEY_A, RSA_PRIVATE_KEY_B, RSA_PUBLIC_KEY_B};
use super::super::{TEST_HS256_SECRET, metadata};
use super::*;

const NORMAL: &str = "agql-auth-clients";
const RECEIVER: &str = "private-receiver";
const KEY_ID: &str = "auth-key-1";

type Owner = Arc<AuthService<MemoryUserStore, MemoryRefreshTokenStore>>;
type Facade = FixedAudienceDelegation<MemoryUserStore, MemoryRefreshTokenStore>;

fn parent_user(disabled: bool) -> StoredUser {
    StoredUser {
        id: "user-1".to_string(),
        principal: "user-1@example.test".to_string(),
        password_hash: "unused".to_string(),
        roles: vec!["Editor".to_string()],
        scopes: vec!["records.read".to_string()],
        disabled,
    }
}

fn users_with_parent() -> Arc<MemoryUserStore> {
    let users = Arc::new(MemoryUserStore::default());
    users.insert(parent_user(false));
    users
}

fn owner_with_parent(
    config: AuthConfig,
    sessions: &ActiveSessionStore,
) -> AuthService<MemoryUserStore, MemoryRefreshTokenStore> {
    AuthService::new(
        config,
        users_with_parent(),
        Arc::new(MemoryRefreshTokenStore::default()),
    )
    .unwrap()
    .with_active_user_session_resolver(Arc::new(sessions.clone()))
}

fn owner_and_facade(config: AuthConfig, sessions: &ActiveSessionStore) -> (Owner, Facade) {
    match owner_with_parent(config, sessions).into_shared_with_fixed_audience_delegation(RECEIVER) {
        Ok(pair) => pair,
        Err(error) => panic!("facade startup failed: {error}"),
    }
}

async fn facade_request(
    facade: &Facade,
    sessions: &ActiveSessionStore,
) -> SessionBoundAccessTokenOnlyRequest {
    facade
        .prepare_session_bound_access_token_only(
            &sessions.initial_resolution().unwrap(),
            vec!["Editor".to_string()],
            vec!["records.read".to_string()],
            delegation_binding(),
        )
        .await
        .unwrap()
}

fn validator(audience: &str, public_key: &str) -> AccessTokenValidator {
    AccessTokenValidator::builder()
        .issuer("agql-auth")
        .audience(audience)
        .rs256_public_pem(public_key)
        .key_id(KEY_ID)
        .build()
        .unwrap()
}

fn receiver_profile_validator() -> AccessTokenValidator {
    AccessTokenValidator::builder()
        .issuer("agql-auth")
        .audience(RECEIVER)
        .rs256_public_pem(RSA_PUBLIC_KEY_A)
        .key_id(KEY_ID)
        .purpose_policy(PurposePolicy::RequireAccessToken)
        .claim_requirements(ClaimRequirements {
            require_jti: true,
            require_purpose: true,
            require_actor: true,
            require_resource_binding: true,
            require_correlation_id: true,
            required_grant_kind: Some(AccessTokenGrantKind::SessionBoundDelegation),
            require_session_version: true,
            require_operation_binding: true,
            ..ClaimRequirements::default()
        })
        .build()
        .unwrap()
}

fn token_part(token: &str, index: usize) -> JsonValue {
    let part = token.split('.').nth(index).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
}

fn startup_error(result: crate::AuthResult<(Owner, Facade)>) -> AuthError {
    match result {
        Ok(_) => panic!("startup must fail"),
        Err(error) => error,
    }
}

#[tokio::test]
async fn audience_differs_and_each_verifier_rejects_the_others_token() {
    let sessions = active_store(OffsetDateTime::now_utc());
    let (owner, facade) = owner_and_facade(rs256_config(), &sessions);
    assert_eq!(facade.audience(), RECEIVER);

    let normal = owner
        .issue_session_bound_access_token_only(
            prepared_request(&owner, &sessions, ["Editor"], ["records.read"]).await,
        )
        .await
        .unwrap();
    let direct = facade
        .issue_session_bound_access_token_only(facade_request(&facade, &sessions).await)
        .await
        .unwrap();
    assert_eq!(token_part(&normal.access_token, 1)["aud"], json!(NORMAL));
    assert_eq!(token_part(&direct.access_token, 1)["aud"], json!(RECEIVER));

    // In-process verifiers.
    assert_eq!(
        owner
            .authenticate_access_token(&normal.access_token)
            .unwrap(),
        normal.user
    );
    assert_eq!(
        facade
            .authenticate_access_token(&direct.access_token)
            .unwrap(),
        direct.user
    );
    assert!(matches!(
        owner.authenticate_access_token(&direct.access_token),
        Err(AuthError::InvalidAccessToken)
    ));
    assert!(matches!(
        facade.authenticate_access_token(&normal.access_token),
        Err(AuthError::InvalidAccessToken)
    ));

    // Store-free verifiers, as a general router and the private receiver deploy them.
    let router = validator(NORMAL, RSA_PUBLIC_KEY_A);
    let receiver = validator(RECEIVER, RSA_PUBLIC_KEY_A);
    assert_eq!(
        router
            .authenticate_access_token(&normal.access_token)
            .unwrap(),
        normal.user
    );
    assert_eq!(
        receiver
            .authenticate_access_token(&direct.access_token)
            .unwrap(),
        direct.user
    );
    assert!(matches!(
        router.authenticate_access_token(&direct.access_token),
        Err(AuthError::InvalidAccessToken)
    ));
    assert!(matches!(
        receiver.authenticate_access_token(&normal.access_token),
        Err(AuthError::InvalidAccessToken)
    ));
}

#[tokio::test]
async fn only_the_audience_differs_from_normal_delegated_issuance() {
    let sessions = active_store(OffsetDateTime::now_utc());
    let (owner, facade) = owner_and_facade(rs256_config(), &sessions);
    let normal = owner
        .issue_session_bound_access_token_only(
            prepared_request(&owner, &sessions, ["Editor"], ["records.read"])
                .await
                .with_ttl(Duration::minutes(5))
                .with_claim("tool_policy", json!("registered-only")),
        )
        .await
        .unwrap();
    let direct = facade
        .issue_session_bound_access_token_only(
            facade_request(&facade, &sessions)
                .await
                .with_ttl(Duration::minutes(5))
                .with_claim("tool_policy", json!("registered-only")),
        )
        .await
        .unwrap();

    assert_eq!(
        token_part(&normal.access_token, 0),
        token_part(&direct.access_token, 0),
        "alg and kid must be identical"
    );
    let mut normal_claims = token_part(&normal.access_token, 1);
    let mut direct_claims = token_part(&direct.access_token, 1);
    for claim in ["aud", "jti", "iat", "exp"] {
        normal_claims.as_object_mut().unwrap().remove(claim);
        direct_claims.as_object_mut().unwrap().remove(claim);
    }
    assert_eq!(normal_claims, direct_claims);
    assert_eq!(direct_claims["session_version"], json!("session-version-1"));
    assert_eq!(
        direct.user.token_claims.grant_kind,
        Some(AccessTokenGrantKind::SessionBoundDelegation)
    );
}

#[tokio::test]
async fn facade_shares_the_exact_signer_keys_and_abuse_state_of_its_owner() {
    let sessions = active_store(OffsetDateTime::now_utc());
    let rate_store = Arc::new(MemoryAuthRateLimitStore::default());
    let mut config = rs256_config();
    config.rate_limits.credential = AuthRateLimitPolicy {
        enabled: true,
        window: Duration::minutes(15),
        backoff_after_attempts: 1,
        max_attempts_before_lockout: 2,
        base_backoff: Duration::ZERO,
        max_backoff: Duration::ZERO,
        lockout_duration: Duration::minutes(5),
        state_ttl: Duration::hours(1),
    };
    let (owner, facade) = match AuthService::new_with_rate_limit_store(
        config,
        users_with_parent(),
        Arc::new(MemoryRefreshTokenStore::default()),
        rate_store.clone(),
    )
    .unwrap()
    .with_active_user_session_resolver(Arc::new(sessions.clone()))
    .into_shared_with_fixed_audience_delegation(RECEIVER)
    {
        Ok(pair) => pair,
        Err(error) => panic!("facade startup failed: {error}"),
    };

    // The facade is structurally a pointer to the one owner and its audience:
    // it has nowhere to keep a second key, policy, store, or clock.
    assert_eq!(
        size_of::<Facade>(),
        size_of::<Weak<AuthService<MemoryUserStore, MemoryRefreshTokenStore>>>()
            + size_of::<Arc<str>>()
    );
    let shared = facade.live_owner().unwrap();
    assert!(Arc::ptr_eq(&owner, &shared));

    assert_eq!(facade.jwks().unwrap(), owner.jwks().unwrap());
    let direct = facade
        .issue_session_bound_access_token_only(facade_request(&facade, &sessions).await)
        .await
        .unwrap();
    let header = token_part(&direct.access_token, 0);
    assert_eq!(header["alg"], json!("RS256"));
    assert_eq!(header["kid"], json!(KEY_ID));
    assert!(
        validator(RECEIVER, RSA_PUBLIC_KEY_A)
            .authenticate_access_token(&direct.access_token)
            .is_ok()
    );
    assert!(
        validator(RECEIVER, RSA_PUBLIC_KEY_B)
            .authenticate_access_token(&direct.access_token)
            .is_err(),
        "the token must be signed by the owner's key and no other"
    );

    // A lockout recorded through the owner is the state the facade's owner reads.
    for _ in 0..2 {
        assert!(matches!(
            owner.login("nobody", "wrong-password", metadata()).await,
            Err(AuthError::InvalidCredentials)
        ));
    }
    assert!(matches!(
        owner.login("nobody", "wrong-password", metadata()).await,
        Err(AuthError::AuthLocked { .. })
    ));
    let keys = shared.rate_limit_keys(
        AuthRateLimitFlow::PasswordLogin,
        Some("nobody"),
        &metadata(),
    );
    assert!(
        rate_store
            .find_auth_rate_limit_state(&keys[0])
            .await
            .unwrap()
            .is_some()
    );
    assert!(matches!(
        shared
            .reject_if_rate_limited(&shared.config.rate_limits.credential, &keys)
            .await,
        Err(AuthError::AuthLocked { .. })
    ));
}

#[test]
fn startup_refuses_unsafe_owners_and_audiences() {
    let sessions = active_store(OffsetDateTime::now_utc());

    let hs256 = test_auth_service_with_resolver(AuthConfig::new(TEST_HS256_SECRET), &sessions);
    assert!(matches!(
        startup_error(hs256.into_shared_with_fixed_audience_delegation(RECEIVER)),
        AuthError::InvalidConfiguration(_)
    ));

    let no_resolver = test_auth_service_with_config(rs256_config());
    assert!(matches!(
        startup_error(no_resolver.into_shared_with_fixed_audience_delegation(RECEIVER)),
        AuthError::InvalidConfiguration(_)
    ));

    for audience in [
        String::new(),
        " ".to_string(),
        " padded".to_string(),
        "padded ".to_string(),
        "line\nbreak".to_string(),
        "a".repeat(1025),
        NORMAL.to_string(),
        NORMAL.to_ascii_uppercase(),
    ] {
        let owner = test_auth_service_with_resolver(rs256_config(), &sessions);
        assert!(
            matches!(
                startup_error(owner.into_shared_with_fixed_audience_delegation(audience.clone())),
                AuthError::InvalidConfiguration(_)
            ),
            "audience {audience:?} must be refused"
        );
    }
}

#[tokio::test]
async fn disabled_or_missing_parent_fails_even_when_the_resolver_does_not_check() {
    let sessions = active_store(OffsetDateTime::now_utc());
    let users = users_with_parent();
    let (_owner, facade) = match AuthService::new(
        rs256_config(),
        users.clone(),
        Arc::new(MemoryRefreshTokenStore::default()),
    )
    .unwrap()
    .with_active_user_session_resolver(Arc::new(sessions.clone()))
    .into_shared_with_fixed_audience_delegation(RECEIVER)
    {
        Ok(pair) => pair,
        Err(error) => panic!("facade startup failed: {error}"),
    };
    let prepare_again = || async {
        facade
            .prepare_session_bound_access_token_only(
                &sessions.initial_resolution().unwrap(),
                vec!["Editor".to_string()],
                vec!["records.read".to_string()],
                delegation_binding(),
            )
            .await
    };

    let request = facade_request(&facade, &sessions).await;
    users.insert(parent_user(true));
    assert!(matches!(
        facade
            .issue_session_bound_access_token_only(request.clone())
            .await,
        Err(AuthError::UserDisabled)
    ));
    assert!(matches!(
        prepare_again().await,
        Err(AuthError::UserDisabled)
    ));

    users.remove("user-1");
    assert!(matches!(
        facade
            .issue_session_bound_access_token_only(request.clone())
            .await,
        Err(AuthError::Forbidden)
    ));
    assert!(matches!(prepare_again().await, Err(AuthError::Forbidden)));

    users.insert(parent_user(false));
    users.corrupt_returned_id("user-1");
    assert!(matches!(
        facade.issue_session_bound_access_token_only(request).await,
        Err(AuthError::AuthServiceUnavailable)
    ));
}

#[tokio::test]
async fn changed_parent_or_reduced_grant_fails_at_both_reads_like_the_owner() {
    type Change = fn(&mut ActiveSessionRecord, OffsetDateTime);
    let cases: [(&str, Change, AuthError); 6] = [
        (
            "revoked",
            |record, _| record.revoked = true,
            AuthError::TokenRevoked,
        ),
        (
            "absolute expiry",
            |record, now| record.absolute_expires_at = now,
            AuthError::AccessTokenExpired,
        ),
        (
            "idle expiry",
            |record, now| record.idle_expires_at = Some(now),
            AuthError::AccessTokenExpired,
        ),
        (
            "version mismatch",
            |record, _| record.version = "session-version-2".to_string(),
            AuthError::Forbidden,
        ),
        (
            "reduced roles",
            |record, _| record.user.roles.retain(|role| role != "Editor"),
            AuthError::Forbidden,
        ),
        (
            "reduced scopes",
            |record, _| record.user.scopes.retain(|scope| scope != "records.read"),
            AuthError::Forbidden,
        ),
    ];

    for (name, change, expected) in cases {
        let now = OffsetDateTime::now_utc();
        let sessions = active_store(now);
        let (owner, facade) = owner_and_facade(rs256_config(), &sessions);
        let resolved = sessions.initial_resolution().unwrap();
        let direct_request = facade_request(&facade, &sessions).await;
        let normal_request =
            prepared_request(&owner, &sessions, ["Editor"], ["records.read"]).await;

        change(&mut sessions.record.lock().unwrap(), now);

        let second_read = facade
            .issue_session_bound_access_token_only(direct_request)
            .await
            .unwrap_err();
        assert_eq!(
            discriminant(&second_read),
            discriminant(&expected),
            "{name}: second read returned {second_read:?}"
        );
        let owner_error = owner
            .issue_session_bound_access_token_only(normal_request)
            .await
            .unwrap_err();
        assert_eq!(
            discriminant(&owner_error),
            discriminant(&expected),
            "{name}"
        );

        let first_read = facade
            .prepare_session_bound_access_token_only(
                &resolved,
                vec!["Editor".to_string()],
                vec!["records.read".to_string()],
                delegation_binding(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            discriminant(&first_read),
            discriminant(&expected),
            "{name}: first read returned {first_read:?}"
        );
    }
}

#[tokio::test]
async fn own_parent_and_host_expiry_caps_are_preserved() {
    let now = OffsetDateTime::now_utc();

    let sessions = active_store(now);
    let (_owner, own) = owner_and_facade(
        rs256_config().with_max_session_bound_delegation_ttl(Duration::minutes(10)),
        &sessions,
    );
    let grant = own
        .issue_session_bound_access_token_only(
            facade_request(&own, &sessions)
                .await
                .with_ttl(Duration::seconds(30)),
        )
        .await
        .unwrap();
    assert_expiry_near(grant.access_token_expires_at, now + Duration::seconds(30));
    assert_eq!(
        token_part(&grant.access_token, 1)["exp"],
        json!(grant.access_token_expires_at.unix_timestamp())
    );

    let sessions = active_store(now);
    let (_owner, host) = owner_and_facade(
        rs256_config().with_max_session_bound_delegation_ttl(Duration::minutes(2)),
        &sessions,
    );
    let grant = host
        .issue_session_bound_access_token_only(
            facade_request(&host, &sessions)
                .await
                .with_ttl(Duration::minutes(5)),
        )
        .await
        .unwrap();
    assert_expiry_near(grant.access_token_expires_at, now + Duration::minutes(2));

    let sessions = active_store(now);
    sessions.record.lock().unwrap().idle_expires_at = Some(now + Duration::minutes(1));
    let (_owner, parent_idle) = owner_and_facade(
        rs256_config().with_max_session_bound_delegation_ttl(Duration::minutes(10)),
        &sessions,
    );
    let grant = parent_idle
        .issue_session_bound_access_token_only(
            facade_request(&parent_idle, &sessions)
                .await
                .with_ttl(Duration::minutes(5)),
        )
        .await
        .unwrap();
    assert_expiry_near(grant.access_token_expires_at, now + Duration::minutes(1));

    let sessions = active_store(now);
    {
        let mut record = sessions.record.lock().unwrap();
        record.absolute_expires_at = now + Duration::minutes(1);
        record.idle_expires_at = None;
    }
    let (_owner, parent_absolute) = owner_and_facade(
        rs256_config().with_max_session_bound_delegation_ttl(Duration::minutes(10)),
        &sessions,
    );
    let grant = parent_absolute
        .issue_session_bound_access_token_only(
            facade_request(&parent_absolute, &sessions)
                .await
                .with_ttl(Duration::minutes(5)),
        )
        .await
        .unwrap();
    assert_expiry_near(grant.access_token_expires_at, now + Duration::minutes(1));

    // The owner's configured token ceiling still refuses an excessive request.
    let sessions = active_store(now);
    let (owner, facade) = owner_and_facade(rs256_config(), &sessions);
    let excessive = facade_request(&facade, &sessions)
        .await
        .with_ttl(owner.config.max_access_token_ttl + Duration::seconds(1));
    assert!(matches!(
        facade
            .issue_session_bound_access_token_only(excessive)
            .await,
        Err(AuthError::InvalidConfiguration(_))
    ));
}

#[derive(Debug)]
struct SwitchableScopeMatch(Arc<AtomicBool>);

impl ScopeMatch for SwitchableScopeMatch {
    fn matches(&self, granted: &str, required: &str) -> bool {
        self.0.load(Ordering::SeqCst) && granted == required
    }
}

#[tokio::test]
async fn retired_owner_leaves_no_usable_facade_and_shared_owner_cannot_be_reconfigured() {
    let sessions = active_store(OffsetDateTime::now_utc());
    let (owner, facade) = owner_and_facade(rs256_config(), &sessions);
    let clone = facade.clone();
    let request = facade_request(&facade, &sessions).await;
    let token = facade
        .issue_session_bound_access_token_only(request.clone())
        .await
        .unwrap()
        .access_token;
    assert!(format!("{facade:?}").contains("owner_live: true"));

    // While any other holder shares the owner, by-value builders are unreachable.
    let second_holder = owner.clone();
    let Err(owner) = Arc::try_unwrap(owner) else {
        panic!("a shared owner must not be unwrapped");
    };
    drop(second_holder);

    // Retiring the owner to change its keys or policy kills every facade.
    let Ok(owner) = Arc::try_unwrap(owner) else {
        panic!("sole holder can retire the owner");
    };
    let _reconfigured = owner.with_scope_matcher(Arc::new(ExactScopeMatch));
    for retired in [&facade, &clone] {
        assert!(retired.live_owner().is_none());
        assert!(format!("{retired:?}").contains("owner_live: false"));
        assert!(matches!(
            retired
                .prepare_session_bound_access_token_only(
                    &sessions.initial_resolution().unwrap(),
                    vec!["Editor".to_string()],
                    vec!["records.read".to_string()],
                    delegation_binding(),
                )
                .await,
            Err(AuthError::AuthServiceUnavailable)
        ));
        assert!(matches!(
            retired
                .issue_session_bound_access_token_only(request.clone())
                .await,
            Err(AuthError::AuthServiceUnavailable)
        ));
        assert!(matches!(
            retired.authenticate_access_token(&token),
            Err(AuthError::AuthServiceUnavailable)
        ));
        assert!(matches!(
            retired.jwks(),
            Err(AuthError::AuthServiceUnavailable)
        ));
    }
}

#[tokio::test]
async fn replacement_owner_with_new_keys_needs_a_new_facade_and_old_one_dies() {
    let sessions = active_store(OffsetDateTime::now_utc());
    let (old_owner, old_facade) = owner_and_facade(rs256_config(), &sessions);
    let old_token = old_facade
        .issue_session_bound_access_token_only(facade_request(&old_facade, &sessions).await)
        .await
        .unwrap()
        .access_token;

    drop(old_owner);
    let (_new_owner, new_facade) = owner_and_facade(
        AuthConfig::with_rs256_pem(RSA_PRIVATE_KEY_B, RSA_PUBLIC_KEY_B, "auth-key-2"),
        &sessions,
    );

    let new_token = new_facade
        .issue_session_bound_access_token_only(facade_request(&new_facade, &sessions).await)
        .await
        .unwrap()
        .access_token;
    assert_eq!(token_part(&new_token, 0)["kid"], json!("auth-key-2"));
    assert!(matches!(
        old_facade
            .issue_session_bound_access_token_only(facade_request_for_retired(&sessions))
            .await,
        Err(AuthError::AuthServiceUnavailable)
    ));
    assert!(matches!(
        new_facade.authenticate_access_token(&old_token),
        Err(AuthError::InvalidAccessToken)
    ));
}

fn facade_request_for_retired(sessions: &ActiveSessionStore) -> SessionBoundAccessTokenOnlyRequest {
    let mut request = delegated_request(sessions, ["Editor"], ["records.read"]);
    request.fixed_audience = Some(RECEIVER.to_string());
    request
}

#[tokio::test]
async fn owner_scope_policy_changes_reach_the_facade_without_rebuilding_it() {
    let sessions = active_store(OffsetDateTime::now_utc());
    let allow = Arc::new(AtomicBool::new(true));
    let owner = owner_with_parent(rs256_config(), &sessions)
        .with_scope_matcher(Arc::new(SwitchableScopeMatch(allow.clone())));
    let (_owner, facade) = match owner.into_shared_with_fixed_audience_delegation(RECEIVER) {
        Ok(pair) => pair,
        Err(error) => panic!("facade startup failed: {error}"),
    };

    let request = facade_request(&facade, &sessions).await;
    assert!(
        facade
            .issue_session_bound_access_token_only(request.clone())
            .await
            .is_ok()
    );
    allow.store(false, Ordering::SeqCst);
    assert!(matches!(
        facade.issue_session_bound_access_token_only(request).await,
        Err(AuthError::Forbidden)
    ));
}

#[tokio::test]
async fn ordinary_callers_cannot_override_the_audience() {
    let sessions = active_store(OffsetDateTime::now_utc());
    let (owner, facade) = owner_and_facade(rs256_config(), &sessions);

    for claim in ["aud", "AUD", "iss", "sub", "jti", "exp", "typ", "purpose"] {
        let request = facade_request(&facade, &sessions)
            .await
            .with_claim(claim, json!("another-receiver"));
        assert!(
            matches!(
                facade.issue_session_bound_access_token_only(request).await,
                Err(AuthError::InvalidConfiguration(_))
            ),
            "claim {claim} must stay reserved"
        );
    }

    // Purpose tokens carry a caller-chosen audience, but not the reserved one.
    let purpose_token = |audience: &str| {
        owner.issue_purpose_token(PurposeTokenIssueRequest::new(
            "user-1",
            "export",
            audience,
            Duration::minutes(1),
        ))
    };
    assert!(matches!(purpose_token(RECEIVER), Err(AuthError::Forbidden)));
    assert!(matches!(
        purpose_token(&RECEIVER.to_ascii_uppercase()),
        Err(AuthError::Forbidden)
    ));
    assert!(purpose_token("another-receiver").is_ok());

    // A request is bound to the path that prepared it.
    let owner_prepared = prepared_request(&owner, &sessions, ["Editor"], ["records.read"]).await;
    assert!(matches!(
        facade
            .issue_session_bound_access_token_only(owner_prepared)
            .await,
        Err(AuthError::Forbidden)
    ));
    let facade_prepared = facade_request(&facade, &sessions).await;
    assert!(matches!(
        owner
            .issue_session_bound_access_token_only(facade_prepared.clone())
            .await,
        Err(AuthError::Forbidden)
    ));
    let (_other_owner, other_facade) = match owner_with_parent(rs256_config(), &sessions)
        .into_shared_with_fixed_audience_delegation("another-receiver")
    {
        Ok(pair) => pair,
        Err(error) => panic!("facade startup failed: {error}"),
    };
    assert!(matches!(
        other_facade
            .issue_session_bound_access_token_only(facade_prepared)
            .await,
        Err(AuthError::Forbidden)
    ));
}

#[tokio::test]
async fn receiver_verifiers_refuse_other_tokens_carrying_the_receiver_audience() {
    let sessions = active_store(OffsetDateTime::now_utc());
    let (_owner, facade) = owner_and_facade(rs256_config(), &sessions);
    let receiver = validator(RECEIVER, RSA_PUBLIC_KEY_A);
    let profile = receiver_profile_validator();

    // Same key on an owner that has not reserved the audience: wrong token type.
    let purpose = test_auth_service_with_config(rs256_config())
        .issue_purpose_token(PurposeTokenIssueRequest::new(
            "user-1",
            "export",
            RECEIVER,
            Duration::minutes(1),
        ))
        .unwrap();
    assert!(matches!(
        facade.authenticate_access_token(&purpose.token),
        Err(AuthError::InvalidAccessToken)
    ));
    assert!(matches!(
        receiver.authenticate_access_token(&purpose.token),
        Err(AuthError::InvalidAccessToken)
    ));
    assert!(matches!(
        profile.authenticate_access_token(&purpose.token),
        Err(AuthError::InvalidAccessToken)
    ));

    // The facade verifier and documented receiver profile accept only fully
    // bound delegation tokens.
    let direct = facade
        .issue_session_bound_access_token_only(facade_request(&facade, &sessions).await)
        .await
        .unwrap();
    assert_eq!(
        profile
            .authenticate_access_token(&direct.access_token)
            .unwrap(),
        direct.user
    );
    let mut claims = token_part(&direct.access_token, 1);
    claims["grant_kind"] = json!("user_session");
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KEY_ID.to_string());
    let ordinary = encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY_A.as_bytes()).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        facade.authenticate_access_token(&ordinary),
        Err(AuthError::InvalidAccessToken)
    ));
    assert!(matches!(
        profile.authenticate_access_token(&ordinary),
        Err(AuthError::InvalidAccessToken)
    ));
}

struct CountingRolesProvider(Arc<AtomicU64>);

#[async_trait]
impl AdditionalTokenRolesProvider for CountingRolesProvider {
    async fn additional_token_roles(&self, _user: &AuthUser) -> crate::AuthResult<Vec<String>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(vec!["role:not-for-delegation".to_string()])
    }
}

#[tokio::test]
async fn facade_creates_no_refresh_row_or_idle_extension_and_cannot_chain() {
    let sessions = active_store(OffsetDateTime::now_utc());
    let refresh_store = MemoryRefreshTokenStore::default();
    let provider_calls = Arc::new(AtomicU64::new(0));
    let (owner, facade) = match AuthService::new(
        rs256_config(),
        users_with_parent(),
        Arc::new(refresh_store.clone()),
    )
    .unwrap()
    .with_active_user_session_resolver(Arc::new(sessions.clone()))
    .with_additional_token_roles_provider(Arc::new(CountingRolesProvider(provider_calls.clone())))
    .into_shared_with_fixed_audience_delegation(RECEIVER)
    {
        Ok(pair) => pair,
        Err(error) => panic!("facade startup failed: {error}"),
    };
    owner
        .issue_session_for_user_with_scopes(
            "another-user",
            Vec::new(),
            Vec::new(),
            SessionContext::for_auth_method(AuthMethod::Oidc),
            ClientMetadata::default(),
        )
        .await
        .unwrap();
    let provider_calls_before = provider_calls.load(Ordering::SeqCst);
    let rows_before = refresh_rows(&refresh_store);
    let families_before = refresh_family_count(&refresh_store);
    let row_before = sessions.snapshot();
    let reads_before = sessions.reads.load(Ordering::Relaxed);

    // Issue from a spawned task: the facade is shareable across a host runtime.
    let issuing_facade = facade.clone();
    let issuing_sessions = sessions.clone();
    let grant = tokio::spawn(async move {
        let request = facade_request(&issuing_facade, &issuing_sessions).await;
        issuing_facade
            .issue_session_bound_access_token_only(request)
            .await
    })
    .await
    .unwrap()
    .unwrap();

    assert_eq!(refresh_rows(&refresh_store), rows_before);
    assert_eq!(refresh_family_count(&refresh_store), families_before);
    assert_eq!(sessions.snapshot(), row_before);
    assert_eq!(
        sessions.reads.load(Ordering::Relaxed),
        reads_before + 2,
        "preparation and issuance each perform one read and nothing else"
    );
    assert_eq!(provider_calls.load(Ordering::SeqCst), provider_calls_before);
    assert!(grant.user.token_claims.authorization_roles.is_empty());
    assert_eq!(
        grant.user.token_claims.session_version.as_deref(),
        Some("session-version-1")
    );

    let delegated = facade
        .authenticate_access_token(&grant.access_token)
        .unwrap();
    assert!(matches!(
        delegated.require_session_management_eligible(),
        Err(AuthError::Forbidden)
    ));
    let reference = AuthPrincipal::User(delegated).reference();
    let current = AuthPrincipal::User(
        sessions
            .resolve_active_user_session(&reference)
            .await
            .unwrap()
            .user()
            .clone(),
    );
    let resolved = ResolvedPrincipal::new(reference, current, OffsetDateTime::now_utc()).unwrap();
    assert!(matches!(
        facade
            .prepare_session_bound_access_token_only(
                &resolved,
                vec!["Editor".to_string()],
                vec!["records.read".to_string()],
                delegation_binding(),
            )
            .await,
        Err(AuthError::Forbidden)
    ));
}
