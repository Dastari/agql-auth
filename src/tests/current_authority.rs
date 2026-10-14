use super::*;

#[derive(Clone)]
struct GrantAuthority(Arc<Mutex<CurrentRefreshGrant>>);
#[async_trait]
impl RefreshGrantAuthority for GrantAuthority {
    async fn current_grant(
        &self,
        _: &StoredRefreshToken,
        _: &StoredUser,
    ) -> crate::AuthResult<CurrentRefreshGrant> {
        Ok(self.0.lock().unwrap().clone())
    }
}

#[tokio::test]
async fn password_refresh_removes_grants_twice_and_never_adds_new_authority() {
    let users = MemoryUserStore::default();
    let refresh = MemoryRefreshTokenStore::default();
    let auth = test_auth_service(users.clone(), refresh);
    let mut user = stored_user(
        &auth,
        "audit-user",
        "audit@example.invalid",
        "synthetic-password",
    );
    user.scopes = vec!["read".into(), "sensitive.write".into()];
    user.roles = vec!["member".into(), "admin".into()];
    users.insert(user.clone());
    let first = auth
        .login(&user.principal, "synthetic-password", metadata())
        .await
        .unwrap();
    user.scopes = vec!["read".into(), "new.scope".into()];
    user.roles = vec!["member".into(), "new.role".into()];
    users.insert(user.clone());
    let second = auth
        .refresh(&first.refresh_token, metadata())
        .await
        .unwrap();
    assert_eq!(second.user.scopes, ["read"]);
    assert_eq!(second.user.roles, ["member"]);
    user.scopes = vec!["sensitive.write".into()];
    user.roles = vec!["admin".into()];
    users.insert(user.clone());
    let third = auth
        .refresh(&second.refresh_token, metadata())
        .await
        .unwrap();
    let signed = auth.authenticate_access_token(&third.access_token).unwrap();
    assert!(signed.scopes.is_empty());
    assert!(signed.roles.is_empty());
    let fresh = auth
        .login(&user.principal, "synthetic-password", metadata())
        .await
        .unwrap();
    assert_eq!(fresh.user.scopes, ["sensitive.write"]);
}

#[tokio::test]
async fn host_refresh_requires_authority_preserves_external_downscope_and_propagates_removal() {
    let users = MemoryUserStore::default();
    let refresh = MemoryRefreshTokenStore::default();
    let auth = test_auth_service(users.clone(), refresh.clone());
    users.insert(stored_user(
        &auth,
        "u",
        "u@example.invalid",
        "synthetic-password",
    ));
    let issued = auth
        .issue_verified_user_session_with_scopes(
            "u",
            vec!["external.member".into()],
            vec!["external.read".into()],
            AuthMethod::Oidc,
            metadata(),
        )
        .await
        .unwrap();
    assert!(matches!(
        auth.refresh(&issued.refresh_token, metadata()).await,
        Err(AuthError::Forbidden)
    ));
    let grants = Arc::new(Mutex::new(CurrentRefreshGrant {
        roles: vec!["external.member".into(), "admin".into()],
        scopes: vec!["external.read".into(), "external.write".into()],
    }));
    let auth = auth.with_refresh_grant_authority(Arc::new(GrantAuthority(grants.clone())));
    let second = auth
        .refresh(&issued.refresh_token, metadata())
        .await
        .unwrap();
    assert_eq!(second.user.scopes, ["external.read"]);
    assert_eq!(second.user.roles, ["external.member"]);
    *grants.lock().unwrap() = CurrentRefreshGrant::default();
    let third = auth
        .refresh(&second.refresh_token, metadata())
        .await
        .unwrap();
    assert!(third.user.scopes.is_empty());
    assert!(third.user.roles.is_empty());
}

struct BrokenAuthority;
#[async_trait]
impl RefreshGrantAuthority for BrokenAuthority {
    async fn current_grant(
        &self,
        _: &StoredRefreshToken,
        _: &StoredUser,
    ) -> crate::AuthResult<CurrentRefreshGrant> {
        Err(AuthError::Store("synthetic authority outage".into()))
    }
}

#[tokio::test]
async fn authority_failure_and_legacy_records_issue_nothing_and_disabled_deleted_users_fail() {
    let users = MemoryUserStore::default();
    let refresh = MemoryRefreshTokenStore::default();
    let auth = test_auth_service(users.clone(), refresh.clone())
        .with_refresh_grant_authority(Arc::new(BrokenAuthority));
    let mut user = stored_user(&auth, "u", "u@example.invalid", "synthetic-password");
    users.insert(user.clone());
    let issued = auth
        .issue_verified_user_session("u", vec![], AuthMethod::Oidc, metadata())
        .await
        .unwrap();
    assert!(matches!(
        auth.refresh(&issued.refresh_token, metadata()).await,
        Err(AuthError::Store(_))
    ));
    assert_eq!(*refresh.rotations.lock().unwrap(), 0);
    for row in refresh.tokens_by_id.lock().unwrap().values_mut() {
        row.grant_source = RefreshGrantSource::Legacy;
    }
    assert!(matches!(
        auth.refresh(&issued.refresh_token, metadata()).await,
        Err(AuthError::Forbidden)
    ));
    user.disabled = true;
    users.insert(user);
    assert!(matches!(
        auth.refresh(&issued.refresh_token, metadata()).await,
        Err(AuthError::UserDisabled)
    ));
    users.users_by_id.lock().unwrap().clear();
    assert!(matches!(
        auth.refresh(&issued.refresh_token, metadata()).await,
        Err(AuthError::InvalidRefreshToken)
    ));
    assert_eq!(refresh.tokens_by_id.lock().unwrap().len(), 1);
}

struct Resolver {
    current: AuthPrincipal,
    fail: bool,
}
#[async_trait]
impl CurrentPrincipalResolver for Resolver {
    async fn resolve(
        &self,
        reference: &PrincipalReference,
    ) -> crate::AuthResult<ResolvedPrincipal> {
        if self.fail {
            return Err(AuthError::Forbidden);
        }
        ResolvedPrincipal::new(
            reference.clone(),
            self.current.clone(),
            OffsetDateTime::now_utc(),
        )
    }
}
struct DelegationStatus(TokenStatus);
#[async_trait]
impl TokenStatusChecker for DelegationStatus {
    async fn check(&self, request: TokenStatusRequest<'_>) -> crate::AuthResult<TokenStatus> {
        assert_eq!(request.token_id, Some("delegated-token"));
        assert_eq!(
            request.principal.reference().grant_kind,
            Some(AccessTokenGrantKind::SessionBoundDelegation)
        );
        Ok(self.0)
    }
}
struct Status(Option<TokenStatus>);
#[async_trait]
impl TokenStatusChecker for Status {
    async fn check(&self, _: TokenStatusRequest<'_>) -> crate::AuthResult<TokenStatus> {
        self.0.ok_or(AuthError::AuthServiceUnavailable)
    }
}

#[tokio::test]
async fn sensitive_revalidation_uses_current_grants_every_time_and_fails_closed() {
    let users = MemoryUserStore::default();
    let auth = test_auth_service(users.clone(), MemoryRefreshTokenStore::default());
    let user = stored_user(&auth, "u", "u@example.invalid", "synthetic-password");
    users.insert(user.clone());
    let issued = auth
        .login(&user.principal, "synthetic-password", metadata())
        .await
        .unwrap();
    let accepted = AuthPrincipal::User(issued.user);
    let now = OffsetDateTime::now_utc();
    let mut current = accepted.clone();
    if let AuthPrincipal::User(user) = &mut current {
        user.roles.clear();
        user.scopes = vec!["new.scope".into()];
    }
    let resolver = Resolver {
        current,
        fail: false,
    };
    let result = revalidate_sensitive_principal(
        &accepted,
        &resolver,
        &Status(Some(TokenStatus::Active)),
        now,
    )
    .await
    .unwrap();
    assert!(result.roles().is_empty());
    assert!(result.scopes().is_empty());
    assert_eq!(result.reference(), accepted.reference());
    for status in [None, Some(TokenStatus::Revoked), Some(TokenStatus::Expired)] {
        assert!(
            revalidate_sensitive_principal(&accepted, &resolver, &Status(status), now)
                .await
                .is_err()
        );
    }
    let broken = Resolver {
        current: accepted.clone(),
        fail: true,
    };
    assert!(
        revalidate_sensitive_principal(&accepted, &broken, &Status(Some(TokenStatus::Active)), now)
            .await
            .is_err()
    );
    let mut wrong = accepted.clone();
    if let AuthPrincipal::User(user) = &mut wrong {
        user.token_claims.jti = Some("replacement-token".into());
    }
    assert!(
        revalidate_sensitive_principal(
            &accepted,
            &Resolver {
                current: wrong,
                fail: false
            },
            &Status(Some(TokenStatus::Active)),
            now
        )
        .await
        .is_err()
    );
    assert!(
        revalidate_sensitive_principal(
            &accepted,
            &resolver,
            &Status(Some(TokenStatus::Active)),
            now + time::Duration::days(1)
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn delegation_revalidation_checks_original_status_and_exact_parent_context() {
    let users = MemoryUserStore::default();
    let auth = test_auth_service(users.clone(), MemoryRefreshTokenStore::default());
    let user = stored_user(&auth, "u", "u@example.invalid", "synthetic-password");
    users.insert(user.clone());
    let issued = auth
        .login(&user.principal, "synthetic-password", metadata())
        .await
        .unwrap();
    let mut parent = issued.user;
    parent.token_claims.session_version = Some("current-v1".into());
    parent.token_claims.tenant_id = Some("tenant-a".into());
    let mut delegated = parent.clone();
    delegated.token_claims.grant_kind = Some(AccessTokenGrantKind::SessionBoundDelegation);
    delegated.token_claims.jti = Some("delegated-token".into());
    delegated.token_claims.resource_type = Some("project".into());
    delegated.token_claims.resource_id = Some("project-1".into());
    let accepted = AuthPrincipal::User(delegated);
    let now = OffsetDateTime::now_utc();
    let resolver = Resolver {
        current: AuthPrincipal::User(parent.clone()),
        fail: false,
    };
    let result = revalidate_sensitive_principal(
        &accepted,
        &resolver,
        &DelegationStatus(TokenStatus::Active),
        now,
    )
    .await
    .unwrap();
    assert_eq!(result.reference(), accepted.reference());
    assert!(
        revalidate_sensitive_principal(
            &accepted,
            &resolver,
            &DelegationStatus(TokenStatus::Revoked),
            now
        )
        .await
        .is_err()
    );
    for change in 0..6 {
        let mut wrong = parent.clone();
        match change {
            0 => wrong.user_id = "other-user".into(),
            1 => wrong.session_id = Uuid::new_v4(),
            2 => wrong.token_claims.tenant_id = Some("tenant-b".into()),
            3 => wrong.token_claims.session_version = Some("revoked-v2".into()),
            4 => {
                wrong.session.active_scope = Some(ActiveScope {
                    tenant_id: Some("tenant-b".into()),
                    ..ActiveScope::default()
                })
            }
            _ => wrong.token_claims.expires_at = Some(now - time::Duration::seconds(1)),
        }
        let resolver = Resolver {
            current: AuthPrincipal::User(wrong),
            fail: false,
        };
        assert!(
            revalidate_sensitive_principal(
                &accepted,
                &resolver,
                &DelegationStatus(TokenStatus::Active),
                now
            )
            .await
            .is_err()
        );
    }
}

#[tokio::test]
async fn api_revalidation_narrows_grants_preserves_bindings_and_checks_each_operation() {
    let now = OffsetDateTime::now_utc();
    let token = ApiTokenPrincipal {
        token_id: Uuid::new_v4(),
        subject: "service-1".into(),
        principal_kind: ApiTokenPrincipalKind::service(),
        scopes: vec!["read".into(), "write".into()],
        audience: Some("sensitive-api".into()),
        resource_type: Some("project".into()),
        resource_id: Some("project-1".into()),
        expires_at: now + time::Duration::hours(1),
    };
    let accepted = AuthPrincipal::ApiToken(token.clone());
    let mut current = token.clone();
    current.scopes = vec!["read".into(), "admin".into()];
    let resolver = Resolver {
        current: AuthPrincipal::ApiToken(current),
        fail: false,
    };
    let result = revalidate_sensitive_principal(
        &accepted,
        &resolver,
        &Status(Some(TokenStatus::Active)),
        now,
    )
    .await
    .unwrap();
    assert_eq!(result.scopes(), ["read"]);
    assert_eq!(result.reference(), accepted.reference());
    assert!(
        revalidate_sensitive_principal(
            &accepted,
            &resolver,
            &Status(Some(TokenStatus::Revoked)),
            now
        )
        .await
        .is_err()
    );
    for change in 0..5 {
        let mut wrong = token.clone();
        match change {
            0 => wrong.token_id = Uuid::new_v4(),
            1 => wrong.subject = "other-service".into(),
            2 => wrong.audience = Some("other-api".into()),
            3 => wrong.resource_id = Some("project-2".into()),
            _ => wrong.principal_kind = ApiTokenPrincipalKind::integration(),
        }
        let resolver = Resolver {
            current: AuthPrincipal::ApiToken(wrong),
            fail: false,
        };
        assert!(
            revalidate_sensitive_principal(
                &accepted,
                &resolver,
                &Status(Some(TokenStatus::Active)),
                now
            )
            .await
            .is_err()
        );
    }
}

#[test]
fn historical_refresh_records_cannot_guess_grant_provenance() {
    assert_eq!(
        serde_json::from_str::<RefreshGrantSource>("\"legacy\"").unwrap(),
        RefreshGrantSource::Legacy
    );
    assert!(serde_json::from_str::<RefreshGrantSource>("\"unsupported\"").is_err());
}

struct PausedAuthority {
    grants: Arc<Mutex<CurrentRefreshGrant>>,
    observed: Arc<tokio::sync::Notify>,
    resume: Arc<tokio::sync::Notify>,
}
#[async_trait]
impl RefreshGrantAuthority for PausedAuthority {
    async fn current_grant(
        &self,
        _: &StoredRefreshToken,
        _: &StoredUser,
    ) -> crate::AuthResult<CurrentRefreshGrant> {
        let snapshot = self.grants.lock().unwrap().clone();
        self.observed.notify_one();
        self.resume.notified().await;
        Ok(snapshot)
    }
}

#[tokio::test]
async fn concurrent_grant_removal_is_ordered_at_authority_read_not_later_rotation() {
    let users = MemoryUserStore::default();
    let auth = test_auth_service(users.clone(), MemoryRefreshTokenStore::default());
    users.insert(stored_user(
        &auth,
        "u",
        "u@example.invalid",
        "synthetic-password",
    ));
    let grants = Arc::new(Mutex::new(CurrentRefreshGrant {
        roles: vec![],
        scopes: vec!["write".into()],
    }));
    let observed = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let auth = Arc::new(auth.with_refresh_grant_authority(Arc::new(PausedAuthority {
        grants: grants.clone(),
        observed: observed.clone(),
        resume: resume.clone(),
    })));
    let first = auth
        .issue_verified_user_session_with_scopes(
            "u",
            vec![],
            vec!["write".into()],
            AuthMethod::Oidc,
            metadata(),
        )
        .await
        .unwrap();
    let rotating = auth.clone();
    let task =
        tokio::spawn(async move { rotating.refresh(&first.refresh_token, metadata()).await });
    observed.notified().await;
    grants.lock().unwrap().scopes.clear();
    resume.notify_one();
    let second = task.await.unwrap().unwrap();
    assert_eq!(
        second.user.scopes,
        ["write"],
        "a later removal cannot change the authority snapshot already read"
    );
    resume.notify_one();
    let third = auth
        .refresh(&second.refresh_token, metadata())
        .await
        .unwrap();
    assert!(
        third.user.scopes.is_empty(),
        "removal completed before this authority read must be reflected"
    );
}
