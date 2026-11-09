use super::*;

fn parent(disabled: bool) -> StoredUser {
    StoredUser {
        id: "user-1".to_string(),
        principal: "user-1@example.test".to_string(),
        password_hash: "unused".to_string(),
        roles: vec!["Editor".to_string()],
        scopes: vec!["records.read".to_string()],
        disabled,
    }
}

fn owner(
    users: &MemoryUserStore,
    sessions: &ActiveSessionStore,
) -> AuthService<MemoryUserStore, MemoryRefreshTokenStore> {
    AuthService::new(
        AuthConfig::new(super::super::TEST_HS256_SECRET),
        Arc::new(users.clone()),
        Arc::new(MemoryRefreshTokenStore::default()),
    )
    .unwrap()
    .with_active_user_session_resolver(Arc::new(sessions.clone()))
}

async fn prepare(
    auth: &AuthService<MemoryUserStore, MemoryRefreshTokenStore>,
    sessions: &ActiveSessionStore,
) -> crate::AuthResult<SessionBoundAccessTokenOnlyRequest> {
    auth.prepare_session_bound_access_token_only(
        &sessions.initial_resolution().unwrap(),
        vec!["Editor".to_string()],
        vec!["records.read".to_string()],
        delegation_binding(),
    )
    .await
}

#[tokio::test]
async fn general_delegation_requires_a_current_enabled_parent_at_both_reads() {
    let sessions = active_store(OffsetDateTime::now_utc());
    let users = MemoryUserStore::default();
    users.insert(parent(false));
    let auth = owner(&users, &sessions);

    let request = prepare(&auth, &sessions).await.unwrap();
    auth.issue_session_bound_access_token_only(request.clone())
        .await
        .unwrap();

    users.insert(parent(true));
    assert!(matches!(
        auth.issue_session_bound_access_token_only(request.clone())
            .await,
        Err(AuthError::UserDisabled)
    ));
    assert!(matches!(
        prepare(&auth, &sessions).await,
        Err(AuthError::UserDisabled)
    ));

    users.remove("user-1");
    assert!(matches!(
        auth.issue_session_bound_access_token_only(request.clone())
            .await,
        Err(AuthError::Forbidden)
    ));
    assert!(matches!(
        prepare(&auth, &sessions).await,
        Err(AuthError::Forbidden)
    ));

    users.insert(parent(false));
    users.corrupt_returned_id("user-1");
    assert!(matches!(
        auth.issue_session_bound_access_token_only(request).await,
        Err(AuthError::AuthServiceUnavailable)
    ));
}
