use time::{Duration, OffsetDateTime};

use super::{MemoryRefreshTokenStore, MemoryUserStore, metadata, stored_user, test_auth_service};
use crate::prelude::*;
use crate::util::hash_refresh_token;

#[tokio::test]
async fn hashes_and_verifies_passwords() {
    let auth = test_auth_service(Default::default(), Default::default());
    let hash = auth.hash_password("correct horse battery staple").unwrap();
    auth.verify_password("correct horse battery staple", &hash)
        .unwrap();
    let err = auth.verify_password("wrong", &hash).unwrap_err();
    assert!(matches!(err, AuthError::InvalidCredentials));
}

#[tokio::test]
async fn login_issues_tokens_and_authenticates_access_token() {
    let user_store = MemoryUserStore::default();
    let refresh_store = MemoryRefreshTokenStore::default();
    let auth = test_auth_service(user_store.clone(), refresh_store.clone());
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

    assert_eq!(payload.user.user_id, "user-1");
    assert_eq!(payload.user.session.auth_method, AuthMethod::Password);
    assert!(!payload.user.session.mfa.satisfied);
    assert!(payload.user.session.mfa.methods.is_empty());
    assert_eq!(payload.user.session.active_scope, None);

    let authenticated = auth
        .authenticate_access_token(&payload.access_token)
        .unwrap();
    assert_eq!(authenticated.user_id, payload.user.user_id);
    assert_eq!(authenticated.session_id, payload.user.session_id);
    assert_eq!(authenticated.session, payload.user.session);
}

#[tokio::test]
async fn login_rejects_disabled_users() {
    let user_store = MemoryUserStore::default();
    let refresh_store = MemoryRefreshTokenStore::default();
    let auth = test_auth_service(user_store.clone(), refresh_store);
    let mut user = stored_user(&auth, "user-1", "alice@example.com", "password123");
    user.disabled = true;
    user_store.insert(user);

    let err = auth
        .login("alice@example.com", "password123", metadata())
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::UserDisabled));
}

#[tokio::test]
async fn refresh_rotates_tokens_and_tracks_usage_metadata() {
    let user_store = MemoryUserStore::default();
    let refresh_store = MemoryRefreshTokenStore::default();
    let auth = test_auth_service(user_store.clone(), refresh_store.clone());
    user_store.insert(stored_user(
        &auth,
        "user-1",
        "alice@example.com",
        "password123",
    ));

    let login_payload = auth
        .login("alice@example.com", "password123", metadata())
        .await
        .unwrap();

    let original_hash = hash_refresh_token(&login_payload.refresh_token);
    let original_record = refresh_store.get_by_hash(&original_hash).unwrap();

    let refreshed = auth
        .refresh(
            &login_payload.refresh_token,
            ClientMetadata {
                ip_address: Some("10.0.0.5".to_string()),
                user_agent: Some("refreshed-agent".to_string()),
            },
        )
        .await
        .unwrap();

    let rotated_original = refresh_store.get_by_hash(&original_hash).unwrap();
    assert_eq!(rotated_original.id, original_record.id);
    assert!(rotated_original.revoked_at.is_some());
    assert!(rotated_original.last_used_at.is_some());
    assert_eq!(rotated_original.ip_address.as_deref(), Some("10.0.0.5"));
    assert_eq!(
        rotated_original.user_agent.as_deref(),
        Some("refreshed-agent")
    );

    let new_record = refresh_store
        .get_by_hash(&hash_refresh_token(&refreshed.refresh_token))
        .unwrap();
    assert_eq!(rotated_original.replaced_by_token_id, Some(new_record.id));
    assert_eq!(
        new_record.session_family_id,
        original_record.session_family_id
    );
    assert_eq!(new_record.session_id, original_record.session_id);
    assert_eq!(new_record.session, original_record.session);
    assert_eq!(refreshed.user.session, login_payload.user.session);
}

#[tokio::test]
async fn refresh_detects_replay_for_revoked_tokens() {
    let user_store = MemoryUserStore::default();
    let refresh_store = MemoryRefreshTokenStore::default();
    let auth = test_auth_service(user_store.clone(), refresh_store.clone());
    user_store.insert(stored_user(
        &auth,
        "user-1",
        "alice@example.com",
        "password123",
    ));

    let login_payload = auth
        .login("alice@example.com", "password123", metadata())
        .await
        .unwrap();
    let _ = auth
        .refresh(&login_payload.refresh_token, metadata())
        .await
        .unwrap();

    let err = auth
        .refresh(&login_payload.refresh_token, metadata())
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::RefreshTokenReplayDetected));
    assert_eq!(refresh_store.family_revocations.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn refresh_rejects_expired_tokens() {
    let user_store = MemoryUserStore::default();
    let refresh_store = MemoryRefreshTokenStore::default();
    let auth = test_auth_service(user_store.clone(), refresh_store.clone());
    user_store.insert(stored_user(
        &auth,
        "user-1",
        "alice@example.com",
        "password123",
    ));

    let login_payload = auth
        .login("alice@example.com", "password123", metadata())
        .await
        .unwrap();
    let original_hash = hash_refresh_token(&login_payload.refresh_token);
    let token_id = refresh_store.get_by_hash(&original_hash).unwrap().id;
    refresh_store
        .tokens_by_id
        .lock()
        .unwrap()
        .get_mut(&token_id)
        .unwrap()
        .expires_at = OffsetDateTime::now_utc() - Duration::seconds(1);

    let err = auth
        .refresh(&login_payload.refresh_token, metadata())
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::RefreshTokenExpired));
}

#[tokio::test]
async fn logout_revokes_single_token_or_entire_family() {
    let user_store = MemoryUserStore::default();
    let refresh_store = MemoryRefreshTokenStore::default();
    let auth = test_auth_service(user_store.clone(), refresh_store.clone());
    user_store.insert(stored_user(
        &auth,
        "user-1",
        "alice@example.com",
        "password123",
    ));

    let first = auth
        .login("alice@example.com", "password123", metadata())
        .await
        .unwrap();
    let second = auth
        .refresh(&first.refresh_token, metadata())
        .await
        .unwrap();
    let first_hash = hash_refresh_token(&first.refresh_token);
    let second_hash = hash_refresh_token(&second.refresh_token);

    auth.logout(&second.refresh_token, false).await.unwrap();
    assert!(
        refresh_store
            .get_by_hash(&second_hash)
            .unwrap()
            .revoked_at
            .is_some()
    );

    auth.logout(&first.refresh_token, true).await.unwrap();
    assert!(
        refresh_store
            .get_by_hash(&first_hash)
            .unwrap()
            .revoked_at
            .is_some()
    );
}

#[tokio::test]
async fn bearer_and_connection_init_authentication_work() {
    let user_store = MemoryUserStore::default();
    let refresh_store = MemoryRefreshTokenStore::default();
    let auth = test_auth_service(user_store.clone(), refresh_store);
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

    let bearer_user = auth
        .authenticate_bearer(&format!("Bearer {}", payload.access_token))
        .unwrap();
    assert_eq!(bearer_user.user_id, "user-1");

    let data = auth
        .authenticate_connection_init_value(serde_json::json!({
            "authorization": format!("Bearer {}", payload.access_token)
        }))
        .await
        .unwrap();
    let data_user = data
        .get(&std::any::TypeId::of::<AuthUser>())
        .and_then(|value| value.downcast_ref::<AuthUser>())
        .unwrap();
    assert_eq!(data_user.user_id, "user-1");
    assert_eq!(data_user.session.auth_method, AuthMethod::Password);
}

#[tokio::test]
async fn verified_user_session_issuance_supports_email_code_and_totp_context() {
    let auth = test_auth_service(Default::default(), Default::default());
    let payload = auth
        .issue_verified_user_session(
            "user-verified",
            vec!["CatalogEditor".to_string()],
            AuthMethod::EmailCode,
            metadata(),
        )
        .await
        .unwrap();

    assert_eq!(payload.user.user_id, "user-verified");
    assert_eq!(payload.user.session.auth_method, AuthMethod::EmailCode);
    assert!(!payload.user.session.mfa.satisfied);
    assert!(payload.user.session.active_scope.is_none());

    let stepped_up = auth
        .issue_session_for_user(
            "user-verified",
            vec!["CatalogEditor".to_string()],
            SessionContext {
                auth_method: AuthMethod::TotpStepUp,
                mfa: MfaState {
                    satisfied: true,
                    methods: vec![MfaMethod::Totp],
                },
                active_scope: Some(ActiveScope {
                    tenant_id: Some("tenant-1".to_string()),
                    organization_id: Some("org-1".to_string()),
                    catalog_id: Some("catalog-1".to_string()),
                }),
            },
            metadata(),
        )
        .await
        .unwrap();

    let decoded = auth
        .authenticate_access_token(&stepped_up.access_token)
        .unwrap();
    assert_eq!(decoded.session.auth_method, AuthMethod::TotpStepUp);
    assert!(decoded.session.mfa.satisfied);
    assert_eq!(decoded.session.mfa.methods, vec![MfaMethod::Totp]);
    assert_eq!(
        decoded
            .session
            .active_scope
            .as_ref()
            .and_then(|scope| scope.catalog_id.as_deref()),
        Some("catalog-1")
    );
}
