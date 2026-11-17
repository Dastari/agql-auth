//! Exercises `agql-auth` strictly through its public API, the way a host
//! application does: host-owned stores implemented outside the crate, the
//! prelude only, and no access to crate internals.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use agql_auth::AuthResult;
use agql_auth::prelude::*;
use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

const SECRET: &str = "public-api-test-secret-at-least-32-bytes";

#[derive(Default, Clone)]
struct Users(Arc<Mutex<Vec<StoredUser>>>);

#[async_trait]
impl UserStore for Users {
    async fn find_user_by_principal(&self, principal: &str) -> AuthResult<Option<StoredUser>> {
        let users = self.0.lock().unwrap();
        Ok(users.iter().find(|u| u.principal == principal).cloned())
    }

    async fn find_user_by_id(&self, user_id: &str) -> AuthResult<Option<StoredUser>> {
        let users = self.0.lock().unwrap();
        Ok(users.iter().find(|u| u.id == user_id).cloned())
    }
}

/// A host refresh store following the documented contract: hashes only,
/// compare-and-swap rotation, revoked records left unchanged.
#[derive(Default, Clone)]
struct Sessions(Arc<Mutex<HashMap<Uuid, StoredRefreshToken>>>);

impl Sessions {
    fn live_count(&self) -> usize {
        let tokens = self.0.lock().unwrap();
        tokens.values().filter(|t| t.revoked_at.is_none()).count()
    }
}

#[async_trait]
impl RefreshTokenStore for Sessions {
    async fn insert_refresh_token(&self, token: StoredRefreshToken) -> AuthResult<()> {
        self.0.lock().unwrap().insert(token.id, token);
        Ok(())
    }

    async fn find_refresh_token_by_hash(
        &self,
        token_hash: &str,
    ) -> AuthResult<Option<StoredRefreshToken>> {
        let tokens = self.0.lock().unwrap();
        Ok(tokens
            .values()
            .find(|t| t.token_hash == token_hash)
            .cloned())
    }

    async fn revoke_refresh_token(
        &self,
        token_id: Uuid,
        revoked_at: OffsetDateTime,
        replaced_by_token_id: Option<Uuid>,
        reason: RefreshTokenRevocationReason,
    ) -> AuthResult<()> {
        let mut tokens = self.0.lock().unwrap();
        if let Some(token) = tokens.get_mut(&token_id).filter(|t| t.revoked_at.is_none()) {
            token.revoked_at = Some(revoked_at);
            token.replaced_by_token_id = replaced_by_token_id;
            let _ = reason;
        }
        Ok(())
    }

    async fn revoke_refresh_token_family(
        &self,
        session_family_id: Uuid,
        revoked_at: OffsetDateTime,
        _reason: RefreshTokenRevocationReason,
    ) -> AuthResult<()> {
        let mut tokens = self.0.lock().unwrap();
        for token in tokens
            .values_mut()
            .filter(|t| t.session_family_id == session_family_id && t.revoked_at.is_none())
        {
            token.revoked_at = Some(revoked_at);
        }
        Ok(())
    }

    async fn revoke_refresh_tokens_for_user(
        &self,
        user_id: &str,
        revoked_at: OffsetDateTime,
        _reason: RefreshTokenRevocationReason,
    ) -> AuthResult<u64> {
        let mut tokens = self.0.lock().unwrap();
        let mut revoked = 0;
        for token in tokens
            .values_mut()
            .filter(|t| t.user_id == user_id && t.revoked_at.is_none())
        {
            token.revoked_at = Some(revoked_at);
            revoked += 1;
        }
        Ok(revoked)
    }

    async fn touch_refresh_token(
        &self,
        token_id: Uuid,
        used_at: OffsetDateTime,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AuthResult<()> {
        if let Some(token) = self.0.lock().unwrap().get_mut(&token_id) {
            token.last_used_at = Some(used_at);
            token.ip_address = ip_address;
            token.user_agent = user_agent;
        }
        Ok(())
    }

    async fn rotate_refresh_token(
        &self,
        current_token_id: Uuid,
        replacement: StoredRefreshToken,
        rotated_at: OffsetDateTime,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AuthResult<bool> {
        let mut tokens = self.0.lock().unwrap();
        let Some(current) = tokens
            .get_mut(&current_token_id)
            .filter(|t| t.revoked_at.is_none())
        else {
            return Ok(false);
        };
        current.revoked_at = Some(rotated_at);
        current.replaced_by_token_id = Some(replacement.id);
        current.last_used_at = Some(rotated_at);
        current.ip_address = ip_address;
        current.user_agent = user_agent;
        tokens.insert(replacement.id, replacement);
        Ok(true)
    }
}

fn client() -> ClientMetadata {
    ClientMetadata {
        ip_address: Some("192.0.2.10".to_string()),
        user_agent: Some("public-api-test".to_string()),
    }
}

fn setup() -> (AuthService<Users, Sessions>, Users, Sessions) {
    let users = Users::default();
    let sessions = Sessions::default();
    let auth = AuthService::new(
        AuthConfig::new(SECRET),
        Arc::new(users.clone()),
        Arc::new(sessions.clone()),
    )
    .unwrap();
    users.0.lock().unwrap().push(StoredUser {
        id: "user-1".to_string(),
        principal: "alice@example.com".to_string(),
        password_hash: auth.hash_password("correct horse battery").unwrap(),
        roles: vec!["member".to_string()],
        scopes: vec!["orders.read".to_string()],
        disabled: false,
    });
    (auth, users, sessions)
}

#[tokio::test]
async fn login_tokens_validate_in_the_service_and_a_resource_server() {
    let (auth, _users, _sessions) = setup();
    let payload = auth
        .login("alice@example.com", "correct horse battery", client())
        .await
        .unwrap();

    let user = auth
        .authenticate_bearer(&format!("Bearer {}", payload.access_token))
        .unwrap();
    assert_eq!(user.user_id, "user-1");
    assert!(user.scopes.iter().any(|s| s == "orders.read"));

    let validator = AccessTokenValidator::builder()
        .issuer("agql-auth")
        .audience("agql-auth-clients")
        .hs256_secret(SECRET)
        .accept_hs256(true)
        .build()
        .unwrap();
    let validated = validator
        .authenticate_bearer(&format!("Bearer {}", payload.access_token))
        .unwrap();
    assert_eq!(validated.user_id, "user-1");
    // Resource servers require the Bearer scheme by default.
    assert!(
        validator
            .authenticate_bearer(&payload.access_token)
            .is_err()
    );
}

#[tokio::test]
async fn wrong_passwords_and_unknown_users_are_indistinguishable() {
    let (auth, _users, sessions) = setup();
    let wrong = auth
        .login("alice@example.com", "wrong", client())
        .await
        .unwrap_err();
    let unknown = auth
        .login("nobody@example.com", "wrong", client())
        .await
        .unwrap_err();
    assert_eq!(wrong.public_code(), "INVALID_CREDENTIALS");
    assert_eq!(unknown.public_code(), wrong.public_code());
    assert_eq!(unknown.to_string(), wrong.to_string());
    assert_eq!(sessions.live_count(), 0);
}

#[tokio::test]
async fn refresh_rotation_replay_and_sign_out_everywhere() {
    let (auth, _users, sessions) = setup();
    let first = auth
        .login("alice@example.com", "correct horse battery", client())
        .await
        .unwrap();
    let rotated = auth.refresh(&first.refresh_token, client()).await.unwrap();
    assert_eq!(sessions.live_count(), 1);

    // Replaying the superseded token is detected and ends the family.
    assert!(auth.refresh(&first.refresh_token, client()).await.is_err());
    assert!(
        auth.refresh(&rotated.refresh_token, client())
            .await
            .is_err()
    );
    assert_eq!(sessions.live_count(), 0);

    let a = auth
        .login("alice@example.com", "correct horse battery", client())
        .await
        .unwrap();
    let _b = auth
        .login("alice@example.com", "correct horse battery", client())
        .await
        .unwrap();
    assert_eq!(sessions.live_count(), 2);
    let revoked = auth
        .revoke_user_sessions("user-1", RefreshTokenRevocationReason::AdminRevoked)
        .await
        .unwrap();
    assert_eq!(revoked, 2);
    assert!(auth.refresh(&a.refresh_token, client()).await.is_err());
}

#[tokio::test]
async fn disabled_users_cannot_refresh() {
    let (auth, users, _sessions) = setup();
    let payload = auth
        .login("alice@example.com", "correct horse battery", client())
        .await
        .unwrap();
    users.0.lock().unwrap()[0].disabled = true;
    assert!(
        auth.refresh(&payload.refresh_token, client())
            .await
            .is_err()
    );
}

#[test]
fn errors_display_only_public_messages() {
    let error = AuthError::Store("connection to db://admin:hunter2@10.0.0.5 failed".into());
    let shown = error.to_string();
    assert!(!shown.contains("hunter2"), "Display leaked: {shown}");
    assert_eq!(error.public_code(), "AUTH_SERVICE_UNAVAILABLE");
    let graphql: async_graphql::Error = error.into();
    assert!(!graphql.message.contains("hunter2"));
}
