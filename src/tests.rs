mod auth_lifecycle;
mod challenges;
mod recovery;
mod scopes;
mod totp;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::prelude::*;

#[derive(Clone, Default)]
pub(super) struct MemoryUserStore {
    users_by_id: Arc<Mutex<HashMap<String, StoredUser>>>,
    principal_to_id: Arc<Mutex<HashMap<String, String>>>,
}

impl MemoryUserStore {
    pub(super) fn insert(&self, user: StoredUser) {
        let user_id = user.id.clone();
        let principal = user.principal.clone();
        self.users_by_id
            .lock()
            .unwrap()
            .insert(user_id.clone(), user);
        self.principal_to_id
            .lock()
            .unwrap()
            .insert(principal, user_id);
    }
}

#[async_trait]
impl UserStore for MemoryUserStore {
    async fn find_user_by_principal(
        &self,
        principal: &str,
    ) -> crate::AuthResult<Option<StoredUser>> {
        let user_id = self.principal_to_id.lock().unwrap().get(principal).cloned();
        Ok(user_id.and_then(|id| self.users_by_id.lock().unwrap().get(&id).cloned()))
    }

    async fn find_user_by_id(&self, user_id: &str) -> crate::AuthResult<Option<StoredUser>> {
        Ok(self.users_by_id.lock().unwrap().get(user_id).cloned())
    }
}

#[derive(Clone, Default)]
pub(super) struct MemoryRefreshTokenStore {
    pub(super) tokens_by_id: Arc<Mutex<HashMap<Uuid, StoredRefreshToken>>>,
    token_hash_to_id: Arc<Mutex<HashMap<String, Uuid>>>,
    pub(super) family_revocations:
        Arc<Mutex<Vec<(Uuid, OffsetDateTime, RefreshTokenRevocationReason)>>>,
}

impl MemoryRefreshTokenStore {
    pub(super) fn get_by_hash(&self, token_hash: &str) -> Option<StoredRefreshToken> {
        let token_id = self
            .token_hash_to_id
            .lock()
            .unwrap()
            .get(token_hash)
            .copied()?;
        self.tokens_by_id.lock().unwrap().get(&token_id).cloned()
    }
}

#[async_trait]
impl RefreshTokenStore for MemoryRefreshTokenStore {
    async fn insert_refresh_token(&self, token: StoredRefreshToken) -> crate::AuthResult<()> {
        self.token_hash_to_id
            .lock()
            .unwrap()
            .insert(token.token_hash.clone(), token.id);
        self.tokens_by_id.lock().unwrap().insert(token.id, token);
        Ok(())
    }

    async fn find_refresh_token_by_hash(
        &self,
        token_hash: &str,
    ) -> crate::AuthResult<Option<StoredRefreshToken>> {
        Ok(self.get_by_hash(token_hash))
    }

    async fn revoke_refresh_token(
        &self,
        token_id: Uuid,
        revoked_at: OffsetDateTime,
        replaced_by_token_id: Option<Uuid>,
        _reason: RefreshTokenRevocationReason,
    ) -> crate::AuthResult<()> {
        if let Some(token) = self.tokens_by_id.lock().unwrap().get_mut(&token_id) {
            token.revoked_at = Some(revoked_at);
            token.replaced_by_token_id = replaced_by_token_id;
        }
        Ok(())
    }

    async fn revoke_refresh_token_family(
        &self,
        session_family_id: Uuid,
        revoked_at: OffsetDateTime,
        reason: RefreshTokenRevocationReason,
    ) -> crate::AuthResult<()> {
        self.family_revocations.lock().unwrap().push((
            session_family_id,
            revoked_at,
            reason.clone(),
        ));
        for token in self.tokens_by_id.lock().unwrap().values_mut() {
            if token.session_family_id == session_family_id {
                token.revoked_at = Some(revoked_at);
            }
        }
        Ok(())
    }

    async fn touch_refresh_token(
        &self,
        token_id: Uuid,
        used_at: OffsetDateTime,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> crate::AuthResult<()> {
        if let Some(token) = self.tokens_by_id.lock().unwrap().get_mut(&token_id) {
            token.last_used_at = Some(used_at);
            token.ip_address = ip_address;
            token.user_agent = user_agent;
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
pub(super) struct MemoryPasswordResetStore {
    issued: Arc<Mutex<HashSet<Uuid>>>,
    consumed: Arc<Mutex<HashSet<Uuid>>>,
}

#[async_trait]
impl PasswordResetTokenStore for MemoryPasswordResetStore {
    async fn insert_password_reset_token(
        &self,
        token_id: Uuid,
        _user_id: &str,
        _expires_at: OffsetDateTime,
    ) -> crate::AuthResult<()> {
        self.issued.lock().unwrap().insert(token_id);
        Ok(())
    }

    async fn consume_password_reset_token(
        &self,
        token_id: Uuid,
        _consumed_at: OffsetDateTime,
    ) -> crate::AuthResult<bool> {
        if !self.issued.lock().unwrap().contains(&token_id) {
            return Ok(false);
        }
        Ok(self.consumed.lock().unwrap().insert(token_id))
    }
}

#[derive(Clone, Default)]
pub(super) struct MemoryLoginChallengeStore {
    pub(super) challenges: Arc<Mutex<HashMap<Uuid, StoredLoginChallenge>>>,
}

#[async_trait]
impl LoginChallengeStore for MemoryLoginChallengeStore {
    async fn insert_login_challenge(
        &self,
        challenge: StoredLoginChallenge,
    ) -> crate::AuthResult<()> {
        self.challenges
            .lock()
            .unwrap()
            .insert(challenge.id, challenge);
        Ok(())
    }

    async fn find_login_challenge(
        &self,
        challenge_id: Uuid,
    ) -> crate::AuthResult<Option<StoredLoginChallenge>> {
        Ok(self.challenges.lock().unwrap().get(&challenge_id).cloned())
    }

    async fn increment_login_challenge_attempts(
        &self,
        challenge_id: Uuid,
        _attempted_at: OffsetDateTime,
    ) -> crate::AuthResult<u32> {
        let mut challenges = self.challenges.lock().unwrap();
        let Some(challenge) = challenges.get_mut(&challenge_id) else {
            return Err(AuthError::InvalidLoginChallenge);
        };
        challenge.failed_attempts += 1;
        Ok(challenge.failed_attempts)
    }

    async fn consume_login_challenge(
        &self,
        challenge_id: Uuid,
        consumed_at: OffsetDateTime,
    ) -> crate::AuthResult<bool> {
        let mut challenges = self.challenges.lock().unwrap();
        let Some(challenge) = challenges.get_mut(&challenge_id) else {
            return Ok(false);
        };
        if challenge.consumed_at.is_some() {
            return Ok(false);
        }
        challenge.consumed_at = Some(consumed_at);
        Ok(true)
    }
}

pub(super) fn test_auth_service(
    user_store: MemoryUserStore,
    refresh_store: MemoryRefreshTokenStore,
) -> AuthService<MemoryUserStore, MemoryRefreshTokenStore> {
    AuthService::new(
        AuthConfig::new("test-secret"),
        Arc::new(user_store),
        Arc::new(refresh_store),
    )
    .unwrap()
}

pub(super) fn stored_user(
    auth: &AuthService<MemoryUserStore, MemoryRefreshTokenStore>,
    id: &str,
    principal: &str,
    password: &str,
) -> StoredUser {
    StoredUser {
        id: id.to_string(),
        principal: principal.to_string(),
        password_hash: auth.hash_password(password).unwrap(),
        roles: vec!["CatalogEditor".to_string()],
        scopes: vec![
            "users.read".to_string(),
            "collection.collection-1.records.read".to_string(),
        ],
        disabled: false,
    }
}

pub(super) fn metadata() -> ClientMetadata {
    ClientMetadata {
        ip_address: Some("127.0.0.1".to_string()),
        user_agent: Some("test-agent".to_string()),
    }
}
