use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    AuthResult, ExternalIdentity, OAuthLoginState, OidcTokenResponse, RefreshTokenRevocationReason,
    StoredLoginChallenge, StoredRefreshToken, StoredUser,
};

#[async_trait]
pub trait UserStore: Send + Sync {
    async fn find_user_by_principal(&self, principal: &str) -> AuthResult<Option<StoredUser>>;
    async fn find_user_by_id(&self, user_id: &str) -> AuthResult<Option<StoredUser>>;
}

#[async_trait]
pub trait RefreshTokenStore: Send + Sync {
    async fn insert_refresh_token(&self, token: StoredRefreshToken) -> AuthResult<()>;

    async fn find_refresh_token_by_hash(
        &self,
        token_hash: &str,
    ) -> AuthResult<Option<StoredRefreshToken>>;

    async fn revoke_refresh_token(
        &self,
        token_id: Uuid,
        revoked_at: OffsetDateTime,
        replaced_by_token_id: Option<Uuid>,
        reason: RefreshTokenRevocationReason,
    ) -> AuthResult<()>;

    async fn revoke_refresh_token_family(
        &self,
        session_family_id: Uuid,
        revoked_at: OffsetDateTime,
        reason: RefreshTokenRevocationReason,
    ) -> AuthResult<()>;

    async fn touch_refresh_token(
        &self,
        token_id: Uuid,
        used_at: OffsetDateTime,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AuthResult<()>;
}

#[async_trait]
pub trait PasswordResetTokenStore: Send + Sync {
    async fn insert_password_reset_token(
        &self,
        token_id: Uuid,
        user_id: &str,
        expires_at: OffsetDateTime,
    ) -> AuthResult<()>;

    async fn consume_password_reset_token(
        &self,
        token_id: Uuid,
        consumed_at: OffsetDateTime,
    ) -> AuthResult<bool>;
}

#[async_trait]
pub trait LoginChallengeStore: Send + Sync {
    async fn insert_login_challenge(&self, challenge: StoredLoginChallenge) -> AuthResult<()>;

    async fn find_login_challenge(
        &self,
        challenge_id: Uuid,
    ) -> AuthResult<Option<StoredLoginChallenge>>;

    async fn increment_login_challenge_attempts(
        &self,
        challenge_id: Uuid,
        attempted_at: OffsetDateTime,
    ) -> AuthResult<u32>;

    async fn consume_login_challenge(
        &self,
        challenge_id: Uuid,
        consumed_at: OffsetDateTime,
    ) -> AuthResult<bool>;
}

#[async_trait]
pub trait OAuthStateStore: Send + Sync {
    async fn insert_oauth_state(&self, state: OAuthLoginState) -> AuthResult<()>;

    async fn consume_oauth_state(
        &self,
        provider_name: &str,
        state_hash: &str,
        consumed_at: OffsetDateTime,
    ) -> AuthResult<Option<OAuthLoginState>>;

    async fn expire_oauth_states(
        &self,
        older_than: OffsetDateTime,
        expired_at: OffsetDateTime,
    ) -> AuthResult<u64>;
}

#[async_trait]
pub trait ExternalIdentityStore: Send + Sync {
    async fn find_external_identity(
        &self,
        provider_name: &str,
        external_subject: &str,
    ) -> AuthResult<Option<ExternalIdentity>>;

    async fn link_external_identity(&self, identity: ExternalIdentity) -> AuthResult<()>;

    async fn update_external_identity_claims_snapshot(
        &self,
        provider_name: &str,
        external_subject: &str,
        claims_snapshot: serde_json::Value,
        updated_at: OffsetDateTime,
    ) -> AuthResult<()>;
}

#[async_trait]
pub trait OAuthTokenStore: Send + Sync {
    async fn store_oauth_tokens(
        &self,
        provider_name: &str,
        external_subject: &str,
        user_id: &str,
        token_response: &OidcTokenResponse,
        stored_at: OffsetDateTime,
    ) -> AuthResult<()>;
}
