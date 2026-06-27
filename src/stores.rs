use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    AuthResult, ExternalIdentity, OAuthLoginState, OidcTokenResponse, RefreshTokenRevocationReason,
    StoredLoginChallenge, StoredRefreshToken, StoredUser,
};

#[async_trait]
/// Loads local users for password login, refresh, and verified-session flows.
pub trait UserStore: Send + Sync {
    /// Finds a local user by login principal, such as email or username.
    async fn find_user_by_principal(&self, principal: &str) -> AuthResult<Option<StoredUser>>;

    /// Finds a local user by stable local user ID.
    async fn find_user_by_id(&self, user_id: &str) -> AuthResult<Option<StoredUser>>;
}

#[async_trait]
/// Persists rotated opaque refresh tokens.
///
/// Implementations should store only token hashes and should make revocation
/// operations durable before returning.
pub trait RefreshTokenStore: Send + Sync {
    /// Stores a newly issued refresh token record.
    async fn insert_refresh_token(&self, token: StoredRefreshToken) -> AuthResult<()>;

    /// Finds a refresh token by hash.
    ///
    /// Revoked records should still be returned so replay can be detected.
    async fn find_refresh_token_by_hash(
        &self,
        token_hash: &str,
    ) -> AuthResult<Option<StoredRefreshToken>>;

    /// Revokes a single refresh token.
    async fn revoke_refresh_token(
        &self,
        token_id: Uuid,
        revoked_at: OffsetDateTime,
        replaced_by_token_id: Option<Uuid>,
        reason: RefreshTokenRevocationReason,
    ) -> AuthResult<()>;

    /// Revokes all refresh tokens in a session family.
    async fn revoke_refresh_token_family(
        &self,
        session_family_id: Uuid,
        revoked_at: OffsetDateTime,
        reason: RefreshTokenRevocationReason,
    ) -> AuthResult<()>;

    /// Records metadata for a refresh-token use before rotation.
    async fn touch_refresh_token(
        &self,
        token_id: Uuid,
        used_at: OffsetDateTime,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AuthResult<()>;
}

#[async_trait]
/// Persists one-time password-reset token IDs.
pub trait PasswordResetTokenStore: Send + Sync {
    /// Inserts a password-reset token ID with its expiry.
    async fn insert_password_reset_token(
        &self,
        token_id: Uuid,
        user_id: &str,
        expires_at: OffsetDateTime,
    ) -> AuthResult<()>;

    /// Consumes a password-reset token exactly once.
    ///
    /// Return `true` only for the first successful consume operation.
    async fn consume_password_reset_token(
        &self,
        token_id: Uuid,
        consumed_at: OffsetDateTime,
    ) -> AuthResult<bool>;
}

#[async_trait]
/// Persists one-time login challenges.
pub trait LoginChallengeStore: Send + Sync {
    /// Inserts a newly issued login challenge.
    async fn insert_login_challenge(&self, challenge: StoredLoginChallenge) -> AuthResult<()>;

    /// Finds a login challenge by ID.
    async fn find_login_challenge(
        &self,
        challenge_id: Uuid,
    ) -> AuthResult<Option<StoredLoginChallenge>>;

    /// Increments failed attempts and returns the new attempt count.
    async fn increment_login_challenge_attempts(
        &self,
        challenge_id: Uuid,
        attempted_at: OffsetDateTime,
    ) -> AuthResult<u32>;

    /// Consumes a login challenge exactly once.
    ///
    /// Return `true` only for the first successful consume operation.
    async fn consume_login_challenge(
        &self,
        challenge_id: Uuid,
        consumed_at: OffsetDateTime,
    ) -> AuthResult<bool>;
}

#[async_trait]
/// Persists OIDC authorization state for one-time callback validation.
pub trait OAuthStateStore: Send + Sync {
    /// Inserts an OAuth login state record.
    async fn insert_oauth_state(&self, state: OAuthLoginState) -> AuthResult<()>;

    /// Consumes an OAuth state record exactly once.
    ///
    /// Implementations should match on provider name and hashed state, set
    /// `consumed_at`, and return the record atomically.
    async fn consume_oauth_state(
        &self,
        provider_name: &str,
        state_hash: &str,
        consumed_at: OffsetDateTime,
    ) -> AuthResult<Option<OAuthLoginState>>;

    /// Marks old OAuth state records expired or deletes them.
    async fn expire_oauth_states(
        &self,
        older_than: OffsetDateTime,
        expired_at: OffsetDateTime,
    ) -> AuthResult<u64>;
}

#[async_trait]
/// Stores stable links between external OIDC identities and local users.
pub trait ExternalIdentityStore: Send + Sync {
    /// Finds a linked external identity by provider and stable external subject.
    async fn find_external_identity(
        &self,
        provider_name: &str,
        external_subject: &str,
    ) -> AuthResult<Option<ExternalIdentity>>;

    /// Links an external identity to a local user.
    async fn link_external_identity(&self, identity: ExternalIdentity) -> AuthResult<()>;

    /// Updates the stored claims snapshot for an existing external identity.
    async fn update_external_identity_claims_snapshot(
        &self,
        provider_name: &str,
        external_subject: &str,
        claims_snapshot: serde_json::Value,
        updated_at: OffsetDateTime,
    ) -> AuthResult<()>;
}

#[async_trait]
/// Optional storage for provider tokens.
///
/// This trait is not required for OIDC login. Use it only when the host
/// explicitly wants to retain provider tokens, and encrypt refresh tokens
/// before persistence.
pub trait OAuthTokenStore: Send + Sync {
    /// Stores provider tokens for an already validated external identity.
    async fn store_oauth_tokens(
        &self,
        provider_name: &str,
        external_subject: &str,
        user_id: &str,
        token_response: &OidcTokenResponse,
        stored_at: OffsetDateTime,
    ) -> AuthResult<()>;
}
