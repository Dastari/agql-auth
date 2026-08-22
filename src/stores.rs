use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    ApiTokenPrincipalKind, ApiTokenRevocationReason, AuthRateLimitKey, AuthRateLimitSnapshot,
    AuthRateLimitState, AuthResult, AuthUser, ExternalIdentity, OAuthLoginState, OidcTokenResponse,
    RefreshTokenRevocationReason, StoredApiToken, StoredLoginChallenge, StoredRefreshToken,
    StoredUser,
};

#[async_trait]
/// Supplies host-owned authorization roles for refreshable access tokens.
///
/// The returned values are carried in the distinct `authorization_roles`
/// claim. They are not application roles and grant no authority until a
/// resource server expands them through a separately verified catalogue.
pub trait AdditionalTokenRolesProvider: Send + Sync {
    /// Loads the current authorization-role grants for one user session.
    async fn additional_token_roles(&self, user: &AuthUser) -> AuthResult<Vec<String>>;
}

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
/// operations durable before returning. Refresh-token rotation must be atomic:
/// [`AuthService::refresh`](crate::AuthService::refresh) relies on
/// [`RefreshTokenStore::rotate_refresh_token`] to ensure only one concurrent
/// refresh can replace a token.
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

    /// Records metadata for a refresh-token use outside the rotation path.
    ///
    /// [`RefreshTokenStore::rotate_refresh_token`] handles use metadata during
    /// refresh rotation.
    async fn touch_refresh_token(
        &self,
        token_id: Uuid,
        used_at: OffsetDateTime,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AuthResult<()>;

    /// Atomically replaces one refresh token with a new token record.
    ///
    /// Implementations must perform the full operation as one all-or-nothing
    /// store transaction. Return `Ok(true)` only if `current_token_id` existed,
    /// was not revoked, was marked used/revoked for
    /// [`RefreshTokenRevocationReason::Rotation`], had
    /// `replaced_by_token_id = Some(replacement.id)`, and `replacement` was
    /// inserted durably. Return `Ok(false)` when the current token is missing or
    /// already revoked. If the replacement cannot be inserted, return `Err`
    /// and leave the current token unmodified.
    async fn rotate_refresh_token(
        &self,
        current_token_id: Uuid,
        replacement: StoredRefreshToken,
        rotated_at: OffsetDateTime,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AuthResult<bool>;
}

#[async_trait]
/// Persists abuse-protection counters and lockout state.
///
/// Implementations persist [`AuthRateLimitSnapshot`] durably and may delete
/// records after `snapshot.state.expires_at`. Compare-and-swap and conditional
/// clear are the concurrency boundary used by [`crate::AuthService`]; they must
/// be atomic across processes and must never silently fall back to split
/// read/replace behavior.
pub trait AuthRateLimitStore: Send + Sync {
    /// Finds the current versioned state for a flow/bucket key.
    async fn find_auth_rate_limit_state(
        &self,
        key: &AuthRateLimitKey,
    ) -> AuthResult<Option<AuthRateLimitSnapshot>>;

    /// Atomically inserts or replaces one versioned state.
    ///
    /// With `expected_revision = None`, commit only when the key is absent.
    /// With `Some(revision)`, commit only when the stored revision exactly
    /// matches. Return `Ok(true)` only when `replacement` was committed and
    /// `Ok(false)` on a compare conflict without changing storage.
    ///
    /// `replacement.revision` must be persisted with the state. Callers must
    /// provide a fresh revision for every attempt; stores must reject a
    /// replacement whose state key differs from `key`.
    async fn compare_exchange_auth_rate_limit_state(
        &self,
        key: &AuthRateLimitKey,
        expected_revision: Option<Uuid>,
        replacement: AuthRateLimitSnapshot,
    ) -> AuthResult<bool>;

    /// Atomically clears state only when the observed revision is unchanged.
    ///
    /// `None` succeeds only when the key is still absent. `Some(revision)`
    /// deletes only the exact observed version. Return `Ok(false)` on conflict
    /// and leave newer state untouched.
    async fn clear_auth_rate_limit_state(
        &self,
        key: &AuthRateLimitKey,
        expected_revision: Option<Uuid>,
    ) -> AuthResult<bool>;
}

/// In-memory abuse-protection store.
///
/// This is useful for tests, local development, and single-process consumers.
/// Production multi-instance applications should implement
/// [`AuthRateLimitStore`] with durable storage.
#[derive(Clone, Default)]
pub struct MemoryAuthRateLimitStore {
    states: Arc<Mutex<HashMap<AuthRateLimitKey, AuthRateLimitSnapshot>>>,
}

impl MemoryAuthRateLimitStore {
    /// Returns the stored state for tests and diagnostics.
    pub fn get(&self, key: &AuthRateLimitKey) -> Option<AuthRateLimitState> {
        self.states
            .lock()
            .unwrap()
            .get(key)
            .map(|snapshot| snapshot.state.clone())
    }
}

#[async_trait]
impl AuthRateLimitStore for MemoryAuthRateLimitStore {
    async fn find_auth_rate_limit_state(
        &self,
        key: &AuthRateLimitKey,
    ) -> AuthResult<Option<AuthRateLimitSnapshot>> {
        Ok(self.states.lock().unwrap().get(key).cloned())
    }

    async fn compare_exchange_auth_rate_limit_state(
        &self,
        key: &AuthRateLimitKey,
        expected_revision: Option<Uuid>,
        replacement: AuthRateLimitSnapshot,
    ) -> AuthResult<bool> {
        if replacement.state.key != *key {
            return Err(crate::AuthError::Store(
                "rate-limit replacement key does not match compare key".to_string(),
            ));
        }
        let mut states = self.states.lock().unwrap();
        let current_revision = states.get(key).map(|snapshot| snapshot.revision);
        if current_revision != expected_revision {
            return Ok(false);
        }
        states.insert(key.clone(), replacement);
        Ok(true)
    }

    async fn clear_auth_rate_limit_state(
        &self,
        key: &AuthRateLimitKey,
        expected_revision: Option<Uuid>,
    ) -> AuthResult<bool> {
        let mut states = self.states.lock().unwrap();
        if states.get(key).map(|snapshot| snapshot.revision) != expected_revision {
            return Ok(false);
        }
        if expected_revision.is_some() {
            states.remove(key);
        }
        Ok(true)
    }
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
    /// Implementations must atomically find an unconsumed state record by
    /// `(provider_name, state_hash)`, set `consumed_at` in the same operation,
    /// and return the pre-consumption snapshot with `consumed_at == None`.
    /// Return `Ok(None)` when no unconsumed record exists. Do not return the
    /// post-update record with `consumed_at = Some(...)`.
    ///
    /// SQL-style shape:
    ///
    /// ```sql
    /// UPDATE oauth_states
    /// SET consumed_at = ?
    /// WHERE provider_name = ?
    ///   AND state_hash = ?
    ///   AND consumed_at IS NULL
    /// RETURNING provider_name, state_hash, nonce, code_verifier, redirect_uri,
    ///           scopes, created_at, expires_at, NULL AS consumed_at;
    /// ```
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
/// Persists consumed TOTP time steps to prevent code replay.
///
/// Production MFA flows should prefer
/// [`AuthService::verify_totp_code_with_replay_store`](crate::AuthService::verify_totp_code_with_replay_store)
/// over stateless verification. Implementations should atomically insert the
/// `(principal_id, factor_id, step)` tuple and return `Ok(true)` only for the
/// first successful consume operation.
pub trait TotpReplayStore: Send + Sync {
    /// Consumes a valid TOTP time step once for a principal/factor.
    async fn consume_totp_step(
        &self,
        principal_id: &str,
        factor_id: Option<&str>,
        step: i64,
        consumed_at: OffsetDateTime,
    ) -> AuthResult<bool>;
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

#[async_trait]
/// Persists long-lived opaque API/service tokens.
///
/// Implementations should store only token hashes. The raw token is returned
/// once by [`crate::ApiTokenService`] and should not be persisted by hosts.
pub trait ApiTokenStore: Send + Sync {
    /// Stores a newly issued API token record.
    async fn insert_api_token(&self, token: StoredApiToken) -> AuthResult<()>;

    /// Finds an API token by hash.
    ///
    /// Revoked records should still be returned so authentication can report
    /// revocation distinctly from an unknown token.
    async fn find_api_token_by_hash(&self, token_hash: &str) -> AuthResult<Option<StoredApiToken>>;

    /// Records metadata for a successful API-token use.
    async fn touch_api_token(
        &self,
        token_id: Uuid,
        used_at: OffsetDateTime,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AuthResult<()>;

    /// Revokes a single API token.
    async fn revoke_api_token(
        &self,
        token_id: Uuid,
        revoked_at: OffsetDateTime,
        reason: ApiTokenRevocationReason,
    ) -> AuthResult<()>;

    /// Optionally revokes all tokens for a principal.
    async fn revoke_api_tokens_for_principal(
        &self,
        _subject: &str,
        _principal_kind: &ApiTokenPrincipalKind,
        _revoked_at: OffsetDateTime,
        _reason: ApiTokenRevocationReason,
    ) -> AuthResult<u64> {
        Ok(0)
    }

    /// Optionally revokes all tokens bound to a generic resource.
    async fn revoke_api_tokens_for_resource(
        &self,
        _resource_type: &str,
        _resource_id: &str,
        _revoked_at: OffsetDateTime,
        _reason: ApiTokenRevocationReason,
    ) -> AuthResult<u64> {
        Ok(0)
    }
}
