use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    ApiTokenPrincipalKind, ApiTokenRevocationReason, AuthRateLimitKey, AuthRateLimitSnapshot,
    AuthResult, AuthUser, ExternalIdentity, OAuthLoginState, OidcTokenResponse,
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
/// Loads local users for password login, refresh, and host-owned identity reads.
/// Trusted-host `issue_verified_user_session*` / `issue_session_for_user*` calls
/// do not automatically consult this store; their caller must establish current
/// identity/enabled state and grants before issuance.
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
/// operations durable before returning. A session family has at most one
/// unrevoked token, and only [`Self::rotate_refresh_token`] moves it to a new
/// record. Every implementation must keep these rules under concurrency, with
/// or without refresh reuse grace:
///
/// - [`Self::rotate_refresh_token`] is a compare-and-swap. Update the current
///   record first, `... WHERE id = ? AND revoked_at IS NULL`, and insert the
///   replacement in the same transaction only when exactly one row changed.
///   Two rotations of one token must not both succeed.
/// - [`Self::revoke_refresh_token`] leaves an already revoked record unchanged,
///   checked in the same statement.
/// - [`Self::revoke_refresh_token_family`] must not miss a replacement that a
///   rotation commits while it runs, or that token stays live after sign-out
///   or replay detection. At `READ COMMITTED` in PostgreSQL, SQL Server and
///   MySQL a single `UPDATE ... WHERE session_family_id = ? AND revoked_at IS
///   NULL` can miss one. Serialize the two per family, for example with a
///   transaction-scoped lock taken in its own statement.
///
/// A unique index on `session_family_id` over unrevoked rows turns a broken
/// rotation into an error instead of a second live token. See
/// `docs/storage-traits.md` for the SQL shape and per-backend notes, and
/// `testdata/consumer_refresh_token_store.py` for an example that passes the
/// crate's conformance races.
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
    ///
    /// Leave an already revoked record unchanged, checked in the same atomic
    /// statement, for example `UPDATE ... WHERE id = ? AND revoked_at IS NULL`.
    /// Otherwise a sign-out that read the token before a concurrent rotation
    /// overwrites that rotation's `revoked_at` and `replaced_by_token_id`. The
    /// service then cannot see that the token was rotated, and the replacement
    /// outlives the sign-out.
    async fn revoke_refresh_token(
        &self,
        token_id: Uuid,
        revoked_at: OffsetDateTime,
        replaced_by_token_id: Option<Uuid>,
        reason: RefreshTokenRevocationReason,
    ) -> AuthResult<()>;

    /// Revokes all refresh tokens in a session family.
    ///
    /// Must not miss a replacement committed by a concurrent
    /// [`Self::rotate_refresh_token`]; see the trait documentation.
    async fn revoke_refresh_token_family(
        &self,
        session_family_id: Uuid,
        revoked_at: OffsetDateTime,
        reason: RefreshTokenRevocationReason,
    ) -> AuthResult<()>;

    /// Revokes every unrevoked refresh token of a user, in all session
    /// families, and returns how many were revoked.
    ///
    /// [`AuthService::revoke_user_sessions`](crate::AuthService::revoke_user_sessions)
    /// calls this when a host disables a user, changes or resets a password,
    /// or ends every session. Leave already revoked records unchanged.
    ///
    /// Like family revocation, it must not miss a replacement that a
    /// concurrent [`Self::rotate_refresh_token`] commits while it runs. At
    /// `READ COMMITTED` either serialize it with rotation, for example with a
    /// per-user lock that rotation also takes, or repeat the update in the same
    /// transaction until a fresh statement finds no unrevoked token of the
    /// user. SQLite's `BEGIN IMMEDIATE` serializes writers on its own.
    ///
    /// This method has no default: a store that cannot do it must not appear
    /// to succeed. Index `user_id` to keep it efficient.
    async fn revoke_refresh_tokens_for_user(
        &self,
        user_id: &str,
        revoked_at: OffsetDateTime,
        reason: RefreshTokenRevocationReason,
    ) -> AuthResult<u64>;

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
    ///
    /// Decide the outcome from the row count of the conditional update, not
    /// from an earlier read: a read without a lock can see a token that a
    /// concurrent family revocation is revoking.
    async fn rotate_refresh_token(
        &self,
        current_token_id: Uuid,
        replacement: StoredRefreshToken,
        rotated_at: OffsetDateTime,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AuthResult<bool>;

    /// Optional support for [`AuthService::with_refresh_reuse_grace`](crate::AuthService::with_refresh_reuse_grace):
    /// reads every unrevoked token in a session family.
    ///
    /// The default returns `Ok(None)`, meaning not supported, and reuse stays
    /// replay. An override must:
    ///
    /// - Return `Ok(Some(tokens))`, with an empty list for a family with no
    ///   unrevoked token. Include unrevoked tokens past their expiry.
    /// - Read committed state in one consistent snapshot, so a concurrent
    ///   [`Self::rotate_refresh_token`] appears either wholly applied or not at
    ///   all. One plain `SELECT` does this at `READ COMMITTED`. Do not lock the
    ///   rows it returns.
    ///
    /// The concurrency rules in the trait documentation apply to every store.
    /// The grace window is measured from `revoked_at` and
    /// `replaced_by_token_id`, so overriding this also relies on these:
    ///
    /// - `replaced_by_token_id` is set only by rotation.
    /// - Nothing changes `revoked_at` or `replaced_by_token_id` on an already
    ///   revoked token while its family has an unrevoked token.
    ///
    /// See `docs/refresh-reuse-grace.md`.
    async fn find_live_refresh_tokens_in_family(
        &self,
        _session_family_id: Uuid,
    ) -> AuthResult<Option<Vec<StoredRefreshToken>>> {
        Ok(None)
    }
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
    /// `Ok(false)` on a compare conflict without committing the replacement or
    /// altering unexpired state. Expired records may be reclaimed atomically
    /// as part of any operation, including a compare conflict.
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

pub use crate::memory_rate_limit::MemoryAuthRateLimitStore;

#[async_trait]
/// Persists one-time password-reset token IDs.
///
/// Every reset token the crate issues has a record here; a token without one
/// can never be consumed.
pub trait PasswordResetTokenStore: Send + Sync {
    /// Inserts a password-reset token ID with its owning user and expiry.
    ///
    /// Persist `user_id` with the record; sibling invalidation selects by it.
    async fn insert_password_reset_token(
        &self,
        token_id: Uuid,
        user_id: &str,
        expires_at: OffsetDateTime,
    ) -> AuthResult<()>;

    /// Consumes a password-reset token exactly once.
    ///
    /// Must atomically require an existing record that is neither consumed nor
    /// invalidated, then mark it consumed. Return `true` only for the first
    /// successful consume operation, and `false` for a missing, consumed or
    /// invalidated record, for example:
    ///
    /// ```sql
    /// UPDATE password_reset_tokens SET consumed_at = ?
    /// WHERE id = ? AND consumed_at IS NULL AND invalidated_at IS NULL;
    /// -- true exactly when one row changed
    /// ```
    async fn consume_password_reset_token(
        &self,
        token_id: Uuid,
        consumed_at: OffsetDateTime,
    ) -> AuthResult<bool>;

    /// Invalidates every unconsumed reset token of `user_id`, except
    /// `keep_token_id` when given, and returns how many it changed.
    ///
    /// Called after issuing a new token (keeping that one) and after a token is
    /// consumed (keeping none). Afterwards
    /// [`Self::consume_password_reset_token`] must return `false` for every
    /// invalidated token. Return `Err` if this cannot be done; never succeed
    /// without invalidating. One statement is enough:
    ///
    /// ```sql
    /// UPDATE password_reset_tokens SET invalidated_at = ?
    /// WHERE user_id = ? AND (? IS NULL OR id <> ?) AND consumed_at IS NULL
    ///   AND invalidated_at IS NULL;
    /// ```
    async fn invalidate_password_reset_tokens_for_user(
        &self,
        user_id: &str,
        keep_token_id: Option<Uuid>,
        invalidated_at: OffsetDateTime,
    ) -> AuthResult<u64>;
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

    /// Atomically admits one verification attempt and returns its snapshot.
    ///
    /// In one transaction, reject a missing, consumed, expired (expiry <=
    /// `attempted_at`), or exhausted challenge with the corresponding AuthError;
    /// otherwise increment `attempts` and return the resulting record. At most
    /// `max_attempts` calls may succeed for a challenge, including under concurrent
    /// requests. There is no safe read-then-write fallback. Do not hold storage
    /// locks while the caller performs password verification.
    ///
    /// A committed admission remains charged if the caller cancels or fails.
    /// All challenge fields except `attempts` and `consumed_at` are immutable.
    /// IDs must never be reused, and insert must reject an existing ID.
    async fn reserve_login_challenge_attempt(
        &self,
        challenge_id: Uuid,
        attempted_at: OffsetDateTime,
    ) -> AuthResult<StoredLoginChallenge>;

    /// Consumes a login challenge exactly once.
    ///
    /// Atomically require an existing, unconsumed challenge with at least one
    /// admitted attempt and expiry > `consumed_at`, then mark it consumed. A
    /// correctly verified final admitted attempt may consume at attempts ==
    /// max_attempts. Return `false` without changing state on rejection. Never
    /// recreate an absent challenge. Hosts may additionally check the database
    /// clock inside this transaction; use the same trusted time basis.
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
    ///
    /// Persist every field and return it unchanged, including
    /// `browser_binding_hash` and `response_mode`. A record reloaded without
    /// its browser-binding hash is refused at the callback.
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
    ///           scopes, authorization_policy, response_mode, created_at,
    ///           expires_at, NULL AS consumed_at;
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
/// over stateless verification.
pub trait TotpReplayStore: Send + Sync {
    /// Consumes a valid TOTP time step once for a principal/factor.
    ///
    /// Must insert the `(principal_id, factor_id, step)` tuple in one atomic
    /// operation backed by a uniqueness constraint, and return `Ok(true)` only
    /// when this call inserted it. Concurrent calls for the same tuple, from
    /// any process, must see exactly one `Ok(true)`. A read followed by a
    /// separate insert is not atomic. Treat `factor_id = None` as one value
    /// (for example store `''`), because SQL `NULL`s do not collide in a
    /// unique index:
    ///
    /// ```sql
    /// INSERT INTO totp_steps (principal_id, factor_id, step, consumed_at)
    /// VALUES (?, COALESCE(?, ''), ?, ?)
    /// ON CONFLICT (principal_id, factor_id, step) DO NOTHING;
    /// -- Ok(true) exactly when one row was inserted
    /// ```
    ///
    /// Return `Err` when the outcome is unknown; never `Ok(true)`.
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
    ///
    /// Must be atomic on `(provider_name, external_subject)`: a unique
    /// constraint makes a concurrent second link for the same pair fail with
    /// `Err`, and an existing link must never be silently re-pointed to
    /// another user. Check-then-insert without the constraint is not enough:
    ///
    /// ```sql
    /// -- UNIQUE (provider_name, external_subject)
    /// INSERT INTO external_identities (provider_name, external_subject, user_id, ...)
    /// VALUES (?, ?, ?, ...);
    /// -- a unique violation is returned as Err
    /// ```
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
/// Persist `audience`, `resource_type` and `resource_id` exactly: the service
/// refuses tokens whose binding does not match its configuration.
pub trait ApiTokenStore: Send + Sync {
    /// Stores a newly issued API token record.
    async fn insert_api_token(&self, token: StoredApiToken) -> AuthResult<()>;

    /// Finds an API token by hash.
    ///
    /// Revoked records should still be returned so authentication can report
    /// revocation distinctly from an unknown token.
    async fn find_api_token_by_hash(&self, token_hash: &str) -> AuthResult<Option<StoredApiToken>>;

    /// Records metadata for a successful API-token use.
    ///
    /// Best effort: an error here does not fail authentication and is passed
    /// to the service's [`crate::ApiTokenTouchObserver`], if any.
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

    /// Optional bulk revocation of every active token of one principal.
    ///
    /// The default returns [`AuthError::InvalidConfiguration`](crate::AuthError::InvalidConfiguration)
    /// and changes nothing, so an adapter without it can never report a
    /// revocation that did not happen. An override must revoke every matching
    /// unrevoked token durably before returning `Ok(count)`; `Ok(0)` then means
    /// no active token matched. It does not revoke user sessions/JWTs or
    /// invalidate already accepted principals; those require their own
    /// authoritative status/revalidation boundary.
    async fn revoke_api_tokens_for_principal(
        &self,
        _subject: &str,
        _principal_kind: &ApiTokenPrincipalKind,
        _revoked_at: OffsetDateTime,
        _reason: ApiTokenRevocationReason,
    ) -> AuthResult<u64> {
        Err(crate::AuthError::InvalidConfiguration(
            "api token store does not support bulk revocation by principal".to_string(),
        ))
    }

    /// Optional bulk revocation of every active token bound to one resource.
    ///
    /// Shares the default-error and override contract of
    /// [`Self::revoke_api_tokens_for_principal`]. The host authorizes the exact
    /// resource.
    async fn revoke_api_tokens_for_resource(
        &self,
        _resource_type: &str,
        _resource_id: &str,
        _revoked_at: OffsetDateTime,
        _reason: ApiTokenRevocationReason,
    ) -> AuthResult<u64> {
        Err(crate::AuthError::InvalidConfiguration(
            "api token store does not support bulk revocation by resource".to_string(),
        ))
    }
}

#[async_trait]
/// Records consumed purpose-token ids so a purpose token succeeds at most once.
///
/// Used by
/// [`AuthService::consume_purpose_token`](crate::AuthService::consume_purpose_token).
/// Implementations must insert `token_id` atomically (for example a unique-key
/// insert) and return `Ok(true)` only for the first call with that id, and
/// `Ok(false)` for every later call. Records must be kept at least until
/// `expires_at`; they may be deleted afterwards because the token no longer
/// validates. Return an error, never `Ok(true)`, when the outcome is unknown.
pub trait PurposeTokenReplayStore: Send + Sync {
    /// Atomically marks a purpose-token id as consumed.
    async fn consume_purpose_token(
        &self,
        token_id: Uuid,
        expires_at: OffsetDateTime,
    ) -> AuthResult<bool>;
}
