mod challenge;
mod password_reset;
mod totp;

use std::sync::Arc;

use argon2::Argon2;
use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
};
use async_graphql::Data;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use rsa::RsaPublicKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::AuthResult;
use crate::config::{AuthConfig, AuthRateLimitPolicy, ClientMetadata, JwtSigningConfig};
use crate::errors::AuthError;
use crate::models::{
    AuthPayload, AuthRateLimitBucket, AuthRateLimitFlow, AuthRateLimitKey, AuthRateLimitState,
    AuthUser, RefreshTokenRevocationReason, StoredRefreshToken,
};
use crate::session::{AuthMethod, SessionContext};
use crate::stores::{AuthRateLimitStore, MemoryAuthRateLimitStore, RefreshTokenStore, UserStore};
use crate::util::{
    extract_connection_init_token, generate_opaque_token, hash_rate_limit_value,
    hash_refresh_token, map_access_token_decode_error, strip_bearer_prefix,
};

const MIN_HS256_SECRET_BYTES: usize = 32;
const ACCESS_TOKEN_PURPOSE: &str = "access_token";
const DUMMY_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$YWdxbC1hdXRoLWR1bW15LXNsdA$8ClNuSX6M3l/dalOcz8a117s1wLv/AbzbJiKA7dS4Ak";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessTokenClaims {
    sub: String,
    sid: String,
    roles: Vec<String>,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    ctx: SessionContext,
    iss: String,
    aud: String,
    exp: i64,
    iat: i64,
    #[serde(default)]
    purpose: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PasswordResetTokenClaims {
    pub(super) sub: String,
    pub(super) jti: String,
    pub(super) purpose: String,
    pub(super) iss: String,
    pub(super) aud: String,
    pub(super) exp: i64,
    pub(super) iat: i64,
}

/// Main authentication service.
///
/// `AuthService` owns password hashing, local JWT issuance and validation,
/// refresh-token rotation, optional JWKS export, GraphQL request injection,
/// password reset tokens, login challenges, and TOTP helpers. Persistence is
/// supplied by host implementations of [`crate::UserStore`] and
/// [`crate::RefreshTokenStore`].
pub struct AuthService<U, R> {
    pub(super) config: AuthConfig,
    pub(super) user_store: Arc<U>,
    pub(super) refresh_store: Arc<R>,
    pub(super) rate_limit_store: Arc<dyn AuthRateLimitStore>,
    pub(super) argon2: Argon2<'static>,
    pub(super) encoding_key: EncodingKey,
    pub(super) decoding_key: DecodingKey,
    pub(super) validation: Validation,
    signing_algorithm: Algorithm,
    signing_key_id: Option<String>,
    jwks: Option<JsonValue>,
}

impl<U, R> AuthService<U, R>
where
    U: UserStore + 'static,
    R: RefreshTokenStore + 'static,
{
    /// Creates an authentication service and validates local JWT key material.
    ///
    /// RS256 PEM keys are parsed and checked during construction.
    pub fn new(config: AuthConfig, user_store: Arc<U>, refresh_store: Arc<R>) -> AuthResult<Self> {
        Self::new_with_rate_limit_store(
            config,
            user_store,
            refresh_store,
            Arc::new(MemoryAuthRateLimitStore::default()),
        )
    }

    /// Creates an authentication service with a durable abuse-protection store.
    ///
    /// Use this in multi-process or multi-instance applications so throttling
    /// and lockout state survives restarts and is shared by all instances.
    pub fn new_with_rate_limit_store<S>(
        config: AuthConfig,
        user_store: Arc<U>,
        refresh_store: Arc<R>,
        rate_limit_store: Arc<S>,
    ) -> AuthResult<Self>
    where
        S: AuthRateLimitStore + 'static,
    {
        config.rate_limits.validate()?;
        let jwt_keys = JwtKeyMaterial::from_config(&config)?;
        let rate_limit_store: Arc<dyn AuthRateLimitStore> = rate_limit_store;

        Ok(Self {
            encoding_key: jwt_keys.encoding_key,
            decoding_key: jwt_keys.decoding_key,
            validation: jwt_keys.validation,
            signing_algorithm: jwt_keys.algorithm,
            signing_key_id: jwt_keys.key_id,
            jwks: jwt_keys.jwks,
            config,
            user_store,
            refresh_store,
            rate_limit_store,
            argon2: Argon2::default(),
        })
    }

    /// Hashes a password with Argon2.
    pub fn hash_password(&self, password: &str) -> AuthResult<String> {
        let salt = SaltString::generate(&mut OsRng);
        self.argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|err| AuthError::PasswordHashing(err.to_string()))
    }

    /// Verifies a password against an Argon2 password hash.
    pub fn verify_password(&self, password: &str, password_hash: &str) -> AuthResult<()> {
        let parsed_hash = PasswordHash::new(password_hash)
            .map_err(|err| AuthError::PasswordHashing(err.to_string()))?;
        self.argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| AuthError::InvalidCredentials)
    }

    /// Performs password login and issues a local session.
    ///
    /// The returned [`AuthPayload`] contains a short-lived local JWT access
    /// token and an opaque refresh token.
    pub async fn login(
        &self,
        principal: &str,
        password: &str,
        metadata: ClientMetadata,
    ) -> AuthResult<AuthPayload> {
        let rate_limit_keys =
            self.rate_limit_keys(AuthRateLimitFlow::PasswordLogin, Some(principal), &metadata);
        self.reject_if_rate_limited(&self.config.rate_limits.credential, &rate_limit_keys)
            .await?;

        let Some(user) = self.user_store.find_user_by_principal(principal).await? else {
            let _ = self.verify_password(password, DUMMY_PASSWORD_HASH);
            self.record_rate_limit_attempt(&self.config.rate_limits.credential, &rate_limit_keys)
                .await?;
            return Err(AuthError::InvalidCredentials);
        };

        if user.disabled {
            return Err(AuthError::UserDisabled);
        }

        if let Err(err) = self.verify_password(password, &user.password_hash) {
            self.record_rate_limit_attempt(&self.config.rate_limits.credential, &rate_limit_keys)
                .await?;
            return Err(err);
        }
        self.clear_rate_limit_attempts(&self.config.rate_limits.credential, &rate_limit_keys)
            .await?;

        let session_id = Uuid::new_v4();
        let session_family_id = Uuid::new_v4();
        let auth_user = AuthUser {
            user_id: user.id,
            session_id,
            roles: user.roles,
            scopes: user.scopes,
            session: SessionContext::for_auth_method(AuthMethod::Password),
        };

        self.issue_auth_payload(auth_user, session_family_id, metadata)
            .await
    }

    /// Rotates a refresh token and returns a new local session payload.
    ///
    /// Reuse of a revoked refresh token is treated as replay and revokes the
    /// token family through the configured store.
    pub async fn refresh(
        &self,
        refresh_token: &str,
        metadata: ClientMetadata,
    ) -> AuthResult<AuthPayload> {
        let now = OffsetDateTime::now_utc();
        let token_hash = hash_refresh_token(refresh_token);
        let existing = self
            .refresh_store
            .find_refresh_token_by_hash(&token_hash)
            .await?
            .ok_or(AuthError::InvalidRefreshToken)?;

        if existing.is_revoked() {
            self.refresh_store
                .revoke_refresh_token_family(
                    existing.session_family_id,
                    now,
                    RefreshTokenRevocationReason::ReplayDetected,
                )
                .await?;
            return Err(AuthError::RefreshTokenReplayDetected);
        }

        if existing.is_expired(now) {
            self.refresh_store
                .revoke_refresh_token(
                    existing.id,
                    now,
                    None,
                    RefreshTokenRevocationReason::Expired,
                )
                .await?;
            return Err(AuthError::RefreshTokenExpired);
        }

        let user = self
            .user_store
            .find_user_by_id(&existing.user_id)
            .await?
            .ok_or(AuthError::InvalidRefreshToken)?;

        if user.disabled {
            return Err(AuthError::UserDisabled);
        }

        let auth_user = AuthUser {
            user_id: user.id,
            session_id: existing.session_id,
            roles: user.roles,
            scopes: existing.scopes.clone(),
            session: existing.session.clone(),
        };

        let (new_raw_refresh_token, new_record, access_token, access_token_expires_at) = self
            .issue_tokens_only(
                &auth_user,
                existing.session_family_id,
                metadata.clone(),
                now,
            )
            .await?;

        let rotated = self
            .refresh_store
            .rotate_refresh_token(
                existing.id,
                new_record.clone(),
                now,
                metadata.ip_address,
                metadata.user_agent,
            )
            .await?;

        if !rotated {
            self.refresh_store
                .revoke_refresh_token_family(
                    existing.session_family_id,
                    now,
                    RefreshTokenRevocationReason::ReplayDetected,
                )
                .await?;
            return Err(AuthError::RefreshTokenReplayDetected);
        }

        Ok(AuthPayload {
            user: auth_user,
            access_token,
            access_token_expires_at,
            refresh_token: new_raw_refresh_token,
            refresh_token_expires_at: new_record.expires_at,
        })
    }

    /// Revokes a refresh token or its full session family.
    pub async fn logout(&self, refresh_token: &str, revoke_family: bool) -> AuthResult<()> {
        let now = OffsetDateTime::now_utc();
        let token_hash = hash_refresh_token(refresh_token);
        let Some(existing) = self
            .refresh_store
            .find_refresh_token_by_hash(&token_hash)
            .await?
        else {
            return Ok(());
        };

        if revoke_family {
            self.refresh_store
                .revoke_refresh_token_family(
                    existing.session_family_id,
                    now,
                    RefreshTokenRevocationReason::Logout,
                )
                .await
        } else {
            self.refresh_store
                .revoke_refresh_token(existing.id, now, None, RefreshTokenRevocationReason::Logout)
                .await
        }
    }

    /// Validates a local JWT access token and returns the authenticated user.
    pub fn authenticate_access_token(&self, token: &str) -> AuthResult<AuthUser> {
        self.validate_local_jwt_header(token)
            .map_err(|_| AuthError::InvalidAccessToken)?;
        let token_data = decode::<AccessTokenClaims>(token, &self.decoding_key, &self.validation)
            .map_err(map_access_token_decode_error)?;
        let claims = token_data.claims;
        if claims.exp <= OffsetDateTime::now_utc().unix_timestamp() {
            return Err(AuthError::AccessTokenExpired);
        }
        if !matches!(claims.purpose.as_deref(), None | Some(ACCESS_TOKEN_PURPOSE)) {
            return Err(AuthError::InvalidAccessToken);
        }
        let session_id = Uuid::parse_str(&claims.sid).map_err(|_| AuthError::InvalidAccessToken)?;

        Ok(AuthUser {
            user_id: claims.sub,
            session_id,
            roles: claims.roles,
            scopes: claims.scopes,
            session: claims.ctx,
        })
    }

    /// Validates a bearer token with or without the `Bearer ` prefix.
    pub fn authenticate_bearer(&self, bearer_or_token: &str) -> AuthResult<AuthUser> {
        let token = strip_bearer_prefix(bearer_or_token)?;
        self.authenticate_access_token(token)
    }

    /// Returns the public JWKS document for asymmetric signing.
    ///
    /// HS256 configurations return [`AuthError::JwksUnsupported`].
    pub fn jwks(&self) -> AuthResult<JsonValue> {
        self.jwks.clone().ok_or(AuthError::JwksUnsupported)
    }

    /// Issues a local session for a user already verified by the host.
    pub async fn issue_verified_user_session(
        &self,
        user_id: impl Into<String>,
        roles: Vec<String>,
        auth_method: AuthMethod,
        metadata: ClientMetadata,
    ) -> AuthResult<AuthPayload> {
        self.issue_verified_user_session_with_scopes(
            user_id,
            roles,
            Vec::new(),
            auth_method,
            metadata,
        )
        .await
    }

    /// Issues a local session with roles and scopes for a user already verified by the host.
    pub async fn issue_verified_user_session_with_scopes(
        &self,
        user_id: impl Into<String>,
        roles: Vec<String>,
        scopes: Vec<String>,
        auth_method: AuthMethod,
        metadata: ClientMetadata,
    ) -> AuthResult<AuthPayload> {
        self.issue_session_for_user_with_scopes(
            user_id,
            roles,
            scopes,
            SessionContext::for_auth_method(auth_method),
            metadata,
        )
        .await
    }

    /// Issues a local session with an explicit session context.
    pub async fn issue_session_for_user(
        &self,
        user_id: impl Into<String>,
        roles: Vec<String>,
        session: SessionContext,
        metadata: ClientMetadata,
    ) -> AuthResult<AuthPayload> {
        self.issue_session_for_user_with_scopes(user_id, roles, Vec::new(), session, metadata)
            .await
    }

    /// Issues a local session with scopes and an explicit session context.
    pub async fn issue_session_for_user_with_scopes(
        &self,
        user_id: impl Into<String>,
        roles: Vec<String>,
        scopes: Vec<String>,
        session: SessionContext,
        metadata: ClientMetadata,
    ) -> AuthResult<AuthPayload> {
        let auth_user = AuthUser {
            user_id: user_id.into(),
            session_id: Uuid::new_v4(),
            roles,
            scopes,
            session,
        };
        self.issue_auth_payload(auth_user, Uuid::new_v4(), metadata)
            .await
    }

    /// Injects an authenticated user into an `async-graphql` request when a token is present.
    ///
    /// Passing `None` leaves the request unauthenticated.
    pub async fn inject_http_auth(
        &self,
        mut request: async_graphql::Request,
        bearer_or_token: Option<&str>,
    ) -> AuthResult<async_graphql::Request> {
        if let Some(raw) = bearer_or_token {
            let auth_user = self.authenticate_bearer(raw)?;
            request = request.data(auth_user);
        }

        Ok(request)
    }

    /// Authenticates an `async-graphql` WebSocket connection-init payload.
    pub async fn authenticate_connection_init_value(&self, value: JsonValue) -> AuthResult<Data> {
        let token = extract_connection_init_token(&value)?;
        let auth_user = self.authenticate_bearer(&token)?;
        let mut data = Data::default();
        data.insert(auth_user);
        Ok(data)
    }

    async fn issue_auth_payload(
        &self,
        auth_user: AuthUser,
        session_family_id: Uuid,
        metadata: ClientMetadata,
    ) -> AuthResult<AuthPayload> {
        let now = OffsetDateTime::now_utc();
        let (refresh_token, record, access_token, access_token_expires_at) = self
            .issue_tokens_only(&auth_user, session_family_id, metadata, now)
            .await?;

        self.refresh_store
            .insert_refresh_token(record.clone())
            .await?;

        Ok(AuthPayload {
            user: auth_user,
            access_token,
            access_token_expires_at,
            refresh_token,
            refresh_token_expires_at: record.expires_at,
        })
    }

    async fn issue_tokens_only(
        &self,
        auth_user: &AuthUser,
        session_family_id: Uuid,
        metadata: ClientMetadata,
        now: OffsetDateTime,
    ) -> AuthResult<(String, StoredRefreshToken, String, OffsetDateTime)> {
        let access_token_expires_at = now + self.config.access_token_ttl;
        let access_token = self.issue_access_token(auth_user, now, access_token_expires_at)?;

        let raw_refresh_token = generate_opaque_token();
        let refresh_token_expires_at = now + self.config.refresh_token_ttl;
        let refresh_record = StoredRefreshToken {
            id: Uuid::new_v4(),
            user_id: auth_user.user_id.clone(),
            session_id: auth_user.session_id,
            session_family_id,
            scopes: auth_user.scopes.clone(),
            session: auth_user.session.clone(),
            token_hash: hash_refresh_token(&raw_refresh_token),
            created_at: now,
            expires_at: refresh_token_expires_at,
            last_used_at: None,
            revoked_at: None,
            replaced_by_token_id: None,
            user_agent: metadata.user_agent,
            ip_address: metadata.ip_address,
        };

        Ok((
            raw_refresh_token,
            refresh_record,
            access_token,
            access_token_expires_at,
        ))
    }

    fn issue_access_token(
        &self,
        auth_user: &AuthUser,
        issued_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> AuthResult<String> {
        let claims = AccessTokenClaims {
            sub: auth_user.user_id.clone(),
            sid: auth_user.session_id.to_string(),
            roles: auth_user.roles.clone(),
            scopes: auth_user.scopes.clone(),
            ctx: auth_user.session.clone(),
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            exp: expires_at.unix_timestamp(),
            iat: issued_at.unix_timestamp(),
            purpose: Some(ACCESS_TOKEN_PURPOSE.to_string()),
        };

        self.encode_local_jwt(&claims)
    }

    pub(super) fn encode_local_jwt<T>(&self, claims: &T) -> AuthResult<String>
    where
        T: Serialize,
    {
        let mut header = Header::new(self.signing_algorithm);
        header.kid = self.signing_key_id.clone();
        encode(&header, claims, &self.encoding_key)
            .map_err(|err| AuthError::TokenCreation(err.to_string()))
    }

    pub(super) fn validate_local_jwt_header(&self, token: &str) -> AuthResult<()> {
        let header = decode_header(token).map_err(|_| AuthError::InvalidAccessToken)?;
        if header.alg != self.signing_algorithm {
            return Err(AuthError::InvalidAccessToken);
        }

        if let Some(expected_kid) = &self.signing_key_id {
            match header.kid.as_deref() {
                Some(actual_kid) if actual_kid == expected_kid => {}
                _ => return Err(AuthError::InvalidAccessToken),
            }
        }

        Ok(())
    }

    /// Records a password-reset request and returns whether the host should
    /// process it.
    ///
    /// `Ok(false)` means the request was throttled or locked and the host
    /// should preserve silent-success semantics without sending email.
    pub async fn should_process_password_reset_request(
        &self,
        principal: &str,
        metadata: ClientMetadata,
    ) -> AuthResult<bool> {
        self.record_request_rate_limit(AuthRateLimitFlow::PasswordResetRequest, principal, metadata)
            .await
    }

    /// Records a login-code request and returns whether the host should process it.
    ///
    /// `Ok(false)` means the request was throttled or locked and the host
    /// should preserve silent-success semantics without sending email.
    pub async fn should_process_login_code_request(
        &self,
        principal: &str,
        metadata: ClientMetadata,
    ) -> AuthResult<bool> {
        self.record_request_rate_limit(AuthRateLimitFlow::LoginCodeRequest, principal, metadata)
            .await
    }

    async fn record_request_rate_limit(
        &self,
        flow: AuthRateLimitFlow,
        principal: &str,
        metadata: ClientMetadata,
    ) -> AuthResult<bool> {
        let rate_limit_keys = self.rate_limit_keys(flow, Some(principal), &metadata);
        match self
            .reject_if_rate_limited(&self.config.rate_limits.request, &rate_limit_keys)
            .await
        {
            Ok(()) => {}
            Err(AuthError::AuthThrottled { .. } | AuthError::AuthLocked { .. }) => {
                return Ok(false);
            }
            Err(err) => return Err(err),
        }

        self.record_rate_limit_attempt(&self.config.rate_limits.request, &rate_limit_keys)
            .await?;
        Ok(true)
    }

    pub(super) fn rate_limit_keys(
        &self,
        flow: AuthRateLimitFlow,
        principal: Option<&str>,
        metadata: &ClientMetadata,
    ) -> Vec<AuthRateLimitKey> {
        let mut keys = Vec::with_capacity(2);
        if let Some(principal) = principal.and_then(normalize_principal_bucket) {
            keys.push(rate_limit_key(
                flow.clone(),
                AuthRateLimitBucket::Principal,
                &principal,
            ));
        }
        if let Some(client) = metadata
            .ip_address
            .as_deref()
            .and_then(normalize_client_bucket)
        {
            keys.push(rate_limit_key(flow, AuthRateLimitBucket::Client, &client));
        }
        keys
    }

    pub(super) async fn reject_if_rate_limited(
        &self,
        policy: &AuthRateLimitPolicy,
        keys: &[AuthRateLimitKey],
    ) -> AuthResult<()> {
        if !policy.enabled || keys.is_empty() {
            return Ok(());
        }

        let now = OffsetDateTime::now_utc();
        let mut locked_until = None;
        let mut backoff_until = None;

        for key in keys {
            let Some(state) = self
                .rate_limit_store
                .find_auth_rate_limit_state(key)
                .await?
            else {
                continue;
            };

            if state.expires_at <= now {
                self.rate_limit_store
                    .clear_auth_rate_limit_state(key)
                    .await?;
                continue;
            }

            if let Some(until) = state.locked_until.filter(|until| *until > now) {
                locked_until = Some(max_time(locked_until, until));
            } else if let Some(until) = state.backoff_until.filter(|until| *until > now) {
                backoff_until = Some(max_time(backoff_until, until));
            }
        }

        if let Some(until) = locked_until {
            return Err(AuthError::AuthLocked {
                retry_after_seconds: retry_after_seconds(now, until),
            });
        }
        if let Some(until) = backoff_until {
            return Err(AuthError::AuthThrottled {
                retry_after_seconds: retry_after_seconds(now, until),
            });
        }

        Ok(())
    }

    pub(super) async fn record_rate_limit_attempt(
        &self,
        policy: &AuthRateLimitPolicy,
        keys: &[AuthRateLimitKey],
    ) -> AuthResult<()> {
        if !policy.enabled || keys.is_empty() {
            return Ok(());
        }

        let now = OffsetDateTime::now_utc();
        for key in keys {
            let current = self
                .rate_limit_store
                .find_auth_rate_limit_state(key)
                .await?;
            let next = next_rate_limit_state(key.clone(), current, policy, now);
            self.rate_limit_store
                .save_auth_rate_limit_state(next)
                .await?;
        }

        Ok(())
    }

    pub(super) async fn clear_rate_limit_attempts(
        &self,
        policy: &AuthRateLimitPolicy,
        keys: &[AuthRateLimitKey],
    ) -> AuthResult<()> {
        if !policy.enabled || keys.is_empty() {
            return Ok(());
        }

        for key in keys {
            self.rate_limit_store
                .clear_auth_rate_limit_state(key)
                .await?;
        }

        Ok(())
    }
}

fn normalize_principal_bucket(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    (!normalized.is_empty()).then_some(normalized)
}

fn normalize_client_bucket(value: &str) -> Option<String> {
    let normalized = value.trim().to_string();
    (!normalized.is_empty()).then_some(normalized)
}

fn rate_limit_key(
    flow: AuthRateLimitFlow,
    bucket: AuthRateLimitBucket,
    normalized_value: &str,
) -> AuthRateLimitKey {
    AuthRateLimitKey {
        value_hash: hash_rate_limit_value(&format!(
            "{}:{}:{}",
            flow.as_str(),
            bucket.as_str(),
            normalized_value
        )),
        flow,
        bucket,
    }
}

fn next_rate_limit_state(
    key: AuthRateLimitKey,
    current: Option<AuthRateLimitState>,
    policy: &AuthRateLimitPolicy,
    now: OffsetDateTime,
) -> AuthRateLimitState {
    let reset_window = current.as_ref().is_none_or(|state| {
        state.expires_at <= now || state.first_attempt_at + policy.window <= now
    });
    let (attempts, first_attempt_at) = if reset_window {
        (1, now)
    } else {
        let state = current.as_ref().expect("checked above");
        (state.attempts.saturating_add(1), state.first_attempt_at)
    };

    let (backoff_until, locked_until) = if attempts >= policy.max_attempts_before_lockout {
        (None, Some(now + policy.lockout_duration))
    } else if attempts >= policy.backoff_after_attempts {
        (Some(now + backoff_duration(policy, attempts)), None)
    } else {
        (None, None)
    };

    let mut expires_at = now + policy.state_ttl;
    expires_at = max_time(Some(expires_at), first_attempt_at + policy.window);
    if let Some(until) = backoff_until {
        expires_at = max_time(Some(expires_at), until);
    }
    if let Some(until) = locked_until {
        expires_at = max_time(Some(expires_at), until);
    }

    AuthRateLimitState {
        key,
        attempts,
        first_attempt_at,
        last_attempt_at: now,
        backoff_until,
        locked_until,
        expires_at,
    }
}

fn backoff_duration(policy: &AuthRateLimitPolicy, attempts: u32) -> Duration {
    if policy.base_backoff == Duration::ZERO {
        return Duration::ZERO;
    }

    let exponent = attempts.saturating_sub(policy.backoff_after_attempts);
    let mut multiplier = 1_i32;
    for _ in 0..exponent.min(30) {
        multiplier = multiplier.saturating_mul(2);
        let Some(candidate) = policy.base_backoff.checked_mul(multiplier) else {
            return policy.max_backoff;
        };
        if candidate >= policy.max_backoff {
            return policy.max_backoff;
        }
    }

    policy
        .base_backoff
        .checked_mul(multiplier)
        .unwrap_or(policy.max_backoff)
        .min(policy.max_backoff)
}

fn max_time(current: Option<OffsetDateTime>, candidate: OffsetDateTime) -> OffsetDateTime {
    match current {
        Some(current) if current >= candidate => current,
        _ => candidate,
    }
}

fn retry_after_seconds(now: OffsetDateTime, until: OffsetDateTime) -> i64 {
    (until - now).whole_seconds().max(1)
}

struct JwtKeyMaterial {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    validation: Validation,
    algorithm: Algorithm,
    key_id: Option<String>,
    jwks: Option<JsonValue>,
}

impl JwtKeyMaterial {
    fn from_config(config: &AuthConfig) -> AuthResult<Self> {
        let signing = effective_signing_config(config);
        let algorithm = signing.algorithm();
        let (encoding_key, decoding_key, key_id, jwks) = match signing {
            EffectiveJwtSigningConfig::Hs256 { secret } => {
                if secret.len() < MIN_HS256_SECRET_BYTES {
                    return Err(AuthError::InvalidConfiguration(
                        "HS256 secret must be at least 32 bytes".to_string(),
                    ));
                }

                (
                    EncodingKey::from_secret(secret.as_bytes()),
                    DecodingKey::from_secret(secret.as_bytes()),
                    None,
                    None,
                )
            }
            EffectiveJwtSigningConfig::Rs256 {
                private_key_pem,
                public_key_pem,
                key_id,
            } => {
                if key_id.trim().is_empty() {
                    return Err(AuthError::InvalidConfiguration(
                        "RS256 key_id must not be empty".to_string(),
                    ));
                }

                let encoding_key =
                    EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).map_err(|_| {
                        AuthError::InvalidConfiguration("invalid RS256 private key PEM".to_string())
                    })?;
                let decoding_key =
                    DecodingKey::from_rsa_pem(public_key_pem.as_bytes()).map_err(|_| {
                        AuthError::InvalidConfiguration("invalid RS256 public key PEM".to_string())
                    })?;
                validate_rs256_key_pair(&encoding_key, &decoding_key)?;
                let jwks = build_rs256_jwks(public_key_pem, key_id)?;

                (
                    encoding_key,
                    decoding_key,
                    Some(key_id.to_string()),
                    Some(jwks),
                )
            }
        };

        let mut validation = Validation::new(algorithm);
        validation.set_issuer(std::slice::from_ref(&config.issuer));
        validation.set_audience(std::slice::from_ref(&config.audience));
        validation.required_spec_claims.extend(
            ["exp", "iat", "iss", "aud", "sub"]
                .into_iter()
                .map(str::to_string),
        );

        Ok(Self {
            encoding_key,
            decoding_key,
            validation,
            algorithm,
            key_id,
            jwks,
        })
    }
}

enum EffectiveJwtSigningConfig<'a> {
    Hs256 {
        secret: &'a str,
    },
    Rs256 {
        private_key_pem: &'a str,
        public_key_pem: &'a str,
        key_id: &'a str,
    },
}

impl EffectiveJwtSigningConfig<'_> {
    fn algorithm(&self) -> Algorithm {
        match self {
            Self::Hs256 { .. } => Algorithm::HS256,
            Self::Rs256 { .. } => Algorithm::RS256,
        }
    }
}

fn effective_signing_config(config: &AuthConfig) -> EffectiveJwtSigningConfig<'_> {
    match &config.jwt_signing {
        JwtSigningConfig::Hs256 { secret } => EffectiveJwtSigningConfig::Hs256 { secret },
        JwtSigningConfig::Rs256 {
            private_key_pem,
            public_key_pem,
            key_id,
        } => EffectiveJwtSigningConfig::Rs256 {
            private_key_pem,
            public_key_pem,
            key_id,
        },
    }
}

fn validate_rs256_key_pair(
    encoding_key: &EncodingKey,
    decoding_key: &DecodingKey,
) -> AuthResult<()> {
    let probe = json!({
        "sub": "agql-auth-key-validation",
        "exp": OffsetDateTime::now_utc().unix_timestamp() + 60,
    });
    let token = encode(&Header::new(Algorithm::RS256), &probe, encoding_key).map_err(|_| {
        AuthError::InvalidConfiguration("invalid RS256 private key PEM".to_string())
    })?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_aud = false;
    decode::<JsonValue>(&token, decoding_key, &validation).map_err(|_| {
        AuthError::InvalidConfiguration(
            "RS256 private and public keys do not form a valid key pair".to_string(),
        )
    })?;
    Ok(())
}

fn build_rs256_jwks(public_key_pem: &str, key_id: &str) -> AuthResult<JsonValue> {
    let public_key = parse_rsa_public_key(public_key_pem)?;
    Ok(json!({
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": key_id,
                "n": URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
                "e": URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
            }
        ]
    }))
}

fn parse_rsa_public_key(public_key_pem: &str) -> AuthResult<RsaPublicKey> {
    RsaPublicKey::from_public_key_pem(public_key_pem)
        .or_else(|_| RsaPublicKey::from_pkcs1_pem(public_key_pem))
        .map_err(|_| AuthError::InvalidConfiguration("invalid RS256 public key PEM".to_string()))
}
