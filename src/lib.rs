//! Database-agnostic authentication primitives and `async-graphql` helpers.
//!
//! The crate is designed around a few principles:
//!
//! - short-lived JWT access tokens
//! - rotated opaque refresh tokens
//! - database-agnostic storage via traits
//! - thin integration points for `async-graphql` HTTP requests and subscriptions
//! - minimal assumptions about the consuming application's ORM or transport setup

use std::sync::Arc;

use argon2::Argon2;
use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
};
use async_graphql::{Context, Data, ErrorExtensions, Guard, Result as GraphqlResult};
use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use jsonwebtoken::errors::ErrorKind as JwtErrorKind;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

type HmacSha1 = Hmac<Sha1>;

pub type AuthResult<T> = Result<T, AuthError>;

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub issuer: String,
    pub audience: String,
    pub jwt_secret: String,
    pub access_token_ttl: Duration,
    pub refresh_token_ttl: Duration,
}

impl AuthConfig {
    pub fn new(jwt_secret: impl Into<String>) -> Self {
        Self {
            issuer: "agql-auth".to_string(),
            audience: "agql-auth-clients".to_string(),
            jwt_secret: jwt_secret.into(),
            access_token_ttl: Duration::minutes(15),
            refresh_token_ttl: Duration::days(30),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientMetadata {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthMethod {
    Password,
    EmailCode,
    SmsCode,
    TotpStepUp,
    ServiceToken,
}

impl Default for AuthMethod {
    fn default() -> Self {
        Self::Password
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MfaState {
    pub satisfied: bool,
    pub methods: Vec<MfaMethod>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MfaMethod {
    Totp,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveScope {
    pub tenant_id: Option<String>,
    pub organization_id: Option<String>,
    pub catalog_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionContext {
    #[serde(default)]
    pub auth_method: AuthMethod,
    #[serde(default)]
    pub mfa: MfaState,
    #[serde(default)]
    pub active_scope: Option<ActiveScope>,
}

impl SessionContext {
    pub fn for_auth_method(auth_method: AuthMethod) -> Self {
        Self {
            auth_method,
            mfa: MfaState::default(),
            active_scope: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthUser {
    pub user_id: String,
    pub session_id: Uuid,
    pub roles: Vec<String>,
    #[serde(default)]
    pub session: SessionContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredUser {
    pub id: String,
    pub principal: String,
    pub password_hash: String,
    pub roles: Vec<String>,
    pub disabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RefreshTokenRevocationReason {
    Logout,
    Rotation,
    ReplayDetected,
    AdminRevoked,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRefreshToken {
    pub id: Uuid,
    pub user_id: String,
    pub session_id: Uuid,
    pub session_family_id: Uuid,
    #[serde(default)]
    pub session: SessionContext,
    pub token_hash: String,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
    pub replaced_by_token_id: Option<Uuid>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
}

impl StoredRefreshToken {
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        self.expires_at <= now
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthPayload {
    pub user: AuthUser,
    pub access_token: String,
    pub access_token_expires_at: OffsetDateTime,
    pub refresh_token: String,
    pub refresh_token_expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessTokenClaims {
    sub: String,
    sid: String,
    roles: Vec<String>,
    #[serde(default)]
    ctx: SessionContext,
    iss: String,
    aud: String,
    exp: i64,
    iat: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PasswordResetTokenClaims {
    sub: String,
    jti: String,
    purpose: String,
    iss: String,
    aud: String,
    exp: i64,
    iat: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordResetToken {
    pub user_id: String,
    pub token_id: Uuid,
    pub token: String,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedPasswordResetToken {
    pub user_id: String,
    pub token_id: Uuid,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredLoginChallenge {
    pub id: Uuid,
    pub principal: String,
    pub code_hash: String,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub failed_attempts: u32,
    pub max_attempts: u32,
    pub consumed_at: Option<OffsetDateTime>,
    pub channel: Option<String>,
}

impl StoredLoginChallenge {
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        self.expires_at <= now
    }

    pub fn is_consumed(&self) -> bool {
        self.consumed_at.is_some()
    }

    pub fn attempts_exhausted(&self) -> bool {
        self.failed_attempts >= self.max_attempts
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginChallengeOptions {
    pub code_length: usize,
    pub ttl: Duration,
    pub max_attempts: u32,
    pub channel: Option<String>,
}

impl Default for LoginChallengeOptions {
    fn default() -> Self {
        Self {
            code_length: 6,
            ttl: Duration::minutes(10),
            max_attempts: 5,
            channel: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssuedLoginChallenge {
    pub challenge_id: Uuid,
    pub principal: String,
    pub code: String,
    pub expires_at: OffsetDateTime,
    pub max_attempts: u32,
    pub channel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedLoginChallenge {
    pub challenge_id: Uuid,
    pub principal: String,
    pub verified_at: OffsetDateTime,
    pub channel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpSecret {
    pub raw_secret: Vec<u8>,
    pub base32_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpProvisioning {
    pub issuer: String,
    pub account_name: String,
    pub secret: String,
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpOptions {
    pub digits: u32,
    pub period_seconds: u64,
    pub allowed_skew: u64,
}

impl Default for TotpOptions {
    fn default() -> Self {
        Self {
            digits: 6,
            period_seconds: 30,
            allowed_skew: 1,
        }
    }
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("unauthenticated")]
    Unauthenticated,
    #[error("forbidden")]
    Forbidden,
    #[error("invalid bearer token")]
    InvalidBearerToken,
    #[error("invalid access token")]
    InvalidAccessToken,
    #[error("access token expired")]
    AccessTokenExpired,
    #[error("invalid refresh token")]
    InvalidRefreshToken,
    #[error("refresh token expired")]
    RefreshTokenExpired,
    #[error("refresh token replay detected")]
    RefreshTokenReplayDetected,
    #[error("user is disabled")]
    UserDisabled,
    #[error("invalid password reset token")]
    InvalidPasswordResetToken,
    #[error("password reset token expired")]
    PasswordResetTokenExpired,
    #[error("password reset token replay detected")]
    PasswordResetTokenReplayed,
    #[error("invalid login challenge")]
    InvalidLoginChallenge,
    #[error("login challenge expired")]
    LoginChallengeExpired,
    #[error("login challenge replay detected")]
    LoginChallengeReplayed,
    #[error("login challenge attempts exhausted")]
    LoginChallengeAttemptsExhausted,
    #[error("invalid login challenge code")]
    InvalidLoginCode,
    #[error("invalid totp code")]
    InvalidTotpCode,
    #[error("invalid totp secret")]
    InvalidTotpSecret,
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("missing authorization data")]
    MissingAuthorizationData,
    #[error("missing websocket authorization payload")]
    MissingConnectionInitAuth,
    #[error("token creation failed: {0}")]
    TokenCreation(String),
    #[error("password hashing failed: {0}")]
    PasswordHashing(String),
    #[error("storage error: {0}")]
    Store(String),
    #[error("configuration error: {0}")]
    Config(String),
}

impl ErrorExtensions for AuthError {
    fn extend(&self) -> async_graphql::Error {
        async_graphql::Error::new(self.to_string()).extend_with(|_, e| {
            e.set(
                "code",
                match self {
                    AuthError::InvalidCredentials => "INVALID_CREDENTIALS",
                    AuthError::Unauthenticated => "UNAUTHENTICATED",
                    AuthError::Forbidden => "FORBIDDEN",
                    AuthError::InvalidBearerToken => "INVALID_BEARER_TOKEN",
                    AuthError::InvalidAccessToken => "INVALID_ACCESS_TOKEN",
                    AuthError::AccessTokenExpired => "ACCESS_TOKEN_EXPIRED",
                    AuthError::InvalidRefreshToken => "INVALID_REFRESH_TOKEN",
                    AuthError::RefreshTokenExpired => "REFRESH_TOKEN_EXPIRED",
                    AuthError::RefreshTokenReplayDetected => "REFRESH_TOKEN_REPLAY_DETECTED",
                    AuthError::UserDisabled => "USER_DISABLED",
                    AuthError::InvalidPasswordResetToken => "INVALID_PASSWORD_RESET_TOKEN",
                    AuthError::PasswordResetTokenExpired => "PASSWORD_RESET_TOKEN_EXPIRED",
                    AuthError::PasswordResetTokenReplayed => "PASSWORD_RESET_TOKEN_REPLAYED",
                    AuthError::InvalidLoginChallenge => "INVALID_LOGIN_CHALLENGE",
                    AuthError::LoginChallengeExpired => "LOGIN_CHALLENGE_EXPIRED",
                    AuthError::LoginChallengeReplayed => "LOGIN_CHALLENGE_REPLAYED",
                    AuthError::LoginChallengeAttemptsExhausted => {
                        "LOGIN_CHALLENGE_ATTEMPTS_EXHAUSTED"
                    }
                    AuthError::InvalidLoginCode => "INVALID_LOGIN_CODE",
                    AuthError::InvalidTotpCode => "INVALID_TOTP_CODE",
                    AuthError::InvalidTotpSecret => "INVALID_TOTP_SECRET",
                    AuthError::InvalidConfiguration(_) => "INVALID_CONFIGURATION",
                    AuthError::MissingAuthorizationData => "MISSING_AUTHORIZATION_DATA",
                    AuthError::MissingConnectionInitAuth => "MISSING_CONNECTION_INIT_AUTH",
                    AuthError::TokenCreation(_) => "TOKEN_CREATION_FAILED",
                    AuthError::PasswordHashing(_) => "PASSWORD_HASHING_FAILED",
                    AuthError::Store(_) => "STORE_ERROR",
                    AuthError::Config(_) => "CONFIG_ERROR",
                },
            );
        })
    }
}

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

pub struct AuthService<U, R> {
    config: AuthConfig,
    user_store: Arc<U>,
    refresh_store: Arc<R>,
    argon2: Argon2<'static>,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    validation: Validation,
}

impl<U, R> AuthService<U, R>
where
    U: UserStore + 'static,
    R: RefreshTokenStore + 'static,
{
    pub fn new(config: AuthConfig, user_store: Arc<U>, refresh_store: Arc<R>) -> AuthResult<Self> {
        if config.jwt_secret.is_empty() {
            return Err(AuthError::Config(
                "jwt_secret must not be empty".to_string(),
            ));
        }

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[config.issuer.clone()]);
        validation.set_audience(&[config.audience.clone()]);
        validation.required_spec_claims.extend(
            ["exp", "iat", "iss", "aud", "sub"]
                .into_iter()
                .map(str::to_string),
        );

        Ok(Self {
            encoding_key: EncodingKey::from_secret(config.jwt_secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(config.jwt_secret.as_bytes()),
            validation,
            config,
            user_store,
            refresh_store,
            argon2: Argon2::default(),
        })
    }

    pub fn hash_password(&self, password: &str) -> AuthResult<String> {
        let salt = SaltString::generate(&mut OsRng);
        self.argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|err| AuthError::PasswordHashing(err.to_string()))
    }

    pub fn verify_password(&self, password: &str, password_hash: &str) -> AuthResult<()> {
        let parsed_hash = PasswordHash::new(password_hash)
            .map_err(|err| AuthError::PasswordHashing(err.to_string()))?;
        self.argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| AuthError::InvalidCredentials)
    }

    pub async fn login(
        &self,
        principal: &str,
        password: &str,
        metadata: ClientMetadata,
    ) -> AuthResult<AuthPayload> {
        let user = self
            .user_store
            .find_user_by_principal(principal)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;

        if user.disabled {
            return Err(AuthError::UserDisabled);
        }

        self.verify_password(password, &user.password_hash)?;

        let session_id = Uuid::new_v4();
        let session_family_id = Uuid::new_v4();
        let auth_user = AuthUser {
            user_id: user.id,
            session_id,
            roles: user.roles,
            session: SessionContext::for_auth_method(AuthMethod::Password),
        };

        self.issue_auth_payload(auth_user, session_family_id, metadata)
            .await
    }

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

        self.refresh_store
            .touch_refresh_token(
                existing.id,
                now,
                metadata.ip_address.clone(),
                metadata.user_agent.clone(),
            )
            .await?;

        let auth_user = AuthUser {
            user_id: user.id,
            session_id: existing.session_id,
            roles: user.roles,
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

        self.refresh_store
            .revoke_refresh_token(
                existing.id,
                now,
                Some(new_record.id),
                RefreshTokenRevocationReason::Rotation,
            )
            .await?;

        self.refresh_store
            .insert_refresh_token(new_record.clone())
            .await?;

        Ok(AuthPayload {
            user: auth_user,
            access_token,
            access_token_expires_at,
            refresh_token: new_raw_refresh_token,
            refresh_token_expires_at: new_record.expires_at,
        })
    }

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

    pub fn authenticate_access_token(&self, token: &str) -> AuthResult<AuthUser> {
        let token_data = decode::<AccessTokenClaims>(token, &self.decoding_key, &self.validation)
            .map_err(map_access_token_decode_error)?;
        let claims = token_data.claims;
        if claims.exp <= OffsetDateTime::now_utc().unix_timestamp() {
            return Err(AuthError::AccessTokenExpired);
        }
        let session_id = Uuid::parse_str(&claims.sid).map_err(|_| AuthError::InvalidAccessToken)?;

        Ok(AuthUser {
            user_id: claims.sub,
            session_id,
            roles: claims.roles,
            session: claims.ctx,
        })
    }

    pub fn authenticate_bearer(&self, bearer_or_token: &str) -> AuthResult<AuthUser> {
        let token = strip_bearer_prefix(bearer_or_token)?;
        self.authenticate_access_token(token)
    }

    pub async fn issue_verified_user_session(
        &self,
        user_id: impl Into<String>,
        roles: Vec<String>,
        auth_method: AuthMethod,
        metadata: ClientMetadata,
    ) -> AuthResult<AuthPayload> {
        self.issue_session_for_user(
            user_id,
            roles,
            SessionContext::for_auth_method(auth_method),
            metadata,
        )
        .await
    }

    pub async fn issue_session_for_user(
        &self,
        user_id: impl Into<String>,
        roles: Vec<String>,
        session: SessionContext,
        metadata: ClientMetadata,
    ) -> AuthResult<AuthPayload> {
        let auth_user = AuthUser {
            user_id: user_id.into(),
            session_id: Uuid::new_v4(),
            roles,
            session,
        };
        self.issue_auth_payload(auth_user, Uuid::new_v4(), metadata)
            .await
    }

    pub fn issue_password_reset_token(
        &self,
        user_id: impl Into<String>,
    ) -> AuthResult<PasswordResetToken> {
        self.issue_password_reset_token_with_ttl(user_id, Duration::hours(1))
    }

    pub fn issue_password_reset_token_with_ttl(
        &self,
        user_id: impl Into<String>,
        ttl: Duration,
    ) -> AuthResult<PasswordResetToken> {
        let user_id = user_id.into();
        let issued_at = OffsetDateTime::now_utc();
        let expires_at = issued_at + ttl;
        let token_id = Uuid::new_v4();
        let claims = PasswordResetTokenClaims {
            sub: user_id.clone(),
            jti: token_id.to_string(),
            purpose: "password_reset".to_string(),
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            exp: expires_at.unix_timestamp(),
            iat: issued_at.unix_timestamp(),
        };

        let token = encode(&Header::new(Algorithm::HS256), &claims, &self.encoding_key)
            .map_err(|err| AuthError::TokenCreation(err.to_string()))?;

        Ok(PasswordResetToken {
            user_id,
            token_id,
            token,
            expires_at,
        })
    }

    pub async fn issue_password_reset_token_with_store<S>(
        &self,
        store: &S,
        user_id: impl Into<String>,
        ttl: Duration,
    ) -> AuthResult<PasswordResetToken>
    where
        S: PasswordResetTokenStore,
    {
        let issued = self.issue_password_reset_token_with_ttl(user_id, ttl)?;
        store
            .insert_password_reset_token(issued.token_id, &issued.user_id, issued.expires_at)
            .await?;
        Ok(issued)
    }

    pub fn authenticate_password_reset_token(
        &self,
        token: &str,
    ) -> AuthResult<VerifiedPasswordResetToken> {
        let token_data =
            decode::<PasswordResetTokenClaims>(token, &self.decoding_key, &self.validation)
                .map_err(map_password_reset_decode_error)?;
        let claims = token_data.claims;
        if claims.purpose != "password_reset" {
            return Err(AuthError::InvalidPasswordResetToken);
        }

        let token_id =
            Uuid::parse_str(&claims.jti).map_err(|_| AuthError::InvalidPasswordResetToken)?;
        let issued_at = OffsetDateTime::from_unix_timestamp(claims.iat)
            .map_err(|_| AuthError::InvalidPasswordResetToken)?;
        let expires_at = OffsetDateTime::from_unix_timestamp(claims.exp)
            .map_err(|_| AuthError::InvalidPasswordResetToken)?;
        if expires_at <= OffsetDateTime::now_utc() {
            return Err(AuthError::PasswordResetTokenExpired);
        }

        Ok(VerifiedPasswordResetToken {
            user_id: claims.sub,
            token_id,
            issued_at,
            expires_at,
        })
    }

    pub async fn consume_password_reset_token<S>(
        &self,
        store: &S,
        token: &str,
    ) -> AuthResult<VerifiedPasswordResetToken>
    where
        S: PasswordResetTokenStore,
    {
        let verified = self.authenticate_password_reset_token(token)?;
        let consumed = store
            .consume_password_reset_token(verified.token_id, OffsetDateTime::now_utc())
            .await?;
        if !consumed {
            return Err(AuthError::PasswordResetTokenReplayed);
        }
        Ok(verified)
    }

    pub async fn create_login_challenge<S>(
        &self,
        store: &S,
        principal: impl Into<String>,
        options: LoginChallengeOptions,
    ) -> AuthResult<IssuedLoginChallenge>
    where
        S: LoginChallengeStore,
    {
        validate_login_challenge_options(&options)?;
        let code = generate_numeric_code(options.code_length);
        let code_hash = self.hash_password(&code)?;
        let now = OffsetDateTime::now_utc();
        let challenge = StoredLoginChallenge {
            id: Uuid::new_v4(),
            principal: principal.into(),
            code_hash,
            created_at: now,
            expires_at: now + options.ttl,
            failed_attempts: 0,
            max_attempts: options.max_attempts,
            consumed_at: None,
            channel: options.channel.clone(),
        };
        store.insert_login_challenge(challenge.clone()).await?;

        Ok(IssuedLoginChallenge {
            challenge_id: challenge.id,
            principal: challenge.principal,
            code,
            expires_at: challenge.expires_at,
            max_attempts: challenge.max_attempts,
            channel: challenge.channel,
        })
    }

    pub async fn verify_login_challenge<S>(
        &self,
        store: &S,
        challenge_id: Uuid,
        code: &str,
    ) -> AuthResult<VerifiedLoginChallenge>
    where
        S: LoginChallengeStore,
    {
        let now = OffsetDateTime::now_utc();
        let challenge = store
            .find_login_challenge(challenge_id)
            .await?
            .ok_or(AuthError::InvalidLoginChallenge)?;

        if challenge.is_consumed() {
            return Err(AuthError::LoginChallengeReplayed);
        }

        if challenge.is_expired(now) {
            return Err(AuthError::LoginChallengeExpired);
        }

        if challenge.attempts_exhausted() {
            return Err(AuthError::LoginChallengeAttemptsExhausted);
        }

        if self.verify_password(code, &challenge.code_hash).is_err() {
            let attempts = store
                .increment_login_challenge_attempts(challenge_id, now)
                .await?;
            if attempts >= challenge.max_attempts {
                return Err(AuthError::LoginChallengeAttemptsExhausted);
            }
            return Err(AuthError::InvalidLoginCode);
        }

        let consumed = store.consume_login_challenge(challenge_id, now).await?;
        if !consumed {
            return Err(AuthError::LoginChallengeReplayed);
        }

        Ok(VerifiedLoginChallenge {
            challenge_id,
            principal: challenge.principal,
            verified_at: now,
            channel: challenge.channel,
        })
    }

    pub fn generate_totp_secret(&self, num_bytes: usize) -> AuthResult<TotpSecret> {
        if num_bytes < 10 {
            return Err(AuthError::InvalidConfiguration(
                "totp secret must be at least 10 bytes".to_string(),
            ));
        }

        let mut raw_secret = vec![0u8; num_bytes];
        rand::rngs::OsRng.fill_bytes(&mut raw_secret);
        let base32_secret = BASE32_NOPAD.encode(&raw_secret);
        Ok(TotpSecret {
            raw_secret,
            base32_secret,
        })
    }

    pub fn build_totp_provisioning(
        &self,
        secret: &TotpSecret,
        issuer: impl Into<String>,
        account_name: impl Into<String>,
        options: TotpOptions,
    ) -> AuthResult<TotpProvisioning> {
        validate_totp_options(&options)?;
        let issuer = issuer.into();
        let account_name = account_name.into();
        let label = format!("{}:{}", issuer, account_name);
        let uri = format!(
            "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
            utf8_percent_encode(&label, NON_ALPHANUMERIC),
            utf8_percent_encode(&secret.base32_secret, NON_ALPHANUMERIC),
            utf8_percent_encode(&issuer, NON_ALPHANUMERIC),
            options.digits,
            options.period_seconds
        );

        Ok(TotpProvisioning {
            issuer,
            account_name,
            secret: secret.base32_secret.clone(),
            uri,
        })
    }

    pub fn verify_totp_code(
        &self,
        secret_base32: &str,
        code: &str,
        options: TotpOptions,
        now: OffsetDateTime,
    ) -> AuthResult<()> {
        validate_totp_options(&options)?;
        if !code.chars().all(|ch| ch.is_ascii_digit()) {
            return Err(AuthError::InvalidTotpCode);
        }

        let secret = BASE32_NOPAD
            .decode(secret_base32.as_bytes())
            .map_err(|_| AuthError::InvalidTotpSecret)?;
        let current_step = totp_step(now, options.period_seconds)?;
        let skew = i64::try_from(options.allowed_skew)
            .map_err(|_| AuthError::InvalidConfiguration("invalid totp skew".to_string()))?;

        for offset in -skew..=skew {
            let step = current_step + offset;
            if step < 0 {
                continue;
            }
            let expected = generate_totp_code_for_step(
                &secret,
                u64::try_from(step).map_err(|_| {
                    AuthError::InvalidConfiguration("invalid totp step".to_string())
                })?,
                options.digits,
            )?;
            if expected == code {
                return Ok(());
            }
        }

        Err(AuthError::InvalidTotpCode)
    }

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
            ctx: auth_user.session.clone(),
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            exp: expires_at.unix_timestamp(),
            iat: issued_at.unix_timestamp(),
        };

        encode(&Header::new(Algorithm::HS256), &claims, &self.encoding_key)
            .map_err(|err| AuthError::TokenCreation(err.to_string()))
    }
}

pub fn auth_user_from_ctx<'a>(ctx: &'a Context<'_>) -> GraphqlResult<&'a AuthUser> {
    ctx.data_opt::<AuthUser>()
        .ok_or(AuthError::Unauthenticated.extend())
}

pub fn auth_user_from_ctx_opt<'a>(ctx: &'a Context<'_>) -> Option<&'a AuthUser> {
    ctx.data_opt::<AuthUser>()
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RequireAuth;

impl RequireAuth {
    pub fn new() -> Self {
        Self
    }
}

impl Guard for RequireAuth {
    fn check(
        &self,
        ctx: &Context<'_>,
    ) -> impl std::future::Future<Output = GraphqlResult<()>> + Send {
        let result = auth_user_from_ctx(ctx).map(|_| ());
        async move { result }
    }
}

#[derive(Clone, Debug)]
pub struct RequireAnyRole {
    roles: Vec<String>,
}

impl RequireAnyRole {
    pub fn new<I, S>(roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            roles: roles.into_iter().map(Into::into).collect(),
        }
    }
}

impl Guard for RequireAnyRole {
    fn check(
        &self,
        ctx: &Context<'_>,
    ) -> impl std::future::Future<Output = GraphqlResult<()>> + Send {
        let allowed = auth_user_from_ctx(ctx).and_then(|user| {
            if self
                .roles
                .iter()
                .any(|role| user.roles.iter().any(|r| r == role))
            {
                Ok(())
            } else {
                Err(AuthError::Forbidden.extend())
            }
        });
        async move { allowed }
    }
}

#[derive(Clone, Debug)]
pub struct RequireAllRoles {
    roles: Vec<String>,
}

impl RequireAllRoles {
    pub fn new<I, S>(roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            roles: roles.into_iter().map(Into::into).collect(),
        }
    }
}

impl Guard for RequireAllRoles {
    fn check(
        &self,
        ctx: &Context<'_>,
    ) -> impl std::future::Future<Output = GraphqlResult<()>> + Send {
        let allowed = auth_user_from_ctx(ctx).and_then(|user| {
            if self
                .roles
                .iter()
                .all(|role| user.roles.iter().any(|r| r == role))
            {
                Ok(())
            } else {
                Err(AuthError::Forbidden.extend())
            }
        });
        async move { allowed }
    }
}

fn strip_bearer_prefix(input: &str) -> AuthResult<&str> {
    let trimmed = input.trim();
    if let Some(rest) = trimmed.strip_prefix("Bearer ") {
        Ok(rest.trim())
    } else if let Some(rest) = trimmed.strip_prefix("bearer ") {
        Ok(rest.trim())
    } else if trimmed.is_empty() {
        Err(AuthError::InvalidBearerToken)
    } else {
        Ok(trimmed)
    }
}

fn extract_connection_init_token(value: &JsonValue) -> AuthResult<String> {
    let Some(object) = value.as_object() else {
        return Err(AuthError::MissingConnectionInitAuth);
    };

    for key in [
        "authorization",
        "Authorization",
        "access_token",
        "accessToken",
    ] {
        if let Some(raw) = object.get(key).and_then(JsonValue::as_str) {
            return Ok(raw.to_string());
        }
    }

    Err(AuthError::MissingConnectionInitAuth)
}

fn map_access_token_decode_error(err: jsonwebtoken::errors::Error) -> AuthError {
    match err.kind() {
        JwtErrorKind::ExpiredSignature => AuthError::AccessTokenExpired,
        _ => AuthError::InvalidAccessToken,
    }
}

fn map_password_reset_decode_error(err: jsonwebtoken::errors::Error) -> AuthError {
    match err.kind() {
        JwtErrorKind::ExpiredSignature => AuthError::PasswordResetTokenExpired,
        _ => AuthError::InvalidPasswordResetToken,
    }
}

fn validate_login_challenge_options(options: &LoginChallengeOptions) -> AuthResult<()> {
    if options.code_length == 0 {
        return Err(AuthError::InvalidConfiguration(
            "login challenge code length must be greater than zero".to_string(),
        ));
    }

    if options.max_attempts == 0 {
        return Err(AuthError::InvalidConfiguration(
            "login challenge max_attempts must be greater than zero".to_string(),
        ));
    }

    if options.ttl <= Duration::ZERO {
        return Err(AuthError::InvalidConfiguration(
            "login challenge ttl must be greater than zero".to_string(),
        ));
    }

    Ok(())
}

fn validate_totp_options(options: &TotpOptions) -> AuthResult<()> {
    if !(6..=8).contains(&options.digits) {
        return Err(AuthError::InvalidConfiguration(
            "totp digits must be between 6 and 8".to_string(),
        ));
    }

    if options.period_seconds == 0 {
        return Err(AuthError::InvalidConfiguration(
            "totp period must be greater than zero".to_string(),
        ));
    }

    Ok(())
}

fn generate_numeric_code(length: usize) -> String {
    let mut bytes = vec![0u8; length];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let mut out = String::with_capacity(length);
    for byte in bytes {
        out.push(char::from(b'0' + (byte % 10)));
    }
    out
}

fn generate_opaque_token() -> String {
    let mut bytes = [0u8; 48];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn hash_refresh_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let digest = hasher.finalize();
    encode_hex(digest.as_slice())
}

fn encode_hex(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{byte:02x}"));
    }
    out
}

fn totp_step(now: OffsetDateTime, period_seconds: u64) -> AuthResult<i64> {
    let period = i64::try_from(period_seconds)
        .map_err(|_| AuthError::InvalidConfiguration("totp period is too large".to_string()))?;
    Ok(now.unix_timestamp() / period)
}

fn generate_totp_code_for_step(secret: &[u8], step: u64, digits: u32) -> AuthResult<String> {
    let mut mac = HmacSha1::new_from_slice(secret).map_err(|_| AuthError::InvalidTotpSecret)?;
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0f);
    let binary = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let modulo = 10u32
        .checked_pow(digits)
        .ok_or_else(|| AuthError::InvalidConfiguration("invalid totp digits".to_string()))?;
    Ok(format!(
        "{:0width$}",
        binary % modulo,
        width = usize::try_from(digits)
            .map_err(|_| AuthError::InvalidConfiguration("invalid totp digits".to_string()))?
    ))
}

pub mod prelude {
    pub use crate::ActiveScope;
    pub use crate::AuthConfig;
    pub use crate::AuthError;
    pub use crate::AuthMethod;
    pub use crate::AuthPayload;
    pub use crate::AuthResult;
    pub use crate::AuthService;
    pub use crate::AuthUser;
    pub use crate::ClientMetadata;
    pub use crate::IssuedLoginChallenge;
    pub use crate::LoginChallengeOptions;
    pub use crate::LoginChallengeStore;
    pub use crate::MfaMethod;
    pub use crate::MfaState;
    pub use crate::PasswordResetToken;
    pub use crate::PasswordResetTokenStore;
    pub use crate::RefreshTokenRevocationReason;
    pub use crate::RefreshTokenStore;
    pub use crate::RequireAllRoles;
    pub use crate::RequireAnyRole;
    pub use crate::RequireAuth;
    pub use crate::SessionContext;
    pub use crate::StoredLoginChallenge;
    pub use crate::StoredRefreshToken;
    pub use crate::StoredUser;
    pub use crate::TotpOptions;
    pub use crate::TotpProvisioning;
    pub use crate::TotpSecret;
    pub use crate::UserStore;
    pub use crate::VerifiedLoginChallenge;
    pub use crate::VerifiedPasswordResetToken;
    pub use crate::auth_user_from_ctx;
    pub use crate::auth_user_from_ctx_opt;
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Default)]
    struct MemoryUserStore {
        users_by_id: Arc<Mutex<HashMap<String, StoredUser>>>,
        principal_to_id: Arc<Mutex<HashMap<String, String>>>,
    }

    impl MemoryUserStore {
        fn insert(&self, user: StoredUser) {
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
        async fn find_user_by_principal(&self, principal: &str) -> AuthResult<Option<StoredUser>> {
            let user_id = self.principal_to_id.lock().unwrap().get(principal).cloned();
            Ok(user_id.and_then(|id| self.users_by_id.lock().unwrap().get(&id).cloned()))
        }

        async fn find_user_by_id(&self, user_id: &str) -> AuthResult<Option<StoredUser>> {
            Ok(self.users_by_id.lock().unwrap().get(user_id).cloned())
        }
    }

    #[derive(Clone, Default)]
    struct MemoryRefreshTokenStore {
        tokens_by_id: Arc<Mutex<HashMap<Uuid, StoredRefreshToken>>>,
        token_hash_to_id: Arc<Mutex<HashMap<String, Uuid>>>,
        family_revocations: Arc<Mutex<Vec<(Uuid, OffsetDateTime, RefreshTokenRevocationReason)>>>,
    }

    impl MemoryRefreshTokenStore {
        fn get_by_hash(&self, token_hash: &str) -> Option<StoredRefreshToken> {
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
        async fn insert_refresh_token(&self, token: StoredRefreshToken) -> AuthResult<()> {
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
        ) -> AuthResult<Option<StoredRefreshToken>> {
            Ok(self.get_by_hash(token_hash))
        }

        async fn revoke_refresh_token(
            &self,
            token_id: Uuid,
            revoked_at: OffsetDateTime,
            replaced_by_token_id: Option<Uuid>,
            _reason: RefreshTokenRevocationReason,
        ) -> AuthResult<()> {
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
        ) -> AuthResult<()> {
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
        ) -> AuthResult<()> {
            if let Some(token) = self.tokens_by_id.lock().unwrap().get_mut(&token_id) {
                token.last_used_at = Some(used_at);
                token.ip_address = ip_address;
                token.user_agent = user_agent;
            }
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct MemoryPasswordResetStore {
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
        ) -> AuthResult<()> {
            self.issued.lock().unwrap().insert(token_id);
            Ok(())
        }

        async fn consume_password_reset_token(
            &self,
            token_id: Uuid,
            _consumed_at: OffsetDateTime,
        ) -> AuthResult<bool> {
            if !self.issued.lock().unwrap().contains(&token_id) {
                return Ok(false);
            }
            Ok(self.consumed.lock().unwrap().insert(token_id))
        }
    }

    #[derive(Clone, Default)]
    struct MemoryLoginChallengeStore {
        challenges: Arc<Mutex<HashMap<Uuid, StoredLoginChallenge>>>,
    }

    #[async_trait]
    impl LoginChallengeStore for MemoryLoginChallengeStore {
        async fn insert_login_challenge(&self, challenge: StoredLoginChallenge) -> AuthResult<()> {
            self.challenges
                .lock()
                .unwrap()
                .insert(challenge.id, challenge);
            Ok(())
        }

        async fn find_login_challenge(
            &self,
            challenge_id: Uuid,
        ) -> AuthResult<Option<StoredLoginChallenge>> {
            Ok(self.challenges.lock().unwrap().get(&challenge_id).cloned())
        }

        async fn increment_login_challenge_attempts(
            &self,
            challenge_id: Uuid,
            _attempted_at: OffsetDateTime,
        ) -> AuthResult<u32> {
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
        ) -> AuthResult<bool> {
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

    fn test_auth_service(
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

    fn stored_user(
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
            disabled: false,
        }
    }

    fn metadata() -> ClientMetadata {
        ClientMetadata {
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("test-agent".to_string()),
        }
    }

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
        assert!(!payload.access_token.is_empty());
        assert!(!payload.refresh_token.is_empty());

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
        assert!(rotated_original.replaced_by_token_id.is_some());

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

    #[tokio::test]
    async fn password_reset_tokens_support_success_expiry_and_replay() {
        let auth = test_auth_service(Default::default(), Default::default());
        let store = MemoryPasswordResetStore::default();

        let issued = auth
            .issue_password_reset_token_with_store(&store, "user-1", Duration::hours(1))
            .await
            .unwrap();

        let verified = auth
            .consume_password_reset_token(&store, &issued.token)
            .await
            .unwrap();
        assert_eq!(verified.user_id, "user-1");
        assert_eq!(verified.token_id, issued.token_id);

        let replay = auth
            .consume_password_reset_token(&store, &issued.token)
            .await
            .unwrap_err();
        assert!(matches!(replay, AuthError::PasswordResetTokenReplayed));

        let expired = auth
            .issue_password_reset_token_with_ttl("user-2", Duration::seconds(-1))
            .unwrap();
        let err = auth
            .authenticate_password_reset_token(&expired.token)
            .unwrap_err();
        assert!(matches!(err, AuthError::PasswordResetTokenExpired));
    }

    #[tokio::test]
    async fn password_reset_tokens_reject_non_reset_tokens() {
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

        let err = auth
            .authenticate_password_reset_token(&payload.access_token)
            .unwrap_err();
        assert!(matches!(err, AuthError::InvalidPasswordResetToken));
    }

    #[tokio::test]
    async fn login_challenges_support_success_invalid_code_exhaustion_and_replay() {
        let auth = test_auth_service(Default::default(), Default::default());
        let store = MemoryLoginChallengeStore::default();
        let issued = auth
            .create_login_challenge(
                &store,
                "alice@example.com",
                LoginChallengeOptions {
                    max_attempts: 2,
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let invalid = auth
            .verify_login_challenge(&store, issued.challenge_id, "000000")
            .await
            .unwrap_err();
        assert!(matches!(invalid, AuthError::InvalidLoginCode));

        let exhausted = auth
            .verify_login_challenge(&store, issued.challenge_id, "111111")
            .await
            .unwrap_err();
        assert!(matches!(
            exhausted,
            AuthError::LoginChallengeAttemptsExhausted
        ));

        let fresh = auth
            .create_login_challenge(&store, "bob@example.com", Default::default())
            .await
            .unwrap();
        let verified = auth
            .verify_login_challenge(&store, fresh.challenge_id, &fresh.code)
            .await
            .unwrap();
        assert_eq!(verified.principal, "bob@example.com");

        let replay = auth
            .verify_login_challenge(&store, fresh.challenge_id, &fresh.code)
            .await
            .unwrap_err();
        assert!(matches!(replay, AuthError::LoginChallengeReplayed));
    }

    #[tokio::test]
    async fn login_challenges_reject_expired_codes() {
        let auth = test_auth_service(Default::default(), Default::default());
        let store = MemoryLoginChallengeStore::default();
        let issued = auth
            .create_login_challenge(
                &store,
                "alice@example.com",
                LoginChallengeOptions {
                    ttl: Duration::seconds(1),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        store
            .challenges
            .lock()
            .unwrap()
            .get_mut(&issued.challenge_id)
            .unwrap()
            .expires_at = OffsetDateTime::now_utc() - Duration::seconds(1);

        let err = auth
            .verify_login_challenge(&store, issued.challenge_id, &issued.code)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::LoginChallengeExpired));
    }

    #[tokio::test]
    async fn totp_supports_known_vector_and_invalid_code_rejection() {
        let auth = test_auth_service(Default::default(), Default::default());
        let options = TotpOptions {
            digits: 8,
            period_seconds: 30,
            allowed_skew: 0,
        };
        let secret = TotpSecret {
            raw_secret: b"12345678901234567890".to_vec(),
            base32_secret: BASE32_NOPAD.encode(b"12345678901234567890"),
        };

        auth.verify_totp_code(
            &secret.base32_secret,
            "94287082",
            options.clone(),
            OffsetDateTime::from_unix_timestamp(59).unwrap(),
        )
        .unwrap();

        let err = auth
            .verify_totp_code(
                &secret.base32_secret,
                "00000000",
                options.clone(),
                OffsetDateTime::from_unix_timestamp(59).unwrap(),
            )
            .unwrap_err();
        assert!(matches!(err, AuthError::InvalidTotpCode));

        let provisioning = auth
            .build_totp_provisioning(&secret, "agql-auth", "alice@example.com", options)
            .unwrap();
        assert!(provisioning.uri.starts_with("otpauth://totp/"));
        assert!(provisioning.uri.contains("issuer="));
    }
}
