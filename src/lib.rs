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
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

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
pub struct AuthUser {
    pub user_id: String,
    pub session_id: Uuid,
    pub roles: Vec<String>,
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
    iss: String,
    aud: String,
    exp: i64,
    iat: i64,
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
    #[error("invalid refresh token")]
    InvalidRefreshToken,
    #[error("refresh token expired")]
    RefreshTokenExpired,
    #[error("refresh token replay detected")]
    RefreshTokenReplayDetected,
    #[error("user is disabled")]
    UserDisabled,
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
                    AuthError::InvalidRefreshToken => "INVALID_REFRESH_TOKEN",
                    AuthError::RefreshTokenExpired => "REFRESH_TOKEN_EXPIRED",
                    AuthError::RefreshTokenReplayDetected => "REFRESH_TOKEN_REPLAY_DETECTED",
                    AuthError::UserDisabled => "USER_DISABLED",
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
            .map_err(|_| AuthError::InvalidAccessToken)?;
        let claims = token_data.claims;
        let session_id = Uuid::parse_str(&claims.sid).map_err(|_| AuthError::InvalidAccessToken)?;

        Ok(AuthUser {
            user_id: claims.sub,
            session_id,
            roles: claims.roles,
        })
    }

    pub fn authenticate_bearer(&self, bearer_or_token: &str) -> AuthResult<AuthUser> {
        let token = strip_bearer_prefix(bearer_or_token)?;
        self.authenticate_access_token(token)
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

pub mod prelude {
    pub use crate::AuthConfig;
    pub use crate::AuthError;
    pub use crate::AuthPayload;
    pub use crate::AuthResult;
    pub use crate::AuthService;
    pub use crate::AuthUser;
    pub use crate::ClientMetadata;
    pub use crate::RefreshTokenRevocationReason;
    pub use crate::RefreshTokenStore;
    pub use crate::RequireAllRoles;
    pub use crate::RequireAnyRole;
    pub use crate::RequireAuth;
    pub use crate::StoredRefreshToken;
    pub use crate::StoredUser;
    pub use crate::UserStore;
    pub use crate::auth_user_from_ctx;
    pub use crate::auth_user_from_ctx_opt;
}
