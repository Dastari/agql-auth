mod challenge;
mod password_reset;
mod totp;

use std::sync::Arc;

use argon2::Argon2;
use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
};
use async_graphql::Data;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::AuthResult;
use crate::config::{AuthConfig, ClientMetadata};
use crate::errors::AuthError;
use crate::models::{AuthPayload, AuthUser, RefreshTokenRevocationReason, StoredRefreshToken};
use crate::session::{AuthMethod, SessionContext};
use crate::stores::{RefreshTokenStore, UserStore};
use crate::util::{
    extract_connection_init_token, generate_opaque_token, hash_refresh_token,
    map_access_token_decode_error, strip_bearer_prefix,
};

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
pub(super) struct PasswordResetTokenClaims {
    pub(super) sub: String,
    pub(super) jti: String,
    pub(super) purpose: String,
    pub(super) iss: String,
    pub(super) aud: String,
    pub(super) exp: i64,
    pub(super) iat: i64,
}

pub struct AuthService<U, R> {
    pub(super) config: AuthConfig,
    pub(super) user_store: Arc<U>,
    pub(super) refresh_store: Arc<R>,
    pub(super) argon2: Argon2<'static>,
    pub(super) encoding_key: EncodingKey,
    pub(super) decoding_key: DecodingKey,
    pub(super) validation: Validation,
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
