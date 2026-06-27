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
use time::OffsetDateTime;
use uuid::Uuid;

use crate::AuthResult;
use crate::config::{AuthConfig, ClientMetadata, JwtSigningConfig};
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
    scopes: Vec<String>,
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
    signing_algorithm: Algorithm,
    signing_key_id: Option<String>,
    jwks: Option<JsonValue>,
}

impl<U, R> AuthService<U, R>
where
    U: UserStore + 'static,
    R: RefreshTokenStore + 'static,
{
    pub fn new(config: AuthConfig, user_store: Arc<U>, refresh_store: Arc<R>) -> AuthResult<Self> {
        let jwt_keys = JwtKeyMaterial::from_config(&config)?;

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
            scopes: user.scopes,
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
        self.validate_local_jwt_header(token)
            .map_err(|_| AuthError::InvalidAccessToken)?;
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
            scopes: claims.scopes,
            session: claims.ctx,
        })
    }

    pub fn authenticate_bearer(&self, bearer_or_token: &str) -> AuthResult<AuthUser> {
        let token = strip_bearer_prefix(bearer_or_token)?;
        self.authenticate_access_token(token)
    }

    pub fn jwks(&self) -> AuthResult<JsonValue> {
        self.jwks.clone().ok_or(AuthError::JwksUnsupported)
    }

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
                if secret.is_empty() {
                    return Err(AuthError::Config(
                        "jwt_secret must not be empty".to_string(),
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
        JwtSigningConfig::Hs256 { secret } => {
            let secret = if !config.jwt_secret.is_empty() && config.jwt_secret != *secret {
                config.jwt_secret.as_str()
            } else {
                secret.as_str()
            };
            EffectiveJwtSigningConfig::Hs256 { secret }
        }
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
