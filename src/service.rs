mod challenge;
mod password_reset;
mod totp;

use std::collections::BTreeMap;
use std::sync::Arc;

use argon2::Argon2;
use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
};
use async_graphql::Data;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rsa::RsaPublicKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::AuthResult;
use crate::assurance::{
    MfaAcceptance, RefreshableTokenMetadata, SessionAssurance, StepUpAuthentication,
};
use crate::claims::AccessTokenMetadata;
use crate::clock::Clock;
use crate::config::{AuthConfig, AuthRateLimitPolicy, ClientMetadata, JwtSigningConfig};
use crate::errors::AuthError;
use crate::grant::{AccessTokenOnlyGrant, AccessTokenOnlyRequest};
use crate::models::{
    AuthPayload, AuthRateLimitBucket, AuthRateLimitFlow, AuthRateLimitKey, AuthRateLimitState,
    AuthUser, IssuedPurposeToken, PurposeTokenIssueRequest, PurposeTokenValidation,
    RefreshTokenRevocationReason, StoredRefreshToken, VerifiedPurposeToken,
};
use crate::scope_match::{AuthRuntime, ExactScopeMatch, ScopeMatch};
use crate::session::{AuthMethod, SessionContext};
use crate::stores::{AuthRateLimitStore, MemoryAuthRateLimitStore, RefreshTokenStore, UserStore};
use crate::token_decode::{
    ACCESS_TOKEN_PURPOSE, ACCESS_TOKEN_TYPE, AccessTokenClaims, AccessTokenDecodeConfig,
    access_token_claims_to_user, audience_claim, decode_access_token_claims,
};
use crate::util::{
    extract_connection_init_token, generate_opaque_token, hash_rate_limit_value,
    hash_refresh_token, map_purpose_token_decode_error, strip_bearer_prefix,
};

const MIN_HS256_SECRET_BYTES: usize = 32;
const PASSWORD_RESET_TOKEN_TYPE: &str = "password_reset";
const PASSWORD_RESET_TOKEN_PURPOSE: &str = "password_reset";
const PURPOSE_TOKEN_TYPE: &str = "purpose_token";
const DUMMY_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$YWdxbC1hdXRoLWR1bW15LXNsdA$8ClNuSX6M3l/dalOcz8a117s1wLv/AbzbJiKA7dS4Ak";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PasswordResetTokenClaims {
    pub(super) sub: String,
    pub(super) jti: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) typ: Option<String>,
    pub(super) purpose: String,
    pub(super) iss: String,
    pub(super) aud: String,
    pub(super) exp: i64,
    pub(super) iat: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PurposeTokenClaims {
    typ: String,
    sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sid: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
    purpose: String,
    iss: String,
    aud: String,
    exp: i64,
    iat: i64,
    #[serde(flatten)]
    custom: BTreeMap<String, JsonValue>,
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
    scope_matcher: Arc<dyn ScopeMatch>,
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
            scope_matcher: Arc::new(ExactScopeMatch),
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

    /// Returns a clone of the configured request-time scope matcher.
    pub fn scope_matcher(&self) -> Arc<dyn ScopeMatch> {
        self.scope_matcher.clone()
    }

    /// Sets the request-time scope matcher used by GraphQL auth injection.
    ///
    /// Direct [`AuthUser::has_scope`](crate::AuthUser::has_scope) calls remain
    /// exact; guards use this matcher when [`AuthRuntime`] is injected.
    pub fn with_scope_matcher(mut self, scope_matcher: Arc<dyn ScopeMatch>) -> Self {
        self.scope_matcher = scope_matcher;
        self
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
            roles: dedupe_stable(user.roles),
            scopes: dedupe_stable(user.scopes),
            session: SessionContext::for_auth_method(AuthMethod::Password),
            token_claims: AccessTokenMetadata {
                session_family_id: Some(session_family_id.to_string()),
                ..AccessTokenMetadata::default()
            },
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
        self.rotate_session(refresh_token, metadata, None).await
    }

    /// Rotates one refreshable session after a successful host-verified step-up.
    ///
    /// The injected clock supplies the genuine step-up time. Only the session
    /// identified by `refresh_token` is changed; unrelated sessions and token
    /// families are untouched. Calling this method is the host's assertion that
    /// the supplied methods/ACR satisfy its MFA policy.
    pub async fn step_up_session(
        &self,
        refresh_token: &str,
        step_up: StepUpAuthentication,
        metadata: ClientMetadata,
        clock: &dyn Clock,
    ) -> AuthResult<AuthPayload> {
        let assurance = SessionAssurance::new(
            clock.now(),
            step_up.methods,
            step_up.acr,
            step_up.context,
            MfaAcceptance::Satisfied,
        )
        .map_err(|error| AuthError::InvalidConfiguration(error.to_string()))?;
        self.rotate_session(refresh_token, metadata, Some(assurance))
            .await
    }

    async fn rotate_session(
        &self,
        refresh_token: &str,
        metadata: ClientMetadata,
        assurance_override: Option<SessionAssurance>,
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

        let mut session = existing.session.clone();
        if let Some(assurance) = assurance_override {
            session = session.with_assurance(assurance);
        }
        let refreshable_metadata = existing.refreshable_metadata.clone().unwrap_or_default();
        let auth_time = session.assurance.as_ref().map(SessionAssurance::auth_time);
        let amr = session
            .assurance
            .as_ref()
            .map(|value| value.methods.clone());
        let acr = session
            .assurance
            .as_ref()
            .and_then(|value| value.acr.clone());
        let auth_user = AuthUser {
            user_id: user.id,
            session_id: existing.session_id,
            roles: dedupe_stable(user.roles),
            scopes: dedupe_stable(existing.scopes.clone()),
            session,
            token_claims: AccessTokenMetadata {
                session_family_id: Some(existing.session_family_id.to_string()),
                tenant_id: refreshable_metadata.tenant_id,
                organization_id: refreshable_metadata.organization_id,
                actor: refreshable_metadata.actor,
                auth_time,
                amr,
                acr,
                correlation_id: refreshable_metadata.correlation_id,
                ..AccessTokenMetadata::default()
            },
        };

        let (new_raw_refresh_token, new_record, access_token, access_token_expires_at, user) = self
            .issue_tokens_only(auth_user, existing.session_family_id, metadata.clone(), now)
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
            user,
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
        let claims = decode_access_token_claims(token, &self.access_token_decode_config())?;
        access_token_claims_to_user(claims)
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

    /// Issues a short-lived JWT for a specific non-session purpose.
    ///
    /// Purpose tokens are signed with the same configured local key material as
    /// access tokens but carry a distinct `typ`, exact `purpose`, and caller
    /// supplied `aud` claim. Validate them with
    /// [`AuthService::authenticate_purpose_token`], not
    /// [`AuthService::authenticate_access_token`].
    pub fn issue_purpose_token(
        &self,
        request: PurposeTokenIssueRequest,
    ) -> AuthResult<IssuedPurposeToken> {
        validate_purpose_token_issue_request(&request)?;
        let issued_at = OffsetDateTime::now_utc();
        let expires_at = issued_at + request.ttl;
        let claims = PurposeTokenClaims {
            typ: PURPOSE_TOKEN_TYPE.to_string(),
            sub: request.subject.clone(),
            sid: request.session_id.map(|session_id| session_id.to_string()),
            scopes: request.scopes.clone(),
            purpose: request.purpose.clone(),
            iss: self.config.issuer.clone(),
            aud: request.audience.clone(),
            exp: expires_at.unix_timestamp(),
            iat: issued_at.unix_timestamp(),
            custom: request.claims.clone(),
        };
        let token = self.encode_local_jwt(&claims)?;

        Ok(IssuedPurposeToken {
            token,
            subject: request.subject,
            purpose: request.purpose,
            audience: request.audience,
            session_id: request.session_id,
            scopes: request.scopes,
            claims: request.claims,
            expires_at,
        })
    }

    /// Validates a short-lived purpose token with exact purpose and audience.
    pub fn authenticate_purpose_token(
        &self,
        token: &str,
        expected: PurposeTokenValidation,
    ) -> AuthResult<VerifiedPurposeToken> {
        if expected.purpose.trim().is_empty() || expected.audience.trim().is_empty() {
            return Err(AuthError::InvalidPurposeToken);
        }

        self.validate_local_jwt_header(token)
            .map_err(|_| AuthError::InvalidPurposeToken)?;
        let validation = self.validation_for_audience(&expected.audience);
        let token_data = decode::<PurposeTokenClaims>(token, &self.decoding_key, &validation)
            .map_err(map_purpose_token_decode_error)?;
        let claims = token_data.claims;
        if claims.exp <= OffsetDateTime::now_utc().unix_timestamp() {
            return Err(AuthError::PurposeTokenExpired);
        }
        if claims.typ != PURPOSE_TOKEN_TYPE
            || claims.purpose != expected.purpose
            || claims.aud != expected.audience
        {
            return Err(AuthError::InvalidPurposeToken);
        }

        let session_id = claims
            .sid
            .as_deref()
            .map(Uuid::parse_str)
            .transpose()
            .map_err(|_| AuthError::InvalidPurposeToken)?;
        let issued_at = OffsetDateTime::from_unix_timestamp(claims.iat)
            .map_err(|_| AuthError::InvalidPurposeToken)?;
        let expires_at = OffsetDateTime::from_unix_timestamp(claims.exp)
            .map_err(|_| AuthError::InvalidPurposeToken)?;

        Ok(VerifiedPurposeToken {
            subject: claims.sub,
            purpose: claims.purpose,
            audience: claims.aud,
            session_id,
            scopes: claims.scopes,
            claims: claims.custom,
            issued_at,
            expires_at,
        })
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
        self.issue_session_for_user_with_metadata(
            user_id,
            roles,
            scopes,
            session,
            RefreshableTokenMetadata::default(),
            metadata,
        )
        .await
    }

    /// Issues a refreshable session with host-validated assurance and an
    /// explicitly refresh-safe subset of standard access-token metadata.
    ///
    /// Existing issuance methods call this with no assurance or refreshable
    /// metadata. Sender/resource bindings and arbitrary custom claims are not
    /// accepted here because their validity may be per-token.
    pub async fn issue_session_for_user_with_metadata(
        &self,
        user_id: impl Into<String>,
        roles: Vec<String>,
        scopes: Vec<String>,
        mut session: SessionContext,
        refreshable_metadata: RefreshableTokenMetadata,
        metadata: ClientMetadata,
    ) -> AuthResult<AuthPayload> {
        if let Some(assurance) = session.assurance.as_ref() {
            assurance
                .validate()
                .map_err(|error| AuthError::InvalidConfiguration(error.to_string()))?;
            session.mfa = assurance.mfa_state();
        }
        let session_family_id = Uuid::new_v4();
        let assurance_auth_time = session.assurance.as_ref().map(SessionAssurance::auth_time);
        let assurance_amr = session
            .assurance
            .as_ref()
            .map(|value| value.methods.clone());
        let assurance_acr = session
            .assurance
            .as_ref()
            .and_then(|value| value.acr.clone());
        let auth_user = AuthUser {
            user_id: user_id.into(),
            session_id: Uuid::new_v4(),
            roles: dedupe_stable(roles),
            scopes: dedupe_stable(scopes),
            session,
            token_claims: AccessTokenMetadata {
                session_family_id: Some(session_family_id.to_string()),
                tenant_id: refreshable_metadata.tenant_id.clone(),
                organization_id: refreshable_metadata.organization_id.clone(),
                actor: refreshable_metadata.actor.clone(),
                auth_time: assurance_auth_time,
                amr: assurance_amr,
                acr: assurance_acr,
                correlation_id: refreshable_metadata.correlation_id.clone(),
                ..AccessTokenMetadata::default()
            },
        };
        self.issue_auth_payload(auth_user, session_family_id, metadata)
            .await
    }

    /// Issues a refreshable session from host-accepted authentication facts.
    ///
    /// This is the direct typed entry point for password, passkey, OIDC, or
    /// other host flows that have already established authoritative assurance.
    #[allow(clippy::too_many_arguments)]
    pub async fn issue_assured_user_session(
        &self,
        user_id: impl Into<String>,
        roles: Vec<String>,
        scopes: Vec<String>,
        auth_method: AuthMethod,
        assurance: SessionAssurance,
        refreshable_metadata: RefreshableTokenMetadata,
        metadata: ClientMetadata,
    ) -> AuthResult<AuthPayload> {
        self.issue_session_for_user_with_metadata(
            user_id,
            roles,
            scopes,
            SessionContext::for_auth_method(auth_method).with_assurance(assurance),
            refreshable_metadata,
            metadata,
        )
        .await
    }

    /// Issues a short-lived access token without writing a refresh-token row.
    ///
    /// This is intended for host-verified service, device, or one-shot grants
    /// that should validate like normal user-shaped access tokens but must not
    /// create a refreshable session.
    pub async fn issue_access_token_only(
        &self,
        request: AccessTokenOnlyRequest,
    ) -> AuthResult<AccessTokenOnlyGrant> {
        validate_access_token_only_request(&request, &self.config)?;
        let now = OffsetDateTime::now_utc();
        let ttl = request.ttl.unwrap_or(self.config.access_token_ttl);
        if ttl <= Duration::ZERO {
            return Err(AuthError::InvalidConfiguration(
                "access-token-only ttl must be greater than zero".to_string(),
            ));
        }
        if ttl > self.config.max_access_token_ttl {
            return Err(AuthError::InvalidConfiguration(
                "access-token-only ttl exceeds configured maximum".to_string(),
            ));
        }

        let jti = Uuid::new_v4().to_string();
        let auth_user = AuthUser {
            user_id: request.user_id,
            session_id: Uuid::new_v4(),
            roles: dedupe_stable(request.roles),
            scopes: dedupe_stable(request.scopes),
            session: request.session,
            token_claims: AccessTokenMetadata {
                jti: Some(jti),
                tenant_id: request.tenant_id,
                organization_id: request.organization_id,
                session_family_id: request.session_family_id,
                actor: request.actor,
                auth_time: request.auth_time,
                amr: request.amr,
                acr: request.acr,
                cnf: request.cnf,
                resource_type: request.resource_type,
                resource_id: request.resource_id,
                correlation_id: request.correlation_id,
                purpose: Some(ACCESS_TOKEN_PURPOSE.to_string()),
                expires_at: None,
                additional: request.additional_claims,
            },
        };
        let access_token_expires_at = now + ttl;
        let (access_token, user) =
            self.issue_access_token_with_user(auth_user, now, access_token_expires_at)?;

        Ok(AccessTokenOnlyGrant {
            access_token,
            access_token_expires_at,
            user,
        })
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
            request = request
                .data(auth_user)
                .data(AuthRuntime::new(self.scope_matcher()));
        }

        Ok(request)
    }

    /// Authenticates an `async-graphql` WebSocket connection-init payload.
    pub async fn authenticate_connection_init_value(&self, value: JsonValue) -> AuthResult<Data> {
        let token = extract_connection_init_token(&value)?;
        let auth_user = self.authenticate_bearer(&token)?;
        let mut data = Data::default();
        data.insert(AuthRuntime::new(self.scope_matcher()));
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
        let (refresh_token, record, access_token, access_token_expires_at, user) = self
            .issue_tokens_only(auth_user, session_family_id, metadata, now)
            .await?;

        self.refresh_store
            .insert_refresh_token(record.clone())
            .await?;

        Ok(AuthPayload {
            user,
            access_token,
            access_token_expires_at,
            refresh_token,
            refresh_token_expires_at: record.expires_at,
        })
    }

    async fn issue_tokens_only(
        &self,
        auth_user: AuthUser,
        session_family_id: Uuid,
        metadata: ClientMetadata,
        now: OffsetDateTime,
    ) -> AuthResult<(String, StoredRefreshToken, String, OffsetDateTime, AuthUser)> {
        let access_token_expires_at = now + self.config.access_token_ttl;
        let (access_token, user) =
            self.issue_access_token_with_user(auth_user, now, access_token_expires_at)?;

        let raw_refresh_token = generate_opaque_token();
        let refresh_token_expires_at = now + self.config.refresh_token_ttl;
        let refreshable_metadata = RefreshableTokenMetadata {
            tenant_id: user.token_claims.tenant_id.clone(),
            organization_id: user.token_claims.organization_id.clone(),
            actor: user.token_claims.actor.clone(),
            correlation_id: user.token_claims.correlation_id.clone(),
        };
        let refreshable_metadata = (refreshable_metadata != RefreshableTokenMetadata::default())
            .then_some(refreshable_metadata);
        let refresh_record = StoredRefreshToken {
            id: Uuid::new_v4(),
            user_id: user.user_id.clone(),
            session_id: user.session_id,
            session_family_id,
            scopes: user.scopes.clone(),
            session: user.session.clone(),
            refreshable_metadata,
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
            user,
        ))
    }

    fn issue_access_token_with_user(
        &self,
        mut auth_user: AuthUser,
        issued_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> AuthResult<(String, AuthUser)> {
        let jti = auth_user
            .token_claims
            .jti
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        auth_user.token_claims.jti = Some(jti.clone());
        auth_user.token_claims.purpose = Some(ACCESS_TOKEN_PURPOSE.to_string());
        // JWT exp is second-precision; keep principal metadata aligned with claims.
        auth_user.token_claims.expires_at =
            OffsetDateTime::from_unix_timestamp(expires_at.unix_timestamp()).ok();

        let claims = AccessTokenClaims {
            typ: Some(ACCESS_TOKEN_TYPE.to_string()),
            sub: auth_user.user_id.clone(),
            sid: auth_user.session_id.to_string(),
            roles: auth_user.roles.clone(),
            scopes: auth_user.scopes.clone(),
            ctx: auth_user.session.clone(),
            iss: self.config.issuer.clone(),
            aud: audience_claim(&self.config.audience),
            exp: expires_at.unix_timestamp(),
            iat: issued_at.unix_timestamp(),
            nbf: None,
            purpose: Some(ACCESS_TOKEN_PURPOSE.to_string()),
            jti: Some(jti),
            tenant_id: auth_user.token_claims.tenant_id.clone(),
            organization_id: auth_user.token_claims.organization_id.clone(),
            session_family_id: auth_user.token_claims.session_family_id.clone(),
            actor: auth_user.token_claims.actor.clone(),
            auth_time: auth_user.token_claims.auth_time,
            amr: auth_user.token_claims.amr.clone(),
            acr: auth_user.token_claims.acr.clone(),
            cnf: auth_user.token_claims.cnf.clone(),
            resource_type: auth_user.token_claims.resource_type.clone(),
            resource_id: auth_user.token_claims.resource_id.clone(),
            correlation_id: auth_user.token_claims.correlation_id.clone(),
            additional: auth_user.token_claims.additional.clone(),
        };

        let token = self.encode_local_jwt(&claims)?;
        Ok((token, auth_user))
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
        let header =
            jsonwebtoken::decode_header(token).map_err(|_| AuthError::InvalidAccessToken)?;
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

    pub(super) fn access_token_decode_config(&self) -> AccessTokenDecodeConfig {
        AccessTokenDecodeConfig::for_service(
            self.decoding_key.clone(),
            self.validation.clone(),
            self.signing_key_id.clone(),
        )
    }

    fn validation_for_audience(&self, audience: &str) -> Validation {
        let mut validation = Validation::new(self.signing_algorithm);
        validation.set_issuer(std::slice::from_ref(&self.config.issuer));
        validation.set_audience(&[audience]);
        validation.required_spec_claims.extend(
            ["exp", "iat", "iss", "aud", "sub"]
                .into_iter()
                .map(str::to_string),
        );
        validation
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

fn validate_purpose_token_issue_request(request: &PurposeTokenIssueRequest) -> AuthResult<()> {
    if request.subject.trim().is_empty() {
        return Err(AuthError::InvalidConfiguration(
            "purpose token subject must not be empty".to_string(),
        ));
    }
    if request.purpose.trim().is_empty() {
        return Err(AuthError::InvalidConfiguration(
            "purpose token purpose must not be empty".to_string(),
        ));
    }
    if request.audience.trim().is_empty() {
        return Err(AuthError::InvalidConfiguration(
            "purpose token audience must not be empty".to_string(),
        ));
    }
    if request.ttl <= Duration::ZERO {
        return Err(AuthError::InvalidConfiguration(
            "purpose token ttl must be greater than zero".to_string(),
        ));
    }

    for key in request.claims.keys() {
        if key.trim().is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "purpose token custom claim name must not be empty".to_string(),
            ));
        }
        if RESERVED_PURPOSE_TOKEN_CLAIMS.contains(&key.as_str()) {
            return Err(AuthError::InvalidConfiguration(format!(
                "purpose token custom claim '{key}' is reserved"
            )));
        }
    }

    Ok(())
}

fn validate_access_token_only_request(
    request: &AccessTokenOnlyRequest,
    config: &AuthConfig,
) -> AuthResult<()> {
    if request.user_id.trim().is_empty() {
        return Err(AuthError::InvalidConfiguration(
            "access-token-only user_id must not be empty".to_string(),
        ));
    }
    if let Some(ttl) = request.ttl {
        if ttl <= Duration::ZERO {
            return Err(AuthError::InvalidConfiguration(
                "access-token-only ttl must be greater than zero".to_string(),
            ));
        }
        if ttl > config.max_access_token_ttl {
            return Err(AuthError::InvalidConfiguration(
                "access-token-only ttl exceeds configured maximum".to_string(),
            ));
        }
    }
    for key in request.additional_claims.keys() {
        if RESERVED_ACCESS_TOKEN_CLAIMS.contains(&key.as_str()) {
            return Err(AuthError::InvalidConfiguration(format!(
                "access-token-only custom claim '{key}' is reserved"
            )));
        }
    }
    Ok(())
}

fn dedupe_stable(values: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        if seen.insert(value.clone()) {
            out.push(value);
        }
    }
    out
}

const RESERVED_ACCESS_TOKEN_CLAIMS: &[&str] = &[
    "typ",
    "sub",
    "sid",
    "roles",
    "scopes",
    "ctx",
    "purpose",
    "iss",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "tenant_id",
    "organization_id",
    "session_family_id",
    "actor",
    "auth_time",
    "amr",
    "acr",
    "cnf",
    "resource_type",
    "resource_id",
    "correlation_id",
];

const RESERVED_PURPOSE_TOKEN_CLAIMS: &[&str] = &[
    "typ", "sub", "sid", "scopes", "purpose", "iss", "aud", "exp", "iat",
];

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
