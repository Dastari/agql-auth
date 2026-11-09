use std::fmt;

use serde::{Deserialize, Serialize};
use time::Duration;

use std::str::FromStr;

use jsonwebtoken::{Algorithm, AlgorithmFamily};
use zeroize::Zeroize;

use crate::client_auth::{
    ClientJwtSigner, TokenEndpointAuthMethod, validate_client_authentication,
};
use crate::errors::AuthError;
use crate::oidc::{is_secure_endpoint_url, is_valid_redirect_uri};

/// Default absolute session lifetime: [`AuthConfig::max_session_lifetime`].
pub const DEFAULT_MAX_SESSION_LIFETIME: Duration = Duration::days(90);

/// Runtime configuration for [`crate::AuthService`].
///
/// `AuthConfig::new(secret)` and [`AuthConfig::with_hs256_secret`] preserve the
/// legacy HS256 behavior with a minimum 32-byte secret. Use
/// [`AuthConfig::with_rs256_pem`] when local
/// `agql-auth` tokens need to be validated by routers or services that should
/// only receive public key material.
#[derive(Clone)]
pub struct AuthConfig {
    /// Expected issuer for locally issued JWTs.
    pub issuer: String,
    /// Expected audience for locally issued JWTs.
    pub audience: String,
    /// Legacy HS256 secret field retained for backward compatibility.
    ///
    /// New code should prefer [`AuthConfig::jwt_signing`] and
    /// [`AuthConfig::set_jwt_signing`]. This field is a legacy mirror and is
    /// not authoritative when it differs from `jwt_signing`.
    pub jwt_secret: String,
    /// Configured local JWT signing mode.
    pub jwt_signing: JwtSigningConfig,
    /// Verification-only RS256 public keys from earlier signing keys.
    ///
    /// They are published by [`crate::AuthService::jwks`] and accepted by the
    /// service's own validation when a token's `kid` names them, but are never
    /// used to sign. Keep a key here until every token it signed has expired;
    /// see `docs/key-rotation.md`. Requires RS256 signing.
    pub previous_verification_keys: Vec<JwtVerificationKey>,
    /// Ordinary session access-token lifetime.
    ///
    /// Must not exceed [`Self::max_access_token_ttl`].
    pub access_token_ttl: Duration,
    /// Maximum allowed access-token lifetime for custom TTLs.
    ///
    /// Used by access-token-only and delegated grants. Ordinary refreshable
    /// sessions use `access_token_ttl` independently; hosts must configure that
    /// lifetime separately.
    pub max_access_token_ttl: Duration,
    /// Maximum lifetime of an existing-session-bound delegated access token.
    ///
    /// Delegated expiry is also clamped to the requested TTL and the remaining
    /// authoritative session lifetime. Defaults to 15 minutes.
    pub max_session_bound_delegation_ttl: Duration,
    /// Refresh-token lifetime.
    pub refresh_token_ttl: Duration,
    /// Absolute session lifetime, measured from the session's first issuance.
    ///
    /// Refresh rotation never extends a session family past it: each
    /// replacement expires at the earlier of `refresh_token_ttl` from rotation
    /// and the deadline recorded at issuance in
    /// [`StoredRefreshToken::session_expires_at`](crate::StoredRefreshToken::session_expires_at).
    /// A record without a recorded deadline is never extended past its own
    /// expiry. `None` lets rotation slide indefinitely. Defaults to 90 days.
    pub max_session_lifetime: Option<Duration>,
    /// Claim shape used for newly issued access-token scopes.
    ///
    /// Version 0.14 defaults to [`AccessTokenScopeClaimFormat::Standard`]. Use
    /// [`AccessTokenScopeClaimFormat::LegacyArray`] only during a staged
    /// migration for consumers that cannot yet read the OAuth `scope` claim.
    pub access_token_scope_claim_format: AccessTokenScopeClaimFormat,
    /// Whether access-token validation accepts the pre-0.14 `scopes` array.
    ///
    /// Defaults to [`LegacyScopeClaims::Reject`]. Select
    /// [`LegacyScopeClaims::Accept`] only while tokens in the pre-0.14 format
    /// are still in circulation, for example when issuing with
    /// [`AccessTokenScopeClaimFormat::LegacyArray`]. A token containing
    /// conflicting `scope` and `scopes` values is rejected in either mode.
    pub legacy_scope_claims: LegacyScopeClaims,
    /// Abuse-protection settings for credential and request flows.
    pub rate_limits: AuthRateLimitConfig,
    /// Argon2id parameters and the password length cap.
    pub password_hashing: PasswordHashingConfig,
}

impl fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthConfig")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("jwt_secret", &"[redacted]")
            .field("jwt_signing", &self.jwt_signing)
            .field(
                "previous_verification_keys",
                &self.previous_verification_keys,
            )
            .field("access_token_ttl", &self.access_token_ttl)
            .field("max_access_token_ttl", &self.max_access_token_ttl)
            .field(
                "max_session_bound_delegation_ttl",
                &self.max_session_bound_delegation_ttl,
            )
            .field("refresh_token_ttl", &self.refresh_token_ttl)
            .field("max_session_lifetime", &self.max_session_lifetime)
            .field(
                "access_token_scope_claim_format",
                &self.access_token_scope_claim_format,
            )
            .field("legacy_scope_claims", &self.legacy_scope_claims)
            .field("rate_limits", &self.rate_limits)
            .field("password_hashing", &self.password_hashing)
            .finish()
    }
}

impl AuthConfig {
    /// Creates a legacy HS256 configuration from a symmetric secret.
    ///
    /// The secret is validated by [`crate::AuthService::new`] and must be at
    /// least 32 bytes.
    pub fn new(jwt_secret: impl Into<String>) -> Self {
        Self::with_hs256_secret(jwt_secret)
    }

    /// Creates an explicit HS256 configuration from a symmetric secret.
    ///
    /// The secret is validated by [`crate::AuthService::new`] and must be at
    /// least 32 bytes.
    pub fn with_hs256_secret(secret: impl Into<String>) -> Self {
        let secret = secret.into();
        Self {
            issuer: "agql-auth".to_string(),
            audience: "agql-auth-clients".to_string(),
            jwt_secret: secret.clone(),
            jwt_signing: JwtSigningConfig::Hs256 { secret },
            previous_verification_keys: Vec::new(),
            access_token_ttl: Duration::minutes(15),
            max_access_token_ttl: Duration::hours(24),
            max_session_bound_delegation_ttl: Duration::minutes(15),
            refresh_token_ttl: Duration::days(30),
            max_session_lifetime: Some(DEFAULT_MAX_SESSION_LIFETIME),
            access_token_scope_claim_format: AccessTokenScopeClaimFormat::Standard,
            legacy_scope_claims: LegacyScopeClaims::Reject,
            rate_limits: AuthRateLimitConfig::default(),
            password_hashing: PasswordHashingConfig::default(),
        }
    }

    /// Creates an RS256 configuration from PEM-encoded key material.
    ///
    /// The private key is used only for signing. The public key is used for
    /// local validation and JWKS export. `key_id` must be non-empty.
    pub fn with_rs256_pem(
        private_key_pem: impl Into<String>,
        public_key_pem: impl Into<String>,
        key_id: impl Into<String>,
    ) -> Self {
        Self {
            issuer: "agql-auth".to_string(),
            audience: "agql-auth-clients".to_string(),
            jwt_secret: String::new(),
            jwt_signing: JwtSigningConfig::Rs256 {
                private_key_pem: private_key_pem.into(),
                public_key_pem: public_key_pem.into(),
                key_id: key_id.into(),
            },
            previous_verification_keys: Vec::new(),
            access_token_ttl: Duration::minutes(15),
            max_access_token_ttl: Duration::hours(24),
            max_session_bound_delegation_ttl: Duration::minutes(15),
            refresh_token_ttl: Duration::days(30),
            max_session_lifetime: Some(DEFAULT_MAX_SESSION_LIFETIME),
            access_token_scope_claim_format: AccessTokenScopeClaimFormat::Standard,
            legacy_scope_claims: LegacyScopeClaims::Reject,
            rate_limits: AuthRateLimitConfig::default(),
            password_hashing: PasswordHashingConfig::default(),
        }
    }

    /// Replaces the local JWT signing configuration.
    ///
    /// This also keeps the legacy `jwt_secret` field in sync for HS256 callers.
    pub fn set_jwt_signing(&mut self, signing: JwtSigningConfig) {
        self.jwt_secret = match &signing {
            JwtSigningConfig::Hs256 { secret } => secret.clone(),
            JwtSigningConfig::Rs256 { .. } => String::new(),
        };
        self.jwt_signing = signing;
    }

    /// Adds a verification-only public key from an earlier RS256 signing key.
    ///
    /// See [`Self::previous_verification_keys`].
    #[must_use]
    pub fn with_previous_verification_key(
        mut self,
        key_id: impl Into<String>,
        public_key_pem: impl Into<String>,
    ) -> Self {
        self.previous_verification_keys
            .push(JwtVerificationKey::rs256_pem(key_id, public_key_pem));
        self
    }

    /// Selects the claim shape used for newly issued access-token scopes.
    #[must_use]
    pub fn with_access_token_scope_claim_format(
        mut self,
        format: AccessTokenScopeClaimFormat,
    ) -> Self {
        self.access_token_scope_claim_format = format;
        self
    }

    /// Selects whether validation accepts the pre-0.14 `scopes` array.
    #[must_use]
    pub fn with_legacy_scope_claims(mut self, policy: LegacyScopeClaims) -> Self {
        self.legacy_scope_claims = policy;
        self
    }

    /// Sets the maximum lifetime for existing-session-bound delegations.
    #[must_use]
    pub fn with_max_session_bound_delegation_ttl(mut self, ttl: Duration) -> Self {
        self.max_session_bound_delegation_ttl = ttl;
        self
    }

    pub(crate) fn validate(&self) -> crate::AuthResult<()> {
        self.rate_limits.validate()?;
        self.password_hashing.argon2()?;
        if self.issuer.trim().is_empty() || self.audience.trim().is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "issuer and audience must not be empty".to_string(),
            ));
        }
        let now = time::OffsetDateTime::now_utc();
        crate::util::checked_expiry(now, self.access_token_ttl, "access-token ttl")?;
        crate::util::checked_expiry(now, self.max_access_token_ttl, "access-token maximum ttl")?;
        crate::util::checked_expiry(now, self.refresh_token_ttl, "refresh-token ttl")?;
        if self.access_token_ttl > self.max_access_token_ttl {
            return Err(AuthError::InvalidConfiguration(
                "access-token ttl must not exceed the access-token maximum".to_string(),
            ));
        }
        if let Some(lifetime) = self.max_session_lifetime {
            crate::util::checked_expiry(now, lifetime, "maximum session lifetime")?;
        }

        if self.max_session_bound_delegation_ttl <= Duration::ZERO
            || self.max_session_bound_delegation_ttl > self.max_access_token_ttl
        {
            return Err(AuthError::InvalidConfiguration(
                "session-bound delegation ttl ceiling must be positive and not exceed the access-token maximum"
                    .to_string(),
            ));
        }
        if self.access_token_scope_claim_format == AccessTokenScopeClaimFormat::LegacyArray
            && self.legacy_scope_claims == LegacyScopeClaims::Reject
        {
            return Err(AuthError::InvalidConfiguration(
                "legacy scope issuance requires legacy scope validation during migration"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

/// Default for [`PasswordHashingConfig::max_password_bytes`].
pub const DEFAULT_MAX_PASSWORD_BYTES: usize = 1024;
/// Upper bound for [`PasswordHashingConfig::max_password_bytes`].
pub const MAX_PASSWORD_BYTES_LIMIT: usize = 4096;

/// Argon2id parameters for new password hashes, and the password length cap.
///
/// Verification reads the parameters stored in each hash, so changing these
/// affects new hashes only. After a successful login, use
/// [`crate::AuthService::password_hash_needs_rehash`] to find hashes made with
/// other parameters and replace them. The defaults match the `argon2` crate's
/// defaults (19 MiB, 2 iterations, 1 lane), the OWASP minimum for Argon2id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordHashingConfig {
    /// Longest password accepted, in UTF-8 bytes. Defaults to
    /// [`DEFAULT_MAX_PASSWORD_BYTES`]; at most [`MAX_PASSWORD_BYTES_LIMIT`].
    ///
    /// A longer password is never hashed. Hashing returns
    /// [`AuthError::PasswordTooLong`]; verification treats it as a wrong
    /// password, `InvalidCredentials`, so login counts it as a credential
    /// failure without queueing Argon2 work.
    pub max_password_bytes: usize,
    /// Argon2 memory cost in KiB.
    pub memory_kib: u32,
    /// Argon2 iterations (time cost).
    pub iterations: u32,
    /// Argon2 lanes (parallelism).
    pub parallelism: u32,
}

impl Default for PasswordHashingConfig {
    fn default() -> Self {
        Self {
            max_password_bytes: DEFAULT_MAX_PASSWORD_BYTES,
            memory_kib: argon2::Params::DEFAULT_M_COST,
            iterations: argon2::Params::DEFAULT_T_COST,
            parallelism: argon2::Params::DEFAULT_P_COST,
        }
    }
}

impl PasswordHashingConfig {
    pub(crate) fn argon2(&self) -> crate::AuthResult<argon2::Argon2<'static>> {
        if !(1..=MAX_PASSWORD_BYTES_LIMIT).contains(&self.max_password_bytes) {
            return Err(AuthError::InvalidConfiguration(format!(
                "maximum password length must be 1..={MAX_PASSWORD_BYTES_LIMIT} bytes"
            )));
        }
        let params = argon2::Params::new(self.memory_kib, self.iterations, self.parallelism, None)
            .map_err(|error| {
                AuthError::InvalidConfiguration(format!("invalid argon2 parameters: {error}"))
            })?;
        Ok(argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        ))
    }
}

/// Claim shape used when issuing access-token scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessTokenScopeClaimFormat {
    /// Emit the OAuth space-delimited `scope` string.
    #[default]
    Standard,
    /// Emit the pre-0.14 `scopes` string array.
    ///
    /// This exists only for staged migration and should not be selected for a
    /// new deployment.
    LegacyArray,
}

/// Policy for validating the pre-0.14 access-token `scopes` array.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LegacyScopeClaims {
    /// Migration opt-in: accept a legacy array when no conflicting standard
    /// claim is present.
    Accept,
    /// Reject every token containing the legacy array, including an empty one.
    /// The default since 0.27.
    #[default]
    Reject,
}

/// Abuse-protection configuration for authentication flows.
#[derive(Debug, Clone)]
pub struct AuthRateLimitConfig {
    /// Policy for credential verification failures.
    pub credential: AuthRateLimitPolicy,
    /// Policy for email/request initiation flows.
    pub request: AuthRateLimitPolicy,
}

impl Default for AuthRateLimitConfig {
    fn default() -> Self {
        Self {
            credential: AuthRateLimitPolicy {
                enabled: true,
                window: Duration::minutes(15),
                backoff_after_attempts: 3,
                max_attempts_before_lockout: 10,
                base_backoff: Duration::seconds(1),
                max_backoff: Duration::minutes(5),
                lockout_duration: Duration::minutes(15),
                state_ttl: Duration::hours(1),
            },
            request: AuthRateLimitPolicy {
                enabled: true,
                window: Duration::hours(1),
                backoff_after_attempts: 1,
                max_attempts_before_lockout: 5,
                base_backoff: Duration::minutes(1),
                max_backoff: Duration::hours(1),
                lockout_duration: Duration::hours(1),
                state_ttl: Duration::hours(6),
            },
        }
    }
}

impl AuthRateLimitConfig {
    pub(crate) fn validate(&self) -> crate::AuthResult<()> {
        self.credential.validate("credential rate limit")?;
        self.request.validate("request rate limit")
    }
}

/// Exponential-backoff and lockout policy for a family of auth flows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRateLimitPolicy {
    /// Disables checks and recording when `false`.
    pub enabled: bool,
    /// Rolling window used to count attempts.
    pub window: Duration,
    /// First attempt count that starts exponential backoff.
    pub backoff_after_attempts: u32,
    /// First attempt count that starts a temporary lockout.
    pub max_attempts_before_lockout: u32,
    /// Initial backoff duration.
    pub base_backoff: Duration,
    /// Maximum exponential-backoff duration.
    pub max_backoff: Duration,
    /// Lockout duration once `max_attempts_before_lockout` is reached.
    pub lockout_duration: Duration,
    /// Expiry for persisted state after the latest recorded attempt.
    pub state_ttl: Duration,
}

impl AuthRateLimitPolicy {
    /// Returns a disabled policy.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            window: Duration::minutes(1),
            backoff_after_attempts: 1,
            max_attempts_before_lockout: 1,
            base_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
            lockout_duration: Duration::ZERO,
            state_ttl: Duration::minutes(1),
        }
    }

    fn validate(&self, name: &str) -> crate::AuthResult<()> {
        if !self.enabled {
            return Ok(());
        }

        if self.window <= Duration::ZERO {
            return Err(AuthError::InvalidConfiguration(format!(
                "{name} window must be greater than zero"
            )));
        }
        if self.backoff_after_attempts == 0 {
            return Err(AuthError::InvalidConfiguration(format!(
                "{name} backoff_after_attempts must be greater than zero"
            )));
        }
        if self.max_attempts_before_lockout == 0 {
            return Err(AuthError::InvalidConfiguration(format!(
                "{name} max_attempts_before_lockout must be greater than zero"
            )));
        }
        if self.backoff_after_attempts > self.max_attempts_before_lockout {
            return Err(AuthError::InvalidConfiguration(format!(
                "{name} backoff_after_attempts must not exceed max_attempts_before_lockout"
            )));
        }
        if self.base_backoff < Duration::ZERO
            || self.max_backoff < Duration::ZERO
            || self.lockout_duration < Duration::ZERO
        {
            return Err(AuthError::InvalidConfiguration(format!(
                "{name} durations must not be negative"
            )));
        }
        if self.max_backoff < self.base_backoff {
            return Err(AuthError::InvalidConfiguration(format!(
                "{name} max_backoff must not be less than base_backoff"
            )));
        }
        if self.state_ttl <= Duration::ZERO {
            return Err(AuthError::InvalidConfiguration(format!(
                "{name} state_ttl must be greater than zero"
            )));
        }

        Ok(())
    }
}

/// Signing configuration for locally issued `agql-auth` JWTs.
#[derive(Clone)]
pub enum JwtSigningConfig {
    /// HS256 signing with a shared symmetric secret.
    Hs256 {
        /// Shared signing and validation secret. Must be at least 32 bytes.
        secret: String,
    },
    /// RS256 signing with private key material and public-key validation.
    Rs256 {
        /// PEM-encoded RSA private key used only for signing.
        private_key_pem: String,
        /// PEM-encoded RSA public key used for local validation and JWKS export.
        public_key_pem: String,
        /// Key identifier placed in JWT headers and JWKS output.
        key_id: String,
    },
}

impl fmt::Debug for JwtSigningConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JwtSigningConfig::Hs256 { .. } => f
                .debug_struct("Hs256")
                .field("secret", &"[redacted]")
                .finish(),
            JwtSigningConfig::Rs256 { key_id, .. } => f
                .debug_struct("Rs256")
                .field("private_key_pem", &"[redacted]")
                .field("public_key_pem", &"[redacted]")
                .field("key_id", key_id)
                .finish(),
        }
    }
}

/// Maximum number of verification-only previous signing keys.
pub const MAX_PREVIOUS_VERIFICATION_KEYS: usize = 8;

/// Verification-only public key of an earlier local signing key.
///
/// Configure it through [`AuthConfig::previous_verification_keys`]. Public key
/// material is not secret, so `Debug` shows the key id only for brevity.
#[derive(Clone, PartialEq, Eq)]
pub struct JwtVerificationKey {
    key_id: String,
    public_key_pem: String,
}

impl JwtVerificationKey {
    /// Creates an RS256 verification key from a PEM-encoded public key.
    pub fn rs256_pem(key_id: impl Into<String>, public_key_pem: impl Into<String>) -> Self {
        Self {
            key_id: key_id.into(),
            public_key_pem: public_key_pem.into(),
        }
    }

    /// Key identifier the earlier key placed in JWT headers.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// PEM-encoded RSA public key.
    pub fn public_key_pem(&self) -> &str {
        &self.public_key_pem
    }
}

impl fmt::Debug for JwtVerificationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtVerificationKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// Metadata captured when issuing or rotating a local session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientMetadata {
    /// Client IP address, if the host chooses to record it.
    pub ip_address: Option<String>,
    /// Client user-agent, if the host chooses to record it.
    pub user_agent: Option<String>,
}

/// Built-in provider behavior for OIDC validation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OidcProviderKind {
    /// Standards-based OIDC validation without Microsoft-specific tenant rules.
    Generic,
    /// Microsoft Entra ID validation with tenant and consumer-account checks.
    MicrosoftEntra,
}

/// OAuth 2.0 authorization response mode.
///
/// The mode is sent as `response_mode` and bound into the one-time state, so a
/// callback delivered in a different mode is refused.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OAuthResponseMode {
    /// Parameters arrive in the redirect URI query string (`GET`).
    #[default]
    Query,
    /// Parameters arrive as an `application/x-www-form-urlencoded` body in a
    /// cross-site `POST` (OAuth 2.0 Form Post Response Mode).
    FormPost,
}

impl OAuthResponseMode {
    /// Protocol value for the `response_mode` parameter.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::FormPost => "form_post",
        }
    }

    /// Whether this is the default query mode.
    pub fn is_query(&self) -> bool {
        matches!(self, Self::Query)
    }
}

/// How a callback proves it returns to the browser that started the flow.
///
/// With [`Self::Required`] (the default) every authorization request returns a
/// random `browser_binding` secret that the host stores in a cookie on the
/// initiating browser. Only its SHA-256 hash is kept in the one-time state, and
/// the callback must present the raw value. A callback without it, or with a
/// different value, is refused with [`AuthError::InvalidOAuthState`] after the
/// state is consumed. This stops login CSRF: an attacker cannot make a victim's
/// browser complete a flow the attacker started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OAuthBrowserBinding {
    /// Issue a per-request binding secret and require it at the callback.
    #[default]
    Required,
    /// Opt out: no binding secret is issued or checked. Use this only when the
    /// host already ties `state` to the initiating browser itself, for example
    /// by keeping the raw state in its own server-side session and comparing it
    /// before calling the provider.
    NotRequiredHostBindsState,
}

impl OAuthBrowserBinding {
    /// Whether the binding secret is issued and required.
    pub fn is_required(&self) -> bool {
        matches!(self, Self::Required)
    }
}

/// Provider-agnostic OIDC configuration.
///
/// `Debug` redacts `client_secret` and `client_jwt`.
#[derive(Clone, Serialize, Deserialize)]
pub struct OidcProviderConfig {
    /// Stable provider name used in state and external-identity storage. It
    /// must not be shared with an [`crate::OAuth2Provider`] or another provider.
    pub provider_name: String,
    /// Provider-specific validation behavior.
    pub provider_kind: OidcProviderKind,
    /// URL of the provider's `.well-known/openid-configuration` document. It
    /// must be an `https://` URL (`http://` only for loopback hosts).
    pub discovery_url: String,
    /// Expected issuer identifier. The discovery document's `issuer` must be
    /// identical to it (OIDC Discovery section 4.3). `None` derives it from
    /// `discovery_url`, which must then end in
    /// `/.well-known/openid-configuration`: the expected issuer is the prefix,
    /// with or without one trailing `/`. Microsoft Entra `common` and
    /// `organizations` expect the literal `{tenantid}` template, which is
    /// substituted only when validating ID tokens.
    #[serde(default)]
    pub issuer: Option<String>,
    /// OAuth2 client ID.
    pub client_id: String,
    /// Optional client secret for confidential clients. Deserialized but
    /// never serialized; `Debug` redacts it.
    #[serde(skip_serializing)]
    pub client_secret: Option<String>,
    /// Redirect URI registered with the provider: an absolute `https://` URL
    /// (`http://` only for loopback hosts) without a fragment. Give every
    /// provider its own redirect URI, so a callback can only reach the
    /// provider that started it.
    pub redirect_uri: String,
    /// Requested OAuth/OIDC scopes before optional `offline_access` is appended.
    pub requested_scopes: Vec<String>,
    /// Whether to request `offline_access`.
    pub request_offline_access: bool,
    /// Allowed tenant IDs for providers that expose tenant claims.
    pub allowed_tenants: Vec<String>,
    /// Allowed issuer strings. Microsoft templates may include `{tenantid}`.
    pub allowed_issuers: Vec<String>,
    /// Whether Microsoft consumer accounts are allowed.
    pub allow_consumer_accounts: bool,
    /// Time to keep fetched JWKS documents in memory.
    pub jwks_cache_ttl: Duration,
    /// Time to keep fetched discovery documents in memory.
    pub discovery_cache_ttl: Duration,
    /// Minimum delay between forced JWKS refreshes for unknown key IDs.
    pub jwks_forced_refresh_cooldown: Duration,
    /// Extra trusted audiences accepted in multi-audience ID tokens.
    pub allowed_additional_audiences: Vec<String>,
    /// Permitted clock skew for token validation.
    pub clock_skew: Duration,
    /// Lifetime for OAuth state records, at most
    /// [`crate::MAX_OAUTH_STATE_TTL_SECONDS`].
    pub state_ttl: Duration,
    /// Allowed ID-token signature algorithms. All must belong to one key
    /// family (RSA `RS*`/`PS*`, EC `ES256`/`ES384`, or `EdDSA`); symmetric
    /// `HS*` algorithms are refused.
    pub allowed_id_token_algs: Vec<String>,
    /// Authorization response mode. Defaults to [`OAuthResponseMode::Query`].
    #[serde(default)]
    pub response_mode: OAuthResponseMode,
    /// Browser binding of the one-time state. Defaults to
    /// [`OAuthBrowserBinding::Required`].
    #[serde(default)]
    pub browser_binding: OAuthBrowserBinding,
    /// Token-endpoint client authentication. Defaults to
    /// [`TokenEndpointAuthMethod::ClientSecretPost`].
    #[serde(default)]
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    /// Host-supplied signer for `private_key_jwt` assertions or a signed
    /// `client_secret`. Mutually exclusive with `client_secret`. Never
    /// serialized; a deserialized configuration must be given its signer again.
    #[serde(skip)]
    pub client_jwt: Option<ClientJwtSigner>,
}

impl fmt::Debug for OidcProviderConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcProviderConfig")
            .field("provider_name", &self.provider_name)
            .field("provider_kind", &self.provider_kind)
            .field("discovery_url", &self.discovery_url)
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[redacted]"),
            )
            .field("redirect_uri", &self.redirect_uri)
            .field("requested_scopes", &self.requested_scopes)
            .field("request_offline_access", &self.request_offline_access)
            .field("allowed_tenants", &self.allowed_tenants)
            .field("allowed_issuers", &self.allowed_issuers)
            .field("allow_consumer_accounts", &self.allow_consumer_accounts)
            .field("jwks_cache_ttl", &self.jwks_cache_ttl)
            .field("discovery_cache_ttl", &self.discovery_cache_ttl)
            .field(
                "jwks_forced_refresh_cooldown",
                &self.jwks_forced_refresh_cooldown,
            )
            .field(
                "allowed_additional_audiences",
                &self.allowed_additional_audiences,
            )
            .field("clock_skew", &self.clock_skew)
            .field("state_ttl", &self.state_ttl)
            .field("allowed_id_token_algs", &self.allowed_id_token_algs)
            .field("response_mode", &self.response_mode)
            .field("browser_binding", &self.browser_binding)
            .field(
                "token_endpoint_auth_method",
                &self.token_endpoint_auth_method,
            )
            .field("client_jwt", &self.client_jwt)
            .finish()
    }
}

impl Drop for OidcProviderConfig {
    fn drop(&mut self) {
        zeroize_secret(&mut self.client_secret);
    }
}

impl OidcProviderConfig {
    /// Creates a generic OIDC provider config with `openid profile email`.
    pub fn new(
        provider_name: impl Into<String>,
        discovery_url: impl Into<String>,
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            provider_name: provider_name.into(),
            provider_kind: OidcProviderKind::Generic,
            discovery_url: discovery_url.into(),
            issuer: None,
            client_id: client_id.into(),
            client_secret: None,
            redirect_uri: redirect_uri.into(),
            requested_scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            request_offline_access: false,
            allowed_tenants: Vec::new(),
            allowed_issuers: Vec::new(),
            allow_consumer_accounts: false,
            jwks_cache_ttl: Duration::hours(1),
            discovery_cache_ttl: Duration::hours(1),
            jwks_forced_refresh_cooldown: Duration::seconds(60),
            allowed_additional_audiences: Vec::new(),
            clock_skew: Duration::seconds(60),
            state_ttl: Duration::minutes(10),
            allowed_id_token_algs: vec!["RS256".to_string()],
            response_mode: OAuthResponseMode::Query,
            browser_binding: OAuthBrowserBinding::Required,
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretPost,
            client_jwt: None,
        }
    }

    /// Validates required provider configuration.
    pub fn validate(&self) -> crate::AuthResult<()> {
        if self.provider_name.trim().is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "OIDC provider_name must not be empty".to_string(),
            ));
        }

        if !is_secure_endpoint_url(&self.discovery_url) {
            return Err(AuthError::InvalidConfiguration(
                "OIDC discovery_url must be an https URL (http only for loopback hosts)"
                    .to_string(),
            ));
        }

        if self
            .issuer
            .as_deref()
            .is_some_and(|issuer| !is_secure_endpoint_url(issuer))
        {
            return Err(AuthError::InvalidConfiguration(
                "OIDC issuer must be an https URL (http only for loopback hosts)".to_string(),
            ));
        }

        if self.expected_discovery_issuers().is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "OIDC issuer must be set when discovery_url does not end in /.well-known/openid-configuration"
                    .to_string(),
            ));
        }

        if self.client_id.trim().is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "OIDC client_id must not be empty".to_string(),
            ));
        }

        if !is_valid_redirect_uri(&self.redirect_uri) {
            return Err(AuthError::InvalidConfiguration(
                "OIDC redirect_uri must be an absolute https URL without a fragment (http only for loopback hosts)"
                    .to_string(),
            ));
        }

        if !self.requested_scopes.iter().any(|scope| scope == "openid") {
            return Err(AuthError::InvalidConfiguration(
                "OIDC requested_scopes must include openid".to_string(),
            ));
        }

        if self.jwks_cache_ttl <= Duration::ZERO {
            return Err(AuthError::InvalidConfiguration(
                "OIDC jwks_cache_ttl must be greater than zero".to_string(),
            ));
        }

        if self.discovery_cache_ttl <= Duration::ZERO {
            return Err(AuthError::InvalidConfiguration(
                "OIDC discovery_cache_ttl must be greater than zero".to_string(),
            ));
        }

        if self.jwks_forced_refresh_cooldown < Duration::ZERO {
            return Err(AuthError::InvalidConfiguration(
                "OIDC jwks_forced_refresh_cooldown must not be negative".to_string(),
            ));
        }

        if self
            .allowed_additional_audiences
            .iter()
            .any(|audience| audience.trim().is_empty())
        {
            return Err(AuthError::InvalidConfiguration(
                "OIDC allowed_additional_audiences must not contain empty values".to_string(),
            ));
        }

        if self.clock_skew < Duration::ZERO {
            return Err(AuthError::InvalidConfiguration(
                "OIDC clock_skew must not be negative".to_string(),
            ));
        }

        if self.state_ttl <= Duration::ZERO
            || self.state_ttl > Duration::seconds(crate::MAX_OAUTH_STATE_TTL_SECONDS)
        {
            return Err(AuthError::InvalidConfiguration(
                "OIDC state_ttl must be greater than zero and at most the supported maximum"
                    .to_string(),
            ));
        }

        self.id_token_algorithms()?;

        validate_client_authentication(
            "OIDC",
            self.token_endpoint_auth_method,
            &self.client_id,
            self.client_secret.as_deref(),
            self.client_jwt.as_ref(),
        )?;

        Ok(())
    }

    /// Parses `allowed_id_token_algs`, requiring one asymmetric key family.
    pub(crate) fn id_token_algorithms(&self) -> crate::AuthResult<Vec<Algorithm>> {
        let invalid = |message: &str| AuthError::InvalidConfiguration(message.to_string());
        let mut family = None;
        let mut algorithms = Vec::with_capacity(self.allowed_id_token_algs.len());
        for name in &self.allowed_id_token_algs {
            let algorithm = Algorithm::from_str(name).map_err(|_| {
                invalid("OIDC allowed_id_token_algs contains an unsupported algorithm")
            })?;
            let algorithm_family = algorithm.family();
            if algorithm_family == AlgorithmFamily::Hmac {
                return Err(invalid(
                    "OIDC allowed_id_token_algs must not contain symmetric HS algorithms",
                ));
            }
            if family.is_some_and(|family| family != algorithm_family) {
                return Err(invalid(
                    "OIDC allowed_id_token_algs must all belong to one key family",
                ));
            }
            family = Some(algorithm_family);
            if !algorithms.contains(&algorithm) {
                algorithms.push(algorithm);
            }
        }
        if algorithms.is_empty() {
            return Err(invalid("OIDC allowed_id_token_algs must not be empty"));
        }
        Ok(algorithms)
    }

    /// Issuer values the discovery document may state, compared exactly.
    ///
    /// Empty when no issuer is configured and none can be derived.
    pub(crate) fn expected_discovery_issuers(&self) -> Vec<String> {
        if let Some(issuer) = &self.issuer {
            return vec![issuer.clone()];
        }
        let Some(prefix) = self
            .discovery_url
            .strip_suffix("/.well-known/openid-configuration")
            .filter(|prefix| is_secure_endpoint_url(prefix))
        else {
            return Vec::new();
        };
        if self.provider_kind == OidcProviderKind::MicrosoftEntra
            && let Some(tenant) = prefix
                .strip_prefix(MICROSOFT_LOGIN_ORIGIN)
                .and_then(|path| path.strip_suffix("/v2.0"))
        {
            match tenant {
                "common" | "organizations" => {
                    return vec![microsoft_v2_issuer(MICROSOFT_TENANT_TEMPLATE)];
                }
                "consumers" => {
                    return vec![microsoft_v2_issuer(
                        crate::oidc::MICROSOFT_CONSUMER_TENANT_ID,
                    )];
                }
                _ => {}
            }
        }
        vec![prefix.to_string(), format!("{prefix}/")]
    }

    /// Returns requested scopes with `offline_access` appended when configured.
    pub fn scopes(&self) -> Vec<String> {
        let mut scopes = self.requested_scopes.clone();
        if self.request_offline_access && !scopes.iter().any(|scope| scope == "offline_access") {
            scopes.push("offline_access".to_string());
        }
        scopes
    }
}

/// Microsoft Entra tenant mode.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MicrosoftEntraTenant {
    /// A single tenant by tenant ID.
    TenantId(String),
    /// Work or school accounts from any organization.
    Organizations,
    /// Both organization and consumer accounts, subject to account policy.
    Common,
    /// Consumer accounts only. Disabled unless explicitly selected.
    Consumers,
}

impl MicrosoftEntraTenant {
    /// Returns the path segment used in Microsoft discovery URLs.
    pub fn as_path_segment(&self) -> &str {
        match self {
            MicrosoftEntraTenant::TenantId(tenant_id) => tenant_id.as_str(),
            MicrosoftEntraTenant::Organizations => "organizations",
            MicrosoftEntraTenant::Common => "common",
            MicrosoftEntraTenant::Consumers => "consumers",
        }
    }
}

/// Microsoft Entra ID OIDC configuration helper.
///
/// `Debug` redacts `client_secret`.
#[derive(Clone, Serialize, Deserialize)]
pub struct MicrosoftEntraConfig {
    /// Stable provider name used in state and external-identity storage.
    pub provider_name: String,
    /// Tenant mode for Microsoft endpoints.
    pub tenant: MicrosoftEntraTenant,
    /// Microsoft application client ID.
    pub client_id: String,
    /// Optional client secret for confidential clients. Deserialized but
    /// never serialized; `Debug` redacts it.
    #[serde(skip_serializing)]
    pub client_secret: Option<String>,
    /// Registered redirect URI.
    pub redirect_uri: String,
    /// Allowed tenant IDs. Empty means any tenant accepted by the tenant mode.
    pub allowed_tenants: Vec<String>,
    /// Allowed issuer strings. Templates may include `{tenantid}`.
    pub allowed_issuers: Vec<String>,
    /// Requested OAuth/OIDC scopes before optional `offline_access` is appended.
    pub requested_scopes: Vec<String>,
    /// Whether to request `offline_access`.
    pub request_offline_access: bool,
    /// Time to keep fetched JWKS documents in memory.
    pub jwks_cache_ttl: Duration,
    /// Time to keep fetched discovery documents in memory.
    pub discovery_cache_ttl: Duration,
    /// Minimum delay between forced JWKS refreshes for unknown key IDs.
    pub jwks_forced_refresh_cooldown: Duration,
    /// Extra trusted audiences accepted in multi-audience ID tokens.
    pub allowed_additional_audiences: Vec<String>,
    /// Permitted clock skew for token validation.
    pub clock_skew: Duration,
    /// Lifetime for OAuth state records.
    pub state_ttl: Duration,
    /// Whether Microsoft consumer accounts are allowed.
    pub allow_consumers: bool,
}

impl fmt::Debug for MicrosoftEntraConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MicrosoftEntraConfig")
            .field("provider_name", &self.provider_name)
            .field("tenant", &self.tenant)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[redacted]"),
            )
            .field("redirect_uri", &self.redirect_uri)
            .field("allowed_tenants", &self.allowed_tenants)
            .field("allowed_issuers", &self.allowed_issuers)
            .field("requested_scopes", &self.requested_scopes)
            .field("request_offline_access", &self.request_offline_access)
            .field("jwks_cache_ttl", &self.jwks_cache_ttl)
            .field("discovery_cache_ttl", &self.discovery_cache_ttl)
            .field(
                "jwks_forced_refresh_cooldown",
                &self.jwks_forced_refresh_cooldown,
            )
            .field(
                "allowed_additional_audiences",
                &self.allowed_additional_audiences,
            )
            .field("clock_skew", &self.clock_skew)
            .field("state_ttl", &self.state_ttl)
            .field("allow_consumers", &self.allow_consumers)
            .finish()
    }
}

impl Drop for MicrosoftEntraConfig {
    fn drop(&mut self) {
        zeroize_secret(&mut self.client_secret);
    }
}

impl MicrosoftEntraConfig {
    /// Creates a single-tenant Microsoft Entra configuration.
    pub fn single_tenant(
        tenant_id: impl Into<String>,
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        let tenant_id = tenant_id.into();
        Self {
            provider_name: "microsoft".to_string(),
            tenant: MicrosoftEntraTenant::TenantId(tenant_id.clone()),
            client_id: client_id.into(),
            client_secret: None,
            redirect_uri: redirect_uri.into(),
            allowed_tenants: vec![tenant_id.clone()],
            allowed_issuers: vec![microsoft_v2_issuer(&tenant_id)],
            requested_scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            request_offline_access: false,
            jwks_cache_ttl: Duration::hours(1),
            discovery_cache_ttl: Duration::hours(1),
            jwks_forced_refresh_cooldown: Duration::seconds(60),
            allowed_additional_audiences: Vec::new(),
            clock_skew: Duration::seconds(60),
            state_ttl: Duration::minutes(10),
            allow_consumers: false,
        }
    }

    /// Creates a multi-tenant work/school configuration.
    pub fn organizations(client_id: impl Into<String>, redirect_uri: impl Into<String>) -> Self {
        Self::multi_tenant(MicrosoftEntraTenant::Organizations, client_id, redirect_uri)
    }

    /// Creates a Microsoft `common` configuration.
    pub fn common(client_id: impl Into<String>, redirect_uri: impl Into<String>) -> Self {
        Self::multi_tenant(MicrosoftEntraTenant::Common, client_id, redirect_uri)
    }

    /// Creates a consumer-account configuration and explicitly enables consumers.
    pub fn consumers(client_id: impl Into<String>, redirect_uri: impl Into<String>) -> Self {
        let mut config =
            Self::multi_tenant(MicrosoftEntraTenant::Consumers, client_id, redirect_uri);
        config.allow_consumers = true;
        config
    }

    fn multi_tenant(
        tenant: MicrosoftEntraTenant,
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            provider_name: "microsoft".to_string(),
            tenant,
            client_id: client_id.into(),
            client_secret: None,
            redirect_uri: redirect_uri.into(),
            allowed_tenants: Vec::new(),
            allowed_issuers: vec![microsoft_v2_issuer(MICROSOFT_TENANT_TEMPLATE)],
            requested_scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            request_offline_access: false,
            jwks_cache_ttl: Duration::hours(1),
            discovery_cache_ttl: Duration::hours(1),
            jwks_forced_refresh_cooldown: Duration::seconds(60),
            allowed_additional_audiences: Vec::new(),
            clock_skew: Duration::seconds(60),
            state_ttl: Duration::minutes(10),
            allow_consumers: false,
        }
    }

    /// Converts the Microsoft helper into provider-agnostic OIDC configuration.
    ///
    /// The expected discovery issuer is the tenant's v2.0 issuer, the
    /// `{tenantid}` template for `organizations` and `common`, or the Microsoft
    /// consumer tenant's issuer for `consumers`.
    pub fn into_oidc_provider_config(mut self) -> crate::AuthResult<OidcProviderConfig> {
        if matches!(self.tenant, MicrosoftEntraTenant::Consumers) && !self.allow_consumers {
            return Err(AuthError::InvalidConfiguration(
                "Microsoft consumers tenant mode must be explicitly enabled".to_string(),
            ));
        }

        let issuer = match &self.tenant {
            MicrosoftEntraTenant::TenantId(tenant_id) => microsoft_v2_issuer(tenant_id),
            MicrosoftEntraTenant::Organizations | MicrosoftEntraTenant::Common => {
                microsoft_v2_issuer(MICROSOFT_TENANT_TEMPLATE)
            }
            MicrosoftEntraTenant::Consumers => {
                microsoft_v2_issuer(crate::oidc::MICROSOFT_CONSUMER_TENANT_ID)
            }
        };
        let mut config = OidcProviderConfig::new(
            std::mem::take(&mut self.provider_name),
            format!(
                "{MICROSOFT_LOGIN_ORIGIN}{}/v2.0/.well-known/openid-configuration",
                self.tenant.as_path_segment()
            ),
            std::mem::take(&mut self.client_id),
            std::mem::take(&mut self.redirect_uri),
        );
        config.provider_kind = OidcProviderKind::MicrosoftEntra;
        config.issuer = Some(issuer);
        config.client_secret = self.client_secret.take();
        config.allowed_tenants = std::mem::take(&mut self.allowed_tenants);
        config.allowed_issuers = std::mem::take(&mut self.allowed_issuers);
        config.allow_consumer_accounts = self.allow_consumers;
        config.requested_scopes = std::mem::take(&mut self.requested_scopes);
        config.request_offline_access = self.request_offline_access;
        config.jwks_cache_ttl = self.jwks_cache_ttl;
        config.discovery_cache_ttl = self.discovery_cache_ttl;
        config.jwks_forced_refresh_cooldown = self.jwks_forced_refresh_cooldown;
        config.allowed_additional_audiences =
            std::mem::take(&mut self.allowed_additional_audiences);
        config.clock_skew = self.clock_skew;
        config.state_ttl = self.state_ttl;
        config.validate()?;
        Ok(config)
    }
}

const MICROSOFT_LOGIN_ORIGIN: &str = "https://login.microsoftonline.com/";
const MICROSOFT_TENANT_TEMPLATE: &str = "{tenantid}";

fn microsoft_v2_issuer(tenant_id: &str) -> String {
    format!("{MICROSOFT_LOGIN_ORIGIN}{tenant_id}/v2.0")
}

/// Overwrites a secret's bytes before its allocation is released.
pub(crate) fn zeroize_secret(secret: &mut Option<String>) {
    if let Some(secret) = secret.as_mut() {
        secret.zeroize();
    }
}
