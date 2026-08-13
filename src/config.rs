use std::fmt;

use serde::{Deserialize, Serialize};
use time::Duration;

use crate::errors::AuthError;

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
    /// Access-token lifetime.
    pub access_token_ttl: Duration,
    /// Maximum allowed access-token lifetime for custom TTLs.
    ///
    /// Used by access-token-only grants and similar short-lived issuance paths.
    pub max_access_token_ttl: Duration,
    /// Maximum lifetime of an existing-session-bound delegated access token.
    ///
    /// Delegated expiry is also clamped to the requested TTL and the remaining
    /// authoritative session lifetime. Defaults to 15 minutes.
    pub max_session_bound_delegation_ttl: Duration,
    /// Refresh-token lifetime.
    pub refresh_token_ttl: Duration,
    /// Claim shape used for newly issued access-token scopes.
    ///
    /// Version 0.14 defaults to [`AccessTokenScopeClaimFormat::Standard`]. Use
    /// [`AccessTokenScopeClaimFormat::LegacyArray`] only during a staged
    /// migration for consumers that cannot yet read the OAuth `scope` claim.
    pub access_token_scope_claim_format: AccessTokenScopeClaimFormat,
    /// Whether access-token validation accepts the pre-0.14 `scopes` array.
    ///
    /// Keep this at [`LegacyScopeClaims::Accept`] until every access token
    /// issued before the migration has expired, then switch to
    /// [`LegacyScopeClaims::Reject`]. A token containing conflicting `scope`
    /// and `scopes` values is rejected in either mode.
    pub legacy_scope_claims: LegacyScopeClaims,
    /// Abuse-protection settings for credential and request flows.
    pub rate_limits: AuthRateLimitConfig,
}

impl fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthConfig")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("jwt_secret", &"[redacted]")
            .field("jwt_signing", &self.jwt_signing)
            .field("access_token_ttl", &self.access_token_ttl)
            .field("max_access_token_ttl", &self.max_access_token_ttl)
            .field(
                "max_session_bound_delegation_ttl",
                &self.max_session_bound_delegation_ttl,
            )
            .field("refresh_token_ttl", &self.refresh_token_ttl)
            .field(
                "access_token_scope_claim_format",
                &self.access_token_scope_claim_format,
            )
            .field("legacy_scope_claims", &self.legacy_scope_claims)
            .field("rate_limits", &self.rate_limits)
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
            access_token_ttl: Duration::minutes(15),
            max_access_token_ttl: Duration::hours(24),
            max_session_bound_delegation_ttl: Duration::minutes(15),
            refresh_token_ttl: Duration::days(30),
            access_token_scope_claim_format: AccessTokenScopeClaimFormat::Standard,
            legacy_scope_claims: LegacyScopeClaims::Accept,
            rate_limits: AuthRateLimitConfig::default(),
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
            access_token_ttl: Duration::minutes(15),
            max_access_token_ttl: Duration::hours(24),
            max_session_bound_delegation_ttl: Duration::minutes(15),
            refresh_token_ttl: Duration::days(30),
            access_token_scope_claim_format: AccessTokenScopeClaimFormat::Standard,
            legacy_scope_claims: LegacyScopeClaims::Accept,
            rate_limits: AuthRateLimitConfig::default(),
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
    /// Accept a legacy array when no conflicting standard claim is present.
    #[default]
    Accept,
    /// Reject every token containing the legacy array, including an empty one.
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

/// Provider-agnostic OIDC configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcProviderConfig {
    /// Stable provider name used in state and external-identity storage.
    pub provider_name: String,
    /// Provider-specific validation behavior.
    pub provider_kind: OidcProviderKind,
    /// URL of the provider's `.well-known/openid-configuration` document.
    pub discovery_url: String,
    /// OAuth2 client ID.
    pub client_id: String,
    /// Optional client secret for confidential clients.
    pub client_secret: Option<String>,
    /// Redirect URI registered with the provider.
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
    /// Lifetime for OAuth state records.
    pub state_ttl: Duration,
    /// Allowed ID-token signature algorithms.
    pub allowed_id_token_algs: Vec<String>,
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
        }
    }

    /// Validates required provider configuration.
    pub fn validate(&self) -> crate::AuthResult<()> {
        if self.provider_name.trim().is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "OIDC provider_name must not be empty".to_string(),
            ));
        }

        if self.discovery_url.trim().is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "OIDC discovery_url must not be empty".to_string(),
            ));
        }

        if self.client_id.trim().is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "OIDC client_id must not be empty".to_string(),
            ));
        }

        if self.redirect_uri.trim().is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "OIDC redirect_uri must not be empty".to_string(),
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

        if self.state_ttl <= Duration::ZERO {
            return Err(AuthError::InvalidConfiguration(
                "OIDC state_ttl must be greater than zero".to_string(),
            ));
        }

        if self.allowed_id_token_algs.is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "OIDC allowed_id_token_algs must not be empty".to_string(),
            ));
        }

        Ok(())
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicrosoftEntraConfig {
    /// Stable provider name used in state and external-identity storage.
    pub provider_name: String,
    /// Tenant mode for Microsoft endpoints.
    pub tenant: MicrosoftEntraTenant,
    /// Microsoft application client ID.
    pub client_id: String,
    /// Optional client secret for confidential clients.
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
            allowed_issuers: vec!["https://login.microsoftonline.com/{tenantid}/v2.0".to_string()],
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
    pub fn into_oidc_provider_config(self) -> crate::AuthResult<OidcProviderConfig> {
        if matches!(self.tenant, MicrosoftEntraTenant::Consumers) && !self.allow_consumers {
            return Err(AuthError::InvalidConfiguration(
                "Microsoft consumers tenant mode must be explicitly enabled".to_string(),
            ));
        }

        let mut config = OidcProviderConfig::new(
            self.provider_name,
            format!(
                "https://login.microsoftonline.com/{}/v2.0/.well-known/openid-configuration",
                self.tenant.as_path_segment()
            ),
            self.client_id,
            self.redirect_uri,
        );
        config.provider_kind = OidcProviderKind::MicrosoftEntra;
        config.client_secret = self.client_secret;
        config.allowed_tenants = self.allowed_tenants;
        config.allowed_issuers = self.allowed_issuers;
        config.allow_consumer_accounts = self.allow_consumers;
        config.requested_scopes = self.requested_scopes;
        config.request_offline_access = self.request_offline_access;
        config.jwks_cache_ttl = self.jwks_cache_ttl;
        config.discovery_cache_ttl = self.discovery_cache_ttl;
        config.jwks_forced_refresh_cooldown = self.jwks_forced_refresh_cooldown;
        config.allowed_additional_audiences = self.allowed_additional_audiences;
        config.clock_skew = self.clock_skew;
        config.state_ttl = self.state_ttl;
        config.validate()?;
        Ok(config)
    }
}

fn microsoft_v2_issuer(tenant_id: &str) -> String {
    format!("https://login.microsoftonline.com/{tenant_id}/v2.0")
}
