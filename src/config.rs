use std::fmt;

use serde::{Deserialize, Serialize};
use time::Duration;

use crate::errors::AuthError;

/// Runtime configuration for [`crate::AuthService`].
///
/// `AuthConfig::new(secret)` and [`AuthConfig::with_hs256_secret`] preserve the
/// legacy HS256 behavior. Use [`AuthConfig::with_rs256_pem`] when local
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
    /// New code should prefer [`AuthConfig::jwt_signing`].
    pub jwt_secret: String,
    /// Configured local JWT signing mode.
    pub jwt_signing: JwtSigningConfig,
    /// Access-token lifetime.
    pub access_token_ttl: Duration,
    /// Refresh-token lifetime.
    pub refresh_token_ttl: Duration,
}

impl fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthConfig")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("jwt_secret", &"[redacted]")
            .field("jwt_signing", &self.jwt_signing)
            .field("access_token_ttl", &self.access_token_ttl)
            .field("refresh_token_ttl", &self.refresh_token_ttl)
            .finish()
    }
}

impl AuthConfig {
    /// Creates a legacy HS256 configuration from a symmetric secret.
    pub fn new(jwt_secret: impl Into<String>) -> Self {
        Self::with_hs256_secret(jwt_secret)
    }

    /// Creates an explicit HS256 configuration from a symmetric secret.
    pub fn with_hs256_secret(secret: impl Into<String>) -> Self {
        let secret = secret.into();
        Self {
            issuer: "agql-auth".to_string(),
            audience: "agql-auth-clients".to_string(),
            jwt_secret: secret.clone(),
            jwt_signing: JwtSigningConfig::Hs256 { secret },
            access_token_ttl: Duration::minutes(15),
            refresh_token_ttl: Duration::days(30),
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
            refresh_token_ttl: Duration::days(30),
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
}

/// Signing configuration for locally issued `agql-auth` JWTs.
#[derive(Clone)]
pub enum JwtSigningConfig {
    /// HS256 signing with a shared symmetric secret.
    Hs256 {
        /// Shared signing and validation secret.
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
        config.clock_skew = self.clock_skew;
        config.state_ttl = self.state_ttl;
        config.validate()?;
        Ok(config)
    }
}

fn microsoft_v2_issuer(tenant_id: &str) -> String {
    format!("https://login.microsoftonline.com/{tenant_id}/v2.0")
}
