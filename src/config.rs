use serde::{Deserialize, Serialize};
use time::Duration;

use crate::errors::AuthError;

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
pub enum OidcProviderKind {
    Generic,
    MicrosoftEntra,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcProviderConfig {
    pub provider_name: String,
    pub provider_kind: OidcProviderKind,
    pub discovery_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub requested_scopes: Vec<String>,
    pub request_offline_access: bool,
    pub allowed_tenants: Vec<String>,
    pub allowed_issuers: Vec<String>,
    pub allow_consumer_accounts: bool,
    pub jwks_cache_ttl: Duration,
    pub clock_skew: Duration,
    pub state_ttl: Duration,
    pub allowed_id_token_algs: Vec<String>,
}

impl OidcProviderConfig {
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

    pub fn scopes(&self) -> Vec<String> {
        let mut scopes = self.requested_scopes.clone();
        if self.request_offline_access && !scopes.iter().any(|scope| scope == "offline_access") {
            scopes.push("offline_access".to_string());
        }
        scopes
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MicrosoftEntraTenant {
    TenantId(String),
    Organizations,
    Common,
    Consumers,
}

impl MicrosoftEntraTenant {
    pub fn as_path_segment(&self) -> &str {
        match self {
            MicrosoftEntraTenant::TenantId(tenant_id) => tenant_id.as_str(),
            MicrosoftEntraTenant::Organizations => "organizations",
            MicrosoftEntraTenant::Common => "common",
            MicrosoftEntraTenant::Consumers => "consumers",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicrosoftEntraConfig {
    pub provider_name: String,
    pub tenant: MicrosoftEntraTenant,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub allowed_tenants: Vec<String>,
    pub allowed_issuers: Vec<String>,
    pub requested_scopes: Vec<String>,
    pub request_offline_access: bool,
    pub jwks_cache_ttl: Duration,
    pub clock_skew: Duration,
    pub state_ttl: Duration,
    pub allow_consumers: bool,
}

impl MicrosoftEntraConfig {
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

    pub fn organizations(client_id: impl Into<String>, redirect_uri: impl Into<String>) -> Self {
        Self::multi_tenant(MicrosoftEntraTenant::Organizations, client_id, redirect_uri)
    }

    pub fn common(client_id: impl Into<String>, redirect_uri: impl Into<String>) -> Self {
        Self::multi_tenant(MicrosoftEntraTenant::Common, client_id, redirect_uri)
    }

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
