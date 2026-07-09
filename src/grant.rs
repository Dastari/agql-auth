use std::collections::BTreeMap;
use std::fmt;

use serde_json::Value as JsonValue;
use time::{Duration, OffsetDateTime};

use crate::claims::{ActorIdentity, ConfirmationClaims};
use crate::models::AuthUser;
use crate::session::SessionContext;

/// Request to issue a short-lived access token without a refresh token.
#[derive(Debug, Clone)]
pub struct AccessTokenOnlyRequest {
    /// Principal subject placed in the access token `sub` claim.
    pub user_id: String,
    /// Roles embedded in the access token.
    pub roles: Vec<String>,
    /// Scopes embedded in the access token.
    pub scopes: Vec<String>,
    /// Session context embedded in the access token `ctx` claim.
    pub session: SessionContext,
    /// Optional token lifetime. Defaults to [`crate::AuthConfig::access_token_ttl`].
    pub ttl: Option<Duration>,
    /// Optional tenant identifier.
    pub tenant_id: Option<String>,
    /// Optional organization identifier.
    pub organization_id: Option<String>,
    /// Optional session-family identifier.
    pub session_family_id: Option<String>,
    /// Optional actor / on-behalf-of identity.
    pub actor: Option<ActorIdentity>,
    /// Optional authentication time (unix timestamp).
    pub auth_time: Option<i64>,
    /// Optional authentication method references.
    pub amr: Option<Vec<String>>,
    /// Optional authentication context class reference.
    pub acr: Option<String>,
    /// Optional confirmation binding.
    pub cnf: Option<ConfirmationClaims>,
    /// Optional resource type binding.
    pub resource_type: Option<String>,
    /// Optional resource ID binding.
    pub resource_id: Option<String>,
    /// Optional audit correlation identifier.
    pub correlation_id: Option<String>,
    /// Additional non-reserved custom claims.
    pub additional_claims: BTreeMap<String, JsonValue>,
}

impl AccessTokenOnlyRequest {
    /// Creates a minimal access-token-only request.
    pub fn new(
        user_id: impl Into<String>,
        roles: Vec<String>,
        scopes: Vec<String>,
        session: SessionContext,
    ) -> Self {
        Self {
            user_id: user_id.into(),
            roles,
            scopes,
            session,
            ttl: None,
            tenant_id: None,
            organization_id: None,
            session_family_id: None,
            actor: None,
            auth_time: None,
            amr: None,
            acr: None,
            cnf: None,
            resource_type: None,
            resource_id: None,
            correlation_id: None,
            additional_claims: BTreeMap::new(),
        }
    }

    /// Sets a custom TTL.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Sets a tenant identifier.
    pub fn with_tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Adds a non-reserved additional claim.
    pub fn with_claim(mut self, key: impl Into<String>, value: JsonValue) -> Self {
        self.additional_claims.insert(key.into(), value);
        self
    }
}

/// Short-lived access-token-only grant.
#[derive(Clone)]
pub struct AccessTokenOnlyGrant {
    /// Raw JWT access token.
    pub access_token: String,
    /// Access-token expiry time.
    pub access_token_expires_at: OffsetDateTime,
    /// User-shaped principal represented by the access token.
    pub user: AuthUser,
}

impl fmt::Debug for AccessTokenOnlyGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessTokenOnlyGrant")
            .field("access_token", &"[redacted]")
            .field("access_token_expires_at", &self.access_token_expires_at)
            .field("user", &self.user)
            .finish()
    }
}
