use std::collections::BTreeMap;
use std::fmt;

use serde_json::Value as JsonValue;
use time::{Duration, OffsetDateTime};

use crate::claims::{ActorIdentity, ConfirmationClaims, ExactOperationBinding};
use crate::models::AuthUser;
use crate::principal_reference::PrincipalReference;
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

/// Required actor, resource, correlation, and exact-operation bindings for a
/// session-bound delegation.
#[derive(Debug, Clone)]
pub struct SessionBoundDelegationBinding {
    pub(crate) actor: ActorIdentity,
    pub(crate) resource_type: String,
    pub(crate) resource_id: String,
    pub(crate) correlation_id: String,
    pub(crate) operation: ExactOperationBinding,
}

impl SessionBoundDelegationBinding {
    /// Creates the mandatory bindings for one delegated operation.
    pub fn new(
        actor: ActorIdentity,
        resource_type: impl Into<String>,
        resource_id: impl Into<String>,
        correlation_id: impl Into<String>,
        operation: ExactOperationBinding,
    ) -> Self {
        Self {
            actor,
            resource_type: resource_type.into(),
            resource_id: resource_id.into(),
            correlation_id: correlation_id.into(),
            operation,
        }
    }
}

/// Request for an access-token-only grant bound to an existing user session.
///
/// This request stores only a non-secret, authoritatively versioned principal
/// reference and requested authority. It is created by
/// [`crate::AuthService::prepare_session_bound_access_token_only`], and
/// [`crate::AuthService::issue_session_bound_access_token_only`] re-reads the
/// authoritative session a second time during issuance.
#[derive(Clone)]
pub struct SessionBoundAccessTokenOnlyRequest {
    pub(crate) reference: PrincipalReference,
    pub(crate) roles: Vec<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) binding: SessionBoundDelegationBinding,
    pub(crate) ttl: Option<Duration>,
    pub(crate) cnf: Option<ConfirmationClaims>,
    pub(crate) additional_claims: BTreeMap<String, JsonValue>,
}

impl SessionBoundAccessTokenOnlyRequest {
    pub(crate) fn from_prepared_reference(
        reference: PrincipalReference,
        roles: Vec<String>,
        scopes: Vec<String>,
        binding: SessionBoundDelegationBinding,
    ) -> Self {
        Self {
            reference,
            roles: dedupe_stable(roles),
            scopes: dedupe_stable(scopes),
            binding,
            ttl: None,
            cnf: None,
            additional_claims: BTreeMap::new(),
        }
    }

    /// Sets a requested TTL. Final expiry is clamped to the configured
    /// delegation ceiling and remaining authoritative session lifetime.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Sets optional confirmation binding material.
    pub fn with_confirmation(mut self, confirmation: ConfirmationClaims) -> Self {
        self.cnf = Some(confirmation);
        self
    }

    /// Adds one non-reserved custom claim in addition to the mandatory typed
    /// exact-operation binding.
    pub fn with_claim(mut self, key: impl Into<String>, value: JsonValue) -> Self {
        self.additional_claims.insert(key.into(), value);
        self
    }
}

impl fmt::Debug for SessionBoundAccessTokenOnlyRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionBoundAccessTokenOnlyRequest")
            .field("reference", &self.reference)
            .field("roles", &self.roles)
            .field("scopes", &self.scopes)
            .field("binding", &self.binding)
            .field("ttl", &self.ttl)
            .field("cnf", &self.cnf)
            .field(
                "additional_claim_names",
                &self.additional_claims.keys().collect::<Vec<_>>(),
            )
            .finish()
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
