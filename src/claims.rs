//! Project-agnostic multi-tenant and sender-binding claim types.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use time::OffsetDateTime;

/// Actor / on-behalf-of identity for impersonation or delegation.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorIdentity {
    /// Actor subject identifier.
    pub sub: String,
    /// Optional actor authentication method references.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub amr: Vec<String>,
}

/// Confirmation (`cnf`) binding material.
///
/// Formats are intentionally host-defined strings rather than product-specific
/// certificate parsers.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfirmationClaims {
    /// X.509 certificate SHA-256 thumbprint (`x5t#S256`).
    #[serde(rename = "x5t#S256", default, skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
    /// JWK thumbprint (`jkt`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jkt: Option<String>,
}

/// Optional standard claims carried by access tokens and exposed on principals.
///
/// All fields remain optional for compatibility. Resource servers that need
/// stronger guarantees configure [`ClaimRequirements`] on the validator.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessTokenMetadata {
    /// JWT ID (`jti`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Tenant or organization identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Organization identifier when distinct from tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    /// Session-family identifier used for family-wide revocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_family_id: Option<String>,
    /// Actor / on-behalf-of identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<ActorIdentity>,
    /// Authentication time as a unix timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    /// Authentication method references.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    /// Authentication context class reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// Confirmation binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<ConfirmationClaims>,
    /// Optional resource type binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    /// Optional resource ID binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    /// Authorization/audit correlation identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Explicit token purpose when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Token expiry as an absolute timestamp when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<OffsetDateTime>,
    /// Additional non-reserved custom claims.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub additional: BTreeMap<String, JsonValue>,
}

/// Policy that requires selected claim sets for a resource server.
///
/// Defaults keep existing tokens valid. Stricter resource servers opt in
/// explicitly; a future major release may tighten defaults after a migration
/// window.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaimRequirements {
    /// Require a non-empty `jti`.
    pub require_jti: bool,
    /// Require a non-empty tenant identifier.
    pub require_tenant_id: bool,
    /// Require a non-empty organization identifier.
    pub require_organization_id: bool,
    /// Require confirmation binding (`cnf`).
    pub require_cnf: bool,
    /// Require `purpose = access_token` (reject legacy tokens missing purpose).
    pub require_purpose: bool,
    /// Require a session-family identifier.
    pub require_session_family_id: bool,
    /// Require actor / on-behalf-of identity.
    pub require_actor: bool,
    /// Require resource type and resource ID.
    pub require_resource_binding: bool,
    /// Require an audit correlation identifier.
    pub require_correlation_id: bool,
}

impl ClaimRequirements {
    /// Creates an empty (compatibility) requirements set.
    pub fn none() -> Self {
        Self::default()
    }

    /// Common multi-tenant API profile: tenant + jti.
    pub fn tenant_and_jti() -> Self {
        Self {
            require_jti: true,
            require_tenant_id: true,
            ..Self::default()
        }
    }

    /// Multi-tenant API that also requires confirmation binding.
    pub fn tenant_jti_and_cnf() -> Self {
        Self {
            require_jti: true,
            require_tenant_id: true,
            require_cnf: true,
            ..Self::default()
        }
    }

    /// Validates metadata against this policy.
    pub fn validate(&self, metadata: &AccessTokenMetadata) -> Result<(), ClaimRequirementError> {
        if self.require_jti && metadata.jti.as_ref().is_none_or(|v| v.trim().is_empty()) {
            return Err(ClaimRequirementError::MissingJti);
        }
        if self.require_tenant_id
            && metadata
                .tenant_id
                .as_ref()
                .is_none_or(|v| v.trim().is_empty())
        {
            return Err(ClaimRequirementError::MissingTenantId);
        }
        if self.require_organization_id
            && metadata
                .organization_id
                .as_ref()
                .is_none_or(|v| v.trim().is_empty())
        {
            return Err(ClaimRequirementError::MissingOrganizationId);
        }
        if self.require_cnf {
            let Some(cnf) = &metadata.cnf else {
                return Err(ClaimRequirementError::MissingCnf);
            };
            if cnf.x5t_s256.is_none() && cnf.jkt.is_none() {
                return Err(ClaimRequirementError::MissingCnf);
            }
        }
        if self.require_purpose
            && metadata.purpose.as_deref() != Some(crate::token_decode::ACCESS_TOKEN_PURPOSE)
        {
            return Err(ClaimRequirementError::MissingOrInvalidPurpose);
        }
        if self.require_session_family_id
            && metadata
                .session_family_id
                .as_ref()
                .is_none_or(|v| v.trim().is_empty())
        {
            return Err(ClaimRequirementError::MissingSessionFamilyId);
        }
        if self.require_actor
            && metadata
                .actor
                .as_ref()
                .is_none_or(|actor| actor.sub.trim().is_empty())
        {
            return Err(ClaimRequirementError::MissingActor);
        }
        if self.require_resource_binding {
            let has_type = metadata
                .resource_type
                .as_ref()
                .is_some_and(|v| !v.trim().is_empty());
            let has_id = metadata
                .resource_id
                .as_ref()
                .is_some_and(|v| !v.trim().is_empty());
            if !(has_type && has_id) {
                return Err(ClaimRequirementError::MissingResourceBinding);
            }
        }
        if self.require_correlation_id
            && metadata
                .correlation_id
                .as_ref()
                .is_none_or(|v| v.trim().is_empty())
        {
            return Err(ClaimRequirementError::MissingCorrelationId);
        }
        Ok(())
    }
}

/// Claim requirement failure reason (mapped to public invalid-token errors).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimRequirementError {
    /// Missing or empty `jti`.
    MissingJti,
    /// Missing or empty tenant identifier.
    MissingTenantId,
    /// Missing or empty organization identifier.
    MissingOrganizationId,
    /// Missing confirmation binding.
    MissingCnf,
    /// Missing or invalid purpose under a strict policy.
    MissingOrInvalidPurpose,
    /// Missing session-family identifier.
    MissingSessionFamilyId,
    /// Missing actor identity.
    MissingActor,
    /// Missing resource type/id binding.
    MissingResourceBinding,
    /// Missing correlation identifier.
    MissingCorrelationId,
}
