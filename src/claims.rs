//! Project-agnostic multi-tenant and sender-binding claim types.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use time::OffsetDateTime;

/// Closed classification for locally issued access-token grants.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessTokenGrantKind {
    /// Access token belonging to a normal refreshable user session.
    UserSession,
    /// Sessionless service, device, or one-shot access-token-only grant.
    Sessionless,
    /// Non-refreshable delegation bound to an existing active user session.
    SessionBoundDelegation,
}

impl AccessTokenGrantKind {
    /// Returns whether this credential may be used to manage or further
    /// delegate a user session.
    pub const fn permits_session_management(self) -> bool {
        matches!(self, Self::UserSession)
    }
}

/// Exact registered operation bound to a session delegation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExactOperationBinding {
    /// Stable registered operation name or identifier.
    pub operation_name: String,
    /// Exact allowlisted GraphQL document hash.
    pub document_sha256: String,
}

impl ExactOperationBinding {
    /// Creates an exact operation binding. Issuance validates both values.
    pub fn new(operation_name: impl Into<String>, document_sha256: impl Into<String>) -> Self {
        Self {
            operation_name: operation_name.into(),
            document_sha256: document_sha256.into(),
        }
    }
}

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
    /// Closed grant classification for newly issued access tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_kind: Option<AccessTokenGrantKind>,
    /// Authoritative host session/security version, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_version: Option<String>,
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
    /// Exact registered operation binding for delegated execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<ExactOperationBinding>,
    /// Host-defined authorization-role grants carried separately from
    /// application roles and expanded by a verified resource-server catalogue.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorization_roles: Vec<String>,
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

impl AccessTokenMetadata {
    /// Returns whether the token acts on behalf of someone else: a
    /// [`AccessTokenGrantKind::SessionBoundDelegation`] or any token carrying
    /// an `actor` claim.
    ///
    /// The crate's user and principal guards refuse such tokens unless the
    /// guard opts in with `allow_delegated()`.
    pub fn is_delegated(&self) -> bool {
        self.grant_kind == Some(AccessTokenGrantKind::SessionBoundDelegation)
            || self.actor.is_some()
    }

    /// Verifies that the caller presented the key or certificate the token's
    /// `cnf` claim is bound to.
    ///
    /// `presented` is material the host verified itself: the SHA-256
    /// thumbprint of the mTLS client certificate the TLS layer authenticated
    /// (`x5t#S256`, RFC 8705) or of the JWK whose DPoP proof it checked (`jkt`,
    /// RFC 9449). Every confirmation method in the token must be matched;
    /// values are compared in constant time. A token without `cnf`, or with a
    /// method the caller did not present, fails.
    pub fn verify_confirmation(
        &self,
        presented: &PresentedConfirmation,
    ) -> Result<(), ClaimRequirementError> {
        let cnf = self.cnf.as_ref().ok_or(ClaimRequirementError::MissingCnf)?;
        if cnf.x5t_s256.is_none() && cnf.jkt.is_none() {
            return Err(ClaimRequirementError::MissingCnf);
        }
        for (bound, offered) in [
            (&cnf.x5t_s256, &presented.x5t_s256),
            (&cnf.jkt, &presented.jkt),
        ] {
            if let Some(bound) = bound {
                let matched = offered
                    .as_deref()
                    .is_some_and(|offered| constant_time_eq(bound, offered));
                if !matched {
                    return Err(ClaimRequirementError::ConfirmationMismatch);
                }
            }
        }
        Ok(())
    }
}

/// Proof-of-possession material the host verified for the current request.
///
/// Pass it to [`AccessTokenMetadata::verify_confirmation`] or
/// `AccessTokenValidator::authenticate_bearer_with_confirmation`. Values are
/// base64url SHA-256 thumbprints, compared exactly.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct PresentedConfirmation {
    x5t_s256: Option<String>,
    jkt: Option<String>,
}

impl PresentedConfirmation {
    /// Material for an mTLS client certificate the TLS layer authenticated.
    pub fn certificate_thumbprint(x5t_s256: impl Into<String>) -> Self {
        Self {
            x5t_s256: Some(x5t_s256.into()),
            jkt: None,
        }
    }

    /// Material for a JWK whose proof of possession (for example DPoP) the
    /// host verified.
    pub fn jwk_thumbprint(jkt: impl Into<String>) -> Self {
        Self {
            x5t_s256: None,
            jkt: Some(jkt.into()),
        }
    }

    /// Adds a verified JWK thumbprint to certificate material.
    pub fn with_jwk_thumbprint(mut self, jkt: impl Into<String>) -> Self {
        self.jkt = Some(jkt.into());
        self
    }
}

impl std::fmt::Debug for PresentedConfirmation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PresentedConfirmation")
            .field("x5t_s256", &self.x5t_s256.is_some())
            .field("jkt", &self.jkt.is_some())
            .finish()
    }
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;
    // Hash first so neither the comparison time nor an early length check
    // reveals how much of the bound value matched.
    Sha256::digest(left.as_bytes())
        .ct_eq(&Sha256::digest(right.as_bytes()))
        .into()
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
    /// Require a confirmation binding (`cnf`) and proof that the caller holds
    /// the bound key or certificate.
    ///
    /// Validation compares the token's `cnf` with the
    /// [`PresentedConfirmation`] the caller supplies (see
    /// [`Self::validate_with_confirmation`]). Without presented material the
    /// requirement fails closed: presence of `cnf` alone proves nothing.
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
    /// Require one exact grant classification.
    pub required_grant_kind: Option<AccessTokenGrantKind>,
    /// Require a non-empty authoritative session/security version.
    pub require_session_version: bool,
    /// Require a non-empty exact-operation name and document hash.
    pub require_operation_binding: bool,
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

    /// Multi-tenant API that also requires a verified confirmation binding.
    ///
    /// Tokens validate only through a confirmation-aware path such as
    /// `AccessTokenValidator::authenticate_bearer_with_confirmation`, which
    /// compares `cnf` with the certificate or key the host verified.
    pub fn tenant_jti_and_cnf() -> Self {
        Self {
            require_jti: true,
            require_tenant_id: true,
            require_cnf: true,
            ..Self::default()
        }
    }

    /// Validates metadata against this policy without presented
    /// proof-of-possession material.
    ///
    /// When [`Self::require_cnf`] is set this fails with
    /// [`ClaimRequirementError::ConfirmationNotPresented`]; use
    /// [`Self::validate_with_confirmation`].
    pub fn validate(&self, metadata: &AccessTokenMetadata) -> Result<(), ClaimRequirementError> {
        self.validate_with_confirmation(metadata, None)
    }

    /// Validates metadata against this policy, verifying `cnf` against the
    /// key or certificate the host verified for this request.
    pub fn validate_with_confirmation(
        &self,
        metadata: &AccessTokenMetadata,
        presented: Option<&PresentedConfirmation>,
    ) -> Result<(), ClaimRequirementError> {
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
            let presented = presented.ok_or(ClaimRequirementError::ConfirmationNotPresented)?;
            metadata.verify_confirmation(presented)?;
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
        if self
            .required_grant_kind
            .is_some_and(|required| metadata.grant_kind != Some(required))
        {
            return Err(ClaimRequirementError::MissingOrInvalidGrantKind);
        }
        if self.require_session_version
            && metadata
                .session_version
                .as_ref()
                .is_none_or(|version| version.trim().is_empty())
        {
            return Err(ClaimRequirementError::MissingSessionVersion);
        }
        if self.require_operation_binding
            && metadata.operation.as_ref().is_none_or(|operation| {
                operation.operation_name.trim().is_empty()
                    || operation.document_sha256.trim().is_empty()
            })
        {
            return Err(ClaimRequirementError::MissingOperationBinding);
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
    /// Grant classification was missing or did not match policy.
    MissingOrInvalidGrantKind,
    /// Authoritative session/security version was missing.
    MissingSessionVersion,
    /// Exact registered operation binding was missing or empty.
    MissingOperationBinding,
    /// The presented key or certificate did not match the token's `cnf`.
    ConfirmationMismatch,
    /// `require_cnf` is set but the caller supplied no presented key or
    /// certificate to compare.
    ConfirmationNotPresented,
}
