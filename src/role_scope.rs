//! Provider-neutral role-to-scope expansion contracts.
//!
//! Hosts own role membership, catalogue transport, signature verification,
//! caching, and policy names. This module supplies a bounded wire model and a
//! deterministic expansion boundary shared by issuers and resource servers.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum number of scope definitions in one catalogue.
pub const MAX_ROLE_SCOPE_CATALOGUE_SCOPES: usize = 4_096;
/// Maximum number of role definitions in one catalogue.
pub const MAX_ROLE_SCOPE_CATALOGUE_ROLES: usize = 1_024;
/// Maximum scopes referenced by one role.
pub const MAX_ROLE_SCOPE_CATALOGUE_SCOPES_PER_ROLE: usize = 1_024;
/// Maximum number of exact-only scope patterns in one catalogue.
pub const MAX_ROLE_SCOPE_CATALOGUE_EXACT_ONLY_PATTERNS: usize = 1_024;
/// Maximum byte length of role IDs, scope IDs, patterns, and versions.
pub const MAX_ROLE_SCOPE_CATALOGUE_VALUE_LENGTH: usize = 512;
/// Stable purpose carried by signed catalogue claims.
pub const ROLE_SCOPE_CATALOGUE_PURPOSE: &str = "role_scope_catalogue";

/// One scope registered in a role-scope catalogue.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct RoleScopeDefinition {
    /// Exact scope identity.
    pub scope: String,
    /// Whether the host requires exact-grant matching for this scope.
    pub exact_only: bool,
}

impl RoleScopeDefinition {
    /// Creates an ordinary scope definition.
    pub fn new(scope: impl Into<String>) -> Self {
        Self {
            scope: scope.into(),
            exact_only: false,
        }
    }

    /// Marks the scope as exact-only.
    pub fn exact_only(mut self) -> Self {
        self.exact_only = true;
        self
    }
}

/// One role and its exact scope expansion.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct RoleScopeGrant {
    /// Stable role identifier carried by access tokens.
    pub id: String,
    /// Human-readable role name. It is presentation metadata, not authority.
    pub name: String,
    /// Exact registered scopes granted by the role.
    pub scopes: Vec<String>,
}

impl RoleScopeGrant {
    /// Creates a role definition.
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            scopes: scopes.into_iter().map(Into::into).collect(),
        }
    }
}

/// Versioned role-to-scope catalogue transported by a host application.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct RoleScopeCatalogue {
    /// Opaque content version. Consumers compare it exactly.
    pub version: String,
    /// Registered scope identities and their matching classification.
    pub scopes: Vec<RoleScopeDefinition>,
    /// Role definitions and their exact scope expansions.
    pub roles: Vec<RoleScopeGrant>,
    /// Host-defined exact-only wildcard patterns.
    #[serde(default)]
    pub exact_only_scope_patterns: Vec<String>,
}

impl RoleScopeCatalogue {
    /// Creates a catalogue without exact-only patterns.
    pub fn new(
        version: impl Into<String>,
        scopes: impl IntoIterator<Item = RoleScopeDefinition>,
        roles: impl IntoIterator<Item = RoleScopeGrant>,
    ) -> Self {
        Self {
            version: version.into(),
            scopes: scopes.into_iter().collect(),
            roles: roles.into_iter().collect(),
            exact_only_scope_patterns: Vec::new(),
        }
    }

    /// Sets exact-only scope patterns owned by the host.
    pub fn with_exact_only_scope_patterns(
        mut self,
        patterns: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.exact_only_scope_patterns = patterns.into_iter().map(Into::into).collect();
        self
    }

    /// Validates all bounds, uniqueness, and role-to-scope references.
    pub fn validate(&self) -> Result<(), RoleScopeCatalogueError> {
        validate_value(&self.version)?;
        if self.scopes.len() > MAX_ROLE_SCOPE_CATALOGUE_SCOPES {
            return invalid("catalogue has too many scope definitions");
        }
        if self.roles.len() > MAX_ROLE_SCOPE_CATALOGUE_ROLES {
            return invalid("catalogue has too many role definitions");
        }
        if self.exact_only_scope_patterns.len() > MAX_ROLE_SCOPE_CATALOGUE_EXACT_ONLY_PATTERNS {
            return invalid("catalogue has too many exact-only patterns");
        }

        let mut registered_scopes = BTreeSet::new();
        for definition in &self.scopes {
            validate_value(&definition.scope)?;
            if !registered_scopes.insert(definition.scope.as_str()) {
                return invalid("catalogue contains a duplicate scope");
            }
        }

        let mut role_ids = BTreeSet::new();
        for role in &self.roles {
            validate_value(&role.id)?;
            validate_display_name(&role.name)?;
            if !role_ids.insert(role.id.as_str()) {
                return invalid("catalogue contains a duplicate role ID");
            }
            if role.scopes.len() > MAX_ROLE_SCOPE_CATALOGUE_SCOPES_PER_ROLE {
                return invalid("role has too many scope references");
            }
            let mut role_scopes = BTreeSet::new();
            for scope in &role.scopes {
                validate_value(scope)?;
                if !registered_scopes.contains(scope.as_str()) {
                    return invalid("role references an unregistered scope");
                }
                if !role_scopes.insert(scope.as_str()) {
                    return invalid("role contains a duplicate scope reference");
                }
            }
        }

        let mut patterns = BTreeSet::new();
        for pattern in &self.exact_only_scope_patterns {
            validate_value(pattern)?;
            if !patterns.insert(pattern.as_str()) {
                return invalid("catalogue contains a duplicate exact-only pattern");
            }
        }
        Ok(())
    }
}

/// Signed transport envelope. The signature format and key distribution stay
/// with the host; consumers must verify it before accepting the catalogue.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct SignedRoleScopeCatalogue {
    /// Catalogue repeated in clear text for HTTP cache and inspection.
    pub catalogue: RoleScopeCatalogue,
    /// Host-created signature over claims that contain the exact catalogue.
    pub signature: String,
}

impl SignedRoleScopeCatalogue {
    /// Creates a signed envelope after host-owned signing.
    pub fn new(catalogue: RoleScopeCatalogue, signature: impl Into<String>) -> Self {
        Self {
            catalogue,
            signature: signature.into(),
        }
    }

    /// Checks the unsigned envelope structure before cryptographic validation.
    pub fn validate_structure(&self) -> Result<(), RoleScopeCatalogueError> {
        self.catalogue.validate()?;
        if self.signature.is_empty() || self.signature.len() > 64 * 1024 {
            return invalid("catalogue signature is missing or too large");
        }
        Ok(())
    }
}

/// Claims carried by a host-signed role-scope catalogue token.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct RoleScopeCatalogueClaims {
    /// Exact catalogue protected by the signature.
    pub catalogue: RoleScopeCatalogue,
    /// Stable catalogue-token purpose.
    pub purpose: String,
    /// Signing authority.
    pub iss: String,
    /// Intended resource-server audience.
    pub aud: String,
    /// Issued-at Unix timestamp.
    pub iat: i64,
    /// Expiry Unix timestamp.
    pub exp: i64,
}

/// Host-selected time policy for validating a freshly fetched signed
/// catalogue. Cache refresh cadence is intentionally not part of this policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RoleScopeCatalogueValidationOptions {
    maximum_lifetime_seconds: i64,
    clock_skew_leeway_seconds: i64,
}

impl Default for RoleScopeCatalogueValidationOptions {
    fn default() -> Self {
        Self {
            maximum_lifetime_seconds: 24 * 60 * 60,
            clock_skew_leeway_seconds: 0,
        }
    }
}

impl RoleScopeCatalogueValidationOptions {
    /// Sets the longest signed lifetime accepted from an issuer.
    pub fn with_maximum_lifetime_seconds(mut self, seconds: i64) -> Self {
        self.maximum_lifetime_seconds = seconds;
        self
    }

    /// Sets symmetric clock-skew leeway for `iat` and `exp` validation.
    pub fn with_clock_skew_leeway_seconds(mut self, seconds: i64) -> Self {
        self.clock_skew_leeway_seconds = seconds;
        self
    }
}

impl RoleScopeCatalogueClaims {
    /// Creates claims with the stable catalogue purpose.
    pub fn new(
        catalogue: RoleScopeCatalogue,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        issued_at: i64,
        expires_at: i64,
    ) -> Self {
        Self {
            catalogue,
            purpose: ROLE_SCOPE_CATALOGUE_PURPOSE.to_owned(),
            iss: issuer.into(),
            aud: audience.into(),
            iat: issued_at,
            exp: expires_at,
        }
    }

    /// Validates binding after a host cryptographically verifies the signature.
    pub fn validate_binding(
        &self,
        envelope: &SignedRoleScopeCatalogue,
        expected_issuer: &str,
        expected_audience: &str,
        now: i64,
        maximum_lifetime_seconds: i64,
    ) -> Result<(), RoleScopeCatalogueError> {
        self.validate_binding_with_options(
            envelope,
            expected_issuer,
            expected_audience,
            now,
            RoleScopeCatalogueValidationOptions::default()
                .with_maximum_lifetime_seconds(maximum_lifetime_seconds),
        )
    }

    /// Validates binding and a host-selected signed-lifetime policy after a
    /// host cryptographically verifies the signature.
    pub fn validate_binding_with_options(
        &self,
        envelope: &SignedRoleScopeCatalogue,
        expected_issuer: &str,
        expected_audience: &str,
        now: i64,
        options: RoleScopeCatalogueValidationOptions,
    ) -> Result<(), RoleScopeCatalogueError> {
        envelope.validate_structure()?;
        self.catalogue.validate()?;
        if self.purpose != ROLE_SCOPE_CATALOGUE_PURPOSE
            || self.iss != expected_issuer
            || self.aud != expected_audience
            || self.catalogue != envelope.catalogue
        {
            return invalid("catalogue signature claims do not match the envelope");
        }
        if options.maximum_lifetime_seconds <= 0
            || options.clock_skew_leeway_seconds < 0
            || self.iat > now.saturating_add(options.clock_skew_leeway_seconds)
            || self.exp <= now.saturating_sub(options.clock_skew_leeway_seconds)
            || self.exp <= self.iat
            || self.exp.saturating_sub(self.iat) > options.maximum_lifetime_seconds
        {
            return invalid("catalogue signature lifetime is invalid");
        }
        Ok(())
    }
}

/// Successful role expansion from one verified catalogue version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleScopeExpansion {
    /// Opaque catalogue version used for the decision.
    pub catalogue_version: String,
    /// Sorted, de-duplicated scopes contributed by matched roles.
    pub scopes: Vec<String>,
}

/// Failure to load or use role-to-scope expansion state.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RoleScopeExpansionError {
    /// Required verified expansion state is not currently available.
    #[error("role-scope expansion is unavailable")]
    Unavailable,
    /// A token referenced a role absent from the verified catalogue.
    #[error("role-scope catalogue does not contain role `{0}`")]
    UnknownRole(String),
    /// Expansion state violated the bounded catalogue contract.
    #[error("invalid role-scope catalogue: {0}")]
    InvalidCatalogue(&'static str),
}

/// Structural catalogue validation failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RoleScopeCatalogueError {
    /// The catalogue violated a bounded structural or binding rule.
    #[error("invalid role-scope catalogue: {0}")]
    Invalid(&'static str),
}

impl From<RoleScopeCatalogueError> for RoleScopeExpansionError {
    fn from(error: RoleScopeCatalogueError) -> Self {
        match error {
            RoleScopeCatalogueError::Invalid(message) => Self::InvalidCatalogue(message),
        }
    }
}

/// Host-supplied expansion provider used after token roles are verified.
pub trait RoleScopeExpansionProvider: Send + Sync + fmt::Debug {
    /// Resolves every supplied authorization role to one catalogue version
    /// and scope set. Unknown roles return an explicit error so a remote cache
    /// can refresh immediately and callers can fail closed.
    fn expand_roles(&self, roles: &[String])
    -> Result<RoleScopeExpansion, RoleScopeExpansionError>;
}

/// Immutable expansion provider built from one already verified catalogue.
#[derive(Clone)]
pub struct StaticRoleScopeExpansion {
    version: String,
    role_scopes: Arc<BTreeMap<String, Arc<[String]>>>,
}

impl StaticRoleScopeExpansion {
    /// Builds deterministic expansion state from a verified catalogue.
    pub fn new(catalogue: &RoleScopeCatalogue) -> Result<Self, RoleScopeExpansionError> {
        catalogue.validate()?;
        let role_scopes = catalogue
            .roles
            .iter()
            .map(|role| (role.id.clone(), Arc::from(role.scopes.clone())))
            .collect();
        Ok(Self {
            version: catalogue.version.clone(),
            role_scopes: Arc::new(role_scopes),
        })
    }
}

impl fmt::Debug for StaticRoleScopeExpansion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StaticRoleScopeExpansion")
            .field("version", &self.version)
            .field("role_count", &self.role_scopes.len())
            .finish()
    }
}

impl RoleScopeExpansionProvider for StaticRoleScopeExpansion {
    fn expand_roles(
        &self,
        roles: &[String],
    ) -> Result<RoleScopeExpansion, RoleScopeExpansionError> {
        let scopes = roles
            .iter()
            .map(|role| {
                self.role_scopes
                    .get(role)
                    .ok_or_else(|| RoleScopeExpansionError::UnknownRole(role.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flat_map(|scopes| scopes.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok(RoleScopeExpansion {
            catalogue_version: self.version.clone(),
            scopes,
        })
    }
}

/// Produces the sorted union of direct scopes and a verified role expansion.
pub fn effective_scopes(
    direct_scopes: impl IntoIterator<Item = impl Into<String>>,
    expansion: &RoleScopeExpansion,
) -> Vec<String> {
    direct_scopes
        .into_iter()
        .map(Into::into)
        .chain(expansion.scopes.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn validate_value(value: &str) -> Result<(), RoleScopeCatalogueError> {
    if value.is_empty()
        || value.len() > MAX_ROLE_SCOPE_CATALOGUE_VALUE_LENGTH
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return invalid("catalogue contains an empty, oversized, or whitespace-bearing value");
    }
    Ok(())
}

fn validate_display_name(value: &str) -> Result<(), RoleScopeCatalogueError> {
    if value.trim().is_empty()
        || value.len() > MAX_ROLE_SCOPE_CATALOGUE_VALUE_LENGTH
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return invalid("catalogue contains an invalid role name");
    }
    Ok(())
}

fn invalid<T>(message: &'static str) -> Result<T, RoleScopeCatalogueError> {
    Err(RoleScopeCatalogueError::Invalid(message))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalogue() -> RoleScopeCatalogue {
        RoleScopeCatalogue::new(
            "revision-7",
            [
                RoleScopeDefinition::new("inventory.read"),
                RoleScopeDefinition::new("inventory.write").exact_only(),
                RoleScopeDefinition::new("billing.read"),
            ],
            [
                RoleScopeGrant::new("support", "Support", ["inventory.read", "billing.read"]),
                RoleScopeGrant::new("operator", "Operator", ["inventory.write"]),
            ],
        )
        .with_exact_only_scope_patterns(["inventory.item.*.delete"])
    }

    #[test]
    fn neutral_catalogue_round_trips_and_expands_deterministically() {
        let catalogue = catalogue();
        let encoded = serde_json::to_string(&catalogue).unwrap();
        let decoded: RoleScopeCatalogue = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, catalogue);
        let provider = StaticRoleScopeExpansion::new(&decoded).unwrap();
        let expansion = provider
            .expand_roles(&[
                "operator".to_owned(),
                "support".to_owned(),
                "support".to_owned(),
            ])
            .unwrap();
        assert_eq!(expansion.catalogue_version, "revision-7");
        assert_eq!(
            expansion.scopes,
            ["billing.read", "inventory.read", "inventory.write"]
        );
        assert_eq!(
            effective_scopes(["profile.read", "inventory.read"], &expansion),
            [
                "billing.read",
                "inventory.read",
                "inventory.write",
                "profile.read"
            ]
        );
    }

    #[test]
    fn unknown_authorization_role_fails_explicitly() {
        let provider = StaticRoleScopeExpansion::new(&catalogue()).unwrap();
        assert_eq!(
            provider.expand_roles(&["unknown".to_owned()]),
            Err(RoleScopeExpansionError::UnknownRole("unknown".to_owned()))
        );
    }

    #[test]
    fn role_references_and_duplicates_fail_closed() {
        let mut unregistered = catalogue();
        unregistered.roles[0].scopes.push("unknown.read".to_owned());
        assert!(matches!(
            StaticRoleScopeExpansion::new(&unregistered),
            Err(RoleScopeExpansionError::InvalidCatalogue(
                "role references an unregistered scope"
            ))
        ));
        let mut duplicate = catalogue();
        duplicate.roles.push(duplicate.roles[0].clone());
        assert!(duplicate.validate().is_err());
    }

    #[test]
    fn signed_claim_binding_rejects_mismatch_and_invalid_lifetime() {
        let catalogue = catalogue();
        let envelope = SignedRoleScopeCatalogue::new(catalogue.clone(), "signed.token.value");
        let claims = RoleScopeCatalogueClaims::new(
            catalogue.clone(),
            "https://issuer.test",
            "resource-servers",
            1_000,
            1_300,
        );
        claims
            .validate_binding(
                &envelope,
                "https://issuer.test",
                "resource-servers",
                1_100,
                300,
            )
            .unwrap();
        let mut mismatch = claims.clone();
        mismatch.catalogue.version = "revision-8".to_owned();
        assert!(
            mismatch
                .validate_binding(
                    &envelope,
                    "https://issuer.test",
                    "resource-servers",
                    1_100,
                    300,
                )
                .is_err()
        );
        assert!(
            claims
                .validate_binding(
                    &envelope,
                    "https://issuer.test",
                    "resource-servers",
                    1_300,
                    300,
                )
                .is_err()
        );
        claims
            .validate_binding_with_options(
                &envelope,
                "https://issuer.test",
                "resource-servers",
                999,
                RoleScopeCatalogueValidationOptions::default()
                    .with_maximum_lifetime_seconds(300)
                    .with_clock_skew_leeway_seconds(2),
            )
            .unwrap();
    }
}
