//! Authoritative session assurance and recent-MFA policy helpers.

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::{AuthUser, Clock, MfaState};

/// Maximum accepted authentication-method references in one assurance value.
pub const MAX_ASSURANCE_METHODS: usize = 16;
/// Maximum UTF-8 byte length of an AMR value.
pub const MAX_ASSURANCE_METHOD_LENGTH: usize = 64;
/// Maximum UTF-8 byte length of an ACR or assurance-context value.
pub const MAX_ASSURANCE_CONTEXT_LENGTH: usize = 256;

/// Whether the host authoritatively accepted authentication facts as MFA.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MfaAcceptance {
    /// The facts do not satisfy the host's MFA policy.
    Unsatisfied,
    /// The facts satisfy the host's MFA policy.
    Satisfied,
}

/// Host-accepted authentication assurance bound to one refreshable session.
///
/// Construct this only after the host has verified the authentication event and
/// mapped any provider AMR/ACR values through local policy. Provider claims are
/// evidence for that decision, not authority by themselves.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionAssurance {
    /// Genuine time at which the relevant authentication or step-up occurred.
    pub authenticated_at: OffsetDateTime,
    /// Normalized, stable-deduplicated authentication method references.
    pub methods: Vec<String>,
    /// Provider or host authentication context class reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// Optional host/provider namespace or policy context for interpreting AMR/ACR.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    /// Host-authoritative MFA acceptance state.
    pub mfa: MfaAcceptance,
}

impl SessionAssurance {
    /// Creates validated assurance and normalizes AMR values.
    pub fn new<I, S>(
        authenticated_at: OffsetDateTime,
        methods: I,
        acr: Option<String>,
        context: Option<String>,
        mfa: MfaAcceptance,
    ) -> Result<Self, AssuranceInputError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let methods = normalize_methods(methods)?;
        validate_optional_value("acr", acr.as_deref())?;
        validate_optional_value("context", context.as_deref())?;
        Ok(Self {
            authenticated_at,
            methods,
            acr,
            context,
            mfa,
        })
    }

    /// Validates assurance deserialized or constructed outside [`SessionAssurance::new`].
    pub fn validate(&self) -> Result<(), AssuranceInputError> {
        if self.methods.len() > MAX_ASSURANCE_METHODS {
            return Err(AssuranceInputError::TooManyMethods);
        }
        let normalized = normalize_methods(self.methods.clone())?;
        if normalized != self.methods {
            return Err(AssuranceInputError::MethodsNotNormalized);
        }
        validate_optional_value("acr", self.acr.as_deref())?;
        validate_optional_value("context", self.context.as_deref())
    }

    /// Returns the standard `auth_time` value.
    pub fn auth_time(&self) -> i64 {
        self.authenticated_at.unix_timestamp()
    }

    /// Returns the corresponding compatibility MFA state in session context.
    pub fn mfa_state(&self) -> MfaState {
        MfaState {
            satisfied: self.mfa == MfaAcceptance::Satisfied,
            methods: Vec::new(),
        }
    }
}

fn normalize_methods<I, S>(methods: I) -> Result<Vec<String>, AssuranceInputError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut normalized = Vec::new();
    let mut seen = HashSet::new();
    let mut count = 0;
    for method in methods {
        count += 1;
        if count > MAX_ASSURANCE_METHODS {
            return Err(AssuranceInputError::TooManyMethods);
        }
        let method = method.into().trim().to_ascii_lowercase();
        if method.is_empty() || method.len() > MAX_ASSURANCE_METHOD_LENGTH {
            return Err(AssuranceInputError::InvalidMethod);
        }
        if seen.insert(method.clone()) {
            normalized.push(method);
        }
    }
    Ok(normalized)
}

fn validate_optional_value(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), AssuranceInputError> {
    if value
        .is_some_and(|value| value.trim().is_empty() || value.len() > MAX_ASSURANCE_CONTEXT_LENGTH)
    {
        return Err(AssuranceInputError::InvalidContext(field));
    }
    Ok(())
}

/// Invalid host-supplied assurance input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AssuranceInputError {
    /// Too many AMR values were supplied.
    #[error("too many authentication methods")]
    TooManyMethods,
    /// An AMR value was empty or oversized.
    #[error("invalid authentication method")]
    InvalidMethod,
    /// AMR values were not normalized and stable-deduplicated.
    #[error("authentication methods are not normalized")]
    MethodsNotNormalized,
    /// An ACR/context value was empty or oversized.
    #[error("invalid assurance {0}")]
    InvalidContext(&'static str),
}

/// Standard token metadata deliberately safe to carry across refresh rotation.
///
/// Per-token values (`jti`, expiry, purpose), sender/resource bindings (`cnf`,
/// resource type/ID), and arbitrary additional claims are intentionally absent.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefreshableTokenMetadata {
    /// Tenant or organization identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Organization identifier when distinct from tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    /// Actor/on-behalf-of identity accepted for the session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<crate::ActorIdentity>,
    /// Session-level authorization/audit correlation identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

/// Input for a successful, host-verified step-up event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StepUpAuthentication {
    /// Authentication methods used by the successful step-up.
    pub methods: Vec<String>,
    /// Host-accepted ACR for the step-up.
    pub acr: Option<String>,
    /// Host/provider namespace or policy context.
    pub context: Option<String>,
}

/// Stable public reason code for recent-MFA denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssuranceDenialCode {
    /// No authoritative assurance is present.
    AssuranceRequired,
    /// Host MFA policy was not satisfied.
    MfaRequired,
    /// AMR/ACR does not meet configured allowlists.
    AssuranceMethodNotAllowed,
    /// Authentication time is invalid or too far in the future.
    InvalidAuthenticationTime,
    /// Authentication is older than the configured maximum.
    AuthenticationTooOld,
    /// Policy configuration or time arithmetic was unsafe.
    AssurancePolicyError,
}

/// How configured AMR and ACR allowlists combine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AssuranceMatchMode {
    /// Every non-empty configured allowlist must match.
    #[default]
    All,
    /// At least one non-empty configured allowlist must match.
    Any,
}

impl AssuranceDenialCode {
    /// Stable machine-readable public code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AssuranceRequired => "ASSURANCE_REQUIRED",
            Self::MfaRequired => "MFA_REQUIRED",
            Self::AssuranceMethodNotAllowed => "ASSURANCE_METHOD_NOT_ALLOWED",
            Self::InvalidAuthenticationTime => "INVALID_AUTHENTICATION_TIME",
            Self::AuthenticationTooOld => "AUTHENTICATION_TOO_OLD",
            Self::AssurancePolicyError => "ASSURANCE_POLICY_ERROR",
        }
    }
}

/// Safe public denial with server-only diagnostic detail.
#[derive(Clone, PartialEq, Eq)]
pub struct AssuranceDenial {
    code: AssuranceDenialCode,
    internal_detail: String,
}

impl AssuranceDenial {
    fn new(code: AssuranceDenialCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            internal_detail: detail.into(),
        }
    }

    /// Stable public code.
    pub const fn code(&self) -> AssuranceDenialCode {
        self.code
    }

    /// Safe client-facing message.
    pub const fn public_message(&self) -> &'static str {
        "additional authentication is required"
    }

    /// Server-only diagnostic detail. Do not return this to clients.
    pub fn internal_detail(&self) -> &str {
        &self.internal_detail
    }
}

impl fmt::Debug for AssuranceDenial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AssuranceDenial")
            .field("code", &self.code)
            .field("message", &self.public_message())
            .finish()
    }
}

impl fmt::Display for AssuranceDenial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.public_message())
    }
}

impl std::error::Error for AssuranceDenial {}

/// Opt-in resource policy requiring current host-accepted MFA assurance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecentMfaPolicy {
    /// Maximum authentication age (inclusive).
    pub maximum_age: Duration,
    /// Allowed future clock skew (inclusive).
    pub clock_skew: Duration,
    /// Allowed AMR values. Empty means no AMR allowlist requirement.
    pub allowed_amr: Vec<String>,
    /// Allowed ACR values. Empty means no ACR allowlist requirement.
    pub allowed_acr: Vec<String>,
    /// Whether AMR and ACR allowlists combine with AND or OR semantics.
    pub match_mode: AssuranceMatchMode,
}

impl RecentMfaPolicy {
    /// Evaluates a signed, decoded user with an injected clock.
    pub fn evaluate(&self, user: &AuthUser, clock: &dyn Clock) -> Result<(), AssuranceDenial> {
        if self.maximum_age < Duration::ZERO || self.clock_skew < Duration::ZERO {
            return Err(AssuranceDenial::new(
                AssuranceDenialCode::AssurancePolicyError,
                "maximum_age and clock_skew must be non-negative",
            ));
        }
        let assurance = user.session.assurance.as_ref().ok_or_else(|| {
            AssuranceDenial::new(
                AssuranceDenialCode::AssuranceRequired,
                "session assurance missing",
            )
        })?;
        assurance.validate().map_err(|error| {
            AssuranceDenial::new(AssuranceDenialCode::AssuranceRequired, error.to_string())
        })?;
        if assurance.mfa != MfaAcceptance::Satisfied || !user.session.mfa.satisfied {
            return Err(AssuranceDenial::new(
                AssuranceDenialCode::MfaRequired,
                "host MFA acceptance is unsatisfied",
            ));
        }
        let amr_configured = !self.allowed_amr.is_empty();
        let acr_configured = !self.allowed_acr.is_empty();
        let amr_matches = assurance
            .methods
            .iter()
            .any(|method| self.allowed_amr.iter().any(|allowed| allowed == method));
        let acr_matches = assurance
            .acr
            .as_ref()
            .is_some_and(|acr| self.allowed_acr.iter().any(|allowed| allowed == acr));
        let allowlists_match = match self.match_mode {
            AssuranceMatchMode::All => {
                (!amr_configured || amr_matches) && (!acr_configured || acr_matches)
            }
            AssuranceMatchMode::Any => {
                (!amr_configured && !acr_configured)
                    || (amr_configured && amr_matches)
                    || (acr_configured && acr_matches)
            }
        };
        if !allowlists_match {
            return Err(AssuranceDenial::new(
                AssuranceDenialCode::AssuranceMethodNotAllowed,
                "session AMR/ACR did not satisfy the configured allowlists",
            ));
        }

        let token_auth_time = user.token_claims.auth_time.ok_or_else(|| {
            AssuranceDenial::new(
                AssuranceDenialCode::AssuranceRequired,
                "access token auth_time is missing",
            )
        })?;
        let token_authenticated_at =
            OffsetDateTime::from_unix_timestamp(token_auth_time).map_err(|_| {
                AssuranceDenial::new(
                    AssuranceDenialCode::InvalidAuthenticationTime,
                    "access token auth_time is outside supported bounds",
                )
            })?;
        if token_authenticated_at != assurance.authenticated_at
            || user.token_claims.amr.as_ref() != Some(&assurance.methods)
            || user.token_claims.acr != assurance.acr
        {
            return Err(AssuranceDenial::new(
                AssuranceDenialCode::AssuranceRequired,
                "access-token assurance claims do not match authoritative session assurance",
            ));
        }

        let now = clock.now();
        let latest = now.checked_add(self.clock_skew).ok_or_else(|| {
            AssuranceDenial::new(
                AssuranceDenialCode::AssurancePolicyError,
                "future-skew calculation overflowed",
            )
        })?;
        if token_authenticated_at > latest {
            return Err(AssuranceDenial::new(
                AssuranceDenialCode::InvalidAuthenticationTime,
                "auth_time is beyond allowed future clock skew",
            ));
        }
        let oldest = now.checked_sub(self.maximum_age).ok_or_else(|| {
            AssuranceDenial::new(
                AssuranceDenialCode::AssurancePolicyError,
                "maximum-age calculation overflowed",
            )
        })?;
        if token_authenticated_at < oldest {
            return Err(AssuranceDenial::new(
                AssuranceDenialCode::AuthenticationTooOld,
                "auth_time exceeds maximum authentication age",
            ));
        }
        Ok(())
    }
}
