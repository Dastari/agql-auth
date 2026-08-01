//! Authoritative session assurance and recent-MFA policy helpers.

use std::collections::{BTreeMap, HashSet};
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
/// Maximum UTF-8 byte length of a stable assurance policy identifier.
pub const MAX_ASSURANCE_POLICY_ID_LENGTH: usize = 128;

/// Stable, provider-neutral identifier for a host-defined assurance policy.
///
/// Policy identifiers are configuration identities shared by resource servers,
/// schemas, and clients. They are not provider ACR values and do not select an
/// authentication mechanism by themselves.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[serde(transparent)]
pub struct AssurancePolicyId(String);

impl AssurancePolicyId {
    /// Creates a validated policy identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, AssurancePolicyIdError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_ASSURANCE_POLICY_ID_LENGTH
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
            })
        {
            return Err(AssurancePolicyIdError);
        }
        Ok(Self(value))
    }

    /// Returns the stable wire value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Invalid stable assurance policy identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid assurance policy id")]
pub struct AssurancePolicyIdError;

impl fmt::Display for AssurancePolicyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AssurancePolicyId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Declarative requirement to satisfy one host-defined assurance policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct AssuranceRequirement {
    /// Stable policy identity. The host supplies the corresponding policy.
    pub policy_id: AssurancePolicyId,
}

impl AssuranceRequirement {
    /// Creates a requirement for a validated policy ID.
    pub const fn new(policy_id: AssurancePolicyId) -> Self {
        Self { policy_id }
    }
}

/// Server time at which an assurance decision was evaluated.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Ord, PartialOrd)]
#[serde(transparent)]
pub struct ServerEvaluationTime(OffsetDateTime);

impl ServerEvaluationTime {
    /// Returns the timestamp.
    pub const fn get(self) -> OffsetDateTime {
        self.0
    }
}

/// Genuine host-accepted authentication or step-up time.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Ord, PartialOrd)]
#[serde(transparent)]
pub struct AuthenticatedAt(OffsetDateTime);

impl AuthenticatedAt {
    /// Returns the timestamp.
    pub const fn get(self) -> OffsetDateTime {
        self.0
    }
}

/// Inclusive time through which the evaluated policy is satisfied.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Ord, PartialOrd)]
#[serde(transparent)]
pub struct SatisfiedUntil(OffsetDateTime);

impl SatisfiedUntil {
    /// Returns the timestamp.
    pub const fn get(self) -> OffsetDateTime {
        self.0
    }
}

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
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
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

    /// Stable GraphQL error category for this denial.
    ///
    /// Detailed assurance failures intentionally collapse to
    /// `STEP_UP_REQUIRED`; unsafe or missing policy configuration is
    /// `FORBIDDEN`. Callers therefore never need to parse a message.
    pub const fn graphql_extension_code(self) -> &'static str {
        match self {
            Self::AssurancePolicyError => "FORBIDDEN",
            Self::AssuranceRequired
            | Self::MfaRequired
            | Self::AssuranceMethodNotAllowed
            | Self::InvalidAuthenticationTime
            | Self::AuthenticationTooOld => "STEP_UP_REQUIRED",
        }
    }
}

/// Stable, client-safe result of evaluating an assurance requirement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AssuranceEvaluationState {
    /// The declared policy is satisfied through `satisfied_until`.
    Satisfied,
    /// No authenticated user session was supplied.
    Unauthenticated,
    /// The user session exists but needs additional authentication.
    StepUpRequired {
        /// Detailed machine-readable reason suitable for telemetry and UI logic.
        denial_code: AssuranceDenialCode,
    },
    /// The policy could not be safely evaluated or was not configured.
    Forbidden {
        /// Detailed machine-readable reason suitable for trusted diagnostics.
        denial_code: AssuranceDenialCode,
    },
}

impl AssuranceEvaluationState {
    /// GraphQL `extensions.code` value for a denied evaluation.
    pub const fn graphql_extension_code(&self) -> Option<&'static str> {
        match self {
            Self::Satisfied => None,
            Self::Unauthenticated => Some("UNAUTHENTICATED"),
            Self::StepUpRequired { .. } => Some("STEP_UP_REQUIRED"),
            Self::Forbidden { .. } => Some("FORBIDDEN"),
        }
    }

    /// Detailed denial code, when the evaluation reached a policy denial.
    pub const fn denial_code(&self) -> Option<AssuranceDenialCode> {
        match self {
            Self::StepUpRequired { denial_code } | Self::Forbidden { denial_code } => {
                Some(*denial_code)
            }
            Self::Satisfied | Self::Unauthenticated => None,
        }
    }
}

/// Safe, deterministic evaluation of one assurance requirement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssuranceEvaluation {
    /// Requirement that was evaluated.
    pub requirement: AssuranceRequirement,
    /// Server-authored decision state.
    pub state: AssuranceEvaluationState,
    /// Time read exactly once from the injected clock for this evaluation.
    pub server_evaluation_time: ServerEvaluationTime,
    /// Genuine accepted authentication time, when structurally trustworthy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated_at: Option<AuthenticatedAt>,
    /// Inclusive policy boundary, present only for a satisfied evaluation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub satisfied_until: Option<SatisfiedUntil>,
}

impl AssuranceEvaluation {
    /// Returns whether server-side evaluation satisfied the requirement.
    pub const fn is_satisfied(&self) -> bool {
        matches!(self.state, AssuranceEvaluationState::Satisfied)
    }
}

/// Credential-free session assurance projection suitable for clients.
///
/// This intentionally omits session IDs, method/context values, token claims,
/// access tokens, refresh tokens, secrets, and provider payloads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionAssuranceStatus {
    /// Whether an authenticated user session was supplied.
    pub authenticated: bool,
    /// Genuine accepted authentication time, when valid and claim-consistent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated_at: Option<AuthenticatedAt>,
    /// Whether the host accepted the session as MFA.
    pub mfa_satisfied: bool,
}

impl SessionAssuranceStatus {
    /// Projects a decoded user session without exposing credentials or claims payloads.
    pub fn from_user(user: Option<&AuthUser>) -> Self {
        let Some(user) = user else {
            return Self {
                authenticated: false,
                authenticated_at: None,
                mfa_satisfied: false,
            };
        };
        let assurance = user.session.assurance.as_ref().filter(|assurance| {
            assurance.validate().is_ok()
                && user.token_claims.auth_time == Some(assurance.auth_time())
                && user.token_claims.amr.as_ref() == Some(&assurance.methods)
                && user.token_claims.acr == assurance.acr
        });
        Self {
            authenticated: true,
            authenticated_at: assurance.map(|value| AuthenticatedAt(value.authenticated_at)),
            mfa_satisfied: assurance.is_some_and(|value| {
                value.mfa == MfaAcceptance::Satisfied && user.session.mfa.satisfied
            }),
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
        self.evaluate_at(user, clock.now()).map(|_| ())
    }

    /// Evaluates a declarative requirement and returns a client-safe status.
    pub fn evaluate_requirement(
        &self,
        requirement: &AssuranceRequirement,
        user: Option<&AuthUser>,
        clock: &dyn Clock,
    ) -> AssuranceEvaluation {
        let now = clock.now();
        let Some(user) = user else {
            return AssuranceEvaluation {
                requirement: requirement.clone(),
                state: AssuranceEvaluationState::Unauthenticated,
                server_evaluation_time: ServerEvaluationTime(now),
                authenticated_at: None,
                satisfied_until: None,
            };
        };
        match self.evaluate_at(user, now) {
            Ok((authenticated_at, satisfied_until)) => AssuranceEvaluation {
                requirement: requirement.clone(),
                state: AssuranceEvaluationState::Satisfied,
                server_evaluation_time: ServerEvaluationTime(now),
                authenticated_at: Some(AuthenticatedAt(authenticated_at)),
                satisfied_until: Some(SatisfiedUntil(satisfied_until)),
            },
            Err(denial) => {
                let code = denial.code();
                let state = if code.graphql_extension_code() == "FORBIDDEN" {
                    AssuranceEvaluationState::Forbidden { denial_code: code }
                } else {
                    AssuranceEvaluationState::StepUpRequired { denial_code: code }
                };
                AssuranceEvaluation {
                    requirement: requirement.clone(),
                    state,
                    server_evaluation_time: ServerEvaluationTime(now),
                    authenticated_at: None,
                    satisfied_until: None,
                }
            }
        }
    }

    fn evaluate_at(
        &self,
        user: &AuthUser,
        now: OffsetDateTime,
    ) -> Result<(OffsetDateTime, OffsetDateTime), AssuranceDenial> {
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
        let satisfied_until = token_authenticated_at
            .checked_add(self.maximum_age)
            .ok_or_else(|| {
                AssuranceDenial::new(
                    AssuranceDenialCode::AssurancePolicyError,
                    "satisfied-until calculation overflowed",
                )
            })?;
        Ok((token_authenticated_at, satisfied_until))
    }
}

/// Host-configured mapping from stable policy IDs to recent-MFA policies.
#[derive(Debug, Clone, Default)]
pub struct AssurancePolicySet {
    policies: BTreeMap<AssurancePolicyId, RecentMfaPolicy>,
}

impl AssurancePolicySet {
    /// Creates an empty policy set.
    pub const fn new() -> Self {
        Self {
            policies: BTreeMap::new(),
        }
    }

    /// Inserts or replaces one policy.
    pub fn insert(
        &mut self,
        policy_id: AssurancePolicyId,
        policy: RecentMfaPolicy,
    ) -> Option<RecentMfaPolicy> {
        self.policies.insert(policy_id, policy)
    }

    /// Returns a configured policy.
    pub fn get(&self, policy_id: &AssurancePolicyId) -> Option<&RecentMfaPolicy> {
        self.policies.get(policy_id)
    }

    /// Evaluates a requirement with one injected-clock read.
    ///
    /// An unknown policy fails closed as `FORBIDDEN`; it never falls back to a
    /// weaker policy or silently treats the requirement as satisfied.
    pub fn evaluate(
        &self,
        requirement: &AssuranceRequirement,
        user: Option<&AuthUser>,
        clock: &dyn Clock,
    ) -> AssuranceEvaluation {
        let Some(policy) = self.get(&requirement.policy_id) else {
            return AssuranceEvaluation {
                requirement: requirement.clone(),
                state: AssuranceEvaluationState::Forbidden {
                    denial_code: AssuranceDenialCode::AssurancePolicyError,
                },
                server_evaluation_time: ServerEvaluationTime(clock.now()),
                authenticated_at: None,
                satisfied_until: None,
            };
        };
        policy.evaluate_requirement(requirement, user, clock)
    }
}
