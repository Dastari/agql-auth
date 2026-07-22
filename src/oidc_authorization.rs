use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as JsonValue, json};
use time::OffsetDateTime;

use crate::{AuthError, AuthResult};

/// Maximum accepted `max_age` request, in seconds (one year).
pub const MAX_OIDC_MAX_AGE_SECONDS: u64 = 31_536_000;
/// Maximum number of values in an OIDC prompt or assurance-context list.
pub const MAX_OIDC_AUTHORIZATION_VALUES: usize = 16;
/// Maximum UTF-8 byte length of one requested or returned context value.
pub const MAX_OIDC_AUTHORIZATION_VALUE_LENGTH: usize = 256;
/// Maximum aggregate UTF-8 byte length of a context list.
pub const MAX_OIDC_AUTHORIZATION_TOTAL_VALUE_LENGTH: usize = 2_048;
/// Maximum serialized size of the OIDC `claims` request.
pub const MAX_OIDC_CLAIMS_REQUEST_LENGTH: usize = 4_096;

/// Standard OIDC `prompt` values supported by typed authorization requests.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum OidcPrompt {
    /// Do not display authentication or consent UI. This cannot be combined
    /// with another prompt value.
    None,
    /// Require active reauthentication.
    Login,
    /// Ask the user for consent.
    Consent,
    /// Ask the user to select an account.
    SelectAccount,
}

impl OidcPrompt {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Login => "login",
            Self::Consent => "consent",
            Self::SelectAccount => "select_account",
        }
    }
}

/// Typed ID-token claim requirements supported by authorization requests.
///
/// These requirements request provider evidence. They do not accept that
/// evidence as local MFA; host mapping remains a separate trust boundary.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "claim", rename_all = "snake_case")]
pub enum OidcIdTokenClaimRequest {
    /// Require a provider `auth_time` claim.
    EssentialAuthTime,
    /// Require the standard scalar `acr` claim to equal one of these values.
    EssentialAcr {
        /// Exact, case-sensitive accepted `acr` values.
        values: Vec<String>,
    },
    /// Require the provider list-valued `acrs` claim to contain this exact
    /// authentication-context reference.
    EssentialAcrs {
        /// Exact, case-sensitive authentication-context reference.
        value: String,
    },
}

impl fmt::Debug for OidcIdTokenClaimRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EssentialAuthTime => f.write_str("EssentialAuthTime"),
            Self::EssentialAcr { values } => f
                .debug_struct("EssentialAcr")
                .field("value_count", &values.len())
                .finish(),
            Self::EssentialAcrs { .. } => f
                .debug_struct("EssentialAcrs")
                .field("value", &"[redacted]")
                .finish(),
        }
    }
}

/// Typed inputs for an OIDC authorization request.
///
/// Validation occurs before OAuth state is inserted. The type intentionally
/// has no arbitrary query-parameter map, so reserved parameter collisions are
/// structurally unrepresentable.
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcAuthorizationOptions {
    /// Standard prompt values. Duplicates and `none` combinations are rejected.
    #[serde(default)]
    pub prompt: Vec<OidcPrompt>,
    /// Requested maximum authentication age in seconds. Zero is permitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age: Option<i64>,
    /// Voluntary, ordered standard `acr_values` preferences.
    #[serde(default)]
    pub acr_values: Vec<String>,
    /// Essential ID-token claim requirements.
    #[serde(default)]
    pub id_token_claims: Vec<OidcIdTokenClaimRequest>,
}

impl fmt::Debug for OidcAuthorizationOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcAuthorizationOptions")
            .field("prompt", &self.prompt)
            .field("max_age", &self.max_age)
            .field("acr_value_count", &self.acr_values.len())
            .field("id_token_claim_count", &self.id_token_claims.len())
            .finish()
    }
}

impl OidcAuthorizationOptions {
    /// Normalizes and validates these options without creating provider state.
    pub fn validate(&self) -> AuthResult<OidcAuthorizationPolicy> {
        OidcAuthorizationPolicy::try_from(self)
    }
}

/// Versioned normalized policy cryptographically correlated through OAuth state.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcAuthorizationPolicy {
    version: u8,
    prompt: Vec<OidcPrompt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_age_seconds: Option<u64>,
    #[serde(default)]
    acr_values: Vec<String>,
    #[serde(default)]
    essential_auth_time: bool,
    #[serde(default)]
    essential_acr_values: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    essential_acrs_value: Option<String>,
}

impl fmt::Debug for OidcAuthorizationPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcAuthorizationPolicy")
            .field("version", &self.version)
            .field("prompt", &self.prompt)
            .field("max_age_seconds", &self.max_age_seconds)
            .field("acr_value_count", &self.acr_values.len())
            .field("essential_auth_time", &self.essential_auth_time)
            .field(
                "essential_acr_value_count",
                &self.essential_acr_values.len(),
            )
            .field("essential_acrs", &self.essential_acrs_value.is_some())
            .finish()
    }
}

impl OidcAuthorizationPolicy {
    /// Stored representation version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Normalized prompt values.
    pub fn prompt(&self) -> &[OidcPrompt] {
        &self.prompt
    }

    /// Requested maximum authentication age, in seconds.
    pub fn max_age_seconds(&self) -> Option<u64> {
        self.max_age_seconds
    }

    /// Ordered, voluntary standard ACR preferences.
    pub fn acr_values(&self) -> &[String] {
        &self.acr_values
    }

    /// Whether a signed `auth_time` was essential.
    pub fn essential_auth_time(&self) -> bool {
        self.essential_auth_time
    }

    /// Exact standard scalar ACR values required in the ID token.
    pub fn essential_acr_values(&self) -> &[String] {
        &self.essential_acr_values
    }

    /// Exact provider list-valued `acrs` context required in the ID token.
    pub fn essential_acrs_value(&self) -> Option<&str> {
        self.essential_acrs_value.as_deref()
    }

    pub(crate) fn prompt_parameter(&self) -> Option<String> {
        (!self.prompt.is_empty()).then(|| {
            self.prompt
                .iter()
                .map(|value| value.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        })
    }

    pub(crate) fn acr_values_parameter(&self) -> Option<String> {
        (!self.acr_values.is_empty()).then(|| self.acr_values.join(" "))
    }

    pub(crate) fn claims_parameter(&self) -> AuthResult<Option<String>> {
        if !self.essential_auth_time
            && self.essential_acr_values.is_empty()
            && self.essential_acrs_value.is_none()
        {
            return Ok(None);
        }
        let mut id_token = Map::new();
        if self.essential_auth_time {
            id_token.insert("auth_time".to_string(), json!({ "essential": true }));
        }
        if !self.essential_acr_values.is_empty() {
            id_token.insert(
                "acr".to_string(),
                json!({ "essential": true, "values": self.essential_acr_values }),
            );
        }
        if let Some(value) = &self.essential_acrs_value {
            id_token.insert(
                "acrs".to_string(),
                json!({ "essential": true, "value": value }),
            );
        }
        let mut root = Map::new();
        root.insert("id_token".to_string(), JsonValue::Object(id_token));
        let serialized = serde_json::to_string(&JsonValue::Object(root)).map_err(|_| {
            AuthError::InvalidOidcAuthorizationOptions(
                "claims request could not be serialized".to_string(),
            )
        })?;
        if serialized.len() > MAX_OIDC_CLAIMS_REQUEST_LENGTH {
            return Err(AuthError::InvalidOidcAuthorizationOptions(
                "claims request exceeds the size limit".to_string(),
            ));
        }
        Ok(Some(serialized))
    }

    pub(crate) fn validate_stored(&self) -> AuthResult<()> {
        match self.version {
            1 if self.essential_acrs_value.is_some() => {
                return invalid("stored version 1 policy contains an acrs requirement");
            }
            1 => {}
            2 if self.essential_acrs_value.is_none() => {
                return invalid("stored version 2 policy is missing its acrs requirement");
            }
            2 => {}
            _ => return invalid("stored authorization policy version is unsupported"),
        }
        if self
            .max_age_seconds
            .is_some_and(|value| value > MAX_OIDC_MAX_AGE_SECONDS)
        {
            return invalid("stored max_age exceeds the finite limit");
        }
        if self.prompt.len() > MAX_OIDC_AUTHORIZATION_VALUES {
            return invalid("stored policy has too many prompt values");
        }
        let mut prompts = HashSet::new();
        if self.prompt.iter().any(|value| !prompts.insert(*value)) {
            return invalid("stored policy has duplicate prompt values");
        }
        if self.prompt.contains(&OidcPrompt::None) && self.prompt.len() != 1 {
            return invalid("stored prompt none has an invalid combination");
        }
        validate_values("stored acr_values", &self.acr_values, false)?;
        validate_values(
            "stored essential acr",
            &self.essential_acr_values,
            !self.essential_acr_values.is_empty(),
        )?;
        if let Some(value) = &self.essential_acrs_value {
            validate_values("stored essential acrs", std::slice::from_ref(value), true)?;
        }
        if !self.acr_values.is_empty() && !self.essential_acr_values.is_empty() {
            return invalid("stored policy combines voluntary and essential acr requests");
        }
        let _ = self.claims_parameter()?;
        Ok(())
    }
}

impl TryFrom<&OidcAuthorizationOptions> for OidcAuthorizationPolicy {
    type Error = AuthError;

    fn try_from(options: &OidcAuthorizationOptions) -> Result<Self, Self::Error> {
        if options.prompt.len() > MAX_OIDC_AUTHORIZATION_VALUES {
            return invalid("too many prompt values");
        }
        let mut seen_prompt = HashSet::new();
        for prompt in &options.prompt {
            if !seen_prompt.insert(*prompt) {
                return invalid("duplicate prompt value");
            }
        }
        if options.prompt.contains(&OidcPrompt::None) && options.prompt.len() != 1 {
            return invalid("prompt none cannot be combined with another prompt");
        }

        let max_age_seconds = options
            .max_age
            .map(|value| {
                let value = u64::try_from(value)
                    .map_err(|_| invalid_error("max_age must be non-negative"))?;
                if value > MAX_OIDC_MAX_AGE_SECONDS {
                    return invalid("max_age exceeds the finite limit");
                }
                Ok(value)
            })
            .transpose()?;

        validate_values("acr_values", &options.acr_values, false)?;

        let mut essential_auth_time = false;
        let mut essential_acr_values = Vec::new();
        let mut essential_acrs_value = None;
        for claim in &options.id_token_claims {
            match claim {
                OidcIdTokenClaimRequest::EssentialAuthTime => {
                    if essential_auth_time {
                        return invalid("duplicate auth_time claim requirement");
                    }
                    essential_auth_time = true;
                }
                OidcIdTokenClaimRequest::EssentialAcr { values } => {
                    if !essential_acr_values.is_empty() {
                        return invalid("duplicate acr claim requirement");
                    }
                    validate_values("essential acr", values, true)?;
                    essential_acr_values.clone_from(values);
                }
                OidcIdTokenClaimRequest::EssentialAcrs { value } => {
                    if essential_acrs_value.is_some() {
                        return invalid("duplicate acrs claim requirement");
                    }
                    validate_values("essential acrs", std::slice::from_ref(value), true)?;
                    essential_acrs_value = Some(value.clone());
                }
            }
        }
        if !options.acr_values.is_empty() && !essential_acr_values.is_empty() {
            return invalid("acr_values and an essential acr claim cannot be combined");
        }

        let policy = Self {
            version: if essential_acrs_value.is_some() { 2 } else { 1 },
            prompt: options.prompt.clone(),
            max_age_seconds,
            acr_values: options.acr_values.clone(),
            essential_auth_time,
            essential_acr_values,
            essential_acrs_value,
        };
        let _ = policy.claims_parameter()?;
        Ok(policy)
    }
}

/// Validated result of enforcing a policy bound to the consumed OAuth state.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcAuthorizationOutcome {
    /// Normalized bound policy, or `None` for a legacy/default login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<OidcAuthorizationPolicy>,
    /// Authentication time whose presence/freshness was enforced, when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced_auth_time: Option<OffsetDateTime>,
    /// Exact standard scalar ACR that matched an essential request, when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_acr: Option<String>,
    /// Exact provider list-valued `acrs` context that matched the bound
    /// request, when any. This remains provider evidence, not local MFA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_acrs: Option<String>,
}

impl fmt::Debug for OidcAuthorizationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcAuthorizationOutcome")
            .field("policy", &self.policy)
            .field("enforced_auth_time", &self.enforced_auth_time)
            .field(
                "matched_acr",
                &self.matched_acr.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "matched_acrs",
                &self.matched_acrs.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

impl OidcAuthorizationOutcome {
    /// Returns `true` only for a callback bound to non-default typed options.
    pub fn is_bound_authorization(&self) -> bool {
        self.policy.is_some()
    }

    /// Returns `true` when authentication time was actively enforced.
    pub fn recent_authentication_was_enforced(&self) -> bool {
        self.enforced_auth_time.is_some()
    }

    /// Fails closed unless this callback enforced the exact normalized policy
    /// expected by the host's reauthentication endpoint.
    pub fn require_bound_policy(&self, expected: &OidcAuthorizationPolicy) -> AuthResult<()> {
        if self.policy.as_ref() == Some(expected) {
            Ok(())
        } else {
            Err(AuthError::OidcTokenValidation(
                "callback was not bound to the expected authorization policy".to_string(),
            ))
        }
    }
}

pub(crate) fn validate_acrs(values: &[String]) -> AuthResult<()> {
    validate_values("acrs", values, true)
        .map_err(|error| AuthError::OidcTokenValidation(error.to_string()))
}

fn validate_values(label: &str, values: &[String], require_nonempty: bool) -> AuthResult<()> {
    if require_nonempty && values.is_empty() {
        return invalid(&format!("{label} must contain a value"));
    }
    if values.len() > MAX_OIDC_AUTHORIZATION_VALUES {
        return invalid(&format!("{label} contains too many values"));
    }
    let mut seen = HashSet::new();
    let mut total = 0usize;
    for value in values {
        if value.is_empty()
            || value.trim() != value
            || value
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return invalid(&format!(
                "{label} contains a blank, control, or noncanonical value"
            ));
        }
        if value.len() > MAX_OIDC_AUTHORIZATION_VALUE_LENGTH {
            return invalid(&format!("{label} contains an oversized value"));
        }
        total = total
            .checked_add(value.len())
            .ok_or_else(|| invalid_error(&format!("{label} aggregate size overflowed")))?;
        if total > MAX_OIDC_AUTHORIZATION_TOTAL_VALUE_LENGTH {
            return invalid(&format!("{label} exceeds the aggregate size limit"));
        }
        if !seen.insert(value) {
            return invalid(&format!("{label} contains a duplicate value"));
        }
    }
    Ok(())
}

fn invalid<T>(detail: &str) -> AuthResult<T> {
    Err(invalid_error(detail))
}

fn invalid_error(detail: &str) -> AuthError {
    AuthError::InvalidOidcAuthorizationOptions(detail.to_string())
}
