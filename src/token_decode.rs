use std::collections::BTreeMap;
use std::sync::Arc;

use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::AuthResult;
use crate::claims::{AccessTokenMetadata, ActorIdentity, ClaimRequirements, ConfirmationClaims};
use crate::clock::{Clock, SystemClock};
use crate::config::{AccessTokenScopeClaimFormat, LegacyScopeClaims};
use crate::errors::AuthError;
use crate::models::AuthUser;
use crate::session::SessionContext;
use crate::util::map_access_token_decode_error;

pub(crate) const ACCESS_TOKEN_TYPE: &str = "access";
pub(crate) const ACCESS_TOKEN_PURPOSE: &str = "access_token";

/// Maximum number of scope values accepted in one access token.
pub const MAX_ACCESS_TOKEN_SCOPES: usize = 256;
/// Maximum encoded byte length of one access-token scope value.
pub const MAX_ACCESS_TOKEN_SCOPE_LENGTH: usize = 512;
/// Maximum aggregate encoded byte length of access-token scope values.
pub const MAX_ACCESS_TOKEN_SCOPE_CLAIM_LENGTH: usize = 16 * 1024;

/// How missing `purpose` claims are treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PurposePolicy {
    /// Accept `purpose = access_token` and legacy tokens without purpose.
    #[default]
    AccessTokenOrLegacy,
    /// Require `purpose = access_token`.
    RequireAccessToken,
}

/// Whether raw tokens without a `Bearer` scheme are accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BearerParseMode {
    /// Accept `Bearer <token>` and raw token values.
    #[default]
    BearerOrRaw,
    /// Require an explicit `Bearer` scheme.
    RequireBearer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AccessTokenClaims {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) typ: Option<String>,
    pub(crate) sub: String,
    pub(crate) sid: String,
    pub(crate) roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) scope: Option<String>,
    #[serde(default, rename = "scopes", skip_serializing_if = "Option::is_none")]
    pub(crate) legacy_scopes: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) ctx: SessionContext,
    pub(crate) iss: String,
    pub(crate) aud: JsonValue,
    pub(crate) exp: i64,
    pub(crate) iat: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) nbf: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) organization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) session_family_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) actor: Option<ActorIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) auth_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) amr: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) acr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cnf: Option<ConfirmationClaims>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) resource_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) resource_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) correlation_id: Option<String>,
    #[serde(default, flatten)]
    pub(crate) additional: BTreeMap<String, JsonValue>,
}

pub(crate) struct AccessTokenDecodeConfig {
    pub(crate) decoding_key: DecodingKey,
    pub(crate) validation: Validation,
    pub(crate) expected_kid: Option<String>,
    pub(crate) leeway_seconds: u64,
    pub(crate) purpose_policy: PurposePolicy,
    pub(crate) legacy_scope_claims: LegacyScopeClaims,
    pub(crate) claim_requirements: ClaimRequirements,
    pub(crate) clock: Arc<dyn Clock>,
    /// When set, algorithm is taken from the resolved key path instead.
    pub(crate) allowed_algorithms: Vec<jsonwebtoken::Algorithm>,
}

impl AccessTokenDecodeConfig {
    pub(crate) fn for_service(
        decoding_key: DecodingKey,
        validation: Validation,
        expected_kid: Option<String>,
        legacy_scope_claims: LegacyScopeClaims,
    ) -> Self {
        let allowed_algorithms = validation.algorithms.clone();
        Self {
            decoding_key,
            validation,
            expected_kid,
            leeway_seconds: 0,
            purpose_policy: PurposePolicy::AccessTokenOrLegacy,
            legacy_scope_claims,
            claim_requirements: ClaimRequirements::default(),
            clock: Arc::new(SystemClock),
            allowed_algorithms,
        }
    }
}

pub(crate) fn decode_access_token_claims(
    token: &str,
    config: &AccessTokenDecodeConfig,
) -> AuthResult<DecodedAccessTokenClaims> {
    let header = decode_header(token).map_err(|_| AuthError::InvalidAccessToken)?;
    if !config.allowed_algorithms.contains(&header.alg)
        && !config.validation.algorithms.contains(&header.alg)
    {
        return Err(AuthError::InvalidAccessToken);
    }

    if let Some(expected_kid) = &config.expected_kid {
        match header.kid.as_deref() {
            Some(actual_kid) if actual_kid == expected_kid => {}
            _ => return Err(AuthError::InvalidAccessToken),
        }
    }

    let mut validation = config.validation.clone();
    // Perform exp/nbf checks with the injectable clock so tests are deterministic
    // and leeway is applied consistently.
    validation.validate_exp = false;
    validation.validate_nbf = false;

    let token_data = decode::<AccessTokenClaims>(token, &config.decoding_key, &validation)
        .map_err(map_access_token_decode_error)?;
    let claims = token_data.claims;

    validate_time_claims(&claims, config)?;
    validate_type_and_purpose(&claims, config.purpose_policy)?;
    Uuid::parse_str(&claims.sid).map_err(|_| AuthError::InvalidAccessToken)?;
    let scopes = parse_access_token_scopes(&claims, config.legacy_scope_claims)?;

    let metadata = claims_to_metadata(&claims);
    config
        .claim_requirements
        .validate(&metadata)
        .map_err(|_| AuthError::InvalidAccessToken)?;

    Ok(DecodedAccessTokenClaims { claims, scopes })
}

pub(crate) struct DecodedAccessTokenClaims {
    claims: AccessTokenClaims,
    scopes: Vec<String>,
}

fn validate_time_claims(
    claims: &AccessTokenClaims,
    config: &AccessTokenDecodeConfig,
) -> AuthResult<()> {
    let now = config.clock.now().unix_timestamp();
    let leeway = i64::try_from(config.leeway_seconds).unwrap_or(i64::MAX);

    if claims.exp + leeway <= now {
        return Err(AuthError::AccessTokenExpired);
    }
    if let Some(nbf) = claims.nbf
        && nbf > now + leeway
    {
        return Err(AuthError::InvalidAccessToken);
    }
    Ok(())
}

fn validate_type_and_purpose(
    claims: &AccessTokenClaims,
    purpose_policy: PurposePolicy,
) -> AuthResult<()> {
    if !matches!(claims.typ.as_deref(), None | Some(ACCESS_TOKEN_TYPE)) {
        return Err(AuthError::InvalidAccessToken);
    }
    match purpose_policy {
        PurposePolicy::AccessTokenOrLegacy => {
            if !matches!(claims.purpose.as_deref(), None | Some(ACCESS_TOKEN_PURPOSE)) {
                return Err(AuthError::InvalidAccessToken);
            }
        }
        PurposePolicy::RequireAccessToken => {
            if claims.purpose.as_deref() != Some(ACCESS_TOKEN_PURPOSE) {
                return Err(AuthError::InvalidAccessToken);
            }
        }
    }
    Ok(())
}

pub(crate) fn claims_to_metadata(claims: &AccessTokenClaims) -> AccessTokenMetadata {
    let expires_at = OffsetDateTime::from_unix_timestamp(claims.exp).ok();
    AccessTokenMetadata {
        jti: claims.jti.clone(),
        tenant_id: claims.tenant_id.clone(),
        organization_id: claims.organization_id.clone(),
        session_family_id: claims.session_family_id.clone(),
        actor: claims.actor.clone(),
        auth_time: claims.auth_time,
        amr: claims.amr.clone(),
        acr: claims.acr.clone(),
        cnf: claims.cnf.clone(),
        resource_type: claims.resource_type.clone(),
        resource_id: claims.resource_id.clone(),
        correlation_id: claims.correlation_id.clone(),
        purpose: claims.purpose.clone(),
        expires_at,
        additional: claims.additional.clone(),
    }
}

pub(crate) fn access_token_claims_to_user(
    decoded: DecodedAccessTokenClaims,
) -> AuthResult<AuthUser> {
    let claims = decoded.claims;
    let metadata = claims_to_metadata(&claims);
    Ok(AuthUser {
        user_id: claims.sub,
        session_id: Uuid::parse_str(&claims.sid).map_err(|_| AuthError::InvalidAccessToken)?,
        roles: claims.roles,
        scopes: decoded.scopes,
        session: claims.ctx,
        token_claims: metadata,
    })
}

pub(crate) fn issued_scope_claims(
    scopes: &[String],
    format: AccessTokenScopeClaimFormat,
) -> AuthResult<(Option<String>, Option<Vec<String>>)> {
    if !valid_scope_set(scopes) {
        return Err(AuthError::TokenCreation(
            "access-token scopes contain a value that cannot be represented safely".to_string(),
        ));
    }

    Ok(match format {
        AccessTokenScopeClaimFormat::Standard => {
            let scope = (!scopes.is_empty()).then(|| scopes.join(" "));
            (scope, None)
        }
        AccessTokenScopeClaimFormat::LegacyArray => (None, Some(scopes.to_vec())),
    })
}

fn parse_access_token_scopes(
    claims: &AccessTokenClaims,
    legacy_policy: LegacyScopeClaims,
) -> AuthResult<Vec<String>> {
    let standard = claims
        .scope
        .as_deref()
        .map(parse_standard_scope)
        .transpose()?;
    let legacy = match claims.legacy_scopes.as_deref() {
        None => None,
        Some(_) if legacy_policy == LegacyScopeClaims::Reject => {
            return Err(AuthError::InvalidAccessToken);
        }
        Some(scopes) => Some(parse_legacy_scopes(scopes)?),
    };

    match (standard, legacy) {
        (Some(standard), Some(legacy))
            if canonical_scopes(&standard) != canonical_scopes(&legacy) =>
        {
            Err(AuthError::InvalidAccessToken)
        }
        (Some(standard), _) => Ok(standard),
        (None, Some(legacy)) => Ok(legacy),
        (None, None) => Ok(Vec::new()),
    }
}

fn parse_standard_scope(value: &str) -> AuthResult<Vec<String>> {
    if value.is_empty() || value.len() > MAX_ACCESS_TOKEN_SCOPE_CLAIM_LENGTH {
        return Err(AuthError::InvalidAccessToken);
    }
    let scopes = value.split(' ').map(str::to_owned).collect::<Vec<_>>();
    if !valid_scope_set(&scopes) {
        return Err(AuthError::InvalidAccessToken);
    }
    Ok(dedupe_stable(scopes))
}

fn parse_legacy_scopes(scopes: &[String]) -> AuthResult<Vec<String>> {
    if !valid_scope_set(scopes) {
        return Err(AuthError::InvalidAccessToken);
    }
    Ok(dedupe_stable(scopes.to_vec()))
}

fn canonical_scopes(scopes: &[String]) -> Vec<&str> {
    let mut canonical = scopes.iter().map(String::as_str).collect::<Vec<_>>();
    canonical.sort_unstable();
    canonical.dedup();
    canonical
}

fn dedupe_stable(scopes: Vec<String>) -> Vec<String> {
    let mut result = Vec::with_capacity(scopes.len());
    for scope in scopes {
        if !result.contains(&scope) {
            result.push(scope);
        }
    }
    result
}

fn valid_scope_token(scope: &str) -> bool {
    !scope.is_empty()
        && scope.len() <= MAX_ACCESS_TOKEN_SCOPE_LENGTH
        && scope
            .bytes()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
}

fn valid_scope_set(scopes: &[String]) -> bool {
    scopes.len() <= MAX_ACCESS_TOKEN_SCOPES
        && scopes.iter().all(|scope| valid_scope_token(scope))
        && scopes
            .iter()
            .try_fold(0usize, |total, scope| total.checked_add(scope.len()))
            .and_then(|total| total.checked_add(scopes.len().saturating_sub(1)))
            .is_some_and(|total| total <= MAX_ACCESS_TOKEN_SCOPE_CLAIM_LENGTH)
}

pub(crate) fn audience_claim(audience: &str) -> JsonValue {
    JsonValue::String(audience.to_string())
}
