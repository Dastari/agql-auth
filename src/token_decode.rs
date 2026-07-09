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
use crate::errors::AuthError;
use crate::models::AuthUser;
use crate::session::SessionContext;
use crate::util::map_access_token_decode_error;

pub(crate) const ACCESS_TOKEN_TYPE: &str = "access";
pub(crate) const ACCESS_TOKEN_PURPOSE: &str = "access_token";

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
    #[serde(default)]
    pub(crate) typ: Option<String>,
    pub(crate) sub: String,
    pub(crate) sid: String,
    pub(crate) roles: Vec<String>,
    #[serde(default)]
    pub(crate) scopes: Vec<String>,
    #[serde(default)]
    pub(crate) ctx: SessionContext,
    pub(crate) iss: String,
    pub(crate) aud: JsonValue,
    pub(crate) exp: i64,
    pub(crate) iat: i64,
    #[serde(default)]
    pub(crate) nbf: Option<i64>,
    #[serde(default)]
    pub(crate) purpose: Option<String>,
    #[serde(default)]
    pub(crate) jti: Option<String>,
    #[serde(default)]
    pub(crate) tenant_id: Option<String>,
    #[serde(default)]
    pub(crate) organization_id: Option<String>,
    #[serde(default)]
    pub(crate) session_family_id: Option<String>,
    #[serde(default)]
    pub(crate) actor: Option<ActorIdentity>,
    #[serde(default)]
    pub(crate) auth_time: Option<i64>,
    #[serde(default)]
    pub(crate) amr: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) acr: Option<String>,
    #[serde(default)]
    pub(crate) cnf: Option<ConfirmationClaims>,
    #[serde(default)]
    pub(crate) resource_type: Option<String>,
    #[serde(default)]
    pub(crate) resource_id: Option<String>,
    #[serde(default)]
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
    ) -> Self {
        let allowed_algorithms = validation.algorithms.clone();
        Self {
            decoding_key,
            validation,
            expected_kid,
            leeway_seconds: 0,
            purpose_policy: PurposePolicy::AccessTokenOrLegacy,
            claim_requirements: ClaimRequirements::default(),
            clock: Arc::new(SystemClock),
            allowed_algorithms,
        }
    }
}

pub(crate) fn decode_access_token_claims(
    token: &str,
    config: &AccessTokenDecodeConfig,
) -> AuthResult<AccessTokenClaims> {
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

    let metadata = claims_to_metadata(&claims);
    config
        .claim_requirements
        .validate(&metadata)
        .map_err(|_| AuthError::InvalidAccessToken)?;

    Ok(claims)
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

pub(crate) fn access_token_claims_to_user(claims: AccessTokenClaims) -> AuthResult<AuthUser> {
    let metadata = claims_to_metadata(&claims);
    Ok(AuthUser {
        user_id: claims.sub,
        session_id: Uuid::parse_str(&claims.sid).map_err(|_| AuthError::InvalidAccessToken)?,
        roles: claims.roles,
        scopes: claims.scopes,
        session: claims.ctx,
        token_claims: metadata,
    })
}

pub(crate) fn audience_claim(audience: &str) -> JsonValue {
    JsonValue::String(audience.to_string())
}
