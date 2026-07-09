use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::AuthResult;
use crate::errors::AuthError;
use crate::models::AuthUser;
use crate::session::SessionContext;
use crate::util::map_access_token_decode_error;

pub(crate) const ACCESS_TOKEN_TYPE: &str = "access";
pub(crate) const ACCESS_TOKEN_PURPOSE: &str = "access_token";

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
    pub(crate) aud: String,
    pub(crate) exp: i64,
    pub(crate) iat: i64,
    #[serde(default)]
    pub(crate) purpose: Option<String>,
}

pub(crate) struct AccessTokenDecodeConfig {
    pub(crate) decoding_key: DecodingKey,
    pub(crate) validation: Validation,
    pub(crate) expected_kid: Option<String>,
}

pub(crate) fn decode_access_token_claims(
    token: &str,
    config: &AccessTokenDecodeConfig,
) -> AuthResult<AccessTokenClaims> {
    let header = decode_header(token).map_err(|_| AuthError::InvalidAccessToken)?;
    if !config.validation.algorithms.contains(&header.alg) {
        return Err(AuthError::InvalidAccessToken);
    }

    if let Some(expected_kid) = &config.expected_kid {
        match header.kid.as_deref() {
            Some(actual_kid) if actual_kid == expected_kid => {}
            _ => return Err(AuthError::InvalidAccessToken),
        }
    }

    let token_data = decode::<AccessTokenClaims>(token, &config.decoding_key, &config.validation)
        .map_err(map_access_token_decode_error)?;
    let claims = token_data.claims;
    if claims.exp <= OffsetDateTime::now_utc().unix_timestamp() {
        return Err(AuthError::AccessTokenExpired);
    }
    if !matches!(claims.typ.as_deref(), None | Some(ACCESS_TOKEN_TYPE)) {
        return Err(AuthError::InvalidAccessToken);
    }
    if !matches!(claims.purpose.as_deref(), None | Some(ACCESS_TOKEN_PURPOSE)) {
        return Err(AuthError::InvalidAccessToken);
    }
    Uuid::parse_str(&claims.sid).map_err(|_| AuthError::InvalidAccessToken)?;

    Ok(claims)
}

pub(crate) fn access_token_claims_to_user(claims: AccessTokenClaims) -> AuthResult<AuthUser> {
    Ok(AuthUser {
        user_id: claims.sub,
        session_id: Uuid::parse_str(&claims.sid).map_err(|_| AuthError::InvalidAccessToken)?,
        roles: claims.roles,
        scopes: claims.scopes,
        session: claims.ctx,
    })
}
