use std::sync::Arc;

use async_graphql::Request;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::Value as JsonValue;

use crate::scope_match::{AuthRuntime, ExactScopeMatch, ScopeMatch};
use crate::token_decode::{
    AccessTokenDecodeConfig, access_token_claims_to_user, decode_access_token_claims,
};
use crate::util::strip_bearer_prefix;
use crate::{AuthError, AuthPrincipal, AuthResult, AuthUser};

const MIN_HS256_SECRET_BYTES: usize = 32;

/// Store-free validator for local `agql-auth` access tokens.
///
/// Resource servers can use this with issuer, audience, and static public key
/// material without implementing [`crate::UserStore`] or
/// [`crate::RefreshTokenStore`].
pub struct AccessTokenValidator {
    decode: AccessTokenDecodeConfig,
    scope_matcher: Arc<dyn ScopeMatch>,
}

/// Builder for [`AccessTokenValidator`].
pub struct AccessTokenValidatorBuilder {
    issuer: Option<String>,
    audience: Option<String>,
    leeway_seconds: Option<u64>,
    key_id: Option<String>,
    key_material: Option<ValidatorKeyMaterial>,
    accept_hs256: bool,
    scope_matcher: Arc<dyn ScopeMatch>,
}

enum ValidatorKeyMaterial {
    Rs256PublicPem(String),
    JwksJson(String),
    Hs256Secret(String),
}

impl AccessTokenValidatorBuilder {
    /// Creates a validator builder.
    pub fn new() -> Self {
        Self {
            issuer: None,
            audience: None,
            leeway_seconds: None,
            key_id: None,
            key_material: None,
            accept_hs256: false,
            scope_matcher: Arc::new(ExactScopeMatch),
        }
    }

    /// Sets the expected issuer.
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Sets the expected audience.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Sets clock skew in seconds for JWT validation.
    pub fn leeway_seconds(mut self, seconds: u64) -> Self {
        self.leeway_seconds = Some(seconds);
        self
    }

    /// Uses an RS256 public key PEM.
    pub fn rs256_public_pem(mut self, pem: impl Into<String>) -> Self {
        self.key_material = Some(ValidatorKeyMaterial::Rs256PublicPem(pem.into()));
        self
    }

    /// Uses a static JWKS JSON document.
    ///
    /// When the JWKS has multiple keys, call [`Self::key_id`] so the validator
    /// can select the intended key.
    pub fn jwks_json(mut self, jwks_json: impl Into<String>) -> Self {
        self.key_material = Some(ValidatorKeyMaterial::JwksJson(jwks_json.into()));
        self
    }

    /// Requires the JWT header `kid` to match this key id.
    pub fn key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// Uses an HS256 secret. HS256 remains disabled unless
    /// [`Self::accept_hs256`] is also set to `true`.
    pub fn hs256_secret(mut self, secret: impl Into<String>) -> Self {
        self.key_material = Some(ValidatorKeyMaterial::Hs256Secret(secret.into()));
        self
    }

    /// Explicitly enables or disables HS256 validation.
    pub fn accept_hs256(mut self, yes: bool) -> Self {
        self.accept_hs256 = yes;
        self
    }

    /// Sets the request-time scope matcher injected into GraphQL data.
    pub fn scope_matcher(mut self, matcher: Arc<dyn ScopeMatch>) -> Self {
        self.scope_matcher = matcher;
        self
    }

    /// Builds the validator.
    pub fn build(self) -> AuthResult<AccessTokenValidator> {
        let issuer = required_non_empty(self.issuer, "issuer")?;
        let audience = required_non_empty(self.audience, "audience")?;
        let key_material = self.key_material.ok_or_else(|| {
            AuthError::InvalidConfiguration("validator key material is required".to_string())
        })?;

        let (algorithm, decoding_key, expected_kid) =
            build_decoding_key(key_material, self.key_id, self.accept_hs256)?;
        let mut validation = Validation::new(algorithm);
        validation.set_issuer(std::slice::from_ref(&issuer));
        validation.set_audience(std::slice::from_ref(&audience));
        if let Some(leeway) = self.leeway_seconds {
            validation.leeway = leeway;
        }
        validation.required_spec_claims.extend(
            ["exp", "iat", "iss", "aud", "sub"]
                .into_iter()
                .map(str::to_string),
        );

        Ok(AccessTokenValidator {
            decode: AccessTokenDecodeConfig {
                decoding_key,
                validation,
                expected_kid,
            },
            scope_matcher: self.scope_matcher,
        })
    }
}

impl Default for AccessTokenValidatorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl AccessTokenValidator {
    /// Creates a validator builder.
    pub fn builder() -> AccessTokenValidatorBuilder {
        AccessTokenValidatorBuilder::new()
    }

    /// Returns a clone of the configured request-time scope matcher.
    pub fn scope_matcher(&self) -> Arc<dyn ScopeMatch> {
        self.scope_matcher.clone()
    }

    /// Validates a raw access token and returns the authenticated user.
    pub fn authenticate_access_token(&self, token: &str) -> AuthResult<AuthUser> {
        let claims = decode_access_token_claims(token, &self.decode)?;
        access_token_claims_to_user(claims)
    }

    /// Validates a bearer value with or without the `Bearer ` prefix.
    pub fn authenticate_bearer(&self, bearer_or_token: &str) -> AuthResult<AuthUser> {
        let token = strip_bearer_prefix(bearer_or_token)?;
        self.authenticate_access_token(token)
    }

    /// Validates an optional bearer value.
    pub fn authenticate_bearer_opt(
        &self,
        bearer_or_token: Option<&str>,
    ) -> AuthResult<Option<AuthUser>> {
        bearer_or_token
            .map(|token| self.authenticate_bearer(token).map(Some))
            .unwrap_or(Ok(None))
    }

    /// Validates a bearer value and wraps the result as an [`AuthPrincipal`].
    pub fn authenticate_principal(&self, bearer_or_token: &str) -> AuthResult<AuthPrincipal> {
        self.authenticate_bearer(bearer_or_token)
            .map(AuthPrincipal::User)
    }

    /// Injects `AuthUser`, `AuthPrincipal`, and `AuthRuntime` when a token is present.
    ///
    /// Missing auth leaves the request unchanged. Invalid auth returns an error.
    pub fn inject_http_auth(
        &self,
        mut request: Request,
        bearer_or_token: Option<&str>,
    ) -> AuthResult<Request> {
        if let Some(raw) = bearer_or_token {
            let auth_user = self.authenticate_bearer(raw)?;
            request = request
                .data(AuthRuntime::new(self.scope_matcher()))
                .data(AuthPrincipal::User(auth_user.clone()))
                .data(auth_user);
        }

        Ok(request)
    }

    /// Authenticates a GraphQL WebSocket `connection_init` payload.
    pub fn authenticate_connection_init_value(
        &self,
        value: &JsonValue,
        authorization_keys: &[&str],
    ) -> AuthResult<AuthUser> {
        let object = value
            .as_object()
            .ok_or(AuthError::MissingConnectionInitAuth)?;
        let keys: &[&str] = if authorization_keys.is_empty() {
            &[
                "authorization",
                "Authorization",
                "access_token",
                "accessToken",
            ]
        } else {
            authorization_keys
        };

        let token = keys
            .iter()
            .find_map(|key| object.get(*key).and_then(JsonValue::as_str))
            .ok_or(AuthError::MissingConnectionInitAuth)?;
        self.authenticate_bearer(token)
    }
}

fn required_non_empty(value: Option<String>, name: &str) -> AuthResult<String> {
    let value = value
        .ok_or_else(|| AuthError::InvalidConfiguration(format!("validator {name} is required")))?;
    if value.trim().is_empty() {
        return Err(AuthError::InvalidConfiguration(format!(
            "validator {name} must not be empty"
        )));
    }
    Ok(value)
}

fn build_decoding_key(
    key_material: ValidatorKeyMaterial,
    key_id: Option<String>,
    accept_hs256: bool,
) -> AuthResult<(Algorithm, DecodingKey, Option<String>)> {
    match key_material {
        ValidatorKeyMaterial::Rs256PublicPem(public_key_pem) => {
            let key = DecodingKey::from_rsa_pem(public_key_pem.as_bytes()).map_err(|_| {
                AuthError::InvalidConfiguration("invalid RS256 public key PEM".to_string())
            })?;
            Ok((Algorithm::RS256, key, key_id))
        }
        ValidatorKeyMaterial::JwksJson(jwks_json) => {
            let jwks: JwkSet = serde_json::from_str(&jwks_json).map_err(|_| {
                AuthError::InvalidConfiguration("invalid JWKS JSON document".to_string())
            })?;
            let (jwk, expected_kid) = match key_id {
                Some(key_id) => {
                    let jwk = jwks.find(&key_id).ok_or_else(|| {
                        AuthError::InvalidConfiguration("JWKS key_id was not found".to_string())
                    })?;
                    (jwk, Some(key_id))
                }
                None if jwks.keys.len() == 1 => {
                    let jwk = &jwks.keys[0];
                    (jwk, jwk.common.key_id.clone())
                }
                None => {
                    return Err(AuthError::InvalidConfiguration(
                        "validator key_id is required for multi-key JWKS".to_string(),
                    ));
                }
            };
            let key = DecodingKey::from_jwk(jwk)
                .map_err(|_| AuthError::InvalidConfiguration("unsupported JWKS key".to_string()))?;
            Ok((Algorithm::RS256, key, expected_kid))
        }
        ValidatorKeyMaterial::Hs256Secret(secret) => {
            if !accept_hs256 {
                return Err(AuthError::InvalidConfiguration(
                    "HS256 validation requires accept_hs256(true)".to_string(),
                ));
            }
            if secret.len() < MIN_HS256_SECRET_BYTES {
                return Err(AuthError::InvalidConfiguration(
                    "HS256 secret must be at least 32 bytes".to_string(),
                ));
            }
            Ok((
                Algorithm::HS256,
                DecodingKey::from_secret(secret.as_bytes()),
                key_id,
            ))
        }
    }
}
