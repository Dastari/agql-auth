use std::sync::Arc;

use async_graphql::Request;
use jsonwebtoken::{Algorithm, Validation, decode_header};
use serde_json::Value as JsonValue;

use crate::claims::ClaimRequirements;
use crate::clock::{Clock, SystemClock};
use crate::config::LegacyScopeClaims;
use crate::keys::{AccessTokenKeyResolver, StaticHs256Key, StaticJwksKeySet, StaticRs256Key};
use crate::scope_match::{AuthRuntime, ExactScopeMatch, ScopeMatch};
use crate::token_decode::{
    AccessTokenDecodeConfig, BearerParseMode, PurposePolicy, access_token_claims_to_user,
    decode_access_token_claims,
};
use crate::util::strip_bearer_prefix_with_mode;
use crate::{AuthError, AuthPrincipal, AuthResult, AuthUser};

const MIN_HS256_SECRET_BYTES: usize = 32;
const DEFAULT_MAX_LEEWAY_SECONDS: u64 = 300;

/// Store-free validator for local `agql-auth` access tokens.
///
/// Resource servers can use this with issuer, audience, and static public key
/// material without implementing [`crate::UserStore`] or
/// [`crate::RefreshTokenStore`].
pub struct AccessTokenValidator {
    issuer: String,
    audiences: Vec<String>,
    leeway_seconds: u64,
    allowed_algorithms: Vec<Algorithm>,
    purpose_policy: PurposePolicy,
    legacy_scope_claims: LegacyScopeClaims,
    claim_requirements: ClaimRequirements,
    key_resolver: Arc<dyn AccessTokenKeyResolver>,
    expected_kid: Option<String>,
    clock: Arc<dyn Clock>,
    scope_matcher: Arc<dyn ScopeMatch>,
    bearer_parse_mode: BearerParseMode,
}

/// Builder for [`AccessTokenValidator`].
pub struct AccessTokenValidatorBuilder {
    issuer: Option<String>,
    audiences: Vec<String>,
    leeway_seconds: Option<u64>,
    key_id: Option<String>,
    key_material: Option<ValidatorKeyMaterial>,
    key_resolver: Option<Arc<dyn AccessTokenKeyResolver>>,
    accept_hs256: bool,
    allowed_algorithms: Option<Vec<Algorithm>>,
    purpose_policy: PurposePolicy,
    legacy_scope_claims: LegacyScopeClaims,
    claim_requirements: ClaimRequirements,
    bearer_parse_mode: BearerParseMode,
    clock: Arc<dyn Clock>,
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
            audiences: Vec::new(),
            leeway_seconds: None,
            key_id: None,
            key_material: None,
            key_resolver: None,
            accept_hs256: false,
            allowed_algorithms: None,
            purpose_policy: PurposePolicy::AccessTokenOrLegacy,
            legacy_scope_claims: LegacyScopeClaims::Accept,
            claim_requirements: ClaimRequirements::default(),
            bearer_parse_mode: BearerParseMode::BearerOrRaw,
            clock: Arc::new(SystemClock),
            scope_matcher: Arc::new(ExactScopeMatch),
        }
    }

    /// Sets the expected issuer.
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Sets a single expected audience.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audiences = vec![audience.into()];
        self
    }

    /// Sets one or more expected audiences.
    ///
    /// A token is accepted when any of its audiences matches any configured
    /// audience (exact string match via `jsonwebtoken` validation).
    pub fn audiences<I, S>(mut self, audiences: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.audiences = audiences.into_iter().map(Into::into).collect();
        self
    }

    /// Sets clock skew in seconds for JWT validation.
    ///
    /// Values above 300 seconds are rejected as excessive.
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
    pub fn jwks_json(mut self, jwks_json: impl Into<String>) -> Self {
        self.key_material = Some(ValidatorKeyMaterial::JwksJson(jwks_json.into()));
        self
    }

    /// Requires the JWT header `kid` to match this key id for single-key setups.
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

    /// Restricts accepted signature algorithms.
    ///
    /// Algorithms are never inferred solely from untrusted token headers without
    /// comparison to this configured policy.
    pub fn allowed_algorithms(mut self, algorithms: impl IntoIterator<Item = Algorithm>) -> Self {
        self.allowed_algorithms = Some(algorithms.into_iter().collect());
        self
    }

    /// Installs a custom key resolver (static multi-key JWKS, rotating set, etc.).
    pub fn key_resolver(mut self, resolver: Arc<dyn AccessTokenKeyResolver>) -> Self {
        self.key_resolver = Some(resolver);
        self
    }

    /// Sets purpose validation policy.
    pub fn purpose_policy(mut self, policy: PurposePolicy) -> Self {
        self.purpose_policy = policy;
        self
    }

    /// Controls whether the pre-0.14 access-token `scopes` array is accepted.
    ///
    /// The default is [`LegacyScopeClaims::Accept`] for rolling upgrades.
    /// Select [`LegacyScopeClaims::Reject`] after every legacy token has
    /// expired. Conflicting standard and legacy claims always fail closed.
    pub fn legacy_scope_claims(mut self, policy: LegacyScopeClaims) -> Self {
        self.legacy_scope_claims = policy;
        self
    }

    /// Sets optional multi-tenant / binding claim requirements.
    pub fn claim_requirements(mut self, requirements: ClaimRequirements) -> Self {
        self.claim_requirements = requirements;
        self
    }

    /// Controls whether raw tokens without a `Bearer` scheme are accepted.
    pub fn bearer_parse_mode(mut self, mode: BearerParseMode) -> Self {
        self.bearer_parse_mode = mode;
        self
    }

    /// Installs an injectable clock (useful for deterministic tests).
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
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
        if self.audiences.is_empty()
            || self
                .audiences
                .iter()
                .any(|audience| audience.trim().is_empty())
        {
            return Err(AuthError::InvalidConfiguration(
                "validator audience is required".to_string(),
            ));
        }
        let leeway = self.leeway_seconds.unwrap_or(0);
        if leeway > DEFAULT_MAX_LEEWAY_SECONDS {
            return Err(AuthError::InvalidConfiguration(format!(
                "validator leeway_seconds must be <= {DEFAULT_MAX_LEEWAY_SECONDS}"
            )));
        }

        let (default_algorithm, key_resolver, expected_kid) = build_key_resolver(
            self.key_material,
            self.key_resolver,
            self.key_id,
            self.accept_hs256,
        )?;

        let allowed_algorithms = match self.allowed_algorithms {
            Some(algorithms) if !algorithms.is_empty() => {
                if algorithms.contains(&Algorithm::HS256) && !self.accept_hs256 {
                    return Err(AuthError::InvalidConfiguration(
                        "HS256 must be enabled with accept_hs256(true)".to_string(),
                    ));
                }
                algorithms
            }
            _ => vec![default_algorithm],
        };

        Ok(AccessTokenValidator {
            issuer,
            audiences: self.audiences,
            leeway_seconds: leeway,
            allowed_algorithms,
            purpose_policy: self.purpose_policy,
            legacy_scope_claims: self.legacy_scope_claims,
            claim_requirements: self.claim_requirements,
            key_resolver,
            expected_kid,
            clock: self.clock,
            scope_matcher: self.scope_matcher,
            bearer_parse_mode: self.bearer_parse_mode,
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
        let decode_config = self.decode_config_for_token(token)?;
        let claims = decode_access_token_claims(token, &decode_config)?;
        access_token_claims_to_user(claims)
    }

    /// Validates a bearer value according to the configured parse mode.
    pub fn authenticate_bearer(&self, bearer_or_token: &str) -> AuthResult<AuthUser> {
        let token = strip_bearer_prefix_with_mode(bearer_or_token, self.bearer_parse_mode)?;
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

    fn decode_config_for_token(&self, token: &str) -> AuthResult<AccessTokenDecodeConfig> {
        let header = decode_header(token).map_err(|_| AuthError::InvalidAccessToken)?;
        if !self.allowed_algorithms.contains(&header.alg) {
            return Err(AuthError::InvalidAccessToken);
        }
        if let Some(expected_kid) = &self.expected_kid {
            match header.kid.as_deref() {
                Some(actual) if actual == expected_kid => {}
                _ => return Err(AuthError::InvalidAccessToken),
            }
        }

        let resolved = self.key_resolver.resolve(header.kid.as_deref())?;
        if !self.allowed_algorithms.contains(&resolved.algorithm) {
            return Err(AuthError::InvalidAccessToken);
        }

        let mut validation = Validation::new(resolved.algorithm);
        validation.algorithms = self.allowed_algorithms.clone();
        validation.set_issuer(std::slice::from_ref(&self.issuer));
        validation.set_audience(&self.audiences);
        validation.leeway = self.leeway_seconds;
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.required_spec_claims.extend(
            ["exp", "iat", "iss", "aud", "sub"]
                .into_iter()
                .map(str::to_string),
        );

        Ok(AccessTokenDecodeConfig {
            decoding_key: resolved.decoding_key,
            validation,
            // Kid already enforced above / by resolver.
            expected_kid: None,
            leeway_seconds: self.leeway_seconds,
            purpose_policy: self.purpose_policy,
            legacy_scope_claims: self.legacy_scope_claims,
            claim_requirements: self.claim_requirements.clone(),
            clock: self.clock.clone(),
            allowed_algorithms: self.allowed_algorithms.clone(),
        })
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

fn build_key_resolver(
    key_material: Option<ValidatorKeyMaterial>,
    key_resolver: Option<Arc<dyn AccessTokenKeyResolver>>,
    key_id: Option<String>,
    accept_hs256: bool,
) -> AuthResult<(Algorithm, Arc<dyn AccessTokenKeyResolver>, Option<String>)> {
    if let Some(resolver) = key_resolver {
        let algorithm = resolver
            .resolve(key_id.as_deref())
            .map(|key| key.algorithm)
            .unwrap_or(Algorithm::RS256);
        return Ok((algorithm, resolver, key_id));
    }

    match key_material {
        Some(ValidatorKeyMaterial::Rs256PublicPem(public_key_pem)) => {
            let resolver = Arc::new(StaticRs256Key::from_pem(&public_key_pem, key_id.clone())?)
                as Arc<dyn AccessTokenKeyResolver>;
            Ok((Algorithm::RS256, resolver, key_id))
        }
        Some(ValidatorKeyMaterial::JwksJson(jwks_json)) => {
            let resolver = Arc::new(StaticJwksKeySet::from_jwks_json(&jwks_json)?)
                as Arc<dyn AccessTokenKeyResolver>;
            // Fail fast for multi-key sets without kid when no token is available.
            if key_id.is_none() {
                let _ = resolver.resolve(None).map_err(|_| {
                    AuthError::InvalidConfiguration(
                        "validator key_id is required for multi-key JWKS".to_string(),
                    )
                })?;
            } else {
                let _ = resolver.resolve(key_id.as_deref())?;
            }
            Ok((Algorithm::RS256, resolver, key_id))
        }
        Some(ValidatorKeyMaterial::Hs256Secret(secret)) => {
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
            let resolver = Arc::new(StaticHs256Key::from_secret(&secret, key_id.clone())?)
                as Arc<dyn AccessTokenKeyResolver>;
            Ok((Algorithm::HS256, resolver, key_id))
        }
        None => Err(AuthError::InvalidConfiguration(
            "validator key material is required".to_string(),
        )),
    }
}
