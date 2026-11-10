use std::sync::Arc;

use async_graphql::Request;
use jsonwebtoken::{Algorithm, Validation, decode_header};
use serde_json::Value as JsonValue;

use crate::claims::{ClaimRequirements, PresentedConfirmation};
use crate::clock::{Clock, SystemClock};
use crate::config::LegacyScopeClaims;
use crate::keys::{
    AccessTokenKeyResolver, StaticHs256Key, StaticJwksKeySet, StaticRs256Key, is_hmac,
    validate_hs256_secret,
};
use crate::scope_match::{AuthRuntime, ExactScopeMatch, ScopeMatch};
use crate::token_decode::{
    AccessTokenDecodeConfig, BearerParseMode, PurposePolicy, access_token_claims_to_user,
    decode_access_token_claims,
};
use crate::util::strip_bearer_prefix_with_mode;
use crate::{AuthError, AuthPrincipal, AuthResult, AuthUser};

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
    expected_kids: Vec<String>,
    accept_hs256: bool,
    clock: Arc<dyn Clock>,
    scope_matcher: Arc<dyn ScopeMatch>,
    bearer_parse_mode: BearerParseMode,
}

/// Builder for [`AccessTokenValidator`].
pub struct AccessTokenValidatorBuilder {
    issuer: Option<String>,
    audiences: Vec<String>,
    leeway_seconds: Option<u64>,
    key_ids: Vec<String>,
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
            key_ids: Vec::new(),
            key_material: None,
            key_resolver: None,
            accept_hs256: false,
            allowed_algorithms: None,
            purpose_policy: PurposePolicy::RequireAccessToken,
            legacy_scope_claims: LegacyScopeClaims::Reject,
            claim_requirements: ClaimRequirements::default(),
            bearer_parse_mode: BearerParseMode::RequireBearer,
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
    ///
    /// Tokens select their key by header `kid`, so a document holding the
    /// outgoing and incoming keys accepts both during a rotation overlap. See
    /// [`StaticJwksKeySet`] for the parsing and `kid` rules. Keys other than
    /// RS256 also need [`Self::allowed_algorithms`].
    pub fn jwks_json(mut self, jwks_json: impl Into<String>) -> Self {
        self.key_material = Some(ValidatorKeyMaterial::JwksJson(jwks_json.into()));
        self
    }

    /// Pins the accepted JWT header `kid` to this one key id.
    ///
    /// Replaces any earlier [`Self::key_id`] or [`Self::key_ids`] pin. Every
    /// accepted token must carry a pinned `kid`; the key set must contain it.
    pub fn key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_ids = vec![key_id.into()];
        self
    }

    /// Pins the accepted JWT header `kid` to a set of key ids, for example
    /// the previous and the current key during a rotation overlap.
    ///
    /// Replaces any earlier pin. An empty set removes the pin.
    pub fn key_ids<I, S>(mut self, key_ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.key_ids = key_ids.into_iter().map(Into::into).collect();
        self
    }

    /// Uses an HS256 secret. HS256 remains disabled unless
    /// [`Self::accept_hs256`] is also set to `true`.
    pub fn hs256_secret(mut self, secret: impl Into<String>) -> Self {
        self.key_material = Some(ValidatorKeyMaterial::Hs256Secret(secret.into()));
        self
    }

    /// Explicitly enables or disables HMAC (HS256, HS384, HS512) validation.
    ///
    /// Without it, every HMAC key is refused: from [`Self::hs256_secret`], from
    /// a [`Self::key_resolver`] at build time or per request, and in
    /// [`Self::allowed_algorithms`].
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

    /// Sets the `typ`/`purpose` validation policy.
    ///
    /// The default [`PurposePolicy::RequireAccessToken`] requires
    /// `typ = "access"` and `purpose = "access_token"`, which every token
    /// issued since 0.6.0 carries. [`PurposePolicy::AccessTokenOrLegacy`] is
    /// the opt-in for older tokens.
    pub fn purpose_policy(mut self, policy: PurposePolicy) -> Self {
        self.purpose_policy = policy;
        self
    }

    /// Controls whether the pre-0.14 access-token `scopes` array is accepted.
    ///
    /// The default is [`LegacyScopeClaims::Reject`]. Select
    /// [`LegacyScopeClaims::Accept`] only while an issuer still emits
    /// [`crate::AccessTokenScopeClaimFormat::LegacyArray`] tokens. Conflicting
    /// standard and legacy claims always fail closed.
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
    ///
    /// The default is [`BearerParseMode::RequireBearer`];
    /// [`BearerParseMode::BearerOrRaw`] is the legacy opt-in. The mode also
    /// applies to WebSocket `connection_init` values.
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

        if self.key_ids.iter().any(|kid| kid.trim().is_empty()) {
            return Err(AuthError::InvalidConfiguration(
                "validator key ids must not be empty".to_string(),
            ));
        }
        let (default_algorithm, key_resolver) = build_key_resolver(
            self.key_material,
            self.key_resolver,
            &self.key_ids,
            self.accept_hs256,
        )?;

        let allowed_algorithms = match self.allowed_algorithms {
            Some(algorithms) if !algorithms.is_empty() => algorithms,
            _ => vec![default_algorithm],
        };
        if !self.accept_hs256 && allowed_algorithms.iter().copied().any(is_hmac) {
            return Err(AuthError::InvalidConfiguration(
                "HMAC algorithms must be enabled with accept_hs256(true)".to_string(),
            ));
        }

        Ok(AccessTokenValidator {
            issuer,
            audiences: self.audiences,
            leeway_seconds: leeway,
            allowed_algorithms,
            purpose_policy: self.purpose_policy,
            legacy_scope_claims: self.legacy_scope_claims,
            claim_requirements: self.claim_requirements,
            key_resolver,
            expected_kids: self.key_ids,
            accept_hs256: self.accept_hs256,
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

    /// Returns the current time from the clock used for token validation.
    ///
    /// Transport adapters can use this observation to schedule credential expiry
    /// on the same time basis. Each call reads the retained clock; this does not
    /// validate a credential or check current account/session revocation.
    pub fn current_time(&self) -> time::OffsetDateTime {
        self.clock.now()
    }

    /// Returns a clone of the configured request-time scope matcher.
    pub fn scope_matcher(&self) -> Arc<dyn ScopeMatch> {
        self.scope_matcher.clone()
    }

    /// Validates a raw access token and returns the authenticated user.
    ///
    /// With [`ClaimRequirements::require_cnf`] set this always fails; use
    /// [`Self::authenticate_access_token_with_confirmation`].
    pub fn authenticate_access_token(&self, token: &str) -> AuthResult<AuthUser> {
        self.authenticate(token, None)
    }

    /// Validates a raw access token and checks its `cnf` binding against the
    /// key or certificate thumbprint the host verified for this request.
    ///
    /// A token carrying `cnf` must match `presented` (constant-time compare).
    /// A token without `cnf` is accepted unless
    /// [`ClaimRequirements::require_cnf`] is set.
    pub fn authenticate_access_token_with_confirmation(
        &self,
        token: &str,
        presented: &PresentedConfirmation,
    ) -> AuthResult<AuthUser> {
        self.authenticate(token, Some(presented))
    }

    /// Validates a bearer value according to the configured parse mode.
    pub fn authenticate_bearer(&self, bearer_or_token: &str) -> AuthResult<AuthUser> {
        let token = strip_bearer_prefix_with_mode(bearer_or_token, self.bearer_parse_mode)?;
        self.authenticate_access_token(token)
    }

    /// Validates a bearer value and its `cnf` binding; see
    /// [`Self::authenticate_access_token_with_confirmation`].
    pub fn authenticate_bearer_with_confirmation(
        &self,
        bearer_or_token: &str,
        presented: &PresentedConfirmation,
    ) -> AuthResult<AuthUser> {
        let token = strip_bearer_prefix_with_mode(bearer_or_token, self.bearer_parse_mode)?;
        self.authenticate_access_token_with_confirmation(token, presented)
    }

    fn authenticate(
        &self,
        token: &str,
        presented: Option<&PresentedConfirmation>,
    ) -> AuthResult<AuthUser> {
        let mut decode_config = self.decode_config_for_token(token)?;
        decode_config.presented_confirmation = presented.cloned();
        let claims = decode_access_token_claims(token, &decode_config)?;
        access_token_claims_to_user(claims)
    }

    /// Validates a bearer for a login/session-management endpoint and rejects
    /// sessionless or delegated access-token-only credentials.
    pub fn authenticate_session_management_bearer(
        &self,
        bearer_or_token: &str,
    ) -> AuthResult<AuthUser> {
        let user = self.authenticate_bearer(bearer_or_token)?;
        user.require_session_management_eligible()?;
        Ok(user)
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
            request = inject_user(request, self.scope_matcher(), auth_user);
        }

        Ok(request)
    }

    /// Like [`Self::inject_http_auth`], also checking the token's `cnf`
    /// binding against `presented` when the host verified a client
    /// certificate or proof-of-possession key for this request.
    pub fn inject_http_auth_with_confirmation(
        &self,
        mut request: Request,
        bearer_or_token: Option<&str>,
        presented: Option<&PresentedConfirmation>,
    ) -> AuthResult<Request> {
        if let Some(raw) = bearer_or_token {
            let token = strip_bearer_prefix_with_mode(raw, self.bearer_parse_mode)?;
            let auth_user = self.authenticate(token, presented)?;
            request = inject_user(request, self.scope_matcher(), auth_user);
        }

        Ok(request)
    }

    /// Authenticates a GraphQL WebSocket `connection_init` payload.
    ///
    /// With no `authorization_keys`, an `authorization` / `Authorization` value
    /// follows the configured [`BearerParseMode`](crate::BearerParseMode) and an
    /// `access_token` / `accessToken` value carries the bare token. Custom keys
    /// follow the configured parse mode.
    pub fn authenticate_connection_init_value(
        &self,
        value: &JsonValue,
        authorization_keys: &[&str],
    ) -> AuthResult<AuthUser> {
        let object = value
            .as_object()
            .ok_or(AuthError::MissingConnectionInitAuth)?;
        if authorization_keys.is_empty() {
            let token = crate::util::extract_connection_init_token(value, self.bearer_parse_mode)?;
            return self.authenticate_access_token(&token);
        }

        let token = authorization_keys
            .iter()
            .find_map(|key| object.get(*key).and_then(JsonValue::as_str))
            .ok_or(AuthError::MissingConnectionInitAuth)?;
        self.authenticate_bearer(token)
    }

    fn decode_config_for_token(&self, token: &str) -> AuthResult<AccessTokenDecodeConfig> {
        let header = decode_header(token).map_err(|_| AuthError::InvalidAccessToken)?;
        if !self.algorithm_permitted(header.alg) {
            return Err(AuthError::InvalidAccessToken);
        }
        if !self.expected_kids.is_empty()
            && !header
                .kid
                .as_deref()
                .is_some_and(|actual| self.expected_kids.iter().any(|kid| kid == actual))
        {
            return Err(AuthError::InvalidAccessToken);
        }

        let resolved = self.key_resolver.resolve(header.kid.as_deref())?;
        // A key verifies only its own algorithm, and a resolver cannot hand out
        // an HMAC key unless HMAC was explicitly enabled.
        if resolved.algorithm != header.alg || !self.algorithm_permitted(resolved.algorithm) {
            return Err(AuthError::InvalidAccessToken);
        }

        let mut validation = Validation::new(resolved.algorithm);
        validation.algorithms = vec![resolved.algorithm];
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
            presented_confirmation: None,
            clock: self.clock.clone(),
            allowed_algorithms: vec![resolved.algorithm],
        })
    }

    fn algorithm_permitted(&self, algorithm: Algorithm) -> bool {
        self.allowed_algorithms.contains(&algorithm) && (self.accept_hs256 || !is_hmac(algorithm))
    }
}

fn inject_user(
    request: Request,
    scope_matcher: Arc<dyn ScopeMatch>,
    auth_user: AuthUser,
) -> Request {
    request
        .data(AuthRuntime::new(scope_matcher))
        .data(AuthPrincipal::User(auth_user.clone()))
        .data(auth_user)
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
    key_ids: &[String],
    accept_hs256: bool,
) -> AuthResult<(Algorithm, Arc<dyn AccessTokenKeyResolver>)> {
    let single_kid = || match key_ids {
        [] => Ok(None),
        [kid] => Ok(Some(kid.clone())),
        _ => Err(AuthError::InvalidConfiguration(
            "a single-key validator accepts one key id".to_string(),
        )),
    };
    let hmac_refused = || {
        AuthError::InvalidConfiguration("HMAC validation requires accept_hs256(true)".to_string())
    };

    if let Some(resolver) = key_resolver {
        // The probe only picks the default allowlist; per-request resolution
        // is checked again against the allowlist and the HMAC gate.
        let algorithm = resolver
            .resolve(key_ids.first().map(String::as_str))
            .map(|key| key.algorithm)
            .unwrap_or(Algorithm::RS256);
        if is_hmac(algorithm) && !accept_hs256 {
            return Err(hmac_refused());
        }
        return Ok((algorithm, resolver));
    }

    match key_material {
        Some(ValidatorKeyMaterial::Rs256PublicPem(public_key_pem)) => {
            let resolver = Arc::new(StaticRs256Key::from_pem(&public_key_pem, single_kid()?)?)
                as Arc<dyn AccessTokenKeyResolver>;
            Ok((Algorithm::RS256, resolver))
        }
        Some(ValidatorKeyMaterial::JwksJson(jwks_json)) => {
            let key_set = StaticJwksKeySet::from_jwks_json(&jwks_json)?;
            if let Some(missing) = key_ids.iter().find(|kid| !key_set.has_key_id(kid)) {
                return Err(AuthError::InvalidConfiguration(format!(
                    "validator key id {missing:?} is not in the JWKS document"
                )));
            }
            Ok((
                Algorithm::RS256,
                Arc::new(key_set) as Arc<dyn AccessTokenKeyResolver>,
            ))
        }
        Some(ValidatorKeyMaterial::Hs256Secret(secret)) => {
            if !accept_hs256 {
                return Err(hmac_refused());
            }
            validate_hs256_secret(&secret)?;
            let resolver = Arc::new(StaticHs256Key::from_secret(&secret, single_kid()?)?)
                as Arc<dyn AccessTokenKeyResolver>;
            Ok((Algorithm::HS256, resolver))
        }
        None => Err(AuthError::InvalidConfiguration(
            "validator key material is required".to_string(),
        )),
    }
}
