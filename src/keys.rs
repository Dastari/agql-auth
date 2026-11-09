//! Access-token key resolution for resource servers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use jsonwebtoken::jwk::{
    AlgorithmParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse,
};
use jsonwebtoken::{Algorithm, DecodingKey};
use time::OffsetDateTime;

use crate::AuthResult;
use crate::clock::{Clock, SystemClock};
use crate::errors::AuthError;

/// Minimum HS256 secret length in bytes, enforced on every HS256 path.
pub(crate) const MIN_HS256_SECRET_BYTES: usize = 32;

/// Refuses an HS256 secret shorter than [`MIN_HS256_SECRET_BYTES`].
pub(crate) fn validate_hs256_secret(secret: &str) -> AuthResult<()> {
    if secret.len() < MIN_HS256_SECRET_BYTES {
        return Err(AuthError::InvalidConfiguration(
            "HS256 secret must be at least 32 bytes".to_string(),
        ));
    }
    Ok(())
}

/// Returns whether `algorithm` is a symmetric HMAC algorithm.
pub(crate) fn is_hmac(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
    )
}

/// Resolved verification key for a JWT.
///
/// The key verifies only tokens whose header `alg` equals [`Self::algorithm`].
#[derive(Clone)]
pub struct ResolvedKey {
    /// Decoding key material.
    pub decoding_key: DecodingKey,
    /// Algorithm this key may be used with.
    pub algorithm: Algorithm,
    /// Key id when known.
    pub kid: Option<String>,
}

impl std::fmt::Debug for ResolvedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedKey")
            .field("algorithm", &self.algorithm)
            .field("kid", &self.kid)
            .field("decoding_key", &"[redacted]")
            .finish()
    }
}

/// Resolves verification keys for access-token validation.
pub trait AccessTokenKeyResolver: Send + Sync + std::fmt::Debug {
    /// Resolves a key for the token header `kid`.
    fn resolve(&self, kid: Option<&str>) -> AuthResult<ResolvedKey>;
}

/// Single static RS256 public PEM key.
#[derive(Clone)]
pub struct StaticRs256Key {
    decoding_key: DecodingKey,
    kid: Option<String>,
}

impl StaticRs256Key {
    /// Creates a static RS256 public-key resolver.
    pub fn from_pem(public_key_pem: &str, kid: Option<String>) -> AuthResult<Self> {
        let decoding_key = DecodingKey::from_rsa_pem(public_key_pem.as_bytes()).map_err(|_| {
            AuthError::InvalidConfiguration("invalid RS256 public key PEM".to_string())
        })?;
        Ok(Self { decoding_key, kid })
    }
}

impl std::fmt::Debug for StaticRs256Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticRs256Key")
            .field("kid", &self.kid)
            .field("decoding_key", &"[redacted]")
            .finish()
    }
}

impl AccessTokenKeyResolver for StaticRs256Key {
    fn resolve(&self, kid: Option<&str>) -> AuthResult<ResolvedKey> {
        if let (Some(expected), Some(actual)) = (self.kid.as_deref(), kid)
            && expected != actual
        {
            return Err(AuthError::InvalidAccessToken);
        }
        if self.kid.is_some() && kid.is_none() {
            return Err(AuthError::InvalidAccessToken);
        }
        Ok(ResolvedKey {
            decoding_key: self.decoding_key.clone(),
            algorithm: Algorithm::RS256,
            kid: self.kid.clone(),
        })
    }
}

/// Static JWKS document with key selection by `kid`.
///
/// Each key keeps the algorithm its JWK declares (`alg`), or the one implied by
/// its key type when `alg` is absent: RSA as RS256, EC P-256 as ES256, EC
/// P-384 as ES384 and OKP Ed25519 as EdDSA. A key verifies only tokens whose
/// header `alg` matches. Keys with `use` other than `sig` are skipped.
///
/// Parsing refuses symmetric (`oct`) keys, HMAC or encryption `alg` values,
/// duplicate `kid`s and, in a document with more than one signing key, any key
/// without a `kid`. A multi-key set resolves only by token `kid`, so it can
/// hold the outgoing and incoming keys during a rotation overlap. A one-key set
/// whose JWK has a `kid` requires tokens to carry that `kid`; a one-key set
/// without a `kid` accepts only tokens without one.
#[derive(Clone)]
pub struct StaticJwksKeySet {
    keys_by_kid: HashMap<String, (Algorithm, DecodingKey)>,
    unnamed_key: Option<(Algorithm, DecodingKey)>,
}

impl StaticJwksKeySet {
    /// Parses a JWKS JSON document into a static key set.
    pub fn from_jwks_json(jwks_json: &str) -> AuthResult<Self> {
        let invalid = |message: &str| AuthError::InvalidConfiguration(message.to_string());
        let jwks: JwkSet =
            serde_json::from_str(jwks_json).map_err(|_| invalid("invalid JWKS JSON document"))?;

        let signing_keys = jwks
            .keys
            .iter()
            .filter(|jwk| {
                jwk.common
                    .public_key_use
                    .as_ref()
                    .is_none_or(|key_use| *key_use == PublicKeyUse::Signature)
            })
            .collect::<Vec<_>>();
        if signing_keys.is_empty() {
            return Err(invalid("JWKS document contains no signing keys"));
        }

        let mut keys_by_kid = HashMap::new();
        let mut unnamed_key = None;
        for jwk in &signing_keys {
            let algorithm = jwk_algorithm(jwk)?;
            let key = DecodingKey::from_jwk(jwk).map_err(|_| invalid("unsupported JWKS key"))?;
            match jwk.common.key_id.as_deref() {
                Some("") => return Err(invalid("JWKS key id must not be empty")),
                Some(kid) => {
                    if keys_by_kid
                        .insert(kid.to_string(), (algorithm, key))
                        .is_some()
                    {
                        return Err(invalid("JWKS document contains a duplicate key id"));
                    }
                }
                None if signing_keys.len() == 1 => unnamed_key = Some((algorithm, key)),
                None => {
                    return Err(invalid(
                        "every key in a multi-key JWKS document requires a key id",
                    ));
                }
            }
        }

        Ok(Self {
            keys_by_kid,
            unnamed_key,
        })
    }

    pub(crate) fn has_key_id(&self, kid: &str) -> bool {
        self.keys_by_kid.contains_key(kid)
    }
}

fn jwk_algorithm(jwk: &Jwk) -> AuthResult<Algorithm> {
    let invalid = || AuthError::InvalidConfiguration("unsupported JWKS key".to_string());
    let implied = match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => Algorithm::RS256,
        AlgorithmParameters::EllipticCurve(params) => match params.curve {
            EllipticCurve::P256 => Algorithm::ES256,
            EllipticCurve::P384 => Algorithm::ES384,
            _ => return Err(invalid()),
        },
        AlgorithmParameters::OctetKeyPair(params) if params.curve == EllipticCurve::Ed25519 => {
            Algorithm::EdDSA
        }
        // Symmetric keys are secrets and never belong in a public key set.
        _ => return Err(invalid()),
    };
    let declared = match jwk.common.key_algorithm {
        None => return Ok(implied),
        Some(KeyAlgorithm::RS256) => Algorithm::RS256,
        Some(KeyAlgorithm::RS384) => Algorithm::RS384,
        Some(KeyAlgorithm::RS512) => Algorithm::RS512,
        Some(KeyAlgorithm::PS256) => Algorithm::PS256,
        Some(KeyAlgorithm::PS384) => Algorithm::PS384,
        Some(KeyAlgorithm::PS512) => Algorithm::PS512,
        Some(KeyAlgorithm::ES256) => Algorithm::ES256,
        Some(KeyAlgorithm::ES384) => Algorithm::ES384,
        Some(KeyAlgorithm::EdDSA) => Algorithm::EdDSA,
        Some(_) => return Err(invalid()),
    };
    if declared.family() != implied.family()
        || (implied.family() == jsonwebtoken::AlgorithmFamily::Ec && declared != implied)
    {
        return Err(invalid());
    }
    Ok(declared)
}

impl std::fmt::Debug for StaticJwksKeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut kids = self.keys_by_kid.keys().collect::<Vec<_>>();
        kids.sort();
        f.debug_struct("StaticJwksKeySet")
            .field("kids", &kids)
            .field("unnamed_key", &self.unnamed_key.is_some())
            .finish()
    }
}

impl AccessTokenKeyResolver for StaticJwksKeySet {
    fn resolve(&self, kid: Option<&str>) -> AuthResult<ResolvedKey> {
        let (kid, (algorithm, key)) = match kid {
            Some(kid) => match self.keys_by_kid.get(kid) {
                Some(entry) => (Some(kid.to_string()), entry),
                None => return Err(AuthError::InvalidAccessToken),
            },
            None => match &self.unnamed_key {
                Some(entry) => (None, entry),
                None => return Err(AuthError::InvalidAccessToken),
            },
        };
        Ok(ResolvedKey {
            decoding_key: key.clone(),
            algorithm: *algorithm,
            kid,
        })
    }
}

/// Static HS256 secret resolver. Requires explicit enablement by the host.
#[derive(Clone)]
pub struct StaticHs256Key {
    decoding_key: DecodingKey,
    kid: Option<String>,
}

impl StaticHs256Key {
    /// Creates an HS256 resolver from a secret of at least 32 bytes.
    ///
    /// An `AccessTokenValidator` uses it only with `accept_hs256(true)`.
    pub fn from_secret(secret: &str, kid: Option<String>) -> AuthResult<Self> {
        validate_hs256_secret(secret)?;
        Ok(Self {
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            kid,
        })
    }
}

impl std::fmt::Debug for StaticHs256Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticHs256Key")
            .field("kid", &self.kid)
            .field("decoding_key", &"[redacted]")
            .finish()
    }
}

impl AccessTokenKeyResolver for StaticHs256Key {
    fn resolve(&self, kid: Option<&str>) -> AuthResult<ResolvedKey> {
        if let (Some(expected), Some(actual)) = (self.kid.as_deref(), kid)
            && expected != actual
        {
            return Err(AuthError::InvalidAccessToken);
        }
        Ok(ResolvedKey {
            decoding_key: self.decoding_key.clone(),
            algorithm: Algorithm::HS256,
            kid: self.kid.clone(),
        })
    }
}

/// Behavior when a cached key set is stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StaleKeyPolicy {
    /// Keep using the last known keys for at most
    /// [`KeyRefreshPolicy::max_stale`] after the cache TTL, then reject.
    ///
    /// This is the default: a failing JWKS endpoint does not take the
    /// resource server down at once, yet a key removed from the issuer's JWKS
    /// stops verifying within a bounded time.
    #[default]
    UseStale,
    /// Reject tokens as soon as the cache is older than
    /// [`KeyRefreshPolicy::cache_ttl`]. For deployments whose refresher always
    /// runs ahead of the TTL.
    Reject,
}

/// Refresh controls for resolvers that can reload key material.
///
/// The default keeps keys fresh for 5 minutes and then tolerates a failing
/// refresh for up to 1 hour more before rejecting every token with
/// [`AuthError::AuthServiceUnavailable`]. The host must refresh the set
/// periodically (see [`RotatingJwksKeySet::needs_refresh`]).
#[derive(Debug, Clone)]
pub struct KeyRefreshPolicy {
    /// Maximum cache lifetime before a refresh is preferred.
    pub cache_ttl: StdDuration,
    /// Cooldown after an unknown-`kid` forced refresh.
    pub unknown_kid_cooldown: StdDuration,
    /// Stale-key behavior.
    pub stale_policy: StaleKeyPolicy,
    /// Longest time past `cache_ttl` that [`StaleKeyPolicy::UseStale`] keeps
    /// using the last known keys. Ignored under [`StaleKeyPolicy::Reject`].
    pub max_stale: StdDuration,
}

impl Default for KeyRefreshPolicy {
    fn default() -> Self {
        Self {
            cache_ttl: StdDuration::from_secs(300),
            unknown_kid_cooldown: StdDuration::from_secs(30),
            stale_policy: StaleKeyPolicy::UseStale,
            max_stale: StdDuration::from_secs(3600),
        }
    }
}

fn time_duration(duration: StdDuration) -> time::Duration {
    time::Duration::try_from(duration).unwrap_or(time::Duration::MAX)
}

/// In-memory multi-key set with bounded lifetime metadata for tests and hosts.
///
/// Remote JWKS HTTP fetching is intentionally not embedded here so the core
/// crate stays free of a mandatory HTTP client. Hosts can refresh this set
/// from their own HTTPS client and swap the inner document.
#[derive(Clone)]
pub struct RotatingJwksKeySet {
    inner: Arc<Mutex<RotatingJwksState>>,
    policy: KeyRefreshPolicy,
    clock: Arc<dyn Clock>,
}

struct RotatingJwksState {
    key_set: StaticJwksKeySet,
    loaded_at: OffsetDateTime,
    last_forced_refresh_at: Option<OffsetDateTime>,
    refresh_in_flight: bool,
}

impl RotatingJwksKeySet {
    /// Creates a rotating set from an initial JWKS document.
    pub fn new(jwks_json: &str, policy: KeyRefreshPolicy) -> AuthResult<Self> {
        Self::with_clock(jwks_json, policy, Arc::new(SystemClock))
    }

    /// Creates a rotating set with an injectable clock.
    pub fn with_clock(
        jwks_json: &str,
        policy: KeyRefreshPolicy,
        clock: Arc<dyn Clock>,
    ) -> AuthResult<Self> {
        let key_set = StaticJwksKeySet::from_jwks_json(jwks_json)?;
        let loaded_at = clock.now();
        Ok(Self {
            inner: Arc::new(Mutex::new(RotatingJwksState {
                key_set,
                loaded_at,
                last_forced_refresh_at: None,
                refresh_in_flight: false,
            })),
            policy,
            clock,
        })
    }

    /// Replaces the JWKS document after a successful host-side refresh.
    pub fn replace_jwks(&self, jwks_json: &str) -> AuthResult<()> {
        let key_set = StaticJwksKeySet::from_jwks_json(jwks_json)?;
        let mut state = self
            .inner
            .lock()
            .map_err(|_| AuthError::InvalidConfiguration("key set lock poisoned".to_string()))?;
        state.key_set = key_set;
        state.loaded_at = self.clock.now();
        state.refresh_in_flight = false;
        Ok(())
    }

    /// Returns whether the cached keys are older than
    /// [`KeyRefreshPolicy::cache_ttl`], so the host should fetch the JWKS and
    /// call [`Self::replace_jwks`].
    pub fn needs_refresh(&self) -> bool {
        let Ok(state) = self.inner.lock() else {
            return true;
        };
        self.clock.now() - state.loaded_at >= time_duration(self.policy.cache_ttl)
    }

    /// Returns whether a forced refresh is currently allowed by cooldown.
    pub fn should_force_refresh_for_unknown_kid(&self) -> bool {
        let Ok(state) = self.inner.lock() else {
            return false;
        };
        let now = self.clock.now();
        match state.last_forced_refresh_at {
            None => true,
            Some(last) => {
                let elapsed = now - last;
                elapsed >= time_duration(self.policy.unknown_kid_cooldown)
            }
        }
    }

    /// Marks that a forced refresh was attempted (stampede-aware).
    ///
    /// Returns `true` when this caller should perform the refresh.
    pub fn begin_forced_refresh(&self) -> bool {
        let Ok(mut state) = self.inner.lock() else {
            return false;
        };
        if state.refresh_in_flight {
            return false;
        }
        if let Some(last) = state.last_forced_refresh_at {
            let elapsed = self.clock.now() - last;
            if elapsed < time_duration(self.policy.unknown_kid_cooldown) {
                return false;
            }
        }
        state.refresh_in_flight = true;
        state.last_forced_refresh_at = Some(self.clock.now());
        true
    }

    /// Clears the in-flight refresh flag after a failed host refresh.
    pub fn end_forced_refresh(&self) {
        if let Ok(mut state) = self.inner.lock() {
            state.refresh_in_flight = false;
        }
    }

    fn is_usable(
        state: &RotatingJwksState,
        now: OffsetDateTime,
        policy: &KeyRefreshPolicy,
    ) -> bool {
        let age = now - state.loaded_at;
        let limit = match policy.stale_policy {
            StaleKeyPolicy::Reject => time_duration(policy.cache_ttl),
            StaleKeyPolicy::UseStale => {
                time_duration(policy.cache_ttl).saturating_add(time_duration(policy.max_stale))
            }
        };
        age < limit
    }
}

impl std::fmt::Debug for RotatingJwksKeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotatingJwksKeySet")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl AccessTokenKeyResolver for RotatingJwksKeySet {
    fn resolve(&self, kid: Option<&str>) -> AuthResult<ResolvedKey> {
        let state = self
            .inner
            .lock()
            .map_err(|_| AuthError::InvalidConfiguration("key set lock poisoned".to_string()))?;
        if !Self::is_usable(&state, self.clock.now(), &self.policy) {
            // Keys past the policy's freshness bound are not trusted: a key the
            // issuer withdrew must stop verifying.
            return Err(AuthError::AuthServiceUnavailable);
        }
        state.key_set.resolve(kid)
    }
}
