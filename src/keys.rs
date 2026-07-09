//! Access-token key resolution for resource servers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey};
use time::OffsetDateTime;

use crate::AuthResult;
use crate::clock::{Clock, SystemClock};
use crate::errors::AuthError;

/// Resolved verification key for a JWT.
#[derive(Clone)]
pub struct ResolvedKey {
    /// Decoding key material.
    pub decoding_key: DecodingKey,
    /// Algorithm this key may be used with.
    pub algorithm: Algorithm,
    /// Key id when known.
    pub kid: Option<String>,
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

/// Static JWKS document with multi-key selection by `kid`.
#[derive(Clone)]
pub struct StaticJwksKeySet {
    keys_by_kid: HashMap<String, DecodingKey>,
    single_key: Option<(Option<String>, DecodingKey)>,
}

impl StaticJwksKeySet {
    /// Parses a JWKS JSON document into a static key set.
    pub fn from_jwks_json(jwks_json: &str) -> AuthResult<Self> {
        let jwks: JwkSet = serde_json::from_str(jwks_json).map_err(|_| {
            AuthError::InvalidConfiguration("invalid JWKS JSON document".to_string())
        })?;
        if jwks.keys.is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "JWKS document contains no keys".to_string(),
            ));
        }

        let mut keys_by_kid = HashMap::new();
        for jwk in &jwks.keys {
            let key = DecodingKey::from_jwk(jwk)
                .map_err(|_| AuthError::InvalidConfiguration("unsupported JWKS key".to_string()))?;
            if let Some(kid) = jwk.common.key_id.clone() {
                keys_by_kid.insert(kid, key);
            }
        }

        let single_key = if jwks.keys.len() == 1 {
            let jwk = &jwks.keys[0];
            let key = DecodingKey::from_jwk(jwk)
                .map_err(|_| AuthError::InvalidConfiguration("unsupported JWKS key".to_string()))?;
            Some((jwk.common.key_id.clone(), key))
        } else {
            None
        };

        Ok(Self {
            keys_by_kid,
            single_key,
        })
    }
}

impl std::fmt::Debug for StaticJwksKeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticJwksKeySet")
            .field("kids", &self.keys_by_kid.keys().collect::<Vec<_>>())
            .field("single_key", &self.single_key.as_ref().map(|(kid, _)| kid))
            .finish()
    }
}

impl AccessTokenKeyResolver for StaticJwksKeySet {
    fn resolve(&self, kid: Option<&str>) -> AuthResult<ResolvedKey> {
        if let Some(kid) = kid {
            if let Some(key) = self.keys_by_kid.get(kid) {
                return Ok(ResolvedKey {
                    decoding_key: key.clone(),
                    algorithm: Algorithm::RS256,
                    kid: Some(kid.to_string()),
                });
            }
            return Err(AuthError::InvalidAccessToken);
        }

        if let Some((kid, key)) = &self.single_key {
            return Ok(ResolvedKey {
                decoding_key: key.clone(),
                algorithm: Algorithm::RS256,
                kid: kid.clone(),
            });
        }

        Err(AuthError::InvalidAccessToken)
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
    pub fn from_secret(secret: &str, kid: Option<String>) -> AuthResult<Self> {
        if secret.len() < 32 {
            return Err(AuthError::InvalidConfiguration(
                "HS256 secret must be at least 32 bytes".to_string(),
            ));
        }
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
    /// Continue using the last known keys while refresh fails.
    ///
    /// This is the practical default for host-driven refresh. Security-sensitive
    /// deployments that always have a refresher can select [`Self::Reject`].
    #[default]
    UseStale,
    /// Reject tokens when the cache is stale and refresh is unavailable.
    Reject,
}

/// Refresh controls for resolvers that can reload key material.
#[derive(Debug, Clone)]
pub struct KeyRefreshPolicy {
    /// Maximum cache lifetime before a refresh is preferred.
    pub cache_ttl: StdDuration,
    /// Cooldown after an unknown-`kid` forced refresh.
    pub unknown_kid_cooldown: StdDuration,
    /// Stale-key behavior.
    pub stale_policy: StaleKeyPolicy,
}

impl Default for KeyRefreshPolicy {
    fn default() -> Self {
        Self {
            cache_ttl: StdDuration::from_secs(300),
            unknown_kid_cooldown: StdDuration::from_secs(30),
            stale_policy: StaleKeyPolicy::Reject,
        }
    }
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
                elapsed
                    >= time::Duration::seconds(self.policy.unknown_kid_cooldown.as_secs() as i64)
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
            if elapsed < time::Duration::seconds(self.policy.unknown_kid_cooldown.as_secs() as i64)
            {
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

    fn is_stale(state: &RotatingJwksState, now: OffsetDateTime, policy: &KeyRefreshPolicy) -> bool {
        let age = now - state.loaded_at;
        age >= time::Duration::seconds(policy.cache_ttl.as_secs() as i64)
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
        let now = self.clock.now();
        if Self::is_stale(&state, now, &self.policy)
            && matches!(self.policy.stale_policy, StaleKeyPolicy::Reject)
        {
            // Host should refresh before using stale keys under Reject policy.
            // Still allow resolve if keys match, but signal via unknown kid path
            // only when kid is missing. For known keys with Reject, require fresh
            // cache for security-sensitive deployments.
            return Err(AuthError::AuthServiceUnavailable);
        }
        state.key_set.resolve(kid)
    }
}
