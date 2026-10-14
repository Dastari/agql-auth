//! Bounded process-local abuse state with atomic TTL reclamation.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::num::NonZeroUsize;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    AuthError, AuthRateLimitKey, AuthRateLimitSnapshot, AuthRateLimitState, AuthRateLimitStore,
    AuthResult, Clock, SystemClock,
};

/// Default maximum number of process-local abuse-control records.
pub const DEFAULT_MEMORY_AUTH_RATE_LIMIT_CAPACITY: usize = 16_384;

/// In-memory abuse-protection store with bounded, lazily reclaimed TTL state.
///
/// Every operation reclaims expired entries under the same mutex as compare and
/// swap. At capacity, new keys fail closed with [`AuthError::AuthServiceUnavailable`];
/// existing counters can still update or clear. Active counters and lockouts are
/// never evicted to admit a different principal. The expiry index has exactly one
/// entry per stored key, including after repeated updates.
///
/// Clones share the same state, capacity, and trusted clock. Hosts injecting an
/// authentication rate-limit clock must supply the same time basis here.
/// Multi-instance applications still need a durable [`AuthRateLimitStore`].
pub struct MemoryAuthRateLimitStore {
    states: Arc<Mutex<MemoryState>>,
    capacity: NonZeroUsize,
    // Every clock read occurs while holding states. A clock panic poisons that
    // mutex, and all subsequent authoritative operations fail closed before
    // reading the clock. Preserve the store's existing unwind-safe auto traits.
    clock: AssertUnwindSafe<Arc<dyn Clock>>,
}

impl Clone for MemoryAuthRateLimitStore {
    fn clone(&self) -> Self {
        Self {
            states: self.states.clone(),
            capacity: self.capacity,
            clock: AssertUnwindSafe(self.clock.0.clone()),
        }
    }
}

#[derive(Default)]
struct MemoryState {
    entries: HashMap<AuthRateLimitKey, AuthRateLimitSnapshot>,
    expirations: BTreeMap<OffsetDateTime, HashSet<AuthRateLimitKey>>,
}

impl MemoryState {
    fn purge_expired(&mut self, now: OffsetDateTime) -> usize {
        let mut removed = 0;
        while self
            .expirations
            .first_key_value()
            .is_some_and(|(expiry, _)| *expiry <= now)
        {
            let (_, keys) = self.expirations.pop_first().expect("checked expiry bucket");
            for key in keys {
                removed += usize::from(self.entries.remove(&key).is_some());
            }
        }
        removed
    }

    fn remove(&mut self, key: &AuthRateLimitKey) {
        if let Some(previous) = self.entries.remove(key) {
            let expiry = previous.state.expires_at;
            if let Some(keys) = self.expirations.get_mut(&expiry) {
                keys.remove(key);
                if keys.is_empty() {
                    self.expirations.remove(&expiry);
                }
            }
        }
    }

    fn insert(&mut self, key: AuthRateLimitKey, snapshot: AuthRateLimitSnapshot) {
        self.remove(&key);
        self.expirations
            .entry(snapshot.state.expires_at)
            .or_default()
            .insert(key.clone());
        self.entries.insert(key, snapshot);
    }
}

impl Default for MemoryAuthRateLimitStore {
    fn default() -> Self {
        Self::with_capacity_and_clock(
            NonZeroUsize::new(DEFAULT_MEMORY_AUTH_RATE_LIMIT_CAPACITY)
                .expect("nonzero default capacity"),
            Arc::new(SystemClock),
        )
    }
}

impl MemoryAuthRateLimitStore {
    /// Creates a bounded store with an explicit trusted clock.
    ///
    /// Use the same clock as [`crate::AuthService::new_with_rate_limit_store_and_clock`].
    pub fn with_capacity_and_clock(capacity: NonZeroUsize, clock: Arc<dyn Clock>) -> Self {
        Self {
            states: Arc::default(),
            capacity,
            clock: AssertUnwindSafe(clock),
        }
    }

    /// Reclaims all expired entries and returns the number removed.
    ///
    /// Operations already reclaim expired records. Hosts may call this during
    /// idle periods if they want to release expired state before the next request.
    pub fn purge_expired(&self) -> AuthResult<usize> {
        let mut states = self
            .states
            .lock()
            .map_err(|_| AuthError::AuthServiceUnavailable)?;
        Ok(states.purge_expired(self.clock.now()))
    }

    /// Returns unexpired state for tests and diagnostics, reclaiming expired rows.
    pub fn get(&self, key: &AuthRateLimitKey) -> Option<AuthRateLimitState> {
        let mut states = self.states.lock().expect("memory rate-limit store lock");
        states.purge_expired(self.clock.now());
        states
            .entries
            .get(key)
            .map(|snapshot| snapshot.state.clone())
    }
}

#[async_trait]
impl AuthRateLimitStore for MemoryAuthRateLimitStore {
    async fn find_auth_rate_limit_state(
        &self,
        key: &AuthRateLimitKey,
    ) -> AuthResult<Option<AuthRateLimitSnapshot>> {
        let mut states = self
            .states
            .lock()
            .map_err(|_| AuthError::AuthServiceUnavailable)?;
        states.purge_expired(self.clock.now());
        Ok(states.entries.get(key).cloned())
    }

    async fn compare_exchange_auth_rate_limit_state(
        &self,
        key: &AuthRateLimitKey,
        expected_revision: Option<Uuid>,
        replacement: AuthRateLimitSnapshot,
    ) -> AuthResult<bool> {
        if replacement.state.key != *key {
            return Err(AuthError::Store(
                "rate-limit replacement key does not match compare key".into(),
            ));
        }
        let mut states = self
            .states
            .lock()
            .map_err(|_| AuthError::AuthServiceUnavailable)?;
        let now = self.clock.now();
        states.purge_expired(now);
        if states.entries.get(key).map(|snapshot| snapshot.revision) != expected_revision {
            return Ok(false);
        }
        if replacement.state.expires_at <= now {
            return Err(AuthError::Store(
                "rate-limit replacement is already expired under store clock".into(),
            ));
        }
        if !states.entries.contains_key(key) && states.entries.len() >= self.capacity.get() {
            return Err(AuthError::AuthServiceUnavailable);
        }
        states.insert(key.clone(), replacement);
        Ok(true)
    }

    async fn clear_auth_rate_limit_state(
        &self,
        key: &AuthRateLimitKey,
        expected_revision: Option<Uuid>,
    ) -> AuthResult<bool> {
        let mut states = self
            .states
            .lock()
            .map_err(|_| AuthError::AuthServiceUnavailable)?;
        states.purge_expired(self.clock.now());
        if states.entries.get(key).map(|snapshot| snapshot.revision) != expected_revision {
            return Ok(false);
        }
        if expected_revision.is_some() {
            states.remove(key);
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthRateLimitBucket, AuthRateLimitFlow};
    use time::Duration;

    #[test]
    fn repeated_revisions_do_not_accumulate_expiry_index_entries() {
        let key = AuthRateLimitKey {
            flow: AuthRateLimitFlow::PasswordLogin,
            bucket: AuthRateLimitBucket::Principal,
            value_hash: "synthetic-key".into(),
        };
        let now = OffsetDateTime::UNIX_EPOCH;
        let mut states = MemoryState::default();
        for n in 1..=1000 {
            states.insert(
                key.clone(),
                AuthRateLimitSnapshot {
                    revision: Uuid::new_v4(),
                    state: AuthRateLimitState {
                        key: key.clone(),
                        attempts: n,
                        first_attempt_at: now,
                        last_attempt_at: now,
                        backoff_until: None,
                        locked_until: None,
                        expires_at: now + Duration::seconds(i64::from(n)),
                    },
                },
            );
        }
        assert_eq!(states.entries.len(), 1);
        assert_eq!(
            states.expirations.values().map(HashSet::len).sum::<usize>(),
            1
        );
        assert_eq!(states.purge_expired(now + Duration::seconds(999)), 0);
        assert_eq!(states.purge_expired(now + Duration::seconds(1000)), 1);
        assert!(states.expirations.is_empty());
    }
}

#[cfg(test)]
mod unwind_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug)]
    struct PanickingClock(AtomicBool);
    impl Clock for PanickingClock {
        fn now(&self) -> OffsetDateTime {
            assert!(
                !self.0.swap(false, Ordering::SeqCst),
                "synthetic clock panic"
            );
            OffsetDateTime::UNIX_EPOCH
        }
    }

    #[tokio::test]
    async fn clock_panics_poison_the_store_and_fail_closed_after_catch_unwind() {
        fn existing_auto_traits<T: std::panic::UnwindSafe + std::panic::RefUnwindSafe>() {}
        existing_auto_traits::<MemoryAuthRateLimitStore>();
        let store = MemoryAuthRateLimitStore::with_capacity_and_clock(
            NonZeroUsize::new(1).unwrap(),
            Arc::new(PanickingClock(AtomicBool::new(true))),
        );
        assert!(std::panic::catch_unwind(|| store.purge_expired()).is_err());
        assert!(matches!(
            store.purge_expired(),
            Err(AuthError::AuthServiceUnavailable)
        ));
        let key = AuthRateLimitKey {
            flow: crate::AuthRateLimitFlow::PasswordLogin,
            bucket: crate::AuthRateLimitBucket::Principal,
            value_hash: "synthetic-key".into(),
        };
        assert!(matches!(
            store.find_auth_rate_limit_state(&key).await,
            Err(AuthError::AuthServiceUnavailable)
        ));
    }
}
