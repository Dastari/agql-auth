//! Injectable clocks for deterministic auth tests and validation.

use std::sync::{Arc, Mutex};

use time::OffsetDateTime;

/// Source of the current UTC time used by validators and status checks.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Returns the current UTC timestamp.
    fn now(&self) -> OffsetDateTime;
}

/// System wall clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// Fixed/test clock that can be advanced deliberately.
#[derive(Debug, Clone)]
pub struct FixedClock {
    now: Arc<Mutex<OffsetDateTime>>,
}

impl FixedClock {
    /// Creates a clock fixed at `now`.
    pub fn new(now: OffsetDateTime) -> Self {
        Self {
            now: Arc::new(Mutex::new(now)),
        }
    }

    /// Sets the current time.
    pub fn set(&self, now: OffsetDateTime) {
        *self.now.lock().expect("fixed clock lock") = now;
    }

    /// Advances the clock by `delta` seconds (may be negative).
    pub fn advance_seconds(&self, delta: i64) {
        let mut guard = self.now.lock().expect("fixed clock lock");
        *guard += time::Duration::seconds(delta);
    }
}

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        *self.now.lock().expect("fixed clock lock")
    }
}
