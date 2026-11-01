//! Resolution-failure cache (RFC 9520).
//!
//! When no upstream can resolve a name (every attempt failed, or the
//! upstream itself answered SERVFAIL), the failure is remembered per
//! `(name, type, class)`: repeat queries get an immediate SERVFAIL
//! instead of costing another 0.8 to 2.6 s each (measured on the house
//! trace for names with broken authoritative servers). RFC 9520 §3.2
//! requires at least 1 s and at most 5 min, with backoff for repeated
//! failures; here the first failure holds 5 s, each consecutive one
//! doubles it, capped at 60 s. A success clears the key.
//!
//! The cache never turns a failure into NXDOMAIN or into an answer: it
//! only saves the upstream from being asked again too soon. A stale
//! cache entry, when one exists, still wins (RFC 8767).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::cache::CacheKey;

/// Hold-down after the first failure.
pub const FIRST_HOLD: Duration = Duration::from_secs(5);
/// Longest hold-down, reached after four consecutive failures.
pub const MAX_HOLD: Duration = Duration::from_mins(1);
/// Keys tracked at most; beyond it, keys idle for longer than
/// [`MAX_HOLD`] are pruned, and if none is, the oldest hold is dropped.
const MAX_KEYS: usize = 4096;

#[derive(Debug, Clone, Copy)]
struct Failure {
    until: Instant,
    hold: Duration,
}

/// Per-key failure hold-downs.
#[derive(Debug, Default)]
pub struct FailureCache {
    inner: Mutex<HashMap<CacheKey, Failure>>,
}

impl FailureCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Time left on `key`'s hold-down at `now`, if it is held.
    ///
    /// # Panics
    ///
    /// If the internal mutex is poisoned.
    #[must_use]
    pub fn held(&self, key: &CacheKey, now: Instant) -> Option<Duration> {
        let inner = self.inner.lock().expect("failure cache poisoned");
        inner
            .get(key)
            .and_then(|f| f.until.checked_duration_since(now))
            .filter(|left| !left.is_zero())
    }

    /// Record a failure for `key` at `now`; returns the hold applied.
    /// A failure within [`MAX_HOLD`] of the previous hold's end counts
    /// as consecutive and doubles the hold.
    ///
    /// # Panics
    ///
    /// If the internal mutex is poisoned.
    pub fn record(&self, key: CacheKey, now: Instant) -> Duration {
        let mut inner = self.inner.lock().expect("failure cache poisoned");
        let hold = match inner.get(&key) {
            Some(prev) if now < prev.until + MAX_HOLD => (prev.hold * 2).min(MAX_HOLD),
            _ => FIRST_HOLD,
        };
        if inner.len() >= MAX_KEYS && !inner.contains_key(&key) {
            inner.retain(|_, f| now < f.until + MAX_HOLD);
            if inner.len() >= MAX_KEYS
                && let Some(oldest) = inner
                    .iter()
                    .min_by_key(|(_, f)| f.until)
                    .map(|(k, _)| k.clone())
            {
                inner.remove(&oldest);
            }
        }
        inner.insert(
            key,
            Failure {
                until: now + hold,
                hold,
            },
        );
        hold
    }

    /// The key resolved: forget its failures.
    ///
    /// # Panics
    ///
    /// If the internal mutex is poisoned.
    pub fn clear(&self, key: &CacheKey) {
        self.inner
            .lock()
            .expect("failure cache poisoned")
            .remove(key);
    }

    /// Keys currently tracked (held or remembered for backoff).
    ///
    /// # Panics
    ///
    /// If the internal mutex is poisoned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().expect("failure cache poisoned").len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{DNSClass, Name, RecordType};

    fn key(name: &str, t: RecordType) -> CacheKey {
        CacheKey::new(Name::from_ascii(name).unwrap(), t, DNSClass::IN)
    }

    #[test]
    fn broken_domain_backs_off_5_10_20_40_60_and_a_success_resets_it() {
        let fc = FailureCache::new();
        let k = key("broken.example.", RecordType::A);
        let mut now = Instant::now();
        let mut holds = Vec::new();
        for _ in 0..6 {
            let hold = fc.record(k.clone(), now);
            assert!(fc.held(&k, now).is_some());
            assert!(fc.held(&k, now + hold).is_none(), "hold ends on time");
            holds.push(hold.as_secs());
            now += hold; // the client retries right when the hold ends
        }
        assert_eq!(holds, [5, 10, 20, 40, 60, 60]);
        fc.clear(&k);
        assert_eq!(fc.record(k, now).as_secs(), 5);
    }

    #[test]
    fn holds_are_per_type_and_a_quiet_minute_forgets_the_streak() {
        let fc = FailureCache::new();
        let now = Instant::now();
        let a = key("broken.example.", RecordType::A);
        fc.record(a.clone(), now);
        assert!(
            fc.held(&key("broken.example.", RecordType::AAAA), now)
                .is_none()
        );
        // Next failure long after the hold (and a further minute): 5 s again.
        let later = now + FIRST_HOLD + MAX_HOLD;
        assert_eq!(fc.record(a, later), FIRST_HOLD);
    }

    #[test]
    fn tracked_keys_stay_bounded() {
        let fc = FailureCache::new();
        let now = Instant::now();
        for i in 0..(MAX_KEYS + 100) {
            fc.record(key(&format!("n{i}.example."), RecordType::A), now);
        }
        assert!(fc.len() <= MAX_KEYS);
    }
}
