//! Minimal in-memory rate limiting for the admin UI's credential endpoints
//! (login, password reset, single-tenant basic auth).
//!
//! A sliding window of recent attempt timestamps per string key, throttling —
//! not locking out: a denied attempt is never recorded, so a client is
//! admitted again as soon as an old attempt ages out of the window. Keys are
//! whatever the caller composes (`"login:ip:…"`, `"login:email:…"`), so one
//! limiter serves per-IP and per-account policies alike.
//!
//! Deliberately process-local: multi-instance deployments get a per-instance
//! allowance, which still reduces an online brute force from millions of
//! guesses to a few dozen per hour — the shared-store version can come with
//! the rest of the hosted-service work. Operators whose load balancer /
//! reverse proxy already rate-limits can turn the built-in limiter off with
//! `SCONCE_RATE_LIMIT=off` (see [`RateLimiter::from_env`]).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Above this window count, [`RateLimiter::allow`] sweeps abandoned keys so
/// unauthenticated traffic can't grow the map without bound.
const SWEEP_THRESHOLD: usize = 4096;
/// Age past which a key's newest attempt marks the whole key abandoned. Must
/// be at least as long as any window passed to [`RateLimiter::allow`].
const MAX_WINDOW: Duration = Duration::from_hours(1);
/// Keys are truncated to this many characters — attacker-supplied input
/// (an "email" field) must not become an unbounded allocation.
const MAX_KEY_CHARS: usize = 256;
/// Cap on timestamps retained per key; comfortably above any `max` in use.
const MAX_ATTEMPTS_KEPT: usize = 64;

/// A sliding-window rate limiter over string keys. Cheap to clone (shared
/// state behind an `Arc`).
#[derive(Clone, Debug)]
pub struct RateLimiter {
    /// `false` = every check passes and nothing is recorded — for deployments
    /// whose load balancer / reverse proxy enforces rate limits itself.
    enabled: bool,
    windows: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            enabled: true,
            windows: Arc::default(),
        }
    }
}

impl RateLimiter {
    /// Build from the `SCONCE_RATE_LIMIT` environment variable: set it to
    /// `off` (or `false`/`0`/`disabled`/`no`) to disable the built-in limiter
    /// when the load balancer / reverse proxy in front of sconce already
    /// enforces rate limits. Anything else — including unset — keeps it on.
    pub fn from_env() -> Self {
        Self::from_setting(std::env::var("SCONCE_RATE_LIMIT").ok().as_deref())
    }

    fn from_setting(value: Option<&str>) -> Self {
        let off = value.is_some_and(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "off" | "false" | "0" | "disabled" | "no"
            )
        });
        Self {
            enabled: !off,
            ..Self::default()
        }
    }
    /// Record one attempt under `key` and report whether it is allowed:
    /// `false` once `max` attempts already landed within `window`.
    pub fn allow(&self, key: &str, max: usize, window: Duration) -> bool {
        self.hit(key, Some((max, window)), Instant::now())
    }

    /// Report whether `key` has reached `max` recorded attempts within
    /// `window`, recording nothing. Pair with [`Self::record`] to count only
    /// failures (basic auth, where every page load re-sends the password).
    pub fn at_limit(&self, key: &str, max: usize, window: Duration) -> bool {
        if !self.enabled {
            return false;
        }
        let now = Instant::now();
        let mut windows = self.lock();
        let Some(w) = windows.get_mut(&bounded_key(key)) else {
            return false;
        };
        prune(w, window, now);
        w.len() >= max
    }

    /// Record an attempt under `key` unconditionally.
    pub fn record(&self, key: &str) {
        self.hit(key, None, Instant::now());
    }

    /// Shared body: prune, optionally enforce a limit, then record. Returns
    /// whether the attempt was admitted (always `true` without a limit).
    fn hit(&self, key: &str, limit: Option<(usize, Duration)>, now: Instant) -> bool {
        if !self.enabled {
            return true;
        }
        let mut windows = self.lock();
        if windows.len() >= SWEEP_THRESHOLD {
            windows.retain(|_, w| {
                w.back()
                    .is_some_and(|t| now.saturating_duration_since(*t) < MAX_WINDOW)
            });
        }
        let w = windows.entry(bounded_key(key)).or_default();
        if let Some((max, window)) = limit {
            prune(w, window, now);
            if w.len() >= max {
                return false;
            }
        } else {
            prune(w, MAX_WINDOW, now);
        }
        if w.len() == MAX_ATTEMPTS_KEPT {
            w.pop_front();
        }
        w.push_back(now);
        true
    }

    /// Poison-tolerant lock: the map stays coherent across a panicking thread
    /// (every update leaves it valid), so recover rather than propagate.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, VecDeque<Instant>>> {
        self.windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn prune(w: &mut VecDeque<Instant>, window: Duration, now: Instant) {
    while w
        .front()
        .is_some_and(|t| now.saturating_duration_since(*t) >= window)
    {
        w.pop_front();
    }
}

fn bounded_key(key: &str) -> String {
    key.chars().take(MAX_KEY_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOW: Duration = Duration::from_millis(40);

    #[test]
    fn allows_up_to_max_then_denies() {
        let rl = RateLimiter::default();
        assert!(rl.allow("k", 3, WINDOW));
        assert!(rl.allow("k", 3, WINDOW));
        assert!(rl.allow("k", 3, WINDOW));
        assert!(!rl.allow("k", 3, WINDOW));
    }

    #[test]
    fn keys_are_independent() {
        let rl = RateLimiter::default();
        assert!(rl.allow("a", 1, WINDOW));
        assert!(!rl.allow("a", 1, WINDOW));
        assert!(rl.allow("b", 1, WINDOW));
    }

    #[test]
    fn admits_again_after_the_window_passes() {
        let rl = RateLimiter::default();
        assert!(rl.allow("k", 1, WINDOW));
        assert!(!rl.allow("k", 1, WINDOW));
        std::thread::sleep(WINDOW + Duration::from_millis(10));
        assert!(rl.allow("k", 1, WINDOW));
    }

    #[test]
    fn denied_attempts_do_not_extend_the_window() {
        let rl = RateLimiter::default();
        assert!(rl.allow("k", 1, WINDOW));
        // Hammering while denied must not push recovery further out.
        for _ in 0..5 {
            assert!(!rl.allow("k", 1, WINDOW));
        }
        std::thread::sleep(WINDOW + Duration::from_millis(10));
        assert!(rl.allow("k", 1, WINDOW));
    }

    #[test]
    fn at_limit_checks_without_recording() {
        let rl = RateLimiter::default();
        assert!(!rl.at_limit("k", 2, WINDOW));
        rl.record("k");
        assert!(!rl.at_limit("k", 2, WINDOW));
        rl.record("k");
        assert!(rl.at_limit("k", 2, WINDOW));
        // Checking repeatedly never counts as an attempt.
        assert!(rl.at_limit("k", 2, WINDOW));
    }

    #[test]
    fn setting_parses_off_spellings_and_defaults_on() {
        for off in ["off", "false", "0", "disabled", "no", " OFF "] {
            assert!(!RateLimiter::from_setting(Some(off)).enabled, "{off:?}");
        }
        for on in [None, Some("on"), Some("true"), Some(""), Some("42")] {
            assert!(RateLimiter::from_setting(on).enabled, "{on:?}");
        }
    }

    #[test]
    fn disabled_limiter_admits_everything_and_records_nothing() {
        let rl = RateLimiter::from_setting(Some("off"));
        for _ in 0..20 {
            assert!(rl.allow("k", 1, WINDOW));
        }
        rl.record("k");
        assert!(!rl.at_limit("k", 1, WINDOW));
        assert!(rl.lock().is_empty());
    }

    #[test]
    fn oversized_keys_are_bounded_but_still_distinct_within_the_cap() {
        let rl = RateLimiter::default();
        let long_a = format!("{}a", "x".repeat(300));
        let long_b = format!("{}b", "x".repeat(300));
        // Both truncate to the same 256-char prefix and share a window.
        assert!(rl.allow(&long_a, 1, WINDOW));
        assert!(!rl.allow(&long_b, 1, WINDOW));
    }
}
