//! Brute-force protection for unlock attempts.
//!
//! The OATH applet has no retry counter for its password, so all limiting
//! lives here: a per-IP backoff that doubles on each failure, and a global
//! lockout when too many failures happen across all clients.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use ipnet::IpNet;

use crate::clock::Clock;

/// First per-IP backoff, doubled on each further failure.
pub const BASE_BACKOFF_SECS: u64 = 1;
/// Longest per-IP backoff.
pub const MAX_BACKOFF_SECS: u64 = 300;
/// Window for counting global failures, and length of a global lockout.
pub const GLOBAL_WINDOW_SECS: u64 = 900;
/// How long after its backoff ends an IP's failure history is forgotten.
pub const FORGET_AFTER_SECS: u64 = 900;

/// Why an unlock attempt may not proceed now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    /// This IP must wait after earlier failures.
    Backoff { retry_after: u64 },
    /// This IP already has an attempt in progress.
    InFlight { retry_after: u64 },
    /// Too many failures overall; nobody may unlock for a while.
    GlobalLockout { retry_after: u64 },
}

impl Denied {
    /// Seconds to send in `Retry-After`. Always at least 1.
    pub fn retry_after(&self) -> u64 {
        let (Self::Backoff { retry_after }
        | Self::InFlight { retry_after }
        | Self::GlobalLockout { retry_after }) = *self;
        retry_after.max(1)
    }
}

/// What recording a failure did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureOutcome {
    /// Seconds this IP must now wait.
    pub backoff: u64,
    /// Whether this failure engaged the global lockout.
    pub global_lockout_engaged: bool,
}

#[derive(Default)]
struct IpState {
    failures: u32,
    blocked_until: u64,
    in_flight: bool,
}

#[derive(Default)]
struct State {
    per_ip: HashMap<IpAddr, IpState>,
    global_failures: VecDeque<u64>,
    lockout_until: u64,
}

pub struct RateLimiter {
    state: Mutex<State>,
    clock: Arc<dyn Clock>,
    global_limit: u32,
}

impl RateLimiter {
    pub fn new(clock: Arc<dyn Clock>, global_limit: u32) -> Self {
        Self {
            state: Mutex::new(State::default()),
            clock,
            global_limit,
        }
    }

    /// Reserve an unlock attempt for `ip`.
    pub fn acquire(&self, ip: IpAddr) -> Result<UnlockPermit<'_>, Denied> {
        let now = self.clock.now();
        let mut state = self.lock();
        state.per_ip.retain(|_, entry| {
            entry.in_flight || now < entry.blocked_until.saturating_add(FORGET_AFTER_SECS)
        });
        if now < state.lockout_until {
            return Err(Denied::GlobalLockout {
                retry_after: state.lockout_until - now,
            });
        }
        let entry = state.per_ip.entry(ip).or_default();
        if entry.in_flight {
            return Err(Denied::InFlight { retry_after: 1 });
        }
        if now < entry.blocked_until {
            return Err(Denied::Backoff {
                retry_after: entry.blocked_until - now,
            });
        }
        entry.in_flight = true;
        Ok(UnlockPermit { limiter: self, ip })
    }

    /// Number of IPs with remembered state.
    pub fn tracked_ips(&self) -> usize {
        self.lock().per_ip.len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("rate limiter mutex poisoned")
    }
}

/// One reserved unlock attempt. Consume it with [`UnlockPermit::success`] or
/// [`UnlockPermit::failure`]. Dropping it records neither, for attempts that
/// never reached a password check (for example, the card was unavailable).
#[must_use = "record the outcome with success() or failure()"]
pub struct UnlockPermit<'a> {
    limiter: &'a RateLimiter,
    ip: IpAddr,
}

impl UnlockPermit<'_> {
    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    /// The password was right. Clears this IP's backoff.
    pub fn success(self) {
        self.limiter.lock().per_ip.remove(&self.ip);
    }

    /// The password was wrong.
    pub fn failure(self) -> FailureOutcome {
        let limiter = self.limiter;
        let now = limiter.clock.now();
        let mut state = limiter.lock();

        let entry = state.per_ip.entry(self.ip).or_default();
        entry.failures = entry.failures.saturating_add(1);
        let backoff = BASE_BACKOFF_SECS
            .checked_shl(entry.failures - 1)
            .map_or(MAX_BACKOFF_SECS, |b| b.min(MAX_BACKOFF_SECS));
        entry.blocked_until = now + backoff;

        state.global_failures.push_back(now);
        while state
            .global_failures
            .front()
            .is_some_and(|&t| t + GLOBAL_WINDOW_SECS <= now)
        {
            state.global_failures.pop_front();
        }
        let global_lockout_engaged = state.global_failures.len() >= limiter.global_limit as usize;
        if global_lockout_engaged {
            state.lockout_until = now + GLOBAL_WINDOW_SECS;
            state.global_failures.clear();
        }

        FailureOutcome {
            backoff,
            global_lockout_engaged,
        }
    }
}

impl Drop for UnlockPermit<'_> {
    fn drop(&mut self) {
        if let Some(entry) = self.limiter.lock().per_ip.get_mut(&self.ip) {
            entry.in_flight = false;
        }
    }
}

/// The client's address. `X-Forwarded-For` is only honoured when the direct
/// peer is a trusted proxy; then the right-most address that is not itself a
/// trusted proxy is the client.
pub fn client_ip(peer: IpAddr, forwarded_for: Option<&str>, trusted: &[IpNet]) -> IpAddr {
    let is_trusted = |addr: &IpAddr| trusted.iter().any(|net| net.contains(addr));
    let peer = peer.to_canonical();
    let Some(header) = forwarded_for.filter(|_| is_trusted(&peer)) else {
        return peer;
    };
    let Ok(chain) = header
        .split(',')
        .map(|part| part.trim().parse::<IpAddr>().map(|a| a.to_canonical()))
        .collect::<Result<Vec<_>, _>>()
    else {
        return peer;
    };
    chain
        .iter()
        .rev()
        .find(|addr| !is_trusted(addr))
        .or(chain.first())
        .copied()
        .unwrap_or(peer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;

    const START: u64 = 1_000_000;
    const LIMIT: u32 = 5;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Global limit high enough that per-IP tests never trip it.
    fn limiter() -> (Arc<ManualClock>, RateLimiter) {
        limiter_with_global_limit(1000)
    }

    fn limiter_with_global_limit(limit: u32) -> (Arc<ManualClock>, RateLimiter) {
        let clock = Arc::new(ManualClock::new(START));
        (clock.clone(), RateLimiter::new(clock, limit))
    }

    fn fail(limiter: &RateLimiter, addr: &str) -> FailureOutcome {
        limiter.acquire(ip(addr)).unwrap().failure()
    }

    // Per-IP backoff

    #[test]
    fn first_attempt_is_allowed() {
        let (_, limiter) = limiter();
        let permit = limiter.acquire(ip("10.0.0.1")).unwrap();
        assert_eq!(permit.ip(), ip("10.0.0.1"));
        permit.success();
    }

    #[test]
    fn first_failure_sets_one_second_backoff() {
        let (clock, limiter) = limiter();
        assert_eq!(fail(&limiter, "10.0.0.1").backoff, 1);
        assert_eq!(
            limiter.acquire(ip("10.0.0.1")).err(),
            Some(Denied::Backoff { retry_after: 1 })
        );
        clock.advance(1);
        assert!(limiter.acquire(ip("10.0.0.1")).is_ok());
    }

    #[test]
    fn subsequent_failures_double_and_cap_at_five_minutes() {
        let (clock, limiter) = limiter();
        let mut seen = Vec::new();
        for _ in 0..12 {
            let outcome = fail(&limiter, "10.0.0.1");
            seen.push(outcome.backoff);
            clock.advance(outcome.backoff);
        }
        assert_eq!(seen, [1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300, 300]);
    }

    #[test]
    fn retry_after_counts_down() {
        let (clock, limiter) = limiter();
        fail(&limiter, "10.0.0.1");
        clock.advance(1);
        fail(&limiter, "10.0.0.1"); // 2s
        clock.advance(2);
        fail(&limiter, "10.0.0.1"); // 4s
        clock.advance(3);
        assert_eq!(
            limiter.acquire(ip("10.0.0.1")).err(),
            Some(Denied::Backoff { retry_after: 1 })
        );
    }

    #[test]
    fn success_resets_backoff_for_that_ip_only() {
        let (clock, limiter) = limiter();
        for addr in ["10.0.0.1", "10.0.0.2"] {
            fail(&limiter, addr);
        }
        clock.advance(1);
        for addr in ["10.0.0.1", "10.0.0.2"] {
            fail(&limiter, addr);
        }
        clock.advance(2);
        limiter.acquire(ip("10.0.0.1")).unwrap().success();

        assert_eq!(fail(&limiter, "10.0.0.1").backoff, 1);
        assert_eq!(fail(&limiter, "10.0.0.2").backoff, 4);
    }

    #[test]
    fn other_ips_are_not_affected_by_backoff() {
        let (_, limiter) = limiter();
        fail(&limiter, "10.0.0.1");
        assert!(limiter.acquire(ip("10.0.0.2")).is_ok());
    }

    #[test]
    fn only_one_attempt_in_flight_per_ip() {
        let (_, limiter) = limiter();
        let first = limiter.acquire(ip("10.0.0.1")).unwrap();
        assert_eq!(
            limiter.acquire(ip("10.0.0.1")).err(),
            Some(Denied::InFlight { retry_after: 1 })
        );
        assert!(limiter.acquire(ip("10.0.0.2")).is_ok());
        first.success();
        assert!(limiter.acquire(ip("10.0.0.1")).is_ok());
    }

    #[test]
    fn dropped_permit_records_nothing_and_frees_the_ip() {
        let (_, limiter) = limiter();
        drop(limiter.acquire(ip("10.0.0.1")).unwrap());
        let permit = limiter.acquire(ip("10.0.0.1")).unwrap();
        assert_eq!(permit.failure().backoff, 1);
    }

    #[test]
    fn ip_history_is_forgotten_after_backoff_plus_grace() {
        let (clock, limiter) = limiter();
        fail(&limiter, "10.0.0.1");
        clock.advance(1);
        fail(&limiter, "10.0.0.1"); // backoff 2, history kept
        assert_eq!(limiter.tracked_ips(), 1);

        clock.advance(2 + FORGET_AFTER_SECS);
        // Any limiter activity prunes stale entries.
        limiter.acquire(ip("10.0.0.9")).unwrap().success();
        assert_eq!(limiter.tracked_ips(), 0);
        assert_eq!(fail(&limiter, "10.0.0.1").backoff, 1);
    }

    #[test]
    fn ip_history_is_kept_within_grace() {
        let (clock, limiter) = limiter();
        fail(&limiter, "10.0.0.1");
        clock.advance(1 + FORGET_AFTER_SECS - 1);
        assert_eq!(fail(&limiter, "10.0.0.1").backoff, 2);
    }

    // Global lockout

    fn fail_from_many(limiter: &RateLimiter, count: u32) -> Vec<FailureOutcome> {
        (0..count)
            .map(|i| fail(limiter, &format!("10.1.0.{i}")))
            .collect()
    }

    #[test]
    fn global_lockout_engages_at_threshold_within_window() {
        let (_, limiter) = limiter_with_global_limit(LIMIT);
        let outcomes = fail_from_many(&limiter, LIMIT);
        let engaged: Vec<bool> = outcomes.iter().map(|o| o.global_lockout_engaged).collect();
        assert_eq!(engaged, [false, false, false, false, true]);
        assert_eq!(
            limiter.acquire(ip("192.168.1.1")).err(),
            Some(Denied::GlobalLockout {
                retry_after: GLOBAL_WINDOW_SECS
            })
        );
    }

    #[test]
    fn global_lockout_below_threshold_does_not_engage() {
        let (_, limiter) = limiter_with_global_limit(LIMIT);
        fail_from_many(&limiter, LIMIT - 1);
        assert!(limiter.acquire(ip("192.168.1.1")).is_ok());
    }

    #[test]
    fn global_lockout_releases_after_15_minutes() {
        let (clock, limiter) = limiter_with_global_limit(LIMIT);
        fail_from_many(&limiter, LIMIT);
        clock.advance(GLOBAL_WINDOW_SECS - 1);
        assert_eq!(
            limiter.acquire(ip("192.168.1.1")).err(),
            Some(Denied::GlobalLockout { retry_after: 1 })
        );
        clock.advance(1);
        assert!(limiter.acquire(ip("192.168.1.1")).is_ok());
    }

    #[test]
    fn failures_outside_window_do_not_count_toward_global_lockout() {
        let (clock, limiter) = limiter_with_global_limit(LIMIT);
        fail_from_many(&limiter, LIMIT - 1);
        clock.advance(GLOBAL_WINDOW_SECS);
        let outcome = fail(&limiter, "10.2.0.1");
        assert!(!outcome.global_lockout_engaged);
        assert!(limiter.acquire(ip("192.168.1.1")).is_ok());
    }

    #[test]
    fn global_lockout_takes_precedence_over_backoff() {
        let (_, limiter) = limiter_with_global_limit(LIMIT);
        fail_from_many(&limiter, LIMIT);
        assert!(matches!(
            limiter.acquire(ip("10.1.0.0")).err(),
            Some(Denied::GlobalLockout { .. })
        ));
    }

    #[test]
    fn retry_after_is_at_least_one_second() {
        for denied in [
            Denied::Backoff { retry_after: 0 },
            Denied::InFlight { retry_after: 0 },
            Denied::GlobalLockout { retry_after: 0 },
        ] {
            assert_eq!(denied.retry_after(), 1);
        }
        assert_eq!(Denied::Backoff { retry_after: 7 }.retry_after(), 7);
        assert_eq!(
            Denied::GlobalLockout { retry_after: 900 }.retry_after(),
            900
        );
    }

    // Client IP

    fn nets(list: &[&str]) -> Vec<IpNet> {
        list.iter().map(|n| n.parse().unwrap()).collect()
    }

    #[test]
    fn untrusted_peer_ignores_forwarded_for() {
        let trusted = nets(&["172.16.0.0/12"]);
        assert_eq!(
            client_ip(ip("192.168.1.50"), Some("1.2.3.4"), &trusted),
            ip("192.168.1.50")
        );
    }

    #[test]
    fn no_trusted_proxies_ignores_forwarded_for() {
        assert_eq!(
            client_ip(ip("172.18.0.2"), Some("1.2.3.4"), &[]),
            ip("172.18.0.2")
        );
    }

    #[test]
    fn trusted_peer_uses_forwarded_for() {
        let trusted = nets(&["172.16.0.0/12"]);
        assert_eq!(
            client_ip(ip("172.18.0.2"), Some("192.168.1.50"), &trusted),
            ip("192.168.1.50")
        );
    }

    #[test]
    fn trusted_peer_without_header_uses_peer() {
        let trusted = nets(&["172.16.0.0/12"]);
        assert_eq!(
            client_ip(ip("172.18.0.2"), None, &trusted),
            ip("172.18.0.2")
        );
    }

    #[test]
    fn spoofed_left_entries_are_ignored() {
        // A client sends its own X-Forwarded-For; Traefik appends the real one.
        let trusted = nets(&["172.16.0.0/12"]);
        assert_eq!(
            client_ip(ip("172.18.0.2"), Some("6.6.6.6, 192.168.1.50"), &trusted),
            ip("192.168.1.50")
        );
    }

    #[test]
    fn chained_trusted_proxies_are_skipped() {
        let trusted = nets(&["172.16.0.0/12", "10.0.0.0/8"]);
        assert_eq!(
            client_ip(ip("172.18.0.2"), Some("192.168.1.50, 10.0.0.5"), &trusted),
            ip("192.168.1.50")
        );
    }

    #[test]
    fn all_trusted_chain_uses_left_most() {
        let trusted = nets(&["10.0.0.0/8", "172.16.0.0/12"]);
        assert_eq!(
            client_ip(ip("172.18.0.2"), Some("10.0.0.7, 10.0.0.5"), &trusted),
            ip("10.0.0.7")
        );
    }

    #[test]
    fn unparseable_forwarded_for_falls_back_to_peer() {
        let trusted = nets(&["172.16.0.0/12"]);
        for header in ["garbage", "192.168.1.50:1234", "", " , "] {
            assert_eq!(
                client_ip(ip("172.18.0.2"), Some(header), &trusted),
                ip("172.18.0.2"),
                "{header:?}"
            );
        }
    }

    #[test]
    fn ipv4_mapped_addresses_are_normalised() {
        let trusted = nets(&["172.16.0.0/12"]);
        assert_eq!(
            client_ip(
                ip("::ffff:172.18.0.2"),
                Some("::ffff:192.168.1.50"),
                &trusted
            ),
            ip("192.168.1.50")
        );
        assert_eq!(client_ip(ip("::ffff:10.0.0.1"), None, &[]), ip("10.0.0.1"));
    }

    #[test]
    fn ipv6_clients_are_supported() {
        let trusted = nets(&["fd00::/8"]);
        assert_eq!(
            client_ip(ip("fd00::2"), Some("2001:db8::1"), &trusted),
            ip("2001:db8::1")
        );
    }
}
