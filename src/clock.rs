//! Time source. No other module reads system time directly.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Current time as whole seconds since the Unix epoch.
pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}

/// Reads the operating system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        // A clock set before 1970 is a broken host; treat it as the epoch.
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

/// Test clock that only moves when told to.
#[derive(Debug, Default)]
pub struct ManualClock {
    now: AtomicU64,
}

impl ManualClock {
    pub fn new(start: u64) -> Self {
        Self {
            now: AtomicU64::new(start),
        }
    }

    pub fn advance(&self, secs: u64) {
        self.now.fetch_add(secs, Ordering::SeqCst);
    }

    pub fn set(&self, secs: u64) {
        self.now.store(secs, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // 2024-01-01T00:00:00Z
    const JAN_2024: u64 = 1_704_067_200;

    #[test]
    fn system_clock_reports_current_unix_seconds() {
        assert!(SystemClock.now() > JAN_2024);
    }

    #[test]
    fn manual_clock_starts_at_given_time() {
        assert_eq!(ManualClock::new(JAN_2024).now(), JAN_2024);
    }

    #[test]
    fn manual_clock_advance_moves_time_forward() {
        let clock = ManualClock::new(100);
        clock.advance(29);
        clock.advance(1);
        assert_eq!(clock.now(), 130);
    }

    #[test]
    fn manual_clock_set_jumps_to_given_time() {
        let clock = ManualClock::new(100);
        clock.set(59);
        assert_eq!(clock.now(), 59);
    }

    #[test]
    fn manual_clock_changes_are_seen_through_shared_trait_object() {
        let clock = Arc::new(ManualClock::new(0));
        let shared: Arc<dyn Clock> = clock.clone();
        clock.advance(30);
        assert_eq!(shared.now(), 30);
    }
}
