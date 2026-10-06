//! Randomness source for card challenges and session IDs. No other module
//! reads randomness directly.

use std::sync::Mutex;

/// Length of the challenge we send in VALIDATE.
pub const CHALLENGE_LEN: usize = 8;
/// Length of a session ID.
pub const SESSION_ID_LEN: usize = 32;

pub trait ChallengeSource: Send + Sync {
    /// Fill `buf` with random bytes.
    fn fill(&self, buf: &mut [u8]);

    fn challenge(&self) -> [u8; CHALLENGE_LEN] {
        let mut out = [0; CHALLENGE_LEN];
        self.fill(&mut out);
        out
    }

    fn session_id(&self) -> [u8; SESSION_ID_LEN] {
        let mut out = [0; SESSION_ID_LEN];
        self.fill(&mut out);
        out
    }
}

/// Operating system CSPRNG.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsChallengeSource;

impl ChallengeSource for OsChallengeSource {
    fn fill(&self, _buf: &mut [u8]) {}
}

/// Test source. Emits the byte sequence `seed, seed+1, seed+2, ...`
/// (wrapping), continuing across calls, so outputs are predictable and
/// successive calls differ.
#[derive(Debug, Default)]
pub struct SequentialChallengeSource {
    next: Mutex<u8>,
}

impl SequentialChallengeSource {
    pub fn new(_seed: u8) -> Self {
        Self::default()
    }
}

impl ChallengeSource for SequentialChallengeSource {
    fn fill(&self, _buf: &mut [u8]) {
        let _ = &self.next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn os_source_session_ids_are_not_all_zero_and_differ() {
        let a = OsChallengeSource.session_id();
        let b = OsChallengeSource.session_id();
        assert_ne!(a, [0; SESSION_ID_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn sequential_source_challenge_counts_up_from_seed() {
        let rng = SequentialChallengeSource::new(1);
        assert_eq!(rng.challenge(), [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn sequential_source_continues_across_calls() {
        let rng = SequentialChallengeSource::new(0);
        let first = rng.challenge();
        let second = rng.challenge();
        assert_eq!(first, [0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(second, [8, 9, 10, 11, 12, 13, 14, 15]);
    }

    #[test]
    fn sequential_source_wraps_after_255() {
        let rng = SequentialChallengeSource::new(254);
        assert_eq!(rng.challenge()[..3], [254, 255, 0]);
    }

    #[test]
    fn sequential_sources_with_same_seed_agree() {
        let a = SequentialChallengeSource::new(7);
        let b = SequentialChallengeSource::new(7);
        assert_eq!(a.session_id(), b.session_id());
    }

    #[test]
    fn session_id_is_32_bytes_from_the_source() {
        let rng: Arc<dyn ChallengeSource> = Arc::new(SequentialChallengeSource::new(0));
        let id = rng.session_id();
        let expected: Vec<u8> = (0..32).collect();
        assert_eq!(id.as_slice(), expected.as_slice());
    }
}
