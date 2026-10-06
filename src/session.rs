//! In-memory sessions holding the derived OATH key.
//!
//! Sessions expire after an idle timeout or an absolute timeout, whichever
//! comes first. They are lost on restart by design.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::clock::Clock;
use crate::oath::crypto::DerivedKey;
use crate::rng::{ChallengeSource, SESSION_ID_LEN};

/// Raw session ID as sent in the cookie. Never log this; use [`SessionId::log_id`].
#[derive(Clone, PartialEq, Eq)]
pub struct SessionId([u8; SESSION_ID_LEN]);

impl SessionId {
    /// Lowercase hex for the cookie value.
    pub fn to_cookie_value(&self) -> String {
        todo!()
    }

    /// Parse a cookie value. `None` unless it is exactly 64 hex digits.
    pub fn from_cookie_value(_value: &str) -> Option<Self> {
        todo!()
    }

    /// Short, stable, non-reversible identifier for logs.
    pub fn log_id(&self) -> String {
        todo!()
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

struct Entry {
    key: DerivedKey,
    created: u64,
    last_seen: u64,
}

pub struct SessionStore {
    entries: Mutex<HashMap<[u8; 32], Entry>>,
    clock: Arc<dyn Clock>,
    rng: Arc<dyn ChallengeSource>,
    idle_secs: u64,
    max_secs: u64,
}

impl SessionStore {
    pub fn new(
        clock: Arc<dyn Clock>,
        rng: Arc<dyn ChallengeSource>,
        idle_secs: u64,
        max_secs: u64,
    ) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            clock,
            rng,
            idle_secs,
            max_secs,
        }
    }

    /// Store `key` under a new random session ID.
    pub fn create(&self, _key: DerivedKey) -> SessionId {
        let _ = (
            &self.entries,
            &self.clock,
            &self.rng,
            self.idle_secs,
            self.max_secs,
        );
        todo!()
    }

    /// Return the session's key and refresh its idle timeout, or `None` if
    /// the session is unknown or expired. Expired sessions are removed.
    pub fn touch(&self, _id: &SessionId) -> Option<DerivedKey> {
        todo!()
    }

    /// Delete a session. Returns whether it existed.
    pub fn remove(&self, _id: &SessionId) -> bool {
        todo!()
    }

    /// Delete every expired session. Returns how many were removed.
    pub fn purge(&self) -> usize {
        todo!()
    }

    pub fn len(&self) -> usize {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Run [`SessionStore::purge`] every `every` until the task is aborted.
pub fn spawn_purger(_store: Arc<SessionStore>, _every: Duration) -> tokio::task::JoinHandle<()> {
    let _ = Entry::created_unused;
    todo!()
}

impl Entry {
    #[allow(dead_code)]
    fn created_unused(&self) -> (&DerivedKey, u64, u64) {
        (&self.key, self.created, self.last_seen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use crate::oath::crypto::KEY_LEN;
    use crate::rng::SequentialChallengeSource;
    use zeroize::Zeroizing;

    const IDLE: u64 = 300;
    const MAX: u64 = 1800;
    const START: u64 = 1_000_000;

    fn store() -> (Arc<ManualClock>, SessionStore) {
        let clock = Arc::new(ManualClock::new(START));
        let store = SessionStore::new(
            clock.clone(),
            Arc::new(SequentialChallengeSource::new(0)),
            IDLE,
            MAX,
        );
        (clock, store)
    }

    fn key(byte: u8) -> DerivedKey {
        Zeroizing::new([byte; KEY_LEN])
    }

    #[test]
    fn create_stores_key_under_32_byte_id_from_challenge_source() {
        let (_, store) = store();
        let id = store.create(key(7));
        let expected: Vec<u8> = (0..32).collect();
        assert_eq!(id.0.as_slice(), expected.as_slice());
        assert_eq!(*store.touch(&id).unwrap(), [7; KEY_LEN]);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn each_session_gets_its_own_id_and_key() {
        let (_, store) = store();
        let a = store.create(key(1));
        let b = store.create(key(2));
        assert_ne!(a, b);
        assert_eq!(*store.touch(&a).unwrap(), [1; KEY_LEN]);
        assert_eq!(*store.touch(&b).unwrap(), [2; KEY_LEN]);
    }

    #[test]
    fn key_material_is_zeroizing() {
        let (_, store) = store();
        let id = store.create(key(1));
        let _typed: Zeroizing<[u8; KEY_LEN]> = store.touch(&id).unwrap();
    }

    #[test]
    fn unknown_session_is_none() {
        let (_, store) = store();
        let id = SessionId([9; 32]);
        assert!(store.touch(&id).is_none());
    }

    #[test]
    fn idle_expiry_after_idle_secs_without_activity() {
        let (clock, store) = store();
        let id = store.create(key(1));
        clock.set(START + IDLE - 1);
        assert!(store.touch(&id).is_some());

        let id = store.create(key(2));
        let created = clock.now();
        clock.set(created + IDLE);
        assert!(store.touch(&id).is_none());
    }

    #[test]
    fn expired_session_is_removed_when_touched() {
        let (clock, store) = store();
        let id = store.create(key(1));
        clock.advance(IDLE);
        assert!(store.touch(&id).is_none());
        assert!(store.is_empty());
    }

    #[test]
    fn activity_extends_idle_expiry() {
        let (clock, store) = store();
        let id = store.create(key(1));
        clock.advance(200);
        assert!(store.touch(&id).is_some());
        clock.advance(IDLE - 1);
        assert!(store.touch(&id).is_some());
        clock.advance(IDLE);
        assert!(store.touch(&id).is_none());
    }

    #[test]
    fn activity_never_extends_past_absolute_expiry() {
        let (clock, store) = store();
        let id = store.create(key(1));
        while clock.now() + 200 < START + MAX {
            clock.advance(200);
            assert!(store.touch(&id).is_some(), "at {}", clock.now() - START);
        }
        clock.set(START + MAX - 1);
        assert!(store.touch(&id).is_some());
        clock.set(START + MAX);
        assert!(store.touch(&id).is_none());
    }

    #[test]
    fn purge_removes_expired_sessions_only() {
        let (clock, store) = store();
        let old = store.create(key(1));
        clock.advance(200);
        let fresh = store.create(key(2));
        clock.advance(150);

        assert_eq!(store.purge(), 1);
        assert_eq!(store.len(), 1);
        assert!(store.touch(&old).is_none());
        assert!(store.touch(&fresh).is_some());
    }

    #[test]
    fn purge_with_nothing_expired_removes_nothing() {
        let (_, store) = store();
        store.create(key(1));
        assert_eq!(store.purge(), 0);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn remove_deletes_the_session() {
        let (_, store) = store();
        let id = store.create(key(1));
        assert!(store.remove(&id));
        assert!(store.touch(&id).is_none());
        assert!(!store.remove(&id));
    }

    #[test]
    fn cookie_value_round_trips() {
        let (_, store) = store();
        let id = store.create(key(1));
        let value = id.to_cookie_value();
        assert_eq!(value.len(), 64);
        assert!(value.starts_with("000102030405"));
        assert_eq!(SessionId::from_cookie_value(&value), Some(id));
    }

    #[test]
    fn cookie_value_accepts_uppercase_hex() {
        let value = "AB".repeat(32);
        assert_eq!(
            SessionId::from_cookie_value(&value),
            Some(SessionId([0xAB; 32]))
        );
    }

    #[test]
    fn bad_cookie_values_are_rejected() {
        for value in [
            "",
            "00",
            &"0".repeat(63),
            &"0".repeat(65),
            &"zz".repeat(32),
            &"é".repeat(32),
        ] {
            assert_eq!(SessionId::from_cookie_value(value), None, "{value:?}");
        }
    }

    #[test]
    fn debug_output_does_not_reveal_the_id() {
        let id = SessionId([0xAB; 32]);
        let debug = format!("{id:?}");
        assert!(!debug.to_lowercase().contains("abab"), "{debug}");
        assert!(!debug.contains("171"), "{debug}");
    }

    #[test]
    fn log_id_is_short_stable_and_not_the_raw_id() {
        let id = SessionId([0xAB; 32]);
        let log_id = id.log_id();
        assert_eq!(log_id.len(), 16);
        assert!(log_id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(log_id, SessionId([0xAB; 32]).log_id());
        assert_ne!(log_id, SessionId([0xAC; 32]).log_id());
        assert!(!id.to_cookie_value().contains(&log_id));
    }

    #[tokio::test(start_paused = true)]
    async fn purger_runs_periodically() {
        let (clock, store) = store();
        let store = Arc::new(store);
        store.create(key(1));
        let task = spawn_purger(store.clone(), Duration::from_secs(30));

        clock.advance(IDLE);
        assert_eq!(store.len(), 1);
        tokio::time::sleep(Duration::from_secs(31)).await;
        assert!(store.is_empty());
        task.abort();
    }
}
