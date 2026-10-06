//! In-memory sessions holding the derived OATH key.
//!
//! Sessions expire after an idle timeout or an absolute timeout, whichever
//! comes first. They are lost on restart by design.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::clock::Clock;
use crate::oath::crypto::DerivedKey;
use crate::rng::{ChallengeSource, SESSION_ID_LEN};

/// Raw session ID as sent in the cookie. Never log this; use [`SessionId::log_id`].
#[derive(Clone, PartialEq, Eq)]
pub struct SessionId([u8; SESSION_ID_LEN]);

impl SessionId {
    /// Lowercase hex for the cookie value.
    pub fn to_cookie_value(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Parse a cookie value. `None` unless it is exactly 64 hex digits.
    pub fn from_cookie_value(value: &str) -> Option<Self> {
        // from_str_radix alone would also accept a leading '+'.
        if value.len() != SESSION_ID_LEN * 2 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let mut id = [0; SESSION_ID_LEN];
        for (byte, pair) in id.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
            let pair = std::str::from_utf8(pair).ok()?;
            *byte = u8::from_str_radix(pair, 16).ok()?;
        }
        Some(Self(id))
    }

    /// Short, stable, non-reversible identifier for logs.
    pub fn log_id(&self) -> String {
        self.digest()[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// SHA-256 of the ID. The store is keyed by this, not the raw ID.
    fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.0).into()
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionId({})", self.log_id())
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
    pub fn create(&self, key: DerivedKey) -> SessionId {
        let id = SessionId(self.rng.session_id());
        let now = self.clock.now();
        self.lock().insert(
            id.digest(),
            Entry {
                key,
                created: now,
                last_seen: now,
            },
        );
        id
    }

    /// Return the session's key and refresh its idle timeout, or `None` if
    /// the session is unknown or expired. Expired sessions are removed.
    pub fn touch(&self, id: &SessionId) -> Option<DerivedKey> {
        let now = self.clock.now();
        let digest = id.digest();
        let mut entries = self.lock();
        let entry = entries.get_mut(&digest)?;
        if self.expired(entry, now) {
            entries.remove(&digest);
            return None;
        }
        entry.last_seen = now;
        Some(entry.key.clone())
    }

    /// Delete a session. Returns whether it existed.
    pub fn remove(&self, id: &SessionId) -> bool {
        self.lock().remove(&id.digest()).is_some()
    }

    /// Delete every expired session. Returns how many were removed.
    pub fn purge(&self) -> usize {
        let now = self.clock.now();
        let mut entries = self.lock();
        let before = entries.len();
        entries.retain(|_, entry| !self.expired(entry, now));
        before - entries.len()
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn expired(&self, entry: &Entry, now: u64) -> bool {
        now >= entry.last_seen.saturating_add(self.idle_secs)
            || now >= entry.created.saturating_add(self.max_secs)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], Entry>> {
        self.entries.lock().expect("session store mutex poisoned")
    }
}

/// Run [`SessionStore::purge`] every `every` until the task is aborted.
pub fn spawn_purger(store: Arc<SessionStore>, every: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(every);
        loop {
            ticks.tick().await;
            store.purge();
        }
    })
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
            &"+a".repeat(32),
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
