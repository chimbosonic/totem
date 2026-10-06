//! Business logic over the card: startup check, unlock, and code listing.
//!
//! Card access is serialised behind one async mutex and runs on the blocking
//! thread pool. Every operation is a fresh SELECT inside one transaction;
//! nothing relies on the card staying unlocked between requests.

use std::sync::Arc;

use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::card::{self, CardError, CardTransaction, OathCard};
use crate::clock::Clock;
use crate::oath::crypto::{self, DerivedKey};
use crate::oath::proto::{self, Command, EntryState, ProtoError, SelectResponse};
use crate::rng::ChallengeSource;
use crate::session::AuthedSession;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ServiceError {
    #[error("wrong OATH password")]
    WrongPassword,
    #[error("the OATH applet has no password set")]
    NoPassword,
    #[error("card failed to prove it holds the OATH key")]
    CardAuthFailed,
    /// The card stayed unreachable after one reconnect and retry.
    #[error("card unavailable: {0}")]
    Unavailable(CardError),
    #[error("card protocol error: {0}")]
    Protocol(ProtoError),
    #[error("internal error running card operation")]
    Internal,
}

/// What the startup check learned about the applet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardInfo {
    pub version: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Codes {
    pub generated_at: u64,
    pub credentials: Vec<Credential>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub issuer: String,
    pub account: String,
    pub state: CredentialState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialState {
    Ok {
        code: String,
        digits: u8,
        period: u32,
        valid_from: u64,
        valid_until: u64,
    },
    TouchRequired,
    Hotp,
}

pub struct Service {
    card: Arc<Mutex<Box<dyn OathCard>>>,
    clock: Arc<dyn Clock>,
    rng: Arc<dyn ChallengeSource>,
}

impl Service {
    pub fn new(
        card: Box<dyn OathCard>,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn ChallengeSource>,
    ) -> Self {
        Self {
            card: Arc::new(Mutex::new(card)),
            clock,
            rng,
        }
    }

    /// SELECT the applet and refuse to continue if it has no password.
    pub async fn startup_check(&self) -> Result<CardInfo, ServiceError> {
        let select = self.run(select).await?;
        if select.auth.is_none() {
            return Err(ServiceError::NoPassword);
        }
        Ok(CardInfo {
            version: select.version,
        })
    }

    /// Whether the card is reachable and still password protected.
    pub async fn health(&self) -> Result<(), ServiceError> {
        self.startup_check().await.map(|_| ())
    }

    /// Check `password` against the card and return the derived key.
    /// The password is wiped when this returns.
    pub async fn unlock(&self, password: Zeroizing<String>) -> Result<DerivedKey, ServiceError> {
        let rng = self.rng.clone();
        self.run(move |tx| {
            open(tx, rng.as_ref(), |device_id| {
                crypto::derive_key(&password, device_id)
            })
        })
        .await?
        .ok_or(ServiceError::NoPassword)
    }

    /// Unlock the card with the session's key and list every credential.
    pub async fn codes(&self, session: &AuthedSession) -> Result<Codes, ServiceError> {
        let now = self.clock.now();
        let rng = self.rng.clone();
        let key = session.key().clone();
        let credentials = self
            .run(move |tx| {
                if open(tx, rng.as_ref(), |_| key.clone())?.is_none() {
                    return Ok(None);
                }
                list(tx, now).map(Some)
            })
            .await?
            .ok_or(ServiceError::NoPassword)?;
        Ok(Codes {
            generated_at: now,
            credentials,
        })
    }

    /// Run `op` in one card transaction on the blocking pool, with at most
    /// one reconnect and retry.
    async fn run<T, F>(&self, op: F) -> Result<T, ServiceError>
    where
        T: Send + 'static,
        F: Fn(&mut dyn CardTransaction) -> Result<T, CardError> + Send + 'static,
    {
        let mut card = self.card.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || with_retry(card.as_mut(), &op))
            .await
            .map_err(|_| ServiceError::Internal)?
    }
}

fn with_retry<T>(
    card: &mut dyn OathCard,
    op: &dyn Fn(&mut dyn CardTransaction) -> Result<T, CardError>,
) -> Result<T, ServiceError> {
    let attempt = |card: &mut dyn OathCard| card.transaction().and_then(|mut tx| op(&mut *tx));
    let result = match attempt(card) {
        Err(e) if e.needs_reconnect() => card.reconnect().and_then(|()| attempt(card)),
        other => other,
    };
    result.map_err(|e| classify(card, e))
}

/// Map the final card error of an operation to a service error.
fn classify(card: &mut dyn OathCard, error: CardError) -> ServiceError {
    match error {
        CardError::Proto(ProtoError::WrongPassword) => ServiceError::WrongPassword,
        CardError::Proto(ProtoError::CardAuthFailed) => {
            // Never keep talking to a card that failed to prove itself.
            let _ = card.reconnect();
            ServiceError::CardAuthFailed
        }
        CardError::Proto(other) => ServiceError::Protocol(other),
        // Only reached after the reconnect and retry in `with_retry`.
        transport => ServiceError::Unavailable(transport),
    }
}

fn select(tx: &mut dyn CardTransaction) -> Result<SelectResponse, CardError> {
    let data = card::send(tx, &proto::select_apdu(), Command::Select)?;
    Ok(proto::parse_select(&data)?)
}

/// SELECT, then VALIDATE with the key `derive` builds from the device ID.
/// `None` if the applet has no password.
fn open(
    tx: &mut dyn CardTransaction,
    rng: &dyn ChallengeSource,
    derive: impl FnOnce(&[u8]) -> DerivedKey,
) -> Result<Option<DerivedKey>, CardError> {
    let selected = select(tx)?;
    let Some(auth) = selected.auth else {
        return Ok(None);
    };
    let key = derive(&selected.device_id);
    let ours = rng.challenge();
    let apdu = proto::validate_apdu(auth.algorithm, key.as_ref(), &auth.challenge, &ours);
    let data = card::send(tx, &apdu, Command::Validate)?;
    proto::verify_validate_response(&data, auth.algorithm, key.as_ref(), &ours)?;
    Ok(Some(key))
}

/// CALCULATE ALL at the 30s timestep, then CALCULATE any credential with a
/// different period at its own timestep.
fn list(tx: &mut dyn CardTransaction, now: u64) -> Result<Vec<Credential>, CardError> {
    let default_step = crypto::timestep(now, proto::DEFAULT_PERIOD);
    let data = card::send(
        tx,
        &proto::calculate_all_apdu(default_step),
        Command::CalculateAll,
    )?;
    let mut out = Vec::new();
    for entry in proto::parse_calculate_all(&data)? {
        let name = proto::parse_name(&entry.name);
        let state = match entry.state {
            EntryState::Hotp => CredentialState::Hotp,
            EntryState::TouchRequired => CredentialState::TouchRequired,
            EntryState::Code(mut code) => {
                if name.period != proto::DEFAULT_PERIOD {
                    let step = crypto::timestep(now, name.period);
                    let apdu = proto::calculate_apdu(&entry.name, step);
                    code = proto::parse_calculate(&card::send(tx, &apdu, Command::Calculate)?)?;
                }
                let (valid_from, valid_until) = crypto::validity_window(now, name.period);
                CredentialState::Ok {
                    code: code.to_code(),
                    digits: code.digits,
                    period: name.period.get(),
                    valid_from,
                    valid_until,
                }
            }
        };
        out.push(Credential {
            issuer: name.issuer,
            account: name.account,
            state,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::mock::{MockCard, MockCredential, MockEvent, MockFault};
    use crate::clock::ManualClock;
    use crate::oath::crypto::{self, Algorithm};
    use crate::rng::SequentialChallengeSource;
    use crate::session::SessionStore;

    const PASSWORD: &str = "correct horse";
    const SHA1_SEED: &[u8] = b"12345678901234567890";
    const SHA256_SEED: &[u8] = b"12345678901234567890123456789012";
    const SHA512_SEED: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    fn rfc_card() -> MockCard {
        MockCard::new()
            .with_password(PASSWORD)
            .with_credential(MockCredential::totp(
                "RFC6238:sha1",
                Algorithm::Sha1,
                8,
                SHA1_SEED,
            ))
            .with_credential(MockCredential::totp(
                "RFC6238:sha256",
                Algorithm::Sha256,
                8,
                SHA256_SEED,
            ))
            .with_credential(MockCredential::totp(
                "RFC6238:sha512",
                Algorithm::Sha512,
                8,
                SHA512_SEED,
            ))
    }

    fn service(card: &MockCard, now: u64) -> Service {
        Service::new(
            Box::new(card.clone()),
            Arc::new(ManualClock::new(now)),
            Arc::new(SequentialChallengeSource::new(0)),
        )
    }

    fn password(p: &str) -> Zeroizing<String> {
        Zeroizing::new(p.to_owned())
    }

    fn key() -> DerivedKey {
        crypto::derive_key(PASSWORD, &MockCard::DEFAULT_DEVICE_ID)
    }

    /// A live session holding `key`.
    fn authed(key: DerivedKey) -> AuthedSession {
        let store = SessionStore::new(
            Arc::new(ManualClock::new(0)),
            Arc::new(SequentialChallengeSource::new(0)),
            300,
            1800,
        );
        let id = store.create(key);
        store.authenticate(id).unwrap()
    }

    fn ok(code: &str, digits: u8, period: u32, from: u64) -> CredentialState {
        CredentialState::Ok {
            code: code.into(),
            digits,
            period,
            valid_from: from,
            valid_until: from + u64::from(period),
        }
    }

    fn count(events: &[MockEvent], wanted: &MockEvent) -> usize {
        events.iter().filter(|e| *e == wanted).count()
    }

    fn calculate_count(events: &[MockEvent]) -> usize {
        events
            .iter()
            .filter(|e| matches!(e, MockEvent::Apdu(apdu) if apdu[1] == 0xA2))
            .count()
    }

    // Startup

    #[tokio::test]
    async fn startup_check_passes_and_reports_version_when_password_set() {
        let card = rfc_card();
        let info = service(&card, 59).startup_check().await.unwrap();
        assert_eq!(info.version, MockCard::DEFAULT_VERSION);
    }

    #[tokio::test]
    async fn startup_check_fails_when_applet_has_no_password() {
        let card = MockCard::new();
        assert_eq!(
            service(&card, 59).startup_check().await,
            Err(ServiceError::NoPassword)
        );
    }

    // Unlock

    #[tokio::test]
    async fn unlock_with_correct_password_returns_derived_key() {
        let card = rfc_card();
        let derived = service(&card, 59).unlock(password(PASSWORD)).await.unwrap();
        assert_eq!(*derived, *key());
    }

    #[tokio::test]
    async fn unlock_with_wrong_password_is_rejected_without_reconnect() {
        let card = rfc_card();
        assert_eq!(
            service(&card, 59).unlock(password("wrong")).await,
            Err(ServiceError::WrongPassword)
        );
        assert_eq!(count(&card.events(), &MockEvent::Reconnect), 0);
    }

    #[tokio::test]
    async fn unlock_refuses_applet_without_password() {
        let card = MockCard::new();
        assert_eq!(
            service(&card, 59).unlock(password("anything")).await,
            Err(ServiceError::NoPassword)
        );
    }

    #[tokio::test]
    async fn unlock_drops_connection_when_card_proof_fails() {
        let card = rfc_card().with_forged_validate_response();
        assert_eq!(
            service(&card, 59).unlock(password(PASSWORD)).await,
            Err(ServiceError::CardAuthFailed)
        );
        assert_eq!(count(&card.events(), &MockEvent::Reconnect), 1);
    }

    // Health

    #[tokio::test]
    async fn health_is_ok_when_card_reachable_and_protected() {
        let card = rfc_card();
        assert_eq!(service(&card, 59).health().await, Ok(()));
    }

    #[tokio::test]
    async fn health_fails_when_card_unreachable() {
        let card = rfc_card();
        card.fail_next(100, MockFault::NoCard);
        assert_eq!(
            service(&card, 59).health().await,
            Err(ServiceError::Unavailable(CardError::NoCard))
        );
    }

    #[tokio::test]
    async fn health_fails_when_applet_unprotected() {
        let card = MockCard::new();
        assert_eq!(
            service(&card, 59).health().await,
            Err(ServiceError::NoPassword)
        );
    }

    // Codes

    #[tokio::test]
    async fn codes_match_rfc6238_for_fixed_clock() {
        let card = rfc_card();
        let codes = service(&card, 59).codes(&authed(key())).await.unwrap();
        assert_eq!(
            codes,
            Codes {
                generated_at: 59,
                credentials: vec![
                    Credential {
                        issuer: "RFC6238".into(),
                        account: "sha1".into(),
                        state: ok("94287082", 8, 30, 30),
                    },
                    Credential {
                        issuer: "RFC6238".into(),
                        account: "sha256".into(),
                        state: ok("46119246", 8, 30, 30),
                    },
                    Credential {
                        issuer: "RFC6238".into(),
                        account: "sha512".into(),
                        state: ok("90693936", 8, 30, 30),
                    },
                ],
            }
        );
    }

    #[tokio::test]
    async fn codes_run_select_validate_calculate_all_in_one_transaction() {
        let card = rfc_card();
        service(&card, 59).codes(&authed(key())).await.unwrap();
        let events = card.events();
        let ins: Vec<u8> = events
            .iter()
            .filter_map(|e| match e {
                MockEvent::Apdu(apdu) => Some(apdu[1]),
                _ => None,
            })
            .collect();
        assert_eq!(ins, [0xA4, 0xA3, 0xA4]);
        assert_eq!(events.first(), Some(&MockEvent::Begin));
        assert_eq!(events.last(), Some(&MockEvent::End));
        assert_eq!(count(&events, &MockEvent::Begin), 1);
    }

    #[tokio::test]
    async fn non_30s_credentials_are_recomputed_with_their_period() {
        let card = MockCard::new()
            .with_password(PASSWORD)
            .with_credential(MockCredential::totp(
                "Slow:a",
                Algorithm::Sha1,
                6,
                SHA1_SEED,
            ))
            .with_credential(MockCredential::totp(
                "60/Slow:b",
                Algorithm::Sha1,
                6,
                SHA1_SEED,
            ));
        let codes = service(&card, 59).codes(&authed(key())).await.unwrap();
        // 30s: timestep 1 (RFC 4226 counter 1 = 287082).
        // 60s: timestep 0 (RFC 4226 counter 0 = 755224).
        assert_eq!(codes.credentials[0].state, ok("287082", 6, 30, 30));
        assert_eq!(codes.credentials[1].issuer, "Slow");
        assert_eq!(codes.credentials[1].account, "b");
        assert_eq!(codes.credentials[1].state, ok("755224", 6, 60, 0));
        assert_eq!(calculate_count(&card.events()), 1);
    }

    #[tokio::test]
    async fn touch_and_hotp_are_listed_without_codes_or_calculate() {
        let card = MockCard::new()
            .with_password(PASSWORD)
            .with_credential(
                MockCredential::totp("T:touch", Algorithm::Sha1, 6, SHA1_SEED).with_touch(),
            )
            .with_credential(
                MockCredential::totp("60/T:slow-touch", Algorithm::Sha1, 6, SHA1_SEED).with_touch(),
            )
            .with_credential(MockCredential::hotp(
                "H:counter",
                Algorithm::Sha1,
                6,
                SHA1_SEED,
            ));
        let codes = service(&card, 59).codes(&authed(key())).await.unwrap();
        let states: Vec<_> = codes.credentials.iter().map(|c| c.state.clone()).collect();
        assert_eq!(
            states,
            [
                CredentialState::TouchRequired,
                CredentialState::TouchRequired,
                CredentialState::Hotp
            ]
        );
        assert_eq!(calculate_count(&card.events()), 0);
    }

    #[tokio::test]
    async fn codes_with_stale_key_is_wrong_password() {
        let card = rfc_card();
        let stale = crypto::derive_key("old password", &MockCard::DEFAULT_DEVICE_ID);
        assert_eq!(
            service(&card, 59).codes(&authed(stale)).await,
            Err(ServiceError::WrongPassword)
        );
    }

    #[tokio::test]
    async fn codes_refuse_applet_whose_password_was_removed() {
        let card = MockCard::new();
        assert_eq!(
            service(&card, 59).codes(&authed(key())).await,
            Err(ServiceError::NoPassword)
        );
    }

    // Reconnect

    #[tokio::test]
    async fn card_removed_once_reconnects_and_retries() {
        let card = rfc_card();
        card.fail_next(1, MockFault::Removed);
        let codes = service(&card, 59).codes(&authed(key())).await.unwrap();
        assert_eq!(codes.credentials.len(), 3);
        let events = card.events();
        assert_eq!(count(&events, &MockEvent::Reconnect), 1);
        assert_eq!(count(&events, &MockEvent::Begin), 2);
    }

    #[tokio::test]
    async fn card_removed_mid_request_reconnects_once_retries_once_then_unavailable() {
        let card = rfc_card();
        card.fail_next(100, MockFault::Removed);
        assert_eq!(
            service(&card, 59).codes(&authed(key())).await,
            Err(ServiceError::Unavailable(CardError::Removed))
        );
        let events = card.events();
        assert_eq!(count(&events, &MockEvent::Reconnect), 1);
        assert_eq!(count(&events, &MockEvent::Begin), 2);
    }

    #[tokio::test]
    async fn reset_during_unlock_is_retried() {
        let card = rfc_card();
        card.fail_next(1, MockFault::Reset);
        assert!(service(&card, 59).unlock(password(PASSWORD)).await.is_ok());
        assert_eq!(count(&card.events(), &MockEvent::Reconnect), 1);
    }

    #[tokio::test]
    async fn wrong_password_on_retry_is_still_wrong_password() {
        let card = rfc_card();
        card.fail_next(1, MockFault::Reset);
        assert_eq!(
            service(&card, 59).unlock(password("wrong")).await,
            Err(ServiceError::WrongPassword)
        );
    }

    #[tokio::test]
    async fn protocol_errors_are_not_retried() {
        let card = rfc_card();
        let stale = crypto::derive_key("nope", &MockCard::DEFAULT_DEVICE_ID);
        assert!(service(&card, 59).codes(&authed(stale)).await.is_err());
        assert_eq!(count(&card.events(), &MockEvent::Reconnect), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_requests_are_serialised() {
        let card = rfc_card();
        let svc = Arc::new(service(&card, 59));
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let svc = svc.clone();
                tokio::spawn(async move { svc.codes(&authed(key())).await })
            })
            .collect();
        for task in tasks {
            task.await.unwrap().unwrap();
        }

        let mut open = false;
        let mut transactions = 0;
        for event in card.events() {
            match event {
                MockEvent::Begin => {
                    assert!(!open, "transaction began inside another");
                    open = true;
                    transactions += 1;
                }
                MockEvent::End => {
                    assert!(open, "transaction ended twice");
                    open = false;
                }
                MockEvent::Apdu(_) => assert!(open, "APDU outside a transaction"),
                MockEvent::Reconnect => panic!("unexpected reconnect"),
            }
        }
        assert_eq!(transactions, 8);
    }
}
