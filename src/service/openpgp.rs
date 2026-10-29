//! OpenPGP card operations: status, public keys, and using the keys on the
//! card with a PIN given per request.
//!
//! Each operation is one card transaction, like the OATH ones, so it never
//! interleaves with them. The PIN is never stored. Before every VERIFY the
//! retry counter is read, and the PIN is not sent when that would leave the
//! card with `pin_retry_floor` or fewer tries, so this service can never
//! block the PIN. Input is checked against the key before VERIFY, so a bad
//! request never costs a try.
//!
//! Keys with a touch policy are refused before VERIFY: nobody is at the
//! server to touch the key. When the card has KDF enabled, the PIN is sent
//! as the card's iterated and salted S2K hash, as gpg does.

use zeroize::Zeroizing;

use super::{Service, ServiceError};
use crate::card::{self, CardError, CardTransaction};
use crate::openpgp::proto::{
    self, Algorithm, ApplicationData, Command, HashAlgorithm, InputError, Kdf, KeySlot, PgpError,
    PublicKey, TouchPolicy,
};

/// Default for `OATH_OPENPGP_PIN_RETRY_FLOOR`: keep the last try for a
/// person at the host.
pub const DEFAULT_PIN_RETRY_FLOOR: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPgpStatus {
    pub version: String,
    pub serial: String,
    pub keys: Vec<KeyStatus>,
    pub pin_retries: PinRetries,
    /// `None` if the card does not report one.
    pub signature_counter: Option<u32>,
    /// Whether the card wants PINs hashed (KDF-DO set).
    pub kdf_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyStatus {
    pub slot: KeySlot,
    pub algorithm: String,
    /// `None` when the slot is empty.
    pub fingerprint: Option<String>,
    pub created: Option<u32>,
    /// `off`, or a touch policy that makes the key unusable here.
    pub touch_policy: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinRetries {
    pub pin: u8,
    pub reset_code: u8,
    pub admin_pin: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyInfo {
    pub slot: KeySlot,
    pub algorithm: String,
    pub fingerprint: String,
    pub key: PublicKey,
}

/// What a PIN-protected operation sends once the PIN is verified.
#[derive(Clone, Copy)]
enum Operation {
    Sign(HashAlgorithm),
    Decrypt,
    Authenticate,
}

impl Operation {
    fn slot(self) -> KeySlot {
        match self {
            Self::Sign(_) => KeySlot::Sign,
            Self::Decrypt => KeySlot::Decrypt,
            Self::Authenticate => KeySlot::Auth,
        }
    }

    fn command(self) -> Command {
        match self {
            Self::Sign(_) => Command::Sign,
            Self::Decrypt => Command::Decipher,
            Self::Authenticate => Command::Authenticate,
        }
    }

    /// Card input for `data`, checked against the key's algorithm.
    fn input(self, algorithm: &Algorithm, data: &[u8]) -> Result<Vec<u8>, InputError> {
        match self {
            Self::Sign(hash) => proto::signature_input(algorithm, hash, data),
            Self::Decrypt => proto::decipher_input(algorithm, data),
            Self::Authenticate if data.is_empty() => Err(InputError::Empty),
            Self::Authenticate => Ok(data.to_vec()),
        }
    }

    fn apdus(self, input: &[u8]) -> Vec<Vec<u8>> {
        match self {
            Self::Sign(_) => proto::sign_apdus(input),
            Self::Decrypt => proto::decipher_apdus(input),
            Self::Authenticate => proto::authenticate_apdus(input),
        }
    }
}

/// An operation's result, or why the service refused it without a card
/// error. Kept apart from [`CardError`] so refusals are not retried.
type Outcome<T> = Result<T, ServiceError>;

impl Service {
    /// Applet version, serial, keys, PIN retry counters, and signature count.
    pub async fn openpgp_status(&self) -> Result<OpenPgpStatus, ServiceError> {
        self.run(|tx| {
            let data = open(tx)?;
            let mut keys = Vec::with_capacity(data.keys.len());
            for key in &data.keys {
                keys.push(KeyStatus {
                    slot: key.slot,
                    algorithm: key.algorithm.name(),
                    fingerprint: key.fingerprint.as_ref().map(proto::fingerprint_hex),
                    created: key.created,
                    touch_policy: touch_policy(tx, key.slot)?.name(),
                });
            }
            let kdf_enabled = kdf(tx, &data)? != Kdf::None;
            let counter = card::send_openpgp(
                tx,
                &[proto::get_data_apdu(proto::DO_SECURITY_SUPPORT)],
                Command::GetData,
            )
            .and_then(|raw| Ok(proto::parse_signature_counter(&raw)?));
            let signature_counter = match counter {
                Ok(counter) => Some(counter),
                Err(CardError::OpenPgp(_)) => None,
                Err(transport) => return Err(transport),
            };
            Ok(OpenPgpStatus {
                version: data.version(),
                serial: data.serial(),
                keys,
                pin_retries: PinRetries {
                    pin: data.pw_status.pw1_retries,
                    reset_code: data.pw_status.rc_retries,
                    admin_pin: data.pw_status.pw3_retries,
                },
                signature_counter,
                kdf_enabled,
            })
        })
        .await
    }

    /// The public key in `slot`.
    pub async fn openpgp_public_key(&self, slot: KeySlot) -> Result<PublicKeyInfo, ServiceError> {
        self.run(move |tx| {
            let data = open(tx)?;
            let key = data.key(slot);
            let Some(fingerprint) = key.fingerprint else {
                return Ok(Err(ServiceError::NoKey(slot)));
            };
            let raw = card::send_openpgp(
                tx,
                &[proto::read_public_key_apdu(slot)],
                Command::ReadPublicKey,
            )?;
            Ok(Ok(PublicKeyInfo {
                slot,
                algorithm: key.algorithm.name(),
                fingerprint: proto::fingerprint_hex(&fingerprint),
                key: proto::parse_public_key(&raw)?,
            }))
        })
        .await?
    }

    /// Sign `digest`, made with `hash`, with the signing key.
    pub async fn openpgp_sign(
        &self,
        pin: Zeroizing<String>,
        hash: HashAlgorithm,
        digest: Vec<u8>,
    ) -> Result<Vec<u8>, ServiceError> {
        self.with_pin(pin, Operation::Sign(hash), digest)
            .await
            .map(|out| out.to_vec())
    }

    /// Decrypt with the decryption key. For RSA keys `ciphertext` is the
    /// RSA ciphertext; for ECDH keys it is the sender's ephemeral public
    /// point. The result is the session key, wiped when dropped.
    pub async fn openpgp_decrypt(
        &self,
        pin: Zeroizing<String>,
        ciphertext: Vec<u8>,
    ) -> Result<Zeroizing<Vec<u8>>, ServiceError> {
        self.with_pin(pin, Operation::Decrypt, ciphertext).await
    }

    /// Sign `data` as is with the authentication key (INTERNAL
    /// AUTHENTICATE). For RSA keys the caller supplies the DigestInfo.
    pub async fn openpgp_authenticate(
        &self,
        pin: Zeroizing<String>,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, ServiceError> {
        self.with_pin(pin, Operation::Authenticate, data)
            .await
            .map(|out| out.to_vec())
    }

    async fn with_pin(
        &self,
        pin: Zeroizing<String>,
        operation: Operation,
        data: Vec<u8>,
    ) -> Result<Zeroizing<Vec<u8>>, ServiceError> {
        let floor = self.pin_retry_floor;
        self.run(move |tx| run_with_pin(tx, floor, pin.as_bytes(), operation, &data))
            .await?
    }
}

/// SELECT the applet and read its application related data.
fn open(tx: &mut dyn CardTransaction) -> Result<ApplicationData, CardError> {
    card::send_openpgp(tx, &[proto::select_apdu()], Command::Select)?;
    let raw = card::send_openpgp(
        tx,
        &[proto::get_data_apdu(proto::DO_APPLICATION_DATA)],
        Command::GetData,
    )?;
    Ok(proto::parse_application_data(&raw)?)
}

/// The touch policy of the key in `slot`. Cards without touch policies
/// (no user interaction flag DO) never wait for a touch.
fn touch_policy(tx: &mut dyn CardTransaction, slot: KeySlot) -> Result<TouchPolicy, CardError> {
    match card::send_openpgp(
        tx,
        &[proto::get_data_apdu(slot.uif_tag())],
        Command::GetData,
    ) {
        Ok(raw) => Ok(proto::parse_uif(&raw)?),
        Err(CardError::OpenPgp(PgpError::NotFound | PgpError::Status(_))) => Ok(TouchPolicy::Off),
        Err(other) => Err(other),
    }
}

/// How the card wants the PIN sent. Only cards that advertise a KDF-DO are
/// asked; if one of those cannot say, the operation fails rather than risk
/// sending the PIN in the wrong form.
fn kdf(tx: &mut dyn CardTransaction, app: &ApplicationData) -> Result<Kdf, CardError> {
    if !app.kdf_supported {
        return Ok(Kdf::None);
    }
    let raw = card::send_openpgp(tx, &[proto::get_data_apdu(proto::DO_KDF)], Command::GetData)?;
    Ok(proto::parse_kdf(&raw)?)
}

fn pw1_retries(tx: &mut dyn CardTransaction) -> Result<u8, CardError> {
    let raw = card::send_openpgp(
        tx,
        &[proto::get_data_apdu(proto::DO_PW_STATUS)],
        Command::GetData,
    )?;
    Ok(proto::parse_pw_status(&raw)?.pw1_retries)
}

fn run_with_pin(
    tx: &mut dyn CardTransaction,
    floor: u8,
    pin: &[u8],
    operation: Operation,
    data: &[u8],
) -> Result<Outcome<Zeroizing<Vec<u8>>>, CardError> {
    let slot = operation.slot();
    let app = open(tx)?;
    let key = app.key(slot);
    if key.fingerprint.is_none() {
        return Ok(Err(ServiceError::NoKey(slot)));
    }
    if touch_policy(tx, slot)?.requires_touch() {
        return Ok(Err(ServiceError::TouchRequired(slot)));
    }
    let input = match operation.input(&key.algorithm, data) {
        Ok(input) => input,
        Err(e) => return Ok(Err(ServiceError::BadInput(e))),
    };
    let kdf = kdf(tx, &app)?;
    if matches!(kdf, Kdf::Unsupported { .. }) {
        return Ok(Err(ServiceError::KdfUnsupported));
    }
    if pin.len() < proto::PW1_MIN_LEN {
        return Ok(Err(ServiceError::BadPin));
    }
    let pin = proto::kdf_pin(&kdf, pin);
    if pin.len() > usize::from(app.pw_status.pw1_max_len) {
        return Ok(Err(ServiceError::BadPin));
    }
    let retries = app.pw_status.pw1_retries;
    if retries <= floor {
        return Ok(Err(ServiceError::PinRetryFloor {
            retries_left: retries,
        }));
    }
    let verify = proto::verify_apdu(slot, &pin);
    match card::send_openpgp(tx, &[verify.as_slice()], Command::Verify) {
        Ok(_) => {}
        Err(CardError::OpenPgp(PgpError::WrongPin)) => {
            return Ok(Err(ServiceError::WrongPin {
                retries_left: pw1_retries(tx)?,
            }));
        }
        Err(CardError::OpenPgp(PgpError::PinBlocked)) => {
            return Ok(Err(ServiceError::PinRetryFloor { retries_left: 0 }));
        }
        Err(other) => return Err(other),
    }
    let output = card::send_openpgp(tx, &operation.apdus(&input), operation.command())?;
    Ok(Ok(Zeroizing::new(output)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::mock::openpgp::{MockKey, MockOpenPgp};
    use crate::card::mock::{MockCard, MockEvent, MockFault};
    use crate::clock::ManualClock;
    use crate::rng::SequentialChallengeSource;
    use std::sync::Arc;

    const PIN: &str = "123456";
    const DIGEST: [u8; 32] = [0x42; 32];

    fn card() -> MockCard {
        MockCard::new().with_password("oath").with_openpgp(
            MockOpenPgp::new(PIN)
                .with_key(KeySlot::Sign, MockKey::rsa2048(b"sig"))
                .with_key(KeySlot::Decrypt, MockKey::rsa2048(b"dec"))
                .with_key(KeySlot::Auth, MockKey::ed25519(b"aut")),
        )
    }

    fn service(card: &MockCard) -> Service {
        Service::new(
            Box::new(card.clone()),
            Arc::new(ManualClock::new(0)),
            Arc::new(SequentialChallengeSource::new(0)),
        )
    }

    fn pin(p: &str) -> Zeroizing<String> {
        Zeroizing::new(p.to_owned())
    }

    fn verifies(events: &[MockEvent]) -> usize {
        events
            .iter()
            .filter(|e| matches!(e, MockEvent::Apdu(a) if a[1] == 0x20))
            .count()
    }

    fn sha256_digest_info(digest: &[u8]) -> Vec<u8> {
        proto::signature_input(
            &Algorithm::Rsa { bits: 2048 },
            HashAlgorithm::Sha256,
            digest,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn status_reports_keys_retries_and_counter() {
        let card = card();
        let status = service(&card).openpgp_status().await.unwrap();
        assert_eq!(status.version, "3.4");
        assert_eq!(status.serial, "12345678");
        assert_eq!(
            status.pin_retries,
            PinRetries {
                pin: 3,
                reset_code: 0,
                admin_pin: 3
            }
        );
        assert_eq!(status.signature_counter, Some(0));
        assert_eq!(status.keys.len(), 3);
        assert_eq!(status.keys[0].slot, KeySlot::Sign);
        assert_eq!(status.keys[0].algorithm, "rsa2048");
        assert_eq!(
            status.keys[0].fingerprint,
            Some(proto::fingerprint_hex(
                &MockKey::rsa2048(b"sig").fingerprint()
            ))
        );
        assert_eq!(status.keys[2].algorithm, "ed25519");
        assert_eq!(verifies(&card.events()), 0, "status never sends a PIN");
    }

    #[tokio::test]
    async fn status_without_applet_is_unavailable() {
        let card = MockCard::new().with_password("oath");
        assert_eq!(
            service(&card).openpgp_status().await,
            Err(ServiceError::OpenPgpUnavailable)
        );
    }

    #[tokio::test]
    async fn public_key_is_read_for_a_slot_with_a_key() {
        let card = card();
        let info = service(&card)
            .openpgp_public_key(KeySlot::Sign)
            .await
            .unwrap();
        assert_eq!(info.algorithm, "rsa2048");
        assert_eq!(
            info.key,
            PublicKey::Rsa {
                modulus: MockKey::rsa2048(b"sig").public_value(),
                exponent: vec![1, 0, 1],
            }
        );
    }

    #[tokio::test]
    async fn public_key_of_empty_slot_is_no_key() {
        let card = MockCard::new().with_openpgp(MockOpenPgp::new(PIN));
        assert_eq!(
            service(&card).openpgp_public_key(KeySlot::Auth).await,
            Err(ServiceError::NoKey(KeySlot::Auth))
        );
    }

    #[tokio::test]
    async fn sign_with_right_pin_returns_the_card_signature() {
        let card = card();
        let signature = service(&card)
            .openpgp_sign(pin(PIN), HashAlgorithm::Sha256, DIGEST.to_vec())
            .await
            .unwrap();
        assert_eq!(
            signature,
            MockKey::rsa2048(b"sig").signature(&sha256_digest_info(&DIGEST))
        );
        assert_eq!(card.openpgp(MockOpenPgp::signature_counter), 1);
    }

    #[tokio::test]
    async fn wrong_pin_reports_retries_left() {
        let card = card();
        assert_eq!(
            service(&card)
                .openpgp_sign(pin("000000"), HashAlgorithm::Sha256, DIGEST.to_vec())
                .await,
            Err(ServiceError::WrongPin { retries_left: 2 })
        );
    }

    #[tokio::test]
    async fn wrong_pin_answered_with_6982_still_reports_retries_left() {
        let card = MockCard::new().with_openpgp(
            MockOpenPgp::new(PIN)
                .with_wrong_pin_status_6982()
                .with_key(KeySlot::Sign, MockKey::rsa2048(b"sig")),
        );
        assert_eq!(
            service(&card)
                .openpgp_sign(pin("000000"), HashAlgorithm::Sha256, DIGEST.to_vec())
                .await,
            Err(ServiceError::WrongPin { retries_left: 2 })
        );
    }

    #[tokio::test]
    async fn the_floor_keeps_the_last_try() {
        let card = card();
        let service = service(&card);
        let wrong = || service.openpgp_sign(pin("000000"), HashAlgorithm::Sha256, DIGEST.to_vec());
        assert_eq!(
            wrong().await,
            Err(ServiceError::WrongPin { retries_left: 2 })
        );
        assert_eq!(
            wrong().await,
            Err(ServiceError::WrongPin { retries_left: 1 })
        );
        card.clear_events();
        assert_eq!(
            wrong().await,
            Err(ServiceError::PinRetryFloor { retries_left: 1 })
        );
        // Even the right PIN is not sent at the floor.
        assert_eq!(
            service
                .openpgp_sign(pin(PIN), HashAlgorithm::Sha256, DIGEST.to_vec())
                .await,
            Err(ServiceError::PinRetryFloor { retries_left: 1 })
        );
        assert_eq!(verifies(&card.events()), 0);
        assert_eq!(card.openpgp(MockOpenPgp::pin_retries), 1);
    }

    #[tokio::test]
    async fn floor_can_be_lowered_to_zero_and_the_card_still_never_blocks_through_us() {
        let card = card();
        let service = service(&card).with_pin_retry_floor(0);
        for left in [2, 1, 0] {
            assert_eq!(
                service
                    .openpgp_sign(pin("000000"), HashAlgorithm::Sha256, DIGEST.to_vec())
                    .await,
                Err(ServiceError::WrongPin { retries_left: left })
            );
        }
        assert_eq!(
            service
                .openpgp_sign(pin(PIN), HashAlgorithm::Sha256, DIGEST.to_vec())
                .await,
            Err(ServiceError::PinRetryFloor { retries_left: 0 })
        );
    }

    #[tokio::test]
    async fn blocked_pin_is_refused_even_with_floor_zero() {
        let card = MockCard::new().with_openpgp(
            MockOpenPgp::new(PIN)
                .with_pin_retries(0)
                .with_key(KeySlot::Auth, MockKey::ed25519(b"a")),
        );
        let service = service(&card).with_pin_retry_floor(0);
        assert_eq!(
            service.openpgp_authenticate(pin(PIN), b"x".to_vec()).await,
            Err(ServiceError::PinRetryFloor { retries_left: 0 })
        );
    }

    #[tokio::test]
    async fn right_pin_resets_the_counter() {
        let card = card();
        let service = service(&card);
        service
            .openpgp_sign(pin("000000"), HashAlgorithm::Sha256, DIGEST.to_vec())
            .await
            .unwrap_err();
        service
            .openpgp_sign(pin(PIN), HashAlgorithm::Sha256, DIGEST.to_vec())
            .await
            .unwrap();
        assert_eq!(card.openpgp(MockOpenPgp::pin_retries), 3);
    }

    #[tokio::test]
    async fn bad_requests_never_spend_a_pin_try() {
        let card = MockCard::new()
            .with_openpgp(MockOpenPgp::new(PIN).with_key(KeySlot::Sign, MockKey::rsa2048(b"sig")));
        let service = service(&card);
        assert_eq!(
            service
                .openpgp_sign(pin(PIN), HashAlgorithm::Sha256, vec![0; 20])
                .await,
            Err(ServiceError::BadInput(InputError::DigestLength))
        );
        assert_eq!(
            service.openpgp_decrypt(pin(PIN), vec![1]).await,
            Err(ServiceError::NoKey(KeySlot::Decrypt))
        );
        assert_eq!(
            service
                .openpgp_sign(pin("12345"), HashAlgorithm::Sha256, DIGEST.to_vec())
                .await,
            Err(ServiceError::BadPin)
        );
        assert_eq!(
            service
                .openpgp_sign(
                    pin(&"1".repeat(128)),
                    HashAlgorithm::Sha256,
                    DIGEST.to_vec()
                )
                .await,
            Err(ServiceError::BadPin)
        );
        assert_eq!(verifies(&card.events()), 0);
        assert_eq!(card.openpgp(MockOpenPgp::pin_retries), 3);
    }

    #[tokio::test]
    async fn decrypt_returns_the_session_key() {
        let card = card();
        let ciphertext = vec![0x5A; 256];
        let plaintext = service(&card)
            .openpgp_decrypt(pin(PIN), ciphertext.clone())
            .await
            .unwrap();
        let mut input = vec![0x00];
        input.extend_from_slice(&ciphertext);
        assert_eq!(*plaintext, MockKey::rsa2048(b"dec").plaintext(&input));
    }

    #[tokio::test]
    async fn decrypt_of_nothing_is_bad_input() {
        let card = card();
        assert_eq!(
            service(&card).openpgp_decrypt(pin(PIN), Vec::new()).await,
            Err(ServiceError::BadInput(InputError::Empty))
        );
    }

    #[tokio::test]
    async fn authenticate_signs_the_data_as_is() {
        let card = card();
        let service = service(&card);
        assert_eq!(
            service
                .openpgp_authenticate(pin(PIN), b"challenge".to_vec())
                .await,
            Ok(MockKey::ed25519(b"aut").signature(b"challenge"))
        );
        assert_eq!(
            service.openpgp_authenticate(pin(PIN), Vec::new()).await,
            Err(ServiceError::BadInput(InputError::Empty))
        );
    }

    #[tokio::test]
    async fn ecdsa_sign_rejects_an_ecdh_only_key_type() {
        let card = MockCard::new()
            .with_openpgp(MockOpenPgp::new(PIN).with_key(KeySlot::Sign, MockKey::cv25519(b"x")));
        assert_eq!(
            service(&card)
                .openpgp_sign(pin(PIN), HashAlgorithm::Sha256, DIGEST.to_vec())
                .await,
            Err(ServiceError::BadInput(InputError::UnsupportedAlgorithm))
        );
    }

    #[tokio::test]
    async fn sign_survives_one_card_reset_and_rechecks_the_floor() {
        let card = card();
        card.fail_next(1, MockFault::Reset);
        let signature = service(&card)
            .openpgp_sign(pin(PIN), HashAlgorithm::Sha256, DIGEST.to_vec())
            .await
            .unwrap();
        assert_eq!(signature.len(), 256);
        assert_eq!(
            card.events()
                .iter()
                .filter(|e| **e == MockEvent::Reconnect)
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn card_that_stays_gone_is_unavailable() {
        let card = card();
        card.fail_next(10, MockFault::Removed);
        assert_eq!(
            service(&card).openpgp_status().await,
            Err(ServiceError::Unavailable(CardError::Removed))
        );
    }

    fn s2k() -> Kdf {
        Kdf::IterSaltedS2k {
            hash: proto::KdfHash::Sha256,
            count: 65_536,
            pw1_salt: vec![0x5A; 8],
        }
    }

    #[tokio::test]
    async fn kdf_card_gets_the_hashed_pin() {
        let card = MockCard::new().with_openpgp(
            MockOpenPgp::new(PIN)
                .with_kdf(s2k())
                .with_key(KeySlot::Sign, MockKey::rsa2048(b"sig")),
        );
        let service = service(&card);
        assert!(service.openpgp_status().await.unwrap().kdf_enabled);
        service
            .openpgp_sign(pin(PIN), HashAlgorithm::Sha256, DIGEST.to_vec())
            .await
            .unwrap();
        assert_eq!(card.openpgp(MockOpenPgp::pin_retries), 3);
        let sent_hashed = card.events().iter().any(|e| {
            matches!(e, MockEvent::Apdu(a)
                if a[1] == 0x20 && a[5..] == *proto::kdf_pin(&s2k(), PIN.as_bytes()))
        });
        assert!(sent_hashed, "VERIFY carried the S2K hash");
    }

    #[tokio::test]
    async fn kdf_card_still_counts_a_wrong_pin() {
        let card = MockCard::new().with_openpgp(
            MockOpenPgp::new(PIN)
                .with_kdf(s2k())
                .with_key(KeySlot::Sign, MockKey::rsa2048(b"sig")),
        );
        assert_eq!(
            service(&card)
                .openpgp_sign(pin("000000"), HashAlgorithm::Sha256, DIGEST.to_vec())
                .await,
            Err(ServiceError::WrongPin { retries_left: 2 })
        );
    }

    #[tokio::test]
    async fn unsupported_kdf_never_sends_the_pin() {
        let card = MockCard::new().with_openpgp(
            MockOpenPgp::new(PIN)
                .with_kdf(Kdf::Unsupported {
                    algorithm: 3,
                    hash: Some(2),
                })
                .with_key(KeySlot::Sign, MockKey::rsa2048(b"sig")),
        );
        assert_eq!(
            service(&card)
                .openpgp_sign(pin(PIN), HashAlgorithm::Sha256, DIGEST.to_vec())
                .await,
            Err(ServiceError::KdfUnsupported)
        );
        assert_eq!(verifies(&card.events()), 0);
    }

    #[tokio::test]
    async fn version_2_card_is_never_asked_for_a_kdf() {
        let card = MockCard::new().with_openpgp(
            MockOpenPgp::new(PIN)
                .without_kdf_do()
                .without_uif()
                .with_key(KeySlot::Sign, MockKey::rsa2048(b"sig")),
        );
        let service = service(&card);
        let status = service.openpgp_status().await.unwrap();
        assert!(!status.kdf_enabled);
        assert!(status.keys.iter().all(|k| k.touch_policy == "off"));
        service
            .openpgp_sign(pin(PIN), HashAlgorithm::Sha256, DIGEST.to_vec())
            .await
            .unwrap();
        let asked_for_kdf = card
            .events()
            .iter()
            .any(|e| matches!(e, MockEvent::Apdu(a) if a[..4] == [0x00, 0xCA, 0x00, 0xF9]));
        assert!(!asked_for_kdf);
    }

    #[tokio::test]
    async fn touch_keys_are_refused_before_the_pin_is_sent() {
        let card = MockCard::new().with_openpgp(
            MockOpenPgp::new(PIN)
                .with_key(KeySlot::Sign, MockKey::rsa2048(b"sig"))
                .with_key(KeySlot::Decrypt, MockKey::rsa2048(b"dec"))
                .with_key(KeySlot::Auth, MockKey::ed25519(b"aut"))
                .with_touch(KeySlot::Sign, 0x03)
                .with_touch(KeySlot::Decrypt, 0x01)
                .with_touch(KeySlot::Auth, 0x02),
        );
        let service = service(&card);
        let status = service.openpgp_status().await.unwrap();
        let policies: Vec<&str> = status
            .keys
            .iter()
            .map(|k| k.touch_policy.as_str())
            .collect();
        assert_eq!(policies, ["cached", "on", "fixed"]);
        assert_eq!(
            service
                .openpgp_sign(pin(PIN), HashAlgorithm::Sha256, DIGEST.to_vec())
                .await,
            Err(ServiceError::TouchRequired(KeySlot::Sign))
        );
        assert_eq!(
            service.openpgp_decrypt(pin(PIN), vec![1; 256]).await,
            Err(ServiceError::TouchRequired(KeySlot::Decrypt))
        );
        assert_eq!(
            service.openpgp_authenticate(pin(PIN), b"x".to_vec()).await,
            Err(ServiceError::TouchRequired(KeySlot::Auth))
        );
        assert_eq!(verifies(&card.events()), 0);
        // Public keys never need a touch.
        service.openpgp_public_key(KeySlot::Sign).await.unwrap();
    }

    #[tokio::test]
    async fn touch_on_another_slot_does_not_matter() {
        let card = MockCard::new().with_openpgp(
            MockOpenPgp::new(PIN)
                .with_key(KeySlot::Sign, MockKey::rsa2048(b"sig"))
                .with_touch(KeySlot::Decrypt, 0x01),
        );
        service(&card)
            .openpgp_sign(pin(PIN), HashAlgorithm::Sha256, DIGEST.to_vec())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn openpgp_and_oath_share_the_card() {
        let card = card();
        let service = service(&card);
        service.openpgp_status().await.unwrap();
        service.startup_check().await.unwrap();
        service
            .openpgp_sign(pin(PIN), HashAlgorithm::Sha256, DIGEST.to_vec())
            .await
            .unwrap();
    }
}
