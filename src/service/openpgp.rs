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
use crate::openpgp::encrypted::{self, DataFormat, DecryptError};
use crate::openpgp::message::{self, Format, SignatureBuilder};
use crate::openpgp::proto::{
    self, ApplicationData, Command, HashAlgorithm, InputError, Kdf, KeyInfo, KeySlot, PgpError,
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

/// The session key of an encrypted message, recovered with the card.
#[derive(Clone, PartialEq, Eq)]
pub struct MessageSessionKey {
    /// `algorithm:HEX`, for `gpg --override-session-key` and
    /// `sq decrypt --session-key`. Wiped when dropped.
    pub session_key: Zeroizing<String>,
    pub cipher: &'static str,
    /// The key ID the message names for this key.
    pub key_id: String,
    pub data_format: DataFormat,
}

impl std::fmt::Debug for MessageSessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageSessionKey")
            .field("cipher", &self.cipher)
            .field("key_id", &self.key_id)
            .field("data_format", &self.data_format)
            .finish_non_exhaustive()
    }
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
    /// An OpenPGP signature over prepared signed bytes
    /// ([`message::signed_data`]), made at Unix time `created`. The card
    /// signs the signature packet's digest.
    Message {
        hash: HashAlgorithm,
        format: Format,
        created: u32,
    },
    /// PSO: DECIPHER of a message's encrypted session key.
    Decrypt,
}

impl Operation {
    fn slot(self) -> KeySlot {
        match self {
            Self::Message { .. } => KeySlot::Sign,
            Self::Decrypt => KeySlot::Decrypt,
        }
    }

    fn command(self) -> Command {
        match self {
            Self::Message { .. } => Command::Sign,
            Self::Decrypt => Command::Decipher,
        }
    }

    /// Card input for `data`, checked against the key.
    fn input(self, key: &KeyInfo, data: &[u8]) -> Result<Vec<u8>, InputError> {
        let algorithm = &key.algorithm;
        match self {
            Self::Message {
                hash,
                format,
                created,
            } => {
                let digest = SignatureBuilder::new(key, hash, format, created)?.digest(data);
                proto::signature_input(algorithm, hash, &digest)
            }
            Self::Decrypt => proto::decipher_input(algorithm, data),
        }
    }

    fn apdus(self, input: &[u8]) -> Vec<Vec<u8>> {
        match self {
            Self::Message { .. } => proto::sign_apdus(input),
            Self::Decrypt => proto::decipher_apdus(input),
        }
    }
}

/// An operation's result, or why the service refused it without a card
/// error. Kept apart from [`CardError`] so refusals are not retried.
type Outcome<T> = Result<T, ServiceError>;

/// What the card returned for a PIN-protected operation, wiped when
/// dropped, and the key that produced it.
type CardOutput = (Zeroizing<Vec<u8>>, KeyInfo);

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

    /// Sign `text` with the signing key as an OpenPGP message: a cleartext
    /// signed message, or an armored detached signature over its exact
    /// bytes. Timestamped with the service clock.
    pub async fn openpgp_sign_message(
        &self,
        pin: Zeroizing<String>,
        hash: HashAlgorithm,
        format: Format,
        text: String,
    ) -> Result<String, ServiceError> {
        if text.is_empty() {
            return Err(ServiceError::BadInput(InputError::Empty));
        }
        let created = u32::try_from(self.clock.now()).unwrap_or(u32::MAX);
        let data = message::signed_data(format, &text);
        let operation = Operation::Message {
            hash,
            format,
            created,
        };
        let (signature, key) = self.with_pin(pin, operation, data.clone()).await?;
        // The same builder inputs as inside the transaction, so the same
        // digest the card signed.
        let builder =
            SignatureBuilder::new(&key, hash, format, created).map_err(ServiceError::BadInput)?;
        let packet = builder
            .packet(&builder.digest(&data), &signature)
            .map_err(ServiceError::OpenPgpProtocol)?;
        Ok(message::render(format, &text, hash, &packet))
    }

    /// Recover the session key of an armored OpenPGP message encrypted to
    /// the card's decryption key. The message is not decrypted; the
    /// caller's gpg or sq does that with the session key.
    pub async fn openpgp_decrypt_message(
        &self,
        pin: Zeroizing<String>,
        armored: &str,
    ) -> Result<MessageSessionKey, ServiceError> {
        // Everything that can fail without the PIN fails first.
        let message = encrypted::dearmor(armored)
            .and_then(|data| encrypted::parse_message(&data))
            .map_err(ServiceError::Decrypt)?;
        let key = self
            .run(|tx| Ok(open(tx)?.key(KeySlot::Decrypt).clone()))
            .await?;
        if key.fingerprint.is_none() {
            return Err(ServiceError::NoKey(KeySlot::Decrypt));
        }
        let pkesk = encrypted::select(&message, &key).map_err(ServiceError::Decrypt)?;
        let input = encrypted::card_input(pkesk, &key).map_err(ServiceError::Decrypt)?;
        let (output, used) = self.with_pin(pin, Operation::Decrypt, input).await?;
        if used.fingerprint != key.fingerprint {
            // The card changed between the two transactions.
            return Err(ServiceError::Decrypt(DecryptError::Recovery));
        }
        let session =
            encrypted::session_key(pkesk, &used, &output).map_err(ServiceError::Decrypt)?;
        Ok(MessageSessionKey {
            session_key: session.tool_form(),
            cipher: session.cipher_name(),
            key_id: pkesk.key_id.iter().map(|b| format!("{b:02X}")).collect(),
            data_format: message.data_format,
        })
    }

    async fn with_pin(
        &self,
        pin: Zeroizing<String>,
        operation: Operation,
        data: Vec<u8>,
    ) -> Result<CardOutput, ServiceError> {
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

/// Check everything that can fail without the PIN, then VERIFY and run
/// `operation`. Returns the card output and the key that produced it.
fn run_with_pin(
    tx: &mut dyn CardTransaction,
    floor: u8,
    pin: &[u8],
    operation: Operation,
    data: &[u8],
) -> Result<Outcome<CardOutput>, CardError> {
    let slot = operation.slot();
    let app = open(tx)?;
    let key = app.key(slot);
    if key.fingerprint.is_none() {
        return Ok(Err(ServiceError::NoKey(slot)));
    }
    if touch_policy(tx, slot)?.requires_touch() {
        return Ok(Err(ServiceError::TouchRequired(slot)));
    }
    let input = match operation.input(key, data) {
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
    Ok(Ok((Zeroizing::new(output), key.clone())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::mock::openpgp::{MockKey, MockOpenPgp};
    use crate::card::mock::{MockCard, MockEvent, MockFault};
    use crate::clock::ManualClock;
    use crate::openpgp::encrypted::fixtures;
    use crate::rng::SequentialChallengeSource;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use std::sync::Arc;

    const PIN: &str = "123456";

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

    /// Clearsign "hello": the PIN-protected path the API offers for signing.
    async fn sign(service: &Service, pin_text: &str) -> Result<String, ServiceError> {
        service
            .openpgp_sign_message(
                pin(pin_text),
                HashAlgorithm::Sha256,
                Format::Clearsign,
                "hello".into(),
            )
            .await
    }

    fn verifies(events: &[MockEvent]) -> usize {
        events
            .iter()
            .filter(|e| matches!(e, MockEvent::Apdu(a) if a[1] == 0x20))
            .count()
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
    async fn wrong_pin_reports_retries_left() {
        let card = card();
        assert_eq!(
            sign(&service(&card), "000000").await,
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
            sign(&service(&card), "000000").await,
            Err(ServiceError::WrongPin { retries_left: 2 })
        );
    }

    #[tokio::test]
    async fn the_floor_keeps_the_last_try() {
        let card = card();
        let service = service(&card);
        let wrong = || sign(&service, "000000");
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
            sign(&service, PIN).await,
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
                sign(&service, "000000").await,
                Err(ServiceError::WrongPin { retries_left: left })
            );
        }
        assert_eq!(
            sign(&service, PIN).await,
            Err(ServiceError::PinRetryFloor { retries_left: 0 })
        );
    }

    #[tokio::test]
    async fn blocked_pin_is_refused_even_with_floor_zero() {
        let card = MockCard::new().with_openpgp(
            MockOpenPgp::new(PIN)
                .with_pin_retries(0)
                .with_key(KeySlot::Sign, MockKey::ed25519(b"a")),
        );
        let service = service(&card).with_pin_retry_floor(0);
        assert_eq!(
            sign(&service, PIN).await,
            Err(ServiceError::PinRetryFloor { retries_left: 0 })
        );
    }

    #[tokio::test]
    async fn right_pin_resets_the_counter() {
        let card = card();
        let service = service(&card);
        sign(&service, "000000").await.unwrap_err();
        sign(&service, PIN).await.unwrap();
        assert_eq!(card.openpgp(MockOpenPgp::pin_retries), 3);
    }

    #[tokio::test]
    async fn bad_requests_never_spend_a_pin_try() {
        let card = MockCard::new()
            .with_openpgp(MockOpenPgp::new(PIN).with_key(KeySlot::Sign, MockKey::rsa2048(b"sig")));
        let service = service(&card);
        assert_eq!(
            service
                .openpgp_sign_message(
                    pin(PIN),
                    HashAlgorithm::Sha256,
                    Format::Clearsign,
                    String::new()
                )
                .await,
            Err(ServiceError::BadInput(InputError::Empty))
        );
        assert_eq!(sign(&service, "12345").await, Err(ServiceError::BadPin));
        assert_eq!(
            sign(&service, &"1".repeat(128)).await,
            Err(ServiceError::BadPin)
        );
        assert_eq!(verifies(&card.events()), 0);
        assert_eq!(card.openpgp(MockOpenPgp::pin_retries), 3);
    }

    #[tokio::test]
    async fn sign_survives_one_card_reset_and_rechecks_the_floor() {
        let card = card();
        card.fail_next(1, MockFault::Reset);
        let armored = sign(&service(&card), PIN).await.unwrap();
        assert!(armored.starts_with("-----BEGIN PGP SIGNED MESSAGE-----"));
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
        sign(&service, PIN).await.unwrap();
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
            sign(&service(&card), "000000").await,
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
            sign(&service(&card), PIN).await,
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
        sign(&service, PIN).await.unwrap();
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
                .with_key(
                    KeySlot::Decrypt,
                    MockKey::rsa2048(b"dec").with_fingerprint(fixtures::RSA_FPR),
                )
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
            sign(&service, PIN).await,
            Err(ServiceError::TouchRequired(KeySlot::Sign))
        );
        assert_eq!(
            service
                .openpgp_decrypt_message(pin(PIN), fixtures::RSA_SQ_MESSAGE)
                .await,
            Err(ServiceError::TouchRequired(KeySlot::Decrypt))
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
        sign(&service(&card), PIN).await.unwrap();
    }

    /// The packet inside an armored signature.
    fn armored_packet(armored: &str) -> Vec<u8> {
        let body: String = armored
            .split("-----BEGIN PGP SIGNATURE-----\n\n")
            .nth(1)
            .unwrap()
            .lines()
            .take_while(|line| !line.starts_with('='))
            .collect();
        BASE64.decode(body).unwrap()
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    fn ed_sign_card() -> MockCard {
        MockCard::new()
            .with_openpgp(MockOpenPgp::new(PIN).with_key(KeySlot::Sign, MockKey::ed25519(b"sig")))
    }

    #[tokio::test]
    async fn clearsigned_message_names_the_card_key_and_uses_the_service_clock() {
        let card = card();
        let service = Service::new(
            Box::new(card.clone()),
            Arc::new(ManualClock::new(1_700_000_000)),
            Arc::new(SequentialChallengeSource::new(0)),
        );
        let armored = service
            .openpgp_sign_message(
                pin(PIN),
                HashAlgorithm::Sha256,
                Format::Clearsign,
                "hello  \n".into(),
            )
            .await
            .unwrap();
        assert!(
            armored.starts_with(
                "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nhello\n-----BEGIN PGP SIGNATURE-----\n"
            ),
            "{armored}"
        );
        assert!(armored.ends_with("-----END PGP SIGNATURE-----\n"));
        let packet = armored_packet(&armored);
        // Old-format signature packet, version 4, canonical text, RSA.
        assert_eq!(packet[3..6], [4, 0x01, 1]);
        let fingerprint = MockKey::rsa2048(b"sig").fingerprint();
        let created = 1_700_000_000u32.to_be_bytes();
        assert!(contains(
            &packet,
            &[&[22, 33, 4][..], &fingerprint].concat()
        ));
        assert!(contains(&packet, &[&[5, 2][..], &created].concat()));
        assert_eq!(card.openpgp(MockOpenPgp::signature_counter), 1);
        assert_eq!(card.openpgp(MockOpenPgp::pin_retries), 3);
    }

    #[tokio::test]
    async fn detached_signature_is_armored() {
        let card = ed_sign_card();
        let armored = service(&card)
            .openpgp_sign_message(
                pin(PIN),
                HashAlgorithm::Sha512,
                Format::Detached,
                "data".into(),
            )
            .await
            .unwrap();
        assert!(
            armored.starts_with("-----BEGIN PGP SIGNATURE-----\n\n"),
            "{armored}"
        );
        let packet = armored_packet(&armored);
        // Binary document signature, EdDSA, SHA-512.
        assert_eq!(packet[2..6], [4, 0x00, 22, 10]);
    }

    #[tokio::test]
    async fn message_requests_that_cannot_work_never_send_the_pin() {
        let empty = card();
        assert_eq!(
            service(&empty)
                .openpgp_sign_message(
                    pin(PIN),
                    HashAlgorithm::Sha256,
                    Format::Clearsign,
                    String::new()
                )
                .await,
            Err(ServiceError::BadInput(InputError::Empty))
        );
        assert_eq!(verifies(&empty.events()), 0);

        let ecdh = MockCard::new()
            .with_openpgp(MockOpenPgp::new(PIN).with_key(KeySlot::Sign, MockKey::cv25519(b"x")));
        assert_eq!(
            service(&ecdh)
                .openpgp_sign_message(
                    pin(PIN),
                    HashAlgorithm::Sha256,
                    Format::Clearsign,
                    "x".into()
                )
                .await,
            Err(ServiceError::BadInput(InputError::UnsupportedAlgorithm))
        );
        assert_eq!(verifies(&ecdh.events()), 0);

        let touch = MockCard::new().with_openpgp(
            MockOpenPgp::new(PIN)
                .with_key(KeySlot::Sign, MockKey::rsa2048(b"sig"))
                .with_touch(KeySlot::Sign, 0x01),
        );
        assert_eq!(
            service(&touch)
                .openpgp_sign_message(
                    pin(PIN),
                    HashAlgorithm::Sha256,
                    Format::Clearsign,
                    "x".into()
                )
                .await,
            Err(ServiceError::TouchRequired(KeySlot::Sign))
        );
        assert_eq!(verifies(&touch.events()), 0);
    }

    #[tokio::test]
    async fn message_with_a_wrong_pin_reports_retries() {
        let card = ed_sign_card();
        assert_eq!(
            service(&card)
                .openpgp_sign_message(
                    pin("000000"),
                    HashAlgorithm::Sha256,
                    Format::Clearsign,
                    "x".into()
                )
                .await,
            Err(ServiceError::WrongPin { retries_left: 2 })
        );
    }

    fn decrypt_card(key: MockKey) -> MockCard {
        MockCard::new().with_openpgp(MockOpenPgp::new(PIN).with_key(KeySlot::Decrypt, key))
    }

    fn rsa_fixture_key() -> MockKey {
        MockKey::rsa2048(b"dec")
            .with_fingerprint(fixtures::RSA_FPR)
            .with_decipher_output(&fixtures::RSA_SQ_CARD_OUTPUT)
    }

    #[tokio::test]
    async fn rsa_message_session_key_is_recovered() {
        let card = decrypt_card(rsa_fixture_key());
        let result = service(&card)
            .openpgp_decrypt_message(pin(PIN), fixtures::RSA_SQ_MESSAGE)
            .await
            .unwrap();
        assert_eq!(result.session_key.as_str(), fixtures::RSA_SQ_SESSION_KEY);
        assert_eq!(result.cipher, "aes256");
        assert_eq!(result.key_id, "B407021995AE2021");
        assert_eq!(result.data_format, DataFormat::SeipdV1);
        assert!(!format!("{result:?}").contains(&fixtures::RSA_SQ_SESSION_KEY[2..10]));
        // The card got 0x00 and the 256-byte ciphertext, command chained.
        let decipher: Vec<_> = card
            .events()
            .into_iter()
            .filter_map(|e| match e {
                MockEvent::Apdu(a) if a[1..4] == [0x2A, 0x80, 0x86] => Some(a),
                _ => None,
            })
            .collect();
        assert_eq!(decipher.len(), 2);
        assert_eq!(decipher[0][0], 0x10, "first part is chained");
        assert_eq!(decipher[0][5], 0x00, "padding indicator");
    }

    #[tokio::test]
    async fn curve25519_message_session_key_is_recovered() {
        let card = decrypt_card(
            MockKey::cv25519(b"dec")
                .with_fingerprint(fixtures::CV_FPR)
                .with_decipher_output(&fixtures::CV_SQ_CARD_OUTPUT),
        );
        let result = service(&card)
            .openpgp_decrypt_message(pin(PIN), fixtures::CV_SQ_MESSAGE)
            .await
            .unwrap();
        assert_eq!(result.session_key.as_str(), fixtures::CV_SQ_SESSION_KEY);
        assert_eq!(result.key_id, "0F704F4E8FE94366");
    }

    #[tokio::test]
    async fn message_problems_never_reach_the_pin() {
        let card = decrypt_card(rsa_fixture_key());
        let first = service(&card);
        assert_eq!(
            first
                .openpgp_decrypt_message(pin(PIN), "not a message")
                .await,
            Err(ServiceError::Decrypt(DecryptError::NotArmored))
        );
        assert!(card.events().is_empty(), "bad input never reaches the card");
        let other = decrypt_card(MockKey::rsa2048(b"other"));
        assert!(matches!(
            service(&other)
                .openpgp_decrypt_message(pin(PIN), fixtures::RSA_SQ_MESSAGE)
                .await,
            Err(ServiceError::Decrypt(DecryptError::NotForThisKey { .. }))
        ));
        assert_eq!(verifies(&other.events()), 0);
        let none = MockCard::new().with_openpgp(MockOpenPgp::new(PIN));
        assert_eq!(
            service(&none)
                .openpgp_decrypt_message(pin(PIN), fixtures::RSA_SQ_MESSAGE)
                .await,
            Err(ServiceError::NoKey(KeySlot::Decrypt))
        );
        let touch = MockCard::new().with_openpgp(
            MockOpenPgp::new(PIN)
                .with_key(KeySlot::Decrypt, rsa_fixture_key())
                .with_touch(KeySlot::Decrypt, 0x03),
        );
        assert_eq!(
            service(&touch)
                .openpgp_decrypt_message(pin(PIN), fixtures::RSA_SQ_MESSAGE)
                .await,
            Err(ServiceError::TouchRequired(KeySlot::Decrypt))
        );
        assert_eq!(verifies(&touch.events()), 0);
    }

    #[tokio::test]
    async fn message_decrypt_counts_a_wrong_pin() {
        let card = decrypt_card(rsa_fixture_key());
        assert_eq!(
            service(&card)
                .openpgp_decrypt_message(pin("000000"), fixtures::RSA_SQ_MESSAGE)
                .await,
            Err(ServiceError::WrongPin { retries_left: 2 })
        );
    }

    #[tokio::test]
    async fn a_card_answer_that_is_not_the_session_key_is_refused() {
        let card = decrypt_card(
            MockKey::rsa2048(b"dec")
                .with_fingerprint(fixtures::RSA_FPR)
                .with_decipher_output(&[9; 35]),
        );
        assert_eq!(
            service(&card)
                .openpgp_decrypt_message(pin(PIN), fixtures::RSA_SQ_MESSAGE)
                .await,
            Err(ServiceError::Decrypt(DecryptError::Recovery))
        );
    }

    #[tokio::test]
    async fn openpgp_and_oath_share_the_card() {
        let card = card();
        let service = service(&card);
        service.openpgp_status().await.unwrap();
        service.startup_check().await.unwrap();
        sign(&service, PIN).await.unwrap();
    }
}
