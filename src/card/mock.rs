//! In-memory YKOATH card for tests.
//!
//! Implements SELECT, VALIDATE, CALCULATE ALL, CALCULATE, and SEND REMAINING
//! chunking. Clones share state, so a test can keep a handle to inspect
//! events and inject faults after handing the card to the service.
//!
//! Not emulated: touch (CALCULATE on a touch or HOTP credential is refused)
//! and credential management.

use std::sync::{Arc, Mutex};

use super::{CardError, CardTransaction, OathCard};
use crate::oath::crypto::{self, Algorithm, DerivedKey};
use crate::oath::proto::AID;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockKind {
    Totp,
    Hotp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockCredential {
    pub name: Vec<u8>,
    pub kind: MockKind,
    pub algorithm: Algorithm,
    pub digits: u8,
    pub secret: Vec<u8>,
    pub touch: bool,
}

impl MockCredential {
    pub fn totp(name: &str, algorithm: Algorithm, digits: u8, secret: &[u8]) -> Self {
        Self {
            name: name.as_bytes().to_vec(),
            kind: MockKind::Totp,
            algorithm,
            digits,
            secret: secret.to_vec(),
            touch: false,
        }
    }

    pub fn hotp(name: &str, algorithm: Algorithm, digits: u8, secret: &[u8]) -> Self {
        Self {
            kind: MockKind::Hotp,
            ..Self::totp(name, algorithm, digits, secret)
        }
    }

    pub fn with_touch(self) -> Self {
        Self {
            touch: true,
            ..self
        }
    }
}

/// Fault to inject on upcoming APDUs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockFault {
    Removed,
    Reset,
    NoCard,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockEvent {
    Begin,
    Apdu(Vec<u8>),
    End,
    Reconnect,
}

#[derive(Clone)]
pub struct MockCard {
    _state: Arc<Mutex<()>>,
}

impl MockCard {
    /// Device ID used when none is set.
    pub const DEFAULT_DEVICE_ID: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    /// Applet version used when none is set.
    pub const DEFAULT_VERSION: [u8; 3] = [5, 7, 0];

    /// A card with no password and no credentials.
    pub fn new() -> Self {
        todo!()
    }

    /// Set the OATH password. The key is derived from it and the device ID.
    pub fn with_password(self, _password: &str) -> Self {
        todo!()
    }

    pub fn with_credential(self, _credential: MockCredential) -> Self {
        todo!()
    }

    /// Largest response data chunk before SEND REMAINING is needed.
    pub fn with_chunk_size(self, _chunk_size: usize) -> Self {
        todo!()
    }

    /// Fail the next `count` APDUs with `fault`. The card loses its
    /// selected and unlocked state, as a real removal or reset would.
    pub fn fail_next(&self, _count: usize, _fault: MockFault) {
        todo!()
    }

    pub fn events(&self) -> Vec<MockEvent> {
        todo!()
    }

    pub fn clear_events(&self) {
        todo!()
    }
}

impl Default for MockCard {
    fn default() -> Self {
        Self::new()
    }
}

impl OathCard for MockCard {
    fn transaction(&mut self) -> Result<Box<dyn CardTransaction + '_>, CardError> {
        todo!()
    }

    fn reconnect(&mut self) -> Result<(), CardError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::send;
    use crate::oath::proto::{
        self, AuthChallenge, Command, EntryState, ProtoError, calculate_all_apdu, calculate_apdu,
        parse_calculate, parse_calculate_all, parse_select, select_apdu, validate_apdu,
        verify_validate_response,
    };

    const PASSWORD: &str = "correct horse";
    const OUR_CHALLENGE: [u8; 8] = [0xA1; 8];
    const SHA1_SEED: &[u8] = b"12345678901234567890";
    const SHA256_SEED: &[u8] = b"12345678901234567890123456789012";
    const SHA512_SEED: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    fn rfc_card() -> MockCard {
        MockCard::new()
            .with_password(PASSWORD)
            .with_credential(MockCredential::totp(
                "RFC:sha1",
                Algorithm::Sha1,
                8,
                SHA1_SEED,
            ))
            .with_credential(MockCredential::totp(
                "RFC:sha256",
                Algorithm::Sha256,
                8,
                SHA256_SEED,
            ))
            .with_credential(MockCredential::totp(
                "RFC:sha512",
                Algorithm::Sha512,
                8,
                SHA512_SEED,
            ))
    }

    fn key() -> DerivedKey {
        crypto::derive_key(PASSWORD, &MockCard::DEFAULT_DEVICE_ID)
    }

    /// SELECT then VALIDATE with `key`. Returns the VALIDATE result.
    fn unlock(tx: &mut dyn CardTransaction, key: &[u8]) -> Result<(), CardError> {
        let select = parse_select(&send(tx, &select_apdu(), Command::Select)?)?;
        let auth = select.auth.expect("card has a password");
        let apdu = validate_apdu(auth.algorithm, key, &auth.challenge, &OUR_CHALLENGE);
        let data = send(tx, &apdu, Command::Validate)?;
        verify_validate_response(&data, auth.algorithm, key, &OUR_CHALLENGE)?;
        Ok(())
    }

    fn codes(tx: &mut dyn CardTransaction, timestep: u64) -> Vec<(String, EntryState)> {
        let data = send(tx, &calculate_all_apdu(timestep), Command::CalculateAll).unwrap();
        parse_calculate_all(&data)
            .unwrap()
            .into_iter()
            .map(|e| (String::from_utf8(e.name).unwrap(), e.state))
            .collect()
    }

    fn code_strings(tx: &mut dyn CardTransaction, timestep: u64) -> Vec<String> {
        codes(tx, timestep)
            .into_iter()
            .map(|(_, state)| match state {
                EntryState::Code(code) => code.to_code(),
                other => panic!("expected a code, got {other:?}"),
            })
            .collect()
    }

    #[test]
    fn select_reports_version_device_id_and_password_challenge() {
        let mut card = rfc_card();
        let mut tx = card.transaction().unwrap();
        let select =
            parse_select(&send(&mut *tx, &select_apdu(), Command::Select).unwrap()).unwrap();
        assert_eq!(select.version, MockCard::DEFAULT_VERSION);
        assert_eq!(select.device_id, MockCard::DEFAULT_DEVICE_ID);
        let AuthChallenge {
            challenge,
            algorithm,
        } = select.auth.unwrap();
        assert_eq!(challenge.len(), 8);
        assert_eq!(algorithm, Algorithm::Sha1);
    }

    #[test]
    fn select_without_password_has_no_challenge() {
        let mut card = MockCard::new();
        let mut tx = card.transaction().unwrap();
        let select =
            parse_select(&send(&mut *tx, &select_apdu(), Command::Select).unwrap()).unwrap();
        assert_eq!(select.auth, None);
    }

    #[test]
    fn select_with_wrong_aid_is_rejected() {
        let mut card = MockCard::new();
        let mut tx = card.transaction().unwrap();
        let apdu = [0x00, 0xA4, 0x04, 0x00, 0x03, 0xA0, 0x00, 0x00];
        assert_eq!(
            send(&mut *tx, &apdu, Command::Select),
            Err(CardError::Proto(ProtoError::Status(0x6A82)))
        );
    }

    #[test]
    fn select_challenges_differ() {
        let mut card = rfc_card();
        let mut tx = card.transaction().unwrap();
        let mut challenge = || {
            parse_select(&send(&mut *tx, &select_apdu(), Command::Select).unwrap())
                .unwrap()
                .auth
                .unwrap()
                .challenge
        };
        assert_ne!(challenge(), challenge());
    }

    #[test]
    fn validate_with_correct_key_unlocks_and_card_proves_key() {
        let mut card = rfc_card();
        let mut tx = card.transaction().unwrap();
        assert_eq!(unlock(&mut *tx, &*key()), Ok(()));
    }

    #[test]
    fn validate_with_wrong_key_is_wrong_password() {
        let mut card = rfc_card();
        let mut tx = card.transaction().unwrap();
        let wrong = crypto::derive_key("wrong", &MockCard::DEFAULT_DEVICE_ID);
        assert_eq!(
            unlock(&mut *tx, &*wrong),
            Err(CardError::Proto(ProtoError::WrongPassword))
        );
    }

    #[test]
    fn validate_challenge_is_single_use() {
        let mut card = rfc_card();
        let mut tx = card.transaction().unwrap();
        let select =
            parse_select(&send(&mut *tx, &select_apdu(), Command::Select).unwrap()).unwrap();
        let auth = select.auth.unwrap();
        let apdu = validate_apdu(auth.algorithm, &*key(), &auth.challenge, &OUR_CHALLENGE);
        send(&mut *tx, &apdu, Command::Validate).unwrap();
        assert_eq!(
            send(&mut *tx, &apdu, Command::Validate),
            Err(CardError::Proto(ProtoError::WrongPassword))
        );
    }

    #[test]
    fn calculate_all_requires_validation() {
        let mut card = rfc_card();
        let mut tx = card.transaction().unwrap();
        send(&mut *tx, &select_apdu(), Command::Select).unwrap();
        assert_eq!(
            send(&mut *tx, &calculate_all_apdu(1), Command::CalculateAll),
            Err(CardError::Proto(ProtoError::AuthRequired))
        );
    }

    #[test]
    fn reselect_clears_unlocked_state() {
        let mut card = rfc_card();
        let mut tx = card.transaction().unwrap();
        unlock(&mut *tx, &*key()).unwrap();
        send(&mut *tx, &select_apdu(), Command::Select).unwrap();
        assert_eq!(
            send(&mut *tx, &calculate_all_apdu(1), Command::CalculateAll),
            Err(CardError::Proto(ProtoError::AuthRequired))
        );
    }

    #[test]
    fn calculate_all_without_password_needs_no_validate() {
        let mut card = MockCard::new().with_credential(MockCredential::totp(
            "A:b",
            Algorithm::Sha1,
            8,
            SHA1_SEED,
        ));
        let mut tx = card.transaction().unwrap();
        send(&mut *tx, &select_apdu(), Command::Select).unwrap();
        // RFC 6238: t=59 -> timestep 1.
        assert_eq!(code_strings(&mut *tx, 1), ["94287082"]);
    }

    #[test]
    fn calculate_all_before_select_is_rejected() {
        let mut card = MockCard::new();
        let mut tx = card.transaction().unwrap();
        assert!(send(&mut *tx, &calculate_all_apdu(1), Command::CalculateAll).is_err());
    }

    // RFC 6238 appendix B, literal expected values.
    #[test]
    fn calculate_all_matches_rfc6238_vectors() {
        let mut card = rfc_card();
        let mut tx = card.transaction().unwrap();
        unlock(&mut *tx, &*key()).unwrap();
        for (time, expected) in [
            (59u64, ["94287082", "46119246", "90693936"]),
            (1111111109, ["07081804", "68084774", "25091201"]),
            (1234567890, ["89005924", "91819424", "93441116"]),
            (20000000000, ["65353130", "77737706", "47863826"]),
        ] {
            assert_eq!(code_strings(&mut *tx, time / 30), expected, "t={time}");
        }
    }

    #[test]
    fn calculate_all_returns_names_in_card_order() {
        let mut card = rfc_card();
        let mut tx = card.transaction().unwrap();
        unlock(&mut *tx, &*key()).unwrap();
        let names: Vec<String> = codes(&mut *tx, 1).into_iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["RFC:sha1", "RFC:sha256", "RFC:sha512"]);
    }

    #[test]
    fn calculate_all_reports_hotp_and_touch_without_codes() {
        let mut card = MockCard::new()
            .with_credential(MockCredential::totp("T:ok", Algorithm::Sha1, 6, SHA1_SEED))
            .with_credential(
                MockCredential::totp("T:touch", Algorithm::Sha1, 6, SHA1_SEED).with_touch(),
            )
            .with_credential(MockCredential::hotp(
                "H:counter",
                Algorithm::Sha1,
                6,
                SHA1_SEED,
            ));
        let mut tx = card.transaction().unwrap();
        send(&mut *tx, &select_apdu(), Command::Select).unwrap();
        let states: Vec<EntryState> = codes(&mut *tx, 1).into_iter().map(|(_, s)| s).collect();
        assert!(matches!(states[0], EntryState::Code(c) if c.digits == 6));
        assert_eq!(states[1], EntryState::TouchRequired);
        assert_eq!(states[2], EntryState::Hotp);
    }

    #[test]
    fn calculate_computes_one_credential_for_given_timestep() {
        let mut card = MockCard::new().with_credential(MockCredential::totp(
            "60/A:b",
            Algorithm::Sha1,
            8,
            SHA1_SEED,
        ));
        let mut tx = card.transaction().unwrap();
        send(&mut *tx, &select_apdu(), Command::Select).unwrap();
        // Same secret and timestep as RFC 6238 t=59 with a 30s period.
        let data = send(&mut *tx, &calculate_apdu(b"60/A:b", 1), Command::Calculate).unwrap();
        assert_eq!(parse_calculate(&data).unwrap().to_code(), "94287082");
    }

    #[test]
    fn calculate_unknown_name_is_not_found() {
        let mut card = MockCard::new();
        let mut tx = card.transaction().unwrap();
        send(&mut *tx, &select_apdu(), Command::Select).unwrap();
        assert_eq!(
            send(&mut *tx, &calculate_apdu(b"nope", 1), Command::Calculate),
            Err(CardError::Proto(ProtoError::NotFound))
        );
    }

    #[test]
    fn calculate_requires_validation() {
        let mut card = rfc_card();
        let mut tx = card.transaction().unwrap();
        send(&mut *tx, &select_apdu(), Command::Select).unwrap();
        assert_eq!(
            send(
                &mut *tx,
                &calculate_apdu(b"RFC:sha1", 1),
                Command::Calculate
            ),
            Err(CardError::Proto(ProtoError::AuthRequired))
        );
    }

    fn twenty_credentials() -> MockCard {
        (0..20).fold(MockCard::new(), |card, i| {
            card.with_credential(MockCredential::totp(
                &format!("Issuer{i}:account{i}"),
                Algorithm::Sha1,
                6,
                SHA1_SEED,
            ))
        })
    }

    #[test]
    fn long_responses_are_chunked_and_reassembled() {
        let expected = {
            let mut card = twenty_credentials();
            let mut tx = card.transaction().unwrap();
            send(&mut *tx, &select_apdu(), Command::Select).unwrap();
            codes(&mut *tx, 1)
        };
        assert_eq!(expected.len(), 20);

        let mut card = twenty_credentials().with_chunk_size(16);
        let mut tx = card.transaction().unwrap();
        send(&mut *tx, &select_apdu(), Command::Select).unwrap();
        let raw = tx.transmit(&calculate_all_apdu(1)).unwrap();
        assert_eq!(raw.len(), 16 + 2);
        assert_eq!(raw[16], 0x61);

        send(&mut *tx, &select_apdu(), Command::Select).unwrap();
        assert_eq!(codes(&mut *tx, 1), expected);
    }

    #[test]
    fn clones_share_state() {
        let card = MockCard::new();
        let configured = card.clone().with_chunk_size(8);
        let mut original = card;
        let mut tx = original.transaction().unwrap();
        let _ = configured;
        // SELECT data (version + name TLVs, 15 bytes) is longer than 8.
        let raw = tx.transmit(&select_apdu()).unwrap();
        assert_eq!(raw[raw.len() - 2], 0x61);
    }

    #[test]
    fn unknown_instruction_is_rejected() {
        let mut card = MockCard::new();
        let mut tx = card.transaction().unwrap();
        let raw = tx.transmit(&[0x00, 0x01, 0x00, 0x00]).unwrap();
        assert_eq!(proto::Response::parse(&raw).unwrap().sw, 0x6D00);
    }

    #[test]
    fn malformed_apdu_is_rejected() {
        let mut card = MockCard::new();
        let mut tx = card.transaction().unwrap();
        for apdu in [&[0x00, 0xA4][..], &[0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0]] {
            let raw = tx.transmit(apdu).unwrap();
            assert_eq!(
                proto::Response::parse(&raw).unwrap().sw,
                0x6700,
                "{apdu:02x?}"
            );
        }
    }

    #[test]
    fn fail_next_fails_that_many_apdus_then_recovers_after_reconnect() {
        let mut card = rfc_card();
        card.fail_next(2, MockFault::Removed);
        {
            let mut tx = card.transaction().unwrap();
            assert_eq!(tx.transmit(&select_apdu()), Err(CardError::Removed));
            assert_eq!(tx.transmit(&select_apdu()), Err(CardError::Removed));
        }
        card.reconnect().unwrap();
        let mut tx = card.transaction().unwrap();
        assert_eq!(unlock(&mut *tx, &*key()), Ok(()));
    }

    #[test]
    fn faults_report_the_requested_kind() {
        let mut card = MockCard::new();
        card.fail_next(1, MockFault::Reset);
        card.fail_next(1, MockFault::NoCard);
        let mut tx = card.transaction().unwrap();
        // The later call replaces the earlier one.
        assert_eq!(tx.transmit(&select_apdu()), Err(CardError::NoCard));
        drop(tx);
        card.fail_next(1, MockFault::Reset);
        let mut tx = card.transaction().unwrap();
        assert_eq!(tx.transmit(&select_apdu()), Err(CardError::Reset));
    }

    #[test]
    fn fault_drops_unlocked_state() {
        let mut card = rfc_card();
        let mut tx = card.transaction().unwrap();
        unlock(&mut *tx, &*key()).unwrap();
        drop(tx);
        card.fail_next(1, MockFault::Reset);
        let mut tx = card.transaction().unwrap();
        assert!(tx.transmit(&calculate_all_apdu(1)).is_err());
        assert!(send(&mut *tx, &calculate_all_apdu(1), Command::CalculateAll).is_err());
    }

    #[test]
    fn events_record_transactions_apdus_and_reconnects() {
        let mut card = MockCard::new();
        let handle = card.clone();
        {
            let mut tx = card.transaction().unwrap();
            tx.transmit(&select_apdu()).unwrap();
        }
        card.reconnect().unwrap();
        assert_eq!(
            handle.events(),
            vec![
                MockEvent::Begin,
                MockEvent::Apdu(select_apdu()),
                MockEvent::End,
                MockEvent::Reconnect,
            ]
        );
        handle.clear_events();
        assert!(card.events().is_empty());
    }
}
