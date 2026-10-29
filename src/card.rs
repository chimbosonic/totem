//! Card access. [`Card`] is implemented by the real PC/SC reader and by
//! [`mock::MockCard`] for tests.

pub mod mock;
pub mod pcsc;

use crate::oath::proto::{self, Command, ProtoError};
use crate::openpgp::proto::{self as pgp, PgpError};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CardError {
    #[error("card was removed")]
    Removed,
    #[error("card was reset")]
    Reset,
    #[error("no card in the reader")]
    NoCard,
    #[error("reader error: {0}")]
    Reader(String),
    #[error(transparent)]
    Proto(#[from] ProtoError),
    #[error(transparent)]
    OpenPgp(#[from] PgpError),
}

impl CardError {
    /// Whether dropping the connection and reconnecting might fix this.
    pub fn needs_reconnect(&self) -> bool {
        !matches!(self, Self::Proto(_) | Self::OpenPgp(_))
    }
}

/// An exclusive transaction with the card. It ends when dropped.
pub trait CardTransaction {
    /// Send one APDU and return the raw response, status word included.
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, CardError>;
}

pub trait Card: Send {
    /// Begin an exclusive transaction.
    fn transaction(&mut self) -> Result<Box<dyn CardTransaction + '_>, CardError>;

    /// Drop the current connection and connect again.
    fn reconnect(&mut self) -> Result<(), CardError>;
}

/// Pick a reader: the first whose name contains `filter`, or without a
/// filter the first containing "YubiKey". Matching ignores case.
pub fn pick_reader<'a>(readers: &'a [String], filter: Option<&str>) -> Option<&'a str> {
    let needle = filter.unwrap_or("YubiKey").to_lowercase();
    readers
        .iter()
        .find(|name| name.to_lowercase().contains(&needle))
        .map(String::as_str)
}

/// Send `apdu`, follow SEND REMAINING chaining, and return the response
/// data if the final status is success.
pub fn send(
    tx: &mut dyn CardTransaction,
    apdu: &[u8],
    command: Command,
) -> Result<Vec<u8>, CardError> {
    let response = proto::transmit_chained(|a| tx.transmit(a), apdu)?;
    Ok(response.into_data(command)?)
}

/// Send one OpenPGP command, given as its command-chained APDUs, follow
/// GET RESPONSE chaining, and return the response data if every part
/// succeeded.
///
/// # Panics
///
/// If `apdus` is empty.
pub fn send_openpgp<A: AsRef<[u8]>>(
    tx: &mut dyn CardTransaction,
    apdus: &[A],
    command: pgp::Command,
) -> Result<Vec<u8>, CardError> {
    let (last, parts) = apdus.split_last().expect("at least one APDU");
    let get_response = pgp::get_response_apdu();
    for part in parts {
        let response =
            proto::transmit_chained_with(|a| tx.transmit(a), part.as_ref(), &get_response)?;
        pgp::check_status(command, response.data, response.sw)?;
    }
    let response = proto::transmit_chained_with(|a| tx.transmit(a), last.as_ref(), &get_response)?;
    Ok(pgp::check_status(command, response.data, response.sw)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oath::proto::send_remaining_apdu;
    use hex_literal::hex;
    use std::collections::VecDeque;

    struct Script {
        responses: VecDeque<Result<Vec<u8>, CardError>>,
        sent: Vec<Vec<u8>>,
    }

    impl CardTransaction for Script {
        fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, CardError> {
            self.sent.push(apdu.to_vec());
            self.responses.pop_front().expect("script ran out")
        }
    }

    fn script(responses: Vec<Result<Vec<u8>, CardError>>) -> Script {
        Script {
            responses: responses.into(),
            sent: Vec::new(),
        }
    }

    fn readers(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    #[test]
    fn pick_reader_defaults_to_first_yubikey() {
        let list = readers(&[
            "Generic Reader",
            "Yubico YubiKey OTP+FIDO+CCID",
            "Yubico YubiKey NEO",
        ]);
        assert_eq!(
            pick_reader(&list, None),
            Some("Yubico YubiKey OTP+FIDO+CCID")
        );
    }

    #[test]
    fn pick_reader_uses_filter_substring_ignoring_case() {
        let list = readers(&["Yubico YubiKey OTP+FIDO+CCID", "Yubico YubiKey NEO"]);
        assert_eq!(pick_reader(&list, Some("neo")), Some("Yubico YubiKey NEO"));
    }

    #[test]
    fn pick_reader_with_unmatched_filter_finds_nothing() {
        let list = readers(&["Yubico YubiKey NEO"]);
        assert_eq!(pick_reader(&list, Some("Nitrokey")), None);
    }

    #[test]
    fn pick_reader_without_yubikey_finds_nothing() {
        assert_eq!(pick_reader(&readers(&["Generic Reader"]), None), None);
        assert_eq!(pick_reader(&[], None), None);
    }

    #[test]
    fn transport_errors_need_reconnect_protocol_errors_do_not() {
        assert!(CardError::Removed.needs_reconnect());
        assert!(CardError::Reset.needs_reconnect());
        assert!(CardError::NoCard.needs_reconnect());
        assert!(CardError::Reader("gone".into()).needs_reconnect());
        assert!(!CardError::Proto(ProtoError::WrongPassword).needs_reconnect());
        assert!(!CardError::Proto(ProtoError::Status(0x6A80)).needs_reconnect());
        assert!(!CardError::OpenPgp(PgpError::WrongPin).needs_reconnect());
    }

    #[test]
    fn send_openpgp_sends_every_chained_part_and_follows_get_response() {
        let mut tx = script(vec![
            Ok(hex!("9000").to_vec()),
            Ok(hex!("01026101").to_vec()),
            Ok(hex!("039000").to_vec()),
        ]);
        let apdus = [vec![0x10, 0xAA], vec![0x00, 0xBB]];
        assert_eq!(
            send_openpgp(&mut tx, &apdus, pgp::Command::Decipher),
            Ok(vec![1, 2, 3])
        );
        assert_eq!(
            tx.sent,
            vec![vec![0x10, 0xAA], vec![0x00, 0xBB], pgp::get_response_apdu()]
        );
    }

    #[test]
    fn send_openpgp_stops_at_a_failed_chained_part() {
        let mut tx = script(vec![Ok(hex!("6982").to_vec())]);
        let apdus = [vec![0x10, 0xAA], vec![0x00, 0xBB]];
        assert_eq!(
            send_openpgp(&mut tx, &apdus, pgp::Command::Sign),
            Err(CardError::OpenPgp(PgpError::NotVerified))
        );
        assert_eq!(tx.sent.len(), 1);
    }

    #[test]
    fn send_openpgp_maps_status_for_the_command() {
        let mut tx = script(vec![Ok(hex!("63c2").to_vec())]);
        assert_eq!(
            send_openpgp(&mut tx, &[[0x00]], pgp::Command::Verify),
            Err(CardError::OpenPgp(PgpError::WrongPin))
        );
    }

    #[test]
    fn send_follows_chaining_and_returns_data() {
        let mut tx = script(vec![
            Ok(hex!("01026101").to_vec()),
            Ok(hex!("039000").to_vec()),
        ]);
        assert_eq!(
            send(&mut tx, &[0xAA], Command::CalculateAll),
            Ok(vec![1, 2, 3])
        );
        assert_eq!(tx.sent, vec![vec![0xAA], send_remaining_apdu()]);
    }

    #[test]
    fn send_maps_status_word_for_the_command() {
        let mut tx = script(vec![Ok(hex!("6984").to_vec())]);
        assert_eq!(
            send(&mut tx, &[0xAA], Command::Validate),
            Err(CardError::Proto(ProtoError::WrongPassword))
        );
    }

    #[test]
    fn send_passes_transport_errors_through() {
        let mut tx = script(vec![Err(CardError::Removed)]);
        assert_eq!(
            send(&mut tx, &[0xAA], Command::Select),
            Err(CardError::Removed)
        );
    }
}
