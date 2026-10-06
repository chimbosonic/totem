//! Card access. [`OathCard`] is implemented by the real PC/SC reader and by
//! [`mock::MockCard`] for tests.

pub mod mock;

use crate::oath::proto::{self, Command, ProtoError};

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
}

impl CardError {
    /// Whether dropping the connection and reconnecting might fix this.
    pub fn needs_reconnect(&self) -> bool {
        !matches!(self, Self::Proto(_))
    }
}

/// An exclusive transaction with the card. It ends when dropped.
pub trait CardTransaction {
    /// Send one APDU and return the raw response, status word included.
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, CardError>;
}

pub trait OathCard: Send {
    /// Begin an exclusive transaction.
    fn transaction(&mut self) -> Result<Box<dyn CardTransaction + '_>, CardError>;

    /// Drop the current connection and connect again.
    fn reconnect(&mut self) -> Result<(), CardError>;
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

    #[test]
    fn transport_errors_need_reconnect_protocol_errors_do_not() {
        assert!(CardError::Removed.needs_reconnect());
        assert!(CardError::Reset.needs_reconnect());
        assert!(CardError::NoCard.needs_reconnect());
        assert!(CardError::Reader("gone".into()).needs_reconnect());
        assert!(!CardError::Proto(ProtoError::WrongPassword).needs_reconnect());
        assert!(!CardError::Proto(ProtoError::Status(0x6A80)).needs_reconnect());
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
