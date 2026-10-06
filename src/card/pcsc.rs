//! Real card access through PC/SC (pcscd on Linux, PCSC.framework on macOS).
//!
//! Deliberately thin: APDU transport and error mapping only. Not unit tested
//! against hardware; see the manual checklist and `tests/hardware.rs`.

use std::ffi::CString;

use pcsc::{Context, Protocols, Scope, ShareMode};

use super::{CardError, CardTransaction, OathCard, pick_reader};

pub struct PcscCard {
    filter: Option<String>,
    reader: String,
    context: Context,
    card: Option<pcsc::Card>,
}

impl PcscCard {
    /// Connect to the reader chosen by `filter` (see [`pick_reader`]).
    pub fn connect(_filter: Option<&str>) -> Result<Self, CardError> {
        let _ = (
            CString::default(),
            Protocols::ANY,
            Scope::User,
            ShareMode::Shared,
            pick_reader,
        );
        todo!()
    }

    /// Name of the reader currently in use.
    pub fn reader_name(&self) -> &str {
        let _ = (&self.filter, &self.context, &self.card);
        &self.reader
    }
}

impl OathCard for PcscCard {
    fn transaction(&mut self) -> Result<Box<dyn CardTransaction + '_>, CardError> {
        todo!()
    }

    fn reconnect(&mut self) -> Result<(), CardError> {
        todo!()
    }
}

/// Map a PC/SC error to a card error.
pub fn map_error(_error: pcsc::Error) -> CardError {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn card_state_errors_map_to_typed_errors() {
        assert_eq!(map_error(pcsc::Error::RemovedCard), CardError::Removed);
        assert_eq!(map_error(pcsc::Error::ResetCard), CardError::Reset);
        assert_eq!(map_error(pcsc::Error::NoSmartcard), CardError::NoCard);
    }

    #[test]
    fn other_errors_are_reader_errors_with_a_message() {
        for error in [
            pcsc::Error::NoService,
            pcsc::Error::ReaderUnavailable,
            pcsc::Error::NoReadersAvailable,
            pcsc::Error::UnknownReader,
        ] {
            match map_error(error) {
                CardError::Reader(message) => assert!(!message.is_empty()),
                other => panic!("{error:?} mapped to {other:?}"),
            }
        }
    }

    #[test]
    fn every_mapped_error_needs_reconnect() {
        for error in [
            pcsc::Error::RemovedCard,
            pcsc::Error::ResetCard,
            pcsc::Error::NoSmartcard,
            pcsc::Error::NoService,
        ] {
            assert!(map_error(error).needs_reconnect(), "{error:?}");
        }
    }
}
