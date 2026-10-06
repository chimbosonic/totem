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
    pub fn connect(filter: Option<&str>) -> Result<Self, CardError> {
        let (context, reader, card) = open(filter)?;
        Ok(Self {
            filter: filter.map(str::to_owned),
            reader,
            context,
            card: Some(card),
        })
    }

    /// Name of the reader currently in use.
    pub fn reader_name(&self) -> &str {
        &self.reader
    }
}

/// Establish a context, pick the reader, and connect to the card in it.
fn open(filter: Option<&str>) -> Result<(Context, String, pcsc::Card), CardError> {
    let context = Context::establish(Scope::User).map_err(map_error)?;
    let readers: Vec<String> = context
        .list_readers_owned()
        .map_err(map_error)?
        .into_iter()
        .map(|name| name.to_string_lossy().into_owned())
        .collect();
    let reader = pick_reader(&readers, filter)
        .ok_or_else(|| CardError::Reader(format!("no matching reader among {readers:?}")))?
        .to_owned();
    let name = CString::new(reader.clone())
        .map_err(|_| CardError::Reader("reader name contains NUL".into()))?;
    let card = context
        .connect(&name, ShareMode::Shared, Protocols::ANY)
        .map_err(map_error)?;
    Ok((context, reader, card))
}

impl OathCard for PcscCard {
    fn transaction(&mut self) -> Result<Box<dyn CardTransaction + '_>, CardError> {
        let card = self.card.as_mut().ok_or(CardError::NoCard)?;
        let tx = card.transaction().map_err(map_error)?;
        Ok(Box::new(PcscTransaction(tx)))
    }

    fn reconnect(&mut self) -> Result<(), CardError> {
        // Drop the old handle first. A replugged key can come back under a
        // new reader name, and a restarted pcscd invalidates the context,
        // so start from scratch.
        self.card = None;
        let (context, reader, card) = open(self.filter.as_deref())?;
        self.context = context;
        self.reader = reader;
        self.card = Some(card);
        Ok(())
    }
}

struct PcscTransaction<'a>(pcsc::Transaction<'a>);

impl CardTransaction for PcscTransaction<'_> {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, CardError> {
        let mut buffer = [0; pcsc::MAX_BUFFER_SIZE_EXTENDED];
        let response = self.0.transmit(apdu, &mut buffer).map_err(map_error)?;
        Ok(response.to_vec())
    }
}

/// Map a PC/SC error to a card error.
pub fn map_error(error: pcsc::Error) -> CardError {
    match error {
        pcsc::Error::RemovedCard => CardError::Removed,
        pcsc::Error::ResetCard => CardError::Reset,
        pcsc::Error::NoSmartcard => CardError::NoCard,
        other => CardError::Reader(other.to_string()),
    }
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
