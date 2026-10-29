//! Response chaining (61xx, SEND REMAINING, GET RESPONSE) and command
//! chaining against a card that answers with fuzzer-chosen bytes. Must end
//! (bounded rounds) and never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use totem::card::{self, CardError, CardTransaction};
use totem::oath::proto as oath;
use totem::openpgp::proto as pgp;

/// A card that replies with successive length-prefixed chunks of the input.
struct Scripted<'a> {
    rest: &'a [u8],
    sent: usize,
}

impl CardTransaction for Scripted<'_> {
    fn transmit(&mut self, _apdu: &[u8]) -> Result<Vec<u8>, CardError> {
        self.sent += 1;
        let Some((&len, rest)) = self.rest.split_first() else {
            return Err(CardError::Removed);
        };
        let len = usize::from(len).min(rest.len());
        let (reply, rest) = rest.split_at(len);
        self.rest = rest;
        Ok(reply.to_vec())
    }
}

fuzz_target!(|data: &[u8]| {
    let mut tx = Scripted { rest: data, sent: 0 };
    let _ = card::send(&mut tx, &oath::select_apdu(), oath::Command::Select);
    let mut tx = Scripted { rest: data, sent: 0 };
    let _ = card::send_openpgp(&mut tx, &pgp::decipher_apdus(&[0x5A; 600]), pgp::Command::Decipher);
    // Three command-chained parts, each followed by at most 64 rounds of
    // response chaining.
    assert!(tx.sent <= 3 * 65, "chaining did not stop: {} APDUs", tx.sent);
});
