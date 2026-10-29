//! Encrypted messages from an untrusted caller, and card answers: armor,
//! packet parsing, recipient selection, card input, and session key
//! recovery must give an error, never a panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use totem::openpgp::encrypted;
use totem::openpgp::proto::{Algorithm, Curve, KeyInfo, KeySlot};

const CV25519_OID: [u8; 10] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let split = rest.len() * 3 / 4;
    let (message, card_output) = rest.split_at(split);
    // Both as armored text and as binary packets.
    let _ = encrypted::dearmor(&String::from_utf8_lossy(message));
    let Ok(parsed) = encrypted::parse_message(message) else {
        return;
    };
    let algorithm = if selector & 1 == 0 {
        Algorithm::Rsa {
            bits: 1024 << (selector >> 1 & 3),
        }
    } else {
        Algorithm::Ecdh(Curve {
            oid: CV25519_OID.to_vec(),
        })
    };
    let mut fingerprint = [0u8; 20];
    if let Some(first) = parsed.pkesks.first() {
        fingerprint[12..].copy_from_slice(&first.key_id);
    }
    let key = KeyInfo {
        slot: KeySlot::Decrypt,
        algorithm,
        fingerprint: Some(fingerprint),
        created: None,
    };
    let Ok(pkesk) = encrypted::select(&parsed, &key) else {
        return;
    };
    if encrypted::card_input(pkesk, &key).is_ok()
        && let Ok(session) = encrypted::session_key(pkesk, &key, card_output)
    {
        let form = session.tool_form();
        assert!(form.split_once(':').is_some_and(|(id, hex)| {
            id.bytes().all(|b| b.is_ascii_digit())
                && hex.bytes().all(|b| b.is_ascii_hexdigit())
        }));
    }
});
