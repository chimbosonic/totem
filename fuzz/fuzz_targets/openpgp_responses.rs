//! Every parser that reads OpenPGP card responses, on arbitrary bytes, and
//! what the service does with the parsed values before any PIN is sent.
#![no_main]

use libfuzzer_sys::fuzz_target;
use totem::openpgp::proto::{self, HashAlgorithm, Kdf, KeySlot};
use totem::openpgp::tlv;

fuzz_target!(|data: &[u8]| {
    let _ = tlv::parse_all(data);
    for tag in [0x6E, 0x73, 0xC4, 0xC5, 0x7F49, 0x86, 0xF9] {
        let _ = tlv::find(data, tag);
    }
    if let Ok(app) = proto::parse_application_data(data) {
        let _ = app.version();
        let _ = app.serial();
        for slot in KeySlot::ALL {
            let key = app.key(slot);
            let _ = key.algorithm.name();
            if let Some(fingerprint) = &key.fingerprint {
                let _ = proto::fingerprint_hex(fingerprint);
            }
            for hash in [HashAlgorithm::Sha256, HashAlgorithm::Sha512] {
                let _ = proto::signature_input(&key.algorithm, hash, &vec![0; hash.digest_len()]);
            }
            let _ = proto::decipher_input(&key.algorithm, data);
        }
    }
    let _ = proto::parse_pw_status(data);
    let _ = proto::parse_algorithm(data);
    let _ = proto::parse_public_key(data);
    let _ = proto::parse_uif(data);
    let _ = proto::parse_signature_counter(data);
    if let Ok(kdf) = proto::parse_kdf(data) {
        // parse_kdf caps the count; keep fuzzing fast by hashing only small
        // ones here (the cap itself is unit tested).
        let small = match &kdf {
            Kdf::IterSaltedS2k { count, .. } => *count <= 4096,
            Kdf::None => true,
            Kdf::Unsupported { .. } => false,
        };
        if small {
            let _ = proto::kdf_pin(&kdf, b"123456");
        }
    }
    for command in [
        proto::Command::Select,
        proto::Command::Verify,
        proto::Command::Sign,
    ] {
        if let [hi, lo, ..] = *data {
            let _ = proto::status_error(command, u16::from_be_bytes([hi, lo]));
        }
    }
});
