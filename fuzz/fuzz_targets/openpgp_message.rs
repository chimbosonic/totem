//! OpenPGP message building on arbitrary text and card signatures. Checks
//! the properties the format depends on, not just the absence of panics.
#![no_main]

use libfuzzer_sys::fuzz_target;
use totem::openpgp::message::{self, Format, SignatureBuilder};
use totem::openpgp::proto::{Algorithm, Curve, HashAlgorithm, KeyInfo, KeySlot};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let split = rest.len() / 2;
    let (text, signature) = rest.split_at(split);
    let text = String::from_utf8_lossy(text);
    let format = if selector & 1 == 0 {
        Format::Clearsign
    } else {
        Format::Detached
    };
    let hash = match (selector >> 1) % 3 {
        0 => HashAlgorithm::Sha256,
        1 => HashAlgorithm::Sha384,
        _ => HashAlgorithm::Sha512,
    };
    let algorithm = match (selector >> 3) % 3 {
        0 => Algorithm::Rsa { bits: 2048 },
        1 => Algorithm::EdDsa(Curve {
            oid: vec![0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01],
        }),
        _ => Algorithm::Ecdsa(Curve {
            oid: vec![0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
        }),
    };
    let key = KeyInfo {
        slot: KeySlot::Sign,
        algorithm,
        fingerprint: Some([7; 20]),
        created: None,
    };
    let builder = SignatureBuilder::new(&key, hash, format, 1_700_000_000).unwrap();
    let signed = message::signed_data(format, &text);
    let digest = builder.digest(&signed);
    let Ok(packet) = builder.packet(&digest, signature) else {
        return;
    };
    let armored = message::render(format, &text, hash, &packet);
    assert!(armored.ends_with("-----END PGP SIGNATURE-----\n"));
    if format == Format::Clearsign {
        // The signed text has no trailing whitespace before a line break,
        // so RFC 4880 and RFC 9580 verifiers hash the same bytes.
        for line in signed.split(|&b| b == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            assert!(!line.ends_with(b" ") && !line.ends_with(b"\t"));
        }
        // No line of the shown text can be mistaken for an armor header.
        let body = armored
            .split_once("\n\n")
            .unwrap()
            .1
            .rsplit_once("-----BEGIN PGP SIGNATURE-----")
            .unwrap()
            .0;
        assert!(body.lines().all(|line| !line.starts_with("-----")));
    }
});
