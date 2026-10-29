//! OpenPGP signatures around a signature made on the card: cleartext signed
//! messages (`-----BEGIN PGP SIGNED MESSAGE-----`) and ASCII-armored
//! detached signatures, as version 4 signature packets (RFC 4880 sections
//! 5.2, 6, and 7; RFC 9580).
//!
//! Everything here is pure, and no private key is involved: the card signs
//! the digest this module computes, and this module wraps that signature in
//! a packet. The layout is gpg's: issuer fingerprint and creation time
//! hashed, issuer key ID unhashed, old-format packet header, CRC-24 armor
//! checksum. Tests check the output against gpg-verified fixtures and
//! verify the signatures in them with independent RSA and Ed25519 code.
//!
//! Before clearsigning, trailing spaces and tabs are removed from each line
//! of the text, in what is shown as well as what is signed. RFC 4880
//! verifiers (gpg) ignore trailing whitespace and RFC 9580 ones do not, so
//! removing it up front makes both agree on what was signed.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha256, Sha384, Sha512};

use super::proto::{Algorithm, HashAlgorithm, InputError, KeyInfo, PgpError};

/// Signature over a binary document.
const SIG_BINARY: u8 = 0x00;
/// Signature over canonical text, as cleartext signatures are.
const SIG_TEXT: u8 = 0x01;

const PUBKEY_RSA: u8 = 1;
const PUBKEY_ECDSA: u8 = 19;
const PUBKEY_EDDSA: u8 = 22;

const SUBPACKET_CREATED: u8 = 2;
const SUBPACKET_ISSUER: u8 = 16;
const SUBPACKET_ISSUER_FINGERPRINT: u8 = 33;
const KEY_VERSION: u8 = 4;
const SIGNATURE_PACKET_TAG: u8 = 2;

const ARMOR_LINE: usize = 64;

/// What to produce around the card's signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// The text and its signature in one cleartext signed message.
    Clearsign,
    /// An armored signature over the exact bytes of the text.
    Detached,
}

impl Format {
    fn signature_type(self) -> u8 {
        match self {
            Self::Clearsign => SIG_TEXT,
            Self::Detached => SIG_BINARY,
        }
    }
}

impl HashAlgorithm {
    /// OpenPGP hash algorithm ID (RFC 9580 section 9.5).
    fn openpgp_id(self) -> u8 {
        match self {
            Self::Sha256 => 8,
            Self::Sha384 => 9,
            Self::Sha512 => 10,
        }
    }

    /// Name in the cleartext `Hash:` header.
    fn armor_name(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA256",
            Self::Sha384 => "SHA384",
            Self::Sha512 => "SHA512",
        }
    }

    fn hash(self, parts: &[&[u8]]) -> Vec<u8> {
        fn run<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut hasher = D::new();
            for part in parts {
                hasher.update(part);
            }
            hasher.finalize().to_vec()
        }
        match self {
            Self::Sha256 => run::<Sha256>(parts),
            Self::Sha384 => run::<Sha384>(parts),
            Self::Sha512 => run::<Sha512>(parts),
        }
    }
}

/// A version 4 signature being made by one card key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureBuilder {
    pubkey_algorithm: u8,
    fingerprint: [u8; 20],
    hash: HashAlgorithm,
    signature_type: u8,
    created: u32,
}

impl SignatureBuilder {
    /// A signature by `key`, made at Unix time `created`. Fails for keys
    /// that cannot sign (ECDH, unknown) or an empty slot.
    pub fn new(
        key: &KeyInfo,
        hash: HashAlgorithm,
        format: Format,
        created: u32,
    ) -> Result<Self, InputError> {
        let pubkey_algorithm = match key.algorithm {
            Algorithm::Rsa { .. } => PUBKEY_RSA,
            Algorithm::Ecdsa(_) => PUBKEY_ECDSA,
            Algorithm::EdDsa(_) => PUBKEY_EDDSA,
            Algorithm::Ecdh(_) | Algorithm::Unknown(_) => {
                return Err(InputError::UnsupportedAlgorithm);
            }
        };
        let fingerprint = key.fingerprint.ok_or(InputError::UnsupportedAlgorithm)?;
        Ok(Self {
            pubkey_algorithm,
            fingerprint,
            hash,
            signature_type: format.signature_type(),
            created,
        })
    }

    /// Version, type, algorithms, and the hashed subpackets: issuer
    /// fingerprint, then creation time.
    fn hashed_area(&self) -> Vec<u8> {
        let mut subpackets = Vec::new();
        subpackets.extend_from_slice(&[22, SUBPACKET_ISSUER_FINGERPRINT, KEY_VERSION]);
        subpackets.extend_from_slice(&self.fingerprint);
        subpackets.extend_from_slice(&[5, SUBPACKET_CREATED]);
        subpackets.extend_from_slice(&self.created.to_be_bytes());
        let mut out = vec![
            4,
            self.signature_type,
            self.pubkey_algorithm,
            self.hash.openpgp_id(),
        ];
        out.extend_from_slice(&(subpackets.len() as u16).to_be_bytes());
        out.extend_from_slice(&subpackets);
        out
    }

    /// The digest the card must sign for `data`, which is [`signed_data`].
    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        let hashed = self.hashed_area();
        let mut trailer = vec![4, 0xFF];
        trailer.extend_from_slice(&(hashed.len() as u32).to_be_bytes());
        self.hash.hash(&[data, &hashed, &trailer])
    }

    /// The signature packet for `digest` and the card's signature over it.
    pub fn packet(&self, digest: &[u8], card_signature: &[u8]) -> Result<Vec<u8>, PgpError> {
        let mut body = self.hashed_area();
        let mut unhashed = vec![9, SUBPACKET_ISSUER];
        unhashed.extend_from_slice(&self.fingerprint[12..]);
        body.extend_from_slice(&(unhashed.len() as u16).to_be_bytes());
        body.extend_from_slice(&unhashed);
        body.extend_from_slice(
            digest
                .get(..2)
                .ok_or(PgpError::Malformed("digest shorter than 2 bytes"))?,
        );
        if card_signature.is_empty() {
            return Err(PgpError::Malformed("empty signature"));
        }
        if self.pubkey_algorithm == PUBKEY_RSA {
            mpi(&mut body, card_signature);
        } else {
            // ECDSA and EdDSA cards return r and s of equal length.
            if !card_signature.len().is_multiple_of(2) {
                return Err(PgpError::Malformed("EC signature is not r and s"));
            }
            let (r, s) = card_signature.split_at(card_signature.len() / 2);
            mpi(&mut body, r);
            mpi(&mut body, s);
        }
        Ok(old_format_packet(SIGNATURE_PACKET_TAG, &body))
    }
}

/// An OpenPGP multiprecision integer: bit count, then the bytes without
/// leading zeros (RFC 9580 section 3.2).
fn mpi(out: &mut Vec<u8>, value: &[u8]) {
    let start = value.iter().position(|&b| b != 0).unwrap_or(value.len());
    let value = &value[start..];
    let bits = match value.first() {
        None => 0,
        Some(first) => (value.len() - 1) * 8 + (8 - first.leading_zeros() as usize),
    };
    out.extend_from_slice(&(bits as u16).to_be_bytes());
    out.extend_from_slice(value);
}

/// An old-format packet (RFC 9580 section 4.2.2) with the shortest length.
fn old_format_packet(tag: u8, body: &[u8]) -> Vec<u8> {
    let ctb = 0x80 | (tag << 2);
    let mut out = match u8::try_from(body.len()) {
        Ok(len) => vec![ctb, len],
        Err(_) => match u16::try_from(body.len()) {
            Ok(len) => [&[ctb | 1][..], &len.to_be_bytes()].concat(),
            Err(_) => [&[ctb | 2][..], &(body.len() as u32).to_be_bytes()].concat(),
        },
    };
    out.extend_from_slice(body);
    out
}

/// The lines of `text` for a cleartext message. CRLF and bare CR both end
/// a line (OpenPGP tools disagree on a bare CR, so it is never left in a
/// line), one final line break is dropped (the message block ends every
/// line itself), and trailing spaces and tabs are removed.
fn lines(text: &str) -> Vec<String> {
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let text = text.strip_suffix('\n').unwrap_or(&text);
    text.split('\n')
        .map(|line| line.trim_end_matches([' ', '\t']).to_owned())
        .collect()
}

/// The bytes a cleartext signature covers: the lines joined by CRLF, with
/// no line ending after the last (RFC 9580 section 7.2).
fn signed_text(text: &str) -> Vec<u8> {
    lines(text).join("\r\n").into_bytes()
}

/// The text as shown in a cleartext message: lines starting with `-` are
/// dash-escaped, and every line ends in `\n`.
fn cleartext_block(text: &str) -> String {
    let mut out = String::new();
    for line in lines(text) {
        if line.starts_with('-') {
            out.push_str("- ");
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// CRC-24 as used for the armor checksum (RFC 4880 section 6.1).
fn crc24(data: &[u8]) -> u32 {
    const INIT: u32 = 0x00B7_04CE;
    const POLY: u32 = 0x0186_4CFB;
    let mut crc = INIT;
    for &byte in data {
        crc ^= u32::from(byte) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x0100_0000 != 0 {
                crc ^= POLY;
            }
        }
    }
    crc & 0x00FF_FFFF
}

/// ASCII armor for a signature packet.
fn armor_signature(packet: &[u8]) -> String {
    let body = BASE64.encode(packet);
    let mut out = String::from("-----BEGIN PGP SIGNATURE-----\n\n");
    for chunk in body.as_bytes().chunks(ARMOR_LINE) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push('=');
    out.push_str(&BASE64.encode(&crc24(packet).to_be_bytes()[1..]));
    out.push_str("\n-----END PGP SIGNATURE-----\n");
    out
}

/// The bytes the signature in `format` covers for `text`.
pub fn signed_data(format: Format, text: &str) -> Vec<u8> {
    match format {
        Format::Clearsign => signed_text(text),
        Format::Detached => text.as_bytes().to_vec(),
    }
}

/// The armored result for `format`.
pub fn render(format: Format, text: &str, hash: HashAlgorithm, packet: &[u8]) -> String {
    match format {
        Format::Clearsign => format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: {}\n\n{}{}",
            hash.armor_name(),
            cleartext_block(text),
            armor_signature(packet)
        ),
        Format::Detached => armor_signature(packet),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openpgp::proto::{Curve, KeySlot, signature_input};
    use hex_literal::hex;

    // Fixtures: throwaway gpg test keys made for this (created 2024-01-01),
    // standing in for the card. For each, `gpg --verify` (GnuPG 2.5.24)
    // reported a good signature on the expected output, along with 105
    // other combinations of key, hash, format, and text (see AGENT.md).
    // Every test also verifies the signature again with an independent
    // implementation (RustCrypto `rsa` and `p256`, `ed25519-dalek`) over
    // the digest this module computes.
    const CREATED: u32 = 1_704_164_645;

    const RSA_FPR: [u8; 20] = hex!("2C55B8E025BB1456B272D1352988BF1247A1B470");
    const RSA_N: [u8; 256] = hex!(
        "c818dcdbda86485081923789908ccddb63f1f7cfc24d4be48e9bb5e88e810d77"
        "5821e2d14745be25edbd025d86fb122883836f77c4bd8fbcdae0957b74bb7faf"
        "ca18d74b1a81a1570742c2a5af2ea83ad2669e0e96851695a70285cf0cbba9db"
        "3e13a7a5ce8f0ad5afe62bb964222b8a60d7bf3ed97bd3c8139b1924f2b91b7c"
        "8aa53efa3a4e90fd1e0a45865c6bf65a2192ada7cc36db5cdc37f2bbd000c14e"
        "170ef65a7d54a82b14333865d703a96c09d505b6702a4a2d900f21ec0d86879e"
        "c0d163f4e2623e92280986d04b80cd60667337880cb3398059d030a007cfbd46"
        "fafc51d34b948403cbf9956b70a4746fdca74a69cd1e14944b9b1a07bb1bc761"
    );
    const ED_FPR: [u8; 20] = hex!("F7BC8FE6BDCB199D7516715CC1342DFF54C531C6");
    const ED_POINT: [u8; 33] =
        hex!("405dc42c8215b3c5d398036bad8cf6a30eab8a5f09d21130c53b260856c5fcac07");
    const P256_FPR: [u8; 20] = hex!("25FD765E261D7526548B572A5213CC626F7265C5");
    const P256_POINT: [u8; 65] = hex!(
        "0470a5f1f5a277b5d5d4ca14d0fc2636c3342b912127d1fc2a8786f211e1feccfd"
        "53d918d6f3b88c78688535ce416e61cdc246371129a54be74592c1dc0300fee7"
    );

    fn key(algorithm: Algorithm, fingerprint: [u8; 20]) -> KeyInfo {
        KeyInfo {
            slot: KeySlot::Sign,
            algorithm,
            fingerprint: Some(fingerprint),
            created: None,
        }
    }

    fn rsa_key() -> KeyInfo {
        key(Algorithm::Rsa { bits: 2048 }, RSA_FPR)
    }

    fn ed_key() -> KeyInfo {
        key(
            Algorithm::EdDsa(Curve {
                oid: hex!("2b06010401da470f01").to_vec(),
            }),
            ED_FPR,
        )
    }

    fn p256_key() -> KeyInfo {
        key(
            Algorithm::Ecdsa(Curve {
                oid: hex!("2a8648ce3d030107").to_vec(),
            }),
            P256_FPR,
        )
    }

    /// The digest the card signs, and the full armored result.
    fn sign(
        key: &KeyInfo,
        hash: HashAlgorithm,
        format: Format,
        text: &str,
        signature: &[u8],
    ) -> (Vec<u8>, String) {
        let builder = SignatureBuilder::new(key, hash, format, CREATED).unwrap();
        let digest = builder.digest(&signed_data(format, text));
        let packet = builder.packet(&digest, signature).unwrap();
        (digest, render(format, text, hash, &packet))
    }

    #[test]
    fn rsa_clearsigned_message_matches_gpg_and_verifies() {
        let signature = hex!(
            "601b8345942ed2706c9060b3d3458d77e386682bbf2bc0247fff2fe5c5a68974"
            "9c1a01f20df8ba5f2acd3d90ca21d830616a753f589c7521d34a94800e6cf99d"
            "4b301cb7687b0040989f0f39d7ddc701783e281cafff3a9f8b7b9ac5c7434a71"
            "a78aa270481ebcfbb5745604a1b0a298053feaea3efba76d702d3b0386f2b28b"
            "8012336aa42f01c5c1f0f8d605e0763e44132b303f074f4e940bf40a6a376628"
            "93615ce66eeb4f843a3d9121fec521dab6fc8b7d27843107302cb519a0d1a5ba"
            "59d7834db07e04098f001504e62bba9a9656de3ed0c568390deabd412ac564dc"
            "8dac1d67078940e7da0630a86e845cc66204c38de0008bad5c47f7830f835108"
        );
        let (digest, armored) = sign(
            &rsa_key(),
            HashAlgorithm::Sha256,
            Format::Clearsign,
            "hello world  \n-dash line\n\ttabbed\t\nlast line",
            &signature,
        );
        let expected = concat!(
            "-----BEGIN PGP SIGNED MESSAGE-----\n",
            "Hash: SHA256\n",
            "\n",
            "hello world\n",
            "- -dash line\n",
            "\ttabbed\n",
            "last line\n",
            "-----BEGIN PGP SIGNATURE-----\n",
            "\n",
            "iQEzBAEBCAAdFiEELFW44CW7FFayctE1KYi/EkehtHAFAmWTfSUACgkQKYi/Ekeh\n",
            "tHCF8Af/YBuDRZQu0nBskGCz00WNd+OGaCu/K8Akf/8v5cWmiXScGgHyDfi6XyrN\n",
            "PZDKIdgwYWp1P1icdSHTSpSADmz5nUswHLdoewBAmJ8POdfdxwF4Pigcr/86n4t7\n",
            "msXHQ0pxp4qicEgevPu1dFYEobCimAU/6uo++6dtcC07A4bysouAEjNqpC8BxcHw\n",
            "+NYF4HY+RBMrMD8HT06UC/QKajdmKJNhXOZu60+EOj2RIf7FIdq2/It9J4QxBzAs\n",
            "tRmg0aW6WdeDTbB+BAmPABUE5iu6mpZW3j7QxWg5Deq9QSrFZNyNrB1nB4lA59oG\n",
            "MKhuhFzGYgTDjeAAi61cR/eDD4NRCA==\n",
            "=LUwU\n",
            "-----END PGP SIGNATURE-----\n",
        );
        assert_eq!(armored, expected);
        // RustCrypto `rsa`, with its own SHA-256 DigestInfo, accepts the
        // signature over the digest computed here.
        let public = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(&RSA_N),
            rsa::BigUint::from_bytes_be(&[1, 0, 1]),
        )
        .unwrap();
        public
            .verify(
                rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha256>(),
                &digest,
                &signature,
            )
            .unwrap();
    }

    #[test]
    fn eddsa_clearsigned_message_matches_gpg_and_verifies() {
        let signature = hex!(
            "ee0b1d813cbd7b287a0f12f7b64c8e204f0faf40c4627c73aec7901631f26d3f"
            "8780b87fe8330622c7caa69aa150cf5ae322b227d5c56edc12fc88ae8f51d000"
        );
        let (digest, armored) = sign(
            &ed_key(),
            HashAlgorithm::Sha512,
            Format::Clearsign,
            "line one\r\nline two\n\n-- \nsig\n",
            &signature,
        );
        let expected = concat!(
            "-----BEGIN PGP SIGNED MESSAGE-----\n",
            "Hash: SHA512\n",
            "\n",
            "line one\n",
            "line two\n",
            "\n",
            "- --\n",
            "sig\n",
            "-----BEGIN PGP SIGNATURE-----\n",
            "\n",
            "iHUEARYKAB0WIQT3vI/mvcsZnXUWcVzBNC3/VMUxxgUCZZN9JQAKCRDBNC3/VMUx\n",
            "xooJAQDuCx2BPL17KHoPEve2TI4gTw+vQMRifHOux5AWMfJtPwEAh4C4f+gzBiLH\n",
            "yqaaoVDPWuMisifVxW7cEvyIro9R0AA=\n",
            "=45Kh\n",
            "-----END PGP SIGNATURE-----\n",
        );
        assert_eq!(armored, expected);
        let public =
            ed25519_dalek::VerifyingKey::from_bytes(&ED_POINT[1..].try_into().unwrap()).unwrap();
        public
            .verify_strict(&digest, &ed25519_dalek::Signature::from_bytes(&signature))
            .unwrap();
    }

    #[test]
    fn ecdsa_detached_signature_matches_gpg_and_verifies() {
        let signature = hex!(
            "cf4fc5fe7f9c1dc425aeb4faf4c23c140ff784f2b7fc2eb1ee971105f2be655d"
            "48c77fab23f514ba9eddf1941dc867023196d988fe12e0ffde41bb29435a7497"
        );
        let (digest, armored) = sign(
            &p256_key(),
            HashAlgorithm::Sha384,
            Format::Detached,
            "-dash\nend",
            &signature,
        );
        let expected = concat!(
            "-----BEGIN PGP SIGNATURE-----\n",
            "\n",
            "iHUEABMJAB0WIQQl/XZeJh11JlSLVypSE8xib3JlxQUCZZN9JQAKCRBSE8xib3Jl\n",
            "xWjMAQDPT8X+f5wdxCWutPr0wjwUD/eE8rf8LrHulxEF8r5lXQD/SMd/qyP1FLqe\n",
            "3fGUHchnAjGW2Yj+EuD/3kG7KUNadJc=\n",
            "=AMdT\n",
            "-----END PGP SIGNATURE-----\n",
        );
        assert_eq!(armored, expected);
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        let public = p256::ecdsa::VerifyingKey::from_sec1_bytes(&P256_POINT).unwrap();
        public
            .verify_prehash(
                &digest,
                &p256::ecdsa::Signature::from_slice(&signature).unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn rsa_digest_info_matches_rustcrypto() {
        // Our DigestInfo prefixes against the `rsa` crate's own.
        for (hash, prefix) in [
            (
                HashAlgorithm::Sha256,
                rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha256>().prefix,
            ),
            (
                HashAlgorithm::Sha384,
                rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha384>().prefix,
            ),
            (
                HashAlgorithm::Sha512,
                rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha512>().prefix,
            ),
        ] {
            let digest = vec![0xAB; hash.digest_len()];
            let input = signature_input(&Algorithm::Rsa { bits: 2048 }, hash, &digest).unwrap();
            assert_eq!(input, [&prefix[..], &digest].concat(), "{hash:?}");
        }
    }

    #[test]
    fn tampered_text_no_longer_verifies() {
        let signature = hex!(
            "ee0b1d813cbd7b287a0f12f7b64c8e204f0faf40c4627c73aec7901631f26d3f"
            "8780b87fe8330622c7caa69aa150cf5ae322b227d5c56edc12fc88ae8f51d000"
        );
        let (digest, _) = sign(
            &ed_key(),
            HashAlgorithm::Sha512,
            Format::Clearsign,
            "line one\r\nline tw0\n\n-- \nsig\n",
            &signature,
        );
        let public =
            ed25519_dalek::VerifyingKey::from_bytes(&ED_POINT[1..].try_into().unwrap()).unwrap();
        assert!(
            public
                .verify_strict(&digest, &ed25519_dalek::Signature::from_bytes(&signature))
                .is_err()
        );
    }

    #[test]
    fn clearsigned_text_ignores_trailing_whitespace_and_line_endings() {
        let digest = |format, text| {
            let builder =
                SignatureBuilder::new(&rsa_key(), HashAlgorithm::Sha256, format, 1).unwrap();
            builder.digest(&signed_data(format, text))
        };
        let clear = |text| digest(Format::Clearsign, text);
        assert_eq!(clear("a  \nb\t"), clear("a\nb"));
        assert_eq!(clear("a\r\nb\r\n"), clear("a\nb"));
        assert_eq!(clear("a\nb\n"), clear("a\nb"), "one final newline");
        assert_ne!(clear("a\nb\n\n"), clear("a\nb"), "a blank last line counts");
        let detached = |text| digest(Format::Detached, text);
        assert_ne!(detached("a \nb"), detached("a\nb"), "detached: exact bytes");
    }

    #[test]
    fn bare_carriage_returns_are_line_breaks() {
        // Found by fuzzing: OpenPGP tools disagree on a CR without LF, so
        // treat it as a line break and leave nothing ambiguous.
        assert_eq!(signed_text("a\t\rb \rc"), b"a\r\nb\r\nc".to_vec());
        assert_eq!(cleartext_block("a\t\rb"), "a\nb\n");
        assert_eq!(signed_text("a\r\r\nb"), b"a\r\n\r\nb".to_vec());
        assert_eq!(signed_text("a\r"), b"a".to_vec());
    }

    #[test]
    fn signed_text_and_cleartext_block() {
        assert_eq!(signed_text("a  \r\n\tb\t\nc\n"), b"a\r\n\tb\r\nc".to_vec());
        assert_eq!(signed_text(""), b"".to_vec());
        assert_eq!(cleartext_block("-a\nb  \n--\n"), "- -a\nb\n- --\n");
        assert_eq!(cleartext_block("x"), "x\n");
    }

    #[test]
    fn hashed_area_has_fingerprint_then_creation_time() {
        let builder = SignatureBuilder::new(
            &rsa_key(),
            HashAlgorithm::Sha384,
            Format::Detached,
            0x0102_0304,
        )
        .unwrap();
        let mut expected = hex!("04 00 01 09 001d 16 21 04").to_vec();
        expected.extend_from_slice(&RSA_FPR);
        expected.extend_from_slice(&hex!("05 02 01020304"));
        assert_eq!(builder.hashed_area(), expected);
    }

    #[test]
    fn non_signing_keys_and_empty_slots_are_refused() {
        let curve = Curve {
            oid: hex!("2b060104019755010501").to_vec(),
        };
        for algorithm in [Algorithm::Ecdh(curve), Algorithm::Unknown(9)] {
            assert_eq!(
                SignatureBuilder::new(
                    &key(algorithm, RSA_FPR),
                    HashAlgorithm::Sha256,
                    Format::Detached,
                    1
                ),
                Err(InputError::UnsupportedAlgorithm)
            );
        }
        let mut empty = rsa_key();
        empty.fingerprint = None;
        assert_eq!(
            SignatureBuilder::new(&empty, HashAlgorithm::Sha256, Format::Clearsign, 1),
            Err(InputError::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn malformed_card_signatures_are_refused() {
        let ec =
            SignatureBuilder::new(&p256_key(), HashAlgorithm::Sha256, Format::Detached, 1).unwrap();
        let rsa =
            SignatureBuilder::new(&rsa_key(), HashAlgorithm::Sha256, Format::Detached, 1).unwrap();
        for (builder, digest, signature) in [
            (&ec, &[0u8; 32][..], &[1, 2, 3][..]),
            (&ec, &[0; 32], &[]),
            (&rsa, &[0; 32], &[]),
            (&rsa, &[0; 1], &[1]),
        ] {
            assert!(matches!(
                builder.packet(digest, signature),
                Err(PgpError::Malformed(_))
            ));
        }
        // r = 1 and s = 2 become one-bit and two-bit MPIs.
        let packet = ec.packet(&[0xAB, 0xCD], &[0, 1, 0, 2]).unwrap();
        assert_eq!(packet[packet.len() - 6..], hex!("0001 01 0002 02"));
    }

    #[test]
    fn mpis_and_packet_headers() {
        let mut out = Vec::new();
        mpi(&mut out, &[0, 0, 0x01, 0xFF]);
        assert_eq!(out, hex!("0009 01ff"));
        out.clear();
        mpi(&mut out, &[0, 0]);
        assert_eq!(out, hex!("0000"));
        assert_eq!(old_format_packet(2, &[7; 3])[..2], [0x88, 3]);
        assert_eq!(old_format_packet(2, &[7; 300])[..3], [0x89, 0x01, 0x2C]);
        assert_eq!(
            old_format_packet(2, &vec![7; 70_000])[..5],
            [0x8A, 0, 1, 0x11, 0x70]
        );
    }

    #[test]
    fn crc24_matches_known_values() {
        assert_eq!(crc24(b""), 0xB704CE);
        // gpg-verified fixture above ends in "=AMdT".
        let packet = BASE64
            .decode(concat!(
                "iHUEABMJAB0WIQQl/XZeJh11JlSLVypSE8xib3JlxQUCZZN9JQAKCRBSE8xib3Jl",
                "xWjMAQDPT8X+f5wdxCWutPr0wjwUD/eE8rf8LrHulxEF8r5lXQD/SMd/qyP1FLqe",
                "3fGUHchnAjGW2Yj+EuD/3kG7KUNadJc="
            ))
            .unwrap();
        assert_eq!(BASE64.encode(&crc24(&packet).to_be_bytes()[1..]), "AMdT");
    }
}
