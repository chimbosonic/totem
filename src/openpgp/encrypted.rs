//! Recovering the session key of an OpenPGP encrypted message with the
//! card's decryption key, without decrypting the message itself.
//!
//! An encrypted message starts with public-key encrypted session key
//! packets (PKESK, RFC 9580 section 5.1), one per recipient, followed by
//! the encrypted data. This module finds the PKESK for the card's key,
//! prepares the card's PSO: DECIPHER input, and turns the card's answer
//! into the session key, in the `cipher:hex` form that
//! `gpg --override-session-key` and `sq decrypt --session-key` take. The
//! message's plaintext never reaches this code.
//!
//! Supported: version 3 PKESKs for RSA keys, and for ECDH keys on
//! Curve25519 (RFC 6637 key derivation, then RFC 3394 AES key unwrap from
//! RustCrypto's `aes-kw`, whose integrity check rejects a wrong key).

use aes_kw::{KeyInit, KwAes128, KwAes192, KwAes256};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha256, Sha384, Sha512};
use zeroize::Zeroizing;

use super::proto::{Algorithm, KeyInfo};

const TAG_PKESK: u8 = 1;
const TAG_SKESK: u8 = 3;
const TAG_MARKER: u8 = 10;
const TAG_SEIPD: u8 = 18;
const TAG_GNUPG_OCB: u8 = 20;

const PKESK_V3: u8 = 3;
const PUBKEY_RSA: u8 = 1;
const PUBKEY_RSA_ENCRYPT: u8 = 2;
const PUBKEY_ECDH: u8 = 18;

/// Curve25519 for ECDH (RFC 9580 section 9.2, legacy OID).
const CV25519_OID: [u8; 10] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];
/// Prefix of a native Curve25519 point in an MPI.
const CV25519_PREFIX: u8 = 0x40;

/// More recipients than any real message has; bounds the work per request.
const MAX_PKESKS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecryptError {
    #[error("no -----BEGIN PGP MESSAGE----- armor found")]
    NotArmored,
    #[error("the armor checksum does not match; the message is damaged")]
    BadChecksum,
    #[error("malformed OpenPGP message: {0}")]
    Malformed(&'static str),
    #[error("the message has no public-key encrypted session key")]
    NoSessionKey,
    #[error(
        "the message is not encrypted to this card's decryption key \
         (message key IDs: {message}; card key ID: {card})"
    )]
    NotForThisKey { message: String, card: String },
    #[error("not supported: {0}")]
    Unsupported(&'static str),
    #[error(
        "the session key could not be recovered: the message may not be \
         for this key, or uses unusual ECDH parameters"
    )]
    Recovery,
}

/// How the message's data is encrypted, which decides the tools that can
/// read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataFormat {
    /// Symmetrically encrypted integrity protected data, version 1 (MDC).
    /// gpg and Sequoia both read it.
    SeipdV1,
    /// SEIPD version 2 (RFC 9580 AEAD).
    SeipdV2,
    /// GnuPG's OCB packet (type 20, LibrePGP). gpg reads it; Sequoia does
    /// not.
    GnupgOcb,
    /// Anything else, or the message ended before its data.
    Unknown,
}

impl DataFormat {
    pub fn name(self) -> &'static str {
        match self {
            Self::SeipdV1 => "seipd_v1",
            Self::SeipdV2 => "seipd_v2",
            Self::GnupgOcb => "gnupg_ocb",
            Self::Unknown => "unknown",
        }
    }
}

/// One version 3 public-key encrypted session key packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkesk {
    /// Recipient key ID; all zeros for an anonymous recipient.
    pub key_id: [u8; 8],
    pub kind: PkeskKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PkeskKind {
    /// RSA: the encrypted session key, an integer below the modulus.
    Rsa { ciphertext: Vec<u8> },
    /// ECDH: the sender's ephemeral point and the wrapped session key.
    Ecdh {
        ephemeral: Vec<u8>,
        wrapped: Vec<u8>,
    },
    /// A public key algorithm this module does not handle.
    Other { algorithm: u8 },
}

/// What the message says about its recipients and data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedMessage {
    pub pkesks: Vec<Pkesk>,
    pub data_format: DataFormat,
}

/// A recovered session key. The key is wiped when dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKey {
    /// OpenPGP symmetric algorithm ID.
    pub algorithm: u8,
    pub key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl SessionKey {
    /// `algorithm:HEX`, as `gpg --override-session-key` and
    /// `sq decrypt --session-key` take it. Wiped when dropped.
    pub fn tool_form(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(format!("{}:", self.algorithm));
        for byte in self.key.iter() {
            out.push_str(&format!("{byte:02X}"));
        }
        out
    }

    pub fn cipher_name(&self) -> &'static str {
        symmetric_algorithm(self.algorithm).map_or("unknown", |(name, _)| name)
    }
}

/// Name and key length of an OpenPGP symmetric algorithm (RFC 9580
/// section 9.3). IDEA (1) is not accepted.
fn symmetric_algorithm(id: u8) -> Option<(&'static str, usize)> {
    Some(match id {
        2 => ("tripledes", 24),
        3 => ("cast5", 16),
        4 => ("blowfish", 16),
        7 => ("aes128", 16),
        8 => ("aes192", 24),
        9 => ("aes256", 32),
        10 => ("twofish", 32),
        11 => ("camellia128", 16),
        12 => ("camellia192", 24),
        13 => ("camellia256", 32),
        _ => return None,
    })
}

/// The binary message inside `-----BEGIN PGP MESSAGE-----` armor. The CRC
/// line, if present, must match.
pub fn dearmor(armored: &str) -> Result<Vec<u8>, DecryptError> {
    const BEGIN: &str = "-----BEGIN PGP MESSAGE-----";
    const END: &str = "-----END PGP MESSAGE-----";
    let start = armored.find(BEGIN).ok_or(DecryptError::NotArmored)?;
    let rest = &armored[start + BEGIN.len()..];
    let end = rest.find(END).ok_or(DecryptError::NotArmored)?;
    let mut lines = rest[..end].lines().map(str::trim);
    // Header lines ("Comment: ...") run up to the first blank line.
    if lines.next() != Some("") {
        return Err(DecryptError::Malformed("armor header line not ended"));
    }
    for line in lines.by_ref() {
        if line.is_empty() {
            break;
        }
        if !line.contains(": ") {
            // No headers: this is already the first data line.
            return dearmor_body(std::iter::once(line).chain(lines));
        }
    }
    dearmor_body(lines)
}

fn dearmor_body<'a>(lines: impl Iterator<Item = &'a str>) -> Result<Vec<u8>, DecryptError> {
    let mut body = String::new();
    let mut checksum = None;
    for line in lines.filter(|line| !line.is_empty()) {
        if let Some(crc) = line.strip_prefix('=') {
            checksum = Some(crc.to_owned());
            break;
        }
        body.push_str(line);
    }
    let data = BASE64
        .decode(body)
        .map_err(|_| DecryptError::Malformed("armor is not valid base64"))?;
    if let Some(crc) = checksum {
        let expected = BASE64
            .decode(crc)
            .map_err(|_| DecryptError::Malformed("armor checksum is not base64"))?;
        if expected != crc24(&data).to_be_bytes()[1..] {
            return Err(DecryptError::BadChecksum);
        }
    }
    Ok(data)
}

/// CRC-24 as used for the armor checksum (RFC 4880 section 6.1).
fn crc24(data: &[u8]) -> u32 {
    let mut crc: u32 = 0x00B7_04CE;
    for &byte in data {
        crc ^= u32::from(byte) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x0100_0000 != 0 {
                crc ^= 0x0186_4CFB;
            }
        }
    }
    crc & 0x00FF_FFFF
}

/// One packet header: tag and body, or `None` for a length this module
/// does not follow (partial or indeterminate, used only for data packets).
/// A packet's tag, its body, and the input after it.
type Packet<'a> = (u8, &'a [u8], &'a [u8]);

fn next_packet(input: &[u8]) -> Result<Option<Packet<'_>>, DecryptError> {
    let malformed = DecryptError::Malformed("packet header cut short");
    let (&ctb, rest) = input.split_first().ok_or(malformed.clone())?;
    if ctb & 0x80 == 0 {
        return Err(DecryptError::Malformed("not an OpenPGP packet"));
    }
    let (tag, len, rest) = if ctb & 0x40 != 0 {
        let tag = ctb & 0x3F;
        let (&first, rest) = rest.split_first().ok_or(malformed.clone())?;
        match first {
            0..=191 => (tag, usize::from(first), rest),
            192..=223 => {
                let (&second, rest) = rest.split_first().ok_or(malformed.clone())?;
                let len = ((usize::from(first) - 192) << 8) + usize::from(second) + 192;
                (tag, len, rest)
            }
            255 => {
                let (len, rest) = rest.split_first_chunk::<4>().ok_or(malformed.clone())?;
                (tag, u32::from_be_bytes(*len) as usize, rest)
            }
            _ => return Ok(None),
        }
    } else {
        let tag = (ctb >> 2) & 0x0F;
        match ctb & 0x03 {
            0 => {
                let (&len, rest) = rest.split_first().ok_or(malformed.clone())?;
                (tag, usize::from(len), rest)
            }
            1 => {
                let (len, rest) = rest.split_first_chunk::<2>().ok_or(malformed.clone())?;
                (tag, usize::from(u16::from_be_bytes(*len)), rest)
            }
            2 => {
                let (len, rest) = rest.split_first_chunk::<4>().ok_or(malformed.clone())?;
                (tag, u32::from_be_bytes(*len) as usize, rest)
            }
            _ => return Ok(None),
        }
    };
    if rest.len() < len {
        // The key packets must be whole. The encrypted data is never read,
        // so a cut-short data packet still shows its tag and first bytes.
        if matches!(tag, TAG_PKESK | TAG_SKESK | TAG_MARKER) {
            return Err(DecryptError::Malformed("packet longer than the message"));
        }
        return Ok(Some((tag, rest, &[])));
    }
    let (body, rest) = rest.split_at(len);
    Ok(Some((tag, body, rest)))
}

/// A multiprecision integer: bit count, then the bytes.
fn read_mpi(input: &[u8]) -> Result<(&[u8], &[u8]), DecryptError> {
    let (bits, rest) = input
        .split_first_chunk::<2>()
        .ok_or(DecryptError::Malformed("MPI cut short"))?;
    let len = usize::from(u16::from_be_bytes(*bits)).div_ceil(8);
    if rest.len() < len {
        return Err(DecryptError::Malformed("MPI cut short"));
    }
    Ok(rest.split_at(len))
}

fn parse_pkesk(body: &[u8]) -> Result<Option<Pkesk>, DecryptError> {
    let malformed = DecryptError::Malformed("encrypted session key packet cut short");
    let (&version, rest) = body.split_first().ok_or(malformed.clone())?;
    if version != PKESK_V3 {
        // Version 6 PKESKs belong to version 6 keys, which OpenPGP cards
        // do not hold.
        return Ok(None);
    }
    let (key_id, rest) = rest.split_first_chunk::<8>().ok_or(malformed.clone())?;
    let (&algorithm, rest) = rest.split_first().ok_or(malformed.clone())?;
    let kind = match algorithm {
        PUBKEY_RSA | PUBKEY_RSA_ENCRYPT => {
            let (ciphertext, _) = read_mpi(rest)?;
            PkeskKind::Rsa {
                ciphertext: ciphertext.to_vec(),
            }
        }
        PUBKEY_ECDH => {
            let (ephemeral, rest) = read_mpi(rest)?;
            let (&len, rest) = rest.split_first().ok_or(malformed.clone())?;
            let wrapped = rest.get(..usize::from(len)).ok_or(malformed)?;
            PkeskKind::Ecdh {
                ephemeral: ephemeral.to_vec(),
                wrapped: wrapped.to_vec(),
            }
        }
        other => PkeskKind::Other { algorithm: other },
    };
    Ok(Some(Pkesk {
        key_id: *key_id,
        kind,
    }))
}

/// The encrypted session keys at the start of `data` and the format of
/// the encrypted data after them. Reading stops at the data.
pub fn parse_message(data: &[u8]) -> Result<EncryptedMessage, DecryptError> {
    let mut pkesks = Vec::new();
    let mut rest = data;
    let mut data_format = DataFormat::Unknown;
    while !rest.is_empty() {
        let Some((tag, body, after)) = next_packet(rest)? else {
            break;
        };
        match tag {
            TAG_PKESK => {
                if pkesks.len() == MAX_PKESKS {
                    return Err(DecryptError::Malformed("too many recipients"));
                }
                if let Some(pkesk) = parse_pkesk(body)? {
                    pkesks.push(pkesk);
                }
            }
            TAG_SKESK | TAG_MARKER => {}
            TAG_SEIPD => {
                data_format = match body.first() {
                    Some(1) => DataFormat::SeipdV1,
                    Some(2) => DataFormat::SeipdV2,
                    _ => DataFormat::Unknown,
                };
                break;
            }
            TAG_GNUPG_OCB => {
                data_format = DataFormat::GnupgOcb;
                break;
            }
            _ => break,
        }
        rest = after;
    }
    // A partial-length data packet ends the loop without a body; its tag
    // is still visible in the header byte.
    if data_format == DataFormat::Unknown && !rest.is_empty() {
        data_format = match header_tag(rest[0]) {
            TAG_SEIPD => match seipd_version(rest) {
                Some(1) => DataFormat::SeipdV1,
                Some(2) => DataFormat::SeipdV2,
                _ => DataFormat::Unknown,
            },
            TAG_GNUPG_OCB => DataFormat::GnupgOcb,
            _ => DataFormat::Unknown,
        };
    }
    if pkesks.is_empty() {
        return Err(DecryptError::NoSessionKey);
    }
    Ok(EncryptedMessage {
        pkesks,
        data_format,
    })
}

fn header_tag(ctb: u8) -> u8 {
    if ctb & 0x40 != 0 {
        ctb & 0x3F
    } else {
        (ctb >> 2) & 0x0F
    }
}

/// First body byte of a new-format packet with a partial length.
fn seipd_version(packet: &[u8]) -> Option<u8> {
    packet.get(2).copied()
}

/// The PKESK for `key`: one with its key ID, or else an anonymous one.
pub fn select<'a>(message: &'a EncryptedMessage, key: &KeyInfo) -> Result<&'a Pkesk, DecryptError> {
    let fingerprint = key
        .fingerprint
        .ok_or(DecryptError::Unsupported("the card has no decryption key"))?;
    let key_id: [u8; 8] = fingerprint[12..].try_into().expect("8 bytes");
    message
        .pkesks
        .iter()
        .find(|p| p.key_id == key_id)
        .or_else(|| message.pkesks.iter().find(|p| p.key_id == [0; 8]))
        .ok_or_else(|| DecryptError::NotForThisKey {
            message: message
                .pkesks
                .iter()
                .map(|p| hex_upper(&p.key_id))
                .collect::<Vec<_>>()
                .join(", "),
            card: hex_upper(&key_id),
        })
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// The PSO: DECIPHER data for `pkesk` and `key` (before the card's own
/// wrapping): the RSA ciphertext padded to the modulus length, or the
/// native 32-byte Curve25519 ephemeral point.
pub fn card_input(pkesk: &Pkesk, key: &KeyInfo) -> Result<Vec<u8>, DecryptError> {
    match (&pkesk.kind, &key.algorithm) {
        (PkeskKind::Rsa { ciphertext }, Algorithm::Rsa { bits }) => {
            let len = usize::from(*bits).div_ceil(8);
            if ciphertext.is_empty() || ciphertext.len() > len {
                return Err(DecryptError::Malformed(
                    "RSA ciphertext does not fit the key",
                ));
            }
            let mut padded = vec![0; len - ciphertext.len()];
            padded.extend_from_slice(ciphertext);
            Ok(padded)
        }
        (PkeskKind::Ecdh { ephemeral, .. }, Algorithm::Ecdh(curve)) => {
            if curve.oid != CV25519_OID {
                return Err(DecryptError::Unsupported(
                    "ECDH decryption keys other than Curve25519",
                ));
            }
            match ephemeral.split_first() {
                Some((&CV25519_PREFIX, point)) if point.len() == 32 => Ok(point.to_vec()),
                _ => Err(DecryptError::Malformed("Curve25519 ephemeral point")),
            }
        }
        (PkeskKind::Other { .. }, _) => Err(DecryptError::Unsupported(
            "the message's public key algorithm",
        )),
        _ => Err(DecryptError::Malformed(
            "the message's key type does not match the card's key",
        )),
    }
}

/// The session key from the card's PSO: DECIPHER answer.
pub fn session_key(
    pkesk: &Pkesk,
    key: &KeyInfo,
    card_output: &[u8],
) -> Result<SessionKey, DecryptError> {
    match &pkesk.kind {
        // The card has removed the PKCS #1 padding.
        PkeskKind::Rsa { .. } => checked_session_key(card_output),
        PkeskKind::Ecdh { wrapped, .. } => {
            let fingerprint = key
                .fingerprint
                .ok_or(DecryptError::Unsupported("the card has no decryption key"))?;
            let shared = match card_output {
                [CV25519_PREFIX, rest @ ..] if rest.len() == 32 => rest,
                shared if shared.len() == 32 => shared,
                _ => return Err(DecryptError::Recovery),
            };
            unwrap_ecdh(shared, wrapped, &fingerprint)
        }
        PkeskKind::Other { .. } => Err(DecryptError::Unsupported(
            "the message's public key algorithm",
        )),
    }
}

/// `algorithm || key || checksum`, with the checksum (sum of the key bytes
/// mod 65536) and the key length checked.
fn checked_session_key(data: &[u8]) -> Result<SessionKey, DecryptError> {
    let Some((&algorithm, rest)) = data.split_first() else {
        return Err(DecryptError::Recovery);
    };
    let Some((key, checksum)) = rest.split_last_chunk::<2>() else {
        return Err(DecryptError::Recovery);
    };
    let Some((_, key_len)) = symmetric_algorithm(algorithm) else {
        return Err(DecryptError::Recovery);
    };
    let sum = key
        .iter()
        .fold(0u16, |sum, &byte| sum.wrapping_add(u16::from(byte)));
    if key.len() != key_len || sum != u16::from_be_bytes(*checksum) {
        return Err(DecryptError::Recovery);
    }
    Ok(SessionKey {
        algorithm,
        key: Zeroizing::new(key.to_vec()),
    })
}

/// KDF hash and key-wrap algorithm pairs to try, gpg's Curve25519 default
/// first. The KDF parameters live on the public key, not on the card;
/// the key unwrap's integrity check rejects a wrong pair.
const ECDH_KDF_CANDIDATES: [(u8, u8); 4] = [(8, 7), (10, 9), (9, 8), (8, 9)];

/// RFC 6637 section 7 (RFC 9580 section 11.5): derive the key-encryption
/// key from the shared secret, unwrap the session key, remove the PKCS #5
/// padding.
fn unwrap_ecdh(
    shared: &[u8],
    wrapped: &[u8],
    fingerprint: &[u8; 20],
) -> Result<SessionKey, DecryptError> {
    for (hash, kek_algorithm) in ECDH_KDF_CANDIDATES {
        let mut param = vec![CV25519_OID.len() as u8];
        param.extend_from_slice(&CV25519_OID);
        param.extend_from_slice(&[PUBKEY_ECDH, 3, 1, hash, kek_algorithm]);
        param.extend_from_slice(b"Anonymous Sender    ");
        param.extend_from_slice(fingerprint);
        let parts: [&[u8]; 3] = [&[0, 0, 0, 1], shared, &param];
        let digest = Zeroizing::new(match hash {
            8 => hash_parts::<Sha256>(&parts),
            9 => hash_parts::<Sha384>(&parts),
            _ => hash_parts::<Sha512>(&parts),
        });
        let mut buf = Zeroizing::new(vec![0; wrapped.len()]);
        let unwrapped = match kek_algorithm {
            7 => KwAes128::new_from_slice(&digest[..16])
                .ok()
                .and_then(|kw| kw.unwrap_key(wrapped, &mut buf).ok()),
            8 => KwAes192::new_from_slice(&digest[..24])
                .ok()
                .and_then(|kw| kw.unwrap_key(wrapped, &mut buf).ok()),
            _ => KwAes256::new_from_slice(&digest[..32])
                .ok()
                .and_then(|kw| kw.unwrap_key(wrapped, &mut buf).ok()),
        };
        if let Some(unwrapped) = unwrapped {
            return checked_session_key(remove_pkcs5_padding(unwrapped)?);
        }
    }
    Err(DecryptError::Recovery)
}

fn hash_parts<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = D::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().to_vec()
}

fn remove_pkcs5_padding(data: &[u8]) -> Result<&[u8], DecryptError> {
    let pad = *data.last().ok_or(DecryptError::Recovery)?;
    let pad_len = usize::from(pad);
    if pad_len == 0 || pad_len > 8 || pad_len > data.len() {
        return Err(DecryptError::Recovery);
    }
    let (body, padding) = data.split_at(data.len() - pad_len);
    if padding.iter().any(|&b| b != pad) {
        return Err(DecryptError::Recovery);
    }
    Ok(body)
}

/// Recorded messages and card answers, shared by tests across the crate.
#[cfg(test)]
pub(crate) mod fixtures {
    use hex_literal::hex;

    // Fixtures: messages encrypted with gpg 2.5.24 and sq 1.5.0 to
    // throwaway keys made for this. `card_output` is what the card
    // returns, computed with the test private key (RSA decryption, or
    // X25519). Each expected session key is gpg's own
    // `--show-session-key` for the message, and decrypting the message
    // with it worked in gpg and, for Sequoia's messages, in sq (see
    // AGENT.md).

    pub const RSA_FPR: [u8; 20] = hex!("C0A30E2ABA8260E99A05DA14B407021995AE2021");
    pub const CV_FPR: [u8; 20] = hex!("595249D126646AE10718BE510F704F4E8FE94366");

    pub const RSA_SQ_MESSAGE: &str = "-----BEGIN PGP MESSAGE-----

    wcBMA7QHAhmVriAhAQgAwuYz9k3NIrwJ/JhHLcrMQL2sbyCJMk4IUvzlTDRR5IKF
    yJtHdnC7PJuTd9YIFaGIfJE9V9Dn1ENnt0PqurHfdDRzwbhiW2xhD76RaxV2uvai
    p6aEIkfTtUd/BsUHM5KDB5F5hDV7KtdITGBfIDBrVnx1oDP9xa5wZqOUcNsaPraf
    TU9QJ3DgfoPSm1tiC/XL2R+jYlxrgGz7yv/OJBMBKp0F6RDpnbxNTchNcocarAYe
    DArx5f/vNoBtlkfgxthypP4nzdGaATgLeoBuGCIeVw09TpE84qWxushYwtdwZHbr
    IVzlJCrl9D9K73jMxyPO3bsnWGeOmy+PR3T0HjgMhdJCAQ6ymbE+NVJ4ybPUb15H
    hhaBbexEmfeHezxELcwziot52XxAFi0cEnWfqMsQkOa2A8QilS0vT8RQOCnabTtS
    nRgN
    =lzu/
    -----END PGP MESSAGE-----
    ";
    pub const RSA_SQ_CARD_OUTPUT: [u8; 35] =
        hex!("0937a9d65defbfe689c139e154e7cb487c60bfebcd43c7969a21400617759a1a8d111a");
    pub const RSA_SQ_SESSION_KEY: &str =
        "9:37A9D65DEFBFE689C139E154E7CB487C60BFEBCD43C7969A21400617759A1A8D";

    pub const CV_SQ_MESSAGE: &str = "-----BEGIN PGP MESSAGE-----

    wV4DD3BPTo/pQ2YSAQdA/YYOS8MGekZDkiQ0O9HQYMgSaTWCzZqeJiSJ9Uy2P1Yw
    EOq4XZGkxhmxn5n0BpsU8SBZD1Lq2K5S4CoFKuH5Mbf74jfpzsZN12kg8faebdGm
    0kIBfTum3UBDHzHigyOgoiCwWKg592t3gFE4Wq2pLzXyqfcgqoqPbgZ2k+UPLlWK
    qB+qqCJWpX1jEyrGQ5b09HPyR0A=
    =6KRI
    -----END PGP MESSAGE-----
    ";
    pub const CV_SQ_CARD_OUTPUT: [u8; 32] =
        hex!("257118b97d326c5eea2a2a04ab92b78e655b2514c44a7daaf98c378f796e8416");
    pub const CV_SQ_SESSION_KEY: &str =
        "9:A883DF26086A08C3BB83C9E550330051EE3D3F5AE0EB948ACF4C293E1492451A";

    pub const CV_GPG_OCB_MESSAGE: &str = "-----BEGIN PGP MESSAGE-----

    hF4DD3BPTo/pQ2YSAQdAOB1XU5zgIy8/KTzudeRQidqcwj2aRQR8N8B1tAe6sRow
    qLM7md3lLJvnoS7VFZ3AlCaGuTyT/wudaHBujFsIqKUOdP70l3uEk3/xUH8SSbIX
    1F8BCQIQxkt5K0RLmLJqTa+krxvddRC0THPmKPyYJ0pUFIp67Ajdh3TGygC1emaF
    ZYYiB0o7nGS/+a/ooglkqBDjD/1HoNsg8QZLojX0c+CyO8CLgRfdC0J+E3oAq2v+
    Dg==
    =8SRr
    -----END PGP MESSAGE-----
    ";
    pub const CV_GPG_OCB_CARD_OUTPUT: [u8; 32] =
        hex!("6a2a36037bd1bb75549e4d061b1c46016f638488e55633669668d80b50588563");
    // gpg shows it as "9.2:..."; the ".2" (OCB) is not needed to decrypt.
    pub const CV_GPG_OCB_SESSION_KEY: &str =
        "9:85540CD22DDB18953E4D374D0D9E86AB487FAC9D4FA21BE941858FBECEE5A563";
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::openpgp::proto::{Curve, KeySlot};
    use hex_literal::hex;

    fn rsa_key() -> KeyInfo {
        KeyInfo {
            slot: KeySlot::Decrypt,
            algorithm: Algorithm::Rsa { bits: 2048 },
            fingerprint: Some(RSA_FPR),
            created: None,
        }
    }

    fn cv_key() -> KeyInfo {
        KeyInfo {
            slot: KeySlot::Decrypt,
            algorithm: Algorithm::Ecdh(Curve {
                oid: CV25519_OID.to_vec(),
            }),
            fingerprint: Some(CV_FPR),
            created: None,
        }
    }

    fn recover(
        armored: &str,
        key: &KeyInfo,
        card_output: &[u8],
    ) -> Result<SessionKey, DecryptError> {
        let message = parse_message(&dearmor(armored)?)?;
        let pkesk = select(&message, key)?;
        card_input(pkesk, key)?;
        session_key(pkesk, key, card_output)
    }

    #[test]
    fn rsa_message_gives_gpgs_session_key() {
        let message = parse_message(&dearmor(RSA_SQ_MESSAGE).unwrap()).unwrap();
        assert_eq!(message.data_format, DataFormat::SeipdV1);
        let pkesk = select(&message, &rsa_key()).unwrap();
        let input = card_input(pkesk, &rsa_key()).unwrap();
        assert_eq!(input.len(), 256, "padded to the modulus length");
        let session = session_key(pkesk, &rsa_key(), &RSA_SQ_CARD_OUTPUT).unwrap();
        assert_eq!(session.tool_form().as_str(), RSA_SQ_SESSION_KEY);
        assert_eq!(session.cipher_name(), "aes256");
    }

    #[test]
    fn curve25519_message_gives_gpgs_session_key() {
        let message = parse_message(&dearmor(CV_SQ_MESSAGE).unwrap()).unwrap();
        let pkesk = select(&message, &cv_key()).unwrap();
        let input = card_input(pkesk, &cv_key()).unwrap();
        let PkeskKind::Ecdh { ephemeral, .. } = &pkesk.kind else {
            panic!("ECDH");
        };
        assert_eq!(
            input[..],
            ephemeral[1..],
            "native point, 0x40 prefix removed"
        );
        let session = session_key(pkesk, &cv_key(), &CV_SQ_CARD_OUTPUT).unwrap();
        assert_eq!(session.tool_form().as_str(), CV_SQ_SESSION_KEY);
        // A card answering with the 0x40 prefix works too.
        let prefixed = [&[0x40][..], &CV_SQ_CARD_OUTPUT].concat();
        assert_eq!(
            session_key(pkesk, &cv_key(), &prefixed)
                .unwrap()
                .tool_form()
                .as_str(),
            CV_SQ_SESSION_KEY
        );
    }

    #[test]
    fn gnupg_ocb_message_is_recognised_and_works() {
        let message = parse_message(&dearmor(CV_GPG_OCB_MESSAGE).unwrap()).unwrap();
        assert_eq!(message.data_format, DataFormat::GnupgOcb);
        assert_eq!(message.data_format.name(), "gnupg_ocb");
        assert_eq!(
            recover(CV_GPG_OCB_MESSAGE, &cv_key(), &CV_GPG_OCB_CARD_OUTPUT)
                .unwrap()
                .tool_form()
                .as_str(),
            CV_GPG_OCB_SESSION_KEY
        );
    }

    #[test]
    fn a_wrong_card_answer_is_never_taken_for_a_session_key() {
        let mut rsa = RSA_SQ_CARD_OUTPUT;
        rsa[5] ^= 1;
        assert_eq!(
            recover(RSA_SQ_MESSAGE, &rsa_key(), &rsa),
            Err(DecryptError::Recovery)
        );
        let mut shared = CV_SQ_CARD_OUTPUT;
        shared[0] ^= 1;
        assert_eq!(
            recover(CV_SQ_MESSAGE, &cv_key(), &shared),
            Err(DecryptError::Recovery)
        );
        for bad in [&[][..], &[9], &[0x40; 31], &[0x41; 33]] {
            assert_eq!(
                recover(CV_SQ_MESSAGE, &cv_key(), bad),
                Err(DecryptError::Recovery)
            );
        }
    }

    #[test]
    fn a_message_for_another_key_names_both_key_ids() {
        let mut other = rsa_key();
        other.fingerprint = Some([0xAA; 20]);
        assert_eq!(
            recover(RSA_SQ_MESSAGE, &other, &RSA_SQ_CARD_OUTPUT),
            Err(DecryptError::NotForThisKey {
                message: "B407021995AE2021".into(),
                card: "AAAAAAAAAAAAAAAA".into(),
            })
        );
        let mut empty = rsa_key();
        empty.fingerprint = None;
        assert!(matches!(
            recover(RSA_SQ_MESSAGE, &empty, &RSA_SQ_CARD_OUTPUT),
            Err(DecryptError::Unsupported(_))
        ));
    }

    fn armor(data: &[u8]) -> String {
        format!(
            "-----BEGIN PGP MESSAGE-----\nComment: test\n\n{}\n={}\n-----END PGP MESSAGE-----\n",
            BASE64.encode(data),
            BASE64.encode(&crc24(data).to_be_bytes()[1..])
        )
    }

    fn rsa_pkesk(key_id: [u8; 8], ciphertext: &[u8]) -> Vec<u8> {
        let mut body = vec![3];
        body.extend_from_slice(&key_id);
        body.push(1);
        body.extend_from_slice(&((ciphertext.len() * 8) as u16).to_be_bytes());
        body.extend_from_slice(ciphertext);
        // Old-format header with a two-byte length.
        let mut packet = vec![0x85];
        packet.extend_from_slice(&(body.len() as u16).to_be_bytes());
        packet.extend_from_slice(&body);
        packet
    }

    #[test]
    fn anonymous_recipients_are_tried() {
        let mut data = rsa_pkesk([0; 8], &[0x80; 200]);
        data.extend_from_slice(&[0xD2, 0x02, 0x01, 0x00]);
        let message = parse_message(&data).unwrap();
        assert_eq!(message.data_format, DataFormat::SeipdV1);
        let pkesk = select(&message, &rsa_key()).unwrap();
        assert_eq!(pkesk.key_id, [0; 8]);
        assert_eq!(card_input(pkesk, &rsa_key()).unwrap().len(), 256);
    }

    #[test]
    fn armor_problems_are_reported() {
        assert_eq!(dearmor("hello"), Err(DecryptError::NotArmored));
        assert_eq!(
            dearmor("-----BEGIN PGP MESSAGE-----\n\nAAAA\n"),
            Err(DecryptError::NotArmored)
        );
        let good = armor(&rsa_pkesk([1; 8], &[0x80; 10]));
        assert!(dearmor(&good).is_ok(), "header lines are skipped");
        let damaged = good.replacen("AQEB", "AQEC", 1);
        assert_eq!(dearmor(&damaged), Err(DecryptError::BadChecksum));
        assert!(matches!(
            dearmor("-----BEGIN PGP MESSAGE-----\n\n!!!\n-----END PGP MESSAGE-----"),
            Err(DecryptError::Malformed(_))
        ));
        assert!(matches!(
            dearmor("-----BEGIN PGP MESSAGE-----junk\n\n-----END PGP MESSAGE-----"),
            Err(DecryptError::Malformed(_))
        ));
        // Without a checksum line the body is still read.
        let no_crc = format!(
            "-----BEGIN PGP MESSAGE-----\n\n{}\n-----END PGP MESSAGE-----",
            BASE64.encode([1, 2, 3])
        );
        assert_eq!(dearmor(&no_crc), Ok(vec![1, 2, 3]));
    }

    #[test]
    fn malformed_packets_are_refused() {
        for (data, what) in [
            (vec![0x00], "not a packet"),
            (vec![0xC1], "cut-short header"),
            (vec![0xC1, 0x05, 3, 0, 0], "cut-short PKESK"),
            (vec![0x84, 0x02, 3, 1], "cut-short old-format PKESK"),
            (
                rsa_pkesk([1; 8], &[0x80; 4])[..10].to_vec(),
                "cut-short key ID",
            ),
        ] {
            assert!(
                matches!(parse_message(&data), Err(DecryptError::Malformed(_))),
                "{what}"
            );
        }
        // An MPI longer than the packet.
        let mut bad_mpi = vec![0xC1, 12, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0x08, 0x00];
        bad_mpi.extend_from_slice(&[0; 0]);
        assert!(matches!(
            parse_message(&bad_mpi),
            Err(DecryptError::Malformed(_))
        ));
    }

    #[test]
    fn messages_without_a_usable_session_key_are_refused() {
        // Only encrypted data.
        assert_eq!(
            parse_message(&[0xD2, 0x01, 0x01]),
            Err(DecryptError::NoSessionKey)
        );
        // A version 6 PKESK is skipped.
        assert_eq!(
            parse_message(&[0xC1, 0x02, 6, 0, 0xD2, 0x01, 0x02]),
            Err(DecryptError::NoSessionKey)
        );
        // An unknown algorithm is listed but cannot be used.
        let mut body = vec![3];
        body.extend_from_slice(&RSA_FPR[12..]);
        body.push(22);
        let mut data = vec![0xC1, body.len() as u8];
        data.extend_from_slice(&body);
        let message = parse_message(&data).unwrap();
        let pkesk = select(&message, &rsa_key()).unwrap();
        assert!(matches!(
            card_input(pkesk, &rsa_key()),
            Err(DecryptError::Unsupported(_))
        ));
        assert!(matches!(
            session_key(pkesk, &rsa_key(), &[]),
            Err(DecryptError::Unsupported(_))
        ));
    }

    #[test]
    fn key_types_must_match_and_be_supported() {
        let message = parse_message(&dearmor(RSA_SQ_MESSAGE).unwrap()).unwrap();
        let pkesk = &message.pkesks[0];
        assert!(matches!(
            card_input(pkesk, &cv_key()),
            Err(DecryptError::Malformed(_))
        ));
        let mut nist = cv_key();
        nist.algorithm = Algorithm::Ecdh(Curve {
            oid: hex!("2a8648ce3d030107").to_vec(),
        });
        let message = parse_message(&dearmor(CV_SQ_MESSAGE).unwrap()).unwrap();
        assert!(matches!(
            card_input(&message.pkesks[0], &nist),
            Err(DecryptError::Unsupported(_))
        ));
        // A ciphertext longer than the modulus.
        let long = Pkesk {
            key_id: [0; 8],
            kind: PkeskKind::Rsa {
                ciphertext: vec![1; 257],
            },
        };
        assert!(matches!(
            card_input(&long, &rsa_key()),
            Err(DecryptError::Malformed(_))
        ));
    }

    #[test]
    fn data_formats_are_recognised() {
        let pkesk = rsa_pkesk([1; 8], &[0x80; 4]);
        for (data, format) in [
            (vec![0xD2, 0x01, 0x01], DataFormat::SeipdV1),
            (vec![0xD2, 0x01, 0x02], DataFormat::SeipdV2),
            (vec![0xD4, 0x01, 0x01], DataFormat::GnupgOcb),
            // Partial lengths, as gpg uses for long messages.
            (vec![0xD2, 0xE1, 0x01, 0x00], DataFormat::SeipdV1),
            (vec![0xD2, 0xE1, 0x02, 0x00], DataFormat::SeipdV2),
            (vec![0xD4, 0xE1, 0x01], DataFormat::GnupgOcb),
            (vec![0xC8, 0x01, 0x00], DataFormat::Unknown),
            // A data packet cut short still shows its type.
            (vec![0xD2, 0x10, 0x01], DataFormat::SeipdV1),
        ] {
            let message = parse_message(&[pkesk.clone(), data.clone()].concat()).unwrap();
            assert_eq!(message.data_format, format, "{data:02x?}");
        }
        // Marker and symmetric session key packets are skipped.
        let skipped = [&[0xCA, 0x03, b'P', b'G', b'P', 0xC3, 0x00][..], &pkesk].concat();
        assert_eq!(parse_message(&skipped).unwrap().pkesks.len(), 1);
    }

    #[test]
    fn recipient_count_is_bounded() {
        let one = rsa_pkesk([1; 8], &[0x80; 4]);
        let many: Vec<u8> = one.repeat(MAX_PKESKS + 1);
        assert!(matches!(
            parse_message(&many),
            Err(DecryptError::Malformed(_))
        ));
        assert_eq!(
            parse_message(&one.repeat(MAX_PKESKS)).unwrap().pkesks.len(),
            MAX_PKESKS
        );
    }

    #[test]
    fn session_key_checks() {
        // algorithm 7 (AES-128), 16 key bytes, checksum.
        let key = [1u8; 16];
        let mut data = vec![7];
        data.extend_from_slice(&key);
        data.extend_from_slice(&16u16.to_be_bytes());
        assert_eq!(checked_session_key(&data).unwrap().cipher_name(), "aes128");
        let mut wrong_len = data.clone();
        wrong_len[0] = 9;
        assert_eq!(checked_session_key(&wrong_len), Err(DecryptError::Recovery));
        let mut idea = data.clone();
        idea[0] = 1;
        assert_eq!(checked_session_key(&idea), Err(DecryptError::Recovery));
        assert_eq!(checked_session_key(&[7, 1]), Err(DecryptError::Recovery));
        assert_eq!(checked_session_key(&[]), Err(DecryptError::Recovery));
        let names: Vec<_> = (0..=14)
            .filter_map(symmetric_algorithm)
            .map(|(n, _)| n)
            .collect();
        assert_eq!(names.len(), 10);
    }

    #[test]
    fn pkcs5_padding_is_checked() {
        assert_eq!(remove_pkcs5_padding(&[9, 9, 3, 3, 3]), Ok(&[9, 9][..]));
        for bad in [&[][..], &[1, 0], &[1, 9], &[1, 2, 3], &[3, 3]] {
            assert_eq!(
                remove_pkcs5_padding(bad),
                Err(DecryptError::Recovery),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn session_keys_do_not_show_in_debug_output() {
        let session = SessionKey {
            algorithm: 9,
            key: Zeroizing::new(vec![0xAB; 32]),
        };
        assert!(!format!("{session:?}").contains("171"));
        assert!(!format!("{session:?}").to_lowercase().contains("ab, "));
    }
}
