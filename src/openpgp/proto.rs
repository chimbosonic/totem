//! OpenPGP card APDU builders and response parsers (OpenPGP card spec 3.4,
//! also accepted by version 2 applets such as the YubiKey NEO's).
//!
//! Everything here is pure. Only commands that use keys already on the card
//! are built; nothing generates, imports, or changes keys or PINs.

use std::fmt;

use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use super::tlv;
use crate::oath::tlv::TlvError;

/// OpenPGP application ID prefix (RID plus PIX up to the version). SELECT
/// with this matches the applet whatever its version and serial.
pub const AID_PREFIX: [u8; 6] = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];
/// Shortest PW1 the spec allows. Anything shorter is refused locally
/// instead of spending a retry on it.
pub const PW1_MIN_LEN: usize = 6;

const CLA: u8 = 0x00;
const CLA_CHAIN: u8 = 0x10;
const MAX_SHORT_DATA: usize = 255;

const INS_SELECT: u8 = 0xA4;
const INS_GET_DATA: u8 = 0xCA;
const INS_VERIFY: u8 = 0x20;
const INS_PSO: u8 = 0x2A;
const INS_INTERNAL_AUTHENTICATE: u8 = 0x88;
const INS_READ_PUBLIC_KEY: u8 = 0x47;
const INS_GET_RESPONSE: u8 = 0xC0;

pub const DO_APPLICATION_DATA: u16 = 0x6E;
pub const DO_SECURITY_SUPPORT: u16 = 0x7A;
pub const DO_PW_STATUS: u16 = 0xC4;
/// KDF-DO: how the card expects PINs to be hashed before VERIFY.
pub const DO_KDF: u16 = 0xF9;
const TAG_EXTENDED_CAPABILITIES: u16 = 0xC0;
/// Extended capabilities, first byte: the card has a KDF-DO.
const CAPABILITY_KDF: u8 = 0x01;
const TAG_KDF_ALGORITHM: u16 = 0x81;
const TAG_KDF_HASH: u16 = 0x82;
const TAG_KDF_COUNT: u16 = 0x83;
const TAG_KDF_PW1_SALT: u16 = 0x84;
const KDF_NONE: u8 = 0x00;
const KDF_ITERSALTED_S2K: u8 = 0x03;
const KDF_HASH_SHA256: u8 = 0x08;
const KDF_HASH_SHA512: u8 = 0x0A;
const TAG_AID: u16 = 0x4F;
const TAG_FINGERPRINTS: u16 = 0xC5;
const TAG_GENERATION_TIMES: u16 = 0xCD;
const TAG_SIGNATURE_COUNTER: u16 = 0x93;
const TAG_PUBLIC_KEY: u16 = 0x7F49;
const TAG_RSA_MODULUS: u16 = 0x81;
const TAG_RSA_EXPONENT: u16 = 0x82;
const TAG_EC_POINT: u16 = 0x86;
const TAG_CIPHER: u16 = 0xA6;

const SW_OK: u16 = 0x9000;
const SW_SECURITY_STATUS: u16 = 0x6982;
const SW_PIN_BLOCKED: u16 = 0x6983;
const SW_FILE_NOT_FOUND: u16 = 0x6A82;
const SW_DATA_NOT_FOUND: u16 = 0x6A88;

const ALGO_RSA: u8 = 0x01;
const ALGO_ECDH: u8 = 0x12;
const ALGO_ECDSA: u8 = 0x13;
const ALGO_EDDSA: u8 = 0x16;
/// Optional import-format byte some cards append to EC attributes.
const EC_IMPORT_FORMAT_PUBKEY: u8 = 0xFF;

/// Which command a status word belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Select,
    GetData,
    Verify,
    Sign,
    Decipher,
    Authenticate,
    ReadPublicKey,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PgpError {
    #[error("wrong PIN")]
    WrongPin,
    #[error("PIN is blocked")]
    PinBlocked,
    #[error("no OpenPGP applet on the card")]
    NotInstalled,
    #[error("PIN not verified")]
    NotVerified,
    #[error("referenced data not found")]
    NotFound,
    #[error("card returned status {0:#06x}")]
    Status(u16),
    #[error("malformed card response: {0}")]
    Malformed(&'static str),
    #[error("malformed card response: {0}")]
    Tlv(#[from] TlvError),
}

/// Map a non-success status word to a typed error.
pub fn status_error(command: Command, sw: u16) -> PgpError {
    match (command, sw) {
        (Command::Select, SW_FILE_NOT_FOUND) => PgpError::NotInstalled,
        // 63Cx carries the retries left; some applets send 6982 instead.
        (Command::Verify, SW_SECURITY_STATUS) => PgpError::WrongPin,
        (Command::Verify, sw) if sw & 0xFFF0 == 0x63C0 => PgpError::WrongPin,
        (_, SW_PIN_BLOCKED) => PgpError::PinBlocked,
        (_, SW_SECURITY_STATUS) => PgpError::NotVerified,
        (_, SW_DATA_NOT_FOUND) => PgpError::NotFound,
        (_, other) => PgpError::Status(other),
    }
}

/// The data if the status is `9000`, otherwise the typed error.
pub fn check_status(command: Command, data: Vec<u8>, sw: u16) -> Result<Vec<u8>, PgpError> {
    match sw {
        SW_OK => Ok(data),
        sw => Err(status_error(command, sw)),
    }
}

/// One of the three key slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeySlot {
    Sign,
    Decrypt,
    Auth,
}

impl KeySlot {
    pub const ALL: [KeySlot; 3] = [KeySlot::Sign, KeySlot::Decrypt, KeySlot::Auth];

    fn index(self) -> usize {
        match self {
            Self::Sign => 0,
            Self::Decrypt => 1,
            Self::Auth => 2,
        }
    }

    /// Control reference template tag naming the key in READ PUBLIC KEY.
    fn crt(self) -> u8 {
        match self {
            Self::Sign => 0xB6,
            Self::Decrypt => 0xB8,
            Self::Auth => 0xA4,
        }
    }

    /// User interaction flag (touch policy) data object.
    pub fn uif_tag(self) -> u16 {
        match self {
            Self::Sign => 0xD6,
            Self::Decrypt => 0xD7,
            Self::Auth => 0xD8,
        }
    }

    /// Algorithm attributes data object.
    fn attributes_tag(self) -> u16 {
        match self {
            Self::Sign => 0xC1,
            Self::Decrypt => 0xC2,
            Self::Auth => 0xC3,
        }
    }

    /// VERIFY reference: PW1 for signing (81), or for everything else (82).
    fn pin_reference(self) -> u8 {
        match self {
            Self::Sign => 0x81,
            Self::Decrypt | Self::Auth => 0x82,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Sign => "sign",
            Self::Decrypt => "decrypt",
            Self::Auth => "auth",
        }
    }
}

impl fmt::Display for KeySlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Short APDUs for one command, split with command chaining when the data
/// does not fit in one. Only the last carries `Le`, when `le` is set.
fn command(ins: u8, p1: u8, p2: u8, data: &[u8], le: bool) -> Vec<Vec<u8>> {
    let mut chunks: Vec<&[u8]> = data.chunks(MAX_SHORT_DATA).collect();
    if chunks.is_empty() {
        chunks.push(&[]);
    }
    let last = chunks.len() - 1;
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| {
            let cla = if i == last { CLA } else { CLA_CHAIN };
            let mut out = vec![cla, ins, p1, p2];
            if !chunk.is_empty() {
                out.push(chunk.len() as u8);
                out.extend_from_slice(chunk);
            }
            if le && i == last {
                out.push(0x00);
            }
            out
        })
        .collect()
}

fn single(apdus: Vec<Vec<u8>>) -> Vec<u8> {
    let [apdu] = <[Vec<u8>; 1]>::try_from(apdus).expect("command fits in one APDU");
    apdu
}

pub fn select_apdu() -> Vec<u8> {
    single(command(INS_SELECT, 0x04, 0x00, &AID_PREFIX, false))
}

pub fn get_data_apdu(tag: u16) -> Vec<u8> {
    let [p1, p2] = tag.to_be_bytes();
    single(command(INS_GET_DATA, p1, p2, &[], true))
}

/// ISO GET RESPONSE, sent after a `61xx` status for the rest of the data.
pub fn get_response_apdu() -> Vec<u8> {
    single(command(INS_GET_RESPONSE, 0x00, 0x00, &[], true))
}

/// VERIFY PW1 for using the key in `slot`. The APDU holds the PIN, so it is
/// wiped when dropped.
///
/// # Panics
///
/// If the PIN is longer than 255 bytes; callers check the length against
/// the card's maximum first.
pub fn verify_apdu(slot: KeySlot, pin: &[u8]) -> Zeroizing<Vec<u8>> {
    assert!(pin.len() <= MAX_SHORT_DATA, "PIN longer than one APDU");
    Zeroizing::new(single(command(
        INS_VERIFY,
        0x00,
        slot.pin_reference(),
        pin,
        false,
    )))
}

pub fn read_public_key_apdu(slot: KeySlot) -> Vec<u8> {
    single(command(
        INS_READ_PUBLIC_KEY,
        0x81,
        0x00,
        &[slot.crt(), 0x00],
        true,
    ))
}

/// PSO: COMPUTE DIGITAL SIGNATURE over `input` with the signing key.
pub fn sign_apdus(input: &[u8]) -> Vec<Vec<u8>> {
    command(INS_PSO, 0x9E, 0x9A, input, true)
}

/// PSO: DECIPHER `input` (see [`decipher_input`]) with the decryption key.
pub fn decipher_apdus(input: &[u8]) -> Vec<Vec<u8>> {
    command(INS_PSO, 0x80, 0x86, input, true)
}

/// INTERNAL AUTHENTICATE: sign `input` with the authentication key.
pub fn authenticate_apdus(input: &[u8]) -> Vec<Vec<u8>> {
    command(INS_INTERNAL_AUTHENTICATE, 0x00, 0x00, input, true)
}

/// PW status bytes (DO `C4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PwStatus {
    pub pw1_max_len: u8,
    pub pw1_retries: u8,
    pub rc_retries: u8,
    pub pw3_retries: u8,
}

pub fn parse_pw_status(value: &[u8]) -> Result<PwStatus, PgpError> {
    match *value {
        [
            _,
            pw1_max_len,
            _,
            _,
            pw1_retries,
            rc_retries,
            pw3_retries,
            ..,
        ] => Ok(PwStatus {
            pw1_max_len,
            pw1_retries,
            rc_retries,
            pw3_retries,
        }),
        _ => Err(PgpError::Malformed("PW status shorter than 7 bytes")),
    }
}

/// What a key slot's algorithm attributes say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Algorithm {
    Rsa { bits: u16 },
    Ecdh(Curve),
    Ecdsa(Curve),
    EdDsa(Curve),
    Unknown(u8),
}

impl Algorithm {
    /// Short name such as `rsa2048`, `nistp256`, or `ed25519`.
    pub fn name(&self) -> String {
        match self {
            Self::Rsa { bits } => format!("rsa{bits}"),
            Self::Ecdh(curve) | Self::Ecdsa(curve) | Self::EdDsa(curve) => curve.name(),
            Self::Unknown(id) => format!("unknown-{id:#04x}"),
        }
    }
}

/// An elliptic curve, by OID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Curve {
    pub oid: Vec<u8>,
}

const CURVES: [(&str, &[u8]); 10] = [
    (
        "nistp256",
        &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
    ),
    ("nistp384", &[0x2B, 0x81, 0x04, 0x00, 0x22]),
    ("nistp521", &[0x2B, 0x81, 0x04, 0x00, 0x23]),
    ("secp256k1", &[0x2B, 0x81, 0x04, 0x00, 0x0A]),
    (
        "brainpoolP256r1",
        &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07],
    ),
    (
        "brainpoolP384r1",
        &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B],
    ),
    (
        "brainpoolP512r1",
        &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D],
    ),
    (
        "ed25519",
        &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01],
    ),
    (
        "cv25519",
        &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01],
    ),
    ("ed448", &[0x2B, 0x65, 0x71]),
];

impl Curve {
    pub fn name(&self) -> String {
        CURVES
            .iter()
            .find(|(_, oid)| *oid == self.oid.as_slice())
            .map(|(name, _)| (*name).to_owned())
            .unwrap_or_else(|| {
                let hex: String = self.oid.iter().map(|b| format!("{b:02x}")).collect();
                format!("ecc-{hex}")
            })
    }
}

pub fn parse_algorithm(attributes: &[u8]) -> Result<Algorithm, PgpError> {
    let (&id, rest) = attributes
        .split_first()
        .ok_or(PgpError::Malformed("empty algorithm attributes"))?;
    let curve = || {
        let oid = match rest.split_last() {
            Some((&EC_IMPORT_FORMAT_PUBKEY, oid)) => oid,
            _ => rest,
        };
        if oid.is_empty() {
            return Err(PgpError::Malformed("EC algorithm attributes without OID"));
        }
        Ok(Curve { oid: oid.to_vec() })
    };
    Ok(match id {
        ALGO_RSA => {
            let bits = rest
                .first_chunk::<2>()
                .ok_or(PgpError::Malformed("RSA algorithm attributes too short"))?;
            Algorithm::Rsa {
                bits: u16::from_be_bytes(*bits),
            }
        }
        ALGO_ECDH => Algorithm::Ecdh(curve()?),
        ALGO_ECDSA => Algorithm::Ecdsa(curve()?),
        ALGO_EDDSA => Algorithm::EdDsa(curve()?),
        other => Algorithm::Unknown(other),
    })
}

/// What the card says about one key slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    pub slot: KeySlot,
    pub algorithm: Algorithm,
    /// `None` when the slot holds no key (all-zero fingerprint).
    pub fingerprint: Option<[u8; 20]>,
    /// Unix time the key was generated, if the card records it.
    pub created: Option<u32>,
}

/// Application related data (DO `6E`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationData {
    pub aid: Vec<u8>,
    pub keys: [KeyInfo; 3],
    pub pw_status: PwStatus,
    /// Whether the card has a KDF-DO (`F9`) that may require hashed PINs.
    pub kdf_supported: bool,
}

impl ApplicationData {
    /// Applet version from the AID, for example `3.4`.
    pub fn version(&self) -> String {
        match self.aid.get(6..8) {
            Some(&[major, minor]) => format!("{major:x}.{minor:x}"),
            _ => String::new(),
        }
    }

    /// Card serial from the AID, as 8 hex digits.
    pub fn serial(&self) -> String {
        self.aid
            .get(10..14)
            .map(|bytes| bytes.iter().map(|b| format!("{b:02X}")).collect())
            .unwrap_or_default()
    }

    pub fn key(&self, slot: KeySlot) -> &KeyInfo {
        &self.keys[slot.index()]
    }
}

fn required(data: &[u8], tag: u16, what: &'static str) -> Result<Vec<u8>, PgpError> {
    tlv::find(data, tag)?
        .map(<[u8]>::to_vec)
        .ok_or(PgpError::Malformed(what))
}

pub fn parse_application_data(data: &[u8]) -> Result<ApplicationData, PgpError> {
    let aid = required(data, TAG_AID, "application data without AID")?;
    let fingerprints = required(
        data,
        TAG_FINGERPRINTS,
        "application data without fingerprints",
    )?;
    let pw_status = parse_pw_status(&required(
        data,
        DO_PW_STATUS,
        "application data without PW status",
    )?)?;
    // Version 2 applets may leave out the generation times.
    let times = tlv::find(data, TAG_GENERATION_TIMES)?.unwrap_or_default();
    let (fingerprints, _) = fingerprints.as_chunks::<20>();
    if fingerprints.len() < 3 {
        return Err(PgpError::Malformed("fingerprints shorter than 60 bytes"));
    }
    let (times, _) = times.as_chunks::<4>();
    let mut keys = Vec::with_capacity(3);
    for slot in KeySlot::ALL {
        let i = slot.index();
        let attributes = required(
            data,
            slot.attributes_tag(),
            "application data without algorithm attributes",
        )?;
        keys.push(KeyInfo {
            slot,
            algorithm: parse_algorithm(&attributes)?,
            fingerprint: Some(fingerprints[i]).filter(|f| f.iter().any(|&b| b != 0)),
            created: times
                .get(i)
                .map(|t| u32::from_be_bytes(*t))
                .filter(|&t| t != 0),
        });
    }
    let keys = <[KeyInfo; 3]>::try_from(keys).expect("three key slots");
    // Version 2 cards have no KDF; their capability bit is reserved (0).
    let kdf_supported = tlv::find(data, TAG_EXTENDED_CAPABILITIES)?
        .and_then(|caps| caps.first())
        .is_some_and(|flags| flags & CAPABILITY_KDF != 0);
    Ok(ApplicationData {
        aid,
        keys,
        pw_status,
        kdf_supported,
    })
}

/// A key's touch policy (Yubico's user interaction flag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchPolicy {
    Off,
    On,
    Fixed,
    Cached,
    CachedFixed,
    Unknown(u8),
}

impl TouchPolicy {
    /// Whether using the key waits for a touch on the YubiKey.
    pub fn requires_touch(self) -> bool {
        self != Self::Off
    }

    pub fn name(self) -> String {
        match self {
            Self::Off => "off".into(),
            Self::On => "on".into(),
            Self::Fixed => "fixed".into(),
            Self::Cached => "cached".into(),
            Self::CachedFixed => "cached_fixed".into(),
            Self::Unknown(flag) => format!("unknown-{flag:#04x}"),
        }
    }
}

/// Parse a user interaction flag DO (`D6`, `D7`, `D8`).
pub fn parse_uif(value: &[u8]) -> Result<TouchPolicy, PgpError> {
    let flag = *value
        .first()
        .ok_or(PgpError::Malformed("empty user interaction flag"))?;
    Ok(match flag {
        0x00 => TouchPolicy::Off,
        0x01 => TouchPolicy::On,
        0x02 => TouchPolicy::Fixed,
        0x03 => TouchPolicy::Cached,
        0x04 => TouchPolicy::CachedFixed,
        other => TouchPolicy::Unknown(other),
    })
}

/// Hash used by the iterated and salted S2K PIN derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfHash {
    Sha256,
    Sha512,
}

/// How the card wants PW1 sent, from the KDF-DO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kdf {
    /// Send the PIN as is.
    None,
    /// Send the OpenPGP iterated and salted S2K hash of the PIN (RFC 4880
    /// section 3.7.1.3), hashing `count` bytes of salt and PIN repeated.
    IterSaltedS2k {
        hash: KdfHash,
        count: u32,
        pw1_salt: Vec<u8>,
    },
    /// A KDF this service does not implement. Never send the PIN.
    Unsupported { algorithm: u8, hash: Option<u8> },
}

/// Parse the KDF-DO, with or without its `F9` wrapper.
pub fn parse_kdf(data: &[u8]) -> Result<Kdf, PgpError> {
    let inner = match tlv::parse_all(data)?.as_slice() {
        [item] if item.tag == DO_KDF => item.value,
        _ => data,
    };
    let field = |tag| tlv::find(inner, tag);
    let algorithm = *field(TAG_KDF_ALGORITHM)?
        .and_then(|v| v.first())
        .ok_or(PgpError::Malformed("KDF-DO without algorithm"))?;
    match algorithm {
        KDF_NONE => return Ok(Kdf::None),
        KDF_ITERSALTED_S2K => {}
        other => {
            return Ok(Kdf::Unsupported {
                algorithm: other,
                hash: None,
            });
        }
    }
    let hash_id = *field(TAG_KDF_HASH)?
        .and_then(|v| v.first())
        .ok_or(PgpError::Malformed("KDF-DO without hash"))?;
    let hash = match hash_id {
        KDF_HASH_SHA256 => KdfHash::Sha256,
        KDF_HASH_SHA512 => KdfHash::Sha512,
        other => {
            return Ok(Kdf::Unsupported {
                algorithm,
                hash: Some(other),
            });
        }
    };
    let count = field(TAG_KDF_COUNT)?
        .and_then(|v| <[u8; 4]>::try_from(v).ok())
        .map(u32::from_be_bytes)
        .ok_or(PgpError::Malformed("KDF-DO without a 4 byte count"))?;
    let pw1_salt = field(TAG_KDF_PW1_SALT)?
        .filter(|salt| !salt.is_empty())
        .ok_or(PgpError::Malformed("KDF-DO without a PW1 salt"))?
        .to_vec();
    Ok(Kdf::IterSaltedS2k {
        hash,
        count,
        pw1_salt,
    })
}

/// The bytes to send in VERIFY for `pin` under `kdf`, wiped when dropped.
///
/// # Panics
///
/// For [`Kdf::Unsupported`]; callers refuse those before getting here.
pub fn kdf_pin(kdf: &Kdf, pin: &[u8]) -> Zeroizing<Vec<u8>> {
    match kdf {
        Kdf::None => Zeroizing::new(pin.to_vec()),
        Kdf::IterSaltedS2k {
            hash,
            count,
            pw1_salt,
        } => match hash {
            KdfHash::Sha256 => s2k::<Sha256>(pw1_salt, pin, *count),
            KdfHash::Sha512 => s2k::<Sha512>(pw1_salt, pin, *count),
        },
        Kdf::Unsupported { .. } => panic!("unsupported KDF reached kdf_pin"),
    }
}

/// RFC 4880 iterated and salted S2K: hash `salt || pin` repeated until
/// `count` bytes have been hashed, and at least once in full.
fn s2k<D: Digest>(salt: &[u8], pin: &[u8], count: u32) -> Zeroizing<Vec<u8>> {
    let data = Zeroizing::new([salt, pin].concat());
    let mut remaining = (count as usize).max(data.len());
    let mut hasher = D::new();
    while remaining > 0 {
        let n = remaining.min(data.len());
        hasher.update(&data[..n]);
        remaining -= n;
    }
    Zeroizing::new(hasher.finalize().to_vec())
}

/// Digital signature counter from the security support template (DO `7A`).
pub fn parse_signature_counter(data: &[u8]) -> Result<u32, PgpError> {
    let value = required(data, TAG_SIGNATURE_COUNTER, "no signature counter")?;
    match *value {
        [a, b, c] => Ok(u32::from_be_bytes([0, a, b, c])),
        _ => Err(PgpError::Malformed("signature counter is not 3 bytes")),
    }
}

/// A public key as READ PUBLIC KEY returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    Rsa { modulus: Vec<u8>, exponent: Vec<u8> },
    Ec { point: Vec<u8> },
}

pub fn parse_public_key(data: &[u8]) -> Result<PublicKey, PgpError> {
    let key = required(data, TAG_PUBLIC_KEY, "READ PUBLIC KEY without 7F49")?;
    if let Some(point) = tlv::find(&key, TAG_EC_POINT)? {
        return Ok(PublicKey::Ec {
            point: point.to_vec(),
        });
    }
    Ok(PublicKey::Rsa {
        modulus: required(&key, TAG_RSA_MODULUS, "RSA public key without modulus")?,
        exponent: required(&key, TAG_RSA_EXPONENT, "RSA public key without exponent")?,
    })
}

/// Hash a caller says produced a digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    pub fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// DER DigestInfo header that precedes the digest for RSA signatures.
    fn digest_info_prefix(self) -> &'static [u8] {
        match self {
            Self::Sha256 => &[
                0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            Self::Sha384 => &[
                0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            Self::Sha512 => &[
                0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }
}

/// Why caller input cannot be sent to the card.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InputError {
    #[error("digest length does not match the hash")]
    DigestLength,
    #[error("the key's algorithm is not supported for this operation")]
    UnsupportedAlgorithm,
    #[error("input is empty")]
    Empty,
}

/// The PSO: COMPUTE DIGITAL SIGNATURE input for `digest`: a DigestInfo for
/// RSA keys, the bare digest for ECDSA and EdDSA keys.
pub fn signature_input(
    algorithm: &Algorithm,
    hash: HashAlgorithm,
    digest: &[u8],
) -> Result<Vec<u8>, InputError> {
    if digest.len() != hash.digest_len() {
        return Err(InputError::DigestLength);
    }
    match algorithm {
        Algorithm::Rsa { .. } => Ok([hash.digest_info_prefix(), digest].concat()),
        Algorithm::Ecdsa(_) | Algorithm::EdDsa(_) => Ok(digest.to_vec()),
        Algorithm::Ecdh(_) | Algorithm::Unknown(_) => Err(InputError::UnsupportedAlgorithm),
    }
}

/// The PSO: DECIPHER input: for RSA the padding indicator byte and the
/// ciphertext, for ECDH the sender's ephemeral public point wrapped in the
/// cipher data object.
pub fn decipher_input(algorithm: &Algorithm, ciphertext: &[u8]) -> Result<Vec<u8>, InputError> {
    if ciphertext.is_empty() {
        return Err(InputError::Empty);
    }
    match algorithm {
        Algorithm::Rsa { .. } => Ok([&[0x00][..], ciphertext].concat()),
        Algorithm::Ecdh(_) => {
            let mut point = Vec::new();
            tlv::encode(&mut point, TAG_EC_POINT, ciphertext);
            let mut key = Vec::new();
            tlv::encode(&mut key, TAG_PUBLIC_KEY, &point);
            let mut out = Vec::new();
            tlv::encode(&mut out, TAG_CIPHER, &key);
            Ok(out)
        }
        Algorithm::Ecdsa(_) | Algorithm::EdDsa(_) | Algorithm::Unknown(_) => {
            Err(InputError::UnsupportedAlgorithm)
        }
    }
}

/// Fingerprint as 40 uppercase hex digits.
pub fn fingerprint_hex(fingerprint: &[u8; 20]) -> String {
    fingerprint.iter().map(|b| format!("{b:02X}")).collect()
}

/// Short, non-reversible tag for logging which input was processed, so
/// logs can correlate requests without holding the input itself.
pub fn input_tag(input: &[u8]) -> String {
    Sha256::digest(input)[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn select_get_data_and_get_response_bytes() {
        assert_eq!(select_apdu(), hex!("00a4040006d27600012401"));
        assert_eq!(get_data_apdu(DO_APPLICATION_DATA), hex!("00ca006e00"));
        assert_eq!(get_data_apdu(DO_PW_STATUS), hex!("00ca00c400"));
        assert_eq!(get_response_apdu(), hex!("00c0000000"));
    }

    #[test]
    fn verify_uses_81_for_signing_and_82_otherwise() {
        assert_eq!(
            verify_apdu(KeySlot::Sign, b"123456").as_slice(),
            hex!("0020008106313233343536")
        );
        assert_eq!(verify_apdu(KeySlot::Decrypt, b"123456")[3], 0x82);
        assert_eq!(verify_apdu(KeySlot::Auth, b"123456")[3], 0x82);
    }

    #[test]
    #[should_panic(expected = "longer than one APDU")]
    fn verify_refuses_oversized_pin() {
        verify_apdu(KeySlot::Sign, &[b'1'; 256]);
    }

    #[test]
    fn read_public_key_names_the_slot() {
        assert_eq!(
            read_public_key_apdu(KeySlot::Sign),
            hex!("0047810002b60000")
        );
        assert_eq!(
            read_public_key_apdu(KeySlot::Decrypt),
            hex!("0047810002b80000")
        );
        assert_eq!(
            read_public_key_apdu(KeySlot::Auth),
            hex!("0047810002a40000")
        );
    }

    #[test]
    fn short_operations_are_one_apdu_with_le() {
        assert_eq!(sign_apdus(&[1, 2]), vec![hex!("002a9e9a02010200").to_vec()]);
        assert_eq!(decipher_apdus(&[1]), vec![hex!("002a80860101 00").to_vec()]);
        assert_eq!(
            authenticate_apdus(&[9]),
            vec![hex!("00880000010900").to_vec()]
        );
    }

    #[test]
    fn long_input_is_split_with_command_chaining() {
        let input: Vec<u8> = (0..300u16).map(|i| i as u8).collect();
        let apdus = decipher_apdus(&input);
        assert_eq!(apdus.len(), 2);
        assert_eq!(apdus[0][..5], [0x10, 0x2A, 0x80, 0x86, 0xFF]);
        assert_eq!(apdus[0].len(), 5 + 255, "no Le on a chained part");
        assert_eq!(apdus[0][5..], input[..255]);
        assert_eq!(apdus[1][..5], [0x00, 0x2A, 0x80, 0x86, 45]);
        assert_eq!(apdus[1][5..50], input[255..]);
        assert_eq!(apdus[1][50..], [0x00]);
    }

    #[test]
    fn input_of_exactly_255_bytes_is_not_chained() {
        let apdus = sign_apdus(&[7; 255]);
        assert_eq!(apdus.len(), 1);
        assert_eq!(apdus[0][0], 0x00);
    }

    #[test]
    fn status_words_map_to_typed_errors() {
        assert_eq!(
            status_error(Command::Select, 0x6A82),
            PgpError::NotInstalled
        );
        assert_eq!(status_error(Command::Verify, 0x63C2), PgpError::WrongPin);
        assert_eq!(status_error(Command::Verify, 0x63C0), PgpError::WrongPin);
        assert_eq!(status_error(Command::Verify, 0x6982), PgpError::WrongPin);
        assert_eq!(status_error(Command::Verify, 0x6983), PgpError::PinBlocked);
        assert_eq!(status_error(Command::Sign, 0x6982), PgpError::NotVerified);
        assert_eq!(status_error(Command::Sign, 0x6983), PgpError::PinBlocked);
        assert_eq!(
            status_error(Command::ReadPublicKey, 0x6A88),
            PgpError::NotFound
        );
        assert_eq!(
            status_error(Command::GetData, 0x6A82),
            PgpError::Status(0x6A82)
        );
        assert_eq!(
            status_error(Command::Decipher, 0x63C1),
            PgpError::Status(0x63C1)
        );
    }

    #[test]
    fn check_status_passes_data_on_9000_only() {
        assert_eq!(check_status(Command::Sign, vec![1], 0x9000), Ok(vec![1]));
        assert_eq!(
            check_status(Command::Sign, vec![1], 0x6982),
            Err(PgpError::NotVerified)
        );
    }

    #[test]
    fn pw_status_parses_lengths_and_counters() {
        assert_eq!(
            parse_pw_status(&hex!("0120 2020 030003")).unwrap(),
            PwStatus {
                pw1_max_len: 0x20,
                pw1_retries: 3,
                rc_retries: 0,
                pw3_retries: 3,
            }
        );
        assert!(matches!(
            parse_pw_status(&hex!("01202020 0300")),
            Err(PgpError::Malformed(_))
        ));
    }

    #[test]
    fn algorithm_attributes_parse() {
        assert_eq!(
            parse_algorithm(&hex!("010800002000")).unwrap(),
            Algorithm::Rsa { bits: 2048 }
        );
        let ed = parse_algorithm(&hex!("16 2b06010401da470f01")).unwrap();
        assert_eq!(ed.name(), "ed25519");
        assert!(matches!(ed, Algorithm::EdDsa(_)));
        let p256 = parse_algorithm(&hex!("13 2a8648ce3d030107 ff")).unwrap();
        assert_eq!(p256.name(), "nistp256", "import format byte is ignored");
        let cv = parse_algorithm(&hex!("12 2b060104019755010501")).unwrap();
        assert!(matches!(cv, Algorithm::Ecdh(_)));
        assert_eq!(cv.name(), "cv25519");
        assert_eq!(
            parse_algorithm(&hex!("13 2b0102")).unwrap().name(),
            "ecc-2b0102"
        );
        assert_eq!(parse_algorithm(&[0x42]).unwrap().name(), "unknown-0x42");
        assert_eq!(Algorithm::Rsa { bits: 4096 }.name(), "rsa4096");
    }

    #[test]
    fn malformed_algorithm_attributes_are_errors() {
        for bad in [&[][..], &[0x01, 0x08], &[0x13], &[0x13, 0xFF]] {
            assert!(
                matches!(parse_algorithm(bad), Err(PgpError::Malformed(_))),
                "{bad:02x?}"
            );
        }
    }

    /// Application related data as a YubiKey returns it: a signing key and
    /// an authentication key, no decryption key.
    fn sample_application_data() -> Vec<u8> {
        let mut discretionary = Vec::new();
        tlv::encode(&mut discretionary, 0xC1, &hex!("010800002000"));
        tlv::encode(&mut discretionary, 0xC2, &hex!("010800002000"));
        tlv::encode(&mut discretionary, 0xC3, &hex!("16 2b06010401da470f01"));
        tlv::encode(&mut discretionary, 0xC4, &hex!("0120 2020 030003"));
        let mut fingerprints = vec![0xAB; 20];
        fingerprints.extend_from_slice(&[0; 20]);
        fingerprints.extend_from_slice(&[0xCD; 20]);
        tlv::encode(&mut discretionary, 0xC5, &fingerprints);
        tlv::encode(&mut discretionary, 0xC6, &[0; 60]);
        tlv::encode(
            &mut discretionary,
            0xCD,
            &hex!("5f000000 00000000 60000000"),
        );
        let mut inner = Vec::new();
        tlv::encode(&mut inner, 0x4F, &hex!("d2760001240103040006123456780000"));
        tlv::encode(&mut inner, 0x5F52, &hex!("0073000080059000"));
        tlv::encode(&mut inner, 0x73, &discretionary);
        let mut out = Vec::new();
        tlv::encode(&mut out, 0x6E, &inner);
        out
    }

    #[test]
    fn application_data_parses() {
        let data = parse_application_data(&sample_application_data()).unwrap();
        assert_eq!(data.version(), "3.4");
        assert_eq!(data.serial(), "12345678");
        assert_eq!(data.pw_status.pw1_retries, 3);
        let sign = data.key(KeySlot::Sign);
        assert_eq!(sign.algorithm, Algorithm::Rsa { bits: 2048 });
        assert_eq!(sign.fingerprint, Some([0xAB; 20]));
        assert_eq!(sign.created, Some(0x5F00_0000));
        let decrypt = data.key(KeySlot::Decrypt);
        assert_eq!(decrypt.fingerprint, None);
        assert_eq!(decrypt.created, None);
        let auth = data.key(KeySlot::Auth);
        assert_eq!(auth.algorithm.name(), "ed25519");
        assert_eq!(auth.created, Some(0x6000_0000));
    }

    #[test]
    fn application_data_without_generation_times_has_no_dates() {
        let full = sample_application_data();
        // Rebuild without CD by filtering the discretionary objects.
        let disc = tlv::find(&full, 0x73).unwrap().unwrap();
        let mut stripped = Vec::new();
        for item in tlv::parse_all(disc).unwrap() {
            if item.tag != 0xCD {
                tlv::encode(&mut stripped, item.tag, item.value);
            }
        }
        let mut data = Vec::new();
        tlv::encode(&mut data, 0x4F, &hex!("d2760001240102000006123456780000"));
        tlv::encode(&mut data, 0x73, &stripped);
        let parsed = parse_application_data(&data).unwrap();
        assert_eq!(parsed.version(), "2.0");
        assert!(parsed.keys.iter().all(|k| k.created.is_none()));
    }

    #[test]
    fn application_data_missing_parts_is_malformed() {
        assert!(matches!(
            parse_application_data(&hex!("6e00")),
            Err(PgpError::Malformed(_))
        ));
        let mut short = Vec::new();
        tlv::encode(&mut short, 0x4F, &[0xD2]);
        tlv::encode(&mut short, 0xC4, &hex!("0120 2020 030003"));
        tlv::encode(&mut short, 0xC5, &[1; 40]);
        assert!(matches!(
            parse_application_data(&short),
            Err(PgpError::Malformed("fingerprints shorter than 60 bytes"))
        ));
    }

    #[test]
    fn short_aid_gives_empty_version_and_serial() {
        let mut data = parse_application_data(&sample_application_data()).unwrap();
        data.aid = vec![0xD2];
        assert_eq!(data.version(), "");
        assert_eq!(data.serial(), "");
    }

    #[test]
    fn kdf_capability_comes_from_extended_capabilities() {
        assert!(
            !parse_application_data(&sample_application_data())
                .unwrap()
                .kdf_supported,
            "no C0 means no KDF"
        );
        let with_caps = |flags: u8| {
            let mut data = sample_application_data();
            let mut caps = Vec::new();
            tlv::encode(
                &mut caps,
                0xC0,
                &[flags, 0, 0, 0xFF, 0, 0xFF, 0, 0xFF, 0, 0],
            );
            data.extend_from_slice(&caps);
            parse_application_data(&data).unwrap().kdf_supported
        };
        assert!(with_caps(0x7D));
        assert!(!with_caps(0x7C));
    }

    #[test]
    fn touch_policies_parse() {
        for (flag, policy, name) in [
            (0x00, TouchPolicy::Off, "off"),
            (0x01, TouchPolicy::On, "on"),
            (0x02, TouchPolicy::Fixed, "fixed"),
            (0x03, TouchPolicy::Cached, "cached"),
            (0x04, TouchPolicy::CachedFixed, "cached_fixed"),
            (0x09, TouchPolicy::Unknown(9), "unknown-0x09"),
        ] {
            let parsed = parse_uif(&[flag, 0x20]).unwrap();
            assert_eq!(parsed, policy);
            assert_eq!(parsed.name(), name);
            assert_eq!(parsed.requires_touch(), flag != 0);
        }
        assert!(matches!(parse_uif(&[]), Err(PgpError::Malformed(_))));
        assert_eq!(KeySlot::Sign.uif_tag(), 0xD6);
        assert_eq!(KeySlot::Decrypt.uif_tag(), 0xD7);
        assert_eq!(KeySlot::Auth.uif_tag(), 0xD8);
    }

    fn kdf_do(algorithm: u8, hash: u8, count: u32, salt: &[u8]) -> Vec<u8> {
        let mut inner = Vec::new();
        tlv::encode(&mut inner, 0x81, &[algorithm]);
        tlv::encode(&mut inner, 0x82, &[hash]);
        tlv::encode(&mut inner, 0x83, &count.to_be_bytes());
        tlv::encode(&mut inner, 0x84, salt);
        tlv::encode(&mut inner, 0x85, &[9; 8]);
        tlv::encode(&mut inner, 0x86, &[7; 8]);
        let mut out = Vec::new();
        tlv::encode(&mut out, DO_KDF, &inner);
        out
    }

    #[test]
    fn kdf_do_parses_with_or_without_wrapper() {
        let salt = hex!("0102030405060708");
        let expected = Kdf::IterSaltedS2k {
            hash: KdfHash::Sha256,
            count: 100_000,
            pw1_salt: salt.to_vec(),
        };
        let wrapped = kdf_do(0x03, 0x08, 100_000, &salt);
        assert_eq!(parse_kdf(&wrapped).unwrap(), expected);
        let bare = tlv::find(&wrapped, DO_KDF).unwrap().unwrap();
        assert_eq!(parse_kdf(bare).unwrap(), expected);
        assert_eq!(parse_kdf(&hex!("f903 810100")).unwrap(), Kdf::None);
        assert_eq!(parse_kdf(&hex!("810100")).unwrap(), Kdf::None);
    }

    #[test]
    fn unknown_kdf_or_hash_is_unsupported() {
        assert_eq!(
            parse_kdf(&hex!("810107")).unwrap(),
            Kdf::Unsupported {
                algorithm: 7,
                hash: None
            }
        );
        assert_eq!(
            parse_kdf(&kdf_do(0x03, 0x02, 10, &[1; 8])).unwrap(),
            Kdf::Unsupported {
                algorithm: 3,
                hash: Some(2)
            }
        );
    }

    #[test]
    fn malformed_kdf_do_is_an_error() {
        for bad in [
            hex!("f900").to_vec(),
            hex!("810103").to_vec(),
            hex!("810103 820108").to_vec(),
            hex!("810103 820108 830200ff").to_vec(),
            hex!("810103 820108 830400000010").to_vec(),
            hex!("810103 820108 830400000010 8400").to_vec(),
        ] {
            assert!(
                matches!(parse_kdf(&bad), Err(PgpError::Malformed(_))),
                "{bad:02x?}"
            );
        }
    }

    // Expected hashes from an independent Python hashlib implementation of
    // RFC 4880 section 3.7.1.3 (see AGENT.md).
    #[test]
    fn s2k_matches_reference_vectors() {
        let salt = hex!("0102030405060708").to_vec();
        let kdf = |hash, count| Kdf::IterSaltedS2k {
            hash,
            count,
            pw1_salt: salt.clone(),
        };
        assert_eq!(
            kdf_pin(&kdf(KdfHash::Sha256, 100_000), b"123456").as_slice(),
            hex!("8fc77436ded3825377da921acc4fb1e0c619e426b926c30f06fbb428c6ac9701")
        );
        // 20 bytes: one full copy of salt || PIN, then 6 bytes of the next.
        assert_eq!(
            kdf_pin(&kdf(KdfHash::Sha256, 20), b"123456").as_slice(),
            hex!("55afbadca2968df8494c1f80aa85cb18996a4217e33b206b0ec65319e329ad3f")
        );
        // A count below the data length still hashes it once in full.
        assert_eq!(
            kdf_pin(&kdf(KdfHash::Sha512, 5), b"123456").as_slice(),
            hex!(
                "aac09812feb262c34917f3a810ab49c573a2b840a31883a916107074d377ada7"
                "7652a290f43ea00ba634235dc6220d40b6a9e86a346af967906ef3ac51a4bee1"
            )
        );
    }

    #[test]
    fn no_kdf_sends_the_pin_as_is() {
        assert_eq!(kdf_pin(&Kdf::None, b"123456").as_slice(), b"123456");
    }

    #[test]
    #[should_panic(expected = "unsupported KDF")]
    fn kdf_pin_refuses_unsupported_kdf() {
        kdf_pin(
            &Kdf::Unsupported {
                algorithm: 7,
                hash: None,
            },
            b"123456",
        );
    }

    #[test]
    fn signature_counter_parses() {
        assert_eq!(parse_signature_counter(&hex!("7a05 9303000102")), Ok(258));
        assert!(matches!(
            parse_signature_counter(&hex!("7a04 93020001")),
            Err(PgpError::Malformed(_))
        ));
        assert!(matches!(
            parse_signature_counter(&hex!("7a00")),
            Err(PgpError::Malformed(_))
        ));
    }

    #[test]
    fn public_keys_parse() {
        assert_eq!(
            parse_public_key(&hex!("7f49 08 8102aabb 8202 0101")).unwrap(),
            PublicKey::Rsa {
                modulus: vec![0xAA, 0xBB],
                exponent: vec![0x01, 0x01],
            }
        );
        assert_eq!(
            parse_public_key(&hex!("7f49 04 8602 0405")).unwrap(),
            PublicKey::Ec { point: vec![4, 5] }
        );
        assert!(matches!(
            parse_public_key(&hex!("7f49 04 8102 aabb")),
            Err(PgpError::Malformed(_))
        ));
        assert!(matches!(
            parse_public_key(&hex!("8102aabb")),
            Err(PgpError::Malformed(_))
        ));
    }

    #[test]
    fn rsa_signature_input_is_a_digest_info() {
        let rsa = Algorithm::Rsa { bits: 2048 };
        let input = signature_input(&rsa, HashAlgorithm::Sha256, &[0x11; 32]).unwrap();
        assert_eq!(input[..19], hex!("3031300d060960864801650304020105000420"));
        assert_eq!(input[19..], [0x11; 32]);
        assert_eq!(input.len(), 51);
        let input = signature_input(&rsa, HashAlgorithm::Sha384, &[0; 48]).unwrap();
        assert_eq!(input[..19], hex!("3041300d060960864801650304020205000430"));
        let input = signature_input(&rsa, HashAlgorithm::Sha512, &[0; 64]).unwrap();
        assert_eq!(input[..19], hex!("3051300d060960864801650304020305000440"));
    }

    #[test]
    fn ec_signature_input_is_the_digest() {
        let curve = Curve {
            oid: hex!("2a8648ce3d030107").to_vec(),
        };
        for algorithm in [
            Algorithm::Ecdsa(curve.clone()),
            Algorithm::EdDsa(curve.clone()),
        ] {
            assert_eq!(
                signature_input(&algorithm, HashAlgorithm::Sha256, &[3; 32]),
                Ok(vec![3; 32])
            );
        }
        assert_eq!(
            signature_input(&Algorithm::Ecdh(curve), HashAlgorithm::Sha256, &[3; 32]),
            Err(InputError::UnsupportedAlgorithm)
        );
        assert_eq!(
            signature_input(&Algorithm::Unknown(9), HashAlgorithm::Sha256, &[3; 32]),
            Err(InputError::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn signature_input_checks_digest_length() {
        let rsa = Algorithm::Rsa { bits: 2048 };
        assert_eq!(
            signature_input(&rsa, HashAlgorithm::Sha256, &[0; 31]),
            Err(InputError::DigestLength)
        );
        assert_eq!(
            signature_input(&rsa, HashAlgorithm::Sha512, &[0; 32]),
            Err(InputError::DigestLength)
        );
    }

    #[test]
    fn decipher_input_wraps_by_algorithm() {
        assert_eq!(
            decipher_input(&Algorithm::Rsa { bits: 2048 }, &[1, 2]),
            Ok(vec![0, 1, 2])
        );
        let cv = Algorithm::Ecdh(Curve {
            oid: hex!("2b060104019755010501").to_vec(),
        });
        assert_eq!(
            decipher_input(&cv, &[4, 5]),
            Ok(hex!("a6 07 7f49 04 8602 0405").to_vec())
        );
        let ed = Algorithm::EdDsa(Curve { oid: vec![1] });
        assert_eq!(
            decipher_input(&ed, &[1]),
            Err(InputError::UnsupportedAlgorithm)
        );
        assert_eq!(
            decipher_input(&Algorithm::Rsa { bits: 2048 }, &[]),
            Err(InputError::Empty)
        );
    }

    #[test]
    fn fingerprint_and_input_tag_format() {
        assert_eq!(fingerprint_hex(&[0xAB; 20]), "AB".repeat(20));
        assert_eq!(input_tag(b"abc"), "ba7816bf");
    }

    #[test]
    fn slot_names_and_display() {
        assert_eq!(KeySlot::Sign.to_string(), "sign");
        assert_eq!(KeySlot::Decrypt.name(), "decrypt");
        assert_eq!(KeySlot::Auth.name(), "auth");
    }
}
