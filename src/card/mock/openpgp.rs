//! In-memory OpenPGP card applet for tests, routed to by [`super::MockCard`]
//! after an OpenPGP SELECT.
//!
//! Implements GET DATA (`6E`, `7A`, `C4`, the KDF-DO `F9`, and the touch
//! policies `D6` to `D8`), VERIFY with a retry counter and optional KDF,
//! PSO: COMPUTE DIGITAL SIGNATURE, PSO: DECIPHER, INTERNAL AUTHENTICATE,
//! and READ PUBLIC KEY. There is no real cryptography: outputs are
//! deterministic hashes of the key seed and input, which tests recompute
//! with [`MockKey::signature`] and [`MockKey::plaintext`].
//!
//! A key with a touch policy refuses to be used (`6985`), standing in for a
//! real card waiting for a touch nobody gives.
//!
//! Not emulated: key generation and import, PIN changes, and the reset code.

use sha2::{Digest, Sha256, Sha512};

use crate::openpgp::proto::{AID_PREFIX, Kdf, KdfHash, KeySlot, kdf_pin};
use crate::openpgp::tlv;

const SW_SECURITY_STATUS: u16 = 0x6982;
const SW_PIN_BLOCKED: u16 = 0x6983;
const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
const SW_WRONG_DATA: u16 = 0x6A80;
const SW_DATA_NOT_FOUND: u16 = 0x6A88;
const SW_WRONG_P1P2: u16 = 0x6B00;
const SW_INS_NOT_SUPPORTED: u16 = 0x6D00;

pub(super) const INS_GET_RESPONSE: u8 = 0xC0;
const INS_GET_DATA: u8 = 0xCA;
const INS_VERIFY: u8 = 0x20;
const INS_PSO: u8 = 0x2A;
const INS_INTERNAL_AUTHENTICATE: u8 = 0x88;
const INS_READ_PUBLIC_KEY: u8 = 0x47;

/// Retries PW1 starts with, as on a fresh card.
pub const DEFAULT_PIN_RETRIES: u8 = 3;
const PW1_MAX_LEN: u8 = 127;

const RSA_2048_ATTRIBUTES: [u8; 6] = [0x01, 0x08, 0x00, 0x00, 0x20, 0x00];
const ED25519_ATTRIBUTES: [u8; 10] = [0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
const CV25519_ATTRIBUTES: [u8; 11] = [
    0x12, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MockKeyKind {
    Rsa2048,
    Ed25519,
    Cv25519,
}

/// A key in one slot. Its "public key" and outputs derive from `seed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockKey {
    kind: MockKeyKind,
    seed: Vec<u8>,
    pub created: u32,
}

impl MockKey {
    pub fn rsa2048(seed: &[u8]) -> Self {
        Self {
            kind: MockKeyKind::Rsa2048,
            seed: seed.to_vec(),
            created: 1_600_000_000,
        }
    }

    pub fn ed25519(seed: &[u8]) -> Self {
        Self {
            kind: MockKeyKind::Ed25519,
            ..Self::rsa2048(seed)
        }
    }

    pub fn cv25519(seed: &[u8]) -> Self {
        Self {
            kind: MockKeyKind::Cv25519,
            ..Self::rsa2048(seed)
        }
    }

    pub fn attributes(&self) -> &'static [u8] {
        match self.kind {
            MockKeyKind::Rsa2048 => &RSA_2048_ATTRIBUTES,
            MockKeyKind::Ed25519 => &ED25519_ATTRIBUTES,
            MockKeyKind::Cv25519 => &CV25519_ATTRIBUTES,
        }
    }

    pub fn fingerprint(&self) -> [u8; 20] {
        let digest = Sha256::new()
            .chain_update(b"fingerprint")
            .chain_update(&self.seed)
            .finalize();
        digest[..20].try_into().expect("20 bytes")
    }

    fn stretch(&self, label: &[u8], input: &[u8], len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut counter = 0u32;
        while out.len() < len {
            out.extend_from_slice(
                &Sha512::new()
                    .chain_update(label)
                    .chain_update(&self.seed)
                    .chain_update(counter.to_be_bytes())
                    .chain_update(input)
                    .finalize(),
            );
            counter += 1;
        }
        out.truncate(len);
        out
    }

    /// RSA modulus or EC point.
    pub fn public_value(&self) -> Vec<u8> {
        match self.kind {
            MockKeyKind::Rsa2048 => self.stretch(b"modulus", &[], 256),
            MockKeyKind::Ed25519 | MockKeyKind::Cv25519 => {
                let mut point = vec![0x40];
                point.extend(self.stretch(b"point", &[], 32));
                point
            }
        }
    }

    /// What the card answers to a signature or authentication over `input`.
    pub fn signature(&self, input: &[u8]) -> Vec<u8> {
        let len = match self.kind {
            MockKeyKind::Rsa2048 => 256,
            MockKeyKind::Ed25519 | MockKeyKind::Cv25519 => 64,
        };
        self.stretch(b"signature", input, len)
    }

    /// What the card answers to a decipher of `input`.
    pub fn plaintext(&self, input: &[u8]) -> Vec<u8> {
        self.stretch(b"plaintext", input, 32)
    }
}

#[derive(Debug)]
pub struct MockOpenPgp {
    pin: Vec<u8>,
    pin_retries: u8,
    wrong_pin_sw_6982: bool,
    keys: [Option<MockKey>; 3],
    signature_counter: u32,
    verified_sign: bool,
    verified_other: bool,
    serial: [u8; 4],
    kdf_capable: bool,
    kdf: Kdf,
    uif_supported: bool,
    touch: [u8; 3],
}

impl MockOpenPgp {
    /// Serial number used in the AID.
    pub const SERIAL: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
    /// Version encoded in the AID.
    pub const VERSION: [u8; 2] = [0x03, 0x04];

    pub fn new(pin: &str) -> Self {
        Self {
            pin: pin.as_bytes().to_vec(),
            pin_retries: DEFAULT_PIN_RETRIES,
            wrong_pin_sw_6982: false,
            keys: [None, None, None],
            signature_counter: 0,
            verified_sign: false,
            verified_other: false,
            serial: Self::SERIAL,
            kdf_capable: true,
            kdf: Kdf::None,
            uif_supported: true,
            touch: [0; 3],
        }
    }

    /// Expect PINs hashed with `kdf`, as a card after `gpg --card-edit`
    /// then `kdf-setup`.
    pub fn with_kdf(mut self, kdf: Kdf) -> Self {
        self.kdf = kdf;
        self
    }

    /// Behave like a version 2 card: no KDF capability and no KDF-DO.
    pub fn without_kdf_do(mut self) -> Self {
        self.kdf_capable = false;
        self
    }

    /// Give the key in `slot` a touch policy (user interaction flag).
    pub fn with_touch(mut self, slot: KeySlot, flag: u8) -> Self {
        self.touch[slot_index(slot)] = flag;
        self
    }

    /// Answer GET DATA for the touch policies with "not found", as cards
    /// without them do.
    pub fn without_uif(mut self) -> Self {
        self.uif_supported = false;
        self
    }

    pub fn with_key(mut self, slot: KeySlot, key: MockKey) -> Self {
        self.keys[slot_index(slot)] = Some(key);
        self
    }

    pub fn with_pin_retries(mut self, retries: u8) -> Self {
        self.pin_retries = retries;
        self
    }

    /// Answer a wrong VERIFY with 6982 instead of 63Cx, as some applets do.
    pub fn with_wrong_pin_status_6982(mut self) -> Self {
        self.wrong_pin_sw_6982 = true;
        self
    }

    pub fn pin_retries(&self) -> u8 {
        self.pin_retries
    }

    pub fn signature_counter(&self) -> u32 {
        self.signature_counter
    }

    /// Forget PIN verification, as SELECT, reset, or removal does.
    pub(super) fn reset_verification(&mut self) {
        self.verified_sign = false;
        self.verified_other = false;
    }

    pub(super) fn aid(&self) -> Vec<u8> {
        let mut aid = AID_PREFIX.to_vec();
        aid.extend_from_slice(&Self::VERSION);
        aid.extend_from_slice(&[0x00, 0x06]);
        aid.extend_from_slice(&self.serial);
        aid.extend_from_slice(&[0x00, 0x00]);
        aid
    }

    pub(super) fn handle(&mut self, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Result<Vec<u8>, u16> {
        match (ins, p1, p2) {
            (INS_GET_DATA, _, _) => self.get_data(u16::from_be_bytes([p1, p2])),
            (INS_VERIFY, 0x00, 0x81 | 0x82) => self.verify(p2, data),
            (INS_PSO, 0x9E, 0x9A) => self.sign(data),
            (INS_PSO, 0x80, 0x86) => self.decipher(data),
            (INS_INTERNAL_AUTHENTICATE, 0x00, 0x00) => self.authenticate(data),
            (INS_READ_PUBLIC_KEY, 0x81, 0x00) => self.read_public_key(data),
            (INS_VERIFY | INS_PSO | INS_READ_PUBLIC_KEY, _, _) => Err(SW_WRONG_P1P2),
            _ => Err(SW_INS_NOT_SUPPORTED),
        }
    }

    fn pw_status(&self) -> [u8; 7] {
        [
            0x00,
            PW1_MAX_LEN,
            PW1_MAX_LEN,
            PW1_MAX_LEN,
            self.pin_retries,
            0,
            3,
        ]
    }

    fn get_data(&self, tag: u16) -> Result<Vec<u8>, u16> {
        let mut out = Vec::new();
        match tag {
            0x6E => {
                let mut disc = Vec::new();
                for (i, tag) in [0xC1, 0xC2, 0xC3].into_iter().enumerate() {
                    let attributes = self.keys[i]
                        .as_ref()
                        .map_or(&RSA_2048_ATTRIBUTES[..], MockKey::attributes);
                    tlv::encode(&mut disc, tag, attributes);
                }
                tlv::encode(&mut disc, 0xC4, &self.pw_status());
                let mut fingerprints = Vec::new();
                let mut times = Vec::new();
                for key in &self.keys {
                    match key {
                        Some(key) => {
                            fingerprints.extend_from_slice(&key.fingerprint());
                            times.extend_from_slice(&key.created.to_be_bytes());
                        }
                        None => {
                            fingerprints.extend_from_slice(&[0; 20]);
                            times.extend_from_slice(&[0; 4]);
                        }
                    }
                }
                tlv::encode(&mut disc, 0xC5, &fingerprints);
                tlv::encode(&mut disc, 0xC6, &[0; 60]);
                tlv::encode(&mut disc, 0xCD, &times);
                let mut inner = Vec::new();
                tlv::encode(&mut inner, 0x4F, &self.aid());
                let flags = if self.kdf_capable { 0x7D } else { 0x7C };
                tlv::encode(
                    &mut disc,
                    0xC0,
                    &[flags, 0, 0, 0xFF, 0, 0xFF, 0, 0xFF, 0, 0],
                );
                tlv::encode(&mut inner, 0x73, &disc);
                tlv::encode(&mut out, 0x6E, &inner);
            }
            0x7A => {
                let mut inner = Vec::new();
                tlv::encode(&mut inner, 0x93, &self.signature_counter.to_be_bytes()[1..]);
                tlv::encode(&mut out, 0x7A, &inner);
            }
            0xC4 => out.extend_from_slice(&self.pw_status()),
            0xF9 if self.kdf_capable => {
                let mut inner = Vec::new();
                match &self.kdf {
                    Kdf::None => tlv::encode(&mut inner, 0x81, &[0x00]),
                    Kdf::IterSaltedS2k {
                        hash,
                        count,
                        pw1_salt,
                    } => {
                        let hash = match hash {
                            KdfHash::Sha256 => 0x08,
                            KdfHash::Sha512 => 0x0A,
                        };
                        tlv::encode(&mut inner, 0x81, &[0x03]);
                        tlv::encode(&mut inner, 0x82, &[hash]);
                        tlv::encode(&mut inner, 0x83, &count.to_be_bytes());
                        tlv::encode(&mut inner, 0x84, pw1_salt);
                    }
                    Kdf::Unsupported { algorithm, hash } => {
                        tlv::encode(&mut inner, 0x81, &[*algorithm]);
                        if let Some(hash) = hash {
                            tlv::encode(&mut inner, 0x82, &[*hash]);
                        }
                    }
                }
                tlv::encode(&mut out, 0xF9, &inner);
            }
            0xD6..=0xD8 if self.uif_supported => {
                out.extend_from_slice(&[self.touch[usize::from(tag as u8 - 0xD6)], 0x20]);
            }
            _ => return Err(SW_DATA_NOT_FOUND),
        }
        Ok(out)
    }

    fn verify(&mut self, reference: u8, pin: &[u8]) -> Result<Vec<u8>, u16> {
        if self.pin_retries == 0 {
            return Err(SW_PIN_BLOCKED);
        }
        let expected = match &self.kdf {
            Kdf::Unsupported { .. } => self.pin.clone(),
            kdf => kdf_pin(kdf, &self.pin).to_vec(),
        };
        if pin != expected {
            self.pin_retries -= 1;
            self.reset_verification();
            return Err(if self.wrong_pin_sw_6982 {
                SW_SECURITY_STATUS
            } else {
                0x63C0 | u16::from(self.pin_retries)
            });
        }
        self.pin_retries = DEFAULT_PIN_RETRIES;
        if reference == 0x81 {
            self.verified_sign = true;
        } else {
            self.verified_other = true;
        }
        Ok(Vec::new())
    }

    fn key(&self, slot: KeySlot) -> Result<&MockKey, u16> {
        let key = self.keys[slot_index(slot)]
            .as_ref()
            .ok_or(SW_DATA_NOT_FOUND)?;
        if self.touch[slot_index(slot)] != 0 {
            return Err(SW_CONDITIONS_NOT_SATISFIED);
        }
        Ok(key)
    }

    fn sign(&mut self, input: &[u8]) -> Result<Vec<u8>, u16> {
        let signature = self.key(KeySlot::Sign)?.signature(input);
        if !self.verified_sign {
            return Err(SW_SECURITY_STATUS);
        }
        // PW1 for signing is valid for one signature, the card default.
        self.verified_sign = false;
        self.signature_counter += 1;
        Ok(signature)
    }

    fn decipher(&mut self, input: &[u8]) -> Result<Vec<u8>, u16> {
        let key = self.key(KeySlot::Decrypt)?;
        if !self.verified_other {
            return Err(SW_SECURITY_STATUS);
        }
        let well_formed = match key.kind {
            MockKeyKind::Rsa2048 => input.first() == Some(&0x00) && input.len() > 1,
            MockKeyKind::Cv25519 => tlv::find(input, 0x86).ok().flatten().is_some(),
            MockKeyKind::Ed25519 => false,
        };
        if !well_formed {
            return Err(SW_WRONG_DATA);
        }
        Ok(key.plaintext(input))
    }

    fn authenticate(&mut self, input: &[u8]) -> Result<Vec<u8>, u16> {
        let key = self.key(KeySlot::Auth)?;
        if !self.verified_other {
            return Err(SW_SECURITY_STATUS);
        }
        Ok(key.signature(input))
    }

    fn read_public_key(&self, crt: &[u8]) -> Result<Vec<u8>, u16> {
        let slot = match crt {
            [0xB6, 0x00] => KeySlot::Sign,
            [0xB8, 0x00] => KeySlot::Decrypt,
            [0xA4, 0x00] => KeySlot::Auth,
            _ => return Err(SW_WRONG_DATA),
        };
        // Reading a public key never needs a touch.
        let key = self.keys[slot_index(slot)]
            .as_ref()
            .ok_or(SW_DATA_NOT_FOUND)?;
        let mut inner = Vec::new();
        match key.kind {
            MockKeyKind::Rsa2048 => {
                tlv::encode(&mut inner, 0x81, &key.public_value());
                tlv::encode(&mut inner, 0x82, &[0x01, 0x00, 0x01]);
            }
            MockKeyKind::Ed25519 | MockKeyKind::Cv25519 => {
                tlv::encode(&mut inner, 0x86, &key.public_value());
            }
        }
        let mut out = Vec::new();
        tlv::encode(&mut out, 0x7F49, &inner);
        Ok(out)
    }
}

fn slot_index(slot: KeySlot) -> usize {
    match slot {
        KeySlot::Sign => 0,
        KeySlot::Decrypt => 1,
        KeySlot::Auth => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::mock::MockCard;
    use crate::card::{Card, CardError, CardTransaction, send, send_openpgp};
    use crate::oath::proto as oath;
    use crate::openpgp::proto::{
        self, Algorithm, Command, Kdf, KdfHash, PgpError, PublicKey, authenticate_apdus,
        decipher_apdus, get_data_apdu, parse_application_data, parse_public_key, parse_pw_status,
        parse_signature_counter, read_public_key_apdu, select_apdu, sign_apdus, verify_apdu,
    };

    const PIN: &str = "123456";

    fn card() -> MockCard {
        MockCard::new().with_openpgp(
            MockOpenPgp::new(PIN)
                .with_key(KeySlot::Sign, MockKey::rsa2048(b"sig"))
                .with_key(KeySlot::Decrypt, MockKey::rsa2048(b"dec"))
                .with_key(KeySlot::Auth, MockKey::ed25519(b"aut")),
        )
    }

    fn pgp(
        tx: &mut dyn CardTransaction,
        apdu: &[u8],
        command: Command,
    ) -> Result<Vec<u8>, CardError> {
        send_openpgp(tx, &[apdu], command)
    }

    fn select(tx: &mut dyn CardTransaction) {
        pgp(tx, &select_apdu(), Command::Select).unwrap();
    }

    fn verify(
        tx: &mut dyn CardTransaction,
        slot: KeySlot,
        pin: &str,
    ) -> Result<Vec<u8>, CardError> {
        pgp(tx, &verify_apdu(slot, pin.as_bytes()), Command::Verify)
    }

    fn retries(tx: &mut dyn CardTransaction) -> u8 {
        let data = pgp(tx, &get_data_apdu(proto::DO_PW_STATUS), Command::GetData).unwrap();
        parse_pw_status(&data).unwrap().pw1_retries
    }

    #[test]
    fn select_without_applet_is_not_installed() {
        let mut card = MockCard::new();
        let mut tx = card.transaction().unwrap();
        assert_eq!(
            pgp(&mut *tx, &select_apdu(), Command::Select),
            Err(CardError::OpenPgp(PgpError::NotInstalled))
        );
    }

    #[test]
    fn application_data_describes_the_keys() {
        let mut card = card();
        let mut tx = card.transaction().unwrap();
        select(&mut *tx);
        let raw = pgp(
            &mut *tx,
            &get_data_apdu(proto::DO_APPLICATION_DATA),
            Command::GetData,
        )
        .unwrap();
        let data = parse_application_data(&raw).unwrap();
        assert_eq!(data.version(), "3.4");
        assert_eq!(data.serial(), "12345678");
        assert_eq!(data.pw_status.pw1_retries, DEFAULT_PIN_RETRIES);
        let sign = data.key(KeySlot::Sign);
        assert_eq!(sign.algorithm, Algorithm::Rsa { bits: 2048 });
        assert_eq!(
            sign.fingerprint,
            Some(MockKey::rsa2048(b"sig").fingerprint())
        );
        assert_eq!(sign.created, Some(1_600_000_000));
        assert_eq!(data.key(KeySlot::Auth).algorithm.name(), "ed25519");
    }

    #[test]
    fn empty_slots_have_no_fingerprint() {
        let mut card = MockCard::new().with_openpgp(MockOpenPgp::new(PIN));
        let mut tx = card.transaction().unwrap();
        select(&mut *tx);
        let raw = pgp(&mut *tx, &get_data_apdu(0x6E), Command::GetData).unwrap();
        let data = parse_application_data(&raw).unwrap();
        assert!(
            data.keys
                .iter()
                .all(|k| k.fingerprint.is_none() && k.created.is_none())
        );
        assert_eq!(
            pgp(
                &mut *tx,
                &read_public_key_apdu(KeySlot::Sign),
                Command::ReadPublicKey
            ),
            Err(CardError::OpenPgp(PgpError::NotFound))
        );
        assert_eq!(
            pgp(&mut *tx, &get_data_apdu(0x5F50), Command::GetData),
            Err(CardError::OpenPgp(PgpError::NotFound))
        );
    }

    #[test]
    fn signing_needs_pw1_81_once_per_signature() {
        let mut card = card();
        let mut tx = card.transaction().unwrap();
        select(&mut *tx);
        assert_eq!(
            send_openpgp(&mut *tx, &sign_apdus(b"digest"), Command::Sign),
            Err(CardError::OpenPgp(PgpError::NotVerified))
        );
        verify(&mut *tx, KeySlot::Decrypt, PIN).unwrap();
        assert_eq!(
            send_openpgp(&mut *tx, &sign_apdus(b"digest"), Command::Sign),
            Err(CardError::OpenPgp(PgpError::NotVerified)),
            "PW1 82 does not allow signing"
        );
        verify(&mut *tx, KeySlot::Sign, PIN).unwrap();
        assert_eq!(
            send_openpgp(&mut *tx, &sign_apdus(b"digest"), Command::Sign),
            Ok(MockKey::rsa2048(b"sig").signature(b"digest"))
        );
        assert_eq!(
            send_openpgp(&mut *tx, &sign_apdus(b"digest"), Command::Sign),
            Err(CardError::OpenPgp(PgpError::NotVerified))
        );
        let counter = pgp(&mut *tx, &get_data_apdu(0x7A), Command::GetData).unwrap();
        assert_eq!(parse_signature_counter(&counter), Ok(1));
        drop(tx);
        assert_eq!(card.openpgp(MockOpenPgp::signature_counter), 1);
    }

    #[test]
    fn wrong_pin_counts_down_and_right_pin_resets() {
        let mut card = card();
        let mut tx = card.transaction().unwrap();
        select(&mut *tx);
        assert_eq!(
            verify(&mut *tx, KeySlot::Sign, "000000"),
            Err(CardError::OpenPgp(PgpError::WrongPin))
        );
        assert_eq!(retries(&mut *tx), 2);
        verify(&mut *tx, KeySlot::Sign, PIN).unwrap();
        assert_eq!(retries(&mut *tx), 3);
    }

    #[test]
    fn pin_blocks_at_zero() {
        let mut card = MockCard::new().with_openpgp(MockOpenPgp::new(PIN).with_pin_retries(1));
        let mut tx = card.transaction().unwrap();
        select(&mut *tx);
        assert_eq!(
            verify(&mut *tx, KeySlot::Sign, "000000"),
            Err(CardError::OpenPgp(PgpError::WrongPin))
        );
        assert_eq!(
            verify(&mut *tx, KeySlot::Sign, PIN),
            Err(CardError::OpenPgp(PgpError::PinBlocked))
        );
        drop(tx);
        assert_eq!(card.openpgp(MockOpenPgp::pin_retries), 0);
    }

    #[test]
    fn wrong_pin_can_be_reported_as_6982() {
        let mut card =
            MockCard::new().with_openpgp(MockOpenPgp::new(PIN).with_wrong_pin_status_6982());
        let mut tx = card.transaction().unwrap();
        select(&mut *tx);
        let raw = tx.transmit(&verify_apdu(KeySlot::Sign, b"000000")).unwrap();
        assert_eq!(oath::Response::parse(&raw).unwrap().sw, 0x6982);
    }

    #[test]
    fn long_decipher_input_arrives_through_command_chaining() {
        let mut card = card();
        let mut tx = card.transaction().unwrap();
        select(&mut *tx);
        verify(&mut *tx, KeySlot::Decrypt, PIN).unwrap();
        let mut input = vec![0x00];
        input.extend_from_slice(&[0x5A; 256]);
        let apdus = decipher_apdus(&input);
        assert_eq!(apdus.len(), 2);
        assert_eq!(
            send_openpgp(&mut *tx, &apdus, Command::Decipher),
            Ok(MockKey::rsa2048(b"dec").plaintext(&input))
        );
    }

    #[test]
    fn decipher_rejects_input_the_key_cannot_take() {
        let mut card = card();
        let mut tx = card.transaction().unwrap();
        select(&mut *tx);
        verify(&mut *tx, KeySlot::Decrypt, PIN).unwrap();
        assert_eq!(
            send_openpgp(&mut *tx, &decipher_apdus(&[0x02, 1]), Command::Decipher),
            Err(CardError::OpenPgp(PgpError::Status(0x6A80)))
        );
    }

    #[test]
    fn ecdh_decipher_takes_the_cipher_data_object() {
        let mut card = MockCard::new()
            .with_openpgp(MockOpenPgp::new(PIN).with_key(KeySlot::Decrypt, MockKey::cv25519(b"x")));
        let mut tx = card.transaction().unwrap();
        select(&mut *tx);
        verify(&mut *tx, KeySlot::Decrypt, PIN).unwrap();
        let algorithm = proto::parse_algorithm(MockKey::cv25519(b"x").attributes()).unwrap();
        let input = proto::decipher_input(&algorithm, &[0x40; 33]).unwrap();
        assert_eq!(
            send_openpgp(&mut *tx, &decipher_apdus(&input), Command::Decipher),
            Ok(MockKey::cv25519(b"x").plaintext(&input))
        );
    }

    #[test]
    fn authenticate_uses_the_auth_key_after_pw1_82() {
        let mut card = card();
        let mut tx = card.transaction().unwrap();
        select(&mut *tx);
        assert_eq!(
            send_openpgp(&mut *tx, &authenticate_apdus(b"x"), Command::Authenticate),
            Err(CardError::OpenPgp(PgpError::NotVerified))
        );
        verify(&mut *tx, KeySlot::Auth, PIN).unwrap();
        assert_eq!(
            send_openpgp(&mut *tx, &authenticate_apdus(b"x"), Command::Authenticate),
            Ok(MockKey::ed25519(b"aut").signature(b"x"))
        );
    }

    #[test]
    fn public_keys_come_back_through_get_response() {
        let mut card = card().with_chunk_size(100);
        let mut tx = card.transaction().unwrap();
        select(&mut *tx);
        let raw = pgp(
            &mut *tx,
            &read_public_key_apdu(KeySlot::Sign),
            Command::ReadPublicKey,
        )
        .unwrap();
        assert_eq!(
            parse_public_key(&raw).unwrap(),
            PublicKey::Rsa {
                modulus: MockKey::rsa2048(b"sig").public_value(),
                exponent: vec![1, 0, 1],
            }
        );
        let raw = pgp(
            &mut *tx,
            &read_public_key_apdu(KeySlot::Auth),
            Command::ReadPublicKey,
        )
        .unwrap();
        assert_eq!(
            parse_public_key(&raw).unwrap(),
            PublicKey::Ec {
                point: MockKey::ed25519(b"aut").public_value()
            }
        );
        drop(tx);
        assert!(card.events().iter().any(|e| matches!(
            e,
            crate::card::mock::MockEvent::Apdu(a) if a[1] == INS_GET_RESPONSE
        )));
    }

    #[test]
    fn selecting_again_or_switching_applets_forgets_verification() {
        let mut card = card().with_password("oath");
        let mut tx = card.transaction().unwrap();
        select(&mut *tx);
        verify(&mut *tx, KeySlot::Auth, PIN).unwrap();
        select(&mut *tx);
        assert_eq!(
            send_openpgp(&mut *tx, &authenticate_apdus(b"x"), Command::Authenticate),
            Err(CardError::OpenPgp(PgpError::NotVerified))
        );
        verify(&mut *tx, KeySlot::Auth, PIN).unwrap();
        // OATH SELECT then back to OpenPGP.
        send(&mut *tx, &oath::select_apdu(), oath::Command::Select).unwrap();
        select(&mut *tx);
        assert_eq!(
            send_openpgp(&mut *tx, &authenticate_apdus(b"x"), Command::Authenticate),
            Err(CardError::OpenPgp(PgpError::NotVerified))
        );
    }

    #[test]
    fn oath_still_works_next_to_openpgp() {
        let mut card = card();
        let mut tx = card.transaction().unwrap();
        select(&mut *tx);
        let data = send(&mut *tx, &oath::select_apdu(), oath::Command::Select).unwrap();
        assert_eq!(oath::parse_select(&data).unwrap().auth, None);
    }

    #[test]
    fn chaining_is_refused_outside_openpgp() {
        let mut card = MockCard::new();
        let mut tx = card.transaction().unwrap();
        let raw = tx.transmit(&[0x10, 0xA4, 0x04, 0x00, 0x01, 0xA0]).unwrap();
        assert_eq!(oath::Response::parse(&raw).unwrap().sw, 0x6E00);
    }

    #[test]
    fn faults_forget_verification() {
        let mut card = card();
        {
            let mut tx = card.transaction().unwrap();
            select(&mut *tx);
            verify(&mut *tx, KeySlot::Auth, PIN).unwrap();
        }
        card.fail_next(1, crate::card::mock::MockFault::Reset);
        let mut tx = card.transaction().unwrap();
        assert!(tx.transmit(&[0x00]).is_err());
        assert_eq!(
            send_openpgp(&mut *tx, &authenticate_apdus(b"x"), Command::Authenticate),
            Err(CardError::OpenPgp(PgpError::Status(0x6D00))),
            "no applet is selected after a reset"
        );
    }

    #[test]
    fn unknown_and_misaddressed_commands_are_refused() {
        let mut card = card();
        let mut tx = card.transaction().unwrap();
        select(&mut *tx);
        for (apdu, sw) in [
            (vec![0x00, 0x01, 0x00, 0x00], 0x6D00),
            (vec![0x00, 0x2A, 0x00, 0x00], 0x6B00),
            (vec![0x00, 0x20, 0x00, 0x83, 0x01, 0x31], 0x6B00),
            (vec![0x00, 0x47, 0x81, 0x00, 0x02, 0xB7, 0x00], 0x6A80),
        ] {
            let raw = tx.transmit(&apdu).unwrap();
            assert_eq!(oath::Response::parse(&raw).unwrap().sw, sw, "{apdu:02x?}");
        }
    }

    #[test]
    fn kdf_card_wants_the_hashed_pin() {
        let kdf = Kdf::IterSaltedS2k {
            hash: KdfHash::Sha256,
            count: 1000,
            pw1_salt: vec![1; 8],
        };
        let mut card = MockCard::new().with_openpgp(MockOpenPgp::new(PIN).with_kdf(kdf.clone()));
        let mut tx = card.transaction().unwrap();
        select(&mut *tx);
        let raw = pgp(&mut *tx, &get_data_apdu(proto::DO_KDF), Command::GetData).unwrap();
        assert_eq!(proto::parse_kdf(&raw).unwrap(), kdf);
        assert_eq!(
            verify(&mut *tx, KeySlot::Sign, PIN),
            Err(CardError::OpenPgp(PgpError::WrongPin)),
            "the plain PIN is wrong once KDF is on"
        );
        let hashed = proto::kdf_pin(&kdf, PIN.as_bytes());
        pgp(
            &mut *tx,
            &verify_apdu(KeySlot::Sign, &hashed),
            Command::Verify,
        )
        .unwrap();
    }

    #[test]
    fn kdf_do_and_capability_follow_the_card_version() {
        let mut card = MockCard::new().with_openpgp(MockOpenPgp::new(PIN));
        let mut tx = card.transaction().unwrap();
        select(&mut *tx);
        let raw = pgp(&mut *tx, &get_data_apdu(0x6E), Command::GetData).unwrap();
        assert!(parse_application_data(&raw).unwrap().kdf_supported);
        let raw = pgp(&mut *tx, &get_data_apdu(proto::DO_KDF), Command::GetData).unwrap();
        assert_eq!(proto::parse_kdf(&raw).unwrap(), Kdf::None);
        drop(tx);

        let mut old = MockCard::new().with_openpgp(MockOpenPgp::new(PIN).without_kdf_do());
        let mut tx = old.transaction().unwrap();
        select(&mut *tx);
        let raw = pgp(&mut *tx, &get_data_apdu(0x6E), Command::GetData).unwrap();
        assert!(!parse_application_data(&raw).unwrap().kdf_supported);
        assert_eq!(
            pgp(&mut *tx, &get_data_apdu(proto::DO_KDF), Command::GetData),
            Err(CardError::OpenPgp(PgpError::NotFound))
        );
    }

    #[test]
    fn unsupported_kdf_is_reported_as_configured() {
        let kdf = Kdf::Unsupported {
            algorithm: 3,
            hash: Some(2),
        };
        let mut card = MockCard::new().with_openpgp(MockOpenPgp::new(PIN).with_kdf(kdf.clone()));
        let mut tx = card.transaction().unwrap();
        select(&mut *tx);
        let raw = pgp(&mut *tx, &get_data_apdu(proto::DO_KDF), Command::GetData).unwrap();
        assert_eq!(proto::parse_kdf(&raw).unwrap(), kdf);
    }

    #[test]
    fn touch_policy_is_readable_and_blocks_use_but_not_public_keys() {
        let mut card = MockCard::new().with_openpgp(
            MockOpenPgp::new(PIN)
                .with_key(KeySlot::Sign, MockKey::rsa2048(b"sig"))
                .with_touch(KeySlot::Sign, 0x03),
        );
        let mut tx = card.transaction().unwrap();
        select(&mut *tx);
        let uif = |tx: &mut dyn CardTransaction, slot: KeySlot| {
            let raw = pgp(tx, &get_data_apdu(slot.uif_tag()), Command::GetData).unwrap();
            proto::parse_uif(&raw).unwrap()
        };
        assert_eq!(uif(&mut *tx, KeySlot::Sign), proto::TouchPolicy::Cached);
        assert_eq!(uif(&mut *tx, KeySlot::Auth), proto::TouchPolicy::Off);
        pgp(
            &mut *tx,
            &read_public_key_apdu(KeySlot::Sign),
            Command::ReadPublicKey,
        )
        .unwrap();
        verify(&mut *tx, KeySlot::Sign, PIN).unwrap();
        assert_eq!(
            send_openpgp(&mut *tx, &sign_apdus(b"d"), Command::Sign),
            Err(CardError::OpenPgp(PgpError::Status(0x6985)))
        );
    }

    #[test]
    fn cards_without_uif_answer_not_found() {
        let mut card = MockCard::new().with_openpgp(MockOpenPgp::new(PIN).without_uif());
        let mut tx = card.transaction().unwrap();
        select(&mut *tx);
        assert_eq!(
            pgp(&mut *tx, &get_data_apdu(0xD6), Command::GetData),
            Err(CardError::OpenPgp(PgpError::NotFound))
        );
    }

    #[test]
    fn mock_keys_are_deterministic_and_distinct() {
        let a = MockKey::rsa2048(b"a");
        assert_eq!(a.signature(b"x"), MockKey::rsa2048(b"a").signature(b"x"));
        assert_ne!(a.signature(b"x"), MockKey::rsa2048(b"b").signature(b"x"));
        assert_ne!(a.signature(b"x"), a.signature(b"y"));
        assert_eq!(a.signature(b"x").len(), 256);
        assert_eq!(MockKey::ed25519(b"a").signature(b"x").len(), 64);
        assert_eq!(a.plaintext(b"x").len(), 32);
        assert_eq!(MockKey::cv25519(b"a").public_value().len(), 33);
    }
}
