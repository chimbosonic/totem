//! Tests against a real YubiKey. Compiled only with the `hardware-tests`
//! feature, so `cargo test` never touches hardware (PLAN.md section 14.1).
//!
//! The key must hold the RFC 6238 SHA-256 test credential `RFC6238:sha256`
//! (secret `12345678901234567890123456789012`, 8 digits, 30s).
//!
//! ```sh
//! # Key without an OATH password: checks the service refuses it.
//! cargo test --features hardware-tests --test hardware -- --test-threads=1
//!
//! # Key with a password: checks unlock and codes.
//! OATH_HW_PASSWORD='...' cargo test --features hardware-tests --test hardware -- --test-threads=1
//! ```
//!
//! `OATH_HW_OPENPGP_PIN` is the OpenPGP user PIN. With it, the OpenPGP
//! tests sign with the key in the signature slot. They never send a wrong
//! PIN and refuse to send any PIN when 2 or fewer tries are left. Without
//! it, they only read the status and public keys.
//!
//! `OATH_HW_DERIVED_KEY` (hex) is the PBKDF2 fixture from PLAN.md section
//! 14.4, computed independently of this crate (see
//! `hw_pbkdf2_matches_independent_fixture`). It unlocks the key just like the
//! password does, so keep it in the git-ignored `.env`, never in the repo.
#![cfg(feature = "hardware-tests")]

use std::sync::Arc;

use totem::card::pcsc::PcscCard;
use totem::card::{Card, send};
use totem::clock::{Clock, SystemClock};
use totem::oath::crypto::{self, Algorithm};
use totem::oath::proto::{self, Command};
use totem::openpgp::message::{self, Format, SignatureBuilder};
use totem::openpgp::proto::{self as openpgp, HashAlgorithm, KeySlot, PublicKey};
use totem::rng::OsChallengeSource;
use totem::service::{CredentialState, Service, ServiceError};
use totem::session::SessionStore;
use zeroize::Zeroizing;

const SECRET: &[u8] = b"12345678901234567890123456789012";

fn reader_filter() -> Option<String> {
    std::env::var("OATH_READER").ok()
}

fn password() -> Option<String> {
    std::env::var("OATH_HW_PASSWORD").ok()
}

fn service() -> Service {
    let card = PcscCard::connect(reader_filter().as_deref()).expect("connect to YubiKey");
    Service::new(
        Box::new(card),
        Arc::new(SystemClock),
        Arc::new(OsChallengeSource),
    )
}

#[test]
fn hw_select_reports_applet_over_pcsc() {
    let mut card = PcscCard::connect(reader_filter().as_deref()).expect("connect to YubiKey");
    println!("reader: {}", card.reader_name());
    let mut tx = card.transaction().unwrap();
    let data = send(&mut *tx, &proto::select_apdu(), Command::Select).unwrap();
    let select = proto::parse_select(&data).unwrap();
    let device_id: String = select
        .device_id
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    println!(
        "version: {:?}, device id: {device_id}, password: {}",
        select.version,
        select.auth.is_some()
    );
    assert!(!select.version.is_empty());
    assert!(!select.device_id.is_empty());
}

#[test]
fn hw_reconnect_then_select_works() {
    let mut card = PcscCard::connect(reader_filter().as_deref()).expect("connect to YubiKey");
    card.reconnect().unwrap();
    let mut tx = card.transaction().unwrap();
    assert!(send(&mut *tx, &proto::select_apdu(), Command::Select).is_ok());
}

#[tokio::test]
async fn hw_startup_check_matches_password_state() {
    let result = service().startup_check().await;
    match password() {
        Some(_) => assert!(result.is_ok(), "{result:?}"),
        None => assert_eq!(result, Err(ServiceError::NoPassword)),
    }
}

#[tokio::test]
async fn hw_wrong_password_is_rejected() {
    if password().is_none() {
        // Without a password set there is nothing to get wrong; the
        // startup check test covers the refusal.
        assert_eq!(
            service().unlock(Zeroizing::new("wrong".into())).await,
            Err(ServiceError::NoPassword)
        );
        return;
    }
    assert_eq!(
        service()
            .unlock(Zeroizing::new("definitely wrong".into()))
            .await,
        Err(ServiceError::WrongPassword)
    );
}

#[tokio::test]
async fn hw_unlock_and_codes_match_rfc6238_secret() {
    let Some(password) = password() else {
        panic!("set OATH_HW_PASSWORD to the key's OATH password to run this test");
    };
    let svc = service();
    let key = svc.unlock(Zeroizing::new(password)).await.expect("unlock");
    let store = SessionStore::new(
        Arc::new(SystemClock),
        Arc::new(OsChallengeSource),
        300,
        1800,
    );
    let session = store.authenticate(store.create(key)).unwrap();

    let codes = svc.codes(&session).await.expect("codes");
    let credential = codes
        .credentials
        .iter()
        .find(|c| c.issuer == "RFC6238" && c.account == "sha256")
        .expect("RFC6238:sha256 credential on the key");
    let CredentialState::Ok {
        code,
        digits,
        period,
        ..
    } = &credential.state
    else {
        panic!("expected a code, got {:?}", credential.state);
    };

    let step = crypto::timestep(codes.generated_at, (*period).try_into().unwrap());
    let mac = crypto::hmac(Algorithm::Sha256, SECRET, &step.to_be_bytes());
    let expected = crypto::format_code(*digits, crypto::dynamic_truncate(&mac));
    assert_eq!(code, &expected, "at t={}", codes.generated_at);
    assert!(SystemClock.now() >= codes.generated_at);
}

/// Protocol-level check that works while the key has no password: SELECT
/// then CALCULATE ALL directly, and compare with the RFC 6238 secret.
#[test]
fn hw_calculate_all_on_unprotected_key_matches_rfc6238_secret() {
    if password().is_some() {
        // Protected keys are covered by hw_unlock_and_codes_match_rfc6238_secret.
        return;
    }
    let mut card = PcscCard::connect(reader_filter().as_deref()).expect("connect to YubiKey");
    let mut tx = card.transaction().unwrap();
    send(&mut *tx, &proto::select_apdu(), Command::Select).unwrap();

    let now = SystemClock.now();
    let step = crypto::timestep(now, proto::DEFAULT_PERIOD);
    let data = send(
        &mut *tx,
        &proto::calculate_all_apdu(step),
        Command::CalculateAll,
    )
    .unwrap();
    let entry = proto::parse_calculate_all(&data)
        .unwrap()
        .into_iter()
        .find(|e| e.name == b"RFC6238:sha256")
        .expect("RFC6238:sha256 credential on the key");
    let proto::EntryState::Code(code) = entry.state else {
        panic!("expected a code, got {:?}", entry.state);
    };

    let mac = crypto::hmac(Algorithm::Sha256, SECRET, &step.to_be_bytes());
    let expected = crypto::format_code(code.digits, crypto::dynamic_truncate(&mac));
    println!(
        "card: {} expected: {} digits: {}",
        code.to_code(),
        expected,
        code.digits
    );
    assert_eq!(code.to_code(), expected);
}

/// PLAN.md section 14.4 item 4: our PBKDF2 matches a key derived outside
/// this crate for the real password and device ID. Capture the fixture with:
///
/// ```sh
/// python3 -c 'import hashlib,os,sys; print(hashlib.pbkdf2_hmac("sha1",
///   os.environ["OATH_HW_PASSWORD"].encode(), bytes.fromhex(sys.argv[1]),
///   1000, 16).hex())' <device id hex from hw_select_reports_applet_over_pcsc>
/// ```
#[test]
fn hw_pbkdf2_matches_independent_fixture() {
    let (Some(password), Ok(expected)) = (password(), std::env::var("OATH_HW_DERIVED_KEY")) else {
        panic!("set OATH_HW_PASSWORD and OATH_HW_DERIVED_KEY (see this test's docs)");
    };
    let mut card = PcscCard::connect(reader_filter().as_deref()).expect("connect to YubiKey");
    let mut tx = card.transaction().unwrap();
    let data = send(&mut *tx, &proto::select_apdu(), Command::Select).unwrap();
    let device_id = proto::parse_select(&data).unwrap().device_id;

    let derived: String = crypto::derive_key(&password, &device_id)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    // Compare without printing either value on failure.
    assert!(
        derived == expected.trim().to_ascii_lowercase(),
        "derived key does not match OATH_HW_DERIVED_KEY"
    );
}

/// Unlock with `OATH_HW_PASSWORD` and fetch every credential.
async fn fetch_codes() -> totem::service::Codes {
    let Some(password) = password() else {
        panic!("set OATH_HW_PASSWORD to the key's OATH password to run this test");
    };
    let svc = service();
    let key = svc.unlock(Zeroizing::new(password)).await.expect("unlock");
    let store = SessionStore::new(
        Arc::new(SystemClock),
        Arc::new(OsChallengeSource),
        300,
        1800,
    );
    let session = store.authenticate(store.create(key)).unwrap();
    svc.codes(&session).await.expect("codes")
}

/// Needs `60/RFC6238:sha256-60s` (same secret, SHA-256, 8 digits, 60s).
#[tokio::test]
async fn hw_sixty_second_totp_uses_its_own_timestep() {
    let codes = fetch_codes().await;
    let credential = codes
        .credentials
        .iter()
        .find(|c| c.issuer == "RFC6238" && c.account == "sha256-60s")
        .expect("60/RFC6238:sha256-60s credential on the key");
    let CredentialState::Ok {
        code,
        digits,
        period,
        valid_from,
        valid_until,
    } = &credential.state
    else {
        panic!("expected a code, got {:?}", credential.state);
    };
    assert_eq!(*period, 60);
    assert_eq!(valid_from % 60, 0);
    assert_eq!(valid_until - valid_from, 60);

    let step = codes.generated_at / 60;
    let mac = crypto::hmac(Algorithm::Sha256, SECRET, &step.to_be_bytes());
    let expected = crypto::format_code(*digits, crypto::dynamic_truncate(&mac));
    assert_eq!(code, &expected, "at t={}", codes.generated_at);
}

/// Needs `RFC4226:sha1` (HOTP). Listed, never computed, so its counter is
/// not advanced. Confirm the counter by hand with `ykman oath accounts code
/// RFC4226`: the first code ever generated should be 755224 (counter 0).
#[tokio::test]
async fn hw_hotp_is_listed_without_a_code() {
    let codes = fetch_codes().await;
    let credential = codes
        .credentials
        .iter()
        .find(|c| c.issuer == "RFC4226" && c.account == "sha1")
        .expect("RFC4226:sha1 HOTP credential on the key");
    assert_eq!(credential.state, CredentialState::Hotp);
}

// OpenPGP

fn openpgp_pin() -> Option<String> {
    std::env::var("OATH_HW_OPENPGP_PIN").ok()
}

/// Keep two tries in reserve on a real key, one more than the default.
fn openpgp_service() -> Service {
    service().with_pin_retry_floor(2)
}

#[tokio::test]
async fn hw_openpgp_status_and_public_keys() {
    let svc = openpgp_service();
    let status = svc.openpgp_status().await.expect("OpenPGP status");
    println!(
        "OpenPGP {} serial {} retries {:?} signatures {:?}",
        status.version, status.serial, status.pin_retries, status.signature_counter
    );
    assert!(!status.version.is_empty());
    assert_eq!(status.serial.len(), 8);
    for key in &status.keys {
        println!(
            "  {}: {} {:?} touch {}",
            key.slot, key.algorithm, key.fingerprint, key.touch_policy
        );
        let result = svc.openpgp_public_key(key.slot).await;
        match &key.fingerprint {
            None => assert_eq!(result, Err(ServiceError::NoKey(key.slot))),
            Some(fingerprint) => {
                let info = result.expect("public key");
                assert_eq!(&info.fingerprint, fingerprint);
                assert_eq!(info.algorithm, key.algorithm);
            }
        }
    }
}

#[tokio::test]
async fn hw_openpgp_rsa_signature_verifies_against_the_card_key() {
    let Some(pin) = openpgp_pin() else {
        println!("OATH_HW_OPENPGP_PIN not set; skipping the signature check");
        return;
    };
    let svc = openpgp_service();
    let status = svc.openpgp_status().await.expect("OpenPGP status");
    let sign = &status.keys[0];
    if sign.fingerprint.is_none() {
        println!("no key in the signature slot; skipping");
        return;
    }
    if sign.touch_policy != "off" {
        // The service would refuse with TouchRequired before sending the
        // PIN; skip rather than fail, since the key is set up that way.
        println!(
            "signature key has touch policy {}; skipping",
            sign.touch_policy
        );
        return;
    }
    println!("KDF enabled: {}", status.kdf_enabled);
    assert!(
        status.pin_retries.pin > 2,
        "only {} PIN tries left; reset them at the host before running this",
        status.pin_retries.pin
    );
    let text = "totem hardware test";
    let armored = svc
        .openpgp_sign_message(
            Zeroizing::new(pin),
            HashAlgorithm::Sha256,
            Format::Detached,
            text.into(),
        )
        .await
        .expect("sign");
    println!("{armored}");
    let after = svc.openpgp_status().await.unwrap();
    assert_eq!(after.pin_retries.pin, status.pin_retries.pin);
    if let (Some(before), Some(now)) = (status.signature_counter, after.signature_counter) {
        assert_eq!(now, before + 1);
    }
    let info = svc.openpgp_public_key(KeySlot::Sign).await.unwrap();
    let PublicKey::Rsa { modulus, exponent } = info.key else {
        println!(
            "signature key is {}, not RSA; checked the armor only",
            info.algorithm
        );
        assert!(armored.starts_with("-----BEGIN PGP SIGNATURE-----"));
        return;
    };
    // Take the signature packet apart: creation time from the hashed
    // subpackets, the RSA signature from the final MPI.
    let packet = armored_packet(&armored);
    let (hashed, signature) = signature_packet_parts(&packet);
    let created_at = hashed
        .windows(6)
        .find(|w| w[..2] == [5, 2])
        .map(|w| u32::from_be_bytes(w[2..6].try_into().unwrap()))
        .expect("creation time subpacket");
    let fingerprint: [u8; 20] = (0..40)
        .step_by(2)
        .map(|i| u8::from_str_radix(&info.fingerprint[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let key_info = openpgp::KeyInfo {
        slot: KeySlot::Sign,
        algorithm: openpgp::Algorithm::Rsa {
            bits: (modulus.len() * 8) as u16,
        },
        fingerprint: Some(fingerprint),
        created: None,
    };
    let builder = SignatureBuilder::new(
        &key_info,
        HashAlgorithm::Sha256,
        Format::Detached,
        created_at,
    )
    .unwrap();
    let digest = builder.digest(&message::signed_data(Format::Detached, text));
    let key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&modulus),
        rsa::BigUint::from_bytes_be(&exponent),
    )
    .unwrap();
    // RustCrypto's own SHA-256 DigestInfo, independent of ours.
    key.verify(
        rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha256>(),
        &digest,
        &left_pad(signature, modulus.len()),
    )
    .expect("card signature verifies with the card's public key");
}

/// The packet inside armor.
fn armored_packet(armored: &str) -> Vec<u8> {
    use base64::Engine;
    let body: String = armored
        .split("\n\n")
        .nth(1)
        .unwrap()
        .lines()
        .take_while(|line| !line.starts_with('='))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap()
}

/// A version 4 signature packet's hashed subpacket area and its RSA
/// signature value (the one MPI): header, version/type/algorithms, hashed
/// area, unhashed area, two digest bytes, then the MPI.
fn signature_packet_parts(packet: &[u8]) -> (&[u8], &[u8]) {
    let body = match packet[0] & 3 {
        0 => &packet[2..],
        1 => &packet[3..],
        _ => &packet[5..],
    };
    let length_at = |at: usize| usize::from(u16::from_be_bytes([body[at], body[at + 1]]));
    let hashed_len = length_at(4);
    let hashed = &body[6..6 + hashed_len];
    let unhashed_at = 6 + hashed_len;
    let mpi_at = unhashed_at + 2 + length_at(unhashed_at) + 2;
    let bits = length_at(mpi_at);
    let value = &body[mpi_at + 2..mpi_at + 2 + bits.div_ceil(8)];
    (hashed, value)
}

/// `value` with leading zeros put back, to `len` bytes.
fn left_pad(value: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0; len - value.len()];
    out.extend_from_slice(value);
    out
}
