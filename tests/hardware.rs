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
#![cfg(feature = "hardware-tests")]

use std::sync::Arc;

use oath_web::card::pcsc::PcscCard;
use oath_web::card::{OathCard, send};
use oath_web::clock::{Clock, SystemClock};
use oath_web::oath::crypto::{self, Algorithm};
use oath_web::oath::proto::{self, Command};
use oath_web::rng::OsChallengeSource;
use oath_web::service::{CredentialState, Service, ServiceError};
use oath_web::session::SessionStore;
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
    println!(
        "version: {:?}, device id: {} bytes, password: {}",
        select.version,
        select.device_id.len(),
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
