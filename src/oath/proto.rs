//! YKOATH APDU builders and response parsers.
//!
//! Everything here is pure. The only I/O goes through the `transmit` closure
//! given to [`transmit_chained`].

use std::num::NonZeroU32;

use super::crypto::{self, Algorithm};
use super::tlv::{self, TlvError};

/// OATH applet AID.
pub const AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];
/// Period used when a credential name has no `{period}/` prefix.
pub const DEFAULT_PERIOD: NonZeroU32 = NonZeroU32::new(30).unwrap();

const INS_SELECT: u8 = 0xA4;
const INS_CALCULATE: u8 = 0xA2;
const INS_VALIDATE: u8 = 0xA3;
const INS_CALCULATE_ALL: u8 = 0xA4;
const INS_SEND_REMAINING: u8 = 0xA5;

const TAG_NAME: u8 = 0x71;
const TAG_CHALLENGE: u8 = 0x74;
const TAG_RESPONSE: u8 = 0x75;
const TAG_TRUNCATED: u8 = 0x76;
const TAG_HOTP: u8 = 0x77;
const TAG_VERSION: u8 = 0x79;
const TAG_ALGORITHM: u8 = 0x7B;
const TAG_TOUCH: u8 = 0x7C;

const SW_OK: u16 = 0x9000;
const SW_AUTH_REQUIRED: u16 = 0x6982;
const SW_NO_SUCH_OBJECT: u16 = 0x6984;
const SW_WRONG_DATA: u16 = 0x6A80;
/// Upper bound on SEND REMAINING round trips for one command.
const MAX_CHAIN: usize = 64;

/// Which command a status word belongs to. Some status words mean different
/// things for different commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Select,
    Validate,
    Calculate,
    CalculateAll,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtoError {
    #[error("wrong OATH password")]
    WrongPassword,
    #[error("credential not found")]
    NotFound,
    #[error("OATH applet requires authentication")]
    AuthRequired,
    #[error("card returned status {0:#06x}")]
    Status(u16),
    #[error("card failed to prove it holds the OATH key")]
    CardAuthFailed,
    #[error("malformed card response: {0}")]
    Malformed(&'static str),
    #[error("malformed card response: {0}")]
    Tlv(#[from] TlvError),
}

/// Map a non-success status word to a typed error.
pub fn status_error(command: Command, sw: u16) -> ProtoError {
    match (command, sw) {
        // The spec lists 6984 for a wrong VALIDATE; a YubiKey NEO (applet
        // 1.0.0) sends 6A80. ykman treats both as a wrong password, and so
        // must we, or wrong guesses would not count against the rate limit.
        (Command::Validate, SW_NO_SUCH_OBJECT | SW_WRONG_DATA) => ProtoError::WrongPassword,
        (_, SW_NO_SUCH_OBJECT) => ProtoError::NotFound,
        (_, SW_AUTH_REQUIRED) => ProtoError::AuthRequired,
        (_, other) => ProtoError::Status(other),
    }
}

/// Response data with its final status word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub data: Vec<u8>,
    pub sw: u16,
}

impl Response {
    /// Split a raw card response into data and the trailing status word.
    pub fn parse(raw: &[u8]) -> Result<Self, ProtoError> {
        let (data, sw) = raw
            .split_last_chunk::<2>()
            .ok_or(ProtoError::Malformed("response shorter than a status word"))?;
        Ok(Self {
            data: data.to_vec(),
            sw: u16::from_be_bytes(*sw),
        })
    }

    /// The data if the status is `9000`, otherwise the typed error.
    pub fn into_data(self, command: Command) -> Result<Vec<u8>, ProtoError> {
        match self.sw {
            SW_OK => Ok(self.data),
            sw => Err(status_error(command, sw)),
        }
    }
}

/// Send `apdu`, then keep sending SEND REMAINING while the card answers
/// `61xx`, concatenating the data. Returns the data and the final status word.
pub fn transmit_chained<E: From<ProtoError>>(
    mut transmit: impl FnMut(&[u8]) -> Result<Vec<u8>, E>,
    apdu: &[u8],
) -> Result<Response, E> {
    let mut response = Response::parse(&transmit(apdu)?)?;
    let mut rounds = 0;
    while response.sw >> 8 == 0x61 {
        rounds += 1;
        if rounds > MAX_CHAIN {
            return Err(ProtoError::Malformed("too many SEND REMAINING rounds").into());
        }
        let next = Response::parse(&transmit(&send_remaining_apdu())?)?;
        response.data.extend(next.data);
        response.sw = next.sw;
    }
    Ok(response)
}

/// Short APDU with optional data and no Le, as ykman sends them.
fn apdu(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let lc = u8::try_from(data.len()).expect("APDU data longer than 255 bytes");
    let mut out = vec![0x00, ins, p1, p2];
    if lc > 0 {
        out.push(lc);
        out.extend_from_slice(data);
    }
    out
}

pub fn select_apdu() -> Vec<u8> {
    apdu(INS_SELECT, 0x04, 0x00, &AID)
}

pub fn send_remaining_apdu() -> Vec<u8> {
    apdu(INS_SEND_REMAINING, 0x00, 0x00, &[])
}

/// VALIDATE: prove we hold `key` by answering `card_challenge`, and send
/// `our_challenge` for the card to answer.
pub fn validate_apdu(
    algorithm: Algorithm,
    key: &[u8],
    card_challenge: &[u8],
    our_challenge: &[u8],
) -> Vec<u8> {
    let mut data = Vec::new();
    tlv::encode(
        &mut data,
        TAG_RESPONSE,
        &crypto::hmac(algorithm, key, card_challenge),
    );
    tlv::encode(&mut data, TAG_CHALLENGE, our_challenge);
    apdu(INS_VALIDATE, 0x00, 0x00, &data)
}

/// CALCULATE ALL with truncated responses for `timestep`.
pub fn calculate_all_apdu(timestep: u64) -> Vec<u8> {
    let mut data = Vec::new();
    tlv::encode(&mut data, TAG_CHALLENGE, &timestep.to_be_bytes());
    apdu(INS_CALCULATE_ALL, 0x00, 0x01, &data)
}

/// CALCULATE with a truncated response for one credential.
pub fn calculate_apdu(name: &[u8], timestep: u64) -> Vec<u8> {
    let mut data = Vec::new();
    tlv::encode(&mut data, TAG_NAME, name);
    tlv::encode(&mut data, TAG_CHALLENGE, &timestep.to_be_bytes());
    apdu(INS_CALCULATE, 0x00, 0x01, &data)
}

/// Challenge and algorithm the card sends when a password is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthChallenge {
    pub challenge: Vec<u8>,
    pub algorithm: Algorithm,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectResponse {
    pub version: Vec<u8>,
    /// Device ID. Used as the PBKDF2 salt.
    pub device_id: Vec<u8>,
    /// `None` means the applet has no password.
    pub auth: Option<AuthChallenge>,
}

pub fn parse_select(data: &[u8]) -> Result<SelectResponse, ProtoError> {
    let (mut version, mut device_id, mut challenge, mut algorithm) = (None, None, None, None);
    for item in tlv::parse_all(data)? {
        match item.tag {
            TAG_VERSION => version = Some(item.value.to_vec()),
            TAG_NAME => device_id = Some(item.value.to_vec()),
            TAG_CHALLENGE => challenge = Some(item.value.to_vec()),
            TAG_ALGORITHM => algorithm = Some(item.value),
            // Newer firmware adds tags we do not need.
            _ => {}
        }
    }
    let auth = match challenge {
        None => None,
        Some(challenge) => {
            let algorithm = algorithm
                .and_then(|a| a.first().copied())
                .and_then(Algorithm::from_ykoath)
                .ok_or(ProtoError::Malformed(
                    "SELECT challenge without a known algorithm",
                ))?;
            Some(AuthChallenge {
                challenge,
                algorithm,
            })
        }
    };
    Ok(SelectResponse {
        version: version.ok_or(ProtoError::Malformed("SELECT without version"))?,
        device_id: device_id.ok_or(ProtoError::Malformed("SELECT without name"))?,
        auth,
    })
}

/// Check the card's VALIDATE answer to `our_challenge`.
pub fn verify_validate_response(
    data: &[u8],
    algorithm: Algorithm,
    key: &[u8],
    our_challenge: &[u8],
) -> Result<(), ProtoError> {
    let answer = tlv::parse_all(data)?
        .into_iter()
        .find(|item| item.tag == TAG_RESPONSE)
        .ok_or(ProtoError::Malformed("VALIDATE without response"))?;
    let expected = crypto::hmac(algorithm, key, our_challenge);
    if crypto::constant_time_eq(answer.value, &expected) {
        Ok(())
    } else {
        Err(ProtoError::CardAuthFailed)
    }
}

/// A truncated code: digit count plus the 4 value bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TruncatedCode {
    pub digits: u8,
    pub value: [u8; 4],
}

impl TruncatedCode {
    pub fn to_code(self) -> String {
        crypto::format_code(self.digits, self.value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryState {
    Code(TruncatedCode),
    Hotp,
    TouchRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalculatedEntry {
    /// Raw credential name as stored on the card.
    pub name: Vec<u8>,
    pub state: EntryState,
}

pub fn parse_calculate_all(data: &[u8]) -> Result<Vec<CalculatedEntry>, ProtoError> {
    let items = tlv::parse_all(data)?;
    let mut pairs = items.chunks_exact(2);
    let mut entries = Vec::with_capacity(items.len() / 2);
    for pair in &mut pairs {
        let (name, result) = (pair[0], pair[1]);
        if name.tag != TAG_NAME {
            return Err(ProtoError::Malformed("CALCULATE ALL entry without name"));
        }
        let state = match result.tag {
            TAG_TRUNCATED => EntryState::Code(parse_truncated(result.value)?),
            TAG_HOTP => EntryState::Hotp,
            TAG_TOUCH => EntryState::TouchRequired,
            _ => {
                return Err(ProtoError::Malformed(
                    "CALCULATE ALL entry with unknown result",
                ));
            }
        };
        entries.push(CalculatedEntry {
            name: name.value.to_vec(),
            state,
        });
    }
    if !pairs.remainder().is_empty() {
        return Err(ProtoError::Malformed("CALCULATE ALL name without result"));
    }
    Ok(entries)
}

pub fn parse_calculate(data: &[u8]) -> Result<TruncatedCode, ProtoError> {
    let item = tlv::parse_all(data)?
        .into_iter()
        .find(|item| item.tag == TAG_TRUNCATED)
        .ok_or(ProtoError::Malformed(
            "CALCULATE without truncated response",
        ))?;
    parse_truncated(item.value)
}

fn parse_truncated(value: &[u8]) -> Result<TruncatedCode, ProtoError> {
    match *value {
        [digits, a, b, c, d] => Ok(TruncatedCode {
            digits,
            value: [a, b, c, d],
        }),
        _ => Err(ProtoError::Malformed("truncated response is not 5 bytes")),
    }
}

/// A credential name split into its parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialName {
    pub period: NonZeroU32,
    pub issuer: String,
    pub account: String,
}

/// Parse `[{period}/][{issuer}:]{account}`.
///
/// A prefix that is not a positive whole number followed by `/` is left as
/// part of the name, so a strange name never hides a credential.
pub fn parse_name(raw: &[u8]) -> CredentialName {
    let name = String::from_utf8_lossy(raw);
    let (period, rest) = name
        .split_once('/')
        .filter(|(prefix, _)| !prefix.is_empty() && prefix.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|(prefix, rest)| Some((prefix.parse::<NonZeroU32>().ok()?, rest)))
        .unwrap_or((DEFAULT_PERIOD, &name));
    let (issuer, account) = rest.split_once(':').unwrap_or(("", rest));
    CredentialName {
        period,
        issuer: issuer.to_owned(),
        account: account.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use std::collections::VecDeque;

    const KEY: [u8; 16] = hex!("6e88be8bad7eae9d9e10aa061224034f");
    const CARD_CHALLENGE: [u8; 8] = hex!("0102030405060708");
    const OUR_CHALLENGE: [u8; 8] = hex!("a1a2a3a4a5a6a7a8");

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        tlv::encode(&mut out, tag, value);
        out
    }

    fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
        parts.concat()
    }

    // Status words

    #[test]
    fn status_words_map_to_typed_errors() {
        assert_eq!(
            status_error(Command::Validate, 0x6984),
            ProtoError::WrongPassword
        );
        assert_eq!(
            status_error(Command::Calculate, 0x6984),
            ProtoError::NotFound
        );
        assert_eq!(
            status_error(Command::CalculateAll, 0x6982),
            ProtoError::AuthRequired
        );
        assert_eq!(
            status_error(Command::Calculate, 0x6982),
            ProtoError::AuthRequired
        );
        assert_eq!(
            status_error(Command::Select, 0x6A82),
            ProtoError::Status(0x6A82)
        );
        // A YubiKey NEO (applet 1.0.0) answers a wrong VALIDATE with 6A80,
        // not the 6984 the spec lists. ykman treats both as a wrong password.
        assert_eq!(
            status_error(Command::Validate, 0x6A80),
            ProtoError::WrongPassword
        );
        assert_eq!(
            status_error(Command::Calculate, 0x6A80),
            ProtoError::Status(0x6A80)
        );
    }

    #[test]
    fn response_splits_data_and_status_word() {
        let response = Response::parse(&hex!("aabb9000")).unwrap();
        assert_eq!(
            response,
            Response {
                data: vec![0xAA, 0xBB],
                sw: 0x9000
            }
        );
        assert_eq!(Response::parse(&hex!("6984")).unwrap().sw, 0x6984);
    }

    #[test]
    fn response_shorter_than_status_word_is_malformed() {
        assert!(matches!(
            Response::parse(&[0x90]),
            Err(ProtoError::Malformed(_))
        ));
        assert!(matches!(
            Response::parse(&[]),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn into_data_returns_data_on_9000_and_error_otherwise() {
        let ok = Response {
            data: vec![1],
            sw: 0x9000,
        };
        assert_eq!(ok.into_data(Command::Select), Ok(vec![1]));
        let bad = Response {
            data: vec![],
            sw: 0x6984,
        };
        assert_eq!(
            bad.into_data(Command::Validate),
            Err(ProtoError::WrongPassword)
        );
    }

    // SEND REMAINING chaining

    /// Scripted card: returns canned responses in order and records APDUs.
    struct Script {
        responses: VecDeque<Vec<u8>>,
        sent: Vec<Vec<u8>>,
    }

    impl Script {
        fn new(responses: &[&[u8]]) -> Self {
            Self {
                responses: responses.iter().map(|r| r.to_vec()).collect(),
                sent: Vec::new(),
            }
        }

        fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, ProtoError> {
            self.sent.push(apdu.to_vec());
            Ok(self.responses.pop_front().expect("script ran out"))
        }
    }

    #[test]
    fn send_remaining_apdu_bytes() {
        assert_eq!(send_remaining_apdu(), hex!("00a50000"));
    }

    #[test]
    fn single_response_is_returned_as_is() {
        let mut card = Script::new(&[&hex!("01029000")]);
        let response = transmit_chained(|a| card.transmit(a), &[0xAA]).unwrap();
        assert_eq!(
            response,
            Response {
                data: vec![1, 2],
                sw: 0x9000
            }
        );
        assert_eq!(card.sent, vec![vec![0xAA]]);
    }

    #[test]
    fn chained_61xx_responses_are_concatenated() {
        let mut card = Script::new(&[&hex!("01026102"), &hex!("03046101"), &hex!("059000")]);
        let response = transmit_chained(|a| card.transmit(a), &[0xAA]).unwrap();
        assert_eq!(
            response,
            Response {
                data: vec![1, 2, 3, 4, 5],
                sw: 0x9000
            }
        );
        assert_eq!(
            card.sent,
            vec![vec![0xAA], send_remaining_apdu(), send_remaining_apdu()]
        );
    }

    #[test]
    fn chain_ending_in_error_status_is_an_error() {
        let mut card = Script::new(&[&hex!("01026102"), &hex!("6a80")]);
        let response = transmit_chained(|a| card.transmit(a), &[0xAA]).unwrap();
        assert_eq!(response.sw, 0x6A80);
        assert_eq!(
            response.into_data(Command::CalculateAll),
            Err(ProtoError::Status(0x6A80))
        );
    }

    #[test]
    fn endless_chain_is_cut_off() {
        let mut calls = 0;
        let result = transmit_chained(
            |_| {
                calls += 1;
                Ok::<_, ProtoError>(hex!("006100").to_vec())
            },
            &[0xAA],
        );
        assert!(matches!(result, Err(ProtoError::Malformed(_))));
        assert!(calls <= MAX_CHAIN + 1, "{calls} calls");
    }

    #[derive(Debug, PartialEq)]
    enum TestError {
        Transport,
        Proto(ProtoError),
    }

    impl From<ProtoError> for TestError {
        fn from(e: ProtoError) -> Self {
            Self::Proto(e)
        }
    }

    #[test]
    fn transport_errors_pass_through() {
        let result = transmit_chained(|_| Err(TestError::Transport), &[0xAA]);
        assert_eq!(result, Err(TestError::Transport));
    }

    #[test]
    fn malformed_raw_response_converts_into_caller_error() {
        let result = transmit_chained(|_| Ok::<_, TestError>(vec![0x90]), &[0xAA]);
        assert!(matches!(
            result,
            Err(TestError::Proto(ProtoError::Malformed(_)))
        ));
    }

    // SELECT

    #[test]
    fn select_apdu_matches_spec() {
        assert_eq!(select_apdu(), hex!("00a4040007a0000005272101"));
    }

    #[test]
    fn select_response_without_password() {
        let data = cat(&[tlv(0x79, &[1, 0, 0]), tlv(0x71, &hex!("1122334455667788"))]);
        let select = parse_select(&data).unwrap();
        assert_eq!(select.version, [1, 0, 0]);
        assert_eq!(select.device_id, hex!("1122334455667788"));
        assert_eq!(select.auth, None);
    }

    #[test]
    fn select_response_with_password() {
        let data = cat(&[
            tlv(0x79, &[5, 4, 3]),
            tlv(0x71, &hex!("1122334455667788")),
            tlv(0x74, &CARD_CHALLENGE),
            tlv(0x7B, &[0x01]),
        ]);
        let select = parse_select(&data).unwrap();
        assert_eq!(
            select.auth,
            Some(AuthChallenge {
                challenge: CARD_CHALLENGE.to_vec(),
                algorithm: Algorithm::Sha1,
            })
        );
    }

    #[test]
    fn select_response_ignores_unknown_tags() {
        let data = cat(&[tlv(0x79, &[5, 4, 3]), tlv(0x71, &[9]), tlv(0x8F, &[0xFF])]);
        assert_eq!(parse_select(&data).unwrap().device_id, [9]);
    }

    #[test]
    fn select_response_without_name_or_version_is_malformed() {
        let no_name = tlv(0x79, &[1, 0, 0]);
        assert!(matches!(
            parse_select(&no_name),
            Err(ProtoError::Malformed(_))
        ));
        let no_version = tlv(0x71, &[9]);
        assert!(matches!(
            parse_select(&no_version),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn select_challenge_without_known_algorithm_is_malformed() {
        let base = cat(&[
            tlv(0x79, &[1, 0, 0]),
            tlv(0x71, &[9]),
            tlv(0x74, &CARD_CHALLENGE),
        ]);
        assert!(matches!(parse_select(&base), Err(ProtoError::Malformed(_))));
        let unknown = cat(&[base, tlv(0x7B, &[0x09])]);
        assert!(matches!(
            parse_select(&unknown),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn select_response_with_bad_tlv_is_an_error() {
        assert!(matches!(
            parse_select(&[0x79, 0x05, 1]),
            Err(ProtoError::Tlv(_))
        ));
    }

    // VALIDATE

    #[test]
    fn validate_apdu_contains_response_then_challenge() {
        let answer = crypto::hmac(Algorithm::Sha1, &KEY, &CARD_CHALLENGE);
        let data = cat(&[tlv(0x75, &answer), tlv(0x74, &OUR_CHALLENGE)]);
        let mut expected = hex!("00a30000").to_vec();
        expected.push(data.len() as u8);
        expected.extend(&data);

        assert_eq!(data.len(), 2 + 20 + 2 + 8);
        assert_eq!(
            validate_apdu(Algorithm::Sha1, &KEY, &CARD_CHALLENGE, &OUR_CHALLENGE),
            expected
        );
    }

    #[test]
    fn validate_apdu_uses_the_card_algorithm() {
        let apdu = validate_apdu(Algorithm::Sha256, &KEY, &CARD_CHALLENGE, &OUR_CHALLENGE);
        let answer = crypto::hmac(Algorithm::Sha256, &KEY, &CARD_CHALLENGE);
        assert_eq!(apdu[5..7], [0x75, 32]);
        assert_eq!(apdu[7..39], answer[..]);
    }

    #[test]
    fn validate_succeeds_when_card_response_matches() {
        let card = tlv(0x75, &crypto::hmac(Algorithm::Sha1, &KEY, &OUR_CHALLENGE));
        assert_eq!(
            verify_validate_response(&card, Algorithm::Sha1, &KEY, &OUR_CHALLENGE),
            Ok(())
        );
    }

    #[test]
    fn validate_rejects_wrong_card_response() {
        let mut answer = crypto::hmac(Algorithm::Sha1, &KEY, &OUR_CHALLENGE);
        answer[0] ^= 1;
        let card = tlv(0x75, &answer);
        assert_eq!(
            verify_validate_response(&card, Algorithm::Sha1, &KEY, &OUR_CHALLENGE),
            Err(ProtoError::CardAuthFailed)
        );
    }

    #[test]
    fn validate_rejects_response_without_response_tag() {
        let card = tlv(0x74, &OUR_CHALLENGE);
        assert!(matches!(
            verify_validate_response(&card, Algorithm::Sha1, &KEY, &OUR_CHALLENGE),
            Err(ProtoError::Malformed(_))
        ));
    }

    // CALCULATE ALL and CALCULATE

    #[test]
    fn calculate_all_apdu_encodes_timestep_big_endian() {
        assert_eq!(
            calculate_all_apdu(0x0102_0304_0506_0708),
            hex!("00a400010a 7408 0102030405060708")
        );
        assert_eq!(
            calculate_all_apdu(1),
            hex!("00a400010a 7408 0000000000000001")
        );
    }

    #[test]
    fn calculate_apdu_encodes_name_and_timestep() {
        assert_eq!(
            calculate_apdu(b"60/A:b", 2),
            hex!("00a2000112 7106 36302f413a62 7408 0000000000000002")
        );
    }

    #[test]
    fn calculate_all_response_maps_mixed_entries() {
        let data = cat(&[
            tlv(0x71, b"GitLab:alexis"),
            tlv(0x76, &hex!("06 075bcd15")),
            tlv(0x71, b"Example:x"),
            tlv(0x7C, &[0x06]),
            tlv(0x71, b"Other:y"),
            tlv(0x77, &[0x06]),
        ]);
        let entries = parse_calculate_all(&data).unwrap();
        assert_eq!(
            entries,
            vec![
                CalculatedEntry {
                    name: b"GitLab:alexis".to_vec(),
                    state: EntryState::Code(TruncatedCode {
                        digits: 6,
                        value: hex!("075bcd15"),
                    }),
                },
                CalculatedEntry {
                    name: b"Example:x".to_vec(),
                    state: EntryState::TouchRequired,
                },
                CalculatedEntry {
                    name: b"Other:y".to_vec(),
                    state: EntryState::Hotp,
                },
            ]
        );
        let EntryState::Code(code) = entries[0].state else {
            unreachable!()
        };
        assert_eq!(code.to_code(), "456789");
    }

    #[test]
    fn calculate_all_empty_response_has_no_entries() {
        assert_eq!(parse_calculate_all(&[]).unwrap(), vec![]);
    }

    #[test]
    fn calculate_all_rejects_broken_pairing() {
        let response_first = cat(&[tlv(0x76, &hex!("06 00000001")), tlv(0x71, b"a")]);
        assert!(matches!(
            parse_calculate_all(&response_first),
            Err(ProtoError::Malformed(_))
        ));
        let dangling_name = cat(&[tlv(0x71, b"a"), tlv(0x77, &[]), tlv(0x71, b"b")]);
        assert!(matches!(
            parse_calculate_all(&dangling_name),
            Err(ProtoError::Malformed(_))
        ));
        let unknown_state = cat(&[tlv(0x71, b"a"), tlv(0x75, &[0; 20])]);
        assert!(matches!(
            parse_calculate_all(&unknown_state),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn truncated_response_must_be_five_bytes() {
        let short = cat(&[tlv(0x71, b"a"), tlv(0x76, &hex!("06 000001"))]);
        assert!(matches!(
            parse_calculate_all(&short),
            Err(ProtoError::Malformed(_))
        ));
        assert!(matches!(
            parse_calculate(&tlv(0x76, &hex!("06 0000000100"))),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn calculate_response_parses_truncated_code() {
        assert_eq!(
            parse_calculate(&tlv(0x76, &hex!("08 075bcd15"))).unwrap(),
            TruncatedCode {
                digits: 8,
                value: hex!("075bcd15")
            }
        );
    }

    #[test]
    fn calculate_response_without_truncated_tag_is_malformed() {
        assert!(matches!(
            parse_calculate(&tlv(0x75, &[0; 20])),
            Err(ProtoError::Malformed(_))
        ));
    }

    // Names

    fn name(period: u32, issuer: &str, account: &str) -> CredentialName {
        CredentialName {
            period: NonZeroU32::new(period).unwrap(),
            issuer: issuer.into(),
            account: account.into(),
        }
    }

    #[test]
    fn name_with_issuer_and_account() {
        assert_eq!(parse_name(b"GitLab:alexis"), name(30, "GitLab", "alexis"));
    }

    #[test]
    fn name_with_account_only_has_empty_issuer() {
        assert_eq!(parse_name(b"alexis"), name(30, "", "alexis"));
    }

    #[test]
    fn name_with_period_prefix() {
        assert_eq!(
            parse_name(b"60/GitHub:alexis"),
            name(60, "GitHub", "alexis")
        );
        assert_eq!(parse_name(b"15/alexis"), name(15, "", "alexis"));
    }

    #[test]
    fn name_splits_on_first_colon_only() {
        assert_eq!(
            parse_name(b"Corp:alexis:work:2"),
            name(30, "Corp", "alexis:work:2")
        );
    }

    #[test]
    fn name_with_empty_issuer() {
        assert_eq!(parse_name(b":alexis"), name(30, "", "alexis"));
    }

    #[test]
    fn name_with_invalid_period_keeps_prefix() {
        assert_eq!(parse_name(b"0/A:b"), name(30, "0/A", "b"));
        assert_eq!(parse_name(b"/A:b"), name(30, "/A", "b"));
        assert_eq!(
            parse_name(b"99999999999/A:b"),
            name(30, "99999999999/A", "b")
        );
        assert_eq!(parse_name(b"x1/A:b"), name(30, "x1/A", "b"));
    }

    #[test]
    fn name_with_invalid_utf8_is_still_shown() {
        let parsed = parse_name(b"Issuer:\xFFbad");
        assert_eq!(parsed.issuer, "Issuer");
        assert_eq!(parsed.account, "\u{FFFD}bad");
    }

    #[test]
    fn rfc6238_test_credential_name_parses() {
        assert_eq!(parse_name(b"RFC6238:sha256"), name(30, "RFC6238", "sha256"));
    }
}
