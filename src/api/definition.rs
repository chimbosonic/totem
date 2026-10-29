//! The API trait and its request and response types. The OpenAPI document
//! is generated from this, without needing a card.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use dropshot::{
    Body, HttpError, HttpResponseHeaders, HttpResponseOk, HttpResponseUpdatedNoContent, Path,
    RequestContext, TypedBody,
};
use http::Response;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::openpgp::proto::{HashAlgorithm, KeySlot, PublicKey};
use crate::service::{
    Codes, Credential, CredentialState, KeyStatus, OpenPgpStatus, PinRetries, PublicKeyInfo,
};

/// Largest body accepted by the OpenPGP POST endpoints: room for a base64
/// RSA 4096 ciphertext and a long PIN.
pub const OPENPGP_BODY_MAX_BYTES: usize = 4096;

/// Unlock request. Deliberately has no `Debug`, so the password cannot end
/// up in a log by accident.
#[derive(Deserialize, JsonSchema)]
pub struct UnlockRequest {
    /// The OATH password set on the YubiKey.
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CodesResponse {
    /// Unix time the codes were computed at.
    pub generated_at: u64,
    pub credentials: Vec<CredentialView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CredentialView {
    pub issuer: String,
    pub account: String,
    #[serde(flatten)]
    pub status: CredentialStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CredentialStatus {
    /// A TOTP code valid from `valid_from` (inclusive) to `valid_until`
    /// (exclusive), both Unix times.
    Ok {
        code: String,
        digits: u8,
        period: u32,
        valid_from: u64,
        valid_until: u64,
    },
    /// The credential needs a touch on the key, so no code is computed.
    TouchRequired,
    /// HOTP credentials are listed but never computed.
    Hotp,
}

impl From<Codes> for CodesResponse {
    fn from(codes: Codes) -> Self {
        Self {
            generated_at: codes.generated_at,
            credentials: codes.credentials.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<Credential> for CredentialView {
    fn from(credential: Credential) -> Self {
        let status = match credential.state {
            CredentialState::Ok {
                code,
                digits,
                period,
                valid_from,
                valid_until,
            } => CredentialStatus::Ok {
                code,
                digits,
                period,
                valid_from,
                valid_until,
            },
            CredentialState::TouchRequired => CredentialStatus::TouchRequired,
            CredentialState::Hotp => CredentialStatus::Hotp,
        };
        Self {
            issuer: credential.issuer,
            account: credential.account,
            status,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HealthResponse {
    pub status: String,
}

/// An OpenPGP key slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum KeySlotName {
    /// The signature key.
    Sign,
    /// The decryption key.
    Decrypt,
    /// The authentication key.
    Auth,
}

impl From<KeySlotName> for KeySlot {
    fn from(name: KeySlotName) -> Self {
        match name {
            KeySlotName::Sign => Self::Sign,
            KeySlotName::Decrypt => Self::Decrypt,
            KeySlotName::Auth => Self::Auth,
        }
    }
}

impl From<KeySlot> for KeySlotName {
    fn from(slot: KeySlot) -> Self {
        match slot {
            KeySlot::Sign => Self::Sign,
            KeySlot::Decrypt => Self::Decrypt,
            KeySlot::Auth => Self::Auth,
        }
    }
}

#[derive(Deserialize, JsonSchema)]
pub struct KeySlotPath {
    pub slot: KeySlotName,
}

/// Hash that produced a digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HashName {
    Sha256,
    Sha384,
    Sha512,
}

impl From<HashName> for HashAlgorithm {
    fn from(name: HashName) -> Self {
        match name {
            HashName::Sha256 => Self::Sha256,
            HashName::Sha384 => Self::Sha384,
            HashName::Sha512 => Self::Sha512,
        }
    }
}

/// Sign request. Deliberately has no `Debug`, so the PIN cannot end up in
/// a log by accident.
#[derive(Deserialize, JsonSchema)]
pub struct SignRequest {
    /// The OpenPGP user PIN (PW1). Used once and never stored.
    pub pin: String,
    pub hash: HashName,
    /// The digest to sign, base64. The card wraps it in a DigestInfo for
    /// RSA keys and signs it as is for ECDSA and EdDSA keys.
    pub digest: String,
}

/// Decrypt request. Deliberately has no `Debug`.
#[derive(Deserialize, JsonSchema)]
pub struct DecryptRequest {
    /// The OpenPGP user PIN (PW1). Used once and never stored.
    pub pin: String,
    /// Base64. For RSA keys, the RSA ciphertext. For ECDH keys, the
    /// sender's ephemeral public point.
    pub ciphertext: String,
}

/// Authenticate request. Deliberately has no `Debug`.
#[derive(Deserialize, JsonSchema)]
pub struct AuthenticateRequest {
    /// The OpenPGP user PIN (PW1). Used once and never stored.
    pub pin: String,
    /// Base64 data for the authentication key to sign as is (INTERNAL
    /// AUTHENTICATE). For RSA keys, send a DigestInfo.
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SignatureResponse {
    /// The signature, base64.
    pub signature: String,
}

impl From<Vec<u8>> for SignatureResponse {
    fn from(signature: Vec<u8>) -> Self {
        Self {
            signature: BASE64.encode(signature),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DecryptResponse {
    /// The decrypted session key, base64.
    pub plaintext: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OpenPgpStatusResponse {
    /// Applet version, for example `3.4`.
    pub version: String,
    /// Card serial number, 8 hex digits.
    pub serial: String,
    pub keys: Vec<KeyStatusView>,
    pub pin_retries: PinRetriesView,
    /// Signatures made with the signature key, if the card reports it.
    pub signature_counter: Option<u32>,
    /// Whether the card expects PINs hashed (KDF). The service handles it.
    pub kdf_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct KeyStatusView {
    pub slot: KeySlotName,
    /// For example `rsa2048`, `nistp256`, or `ed25519`.
    pub algorithm: String,
    /// OpenPGP v4 fingerprint, 40 hex digits. Absent for an empty slot.
    pub fingerprint: Option<String>,
    /// Unix time the key was generated, if the card records it.
    pub created: Option<u32>,
    /// `off`, `on`, `fixed`, `cached`, or `cached_fixed`. Keys with any
    /// policy but `off` need a touch, so this service refuses to use them.
    pub touch_policy: String,
}

/// Tries left before each PIN blocks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PinRetriesView {
    /// User PIN (PW1).
    pub pin: u8,
    /// Reset code.
    pub reset_code: u8,
    /// Admin PIN (PW3).
    pub admin_pin: u8,
}

impl From<OpenPgpStatus> for OpenPgpStatusResponse {
    fn from(status: OpenPgpStatus) -> Self {
        let PinRetries {
            pin,
            reset_code,
            admin_pin,
        } = status.pin_retries;
        Self {
            version: status.version,
            serial: status.serial,
            keys: status.keys.into_iter().map(Into::into).collect(),
            pin_retries: PinRetriesView {
                pin,
                reset_code,
                admin_pin,
            },
            signature_counter: status.signature_counter,
            kdf_enabled: status.kdf_enabled,
        }
    }
}

impl From<KeyStatus> for KeyStatusView {
    fn from(key: KeyStatus) -> Self {
        Self {
            slot: key.slot.into(),
            algorithm: key.algorithm,
            fingerprint: key.fingerprint,
            created: key.created,
            touch_policy: key.touch_policy,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PublicKeyResponse {
    pub slot: KeySlotName,
    pub algorithm: String,
    /// OpenPGP v4 fingerprint, 40 hex digits.
    pub fingerprint: String,
    #[serde(flatten)]
    pub key: PublicKeyView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PublicKeyView {
    /// An RSA key. Both values are unsigned big-endian integers, base64.
    Rsa { modulus: String, exponent: String },
    /// An elliptic curve key: the public point, base64.
    Ec { point: String },
}

impl From<PublicKeyInfo> for PublicKeyResponse {
    fn from(info: PublicKeyInfo) -> Self {
        let key = match info.key {
            PublicKey::Rsa { modulus, exponent } => PublicKeyView::Rsa {
                modulus: BASE64.encode(modulus),
                exponent: BASE64.encode(exponent),
            },
            PublicKey::Ec { point } => PublicKeyView::Ec {
                point: BASE64.encode(point),
            },
        };
        Self {
            slot: info.slot.into(),
            algorithm: info.algorithm,
            fingerprint: info.fingerprint,
            key,
        }
    }
}

/// 204 with room for a `Set-Cookie` header.
pub type NoContent = HttpResponseHeaders<HttpResponseUpdatedNoContent>;

#[dropshot::api_description]
pub trait OathApi {
    type Context;

    /// Unlock with the OATH password and start a session.
    #[endpoint { method = POST, path = "/api/unlock" }]
    async fn unlock(
        rqctx: RequestContext<Self::Context>,
        body: TypedBody<UnlockRequest>,
    ) -> Result<NoContent, HttpError>;

    /// End the current session.
    #[endpoint { method = POST, path = "/api/lock" }]
    async fn lock(rqctx: RequestContext<Self::Context>) -> Result<NoContent, HttpError>;

    /// List every credential, with codes for those that can be computed.
    #[endpoint { method = GET, path = "/api/codes" }]
    async fn codes(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseHeaders<HttpResponseOk<CodesResponse>>, HttpError>;

    /// OpenPGP applet status: keys, PIN retry counters, signature count.
    #[endpoint { method = GET, path = "/api/openpgp" }]
    async fn openpgp_status(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseHeaders<HttpResponseOk<OpenPgpStatusResponse>>, HttpError>;

    /// The public key in an OpenPGP key slot.
    #[endpoint { method = GET, path = "/api/openpgp/keys/{slot}" }]
    async fn openpgp_public_key(
        rqctx: RequestContext<Self::Context>,
        path: Path<KeySlotPath>,
    ) -> Result<HttpResponseHeaders<HttpResponseOk<PublicKeyResponse>>, HttpError>;

    /// Sign a digest with the OpenPGP signature key. Needs the user PIN.
    #[endpoint {
        method = POST,
        path = "/api/openpgp/sign",
        request_body_max_bytes = OPENPGP_BODY_MAX_BYTES,
    }]
    async fn openpgp_sign(
        rqctx: RequestContext<Self::Context>,
        body: TypedBody<SignRequest>,
    ) -> Result<HttpResponseHeaders<HttpResponseOk<SignatureResponse>>, HttpError>;

    /// Decrypt a session key with the OpenPGP decryption key. Needs the PIN.
    #[endpoint {
        method = POST,
        path = "/api/openpgp/decrypt",
        request_body_max_bytes = OPENPGP_BODY_MAX_BYTES,
    }]
    async fn openpgp_decrypt(
        rqctx: RequestContext<Self::Context>,
        body: TypedBody<DecryptRequest>,
    ) -> Result<HttpResponseHeaders<HttpResponseOk<DecryptResponse>>, HttpError>;

    /// Sign data with the OpenPGP authentication key. Needs the user PIN.
    #[endpoint {
        method = POST,
        path = "/api/openpgp/authenticate",
        request_body_max_bytes = OPENPGP_BODY_MAX_BYTES,
    }]
    async fn openpgp_authenticate(
        rqctx: RequestContext<Self::Context>,
        body: TypedBody<AuthenticateRequest>,
    ) -> Result<HttpResponseHeaders<HttpResponseOk<SignatureResponse>>, HttpError>;

    /// Whether the card is reachable and password protected.
    #[endpoint { method = GET, path = "/healthz" }]
    async fn healthz(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseHeaders<HttpResponseOk<HealthResponse>>, HttpError>;

    #[endpoint { method = GET, path = "/", unpublished = true }]
    async fn index(rqctx: RequestContext<Self::Context>) -> Result<Response<Body>, HttpError>;

    #[endpoint { method = GET, path = "/app.js", unpublished = true }]
    async fn app_js(rqctx: RequestContext<Self::Context>) -> Result<Response<Body>, HttpError>;

    #[endpoint { method = GET, path = "/app.css", unpublished = true }]
    async fn app_css(rqctx: RequestContext<Self::Context>) -> Result<Response<Body>, HttpError>;

    /// The OpenAPI document for this API, as generated by Dropshot.
    #[endpoint { method = GET, path = "/openapi.json", unpublished = true }]
    async fn openapi(rqctx: RequestContext<Self::Context>) -> Result<Response<Body>, HttpError>;

    /// The API docs page, which renders `/openapi.json`.
    #[endpoint { method = GET, path = "/docs", unpublished = true }]
    async fn docs(rqctx: RequestContext<Self::Context>) -> Result<Response<Body>, HttpError>;

    #[endpoint { method = GET, path = "/docs.js", unpublished = true }]
    async fn docs_js(rqctx: RequestContext<Self::Context>) -> Result<Response<Body>, HttpError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn credential(issuer: &str, account: &str, state: CredentialState) -> Credential {
        Credential {
            issuer: issuer.into(),
            account: account.into(),
            state,
        }
    }

    #[test]
    fn codes_response_has_the_documented_json_shape() {
        let codes = Codes {
            generated_at: 1759752005,
            credentials: vec![
                credential(
                    "GitLab",
                    "alexis",
                    CredentialState::Ok {
                        code: "123456".into(),
                        digits: 6,
                        period: 30,
                        valid_from: 1759752000,
                        valid_until: 1759752030,
                    },
                ),
                credential("Example", "x", CredentialState::TouchRequired),
                credential("Other", "y", CredentialState::Hotp),
            ],
        };
        let value = serde_json::to_value(CodesResponse::from(codes)).unwrap();
        assert_eq!(
            value,
            json!({
                "generated_at": 1759752005,
                "credentials": [
                    {
                        "issuer": "GitLab",
                        "account": "alexis",
                        "status": "ok",
                        "code": "123456",
                        "digits": 6,
                        "period": 30,
                        "valid_from": 1759752000,
                        "valid_until": 1759752030
                    },
                    { "issuer": "Example", "account": "x", "status": "touch_required" },
                    { "issuer": "Other", "account": "y", "status": "hotp" }
                ]
            })
        );
    }

    #[test]
    fn codes_response_round_trips() {
        let value = json!({
            "generated_at": 1,
            "credentials": [{ "issuer": "", "account": "a", "status": "hotp" }]
        });
        let parsed: CodesResponse = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), value);
    }

    #[test]
    fn openpgp_status_has_the_documented_json_shape() {
        let status = OpenPgpStatus {
            version: "3.4".into(),
            serial: "12345678".into(),
            keys: vec![
                KeyStatus {
                    slot: KeySlot::Sign,
                    algorithm: "rsa2048".into(),
                    fingerprint: Some("AB".repeat(20)),
                    created: Some(1_600_000_000),
                    touch_policy: "off".into(),
                },
                KeyStatus {
                    slot: KeySlot::Decrypt,
                    algorithm: "rsa2048".into(),
                    fingerprint: None,
                    created: None,
                    touch_policy: "cached".into(),
                },
            ],
            pin_retries: PinRetries {
                pin: 3,
                reset_code: 0,
                admin_pin: 3,
            },
            signature_counter: Some(7),
            kdf_enabled: true,
        };
        let value = serde_json::to_value(OpenPgpStatusResponse::from(status)).unwrap();
        assert_eq!(
            value,
            json!({
                "version": "3.4",
                "serial": "12345678",
                "keys": [
                    {
                        "slot": "sign",
                        "algorithm": "rsa2048",
                        "fingerprint": "AB".repeat(20),
                        "created": 1_600_000_000,
                        "touch_policy": "off"
                    },
                    {
                        "slot": "decrypt",
                        "algorithm": "rsa2048",
                        "fingerprint": null,
                        "created": null,
                        "touch_policy": "cached"
                    }
                ],
                "pin_retries": { "pin": 3, "reset_code": 0, "admin_pin": 3 },
                "signature_counter": 7,
                "kdf_enabled": true
            })
        );
    }

    #[test]
    fn public_keys_have_the_documented_json_shape() {
        let rsa = PublicKeyResponse::from(PublicKeyInfo {
            slot: KeySlot::Sign,
            algorithm: "rsa2048".into(),
            fingerprint: "CD".repeat(20),
            key: PublicKey::Rsa {
                modulus: vec![0xFF, 0x01],
                exponent: vec![1, 0, 1],
            },
        });
        assert_eq!(
            serde_json::to_value(rsa).unwrap(),
            json!({
                "slot": "sign",
                "algorithm": "rsa2048",
                "fingerprint": "CD".repeat(20),
                "type": "rsa",
                "modulus": "/wE=",
                "exponent": "AQAB"
            })
        );
        let ec = PublicKeyResponse::from(PublicKeyInfo {
            slot: KeySlot::Auth,
            algorithm: "ed25519".into(),
            fingerprint: "EF".repeat(20),
            key: PublicKey::Ec { point: vec![4, 5] },
        });
        assert_eq!(
            serde_json::to_value(ec).unwrap(),
            json!({
                "slot": "auth",
                "algorithm": "ed25519",
                "fingerprint": "EF".repeat(20),
                "type": "ec",
                "point": "BAU="
            })
        );
    }

    #[test]
    fn openpgp_requests_parse() {
        let sign: SignRequest =
            serde_json::from_str(r#"{"pin":"123456","hash":"sha384","digest":"AA=="}"#).unwrap();
        assert_eq!(sign.pin, "123456");
        assert_eq!(HashAlgorithm::from(sign.hash), HashAlgorithm::Sha384);
        assert_eq!(sign.digest, "AA==");
        assert!(
            serde_json::from_str::<SignRequest>(r#"{"pin":"1","hash":"md5","digest":""}"#).is_err()
        );
        let decrypt: DecryptRequest =
            serde_json::from_str(r#"{"pin":"p","ciphertext":"c"}"#).unwrap();
        assert_eq!(decrypt.ciphertext, "c");
        let auth: AuthenticateRequest = serde_json::from_str(r#"{"pin":"p","data":"d"}"#).unwrap();
        assert_eq!(auth.data, "d");
    }

    #[test]
    fn slot_names_convert_both_ways() {
        for slot in KeySlot::ALL {
            assert_eq!(KeySlot::from(KeySlotName::from(slot)), slot);
            let name = serde_json::to_value(KeySlotName::from(slot)).unwrap();
            assert_eq!(name, json!(slot.name()));
        }
        assert_eq!(HashAlgorithm::from(HashName::Sha256), HashAlgorithm::Sha256);
        assert_eq!(HashAlgorithm::from(HashName::Sha512), HashAlgorithm::Sha512);
    }

    #[test]
    fn signature_response_is_base64() {
        assert_eq!(SignatureResponse::from(vec![0, 1, 2]).signature, "AAEC");
    }

    #[test]
    fn unlock_request_parses_password() {
        let request: UnlockRequest = serde_json::from_str(r#"{"password":"pw"}"#).unwrap();
        assert_eq!(request.password, "pw");
    }
}
