//! The API trait and its request and response types. The OpenAPI document
//! is generated from this, without needing a card.

use dropshot::{
    Body, HttpError, HttpResponseHeaders, HttpResponseOk, HttpResponseUpdatedNoContent,
    RequestContext, TypedBody,
};
use http::Response;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::service::{Codes, Credential, CredentialState};

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
    fn unlock_request_parses_password() {
        let request: UnlockRequest = serde_json::from_str(r#"{"password":"pw"}"#).unwrap();
        assert_eq!(request.password, "pw");
    }
}
