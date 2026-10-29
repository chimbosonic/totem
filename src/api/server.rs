//! API implementation, server context, and server startup.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use dropshot::{
    ApiDescription, Body, ClientErrorStatusCode, ConfigDropshot, HandlerTaskMode, HttpError,
    HttpResponseHeaders, HttpResponseOk, HttpResponseUpdatedNoContent, HttpServer, Path,
    RequestContext, ServerBuilder, TypedBody,
};
use http::header::{CONTENT_TYPE, SET_COOKIE};
use http::{HeaderValue, Response, StatusCode};
use slog::{Logger, error, info, warn};
use zeroize::Zeroizing;

use super::auth::{
    acquire_pin_attempt, acquire_unlock_attempt, clear_session_cookie, client_ip, require_session,
    session_cookie,
};
use super::security::{RespKind, require_json, secure_result};
use crate::service::ServiceError;

use super::definition::{
    AuthenticateRequest, CodesResponse, DecryptRequest, DecryptResponse, HealthResponse,
    KeySlotPath, NoContent, OathApi, OpenPgpStatusResponse, PublicKeyResponse, SignRequest,
    SignatureResponse, UnlockRequest, oath_api_mod,
};
use crate::config::Config;
use crate::openpgp::proto::{self as pgp, KeySlot};
use crate::ratelimit::RateLimiter;
use crate::service::Service;
use crate::session::SessionStore;

/// Largest accepted request body. The unlock body is tiny.
pub const REQUEST_BODY_MAX_BYTES: usize = 1024;

const INDEX_HTML: &str = include_str!("../../static/index.html");
const APP_JS: &str = include_str!("../../static/app.js");
const APP_CSS: &str = include_str!("../../static/app.css");
const DOCS_HTML: &str = include_str!("../../static/docs.html");
const DOCS_JS: &str = include_str!("../../static/docs.js");

/// Shared state for every request. Everything is behind `Arc` so tests can
/// build it from mocks.
pub struct ApiContext {
    pub service: Arc<Service>,
    pub sessions: Arc<SessionStore>,
    pub ratelimit: Arc<RateLimiter>,
    /// Limits wrong OpenPGP PINs, separately from OATH unlock.
    pub pin_ratelimit: Arc<RateLimiter>,
    pub config: Arc<Config>,
}

/// Names the API implementation. Never constructed.
pub enum OathApiImpl {}

impl OathApi for OathApiImpl {
    type Context = ApiContext;

    async fn unlock(
        rqctx: RequestContext<ApiContext>,
        body: TypedBody<UnlockRequest>,
    ) -> Result<NoContent, HttpError> {
        secure_result(unlock(&rqctx, body).await, RespKind::Api)
    }

    async fn lock(rqctx: RequestContext<ApiContext>) -> Result<NoContent, HttpError> {
        secure_result(lock(&rqctx).await, RespKind::Api)
    }

    async fn codes(
        rqctx: RequestContext<ApiContext>,
    ) -> Result<HttpResponseHeaders<HttpResponseOk<CodesResponse>>, HttpError> {
        secure_result(codes(&rqctx).await, RespKind::Api)
    }

    async fn openpgp_status(
        rqctx: RequestContext<ApiContext>,
    ) -> Result<HttpResponseHeaders<HttpResponseOk<OpenPgpStatusResponse>>, HttpError> {
        secure_result(openpgp_status(&rqctx).await, RespKind::Api)
    }

    async fn openpgp_public_key(
        rqctx: RequestContext<ApiContext>,
        path: Path<KeySlotPath>,
    ) -> Result<HttpResponseHeaders<HttpResponseOk<PublicKeyResponse>>, HttpError> {
        let slot = path.into_inner().slot.into();
        secure_result(openpgp_public_key(&rqctx, slot).await, RespKind::Api)
    }

    async fn openpgp_sign(
        rqctx: RequestContext<ApiContext>,
        body: TypedBody<SignRequest>,
    ) -> Result<HttpResponseHeaders<HttpResponseOk<SignatureResponse>>, HttpError> {
        secure_result(openpgp_sign(&rqctx, body).await, RespKind::Api)
    }

    async fn openpgp_decrypt(
        rqctx: RequestContext<ApiContext>,
        body: TypedBody<DecryptRequest>,
    ) -> Result<HttpResponseHeaders<HttpResponseOk<DecryptResponse>>, HttpError> {
        secure_result(openpgp_decrypt(&rqctx, body).await, RespKind::Api)
    }

    async fn openpgp_authenticate(
        rqctx: RequestContext<ApiContext>,
        body: TypedBody<AuthenticateRequest>,
    ) -> Result<HttpResponseHeaders<HttpResponseOk<SignatureResponse>>, HttpError> {
        secure_result(openpgp_authenticate(&rqctx, body).await, RespKind::Api)
    }

    async fn healthz(
        rqctx: RequestContext<ApiContext>,
    ) -> Result<HttpResponseHeaders<HttpResponseOk<HealthResponse>>, HttpError> {
        secure_result(healthz(&rqctx).await, RespKind::Api)
    }

    async fn index(_rqctx: RequestContext<ApiContext>) -> Result<Response<Body>, HttpError> {
        secure_result(
            static_file("text/html; charset=utf-8", INDEX_HTML),
            RespKind::Static,
        )
    }

    async fn app_js(_rqctx: RequestContext<ApiContext>) -> Result<Response<Body>, HttpError> {
        secure_result(
            static_file("text/javascript; charset=utf-8", APP_JS),
            RespKind::Static,
        )
    }

    async fn app_css(_rqctx: RequestContext<ApiContext>) -> Result<Response<Body>, HttpError> {
        secure_result(
            static_file("text/css; charset=utf-8", APP_CSS),
            RespKind::Static,
        )
    }

    async fn openapi(_rqctx: RequestContext<ApiContext>) -> Result<Response<Body>, HttpError> {
        static OPENAPI: OnceLock<String> = OnceLock::new();
        secure_result(
            static_file(
                "application/json; charset=utf-8",
                OPENAPI.get_or_init(openapi_json),
            ),
            RespKind::Static,
        )
    }

    async fn docs(_rqctx: RequestContext<ApiContext>) -> Result<Response<Body>, HttpError> {
        secure_result(
            static_file("text/html; charset=utf-8", DOCS_HTML),
            RespKind::Static,
        )
    }

    async fn docs_js(_rqctx: RequestContext<ApiContext>) -> Result<Response<Body>, HttpError> {
        secure_result(
            static_file("text/javascript; charset=utf-8", DOCS_JS),
            RespKind::Static,
        )
    }
}

async fn unlock(
    rqctx: &RequestContext<ApiContext>,
    body: TypedBody<UnlockRequest>,
) -> Result<NoContent, HttpError> {
    require_json(rqctx.request.headers())?;
    let ctx = rqctx.context();
    let permit = acquire_unlock_attempt(rqctx).await?;
    let ip = permit.ip();
    let password = Zeroizing::new(body.into_inner().password);

    match ctx.service.unlock(password).await {
        Ok(key) => {
            permit.success();
            let id = ctx.sessions.create(key);
            info!(rqctx.log, "unlock succeeded";
                "event" => "unlock_success",
                "client_ip" => %ip,
                "session" => id.log_id(),
            );
            with_cookie(session_cookie(&id))
        }
        Err(ServiceError::WrongPassword) => {
            let outcome = permit.failure();
            warn!(rqctx.log, "unlock failed";
                "event" => "unlock_failure",
                "client_ip" => %ip,
                "backoff_secs" => outcome.backoff,
            );
            if outcome.global_lockout_engaged {
                warn!(rqctx.log, "global unlock lockout engaged";
                    "event" => "global_lockout_engaged",
                );
            }
            Err(ServiceError::WrongPassword.into())
        }
        Err(other) => {
            // Never reached the password check, so record nothing.
            drop(permit);
            Err(card_error(&rqctx.log, other))
        }
    }
}

async fn lock(rqctx: &RequestContext<ApiContext>) -> Result<NoContent, HttpError> {
    require_json(rqctx.request.headers())?;
    let session = require_session(rqctx).await?;
    rqctx.context().sessions.remove(session.id());
    info!(rqctx.log, "session locked";
        "event" => "lock",
        "client_ip" => %client_ip(rqctx),
        "session" => session.log_id(),
    );
    with_cookie(clear_session_cookie())
}

async fn codes(
    rqctx: &RequestContext<ApiContext>,
) -> Result<HttpResponseHeaders<HttpResponseOk<CodesResponse>>, HttpError> {
    let ctx = rqctx.context();
    let session = require_session(rqctx).await?;
    let codes = match ctx.service.codes(&session).await {
        Ok(codes) => codes,
        Err(ServiceError::WrongPassword) => {
            // The password changed since unlock; this session is useless now.
            ctx.sessions.remove(session.id());
            return Err(ServiceError::WrongPassword.into());
        }
        Err(other) => return Err(card_error(&rqctx.log, other)),
    };
    info!(rqctx.log, "codes fetched";
        "event" => "codes_fetched",
        "client_ip" => %client_ip(rqctx),
        "session" => session.log_id(),
        "count" => codes.credentials.len(),
    );
    Ok(HttpResponseHeaders::new_unnamed(HttpResponseOk(
        codes.into(),
    )))
}

async fn healthz(
    rqctx: &RequestContext<ApiContext>,
) -> Result<HttpResponseHeaders<HttpResponseOk<HealthResponse>>, HttpError> {
    rqctx.context().service.health().await?;
    Ok(HttpResponseHeaders::new_unnamed(HttpResponseOk(
        HealthResponse {
            status: "ok".into(),
        },
    )))
}

type Ok200<T> = HttpResponseHeaders<HttpResponseOk<T>>;

fn ok<T: serde::Serialize + schemars::JsonSchema + Send + Sync + 'static>(body: T) -> Ok200<T> {
    HttpResponseHeaders::new_unnamed(HttpResponseOk(body))
}

/// Turn a service error into the HTTP error, logging card problems.
fn service_error(log: &Logger, error: ServiceError) -> HttpError {
    match error {
        ServiceError::Unavailable(_)
        | ServiceError::Protocol(_)
        | ServiceError::OpenPgpProtocol(_)
        | ServiceError::CardAuthFailed
        | ServiceError::Internal => card_error(log, error),
        other => other.into(),
    }
}

async fn openpgp_status(
    rqctx: &RequestContext<ApiContext>,
) -> Result<Ok200<OpenPgpStatusResponse>, HttpError> {
    require_session(rqctx).await?;
    let status = rqctx
        .context()
        .service
        .openpgp_status()
        .await
        .map_err(|e| service_error(&rqctx.log, e))?;
    Ok(ok(status.into()))
}

async fn openpgp_public_key(
    rqctx: &RequestContext<ApiContext>,
    slot: KeySlot,
) -> Result<Ok200<PublicKeyResponse>, HttpError> {
    require_session(rqctx).await?;
    let info = rqctx
        .context()
        .service
        .openpgp_public_key(slot)
        .await
        .map_err(|e| service_error(&rqctx.log, e))?;
    Ok(ok(info.into()))
}

/// Decode a base64 request field, or a 400 naming it.
fn base64_field(name: &str, value: &str) -> Result<Vec<u8>, HttpError> {
    BASE64.decode(value).map_err(|_| {
        HttpError::for_client_error(
            Some("BadInput".into()),
            ClientErrorStatusCode::BAD_REQUEST,
            format!("{name} is not valid base64"),
        )
    })
}

/// Run a PIN-protected OpenPGP operation under the PIN rate limit, and
/// write its audit events. `event` names the operation in the log.
async fn with_pin<T>(
    rqctx: &RequestContext<ApiContext>,
    event: &'static str,
    slot: KeySlot,
    input: &[u8],
    operation: impl Future<Output = Result<T, ServiceError>>,
) -> Result<T, HttpError> {
    let session_log_id = require_session(rqctx).await?.log_id();
    let permit = acquire_pin_attempt(rqctx)?;
    let ip = permit.ip();
    match operation.await {
        Ok(out) => {
            permit.success();
            info!(rqctx.log, "OpenPGP key used";
                "event" => event,
                "client_ip" => %ip,
                "session" => &session_log_id,
                "slot" => slot.name(),
                "input" => pgp::input_tag(input),
            );
            Ok(out)
        }
        Err(error @ ServiceError::WrongPin { retries_left }) => {
            let outcome = permit.failure();
            warn!(rqctx.log, "OpenPGP PIN wrong";
                "event" => "openpgp_pin_failure",
                "client_ip" => %ip,
                "session" => &session_log_id,
                "slot" => slot.name(),
                "retries_left" => retries_left,
                "backoff_secs" => outcome.backoff,
            );
            if outcome.global_lockout_engaged {
                warn!(rqctx.log, "global OpenPGP PIN lockout engaged";
                    "event" => "openpgp_pin_lockout_engaged",
                );
            }
            Err(error.into())
        }
        Err(error @ ServiceError::PinRetryFloor { retries_left }) => {
            drop(permit);
            warn!(rqctx.log, "OpenPGP PIN not sent: too few retries left";
                "event" => "openpgp_pin_floor_reached",
                "client_ip" => %ip,
                "session" => &session_log_id,
                "slot" => slot.name(),
                "retries_left" => retries_left,
            );
            Err(error.into())
        }
        Err(other) => {
            // The PIN never reached the card, so record nothing.
            drop(permit);
            Err(service_error(&rqctx.log, other))
        }
    }
}

async fn openpgp_sign(
    rqctx: &RequestContext<ApiContext>,
    body: TypedBody<SignRequest>,
) -> Result<Ok200<SignatureResponse>, HttpError> {
    require_json(rqctx.request.headers())?;
    let request = body.into_inner();
    let pin = Zeroizing::new(request.pin);
    let digest = base64_field("digest", &request.digest)?;
    let service = &rqctx.context().service;
    let operation = service.openpgp_sign(pin, request.hash.into(), digest.clone());
    let signature = with_pin(rqctx, "openpgp_sign", KeySlot::Sign, &digest, operation).await?;
    Ok(ok(signature.into()))
}

async fn openpgp_decrypt(
    rqctx: &RequestContext<ApiContext>,
    body: TypedBody<DecryptRequest>,
) -> Result<Ok200<DecryptResponse>, HttpError> {
    require_json(rqctx.request.headers())?;
    let request = body.into_inner();
    let pin = Zeroizing::new(request.pin);
    let ciphertext = base64_field("ciphertext", &request.ciphertext)?;
    let service = &rqctx.context().service;
    let operation = service.openpgp_decrypt(pin, ciphertext.clone());
    let plaintext = with_pin(
        rqctx,
        "openpgp_decrypt",
        KeySlot::Decrypt,
        &ciphertext,
        operation,
    )
    .await?;
    Ok(ok(DecryptResponse {
        plaintext: BASE64.encode(plaintext.as_slice()),
    }))
}

async fn openpgp_authenticate(
    rqctx: &RequestContext<ApiContext>,
    body: TypedBody<AuthenticateRequest>,
) -> Result<Ok200<SignatureResponse>, HttpError> {
    require_json(rqctx.request.headers())?;
    let request = body.into_inner();
    let pin = Zeroizing::new(request.pin);
    let data = base64_field("data", &request.data)?;
    let service = &rqctx.context().service;
    let operation = service.openpgp_authenticate(pin, data.clone());
    let signature = with_pin(
        rqctx,
        "openpgp_authenticate",
        KeySlot::Auth,
        &data,
        operation,
    )
    .await?;
    Ok(ok(signature.into()))
}

/// Log a card problem as an audit event and turn it into the HTTP error.
fn card_error(log: &Logger, error: ServiceError) -> HttpError {
    let reconnect_attempted = matches!(
        error,
        ServiceError::Unavailable(_) | ServiceError::CardAuthFailed
    );
    error!(log, "card error";
        "event" => "card_error",
        "kind" => %error,
        "reconnect_attempted" => reconnect_attempted,
    );
    error.into()
}

fn with_cookie(cookie: String) -> Result<NoContent, HttpError> {
    let value = HeaderValue::try_from(cookie)
        .map_err(|e| HttpError::for_internal_error(format!("bad cookie header: {e}")))?;
    let mut response = HttpResponseHeaders::new_unnamed(HttpResponseUpdatedNoContent());
    response.headers_mut().insert(SET_COOKIE, value);
    Ok(response)
}

fn static_file(
    content_type: &'static str,
    body: &'static str,
) -> Result<Response<Body>, HttpError> {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .body(Body::from(body))
        .map_err(|e| HttpError::for_internal_error(e.to_string()))
}

/// The API description with the real handlers.
pub fn api() -> ApiDescription<ApiContext> {
    oath_api_mod::api_description::<OathApiImpl>().expect("API description is valid")
}

/// The OpenAPI document, pretty-printed, generated without a card.
pub fn openapi_json() -> String {
    let description = oath_api_mod::stub_api_description().expect("API description is valid");
    let version = dropshot::semver::Version::parse(env!("CARGO_PKG_VERSION"))
        .expect("crate version is semver");
    let mut openapi = description.openapi("totem", version);
    openapi.description(
        "Read TOTP codes from a YubiKey OATH applet, and use the keys in its OpenPGP applet.",
    );
    let value = openapi.json().expect("OpenAPI serialises");
    let mut out = serde_json::to_string_pretty(&value).expect("JSON serialises");
    out.push('\n');
    out
}

/// Start the HTTP server on `bind`.
pub fn start(
    context: ApiContext,
    bind: SocketAddr,
    log: Logger,
) -> Result<HttpServer<ApiContext>, dropshot::BuildError> {
    let config = ConfigDropshot {
        bind_address: bind,
        default_request_body_max_bytes: REQUEST_BODY_MAX_BYTES,
        // Let unlock attempts finish even if the client disconnects, so a
        // failure is always recorded against the rate limit.
        default_handler_task_mode: HandlerTaskMode::Detached,
        ..ConfigDropshot::default()
    };
    ServerBuilder::new(api(), context, log)
        .config(config)
        .start()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::mock::openpgp::{MockKey, MockOpenPgp};
    use crate::card::mock::{MockCard, MockCredential, MockEvent, MockFault};
    use crate::clock::ManualClock;
    use crate::logging::test_support::SharedBuf;
    use crate::oath::crypto::{self, Algorithm};
    use crate::rng::SequentialChallengeSource;
    use reqwest::StatusCode;
    use serde_json::{Value, json};

    const PASSWORD: &str = "correct horse battery";
    const SHA1_SEED: &[u8] = b"12345678901234567890";
    const SHA256_SEED: &[u8] = b"12345678901234567890123456789012";
    /// RFC 6238 codes at t=59 for the two seeds above.
    const CODES_AT_59: [&str; 2] = ["94287082", "46119246"];

    struct Harness {
        server: Option<HttpServer<ApiContext>>,
        base: String,
        client: reqwest::Client,
        card: MockCard,
        clock: Arc<ManualClock>,
        logs: SharedBuf,
    }

    fn rfc_card() -> MockCard {
        MockCard::new()
            .with_password(PASSWORD)
            .with_credential(MockCredential::totp(
                "RFC6238:sha1",
                Algorithm::Sha1,
                8,
                SHA1_SEED,
            ))
            .with_credential(MockCredential::totp(
                "RFC6238:sha256",
                Algorithm::Sha256,
                8,
                SHA256_SEED,
            ))
            .with_credential(
                MockCredential::totp("Touchy:t", Algorithm::Sha1, 6, SHA1_SEED).with_touch(),
            )
            .with_credential(MockCredential::hotp(
                "Counter:h",
                Algorithm::Sha1,
                6,
                SHA1_SEED,
            ))
            .with_openpgp(
                MockOpenPgp::new(PIN)
                    .with_key(pgp::KeySlot::Sign, MockKey::rsa2048(b"sig"))
                    .with_key(pgp::KeySlot::Decrypt, MockKey::rsa2048(b"dec"))
                    .with_key(pgp::KeySlot::Auth, MockKey::ed25519(b"aut")),
            )
    }

    const PIN: &str = "pin-123456";
    const DIGEST: [u8; 32] = [0x42; 32];

    fn base_config() -> Config {
        Config::from_lookup(|_| None).unwrap()
    }

    async fn harness_with(card: MockCard, config: Config) -> Harness {
        let clock = Arc::new(ManualClock::new(59));
        let rng = Arc::new(SequentialChallengeSource::new(0x40));
        let logs = SharedBuf::default();
        let context = ApiContext {
            service: Arc::new(Service::new(
                Box::new(card.clone()),
                clock.clone(),
                rng.clone(),
            )),
            sessions: Arc::new(SessionStore::new(
                clock.clone(),
                rng,
                config.session_idle_secs,
                config.session_max_secs,
            )),
            ratelimit: Arc::new(RateLimiter::new(clock.clone(), config.global_fail_limit)),
            pin_ratelimit: Arc::new(RateLimiter::new(
                clock.clone(),
                config.openpgp_global_fail_limit,
            )),
            config: Arc::new(config),
        };
        let server = start(context, "127.0.0.1:0".parse().unwrap(), logs.logger()).unwrap();
        let base = format!("http://{}", server.local_addr());
        Harness {
            server: Some(server),
            base,
            client: reqwest::Client::new(),
            card,
            clock,
            logs,
        }
    }

    async fn harness() -> Harness {
        harness_with(rfc_card(), base_config()).await
    }

    impl Harness {
        fn url(&self, path: &str) -> String {
            format!("{}{path}", self.base)
        }

        async fn unlock_with(&self, password: &str, xff: Option<&str>) -> reqwest::Response {
            let mut request = self
                .client
                .post(self.url("/api/unlock"))
                .header("content-type", "application/json")
                .body(json!({ "password": password }).to_string());
            if let Some(xff) = xff {
                request = request.header("x-forwarded-for", xff);
            }
            request.send().await.unwrap()
        }

        async fn unlock(&self, password: &str) -> reqwest::Response {
            self.unlock_with(password, None).await
        }

        /// Unlock and return the `name=value` part of the session cookie.
        async fn login(&self) -> String {
            let response = self.unlock(PASSWORD).await;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            set_cookie(&response).split(';').next().unwrap().to_owned()
        }

        async fn get(&self, path: &str, cookie: Option<&str>) -> reqwest::Response {
            let mut request = self.client.get(self.url(path));
            if let Some(cookie) = cookie {
                request = request.header("cookie", cookie);
            }
            request.send().await.unwrap()
        }

        async fn lock(&self, cookie: Option<&str>) -> reqwest::Response {
            let mut request = self
                .client
                .post(self.url("/api/lock"))
                .header("content-type", "application/json");
            if let Some(cookie) = cookie {
                request = request.header("cookie", cookie);
            }
            request.send().await.unwrap()
        }

        async fn post(&self, path: &str, cookie: Option<&str>, body: Value) -> reqwest::Response {
            let mut request = self
                .client
                .post(self.url(path))
                .header("content-type", "application/json")
                .body(body.to_string());
            if let Some(cookie) = cookie {
                request = request.header("cookie", cookie);
            }
            request.send().await.unwrap()
        }

        async fn sign(&self, cookie: &str, pin: &str) -> reqwest::Response {
            self.post(
                "/api/openpgp/sign",
                Some(cookie),
                json!({ "pin": pin, "hash": "sha256", "digest": BASE64.encode(DIGEST) }),
            )
            .await
        }

        async fn shutdown(mut self) -> String {
            self.server.take().unwrap().close().await.unwrap();
            self.logs.text()
        }
    }

    fn set_cookie(response: &reqwest::Response) -> String {
        response
            .headers()
            .get("set-cookie")
            .expect("set-cookie header")
            .to_str()
            .unwrap()
            .to_owned()
    }

    fn header<'a>(response: &'a reqwest::Response, name: &str) -> Option<&'a str> {
        response.headers().get(name).map(|v| v.to_str().unwrap())
    }

    fn assert_security_headers(response: &reqwest::Response, api: bool) {
        let path = response.url().path().to_owned();
        assert_eq!(
            header(response, "content-security-policy"),
            Some(super::super::security::CSP),
            "{path}"
        );
        assert_eq!(
            header(response, "x-content-type-options"),
            Some("nosniff"),
            "{path}"
        );
        assert_eq!(
            header(response, "referrer-policy"),
            Some("no-referrer"),
            "{path}"
        );
        if api {
            assert_eq!(
                header(response, "cache-control"),
                Some("no-store"),
                "{path}"
            );
        }
    }

    fn apdu_count(card: &MockCard) -> usize {
        card.events()
            .iter()
            .filter(|e| matches!(e, crate::card::mock::MockEvent::Apdu(_)))
            .count()
    }

    // Unlock

    #[tokio::test]
    async fn unlock_with_correct_password_sets_secure_session_cookie() {
        let h = harness().await;
        let response = h.unlock(PASSWORD).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let cookie = set_cookie(&response);
        let (pair, attributes) = cookie.split_once("; ").unwrap();
        let (name, value) = pair.split_once('=').unwrap();
        assert_eq!(name, "oath_session");
        assert_eq!(value.len(), 64);
        for attribute in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/"] {
            assert!(attributes.split("; ").any(|a| a == attribute), "{cookie}");
        }
        assert_security_headers(&response, true);
        h.shutdown().await;
    }

    #[tokio::test]
    async fn wrong_password_returns_401_then_429_with_retry_after() {
        let h = harness().await;
        let response = h.unlock("wrong").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get("set-cookie").is_none());
        assert_security_headers(&response, true);

        let response = h.unlock("wrong").await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(header(&response, "retry-after"), Some("1"));
        assert_security_headers(&response, true);

        h.clock.advance(1);
        assert_eq!(h.unlock("wrong").await.status(), StatusCode::UNAUTHORIZED);
        let response = h.unlock(PASSWORD).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(header(&response, "retry-after"), Some("2"));
        h.shutdown().await;
    }

    #[tokio::test]
    async fn rate_limited_unlock_does_not_touch_the_card() {
        let h = harness().await;
        h.unlock("wrong").await;
        let before = apdu_count(&h.card);
        assert_eq!(
            h.unlock(PASSWORD).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(apdu_count(&h.card), before);
        h.shutdown().await;
    }

    #[tokio::test]
    async fn global_lockout_applies_to_every_client() {
        let mut config = base_config();
        config.global_fail_limit = 2;
        config.trusted_proxies = vec!["127.0.0.0/8".parse().unwrap()];
        let h = harness_with(rfc_card(), config).await;
        assert_eq!(h.unlock_with("x", Some("192.168.1.1")).await.status(), 401);
        assert_eq!(h.unlock_with("x", Some("192.168.1.2")).await.status(), 401);
        let response = h.unlock_with(PASSWORD, Some("192.168.1.3")).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(header(&response, "retry-after"), Some("900"));
        let logs = h.shutdown().await;
        assert!(logs.contains("global_lockout_engaged"), "{logs}");
    }

    #[tokio::test]
    async fn forwarded_for_is_honoured_only_from_trusted_proxy() {
        let mut config = base_config();
        config.trusted_proxies = vec!["127.0.0.0/8".parse().unwrap()];
        let h = harness_with(rfc_card(), config).await;
        assert_eq!(h.unlock_with("x", Some("192.168.1.1")).await.status(), 401);
        // A different forwarded client is not affected by the first one's backoff.
        assert_eq!(h.unlock_with("x", Some("192.168.1.2")).await.status(), 401);
        let logs = h.shutdown().await;
        assert!(
            logs.contains("192.168.1.1") && logs.contains("192.168.1.2"),
            "{logs}"
        );

        // Without trust, both requests are the same peer and the second is limited.
        let h = harness().await;
        assert_eq!(h.unlock_with("x", Some("192.168.1.1")).await.status(), 401);
        assert_eq!(h.unlock_with("x", Some("192.168.1.2")).await.status(), 429);
        h.shutdown().await;
    }

    #[tokio::test]
    async fn non_json_content_type_is_rejected() {
        let h = harness().await;
        let body = json!({ "password": PASSWORD }).to_string();
        for content_type in [
            None,
            Some("text/plain"),
            Some("application/merge-patch+json"),
        ] {
            let mut request = h.client.post(h.url("/api/unlock")).body(body.clone());
            if let Some(content_type) = content_type {
                request = request.header("content-type", content_type);
            }
            let response = request.send().await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "{content_type:?}"
            );
        }
        assert_eq!(apdu_count(&h.card), 0);
        // None of these counted as a failed attempt.
        assert_eq!(h.unlock(PASSWORD).await.status(), StatusCode::NO_CONTENT);
        h.shutdown().await;
    }

    #[tokio::test]
    async fn oversized_body_is_rejected() {
        let h = harness().await;
        let response = h
            .client
            .post(h.url("/api/unlock"))
            .header("content-type", "application/json")
            .body(json!({ "password": "x".repeat(REQUEST_BODY_MAX_BYTES) }).to_string())
            .send()
            .await
            .unwrap();
        assert!(response.status().is_client_error(), "{}", response.status());
        assert_eq!(apdu_count(&h.card), 0);
        h.shutdown().await;
    }

    // Codes

    #[tokio::test]
    async fn codes_without_session_is_401() {
        let h = harness().await;
        let response = h.get("/api/codes", None).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_security_headers(&response, true);
        let bogus = format!("oath_session={}", "00".repeat(32));
        assert_eq!(h.get("/api/codes", Some(&bogus)).await.status(), 401);
        h.shutdown().await;
    }

    #[tokio::test]
    async fn codes_with_session_returns_documented_shape() {
        let h = harness().await;
        let cookie = h.login().await;
        let response = h.get("/api/codes", Some(&cookie)).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_security_headers(&response, true);
        let body: Value = response.json_value().await;
        assert_eq!(
            body,
            json!({
                "generated_at": 59,
                "credentials": [
                    { "issuer": "RFC6238", "account": "sha1", "status": "ok",
                      "code": CODES_AT_59[0], "digits": 8, "period": 30,
                      "valid_from": 30, "valid_until": 60 },
                    { "issuer": "RFC6238", "account": "sha256", "status": "ok",
                      "code": CODES_AT_59[1], "digits": 8, "period": 30,
                      "valid_from": 30, "valid_until": 60 },
                    { "issuer": "Touchy", "account": "t", "status": "touch_required" },
                    { "issuer": "Counter", "account": "h", "status": "hotp" }
                ]
            })
        );
        h.shutdown().await;
    }

    #[tokio::test]
    async fn session_expires_after_idle_timeout() {
        let h = harness().await;
        let cookie = h.login().await;
        h.clock.advance(base_config().session_idle_secs);
        assert_eq!(h.get("/api/codes", Some(&cookie)).await.status(), 401);
        h.shutdown().await;
    }

    #[tokio::test]
    async fn card_unavailable_returns_503_without_details() {
        let h = harness().await;
        let cookie = h.login().await;
        h.card.fail_next(100, MockFault::Removed);
        let response = h.get("/api/codes", Some(&cookie)).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_security_headers(&response, true);
        let text = response.text().await.unwrap();
        assert!(text.contains("card unavailable"), "{text}");
        assert!(!text.to_lowercase().contains("removed"), "{text}");
        let logs = h.shutdown().await;
        assert!(logs.contains("card_error"), "{logs}");
    }

    #[tokio::test]
    async fn stale_session_after_password_change_is_401_and_removed() {
        let card = rfc_card();
        let h = harness_with(card.clone(), base_config()).await;
        let cookie = h.login().await;
        // Same card, new password: the stored key no longer validates.
        let _ = card.with_password("a new password");
        assert_eq!(h.get("/api/codes", Some(&cookie)).await.status(), 401);
        let _ = h.card.clone().with_password(PASSWORD);
        assert_eq!(h.get("/api/codes", Some(&cookie)).await.status(), 401);
        h.shutdown().await;
    }

    // Lock

    #[tokio::test]
    async fn lock_deletes_session_and_clears_cookie() {
        let h = harness().await;
        let cookie = h.login().await;
        let response = h.lock(Some(&cookie)).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_security_headers(&response, true);
        let cleared = set_cookie(&response);
        assert!(cleared.starts_with("oath_session=;"), "{cleared}");
        assert!(cleared.contains("Max-Age=0"), "{cleared}");
        assert_eq!(h.get("/api/codes", Some(&cookie)).await.status(), 401);
        h.shutdown().await;
    }

    #[tokio::test]
    async fn lock_without_session_is_401() {
        let h = harness().await;
        assert_eq!(h.lock(None).await.status(), StatusCode::UNAUTHORIZED);
        h.shutdown().await;
    }

    #[tokio::test]
    async fn lock_requires_json_content_type() {
        let h = harness().await;
        let cookie = h.login().await;
        let response = h
            .client
            .post(h.url("/api/lock"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(h.get("/api/codes", Some(&cookie)).await.status(), 200);
        h.shutdown().await;
    }

    // Health

    #[tokio::test]
    async fn healthz_is_ok_and_has_no_account_names() {
        let h = harness().await;
        let response = h.get("/healthz", None).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_security_headers(&response, true);
        let text = response.text().await.unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&text).unwrap(),
            json!({ "status": "ok" })
        );
        for name in ["RFC6238", "sha1", "Touchy", "Counter"] {
            assert!(!text.contains(name), "{text}");
        }
        h.shutdown().await;
    }

    #[tokio::test]
    async fn healthz_is_503_when_card_unavailable() {
        let h = harness().await;
        h.card.fail_next(100, MockFault::NoCard);
        let response = h.get("/healthz", None).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_security_headers(&response, true);
        let text = response.text().await.unwrap();
        assert!(!text.contains("RFC6238"), "{text}");
        h.shutdown().await;
    }

    // Static frontend

    #[tokio::test]
    async fn static_files_have_correct_content_types_and_headers() {
        let h = harness().await;
        for (path, content_type, body) in [
            ("/", "text/html; charset=utf-8", INDEX_HTML),
            ("/app.js", "text/javascript; charset=utf-8", APP_JS),
            ("/app.css", "text/css; charset=utf-8", APP_CSS),
            ("/docs", "text/html; charset=utf-8", DOCS_HTML),
            ("/docs.js", "text/javascript; charset=utf-8", DOCS_JS),
        ] {
            let response = h.get(path, None).await;
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(
                header(&response, "content-type"),
                Some(content_type),
                "{path}"
            );
            assert_security_headers(&response, false);
            assert_eq!(response.text().await.unwrap(), body, "{path}");
        }
        h.shutdown().await;
    }

    #[tokio::test]
    async fn openapi_document_is_served_as_generated() {
        let h = harness().await;
        let response = h.get("/openapi.json", None).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            header(&response, "content-type"),
            Some("application/json; charset=utf-8")
        );
        assert_security_headers(&response, false);
        assert_eq!(response.text().await.unwrap(), openapi_json());
        h.shutdown().await;
    }

    // Static file rules. The CSP (default-src 'self') would silently break
    // anything inline, so check the files themselves.

    const STATIC_FILES: [(&str, &str); 5] = [
        ("index.html", INDEX_HTML),
        ("app.js", APP_JS),
        ("app.css", APP_CSS),
        ("docs.html", DOCS_HTML),
        ("docs.js", DOCS_JS),
    ];

    const PAGES: [(&str, &str, &str); 2] = [
        ("index.html", INDEX_HTML, APP_JS),
        ("docs.html", DOCS_HTML, DOCS_JS),
    ];

    /// Attribute names in `html` that start with `on`, like `onclick`.
    fn inline_handlers(html: &str) -> Vec<String> {
        let lower = html.to_ascii_lowercase();
        let bytes = lower.as_bytes();
        let mut found = Vec::new();
        for (i, window) in bytes.windows(3).enumerate() {
            if !(window[0].is_ascii_whitespace() && window[1] == b'o' && window[2] == b'n') {
                continue;
            }
            let name: String = lower[i + 1..]
                .chars()
                .take_while(|c| c.is_ascii_alphabetic())
                .collect();
            if name.len() > 2 && lower[i + 1 + name.len()..].trim_start().starts_with('=') {
                found.push(name);
            }
        }
        found
    }

    #[test]
    fn pages_have_no_inline_script_style_or_handlers() {
        for (name, html, _) in PAGES {
            assert_no_inline_code(name, html);
        }
    }

    fn assert_no_inline_code(name: &str, html: &str) {
        let lower = html.to_ascii_lowercase();
        let mut rest = lower.as_str();
        let mut scripts = 0;
        while let Some(start) = rest.find("<script") {
            let tag_end = rest[start..].find('>').unwrap() + start;
            let tag = &rest[start..=tag_end];
            assert!(tag.contains("src="), "{name}: inline script: {tag}");
            assert!(
                rest[tag_end + 1..].starts_with("</script>"),
                "{name}: script has a body: {tag}"
            );
            scripts += 1;
            rest = &rest[tag_end..];
        }
        assert_eq!(scripts, 1, "{name}");
        assert!(!lower.contains("<style"), "{name}: inline <style>");
        assert!(!lower.contains(" style="), "{name}: style attribute");
        assert_eq!(inline_handlers(html), Vec::<String>::new(), "{name}");
    }

    #[test]
    fn unlock_form_supports_password_managers() {
        // Browsers and password managers expect a username next to a
        // password; a fixed, hidden one keeps them from guessing.
        assert!(INDEX_HTML.contains(r#"autocomplete="username""#));
        assert!(INDEX_HTML.contains(r#"autocomplete="current-password""#));
    }

    #[test]
    fn inline_handler_check_finds_handlers() {
        assert_eq!(inline_handlers(r#"<a onclick="x()">"#), ["onclick"]);
        assert_eq!(inline_handlers(r#"<b ONLOAD = 'x'>"#), ["onload"]);
        assert!(inline_handlers(r#"<p class="once">on time</p>"#).is_empty());
    }

    #[test]
    fn static_files_reference_no_external_urls() {
        for (name, body) in STATIC_FILES {
            let lower = body.to_ascii_lowercase();
            for needle in [
                "http://",
                "https://",
                "src=\"//",
                "href=\"//",
                "url(//",
                "@import",
            ] {
                assert!(!lower.contains(needle), "{name} contains {needle}");
            }
        }
    }

    #[test]
    fn every_element_a_script_looks_up_exists_in_its_page() {
        for (name, html, js) in PAGES {
            let mut ids = Vec::new();
            let mut rest = js;
            while let Some(start) = rest.find("getElementById(\"") {
                let after = &rest[start + "getElementById(\"".len()..];
                let end = after.find('"').unwrap();
                ids.push(&after[..end]);
                rest = &after[end..];
            }
            assert!(ids.len() >= 5, "{name}: script looks up {ids:?}");
            for id in ids {
                assert!(
                    html.contains(&format!("id=\"{id}\"")),
                    "{name} has no id {id:?}"
                );
            }
        }
    }

    #[test]
    fn scripts_never_parse_strings_as_html_or_code() {
        for banned in [
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "eval(",
            "new Function",
            "setAttribute(\"style\"",
        ] {
            for (name, _, js) in PAGES {
                assert!(!js.contains(banned), "script for {name} uses {banned}");
            }
        }
    }

    // Every endpoint

    #[tokio::test]
    async fn every_endpoint_returns_security_headers() {
        let h = harness().await;
        let cookie = h.login().await;
        let router = api().into_router();
        let mut seen = 0;
        for (path, method, _) in router.endpoints(None) {
            let method: reqwest::Method = method.parse().unwrap();
            let url = h.url(&path.replace("{slot}", "sign"));
            // One body that parses for every endpoint, so each request
            // reaches its handler.
            let body = json!({
                "password": "probe",
                "pin": "probe",
                "hash": "sha256",
                "digest": "",
                "ciphertext": "",
                "data": "",
            });
            let response = h
                .client
                .request(method.clone(), url)
                .header("content-type", "application/json")
                .header("cookie", &cookie)
                .body(body.to_string())
                .send()
                .await
                .unwrap();
            let api_path = path.starts_with("/api/") || path == "/healthz";
            assert_security_headers(&response, api_path);
            seen += 1;
        }
        assert_eq!(seen, 15);
        h.shutdown().await;
    }

    // Logs

    #[tokio::test]
    async fn audit_events_are_logged() {
        let h = harness().await;
        h.unlock("wrong").await;
        h.clock.advance(1);
        let cookie = h.login().await;
        h.get("/api/codes", Some(&cookie)).await;
        h.lock(Some(&cookie)).await;
        let logs = h.shutdown().await;
        for event in ["unlock_failure", "unlock_success", "codes_fetched", "lock"] {
            assert!(
                logs.lines()
                    .any(|l| l.contains(&format!("\"event\":\"{event}\""))),
                "{event} missing from {logs}"
            );
        }
    }

    #[tokio::test]
    async fn logs_never_contain_password_key_session_id_or_codes() {
        let h = harness().await;
        h.unlock("hunter2-wrong-guess").await;
        h.clock.advance(1);
        let cookie = h.login().await;
        let session_value = cookie.split_once('=').unwrap().1.to_owned();
        h.get("/api/codes", Some(&cookie)).await;
        h.lock(Some(&cookie)).await;
        let logs = h.shutdown().await;

        let key = crypto::derive_key(PASSWORD, &MockCard::DEFAULT_DEVICE_ID);
        let key_hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        for secret in [
            PASSWORD,
            "hunter2-wrong-guess",
            &key_hex,
            &session_value,
            CODES_AT_59[0],
            CODES_AT_59[1],
        ] {
            assert!(!logs.contains(secret), "log contains {secret:?}");
        }
        assert!(!logs.is_empty());
    }

    // OpenPGP

    fn error_code(value: &Value) -> &str {
        value["error_code"].as_str().unwrap()
    }

    fn verifies(card: &MockCard) -> usize {
        card.events()
            .iter()
            .filter(|e| matches!(e, MockEvent::Apdu(a) if a[1] == 0x20))
            .count()
    }

    fn rsa_sha256_signature_input(digest: &[u8]) -> Vec<u8> {
        pgp::signature_input(
            &pgp::Algorithm::Rsa { bits: 2048 },
            pgp::HashAlgorithm::Sha256,
            digest,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn openpgp_endpoints_need_a_session() {
        let h = harness().await;
        assert_eq!(
            h.get("/api/openpgp", None).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            h.get("/api/openpgp/keys/sign", None).await.status(),
            StatusCode::UNAUTHORIZED
        );
        let response = h
            .post(
                "/api/openpgp/sign",
                None,
                json!({ "pin": PIN, "hash": "sha256", "digest": BASE64.encode(DIGEST) }),
            )
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(verifies(&h.card), 0);
        h.shutdown().await;
    }

    #[tokio::test]
    async fn openpgp_status_lists_keys_and_retries() {
        let h = harness().await;
        let cookie = h.login().await;
        let response = h.get("/api/openpgp", Some(&cookie)).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_security_headers(&response, true);
        let body = response.json_value().await;
        assert_eq!(body["version"], "3.4");
        assert_eq!(body["serial"], "12345678");
        assert_eq!(body["pin_retries"]["pin"], 3);
        assert_eq!(body["signature_counter"], 0);
        assert_eq!(body["keys"][0]["slot"], "sign");
        assert_eq!(body["keys"][0]["algorithm"], "rsa2048");
        assert_eq!(body["keys"][2]["algorithm"], "ed25519");
        assert_eq!(
            body["keys"][1]["fingerprint"],
            pgp::fingerprint_hex(&MockKey::rsa2048(b"dec").fingerprint())
        );
        h.shutdown().await;
    }

    #[tokio::test]
    async fn openpgp_public_keys_are_base64() {
        let h = harness().await;
        let cookie = h.login().await;
        let body = h
            .get("/api/openpgp/keys/sign", Some(&cookie))
            .await
            .json_value()
            .await;
        assert_eq!(body["type"], "rsa");
        assert_eq!(
            body["modulus"],
            BASE64.encode(MockKey::rsa2048(b"sig").public_value())
        );
        assert_eq!(body["exponent"], "AQAB");
        let body = h
            .get("/api/openpgp/keys/auth", Some(&cookie))
            .await
            .json_value()
            .await;
        assert_eq!(body["type"], "ec");
        assert_eq!(body["algorithm"], "ed25519");
        assert_eq!(
            body["point"],
            BASE64.encode(MockKey::ed25519(b"aut").public_value())
        );
        let response = h.get("/api/openpgp/keys/nope", Some(&cookie)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        h.shutdown().await;
    }

    #[tokio::test]
    async fn openpgp_sign_returns_the_card_signature() {
        let h = harness().await;
        let cookie = h.login().await;
        let response = h.sign(&cookie, PIN).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_security_headers(&response, true);
        let body = response.json_value().await;
        let expected = MockKey::rsa2048(b"sig").signature(&rsa_sha256_signature_input(&DIGEST));
        assert_eq!(body["signature"], BASE64.encode(expected));
        h.shutdown().await;
    }

    #[tokio::test]
    async fn openpgp_decrypt_and_authenticate_work() {
        let h = harness().await;
        let cookie = h.login().await;
        // Bigger than the global 1 KiB body limit, within the OpenPGP one.
        let ciphertext = vec![0x5A; 900];
        let response = h
            .post(
                "/api/openpgp/decrypt",
                Some(&cookie),
                json!({ "pin": PIN, "ciphertext": BASE64.encode(&ciphertext) }),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let mut input = vec![0x00];
        input.extend_from_slice(&ciphertext);
        assert_eq!(
            response.json_value().await["plaintext"],
            BASE64.encode(MockKey::rsa2048(b"dec").plaintext(&input))
        );

        let response = h
            .post(
                "/api/openpgp/authenticate",
                Some(&cookie),
                json!({ "pin": PIN, "data": BASE64.encode(b"challenge") }),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.json_value().await["signature"],
            BASE64.encode(MockKey::ed25519(b"aut").signature(b"challenge"))
        );
        h.shutdown().await;
    }

    #[tokio::test]
    async fn openpgp_body_over_the_limit_is_rejected() {
        let h = harness().await;
        let cookie = h.login().await;
        let response = h
            .post(
                "/api/openpgp/decrypt",
                Some(&cookie),
                json!({ "pin": PIN, "ciphertext": "A".repeat(5000) }),
            )
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(verifies(&h.card), 0);
        h.shutdown().await;
    }

    #[tokio::test]
    async fn wrong_pin_is_403_then_backed_off() {
        let h = harness().await;
        let cookie = h.login().await;
        let response = h.sign(&cookie, "wrong-pin").await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = response.json_value().await;
        assert_eq!(error_code(&body), "WrongPin");
        assert_eq!(body["message"], "wrong PIN, 2 tries left");

        let response = h.sign(&cookie, PIN).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(header(&response, "retry-after"), Some("1"));

        h.clock.advance(1);
        assert_eq!(h.sign(&cookie, PIN).await.status(), StatusCode::OK);
        assert_eq!(h.card.openpgp(MockOpenPgp::pin_retries), 3);
        h.shutdown().await;
    }

    #[tokio::test]
    async fn pin_is_never_sent_at_the_retry_floor() {
        let h = harness().await;
        let cookie = h.login().await;
        assert_eq!(
            h.sign(&cookie, "wrong-pin").await.status(),
            StatusCode::FORBIDDEN
        );
        h.clock.advance(1);
        assert_eq!(
            h.sign(&cookie, "wrong-pin").await.status(),
            StatusCode::FORBIDDEN
        );
        h.clock.advance(60);
        h.card.clear_events();
        let response = h.sign(&cookie, PIN).await;
        assert_eq!(response.status(), StatusCode::LOCKED);
        assert_eq!(error_code(&response.json_value().await), "PinRetryFloor");
        assert_eq!(verifies(&h.card), 0);
        assert_eq!(h.card.openpgp(MockOpenPgp::pin_retries), 1);
        let logs = h.shutdown().await;
        assert!(logs.contains("\"event\":\"openpgp_pin_floor_reached\""));
    }

    #[tokio::test]
    async fn bad_openpgp_input_is_400_and_costs_no_pin_try() {
        let h = harness().await;
        let cookie = h.login().await;
        for (path, body, code) in [
            (
                "/api/openpgp/sign",
                json!({ "pin": PIN, "hash": "sha256", "digest": "not base64!" }),
                "BadInput",
            ),
            (
                "/api/openpgp/sign",
                json!({ "pin": PIN, "hash": "sha512", "digest": BASE64.encode(DIGEST) }),
                "BadInput",
            ),
            (
                "/api/openpgp/sign",
                json!({ "pin": "123", "hash": "sha256", "digest": BASE64.encode(DIGEST) }),
                "BadPin",
            ),
            (
                "/api/openpgp/decrypt",
                json!({ "pin": PIN, "ciphertext": "" }),
                "BadInput",
            ),
        ] {
            let response = h.post(path, Some(&cookie), body).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
            assert_eq!(error_code(&response.json_value().await), code, "{path}");
        }
        assert_eq!(verifies(&h.card), 0);
        // None of those counted against the PIN rate limit.
        assert_eq!(h.sign(&cookie, PIN).await.status(), StatusCode::OK);
        h.shutdown().await;
    }

    #[tokio::test]
    async fn openpgp_post_needs_json_content_type() {
        let h = harness().await;
        let cookie = h.login().await;
        let response = h
            .client
            .post(h.url("/api/openpgp/sign"))
            .header("content-type", "text/plain")
            .header("cookie", &cookie)
            .body(json!({ "pin": PIN, "hash": "sha256", "digest": "" }).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        h.shutdown().await;
    }

    #[tokio::test]
    async fn touch_key_is_409_and_shown_in_status() {
        let card = MockCard::new().with_password(PASSWORD).with_openpgp(
            MockOpenPgp::new(PIN)
                .with_key(pgp::KeySlot::Sign, MockKey::rsa2048(b"sig"))
                .with_touch(pgp::KeySlot::Sign, 0x03),
        );
        let h = harness_with(card, base_config()).await;
        let cookie = h.login().await;
        let status = h
            .get("/api/openpgp", Some(&cookie))
            .await
            .json_value()
            .await;
        assert_eq!(status["keys"][0]["touch_policy"], "cached");
        assert_eq!(status["keys"][1]["touch_policy"], "off");
        let response = h.sign(&cookie, PIN).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(error_code(&response.json_value().await), "TouchRequired");
        assert_eq!(verifies(&h.card), 0);
        h.shutdown().await;
    }

    #[tokio::test]
    async fn kdf_card_signs_through_the_api() {
        let card = MockCard::new().with_password(PASSWORD).with_openpgp(
            MockOpenPgp::new(PIN)
                .with_kdf(pgp::Kdf::IterSaltedS2k {
                    hash: pgp::KdfHash::Sha512,
                    count: 1024,
                    pw1_salt: vec![3; 8],
                })
                .with_key(pgp::KeySlot::Sign, MockKey::rsa2048(b"sig")),
        );
        let h = harness_with(card, base_config()).await;
        let cookie = h.login().await;
        let status = h
            .get("/api/openpgp", Some(&cookie))
            .await
            .json_value()
            .await;
        assert_eq!(status["kdf_enabled"], true);
        assert_eq!(h.sign(&cookie, PIN).await.status(), StatusCode::OK);
        assert_eq!(h.card.openpgp(MockOpenPgp::pin_retries), 3);
        h.shutdown().await;
    }

    #[tokio::test]
    async fn card_without_openpgp_is_404() {
        let card = MockCard::new().with_password(PASSWORD);
        let h = harness_with(card, base_config()).await;
        let cookie = h.login().await;
        let response = h.get("/api/openpgp", Some(&cookie)).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            error_code(&response.json_value().await),
            "OpenPgpUnavailable"
        );
        let response = h.sign(&cookie, PIN).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        h.shutdown().await;
    }

    #[tokio::test]
    async fn openpgp_audit_events_are_logged_without_secrets() {
        let h = harness().await;
        let cookie = h.login().await;
        let signature = h.sign(&cookie, PIN).await.json_value().await["signature"].clone();
        h.clock.advance(1);
        h.sign(&cookie, "wrong-pin-guess").await;
        h.clock.advance(10);
        let ciphertext = BASE64.encode([0x77; 64]);
        let plaintext = h
            .post(
                "/api/openpgp/decrypt",
                Some(&cookie),
                json!({ "pin": PIN, "ciphertext": ciphertext }),
            )
            .await
            .json_value()
            .await["plaintext"]
            .clone();
        let auth = h
            .post(
                "/api/openpgp/authenticate",
                Some(&cookie),
                json!({ "pin": PIN, "data": BASE64.encode(b"ssh-challenge") }),
            )
            .await
            .json_value()
            .await["signature"]
            .clone();
        let logs = h.shutdown().await;
        for event in [
            "openpgp_sign",
            "openpgp_pin_failure",
            "openpgp_decrypt",
            "openpgp_authenticate",
        ] {
            assert!(
                logs.contains(&format!("\"event\":\"{event}\"")),
                "{event} missing from {logs}"
            );
        }
        let digest_b64 = BASE64.encode(DIGEST);
        let digest_hex: String = DIGEST.iter().map(|b| format!("{b:02x}")).collect();
        for secret in [
            PIN,
            "wrong-pin-guess",
            &digest_b64,
            &digest_hex,
            &ciphertext,
            "ssh-challenge",
            signature.as_str().unwrap(),
            plaintext.as_str().unwrap(),
            auth.as_str().unwrap(),
        ] {
            assert!(!logs.contains(secret), "log contains {secret:?}");
        }
    }

    // OpenAPI

    #[test]
    fn openapi_matches_committed_document() {
        expectorate::assert_contents("openapi/totem.json", &openapi_json());
    }

    #[test]
    fn unpublished_static_endpoints_are_not_in_openapi() {
        let doc: Value = serde_json::from_str(&openapi_json()).unwrap();
        let mut paths: Vec<&str> = doc["paths"]
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        paths.sort_unstable();
        assert_eq!(
            paths,
            [
                "/api/codes",
                "/api/lock",
                "/api/openpgp",
                "/api/openpgp/authenticate",
                "/api/openpgp/decrypt",
                "/api/openpgp/keys/{slot}",
                "/api/openpgp/sign",
                "/api/unlock",
                "/healthz"
            ]
        );
    }

    trait JsonValue {
        async fn json_value(self) -> Value;
    }

    impl JsonValue for reqwest::Response {
        async fn json_value(self) -> Value {
            serde_json::from_str(&self.text().await.unwrap()).unwrap()
        }
    }
}
