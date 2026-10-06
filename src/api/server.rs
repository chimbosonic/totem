//! API implementation, server context, and server startup.

use std::net::SocketAddr;
use std::sync::Arc;

use dropshot::{
    ApiDescription, Body, ConfigDropshot, HandlerTaskMode, HttpError, HttpResponseHeaders,
    HttpResponseOk, HttpServer, RequestContext, ServerBuilder, TypedBody,
};
use http::Response;
use slog::Logger;

use super::definition::{
    CodesResponse, HealthResponse, NoContent, OathApi, UnlockRequest, oath_api_mod,
};
use crate::config::Config;
use crate::ratelimit::RateLimiter;
use crate::service::Service;
use crate::session::SessionStore;

/// Largest accepted request body. The unlock body is tiny.
pub const REQUEST_BODY_MAX_BYTES: usize = 1024;

const INDEX_HTML: &str = include_str!("../../static/index.html");
const APP_JS: &str = include_str!("../../static/app.js");
const APP_CSS: &str = include_str!("../../static/app.css");

/// Shared state for every request. Everything is behind `Arc` so tests can
/// build it from mocks.
pub struct ApiContext {
    pub service: Arc<Service>,
    pub sessions: Arc<SessionStore>,
    pub ratelimit: Arc<RateLimiter>,
    pub config: Arc<Config>,
}

/// Names the API implementation. Never constructed.
pub enum OathApiImpl {}

impl OathApi for OathApiImpl {
    type Context = ApiContext;

    async fn unlock(
        _rqctx: RequestContext<ApiContext>,
        _body: TypedBody<UnlockRequest>,
    ) -> Result<NoContent, HttpError> {
        todo!()
    }

    async fn lock(_rqctx: RequestContext<ApiContext>) -> Result<NoContent, HttpError> {
        todo!()
    }

    async fn codes(
        _rqctx: RequestContext<ApiContext>,
    ) -> Result<HttpResponseHeaders<HttpResponseOk<CodesResponse>>, HttpError> {
        todo!()
    }

    async fn healthz(
        _rqctx: RequestContext<ApiContext>,
    ) -> Result<HttpResponseHeaders<HttpResponseOk<HealthResponse>>, HttpError> {
        todo!()
    }

    async fn index(_rqctx: RequestContext<ApiContext>) -> Result<Response<Body>, HttpError> {
        let _ = (INDEX_HTML, APP_JS, APP_CSS);
        todo!()
    }

    async fn app_js(_rqctx: RequestContext<ApiContext>) -> Result<Response<Body>, HttpError> {
        todo!()
    }

    async fn app_css(_rqctx: RequestContext<ApiContext>) -> Result<Response<Body>, HttpError> {
        todo!()
    }
}

/// The API description with the real handlers.
pub fn api() -> ApiDescription<ApiContext> {
    oath_api_mod::api_description::<OathApiImpl>().expect("API description is valid")
}

/// The OpenAPI document, pretty-printed, generated without a card.
pub fn openapi_json() -> String {
    todo!()
}

/// Start the HTTP server on `bind`.
pub fn start(
    _context: ApiContext,
    _bind: SocketAddr,
    _log: Logger,
) -> Result<HttpServer<ApiContext>, dropshot::BuildError> {
    let _ = (
        ConfigDropshot::default(),
        HandlerTaskMode::Detached,
        ServerBuilder::<ApiContext>::new,
        REQUEST_BODY_MAX_BYTES,
    );
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::mock::{MockCard, MockCredential, MockFault};
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
    }

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

    // Every endpoint

    #[tokio::test]
    async fn every_endpoint_returns_security_headers() {
        let h = harness().await;
        let cookie = h.login().await;
        let router = api().into_router();
        let mut seen = 0;
        for (path, method, _) in router.endpoints(None) {
            let method: reqwest::Method = method.parse().unwrap();
            let response = h
                .client
                .request(method.clone(), h.url(&path))
                .header("content-type", "application/json")
                .header("cookie", &cookie)
                .body(json!({ "password": "probe" }).to_string())
                .send()
                .await
                .unwrap();
            let api_path = path.starts_with("/api/") || path == "/healthz";
            assert_security_headers(&response, api_path);
            seen += 1;
        }
        assert_eq!(seen, 7);
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

    // OpenAPI

    #[test]
    fn openapi_matches_committed_document() {
        expectorate::assert_contents("openapi/oath-web.json", &openapi_json());
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
            ["/api/codes", "/api/lock", "/api/unlock", "/healthz"]
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
