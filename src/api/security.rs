//! Security headers and request content checks.
//!
//! Every handler passes its result through [`secure_result`]. That is a
//! convention, not middleware, so `server` has a test that calls every
//! endpoint in the API description and checks the headers.
//!
//! Responses Dropshot generates before a handler returns (unknown routes,
//! `TypedBody` parse and size errors) do not pass through here. They carry
//! no secrets; the Traefik headers middleware is the backstop for them.

use dropshot::{Body, HttpCodedResponse, HttpError, HttpResponseHeaders};
use http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
    X_FRAME_OPTIONS,
};
use http::{HeaderMap, HeaderValue, Response};
use schemars::JsonSchema;
use serde::Serialize;

pub const CSP: &str =
    "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";

/// Which header set a response gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RespKind {
    /// `/api/*` and `/healthz`: also `Cache-Control: no-store`.
    Api,
    /// The static frontend.
    Static,
}

/// Add the security headers for `kind`, replacing any existing values.
pub fn apply_security_headers(headers: &mut HeaderMap, kind: RespKind) {
    headers.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    if kind == RespKind::Api {
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
}

/// Anything that can carry response headers.
pub trait Secure {
    fn header_map(&mut self) -> &mut HeaderMap;
}

impl Secure for Response<Body> {
    fn header_map(&mut self) -> &mut HeaderMap {
        self.headers_mut()
    }
}

impl<T, H> Secure for HttpResponseHeaders<T, H>
where
    T: HttpCodedResponse,
    H: JsonSchema + Serialize + Send + Sync + 'static,
{
    fn header_map(&mut self) -> &mut HeaderMap {
        self.headers_mut()
    }
}

impl Secure for HttpError {
    fn header_map(&mut self) -> &mut HeaderMap {
        self.headers_mut()
    }
}

/// Apply the security headers to a response or error.
pub fn secure<T: Secure>(mut value: T, kind: RespKind) -> T {
    apply_security_headers(value.header_map(), kind);
    value
}

/// Apply the security headers to whichever side of `result` is present.
pub fn secure_result<T: Secure>(
    result: Result<T, HttpError>,
    kind: RespKind,
) -> Result<T, HttpError> {
    result
        .map(|ok| secure(ok, kind))
        .map_err(|err| secure(err, kind))
}

/// Require `Content-Type: application/json` (parameters such as charset
/// allowed). Dropshot's `TypedBody` treats a missing content type as JSON and
/// also accepts `application/*+json`, so POST handlers check explicitly.
pub fn require_json(headers: &HeaderMap) -> Result<(), HttpError> {
    let is_json = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or_default().trim())
        .is_some_and(|mime| mime.eq_ignore_ascii_case("application/json"));
    if is_json {
        Ok(())
    } else {
        Err(super::errors::bad_content_type())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dropshot::{HttpResponseOk, HttpResponseUpdatedNoContent};

    fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
        headers.get(name).map(|v| v.to_str().unwrap())
    }

    fn assert_common(headers: &HeaderMap) {
        assert_eq!(header(headers, "content-security-policy"), Some(CSP));
        assert!(CSP.starts_with("default-src 'self'"));
        assert_eq!(header(headers, "x-content-type-options"), Some("nosniff"));
        assert_eq!(header(headers, "referrer-policy"), Some("no-referrer"));
        assert_eq!(header(headers, "x-frame-options"), Some("DENY"));
    }

    #[test]
    fn api_responses_get_security_headers_and_no_store() {
        let mut headers = HeaderMap::new();
        apply_security_headers(&mut headers, RespKind::Api);
        assert_common(&headers);
        assert_eq!(header(&headers, "cache-control"), Some("no-store"));
    }

    #[test]
    fn static_responses_get_security_headers_without_no_store() {
        let mut headers = HeaderMap::new();
        apply_security_headers(&mut headers, RespKind::Static);
        assert_common(&headers);
        assert_eq!(header(&headers, "cache-control"), None);
    }

    #[test]
    fn security_headers_replace_existing_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-security-policy",
            HeaderValue::from_static("default-src *"),
        );
        apply_security_headers(&mut headers, RespKind::Api);
        assert_eq!(headers.get_all("content-security-policy").iter().count(), 1);
        assert_eq!(header(&headers, "content-security-policy"), Some(CSP));
    }

    #[test]
    fn secure_applies_to_typed_raw_and_error_responses() {
        let typed = secure(
            HttpResponseHeaders::new_unnamed(HttpResponseOk(1u8)),
            RespKind::Api,
        );
        let mut typed = typed;
        assert_common(typed.header_map());

        let mut raw = secure(Response::new(Body::from("x")), RespKind::Static);
        assert_common(raw.header_map());

        let mut error = secure(HttpError::for_internal_error("x".into()), RespKind::Api);
        assert_common(error.header_map());
    }

    #[test]
    fn secure_result_covers_ok_and_err() {
        let ok: Result<HttpResponseHeaders<HttpResponseUpdatedNoContent>, HttpError> = Ok(
            HttpResponseHeaders::new_unnamed(HttpResponseUpdatedNoContent()),
        );
        let mut ok = secure_result(ok, RespKind::Api).ok().unwrap();
        assert_common(ok.header_map());

        let err: Result<Response<Body>, HttpError> = Err(HttpError::for_internal_error("x".into()));
        let mut err = secure_result(err, RespKind::Api).err().unwrap();
        assert_common(err.header_map());
    }

    fn with_content_type(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn require_json_accepts_application_json() {
        for value in [
            "application/json",
            "Application/JSON",
            "application/json; charset=utf-8",
        ] {
            assert!(require_json(&with_content_type(value)).is_ok(), "{value}");
        }
    }

    #[test]
    fn require_json_rejects_missing_or_other_types() {
        assert_eq!(
            require_json(&HeaderMap::new())
                .unwrap_err()
                .status_code
                .as_u16(),
            400
        );
        for value in [
            "text/plain",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "application/merge-patch+json",
            "application/jsonp",
        ] {
            let err = require_json(&with_content_type(value)).unwrap_err();
            assert_eq!(err.status_code.as_u16(), 400, "{value}");
        }
    }

    #[test]
    fn require_json_rejects_non_utf8_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_bytes(b"application/json\xff").unwrap(),
        );
        assert!(require_json(&headers).is_err());
    }
}
