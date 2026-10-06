//! Session, client IP, and rate-limit checks as plain functions that return
//! typed values (PLAN.md section 9a). Each `RequestContext` wrapper is one
//! line over a function that takes plain values, so the logic is unit tested
//! without a server.

use std::net::IpAddr;

use dropshot::{HttpError, RequestContext};
use http::HeaderMap;
use http::header::COOKIE;
use ipnet::IpNet;

use super::server::ApiContext;
use crate::ratelimit::{self, RateLimiter, UnlockPermit};
use crate::session::{AuthedSession, SessionId, SessionStore};

pub const COOKIE_NAME: &str = "oath_session";
const COOKIE_ATTRIBUTES: &str = "HttpOnly; Secure; SameSite=Strict; Path=/";
const FORWARDED_FOR: &str = "x-forwarded-for";

/// `Set-Cookie` value that starts a session.
pub fn session_cookie(_id: &SessionId) -> String {
    let _ = COOKIE_ATTRIBUTES;
    todo!()
}

/// `Set-Cookie` value that removes the session cookie.
pub fn clear_session_cookie() -> String {
    todo!()
}

/// The first well-formed `oath_session` value in the `Cookie` headers.
pub fn session_id_from_headers(_headers: &HeaderMap) -> Option<SessionId> {
    let _ = COOKIE;
    todo!()
}

/// Look up the request's session, refreshing its idle timeout.
pub fn session_from_headers(
    _sessions: &SessionStore,
    _headers: &HeaderMap,
) -> Result<AuthedSession, HttpError> {
    todo!()
}

pub async fn require_session(
    rqctx: &RequestContext<ApiContext>,
) -> Result<AuthedSession, HttpError> {
    session_from_headers(&rqctx.context().sessions, rqctx.request.headers())
}

/// Client IP from the peer address and any `X-Forwarded-For` headers.
pub fn client_ip_from(_trusted: &[IpNet], _peer: IpAddr, _headers: &HeaderMap) -> IpAddr {
    let _ = (FORWARDED_FOR, ratelimit::client_ip);
    todo!()
}

pub fn client_ip(rqctx: &RequestContext<ApiContext>) -> IpAddr {
    client_ip_from(
        &rqctx.context().config.trusted_proxies,
        rqctx.request.remote_addr().ip(),
        rqctx.request.headers(),
    )
}

/// Reserve an unlock attempt for `ip`, or a 429.
pub fn acquire_unlock_attempt_for(
    _limiter: &RateLimiter,
    _ip: IpAddr,
) -> Result<UnlockPermit<'_>, HttpError> {
    todo!()
}

pub async fn acquire_unlock_attempt(
    rqctx: &RequestContext<ApiContext>,
) -> Result<UnlockPermit<'_>, HttpError> {
    acquire_unlock_attempt_for(&rqctx.context().ratelimit, client_ip(rqctx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use crate::oath::crypto::KEY_LEN;
    use crate::rng::SequentialChallengeSource;
    use http::HeaderValue;
    use std::sync::Arc;
    use zeroize::Zeroizing;

    fn store() -> (Arc<ManualClock>, SessionStore) {
        let clock = Arc::new(ManualClock::new(1000));
        let store = SessionStore::new(
            clock.clone(),
            Arc::new(SequentialChallengeSource::new(0)),
            300,
            1800,
        );
        (clock, store)
    }

    fn cookies(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(COOKIE, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // Cookies

    #[test]
    fn session_cookie_has_required_attributes() {
        let (_, store) = store();
        let id = store.create(Zeroizing::new([1; KEY_LEN]));
        let cookie = session_cookie(&id);
        assert!(cookie.starts_with(&format!("oath_session={};", id.to_cookie_value())));
        for attribute in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/"] {
            assert!(
                cookie.split("; ").any(|a| a == attribute),
                "{attribute} in {cookie}"
            );
        }
    }

    #[test]
    fn clear_cookie_expires_immediately_with_same_attributes() {
        let cookie = clear_session_cookie();
        assert!(cookie.starts_with("oath_session=;"));
        for attribute in [
            "Max-Age=0",
            "HttpOnly",
            "Secure",
            "SameSite=Strict",
            "Path=/",
        ] {
            assert!(
                cookie.split("; ").any(|a| a == attribute),
                "{attribute} in {cookie}"
            );
        }
    }

    #[test]
    fn session_id_is_found_among_other_cookies() {
        let value = "ab".repeat(32);
        let headers = cookies(&[&format!("theme=dark; oath_session={value}; lang=en")]);
        assert_eq!(
            session_id_from_headers(&headers).map(|id| id.to_cookie_value()),
            Some(value)
        );
    }

    #[test]
    fn session_id_is_found_across_multiple_cookie_headers() {
        let value = "cd".repeat(32);
        let headers = cookies(&["theme=dark", &format!("oath_session={value}")]);
        assert!(session_id_from_headers(&headers).is_some());
    }

    #[test]
    fn malformed_session_cookies_are_ignored() {
        for header in [
            "",
            "oath_session=",
            "oath_session=nothex",
            "oath_session_x=",
            "other=1",
            "oath_session",
        ] {
            assert!(
                session_id_from_headers(&cookies(&[header])).is_none(),
                "{header:?}"
            );
        }
        assert!(session_id_from_headers(&HeaderMap::new()).is_none());
    }

    #[test]
    fn first_well_formed_session_cookie_wins() {
        let good = "ef".repeat(32);
        let headers = cookies(&[&format!("oath_session=bad; oath_session={good}")]);
        assert_eq!(
            session_id_from_headers(&headers).map(|id| id.to_cookie_value()),
            Some(good)
        );
    }

    // require_session

    #[test]
    fn session_from_headers_returns_live_session() {
        let (_, store) = store();
        let id = store.create(Zeroizing::new([5; KEY_LEN]));
        let headers = cookies(&[&format!("oath_session={}", id.to_cookie_value())]);
        let session = session_from_headers(&store, &headers).unwrap();
        assert_eq!(session.id(), &id);
    }

    #[test]
    fn session_from_headers_rejects_missing_unknown_and_expired() {
        let (clock, store) = store();
        assert_eq!(
            session_from_headers(&store, &HeaderMap::new())
                .unwrap_err()
                .status_code
                .as_u16(),
            401
        );
        let unknown = cookies(&[&format!("oath_session={}", "00".repeat(32))]);
        assert_eq!(
            session_from_headers(&store, &unknown)
                .unwrap_err()
                .status_code
                .as_u16(),
            401
        );
        let id = store.create(Zeroizing::new([5; KEY_LEN]));
        clock.advance(300);
        let expired = cookies(&[&format!("oath_session={}", id.to_cookie_value())]);
        assert_eq!(
            session_from_headers(&store, &expired)
                .unwrap_err()
                .status_code
                .as_u16(),
            401
        );
    }

    // client_ip

    fn forwarded(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append("x-forwarded-for", HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    #[test]
    fn client_ip_uses_peer_when_untrusted() {
        let trusted: Vec<IpNet> = vec!["172.16.0.0/12".parse().unwrap()];
        assert_eq!(
            client_ip_from(&trusted, ip("192.168.1.9"), &forwarded(&["1.2.3.4"])),
            ip("192.168.1.9")
        );
    }

    #[test]
    fn client_ip_uses_forwarded_for_from_trusted_peer() {
        let trusted: Vec<IpNet> = vec!["172.16.0.0/12".parse().unwrap()];
        assert_eq!(
            client_ip_from(&trusted, ip("172.18.0.2"), &forwarded(&["192.168.1.9"])),
            ip("192.168.1.9")
        );
    }

    #[test]
    fn multiple_forwarded_for_headers_are_one_list() {
        let trusted: Vec<IpNet> = vec!["172.16.0.0/12".parse().unwrap()];
        assert_eq!(
            client_ip_from(
                &trusted,
                ip("172.18.0.2"),
                &forwarded(&["6.6.6.6", "192.168.1.9"])
            ),
            ip("192.168.1.9")
        );
    }

    #[test]
    fn non_utf8_forwarded_for_falls_back_to_peer() {
        let trusted: Vec<IpNet> = vec!["172.16.0.0/12".parse().unwrap()];
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_bytes(b"1.2.3.4\xff").unwrap(),
        );
        assert_eq!(
            client_ip_from(&trusted, ip("172.18.0.2"), &headers),
            ip("172.18.0.2")
        );
    }

    // acquire_unlock_attempt

    #[test]
    fn acquire_returns_permit_then_429_while_in_flight() {
        let limiter = RateLimiter::new(Arc::new(ManualClock::new(0)), 20);
        let permit = acquire_unlock_attempt_for(&limiter, ip("10.0.0.1")).unwrap();
        assert_eq!(permit.ip(), ip("10.0.0.1"));
        let denied = acquire_unlock_attempt_for(&limiter, ip("10.0.0.1"))
            .err()
            .unwrap();
        assert_eq!(denied.status_code.as_u16(), 429);
        drop(permit);
    }

    #[test]
    fn acquire_after_failure_is_429_with_retry_after() {
        let limiter = RateLimiter::new(Arc::new(ManualClock::new(0)), 20);
        acquire_unlock_attempt_for(&limiter, ip("10.0.0.1"))
            .unwrap()
            .failure();
        let denied = acquire_unlock_attempt_for(&limiter, ip("10.0.0.1"))
            .err()
            .unwrap();
        assert_eq!(denied.status_code.as_u16(), 429);
        assert_eq!(denied.headers.unwrap().get("retry-after").unwrap(), "1");
    }
}
