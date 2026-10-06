//! Mapping from internal errors to HTTP errors, in one place.
//!
//! External messages never contain the password, codes, or card internals.
//! The detail goes in the internal message, which only reaches the log.

use dropshot::{ClientErrorStatusCode, ErrorStatusCode, HttpError};
use http::HeaderValue;
use http::header::RETRY_AFTER;

use crate::ratelimit::Denied;
use crate::service::ServiceError;

impl From<ServiceError> for HttpError {
    fn from(error: ServiceError) -> Self {
        match error {
            ServiceError::WrongPassword => client_error(
                ClientErrorStatusCode::UNAUTHORIZED,
                "WrongPassword",
                "wrong password",
            ),
            ServiceError::NoPassword
            | ServiceError::CardAuthFailed
            | ServiceError::Unavailable(_)
            | ServiceError::Protocol(_) => HttpError {
                status_code: ErrorStatusCode::SERVICE_UNAVAILABLE,
                error_code: Some("CardUnavailable".into()),
                external_message: "card unavailable".into(),
                internal_message: error.to_string(),
                headers: None,
            },
            ServiceError::Internal => HttpError::for_internal_error(error.to_string()),
        }
    }
}

fn client_error(status: ClientErrorStatusCode, code: &str, message: &str) -> HttpError {
    HttpError::for_client_error(Some(code.into()), status, message.into())
}

/// 401 for a missing, unknown, or expired session.
pub fn no_session() -> HttpError {
    client_error(
        ClientErrorStatusCode::UNAUTHORIZED,
        "NoSession",
        "no valid session",
    )
}

/// 429 with `Retry-After`.
pub fn too_many_attempts(denied: Denied) -> HttpError {
    let mut error = client_error(
        ClientErrorStatusCode::TOO_MANY_REQUESTS,
        "TooManyAttempts",
        "too many unlock attempts",
    );
    error
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from(denied.retry_after()));
    error
}

/// 400 for a POST without `Content-Type: application/json`.
pub fn bad_content_type() -> HttpError {
    client_error(
        ClientErrorStatusCode::BAD_REQUEST,
        "BadContentType",
        "expected Content-Type: application/json",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::CardError;
    use crate::oath::proto::ProtoError;

    fn status(e: &HttpError) -> u16 {
        e.status_code.as_u16()
    }

    #[test]
    fn every_service_error_maps_to_a_status() {
        let cases = [
            (ServiceError::WrongPassword, 401),
            (ServiceError::NoPassword, 503),
            (ServiceError::CardAuthFailed, 503),
            (ServiceError::Unavailable(CardError::Removed), 503),
            (ServiceError::Protocol(ProtoError::Status(0x6A80)), 503),
            (ServiceError::Internal, 500),
        ];
        // Make sure a new variant cannot be added without a case here.
        for (error, _) in &cases {
            match error {
                ServiceError::WrongPassword
                | ServiceError::NoPassword
                | ServiceError::CardAuthFailed
                | ServiceError::Unavailable(_)
                | ServiceError::Protocol(_)
                | ServiceError::Internal => {}
            }
        }
        for (error, expected) in cases {
            let debug = format!("{error:?}");
            assert_eq!(status(&HttpError::from(error)), expected, "{debug}");
        }
    }

    #[test]
    fn card_errors_do_not_leak_details_to_clients() {
        for error in [
            ServiceError::NoPassword,
            ServiceError::CardAuthFailed,
            ServiceError::Unavailable(CardError::Reader("SCARD_E_NO_SERVICE".into())),
            ServiceError::Protocol(ProtoError::Malformed("SELECT without name")),
        ] {
            let internal = error.to_string();
            let http = HttpError::from(error);
            assert_eq!(http.external_message, "card unavailable");
            assert_eq!(http.internal_message, internal);
        }
    }

    #[test]
    fn wrong_password_message_is_generic() {
        let http = HttpError::from(ServiceError::WrongPassword);
        assert_eq!(http.external_message, "wrong password");
    }

    #[test]
    fn internal_error_is_generic() {
        let http = HttpError::from(ServiceError::Internal);
        assert_eq!(http.external_message, "Internal Server Error");
    }

    #[test]
    fn no_session_is_401() {
        let http = no_session();
        assert_eq!(status(&http), 401);
        assert_eq!(http.external_message, "no valid session");
    }

    #[test]
    fn too_many_attempts_is_429_with_retry_after() {
        for (denied, seconds) in [
            (Denied::Backoff { retry_after: 4 }, "4"),
            (Denied::InFlight { retry_after: 1 }, "1"),
            (Denied::GlobalLockout { retry_after: 900 }, "900"),
            (Denied::Backoff { retry_after: 0 }, "1"),
        ] {
            let http = too_many_attempts(denied);
            assert_eq!(status(&http), 429);
            let headers = http.headers.as_ref().expect("headers");
            assert_eq!(headers.get("retry-after").unwrap(), seconds);
        }
    }

    #[test]
    fn bad_content_type_is_400() {
        assert_eq!(status(&bad_content_type()), 400);
    }
}
