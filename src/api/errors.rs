//! Mapping from internal errors to HTTP errors, in one place.
//!
//! External messages never contain the password, codes, or card internals.
//! The detail goes in the internal message, which only reaches the log.

use dropshot::{ClientErrorStatusCode, ErrorStatusCode, HttpError};
use http::HeaderValue;
use http::header::RETRY_AFTER;

use crate::openpgp::encrypted::DecryptError;
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
            ServiceError::OpenPgpUnavailable => client_error(
                ClientErrorStatusCode::NOT_FOUND,
                "OpenPgpUnavailable",
                "the card has no OpenPGP applet",
            ),
            ServiceError::NoKey(slot) => client_error(
                ClientErrorStatusCode::NOT_FOUND,
                "NoKey",
                &format!("no key in the {slot} slot"),
            ),
            ServiceError::WrongPin { retries_left } => client_error(
                ClientErrorStatusCode::FORBIDDEN,
                "WrongPin",
                &format!("wrong PIN, {retries_left} tries left"),
            ),
            ServiceError::PinRetryFloor { retries_left } => client_error(
                ClientErrorStatusCode::LOCKED,
                "PinRetryFloor",
                &format!(
                    "the PIN has {retries_left} tries left, too few to risk one; \
                     verify it at the host (for example with gpg --card-edit)"
                ),
            ),
            ServiceError::BadPin => client_error(
                ClientErrorStatusCode::BAD_REQUEST,
                "BadPin",
                "PIN length is outside what the card accepts",
            ),
            ServiceError::TouchRequired(slot) => client_error(
                ClientErrorStatusCode::CONFLICT,
                "TouchRequired",
                &format!(
                    "the {slot} key requires a touch, which nobody at the server can give; \
                     turn it off at the host with ykman openpgp keys set-touch"
                ),
            ),
            ServiceError::KdfUnsupported => HttpError {
                status_code: ErrorStatusCode::NOT_IMPLEMENTED,
                error_code: Some("KdfUnsupported".into()),
                external_message: "the card's PIN KDF settings are not supported".into(),
                internal_message: error.to_string(),
                headers: None,
            },
            ServiceError::Decrypt(e) => {
                let (status, code) = match e {
                    DecryptError::NotArmored
                    | DecryptError::BadChecksum
                    | DecryptError::Malformed(_)
                    | DecryptError::NoSessionKey => {
                        (ClientErrorStatusCode::BAD_REQUEST, "BadMessage")
                    }
                    DecryptError::NotForThisKey { .. } => {
                        (ClientErrorStatusCode::UNPROCESSABLE_ENTITY, "NotForThisKey")
                    }
                    DecryptError::Unsupported(_) => (
                        ClientErrorStatusCode::UNPROCESSABLE_ENTITY,
                        "UnsupportedMessage",
                    ),
                    DecryptError::Recovery => (
                        ClientErrorStatusCode::UNPROCESSABLE_ENTITY,
                        "SessionKeyRecoveryFailed",
                    ),
                };
                client_error(status, code, &e.to_string())
            }
            ServiceError::BadInput(e) => client_error(
                ClientErrorStatusCode::BAD_REQUEST,
                "BadInput",
                &e.to_string(),
            ),
            ServiceError::NoPassword
            | ServiceError::CardAuthFailed
            | ServiceError::Unavailable(_)
            | ServiceError::Protocol(_)
            | ServiceError::OpenPgpProtocol(_) => HttpError {
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
    rate_limited(denied, "too many unlock attempts")
}

/// 429 with `Retry-After`, for OpenPGP PIN attempts.
pub fn too_many_pin_attempts(denied: Denied) -> HttpError {
    rate_limited(denied, "too many PIN attempts")
}

fn rate_limited(denied: Denied, message: &str) -> HttpError {
    let mut error = client_error(
        ClientErrorStatusCode::TOO_MANY_REQUESTS,
        "TooManyAttempts",
        message,
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
    use crate::openpgp::proto::{InputError, KeySlot, PgpError};

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
            (ServiceError::OpenPgpUnavailable, 404),
            (ServiceError::NoKey(KeySlot::Sign), 404),
            (ServiceError::WrongPin { retries_left: 2 }, 403),
            (ServiceError::PinRetryFloor { retries_left: 1 }, 423),
            (ServiceError::BadPin, 400),
            (ServiceError::TouchRequired(KeySlot::Sign), 409),
            (ServiceError::KdfUnsupported, 501),
            (ServiceError::Decrypt(DecryptError::NotArmored), 400),
            (ServiceError::Decrypt(DecryptError::BadChecksum), 400),
            (ServiceError::Decrypt(DecryptError::Malformed("x")), 400),
            (ServiceError::Decrypt(DecryptError::NoSessionKey), 400),
            (
                ServiceError::Decrypt(DecryptError::NotForThisKey {
                    message: "A".into(),
                    card: "B".into(),
                }),
                422,
            ),
            (ServiceError::Decrypt(DecryptError::Unsupported("x")), 422),
            (ServiceError::Decrypt(DecryptError::Recovery), 422),
            (ServiceError::BadInput(InputError::DigestLength), 400),
            (ServiceError::OpenPgpProtocol(PgpError::Status(0x6F00)), 503),
        ];
        // Make sure a new variant cannot be added without a case here.
        for (error, _) in &cases {
            match error {
                ServiceError::WrongPassword
                | ServiceError::NoPassword
                | ServiceError::CardAuthFailed
                | ServiceError::Unavailable(_)
                | ServiceError::Protocol(_)
                | ServiceError::Internal
                | ServiceError::OpenPgpUnavailable
                | ServiceError::NoKey(_)
                | ServiceError::WrongPin { .. }
                | ServiceError::PinRetryFloor { .. }
                | ServiceError::BadPin
                | ServiceError::TouchRequired(_)
                | ServiceError::KdfUnsupported
                | ServiceError::Decrypt(_)
                | ServiceError::BadInput(_)
                | ServiceError::OpenPgpProtocol(_) => {}
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
            ServiceError::OpenPgpProtocol(PgpError::Malformed("no signature counter")),
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
    fn openpgp_messages_tell_the_caller_what_to_do() {
        let http = HttpError::from(ServiceError::WrongPin { retries_left: 2 });
        assert_eq!(http.external_message, "wrong PIN, 2 tries left");
        assert_eq!(http.error_code.as_deref(), Some("WrongPin"));
        let http = HttpError::from(ServiceError::PinRetryFloor { retries_left: 1 });
        assert!(http.external_message.contains("1 tries left"));
        assert!(http.external_message.contains("gpg --card-edit"));
        let http = HttpError::from(ServiceError::TouchRequired(KeySlot::Sign));
        assert!(
            http.external_message
                .starts_with("the sign key requires a touch")
        );
        assert!(http.external_message.contains("set-touch"));
        let http = HttpError::from(ServiceError::NoKey(KeySlot::Decrypt));
        assert_eq!(http.external_message, "no key in the decrypt slot");
        let http = HttpError::from(ServiceError::BadInput(InputError::DigestLength));
        assert_eq!(
            http.external_message,
            "digest length does not match the hash"
        );
    }

    #[test]
    fn too_many_pin_attempts_is_429_with_its_own_message() {
        let http = too_many_pin_attempts(Denied::Backoff { retry_after: 2 });
        assert_eq!(status(&http), 429);
        assert_eq!(http.external_message, "too many PIN attempts");
        let headers = http.headers.as_ref().expect("headers");
        assert_eq!(headers.get("retry-after").unwrap(), "2");
    }

    #[test]
    fn bad_content_type_is_400() {
        assert_eq!(status(&bad_content_type()), 400);
    }
}
