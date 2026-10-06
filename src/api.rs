//! HTTP API built with Dropshot (PLAN.md sections 9 and 9a).
//!
//! Dropshot has no middleware, so shared behaviour is plain function calls:
//! [`auth`] for sessions, client IP, and rate limiting; [`security`] for the
//! response headers every handler applies; [`errors`] for status mapping.

pub mod auth;
pub mod definition;
pub mod errors;
pub mod security;
pub mod server;
