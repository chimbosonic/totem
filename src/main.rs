#![forbid(unsafe_code)]

//! Startup wiring only. All logic lives in the library, where it is tested.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use oath_web::api::server::{self, ApiContext};
use oath_web::card::pcsc::PcscCard;
use oath_web::clock::SystemClock;
use oath_web::config::Config;
use oath_web::ratelimit::RateLimiter;
use oath_web::rng::OsChallengeSource;
use oath_web::service::{Service, ServiceError};
use oath_web::session::{self, SessionStore};
use slog::{error, info};

const PURGE_INTERVAL: Duration = Duration::from_secs(30);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Arc::new(Config::from_env().context("invalid configuration")?);
    let log = oath_web::logging::build_logger(std::io::stdout(), config.log_level);
    info!(log, "oath-web starting"; "version" => env!("CARGO_PKG_VERSION"));

    let card = match PcscCard::connect(config.reader.as_deref()) {
        Ok(card) => card,
        Err(e) => {
            error!(log, "no usable smart card reader; is pcscd running and the YubiKey plugged in?";
                "error" => %e,
                "reader_filter" => config.reader.as_deref().unwrap_or("YubiKey"),
            );
            bail!("no usable smart card reader: {e}");
        }
    };
    let reader = card.reader_name().to_owned();

    let clock = Arc::new(SystemClock);
    let rng = Arc::new(OsChallengeSource);
    let service = Arc::new(Service::new(Box::new(card), clock.clone(), rng.clone()));

    match service.startup_check().await {
        Ok(info) => {
            info!(log, "OATH applet ready"; "reader" => &reader, "applet_version" => info.version_string());
        }
        Err(ServiceError::NoPassword) => {
            error!(log, "the OATH applet has no password; refusing to serve codes. Set one with `ykman oath access change`";
                "reader" => &reader,
            );
            bail!("OATH applet has no password");
        }
        Err(e) => {
            error!(log, "OATH applet check failed"; "reader" => &reader, "error" => %e);
            bail!("OATH applet check failed: {e}");
        }
    }

    let sessions = Arc::new(SessionStore::new(
        clock.clone(),
        rng,
        config.session_idle_secs,
        config.session_max_secs,
    ));
    let purger = session::spawn_purger(sessions.clone(), PURGE_INTERVAL);
    let context = ApiContext {
        service,
        sessions,
        ratelimit: Arc::new(RateLimiter::new(clock, config.global_fail_limit)),
        config: config.clone(),
    };

    let server = server::start(context, config.bind, log.clone())
        .map_err(|e| anyhow::anyhow!("failed to start HTTP server: {e}"))?;
    info!(log, "listening"; "bind" => %server.local_addr());

    let result = tokio::select! {
        result = server.wait_for_shutdown() => result,
        () = shutdown_signal() => {
            info!(log, "shutting down");
            server.close().await
        }
    };
    purger.abort();
    result.map_err(|e| anyhow::anyhow!("HTTP server failed: {e}"))
}

/// Resolve on SIGTERM (what `docker stop` sends) or Ctrl-C.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}
