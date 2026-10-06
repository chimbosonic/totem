#![forbid(unsafe_code)]

use anyhow::Context;
use oath_web::config::Config;
use slog::info;

fn main() -> anyhow::Result<()> {
    let config = Config::from_env().context("invalid configuration")?;
    let log = oath_web::logging::build_logger(std::io::stdout(), config.log_level);
    info!(log, "oath-web starting";
        "version" => env!("CARGO_PKG_VERSION"),
        "bind" => %config.bind,
    );
    Ok(())
}
