#![forbid(unsafe_code)]

use slog::{Level, info};

fn main() {
    let log = oath_web::logging::build_logger(std::io::stdout(), Level::Info);
    info!(log, "oath-web starting"; "version" => env!("CARGO_PKG_VERSION"));
}
