//! Builds the root `slog::Logger`: JSON lines to a writer, filtered by level.

use std::io::Write;

use slog::{Drain, Level, LevelFilter, Logger, o};

/// Build a JSON logger that writes one object per line to `writer`.
///
/// Records are written on a background thread. Dropping the last clone of the
/// returned logger flushes everything still queued.
pub fn build_logger<W: Write + Send + 'static>(writer: W, level: Level) -> Logger {
    let json = slog_json::Json::new(writer)
        .add_default_keys()
        .build()
        .fuse();
    let filtered = LevelFilter::new(json, level).fuse();
    let drain = slog_async::Async::new(filtered).build().fuse();
    Logger::root(drain, o!())
}

/// In-memory log capture for tests.
#[cfg(test)]
pub(crate) mod test_support {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use slog::{Drain, Logger, o};

    #[derive(Clone, Default)]
    pub(crate) struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl SharedBuf {
        pub(crate) fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }

        pub(crate) fn lines(&self) -> Vec<serde_json::Value> {
            self.text()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        }

        /// A synchronous JSON logger writing to this buffer at every level,
        /// so tests can read records without waiting for a background thread.
        pub(crate) fn logger(&self) -> Logger {
            let json = slog_json::Json::new(self.clone())
                .add_default_keys()
                .build();
            Logger::root(Mutex::new(json).fuse(), o!())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::SharedBuf;
    use super::*;
    use slog::{debug, info};

    #[test]
    fn logger_writes_json_lines_with_message_and_fields() {
        let buf = SharedBuf::default();
        let log = build_logger(buf.clone(), Level::Info);
        info!(log, "hello"; "event" => "startup");
        drop(log);

        let lines = buf.lines();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["msg"], "hello");
        assert_eq!(lines[0]["event"], "startup");
        assert_eq!(lines[0]["level"], "INFO");
    }

    #[test]
    fn logger_drops_records_below_configured_level() {
        let buf = SharedBuf::default();
        let log = build_logger(buf.clone(), Level::Info);
        debug!(log, "hidden");
        drop(log);

        assert!(buf.lines().is_empty());
    }
}
