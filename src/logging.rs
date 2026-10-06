//! Builds the root `slog::Logger`: JSON lines to a writer, filtered by level.

use std::io::Write;

use slog::{Discard, Level, Logger, o};

/// Build a JSON logger that writes one object per line to `writer`.
pub fn build_logger<W: Write + Send + 'static>(_writer: W, _level: Level) -> Logger {
    Logger::root(Discard, o!())
}

#[cfg(test)]
mod tests {
    use super::*;
    use slog::{debug, info};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl SharedBuf {
        fn lines(&self) -> Vec<serde_json::Value> {
            let bytes = self.0.lock().unwrap().clone();
            String::from_utf8(bytes)
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        }
    }

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
