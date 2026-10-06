//! Service configuration from `OATH_*` environment variables (PLAN.md section 11).

use std::net::{IpAddr, SocketAddr};

use ipnet::IpNet;
use slog::Level;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// `OATH_BIND`: listen address.
    pub bind: SocketAddr,
    /// `OATH_READER`: reader name substring. `None` picks the first YubiKey reader.
    pub reader: Option<String>,
    /// `OATH_SESSION_IDLE_SECS`: idle session TTL.
    pub session_idle_secs: u64,
    /// `OATH_SESSION_MAX_SECS`: absolute session TTL.
    pub session_max_secs: u64,
    /// `OATH_GLOBAL_FAIL_LIMIT`: failures before global unlock lockout.
    pub global_fail_limit: u32,
    /// `OATH_TRUSTED_PROXIES`: peers allowed to set `X-Forwarded-For`.
    pub trusted_proxies: Vec<IpNet>,
    /// `OATH_LOG_LEVEL`: minimum log level.
    pub log_level: Level,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("{var}={value:?} is invalid: {reason}")]
    Invalid {
        var: &'static str,
        value: String,
        reason: &'static str,
    },
    #[error(
        "OATH_SESSION_IDLE_SECS ({idle}) must not be greater than OATH_SESSION_MAX_SECS ({max})"
    )]
    IdleExceedsMax { idle: u64, max: u64 },
}

impl Config {
    /// Read configuration from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Read configuration through `lookup`, which returns a variable's value
    /// or `None` if it is unset.
    pub fn from_lookup(_lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let _ = IpAddr::from([0, 0, 0, 0]);
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn parse(vars: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_lookup(|name| map.get(name).cloned())
    }

    fn invalid_var(result: Result<Config, ConfigError>) -> &'static str {
        match result {
            Err(ConfigError::Invalid { var, .. }) => var,
            other => panic!("expected Invalid error, got {other:?}"),
        }
    }

    #[test]
    fn defaults_apply_when_env_is_empty() {
        let config = parse(&[]).unwrap();
        assert_eq!(
            config,
            Config {
                bind: "0.0.0.0:8080".parse().unwrap(),
                reader: None,
                session_idle_secs: 300,
                session_max_secs: 1800,
                global_fail_limit: 20,
                trusted_proxies: vec![],
                log_level: Level::Info,
            }
        );
    }

    #[test]
    fn all_values_are_read_when_set() {
        let config = parse(&[
            ("OATH_BIND", "127.0.0.1:9000"),
            ("OATH_READER", "Yubico YubiKey NEO"),
            ("OATH_SESSION_IDLE_SECS", "60"),
            ("OATH_SESSION_MAX_SECS", "600"),
            ("OATH_GLOBAL_FAIL_LIMIT", "5"),
            ("OATH_TRUSTED_PROXIES", "172.16.0.0/12, 10.0.0.0/8"),
            ("OATH_LOG_LEVEL", "debug"),
        ])
        .unwrap();
        assert_eq!(config.bind, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(config.reader.as_deref(), Some("Yubico YubiKey NEO"));
        assert_eq!(config.session_idle_secs, 60);
        assert_eq!(config.session_max_secs, 600);
        assert_eq!(config.global_fail_limit, 5);
        assert_eq!(
            config.trusted_proxies,
            vec![
                "172.16.0.0/12".parse::<IpNet>().unwrap(),
                "10.0.0.0/8".parse().unwrap()
            ]
        );
        assert_eq!(config.log_level, Level::Debug);
    }

    #[test]
    fn empty_reader_means_unset() {
        assert_eq!(parse(&[("OATH_READER", "  ")]).unwrap().reader, None);
    }

    #[test]
    fn invalid_bind_is_rejected() {
        assert_eq!(
            invalid_var(parse(&[("OATH_BIND", "localhost")])),
            "OATH_BIND"
        );
    }

    #[test]
    fn non_numeric_ttl_is_rejected() {
        assert_eq!(
            invalid_var(parse(&[("OATH_SESSION_IDLE_SECS", "5m")])),
            "OATH_SESSION_IDLE_SECS"
        );
        assert_eq!(
            invalid_var(parse(&[("OATH_SESSION_MAX_SECS", "-1")])),
            "OATH_SESSION_MAX_SECS"
        );
    }

    #[test]
    fn zero_ttl_is_rejected() {
        assert_eq!(
            invalid_var(parse(&[("OATH_SESSION_IDLE_SECS", "0")])),
            "OATH_SESSION_IDLE_SECS"
        );
    }

    #[test]
    fn idle_greater_than_max_is_rejected() {
        assert_eq!(
            parse(&[
                ("OATH_SESSION_IDLE_SECS", "601"),
                ("OATH_SESSION_MAX_SECS", "600")
            ]),
            Err(ConfigError::IdleExceedsMax {
                idle: 601,
                max: 600
            })
        );
    }

    #[test]
    fn idle_equal_to_max_is_allowed() {
        let config = parse(&[
            ("OATH_SESSION_IDLE_SECS", "600"),
            ("OATH_SESSION_MAX_SECS", "600"),
        ])
        .unwrap();
        assert_eq!(config.session_idle_secs, 600);
    }

    #[test]
    fn invalid_or_zero_fail_limit_is_rejected() {
        assert_eq!(
            invalid_var(parse(&[("OATH_GLOBAL_FAIL_LIMIT", "many")])),
            "OATH_GLOBAL_FAIL_LIMIT"
        );
        assert_eq!(
            invalid_var(parse(&[("OATH_GLOBAL_FAIL_LIMIT", "0")])),
            "OATH_GLOBAL_FAIL_LIMIT"
        );
    }

    #[test]
    fn bad_cidr_is_rejected() {
        assert_eq!(
            invalid_var(parse(&[("OATH_TRUSTED_PROXIES", "10.0.0.0/8,10.0.0.0/33")])),
            "OATH_TRUSTED_PROXIES"
        );
        assert_eq!(
            invalid_var(parse(&[("OATH_TRUSTED_PROXIES", "traefik")])),
            "OATH_TRUSTED_PROXIES"
        );
    }

    #[test]
    fn bare_proxy_ip_is_treated_as_single_host() {
        let config = parse(&[("OATH_TRUSTED_PROXIES", "172.18.0.2,::1")]).unwrap();
        assert_eq!(
            config.trusted_proxies,
            vec![
                "172.18.0.2/32".parse::<IpNet>().unwrap(),
                "::1/128".parse().unwrap()
            ]
        );
    }

    #[test]
    fn empty_proxy_entries_are_ignored() {
        let config = parse(&[("OATH_TRUSTED_PROXIES", " 10.0.0.0/8, ,")]).unwrap();
        assert_eq!(
            config.trusted_proxies,
            vec!["10.0.0.0/8".parse::<IpNet>().unwrap()]
        );
    }

    #[test]
    fn every_log_level_name_is_accepted_case_insensitively() {
        for (name, level) in [
            ("trace", Level::Trace),
            ("DEBUG", Level::Debug),
            ("Info", Level::Info),
            ("warning", Level::Warning),
            ("warn", Level::Warning),
            ("error", Level::Error),
            ("critical", Level::Critical),
        ] {
            assert_eq!(parse(&[("OATH_LOG_LEVEL", name)]).unwrap().log_level, level);
        }
    }

    #[test]
    fn unknown_log_level_is_rejected() {
        assert_eq!(
            invalid_var(parse(&[("OATH_LOG_LEVEL", "verbose")])),
            "OATH_LOG_LEVEL"
        );
    }

    #[test]
    fn error_message_names_the_variable_and_value() {
        let err = parse(&[("OATH_SESSION_IDLE_SECS", "5m")]).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("OATH_SESSION_IDLE_SECS"), "{message}");
        assert!(message.contains("\"5m\""), "{message}");
    }
}
