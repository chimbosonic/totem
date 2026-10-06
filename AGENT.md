# Agent Notes

Working notes for building `oath-web` as described in `PLAN.md`. Update this file as work progresses.

## Ground rules (from PLAN.md)

- Branch: work directly on `main`.
- Rust stable, edition 2024, `#![forbid(unsafe_code)]`.
- `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` must pass.
- HTTP API with Dropshot only. No axum, actix, warp, or tower.
- TDD is mandatory: red, green, refactor, commit. Prefixes: `test:`, `feat:`, `fix:`, `refactor:`.
- Unit tests live in the same file (`#[cfg(test)] mod tests`). Only `card::pcsc` is exempt.
- No sleeping in tests. Time via `Clock`, randomness via `ChallengeSource`.
- Never log the password, derived key, raw session ID, or codes.
- No em dashes in docs, comments, or UI text.

## Environment

- Host: macOS (darwin), fish shell.
- Toolchain: cargo 1.97.0, rustc 1.97.0.
- `cargo llvm-cov`: 0.9.1 installed (plus rustup `llvm-tools` component) for the coverage gate (section 14.3).
- `libpcsclite` not available via pkg-config. On macOS the `pcsc` crate links against `PCSC.framework`, so local builds should still work. Linux CI and Docker need `libpcsclite-dev`.

## Hardware available for integration tests

- YubiKey NEO 3.4.9 (serial 4551023), interfaces OTP+FIDO+CCID, OATH applet version 1.0.0.
- One credential: `RFC6238:sha256` (issuer `RFC6238`, account `sha256`). The user confirmed it uses the RFC 6238 SHA-256 test secret `12345678901234567890123456789012` (ASCII, 32 bytes), so expected codes can be checked against the RFC 6238 Appendix B vectors as well as `ykman oath accounts code`. Verified 2026-10-06: SHA-256, **8 digits**, 30s period; `ykman` code matched an independent Python computation.
- OATH password protection is **disabled** (checked 2026-10-06 with `ykman oath info`). The service refuses to start against an unprotected applet (section 7), so a password must be set (`ykman oath access change`) before a full end-to-end run. Ask the user before changing anything on the key.
- Hardware integration tests must not run in normal `cargo test` (section 14.1: no hardware in tests). Plan: put them in `tests/` behind an opt-in (a Cargo feature or env var), and compare with `ykman oath accounts code`.
- The NEO's older applet may not support SHA512 credentials; do not assume it does in hardware tests.

## Build order progress (section 16)

| # | Step | Status | Notes |
|---|---|---|---|
| 1 | Scaffold crate, forbid unsafe, logging, placeholder test | done | `logging::build_logger` (slog-json + slog-async), 2 tests |
| 2 | `clock` and `rng` traits | done | `Clock` (`SystemClock`, `ManualClock`), `ChallengeSource` (`OsChallengeSource`, `SequentialChallengeSource`), 11 tests |
| 3 | `config` | done | `Config::from_lookup` (tested) and `from_env` (thin wrapper), 15 tests; `main` uses it |
| 4 | `oath::tlv` | done | `encode`, `parse` (lenient, returns rest), `parse_exact` (strict), `parse_all` (strict sequence), 18 tests |
| 5 | `oath::crypto` | done | `derive_key`, `hmac`, `dynamic_truncate`, `format_code`, `timestep`, `validity_window`, `constant_time_eq`, `Algorithm`, 17 tests |
| 6 | `oath::proto` | todo | |
| 7 | `OathCard` trait and mock card | todo | |
| 8 | `service` | todo | |
| 9 | `session` | todo | |
| 10 | `ratelimit` | todo | |
| 11 | `api` (Dropshot) | todo | |
| 12 | Real PC/SC card implementation | todo | |
| 13 | Frontend | todo | |
| 14 | Dockerfile and compose | todo | |
| 15 | GitLab CI with coverage gate | todo | |
| 16 | README | todo | |

## Open questions and things to verify

- YKOATH bytes in section 5 must be checked against the Yubico spec before relying on them.
- Dropshot: which response types allow custom headers (cookies, `Retry-After`)?
- Dropshot: can `HttpError` carry `Retry-After` for 429?
- Dropshot: behaviour of `TypedBody` on non-JSON `Content-Type`.
- PBKDF2 fixture from a real key is pending the manual hardware checklist (section 14.4).

## Decisions log

- 2026-10-06: Repo has no commits yet. Created `AGENT.md` for tracking notes.
- 2026-10-06: Logic lives in `src/lib.rs` modules; `src/main.rs` stays thin so it can be excluded from coverage.
- 2026-10-06: Logging uses `slog-json` with default keys (`msg`, `level`, `ts`) behind `slog-async`, filtered by `LevelFilter`. Level parsing from `OATH_LOG_LEVEL` is deferred to `config` (step 3); `main` hardcodes `Info` for now.
- 2026-10-06: Red and green are committed separately to keep TDD visible in history.
- 2026-10-06: `Clock::now()` returns `u64` Unix seconds. Every consumer (timesteps, TTLs, 1s backoff) works in whole seconds. A pre-epoch system clock maps to 0.
- 2026-10-06: Test implementations (`ManualClock`, `SequentialChallengeSource`) are always compiled, not `#[cfg(test)]`, so later modules and in-process API tests can use them.
- 2026-10-06: OS randomness via `getrandom` 0.4 (`getrandom::fill`) instead of `rand`; we only need raw bytes. `OsChallengeSource` panics if the OS RNG fails, since continuing without randomness is unsafe.
- 2026-10-06: `ChallengeSource` has default `challenge()` (8 bytes) and `session_id()` (32 bytes) built on `fill()`. More scripted test sources (for exact protocol vectors) to be added when a test needs them.

## Session log

- 2026-10-06: Read `PLAN.md`, checked toolchain, created this file.
- 2026-10-06: Installed `llvm-tools` and `cargo-llvm-cov` 0.9.1.
- 2026-10-06: Step 1 done. fmt, clippy, tests green. `logging.rs` line coverage 96%; crate total 88% (includes `main.rs`, to be excluded via `--ignore-filename-regex` in CI).
- 2026-10-06: Config parses through a lookup closure (`Config::from_lookup`). Edition 2024 makes `std::env::set_var` unsafe and we forbid unsafe, so tests pass a map instead of touching the process env. `from_env` is the only uncovered part of `config.rs`.
- 2026-10-06: Config leniency: values are trimmed; empty `OATH_READER` means unset; `OATH_TRUSTED_PROXIES` accepts bare IPs as /32 or /128 and skips empty entries; `OATH_LOG_LEVEL` is case-insensitive and also accepts `warn`. TTLs and the fail limit must be at least 1; idle equal to max is allowed.
- 2026-10-06: Added `thiserror` 2 and `ipnet` 2 (CIDR parsing).
- 2026-10-06: TLV: `encode` is infallible and panics above 65535 bytes (YKOATH values are tiny, so that is a programming error). Parsing accepts non-minimal long lengths (`0x81 0x02`) and rejects length bytes `0x80` and `0x83..=0xFF`. "Strict" means `parse_exact` / `parse_all`; `parse` is the lenient form that returns trailing bytes.
- 2026-10-06: Crypto deps: RustCrypto `pbkdf2` 0.13, `hmac` 0.13, `sha1`/`sha2` 0.11 (one digest 0.11 family, no duplicates), `subtle` 2.6, `zeroize` 1.9; dev `hex-literal` 1.1.
- 2026-10-06: All crypto test vectors were checked with Python stdlib before use. PBKDF2 at 1000 rounds / 16 bytes has no published vector, so the expected values come from `hashlib.pbkdf2_hmac`. The real-key PBKDF2 fixture (section 14.4) is still pending: the key has no password yet.
- 2026-10-06: `format_code` masks the top bit (`& 0x7FFFFFFF`) per RFC 4226, which PLAN.md section 5 omits. Harmless for card output and matches ykman.
- 2026-10-06: `timestep` and `validity_window` take `NonZeroU32` periods so a zero period cannot reach a division. Name parsing in `proto` must reject `0/...`.
- 2026-10-06: The `/api/codes` example in PLAN.md section 9 has `valid_from` 1759751990, which is not a multiple of 30. Real windows are period-aligned; treat the example as illustrative only.
- 2026-10-06: `Algorithm::from_ykoath` uses only the low nibble, so it accepts both a bare algorithm byte (SELECT `0x7B`) and a type|algorithm byte.
- 2026-10-06: User reported a YubiKey with an RFC 6238 credential is plugged in. Checked it read-only with `ykman`; details under "Hardware available".
- 2026-10-06: Step 2 done. 13 tests green, fmt and clippy clean. `clock.rs` and `rng.rs` at 100% line coverage; crate total 96%.
- 2026-10-06: Step 3 done. 28 tests green, fmt and clippy clean. `config.rs` 97% line coverage; crate total 96%. `main` exits 1 with a clear message on invalid config.
- 2026-10-06: Step 4 done. 46 tests green, fmt and clippy clean. `oath/tlv.rs` 100% line coverage; crate total 97%.
- 2026-10-06: Step 5 done. 63 tests green, fmt and clippy clean. `oath/crypto.rs` 100% line coverage; crate total 98%. One test had wrong data copied from the PLAN.md example (see decisions); fixed the test, not the code.
