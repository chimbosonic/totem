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
- One credential: `RFC6238:sha256` (issuer `RFC6238`, account `sha256`). The user says it uses the RFC 6238 test setup.
- OATH password protection is **disabled** (checked 2026-10-06 with `ykman oath info`). The service refuses to start against an unprotected applet (section 7), so a password must be set (`ykman oath access change`) before a full end-to-end run. Ask the user before changing anything on the key.
- Hardware integration tests must not run in normal `cargo test` (section 14.1: no hardware in tests). Plan: put them in `tests/` behind an opt-in (a Cargo feature or env var), and compare with `ykman oath accounts code`.
- The NEO's older applet may not support SHA512 credentials; do not assume it does in hardware tests.

## Build order progress (section 16)

| # | Step | Status | Notes |
|---|---|---|---|
| 1 | Scaffold crate, forbid unsafe, logging, placeholder test | done | `logging::build_logger` (slog-json + slog-async), 2 tests |
| 2 | `clock` and `rng` traits | done | `Clock` (`SystemClock`, `ManualClock`), `ChallengeSource` (`OsChallengeSource`, `SequentialChallengeSource`), 11 tests |
| 3 | `config` | todo | |
| 4 | `oath::tlv` | todo | |
| 5 | `oath::crypto` | todo | |
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
- 2026-10-06: User reported a YubiKey with an RFC 6238 credential is plugged in. Checked it read-only with `ykman`; details under "Hardware available".
- 2026-10-06: Step 2 done. 13 tests green, fmt and clippy clean. `clock.rs` and `rng.rs` at 100% line coverage; crate total 96%.
