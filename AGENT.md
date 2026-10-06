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

## Build order progress (section 16)

| # | Step | Status | Notes |
|---|---|---|---|
| 1 | Scaffold crate, forbid unsafe, logging, placeholder test | todo | |
| 2 | `clock` and `rng` traits | todo | |
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

## Session log

- 2026-10-06: Read `PLAN.md`, checked toolchain, created this file.
- 2026-10-06: Installed `llvm-tools` and `cargo-llvm-cov` 0.9.1.
