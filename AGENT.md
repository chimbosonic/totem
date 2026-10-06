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
- Credentials (as of 2026-10-06):
  - `RFC6238:sha256`: TOTP, SHA-256, 8 digits, 30s, RFC 6238 SHA-256 secret.
  - `60/RFC6238:sha256-60s`: same secret, SHA-256, 8 digits, **60s**.
  - `RFC4226:sha1`: **HOTP**, SHA-1, 6 digits, RFC 4226 secret `12345678901234567890` (base32 `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`). Verified 2026-10-06: after all hardware tests and a real server run, the user's first `ykman oath accounts code RFC4226` gave `755224` (counter 0), so the service never advanced it. That check moved the counter to **1**; the next code is `287082`.
  - Touch-required: **not possible on this key**. `ykman` says "Require touch is not supported on this YubiKey" (the NEO's OATH applet is 1.0.0; touch needs a YubiKey 4.2.4 or newer). Touch handling is covered by the mock only.
- Original credential note: `RFC6238:sha256` (issuer `RFC6238`, account `sha256`). The user confirmed it uses the RFC 6238 SHA-256 test secret `12345678901234567890123456789012` (ASCII, 32 bytes), so expected codes can be checked against the RFC 6238 Appendix B vectors as well as `ykman oath accounts code`. Verified 2026-10-06: SHA-256, **8 digits**, 30s period; `ykman` code matched an independent Python computation.
- Device ID (PBKDF2 salt, not secret): `4d17581a446ffed1`.
- OATH password protection was disabled at first; the user enabled it on 2026-10-06 and put the password in `.env` as `OATH_HW_PASSWORD` (git-ignored). Never print `.env` values; load it with `sh -c 'set -a; . ./.env; set +a; ...'`.
- Hardware integration tests must not run in normal `cargo test` (section 14.1: no hardware in tests). Plan: put them in `tests/` behind an opt-in (a Cargo feature or env var), and compare with `ykman oath accounts code`.
- The NEO's older applet may not support SHA512 credentials; do not assume it does in hardware tests.

## Running against the real key

- `OATH_BIND=127.0.0.1:18080 cargo run` currently exits 1 with "the OATH applet has no password ... `ykman oath access change`" (expected until a password is set).
- Hardware tests (never part of plain `cargo test`):
  - `cargo test --features hardware-tests --test hardware -- --test-threads=1` (unprotected key: 5 pass, the unlock test fails asking for `OATH_HW_PASSWORD`).
  - `OATH_HW_PASSWORD='...' cargo test --features hardware-tests --test hardware -- --test-threads=1` (protected key: unlock, wrong password, codes).
- Frontend tests: `node --test static/` (Node's built-in runner, no npm, no package.json).
- Browser check (headless Chrome over CDP, script kept in the session scratchpad, not the repo): no CSP violations or JS errors in dark or light mode; screenshots looked right.
- Container: Rancher Desktop provides Docker 29.5 at `~/.rd/bin/docker` (not on PATH by default; `export PATH="$HOME/.rd/bin:$PATH"`). The Rancher VM has no pcscd and cannot see the USB key, so the container can only be checked up to the reader error locally.
- Coverage gate excludes `card/pcsc.rs` and `main.rs`: `cargo llvm-cov --ignore-filename-regex '(card/pcsc\.rs|main\.rs)$'`.

## Manual hardware checklist (section 14.4) status

1. Set OATH password: done by the user (2026-10-06).
2. Add one 60s TOTP, one touch-required TOTP, one HOTP: done for 60s TOTP and HOTP; **touch-required is not supported by the NEO** (mock coverage only). Checked by `hw_sixty_second_totp_uses_its_own_timestep` and `hw_hotp_is_listed_without_a_code`.
3. Codes match `ykman oath accounts code`: done for `RFC6238:sha256` (`15566265` while unprotected; protected unlock path matches the RFC secret).
4. PBKDF2 fixture: done, kept in `.env` (`OATH_HW_DERIVED_KEY`), checked by `hw_pbkdf2_matches_independent_fixture`.
5. Unplug and replug with the page open: **pending, user action**. The frontend now exists: unlock, unplug the key (expect "YubiKey unavailable. Is it plugged in? Retrying." every 5s), replug (codes return without unlocking again).
6. Logs contain no password or codes: password checked absent from a real server run's log; codes covered by `logs_never_contain_password_key_session_id_or_codes`.

## Build order progress (section 16)

| # | Step | Status | Notes |
|---|---|---|---|
| 1 | Scaffold crate, forbid unsafe, logging, placeholder test | done | `logging::build_logger` (slog-json + slog-async), 2 tests |
| 2 | `clock` and `rng` traits | done | `Clock` (`SystemClock`, `ManualClock`), `ChallengeSource` (`OsChallengeSource`, `SequentialChallengeSource`), 11 tests |
| 3 | `config` | done | `Config::from_lookup` (tested) and `from_env` (thin wrapper), 15 tests; `main` uses it |
| 4 | `oath::tlv` | done | `encode`, `parse` (lenient, returns rest), `parse_exact` (strict), `parse_all` (strict sequence), 18 tests |
| 5 | `oath::crypto` | done | `derive_key`, `hmac`, `dynamic_truncate`, `format_code`, `timestep`, `validity_window`, `constant_time_eq`, `Algorithm`, 17 tests |
| 6 | `oath::proto` | done | APDU builders, `parse_select`, `verify_validate_response`, `parse_calculate_all`, `parse_calculate`, `transmit_chained`, `status_error`, `parse_name`, 39 tests |
| 7 | `OathCard` trait and mock card | done | `OathCard`, `CardTransaction`, `CardError`, `card::send`, `card::mock::MockCard`, 29 tests (proto driven end to end against the mock) |
| 8 | `service` | done | `Service::{startup_check, unlock, codes}`, retry/reconnect, serialisation, 19 tests (+1 mock test) |
| 9 | `session` | done | `SessionStore::{create, touch, remove, purge}`, `SessionId` (hex cookie, redacted Debug, `log_id`), `spawn_purger`, 17 tests |
| 10 | `ratelimit` | done | `RateLimiter::acquire` -> `UnlockPermit::{success, failure}`, `Denied`, `client_ip`, 26 tests |
| 11 | `api` (Dropshot) | done | API trait (`api::definition`), handlers (`api::server`), `auth`, `security`, `errors`, OpenAPI snapshot, 55 tests (+7 session/service) |
| 12 | Real PC/SC card implementation | done | `card::pcsc::PcscCard`, `card::pick_reader`, `main` wiring, `tests/hardware.rs` (feature `hardware-tests`); 8 unit tests + 6 hardware tests |
| 13 | Frontend | done | `static/{index.html,app.js,app.css}`, 13 JS tests (`node --test static/`), 7 Rust static-file rule tests, repo-wide em dash test |
| 14 | Dockerfile and compose | done | `Dockerfile`, `.dockerignore`, `docker-compose.yml`, 7 rule tests (`tests/container.rs`) |
| 15 | GitLab CI with coverage gate | todo | |
| 16 | README | todo | |

## Open questions and things to verify

- ~~YKOATH bytes: confirm SELECT/CALCULATE ALL on the NEO and that APDUs without Le are accepted.~~ Resolved 2026-10-06: SELECT and CALCULATE ALL work on the NEO (applet 1.0.0) with no Le byte; the RFC6238:sha256 code read through our stack matched both an independent computation and `ykman` (`15566265`). VALIDATE (with the `6A80` finding) and CALCULATE (60s credential) were then confirmed on the protected key.
- ~~Which status word does the NEO return for a wrong VALIDATE?~~ Resolved 2026-10-06: **`6A80`**, not the spec's `6984`. This was a real bug (see Decisions); both now map to `WrongPassword` on VALIDATE. Spec says `6984` (mapped to `WrongPassword`). `6A80` currently maps to a generic `Status` error. Needs a password set on the key to check.
- ~~Dropshot: which response types allow custom headers?~~ Resolved: `HttpResponseHeaders<T>::headers_mut()` (keeps typed OpenAPI) and `Response<Body>`.
- ~~Dropshot: can `HttpError` carry `Retry-After` for 429?~~ Resolved: yes, `HttpError.headers` / `headers_mut()`; applied when rendered.
- ~~Dropshot: `TypedBody` on non-JSON `Content-Type`?~~ Resolved: a missing `Content-Type` is treated as JSON, `application/*+json` is accepted, other types get 400. So POST handlers call `security::require_json` (400 too, for one consistent status).
- ~~PBKDF2 fixture from a real key (section 14.4 item 4)~~ Resolved 2026-10-06 (user's suggestion): the fixture lives in the git-ignored `.env` as `OATH_HW_DERIVED_KEY`, computed with Python `hashlib` from `OATH_HW_PASSWORD` and the device ID, and checked by `hw_pbkdf2_matches_independent_fixture`. It is password-equivalent, so it must never be committed.

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
- 2026-10-06: `proto` is pure. Chaining is `transmit_chained(transmit_closure, apdu)`, generic over the caller's error type `E: From<ProtoError>`, so the card layer passes its own transport errors straight through. Chains are capped at 64 SEND REMAINING rounds.
- 2026-10-06: Status words are mapped per command: `6984` is `WrongPassword` on VALIDATE and `NotFound` elsewhere; `6982` is `AuthRequired`; anything else is `Status(sw)`.
- 2026-10-06: APDUs are short-form with no Le byte, matching ykman. Lc over 255 panics (names are at most 64 bytes, so it is a programming error).
- 2026-10-06: `parse_select` ignores unknown tags (newer firmware adds some) but requires version and name, and a known algorithm whenever a challenge is present. A card HMAC mismatch in VALIDATE is `CardAuthFailed`.
- 2026-10-06: CALCULATE ALL entries keep the raw name bytes; name parsing is separate (`parse_name`) so the service can re-send the exact name in CALCULATE. A full `0x75` response (non-truncated) is treated as malformed since we always ask for truncated.
- 2026-10-06: `parse_name` is infallible. A prefix that is not a positive whole number (`0/`, `/`, overflow, `+5/`) stays in the issuer rather than failing the whole response. Invalid UTF-8 is shown lossily. The period prefix is parsed for every credential type; ykman only does so for TOTP, which only affects how an HOTP named like `60/x` is displayed.
- 2026-10-06: `OathCard::transaction()` returns `Box<dyn CardTransaction + '_>` that ends on drop, mirroring pcsc's `Transaction<'_>`. The trait is object-safe so the service can hold `Box<dyn OathCard>`. `CardError::needs_reconnect()` is true for everything except `Proto(_)`.
- 2026-10-06: `MockCard` state is `Arc<Mutex<_>>`, so clones share state: a test keeps a handle for `events()` and `fail_next()` after moving the card into the service. Builder methods (`with_password`, `with_credential`, `with_chunk_size`) mutate shared state too, so build separate cards when a test needs two configurations.
- 2026-10-06: Mock behaviour choices: the VALIDATE algorithm is always SHA1; the challenge is single-use; reselect, reconnect, or an injected fault drops the unlocked state; CALCULATE on HOTP or touch credentials returns `6985` (touch is not emulated); commands before SELECT return `6985`; SEND REMAINING uses `61xx` with xx capped at `FF`; the default chunk is 255 bytes. Truncated values have the top bit cleared like a real card.
- 2026-10-06: Mock tests compare against literal RFC 6238 table values rather than recomputing with `oath::crypto`, so the mock and the crypto cannot share a bug unnoticed.
- 2026-10-06: `Service` holds `Arc<tokio::sync::Mutex<Box<dyn OathCard>>>`; each operation takes `lock_owned()` and runs in `spawn_blocking`. The card op is a `Fn` closure run inside one transaction, so a retry reruns SELECT/VALIDATE from scratch.
- 2026-10-06: Retry rule: a transport error (`needs_reconnect`) gets one reconnect and one retry; whatever the final error is, it goes through one `classify` function. `ServiceError::Unavailable(CardError)` therefore always means "reconnect attempted and still failing" (no separate flag). A card proof mismatch reconnects to drop the session and returns `CardAuthFailed`. A panicking card op maps to `Internal`.
- 2026-10-06: `Service::codes` takes `&DerivedKey` for now. Section 9a wants `&AuthedSession`; tighten that in step 11 when the type exists.
- 2026-10-06: The password is dropped (and zeroized) when the `unlock` card closure is dropped, right after the operation. It cannot be derived before touching the card, because the PBKDF2 salt is the device ID from SELECT.
- 2026-10-06: `Service::codes` reads the clock once per request; `generated_at`, timesteps, and validity windows all use that one value. Credentials whose name has no valid period prefix use 30s.
- 2026-10-06: Mock gained `with_forged_validate_response()` to test the card proof failure path.
- 2026-10-06: Sessions: the store is keyed by SHA-256 of the session ID, not the raw ID, so a memory dump or debug print never shows a usable cookie. `log_id()` is the first 8 bytes of that digest in hex; `SessionId`'s `Debug` prints only that. Cookie value is 64 lowercase hex chars; parsing accepts upper case and rejects anything that is not exactly 64 hex digits.
- 2026-10-06: Expiry: a session is expired when `now >= last_seen + idle` or `now >= created + max`. `touch()` refreshes `last_seen`, returns a `Zeroizing` copy of the key, and removes the entry if it had expired. Uses `std::sync::Mutex` (no awaits while held).
- 2026-10-06: `spawn_purger` is tested with `#[tokio::test(start_paused = true)]`; the `tokio::time::sleep` there is virtual time, not real sleeping. Added tokio `time` (and `test-util` for dev).
- 2026-10-06: Rate limiting: only one unlock attempt may be in flight per IP (`Denied::InFlight`), otherwise parallel guesses would sidestep the doubling backoff. A dropped `UnlockPermit` records neither success nor failure (for card errors) and frees the IP. Check order: global lockout, in-flight, per-IP backoff.
- 2026-10-06: Global lockout engages on the Nth failure within 15 minutes (N = `OATH_GLOBAL_FAIL_LIMIT`). PLAN.md section 8 says "more than N" but section 11 says "failures before global lockout"; chose the stricter reading. The failure list is cleared when a lockout engages.
- 2026-10-06: Per-IP history is forgotten 15 minutes after its backoff ends (pruned on each `acquire`), so the map cannot grow without bound. An IP that waits that long starts again at 1s.
- 2026-10-06: `client_ip`: X-Forwarded-For is used only when the direct peer is trusted; the right-most entry that is not itself a trusted proxy is the client (left-most if all are trusted). Any unparseable entry (including `ip:port`) falls back to the peer. IPv4-mapped IPv6 addresses are canonicalised.
- 2026-10-06: Dropshot 0.17.1 (source read in `~/.cargo/registry`). It depends on schemars **0.8**, so schemars is pinned to 0.8; 1.x types would not satisfy its `JsonSchema` bound.
- 2026-10-06: Security headers gap: Dropshot cannot add headers to responses it generates itself: unknown route 404/405 (router runs before any handler) and `TypedBody` extractor 400s (bad JSON, wrong content type, body over 1024 bytes). A custom error type does not help: `HttpResponseContent` needs `ApiSchemaGenerator`, which is not exported, and the blanket JSON impl cannot set headers. Every handler-produced response (success and error) goes through `security::secure_result`, enforced by `every_endpoint_returns_security_headers`. Backstop: a Traefik `headers` middleware in the compose file (step 14). These framework responses contain no secrets.
- 2026-10-06: CSP is `default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'` plus `X-Frame-Options: DENY`; stricter than PLAN.md's minimum. `Cache-Control: no-store` on `/api/*` and `/healthz`.
- 2026-10-06: `AuthedSession` lives in `session` (not `api`) so `service` can require it without depending on `api`. Only `SessionStore::authenticate` builds one; its key accessor is `pub(crate)`.
- 2026-10-06: `ApiContext` is `{ service, sessions, ratelimit, config }`. PLAN.md also lists `clock` and `rng`, but every user of them already holds its own `Arc`, so they were left out rather than kept as unused fields.
- 2026-10-06: Testability split for the 9a helpers: each `RequestContext` function (`require_session`, `client_ip`, `acquire_unlock_attempt`) is a one-line wrapper over a pure function (`session_from_headers`, `client_ip_from`, `acquire_unlock_attempt_for`) that is unit tested. A `RequestContext` cannot be built in a unit test.
- 2026-10-06: Unlock flow: `require_json`, then permit (429 before touching the card), then `service.unlock`. A wrong password records a failure; a card error drops the permit (no record) and logs `card_error`. Server uses `HandlerTaskMode::Detached` so a client disconnect cannot cancel an unlock before its failure is recorded.
- 2026-10-06: `/api/codes` returning `WrongPassword` (password changed since unlock) removes the session and returns 401, so the frontend falls back to the locked view.
- 2026-10-06: Status mapping: `WrongPassword` and no session are 401; `NoPassword`, `CardAuthFailed`, `Unavailable`, and `Protocol` are 503 with external message `card unavailable` (details only in the internal message, which goes to the log); `Internal` is 500. Bad content type is 400; rate limit is 429 + `Retry-After`.
- 2026-10-06: Session cookie: `oath_session=<64 hex>; HttpOnly; Secure; SameSite=Strict; Path=/` with no Max-Age (server-side TTLs rule). Lock sends the same attributes with `Max-Age=0`.
- 2026-10-06: `UnlockRequest` deliberately has no `Debug`. The password moves straight into `Zeroizing<String>`; the raw request bytes inside Dropshot/hyper are not zeroized (outside our control).
- 2026-10-06: OpenAPI is generated by `api::server::openapi_json()` from `stub_api_description()` and committed as `openapi/oath-web.json`; regenerate with `EXPECTORATE=overwrite cargo test openapi_matches`. The 2 "ignored" doctests in `cargo test` output come from docs generated by the `#[dropshot::api_description]` macro, not from our code.
- 2026-10-06: API tests run a real Dropshot server on `127.0.0.1:0` with `reqwest` (no default features). Logs are captured with a synchronous slog JSON drain over `logging::test_support::SharedBuf`, so tests can read them after `server.close()`.
- 2026-10-06: Static files are placeholders in `static/` (embedded with `include_str!`) until step 13. `main` is not wired to the server yet; that comes with the real PC/SC card in step 12.
- 2026-10-06: Reader selection (`card::pick_reader`) is case-insensitive substring matching. This matters: the NEO enumerates as `Yubico Yubikey NEO OTP+U2F+CCID` (lowercase k), which a case-sensitive "YubiKey" match would miss.
- 2026-10-06: `PcscCard::reconnect` drops the card handle, re-establishes the PC/SC context, and picks the reader again, because a replugged key can return under a new name and a restarted pcscd invalidates the context. pcsc's `Card` drop disconnects with `ResetCard` and `Transaction` drop ends with `LeaveCard`; both are fine since every operation reselects.
- 2026-10-06: `main` does config, logger, PC/SC connect, startup check (exit 1 with the `ykman oath access change` hint if no password), then sessions, purger, rate limiter, and only then binds the port. It shuts down gracefully on SIGTERM (`docker stop`) or Ctrl-C via `HttpServer::wait_for_shutdown` / `close`. Added tokio `signal`.
- 2026-10-06: Hardware tests live in `tests/hardware.rs` behind the `hardware-tests` feature (not `#[ignore]`, which section 14.1 restricts). They adapt to whether `OATH_HW_PASSWORD` is set; the unlock test panics with instructions when it is not, rather than silently passing.
- 2026-10-06: **Bug found on hardware:** the NEO answers a wrong VALIDATE with `6A80`. It was mapped to `Protocol(Status(0x6A80))`, so a wrong password returned 503 and, worse, the unlock handler treated it as a card error and recorded no failure: wrong guesses bypassed the rate limiter. Fix: `status_error` maps both `6984` and `6A80` on VALIDATE to `WrongPassword` (ykman does the same). The mock now answers a wrong VALIDATE with `6A80` like the real key, which made 11 existing tests (including the API rate-limit and global-lockout tests) fail before the fix. Lesson: keep the mock faithful to real hardware, not just the spec.
- 2026-10-06: `.env` is git-ignored; it holds `OATH_HW_PASSWORD` for hardware tests.
- 2026-10-06: Frontend is vanilla JS, as PLAN.md section 10 says (user considered htmx and chose vanilla). It is tested with `node --test` (user's choice): pure helpers in `static/app.js` are exported via `module.exports` only under Node; in a browser the file is a classic deferred script. `static/app.test.js` is not served (only the three files are `include_str!`'d). CI needs a Node job for it (step 15).
- 2026-10-06: Visual style copies dane.dp42.dev at the user's request: its palette and light-mode palette, monospace everywhere, 16px panels, pills, gradient pill buttons, dashed value boxes. This overrides PLAN.md section 10's "clear sans-serif for labels".
- 2026-10-06: Frontend behaviour: on load it fetches `/api/codes` (401 means locked view, 200 unlocked, 503 unlocked with a retrying message every 5s). The countdown uses the server clock (offset from `generated_at`); it refetches 500ms after the soonest `valid_until`, never more often than 1s, and again when the tab becomes visible. A 429 disables the unlock button with a live countdown from `Retry-After`. The password field is cleared before the request. Copy uses `navigator.clipboard` (needs HTTPS or localhost). Codes are shown in groups of three from the left (`123 456 78` for 8 digits), as the plan says.
- 2026-10-06: CSP safety rules for the static files are enforced by Rust tests: no inline scripts or `<style>`, no `style=` or `on*=` attributes, no external URLs (even in comments), no `innerHTML`/`eval`/`new Function` in app.js, and every `getElementById("...")` id must exist in index.html. The countdown bar is driven by CSSOM `style.transform`, which the CSP allows. A repo-wide test (`tests/repo_rules.rs`) enforces the no em dash rule.
- 2026-10-06: Known, accepted: browsers request `/favicon.ico`, which is a Dropshot 404 (no security headers, no content). A `data:` favicon would violate the CSP; serving a real icon would mean another endpoint. Revisit only if wanted.
- 2026-10-06: No Docker on this Mac. Found Apple's `container` CLI 0.10.0 (service not running) and a Rancher Desktop app (no `docker` on PATH). Did not start either without asking: starting registers a launchd service. The image build is therefore unverified so far.
- 2026-10-06: Dockerfile: `rust:1-bookworm` builder with BuildKit cache mounts, `debian:bookworm-slim` runtime with only `libpcsclite1` and `ca-certificates`, numeric non-root `USER 10001:10001`, no shell use at runtime, compatible with `read_only: true`. No `HEALTHCHECK` because the image has no curl; could add an `oath-web --healthcheck` mode later. Debian 13 trixie is current stable by now, but PLAN.md says bookworm and the base must match the host's pcsc-lite protocol anyway.
- 2026-10-06: `.dockerignore` excludes `.env` (the OATH password), `.git`, `target`, `tests`, `openapi`, and docs.
- 2026-10-06: Compose adds an `oath-headers` Traefik middleware (CSP, nosniff, frameDeny, no-referrer, `Cache-Control: no-store`) as the backstop for Dropshot-generated responses. `tests/container.rs` checks its CSP equals `api::security::CSP`. Also `build: .` so `docker compose up --build` works.
- 2026-10-06: Possible deployment snag to document in the README: newer pcsc-lite builds on some hosts (Fedora, recent Ubuntu) authorise clients through polkit, which can deny a non-root container user even with the socket mounted.
- 2026-10-06: User reported a YubiKey with an RFC 6238 credential is plugged in. Checked it read-only with `ykman`; details under "Hardware available".
- 2026-10-06: Step 2 done. 13 tests green, fmt and clippy clean. `clock.rs` and `rng.rs` at 100% line coverage; crate total 96%.
- 2026-10-06: Step 3 done. 28 tests green, fmt and clippy clean. `config.rs` 97% line coverage; crate total 96%. `main` exits 1 with a clear message on invalid config.
- 2026-10-06: Step 4 done. 46 tests green, fmt and clippy clean. `oath/tlv.rs` 100% line coverage; crate total 97%.
- 2026-10-06: Step 5 done. 63 tests green, fmt and clippy clean. `oath/crypto.rs` 100% line coverage; crate total 98%. One test had wrong data copied from the PLAN.md example (see decisions); fixed the test, not the code.
- 2026-10-06: Step 6 done. 102 tests green, fmt and clippy clean. `oath/proto.rs` 99.6% line coverage; crate total 98.6%.
- 2026-10-06: Step 7 done. 131 tests green, fmt and clippy clean. `card.rs` 100%, `card/mock.rs` 99% line coverage; crate total 98.8%. Caught and fixed two bad tests before going green (a clone sharing state, a chunk size larger than the response).
- 2026-10-06: Step 8 done. 150 tests green, fmt and clippy clean. `service.rs` 99% line coverage; crate total 98.9%. Found a bug before committing (a protocol error on the retry was reported as `Unavailable`); reproduced it with `wrong_password_on_retry_is_still_wrong_password` first, then fixed it.
- 2026-10-06: Step 9 done. 167 tests green, fmt and clippy clean. `session.rs` 100% line coverage; crate total 99%. Found that `u8::from_str_radix` accepts a leading `+`, so `+a+a...` parsed as a session cookie; reproduced with a test, then fixed.
- 2026-10-06: Step 10 done. 193 tests green, fmt and clippy clean. `ratelimit.rs` 100% line coverage; crate total 99%. Three tests had setup bugs (global limit too low for per-IP tests, one wrong clock step); fixed the tests, code unchanged.
- 2026-10-06: Step 11 done. 255 tests green, fmt and clippy clean. Coverage 98.8% lines overall; every `api/*` file 100% except `server.rs` 98.9%. Read Dropshot 0.17.1 source to answer the section 9a questions (see Open questions and Decisions).
- 2026-10-06: Step 12 done. 263 unit tests green, fmt and clippy clean (also with `--features hardware-tests`). Coverage with the pcsc/main exclusion: 99.0% lines. On the real NEO: connect, SELECT, reconnect, CALCULATE ALL (code matched ykman), and the no-password refusal all work. Unlock/VALIDATE on hardware waits for the user to set an OATH password.
- 2026-10-06: With the key password-protected, all 6 hardware tests pass after fixing the `6A80` bug. Smoke-tested the real binary against the key with curl: healthz 200, wrong password 401 then 429 (`Retry-After: 1`), unlock 204 + cookie, codes OK, lock 204, codes after lock 401, SIGTERM exit 0, log free of the password.
- 2026-10-06: Added `hw_pbkdf2_matches_independent_fixture`; fixture computed into `.env` without printing it. All 7 hardware tests pass.
- 2026-10-06: User added a 60s TOTP and an HOTP (touch unsupported on the NEO). Added two hardware tests; all 9 pass. Every YKOATH command we use (SELECT, VALIDATE, CALCULATE ALL, CALCULATE) is now verified on the real key.
- 2026-10-06: HOTP counter confirmed untouched by the service (`755224` on first manual read). Counter is now 1.
- 2026-10-06: Step 13 done. 269 Rust tests and 13 JS tests green, fmt and clippy clean. Checked in headless Chrome against the real key: both views render in dark and light mode, codes and countdown work, no CSP violations.
- 2026-10-06: Step 14 files written; 7 container rule tests green. Image build still to verify on a container runtime.
- 2026-10-06: Built the image with Rancher Desktop (Docker 29.5.3, linux/aarch64): 1.5 min cold build, 34.5 MB image, runs as uid 10001, ships `libpcsclite1 1.9.9-2` and `ca-certificates` only (no curl). Run with `--read-only --cap-drop ALL --security-opt no-new-privileges:true` it logs JSON and exits 1 with the "no usable smart card reader" hint, as expected without pcscd. `docker compose config` validates the compose file and the CSP label resolves intact. Step 14 done.
