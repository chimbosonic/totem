# Build Plan: `oath-web`

A small Rust service that reads TOTP codes from a YubiKey OATH applet plugged into the host and shows them on an internal web page. Access is gated by the OATH password set on the key.

`oath-web` is a working name. Rename freely.

## 1. Goal and scope

**In scope**

- Read TOTP credentials from the YubiKey OATH applet over PC/SC.
- Unlock using the key's own OATH password, entered on the web page.
- Show codes with a countdown, copy button, and lock button.
- Run as a single container, internal network only, behind the existing Traefik v3 setup.

**Out of scope**

- Adding, deleting, or renaming credentials (manage those with `ykman` on the host).
- HOTP codes (calculating one increments the counter, so they are listed but never computed).
- Touch-required credentials (nobody is at the server to touch the key; listed as unavailable).
- Multi-user accounts. One shared password, which is the OATH password.
- Public internet exposure.

## 2. Constraints for the agent

- Rust, stable toolchain, edition 2024.
- No unsafe code (`#![forbid(unsafe_code)]`).
- `cargo fmt --check` and `cargo clippy -- -D warnings` must pass.
- The OATH password must never be logged, written to disk, or returned in any response.
- Codes must never be logged. Account names may be logged in the audit log.
- Keep dependencies small and well known. No frontend build step.
- **The HTTP API must be built with [Dropshot](https://github.com/oxidecomputer/dropshot/).** No axum, actix, warp, or tower middleware. See section 9a.
- Do not use em dashes in any docs, comments, or UI text.
- **Test-driven development is mandatory.** No production code is written without a failing test that requires it. See section 14 for the workflow.
- Every module has unit tests in the same file (`#[cfg(test)] mod tests`). The only exception is the real PC/SC card implementation, which is covered by the manual hardware checklist.

## 3. Architecture

```
Browser (LAN)
   |  HTTPS
Traefik v3  (ipAllowList: LAN ranges)
   |  HTTP on internal Docker network
oath-web container
   |  PC/SC (pcsc crate -> libpcsclite)
pcscd  (host, socket mounted into container)
   |  USB CCID
YubiKey (OATH applet)
```

Modules:

| Module | Responsibility |
|---|---|
| `oath::tlv` | Encode and parse simple TLV used by YKOATH |
| `oath::proto` | APDU builders and response parsers (SELECT, VALIDATE, CALCULATE ALL, CALCULATE, SEND REMAINING) |
| `oath::crypto` | PBKDF2 key derivation, HMAC challenge response, code truncation |
| `card` | `OathCard` trait, real PC/SC implementation, mock implementation |
| `service` | Serialised card access, reconnect handling, business logic |
| `session` | In-memory sessions holding the derived key, TTL, zeroize on drop |
| `ratelimit` | Per-IP backoff and global lockout for unlock attempts |
| `api` | Dropshot API trait, endpoint implementations, auth and rate-limit extractor functions, response helpers, static frontend endpoints |
| `config` | Env var config with validation |
| `clock` | `Clock` trait (`now()`), system and fixed/advanceable test implementations |
| `rng` | `ChallengeSource` trait for random challenges and session IDs, OS and deterministic test implementations |

`Clock` and `ChallengeSource` exist purely so time-dependent and random behaviour (timesteps, TTLs, backoff, challenges) can be unit tested deterministically. No module reads system time or randomness directly.

## 4. Suggested crates

- `dropshot` (HTTP API), `schemars` (JSON Schema for request and response types), `http`, `tokio`
- `pcsc`
- `pbkdf2`, `hmac`, `sha1`, `sha2` (for SHA256/512 credential info only, the card does the HMAC), `rand`
- `zeroize`, `subtle` (constant-time compare)
- `serde`, `serde_json`
- `slog`, `slog-bunyan` or `slog-json`, `slog-async` (Dropshot is slog-based, so the whole service logs through slog)
- `thiserror`, `anyhow` (anyhow only in `main`)
- Dev: plain `#[tokio::test]`, `hex-literal`, `reqwest` (for in-process server tests), `expectorate` (OpenAPI snapshot check)

## 5. YKOATH protocol details

Reference: Yubico "YKOATH Protocol Specification". Verify every byte below against it before relying on it.

**SELECT**

- APDU: `00 A4 04 00` + Lc + AID `A0 00 00 05 27 21 01`
- Response TLVs:
  - `0x79` version
  - `0x71` name (device ID, used as PBKDF2 salt)
  - `0x74` challenge (present only if a password is set)
  - `0x7B` algorithm (present only if a password is set)

**Key derivation**

- `key = PBKDF2-HMAC-SHA1(password_utf8, salt = name from SELECT, iterations = 1000, length = 16)`

**VALIDATE** (INS `0xA3`)

- Data: `0x75` = `HMAC(key, card_challenge)` using the algorithm from `0x7B`, then `0x74` = 8 random bytes (our challenge).
- Response: `0x75` = card's HMAC over our challenge. Verify with a constant-time compare. If it does not match, treat it as a failure and drop the connection.
- A failed VALIDATE returns an error status word. Map it to "wrong password".

**CALCULATE ALL** (INS `0xA4`, P2 `0x01` for truncated)

- Data: `0x74` = 8-byte big-endian timestep, `floor(unix_time / 30)`.
- Response is a sequence of pairs: `0x71` name, then one of:
  - `0x76` truncated response: first byte is digits, next 4 bytes are the value
  - `0x77` HOTP (no code computed)
  - `0x7C` touch required (no code computed)
- Code = `u32::from_be_bytes(value) % 10^digits`, zero-padded to `digits`.

**CALCULATE** (INS `0xA2`, P2 `0x01`)

- Used for TOTP credentials with a non-30-second period. The name is encoded as `"{period}/{issuer}:{account}"`. Parse the period prefix and recompute with the correct timestep for those.

**SEND REMAINING** (INS `0xA5`)

- If a response returns SW `61xx`, keep sending SEND REMAINING and concatenate until SW `9000`.

**Session scope on the card**

- Unlocked state lasts until the applet is reselected or the card is reset. Every request does `SELECT -> VALIDATE -> CALCULATE ALL` inside one exclusive transaction. Do not rely on the card staying unlocked between requests.

**Name parsing**

- Strip optional `{period}/` prefix.
- Split on the first `:` into issuer and account. If no `:`, issuer is empty.

## 6. Card access

- One `pcsc::Context`, reader chosen by `OATH_READER` substring match, or the first reader containing "YubiKey" if unset.
- All card operations run in `tokio::task::spawn_blocking`, behind a `tokio::sync::Mutex` so only one transaction runs at a time.
- Use `card.transaction()` for each request sequence.
- On `RemovedCard`, `ResetCard`, `NoSmartcard`, or reader errors: drop the handle, reconnect once, retry once, then return a 503 to the client.
- `OathCard` trait so the HTTP layer and service logic can be tested with a mock card that implements the protocol in memory.

## 7. Startup checks

On boot, before binding the HTTP port:

1. Connect to pcscd and find the reader. Exit non-zero with a clear message if missing.
2. SELECT the OATH applet. If the response has no `0x74` challenge, **no password is set**. Log an error telling the operator to run `ykman oath access change` and exit non-zero. The service must never run against an unprotected applet.
3. Log the applet version and reader name.

## 8. Sessions and rate limiting

**Sessions**

- `POST /api/unlock` takes the password, derives the key, runs a full SELECT/VALIDATE round trip to confirm it, then stores the derived key in memory under a random 32-byte session ID.
- Key stored as `Zeroizing<[u8; 16]>`. The password string is zeroized right after derivation.
- Cookie: `oath_session`, `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`.
- Idle TTL default 5 minutes, absolute TTL default 30 minutes. Both configurable.
- A background task purges expired sessions every 30 seconds.
- `POST /api/lock` deletes the session.
- Sessions are lost on restart. That is intended.

**Rate limiting**

- The key has no retry counter for the OATH password, so all brute-force protection lives here.
- Per client IP: after each failure, delay doubles starting at 1 second, capped at 5 minutes. Reset on success.
- Global: more than N failures (default 20) in 15 minutes locks unlock for everyone for 15 minutes.
- Client IP comes from `X-Forwarded-For` only when the direct peer is in `OATH_TRUSTED_PROXIES`. Otherwise use the peer address from the Dropshot request context.

## 9. HTTP API

| Method | Path | Auth | Response |
|---|---|---|---|
| GET | `/` | none | Static HTML page |
| GET | `/app.js`, `/app.css` | none | Static assets |
| POST | `/api/unlock` | none | `204` + cookie, `401` wrong password, `429` with `Retry-After` |
| POST | `/api/lock` | session | `204` |
| GET | `/api/codes` | session | `200` JSON, `401` if no or expired session, `503` if card unavailable |
| GET | `/healthz` | none | `200` if reader present, `503` otherwise. No account names. |

`/api/codes` response:

```json
{
  "generated_at": 1759752000,
  "credentials": [
    {
      "issuer": "GitLab",
      "account": "alexis",
      "status": "ok",
      "code": "123456",
      "digits": 6,
      "period": 30,
      "valid_from": 1759751990,
      "valid_until": 1759752020
    },
    { "issuer": "Example", "account": "x", "status": "touch_required" },
    { "issuer": "Other", "account": "y", "status": "hotp" }
  ]
}
```

- `POST` endpoints require `Content-Type: application/json`. Together with `SameSite=Strict` that covers CSRF for this use.
- Security headers on every response: strict CSP (`default-src 'self'`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` on `/api/*`.

## 9a. Dropshot implementation rules

Dropshot deliberately has no middleware or "run on every request" hooks. Shared behaviour is done with plain function calls that return typed values. The agent must follow that pattern rather than working around it.

**API definition**

- Define the API as a Dropshot API trait (`#[dropshot::api_description]`) in `api::definition`, with the implementation in `api::server`. This keeps the OpenAPI spec derivable without a running card and lets tests swap the context.
- Server context type: `ApiContext { service, sessions, ratelimit, clock, rng, config }`, all behind `Arc` and trait objects so tests inject mocks.
- All request and response bodies derive `Serialize`/`Deserialize` and `JsonSchema`.
- Request body limit: Dropshot's default is small (1024 bytes). Set `default_request_body_max_bytes` explicitly to a small value such as 1024 and keep it; the unlock body is tiny.
- Build the server with Dropshot's server builder, bound from `OATH_BIND`. No TLS in Dropshot; Traefik terminates TLS.

**Auth and rate limiting as typed values**

- `async fn require_session(rqctx: &RequestContext<ApiContext>) -> Result<AuthedSession, HttpError>` reads the `oath_session` cookie, checks expiry against the `Clock`, refreshes idle TTL, and returns `AuthedSession` (session ID hash for logging plus access to the derived key).
- `fn client_ip(rqctx) -> IpAddr` applies the trusted proxy rule.
- `async fn acquire_unlock_attempt(rqctx) -> Result<UnlockPermit, HttpError>` checks per-IP backoff and global lockout. `UnlockPermit` must be consumed by either `record_success()` or `record_failure()`.
- `service` functions that need the derived key take `&AuthedSession` as an argument, so a handler cannot fetch codes without first calling `require_session`.

**Responses and headers**

- Every endpoint returns through one helper, for example `fn secure(response: Response<Body>, kind: RespKind) -> Response<Body>`, that adds the security headers from section 9 and `Cache-Control: no-store` for API responses.
- Because the helper is a convention rather than middleware, add a test that iterates every endpoint in the API description, calls it, and asserts the security headers are present. A new endpoint without the helper must fail this test.
- Endpoints that set cookies or need `Retry-After` return a custom response (`Response<Body>` or Dropshot's header-carrying response types). Verify against current Dropshot docs which response types allow custom headers, and use the simplest one that works.
- `HttpError` is used for errors. Map service errors to status codes in one function (`impl From<ServiceError> for HttpError`) so the mapping is unit tested once. Error messages returned to clients must never contain the password, codes, or card internals.
- For 429, confirm whether `HttpError` can carry a `Retry-After` header in the current Dropshot version. If not, return 429 through the custom response path instead.

**Static frontend**

- `GET /`, `/app.js`, `/app.css` are Dropshot endpoints marked `unpublished = true` so they stay out of the OpenAPI spec. They return `Response<Body>` with the correct `Content-Type` and the security headers helper applied.

**Content type**

- `TypedBody<T>` handles JSON parsing. Check how the current Dropshot version responds to a non-JSON `Content-Type` and write the test in section 14.2 to assert that actual behaviour (rejection with a 4xx). If Dropshot accepts other content types for `TypedBody`, add an explicit `Content-Type: application/json` check in the unlock handler.

**OpenAPI**

- Generate the OpenAPI document from the API trait (`stub_api_description()` or equivalent) and commit it as `openapi/oath-web.json`.
- A test regenerates it and compares with `expectorate`, so API changes are always reviewed as a spec diff.

**Logging**

- Dropshot requires a `slog::Logger`. Build one in `main` that writes Bunyan/JSON to stdout (container friendly) rather than using Dropshot's file or terminal modes.
- Audit events (section 12) are logged through `rqctx.log` so they carry Dropshot's request ID.

## 10. Frontend

- Plain HTML, CSS, and vanilla JS, embedded in the binary with `include_str!`. No build step, no external assets.
- Two views:
  - **Locked:** password field and unlock button. Show remaining backoff time on 429.
  - **Unlocked:** list of credentials grouped by issuer, code in a large monospace font, copy button, per-period countdown bar, lock button.
- Refetch `/api/codes` when the soonest `valid_until` passes. No polling faster than that.
- On `401`, return to the locked view.
- Readable defaults: generous spacing, clear sans-serif for labels, codes split into groups of three digits for readability.

## 11. Configuration

| Variable | Default | Purpose |
|---|---|---|
| `OATH_BIND` | `0.0.0.0:8080` | Listen address inside the container |
| `OATH_READER` | unset | Reader name substring |
| `OATH_SESSION_IDLE_SECS` | `300` | Idle session TTL |
| `OATH_SESSION_MAX_SECS` | `1800` | Absolute session TTL |
| `OATH_GLOBAL_FAIL_LIMIT` | `20` | Failures before global lockout |
| `OATH_TRUSTED_PROXIES` | unset | Comma-separated CIDRs allowed to set `X-Forwarded-For` |
| `OATH_LOG_LEVEL` | `info` | slog level (`trace` to `critical`) |

Invalid config exits non-zero at startup.

## 12. Audit logging

JSON logs to stdout via slog, using `rqctx.log` so each event carries the Dropshot request ID. Events:

- `unlock_success` (client IP, session ID hash)
- `unlock_failure` (client IP, current backoff)
- `global_lockout_engaged`
- `codes_fetched` (client IP, session ID hash, count of credentials)
- `lock`
- `card_error` (error kind, reconnect attempted)

Never log the password, derived key, raw session ID, or codes.

## 13. Container

**Dockerfile** (multi-stage)

- Builder: `rust:1-bookworm`, install `libpcsclite-dev` and `pkg-config`, `cargo build --release --locked`.
- Runtime: `debian:bookworm-slim`, install `libpcsclite1` and `ca-certificates` only. Run as a non-root user. Read-only root filesystem compatible.

**pcscd: host socket (default)**

- Host runs `pcscd`. Mount `/run/pcscd` into the container read-write.
- Watch for a pcsc-lite protocol version mismatch between host and container. If the host is not Debian bookworm, match the runtime base image to the host distro or switch to the option below.

**pcscd: inside the container (fallback)**

- Stop `pcscd` on the host.
- Pass the USB device through (`devices: /dev/bus/usb:/dev/bus/usb`), install `pcscd` in the runtime image, and run it under a tiny init (`tini`) alongside the service.
- Document both options in the README; implement the host socket option first.

**docker-compose.yml**

```yaml
services:
  oath-web:
    image: oath-web:latest
    restart: unless-stopped
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    volumes:
      - /run/pcscd:/run/pcscd
    environment:
      OATH_TRUSTED_PROXIES: "172.16.0.0/12"
    networks: [traefik]
    labels:
      traefik.enable: "true"
      traefik.http.routers.oath.rule: Host(`oath.internal.example`)
      traefik.http.routers.oath.entrypoints: websecure
      traefik.http.routers.oath.tls: "true"
      traefik.http.routers.oath.middlewares: oath-lan
      traefik.http.middlewares.oath-lan.ipallowlist.sourcerange: "192.168.0.0/16,10.0.0.0/8"
      traefik.http.services.oath.loadbalancer.server.port: "8080"
networks:
  traefik:
    external: true
```

Hostname, network name, LAN ranges, and any label constraint (for example the existing `edge` label) are placeholders to be set to match the real Traefik config. Do not publish a host port.

## 14. Test-driven development and testing

### 14.1 TDD workflow (mandatory)

For every unit of behaviour:

1. **Red:** write one failing unit test that describes the behaviour. Run `cargo test` and confirm it fails for the expected reason (not a compile error in unrelated code).
2. **Green:** write the minimum production code to make it pass.
3. **Refactor:** clean up with all tests green. No new behaviour during refactor.
4. Commit. Commit messages use the prefix `test:` for a red commit, `feat:` or `fix:` for green, `refactor:` for refactor. Red and green may be squashed into one commit, but the test must be written first.

Rules:

- Bugs found later are fixed by first adding a failing test that reproduces them.
- Tests assert behaviour through public functions of the module, not private internals.
- No `#[ignore]` without a linked issue and a reason in the attribute.
- No sleeping in tests. Time is driven by the `Clock` test implementation, randomness by the deterministic `ChallengeSource`.
- No test touches real hardware, the network, or the filesystem outside `tempfile::tempdir()`.
- Test names describe behaviour: `validate_rejects_wrong_card_response`, not `test_validate_2`.

### 14.2 Required unit tests per module

The agent writes these tests before the corresponding code. The list is a minimum.

**`oath::tlv`**

- Encodes and parses single-byte lengths.
- Encodes and parses `0x81` and `0x82` multi-byte lengths.
- Parses a sequence of TLVs in order.
- Rejects truncated input (length exceeds remaining bytes).
- Rejects trailing garbage when strict parsing is requested.

**`oath::crypto`**

- PBKDF2 derivation matches a known vector. Use a published PBKDF2-HMAC-SHA1 test vector (RFC 6070, adjusted to 1000 iterations and 16 bytes if computed independently) plus a fixture captured from a real key during manual testing.
- HMAC response correct for SHA1, SHA256, SHA512 using RFC 2202 and RFC 4231 vectors.
- Truncation: 6 and 8 digits, zero-padding (value producing leading zeros), and the RFC 6238 TOTP test vectors reproduced through the truncation path.
- Timestep calculation for 30s and 60s periods at boundaries (`t = 29, 30, 59, 60`).
- Constant-time compare returns false for different lengths without panicking.

**`oath::proto`**

- SELECT APDU bytes match the spec exactly.
- SELECT response parsed with and without password (`0x74` / `0x7B` present or absent).
- VALIDATE APDU contains correct `0x75` and `0x74` tags for a given key, card challenge, and our challenge.
- VALIDATE succeeds when card response matches; fails when it does not.
- CALCULATE ALL APDU encodes the timestep big-endian in 8 bytes.
- CALCULATE ALL response with mixed `0x76`, `0x77`, `0x7C` entries maps to `ok`, `hotp`, `touch_required`.
- SEND REMAINING: `61xx` chains are concatenated; a final non-`9000` status is an error.
- Status words map to typed errors (wrong password, not found, generic failure).
- Name parsing: `issuer:account`, `account` only, `60/issuer:account`, colons inside the account part, empty issuer.

**`card` (mock)**

- The mock implements YKOATH in memory well enough for the protocol tests above to run against it end to end: SELECT, VALIDATE with correct and incorrect keys, CALCULATE ALL, SEND REMAINING chunking.
- Mock can be configured to fail with `RemovedCard` or `ResetCard` on the next N calls.

**`service`**

- Full unlock round trip against the mock returns codes matching expected values for a fixed clock.
- Non-30s credentials are recomputed with the correct period.
- Touch-required and HOTP credentials are returned without codes and without issuing a CALCULATE for them.
- Card removed mid-request: one reconnect, one retry, then a typed "unavailable" error.
- Concurrent requests are serialised (two tasks, mock records call ordering, no interleaving).
- Startup check fails when the applet has no password.

**`session`**

- Created session stores the derived key and returns a 32-byte ID from the `ChallengeSource`.
- Idle expiry after `OATH_SESSION_IDLE_SECS` with no activity.
- Activity extends idle expiry but never past absolute expiry.
- Purge removes expired sessions only.
- Lock removes the session.
- Key material is wrapped in `Zeroizing` (compile-time check via type in the test).

**`ratelimit`**

- First failure sets a 1s backoff; subsequent failures double; cap at 5 minutes.
- Success resets backoff for that IP only.
- Global lockout engages at the configured threshold within the window and releases after 15 minutes.
- Failures outside the 15-minute window do not count toward global lockout.
- `X-Forwarded-For` honoured only when the peer is in the trusted proxy list.

**`config`**

- Defaults applied when env vars are absent.
- Invalid values (non-numeric TTL, bad CIDR, idle > max) are rejected with a clear error.

**`api`** (start a real Dropshot server in-process on `127.0.0.1:0` with mock card, fixed clock, and deterministic RNG; drive it with `reqwest` or Dropshot's `test_util` client)

- `POST /api/unlock` with the correct password returns 204 and a cookie with `HttpOnly`, `Secure`, `SameSite=Strict`.
- Wrong password returns 401; repeated failures return 429 with `Retry-After`.
- Non-JSON content type on POST is rejected with a 4xx (assert the exact status Dropshot or the handler returns, see section 9a).
- `GET /api/codes` without a session returns 401; with a session returns the documented JSON shape.
- Card unavailable returns 503.
- `/healthz` never includes account names.
- Security headers present on all responses; `Cache-Control: no-store` on `/api/*`.
- Logs captured with an in-memory slog drain contain no password, derived key, raw session ID, or code.
- Every endpoint in the API description returns the security headers (guards against a handler skipping the helper).
- `require_session`, `client_ip`, and `acquire_unlock_attempt` have their own unit tests independent of endpoints.
- `ServiceError` to `HttpError` mapping covers every variant.
- Generated OpenAPI matches the committed `openapi/oath-web.json`.
- Unpublished static endpoints do not appear in the OpenAPI document.

### 14.3 Coverage

- Measure with `cargo llvm-cov`.
- Minimum line coverage: 95% for `oath::*`, `session`, `ratelimit`; 85% for the crate overall.
- The real PC/SC implementation (`card::pcsc`) and `main.rs` are excluded from the coverage gate and must stay thin.

### 14.4 Manual checklist with a real key

1. `ykman oath access change` to set a password.
2. Add one 30s TOTP, one 60s TOTP, one touch-required TOTP, one HOTP.
3. Confirm codes match `ykman oath accounts code`.
4. Capture the PBKDF2 derived key for the test password and add it as a fixture to the `oath::crypto` tests.
5. Unplug and replug the key while the page is open.
6. Confirm logs contain no password or codes.

## 15. CI (GitLab)

Stages:

1. `check`: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`
2. `test`: `cargo test --locked`
3. `coverage`: `cargo llvm-cov --locked` with the thresholds from section 14.3. Fails the pipeline if thresholds are not met. Publish the Cobertura report as a GitLab coverage artifact.
4. `build`: build and push the image to the GitLab container registry on the default branch and tags.

Install `libpcsclite-dev` in CI jobs that compile.

## 16. Build order for the agent

Every step follows the TDD loop in section 14.1. "Implement" below always means: write failing tests from section 14.2 first, then the code.

1. Scaffold the crate, `#![forbid(unsafe_code)]`, logging, and a single passing placeholder test so CI runs from the first commit.
2. `clock` and `rng` traits with system and test implementations.
3. `config`.
4. `oath::tlv`.
5. `oath::crypto`.
6. `oath::proto`.
7. `OathCard` trait and the mock card. Re-run the proto tests end to end against the mock.
8. `service`, including startup checks, serialisation, and reconnect.
9. `session`.
10. `ratelimit`.
11. `api`: Dropshot API trait, typed extractor functions, response helper, endpoints, OpenAPI snapshot, log redaction tests.
12. Real PC/SC card implementation (thin, no logic beyond APDU transport and error mapping).
13. Frontend.
14. Dockerfile and compose file.
15. GitLab CI including the coverage gate.
16. README covering setup (setting the OATH password, pcscd options, Traefik labels), threat model, TDD expectations for contributors, and the manual test checklist.

Each step must compile, pass all tests, meet coverage, and be committed before moving on.

## 17. Threat model summary (for the README)

- Protects against: casual access on the LAN, password guessing (via rate limiting), secret extraction (secrets never leave the key).
- Does not protect against: anyone who knows the password and can reach the page, a compromised host or container requesting codes while a session is live, a compromised Traefik instance.
- The second factor becomes "knows the password and is on the LAN" rather than "holds the key". This is an accepted trade-off.

## 18. Definition of done

- All tests pass in CI, clippy clean.
- Every module has unit tests covering the behaviours in section 14.2.
- Coverage thresholds from section 14.3 are met and enforced in CI.
- HTTP API is implemented with Dropshot, and the committed OpenAPI document matches the generated one.
- Git history shows tests written before or alongside the code they drive.
- Container runs read-only as non-root with no added capabilities.
- Codes in the UI match `ykman oath accounts code` for all supported credentials.
- Touch-required and HOTP credentials are listed but not computed.
- Service refuses to start against an applet with no password.
- No secrets or codes appear in logs.