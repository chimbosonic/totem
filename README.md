# oath-web

A small Rust service that reads TOTP codes from a YubiKey's OATH applet over
PC/SC and shows them on an internal web page. Access is gated by the OATH
password set on the key itself.

- Codes are computed on the YubiKey. The secrets never leave it.
- One shared password: the key's OATH password. There are no user accounts.
- Meant for an internal network, behind a reverse proxy that terminates TLS.
  Not for the public internet.

What it does not do: add, rename, or delete credentials (use `ykman` on the
host), compute HOTP codes (that would advance the counter), or compute
touch-required codes (nobody is at the server to touch the key). HOTP and
touch-required credentials are listed without a code.

## How it works

```
Browser (LAN)
   |  HTTPS
Reverse proxy (TLS, LAN allow-list)
   |  HTTP
oath-web (one binary: API and web page)
   |  PC/SC
pcscd
   |  USB CCID
YubiKey (OATH applet)
```

Every request runs SELECT, VALIDATE, and CALCULATE ALL against the key inside
one exclusive PC/SC transaction, so nothing relies on the key staying unlocked
between requests. After you unlock, the key derived from your password is kept
in memory only, for the life of the session. It is never logged or written to
disk, and sessions are lost on restart by design.

## Setup

### 1. Set an OATH password on the key

The service refuses to start against a key without one, because anyone on the
network could otherwise read every code.

```sh
ykman oath access change
ykman oath info          # "Password protection: enabled"
```

### 2. Run pcscd on the host

The service talks to the key through `pcscd`. On Debian or Ubuntu:

```sh
sudo apt install pcscd
sudo systemctl enable --now pcscd.socket
```

On macOS nothing is needed; the system's smart card service is used.

### 3. Run it

From source (needs Rust stable and `libpcsclite-dev` plus `pkg-config` on
Linux):

```sh
cargo run --release
```

Then open `http://127.0.0.1:8080`. Browsers only allow the copy button on
HTTPS or localhost.

## Configuration

All settings are environment variables. Invalid values stop the service at
startup with a message naming the variable.

| Variable | Default | Purpose |
|---|---|---|
| `OATH_BIND` | `0.0.0.0:8080` | Listen address |
| `OATH_READER` | unset | Reader name substring. Unset picks the first reader whose name contains "YubiKey" (case is ignored) |
| `OATH_SESSION_IDLE_SECS` | `300` | Session ends after this long without a request |
| `OATH_SESSION_MAX_SECS` | `1800` | Session ends after this long regardless of activity |
| `OATH_GLOBAL_FAIL_LIMIT` | `20` | Wrong passwords within 15 minutes, from all clients together, that lock unlocking for everyone for 15 minutes |
| `OATH_TRUSTED_PROXIES` | unset | Comma-separated CIDRs (or single IPs) allowed to set `X-Forwarded-For` |
| `OATH_LOG_LEVEL` | `info` | `trace`, `debug`, `info`, `warning`, `error`, or `critical` |

## Container

The image is built from the `Dockerfile` (Debian bookworm slim, runs as uid
10001, about 35 MB). CI publishes it to `ghcr.io/<owner>/oath-web` for pushes
to `main` and for version tags.

```sh
docker build -t oath-web:latest .
```

### pcscd option A: host socket (default)

The host runs `pcscd`; the container uses its socket.

```sh
docker run -d --name oath-web --restart unless-stopped \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -v /run/pcscd:/run/pcscd \
  -e OATH_TRUSTED_PROXIES=172.16.0.0/12 \
  --network <your proxy network> \
  oath-web:latest
```

- Do not publish a port (`-p`). Only the reverse proxy should reach the
  service, over the shared network.
- The root filesystem can be read-only: the service writes nothing and logs
  JSON to stdout.
- The pcsc-lite client in the image (1.9.9, Debian bookworm) must speak the
  same protocol as the host's `pcscd`. If the host is not Debian bookworm and
  the container cannot connect, change both `FROM` lines in the `Dockerfile` to
  match the host distro, or use option B.
- Some hosts (recent Fedora, Ubuntu) build pcsc-lite with polkit, which can
  refuse clients that are not local users, including a container. If the log
  says access was denied, allow the client in polkit or use option B.

### pcscd option B: pcscd inside the container

Not shipped as an image yet. The outline:

1. Stop `pcscd` on the host (`systemctl disable --now pcscd.socket pcscd`),
   since only one process can own the reader.
2. Build a variant image that also installs `pcscd` and `tini`, and starts
   `pcscd` before `oath-web` under `tini`.
3. Pass the USB device through: `--device /dev/bus/usb:/dev/bus/usb`.
   `pcscd` needs write access to it, so the image cannot stay as locked down
   as option A.

### Behind a reverse proxy

- Terminate TLS at the proxy and forward plain HTTP to port 8080.
- Allow only LAN ranges at the proxy.
- Set `OATH_TRUSTED_PROXIES` to the proxy's address range. Without it, every
  request appears to come from the proxy and all clients share one rate limit
  backoff.
- The service sets its security headers (CSP, `nosniff`, `no-referrer`,
  `X-Frame-Options`, and `Cache-Control: no-store` on the API) on every
  response it builds. A few responses are generated inside the HTTP framework
  before the service's code runs: 404 and 405 for unknown paths and 400 for
  malformed request bodies. They carry no secrets, but have no security
  headers. Add the headers at the proxy if you want them everywhere.

## Security

### Threat model

Protects against:

- Casual access on the LAN: nothing is shown without the OATH password.
- Password guessing: the key has no retry counter for its OATH password, so
  the service limits attempts. Each wrong password doubles that client's wait
  (1 s up to 5 minutes), only one attempt per client can run at a time, and
  `OATH_GLOBAL_FAIL_LIMIT` failures within 15 minutes lock unlocking for
  everyone for 15 minutes.
- Secret extraction: TOTP secrets never leave the key.

Does not protect against:

- Anyone who knows the password and can reach the page.
- A compromised host or container requesting codes while a session is live.
- A compromised reverse proxy.

The second factor becomes "knows the password and is on the LAN" rather than
"holds the key". That is an accepted trade-off.

### What is never logged

The password, the derived key, raw session IDs, and codes. Audit events
(`unlock_success`, `unlock_failure`, `global_lockout_engaged`,
`codes_fetched`, `lock`, `card_error`) log the client IP and a short hash of
the session ID. Tests check that none of the secrets appear in the logs.

## API

| Method | Path | Auth | Response |
|---|---|---|---|
| GET | `/`, `/app.js`, `/app.css` | none | Web page |
| POST | `/api/unlock` | none | `204` and session cookie; `401` wrong password; `429` with `Retry-After` |
| POST | `/api/lock` | session | `204` |
| GET | `/api/codes` | session | `200` JSON; `401` no or expired session; `503` key unavailable |
| GET | `/healthz` | none | `200` if the key is reachable and password protected, else `503` |

POST requests must send `Content-Type: application/json`. The session cookie
is `HttpOnly; Secure; SameSite=Strict`. The full schema is in
[`openapi/oath-web.json`](openapi/oath-web.json), generated from the code.

## Development

Test-driven development is mandatory for this project (see `PLAN.md` section
14):

1. Write one failing test for the behaviour and check it fails for the
   expected reason.
2. Write the least code that makes it pass.
3. Refactor with all tests green.
4. Commit: `test:` for a failing test, `feat:` or `fix:` for code that makes
   it pass, `refactor:` for refactoring. A bug is fixed by first adding a test
   that reproduces it.

Tests never sleep (time comes from a test clock), never use real randomness,
and never touch hardware, the network, or files outside the repository. Every
module keeps its unit tests in the same file.

### Running the checks

These are the same commands CI runs (`.github/workflows/ci.yml`):

```sh
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
node --test static/                    # frontend helpers, no npm needed
python3 -m unittest discover -s ci     # the coverage gate's own tests
```

Coverage (needs `cargo install cargo-llvm-cov` and the `llvm-tools-preview`
rustup component). The gate requires 95% of lines in `oath::*`, `session`, and
`ratelimit`, and 85% overall; the PC/SC transport and `main.rs` are excluded.

```sh
cargo llvm-cov --locked --no-report
cargo llvm-cov report --json --summary-only --output-path cov.json \
  --ignore-filename-regex '(card/pcsc\.rs|main\.rs|/tests/)'
python3 ci/coverage_gate.py cov.json
```

After changing the API, regenerate the OpenAPI document and review the diff:

```sh
EXPECTORATE=overwrite cargo test openapi_matches
```

### Hardware tests

`tests/hardware.rs` talks to a real YubiKey and only builds with the
`hardware-tests` feature, so `cargo test` never touches hardware. The key needs
the RFC 6238 test credentials:

```sh
SECRET=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====
ykman oath accounts add -i RFC6238 -a sha256 -d 8 sha256 "$SECRET"
ykman oath accounts add -i RFC6238 -a sha256 -d 8 -P 60 sha256-60s "$SECRET"
ykman oath accounts add -o hotp -i RFC4226 -d 6 sha1 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
```

Put the key's password in a `.env` file (git-ignored, never commit it):

```sh
OATH_HW_PASSWORD=...
# Optional PBKDF2 fixture, see hw_pbkdf2_matches_independent_fixture.
# It unlocks the key just like the password, so it stays in .env too.
OATH_HW_DERIVED_KEY=...
```

Then:

```sh
sh -c 'set -a; . ./.env; set +a; cargo test --features hardware-tests --test hardware -- --test-threads=1'
```

### Manual checklist with a real key

1. Set a password with `ykman oath access change`.
2. Add a 30 s TOTP, a 60 s TOTP, a touch-required TOTP, and an HOTP
   credential (a YubiKey NEO cannot hold touch-required credentials).
3. Confirm the codes on the page match `ykman oath accounts code`.
4. Check the PBKDF2 fixture with the hardware tests.
5. Unplug and replug the key while the page is open: the page should show
   "YubiKey unavailable" and recover on its own once the key is back.
6. Confirm the logs contain no password or codes.

## Project notes

- `PLAN.md`: the original build plan.
- `AGENT.md`: decisions and findings made while building it, including where
  the implementation differs from the plan and why.
