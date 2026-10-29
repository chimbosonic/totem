# totem

A web front end for YubiKey features, run on the host the key is plugged into.
Today it covers the OATH applet (TOTP codes on a web page) and, over the
API, the OpenPGP applet (sign, decrypt, and authenticate with keys already on
the key, so it can act as a small network HSM).

The current release is a small Rust service that reads TOTP codes from a
YubiKey's OATH applet over PC/SC and shows them on an internal web page.
Access is gated by the OATH password set on the key itself.

- Codes are computed on the YubiKey. The secrets never leave it.
- One shared password: the key's OATH password. There are no user accounts.
- Meant for an internal network, behind a reverse proxy that terminates TLS.
  Not for the public internet.

What it does not do: add, rename, or delete credentials (use `ykman` on the
host), compute HOTP codes (that would advance the counter), or compute
touch-required codes (nobody is at the server to touch the key). HOTP and
touch-required credentials are listed without a code. For OpenPGP it never
generates, imports, or exports keys, and never changes a PIN (use `gpg
--card-edit` or `ykman openpgp` on the host).

## How it works

```
Browser (LAN)
   |  HTTPS
Reverse proxy (TLS, LAN allow-list)
   |  HTTP
totem (one binary: API and web page)
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
| `OATH_OPENPGP_PIN_RETRY_FLOOR` | `1` | `0`, `1`, or `2`. The OpenPGP PIN is never sent when the key has this many tries left or fewer (see [OpenPGP](#openpgp)) |
| `OATH_OPENPGP_GLOBAL_FAIL_LIMIT` | `10` | Wrong OpenPGP PINs within 15 minutes, from all clients together, that stop PIN use for everyone for 15 minutes |

## Container

The image is built from the `Dockerfile` (Debian trixie slim, runs as uid
10001, about 35 MB). CI publishes it to `ghcr.io/<owner>/totem` for pushes
to `main` and for version tags.

```sh
docker build -t totem:latest .
```

### pcscd option A: host socket (default)

The host runs `pcscd`; the container uses its socket.

```sh
docker run -d --name totem --restart unless-stopped \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -v /run/pcscd:/run/pcscd \
  -e OATH_TRUSTED_PROXIES=172.16.0.0/12 \
  --network <your proxy network> \
  totem:latest
```

- Do not publish a port (`-p`). Only the reverse proxy should reach the
  service, over the shared network.
- The root filesystem can be read-only: the service writes nothing and logs
  JSON to stdout.
- The pcsc-lite client in the image (2.x from Debian trixie, protocol 4:5)
  must speak the same protocol as the host's `pcscd`. Hosts with pcsc-lite 2.x
  (Debian trixie, current Ubuntu, Fedora, openSUSE Tumbleweed) match. On a host
  with pcsc-lite 1.x (Debian bookworm and older), the container cannot connect
  and the host's `pcscd` logs "Communication protocol mismatch"; change both
  `FROM` lines in the `Dockerfile` to match the host distro, or use option B.
- Some hosts (recent Fedora, Ubuntu) build pcsc-lite with polkit, which can
  refuse clients that are not local users, including a container. If the log
  says access was denied, allow the client in polkit or use option B.

### pcscd option B: pcscd inside the container

Not shipped as an image yet. The outline:

1. Stop `pcscd` on the host (`systemctl disable --now pcscd.socket pcscd`),
   since only one process can own the reader.
2. Build a variant image that also installs `pcscd` and `tini`, and starts
   `pcscd` before `totem` under `tini`.
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
- Secret extraction: TOTP secrets and OpenPGP private keys never leave the
  key.
- Blocking the OpenPGP PIN through the API: see [OpenPGP](#openpgp).

Does not protect against:

- Anyone who knows the password and can reach the page. For OpenPGP, anyone
  who knows both the OATH password and the OpenPGP PIN can sign and decrypt
  with the key for as long as they can reach the service.
- A compromised host or container requesting codes while a session is live.
- A compromised reverse proxy.

The second factor becomes "knows the password and is on the LAN" rather than
"holds the key". That is an accepted trade-off.

### What is never logged

The password, the derived key, raw session IDs, and codes. For OpenPGP, the
PIN and the data: digests, ciphertexts, plaintexts, and signatures. Audit
events (`unlock_success`, `unlock_failure`, `global_lockout_engaged`,
`codes_fetched`, `lock`, `card_error`, `openpgp_sign`, `openpgp_decrypt`,
`openpgp_authenticate`, `openpgp_pin_failure`, `openpgp_pin_lockout_engaged`,
`openpgp_pin_floor_reached`) log the client IP and a short hash of the
session ID. OpenPGP use events also log the key slot and the first 4 bytes of
the SHA-256 of the input, so requests can be matched up without logging the
input. Tests check that none of the secrets appear in the logs.

## API

| Method | Path | Auth | Response |
|---|---|---|---|
| GET | `/`, `/app.js`, `/app.css` | none | Web page |
| GET | `/docs`, `/docs.js` | none | API docs page |
| GET | `/openapi.json` | none | The OpenAPI document |
| POST | `/api/unlock` | none | `204` and session cookie; `401` wrong password; `429` with `Retry-After` |
| POST | `/api/lock` | session | `204` |
| GET | `/api/codes` | session | `200` JSON; `401` no or expired session; `503` key unavailable |
| GET | `/api/openpgp` | session | `200` keys, PIN retry counters, signature count; `404` no OpenPGP applet |
| GET | `/api/openpgp/keys/{slot}` | session | `200` public key of `sign`, `decrypt`, or `auth`; `404` empty slot |
| POST | `/api/openpgp/sign` | session + PIN | `200` signature over a digest |
| POST | `/api/openpgp/decrypt` | session + PIN | `200` decrypted session key |
| POST | `/api/openpgp/authenticate` | session + PIN | `200` signature with the authentication key |
| GET | `/healthz` | none | `200` if the key is reachable and password protected, else `503` |

POST requests must send `Content-Type: application/json`. The session cookie
is `HttpOnly; Secure; SameSite=Strict`. The full schema is in
[`openapi/totem.json`](openapi/totem.json), generated from the code by
Dropshot. The running service also serves it at `/openapi.json`, and renders
it at `/docs` (linked from the main page).

### OpenPGP

The OpenPGP endpoints use keys already on the key. They need an unlocked
session (the OATH password) and, for sign, decrypt, and authenticate, the
OpenPGP user PIN in the request body. The PIN is used for that one request
and never stored. Binary values are base64.

```sh
# After POST /api/unlock, with the session cookie in $COOKIE:
curl -s -b "$COOKIE" https://totem.lan/api/openpgp
digest=$(printf 'hello' | openssl dgst -sha256 -binary | base64)
curl -s -b "$COOKIE" -H 'content-type: application/json' \
  -d "{\"pin\":\"$PIN\",\"hash\":\"sha256\",\"digest\":\"$digest\"}" \
  https://totem.lan/api/openpgp/sign
```

- Sign takes a digest and the hash that made it (`sha256`, `sha384`, or
  `sha512`). For RSA keys the service wraps it in a PKCS #1 DigestInfo; for
  ECDSA and EdDSA keys it is signed as is.
- Decrypt takes the RSA ciphertext for RSA keys, or the sender's ephemeral
  public point for ECDH keys, and returns the session key.
- Authenticate signs `data` as is with the authentication key. For RSA keys,
  send a DigestInfo.

The key blocks its PIN after 3 wrong tries. To make sure the API can never
do that, the service reads the retry counter before every PIN check and
refuses with `423 PinRetryFloor`, without sending the PIN, once the key has
`OATH_OPENPGP_PIN_RETRY_FLOOR` tries left or fewer. With the default of 1,
the last try is always kept for a person at the host, who resets the counter
by entering the right PIN there (for example with `gpg --card-status` and a
signature, or `gpg --card-edit`). Requests that could not succeed (bad
base64, a digest of the wrong length, an empty slot, a PIN shorter than 6
characters) are refused before the PIN is sent, so they never cost a try.

Keys with a touch policy (`ykman openpgp info` shows anything but "Off")
cannot be used: nobody is at the server to touch the key. The service reads
each key's policy, shows it as `touch_policy` in `GET /api/openpgp`, and
refuses to use such a key with `409 TouchRequired` before sending the PIN.
Turn touch off at the host with `ykman openpgp keys set-touch <key> off`
(not possible for the `fixed` and `cached_fixed` policies, short of
replacing the key).

Cards set up with a PIN KDF (`gpg --card-edit`, then `kdf-setup`; shown as
"KDF enabled" in `ykman openpgp info` and `kdf_enabled` in
`GET /api/openpgp`) expect the PIN hashed rather than as typed. The service
reads the card's KDF settings and sends the iterated and salted S2K hash,
as gpg does, so the PIN in the request stays the plain PIN. A KDF it does
not know is refused with `501 KdfUnsupported`, again without sending the
PIN.

Wrong PINs answer `403 WrongPin` with the tries left, and also count against
a rate limit like the one for unlocking: each wrong PIN doubles that client's
wait, and `OATH_OPENPGP_GLOBAL_FAIL_LIMIT` failures within 15 minutes stop PIN
use for everyone for 15 minutes. That limit is separate from the unlock one.

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
node --test "static/*.test.js"         # frontend helpers, no npm needed
python3 -m unittest discover -s ci      # the coverage gate's own tests
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

For the OpenPGP hardware tests, also put the OpenPGP user PIN in `.env`.
They read the status and public keys, sign with any key in the signature
slot, and check RSA signatures against the card's public key. They never
send a wrong PIN, stop if the key has 2 tries or fewer left, and skip
signing when the signature key has a touch policy. Stop gpg's `scdaemon`
first (`gpgconf --kill scdaemon`): by default it holds the key exclusively
and every test fails with "other connections outstanding". Adding
`pcsc-shared` to `~/.gnupg/scdaemon.conf` lets them share it.

```sh
OATH_HW_OPENPGP_PIN=...
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
7. With an OpenPGP key on the card: sign through the API and verify with
   `gpg --verify` or `openssl`; check `/docs` renders.

## Project notes

- `PLAN.md`: the original build plan.
- `AGENT.md`: decisions and findings made while building it, including where
  the implementation differs from the plan and why.
