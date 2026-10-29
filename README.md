# totem

A web front end for YubiKey features, run on the host the key is plugged into.
Today it covers the OATH applet (TOTP codes) and the OpenPGP applet
(OpenPGP signed messages and decrypting OpenPGP messages with keys already
on the key, so it can act as a small network HSM), on the web page and over
the API.

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

### How the security-relevant code is checked

totem implements no cryptographic primitive: hashing, HMAC, PBKDF2, and
constant-time comparison come from RustCrypto (`sha1`, `sha2`, `hmac`,
`pbkdf2`, `subtle`), randomness from `getrandom`, and every private key
operation happens on the YubiKey. What it does implement is protocol code
around those, and each piece is checked against an implementation it did
not write:

| Code | Checked against |
|---|---|
| OATH unlock and codes (PBKDF2 parameters, HMAC challenge and response, truncation) | the YKOATH spec, HMAC vectors from RFC 2202 and 4231, code vectors from RFC 4226 and 6238, a PBKDF2 value from Python `hashlib`, and a real key |
| OpenPGP PIN KDF (iterated and salted S2K) | values produced by GnuPG for the same salt, count, and passphrase |
| RSA DigestInfo prefixes | the RustCrypto `rsa` crate's own prefixes |
| OpenPGP signed messages (packets, armor, cleartext rules) | `gpg --verify` on 108 RSA, Ed25519, and P-256 combinations; pinned fixtures are re-verified on every test run with `rsa`, `ed25519-dalek`, and `p256` |
| Session key recovery from encrypted messages (packets, RSA, Curve25519 key derivation; key unwrap is RustCrypto `aes-kw`) | gpg's own `--show-session-key` for messages made by gpg and by Sequoia; decrypting with the result in gpg and sq |
| Parsers of card responses, chaining, encrypted messages | `cargo fuzz` (arbitrary bytes must give an error, never a panic or a hang) |

Values from the card are treated as untrusted: for example a KDF iteration
count above the largest OpenPGP can encode (65011712) is refused, so a bad
card cannot make each PIN attempt hash gigabytes. Dependencies are checked
with `cargo deny` and `cargo audit` in CI. The crate forbids `unsafe` code.

### What is never logged

The password, the derived key, raw session IDs, and codes. For OpenPGP, the
PIN and the data: texts, messages, signatures, and session keys. Audit
events (`unlock_success`, `unlock_failure`, `global_lockout_engaged`,
`codes_fetched`, `lock`, `card_error`, `openpgp_sign_message`,
`openpgp_decrypt_message`, `openpgp_pin_failure`,
`openpgp_pin_lockout_engaged`, `openpgp_pin_floor_reached`) log the client IP and a short hash of the
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
| POST | `/api/openpgp/sign-message` | session + PIN | `200` armored OpenPGP clearsigned message or detached signature |
| POST | `/api/openpgp/decrypt-message` | session + PIN | `200` session key of an armored encrypted message, for gpg or sq |
| GET | `/healthz` | none | `200` if the key is reachable and password protected, else `503` |

POST requests must send `Content-Type: application/json`. The session cookie
is `HttpOnly; Secure; SameSite=Strict`. The full schema is in
[`openapi/totem.json`](openapi/totem.json), generated from the code by
Dropshot. The running service also serves it at `/openapi.json`, and renders
it at `/docs` (linked from the main page).

### OpenPGP

The web page has an **OpenPGP** tab next to the codes. It shows the card
(version, serial, PIN tries left, signature count, KDF), each key with its
fingerprint and touch policy, and its public key on request. A form
decrypts OpenPGP messages (it recovers the session key and shows the gpg
and sq commands that use it), and makes OpenPGP clearsigned messages and
armored detached signatures. The PIN field is cleared after every request,
and keys that cannot be used (empty slot, touch policy) are disabled with
the reason shown.

The OpenPGP endpoints use keys already on the key. They need an unlocked
session (the OATH password) and, for signing and decrypting, the OpenPGP
user PIN in the request body. The PIN is used for that one request and
never stored. The card's lower-level operations (signing a bare digest,
raw decryption, INTERNAL AUTHENTICATE) are not exposed.

```sh
# After POST /api/unlock, with the session cookie in $COOKIE:
curl -s -b "$COOKIE" https://totem.lan/api/openpgp
curl -s -b "$COOKIE" -H 'content-type: application/json' \
  -d "{\"pin\":\"$PIN\",\"hash\":\"sha256\",\"format\":\"clearsign\",\"text\":\"hello\"}" \
  https://totem.lan/api/openpgp/sign-message
```

- Sign message takes text, a hash, and a format, and returns ASCII armor
  that `gpg --verify` accepts: `clearsign` gives a
  `-----BEGIN PGP SIGNED MESSAGE-----` block, `detached` gives a
  `-----BEGIN PGP SIGNATURE-----` block over the exact bytes of the text
  (save it as `file.asc` next to `file` and run `gpg --verify file.asc
  file`). The service builds a version 4 signature packet and its armor
  (`src/openpgp/message.rs`) around one signature from the card; the issuer
  fingerprint is the card's. RSA, ECDSA, and EdDSA keys work. Before
  clearsigning, trailing spaces and tabs are removed from each line and
  line endings are shown as LF: gpg ignores trailing whitespace when it
  verifies a cleartext message and RFC 9580 tools do not, so trimming it
  first keeps both happy. The verifier needs your public key in its keyring.
- Decrypt message takes a whole armored message
  (`-----BEGIN PGP MESSAGE-----`) encrypted to the card's decryption key,
  RSA or Curve25519, and returns its session key as `cipher:HEX`. The
  server does not decrypt the message; decrypt it on your own machine,
  where no private key is needed:

  ```sh
  gpg --override-session-key 9:HEX --decrypt message.asc
  sq decrypt --session-key 9:HEX message.asc
  ```

  The OpenPGP tab explains this and shows both commands with the key
  filled in. Sequoia cannot read messages gpg 2.5 encrypts with its own
  OCB format (`data_format` is `gnupg_ocb`); use gpg for those. The session
  key opens that one message only; treat it like the message. For
  Curve25519 keys the key derivation parameters are not stored on the
  card, so the common ones are tried (gpg's default, SHA-256 and AES-128,
  first); the key unwrap's integrity check rejects the wrong ones.

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

Supply chain (needs `cargo install --locked cargo-deny cargo-audit`).
`deny.toml` allows crates.io only, permissive licenses only (one MPL-2.0
exception), and denies every advisory except the ones listed there with a
reason; `.cargo/audit.toml` lists the same exceptions:

```sh
cargo deny --locked check
cargo audit --deny warnings
```

Fuzzing (needs `cargo install --locked cargo-fuzz` and a nightly toolchain).
The targets in `fuzz/` feed arbitrary bytes to every parser of card
responses, to response and command chaining, to OpenPGP message
building, and to encrypted messages. CI runs each for 60 seconds; run them longer before a release:

```sh
cargo +nightly fuzz list
cargo +nightly fuzz run openpgp_responses -- -max_total_time=600
```

Coverage (needs `cargo install cargo-llvm-cov` and the `llvm-tools-preview`
rustup component). The gate requires 95% of lines in `oath::*`, `openpgp::*`,
`session`, and `ratelimit`, and 85% overall; the PC/SC transport and
`main.rs` are excluded.

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
7. With an OpenPGP key on the card: sign through the API or the OpenPGP
   tab and verify the signature with `openssl` against the public key the
   page shows (the card returns a raw PKCS #1 v1.5 signature, not an
   OpenPGP signature packet, so `gpg --verify` does not apply); check
   `/docs` renders.

## Project notes

- `PLAN.md`: the original build plan.
- `AGENT.md`: decisions and findings made while building it, including where
  the implementation differs from the plan and why.
