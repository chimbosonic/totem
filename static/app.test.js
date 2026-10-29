"use strict";
// Unit tests for the pure helpers in app.js. Run with: node --test static/
// No dependencies: Node's built-in test runner and assert module only.

const test = require("node:test");
const assert = require("node:assert/strict");
const app = require("./app.js");

test("groupCode splits codes into groups of three from the left", () => {
  assert.equal(app.groupCode("123456"), "123 456");
  assert.equal(app.groupCode("1234567"), "123 456 7");
  assert.equal(app.groupCode("12345678"), "123 456 78");
  assert.equal(app.groupCode("12"), "12");
  assert.equal(app.groupCode(""), "");
});

test("groupByIssuer sorts issuers, puts no issuer last, sorts accounts", () => {
  const input = [
    { issuer: "gitlab", account: "b", status: "ok" },
    { issuer: "", account: "z", status: "hotp" },
    { issuer: "Amazon", account: "x", status: "ok" },
    { issuer: "gitlab", account: "a", status: "touch_required" },
  ];
  const copy = JSON.parse(JSON.stringify(input));
  const groups = app.groupByIssuer(input);
  assert.deepEqual(
    groups.map((g) => [g.issuer, g.credentials.map((c) => c.account)]),
    [
      ["Amazon", ["x"]],
      ["gitlab", ["a", "b"]],
      ["", ["z"]],
    ],
  );
  assert.deepEqual(input, copy, "input is not mutated");
});

test("groupByIssuer of nothing is empty", () => {
  assert.deepEqual(app.groupByIssuer([]), []);
});

test("serverOffsetMs is server time minus client time at receipt", () => {
  assert.equal(app.serverOffsetMs(1000, 1_000_000 + 250), -250);
  assert.equal(app.serverOffsetMs(1000, 999_000), 1000);
});

test("secondsLeft rounds up and never goes negative", () => {
  assert.equal(app.secondsLeft(30_000, 60), 30);
  assert.equal(app.secondsLeft(30_001, 60), 30);
  assert.equal(app.secondsLeft(59_999, 60), 1);
  assert.equal(app.secondsLeft(60_000, 60), 0);
  assert.equal(app.secondsLeft(61_000, 60), 0);
});

test("remainingFraction is the share of the period left, clamped", () => {
  assert.equal(app.remainingFraction(30_000, 30, 60), 1);
  assert.equal(app.remainingFraction(45_000, 30, 60), 0.5);
  assert.equal(app.remainingFraction(60_000, 30, 60), 0);
  assert.equal(app.remainingFraction(90_000, 30, 60), 0);
  assert.equal(app.remainingFraction(0, 30, 60), 1);
});

test("nextRefreshDelayMs waits for the soonest code to expire", () => {
  const credentials = [
    { status: "ok", valid_until: 120 },
    { status: "ok", valid_until: 90 },
    { status: "hotp" },
    { status: "touch_required" },
  ];
  // Server time 60.5s: soonest expiry 90s, so 29.5s plus slack.
  assert.equal(app.nextRefreshDelayMs(credentials, 60_500), 29_500 + app.REFRESH_SLACK_MS);
});

test("nextRefreshDelayMs is null when nothing expires", () => {
  assert.equal(app.nextRefreshDelayMs([{ status: "hotp" }, { status: "touch_required" }], 0), null);
  assert.equal(app.nextRefreshDelayMs([], 0), null);
});

test("nextRefreshDelayMs never schedules faster than the minimum", () => {
  const credentials = [{ status: "ok", valid_until: 60 }];
  assert.equal(app.nextRefreshDelayMs(credentials, 61_000), app.MIN_REFRESH_MS);
});

test("retryAfterSeconds parses the header and falls back to one second", () => {
  assert.equal(app.retryAfterSeconds("4"), 4);
  assert.equal(app.retryAfterSeconds("900"), 900);
  assert.equal(app.retryAfterSeconds(null), 1);
  assert.equal(app.retryAfterSeconds("soon"), 1);
  assert.equal(app.retryAfterSeconds("0"), 1);
  assert.equal(app.retryAfterSeconds("-3"), 1);
});

test("messageForStatus explains each failure without detail", () => {
  assert.equal(app.messageForStatus(401), "Wrong password.");
  assert.equal(app.messageForStatus(503), "YubiKey unavailable. Is it plugged in?");
  assert.equal(app.messageForStatus(400), "Something went wrong (400).");
  assert.equal(app.messageForStatus(500), "Something went wrong (500).");
  assert.match(app.messageForStatus(429, 7), /7 s/);
});

test("statusLabel describes credentials without a code", () => {
  assert.equal(app.statusLabel("touch_required"), "Needs a touch on the key");
  assert.equal(app.statusLabel("hotp"), "HOTP, not computed");
  assert.equal(app.statusLabel("ok"), "");
});

test("loading app.js outside a browser does not touch the DOM", () => {
  assert.equal(typeof document, "undefined");
  assert.equal(typeof app.start, "function");
});

// OpenPGP tab

test("slotLabel names each key slot", () => {
  assert.equal(app.slotLabel("sign"), "Signature key");
  assert.equal(app.slotLabel("decrypt"), "Decryption key");
  assert.equal(app.slotLabel("auth"), "Authentication key");
  assert.equal(app.slotLabel("other"), "other");
});

test("formatFingerprint groups hex digits in fours", () => {
  assert.equal(
    app.formatFingerprint("AC48BC1F029B6188D97E2D807C855DB4466DF0C6"),
    "AC48 BC1F 029B 6188 D97E  2D80 7C85 5DB4 466D F0C6",
  );
  assert.equal(app.formatFingerprint(null), "");
  assert.equal(app.formatFingerprint("ABCD"), "ABCD");
});

test("formatDate shows the UTC day of a Unix time", () => {
  assert.equal(app.formatDate(1_600_000_000), "2020-09-13");
  assert.equal(app.formatDate(null), "");
});

test("keyProblem explains why a slot cannot be used", () => {
  assert.equal(app.keyProblem({ fingerprint: "AB", touch_policy: "off" }), "");
  assert.equal(app.keyProblem({ fingerprint: null, touch_policy: "off" }), "No key in this slot");
  assert.match(app.keyProblem({ fingerprint: "AB", touch_policy: "cached" }), /touch.*cached/i);
});

test("operationSlot maps each operation to its key slot", () => {
  assert.equal(app.operationSlot("clearsign"), "sign");
  assert.equal(app.operationSlot("detached"), "sign");
  assert.equal(app.operationSlot("decrypt-message"), "decrypt");
});

test("publicKeyText lays out RSA and EC keys", () => {
  assert.equal(
    app.publicKeyText({ type: "rsa", modulus: "AQID", exponent: "AQAB" }),
    "modulus (base64): AQID\nexponent (base64): AQAB",
  );
  assert.equal(app.publicKeyText({ type: "ec", point: "BAU=" }), "point (base64): BAU=");
});

test("openpgpErrorMessage turns API errors into page text", () => {
  assert.equal(app.openpgpErrorMessage(401, {}), "Session ended. Unlock again.");
  assert.match(app.openpgpErrorMessage(429, {}, 3), /3 s/);
  assert.equal(
    app.openpgpErrorMessage(404, { error_code: "OpenPgpUnavailable" }),
    "This YubiKey has no OpenPGP applet.",
  );
  assert.equal(app.openpgpErrorMessage(503, {}), "YubiKey unavailable. Is it plugged in?");
  assert.equal(
    app.openpgpErrorMessage(403, { error_code: "WrongPin", message: "wrong PIN, 2 tries left" }),
    "Wrong PIN, 2 tries left.",
  );
  assert.equal(app.openpgpErrorMessage(400, null), "Something went wrong (400).");
});

test("openpgpRequest sends message text exactly as typed", () => {
  assert.deepEqual(app.openpgpRequest("clearsign", "123456", "a b \n c\n", "sha512"), {
    path: "/api/openpgp/sign-message",
    body: { pin: "123456", hash: "sha512", format: "clearsign", text: "a b \n c\n" },
    field: "armored",
  });
  assert.equal(app.openpgpRequest("detached", "p", "x", "sha256").body.format, "detached");
  assert.equal(app.isMessage("clearsign"), true);
  assert.equal(app.isMessage("detached"), true);
  assert.equal(app.isMessage("sign"), false);
});

test("openpgpRequest sends an encrypted message as pasted", () => {
  const message = "-----BEGIN PGP MESSAGE-----\n\nabc\n=xyz\n-----END PGP MESSAGE-----\n";
  assert.deepEqual(app.openpgpRequest("decrypt-message", "123456", message, "sha256"), {
    path: "/api/openpgp/decrypt-message",
    body: { pin: "123456", message },
    field: "session_key",
  });
});

test("looksLikeEncryptedMessage wants the armor header", () => {
  assert.equal(app.looksLikeEncryptedMessage("  -----BEGIN PGP MESSAGE-----\n..."), true);
  assert.equal(app.looksLikeEncryptedMessage("hello"), false);
  assert.equal(app.looksLikeEncryptedMessage("-----BEGIN PGP SIGNATURE-----"), false);
});

test("decryptInstructions gives gpg and sq commands with the session key", () => {
  const steps = app.decryptInstructions("9:ABCD", "seipd_v1");
  assert.deepEqual(
    steps.map((s) => s.tool),
    ["gpg", "Sequoia (sq)"],
  );
  assert.equal(steps[0].command, "gpg --override-session-key 9:ABCD --decrypt message.asc");
  assert.equal(steps[1].command, "sq decrypt --session-key 9:ABCD message.asc");
  assert.equal(steps[1].note, "");
});

test("decryptInstructions explains that sq cannot read gpg's OCB messages", () => {
  const steps = app.decryptInstructions("9:ABCD", "gnupg_ocb");
  assert.equal(steps[0].command, "gpg --override-session-key 9:ABCD --decrypt message.asc");
  assert.equal(steps[1].command, "");
  assert.match(steps[1].note, /cannot read/);
});

test("decryptInstructions refuses anything that is not a session key", () => {
  assert.throws(() => app.decryptInstructions("9:AB; rm -rf /", "seipd_v1"));
  assert.throws(() => app.decryptInstructions("", "seipd_v1"));
});
