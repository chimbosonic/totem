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
