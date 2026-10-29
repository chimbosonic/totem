"use strict";
// totem frontend. Plain JS, no build step, served from the binary.
//
// The pure helpers at the top are unit tested with `node --test static/`.
// `start` wires them to the page and only runs in a browser. Everything that
// came from the card (issuer, account, code, keys, signatures) reaches the
// page through `textContent`, never parsed as HTML. The OpenPGP PIN is read
// from its field once per request, then the field is cleared.

(function () {
  /** Extra wait after the soonest expiry, so the server is in the new period. */
  const REFRESH_SLACK_MS = 500;
  /** Never refetch codes more often than this. */
  const MIN_REFRESH_MS = 1000;
  /** Wait before retrying after the card or server was unavailable. */
  const ERROR_RETRY_MS = 5000;
  /** Countdown redraw interval. */
  const TICK_MS = 250;
  /** Seconds left at which a code is shown as about to expire. */
  const EXPIRING_SECS = 5;

  // Pure helpers

  /** "12345678" -> "123 456 78". */
  function groupCode(code) {
    const groups = code.match(/.{1,3}/g);
    return groups ? groups.join(" ") : "";
  }

  /** Group by issuer, issuers sorted with no issuer last, accounts sorted. */
  function groupByIssuer(credentials) {
    const byIssuer = new Map();
    for (const credential of credentials) {
      if (!byIssuer.has(credential.issuer)) {
        byIssuer.set(credential.issuer, []);
      }
      byIssuer.get(credential.issuer).push(credential);
    }
    const compare = (a, b) => a.localeCompare(b, undefined, { sensitivity: "base" });
    const issuers = [...byIssuer.keys()].sort((a, b) => {
      if (a === "" || b === "") {
        return (a === "") - (b === "");
      }
      return compare(a, b);
    });
    return issuers.map((issuer) => ({
      issuer,
      credentials: [...byIssuer.get(issuer)].sort((a, b) => compare(a.account, b.account)),
    }));
  }

  /** Milliseconds to add to the browser clock to get the server clock. */
  function serverOffsetMs(generatedAt, clientNowMs) {
    return generatedAt * 1000 - clientNowMs;
  }

  function secondsLeft(serverNowMs, validUntil) {
    return Math.max(0, Math.ceil((validUntil * 1000 - serverNowMs) / 1000));
  }

  function remainingFraction(serverNowMs, validFrom, validUntil) {
    const fraction = (validUntil * 1000 - serverNowMs) / ((validUntil - validFrom) * 1000);
    return Math.min(1, Math.max(0, fraction));
  }

  /** Delay until the soonest code expires, or null if no code expires. */
  function nextRefreshDelayMs(credentials, serverNowMs) {
    const expiries = credentials.filter((c) => c.status === "ok").map((c) => c.valid_until);
    if (expiries.length === 0) {
      return null;
    }
    const delay = Math.min(...expiries) * 1000 - serverNowMs + REFRESH_SLACK_MS;
    return Math.max(MIN_REFRESH_MS, delay);
  }

  function retryAfterSeconds(header) {
    const seconds = Number.parseInt(header, 10);
    return Number.isFinite(seconds) && seconds >= 1 ? seconds : 1;
  }

  function messageForStatus(status, retryAfter) {
    switch (status) {
      case 401:
        return "Wrong password.";
      case 429:
        return `Too many attempts. Try again in ${retryAfter} s.`;
      case 503:
        return "YubiKey unavailable. Is it plugged in?";
      default:
        return `Something went wrong (${status}).`;
    }
  }

  function statusLabel(status) {
    switch (status) {
      case "touch_required":
        return "Needs a touch on the key";
      case "hotp":
        return "HOTP, not computed";
      default:
        return "";
    }
  }

  // OpenPGP helpers

  const SLOT_LABELS = {
    sign: "Signature key",
    decrypt: "Decryption key",
    auth: "Authentication key",
  };

  const OPERATIONS = {
    "decrypt-message": {
      slot: "decrypt",
      path: "/api/openpgp/decrypt-message",
      field: "session_key",
    },
    clearsign: { slot: "sign", path: "/api/openpgp/sign-message", field: "armored" },
    detached: { slot: "sign", path: "/api/openpgp/sign-message", field: "armored" },
  };

  function slotLabel(slot) {
    return SLOT_LABELS[slot] || slot;
  }

  function operationSlot(operation) {
    return OPERATIONS[operation].slot;
  }

  /** 40 hex digits as ykman shows them: groups of four, a gap in the middle. */
  function formatFingerprint(hex) {
    if (!hex) {
      return "";
    }
    const groups = hex.match(/.{1,4}/g);
    if (groups.length !== 10) {
      return groups.join(" ");
    }
    return `${groups.slice(0, 5).join(" ")}  ${groups.slice(5).join(" ")}`;
  }

  /** Unix time as a UTC date, "2020-09-13". */
  function formatDate(unixTime) {
    return unixTime ? new Date(unixTime * 1000).toISOString().slice(0, 10) : "";
  }

  /** Why a key cannot be used from here, or "" if it can. */
  function keyProblem(key) {
    if (!key.fingerprint) {
      return "No key in this slot";
    }
    if (key.touch_policy !== "off") {
      return `Needs a touch (policy ${key.touch_policy}), so it cannot be used from here`;
    }
    return "";
  }

  /** Whether an operation signs text as an OpenPGP message. */
  function isMessage(operation) {
    return operation === "clearsign" || operation === "detached";
  }

  function looksLikeEncryptedMessage(text) {
    return text.includes("-----BEGIN PGP MESSAGE-----");
  }

  /** Commands that decrypt the message with its session key, per tool.
   * The session key is checked first, so nothing else can end up in a
   * command someone copies into a shell. */
  function decryptInstructions(sessionKey, dataFormat) {
    if (!/^[0-9]{1,3}:[0-9A-F]+$/.test(sessionKey)) {
      throw new Error("not a session key");
    }
    const sq =
      dataFormat === "gnupg_ocb"
        ? {
            command: "",
            note:
              "Sequoia cannot read this message: gpg encrypted it with its own OCB format. " +
              "Use the gpg command.",
          }
        : { command: `sq decrypt --session-key ${sessionKey} message.asc`, note: "" };
    return [
      {
        tool: "gpg",
        command: `gpg --override-session-key ${sessionKey} --decrypt message.asc`,
        note: "",
      },
      { tool: "Sequoia (sq)", ...sq },
    ];
  }

  /** Path, JSON body, and result field for an OpenPGP operation. The
   * input is sent exactly as typed or pasted. */
  function openpgpRequest(operation, pin, input, hash) {
    const { path, field } = OPERATIONS[operation];
    if (isMessage(operation)) {
      return { path, body: { pin, hash, format: operation, text: input }, field };
    }
    return { path, body: { pin, message: input }, field };
  }

  function publicKeyText(key) {
    if (key.type === "rsa") {
      return `modulus (base64): ${key.modulus}\nexponent (base64): ${key.exponent}`;
    }
    return `point (base64): ${key.point}`;
  }

  /** Page text for an OpenPGP API error. The server's own message is used
   * for errors it explains (wrong PIN, retry floor, touch, bad input). */
  function openpgpErrorMessage(status, body, retryAfter) {
    const code = body && body.error_code;
    if (status === 401) {
      return "Session ended. Unlock again.";
    }
    if (status === 429) {
      return `Too many PIN attempts. Try again in ${retryAfter} s.`;
    }
    if (code === "OpenPgpUnavailable") {
      return "This YubiKey has no OpenPGP applet.";
    }
    if (status === 503) {
      return messageForStatus(503);
    }
    if (body && typeof body.message === "string" && body.message !== "") {
      const text = body.message.charAt(0).toUpperCase() + body.message.slice(1);
      return text.endsWith(".") ? text : `${text}.`;
    }
    return messageForStatus(status);
  }

  // Browser wiring

  function start(doc, win) {
    // Literal ids, so a Rust test can check each one exists in index.html.
    const view = {
      locked: doc.getElementById("locked-view"),
      unlocked: doc.getElementById("unlocked-view"),
      form: doc.getElementById("unlock-form"),
      password: doc.getElementById("password"),
      unlockButton: doc.getElementById("unlock-button"),
      unlockMessage: doc.getElementById("unlock-message"),
      lockButton: doc.getElementById("lock-button"),
      codesMessage: doc.getElementById("codes-message"),
      codes: doc.getElementById("codes"),
      stateDot: doc.getElementById("state-dot"),
      stateText: doc.getElementById("state-text"),
      tabCodes: doc.getElementById("tab-codes"),
      tabOpenpgp: doc.getElementById("tab-openpgp"),
      codesPanel: doc.getElementById("codes-panel"),
      openpgpPanel: doc.getElementById("openpgp-panel"),
      openpgpMessage: doc.getElementById("openpgp-message"),
      openpgpRefresh: doc.getElementById("openpgp-refresh"),
      openpgpCard: doc.getElementById("openpgp-card"),
      openpgpFacts: doc.getElementById("openpgp-facts"),
      openpgpKeys: doc.getElementById("openpgp-keys"),
      openpgpUse: doc.getElementById("openpgp-use"),
      openpgpForm: doc.getElementById("openpgp-form"),
      openpgpOperation: doc.getElementById("openpgp-operation"),
      openpgpSignOptions: doc.getElementById("openpgp-sign-options"),
      openpgpHash: doc.getElementById("openpgp-hash"),
      openpgpInputLabel: doc.getElementById("openpgp-input-label"),
      openpgpInput: doc.getElementById("openpgp-input"),
      openpgpPin: doc.getElementById("openpgp-pin"),
      openpgpSubmit: doc.getElementById("openpgp-submit"),
      openpgpUseMessage: doc.getElementById("openpgp-use-message"),
      openpgpResult: doc.getElementById("openpgp-result"),
      openpgpResultLabel: doc.getElementById("openpgp-result-label"),
      openpgpOutput: doc.getElementById("openpgp-output"),
      openpgpResultActions: doc.getElementById("openpgp-result-actions"),
      openpgpInstructions: doc.getElementById("openpgp-instructions"),
      openpgpDecryptHelp: doc.getElementById("openpgp-decrypt-help"),
    };
    const state = {
      offsetMs: 0,
      credentials: [],
      bars: [],
      unlocked: false,
      refreshTimer: null,
      retryTimer: null,
      tickTimer: null,
      blockTimer: null,
      blockedUntil: 0,
      // Bumped on lock, so a codes response that was in flight cannot
      // unlock the page again.
      generation: 0,
      tab: "codes",
      openpgpKeys: [],
      openpgpBusy: false,
      openpgpBlockedUntil: 0,
      openpgpNotice: "",
    };
    const serverNow = () => Date.now() + state.offsetMs;

    function clearTimers() {
      for (const name of ["refreshTimer", "retryTimer", "tickTimer"]) {
        win.clearTimeout(state[name]);
        win.clearInterval(state[name]);
        state[name] = null;
      }
    }

    function showLocked(message) {
      state.generation += 1;
      clearTimers();
      state.unlocked = false;
      state.credentials = [];
      state.bars = [];
      view.codes.replaceChildren();
      view.codesMessage.textContent = "";
      clearOpenpgp();
      selectTab("codes");
      view.unlocked.hidden = true;
      view.locked.hidden = false;
      view.unlockMessage.textContent = message || "";
      view.stateDot.classList.add("locked");
      view.stateText.textContent = "Locked";
      view.password.focus();
    }

    function showUnlocked() {
      state.unlocked = true;
      view.locked.hidden = true;
      view.unlocked.hidden = false;
      view.unlockMessage.textContent = "";
      view.stateDot.classList.remove("locked");
      view.stateText.textContent = "Unlocked";
    }

    function element(tag, className, text) {
      const node = doc.createElement(tag);
      if (className) {
        node.className = className;
      }
      if (text !== undefined) {
        node.textContent = text;
      }
      return node;
    }

    function copyButton(code, label = "Copy") {
      const button = element("button", "copy", label);
      button.type = "button";
      button.addEventListener("click", async () => {
        try {
          await win.navigator.clipboard.writeText(code);
          button.textContent = "Copied";
        } catch {
          button.textContent = "Copy failed";
        }
        win.setTimeout(() => {
          button.textContent = label;
        }, 1500);
      });
      return button;
    }

    function render() {
      state.bars = [];
      const panels = groupByIssuer(state.credentials).map((group) => {
        const panel = element("section", "panel");
        panel.append(element("div", "section-title", group.issuer || "No issuer"));
        const list = element("div", "credentials");
        for (const credential of group.credentials) {
          const row = element("div", "cred");
          row.append(element("div", "account k", credential.account));
          if (credential.status === "ok") {
            row.append(element("span", "code", groupCode(credential.code)));
            row.append(copyButton(credential.code));
            const bar = element("div", "bar");
            const track = element("div", "bar-track");
            const fill = element("div", "bar-fill");
            const left = element("span", "bar-left");
            track.append(fill);
            bar.append(track, left);
            row.append(bar);
            state.bars.push({ row, fill, left, credential });
          } else {
            row.append(element("span", "pill", statusLabel(credential.status)));
          }
          list.append(row);
        }
        panel.append(list);
        return panel;
      });
      view.codes.replaceChildren(...panels);
      tick();
    }

    function tick() {
      const now = serverNow();
      for (const { row, fill, left, credential } of state.bars) {
        const fraction = remainingFraction(now, credential.valid_from, credential.valid_until);
        const secs = secondsLeft(now, credential.valid_until);
        // CSSOM changes are allowed by the CSP; style attributes are not.
        fill.style.transform = `scaleX(${fraction})`;
        left.textContent = `${secs} s`;
        row.classList.toggle("expiring", secs <= EXPIRING_SECS);
      }
    }

    function scheduleRefresh() {
      win.clearTimeout(state.refreshTimer);
      const delay = nextRefreshDelayMs(state.credentials, serverNow());
      state.refreshTimer = delay === null ? null : win.setTimeout(loadCodes, delay);
    }

    function retryLater(message) {
      view.codesMessage.textContent = message;
      win.clearTimeout(state.retryTimer);
      state.retryTimer = win.setTimeout(loadCodes, ERROR_RETRY_MS);
    }

    async function loadCodes() {
      const generation = state.generation;
      const stale = () => generation !== state.generation;
      let response;
      try {
        response = await win.fetch("/api/codes", { cache: "no-store", credentials: "same-origin" });
      } catch {
        if (stale()) {
          return;
        }
        if (state.unlocked) {
          retryLater("Cannot reach the server. Retrying.");
        } else {
          showLocked("Cannot reach the server.");
        }
        return;
      }
      if (stale()) {
        return;
      }
      if (response.status === 401) {
        showLocked(state.unlocked ? "Session ended. Unlock again." : "");
        return;
      }
      showUnlocked();
      if (!response.ok) {
        retryLater(`${messageForStatus(response.status)} Retrying.`);
        return;
      }
      const data = await response.json();
      if (stale()) {
        return;
      }
      state.offsetMs = serverOffsetMs(data.generated_at, Date.now());
      state.credentials = data.credentials;
      view.codesMessage.textContent = "";
      render();
      scheduleRefresh();
      if (state.tickTimer === null) {
        state.tickTimer = win.setInterval(tick, TICK_MS);
      }
    }

    function blockUnlock(seconds) {
      state.blockedUntil = Date.now() + seconds * 1000;
      view.unlockButton.disabled = true;
      const update = () => {
        const left = Math.ceil((state.blockedUntil - Date.now()) / 1000);
        if (left <= 0) {
          win.clearInterval(state.blockTimer);
          view.unlockButton.disabled = false;
          view.unlockMessage.textContent = "";
          return;
        }
        view.unlockMessage.textContent = messageForStatus(429, left);
      };
      win.clearInterval(state.blockTimer);
      update();
      state.blockTimer = win.setInterval(update, 1000);
    }

    async function unlock(event) {
      event.preventDefault();
      if (Date.now() < state.blockedUntil) {
        return;
      }
      const password = view.password.value;
      view.password.value = "";
      view.unlockButton.disabled = true;
      view.unlockMessage.textContent = "";
      let response;
      try {
        response = await win.fetch("/api/unlock", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password }),
          credentials: "same-origin",
        });
      } catch {
        view.unlockButton.disabled = false;
        view.unlockMessage.textContent = "Cannot reach the server.";
        return;
      }
      if (response.status === 204) {
        view.unlockButton.disabled = false;
        await loadCodes();
        return;
      }
      if (response.status === 429) {
        blockUnlock(retryAfterSeconds(response.headers.get("Retry-After")));
      } else {
        view.unlockButton.disabled = false;
        view.unlockMessage.textContent = messageForStatus(response.status);
      }
      view.password.focus();
    }

    async function lock() {
      // Lock the page now, not when the server answers.
      showLocked("");
      try {
        await win.fetch("/api/lock", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
        });
      } catch {
        // The session may still be alive on the server until it times out.
        view.unlockMessage.textContent = "Cannot reach the server. The session may stay open until it times out.";
      }
    }

    // Tabs

    function selectTab(tab) {
      state.tab = tab;
      const codes = tab === "codes";
      view.tabCodes.setAttribute("aria-selected", String(codes));
      view.tabOpenpgp.setAttribute("aria-selected", String(!codes));
      view.tabCodes.tabIndex = codes ? 0 : -1;
      view.tabOpenpgp.tabIndex = codes ? -1 : 0;
      view.codesPanel.hidden = !codes;
      view.openpgpPanel.hidden = codes;
      if (!codes) {
        loadOpenpgp();
      }
    }

    function tabKeys(event) {
      if (event.key === "ArrowRight" || event.key === "ArrowLeft") {
        const next = state.tab === "codes" ? "openpgp" : "codes";
        selectTab(next);
        (next === "codes" ? view.tabCodes : view.tabOpenpgp).focus();
      }
    }

    // OpenPGP

    function clearOpenpgp() {
      state.openpgpKeys = [];
      view.openpgpPin.value = "";
      view.openpgpInput.value = "";
      view.openpgpMessage.textContent = "";
      view.openpgpUseMessage.textContent = "";
      view.openpgpFacts.replaceChildren();
      view.openpgpKeys.replaceChildren();
      view.openpgpCard.hidden = true;
      view.openpgpUse.hidden = true;
      hideResult();
    }

    function hideResult() {
      view.openpgpOutput.textContent = "";
      view.openpgpResultActions.replaceChildren();
      view.openpgpInstructions.replaceChildren();
      view.openpgpInstructions.hidden = true;
      view.openpgpResult.hidden = true;
    }

    function showInstructions(sessionKey, dataFormat) {
      const nodes = [element("div", "k", "Decrypt it on your own machine")];
      for (const step of decryptInstructions(sessionKey, dataFormat)) {
        nodes.push(element("div", "section-title", step.tool));
        if (step.command) {
          nodes.push(element("pre", "output", step.command));
          const actions = element("div", "actions");
          actions.append(copyButton(step.command, "Copy command"));
          nodes.push(actions);
        }
        if (step.note) {
          nodes.push(element("p", "note", step.note));
        }
      }
      view.openpgpInstructions.replaceChildren(...nodes);
      view.openpgpInstructions.hidden = false;
    }

    function showResult(label, text) {
      view.openpgpResultLabel.textContent = label;
      view.openpgpOutput.textContent = text;
      view.openpgpResultActions.replaceChildren(copyButton(text));
      view.openpgpResult.hidden = false;
    }

    function fact(name, value) {
      const wrap = element("div", "fact");
      wrap.append(element("dt", "k", name), element("dd", "", value));
      return wrap;
    }

    async function errorBody(response) {
      try {
        return await response.json();
      } catch {
        return null;
      }
    }

    function renderOpenpgp(status) {
      view.openpgpFacts.replaceChildren(
        fact("Version", status.version),
        fact("Serial", status.serial),
        fact("PIN tries left", String(status.pin_retries.pin)),
        fact("Admin PIN tries left", String(status.pin_retries.admin_pin)),
        fact(
          "Signatures made",
          status.signature_counter === null ? "unknown" : String(status.signature_counter),
        ),
        fact("PIN KDF", status.kdf_enabled ? "on" : "off"),
      );
      view.openpgpCard.hidden = false;
      state.openpgpKeys = status.keys;
      view.openpgpKeys.replaceChildren(...status.keys.map(renderKey));
      view.openpgpUse.hidden = false;
      updateForm();
    }

    function renderKey(key) {
      const panel = element("section", "panel");
      panel.append(element("div", "section-title", slotLabel(key.slot)));
      const facts = element("dl", "facts");
      if (key.fingerprint) {
        facts.append(
          fact("Algorithm", key.algorithm),
          fact("Fingerprint", formatFingerprint(key.fingerprint)),
          fact("Created", formatDate(key.created) || "unknown"),
          fact("Touch", key.touch_policy),
        );
      }
      panel.append(facts);
      const problem = keyProblem(key);
      if (problem) {
        panel.append(element("span", "pill warn", problem));
      }
      if (key.fingerprint) {
        const output = element("pre", "output");
        output.hidden = true;
        const actions = element("div", "actions");
        const show = element("button", "", "Public key");
        show.type = "button";
        show.addEventListener("click", () => showPublicKey(key.slot, output, actions, show));
        actions.append(show);
        panel.append(actions, output);
      }
      return panel;
    }

    async function showPublicKey(slot, output, actions, button) {
      button.disabled = true;
      let response;
      try {
        response = await win.fetch(`/api/openpgp/keys/${slot}`, {
          cache: "no-store",
          credentials: "same-origin",
        });
      } catch {
        view.openpgpMessage.textContent = "Cannot reach the server.";
        button.disabled = false;
        return;
      }
      if (!response.ok) {
        handleOpenpgpError(response, await errorBody(response), view.openpgpMessage);
        button.disabled = false;
        return;
      }
      const key = await response.json();
      const text = publicKeyText(key);
      output.textContent = text;
      output.hidden = false;
      button.remove();
      actions.append(copyButton(text, "Copy public key"));
    }

    function handleOpenpgpError(response, body, target) {
      if (response.status === 401) {
        showLocked("Session ended. Unlock again.");
        return;
      }
      const retry = retryAfterSeconds(response.headers.get("Retry-After"));
      target.textContent = openpgpErrorMessage(response.status, body, retry);
      if (response.status === 429) {
        state.openpgpBlockedUntil = Date.now() + retry * 1000;
        updateForm();
        win.setTimeout(updateForm, retry * 1000);
      }
    }

    async function loadOpenpgp() {
      const generation = state.generation;
      view.openpgpRefresh.disabled = true;
      let response;
      try {
        response = await win.fetch("/api/openpgp", { cache: "no-store", credentials: "same-origin" });
      } catch {
        view.openpgpRefresh.disabled = false;
        view.openpgpMessage.textContent = "Cannot reach the server.";
        return;
      }
      view.openpgpRefresh.disabled = false;
      if (generation !== state.generation) {
        return;
      }
      if (!response.ok) {
        view.openpgpCard.hidden = true;
        view.openpgpUse.hidden = true;
        view.openpgpKeys.replaceChildren();
        handleOpenpgpError(response, await errorBody(response), view.openpgpMessage);
        return;
      }
      const status = await response.json();
      if (generation !== state.generation) {
        return;
      }
      view.openpgpMessage.textContent = "";
      renderOpenpgp(status);
    }

    /** Show the inputs the chosen operation needs and whether its key works. */
    function updateForm() {
      const operation = view.openpgpOperation.value;
      view.openpgpSignOptions.hidden = !isMessage(operation);
      view.openpgpDecryptHelp.hidden = operation !== "decrypt-message";
      view.openpgpInputLabel.textContent = {
        "decrypt-message": "Encrypted message (the whole -----BEGIN PGP MESSAGE----- block)",
        clearsign: "Text to sign",
        detached: "Text to sign (exactly these bytes)",
      }[operation];
      const key = state.openpgpKeys.find((k) => k.slot === operationSlot(operation));
      const problem = key ? keyProblem(key) : "";
      const blocked = Date.now() < state.openpgpBlockedUntil;
      view.openpgpSubmit.disabled = state.openpgpBusy || problem !== "" || blocked;
      // Only replace the notice this function set, never a request's result.
      const notice = problem ? `${slotLabel(operationSlot(operation))}: ${problem}.` : "";
      if (notice) {
        view.openpgpUseMessage.textContent = notice;
      } else if (view.openpgpUseMessage.textContent === state.openpgpNotice) {
        view.openpgpUseMessage.textContent = "";
      }
      state.openpgpNotice = notice;
    }

    async function runOpenpgp(event) {
      event.preventDefault();
      const operation = view.openpgpOperation.value;
      const pin = view.openpgpPin.value;
      view.openpgpPin.value = "";
      hideResult();
      const input = view.openpgpInput.value;
      const hash = view.openpgpHash.value;
      if (operation === "decrypt-message" && !looksLikeEncryptedMessage(input)) {
        view.openpgpUseMessage.textContent =
          "Paste the whole message, starting with -----BEGIN PGP MESSAGE-----.";
        return;
      }
      const request = openpgpRequest(operation, pin, input, hash);
      const generation = state.generation;
      state.openpgpBusy = true;
      updateForm();
      view.openpgpUseMessage.textContent = "Working on the YubiKey...";
      let response;
      try {
        response = await win.fetch(request.path, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(request.body),
          credentials: "same-origin",
        });
      } catch {
        state.openpgpBusy = false;
        updateForm();
        view.openpgpUseMessage.textContent = "Cannot reach the server.";
        return;
      }
      state.openpgpBusy = false;
      if (generation !== state.generation) {
        return;
      }
      const body = await errorBody(response);
      if (!response.ok) {
        handleOpenpgpError(response, body, view.openpgpUseMessage);
        updateForm();
        if (response.status !== 401) {
          loadOpenpgp();
        }
        return;
      }
      view.openpgpUseMessage.textContent = "";
      updateForm();
      if (operation === "decrypt-message") {
        showResult("Session key (opens this message only)", body.session_key);
        showInstructions(body.session_key, body.data_format);
        loadOpenpgp();
        return;
      }
      const label = {
        clearsign: "Clearsigned message",
        detached: "Detached signature (save as a .asc file next to the text)",
      }[operation];
      showResult(label, body[request.field]);
      // The PIN counter and signature count changed.
      loadOpenpgp();
    }

    view.tabCodes.addEventListener("click", () => selectTab("codes"));
    view.tabOpenpgp.addEventListener("click", () => selectTab("openpgp"));
    view.tabCodes.addEventListener("keydown", tabKeys);
    view.tabOpenpgp.addEventListener("keydown", tabKeys);
    view.openpgpRefresh.addEventListener("click", loadOpenpgp);
    view.openpgpOperation.addEventListener("change", () => {
      hideResult();
      updateForm();
    });
    view.openpgpForm.addEventListener("submit", runOpenpgp);

    view.form.addEventListener("submit", unlock);
    view.lockButton.addEventListener("click", lock);
    doc.addEventListener("visibilitychange", () => {
      // Timers are throttled in background tabs; fetch fresh codes on return.
      if (!doc.hidden && state.unlocked) {
        loadCodes();
      }
    });
    loadCodes();
  }

  const api = {
    REFRESH_SLACK_MS,
    MIN_REFRESH_MS,
    groupCode,
    groupByIssuer,
    serverOffsetMs,
    secondsLeft,
    remainingFraction,
    nextRefreshDelayMs,
    retryAfterSeconds,
    messageForStatus,
    statusLabel,
    slotLabel,
    operationSlot,
    isMessage,
    looksLikeEncryptedMessage,
    decryptInstructions,
    formatFingerprint,
    formatDate,
    keyProblem,
    openpgpRequest,
    publicKeyText,
    openpgpErrorMessage,
    start,
  };

  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    document.addEventListener("DOMContentLoaded", () => start(document, window));
  }
})();
