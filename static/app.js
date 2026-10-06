"use strict";
// oath-web frontend. Plain JS, no build step, served from the binary.
//
// The pure helpers at the top are unit tested with `node --test static/`.
// `start` wires them to the page and only runs in a browser. Everything that
// came from the card (issuer, account, code) reaches the page through
// `textContent`, never parsed as HTML.

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

    function copyButton(code) {
      const button = element("button", "copy", "Copy");
      button.type = "button";
      button.addEventListener("click", async () => {
        try {
          await win.navigator.clipboard.writeText(code);
          button.textContent = "Copied";
        } catch {
          button.textContent = "Copy failed";
        }
        win.setTimeout(() => {
          button.textContent = "Copy";
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
    start,
  };

  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    document.addEventListener("DOMContentLoaded", () => start(document, window));
  }
})();
