// Run with: node --test packages/maverick-dashboard/tests/js/lightwork_ui_halt.test.js
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function response(body, { ok = true, status = 200 } = {}) {
  return {
    ok,
    status,
    async json() { return body; },
  };
}

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

class ClassList {
  constructor() { this.values = new Set(); }
  toggle(value, enabled) {
    if (enabled) this.values.add(value);
    else this.values.delete(value);
  }
  contains(value) { return this.values.has(value); }
}

class Element {
  constructor(canHalt) {
    this.dataset = { canHalt: canHalt ? "true" : "false" };
    this.classList = new ClassList();
    this.attributes = {};
    this.listeners = {};
    this.textContent = "";
  }
  addEventListener(type, callback) { this.listeners[type] = callback; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  removeAttribute(name) { delete this.attributes[name]; }
  getAttribute(name) { return this.attributes[name]; }
}

function haltSource() {
  const source = fs.readFileSync(
    path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-ui.js"),
    "utf8",
  );
  const start = source.indexOf("    // Halt indicator + arm/clear via /api/v1/halt.");
  const end = source.indexOf("    // Shared goal-create form handler.", start);
  assert.notEqual(start, -1, "halt shell block start must exist");
  assert.notEqual(end, -1, "halt shell block end must exist");
  return source.slice(start, end);
}

function fixture(fetchImpl, { canHalt = true, haltTimeoutMs = 1000, loaded = true, chatHome = false } = {}) {
  const pill = new Element(canHalt);
  pill.dataset.haltTimeoutMs = String(haltTimeoutMs);
  const label = new Element(canHalt);
  const toasts = [];
  const confirms = [];
  const intervals = [];
  let onLoad;
  const chatControls = chatHome ? { disabled: false } : null;
  const chatStopNote = chatHome ? { hidden: true } : null;
  const banner = chatHome ? { hidden: true, querySelector() { return null; } } : null;
  const context = {
    document: {
      readyState: loaded ? "complete" : "interactive",
      body: { classList: new ClassList() },
      querySelector() { return chatControls; },
      getElementById(id) {
        if (id === "halt-pill") return pill;
        if (id === "halt-label") return label;
        if (id === "halt-banner") return banner;
        if (id === "chat-stop-note") return chatStopNote;
        return null;
      },
    },
    addEventListener(type, callback) { if (type === "load") onLoad = callback; },
    fetch: fetchImpl,
    mvToast(message, options) { toasts.push({ message, options }); },
    async mvConfirm(message, options) {
      confirms.push({ message, options });
      return true;
    },
    AbortController,
    setTimeout,
    clearTimeout,
    setInterval(callback) { intervals.push(callback); },
  };
  context.window = context;
  vm.runInNewContext(haltSource(), context, { filename: "lightwork-ui.js" });
  return {
    pill,
    label,
    chatControls,
    chatStopNote,
    banner,
    toasts,
    confirms,
    poll() { return intervals[0](); },
    load() { onLoad(); },
  };
}

test("verified emergency stop pauses the chat composer until a verified resume", async () => {
  let armed = true;
  const ui = fixture(async () => response({ active: armed, scope: "local" }),
    { canHalt: false, chatHome: true });
  await turn();
  assert.equal(ui.banner.hidden, false);
  assert.equal(ui.chatControls.disabled, true);
  assert.equal(ui.chatStopNote.hidden, false);

  armed = false;
  await ui.poll();
  await turn();
  assert.equal(ui.banner.hidden, true);
  assert.equal(ui.chatControls.disabled, false);
  assert.equal(ui.chatStopNote.hidden, true);
});

async function turn() {
  await new Promise((resolve) => setImmediate(resolve));
}

function clickEvent() {
  return { preventDefault() {} };
}

test("a local/shared disagreement is partial and never renders STOPPED", async () => {
  let mutations = 0;
  const ui = fixture(async (_url, options = {}) => {
    if (options.method) mutations += 1;
    return response({ active: true, scope: "cluster", cluster_halt: false });
  });
  await turn();

  assert.match(ui.label.textContent, /Partial stop/);
  assert.match(ui.label.textContent, /some workers are not confirmed stopped/);
  assert.doesNotMatch(ui.label.textContent, /STOPPED/);
  assert.equal(ui.pill.getAttribute("aria-disabled"), "true");
  assert.equal(ui.pill.getAttribute("aria-pressed"), "mixed");
  assert.equal(ui.pill.classList.contains("unavailable"), true);

  await ui.pill.listeners.click(clickEvent());
  assert.equal(mutations, 0);
  assert.match(ui.toasts.at(-1).message, /status is unavailable/);
});

test("204 arm and clear responses stay unknown until a strict GET verifies state", async () => {
  const armRead = deferred();
  const clearRead = deferred();
  const reads = [
    Promise.resolve(response({ active: false, scope: "local" })),
    armRead.promise,
    clearRead.promise,
  ];
  const mutations = [];
  const ui = fixture(async (_url, options = {}) => {
    if (!options.method) return reads.shift();
    mutations.push(options.method);
    return response(null, { status: 204 });
  });
  await turn();
  assert.equal(ui.label.textContent, "Emergency stop");

  const arm = ui.pill.listeners.click(clickEvent());
  await turn();
  assert.equal(ui.label.textContent, "Stop requested — checking work status…");
  assert.equal(ui.pill.getAttribute("aria-disabled"), "true");
  assert.equal(ui.pill.getAttribute("aria-pressed"), "mixed");
  assert.doesNotMatch(ui.label.textContent, /STOPPED/);
  armRead.resolve(response({ active: true, scope: "local" }));
  await arm;
  assert.equal(ui.label.textContent, "STOPPED — click to resume");
  assert.equal(ui.pill.getAttribute("aria-disabled"), "false");

  const clear = ui.pill.listeners.click(clickEvent());
  await turn();
  assert.equal(ui.label.textContent, "Resume requested — checking work status…");
  assert.equal(ui.pill.getAttribute("aria-disabled"), "true");
  assert.equal(ui.pill.getAttribute("aria-pressed"), "mixed");
  clearRead.resolve(response({ active: false, scope: "local" }));
  await clear;
  assert.equal(ui.label.textContent, "Emergency stop");
  assert.equal(ui.pill.getAttribute("aria-disabled"), "false");
  assert.deepEqual(mutations, ["POST", "DELETE"]);
});

test("a post-mutation GET from another scope cannot verify the change", async () => {
  const verification = deferred();
  const reads = [
    Promise.resolve(response({ active: false, scope: "cluster", cluster_halt: false })),
    verification.promise,
  ];
  const ui = fixture(async (_url, options = {}) => {
    if (!options.method) return reads.shift();
    return response(null, { status: 204 });
  });
  await turn();

  const arm = ui.pill.listeners.click(clickEvent());
  await turn();
  verification.resolve(response({ active: true, scope: "local" }));
  await arm;

  assert.match(ui.label.textContent, /settings changed/);
  assert.doesNotMatch(ui.label.textContent, /STOPPED/);
  assert.equal(ui.pill.getAttribute("aria-disabled"), "true");
  assert.equal(ui.pill.getAttribute("aria-pressed"), "mixed");
});

test("failed, non-OK, and invalid polls invalidate a previously known state", async () => {
  const reads = [
    response({ active: false, scope: "local" }),
    response({ detail: "authority unavailable" }, { ok: false, status: 503 }),
    response({ active: false, scope: "local" }),
    response({ active: "false", scope: "local" }),
    new Error("network unavailable"),
  ];
  const ui = fixture(async () => {
    const next = reads.shift();
    if (next instanceof Error) throw next;
    return next;
  });
  await turn();
  assert.equal(ui.label.textContent, "Emergency stop");

  await ui.poll();
  assert.equal(ui.label.textContent, "Stop status unavailable");
  assert.equal(ui.pill.getAttribute("aria-disabled"), "true");

  await ui.poll();
  assert.equal(ui.label.textContent, "Emergency stop");
  await ui.poll();
  assert.equal(ui.label.textContent, "Stop status unavailable");
  assert.equal(ui.pill.getAttribute("aria-disabled"), "true");

  await ui.poll();
  assert.equal(ui.label.textContent, "Stop status unavailable");
  assert.equal(ui.pill.getAttribute("aria-pressed"), "mixed");
});

test("an older overlapping poll cannot overwrite a newer verified result", async () => {
  const older = deferred();
  const newer = deferred();
  const reads = [
    Promise.resolve(response({ active: false, scope: "local" })),
    older.promise,
    newer.promise,
  ];
  const ui = fixture(async () => reads.shift());
  await turn();

  const olderPoll = ui.poll();
  const newerPoll = ui.poll();
  newer.resolve(response({ active: true, scope: "local" }));
  await newerPoll;
  assert.equal(ui.label.textContent, "STOPPED — click to resume");

  older.resolve(response({ active: false, scope: "local" }));
  await olderPoll;
  assert.equal(ui.label.textContent, "STOPPED — click to resume");
  assert.equal(ui.pill.getAttribute("aria-pressed"), "true");
});

test("a stalled status read times out and invalidates known state", async () => {
  let calls = 0;
  const ui = fixture(async () => {
    calls += 1;
    if (calls === 1) return response({ active: false, scope: "local" });
    return new Promise(() => {});
  }, { haltTimeoutMs: 10 });
  await turn();
  assert.equal(ui.label.textContent, "Emergency stop");

  await ui.poll();
  assert.equal(ui.label.textContent, "Stop status unavailable");
  assert.equal(ui.pill.getAttribute("aria-disabled"), "true");
  assert.equal(ui.pill.getAttribute("aria-pressed"), "mixed");
});

test("a refused stop change reads as a plain sentence, never a code or server text", async () => {
  const ui = fixture(async (_url, options = {}) => {
    if (options.method) {
      return { ok: false, status: 403, json: async () => ({ detail: "halt requires principal with admin scope" }) };
    }
    return response({ active: false, scope: "local" });
  });
  await turn();
  await ui.pill.listeners.click(clickEvent());
  await turn();
  const message = ui.toasts.at(-1).message;
  assert.match(message, /Emergency stop change failed|Could not change the emergency stop/);
  assert.doesNotMatch(message, /\b403\b|error \d|principal|admin scope/);
});

test("the label is announced only after the first read, and only when its words change", async () => {
  const first = deferred();
  const reads = [first.promise, response({ active: false, scope: "local" }), response({ active: true, scope: "local" })];
  const ui = fixture(async () => reads.shift());
  // Loading the page: "Checking…" then "Emergency stop" are not announced.
  assert.equal(ui.label.getAttribute("aria-live"), undefined);
  first.resolve(response({ active: false, scope: "local" }));
  await turn();
  await turn();
  assert.equal(ui.label.textContent, "Emergency stop");
  assert.equal(ui.label.getAttribute("aria-live"), "polite");

  let writes = 0;
  let text = ui.label.textContent;
  Object.defineProperty(ui.label, "textContent", {
    get() { return text; },
    set(value) { writes += 1; text = value; },
  });
  // The same state on the next poll leaves the live label untouched.
  await ui.poll();
  assert.equal(writes, 0);
  // A real change is written, and so announced.
  await ui.poll();
  assert.equal(ui.label.textContent, "STOPPED — click to resume");
  assert.equal(writes, 1);
});

test("a page still loading keeps the label quiet until it has loaded", async () => {
  const ui = fixture(async () => response({ active: false, scope: "local" }), { loaded: false });
  await turn();
  await turn();
  // The first read is done, but the localization pass may still rewrite the
  // label when the document finishes loading.
  assert.equal(ui.label.textContent, "Emergency stop");
  assert.equal(ui.label.getAttribute("aria-live"), undefined);
  ui.load();
  await turn();
  assert.equal(ui.label.getAttribute("aria-live"), "polite");
});
