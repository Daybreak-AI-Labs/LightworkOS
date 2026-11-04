"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const folder = path.resolve(__dirname, "../../maverick_dashboard");
const markup = fs.readFileSync(path.join(folder, "templates/trust_receipts.html"), "utf8")
  .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "")
  .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, "");
const source = fs.readFileSync(path.join(folder, "static/lightwork-trust-receipts.js"), "utf8");
const HASH = "a".repeat(64);

function statusBody(extra = {}) {
  return Object.assign({ signing_enabled: true, key_custody: "colocated", key_id: "k1", pubkey: "c".repeat(64),
    days: ["2026-01-02", "2026-01-01"], verifier_sha256: "d".repeat(64), trusted_keys: [] }, extra);
}
function rowsBody() {
  return { day: "2026-01-02", total: 3, truncated: false, items: [
    { position: 1, ts: 1767312000, kind: "tool_call", agent: "worker-0", hash: HASH, signed: true, decision: "allowed", tool: "read_file" },
    { position: 2, ts: 1767312001, kind: "governance_denied", agent: "finance-0", hash: "b".repeat(64), signed: true, decision: "denied", tool: "wire_transfer" },
    { position: 3, ts: 1767312002, kind: "tool_call", agent: "worker-0", hash: null, signed: false },
  ] };
}

async function fixture({ intercept = () => undefined, status = statusBody() } = {}) {
  const dom = new JSDOM(markup, { url: "https://lightwork.example/audit/receipts", runScripts: "outside-only" });
  const { window } = dom;
  const ui = { answer: true, confirms: [], calls: [], saved: [] };
  window.mvConfirm = async (message) => { ui.confirms.push(message); return ui.answer; };
  window.mvErrorText = (f, action) => "Could not " + action + ".";
  window.mvCopy = (t) => ui.saved.push(["copy", t]);
  window.mvTimeAbsolute = (ts) => "time:" + ts;
  window.mvDateAbsolute = (day) => "date:" + day;
  window.URL.createObjectURL = () => "blob:x";
  window.URL.revokeObjectURL = () => {};
  window.HTMLAnchorElement.prototype.click = function () { ui.saved.push(["download", this.download]); };
  window.fetch = async (url, opts = {}) => {
    const call = { url: new URL(url, window.location), method: opts.method || "GET", body: opts.body ? JSON.parse(opts.body) : null };
    ui.calls.push(call);
    let reply = await intercept(call);
    const p = call.url.pathname;
    if (reply === undefined) {
      if (p.endsWith("/status")) reply = status;
      else if (p.endsWith("/rows")) reply = rowsBody();
      else if (p.endsWith("/mint")) reply = { kind: "maverick-trust-receipt" };
      else reply = { ok: true };
    }
    const code = reply && reply.__status ? reply.__status : 200;
    return new Response(JSON.stringify(reply), { status: code, headers: { "Content-Type": "application/json" } });
  };
  shell(window);
  window.eval(source);
  async function settle() { for (let i = 0; i < 30; i++) await new Promise((done) => setImmediate(done)); }
  await settle();
  const el = (id) => window.document.getElementById(id);
  return Object.assign(ui, { window, document: window.document, el, settle });
}

test("decisions load with plain labels, a decision-type list and a create button per signed row", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  const table = ui.el("rcp-rows").textContent;
  assert.match(table, /Governance denied/);
  assert.match(table, /Wire transfer/);
  assert.match(table, /recorded before signing was on/);
  assert.doesNotMatch(table, /aaaaaaaa|tool_call|governance_denied/);
  const kinds = [...ui.el("rcp-kind").options].map((o) => o.textContent);
  assert.deepEqual(kinds, ["All decisions", "Governance denied", "Tool call"]);
  assert.equal(ui.el("rcp-custody").textContent, "On this computer");
  // Times and days come from the shared formatters, never the browser default.
  assert.match(table, /time:1767312000/);
  assert.deepEqual([...ui.el("rcp-day").options].map((o) => o.textContent), ["date:2026-01-02 (latest)", "date:2026-01-01"]);
  ui.el("rcp-kind").value = "governance_denied";
  ui.el("rcp-kind").dispatchEvent(new ui.window.Event("change"));
  assert.equal(ui.el("rcp-rows").querySelectorAll("tr").length, 1);
});

test("creating a receipt downloads a file and sends the chosen row, never a typed hash", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  const button = [...ui.el("rcp-rows").querySelectorAll("button")].find((b) => b.textContent === "Create receipt");
  button.click();
  await ui.settle();
  const mint = ui.calls.find((c) => c.url.pathname.endsWith("/mint"));
  assert.equal(mint.method, "POST");
  assert.equal(mint.body.day, "2026-01-02");
  assert.match(mint.body.row_hash, /^[ab]{64}$/);
  assert.ok(ui.saved.some(([kind, name]) => kind === "download" && /^trust-receipt-2026-01-02-\d+\.json$/.test(name)));
  assert.match(ui.el("rcp-mint-msg").textContent, /Receipt saved as/);
});

test("signing off offers the turn-on button, confirmed first", async (t) => {
  const ui = await fixture({ status: statusBody({ signing_enabled: false, key_id: null, pubkey: null, days: [] }) });
  t.after(() => ui.window.close());
  assert.equal(ui.el("rcp-signing-action").hidden, false);
  assert.match(ui.el("rcp-health-detail").textContent, /can't be created/);
  assert.doesNotMatch(ui.document.body.textContent, /\[audit\]|restart\./);
  ui.el("rcp-turn-on-signing").click();
  await ui.settle();
  assert.equal(ui.confirms.length, 1);
  assert.ok(ui.calls.some((c) => c.url.pathname === "/api/v1/compliance/switches/signed_audit" && c.method === "POST"));
});

test("a failed check is a plain sentence and statuses read as words", async (t) => {
  const ui = await fixture({ intercept: (call) => call.url.pathname.endsWith("/verify")
    ? { ok: false, depth: "unverified", reason: "x", claims: [{ name: "row_integrity", status: "FAILS", detail: "sig" }, { name: "commitment", status: "INDETERMINATE", detail: "" }], report: "RAW" }
    : undefined });
  t.after(() => ui.window.close());
  const file = new ui.window.File(['{"kind":"maverick-trust-receipt"}'], "r.json", { type: "application/json" });
  Object.defineProperty(ui.el("rcp-file"), "files", { value: [file] });
  ui.el("rcp-verify-form").dispatchEvent(new ui.window.Event("submit", { cancelable: true }));
  await ui.settle();
  assert.equal(ui.el("rcp-verdict").textContent, "Receipt could not be verified");
  const claims = ui.el("rcp-claims").textContent;
  assert.match(claims, /Failed The decision itself is unchanged/);
  assert.match(claims, /Couldn't check It matches a published checkpoint/);
  assert.doesNotMatch(claims, /FAILS|INDETERMINATE|row_integrity/);
});

test("choosing no file explains what to do", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  ui.el("rcp-verify-form").dispatchEvent(new ui.window.Event("submit", { cancelable: true }));
  await ui.settle();
  assert.equal(ui.el("rcp-verdict-detail").textContent, "Choose the receipt file first.");
});
