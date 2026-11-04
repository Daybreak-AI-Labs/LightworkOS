"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell: loadShell} = require('./_shell');

const folder = path.resolve(__dirname, "../../maverick_dashboard");
const markup = fs.readFileSync(path.join(folder, "templates/privacy_drop_management.html"), "utf8")
  .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "")
  .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, "");
const helpers = fs.readFileSync(path.join(folder, "static/lightwork-record-workflows.js"), "utf8");
const source = fs.readFileSync(path.join(folder, "static/lightwork-privacy-drop-management.js"), "utf8");
const TEMPLATE = "550e8400-e29b-41d4-a716-446655440000";
const FUTURE = Math.floor(Date.now() / 1000) + 30 * 86400;

function overview(extra = {}) {
  return Object.assign({
    requests: [
      { drop_id: 41001, request_type: "DataDeletion", template_id: TEMPLATE, language: "en", valid_until: FUTURE, version: 1, state: "active", usable: true, request: null, outcomes: [] },
      { drop_id: 41002, request_type: "OptOut", template_id: TEMPLATE, language: "es", valid_until: FUTURE, version: 1, state: "active", usable: true,
        request: { status: "PENDING", revision: 1, created_at: 1, updated_at: 1 }, outcomes: [{ status: "OPTED_OUT", version: 1, state: "active" }] },
    ],
    brokers: [{ broker_ref: "acme-data", version: 1, state: "active", valid_until: FUTURE, registration_sha256: "b".repeat(64) }],
    waiting: [
      { proposal_id: "p-mine", kind: "enroll_broker", revision: 1, created_at: 1, proposed_by_you: true, summary: { broker_ref: "other-broker" } },
      { proposal_id: "p-other", kind: "import_record", revision: 1, created_at: 1, proposed_by_you: false, summary: { drop_id: 41003, request_type: "DataDeletion" } },
    ],
  }, extra);
}

async function fixture({ intercept = () => undefined, roles = { canOperate: "true", canAudit: "true", canAdmin: "true" }, data = overview() } = {}) {
  const dom = new JSDOM(markup, { url: "https://lightwork.example/privacy/drop", runScripts: "outside-only" });
  const { window } = dom;
  const document = window.document;
  const shell = document.getElementById("drop-workbench");
  Object.assign(shell.dataset, roles, { apiBase: "/api/v1/privacy/drop" });
  const ui = { answer: true, confirms: [], formValues: null, calls: [] };
  window.mvConfirm = async (message) => { ui.confirms.push(message); return ui.answer; };
  window.mvForm = async () => ui.formValues;
  window.HTMLElement.prototype.scrollIntoView = () => {};
  window.TextDecoder = TextDecoder;
  window.fetch = async (url, opts = {}) => {
    const call = { url: new URL(url, window.location), method: opts.method || "GET", body: opts.body };
    ui.calls.push(call);
    let reply = await intercept(call);
    const p = call.url.pathname;
    if (reply === undefined) {
      if (p.endsWith("/status")) reply = { enabled: true, ready: true };
      else if (p.endsWith("/authority/overview")) reply = data;
      else if (p.endsWith("/compliance/fingerprint")) reply = { sha256: "f".repeat(64), size: 3 };
      else reply = { ok: true };
    }
    const status = reply && reply.__status ? reply.__status : 200;
    return new Response(JSON.stringify(reply), { status, headers: { "Content-Type": "application/json" } });
  };
  loadShell(window);
  window.eval(helpers);
  window.eval(source);
  async function settle() { for (let i = 0; i < 30; i++) await new Promise((done) => setImmediate(done)); }
  await settle();
  const el = (id) => document.getElementById(id);
  const rowButton = (container, rowText, label) => {
    const row = [...el(container).querySelectorAll("tr")].find((tr) => tr.textContent.includes(rowText));
    return row && [...row.querySelectorAll("button")].find((b) => b.textContent === label);
  };
  return Object.assign(ui, { window, document, el, settle, rowButton });
}

test("requests load on arrival with plain labels and one button per next step", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  const text = ui.el("drop-requests").textContent;
  assert.match(text, /41001/);
  assert.match(text, /Delete their data/);
  assert.match(text, /Spanish/);
  assert.match(text, /Not started/);
  assert.match(text, /Result approved, ready to close/);
  assert.ok(ui.rowButton("drop-requests", "41001", "Start"));
  assert.equal(ui.rowButton("drop-requests", "41001", "Close request"), undefined);
  assert.ok(ui.rowButton("drop-requests", "41002", "Close request"));
  assert.doesNotMatch(ui.document.body.textContent, /DataDeletion|OPTED_OUT|sha256/);
});

test("starting a request is confirmed and uses the record's own details", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  ui.answer = false;
  ui.rowButton("drop-requests", "41001", "Start").click(); await ui.settle();
  assert.equal(ui.calls.filter((c) => c.method === "POST").length, 0);
  ui.answer = true;
  ui.rowButton("drop-requests", "41001", "Start").click(); await ui.settle();
  const post = ui.calls.find((c) => c.method === "POST" && c.url.pathname === "/api/v1/privacy/drop/41001/request");
  const body = JSON.parse(post.body);
  assert.equal(body.request_type, "DataDeletion");
  assert.equal(body.template_id, TEMPLATE);
  assert.equal(body.language, "en");
  assert.equal(body.expected_revision, 0);
  assert.ok(body.idempotency_key);
});

test("closing uses the approved result and the request's revision", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  ui.rowButton("drop-requests", "41002", "Close request").click(); await ui.settle();
  assert.match(ui.confirms.at(-1), /Opted out/);
  const put = ui.calls.find((c) => c.method === "PUT");
  assert.equal(put.url.pathname, "/api/v1/privacy/drop/41002");
  const body = JSON.parse(put.body);
  assert.equal(body.status, "OPTED_OUT");
  assert.equal(body.expected_revision, 1);
});

test("administrators cannot approve their own change; others approve with one click after confirming", async (t) => {
  // Approval first reads the complete current change and shows it for review.
  const review = { proposal: { proposal_id: "p-other", kind: "import_record", revision: 1, retained_until: 9 },
    proposed_by_you: false, contents: { drop_id: 41003, request_type: "DataDeletion" } };
  const ui = await fixture({ intercept: (c) => (c.method === "GET" && c.url.pathname.endsWith("/proposals/p-other/review") ? review : undefined) });
  t.after(() => ui.window.close());
  assert.equal(ui.rowButton("drop-waiting", "Other broker", "Approve"), undefined);
  assert.match(ui.el("drop-waiting").textContent, /You/);
  ui.rowButton("drop-waiting", "41003", "Approve").click(); await ui.settle();
  assert.equal(ui.confirms.length, 1);
  assert.match(ui.confirms[0], /DROP request: 41003/);
  const post = ui.calls.find((c) => c.url.pathname.endsWith("/proposals/p-other/approve"));
  assert.equal(JSON.parse(post.body).expected_revision, 1);
});

test("adding a DROP request fingerprints files and takes the broker registration from the chosen broker", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  ui.el("drop-import").click(); await ui.settle();
  assert.equal(ui.el("drop-import-panel").hidden, false);
  const brokerOptions = [...ui.el("drop-import-broker").options].map((o) => o.textContent);
  assert.ok(brokerOptions.some((label) => /Acme data/i.test(label)));
  ui.el("drop-import-number").value = "41009";
  ui.el("drop-import-broker").value = "acme-data";
  ui.el("drop-import-template").value = "not-a-template";
  const file = new ui.window.File(["abc"], "record.json");
  for (const id of ["drop-import-match", "drop-import-evidence"]) {
    Object.defineProperty(ui.el(id), "files", { value: [file] });
  }
  const submit = () => ui.el("drop-import-form").dispatchEvent(new ui.window.Event("submit", { bubbles: true, cancelable: true }));
  submit(); await ui.settle();
  assert.match(ui.el("drop-status").textContent, /exactly as DROP shows it/);
  assert.equal(ui.calls.filter((c) => c.url.pathname.endsWith("/records/proposals")).length, 0);
  ui.el("drop-import-template").value = TEMPLATE;
  submit(); await ui.settle();
  assert.equal(ui.calls.filter((c) => c.url.pathname.endsWith("/compliance/fingerprint")).length, 2);
  const post = ui.calls.find((c) => c.url.pathname.endsWith("/records/proposals"));
  const body = JSON.parse(post.body);
  assert.equal(body.action, "import_record");
  assert.equal(body.drop_id, 41009);
  assert.equal(body.broker_registration_sha256, "b".repeat(64));
  assert.equal(body.subject_binding_sha256, "f".repeat(64));
  assert.equal(body.expected_version, 0);
  assert.ok(body.valid_until > Date.now() / 1000);
  assert.match(ui.el("drop-status").textContent, /Sent for approval/);
});

test("failures read as plain sentences without status codes", async (t) => {
  const ui = await fixture({ intercept: (c) => (c.url.pathname.endsWith("/authority/overview") ? { __status: 503, detail: "DROP authority composition is unavailable" } : undefined) });
  t.after(() => ui.window.close());
  const text = ui.el("drop-status").textContent;
  assert.match(text, /Could not load the DROP requests/);
  assert.doesNotMatch(text, /503|composition|authority/);
  assert.doesNotMatch(ui.el("drop-requests").textContent, /Loading/);
  assert.match(ui.el("drop-requests").textContent, /Nothing to show right now/);
});

test("a turned-off feature says so instead of loading forever", async (t) => {
  const ui = await fixture({ intercept: (c) => (c.url.pathname.endsWith("/status") ? { enabled: false, ready: false } : undefined) });
  t.after(() => ui.window.close());
  assert.equal(ui.calls.filter((c) => c.url.pathname.endsWith("/authority/overview")).length, 0);
  for (const id of ["drop-requests", "drop-waiting", "drop-brokers"]) {
    assert.doesNotMatch(ui.el(id).textContent, /Loading/);
    assert.match(ui.el(id).textContent, /turned off/);
  }
  assert.match(ui.el("drop-readiness").textContent, /turned off/);
});

test("people without list access can look a request up by its number", async (t) => {
  const ui = await fixture({
    roles: { canOperate: "false", canAudit: "false", canAdmin: "false" },
    intercept: (c) => (/\/drop\/77$/.test(c.url.pathname) ? { status: "DELETED", updated_at: 1 } : undefined),
  });
  t.after(() => ui.window.close());
  assert.equal(ui.calls.filter((c) => c.url.pathname.endsWith("/authority/overview")).length, 0);
  ui.formValues = { number: "77" };
  [...ui.el("drop-requests").querySelectorAll("button")].find((b) => b.textContent === "Look up a request").click();
  await ui.settle();
  assert.match(ui.el("drop-status").textContent, /DROP request 77: Data deleted/);
});
