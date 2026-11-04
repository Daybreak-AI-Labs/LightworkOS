// Run with: node --test packages/maverick-dashboard/tests/js/third_party_contracts_client.test.js
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell: loadShell} = require('./_shell');

const folder = path.resolve(__dirname, "../../maverick_dashboard");
const markup = fs.readFileSync(path.join(folder, "templates/third_party_contracts.html"), "utf8")
  .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "").replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, "")
  .replace(/{% if not contracts_[a-z_]+ %}[\s\S]*?{% endif %}/g, "")
  .replace(/{%-?[\s\S]*?-?%}/g, "").replace(/{{[\s\S]*?}}/g, "");
const helpers = fs.readFileSync(path.join(folder, "static/lightwork-record-workflows.js"), "utf8");
const source = fs.readFileSync(path.join(folder, "static/lightwork-third-party-contracts.js"), "utf8");

function record(extra = {}) {
  return Object.assign({ record_id: "contract-1", record_kind: "contract", vendor_id: "vendor-x", title_ref: "Acme-master-agreement", owner_ref: "user:ann.at.example.com",
    status: "active", revision: 4, lifecycle: { agreement_type: "master_services", agreement_ref: "doc.Legal-drive", renewal_mode: "manual", expires_at: 1893456000, notice_period_days: 30 },
    field_schema: [], field_values: {}, formulas: [], computed_values: {} }, extra);
}

async function fixture({ ready = true, records = [record()], intercept = () => undefined, roles = { canOperate: "true", canAudit: "true", canAdmin: "true" }, moduleEnabled = "true" } = {}) {
  const dom = new JSDOM(markup, { url: "https://lightwork.example/third-party/contracts", runScripts: "outside-only" });
  const { window } = dom;
  const shell = window.document.getElementById("third-party-contracts-shell");
  Object.assign(shell.dataset, roles, { apiBase: "/api/v1/third-party/contracts", moduleEnabled });
  const ui = { answer: true, confirms: [], formValues: [], calls: [] };
  window.mvConfirm = async (m) => { ui.confirms.push(m); return ui.answer; };
  window.mvForm = async () => ui.formValues.shift() || null;
  window.mvErrorText = (f, a) => "Could not " + a + ".";
  window.HTMLElement.prototype.scrollIntoView = () => {};
  window.TextDecoder = TextDecoder;
  window.fetch = async (url, opts = {}) => {
    const call = { url: new URL(url, window.location), method: opts.method || "GET", body: opts.body ? JSON.parse(opts.body) : null, opts };
    ui.calls.push(call);
    let reply = await intercept(call);
    const p = call.url.pathname;
    if (reply === undefined) {
      if (p.endsWith("/contracts/status")) reply = { enabled: true, configured: true, ready };
      else if (p === "/api/v1/third-party/intelligence/vendors") reply = { items: [{ vendor_id: "vendor-x", display_label: "Acme Corp", revision: 7, state: "active" }] };
      else if (p === "/api/v1/choices/people") reply = { people: [{ value: "user:ann@example.com", label: "ann@example.com" }] };
      else if (p === "/api/v1/third-party/contracts" && call.method === "GET") reply = { items: records };
      else reply = { ok: true };
    }
    const status = reply.__status || 200;
    return new Response(JSON.stringify(reply), { status, headers: { "Content-Type": "application/json" } });
  };
  loadShell(window);
  window.eval(helpers);
  window.eval(source);
  async function settle() { for (let i = 0; i < 40; i++) await new Promise((r) => setImmediate(r)); }
  await settle();
  const el = (id) => window.document.getElementById(id);
  const rowButton = (text, label) => {
    const row = [...el("tpc-record-list").querySelectorAll("tr")].find((tr) => tr.textContent.includes(text));
    return row && [...row.querySelectorAll("button")].find((b) => b.textContent === label);
  };
  return Object.assign(ui, { window, document: window.document, el, settle, rowButton });
}

test("records load on arrival with names, not references, and a button per next step", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  const text = ui.el("tpc-record-list").textContent;
  assert.match(text, /Acme master agreement/);
  assert.match(text, /Acme Corp/);
  assert.match(text, /ann@example.com/);
  for (const label of ["View details", "Edit", "Change status", "Archive"]) assert.ok(ui.rowButton("Acme", label), label);
  assert.equal(ui.rowButton("Acme", "Delete permanently"), undefined);
  assert.doesNotMatch(ui.document.body.textContent, /vendor-x|contract-1|master_services/);
  assert.equal(ui.el("tpc-operations").disabled, false);
  const list = ui.calls.find((c) => c.url.pathname === "/api/v1/third-party/contracts");
  assert.equal(list.opts.credentials, "same-origin");
  assert.equal(list.opts.redirect, "error");
});

test("the page stays locked with a plain sentence when contracts aren't ready", async (t) => {
  const ui = await fixture({ ready: false }); t.after(() => ui.window.close());
  assert.equal(ui.el("tpc-operations").disabled, true);
  assert.match(ui.el("tpc-readiness-detail").textContent, /aren't set up/);
});

test("adding a contract uses the chosen vendor's current version and a generated request key", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  ui.el("tpc-new").click();
  const form = ui.el("tpc-create-form");
  form.elements.namedItem("title").value = "Beta support contract";
  form.elements.namedItem("agreement").value = "Signed PDF in legal drive";
  form.elements.namedItem("expires_at").value = "2027-01-31";
  ui.el("tpc-add-field").click();
  const row = form.querySelector(".tpc-custom-field");
  row.querySelector('[name="cf_name"]').value = "Annual fee";
  row.querySelector('[name="cf_type"]').value = "decimal";
  row.querySelector('[name="cf_value"]').value = "1200.5";
  form.dispatchEvent(new ui.window.Event("submit", { cancelable: true }));
  await ui.settle();
  const post = ui.calls.find((c) => c.method === "POST" && c.url.pathname.endsWith("/contracts"));
  assert.equal(post.body.vendor_id, "vendor-x");
  assert.equal(post.body.vendor_revision, 7);
  assert.equal(post.body.title_ref, "Beta-support-contract");
  assert.equal(post.body.owner_ref, "user:ann.at.example.com");
  assert.equal(post.body.lifecycle.agreement_ref, "doc.Signed-PDF-in-legal-drive");
  assert.equal(post.body.lifecycle.expires_at, Date.UTC(2027, 0, 31) / 1000);
  assert.deepEqual(post.body.field_values, { "field.annual-fee": 1200.5 });
  assert.equal(post.body.field_schema[0].field_type, "decimal");
  assert.ok(post.body.idempotency_key);
});

test("status changes offer only allowed next steps and carry the row version", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  ui.formValues.push({ status: "suspended" });
  ui.rowButton("Acme", "Change status").click();
  await ui.settle();
  const patch = ui.calls.find((c) => c.method === "PATCH");
  assert.deepEqual({ status: patch.body.status, rev: patch.body.expected_revision }, { status: "suspended", rev: 4 });
});

test("archiving and deleting are confirmed first", async (t) => {
  const ui = await fixture({ records: [record(), record({ record_id: "contract-2", title_ref: "Old-agreement", status: "archived", revision: 9 })] });
  t.after(() => ui.window.close());
  ui.answer = false;
  ui.rowButton("Acme", "Archive").click();
  await ui.settle();
  assert.equal(ui.calls.some((c) => c.url.pathname.endsWith("/archive")), false);
  ui.answer = true;
  ui.rowButton("Old agreement", "Delete permanently").click();
  await ui.settle();
  const del = ui.calls.find((c) => c.method === "DELETE");
  assert.equal(del.body.expected_revision, 9);
  assert.equal(ui.confirms.length, 2);
});

test("a failed save is a plain sentence", async (t) => {
  const ui = await fixture({ intercept: (c) => (c.method === "POST" ? { __status: 409 } : undefined) }); t.after(() => ui.window.close());
  ui.el("tpc-new").click();
  const form = ui.el("tpc-create-form");
  form.elements.namedItem("title").value = "X";
  form.elements.namedItem("agreement").value = "Y";
  form.dispatchEvent(new ui.window.Event("submit", { cancelable: true }));
  await ui.settle();
  assert.equal(ui.el("tpc-form-status").textContent, "Could not save it.");
});

test("contracts that aren't set up say when records will appear instead of loading", async (t) => {
  const ui = await fixture({ ready: false }); t.after(() => ui.window.close());
  assert.equal(ui.el("tpc-list-status").textContent, "Contracts and engagements appear here once the setup is finished.");
});

test("a failed availability check replaces the list's Loading with what happened", async (t) => {
  const ui = await fixture({ intercept: (call) => (call.url.pathname.endsWith("/status") ? { __status: 503, detail: "unavailable" } : undefined) });
  t.after(() => ui.window.close());
  assert.equal(ui.el("tpc-readiness").textContent, "Not available");
  assert.equal(ui.el("tpc-list-status").textContent, "Could not load the contracts.");
});

test("a turned-off contracts module starts no checks or loads behind its gate", async (t) => {
  const ui = await fixture({ moduleEnabled: "false" }); t.after(() => ui.window.close());
  assert.deepEqual(ui.calls, []);
});
