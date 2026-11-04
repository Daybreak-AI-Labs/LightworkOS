"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const folder = path.resolve(__dirname, "../../maverick_dashboard");
// Render the enabled page branch, as Jinja does when the module is on: the
// block-level disabled branch now carries its own data-enabled="false"
// #trc-root, which would otherwise come first.
const markup = fs.readFileSync(path.join(folder, "templates/trc_continuous_evidence.html"), "utf8")
  .replace(/^{%-?\s*if not trc_continuous_evidence_enabled\s*-?%}$[\s\S]*?^{%-?\s*else\s*-?%}$/m, "")
  .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "").replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, "")
  .replace(/{%-?[\s\S]*?-?%}/g, "").replace(/{{[\s\S]*?}}/g, "");
const helpers = fs.readFileSync(path.join(folder, "static/lightwork-record-workflows.js"), "utf8");
const source = fs.readFileSync(path.join(folder, "static/lightwork-trc-continuous-evidence.js"), "utf8");

async function fixture({ running = false, admin = true } = {}) {
  const dom = new JSDOM(markup, { url: "https://lightwork.example/compliance/continuous-evidence", runScripts: "outside-only" });
  const { window } = dom;
  const root = window.document.getElementById("trc-root");
  root.setAttribute("data-api", "/api/v1/compliance/continuous-evidence");
  root.setAttribute("data-can-admin", admin ? "true" : "false");
  root.setAttribute("data-can-audit", "true");
  const ui = { answer: true, confirms: [], formValues: [], calls: [] };
  window.mvConfirm = async (m) => { ui.confirms.push(m); return ui.answer; };
  window.mvForm = async () => ui.formValues.shift() || null;
  window.mvErrorText = (f, a) => "Could not " + a + ".";
  const replies = {
    "/status": { scheduler: { running }, stock_collectors: { ready: false, missing_stock_collector_ids: ["okta_posture_v1"] } },
    "/setup": { items: [
      { key: "local-soc2", label: "Lightwork's own security checks", definition_id: "local-soc2", definition_version: 1, enrollment_id: "local-soc2", control_count: 8, credential_ready: true },
      { key: "okta", label: "Okta policies", definition_id: "okta-def", definition_version: 1, enrollment_id: "okta", control_count: 3, credential_ready: false },
    ] },
    "/definitions": { items: [{ definition_id: "local-soc2", version: 1, state: "approved", allowed_control_refs: ["audit_log"], integrity_sha256: "a".repeat(64), created_at: 1 }] },
    "/enrollments": { items: [{ enrollment_id: "local-soc2", definition_id: "local-soc2", definition_version: 1, state: "active", revision: 3, integrity_sha256: "b".repeat(64) }] },
    "/runs": { items: [{ enrollment_id: "local-soc2", completed_at: 100, complete: true, item_count: 8 }] },
    "/jobs": { items: [] },
    "/alerts": { items: [{ enrollment_id: "local-soc2", control_ref: "encryption_at_rest", previous_status: "observed", current_status: "failed", created_at: 50 }] },
  };
  window.fetch = async (url, opts = {}) => {
    const call = { url: new URL(url, window.location), method: opts.method || "GET", body: opts.body ? JSON.parse(opts.body) : null };
    ui.calls.push(call);
    const key = call.url.pathname.replace("/api/v1/compliance/continuous-evidence", "");
    const reply = call.method === "GET" && replies[key] ? replies[key] : { ok: true, executed: true };
    return new Response(JSON.stringify(reply), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  shell(window);
  window.eval(helpers);
  window.eval(source);
  async function settle() { for (let i = 0; i < 40; i++) await new Promise((r) => setImmediate(r)); }
  await settle();
  const el = (id) => window.document.getElementById(id);
  const rowButton = (id, text, label) => {
    const row = [...el(id).querySelectorAll("tr")].find((tr) => tr.textContent.includes(text));
    return row && [...row.querySelectorAll("button")].find((b) => b.textContent === label);
  };
  return Object.assign(ui, { window, el, settle, rowButton });
}

test("sources show plain states with one button for the next step", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  const text = ui.el("trc-sources").textContent;
  assert.match(text, /Lightwork's own security checks/);
  assert.match(text, /Schedule active/);
  assert.match(text, /Okta policies/);
  assert.match(text, /Missing/);
  assert.ok(ui.rowButton("trc-sources", "Okta", "Set up"));
  assert.ok(ui.rowButton("trc-sources", "own security", "Pause"));
  assert.match(ui.el("trc-alerts").textContent, /Encryption at rest.*Passing.*Failing/);
  assert.equal(ui.el("trc-composition").textContent, "1 step left");
  assert.doesNotMatch(ui.window.document.body.textContent, /local_soc2|dead_letter|observed/);
});

test("collect now stays off until the scheduler is running", async (t) => {
  const off = await fixture({ running: false }); t.after(() => off.window.close());
  assert.equal(off.el("trc-run-cycle").disabled, true);
  const on = await fixture({ running: true }); t.after(() => on.window.close());
  assert.equal(on.el("trc-run-cycle").disabled, false);
});

test("pausing is confirmed and carries the row's version and fingerprint", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  ui.rowButton("trc-sources", "own security", "Pause").click();
  await ui.settle();
  assert.equal(ui.confirms.length, 1);
  const call = ui.calls.find((c) => c.url.pathname.endsWith("/enrollments/local-soc2/state"));
  assert.deepEqual(call.body, { state: "paused", expected_revision: 3, expected_integrity_sha256: "b".repeat(64) });
});

test("setting up a source asks first and sends nothing but the choice", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  ui.rowButton("trc-sources", "Okta", "Set up").click();
  await ui.settle();
  const call = ui.calls.find((c) => c.url.pathname.endsWith("/setup/okta/definition"));
  assert.equal(call.method, "POST");
  assert.equal(call.body, null);
});
