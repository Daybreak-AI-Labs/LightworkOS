"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const folder = path.resolve(__dirname, "../../maverick_dashboard");
const markup = fs.readFileSync(path.join(folder, "templates/third_party_intelligence.html"), "utf8")
  .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "")
  .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, "")
  .replace(/{%-?[\s\S]*?-?%}/g, "")
  .replace(/{{[\s\S]*?}}/g, "");
const helpers = fs.readFileSync(path.join(folder, "static/lightwork-record-workflows.js"), "utf8");
const source = fs.readFileSync(path.join(folder, "static/lightwork-third-party-intelligence.js"), "utf8");
const ME = "tpi-principal-" + "1".repeat(32);
const OTHER = "tpi-principal-" + "2".repeat(32);
const FUTURE = Date.now() / 1000 + 86400 * 30;

function data() {
  return {
    "/sources": [
      { source_id: "source-a", provider: "riskrecon", kind: "sanctions", purposes: ["screening", "monitoring"], territories: ["GLOBAL"], state: "active", revision: 2, enrolled_by: OTHER, provenance_uri: "https://x.example" },
      { source_id: "source-b", provider: "iss", kind: "pep", purposes: ["screening"], territories: ["EU"], state: "pending", revision: 1, enrolled_by: OTHER },
    ],
    "/snapshots": [{ snapshot_id: "snap-a", source_id: "source-a", dataset_revision: "September", observed_at: 10, valid_until: FUTURE }],
    "/vendors": [{ vendor_id: "vendor-x", display_label: "Acme Corp", entity_identity_sha256: "d".repeat(64), territories: ["GLOBAL"], inherent_risk_level: 2, criticality: 3, data_access_level: "limited" }],
    "/screening/runs": [{ run_id: "run-1", vendor_id: "vendor-x", requested_kinds: ["sanctions"], state: "open", revision: 1, initiated_at: 20 }],
    "/risk/policies": [], "/risk/decisions": [], "/edd/cases": [], "/monitors": [], "/monitoring/alerts": [], "/exchange/consents": [],
  };
}

async function fixture({ admin = true } = {}) {
  const dom = new JSDOM(markup, { url: "https://lightwork.example/third-party/intelligence", runScripts: "outside-only" });
  const { window } = dom;
  const root = window.document.getElementById("tpi-root");
  root.setAttribute("data-api", "/api/v1/third-party/intelligence");
  root.setAttribute("data-can-admin", admin ? "true" : "false");
  root.setAttribute("data-can-audit", "true");
  const ui = { answer: true, confirms: [], formValues: [], forms: [], calls: [] };
  window.mvConfirm = async (m) => { ui.confirms.push(m); return ui.answer; };
  window.mvForm = async (title, fields) => { ui.forms.push({ title, fields }); return ui.formValues.shift() || null; };
  window.mvErrorText = (f, a) => "Could not " + a + ".";
  window.HTMLElement.prototype.scrollIntoView = () => {};
  const d = data();
  window.fetch = async (url, opts = {}) => {
    const call = { url: new URL(url, window.location), method: opts.method || "GET", body: opts.body && typeof opts.body === "string" ? JSON.parse(opts.body) : null };
    ui.calls.push(call);
    const p = call.url.pathname.replace("/api/v1/third-party/intelligence", "");
    let reply;
    if (p === "/me") reply = { principal_ref: ME };
    else if (p === "/status") reply = { provider_runtime: { enabled_providers: ["riskrecon"] }, provider_scheduler: { running: false } };
    else if (call.method === "GET" && d[p]) reply = { items: d[p] };
    else if (call.url.pathname === "/api/v1/vendors") reply = { vendors: [{ id: "vend-1", name: "Acme Corp" }] };
    else if (call.url.pathname === "/api/v1/compliance/fingerprint") reply = { sha256: "f".repeat(64) };
    else reply = { ok: true };
    return new Response(JSON.stringify(reply), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  shell(window);
  window.eval(helpers);
  window.eval(source);
  async function settle() { for (let i = 0; i < 40; i++) await new Promise((r) => setImmediate(r)); }
  await settle();
  const el = (id) => window.document.getElementById(id);
  const rowButton = (id, rowText, label) => {
    const row = [...el(id).querySelectorAll("tr")].find((tr) => tr.textContent.includes(rowText));
    return row && [...row.querySelectorAll("button")].find((b) => b.textContent === label);
  };
  return Object.assign(ui, { window, document: window.document, el, settle, rowButton });
}

test("lists load with provider and data names, and approvals only for someone else's sources", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  const sources = ui.el("tpi-sources").textContent;
  assert.match(sources, /RiskRecon/);
  assert.match(sources, /Sanctions lists/);
  assert.match(sources, /Politically exposed people/);
  assert.match(sources, /Waiting for approval/);
  assert.ok(ui.rowButton("tpi-sources", "ISS", "Approve"));
  assert.ok(ui.rowButton("tpi-sources", "RiskRecon", "Record a data update"));
  assert.match(ui.el("tpi-vendors").textContent, /Acme Corp/);
  assert.match(ui.el("tpi-runs").textContent, /Open/);
  assert.doesNotMatch(ui.document.body.textContent, /source-a|vendor-x|tpi-principal|adverse_media|pending_approval/);
});

test("screening binds the current approved data automatically", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  ui.formValues.push({ k0: true });
  ui.rowButton("tpi-vendors", "Acme", "Screen").click();
  await ui.settle();
  const put = ui.calls.find((c) => c.method === "PUT" && c.url.pathname.includes("/screening/runs/"));
  assert.deepEqual(put.body.snapshot_bindings, { sanctions: "snap-a" });
  assert.deepEqual(put.body.requested_kinds, ["sanctions"]);
  assert.equal(put.body.subject_identity_sha256, "d".repeat(64));
});

test("adding a vendor uses a server fingerprint of its name, never a typed digest", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  // The vendor is picked from the Privacy register by its record, not typed.
  ui.formValues.push({ pick: "vend-1", category: "software", inherent: "2", critical: "3", access: "limited", r0: true });
  ui.el("tpi-add-vendor").click();
  await ui.settle();
  const put = ui.calls.find((c) => c.method === "PUT" && c.url.pathname.includes("/vendors/"));
  assert.equal(put.body.display_label, "Acme Corp");
  assert.equal(put.body.register_vendor_id, "vend-1");
  assert.equal(put.body.entity_identity_sha256, "f".repeat(64));
  assert.deepEqual(put.body.territories, ["GLOBAL"]);
  assert.ok(ui.calls.some((c) => c.url.pathname === "/api/v1/compliance/fingerprint"));
});

test("adding a source turns the connection key words into the name the server expects", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  ui.formValues.push({ provider: "riskrecon", kind: "sanctions", uri: "https://feed.example", credential: "sanctions provider token",
    license: "Standard", rights: "Screening suppliers", p0: true, r0: true, keep: "365" });
  ui.el("tpi-add-source").click();
  await ui.settle();
  const put = ui.calls.find((c) => c.method === "PUT" && c.url.pathname.includes("/sources/"));
  assert.equal(put.body.credential_env, "SANCTIONS_PROVIDER_TOKEN");
  assert.deepEqual(put.body.purposes, ["screening"]);
  assert.equal(put.body.retention_seconds, 365 * 86400);
});

test("revoking a source is confirmed first", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  ui.answer = false;
  ui.formValues.push({ why: "Contract ended" });
  ui.rowButton("tpi-sources", "RiskRecon", "Revoke").click();
  await ui.settle();
  assert.equal(ui.confirms.length, 1);
  assert.equal(ui.calls.some((c) => c.url.pathname.endsWith("/revoke")), false);
});

test("non-administrators get no approval, revoke or policy buttons", async (t) => {
  const ui = await fixture({ admin: false }); t.after(() => ui.window.close());
  assert.equal(ui.rowButton("tpi-sources", "ISS", "Approve"), undefined);
  assert.equal(ui.rowButton("tpi-sources", "RiskRecon", "Revoke"), undefined);
});
