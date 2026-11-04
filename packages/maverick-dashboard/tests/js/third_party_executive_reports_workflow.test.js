"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const folder = path.resolve(__dirname, "../../maverick_dashboard");
const markup = fs.readFileSync(path.join(folder, "templates/third_party_executive_reports.html"), "utf8")
  .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "").replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, "")
  .replace(/{%\s*if not reports_module_enabled\s*%}[\s\S]*?{%\s*endif\s*%}/g, "")
  .replace(/{%\s*if not reports_can_audit\s*%}[\s\S]*?{%\s*endif\s*%}/g, "")
  .replace(/{%-?[\s\S]*?-?%}/g, "").replace(/{{[\s\S]*?}}/g, "");
const helpers = fs.readFileSync(path.join(folder, "static/lightwork-record-workflows.js"), "utf8");
const source = fs.readFileSync(path.join(folder, "static/lightwork-third-party-executive-reports.js"), "utf8");

const REPORT = {
  report_id: "exec-1", state: "active", control_revision: 3, created_at: 1790000000, artifact_available: true,
  brand: { report_title: "Board vendor summary", organization_name: "Acme" },
  snapshot: { sources: [
    { source_kind: "intelligence_vendor", source_id: "v-1", state: "available", reason_code: "none" },
    { source_kind: "contract_record", source_id: "c-gone", state: "unavailable", reason_code: "not_found" },
  ] },
};

async function fixture({ ready = true, admin = true } = {}) {
  const dom = new JSDOM(markup, { url: "https://lightwork.example/third-party/executive-reports", runScripts: "outside-only" });
  const { window } = dom;
  window.TextDecoder = TextDecoder;
  const root = window.document.getElementById("tper-workbench");
  root.dataset.apiBase = "/api/v1/third-party/executive-reports";
  root.dataset.moduleEnabled = "true";
  root.dataset.canAdmin = admin ? "true" : "false";
  window.document.querySelectorAll("[data-tper-mutation]").forEach((f) => { f.dataset.authorized = f.id === "tper-revoke-controls" || f.id === "tper-purge-controls" ? String(admin) : "true"; });
  const ui = { answer: true, confirms: [], calls: [], downloads: [] };
  window.mvConfirm = async (m) => { ui.confirms.push(m); return ui.answer; };
  window.mvErrorText = (f, a) => "Could not " + a + ".";
  window.URL.createObjectURL = () => "blob:x";
  window.URL.revokeObjectURL = () => {};
  window.HTMLAnchorElement.prototype.click = function () { ui.downloads.push(this.download); };
  const replies = {
    "/api/v1/third-party/executive-reports/status": { ready, enabled: true },
    "/api/v1/third-party/executive-reports/reports": { items: [REPORT] },
    "/api/v1/vendors": { vendors: [{ id: "acme", name: "Acme Corp" }] },
    "/api/v1/third-party/intelligence/vendors": { items: [{ vendor_id: "v-1", display_label: "Acme Corp", state: "active" }] },
    "/api/v1/third-party/intelligence/screening/runs": { items: [] },
    "/api/v1/third-party/lifecycle/assessments": { items: [{ assessment_id: "a-1", vendor_ref: "acme", highest_severity: "high" }] },
    "/api/v1/third-party/lifecycle/lifecycles": { items: [] },
    "/api/v1/third-party/contracts": { items: [{ record_id: "c-1", title_ref: "Acme-master-agreement", record_kind: "contract", vendor_id: "v-1" }] },
  };
  window.fetch = async (url, opts = {}) => {
    const call = { url: new URL(url, window.location), method: opts.method || "GET", body: opts.body ? JSON.parse(opts.body) : null };
    ui.calls.push(call);
    if (call.url.pathname.endsWith("/downloads/redeem")) {
      return new Response(new Uint8Array([37, 80, 68, 70]), { status: 200, headers: { "Content-Type": "application/pdf" } });
    }
    if (call.url.pathname.endsWith("/download-grants")) {
      return new Response(JSON.stringify({ token: "one-time" }), { status: 201 });
    }
    if (call.url.pathname.endsWith("/collaboration/invitations")) { return new Response("{}", { status: 403 }); }
    const reply = call.method === "GET" && replies[call.url.pathname] ? replies[call.url.pathname] : { ok: true, count: 0 };
    return new Response(JSON.stringify(reply), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  shell(window);
  window.eval(helpers);
  window.eval(source);
  async function settle() { for (let i = 0; i < 40; i++) await new Promise((r) => setImmediate(r)); }
  await settle();
  const el = (id) => window.document.getElementById(id);
  const rowButton = (label) => [...el("tper-reports").querySelectorAll("button")].find((b) => b.textContent === label);
  return Object.assign(ui, { window, el, settle, rowButton });
}

test("reports list in plain words with a button per next step", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  const text = ui.el("tper-reports").textContent;
  assert.match(text, /Board vendor summary/);
  assert.match(text, /Ready/);
  assert.ok(ui.rowButton("Download PDF"));
  assert.ok(ui.rowButton("Withdraw"));
  assert.equal(ui.el("tper-create-controls").disabled, false);
  ui.rowButton("What's inside").click();
  const detail = ui.el("tper-report-detail").textContent;
  assert.match(detail, /Vendors: Acme Corp/);
  assert.match(detail, /not included because it no longer exists/);
  assert.doesNotMatch(text + detail, /intelligence_vendor|not_found|exec-1/);
});

test("controls stay off until reports are ready", async (t) => {
  const ui = await fixture({ ready: false }); t.after(() => ui.window.close());
  assert.equal(ui.el("tper-create-controls").disabled, true);
  assert.equal(ui.el("tper-download-controls").disabled, true);
  assert.match(ui.el("tper-runtime-headline").textContent, /aren't available/);
});

test("download carries the row's version and a generated request key", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  ui.rowButton("Download PDF").click();
  await ui.settle();
  const grant = ui.calls.find((c) => c.url.pathname.endsWith("/download-grants"));
  assert.equal(grant.body.expected_control_revision, 3);
  assert.ok(grant.body.idempotency_key.length >= 8);
  assert.deepEqual(ui.downloads, ["board-vendor-summary.pdf"]);
  assert.match(ui.el("tper-operation-status").textContent, /PDF downloaded/);
});

test("a new report is built by ticking real records", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  ui.el("tper-new").click();
  await ui.settle();
  const sources = ui.el("tper-sources").textContent;
  assert.match(sources, /Acme Corp — high risk/);
  assert.match(sources, /Acme master agreement \(contract, Acme Corp\)/);
  assert.match(sources, /You can't see these records/);
  const form = ui.el("tper-create-form");
  form.requestSubmit();
  await ui.settle();
  assert.match(ui.el("tper-form-status").textContent, /Tick at least one record/);
  [...form.querySelectorAll('input[name="include"]')].slice(0, 2).forEach((b) => { b.checked = true; });
  form.requestSubmit();
  await ui.settle();
  const create = ui.calls.find((c) => c.method === "POST" && c.url.pathname.endsWith("/reports"));
  assert.deepEqual(create.body.selectors, [
    { source_kind: "intelligence_vendor", source_id: "v-1" },
    { source_kind: "lifecycle_assessment", source_id: "a-1" },
  ]);
  assert.equal(create.body.brand.primary_color, "#102A43");
  assert.equal(create.body.expected_absent_revision, 0);
});

test("withdrawing is confirmed and uses the report's version and a chosen reason", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  ui.rowButton("Withdraw").click();
  assert.equal(ui.el("tper-admin").open, true);
  const form = ui.el("tper-revoke-form");
  form.elements.namedItem("reason_code").value = "shared-by-mistake";
  ui.answer = false;
  form.requestSubmit();
  await ui.settle();
  assert.equal(ui.calls.filter((c) => c.url.pathname.endsWith("/revoke")).length, 0);
  ui.answer = true;
  form.requestSubmit();
  await ui.settle();
  assert.match(ui.confirms[1], /Withdraw the report “Board vendor summary” \(it was shared by mistake\)/);
  const revoke = ui.calls.find((c) => c.url.pathname.endsWith("/revoke"));
  assert.equal(revoke.body.expected_control_revision, 3);
  assert.equal(revoke.body.reason_code, "shared-by-mistake");
});

test("viewers without admin rights get no withdraw button", async (t) => {
  const ui = await fixture({ admin: false }); t.after(() => ui.window.close());
  assert.equal(ui.rowButton("Withdraw"), undefined);
  assert.equal(ui.el("tper-revoke-controls").disabled, true);
});
