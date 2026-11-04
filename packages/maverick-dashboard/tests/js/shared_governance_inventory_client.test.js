// Run with: node --test packages/maverick-dashboard/tests/js/shared_governance_inventory_client.test.js
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

function source() {
  return fs.readFileSync(
    path.resolve(
      __dirname,
      "../../maverick_dashboard/static/lightwork-shared-governance-inventory.js",
    ),
    "utf8",
  );
}

test("client uses bounded same-origin JSON and safe DOM projection", () => {
  const text = source();
  assert.match(text, /maxResponseBytes = 2 \* 1024 \* 1024/);
  assert.match(text, /credentials: "same-origin"/);
  assert.match(text, /response\.body\.getReader/);
  assert.match(text, /await reader\.cancel\(\)/);
  assert.match(text, /replaceChildren\(\)/);
  assert.match(text, /textContent = JSON\.stringify/);   // raw answers stay in the collapsed technical details
  assert.doesNotMatch(text, /\.innerHTML\s*=/);
  assert.doesNotMatch(text, /eval\s*\(/);
});

test("mutations carry closed fields and exact compare-and-swap authority", () => {
  const text = source();
  assert.match(text, /expected_active_revision:/);
  assert.match(text, /expected_active_integrity_sha256:/);
  assert.match(text, /operation_id:/);
  assert.match(text, /request\("\/reconcile", \{ method: "POST"/);
  assert.match(text, /window\.mvConfirm/);
  assert.match(text, /request\("\/recovery\/checkpoint", \{ method: "POST"/);
  assert.match(text, /request\("\/recovery\/restore", \{ method: "POST"/);
  assert.doesNotMatch(text, /tenant_id\s*:/);
  assert.doesNotMatch(text, /provider_url\s*:/);
});

// ---- behaviour in a page -------------------------------------------------
const { JSDOM } = require("jsdom");
const {shell: loadShell} = require("./_shell");
const REF_A = "a".repeat(64);
const REF_B = "b".repeat(64);

function page() {
  return fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates/shared_governance_inventory.html"), "utf8")
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, "")
    .replace(/{% if not inventory_can_[a-z]+ %}[\s\S]*?{% endif %}/g, "")   // an administrator's view
    .replace(/{%[^%]*%}/g, "")
    .replace(/{{[^}]*}}/g, "");
}

async function inventoryFixture(intercept = () => undefined) {
  const dom = new JSDOM(page(), { url: "https://lightwork.example/governance/inventory", runScripts: "outside-only" });
  const { window } = dom;
  const ui = { confirms: [], calls: [], answer: true };
  window.mvConfirm = async (m) => { ui.confirms.push(m); return ui.answer; };
  window.mvErrorText = (f, a) => "Could not " + a + ".";
  window.TextDecoder = TextDecoder;
  window.HTMLElement.prototype.scrollIntoView = () => {};
  const entities = [
    { entity_ref_sha256: REF_A, entity_kind: "governance_resource", origin: "suite_capture", source_id: "privacy_automation", record_count: 3, first_observed_at: 1767225600, last_observed_at: 1767312000, latest_action: "record_updated" },
    { entity_ref_sha256: REF_B, entity_kind: "vendor", origin: "entity_graph" },
  ];
  const links = [{ source_entity_ref_sha256: REF_A, relation_type: "assesses", target_entity_ref_sha256: REF_B, valid_from: 1767225600 }];
  window.fetch = async (url, opts = {}) => {
    const call = { url: new URL(url, window.location), method: opts.method || "GET", body: opts.body ? JSON.parse(opts.body) : null };
    ui.calls.push(call);
    let reply = await intercept(call);
    const p = call.url.pathname;
    if (reply === undefined) {
      if (p.endsWith("/status")) reply = { enabled: true, ready: true, complete: true, active: { snapshot_id: "snap-1", revision: 4, integrity_sha256: "c".repeat(64) }, sources: [{ source_id: "privacy_automation", complete: true }] };
      else if (p.endsWith("/snapshots/current")) reply = { projection: { entities, relationships: links } };
      else if (p.endsWith("/snapshots")) reply = { items: [{ snapshot_id: "snap-1", version: 4, state: "available", entity_count: 2, created_at: 1767312000, payload_available: true }] };
      else if (p.endsWith("/entities")) reply = { items: entities, total_matching: 2, next_cursor: null };
      else if (p.endsWith("/relationships")) reply = { items: links, total_matching: 1, next_cursor: null };
      else reply = { verified: true, snapshot_count: 4 };
    }
    return new Response(JSON.stringify(reply), { status: reply.__status || 200, headers: { "Content-Type": "application/json" } });
  };
  loadShell(window);
  window.eval(source());
  async function settle() { for (let i = 0; i < 40; i++) await new Promise((d) => setImmediate(d)); }
  await settle();
  return Object.assign(ui, { window, document: window.document, el: (id) => window.document.getElementById(id), settle });
}

test("records, links and saved versions load on open with readable words", async (t) => {
  const ui = await inventoryFixture(); t.after(() => ui.window.close());
  const records = ui.el("sgi-entity-rows").textContent;
  assert.match(records, /Governance record/);
  assert.match(records, /Privacy/);
  assert.match(records, /Record updated/);
  assert.match(ui.el("sgi-link-rows").textContent, /Governance record \(Privacy\)AssessesVendor/);
  assert.match(ui.el("sgi-snapshot-rows").textContent, /Complete/);
  assert.deepEqual([...ui.el("sgi-kind").options].map((o) => o.textContent), ["All types", "Governance record", "Vendor"]);
  assert.doesNotMatch(ui.document.querySelector("main, body").textContent.replace(ui.el("sgi-output").textContent, ""), /aaaaaaaa|snap-1|privacy_automation|governance_resource/);
});

test("show links sends the chosen record, never a typed reference", async (t) => {
  const ui = await inventoryFixture(); t.after(() => ui.window.close());
  [...ui.el("sgi-entity-rows").querySelectorAll("button")][0].click();
  await ui.settle();
  const last = ui.calls.filter((c) => c.url.pathname.endsWith("/relationships")).pop();
  assert.equal(last.url.searchParams.get("entity_ref_sha256"), REF_A);
  assert.equal(ui.el("sgi-all-links").hidden, false);
});

test("update is confirmed and carries the loaded version check and a generated request key", async (t) => {
  const ui = await inventoryFixture(); t.after(() => ui.window.close());
  ui.el("sgi-reconcile").click();
  await ui.settle();
  assert.equal(ui.confirms.length, 1);
  const call = ui.calls.find((c) => c.url.pathname.endsWith("/reconcile"));
  assert.equal(call.method, "POST");
  assert.equal(call.body.expected_active_revision, 4);
  assert.equal(call.body.expected_active_integrity_sha256, "c".repeat(64));
  assert.match(call.body.operation_id, /^update-/);
});

test("restoring asks first and a refusal is a plain sentence", async (t) => {
  const ui = await inventoryFixture((call) => call.url.pathname.endsWith("/recovery/restore") ? { __status: 409 } : undefined);
  t.after(() => ui.window.close());
  ui.answer = false;
  ui.el("sgi-restore").click();
  await ui.settle();
  assert.equal(ui.calls.some((c) => c.url.pathname.endsWith("/recovery/restore")), false);
  ui.answer = true;
  ui.el("sgi-restore").click();
  await ui.settle();
  assert.equal(ui.el("sgi-operation-state").textContent, "Could not restore the inventory.");
});
