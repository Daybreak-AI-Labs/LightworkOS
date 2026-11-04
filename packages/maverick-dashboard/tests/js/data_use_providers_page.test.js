// Run with: node --test packages/maverick-dashboard/tests/js/data_use_providers_page.test.js
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const root = path.resolve(__dirname, "../../maverick_dashboard");
const read = (name) => fs.readFileSync(path.join(root, name), "utf8").replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
const flush = async () => { for (let i = 0; i < 40; i++) { await new Promise(setImmediate); await new Promise((r) => setTimeout(r, 2)); } };
const reply = (status, body) => ({ ok: status < 400, status, json: async () => body });
const sha = (text) => crypto.createHash("sha256").update(text).digest("hex");

const BINDING = { binding_id: "customers-in-snowflake", provider_id: "snowflake", asset_id: "customers", catalog: "SALES", schema_name: "PUBLIC", table: "CUSTOMERS", principal: "ANALYST", compute_id: "WH", account_or_workspace_id: "acct1", field_map: { email: "EMAIL" }, mask_bindings: {}, row_filter_bindings: {}, state_anchor: ["GOV", "TAGS", "STATE"], revision: 2, revoked: false };
const DECISION = { decision_id: "DUD-1", request_id: "spring-list-1a2b", asset_id: "customers", outcome: "mask", decision_sha256: "d".repeat(64), created_at: 1800000000 };

async function page(options = {}) {
  const html = read("templates/data_use_providers.html").replace(/\{%[\s\S]*?%\}/g, "").replace(/\{\{[\s\S]*?\}\}/g, "");
  const dom = new JSDOM(html, { url: "https://lightwork.test/data-use/providers", runScripts: "outside-only" });
  const w = dom.window, d = w.document, calls = [], confirms = [];
  Object.defineProperty(w, "crypto", { value: crypto.webcrypto });
  w.TextEncoder = TextEncoder;
  Object.assign(d.getElementById("dup-root").dataset, { canAdmin: "true", snowflake: "true", databricks: "false" });
  d.querySelectorAll("button,fieldset,input").forEach((n) => { n.disabled = false; });
  w.mvConfirm = async (message) => { confirms.push(message); return options.confirm !== false; };
  w.mvForm = async () => ({ reason: "table-retired" });
  w.mvErrorText = (_f, action) => "Could not " + action + ".";
  w.fetch = async (url, init = {}) => {
    const method = init.method || "GET", body = init.body ? JSON.parse(init.body) : null;
    calls.push({ url, method, body });
    if (url.includes("/providers/snowflake/bindings?")) return reply(200, { items: [BINDING] });
    if (url.includes("/records/asset")) return reply(200, { items: [{ asset_id: "customers" }] });
    if (url.includes("/records/field")) return reply(200, { items: [{ asset_id: "customers", field_id: "email" }, { asset_id: "customers", field_id: "country" }] });
    if (url.includes("/records/decision")) return reply(200, { items: [DECISION] });
    if (url.endsWith("/providers/row-filters")) return reply(200, { items: [{ row_filter_sha256: "f".repeat(64), asset_id: "customers", policy_id: "eu-only", row_filter: { op: "eq", field: "country", value: "DE" } }] });
    if (options.fourEyes && url.endsWith("/apply")) {
      if (!body.approval_id) return reply(202, { state: "approval_required", approval_id: 41 });
      return reply(200, { state: "completed" });
    }
    return reply(200, {});
  };
  shell(w);
  w.eval(read("static/lightwork-consent-workbench.js"));
  [...read("templates/data_use_providers.html").matchAll(/<script>([\s\S]*?)<\/script>/g)].forEach((m) => w.eval(m[1]));
  await flush();
  const button = (host, label) => [...d.querySelectorAll("#" + host + " button")].find((b) => b.textContent === label);
  return { dom, w, d, calls, confirms, button, posts: () => calls.filter((c) => c.method !== "GET") };
}

test("connections and ready decisions load as rows", async () => {
  const ui = await page();
  try {
    assert.match(ui.d.getElementById("dup-bindings").textContent, /Customers in snowflake.*Snowflake.*SALES\.PUBLIC\.CUSTOMERS.*Connected/);
    assert.match(ui.d.getElementById("dup-decisions").textContent, /Spring list 1a2b.*Allowed with values hidden/);
    assert.ok(ui.button("dup-decisions", "Apply in Snowflake"));
  } finally { ui.dom.window.close(); }
});

test("a connection is built from a column table, not typed documents", async () => {
  const ui = await page();
  try {
    ui.d.getElementById("dup-new").click();
    const form = ui.d.getElementById("dup-enroll");
    form.elements.binding_name.value = "Customers EU";
    for (const [name, value] of Object.entries({ account_or_workspace_id: "acct1", catalog: "SALES", schema_name: "PUBLIC", table: "CUSTOMERS", principal: "ANALYST", compute_id: "WH", state_anchor: "GOV.TAGS.STATE" })) form.elements[name].value = value;
    form.querySelector("[name=map_field][data-key=email]").value = "EMAIL";
    form.querySelector("[name=map_mask][data-key=preserve_last4]").value = "SEC.POL.LAST4";
    const row = form.querySelector("[name=map_row]");
    assert.match(row.parentElement.textContent, /Rows where Country is DE \(rule Eu only\)/i);
    row.value = "SEC.POL.EU_ROWS";
    form.elements.field_inventory_complete.checked = true;
    form.dispatchEvent(new ui.w.Event("submit", { bubbles: true, cancelable: true }));
    await flush();
    const sent = ui.posts().find((c) => c.url.endsWith("/providers/snowflake/bindings/customers-eu"));
    assert.ok(sent);
    assert.deepEqual(sent.body.field_map, { email: "EMAIL" });
    assert.deepEqual(sent.body.mask_bindings, { preserve_last4: "SEC.POL.LAST4" });
    assert.deepEqual(sent.body.row_filter_bindings, { ["f".repeat(64)]: "SEC.POL.EU_ROWS" });
    assert.equal(sent.body.expected_revision, 0);
    assert.equal(sent.body.field_inventory_complete, true);
    assert.equal(sent.body.catalog_snapshot_sha256, sha(JSON.stringify({ provider: "snowflake", account: "acct1", catalog: "SALES", schema: "PUBLIC", table: "CUSTOMERS", columns: { email: "EMAIL" } })));
  } finally { ui.dom.window.close(); }
});

test("an unconfirmed column list is refused with a plain sentence", async () => {
  const ui = await page();
  try {
    ui.d.getElementById("dup-new").click();
    const form = ui.d.getElementById("dup-enroll");
    for (const [name, value] of Object.entries({ account_or_workspace_id: "a", catalog: "b", schema_name: "c", table: "d", principal: "e", compute_id: "f", state_anchor: "G.H.I" })) form.elements[name].value = value;
    form.querySelector("[name=map_field][data-key=email]").value = "EMAIL";
    form.dispatchEvent(new ui.w.Event("submit", { bubbles: true, cancelable: true }));
    await flush();
    assert.equal(ui.posts().length, 0);
    assert.match(ui.d.getElementById("dup-status").textContent, /Confirm that you listed every column/);
  } finally { ui.dom.window.close(); }
});

test("apply, undo and permanent removal each confirm with the consequence", async () => {
  const ui = await page();
  try {
    ui.button("dup-decisions", "Apply in Snowflake").click();
    await flush();
    assert.match(ui.confirms[0], /Access settings in your database change straight away/);
    const applied = ui.posts().find((c) => c.url.endsWith("/decisions/DUD-1/apply"));
    assert.equal(applied.body.expected_decision_sha256, "d".repeat(64));
    ui.button("dup-decisions", "Undo").click();
    await flush();
    assert.match(ui.confirms[1], /Earlier settings made outside Lightwork are not restored/);
    ui.button("dup-bindings", "Remove permanently").click();
    await flush();
    assert.match(ui.confirms[2], /This cannot be undone/);
    const revoked = ui.posts().find((c) => c.url.endsWith("/revoke"));
    assert.deepEqual(revoked.body.expected_revision, 2);
    assert.equal(revoked.body.reason_sha256, sha("lightwork.data-use.provider-revocation.v1:table-retired"));
  } finally { ui.dom.window.close(); }
});

test("declining a confirmation changes nothing", async () => {
  const ui = await page({ confirm: false });
  try {
    ui.button("dup-decisions", "Apply in Snowflake").click();
    await flush();
    assert.equal(ui.posts().length, 0);
  } finally { ui.dom.window.close(); }
});

test("with a second approver required, the next try carries the approval and the same reference", async () => {
  const ui = await page({ fourEyes: true });
  try {
    ui.w.localStorage.clear();
    ui.button("dup-decisions", "Apply in Snowflake").click();
    await flush();
    assert.match(ui.d.getElementById("dup-status").textContent, /second person must approve this on the Approvals page/);
    ui.button("dup-decisions", "Apply in Snowflake").click();
    await flush();
    const applies = ui.posts().filter((c) => c.url.endsWith("/decisions/DUD-1/apply"));
    assert.equal(applies.length, 2);
    assert.equal(applies[0].body.approval_id, undefined);
    assert.equal(applies[1].body.approval_id, 41);
    assert.equal(applies[1].body.idempotency_key, applies[0].body.idempotency_key);
    assert.match(ui.d.getElementById("dup-status").textContent, /Applied in Snowflake/);
  } finally { ui.dom.window.close(); }
});
