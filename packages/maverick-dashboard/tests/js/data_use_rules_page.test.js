// Run with: node --test packages/maverick-dashboard/tests/js/data_use_rules_page.test.js
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

const RECORDS = {
  asset: [{ asset_id: "customers", asset_type: "table", revision: 1 }],
  field: [
    { asset_id: "customers", field_id: "email", data_type: "string", nullable: false, revision: 1 },
    { asset_id: "customers", field_id: "country", data_type: "string", nullable: false, revision: 1 },
  ],
  context: [{ asset_id: "customers", context_kind: "business_purpose", values: ["marketing"], source_system: "crm", fresh_until: Date.now() / 1000 + 86400, revision: 1 }],
  label: [], label_version: [], label_assignment: [],
  policy: [{ policy_id: "marketing-use", state: "draft", current_version: 1, active_version: null, revision: 1 }],
  policy_version: [{ policy_id: "marketing-use", version: 1, document: { scope: { asset_ids: ["customers"], field_ids: [], project_ids: [], actions: ["read"] }, conditions: {}, controls: [{ control_id: "a", effect: "mask", field_ids: ["email"], mask_method: "hash_sha256", row_filter: null }] } }],
  exception: [],
  request: [{ request_id: "spring-list-1a2b", project_id: "project-7", asset_id: "customers", field_ids: ["email"], action: "read", status: "pending", revision: 1 }],
  decision: [],
};

async function page() {
  const html = read("templates/data_use_governance.html")
    .replace(/\{%[\s\S]*?%\}/g, "")
    .replace(/\{\{[\s\S]*?\}\}/g, "");
  const dom = new JSDOM(html, { url: "https://lightwork.test/data-use", runScripts: "outside-only" });
  const w = dom.window, d = w.document, calls = [], confirms = [];
  Object.defineProperty(w, "crypto", { value: crypto.webcrypto });
  w.TextEncoder = TextEncoder;
  Object.assign(d.getElementById("dug-root").dataset, { canAdmin: "true", enabled: "true", compiler: "true" });
  d.querySelectorAll("button,fieldset").forEach((n) => { n.disabled = false; });
  w.mvConfirm = async (message) => { confirms.push(message); return true; };
  w.mvErrorText = (_f, action) => "Could not " + action + ".";
  w.fetch = async (url, init = {}) => {
    const method = init.method || "GET", body = init.body ? JSON.parse(init.body) : null;
    calls.push({ url, method, body });
    if (url.endsWith("/status")) return reply(200, { policy_default: "deny" });
    const match = url.match(/\/records\/([a-z_]+)\?/);
    if (match) return reply(200, { items: RECORDS[match[1]] || [] });
    if (url.endsWith("/authorize")) return reply(200, { decision_id: "DUD-1", outcome: "deny", asset_id: "customers", field_ids: ["email"], controls: [{ field_id: "email", effect: "deny" }], reasons: ["missing_context:consent,regulatory", "contexts_not_independently_sourced"], matched_policy_ids: [], decision_sha256: "a".repeat(64) });
    return reply(200, {});
  };
  shell(w);
  w.eval(read("static/lightwork-consent-workbench.js"));
  const inline = [...read("templates/data_use_governance.html").matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
  inline.forEach((source) => w.eval(source));
  await flush();
  const button = (host, label) => [...d.querySelectorAll("#" + host + " button")].find((b) => b.textContent === label);
  const submit = async (id) => { d.getElementById(id).dispatchEvent(new w.Event("submit", { bubbles: true, cancelable: true })); await flush(); };
  return { dom, w, d, calls, confirms, button, submit, posts: () => calls.filter((c) => c.method !== "GET") };
}

test("records load as plain tables with row buttons", async () => {
  const ui = await page();
  try {
    assert.match(ui.d.getElementById("dug-assets").textContent, /Customers.*Database table.*2.*1 of 4/);
    assert.match(ui.d.getElementById("dug-policies").textContent, /Marketing use.*Customers to read it: Hide part of each value.*Draft/);
    assert.match(ui.d.getElementById("dug-requests").textContent, /Waiting for a decision/);
    assert.ok(ui.button("dug-policies", "Switch on"));
    assert.equal(ui.d.getElementById("dug-policy-default").textContent, "Block");
  } finally { ui.dom.window.close(); }
});

test("the rule builder produces the policy document without any typed code", async () => {
  const ui = await page();
  try {
    ui.d.getElementById("dug-new-policy").click();
    const form = ui.d.getElementById("dug-policy");
    form.elements.policy_name.value = "Europe only";
    form.querySelector("[name=scope_asset][value=customers]").checked = true;
    form.querySelector("[name=scope_asset]").dispatchEvent(new ui.w.Event("change", { bubbles: true }));
    form.querySelector("[name=scope_action][value=export]").checked = true;
    const row = form.querySelector(".dug-control");
    row.querySelector("[data-part=effect]").value = "row_filter";
    row.querySelector("[data-part=filter_field]").value = "country";
    row.querySelector("[data-part=filter_op]").value = "in";
    row.querySelector("[data-part=filter_value]").value = "DE, FR";
    ui.d.getElementById("dug-add-control").click();
    const second = form.querySelectorAll(".dug-control")[1];
    second.querySelector("[data-part=effect]").value = "mask";
    second.querySelector("[data-part=mask]").value = "preserve_last4";
    second.querySelector("[name=ctl2_field][value=email]").checked = true;
    await ui.submit("dug-policy");
    const sent = ui.posts().find((c) => c.url.endsWith("/policies/europe-only/versions"));
    assert.ok(sent, "rule saved");
    assert.equal(sent.body.version, 1);
    assert.equal(sent.body.expected_current_version, 0);
    assert.equal(sent.body.expected_revision, 0);
    assert.deepEqual(sent.body.document.scope, { asset_ids: ["customers"], field_ids: [], project_ids: [], actions: ["export"] });
    assert.deepEqual(sent.body.document.controls[0].row_filter, { op: "in", field: "country", values: ["DE", "FR"] });
    assert.deepEqual(sent.body.document.controls[1], { control_id: "step-2-mask", effect: "mask", field_ids: ["email"], mask_method: "preserve_last4" });
  } finally { ui.dom.window.close(); }
});

test("a reason's source fingerprint depends only on its source", async () => {
  const ui = await page();
  try {
    ui.d.getElementById("dug-new-context").click();
    const form = ui.d.getElementById("dug-context");
    form.elements.context_kind.value = "consent";
    form.elements.context_kind.dispatchEvent(new ui.w.Event("change"));
    form.elements.values.value = "Email opt in";
    form.elements.source_system.value = "Consent register";
    form.elements.evidence_note.value = "Confirmed by the privacy team";
    await ui.submit("dug-context");
    const sent = ui.posts().find((c) => c.url.endsWith("/assets/customers/contexts/consent"));
    assert.deepEqual(sent.body.values, ["email-opt-in"]);
    assert.equal(sent.body.source_system, "consent-register");
    assert.equal(sent.body.source_authority_sha256, sha("lightwork.data-use.source.v1:consent-register"));
    assert.equal(sent.body.evidence_sha256, sha("lightwork.data-use.note.v1\nConfirmed by the privacy team"));
    assert.equal(sent.body.expected_revision, 0);
  } finally { ui.dom.window.close(); }
});

test("missing evidence gives a plain sentence instead of an error", async () => {
  const ui = await page();
  try {
    ui.d.getElementById("dug-new-context").click();
    const form = ui.d.getElementById("dug-context");
    form.elements.values.value = "Marketing";
    form.elements.source_system.value = "CRM";
    await ui.submit("dug-context");
    assert.equal(ui.posts().length, 0);
    assert.match(ui.d.getElementById("dug-status-message").textContent, /Add a short note or attach a document/);
  } finally { ui.dom.window.close(); }
});

test("deciding a request confirms first and explains the outcome plainly", async () => {
  const ui = await page();
  try {
    ui.button("dug-requests", "Decide").click();
    await ui.flush?.();
    await flush();
    assert.match(ui.confirms[0], /Decide the request/);
    const sent = ui.posts().find((c) => c.url.endsWith("/requests/spring-list-1a2b/authorize"));
    assert.equal(sent.body.expected_request_revision, 1);
    const text = ui.d.getElementById("dug-decision-body").textContent;
    assert.match(text, /Blocked/);
    assert.match(text, /Missing reasons: Consent people gave, Laws that apply\./);
    assert.match(text, /Each reason must come from a different source/);
    assert.doesNotMatch(text, /contexts_not|missing_context/);
  } finally { ui.dom.window.close(); }
});
