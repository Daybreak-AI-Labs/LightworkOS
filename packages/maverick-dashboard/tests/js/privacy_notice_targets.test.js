// Run with: node --test packages/maverick-dashboard/tests/js/privacy_notice_targets.test.js
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const dir = path.resolve(__dirname, "../../maverick_dashboard");
const template = fs.readFileSync(path.join(dir, "templates/privacy_notice_governance.html"), "utf8").replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
const start = template.indexOf('<section class="panel" id="png-targets"');
const panel = template.slice(start, template.indexOf("</section>", start) + "</section>".length);
const scripts = [...template.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
const script = scripts.find((s) => s.includes("notice-publication/targets"));
const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { "Content-Type": "application/json" } });
const TARGET = { binding_id: "primary", tenant_id: "acme", notice_id: "privacy-main", consent_publication_ref: "consent-binding:1",
  property_id: "property-main", rule_group_id: "production-rules", rule_group_version: 1, notice_resource_id: "privacy-notice",
  notice_resource_version: 1, source: "installer", locked: false, removable: false };

async function fixture({ targets = [TARGET], forms = [], confirm = true } = {}) {
  const dom = new JSDOM(`<main>${panel}</main>`, { url: "https://lightwork.example/privacy/notice-governance", runScripts: "outside-only" });
  const { window } = dom;
  const calls = [], confirms = [];
  let state = { targets, workspaces: ["acme"] };
  window.mvConfirm = async (m) => { confirms.push(m); return confirm; };
  window.mvForm = async (title, fields) => { const v = forms.shift(); if (v && v.__fields) v.__fields(fields); return v; };
  window.mvErrorText = (_f, a) => `Could not ${a}.`;
  window.mvHuman = (v) => String(v).replace(/[-_]+/g, " ");
  window.fetch = async (url, opts = {}) => {
    const body = opts.body ? JSON.parse(opts.body) : null;
    calls.push({ url, method: opts.method || "GET", body });
    if (url.includes("/notices/records")) return json({ releases: [{ notice_id: "privacy-main", property_id: "property-main" }] });
    if (url.includes("/catalog/properties")) return json({ items: [{ property_id: "property-main" }] });
    if (url.includes("/catalog/rule-groups")) return json({ items: [{ resource_id: "production-rules", version: 3 }] });
    if (url.includes("/catalog/notices")) return json({ items: [{ resource_id: "privacy-notice", version: 5 }] });
    if (opts.method === "PUT" && !body.confirm) return json({ detail: "confirmation required", confirm: "x" }, 409);
    if (opts.method === "PUT") { state = { targets: [{ ...TARGET, ...body, binding_id: "second", source: "here", removable: true }], workspaces: ["acme"] }; return json({ changed: true, ...state }); }
    if (opts.method === "DELETE") return json({ detail: "This publishing target was set by your installer, so it can be changed here but not removed." }, 409);
    return json(state);
  };
  shell(window);
  window.eval(script);
  const settle = async () => { for (let i = 0; i < 30; i++) await new Promise((d) => setImmediate(d)); };
  await settle();
  return { window, document: window.document, calls, confirms, settle };
}

test("targets list shows where each came from and hides removal for installer targets", async () => {
  const ui = await fixture();
  const text = ui.document.getElementById("png-target-list").textContent;
  assert.match(text, /primary.*acme.*privacy main.*property main.*Your installer/);
  assert.ok([...ui.document.querySelectorAll("#png-target-list button")].some((b) => b.textContent === "Change"));
  assert.ok(![...ui.document.querySelectorAll("#png-target-list button")].some((b) => b.textContent === "Remove"));
});

test("adding a target uses choices from real records and confirms before saving", async () => {
  let offered;
  const ui = await fixture({ targets: [], forms: [{ __fields: (f) => { offered = f; }, binding_id: "second", tenant_id: "acme",
    notice_id: "privacy-main", consent_publication_ref: "spring-banner", property_id: "property-main",
    rule_group: "production-rules@3", notice_resource: "privacy-notice@5" }] });
  assert.match(ui.document.getElementById("png-target-list").textContent, /No publishing targets yet/);
  ui.document.getElementById("png-target-add").click();
  await ui.settle();
  assert.equal(offered.find((f) => f.key === "notice_id").type, "select");
  assert.equal(offered.find((f) => f.key === "rule_group").type, "select");
  const puts = ui.calls.filter((c) => c.method === "PUT");
  assert.equal(puts.length, 2);
  assert.equal(puts[0].url.endsWith("/targets/second"), true);
  assert.deepEqual(puts[1].body, { tenant_id: "acme", notice_id: "privacy-main", consent_publication_ref: "spring-banner",
    property_id: "property-main", rule_group_id: "production-rules", rule_group_version: 3,
    notice_resource_id: "privacy-notice", notice_resource_version: 5, confirm: true });
  assert.match(ui.confirms[0], /Approved notices will be published to this target/);
  assert.equal(ui.document.getElementById("png-target-status").textContent, "Saved.");
});

test("declining the confirmation saves nothing", async () => {
  const ui = await fixture({ targets: [], confirm: false, forms: [{ binding_id: "second", tenant_id: "acme",
    notice_id: "privacy-main", consent_publication_ref: "spring-banner", property_id: "property-main",
    rule_group: "production-rules@3", notice_resource: "privacy-notice@5" }] });
  ui.document.getElementById("png-target-add").click();
  await ui.settle();
  assert.equal(ui.calls.filter((c) => c.method === "PUT" && c.body.confirm).length, 0);
});
