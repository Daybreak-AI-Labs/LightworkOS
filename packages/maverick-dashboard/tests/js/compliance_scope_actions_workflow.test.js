"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const dir = path.resolve(__dirname, "../../maverick_dashboard");
const helpers = fs.readFileSync(path.join(dir, "static/lightwork-record-workflows.js"), "utf8");
const source = fs.readFileSync(path.join(dir, "static/lightwork-compliance-scope-actions.js"), "utf8");
const template = fs.readFileSync(path.join(dir, "templates/compliance_scope_actions.html"), "utf8");
const app = template.slice(template.indexOf('<div id="csa-app"'), template.indexOf('<details class="panel" id="csa-technical">'))
  .replace(/{%[\s\S]*?%}/g, "").replace(/{{[\s\S]*?}}/g, "true");
const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { "Content-Type": "application/json" } });

async function fixture({ canCreate = false, forms = [] } = {}) {
  const dom = new JSDOM(`<main>${app}</main>`, { url: "https://lightwork.example/compliance/scope-actions", runScripts: "outside-only" });
  const { window } = dom;
  const calls = [], confirms = [];
  window.mvConfirm = async (m) => { confirms.push(m); return true; };
  window.mvForm = async () => forms.shift();
  window.mvErrorText = (f, a) => `Could not ${a}.`;
  window.HTMLElement.prototype.scrollIntoView = () => {};
  window.fetch = async (url, opts = {}) => {
    calls.push({ url, ...opts });
    if (url.endsWith("/scope-actions/records")) return json({ can_create_tasks: canCreate,
      catalogs: [{ catalog_id: "privacy-controls", version: 1, status: "published", entries: 4, revision: 2 }],
      plans: [{ plan_id: "plan-1", scope_id: "scope-1", status: "approved", controls: 3, evidence_tasks: 2, revision: 2, created_at: 1.9e9 }],
      reports: [] });
    if (url.endsWith("/scoping/records")) return json({ scopes: [{ scope_id: "scope-1", status: "finalized", frameworks: ["framework-eu-privacy"], controls: 3, revision: 4 }] });
    return json({});
  };
  shell(window);
  window.eval(helpers);
  window.eval(source);
  const settle = async () => { for (let i = 0; i < 30; i++) await new Promise((d) => setImmediate(d)); };
  await settle();
  return { window, doc: window.document, calls, confirms, settle };
}

test("final scopes and plans load with row buttons; task creation hides when not connected", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  assert.match(ui.doc.getElementById("csa-scopes").textContent, /EU privacy.*Propose tasks/);
  const plans = ui.doc.getElementById("csa-plans").textContent;
  assert.match(plans, /Approved/);
  assert.doesNotMatch(plans, /Create the tasks/);
  assert.match(ui.doc.getElementById("csa-status").textContent, /not connected/);
  assert.doesNotMatch(ui.doc.body.textContent, /plan-1|scope-1|callback|CAS/);
});

test("proposing tasks picks a mapping and date and carries the scope version", async (t) => {
  const ui = await fixture({ forms: [{ c: "0", until: "2031-01-01" }] });
  t.after(() => ui.window.close());
  [...ui.doc.querySelectorAll("#csa-scopes button")].find((b) => b.textContent === "Propose tasks").click();
  await ui.settle();
  const put = ui.calls.find((c) => c.method === "PUT");
  assert.match(put.url, /\/scopes\/scope-1\/plans\/plan-\d{8}-[a-z0-9]{6}$/);
  const body = JSON.parse(put.body);
  assert.equal(body.catalog_id, "privacy-controls");
  assert.equal(body.expected_scope_revision, 4);
});

test("creating tasks is confirmed when a task system is connected", async (t) => {
  const ui = await fixture({ canCreate: true });
  t.after(() => ui.window.close());
  [...ui.doc.querySelectorAll("#csa-plans button")].find((b) => b.textContent === "Create the tasks").click();
  await ui.settle();
  assert.equal(ui.confirms.length, 1);
  const post = ui.calls.find((c) => c.url.endsWith("/plans/plan-1/apply"));
  assert.equal(JSON.parse(post.body).expected_revision, 2);
});
