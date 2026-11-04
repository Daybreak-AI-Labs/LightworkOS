"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const dir = path.resolve(__dirname, "../../maverick_dashboard");
const helpers = fs.readFileSync(path.join(dir, "static/lightwork-record-workflows.js"), "utf8");
const source = fs.readFileSync(path.join(dir, "static/lightwork-privacy-rights-orchestration.js"), "utf8");
const template = fs.readFileSync(path.join(dir, "templates/privacy_rights_orchestration.html"), "utf8");
const app = template.slice(template.indexOf('<div id="pro-app"'), template.indexOf('<details class="panel" id="pro-technical">'))
  .replace(/{%[\s\S]*?%}/g, "").replace(/{{[\s\S]*?}}/g, "true");
const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { "Content-Type": "application/json" } });
const kase = { case_id: "request-1", rights: ["access", "erasure"], identity_status: "verified", status: "open", revision: 5,
  legal_hold: false, retention_blocks_deletion: false, closure_approved_by: null, created_at: 1.9e9, retained_until: 2e9 };

async function fixture(forms = [], deadLetters = []) {
  const dom = new JSDOM(`<main>${app}</main>`, { url: "https://lightwork.example/privacy/rights-orchestration", runScripts: "outside-only" });
  const { window } = dom;
  const calls = [], confirms = [];
  window.mvConfirm = async (m) => { confirms.push(m); return true; };
  window.mvForm = async () => forms.shift();
  window.mvErrorText = (f, a) => `Could not ${a}.`;
  window.fetch = async (url, opts = {}) => {
    calls.push({ url, ...opts });
    if (url.endsWith("/cases")) return json({ items: [kase] });
    if (url.endsWith("/sources")) return json({ items: [{ source_id: "company-m365", adapter_ref: "microsoft_graph_users", capabilities: ["discover"], state: "active", revision: 1 }] });
    if (url.endsWith("/work")) return json({ tasks: [{ task_id: "t1", source_id: "company-m365", phase: "delete", state: "planned", destructive: true, approved_by: null, revision: 2 }], evidence: [], manifests: [], packages: [], exports: [] });
    if (url.includes("/callbacks?state=dead_letter")) return json({ items: deadLetters, count: deadLetters.length });
    return json({});
  };
  shell(window);
  window.eval(helpers);
  window.eval(source);
  const settle = async () => { for (let i = 0; i < 30; i++) await new Promise((d) => setImmediate(d)); };
  await settle();
  return { window, doc: window.document, calls, confirms, settle };
}

test("requests list in plain words and open into step buttons", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  assert.match(ui.doc.getElementById("pro-cases").textContent, /See a copy of their data, Delete their data/);
  assert.match(ui.doc.getElementById("pro-sources").textContent, /Microsoft 365 users/);
  ui.doc.querySelector("#pro-cases button").click(); await ui.settle();
  const steps = ui.doc.getElementById("pro-case-steps").textContent;
  for (const label of ["Record identity check", "Search a system", "Check completeness", "Approve closing"]) assert.match(steps, new RegExp(label));
  assert.match(ui.doc.getElementById("pro-case-tasks").textContent, /Delete their records.*Approve deletion/);
  assert.doesNotMatch(ui.doc.body.textContent, /request-1|t1|lease|callback/);
});

test("a new request collects choices and never asks for an ID", async (t) => {
  const ui = await fixture([{ person: "jane@example.com", ticket: "T-4521", r_access: true, r_erasure: false, until: "2031-01-01" }]);
  t.after(() => ui.window.close());
  ui.doc.getElementById("pro-new-case").click(); await ui.settle();
  const put = ui.calls.find((c) => c.method === "PUT");
  assert.match(put.url, /\/cases\/request-\d{8}-[a-z0-9]{6}$/);
  const body = JSON.parse(put.body);
  assert.deepEqual(body.rights, ["access"]);
  assert.equal(body.subject_reference, "jane@example.com");
  assert.equal(body.request_version, 1);
});

test("approving a deletion asks for confirmation and carries the task version", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  ui.doc.querySelector("#pro-cases button").click(); await ui.settle();
  [...ui.doc.querySelectorAll("#pro-case-tasks button")].find((b) => b.textContent === "Approve deletion").click();
  await ui.settle();
  assert.equal(ui.confirms.length, 1);
  const post = ui.calls.find((c) => c.url.endsWith("/tasks/t1/approve-destructive"));
  assert.equal(JSON.parse(post.body).expected_revision, 2);
});

test("failed provider work shows a recovery action with the current callback version", async (t) => {
  const ui = await fixture([], [{ callback_id: "callback-1", task_id: "t1", case_id: "request-1", state: "dead_letter", revision: 9 }]);
  t.after(() => ui.window.close());
  ui.doc.querySelector("#pro-cases button").click(); await ui.settle();
  const tasks = ui.doc.getElementById("pro-case-tasks");
  assert.match(tasks.textContent, /Needs attention.*Try again/);
  assert.doesNotMatch(tasks.textContent, /Record result/);
  [...tasks.querySelectorAll("button")].find((b) => b.textContent === "Try again").click();
  await ui.settle();
  const post = ui.calls.find((c) => c.url.endsWith("/callbacks/callback-1/requeue"));
  assert.equal(JSON.parse(post.body).expected_revision, 9);
  assert.match(ui.doc.getElementById("pro-status").textContent, /may be checked again automatically/);
  assert.doesNotMatch(tasks.textContent, /callback-1|t1/);
});
