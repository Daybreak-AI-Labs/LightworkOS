"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const dir = path.resolve(__dirname, "../../maverick_dashboard");
const helpers = fs.readFileSync(path.join(dir, "static/lightwork-record-workflows.js"), "utf8");
const source = fs.readFileSync(path.join(dir, "static/lightwork-compliance-scoping.js"), "utf8");
const template = fs.readFileSync(path.join(dir, "templates/compliance_scoping.html"), "utf8");
const app = template.slice(template.indexOf('<div id="cs-app"'), template.indexOf('<details class="panel" id="cs-technical">'))
  .replace(/{%[\s\S]*?%}/g, "").replace(/{{[\s\S]*?}}/g, "true");
const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { "Content-Type": "application/json" } });
const records = () => ({
  questionnaires: [{ questionnaire_id: "annual-scoping", version: 1, status: "published", revision: 2, questions: 9, rules: 2 }],
  assessments: [{ assessment_id: "assessment-1", questionnaire_id: "annual-scoping", questionnaire_version: 1, status: "open", answered: 0, revision: 1, retained_until: 2e9, created_at: 1.9e9 }],
  scopes: [{ scope_id: "scope-1", assessment_id: "assessment-0", status: "draft", frameworks: ["framework-eu-privacy"], controls: 2, overlaps: 0, revision: 3 }],
  reports: [],
});

async function fixture(reply, formValues = []) {
  const dom = new JSDOM(`<main>${app}</main>`, { url: "https://lightwork.example/compliance/scoping", runScripts: "outside-only" });
  const { window } = dom;
  const calls = [], confirms = [];
  window.mvConfirm = async (m) => { confirms.push(m); return true; };
  window.mvForm = async () => formValues.shift();
  window.mvErrorText = (f, a) => `Could not ${a}.`;
  window.HTMLElement.prototype.scrollIntoView = () => {};
  window.fetch = async (url, opts = {}) => {
    calls.push({ url, ...opts });
    const r = reply && reply(url, opts); if (r) return r;
    if (url.endsWith("/records")) return json(records());
    return json({});
  };
  shell(window);
  window.eval(helpers);
  window.eval(source);
  const settle = async () => { for (let i = 0; i < 30; i++) await new Promise((d) => setImmediate(d)); };
  await settle();
  return { window, doc: window.document, calls, confirms, settle };
}

test("records load into tables with a button per row and plain labels", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  const assessments = ui.doc.getElementById("cs-assessments").textContent;
  assert.match(assessments, /Annual scoping \(version 1\)/);
  assert.match(assessments, /Answer questions/);
  assert.match(assessments, /Work out scope/);
  const scopes = ui.doc.getElementById("cs-scopes").textContent;
  assert.match(scopes, /EU privacy/);
  assert.match(scopes, /Waiting for approval/);
  assert.match(scopes, /Approve/);
  assert.match(ui.doc.getElementById("cs-reports").textContent, /No reports yet/);
  assert.doesNotMatch(ui.doc.body.textContent, /assessment-1|scope-1|ref:|revision/);
});

test("starting an assessment picks a questionnaire and a date, never an ID", async (t) => {
  const ui = await fixture(null, [{ q: "0", until: "2031-01-01" }]);
  t.after(() => ui.window.close());
  ui.doc.getElementById("cs-new-assessment").click(); await ui.settle();
  const put = ui.calls.find((c) => c.method === "PUT");
  assert.match(put.url, /\/assessments\/assessment-\d{8}-[a-z0-9]{6}$/);
  const body = JSON.parse(put.body);
  assert.equal(body.questionnaire_id, "annual-scoping");
  assert.equal(body.questionnaire_version, 1);
  assert.ok(body.retained_until > 1.9e9);
  assert.ok(body.idempotency_key);
});

test("approving a scope confirms and carries the row's version", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  const approve = [...ui.doc.querySelectorAll("#cs-scopes button")].find((b) => b.textContent === "Approve");
  approve.click(); await ui.settle();
  assert.equal(ui.confirms.length, 1);
  const post = ui.calls.find((c) => c.url.endsWith("/scopes/scope-1/approve"));
  assert.equal(JSON.parse(post.body).expected_revision, 3);
});

test("errors are plain sentences", async (t) => {
  const ui = await fixture((url) => (url.endsWith("/records") ? new Response("x", { status: 500 }) : null));
  t.after(() => ui.window.close());
  assert.equal(ui.doc.getElementById("cs-status").textContent, "Could not load your records.");
});
