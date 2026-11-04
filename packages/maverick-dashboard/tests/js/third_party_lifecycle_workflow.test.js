"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const folder = path.resolve(__dirname, "../../maverick_dashboard");
const markup = fs.readFileSync(path.join(folder, "templates/third_party_lifecycle.html"), "utf8")
  .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "")
  .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, "")
  .replace(/{%-?[\s\S]*?-?%}/g, "")
  .replace(/{{[\s\S]*?}}/g, "");
const helpers = fs.readFileSync(path.join(folder, "static/lightwork-record-workflows.js"), "utf8");
const source = fs.readFileSync(path.join(folder, "static/lightwork-third-party-lifecycle.js"), "utf8");
const ME = "tpl-principal-" + "1".repeat(32);

function data() {
  return {
    templates: [
      { template_id: "security-review", version: 1, title_ref: "Security-review", state: "approved", revision: 2, authored_by: "tpl-principal-" + "2".repeat(32),
        questions: [{ question_id: "Do-you-encrypt-data", prompt_ref: "Do-you-encrypt-data", domain: "security", response_type: "boolean", required: true, options: [], risk_rules: [] }], updated_at: 2 },
      { template_id: "privacy", version: 1, title_ref: "Privacy-check", state: "pending_approval", revision: 1, authored_by: "tpl-principal-" + "2".repeat(32), questions: [], updated_at: 1 },
    ],
    assessments: [
      { assessment_id: "assessment-1", vendor_ref: "vend-acme", template_id: "security-review", template_version: 1, owner_ref: ME,
        assignments: { "Do-you-encrypt-data": ME }, responses: {}, tasks: [], route: "not_evaluated", highest_severity: null, recommendations: [], revision: 3, updated_at: 5 },
    ],
    lifecycles: [{ lifecycle_id: "lc-1", vendor_ref: "vend-acme", owner_ref: ME, stage: "onboarding", dependencies: [{ dependency_id: "dep-1", kind: "system", reference: "Payroll-system" }], offboarding_plan_id: null, revision: 1, updated_at: 3 }],
    plans: [],
  };
}

async function fixture({ admin = true, intercept = () => undefined } = {}) {
  const dom = new JSDOM(markup, { url: "https://lightwork.example/third-party/lifecycle", runScripts: "outside-only" });
  const { window } = dom;
  const root = window.document.getElementById("tpl-root");
  root.setAttribute("data-api", "/api/v1/third-party/lifecycle");
  root.setAttribute("data-can-admin", admin ? "true" : "false");
  root.setAttribute("data-can-audit", "true");
  const ui = { answer: true, confirms: [], forms: [], formValues: [], calls: [] };
  window.mvConfirm = async (m) => { ui.confirms.push(m); return ui.answer; };
  window.mvForm = async (title, fields) => { ui.forms.push({ title, fields }); return ui.formValues.shift() || null; };
  window.mvErrorText = (f, a) => "Could not " + a + ".";
  window.mvReveal = (element) => { element.hidden = false; };
  window.HTMLElement.prototype.scrollIntoView = () => {};
  const d = data();
  window.fetch = async (url, opts = {}) => {
    const call = { url: new URL(url, window.location), method: opts.method || "GET", body: opts.body && typeof opts.body === "string" ? JSON.parse(opts.body) : null };
    ui.calls.push(call);
    let reply = await intercept(call);
    const p = call.url.pathname;
    if (reply === undefined) {
      if (p.endsWith("/people")) reply = { me: ME, named_signin: true, local_owner_setup_available: false, items: [{ value: ME, label: "Me" }] };
      else if (p === "/api/v1/vendors") reply = { vendors: [{ id: "vend-acme", name: "Acme Corp" }] };
      else if (p.endsWith("/lifecycle/templates")) reply = { items: d.templates };
      else if (p.endsWith("/lifecycle/assessments")) reply = { items: d.assessments };
      else if (p.endsWith("/lifecycle/lifecycles")) reply = { items: d.lifecycles };
      else if (p.endsWith("/lifecycle/offboarding")) reply = { items: d.plans };
      else if (p.endsWith("/compliance/fingerprint")) reply = { sha256: "f".repeat(64), size: 3 };
      else reply = { ok: true };
    }
    return new Response(JSON.stringify(reply), { status: reply.__status || 200, headers: { "Content-Type": "application/json" } });
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

test("records load on arrival as tables with plain words and row buttons", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  const templates = ui.el("tpl-templates").textContent;
  assert.match(templates, /Security review/);
  assert.match(templates, /Waiting for approval/);
  assert.ok(ui.rowButton("tpl-templates", "Privacy check", "Approve"));
  assert.equal(ui.rowButton("tpl-templates", "Security review", "Approve"), undefined);
  assert.match(ui.el("tpl-assessments").textContent, /Acme Corp/);
  assert.match(ui.el("tpl-assessments").textContent, /Not checked yet/);
  assert.match(ui.el("tpl-lifecycles").textContent, /Payroll system/);
  assert.match(ui.el("tpl-offboarding").textContent, /No vendors are being offboarded/);
  assert.doesNotMatch(ui.document.body.textContent, /tpl-principal|not_evaluated|pending_approval|vend-acme/);
});

test("non-administrators do not get approval or suspension buttons", async (t) => {
  const ui = await fixture({ admin: false }); t.after(() => ui.window.close());
  assert.equal(ui.rowButton("tpl-templates", "Privacy check", "Approve"), undefined);
  assert.equal(ui.rowButton("tpl-lifecycles", "Acme", "Suspend"), undefined);
  assert.ok(ui.rowButton("tpl-lifecycles", "Acme", "Mark active"));
});

test("local shared access explains the named reviewer path and offers no approval", async (t) => {
  const ui = await fixture({ intercept: (c) => c.url.pathname.endsWith("/people")
    ? { me: ME, named_signin: false, local_owner_setup_available: true, items: [{ value: ME, label: "Me" }] }
    : undefined });
  t.after(() => ui.window.close());
  assert.equal(ui.el("tpl-new-template").disabled, true);
  assert.equal(ui.rowButton("tpl-templates", "Privacy check", "Approve"), undefined);
  assert.equal(ui.el("tpl-reviewer-guidance").hidden, false);
  assert.equal(ui.el("tpl-signin-link").getAttribute("href"), "/auth/local-owner");
  assert.match(ui.el("tpl-reviewer-message").textContent, /two people with their own sign-ins/);
});

test("an author cannot see their own approval and gets an invite path", async (t) => {
  const own = { ...data().templates[1], authored_by: ME };
  const ui = await fixture({ intercept: (c) => c.url.pathname.endsWith("/lifecycle/templates") ? { items: [own] } : undefined });
  t.after(() => ui.window.close());
  assert.equal(ui.rowButton("tpl-templates", "Privacy check", "Approve"), undefined);
  assert.match(ui.el("tpl-templates").textContent, /Another administrator must approve/);
  assert.equal(ui.el("tpl-invite-link").hidden, false);
  assert.equal(ui.el("tpl-invite-link").getAttribute("href"), "/users");
});

test("approving carries the row version and a generated request key after a confirmation", async (t) => {
  // Approval first reads the exact current version and shows it in full.
  const current = { ...data().templates[1], mitigation_rules: [], retained_until: 9 };
  const ui = await fixture({ intercept: (c) => c.method === "GET" && c.url.pathname.endsWith("/templates/privacy/versions/1") ? current : undefined });
  t.after(() => ui.window.close());
  ui.rowButton("tpl-templates", "Privacy check", "Approve").click();
  await ui.settle();
  assert.equal(ui.confirms.length, 1);
  assert.match(ui.confirms[0], /Privacy check · version 1/);
  assert.match(ui.confirms[0], /Approve this exact questionnaire for assessments\?/);
  const call = ui.calls.find((c) => c.url.pathname.endsWith("/templates/privacy/versions/1/approve"));
  assert.equal(call.method, "POST");
  assert.equal(call.body.expected_revision, 1);
  assert.ok(call.body.idempotency_key.length >= 8);
});

test("a questionnaire is written in words and saved as questions", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  ui.el("tpl-new-template").click();
  const form = ui.el("tpl-template-form");
  form.querySelector('[name="title"]').value = "Vendor basics";
  const q = form.querySelector(".tpl-question");
  q.querySelector('[name="prompt"]').value = "Do you have a security policy?";
  q.querySelector('[name="flag_when"]').value = "No";
  q.querySelector('[name="fix"]').value = "Ask for their policy";
  form.dispatchEvent(new ui.window.Event("submit", { cancelable: true }));
  await ui.settle();
  const call = ui.calls.find((c) => c.method === "PUT" && c.url.pathname.includes("/templates/"));
  assert.equal(call.url.pathname, "/api/v1/third-party/lifecycle/templates/vendor-basics");
  assert.equal(call.body.expected_latest_version, 0);
  assert.equal(call.body.title_ref, "Vendor-basics");
  assert.equal(call.body.questions[0].prompt_ref, "Do-you-have-a-security-policy");
  assert.equal(call.body.questions[0].response_type, "boolean");
  assert.deepEqual(call.body.questions[0].risk_rules[0].value, false);
  assert.equal(call.body.mitigation_rules[0].task_code, "task.Ask-for-their-policy");
});

test("answering records the chosen value with a server fingerprint of the note", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  ui.rowButton("tpl-assessments", "Acme", "Open").click();
  await ui.settle();
  ui.formValues.push({ value: "yes", note: "Encryption policy v3", attach: false });
  ui.rowButton("tpl-assessment-detail", "Do you encrypt data", "Answer").click();
  await ui.settle();
  const put = ui.calls.find((c) => c.method === "PUT" && c.url.pathname.includes("/responses/"));
  assert.equal(put.body.value, true);
  assert.equal(put.body.evidence_sha256, "f".repeat(64));
  assert.deepEqual(put.body.evidence_refs, ["note.Encryption-policy-v3"]);
  assert.equal(put.body.expected_revision, 3);
  assert.ok(ui.calls.some((c) => c.url.pathname === "/api/v1/compliance/fingerprint"));
});

test("a failed load is a plain sentence", async (t) => {
  const ui = await fixture({ intercept: (c) => c.url.pathname.endsWith("/templates") ? { __status: 503 } : undefined });
  t.after(() => ui.window.close());
  assert.equal(ui.el("tpl-status").textContent, "Could not load the lifecycle records.");
});
