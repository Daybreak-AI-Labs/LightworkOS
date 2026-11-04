"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const folder = path.resolve(__dirname, "../../maverick_dashboard");
const markup = fs.readFileSync(path.join(folder, "templates/third_party_collaboration.html"), "utf8")
  .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "")
  .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, "")
  .replace(/{%-?[\s\S]*?-?%}/g, "")
  .replace(/{{[\s\S]*?}}/g, "");
const helpers = fs.readFileSync(path.join(folder, "static/lightwork-record-workflows.js"), "utf8");
const source = fs.readFileSync(path.join(folder, "static/lightwork-third-party-collaboration.js"), "utf8");
const TOKEN = "tpc1." + "A".repeat(43);

function invitation(extra = {}) {
  return Object.assign({ invitation_id: "invitation-1", vendor_ref: "vend-acme", assessment_id: "assessment-1", template_id: "security-review", template_version: 1,
    respondent_ref: "vendor-contact.vend-acme", allowed_question_ids: ["Do-you-encrypt-data"], status: "active", revision: 4, expires_at: 1767312000, legal_hold: false }, extra);
}

async function fixture({ admin = true, invitations = [invitation()], intercept = () => undefined } = {}) {
  const dom = new JSDOM(markup, { url: "https://lightwork.example/third-party/collaboration", runScripts: "outside-only" });
  const { window } = dom;
  const root = window.document.getElementById("tpc-root");
  root.setAttribute("data-api", "/api/v1/third-party/collaboration");
  root.setAttribute("data-lifecycle-api", "/api/v1/third-party/lifecycle");
  root.setAttribute("data-can-admin", admin ? "true" : "false");
  root.setAttribute("data-can-audit", "true");
  const ui = { answer: true, confirms: [], formValues: [], calls: [], copied: [], pickedFile: null };
  window.mvConfirm = async (m) => { ui.confirms.push(m); return ui.answer; };
  window.mvForm = async () => ui.formValues.shift() || null;
  window.mvCopy = (t) => ui.copied.push(t);
  window.mvErrorText = (f, a) => "Could not " + a + ".";
  window.HTMLElement.prototype.scrollIntoView = () => {};
  window.fetch = async (url, opts = {}) => {
    const call = { url: new URL(url, window.location), method: opts.method || "GET", body: opts.body && typeof opts.body === "string" ? JSON.parse(opts.body) : null };
    ui.calls.push(call);
    let reply = await intercept(call);
    const p = call.url.pathname;
    if (reply === undefined) {
      if (p.endsWith("/lifecycle/assessments")) reply = { items: [{ assessment_id: "assessment-1", vendor_ref: "vend-acme", template_id: "security-review", template_version: 1,
        assignments: { "Do-you-encrypt-data": "vendor-contact.vend-acme" }, revision: 2 }] };
      else if (p.endsWith("/lifecycle/templates")) reply = { items: [{ template_id: "security-review", version: 1, state: "approved", title_ref: "Security-review",
        questions: [{ question_id: "Do-you-encrypt-data", prompt_ref: "Do-you-encrypt-data" }] }] };
      else if (p === "/api/v1/vendors") reply = { vendors: [{ id: "vend-acme", name: "Acme Corp" }] };
      else if (p.endsWith("/sharing")) reply = { portal_path: "/api/v1/external/third-party-collaboration/portal_ref_1234567890/portal", limits: { invitation_seconds: 7 * 86400, retention_seconds: 365 * 86400, max_artifacts: 20, max_artifact_bytes: 10485760 } };
      else if (p.endsWith("/invitations") && call.method === "GET") reply = { items: invitations, next_after: null };
      else if (p.endsWith("/compliance/fingerprint")) reply = { sha256: "e".repeat(64) };
      else if (p.endsWith("/invitations") || p.endsWith("/rotate")) reply = { invitation: invitation(), token: TOKEN, token_disclosed: true };
      else reply = { ok: true };
    }
    return new Response(JSON.stringify(reply), { status: reply.__status || 200, headers: { "Content-Type": "application/json" } });
  };
  shell(window);
  window.eval(helpers);
  window.LwRecords.pickFile = async () => ui.pickedFile;
  window.eval(source);
  async function settle() { for (let i = 0; i < 40; i++) await new Promise((r) => setImmediate(r)); }
  await settle();
  const el = (id) => window.document.getElementById(id);
  const rowButton = (rowText, label) => {
    const row = [...el("tpc-invitations").querySelectorAll("tr")].find((tr) => tr.textContent.includes(rowText));
    return row && [...row.querySelectorAll("button")].find((b) => b.textContent === label);
  };
  return Object.assign(ui, { window, document: window.document, el, settle, rowButton });
}

test("invitations load with names and plain statuses, one button per next step", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  const text = ui.el("tpc-invitations").textContent;
  assert.match(text, /Acme Corp/);
  assert.match(text, /Security review/);
  assert.match(text, /Waiting for answers/);
  assert.match(text, /The vendor's contact at Acme Corp/);
  assert.ok(ui.rowButton("Acme", "Send a new link"));
  assert.ok(ui.rowButton("Acme", "Cancel invitation"));
  assert.equal(ui.rowButton("Acme", "Ask for more information"), undefined);
  assert.doesNotMatch(ui.document.body.textContent, /vend-acme|invitation-1|follow_up_required/);
});

test("inviting a vendor needs no typing and shows the access code once in a copy box", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  ui.el("tpc-invite").click();
  const form = ui.el("tpc-invite-form");
  assert.equal(form.querySelectorAll('input[name="question"]:checked').length, 1);
  ui.pickedFile = new ui.window.File(["notice"], "Vendor privacy notice.pdf");
  ui.el("tpc-notice").click();
  await ui.settle();
  form.dispatchEvent(new ui.window.Event("submit", { cancelable: true }));
  await ui.settle();
  const post = ui.calls.find((c) => c.method === "POST" && c.url.pathname.endsWith("/invitations"));
  assert.equal(post.body.assessment_id, "assessment-1");
  assert.equal(post.body.respondent_ref, "vendor-contact.vend-acme");
  assert.deepEqual(post.body.allowed_question_ids, ["Do-you-encrypt-data"]);
  assert.equal(post.body.notice_ref, "notice.Vendor-privacy-notice");
  assert.equal(post.body.notice_sha256, "e".repeat(64));
  assert.equal(post.body.expires_in_seconds, 7 * 86400);
  assert.ok(post.body.idempotency_key && post.body.invitation_id);
  const once = ui.el("tpc-once");
  assert.equal(once.hidden, false);
  const values = [...once.querySelectorAll("input")].map((i) => i.value);
  assert.ok(values.includes(TOKEN));
  assert.ok(values.some((v) => v.endsWith("/portal")));
  [...once.querySelectorAll("button")].find((b) => b.textContent === "Copy").click();
  assert.equal(ui.copied.length, 1);
  assert.doesNotMatch(once.textContent, /\{|"token"/);
});

test("cancelling asks for a reason from a list and confirms first", async (t) => {
  const ui = await fixture(); t.after(() => ui.window.close());
  ui.formValues.push({ reason: "sent-to-wrong-person" });
  ui.rowButton("Acme", "Cancel invitation").click();
  await ui.settle();
  assert.equal(ui.confirms.length, 1);
  const call = ui.calls.find((c) => c.url.pathname.endsWith("/revoke"));
  assert.deepEqual({ reason: call.body.reason_code, rev: call.body.expected_revision }, { reason: "sent-to-wrong-person", rev: 4 });
});

test("answered invitations offer a follow-up with question checkboxes", async (t) => {
  const ui = await fixture({ invitations: [invitation({ status: "finalized" })] }); t.after(() => ui.window.close());
  ui.formValues.push({ q0: true, reason: "evidence-missing" });
  ui.rowButton("Acme", "Ask for more information").click();
  await ui.settle();
  const call = ui.calls.find((c) => c.url.pathname.endsWith("/follow-up"));
  assert.deepEqual(call.body.question_ids, ["Do-you-encrypt-data"]);
});

test("non-administrators see the list without change buttons", async (t) => {
  const ui = await fixture({ admin: false }); t.after(() => ui.window.close());
  assert.equal(ui.rowButton("Acme", "Send a new link"), undefined);
  assert.equal(ui.calls.some((c) => c.url.pathname.endsWith("/sharing")), false);
});

test("a list that cannot load says so with a retry instead of staying on Loading", async (t) => {
  let down = true;
  const ui = await fixture({ intercept: (call) => (down && call.url.pathname.endsWith("/invitations") && call.method === "GET"
    ? { __status: 503, detail: "unavailable" } : undefined) });
  t.after(() => ui.window.close());
  const list = ui.el("tpc-invitations");
  assert.doesNotMatch(list.textContent, /Loading/);
  assert.match(list.textContent, /Invitations could not be loaded/);
  const retry = [...list.querySelectorAll("button")].find((b) => b.textContent === "Try again");
  assert.ok(retry);
  down = false; retry.click(); await ui.settle();
  assert.match(ui.el("tpc-invitations").textContent, /Acme Corp/);
});
