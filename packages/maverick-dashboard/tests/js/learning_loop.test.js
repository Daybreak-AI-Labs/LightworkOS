"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const source = fs.readFileSync(
  path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-learning-loop.js"), "utf8");
const jobsSource = fs.readFileSync(
  path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-ops-jobs.js"), "utf8");
const passesSource = fs.readFileSync(
  path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-learning-passes.js"), "utf8");
// The reviewed learning pass ("run now") is its own partial on the Learned page.
const passesMarkup = fs.readFileSync(
  path.resolve(__dirname, "../../maverick_dashboard/templates/_learning_passes.html"), "utf8")
  .replace(/<style[\s\S]*?<\/style>|<script[\s\S]*?<\/script>/g, "");
const CONTEXT = "c".repeat(64);
const PASS = "0123456789abcdef0123456789abcdef";  // pragma: allowlist secret

function page(admin) {
  return `<div id="llp-root" data-admin="${admin ? 1 : 0}">
<p id="llp-ref-state"></p><table><tbody id="llp-ref-rows"></tbody></table><ul id="llp-in-force"></ul>
${admin ? `<details id="llp-propose-box"><form id="llp-propose">
<select name="target"><option value="prompt">Standing instructions</option></select>
<input name="title"><textarea name="failure"></textarea><textarea name="change"></textarea><textarea name="rationale"></textarea>
<button type="submit">Suggest this change</button></form></details>` : ""}
<p id="llp-ref-msg"></p>
<select id="llp-model"></select>
<table><tbody id="llp-eff-rows"></tbody></table><ul id="llp-conf"></ul>
<select id="llp-support"><option value="3">3</option><option value="5">5</option></select><button id="llp-preview-btn">Show</button><div id="llp-preview"></div>
<ol id="llp-log"></ol><button id="llp-holdout-btn">Check</button><div id="llp-holdout"></div>
${admin ? `<input type="checkbox" id="llp-quality-remove"><button id="llp-quality-btn">Quality</button>
<p id="llp-cost">Both use the evaluation spending limit.</p><p id="llp-run-status"></p>${passesMarkup}` : ""}
<div id="llp-run-result"></div><p id="llp-harness-msg"></p></div>`;
}

const PENDING = { id: "0123456789abcdef", status: "pending", target: "Standing instructions", title: "Check quote approval",
  failure: "Emailed too early", change: "Confirm the quote first", rationale: "Three blocked tasks",
  approval: "Approved", can_apply: true, can_revert: false, proposed_at: 1700000000,
  technical: { reference: "0123456789abcdef", approval_number: 7, fingerprint: "abcdef0123456789" } };
const PASS_DONE = { context: CONTEXT, operation: PASS, message: "The original learning pass finished. Nothing was repeated.",
  job: { state: "done", worker_available: false }, result: { spent: 0.4, reports: [{ Model: "Claude X", "New lessons adopted": 1 }] } };
const APPLIED = Object.assign({}, PENDING, { id: "fedcba9876543210", status: "applied", can_apply: false, can_revert: true, applied_at: 1700000100 });

function defaults() {
  return {
    "/refinements": { context: CONTEXT, can_manage: true, decisions: [], holds: [],
      enabled: true, require_approval: true, proposals: [PENDING, APPLIED],
      in_force: [{ target: "Standing instructions", title: "Check quote approval", change: "Confirm the quote first", applied_at: 1700000100 }] },
    "/models": { enabled: true, models: [{ value: "claude-x", label: "Claude X" }] },
    "/efficacy": { lessons: [{ text: "always cite", department: "", scope_label: "All work",
      token: "a".repeat(64), went_well: 3, did_not: 1, rate: 0.75, recent_rate: null }] },
    "/conflicts": { pairs: [{ model: "claude-x", first: "always cite", second: "never cite" }] },
    "/log": { events: [{ when: 1700000000, what: "Learned a new lesson", model: "claude-x", lesson: "always cite" }] },
    "/preview": { enabled: true, weaknesses: [{ pattern: "forgot totals", times: 4, kind: "wrong answer", would_add: "check totals" }], scanned: 9, eligible: 5 },
    "/holdout": { configured: true, verified: true, events: 12, checks_used: 3, technical: { ledger: "L1", latest_fingerprint: "ab" } },
    "/passes/current": { context: CONTEXT, revision: "p".repeat(64), requests: [],
      models: [{ value: "claude-x", label: "Claude X" }, { value: "worker-y", label: "Worker Y" }] },
    "/passes/review": { context: CONTEXT, operation: PASS, token: "sealed:pass",
      review: [{ label: "Models", after: "Claude X" }, { label: "Spending limit", after: "$5.00 for testing" }] },
    "/passes/start": PASS_DONE,
    ["/passes/requests/" + PASS]: PASS_DONE,
    "/corpus-quality": { job: { id: "1123456789abcdef", kind: "corpus_quality", state: "done", can_stop: false, result: {  // pragma: allowlist secret
      configured: true, removed: 1, cases: [{ task: "easy task", useful: false, baseline_rate: 1 }] } } },
    "/api/v1/learning-ops/self-harness/plan": { spending_limit: 5, checker: "Claude Checker", careful_testing: true },
    "/refinements/0123456789abcdef/review": { context: CONTEXT, title: "Check quote approval",  // pragma: allowlist secret
      revision: "a".repeat(64), source_revision: "s".repeat(64), review_expires_at: 1700000600,
      changes: [{title: "Check quote approval", before: "", after: "Confirm the quote first"}] },
    "/refinements/fedcba9876543210/review": { context: CONTEXT, title: "Check quote approval",  // pragma: allowlist secret
      revision: "b".repeat(64), source_revision: "s".repeat(64), review_expires_at: 1700000600,
      changes: [{title: "Check quote approval", before: "Confirm the quote first", after: ""},
                {title: "Later change", before: "Check deadlines", after: ""}] },
    "/refinements/0123456789abcdef/apply": { receipt: { status: "confirmed",  // pragma: allowlist secret
      message: "Change applied. Agents follow it on new tasks." } },
  };
}

async function fixture({ admin = true, answers = {}, confirm = true } = {}) {
  const dom = new JSDOM(page(admin), { url: "https://lightwork.example/learned", runScripts: "outside-only" });
  const { window } = dom;
  shell(window);
  const calls = [];
  const table = Object.assign(defaults(), answers);
  window.mvErrorText = (failure, action) => `Could not ${action}.`;
  window.mvHuman = (v) => String(v).replace(/_/g, " ");
  window.mvWhen = () => "14 Nov 2023";
  window.mvConfirm = async (message) => { calls.push({ confirm: message }); return confirm; };
  window.fetch = async (url, init = {}) => {
    const method = init.method || "GET";
    calls.push({ url, method, body: init.body ? JSON.parse(init.body) : null });
    const key = Object.keys(table).sort((a, b) => b.length - a.length)
      .find((k) => url.replace("/api/v1/learning-loop", "").split("?")[0] === k);
    let answer = table[key];
    if (method === "POST" && !key) answer = {};
    const status = answer && answer.__status ? answer.__status : 200;
    return new Response(JSON.stringify(answer && answer.__body ? answer.__body : answer || {}),
      { status, headers: { "Content-Type": "application/json" } });
  };
  const settle = async () => { for (let i = 0; i < 40; i++) await new Promise((done) => setImmediate(done)); };
  window.eval(jobsSource);
  window.eval(source);
  if (admin) window.eval(passesSource);
  await settle();
  return { window, doc: window.document, calls, settle };
}

test("suggested changes list in plain words with apply and undo for admins", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  const rows = ui.doc.getElementById("llp-ref-rows");
  assert.match(rows.textContent, /Check quote approval/);
  assert.match(rows.textContent, /Emailed too early/);
  assert.match(rows.textContent, /In use since 14 Nov 2023/);
  const labels = Array.from(rows.querySelectorAll("button")).map((b) => b.textContent);
  assert.deepEqual(labels, ["Apply", "Undo"]);
  // The reference number only appears inside the collapsed technical details.
  const tech = rows.querySelector("details");
  assert.equal(tech.querySelector("summary").textContent, "Technical details");
  assert.match(ui.doc.getElementById("llp-in-force").textContent, /Confirm the quote first/);
});

test("viewers get no buttons", async (t) => {
  const ui = await fixture({ admin: false });
  t.after(() => ui.window.close());
  assert.equal(ui.doc.querySelectorAll("#llp-ref-rows button").length, 0);
});

test("apply shows the before and after while asking", async (t) => {
  const ui = await fixture({ confirm: false });
  t.after(() => ui.window.close());
  ui.doc.querySelector("#llp-ref-rows button").click();
  await ui.settle();
  assert.match(ui.doc.getElementById("llp-ref-rows").textContent, /Current instructions: \(nothing for this\)/);
  assert.match(ui.doc.getElementById("llp-ref-rows").textContent, /After applying: Confirm the quote first/);
  assert.equal(ui.calls.filter((c) => c.method === "POST").length, 0);
});

test("apply previews, confirms, then calls the apply route", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  ui.doc.querySelector("#llp-ref-rows button").click();
  await ui.settle();
  const previewAt = ui.calls.findIndex((c) => c.url === "/api/v1/learning-loop/refinements/0123456789abcdef/review?context=" + CONTEXT);  // pragma: allowlist secret
  const confirmAt = ui.calls.findIndex((c) => c.confirm && /restore point/.test(c.confirm));
  assert.ok(previewAt >= 0 && confirmAt > previewAt);
  assert.ok(ui.calls.some((c) => c.method === "POST" && c.url === "/api/v1/learning-loop/refinements/0123456789abcdef/apply"));  // pragma: allowlist secret
  const sent = ui.calls.find((c) => c.method === "POST").body;
  assert.match(sent.operation_id, /^[a-f0-9]{32}$/, "the original request carries its own id, so it is never repeated");
  assert.deepEqual(Object.assign({}, sent, { operation_id: "x" }), { revision: "a".repeat(64), confirm: true, context: CONTEXT,
    source_revision: "s".repeat(64), operation_id: "x", review_expires_at: 1700000600 });
  assert.match(ui.doc.getElementById("llp-ref-msg").textContent, /Change applied/);
});

test("declining the undo confirmation sends nothing", async (t) => {
  const ui = await fixture({ confirm: false });
  t.after(() => ui.window.close());
  ui.doc.querySelectorAll("#llp-ref-rows button")[1].click();
  await ui.settle();
  assert.equal(ui.calls.filter((c) => c.method === "POST").length, 0);
});

test("a refusal shows the server's plain sentence", async (t) => {
  const ui = await fixture({ answers: { "/refinements/0123456789abcdef/apply": { __status: 409,  // pragma: allowlist secret
    __body: { detail: "This change is still waiting for approval." } } } });
  t.after(() => ui.window.close());
  ui.doc.querySelector("#llp-ref-rows button").click();
  await ui.settle();
  assert.equal(ui.doc.getElementById("llp-ref-msg").textContent, "This change is still waiting for approval.");
});

test("suggesting a change sends the form fields", async (t) => {
  const ui = await fixture({ answers: { "/refinements_post": {} } });
  t.after(() => ui.window.close());
  const form = ui.doc.getElementById("llp-propose");
  form.querySelector("[name=title]").value = "Check totals";
  form.querySelector("[name=failure]").value = "Wrong totals";
  form.querySelector("[name=change]").value = "Add the totals twice";
  form.querySelector("[name=rationale]").value = "Totals were wrong";
  form.dispatchEvent(new ui.window.Event("submit", { cancelable: true }));
  await ui.settle();
  const sent = ui.calls.find((c) => c.method === "POST");
  assert.equal(sent.url, "/api/v1/learning-loop/refinements");
  assert.deepEqual(sent.body, { target: "prompt", title: "Check totals", failure: "Wrong totals",
    change: "Add the totals twice", rationale: "Totals were wrong" });
});

test("read-outs render lesson results, clashes and the activity timeline", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  assert.equal(ui.doc.getElementById("llp-model").value, "claude-x");
  assert.match(ui.doc.getElementById("llp-eff-rows").textContent, /always cite.*3.*1.*75%/);
  assert.match(ui.doc.getElementById("llp-conf").textContent, /may contradict/);
  assert.match(ui.doc.getElementById("llp-log").textContent, /14 Nov 2023: Learned a new lesson/);
});

test("an administrator can withdraw the exact reviewed lesson from Learned", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  const action = ui.doc.querySelector("#llp-eff-rows details");
  assert.ok(action);
  action.querySelector("textarea").value = "It conflicts with our current policy.";
  action.querySelector("button").click();
  await ui.settle();
  const sent = ui.calls.find((c) => c.url === "/api/v1/learning-loop/lessons/withdraw");
  assert.deepEqual(sent.body, { model_id: "claude-x", token: "a".repeat(64),
    reason: "It conflicts with our current policy.", confirm: true });
  assert.match(ui.doc.getElementById("llp-harness-msg").textContent, /Lesson removed/);
});

test("a viewer has no withdrawal control and a declined confirmation sends nothing", async (t) => {
  const viewer = await fixture({ admin: false });
  t.after(() => viewer.window.close());
  assert.equal(viewer.doc.querySelector("#llp-eff-rows details"), null);
  const admin = await fixture({ confirm: false });
  t.after(() => admin.window.close());
  const action = admin.doc.querySelector("#llp-eff-rows details");
  action.querySelector("textarea").value = "It conflicts with our current policy.";
  action.querySelector("button").click();
  await admin.settle();
  assert.equal(admin.calls.filter((c) => c.url === "/api/v1/learning-loop/lessons/withdraw").length, 0);
});

test("preview and hold-out check explain results in sentences", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  ui.doc.getElementById("llp-preview-btn").click();
  ui.doc.getElementById("llp-holdout-btn").click();
  await ui.settle();
  assert.match(ui.doc.getElementById("llp-preview").textContent, /Seen 4 times: forgot totals/);
  assert.match(ui.doc.getElementById("llp-preview").textContent, /Nothing was changed/);
  assert.match(ui.doc.getElementById("llp-holdout").textContent, /The stored history checks match: 12 entries, 3 test uses recorded\./);
  assert.match(ui.doc.getElementById("llp-holdout").textContent, /does not establish independent custody/);
});

test("an auditor-only read-out explains who can see it", async (t) => {
  const ui = await fixture({ admin: false, answers: { "/log": { __status: 403, __body: {} } } });
  t.after(() => ui.window.close());
  assert.equal(ui.doc.getElementById("llp-log").textContent, "Only administrators and auditors can see the learning activity.");
});

test("a learning pass is reviewed in full, started once and summarised", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  assert.match(ui.doc.getElementById("llp-cost").textContent, /up to \$5\.00/);
  assert.match(ui.doc.getElementById("llp-cost").textContent, /Claude Checker/);
  ui.doc.getElementById("lp-review").click();
  await ui.settle();
  const reviewed = ui.calls.find((c) => c.url === "/api/v1/learning-loop/passes/review");
  assert.deepEqual(reviewed.body, { context: CONTEXT, revision: "p".repeat(64), scope: "main", model_id: "", trial: false, retire: true, instructions: "" });
  const preview = ui.doc.getElementById("lp-preview");
  assert.match(preview.textContent, /Review this learning pass.*Spending limit\$5\.00 for testing/s);
  const run = Array.from(preview.querySelectorAll("button")).find((b) => /Run reviewed learning pass/.test(b.textContent));
  assert.equal(run.disabled, true, "nothing starts before the review is ticked");
  const tick = preview.querySelector('input[type="checkbox"]');
  tick.checked = true;
  tick.dispatchEvent(new ui.window.Event("change"));
  run.click();
  await ui.settle();
  const starts = ui.calls.filter((c) => c.url === "/api/v1/learning-loop/passes/start");
  assert.equal(starts.length, 1);
  assert.deepEqual(starts[0].body, { token: "sealed:pass", confirm: true });
  assert.match(ui.doc.getElementById("lp-result").textContent, /New lessons adopted: 1/);
  assert.match(ui.doc.getElementById("lp-status").textContent, /No automatic retry is made/);
});

test("undo lists the later changes it also removes", async (t) => {
  const ui = await fixture({ confirm: false });
  t.after(() => ui.window.close());
  ui.doc.querySelectorAll("#llp-ref-rows button")[1].click();
  await ui.settle();
  const confirm = ui.calls.find((c) => c.confirm);
  assert.match(confirm.confirm, /earlier instructions may return and later changes may be removed/);
  assert.match(ui.doc.getElementById("llp-ref-rows").textContent, /Later change/);
  assert.match(ui.doc.getElementById("llp-ref-rows").textContent, /Current instructions: Check deadlines.*After restoring: \(removed\)/);
});

test("removing weak test cases asks first and sends the confirmation", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  ui.doc.getElementById("llp-quality-remove").checked = true;
  ui.doc.getElementById("llp-quality-btn").click();
  await ui.settle();
  const confirm = ui.calls.find((c) => c.confirm);
  assert.match(confirm.confirm, /remove the ones that are too easy/);
  const sent = ui.calls.find((c) => c.method === "POST");
  assert.deepEqual(sent.body, { model_id: "claude-x", remove_weak: true, confirm: true });
  assert.match(ui.doc.getElementById("llp-run-result").textContent, /Removed 1 test case/);
});

test("a pass for the chosen model sends that model; the preview sends the threshold", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  ui.doc.getElementById("llp-support").value = "5";
  ui.doc.getElementById("llp-preview-btn").click();
  ui.doc.getElementById("lp-scope").value = "chosen";
  ui.doc.getElementById("lp-scope").dispatchEvent(new ui.window.Event("input"));
  ui.doc.getElementById("lp-model").value = "worker-y";
  ui.doc.getElementById("lp-review").click();
  await ui.settle();
  assert.ok(ui.calls.some((c) => c.url === "/api/v1/learning-loop/preview?min_support=5&model_id=claude-x"));
  const reviewed = ui.calls.find((c) => c.url === "/api/v1/learning-loop/passes/review");
  assert.equal(reviewed.body.scope, "chosen");
  assert.equal(reviewed.body.model_id, "worker-y");
});
