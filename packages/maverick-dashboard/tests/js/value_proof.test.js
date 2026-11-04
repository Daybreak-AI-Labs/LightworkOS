"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const source = fs.readFileSync(
  path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-value-proof.js"), "utf8");

const SPEND = `<div id="vp-spend"><p id="vp-retro-summary"></p><ul id="vp-retro-advice"></ul>
<table id="vp-retro-table" hidden><tbody id="vp-retro-rows"></tbody></table>
<div id="vp-cap"></div><div id="vp-fail"></div><p id="vp-spend-msg"></p></div>`;
const PROOF = `<div id="vp-proof"><div id="vp-comp"></div><div id="vp-dept"></div><p id="vp-ea-state"></p><div id="vp-ea"></div>
<div id="vp-fleet"></div><p id="vp-rec"></p>
<p class="vp-admin" hidden><a id="vp-rec-download" href="/api/v1/value-proof/record-export">A</a>
<a id="vp-mem-download" href="/api/v1/value-proof/memory-export">B</a></p>
<form id="vp-check"><select id="vp-check-kind"><option value="record">R</option><option value="memory">M</option></select>
<input id="vp-check-file" type="file"><button type="submit">Check</button></form><div id="vp-check-result"></div>
<p id="vp-proof-msg"></p></div>`;

function answers(over) {
  return Object.assign({
    "/cost-retro": { total: 12.5, tasks: 3, failed_spend: 2.5, failed_share: 0.2, advice: ["Most spend went to one task."],
      costliest: [{ task: 7, title: "Quarterly report", cost: 9, failed: false }] },
    "/budget-tune": { minimum_tasks: 5, suggestions: [{ for: "Every task", cap: 4.5, typical_high: 3, tasks: 9 }] },
    "/failures": { recording: true, total: 3, reasons: [{ reason: "Hit a spending limit", count: 2 }, { reason: "Other error", count: 1 }] },
    "/access": { admin: true, audit: true },
    "/compounding": { task_types: [{ name: "Invoices", runs: 12, cost_change_pct: -40, success_change: 0.1, improving: true }] },
    "/departments": { departments: [] },
    "/earned-autonomy": { enabled: true, auto_grant_on: false, needs: { outcomes: 10, streak: 10, accuracy_pct: 90 },
      actions: [{ action: "send_invoice", name: "Send invoice", auto_approved: false, evidence_qualified: true, confirmed: 12, missed: 0, streak: 12 }] },
    "/fleet-memory": { enabled: true, agents: [] },
    "/record-stats": { records: 5, tasks: 3, approvals: 2, human_decisions: 2, departments: [{ name: "Finance", count: 4 }] },
    "/earned-autonomy/revoke": { revoked: true },
    "/record-verify": { intact: true, from_this_installation: true, records: 5 },
  }, over || {});
}

async function fixture(html, { over, confirm = true } = {}) {
  const dom = new JSDOM(html, { url: "https://lightwork.example/savings", runScripts: "outside-only" });
  const { window } = dom;
  shell(window);
  const calls = [];
  const table = answers(over);
  window.mvErrorText = (failure, action) => `Could not ${action}.`;
  window.mvConfirm = async (message) => { calls.push({ confirm: message }); return confirm; };
  window.fetch = async (url, init = {}) => {
    calls.push({ url, method: init.method || "GET", body: init.body ? JSON.parse(init.body) : null });
    const key = url.replace("/api/v1/value-proof", "").split("?")[0];
    const answer = table[key];
    const status = answer && answer.__status ? answer.__status : 200;
    return new Response(JSON.stringify(answer && answer.__body ? answer.__body : answer || {}),
      { status, headers: { "Content-Type": "application/json" } });
  };
  const settle = async () => { for (let i = 0; i < 40; i++) await new Promise((done) => setImmediate(done)); };
  window.eval(source);
  await settle();
  return { window, doc: window.document, calls, settle };
}

test("spend page explains where spend went, a suggested cap and failure reasons", async (t) => {
  const ui = await fixture(SPEND);
  t.after(() => ui.window.close());
  assert.match(ui.doc.getElementById("vp-retro-summary").textContent, /\$12.50 spent across 3 tasks. \$2.50 \(20%\)/);
  assert.equal(ui.doc.querySelector("#vp-retro-rows a").getAttribute("href"), "/chat/goal/7");
  assert.equal(ui.doc.getElementById("vp-retro-table").hidden, false);
  assert.match(ui.doc.getElementById("vp-cap").textContent, /Every task\$4.50/);
  assert.match(ui.doc.getElementById("vp-fail").textContent, /Hit a spending limit2/);
  assert.equal(ui.doc.querySelectorAll("#vp-fail .vp-bar").length, 2);
});

test("viewers are told who can see the costliest tasks", async (t) => {
  const ui = await fixture(SPEND, { over: { "/cost-retro": { __status: 403, __body: {} } } });
  t.after(() => ui.window.close());
  assert.equal(ui.doc.getElementById("vp-retro-summary").textContent,
    "Only administrators and auditors can see which tasks cost the most.");
});

test("savings page shows results, automatic approvals with Withdraw and the record", async (t) => {
  const ui = await fixture(PROOF);
  t.after(() => ui.window.close());
  assert.match(ui.doc.getElementById("vp-comp").textContent, /Invoices12-40%\+10%Getting cheaper/);
  assert.match(ui.doc.getElementById("vp-dept").textContent, /No department has enough tasks/);
  assert.match(ui.doc.getElementById("vp-ea").textContent, /No approval granted by evidence/);
  assert.match(ui.doc.getElementById("vp-ea-state").textContent, /10 real outcomes/);
  assert.match(ui.doc.getElementById("vp-fleet").textContent, /No outside agents/);
  assert.match(ui.doc.getElementById("vp-rec").textContent, /5 decisions on record/);
  assert.equal(ui.doc.querySelector(".vp-admin").hidden, false);
});

test("withdraw confirms, then calls the kernel route", async (t) => {
  const ui = await fixture(PROOF);
  t.after(() => ui.window.close());
  ui.doc.querySelector("#vp-ea button").click();
  await ui.settle();
  assert.ok(ui.calls.some((c) => c.confirm && /Explicit consent grants will not change/.test(c.confirm)));
  const sent = ui.calls.find((c) => c.method === "POST");
  assert.deepEqual(sent.body, { action: "send_invoice" });
  assert.match(ui.doc.getElementById("vp-proof-msg").textContent, /qualification cleared for Send invoice/);
});

test("non-admins get no withdraw buttons and no downloads", async (t) => {
  const ui = await fixture(PROOF, { over: { "/access": { admin: false, audit: false } } });
  t.after(() => ui.window.close());
  assert.equal(ui.doc.querySelectorAll("#vp-ea button").length, 0);
  assert.equal(ui.doc.querySelector(".vp-admin").hidden, true);
});

test("checking a record file reports in plain words", async (t) => {
  const ui = await fixture(PROOF);
  t.after(() => ui.window.close());
  const input = ui.doc.getElementById("vp-check-file");
  const file = new ui.window.File(['{"sig":"x"}'], "record.json", { type: "application/json" });
  Object.defineProperty(input, "files", { value: [file] });
  ui.doc.getElementById("vp-check").dispatchEvent(new ui.window.Event("submit", { cancelable: true }));
  await ui.settle();
  const sent = ui.calls.find((c) => c.method === "POST");
  assert.equal(sent.url, "/api/v1/value-proof/record-verify");
  assert.match(ui.doc.getElementById("vp-check-result").textContent, /intact and was signed by this Lightwork installation/);
});

test("a self-signed record does not claim another Lightwork installation as its origin", async (t) => {
  const ui = await fixture(PROOF, { over: { "/record-verify": {
    intact: true, from_this_installation: false, records: 1,
  } } });
  t.after(() => ui.window.close());
  const input = ui.doc.getElementById("vp-check-file");
  Object.defineProperty(input, "files", { value: [new ui.window.File(
    ['{"sig":"x"}'], "record.json", { type: "application/json" },
  )] });
  ui.doc.getElementById("vp-check").dispatchEvent(new ui.window.Event("submit", { cancelable: true }));
  await ui.settle();
  const message = ui.doc.getElementById("vp-check-result").textContent;
  assert.match(message, /who signed it has not been verified/);
  assert.doesNotMatch(message, /different Lightwork installation/);
});

test("a learning statement from another installation is checked with its key file", async (t) => {
  const html = PROOF.replace('<button type="submit">', '<input id="vp-check-key" type="file"><button type="submit">');
  const ui = await fixture(html, { over: { "/memory-verify": { intact: true, from_this_installation: false, claims: [] } } });
  t.after(() => ui.window.close());
  ui.doc.getElementById("vp-check-kind").value = "memory";
  const doc = new ui.window.File(['{"kind":"x"}'], "statement.json", { type: "application/json" });
  const key = new ui.window.File(["pubkey: " + "ab".repeat(32)], "key.txt", { type: "text/plain" });  // pragma: allowlist secret
  Object.defineProperty(ui.doc.getElementById("vp-check-file"), "files", { value: [doc] });
  Object.defineProperty(ui.doc.getElementById("vp-check-key"), "files", { value: [key] });
  ui.doc.getElementById("vp-check").dispatchEvent(new ui.window.Event("submit", { cancelable: true }));
  await ui.settle();
  const sent = ui.calls.find((c) => c.method === "POST");
  assert.equal(sent.url, "/api/v1/value-proof/memory-verify");
  assert.match(sent.body.publisher_key, /^pubkey: (ab){32}$/);
  assert.match(ui.doc.getElementById("vp-check-result").textContent, /signed by the installation whose key you gave/);
});

test("spend tuning selectors reload the suggestion with the chosen options", async (t) => {
  const html = SPEND.replace('<div id="vp-cap">', '<select id="vp-cap-fit"><option value="90">9</option><option value="95">19</option></select>' +
    '<select id="vp-cap-min"><option value="5">5</option></select><div id="vp-cap">');
  const ui = await fixture(html);
  t.after(() => ui.window.close());
  const fit = ui.doc.getElementById("vp-cap-fit");
  fit.value = "95";
  fit.dispatchEvent(new ui.window.Event("change"));
  await ui.settle();
  assert.ok(ui.calls.some((c) => c.url === "/api/v1/value-proof/budget-tune?percentile=95&min_samples=5"));
});
