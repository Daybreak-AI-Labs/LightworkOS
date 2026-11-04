"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const read = (name) => fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/" + name), "utf8");
const jobs = read("lightwork-ops-jobs.js");
const workforce = read("lightwork-workforce-ops.js");

function partial(name) {
  return fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates/", name), "utf8")
    .replace(/\{#[\s\S]*?#\}/g, "").replace(/<script[\s\S]*?<\/script>/g, "");
}

function defaults(admin) {
  return {
    "/api/v1/value-proof/access": { admin: admin, audit: admin },
    "/api/v1/workforce-ops/inventory": { suites: [{ value: "finance", label: "Finance" }], specialists: 40, departments: 3,
      builders: 1, can_change_things_while_drafting: 1, sign_off_enforced: 30, sign_off_only_asked: 2, extra_refusals: 5,
      with_deliverable: 20, levels_enabled: true, independence: { observe: 1, suggest: 30, request: 8, auto: 1 }, still_supervised: 12,
      flagged: [{ specialist: "Invoice drafter", can_reach: ["send_payment"] }] },
    "/api/v1/workforce-ops/test-suite": { cases: 4, specialists: 3, problems: 0, technical: [],
      list: [{ specialist: "Payroll", task: "Run payroll", expects: ["refuses"] }] },
    "/api/v1/workforce-ops/test-suite/specialists": { specialists: [{ value: "finance_ap", label: "Accounts payable" }] },
    "/api/v1/workforce-ops/test-suite/customer": { live_enabled: true, context:"b".repeat(64), baseline_revision:"c".repeat(64), current_instructions:"Check invoices safely before approval.", cases: [{
      id: "a".repeat(32), specialist: "finance_ap", revision: 1, task: "Could these invoices be duplicates?",
      includes: ["duplicate"], excludes: ["payment sent"], refusal: false, citation: false
    }], runs: [] },
    "/api/v1/workforce-ops/test-suite/customer/run": { job: { id: "abcdef0123456789", kind: "customer_answer_check", state: "done", can_stop: false,
      result: { run: { state: "done", passed: 1, total: 1 } } } },
    "/api/v1/workforce-ops/setup-check": { job: { id: "0123456789abcdef", kind: "setup_check", state: "done", can_stop: false, result: {  // pragma: allowlist secret
      specialists: 40, must_fix: 1, could_improve: 2, more: 0, findings: [{ specialist: "Invoice drafter",
        must_fix: ["It has no limit on how risky its actions may be."], could_improve: [], technical: ["max_risk is unset"] }] } } },
    "/api/v1/workforce-ops/upcoming": { days: 30, tasks: [
      { task: 7, title: "File the return", department: "finance_vat", due: 1700000000, overdue: true, questions: 1 },
      { task: 8, title: "Renew the contract", department: "", due: 1700500000, overdue: false, questions: 0 }] },
  };
}

async function fixture(markup, { admin = true, inventory = {}, responses = {}, url = "https://lightwork.example/workforce", storage = {} } = {}) {
  const dom = new JSDOM(markup, { url, runScripts: "outside-only" });
  const { window } = dom;
  shell(window);
  Object.entries(storage).forEach(([key, value]) => window.sessionStorage.setItem(key, value));
  const calls = [];
  const table = defaults(admin);
  Object.assign(table["/api/v1/workforce-ops/inventory"], inventory);
  Object.assign(table, responses);
  window.mvErrorText = (failure, action) => `Could not ${action}.`;
  window.mvPlainDetail = () => "";
  window.mvHuman = (v) => String(v).replace(/_/g, " ");
  window.mvWhen = () => "14 Nov 2023";
  window.mvToast = (m) => calls.push({ toast: m });
  window.mvConfirm = async (m) => { calls.push({ confirm: m }); return true; };
  window.fetch = async (url, init = {}) => {
    calls.push({ url, method: init.method || "GET", body: init.body });
    const path = url.split("?")[0];
    const answer = table[path] || (path.startsWith("/api/v1/workforce-ops/test-suite/customer/run/")
      ? table["/api/v1/workforce-ops/test-suite/customer/run/*"] : null);
    return new Response(JSON.stringify(answer || {}), { status: answer ? 200 : 404, headers: { "Content-Type": "application/json" } });
  };
  const settle = async () => { for (let i = 0; i < 60; i++) await new Promise((done) => setImmediate(done)); };
  window.eval(jobs);
  window.eval(workforce);
  await settle();
  return { window, doc: window.document, calls, settle };
}

test("the inventory reads plainly and flags specialists to review", async (t) => {
  const ui = await fixture(partial("_workforce_ops.html"));
  t.after(() => ui.window.close());
  const inv = ui.doc.getElementById("wo-inv").textContent;
  assert.match(inv, /40 agents and specialists in 3 departments/);
  assert.match(inv, /1 agent or specialist that should only draft can reach tools that change things/);
  assert.match(inv, /Invoice drafter.*send payment/);
  assert.equal(ui.doc.getElementById("wo-inv-suite").options.length, 2);
  assert.equal(ui.doc.getElementById("wo-lint-run").closest("section").hidden, false);
  assert.match(ui.doc.getElementById("wo-suite").textContent, /4 tests across 3 specialists\. Every test is complete\./);
});

test("the inventory lists the independence split only when the levels are on", async (t) => {
  const on = await fixture(partial("_workforce_ops.html"));
  t.after(() => on.window.close());
  assert.match(on.doc.getElementById("wo-inv").textContent, /Independence: Watch only 1, Suggest 30, Ask before acting 8, Act on their own 1\. 12 agents and specialists still supervised/);

  const off = await fixture(partial("_workforce_ops.html"), { inventory: { levels_enabled: false } });
  t.after(() => off.window.close());
  const text = off.doc.getElementById("wo-inv").textContent;
  assert.match(text, /Independence levels are turned off, so every agent and specialist follows the same approval rules\./);
  assert.doesNotMatch(text, /Suggest 30|Ask before acting 8|still supervised/);
});

test("the setup check runs as a job and lists what to fix", async (t) => {
  const ui = await fixture(partial("_workforce_ops.html"));
  t.after(() => ui.window.close());
  ui.doc.getElementById("wo-lint-run").click();
  await ui.settle();
  const out = ui.doc.getElementById("wo-lint-out").textContent;
  assert.match(out, /Checked 40 agents and specialists: 1 problem to fix and 2 things that could be better/);
  assert.match(out, /It has no limit on how risky its actions may be/);
});

test("non-admins do not see the download or the setup check", async (t) => {
  const ui = await fixture(partial("_workforce_ops.html"), { admin: false });
  t.after(() => ui.window.close());
  assert.equal(ui.doc.getElementById("wo-inv-download").hidden, true);
  assert.equal(ui.doc.getElementById("wo-lint-run").closest("section").hidden, true);
  assert.equal(ui.doc.getElementById("wo-test-form").hidden, true);
});

test("customer can edit and run a saved specialist answer check from Workforce", async (t) => {
  const ui = await fixture(partial("_workforce_ops.html"));
  t.after(() => ui.window.close());
  const select = ui.doc.getElementById("wo-test-specialist");
  select.value = "finance_ap";
  select.dispatchEvent(new ui.window.Event("change"));
  await ui.settle();
  assert.match(ui.doc.getElementById("wo-tests-list").textContent, /Could these invoices be duplicates/);
  assert.equal(ui.doc.getElementById("wo-test-form").hidden, false);
  ui.doc.querySelector("#wo-tests-list button").click();
  assert.equal(ui.doc.getElementById("wo-test-task").value, "Could these invoices be duplicates?");
  ui.doc.getElementById("wo-test-form").dispatchEvent(new ui.window.Event("submit", {cancelable: true}));
  await ui.settle();
  const save = ui.calls.find((c) => c.url === "/api/v1/workforce-ops/test-suite/customer" && c.method === "POST");
  assert.ok(save);
  assert.equal(JSON.parse(save.body).expected_revision, 1);
  ui.doc.getElementById("wo-test-run").click();
  await ui.settle();
  const run = ui.calls.find((c) => c.url === "/api/v1/workforce-ops/test-suite/customer/run" && c.method === "POST");
  assert.match(JSON.parse(run.body).operation_id, /^[a-f0-9]{32}$/);
  assert.deepEqual(JSON.parse(run.body).case_ids, ["a".repeat(32)]);
  assert.deepEqual(JSON.parse(run.body).case_revisions, {["a".repeat(32)]: 1});
  assert.match(ui.doc.getElementById("wo-test-run-out").textContent, /1 of 1 answers passed/);
});

test("a larger saved set runs whole by default and a person can leave checks out", async (t) => {
  const cases = Array.from({length: 6}, (_, i) => ({id: String(i).repeat(32), specialist: "finance_ap",
    revision: 1, task: "Check invoice example " + i, includes: ["duplicate"], excludes: [],
    refusal: false, citation: false}));
  const ui = await fixture(partial("_workforce_ops.html"), {responses: {
    "/api/v1/workforce-ops/test-suite/customer": {live_enabled: true, cases, runs: []}
  }});
  t.after(() => ui.window.close());
  const select = ui.doc.getElementById("wo-test-specialist");
  select.value = "finance_ap";
  select.dispatchEvent(new ui.window.Event("change"));
  await ui.settle();
  const boxes = ui.doc.querySelectorAll(".wo-test-choice");
  // The whole saved set (up to 20) is chosen, so it runs before publishing.
  assert.ok(Array.from(boxes).every((box) => box.checked));
  assert.equal(ui.doc.getElementById("wo-test-run").disabled, false);
  Array.from(boxes).forEach((box) => box.click());
  assert.equal(ui.doc.getElementById("wo-test-run").disabled, true);
  assert.match(ui.doc.getElementById("wo-test-status").textContent, /Choose at least one check/);
  boxes[1].click(); boxes[3].click();
  assert.equal(ui.doc.getElementById("wo-test-run").disabled, false);
  ui.doc.getElementById("wo-test-run").click();
  await ui.settle();
  const run = ui.calls.find((c) => c.url === "/api/v1/workforce-ops/test-suite/customer/run" && c.method === "POST");
  assert.deepEqual(JSON.parse(run.body).case_ids, [cases[1].id, cases[3].id]);
  assert.deepEqual(JSON.parse(run.body).case_revisions, {[cases[1].id]: 1, [cases[3].id]: 1});
  assert.ok(ui.calls.some((c) => c.confirm && /\$0\.10 spending limit/.test(c.confirm)));
});

test("all twenty saved checks run together with a per-question spending limit", async (t) => {
  const cases = Array.from({length: 20}, (_, i) => ({id: (i < 10 ? "0" : "") + String(i).padEnd(31, "a"), specialist: "finance_ap",
    revision: 1, task: "Check invoice example " + i, includes: ["duplicate"], excludes: [],
    refusal: false, citation: false}));
  const ui = await fixture(partial("_workforce_ops.html"), {responses: {
    "/api/v1/workforce-ops/test-suite/customer": {live_enabled: true, cases, runs: []}
  }});
  t.after(() => ui.window.close());
  const select = ui.doc.getElementById("wo-test-specialist");
  select.value = "finance_ap";
  select.dispatchEvent(new ui.window.Event("change"));
  await ui.settle();
  ui.doc.getElementById("wo-test-run").click();
  await ui.settle();
  const run = ui.calls.find((c) => c.url === "/api/v1/workforce-ops/test-suite/customer/run" && c.method === "POST");
  assert.equal(JSON.parse(run.body).case_ids.length, 20);
  assert.ok(ui.calls.some((c) => c.confirm && /\$1\.00 spending limit/.test(c.confirm)));
});

test("each answer goes back to the instructions that produced it", async (t) => {
  const markup = partial("_workforce_ops.html").replace(/data-can-open-agents="[^"]*"/, 'data-can-open-agents="true"');
  const ui = await fixture(markup, {responses: {
    "/api/v1/workforce-ops/test-suite/customer": {live_enabled: true, cases: [], runs: [{
      id: "f".repeat(32), specialist: "finance_ap", state: "done", passed: 1, total: 1, model: "test-model",
      spent_dollars: 0.001, started_at: 1700000000, instructions: "Check every invoice for duplicates.",
      results: [{case_id: "a".repeat(32), task: "Two invoices match?", answer: "This is a duplicate.", passed: true}]}]}
  }});
  t.after(() => ui.window.close());
  const select = ui.doc.getElementById("wo-test-specialist");
  select.value = "finance_ap";
  select.dispatchEvent(new ui.window.Event("change"));
  await ui.settle();
  const history = ui.doc.getElementById("wo-test-history");
  const source = Array.from(history.querySelectorAll("a")).find((a) => a.textContent === "See the instructions used");
  assert.ok(source, history.innerHTML);
  const target = ui.doc.getElementById(source.getAttribute("href").slice(1));
  assert.ok(target, "the link lands on the tested instructions");
  assert.match(target.nextElementSibling.textContent, /Check every invoice for duplicates/);
  const edit = Array.from(history.querySelectorAll("a")).find((a) => a.textContent === "Edit in Agent Factory");
  assert.equal(edit.getAttribute("href"), "/agents?name=finance_ap#f-persona");
});

test("instructions handed over from Agent Factory open the comparison ready to run", async (t) => {
  const dom = partial("_workforce_ops.html");
  const ui = await fixture(dom, {url: "https://lightwork.example/workforce?specialist=finance_ap&compare=1",
    storage: {"lightwork-proposed-instructions:finance_ap": "Always name the duplicate invoice first."}});
  t.after(() => ui.window.close());
  assert.equal(ui.doc.getElementById("wo-test-specialist").value, "finance_ap");
  assert.equal(ui.doc.getElementById("wo-compare").open, true);
  assert.equal(ui.doc.getElementById("wo-compare-instructions").value, "Always name the duplicate invoice first.");
});

test("an uncertain paid check reads its original result without posting another request", async (t) => {
  const ui = await fixture(partial("_workforce_ops.html"), {responses: {
    "/api/v1/workforce-ops/test-suite/customer/run": {job: {id: "unknown-1", state: "done", can_stop: false,
      result: {run: {state: "unknown", passed: 0, total: 1, message: "Provider result uncertain."}}}},
    "/api/v1/workforce-ops/test-suite/customer/run/*": {run: {state: "unknown", passed: 0, total: 1,
      message: "Original result still uncertain."}}
  }});
  t.after(() => ui.window.close());
  const select = ui.doc.getElementById("wo-test-specialist");
  select.value = "finance_ap";
  select.dispatchEvent(new ui.window.Event("change"));
  await ui.settle();
  ui.doc.getElementById("wo-test-run").click();
  await ui.settle();
  ui.doc.getElementById("wo-test-run").click();
  await ui.settle();
  assert.equal(ui.calls.filter((c) => c.url === "/api/v1/workforce-ops/test-suite/customer/run" && c.method === "POST").length, 1);
  assert.ok(ui.calls.some((c) => c.url && c.url.startsWith("/api/v1/workforce-ops/test-suite/customer/run/") && c.method === "GET"));
  assert.match(ui.doc.getElementById("wo-test-run-status").textContent, /Original result still uncertain/);
});

test("instruction comparison reviews exact questions and recovers an uncertain request without spending again", async (t) => {
  const ui = await fixture(partial("_workforce_ops.html"), {responses:{
    "/api/v1/workforce-ops/test-suite/customer/compare":{job:{id:"compare-1", state:"done", can_stop:false,
      result:{run:{state:"unknown", total:2, passed:1, message:"Comparison outcome uncertain."}}}},
    "/api/v1/workforce-ops/test-suite/customer/run/*":{run:{state:"unknown", total:2, passed:1, message:"Original comparison result remains uncertain."}}
  }});
  t.after(() => ui.window.close());
  const select=ui.doc.getElementById("wo-test-specialist");select.value="finance_ap";select.dispatchEvent(new ui.window.Event("change"));await ui.settle();
  ui.doc.getElementById("wo-compare-instructions").value="Always check for duplicate invoices before approval.";
  const review=()=>ui.doc.getElementById("wo-compare-form").dispatchEvent(new ui.window.Event("submit",{cancelable:true}));
  review();assert.equal(ui.doc.getElementById("wo-compare-review").hidden,false);
  assert.match(ui.doc.getElementById("wo-compare-reviewed").textContent,/Current instructionsCheck invoices safely/);
  assert.equal(ui.calls.some(c=>c.url.endsWith("/compare")),false);
  const choice=ui.doc.querySelector(".wo-test-choice");choice.click();assert.equal(ui.doc.getElementById("wo-compare-review").hidden,true);
  choice.click();review();ui.doc.getElementById("wo-compare-start").click();await ui.settle();
  const submitted=ui.calls.filter(c=>c.url=== "/api/v1/workforce-ops/test-suite/customer/compare");assert.equal(submitted.length,1);
  const body=JSON.parse(submitted[0].body);assert.equal(body.baseline_revision,"c".repeat(64));assert.equal(body.expected_context,"b".repeat(64));
  assert.deepEqual(body.case_revisions,{["a".repeat(32)]:1});
  ui.doc.getElementById("wo-test-run").click();await ui.settle();
  assert.equal(ui.calls.filter(c=>c.url==="/api/v1/workforce-ops/test-suite/customer/compare").length,1);
  assert.match(ui.doc.getElementById("wo-test-run-status").textContent,/Original comparison result remains uncertain/);
});

test("tasks coming due list overdue first with links and waiting questions", async (t) => {
  const ui = await fixture(partial("_upcoming_tasks.html"));
  t.after(() => ui.window.close());
  const text = ui.doc.getElementById("wo-up").textContent;
  assert.match(text, /File the returnOverdue: 14 Nov 2023finance vat1 question/);
  assert.equal(ui.doc.querySelector("#wo-up a").getAttribute("href"), "/chat/goal/7");
  ui.doc.getElementById("wo-up-days").value = "7";
  ui.doc.getElementById("wo-up-days").dispatchEvent(new ui.window.Event("change"));
  await ui.settle();
  assert.ok(ui.calls.some((c) => c.url === "/api/v1/workforce-ops/upcoming?days=7"));
});

test("nothing coming due uses the shared empty state and offers a longer period", async (t) => {
  const markup = '<div id="mv-toasts"></div><div id="mv-toasts-alert"></div>' + partial("_upcoming_tasks.html");
  const dom = new JSDOM(markup, { url: "https://lightwork.example/goals", runScripts: "outside-only" });
  t.after(() => dom.window.close());
  const { window } = dom;
  window.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
  window.fetch = async () => new Response(JSON.stringify({ days: 30, tasks: [] }),
    { status: 200, headers: { "Content-Type": "application/json" } });
  window.eval(read("lightwork-ui.js"));
  window.eval(jobs);
  window.eval(workforce);
  const settle = async () => { for (let i = 0; i < 60; i++) await new Promise((done) => setImmediate(done)); };
  await settle();
  const empty = window.document.querySelector("#wo-up .mv-empty.mv-empty--compact");
  assert.ok(empty, "the shared empty state is shown");
  assert.equal(empty.querySelector(".mv-empty__title").textContent, "Nothing is due in the next 30 days");
  assert.match(empty.querySelector(".mv-empty__body").textContent, /Choose a longer period above/);
  window.document.getElementById("wo-up-days").value = "90";
  window.document.getElementById("wo-up-days").dispatchEvent(new window.Event("change"));
  await settle();
  assert.doesNotMatch(window.document.getElementById("wo-up").textContent, /longer period/);
});

test("tool checks are offered only when the setting is on and save each named tool", async (t) => {
  const base = defaults(true)["/api/v1/workforce-ops/test-suite/customer"];
  const ui = await fixture(partial("_workforce_ops.html"), {
    responses: { "/api/v1/workforce-ops/test-suite/customer": { ...base, tool_checks_enabled: true } } });
  t.after(() => ui.window.close());
  const select = ui.doc.getElementById("wo-test-specialist");
  select.value = "finance_ap";
  select.dispatchEvent(new ui.window.Event("change"));
  await ui.settle();
  assert.equal(ui.doc.querySelector("#wo-test-form .wo-test-tools-row").hidden, false);
  const tools = ui.doc.getElementById("wo-test-tools");
  assert.equal(ui.doc.querySelector("#wo-test-form .wo-test-tools-fields").hidden, true);
  tools.checked = true;
  tools.dispatchEvent(new ui.window.Event("change"));
  assert.equal(ui.doc.querySelector("#wo-test-form .wo-test-tools-fields").hidden, false);
  ui.doc.getElementById("wo-test-tools-called").value = "send_email | Acme\nlookup_invoice";
  ui.doc.getElementById("wo-test-tools-absent").value = "delete_record";
  ui.doc.getElementById("wo-test-tools-results").value = "lookup_invoice | Invoice 77 is a duplicate.";
  ui.doc.getElementById("wo-test-form").dispatchEvent(new ui.window.Event("submit", {cancelable: true}));
  await ui.settle();
  const save = ui.calls.find((c) => c.url === "/api/v1/workforce-ops/test-suite/customer" && c.method === "POST");
  const body = JSON.parse(save.body);
  assert.equal(body.with_tools, true);
  assert.deepEqual(body.tools_called, [{name: "send_email", contains: "Acme"}, {name: "lookup_invoice", contains: ""}]);
  assert.deepEqual(body.tools_not_called, ["delete_record"]);
  assert.deepEqual(body.tool_results, [{name: "lookup_invoice", text: "Invoice 77 is a duplicate."}]);
});

test("tool checks stay hidden while the setting is off", async (t) => {
  const ui = await fixture(partial("_workforce_ops.html"));
  t.after(() => ui.window.close());
  const select = ui.doc.getElementById("wo-test-specialist");
  select.value = "finance_ap";
  select.dispatchEvent(new ui.window.Event("change"));
  await ui.settle();
  assert.equal(ui.doc.querySelector("#wo-test-form .wo-test-tools-row").hidden, true);
});

test("a run shows each tool check in plain words and a skipped check as not run", async (t) => {
  const base = defaults(true)["/api/v1/workforce-ops/test-suite/customer"];
  const run = { id: "b".repeat(32), state: "done", started_at: 1700000000, model: "m", spent_dollars: 0, total: 2,
    passed: 0, instructions: "Check invoices.", case_snapshots: [], message: "",
    results: [
      { task: "Could these invoices be duplicates?", answer: "Duplicate.", passed: false, note: "",
        tool_checks: [{ check: "Must call send_email", passed: false, result: "Did not call send_email." }] },
      { task: "Second question", answer: "", passed: false, note: "Skipped: tool checks are turned off in All settings.", tool_checks: [] },
    ] };
  const ui = await fixture(partial("_workforce_ops.html"), {
    responses: { "/api/v1/workforce-ops/test-suite/customer": { ...base, runs: [run] } } });
  t.after(() => ui.window.close());
  const select = ui.doc.getElementById("wo-test-specialist");
  select.value = "finance_ap";
  select.dispatchEvent(new ui.window.Event("change"));
  await ui.settle();
  const history = ui.doc.getElementById("wo-test-history").textContent;
  assert.match(history, /Needs review: Did not call send_email\./);
  assert.match(history, /Not run/);
  assert.match(history, /Skipped: tool checks are turned off/);
});

test("an existing tool check is not saved with its tool lines while tool checks are off", async (t) => {
  const base = defaults(true)["/api/v1/workforce-ops/test-suite/customer"];
  const tooled = {...base.cases[0], with_tools: true, tools_called: [{name: "send_email", contains: "Acme"}],
    tools_not_called: [], tool_results: []};
  const ui = await fixture(partial("_workforce_ops.html"), {
    responses: { "/api/v1/workforce-ops/test-suite/customer": { ...base, tool_checks_enabled: false, cases: [tooled] } } });
  t.after(() => ui.window.close());
  const select = ui.doc.getElementById("wo-test-specialist");
  select.value = "finance_ap";
  select.dispatchEvent(new ui.window.Event("change"));
  await ui.settle();
  const edit = [...ui.doc.querySelectorAll("button")].find((b) => b.textContent === "Edit");
  edit.click();
  await ui.settle();
  assert.equal(ui.doc.querySelector("#wo-test-form .wo-test-tools-fields").hidden, true);
  ui.doc.getElementById("wo-test-form").dispatchEvent(new ui.window.Event("submit", {cancelable: true}));
  await ui.settle();
  assert.equal(ui.calls.filter((c) => c.method === "POST").length, 0);
  assert.match(ui.doc.getElementById("wo-test-status").textContent, /Tool checks are turned off/);
});
