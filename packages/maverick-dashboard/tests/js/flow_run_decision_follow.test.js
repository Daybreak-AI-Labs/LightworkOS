"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const templates = path.resolve(__dirname, "../../maverick_dashboard/templates");
const page = fs.readFileSync(path.join(templates, "flow_run.html"), "utf8").replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
const helpers = fs.readFileSync(path.join(templates, "_dash_helpers.js"), "utf8");
const start = page.indexOf("<script>");
const end = page.indexOf("</script>", start);
// The title comes from the shared page header macro; stand in its <h1>.
const markup = page.slice(page.indexOf("{% block content %}"), start)
  .replace(/{% call hero\([\s\S]*?%}/, '<h1 id="fr-title">Flow run</h1>')
  .replace(/{%[\s\S]*?%}/g, "").replace(/{{[\s\S]*?}}/g, "x");
const script = page.slice(start + 8, end)
  .replace('{% include "_dash_helpers.js" %}', helpers)
  .replace("{{ flow_id | tojson }}", '"orders"')
  .replace("{{ run_id | tojson }}", '"run-42"');
const reply = (status, body) => ({ ok: status >= 200 && status < 300, status, json: async () => body });
const tick = () => new Promise(resolve => setImmediate(resolve));
const settle = async () => { for (let i = 0; i < 12; i += 1) await tick(); };
const card = { summary: "Pay invoice", target: { label: "Invoice 7" },
  authority: { actor: "user:owner" }, parameters: { summary: ["Pay invoice 7"] },
  consequences: {}, budget: {}, preview: { before: "Unpaid", after: "Paid" } };
const waiting = (updated, reviewOnly = false) => ({ status: "paused_approval", cursor: "gate", updated,
  nodes: {}, data: {}, approval_review_only: reviewOnly, approval_card_status: "current",
  approval_binding_sha256: "a".repeat(64), human: { approval_card: card, choices: [], form: [] } });
const finished = { status: "completed", cursor: "end", updated: 3, nodes: {}, data: {} };

async function mount(runs, post, { stream = false, refresh = null } = {}) {
  const dom = new JSDOM("<!doctype html><body>" + markup + "</body>",
    { url: "http://localhost/flows/orders/runs/run-42", runScripts: "outside-only" });
  const calls = [], timers = [];
  let reads = 0, events;
  dom.window.setTimeout = fn => { timers.push(fn); return timers.length; };
  if (stream) dom.window.EventSource = class {
    constructor() { events = {}; }
    addEventListener(name, listener) { events[name] = listener; }
    close() {}
  };
  dom.window.fetch = async (url, options = {}) => {
    const method = options.method || "GET";
    calls.push({ url, method, body: options.body });
    if (method === "POST") return post();
    if (url.endsWith("/approval-refresh") && refresh) return reply(200, refresh);
    if (url === "/api/v1/flows/orders") return reply(200, {
      id: "orders", name: "Orders", start: "gate", nodes: [{ id: "gate", kind: "approval" }] });
    if (url === "/api/v1/flows/runs/run-42") return reply(200, runs[Math.min(reads++, runs.length - 1)]);
    // The run page reads its saved inputs and data as bounded, versioned pages.
    if (url.startsWith("/api/v1/flows/runs/run-42/values?")) return new Response(JSON.stringify({
      version: "d".repeat(64), context: "e".repeat(64), kind: "object", children: [], total: 0, remaining: 0, next: null }),
      { headers: { "Content-Type": "application/json" } });
    return reply(404, {});
  };
  dom.window.mvConfirm = async () => true;
  dom.window.eval(script);
  await settle();
  const document = dom.window.document;
  return {
    dom, calls, timers,
    status: () => document.getElementById("fr-status").textContent,
    message: () => document.getElementById("fr-msg").textContent,
    buttons: () => [...document.querySelectorAll("#fr-actions button")],
    snapshot: run => events.snapshot({ data: JSON.stringify(run) }),
    async drain() {
      for (let n = 0; timers.length && n < 100; n += 1) { timers.shift()(); await settle(); }
    },
  };
}

test("approval submits once and follows the actual run after queued reads", async () => {
  const ui = await mount([waiting(1), waiting(1), waiting(1),
    { status: "resuming", cursor: "gate", updated: 2, nodes: {}, data: {} }, finished],
  () => reply(200, { status: "resuming" }));
  const approve = ui.buttons().find(button => button.textContent === "Approve");
  approve.click(); approve.click();
  assert.equal(approve.disabled, true);
  await settle();
  assert.equal(ui.calls.filter(call => call.method === "POST").length, 1);
  assert.equal(ui.buttons().length, 0, "queued approval must not offer a second vote");
  await ui.drain();
  assert.equal(ui.status(), "Finished");
  ui.dom.window.close();
});

test("a refused approval restores the decision controls", async () => {
  const ui = await mount([waiting(1)], () => reply(409, { detail: "The request changed; review it again." }));
  ui.buttons().find(button => button.textContent === "Approve").click();
  await settle();
  assert.match(ui.message(), /request changed/i);
  assert.equal(ui.buttons().find(button => button.textContent === "Approve").disabled, false);
  ui.dom.window.close();
});

test("an expired open-ended review can be renewed once without retrying the workflow", async () => {
  const expired = {...waiting(1), approval_card_status: "expired", approval_binding_sha256: "", human: {}};
  const ui = await mount([expired, waiting(2)], () => reply(200, {status: "ready", message: "The fresh review is ready."}),
    {refresh: {binding: "b".repeat(64), summary: "Pay invoice", message: "This does not approve or repeat work."}});
  const renew = ui.buttons().find(button => button.textContent === "Request fresh review");
  assert.ok(renew);
  renew.click(); renew.click();
  await settle();
  const writes = ui.calls.filter(call => call.method === "POST");
  assert.equal(writes.length, 1);
  assert.ok(writes[0].url.endsWith("/approval-refresh"));
  assert.deepEqual(JSON.parse(writes[0].body), {binding: "b".repeat(64), confirmed: true});
  assert.ok(ui.buttons().some(button => button.textContent === "Approve"));
  assert.ok(!ui.calls.some(call => call.url.includes("/retry") || call.url.includes("/resume")));
  ui.dom.window.close();
});

test("a timed-out or assigned approval offers no renewal that could extend its deadline", async () => {
  for (const changed of [{resume_at: 1234}, {approval_review_only: true}]) {
    const run = {...waiting(1), approval_card_status: "expired", ...changed};
    const ui = await mount([run], () => assert.fail("must not submit"));
    assert.ok(!ui.buttons().some(button => button.textContent === "Request fresh review"));
    ui.dom.window.close();
  }
});

test("an assigned reviewer never sees the old vote return from a stale stream snapshot", async () => {
  const run = waiting(1, true);
  const ui = await mount([run], () => reply(200, { status: "resuming" }), { stream: true });
  ui.snapshot(run);
  ui.buttons().find(button => button.textContent === "Approve").click();
  await settle();
  ui.snapshot(run);
  assert.equal(ui.status(), "Decision recorded");
  assert.equal(ui.buttons().length, 0);
  assert.match(ui.dom.window.document.getElementById("fr-actions").textContent, /Back to Approvals/);
  ui.dom.window.close();
});
