"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const source = fs.readFileSync(
  path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-ops-jobs.js"), "utf8");

function fixture(answers, { confirm = true } = {}) {
  const dom = new JSDOM(`<button id="go">Go</button><p id="status"></p><div id="out"></div>`,
    { url: "https://lightwork.example/learning", runScripts: "outside-only" });
  const { window } = dom;
  shell(window);
  const calls = [];
  window.mvErrorText = (failure, action) => `Could not ${action}.`;
  window.mvPlainDetail = (d) => (typeof d === "string" && /^[A-Z].*\.$/.test(d) ? d : "");
  window.mvConfirm = async (message) => { calls.push({ confirm: message }); return confirm; };
  window.fetch = async (url, init = {}) => {
    calls.push({ url, method: init.method || "GET", body: init.body || null });
    const next = answers[url] && answers[url].length ? answers[url].shift() : { __status: 404, detail: "Gone." };
    const status = next.__status || 200;
    return new Response(JSON.stringify(next), { status, headers: { "Content-Type": "application/json" } });
  };
  window.setTimeout = (fn) => { fn(); return 0; };
  window.eval(source);
  const settle = async () => { for (let i = 0; i < 60; i++) await new Promise((done) => setImmediate(done)); };
  return { window, doc: window.document, calls, settle };
}

// Replies carry the job reference the client checks: a 16-character id and a kind.
const STARTED = { job: { id: "0123456789abcdef", kind: "probe", state: "running", can_stop: true } };  // pragma: allowlist secret
const POLL = "/api/v1/learning-ops/jobs/0123456789abcdef";  // pragma: allowlist secret

test("a job is polled until it finishes and its result is shown", async (t) => {
  const ui = fixture({
    "/start": [STARTED],
    [POLL]: [{ job: { id: "0123456789abcdef", kind: "probe", state: "done", can_stop: false, result: { n: 3 } } }],  // pragma: allowlist secret
  });
  t.after(() => ui.window.close());
  const J = ui.window.LWJobs;
  J.wire(ui.doc.getElementById("go"), async () => ({ url: "/start", init: { method: "POST", json: {} } }),
    { status: ui.doc.getElementById("status"), out: ui.doc.getElementById("out"), action: "do it",
      render: (r) => J.el("p", null, "Counted " + r.n) });
  ui.doc.getElementById("go").click();
  await ui.settle();
  assert.equal(ui.doc.getElementById("status").textContent, "Finished.");
  assert.equal(ui.doc.getElementById("out").textContent, "Counted 3");
});

test("stop asks first, then calls the stop route", async (t) => {
  const ui = fixture({ "/start": [STARTED], [POLL]: [] });
  t.after(() => ui.window.close());
  const J = ui.window.LWJobs;
  const status = ui.doc.getElementById("status");
  J.follow(STARTED.job, { status, out: ui.doc.getElementById("out"), action: "do it" });
  const stop = status.querySelector("button");
  assert.equal(stop.textContent, "Stop");
  stop.click();
  await ui.settle();
  assert.match(ui.calls.find((c) => c.confirm).confirm, /keeps what it has already done/);
  assert.ok(ui.calls.some((c) => c.method === "POST" && c.url === POLL + "/stop"));
});

test("a refusal to start shows the server's plain sentence", async (t) => {
  const ui = fixture({ "/start": [{ __status: 409, detail: "This is already running." }] });
  t.after(() => ui.window.close());
  const J = ui.window.LWJobs;
  const status = ui.doc.getElementById("status");
  await J.run("/start", { method: "POST", json: {} }, { status, out: ui.doc.getElementById("out"), action: "do it" });
  // The refusal is the server's plain sentence, then how to check before trying again.
  assert.equal(status.textContent, "This is already running. Read recorded tasks before deciding what to do next. "
    + "Work is never repeated automatically. Open recorded tasks");
  assert.equal(status.querySelector("a").getAttribute("href"), "/learning#lo-jobs-panel");
});

test("a failed job shows its plain problem and no result", async (t) => {
  const ui = fixture({ "/start": [{ job: { id: "fedcba9876543210", kind: "probe", state: "failed", problem: "It reached its spending limit and stopped." } }] });
  t.after(() => ui.window.close());
  const J = ui.window.LWJobs;
  const status = ui.doc.getElementById("status");
  await J.run("/start", { method: "POST", json: {} }, { status, out: ui.doc.getElementById("out"), action: "do it",
    render: () => J.el("p", null, "should not render") });
  assert.equal(status.textContent, "It reached its spending limit and stopped.");
  assert.equal(ui.doc.getElementById("out").textContent, "");
});
