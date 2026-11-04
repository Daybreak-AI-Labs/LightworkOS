"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const source = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-cortex.js"), "utf8");
const html = `<div id="ctx-root" data-api-base="/api/v1/cortex"
  data-source-labels='{"knowledge":"Documents","fleet":"Outside assistants\\u0027 notes"}'>
<button type="button" data-cortex-switch="fleet_memory" data-label="Outside assistants' notes">Turn on</button>
<p data-cortex-switch-msg="fleet_memory"></p>
<form id="ctx-recall-form"><textarea name="query">refund policy</textarea>
<select name="domain"><option value="">All areas</option><option value="finance" selected>Finance</option></select>
<select name="k"><option value="5" selected>Up to 5</option></select>
<input type="checkbox" name="sources" value="knowledge" checked><input type="checkbox" name="sources" value="fleet" checked>
<button id="ctx-recall-submit" type="submit">Search</button><span id="ctx-recall-state"></span></form>
<div id="ctx-result" hidden><div id="ctx-result-meta"></div><div id="ctx-denied" hidden></div><div id="ctx-hits"></div></div></div>`;

const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

function fixture({ confirm = true, respond } = {}) {
  const dom = new JSDOM(html, { url: "https://lightwork.example/cortex", runScripts: "outside-only" });
  const { window } = dom;
  const calls = [];
  let reloaded = 0;
  window.mvConfirm = async () => confirm;
  window.mvErrorText = (failure, action) => `Could not ${action}.`;
  window.mvHuman = (v) => { const s = String(v).replace(/_/g, " "); return s.charAt(0).toUpperCase() + s.slice(1); };
  window.fetch = async (url, options = {}) => { calls.push({ url, ...options }); return respond(url, options); };
  window.eval(source.replace("location.reload()", "window.__reload()"));
  window.__reload = () => { reloaded += 1; };
  return { window, document: window.document, calls, reloaded: () => reloaded };
}

test("a search shows source names and plain results, never raw keys or timings", async () => {
  const ui = fixture({ respond: () => json({
    audited: true, tenant: "acme", took_ms: 12, sources: ["knowledge", "fleet"],
    per_source: { knowledge: 1, fleet: 0 }, denied: { fleet: "not enrolled" },
    hits: [{ source: "knowledge", citation: "Refunds.pdf", kind: "document_chunk", score: 0.83, text: "<b>30 days</b>" }]
  }) });
  ui.document.getElementById("ctx-recall-form").dispatchEvent(new ui.window.Event("submit", { cancelable: true }));
  await settle(); await settle();
  const body = JSON.parse(ui.calls[0].body);
  assert.deepEqual(body, { query: "refund policy", sources: ["knowledge", "fleet"], k: 5, domain: "finance" });
  const meta = ui.document.getElementById("ctx-result-meta").textContent;
  assert.match(meta, /Recorded in the activity log/);
  assert.match(meta, /Documents: 1/);
  assert.doesNotMatch(meta, /acme|ms|hits/);
  assert.match(ui.document.getElementById("ctx-denied").textContent, /Outside assistants' notes: not enrolled/);
  const hits = ui.document.getElementById("ctx-hits");
  assert.match(hits.textContent, /Documents · 1/);
  assert.match(hits.textContent, /Match 83%/);
  assert.match(hits.textContent, /Document chunk/);
  assert.equal(hits.querySelector("b"), null);
  assert.match(ui.document.getElementById("ctx-recall-state").textContent, /1 result from 2 sources/);
});

test("a failed search uses the shared plain error text", async () => {
  const ui = fixture({ respond: () => json({ detail: [{ loc: ["body", "k"], msg: "bad" }] }, 422) });
  ui.document.getElementById("ctx-recall-form").dispatchEvent(new ui.window.Event("submit", { cancelable: true }));
  await settle(); await settle();
  assert.equal(ui.document.getElementById("ctx-recall-state").textContent, "Could not search the memory.");
});

test("turning a source on confirms first and uses the admin feature switch", async () => {
  const declined = fixture({ confirm: false, respond: () => json({}) });
  declined.document.querySelector("[data-cortex-switch]").click();
  await settle();
  assert.equal(declined.calls.length, 0);

  const ui = fixture({ respond: () => json({ section: "fleet_memory", enabled: true }) });
  ui.document.querySelector("[data-cortex-switch]").click();
  await settle(); await settle();
  assert.equal(ui.calls[0].url, "/api/v1/features/switches");
  assert.deepEqual(JSON.parse(ui.calls[0].body), { section: "fleet_memory", enabled: true });
  assert.equal(ui.reloaded(), 1);

  const locked = fixture({ respond: () => json({ detail: "x" }, 409) });
  locked.document.querySelector("[data-cortex-switch]").click();
  await settle(); await settle();
  assert.match(locked.document.querySelector("[data-cortex-switch-msg]").textContent, /controlled by your installation settings/);
});
