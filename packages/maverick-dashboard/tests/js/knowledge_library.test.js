// Run with: node --test packages/maverick-dashboard/tests/js/knowledge_library.test.js
"use strict";
// Smoke test for the knowledge library panel (lightwork-knowledge-library.js
// on /knowledge-access): it builds the collections table, the starter list
// and the rebuild jobs with the shared el(tag, cls, text) order.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const root = path.resolve(__dirname, "../../maverick_dashboard");
const template = fs.readFileSync(path.join(root, "templates/knowledge_access.html"), "utf8");
const ui = fs.readFileSync(path.join(root, "static/lightwork-ui.js"), "utf8");
const script = fs.readFileSync(path.join(root, "static/lightwork-knowledge-library.js"), "utf8");
const start = template.indexOf('<section class="panel" id="ka-library"');
const markup = template.slice(start, template.indexOf("</section>", start) + "</section>".length);

function json(status, body) {
  return { ok: status >= 200 && status < 300, status, headers: new Map(), json: async () => body, text: async () => JSON.stringify(body) };
}
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));
const LIBRARY = {
  enabled: true,
  collections: [{ name: "policy_docs", chunks: 42 }, { name: "faq", chunks: null }],
  starter_content: [{ collection: "gdpr", title: "GDPR summary", documents: 12, loaded: true },
    { collection: "eu_ai_act", title: "EU AI Act summary", documents: 8, loaded: false }],
};
const JOBS = { context: "ctx-1", jobs: [{ job_id: "j1", collection: "policy_docs", state: "running", done: 3, count: 10,
  message: "Embedding.", observed_dollars: 0.5, unresolved_dollars: 0.25 }] };

async function page(admin, replies) {
  const html = markup.replace("{{ 'true' if knowledge_can_review else 'false' }}", admin ? "true" : "false");
  const dom = new JSDOM(`<!doctype html><body><main>${html}</main></body>`, { url: "https://lightwork.test/knowledge-access", runScripts: "outside-only" });
  const w = dom.window, calls = [];
  w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
  w.eval(ui);
  w.fetch = async (url, options) => { calls.push({ url, options }); return replies(url, options); };
  w.eval(script);
  for (let i = 0; i < 8; i += 1) await flush();
  return { w, d: w.document, calls };
}
const replies = (url) => (url.endsWith("/reindex-jobs") ? json(200, JOBS) : json(200, LIBRARY));

test("an administrator sees each collection as a row with a rebuild button, and each starter with a load button", async () => {
  const { w, d, calls } = await page(true, replies);
  assert.ok(calls.some((c) => c.url === "/api/v1/knowledge/library"));
  const rows = [...d.querySelectorAll("#ka-library-collections tr")];
  assert.equal(rows.length, 2);
  assert.equal(rows[0].querySelector("th").textContent, "Policy docs");
  assert.equal(rows[0].querySelector("th").scope, "row");
  assert.equal(rows[0].querySelectorAll("td")[0].textContent, "42");
  assert.equal(rows[1].querySelectorAll("td")[0].textContent, "—");
  const rebuild = rows[0].querySelector("button");
  assert.equal(rebuild.textContent, "Rebuild search index");
  assert.equal(rebuild.className, "btn btn--ghost");
  assert.equal(rebuild.getAttribute("aria-label"), "Rebuild the search index for Policy docs");
  const starters = [...d.querySelectorAll("#ka-library-starters li")];
  assert.equal(starters.length, 2);
  assert.match(starters[0].textContent, /^GDPR summary \(12 documents\) — loaded Load again$/);
  assert.equal(starters[1].querySelector("button").textContent, "Load");
  assert.equal(starters[1].querySelector("button").getAttribute("aria-label"), "Load: EU AI Act summary");
  assert.equal(d.getElementById("ka-library-status").textContent, "");
  const jobs = d.querySelector('[aria-label="Search index rebuilds"]');
  assert.equal(jobs.querySelector("h3").textContent, "Search index rebuilds");
  assert.equal(jobs.querySelector("h4").textContent, "Policy docs");
  assert.match(jobs.textContent, /Running: 3 of 10 passages\. Embedding\./);
  assert.equal(jobs.querySelector("progress").value, 3);
  assert.deepEqual([...jobs.querySelectorAll("button")].map((b) => b.textContent),
    ["Cancel at next safe boundary", "Continue after an interruption", "Refresh rebuild progress"]);
  w.close();
});

test("a reader sees the rows without buttons, and a turned-off library says how to turn it on", async () => {
  const reader = await page(false, replies);
  assert.equal(reader.d.querySelectorAll("#ka-library-collections tr").length, 2);
  assert.equal(reader.d.querySelectorAll("#ka-library button:not(#ka-library-refresh)").length, 0);
  assert.equal(reader.calls.some((c) => c.url.endsWith("/reindex-jobs")), false, "only administrators load rebuild jobs");
  reader.w.close();
  const off = await page(true, (url) => (url.endsWith("/reindex-jobs") ? json(200, { context: "c", jobs: [] }) : json(200, { enabled: false })));
  const status = off.d.getElementById("ka-library-status");
  assert.match(status.textContent, /^The knowledge library is turned off\. Turn it on in Settings$/);
  assert.equal(status.querySelector("a").getAttribute("href"), "/settings/all?id=knowledge_access.enable");
  off.w.close();
});

test("a failed load shows plain words, not the server's", async () => {
  const { w, d } = await page(false, () => json(500, { detail: "Traceback: KeyError 'tenant'" }));
  const text = d.getElementById("ka-library-status").textContent;
  assert.match(text, /^Could not load the knowledge library\./);
  assert.doesNotMatch(text, /Traceback|tenant|500/);
  w.close();
});
