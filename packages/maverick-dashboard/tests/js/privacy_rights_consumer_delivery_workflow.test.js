"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const dir = path.resolve(__dirname, "../../maverick_dashboard");
const helpers = fs.readFileSync(path.join(dir, "static/lightwork-record-workflows.js"), "utf8");
const source = fs.readFileSync(path.join(dir, "static/lightwork-privacy-rights-consumer-delivery.js"), "utf8");
const template = fs.readFileSync(path.join(dir, "templates/privacy_rights_consumer_delivery.html"), "utf8");
const app = template.slice(template.indexOf('<div id="prcd-app"'), template.indexOf('<details class="panel" id="prcd-technical">'))
  .replace(/{%[\s\S]*?%}/g, "").replace(/{{[\s\S]*?}}/g, "true");
const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { "Content-Type": "application/json" } });

async function fixture({ ready = true, existing = null, forms = [] } = {}) {
  const dom = new JSDOM(`<main>${app}</main>`, { url: "https://lightwork.example/privacy/rights-consumer-delivery", runScripts: "outside-only" });
  const { window } = dom;
  const calls = [], confirms = [];
  window.mvConfirm = async (m) => { confirms.push(m); return true; };
  window.mvForm = async () => forms.shift();
  window.mvErrorText = (f, a) => `Could not ${a}.`;
  window.fetch = async (url, opts = {}) => {
    calls.push({ url, ...opts });
    if (url.endsWith("/status")) return json({ production_composition: { operator_mint_ready: ready } });
    if (url.endsWith("/cases")) return json({ items: [{ case_id: "request-1", rights: ["access"], status: "closed", updated_at: 1.9e9 }] });
    if (url.endsWith("/work")) return json({ packages: [{ package_id: "package-1", expires_at: 4e9 }] });
    if (url.includes("/deliveries/code-package-1-1") && (!opts.method || opts.method === "GET")) {
      return existing ? json(existing) : new Response("{}", { status: 404 });
    }
    if (url.includes("/deliveries/code-package-1-2") && (!opts.method || opts.method === "GET")) return new Response("{}", { status: 404 });
    if (url.includes("/fingerprint")) return json({ sha256: "a".repeat(64), size: 3 });
    if (opts.method === "PUT") return json({ capability: "one-time-secret-code", delivery: {} });
    return json({});
  };
  shell(window);
  window.eval(helpers);
  window.eval(source);
  const settle = async () => { for (let i = 0; i < 40; i++) await new Promise((d) => setImmediate(d)); };
  await settle();
  return { window, doc: window.document, calls, confirms, settle };
}

test("closed requests list with a create button only when codes can be created", async (t) => {
  const ui = await fixture({ ready: false });
  t.after(() => ui.window.close());
  assert.match(ui.doc.getElementById("prcd-ready").textContent, /Not ready yet/);
  assert.match(ui.doc.getElementById("prcd-packages").textContent, /See a copy of their data.*None yet/);
  assert.doesNotMatch(ui.doc.getElementById("prcd-packages").textContent, /Create download code/);
});

test("revoking the latest code confirms and carries its version", async (t) => {
  const ui = await fixture({ existing: { status: "active", revision: 3 }, forms: [{ reason: "requester-asked" }] });
  t.after(() => ui.window.close());
  [...ui.doc.querySelectorAll("#prcd-packages button")].find((b) => b.textContent === "Revoke code").click();
  await ui.settle();
  assert.equal(ui.confirms.length, 1);
  const post = ui.calls.find((c) => c.url.endsWith("/deliveries/code-package-1-1/revoke"));
  assert.deepEqual(JSON.parse(post.body).expected_revision, 3);
});

test("the page script keeps no copy of codes in browser storage", () => {
  assert.doesNotMatch(source, /localStorage|sessionStorage|indexedDB/);
});
