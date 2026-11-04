// Run with: node --test packages/maverick-dashboard/tests/js/model_risk_assurance_portal.test.js
// The /security/assurance supplier access codes: a refused load says so in
// both tables instead of leaving "Loading…" behind a closed disclosure, and a
// refused response is released so the page can go quiet.
"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {JSDOM} = require("jsdom");
const {shell} = require('./_shell');

const template = fs.readFileSync(path.join(__dirname, "../../maverick_dashboard/templates/model_risk_assurance.html"), "utf8").replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
const scripts = [...template.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(match => match[1]);
const helpers = scripts.find(source => source.includes("window.mraFailure ="));
const supplier = scripts.find(source => source.includes("const portalInvitations"))
  .replace("{{ MRA_NAMES|tojson }}", "{}").replace(/\{%[\s\S]*?%\}/g, "");

function page(t, answer) {
  const dom = new JSDOM(`<main>
    <span id="ai-vendor-portal-status" role="status"></span>
    <table><tbody id="ai-vendor-portal-invitations"><tr><td colspan="4">Loading…</td></tr></tbody></table>
    <table><tbody id="ai-vendor-portal-submissions"><tr><td colspan="4">Loading…</td></tr></tbody></table>
    <button id="ai-vendor-portal-refresh" type="button">Refresh</button></main>`,
  {url: "https://lightwork.test/security/assurance", runScripts: "outside-only"});
  t.after(() => dom.window.close());
  const w = dom.window, released = [];
  w.mvErrorText = (failure, action) => `Could not ${action}. Ask an administrator. (${failure.status})`;
  w.fetch = async url => answer(String(url), released);
  shell(w);
  w.eval(helpers);
  w.eval(supplier);
  const settle = async () => { for (let i = 0; i < 20; i += 1) await new Promise(resolve => setImmediate(resolve)); };
  return {w, released, settle, text: id => w.document.getElementById(id).textContent};
}

test("refused access-code lists say so in both tables and release the responses", async t => {
  const h = page(t, (url, released) => ({ok: false, status: 403, body: {cancel: async () => { released.push(url); }}}));
  await h.settle();
  assert.equal(h.text("ai-vendor-portal-invitations"), "Access codes could not be loaded. Refresh the page and try again.");
  assert.equal(h.text("ai-vendor-portal-submissions"), "Answers could not be loaded. Refresh the page and try again.");
  assert.equal(h.text("ai-vendor-portal-status"), "Could not load the access codes. Ask an administrator. (403)");
  assert.equal(h.released.length, 2);
});
