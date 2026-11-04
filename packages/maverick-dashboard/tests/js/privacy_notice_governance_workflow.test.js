"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const dir = path.resolve(__dirname, "../../maverick_dashboard");
const helpers = fs.readFileSync(path.join(dir, "static/lightwork-record-workflows.js"), "utf8");
const source = fs.readFileSync(path.join(dir, "static/lightwork-privacy-notice-governance.js"), "utf8");
// The protected version save lives with the accepted-update controls.
const versions = fs.readFileSync(path.join(dir, "static/lightwork-privacy-notice-proposals.js"), "utf8");
const template = fs.readFileSync(path.join(dir, "templates/privacy_notice_governance.html"), "utf8");
let app = template.slice(template.indexOf('<div id="png-app"'), template.indexOf('<details class="panel" id="png-technical">'));
app = app.replace(/{% for code, name in jurisdictions %}[\s\S]*?{% endfor %}/g, '<label><input type="checkbox" name="jurisdiction" value="eu"> European Union</label>')
  .replace(/{% for code, name in languages %}[\s\S]*?{% endfor %}/g, '<label><input type="checkbox" name="locale" value="en"> English</label>')
  .replace(/{%[\s\S]*?%}/g, "").replace(/{{[\s\S]*?}}/g, "true");
const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { "Content-Type": "application/json" } });
const records = {
  policies: [{ policy_id: "standard-approval", required_roles: ["privacy", "legal"], quorum: 2, approval_ttl_seconds: 2592000, revision: 1 }],
  releases: [{ notice_id: "website-privacy-notice", version: 2, property_id: "main-website", state: "review", required_roles: ["privacy", "legal"], quorum: 2,
    release_sha256: "d".repeat(64), revision: 4, effective_from: 1.9e9, retained_until: 2.1e9 }],
  approvals: [{ notice_id: "website-privacy-notice", version: 2, role: "privacy", revoked: false, revision: 1 }],
  proposals: [], records: [], queue: { pending: 1 },
};

async function fixture(forms = []) {
  const dom = new JSDOM(`<main>${app}</main>`, { url: "https://lightwork.example/privacy/notices", runScripts: "outside-only" });
  const { window } = dom;
  const calls = [], confirms = [];
  window.mvConfirm = async (m) => { confirms.push(m); return true; };
  window.mvForm = async (title, fields) => { const v = forms.shift(); if (v && v.__fields) v.__fields(fields); return v; };
  window.mvErrorText = (f, a) => `Could not ${a}.`;
  window.HTMLElement.prototype.scrollIntoView = () => {};
  window.fetch = async (url, opts = {}) => {
    calls.push({ url, ...opts });
    if (url.endsWith("/records")) return json(records);
    return json({});
  };
  shell(window);
  window.eval(helpers);
  window.eval(source);
  window.eval(versions);
  const settle = async () => { for (let i = 0; i < 30; i++) await new Promise((d) => setImmediate(d)); };
  await settle();
  return { window, doc: window.document, calls, confirms, settle };
}

test("versions list with approval progress and plain status", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  const text = ui.doc.getElementById("png-releases").textContent;
  assert.match(text, /Website privacy notice/);
  assert.match(text, /Waiting for approval/);
  assert.match(text, /Privacy \(1 of 2\)/);
  assert.match(ui.doc.getElementById("png-sched").textContent, /1 update\(s\) waiting/);
  assert.doesNotMatch(ui.doc.body.textContent, /dddddddd|website-privacy-notice|revision/);
});

test("approving offers only the roles still missing and carries the fingerprint and version", async (t) => {
  let offered;
  const ui = await fixture([{ role: "legal", __fields: (f) => { offered = f[0].options.map((o) => o.value); } }]);
  t.after(() => ui.window.close());
  [...ui.doc.querySelectorAll("#png-releases button")].find((b) => b.textContent === "Approve").click();
  await ui.settle();
  assert.deepEqual(JSON.parse(JSON.stringify(offered)), ["legal"]);
  const post = ui.calls.find((c) => c.url.endsWith("/versions/2/approvals"));
  assert.deepEqual(JSON.parse(post.body).expected_release_sha256, "d".repeat(64));
  assert.equal(JSON.parse(post.body).expected_revision, 4);
});

test("new version form refuses to save without files or places", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  ui.doc.getElementById("png-new-version").click(); await ui.settle();
  assert.equal(ui.doc.getElementById("png-release-panel").hidden, false);
  ui.doc.getElementById("png-notice-name").value = "Website notice";
  ui.doc.getElementById("png-release-form").dispatchEvent(new ui.window.Event("submit", { cancelable: true }));
  await ui.settle();
  assert.equal(ui.doc.getElementById("png-status").textContent, "Choose jurisdictions and languages, then check the effective and keep-until dates.");
  assert.equal(ui.calls.some((c) => c.method === "PUT"), false);
});
