"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const dir = path.resolve(__dirname, "../../maverick_dashboard");
const helpers = fs.readFileSync(path.join(dir, "static/lightwork-record-workflows.js"), "utf8");
const source = fs.readFileSync(path.join(dir, "static/lightwork-privacy-regulatory-intelligence.js"), "utf8");
let template = fs.readFileSync(path.join(dir, "templates/privacy_regulatory_intelligence.html"), "utf8");
template = template.slice(template.indexOf('<div id="pri-app"'), template.lastIndexOf("<script"))
  .replace(/{% for code, name in places %}[\s\S]*?{% endfor %}/g, '<label><input type="checkbox" name="pri-where" value="US-CA"> California</label><label><input type="checkbox" name="pri-where" value="EU"> European Union</label><label><input type="checkbox" name="pri-src-where" value="EU"> European Union</label>')
  .replace(/{% for code, name in [a-z_]+ %}[\s\S]*?{% endfor %}/g, "")
  .replace(/{%[\s\S]*?%}/g, "").replace(/{{[\s\S]*?}}/g, "true");
const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { "Content-Type": "application/json" } });

async function fixture(reply) {
  const dom = new JSDOM(`<main>${template}</main>`, { url: "https://lightwork.example/privacy/regulatory-intelligence", runScripts: "outside-only" });
  const { window } = dom;
  const calls = [], confirms = [];
  window.mvConfirm = async (m) => { confirms.push(m); return true; };
  window.mvForm = async () => null;
  window.mvErrorText = (f, a) => `Could not ${a}.`;
  window.HTMLElement.prototype.scrollIntoView = () => {};
  window.fetch = async (url, opts = {}) => {
    calls.push({ url, ...opts });
    const r = reply && reply(url, opts); if (r) return r;
    if (url.endsWith("/sources")) return json({ items: [{ source_id: "eu-journal", name: "EU official journal", jurisdictions: ["EU"], state: "pending", revision: 1 }] });
    if (url.endsWith("/records")) return json({ documents: [], trackers: [], reports: [] });
    return json({});
  };
  shell(window);
  window.eval(helpers);
  window.eval(source);
  const settle = async () => { for (let i = 0; i < 30; i++) await new Promise((d) => setImmediate(d)); };
  await settle();
  return { window, doc: window.document, calls, confirms, settle };
}

test("sources list with review buttons and places in plain words", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  const text = ui.doc.getElementById("pri-sources").textContent;
  assert.match(text, /EU official journal/);
  assert.match(text, /European Union/);
  assert.match(text, /Waiting for approval/);
  assert.match(text, /Approve use/);
});

test("an answer shows numbered sources and a plain abstention", async (t) => {
  const ui = await fixture((url) => url.endsWith("/research")
    ? json({ status: "grounded", answer: "Within 45 days.", citations: [{ title: "Section 1798.130", uri: "https://law.example/1", pinpoint: "(a)(2)" }] })
    : null);
  t.after(() => ui.window.close());
  ui.doc.getElementById("pri-question").value = "How long to answer?";
  ui.doc.querySelector('input[name="pri-where"][value="US-CA"]').checked = true;
  ui.doc.getElementById("pri-research").dispatchEvent(new ui.window.Event("submit", { cancelable: true }));
  await ui.settle();
  const body = JSON.parse(ui.calls.find((c) => c.url.endsWith("/research")).body);
  assert.deepEqual(body.jurisdictions, ["US-CA"]);
  const out = ui.doc.getElementById("pri-answer");
  assert.match(out.textContent, /Within 45 days\./);
  assert.equal(out.querySelectorAll("ol li").length, 1);
  assert.match(out.textContent, /not legal advice/);
});

test("comparing needs two ticked places", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  ui.doc.getElementById("pri-question").value = "Access timing";
  const submit = new ui.window.Event("submit", { cancelable: true });
  submit.submitter = { value: "compare" };
  ui.doc.getElementById("pri-research").dispatchEvent(submit);
  await ui.settle();
  assert.equal(ui.doc.getElementById("pri-status").textContent, "Tick at least two places to compare.");
});
