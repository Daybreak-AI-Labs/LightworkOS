"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const source = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-compliance.js"), "utf8");
// Retention periods are filled by their own script on the same page.
const retentionSource = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-retention-maintenance.js"), "utf8");
const html = `<div id="cmp-status"></div>
<button type="button" data-cmp-switch="signed_audit" data-cmp-confirm="Sign it?">Turn on</button>
<button type="button" data-cmp-halt>Stop</button>
<select id="cmp-person"></select><button id="cmp-export">Download</button><button id="cmp-erase">Erase</button>
<p id="cmp-people-result"></p>
<form id="cmp-retention-form"><select id="cmp-ret-audit_days" name="audit_days"><option value="">Keep</option></select></form>
<button id="cmp-retention-save">Save</button><button id="cmp-retention-apply">Apply</button><p id="cmp-retention-result"></p>
<select id="cmp-assessment"></select><button id="cmp-oscal">OSCAL</button><button id="cmp-soa">SoA</button><p id="cmp-assessment-result"></p>
<button id="cmp-ai-act">Run</button><div id="cmp-ai-act-result"></div>
<form id="cmp-finder"><input id="cmp-finder-q"><button type="submit">Search</button></form><div id="cmp-finder-result"></div>`;

const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });

async function fixture({ confirm = true, reply } = {}) {
  const dom = new JSDOM(html, { url: "https://lightwork.example/compliance", runScripts: "outside-only" });
  const { window } = dom;
  shell(window);
  const calls = [];
  const confirms = [];
  window.mvConfirm = async (message) => { confirms.push(message); return confirm; };
  window.mvErrorText = (failure, action) => `Could not ${action}.`;
  window.URL.createObjectURL = () => "blob:x";
  window.URL.revokeObjectURL = () => {};
  window.fetch = async (url, options = {}) => {
    calls.push({ url, ...options });
    if (reply) { const r = reply(url, options); if (r) return r; }
    if (url.endsWith("/people")) return json({ people: [{ channel: "slack", user: "U1", channel_label: "Slack", person: "U1", conversations: 2 }] });
    if (url.endsWith("/retention")) return json({ fields: [{ key: "audit_days", label: "Activity record", days: 365 }], choices: [30, 365] });
    if (url.endsWith("/assessments")) return json({ assessments: [] });
    if (url.includes("/people/erase")) return json({ erased: true, message: "Erased 2 conversation(s) and everything linked to them." });
    if (url.includes("/people/export")) return new Response("{}", { status: 200 });
    if (url.includes("/switches/")) return json({ saved: true, active: false, message: "Saved. It takes effect after Lightwork restarts." });
    if (url.includes("/ai-act")) return json({ notice_on: true, default_level: "Limited risk.", banned_uses: ["A"], high_risk_uses: ["B"], duties: [], note: "" });
    if (url.includes("/control-finder")) return json({ controls: [] });
    return json({});
  };
  const settle = async () => { for (let i = 0; i < 20; i++) await new Promise((done) => setImmediate(done)); };
  window.eval(source);
  window.eval(retentionSource);
  await settle();
  return { window, doc: window.document, calls, confirms, settle };
}

test("people and retention load into selectors on page load", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  const person = ui.doc.getElementById("cmp-person");
  assert.equal(person.options.length, 2);
  assert.match(person.options[1].textContent, /U1 \(Slack, 2 conversations\)/);
  assert.equal(ui.doc.getElementById("cmp-ret-audit_days").value, "365");
  assert.match(ui.doc.getElementById("cmp-assessment-result").textContent, /Start an assessment/);
});

test("erase needs a chosen person and a confirmation", async (t) => {
  const ui = await fixture({ confirm: false });
  t.after(() => ui.window.close());
  ui.doc.getElementById("cmp-erase").click(); await ui.settle();
  assert.match(ui.doc.getElementById("cmp-people-result").textContent, /Choose a person first/);
  ui.doc.getElementById("cmp-person").value = "1";
  ui.doc.getElementById("cmp-erase").click(); await ui.settle();
  assert.equal(ui.confirms.length, 1);
  assert.equal(ui.calls.some((c) => c.url.includes("/people/erase")), false);
});

test("confirmed erase posts the chosen person and shows a plain result", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  ui.doc.getElementById("cmp-person").value = "1";
  ui.doc.getElementById("cmp-erase").click(); await ui.settle();
  const call = ui.calls.find((c) => c.url.includes("/people/erase"));
  assert.deepEqual(JSON.parse(call.body), { channel: "slack", user: "U1" });
  assert.match(ui.doc.getElementById("cmp-people-result").textContent, /Erased 2 conversation/);
});

test("a protection switch confirms, posts and reports in plain words", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  ui.doc.querySelector("[data-cmp-switch]").click(); await ui.settle();
  assert.deepEqual(ui.confirms, ["Sign it?"]);
  assert.ok(ui.calls.some((c) => c.url.endsWith("/switches/signed_audit") && c.method === "POST"));
  assert.match(ui.doc.getElementById("cmp-status").textContent, /takes effect after Lightwork restarts/);
});

test("failures never show status codes", async (t) => {
  const ui = await fixture({ reply: (url) => (url.includes("/switches/") ? new Response("boom", { status: 500 }) : null) });
  t.after(() => ui.window.close());
  ui.doc.querySelector("[data-cmp-switch]").click(); await ui.settle();
  const text = ui.doc.getElementById("cmp-status").textContent;
  assert.equal(text, "Could not turn this protection on.");
  assert.doesNotMatch(text, /500|HTTP/);
});

test("a save that an installation policy overrides says so instead of a generic failure", async (t) => {
  // The periods are saved, then a 409 explains the override in {message, effective};
  // only string details were shown, so the admin was told retention was unavailable.
  const ui = await fixture({ reply: (url, options) => (url.endsWith("/retention") && options.method === "POST")
    ? json({ detail: { message: "The saved preference is overridden by installation policy. Effective periods have not changed; ask your installation administrator.", effective: {} } }, 409)
    : null });
  t.after(() => ui.window.close());
  ui.doc.getElementById("cmp-retention-save").click();
  await ui.settle();
  const shown = ui.doc.getElementById("cmp-retention-result").textContent;
  assert.match(shown, /overridden by installation policy/);
  assert.doesNotMatch(shown, /Retention is unavailable/);
});
