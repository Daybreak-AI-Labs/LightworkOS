"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const source = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-security-hunt.js"), "utf8");
const envHtml = `<div id="hunt-root" data-hunt="environment" data-api="/api/v1/security/soc">
<strong id="hunt-open"></strong><strong id="hunt-investigations"></strong><strong id="hunt-safety"></strong>
<p id="hunt-status"></p><p id="hunt-error"></p>
<select id="soc-pull-connector"><option value="okta">Okta sign-ins</option></select><select id="soc-pull-window"><option value="3600">Last hour</option></select>
<button id="soc-pull-run">Look</button>
<select id="soc-file-connector"><option value="cloudtrail">AWS</option></select><input type="file" id="soc-file">
<div id="soc-preview" hidden><p id="soc-preview-summary"></p><table><tbody id="soc-preview-rows"></tbody></table><button id="soc-file-run">Run</button></div>
<table><tbody id="soc-custom-rows"></tbody></table><button id="soc-rule-add">Add</button><input type="file" id="soc-rule-file">
<table><tbody id="hunt-heatmap"></tbody></table><table><tbody id="hunt-findings"></tbody></table>
<table><tbody id="hunt-investigations-rows"></tbody></table><div id="hunt-detail"></div></div>
<script type="application/json" id="hunt-people">[{"value":"user:amy","label":"Amy"}]</script>`;

const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
const SUMMARY = {
  open_findings: 1, reduced_autonomy: true,
  attack_heatmap: [{ technique: "T1078", count: 1, severities: { high: 1 } }],
  findings: [{ finding_id: "f1", revision: 3, severity: "high", title: "Console login without MFA", mitre_techniques: ["T1078"],
    confidence: 0.9, status: "open", evidence: [{ source: "cloudtrail", event_id: "e1", observed_at: 1700000000, quote: "ConsoleLogin by bob" }] }],
  investigations: [{ investigation_id: "i1", revision: 2, title: "Bob's account", status: "open", timeline: [{ observed_at: 1700000000, action: "ConsoleLogin" }],
    response_proposal: { action: "disable_user" }, approval_id: 12 }]
};

async function fixture({ confirm = true, form = null } = {}) {
  const dom = new JSDOM(envHtml, { url: "https://lightwork.example/security/soc", runScripts: "outside-only" });
  const { window } = dom;
  const calls = [];
  window.mvConfirm = async () => confirm;
  window.mvForm = async () => form;
  window.mvErrorText = (failure, action) => `Could not ${action}.`;
  window.mvHuman = (v) => { const s = String(v).replace(/_/g, " "); return s.charAt(0).toUpperCase() + s.slice(1); };
  window.mvWhen = () => "14 Nov";
  window.mvToast = () => {};
  window.fetch = async (url, options = {}) => {
    calls.push({ url, ...options });
    if (url.endsWith("/summary")) return json(SUMMARY);
    if (url.endsWith("/ingest")) return json({ events_accepted: 5, findings_created: 2 });
    return json({ status: "triaged" });
  };
  const settle = async () => { for (let i = 0; i < 30; i++) await new Promise((done) => setImmediate(done)); };
  shell(window);
  window.eval(source);
  await settle();
  return { window, doc: window.document, calls, settle };
}

test("findings and investigations read in plain words", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  const findings = ui.doc.getElementById("hunt-findings").textContent;
  assert.match(findings, /Using stolen or valid accounts \(T1078\)/);
  assert.match(findings, /Very sure/);
  assert.match(findings, /1 event/);
  assert.match(ui.doc.getElementById("hunt-safety").textContent, /automatic steps paused/);
  const inv = ui.doc.getElementById("hunt-investigations-rows");
  assert.equal(inv.querySelector("a").getAttribute("href"), "/approvals#approval-12");
  assert.doesNotMatch(ui.doc.body.textContent, /false_positive|HTTP/);
});

test("marking a finding sends its status with the loaded version", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  const btn = [...ui.doc.querySelectorAll("#hunt-findings button")].find((b) => b.textContent === "Not a problem");
  btn.click(); await ui.settle();
  const call = ui.calls.find((c) => c.method === "PATCH");
  assert.equal(call.url, "/api/v1/security/soc/findings/f1");
  assert.deepEqual(JSON.parse(call.body), { changes: { status: "false_positive" }, expected_revision: 3 });
});

test("looking at a connected system sends a time window, not pasted events", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  ui.doc.getElementById("soc-pull-run").click(); await ui.settle();
  const call = ui.calls.find((c) => c.url.endsWith("/ingest"));
  const body = JSON.parse(call.body);
  assert.equal(body.connector, "okta");
  assert.ok(body.end - body.start === 3600);
  assert.equal(body.events, undefined);
  assert.match(ui.doc.getElementById("hunt-status").textContent, /5 events looked at; 2 new findings/);
});

test("a check built from the form is sent as a rule with each analysis", async (t) => {
  const ui = await fixture({ form: { title: "Test account", field: "principal", match: "equals", value: "test@acme", level: "high", technique: "T1078" } });
  t.after(() => ui.window.close());
  ui.doc.getElementById("soc-rule-add").click(); await ui.settle();
  assert.match(ui.doc.getElementById("soc-custom-rows").textContent, /Who did it is “test@acme”/);
  ui.doc.getElementById("soc-pull-run").click(); await ui.settle();
  const rule = JSON.parse(JSON.parse(ui.calls.find((c) => c.url.endsWith("/ingest")).body).sigma_rules[0]);
  assert.deepEqual(rule.detection, { selection: { principal: "test@acme" }, condition: "selection" });
  assert.deepEqual(rule.tags, ["attack.t1078"]);
});
