"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell: loadShell} = require("./_shell");

const dir = path.resolve(__dirname, "../../maverick_dashboard");
const source = fs.readFileSync(path.join(dir, "static/lightwork-regulatory-obligations.js"), "utf8");
const template = fs.readFileSync(path.join(dir, "templates/regulatory_obligations.html"), "utf8");
const content = template.split("{% block content %}")[1].split("{% endblock %}")[0]
  .replace(/{%[\s\S]*?%}/g, "").replace(/{{[\s\S]*?}}/g, "");
const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { "Content-Type": "application/json" } });
const status = {
  active_profiles: ["gdpr"], obligations: [{ regulation: "GDPR", article: "Art. 17", title: "Erasure only through the governed path", effect: "require_human", actions: ["sql_query"], deny_tools: [], min_risk: null, source_url: "https://eur-lex.europa.eu/x" }],
  library: [{ key: "gdpr", regulation: "GDPR", obligations: 3, active: true }, { key: "hipaa", regulation: "HIPAA", obligations: 1, active: false }],
  verification: { inspected: 3, problems: [], sound: true },
};

async function fixture(canAdmin, reply) {
  const dom = new JSDOM(content, { url: "https://lightwork.example/compliance/obligations", runScripts: "outside-only" });
  const { window } = dom;
  window.document.getElementById("rob-root").dataset.canAdmin = canAdmin ? "true" : "false";
  window.document.getElementById("rob-root").dataset.apiBase = "/api/v1/regulatory";
  const calls = [], confirms = [];
  window.mvConfirm = async (m) => { confirms.push(m); return true; };
  window.mvHuman = (v) => { const s = String(v).replace(/_/g, " "); return s.charAt(0).toUpperCase() + s.slice(1); };
  window.mvErrorText = (f, a) => `Could not ${a}.`;
  window.HTMLElement.prototype.scrollIntoView = () => {};
  window.fetch = async (url, opts = {}) => {
    calls.push({ url, ...opts });
    const r = reply && reply(url, opts); if (r) return r;
    if (url.endsWith("/status")) return json(status);
    if (url.endsWith("/tools")) return json({ items: ["sql_query", "send_email"] });
    if (url.endsWith("/check")) return json({ action: "sql_query", profiles: ["gdpr"], classified: true, risk: "high", decision: "require_human", attenuated: false, obligation: { regulation: "GDPR", article: "Art. 17" } });
    if (url.includes("ai-regulatory-feed")) return new Response("{}", { status: 403 });
    return json({});
  };
  loadShell(window);
  window.eval(source);
  const settle = async () => { for (let i = 0; i < 25; i++) await new Promise((d) => setImmediate(d)); };
  await settle();
  return { window, doc: window.document, calls, confirms, settle };
}

test("actions are chosen from a list and verdicts read as plain words", async (t) => {
  const ui = await fixture(false);
  t.after(() => ui.window.close());
  const select = ui.doc.getElementById("rob-action");
  assert.deepEqual([...select.options].map((o) => o.textContent), ["Choose an action", "Send email", "Sql query"]);
  select.value = "sql_query";
  ui.doc.getElementById("rob-check-form").dispatchEvent(new ui.window.Event("submit", { cancelable: true }));
  await ui.settle();
  assert.equal(ui.doc.getElementById("rob-verdict").textContent, "Sql query: Needs human approval");
  assert.match(ui.doc.getElementById("rob-verdict-detail").textContent, /Risk level: High/);
  assert.match(ui.doc.getElementById("rob-rows").textContent, /Needs approval/);
  assert.doesNotMatch(ui.doc.body.textContent, /require_human|REQUIRE HUMAN/);
  assert.equal(ui.doc.querySelectorAll("#rob-library button.btn--primary").length, 0);
  assert.match(ui.doc.getElementById("rob-updates").textContent, /not turned on/);
});

test("an administrator turns a regulation on after confirming", async (t) => {
  const ui = await fixture(true, (url) => (url.endsWith("/activate") ? json({ active: true, message: "Turned on." }) : null));
  t.after(() => ui.window.close());
  const on = ui.doc.querySelector("#rob-library button.btn--primary");
  assert.equal(on.textContent, "Turn on");
  on.click(); await ui.settle();
  assert.equal(ui.confirms.length, 1);
  assert.ok(ui.calls.some((c) => c.url.endsWith("/profiles/hipaa/activate") && c.method === "POST"));
  assert.equal(ui.doc.getElementById("rob-operation-state").textContent, "Turned on.");
});
