// Run with: node --test packages/maverick-dashboard/tests/js/governance_agents_page.test.js
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell: loadShell} = require("./_shell");

const base = path.join(__dirname, "../../maverick_dashboard");
const template = fs.readFileSync(path.join(base, "templates/governance_agents.html"), "utf8");
const source = fs.readFileSync(path.join(base, "static/lightwork-governance-agents.js"), "utf8");
const shell = template.slice(template.indexOf('<div class="ga-shell"'), template.lastIndexOf("</div>") + 6)
  .replace(/\{% for kind, title, blurb in \[[\s\S]*?\] %\}[\s\S]*?\{% endfor %\}/, "")
  .replace(/\{%[^%]*%\}/g, "").replace(/\{\{[^}]*\}\}/g, "true");

const OPS = { policy_publish: true, policy_revoke: true, analysis: true, run_read: true, review: true, execution: true,
  recovery: true, run_revoke: true, retention_purge: true, integrity: true, maintenance_readiness: false,
  maintenance_bindings: false, maintenance_custody: false, maintenance_intents: false };
const RUN = { run_id: "run-1", agent_kind: "breach_response", capability: "containment_plan", state: "pending_review",
  revision: 2, policy_id: "breach", findings: [{ finding_code: "containment_incomplete", severity: "high", confidence_bps: 8000 }],
  approvals: [], created_at: 1800000000 };
const POLICY = { policy_id: "breach", revision: 1, agent_kind: "breach_response", allowed_capabilities: ["containment_plan"],
  required_approvals: 2, execution_enabled: true, revoked: false, valid_until: 4102444800 };

function streamed(value, status = 200) {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let sent = false;
  return { ok: status < 400, status, headers: { get: () => null },
    body: { getReader: () => ({ async read() { if (sent) return { done: true }; sent = true; return { done: false, value: bytes }; }, async cancel() {} }) } };
}

function page(t, extra = "") {
  const dom = new JSDOM(`<main>${extra}${shell}</main>`, { url: "https://lightwork.test/governance-agents", runScripts: "outside-only" });
  t.after(() => dom.window.close());
  const w = dom.window;
  w.TextDecoder = TextDecoder;
  const calls = [];
  w.mvForm = async () => ({ reason: "evidence_sufficient" });
  w.mvConfirm = async () => true;
  w.fetch = async (url, options = {}) => {
    const key = (options.method || "GET") + " " + url.replace("/api/v1/governance-agents", "");
    calls.push({ key, body: options.body ? JSON.parse(options.body) : undefined });
    if (key === "GET /status") return streamed({ schema: "lightwork.governance-agent-status.v1", composition: {
      assessment: "configured_for_attempt_only", status_opened_store: false, operational_verification_performed: false,
      operations_configured_for_attempt: OPS } });
    if (key === "GET /policies") return streamed({ items: [POLICY] });
    if (key.startsWith("GET /runs")) return streamed({ items: [RUN] });
    if (key === "GET /context/preview/breach_response") return streamed({ complete: true, references: [
      { item_id: "i1", source_kind: "incident", source_ref: "gcx:1", source_revision: 3 }] });
    if (key.endsWith("/review")) return streamed({ ...RUN, revision: 3 });
    if (key.endsWith("/analysis")) return streamed({ ...RUN, run_id: "run-2" });
    return streamed({ detail: "nope" }, 404);
  };
  loadShell(w);
  w.eval(source);
  const settle = async () => { for (let i = 0; i < 40; i += 1) await new Promise((r) => setImmediate(r)); };
  return { w, calls, settle, $: (id) => w.document.getElementById(id) };
}

test("reviews and policies load as rows in plain words", async (t) => {
  const h = page(t);
  await h.settle();
  const runs = h.$("ga-runs").textContent;
  assert.match(runs, /Breach response/);
  assert.match(runs, /Containment plan/);
  assert.match(runs, /Waiting for review/);
  assert.match(runs, /0 of 2 approvals/);
  assert.doesNotMatch(runs, /run-1|pending_review|containment_plan/);
  assert.match(h.$("ga-policies").textContent, /In use/);
  assert.match(h.$("ga-missing").textContent, /readiness checks/);
});

test("approving asks for a reason and carries the review's version", async (t) => {
  const h = page(t);
  await h.settle();
  const approve = [...h.$("ga-runs").querySelectorAll("button")].find((b) => b.textContent === "Approve");
  assert.equal(approve.disabled, false);
  approve.click();
  await h.settle();
  const call = h.calls.find((c) => c.key === "POST /runs/run-1/review");
  assert.deepEqual(call.body, { expected_revision: 2, decision: "approve", rationale_code: "evidence_sufficient" });
});

test("starting a review uses the server's own record list, never typed references", async (t) => {
  const h = page(t, '<button type="button" data-op="analysis" data-start="breach_response" disabled>Start a review</button>');
  await h.settle();
  const start = h.w.document.querySelector("[data-start]");
  assert.equal(start.disabled, false);
  start.click();
  await h.settle();
  assert.equal(h.$("ga-start-panel").hidden, false);
  assert.match(h.$("ga-start-sources").textContent, /Incident \(1\)/);
  h.$("ga-start-form").dispatchEvent(new h.w.Event("submit", { cancelable: true }));
  await h.settle();
  const put = h.calls.find((c) => c.key.startsWith("PUT /runs/"));
  assert.ok(put, h.$("ga-result").textContent);
  assert.equal(put.body.policy_id, "breach");
  assert.equal(put.body.policy_revision, 1);
  assert.equal(put.body.capability, "containment_plan");
  assert.deepEqual(put.body.context, [{ item_id: "i1", source_kind: "incident", source_ref: "gcx:1", source_revision: 3 }]);
});
