// Run with: node --test packages/maverick-dashboard/tests/js/ai_evidence_analysis_client.test.js
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { JSDOM: ShellDOM } = require("jsdom");
const { shell } = require("./_shell");

function client(response) {
  const elements = new Map();
  function element(id) {
    if (!elements.has(id)) {
      elements.set(id, {
        id,
        value: "",
        files: [],
        checked: false,
        disabled: false,
        dataset: {},
        textContent: "",
        addEventListener() {},
      });
    }
    return elements.get(id);
  }
  // The shell's helpers (mvFetchJSON) send through this window's fetch.
  const shellWindow = shell(new ShellDOM("", { url: "https://lightwork.test/ai-evidence-analysis", runScripts: "outside-only" }).window);
  shellWindow.fetch = async () => response;
  const context = {
    console,
    window: shellWindow,
    document: {
      getElementById(id) { return id === "evidence-shell" ? null : element(id); },
    },
    fetch: async () => response,
  };
  vm.createContext(context);
  const source = fs.readFileSync(
    path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-ai-evidence-analysis.js"),
    "utf8",
  );
  vm.runInContext(source, context, { filename: "lightwork-ai-evidence-analysis.js" });
  return () => vm.runInContext('apiRequest("/probe")', context);
}

test("malformed 2xx evidence response rejects generically without echoing its body", async () => {
  const secret = "private-evidence-response-content";
  const request = client({
    ok: true,
    status: 200,
    async json() { throw new Error(secret); },
  });

  await assert.rejects(request(), (error) => {
    assert.equal(error.message, "Lightwork returned something unexpected. Refresh the page and try again.");
    assert.equal(error.message.includes(secret), false);
    assert.equal(error.status, 0, "nothing confirmed");
    return true;
  });
});

test("a server refusal becomes a plain sentence and keeps the detail only as technical text", async () => {
  const request = client({
    ok: false,
    status: 409,
    async json() { return { detail: "Evidence revision conflict." }; },
  });

  await assert.rejects(request(), (error) => {
    assert.match(error.message, /changed since you opened it/);
    assert.equal(error.message.includes("Evidence revision conflict"), false);
    assert.equal(error.technical, "Evidence revision conflict.");
    assert.equal(error.status, 409);
    return true;
  });
});


// ---- page behaviour (jsdom) -------------------------------------------
const { JSDOM } = require("jsdom");
const { webcrypto } = require("node:crypto");
const pageTemplate = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates/ai_evidence_analysis.html"), "utf8");
const pageSource = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-ai-evidence-analysis.js"), "utf8");
const pageBody = pageTemplate.slice(pageTemplate.indexOf('<div class="evidence-workbench"'), pageTemplate.lastIndexOf("{% endblock %}", pageTemplate.indexOf("{% block scripts_extra %}")))
  .replace("{{ api_base }}", "/api/v1/ai-evidence-analysis")
  .replace(/\{\{\s*hero\([^}]*\}\}/, "").replace(/\{%[^%]*%\}/g, "").replace(/\{\{[^}]*\}\}/g, "true");
const RAW = new TextEncoder().encode("evidence text");
const RAW_SHA = require("node:crypto").createHash("sha256").update(Buffer.from(RAW)).digest("hex");
const ARTIFACT = { artifact_id: "supplier-contract-pdf." + RAW_SHA.slice(0, 8), case_ref: "supplier-review", media_type: "text/plain", content_sha256: RAW_SHA,
  byte_length: RAW.byteLength, source_ref: "direct-upload", source_revision: 1, acquired_at: 1800000000, authority_sha256: "a".repeat(64), registry_revision: 1 };
const CRITERIA = { criteria_set_id: "access-controls", revision: 2, criterion_ids: ["criterion-access"], authority_sha256: "b".repeat(64), registry_revision: 1 };
const RECORD = { analysis_id: "EVA-1", status: "pending_review", revision: 3, artifact: { artifact_id: ARTIFACT.artifact_id },
  criteria: { criteria_set_id: "access-controls" }, summary: { total_criteria: 1, evidence_supported: 1 },
  justification: { score_bps: 8000, maximum_bps: 10000 }, findings: [{ criterion_id: "criterion-access", disposition: "evidence_supported", confidence_bps: 9100 }],
  gaps: [], human_review: {}, created_at: 1800000100 };

function page(t) {
  const dom = new JSDOM(`<main>${pageBody}</main>`, { url: "https://lightwork.test/ai-evidence-analysis", runScripts: "outside-only" });
  t.after(() => dom.window.close());
  const w = dom.window;
  Object.defineProperty(w, "crypto", { value: webcrypto, configurable: true });
  const calls = [];
  let confirmAnswer = true;
  w.mvConfirm = async () => confirmAnswer;
  w.fetch = async (url, options = {}) => {
    const key = (options.method || "GET") + " " + url.replace("/api/v1/ai-evidence-analysis", "");
    calls.push({ key, options });
    const json = (value, status = 200) => new Response(JSON.stringify(value), { status });
    if (key === "GET /status") return json({ ready: true, operational_composition_verified: true, external_parser_binaries_detected: { tesseract: true } });
    if (key === "GET /authorities/artifacts") return json({ items: [ARTIFACT] });
    if (key === "GET /authorities/criteria") return json({ items: [CRITERIA] });
    if (key.startsWith("GET /analyses?")) return json({ items: [RECORD], count: 1 });
    if (key.startsWith("GET /retention/due")) return json({ count: 0, analysis_ids: [] });
    if (key === "POST /analyses") return json({ ...RECORD, analysis_id: "EVA-2" }, 201);
    if (key.endsWith("/review")) return json({ ...RECORD, status: "review_approved", revision: 4 });
    return json({ detail: "not found" }, 404);
  };
  shell(w);
  w.eval(pageSource);
  const settle = async () => { for (let i = 0; i < 40; i += 1) await new Promise((r) => setImmediate(r)); };
  return { w, calls, settle, setConfirm: (v) => { confirmAnswer = v; }, $: (id) => w.document.getElementById(id) };
}

test("the page lists analyses and offers documents and criteria as choices", async (t) => {
  const h = page(t);
  await h.settle();
  const rows = h.$("analyses-rows").textContent;
  assert.match(rows, /Supplier contract pdf/i);
  assert.match(rows, /Waiting for review/);
  assert.match(rows, /1 of 1 supported · score 80%/);
  assert.doesNotMatch(rows, /EVA-1|pending_review|access-controls/);
  const labels = [...h.$("analyses-rows").querySelectorAll("button")].map((b) => b.textContent);
  assert.deepEqual(labels, ["View findings", "Approve", "Reject", "Withdraw", "History"]);
  assert.equal(h.$("artifact-select").options[1].textContent, "Supplier contract PDF (Supplier review)");
  assert.match(h.$("criteria-select").options[1].textContent, /Access controls \(1 check\)/);
});

test("approving confirms and carries the row's version", async (t) => {
  const h = page(t);
  await h.settle();
  const approve = () => [...h.$("analyses-rows").querySelectorAll("button")].find((b) => b.textContent === "Approve");
  h.setConfirm(false);
  approve().click();
  await h.settle();
  assert.equal(h.calls.some((c) => c.key.endsWith("/review")), false);
  h.setConfirm(true);
  approve().click();
  await h.settle();
  const call = h.calls.find((c) => c.key === "POST /analyses/EVA-1/review");
  const body = JSON.parse(call.options.body);
  assert.equal(body.expected_revision, 3);
  assert.equal(body.decision, "approve");
});

test("analysis pins come from the chosen document and criteria, and a changed file is refused", async (t) => {
  const h = page(t);
  await h.settle();
  h.$("artifact-select").value = "0";
  h.$("criteria-select").value = "0";
  const file = new h.w.File([RAW], "contract.txt", { type: "text/plain" });
  file.arrayBuffer = async () => RAW.buffer.slice(0);
  Object.defineProperty(h.$("artifact-file"), "files", { configurable: true, value: [file] });
  h.$("analyze-form").dispatchEvent(new h.w.Event("submit", { cancelable: true }));
  await h.settle();
  const post = h.calls.find((c) => c.key === "POST /analyses");
  assert.ok(post, h.$("operation-status").textContent);
  const metadata = JSON.parse(post.options.headers["X-Lightwork-Evidence-Metadata"]);
  assert.equal(metadata.artifact_id, ARTIFACT.artifact_id);
  assert.equal(metadata.expected_artifact_authority_sha256, ARTIFACT.authority_sha256);
  assert.equal(metadata.expected_criteria_revision, 2);
  const other = new h.w.File([new TextEncoder().encode("different")], "other.txt", { type: "text/plain" });
  other.arrayBuffer = async () => new TextEncoder().encode("different").buffer;
  Object.defineProperty(h.$("artifact-file"), "files", { configurable: true, value: [other] });
  h.$("analyze-form").dispatchEvent(new h.w.Event("submit", { cancelable: true }));
  await h.settle();
  assert.match(h.$("operation-status").textContent, /doesn't match the registered document/);
  assert.equal(h.calls.filter((c) => c.key === "POST /analyses").length, 1);
});

// ---- no loader keeps saying "Loading" ---------------------------------------
function settledPage(t, status, moduleEnabled = "true") {
  const dom = new JSDOM(`<main>${pageBody}</main>`, { url: "https://lightwork.test/ai-evidence-analysis", runScripts: "outside-only" });
  t.after(() => dom.window.close());
  const w = dom.window;
  w.document.getElementById("evidence-shell").dataset.moduleEnabled = moduleEnabled;
  w.mvErrorText = (failure, action) => "Could not " + action + ". Try again in a few minutes.";
  const calls = [];
  w.fetch = async (url) => { calls.push(url); return status(); };
  shell(w);
  w.eval(pageSource);
  const settle = async () => { for (let i = 0; i < 40; i += 1) await new Promise((r) => setImmediate(r)); };
  const loaders = () => ["artifact-select", "criteria-select", "analyses-rows"].map((id) => w.document.getElementById(id).textContent).join(" | ");
  return { calls, settle, loaders, $: (id) => w.document.getElementById(id) };
}

test("a failed availability check settles the document, criteria and analysis loaders", async (t) => {
  const h = settledPage(t, () => new Response(JSON.stringify({ detail: "unavailable" }), { status: 503 }));
  await h.settle();
  assert.equal(h.$("analyses-rows").textContent, "Could not load analyses. Try again in a few minutes.");
  assert.equal(h.$("artifact-select").options[0].textContent, "Not available right now");
  assert.equal(h.$("criteria-select").options[0].textContent, "Not available right now");
  assert.doesNotMatch(h.loaders(), /Loading/);
});

test("unfinished setup says when analyses will appear instead of loading forever", async (t) => {
  const h = settledPage(t, () => new Response(JSON.stringify({ enabled: true, ready: false }), { status: 200 }));
  await h.settle();
  assert.equal(h.$("analyses-rows").textContent, "Analyses appear here once an administrator finishes the setup.");
  assert.doesNotMatch(h.loaders(), /Loading/);
});

test("a turned-off evidence module starts no checks or loads behind its gate", async (t) => {
  const h = settledPage(t, () => { throw new Error("no request expected"); }, "false");
  await h.settle();
  assert.deepEqual(h.calls, []);
});
