"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function client() {
  const window = {};
  const context = { TextDecoder, TextEncoder, console, window };
  vm.createContext(context);
  vm.runInContext(
    fs.readFileSync(
      path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-assessment-evidence-autopopulation.js"),
      "utf8",
    ),
    context,
  );
  return window.LightworkAssessmentEvidenceClient;
}

function response(chunks, contentLength = null) {
  let index = 0;
  let cancelled = false;
  const reader = {
    async read() {
      const value = chunks[index++];
      return value === undefined ? {done: true} : {done: false, value};
    },
    async cancel() { cancelled = true; },
  };
  return {
    value: {
      ok: true,
      status: 200,
      headers: {get: () => contentLength},
      body: {getReader: () => reader},
    },
    state: () => ({index, cancelled}),
  };
}

function plain(value) { return JSON.parse(JSON.stringify(value)); }

test("confidence displays as a percentage without inventing missing or invalid certainty", () => {
  const api = client();
  assert.equal(api.confidenceLabel(10000), "100%");
  assert.equal(api.confidenceLabel(9250), "92.5%");
  assert.equal(api.confidenceLabel(125), "1.25%");
  assert.equal(api.confidenceLabel(0), "0%");
  for (const value of [undefined, null, "9250", -1, 10001, NaN])
    assert.equal(api.confidenceLabel(value), "Not reported");
});

test("bounded response rejects declared and streamed overflow", async () => {
  const api = client();
  const declared = response([], String(api.MAX_RESPONSE_BYTES + 1));
  await assert.rejects(api.boundedResponseText(declared.value), /1 MiB/);
  const streamed = response([
    new Uint8Array(api.MAX_RESPONSE_BYTES),
    new Uint8Array([1]),
  ]);
  await assert.rejects(api.boundedResponseText(streamed.value), /1 MiB/);
  assert.deepEqual(streamed.state(), {index: 2, cancelled: true});
});

test("create payload accepts only assessment evidence selectors", () => {
  const payload = plain(client().buildCreatePayload({
    assessment_id: "assessment-one",
    analysis_ids: "analysis-one\nanalysis-two\nanalysis-one",
    idempotency_key: "create-one",
    tenant_id: "attacker",
    actor_ref: "attacker",
    artifact_bytes: "secret",
  }));
  assert.deepEqual(payload, {
    assessment_id: "assessment-one",
    analysis_ids: ["analysis-one", "analysis-two"],
    idempotency_key: "create-one",
  });
});

test("review approval requires an explicit question selection", () => {
  const api = client();
  assert.throws(() => api.buildReviewPayload({
    decision: "approve",
    selected_question_ids: [],
    rationale: "reviewed",
    expected_revision: "1",
    idempotency_key: "review-one",
  }), /Select at least one/);
  const rejected = plain(api.buildReviewPayload({
    decision: "reject",
    selected_question_ids: [],
    rationale: "insufficient evidence",
    expected_revision: "1",
    idempotency_key: "reject-one",
  }));
  assert.equal(rejected.decision, "reject");
  assert.deepEqual(rejected.selected_question_ids, []);
});

test("apply builder enforces explicit confirmation and closed CAS fields", () => {
  const api = client();
  assert.throws(() => api.buildApplyPayload({
    expected_revision: "2",
    expected_assessment_revision: "4",
    idempotency_key: "apply-one",
    confirm: false,
  }), /Confirm/);
  const payload = plain(api.buildApplyPayload({
    expected_revision: "2",
    expected_assessment_revision: "4",
    idempotency_key: "apply-one",
    confirm: true,
    answers: {pia_security: "no"},
    tenant_id: "attacker",
  }));
  assert.deepEqual(payload, {
    expected_revision: 2,
    expected_assessment_revision: 4,
    idempotency_key: "apply-one",
  });
});

// ---- page behaviour (jsdom) -------------------------------------------
const { JSDOM } = require("jsdom");
const pageTemplate = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates/assessment_evidence_autopopulation.html"), "utf8");
const pageSource = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-assessment-evidence-autopopulation.js"), "utf8");
const pageBody = pageTemplate.slice(pageTemplate.indexOf('<div class="aep-shell"'), pageTemplate.indexOf("{% if not proposal_workspace_missing %}<script"))
  .replace("{{ api_base }}", "/api/v1/assessment-evidence-autopopulation")
  .replace(/\{\{\s*hero\([^}]*\}\}/, "").replace(/\{%[^%]*%\}/g, "").replace(/\{\{[^}]*\}\}/g, "true");
const PROPOSAL = { id: "AEP-1", status: "pending_review", revision: 2,
  assessment: { id: "asm-1", revision: 7, type: "vendor_risk" },
  candidates: [{ question_id: "vr_encryption", answer: "yes", confidence_bps: 9200, eligible_for_apply: true, flags: [],
    citations: [{ analysis_id: "EVA-1", criterion_id: "criterion-encryption" }] }] };

function page(t) {
  const dom = new JSDOM(`<main>${pageBody}</main>`, { url: "https://lightwork.test/assess/evidence-autopopulation", runScripts: "outside-only" });
  t.after(() => dom.window.close());
  const w = dom.window;
  w.TextDecoder = TextDecoder;
  const calls = [];
  let proposal = PROPOSAL;
  w.mvConfirm = async () => true;
  w.fetch = async (url, options = {}) => {
    const key = (options.method || "GET") + " " + url;
    calls.push({ key, body: options.body ? JSON.parse(options.body) : undefined });
    const json = (value, status = 200) => new Response(JSON.stringify(value), { status });
    if (key.endsWith("/assessment-evidence-autopopulation/status")) return json({ ready: true, enabled: true });
    if (key.endsWith("/assess/sessions")) return json({ sessions: [{ id: "asm-1", type: "vendor_risk", subject: "Acme Cloud", status: "pending_review", answered: 3, total: 10 }] });
    if (key.endsWith("/assess/templates/vendor_risk")) return json({ title: "Vendor risk review", questions: [{ id: "vr_encryption", text: "Is data encrypted at rest?" }] });
    if (key.includes("/ai-evidence-analysis/analyses?")) return json({ items: [{ analysis_id: "EVA-1", artifact: { artifact_id: "security-policy-pdf.0badc0de" }, criteria: { criteria_set_id: "encryption-controls" } }] });
    if (key.includes("/proposals?limit=")) return json({ items: [{ id: proposal.id, status: proposal.status, assessment: proposal.assessment, candidate_count: 1, eligible_candidate_count: 1, created_at: 1800000000 }] });
    if (key.endsWith("/proposals/AEP-1")) return json(proposal);
    if (key.endsWith("/review")) { proposal = { ...PROPOSAL, status: "approved", revision: 3, review: { selected_question_ids: ["vr_encryption"] } }; return json(proposal); }
    if (key.endsWith("/apply")) return json({ ...proposal, status: "applied" });
    if (key.endsWith("/proposals")) return json(PROPOSAL, 201);
    return json({ detail: "nope" }, 404);
  };
  w.eval(pageSource);
  const settle = async () => { for (let i = 0; i < 40; i += 1) await new Promise((r) => setImmediate(r)); };
  return { w, calls, settle, $: (id) => w.document.getElementById(id) };
}

test("pickers and the suggestion list replace typed identifiers", async (t) => {
  const h = page(t);
  await h.settle();
  assert.equal(h.$("aep-assessment-id").options[1].textContent, "Acme Cloud — Vendor risk review (3 of 10 answered)");
  assert.match(h.$("aep-analysis-choices").textContent, /Security policy pdf · Encryption controls/);
  const row = h.$("aep-queue").textContent;
  assert.match(row, /Acme Cloud/);
  assert.match(row, /Waiting for review/);
  assert.doesNotMatch(row, /AEP-1|pending_review/);
});

test("reviewing shows question text and approving carries the proposal version", async (t) => {
  const h = page(t);
  await h.settle();
  [...h.$("aep-queue").querySelectorAll("button")].find((b) => b.textContent === "Review").click();
  await h.settle();
  assert.match(h.$("aep-candidates").textContent, /Is data encrypted at rest\?/);
  assert.match(h.$("aep-candidates").textContent, /Security policy pdf/);
  h.$("aep-candidate-selection").querySelector("input").checked = true;
  h.$("aep-review-rationale").value = "Matches the policy";
  const approve = h.$("aep-review-form").querySelector('button[value="approve"]');
  h.$("aep-review-form").dispatchEvent(new h.w.SubmitEvent("submit", { cancelable: true, submitter: approve }));
  await h.settle();
  const review = h.calls.find((c) => c.key.endsWith("/proposals/AEP-1/review"));
  assert.equal(review.body.expected_revision, 2);
  assert.deepEqual(review.body.selected_question_ids, ["vr_encryption"]);
  const add = [...h.$("aep-queue").querySelectorAll("button")].find((b) => b.textContent === "Add approved answers");
  add.click();
  await h.settle();
  const apply = h.calls.find((c) => c.key.endsWith("/proposals/AEP-1/apply"));
  assert.equal(apply.body.expected_revision, 3);
  assert.equal(apply.body.expected_assessment_revision, 7);
});
