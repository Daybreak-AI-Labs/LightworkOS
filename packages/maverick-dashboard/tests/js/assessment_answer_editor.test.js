"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const { fetchHelpers } = require('./_shell');
const templates = path.resolve(__dirname, "../../maverick_dashboard/templates");

function fixture() {
  const nodes = {}, calls = [], renders = [];
  class Element {
    constructor(tag = "div") { this.tag = tag; this.children = []; this.listeners = {}; this.value = ""; this.disabled = false; this.style = {}; this.valid = true; }
    set id(id) { this._id = id; nodes[id] = this; }
    get id() { return this._id; }
    appendChild(child) { this.children.push(child); return child; }
    append(...children) { children.forEach(child => this.appendChild(child)); }
    set textContent(value) { this.text = value; this.children = []; }
    get textContent() { return this.text || ""; }
    addEventListener(type, fn) { this.listeners[type] = fn; }
    reportValidity() { return this.valid; }
    focus() { this.focused = true; }
  }
  const get = id => nodes[id] || (nodes[id] = new Element());
  const documentListeners = {};
  const context = { document: { getElementById: get, listeners: documentListeners, addEventListener: (type, fn) => { documentListeners[type] = fn; } }, currentId: "record", currentRevision: 1, viewGeneration: 1, answerBusy: false, answerDirty: false, selectedQuestion: "", decidedInDialog: false,
    body: new Element(), statusEl: new Element(), mvConfirm: async () => false,
    fetch: async (url, options) => { calls.push({ url, options }); throw new Error("No response configured"); },
    render: record => renders.push(record), reload: async () => {},
    el: (tag, cls, text = "") => { const element = new Element(tag); element.className = cls; element.textContent = text; return element; } };
  for (const name of ["sendBtn", "approveBtn", "rejectBtn", "acceptBtn", "triggerBtn"]) context[name] = new Element("button");
  // The page script's window is this context; the shell's fetch helper sends through its fetch.
  context.window = context;
  context.mvFetchJSON = fetchHelpers(() => context.fetch).mvFetchJSON;
  vm.createContext(context);
  return { context, get, calls, renders, Element };
}
const record = () => ({ id: "record", revision: 1, status: "pending_review", question_text: { first: { text: "Has this been checked?" }, second: { text: "Is there supporting evidence?" } }, answers: {}, followups: [] });
function editor(rec = record(), globals = {}) {
  const ui = fixture(), source = fs.readFileSync(path.join(templates, "../static/lightwork-assessment-review.js"), "utf8");
  Object.assign(ui.context, globals);
  vm.runInContext(source.slice(source.indexOf("    function renderAnswerEditor("), source.indexOf("    const RISK_RANK")), ui.context);
  ui.context.renderAnswerEditor(rec);
  ui.form = ui.context.body.children[0].children.find(child => child.tag === "form");
  return ui;
}
const response = data => ({ ok: true, json: async () => data });
const event = () => ({ preventDefault() {} });

test("question changes do not discard an unsaved answer without confirmation", async () => {
  const ui = editor();
  ui.get("arv-answer-value").value = "unknown"; ui.get("arv-answer-value").listeners.input();
  ui.get("arv-answer-note").value = "Need the source document";
  const picker = ui.get("arv-answer-question"); picker.value = "q:second";
  await picker.listeners.change();
  assert.equal(picker.value, "q:first"); assert.equal(ui.get("arv-answer-value").value, "unknown");
  assert.equal(ui.get("arv-answer-note").value, "Need the source document"); assert.equal(picker.disabled, false);
});

test("answer save sends the pinned question and version once and never approves the assessment", async () => {
  const ui = editor(); let finish;
  ui.get("arv-answer-value").value = "yes"; ui.get("arv-answer-note").value = "Verified by respondent";
  ui.context.fetch = async (url, options) => { ui.calls.push({ url, options }); return await new Promise(resolve => { finish = resolve; }); };
  const first = ui.form.listeners.submit(event());
  await ui.form.listeners.submit(event()); assert.equal(ui.calls.length, 1);
  assert.equal(ui.calls[0].url, "/api/v1/assess/sessions/record/answers/first");
  assert.deepEqual(JSON.parse(ui.calls[0].options.body), { answer: "yes", note: "Verified by respondent", expected_revision: 1 });
  finish(response({ ...record(), revision: 2, answers: { first: { answer: "yes" } } })); await first;
  assert.equal(ui.renders.length, 1); assert.equal(ui.renders[0].status, "pending_review");
  assert.equal(ui.context.approveBtn.disabled, false); assert.equal(ui.context.answerBusy, false);
});

test("conflicting or unconfirmed saves preserve the respondent draft and offer a reload", async () => {
  for (const reply of [{ ok: false, status: 409, json: async () => ({ detail: "changed" }) }, response(null), response({ ...record(), id: "other", revision: 2 })]) {
    const ui = editor(); ui.get("arv-answer-value").value = "no"; ui.get("arv-answer-note").value = "My unsaved explanation";
    ui.context.fetch = async () => reply;
    await ui.form.listeners.submit(event());
    assert.equal(ui.renders.length, 0); assert.equal(ui.get("arv-answer-note").value, "My unsaved explanation");
    assert.equal(ui.context.statusEl.children[0].textContent, "Reload latest assessment");
    assert.equal(ui.context.answerBusy, false);
  }
});

test("a delayed answer response cannot repaint a different assessment", async () => {
  const ui = editor(); let finish; ui.get("arv-answer-value").value = "yes";
  ui.context.fetch = async () => await new Promise(resolve => { finish = resolve; });
  const saving = ui.form.listeners.submit(event());
  ui.context.currentId = "another-record"; ui.context.viewGeneration++;
  finish(response({ ...record(), revision: 2, answers: { first: { answer: "yes" } } })); await saving;
  assert.equal(ui.renders.length, 0);
});

test("unsaved questionnaire changes cannot be mistaken for the answers being approved", async () => {
  const ui = editor(), source = fs.readFileSync(path.join(templates, "../static/lightwork-assessment-review.js"), "utf8");
  vm.runInContext(source.slice(source.indexOf("    async function decide("), source.indexOf("    approveBtn.addEventListener(")), ui.context);
  ui.get("arv-answer-value").value = "yes"; ui.get("arv-answer-value").listeners.input();
  await ui.context.decide("approved");
  assert.equal(ui.calls.length, 0); assert.match(ui.context.statusEl.textContent, /Save or discard/);
});

test("a follow-up answer uses the follow-up endpoint and retains its open review status", async () => {
  const rec = { ...record(), question_text: {}, status: "needs_more", followups: [{ id: "fu-1", question: "Which document?", answer: "" }] };
  const ui = editor(rec); ui.get("arv-answer-note").value = "The dated inspection report";
  ui.context.fetch = async (url, options) => { ui.calls.push({ url, options }); return response({ ...rec, revision: 2, status: "pending_review", followups: [{ id: "fu-1", answer: "The dated inspection report" }] }); };
  await ui.form.listeners.submit(event());
  assert.equal(ui.calls[0].url, "/api/v1/assess/sessions/record/followups/fu-1/answer");
  assert.deepEqual(JSON.parse(ui.calls[0].options.body), { answer: "The dated inspection report", expected_revision: 1 });
  assert.equal(ui.renders[0].status, "pending_review");
});

test("intake quotes a single subject safely and opens only a verified created assessment", async () => {
  const ui = fixture(), opened = [];
  ui.context.mvAssessmentReview = { open: id => opened.push(id) };
  const source = fs.readFileSync(path.join(templates, "_workspace_worklist.html"), "utf8");
  vm.runInContext(source.slice(source.indexOf("  (function assessmentIntake()"), source.lastIndexOf("  </script>")), ui.context);
  ui.get("pw-start-type").value = "pia"; ui.get("pw-start-subject").value = 'Acme, "North"\nOffice';
  ui.context.fetch = async (url, options) => { ui.calls.push({ url, options }); return response({ created_count: 1, error_count: 0, created: [{ id: "new-record", subject: 'Acme, "North"\nOffice', type: "pia" }] }); };
  await ui.get("pw-start-form").listeners.submit(event());
  assert.equal(JSON.parse(ui.calls[0].options.body).csv, 'subject,type\n"Acme, ""North""\nOffice","pia"');
  assert.deepEqual(opened, ["new-record"]); assert.equal(ui.get("pw-start-subject").value, "");
});

test("the page header's Start an assessment opens the intake form", () => {
  const ui = fixture();
  const source = fs.readFileSync(path.join(templates, "_workspace_worklist.html"), "utf8");
  vm.runInContext(source.slice(source.indexOf("  (function assessmentIntake()"), source.lastIndexOf("  </script>")), ui.context);
  let prevented = false;
  const header = { target: { closest: selector => (selector === 'a[href="#pw-start"]' ? {} : null) }, preventDefault() { prevented = true; } };
  ui.context.document.listeners.click(header);
  assert.equal(prevented, true); assert.equal(ui.get("pw-start").open, true); assert.equal(ui.get("pw-start-type").focused, true);
  const elsewhere = { target: { closest: () => null }, preventDefault() { throw new Error("other clicks are left alone"); } };
  ui.get("pw-start").open = false; ui.context.document.listeners.click(elsewhere);
  assert.equal(ui.get("pw-start").open, false);
});

test("risk summary distinguishes empty, unresolved and complete questionnaires without claiming zero risks are controlled", () => {
  const source = fs.readFileSync(path.join(templates, "../static/lightwork-assessment-review.js"), "utf8");
  for (const state of ["empty", "unknown", "complete"]) {
    const ui = fixture();
    ui.context.currentQuestions = {}; ui.context.riskEl = ui.get("arv-risk");
    const begin = source.indexOf("    function riskClass(");
    const end = source.indexOf("      renderAnswerEditor(rec);");
    vm.runInContext(source.slice(begin, end) + "\n    }", ui.context);
    const rec = { ...record(), result: { answered: state === "complete" ? 2 : 0, total: 2,
      inherent_risk: "minimal", residual_risk: "minimal", risks_in_scope: 0, controls_in_place: 0 },
      answers: state === "empty" ? {} : { first: { answer: state === "unknown" ? "unknown" : "yes" } } };
    ui.context.render(rec);
    const childrenText = ui.context.body.children.flatMap(element => [element.textContent, ...element.children]).join(" ");
    if (state === "complete") {
      assert.equal(ui.context.riskEl.textContent, "Risk after safeguards: Minimal");
      assert.ok(childrenText.includes("in-scope risk areas controlled"));
    } else {
      assert.match(ui.context.riskEl.textContent, state === "empty" ? /not yet assessed/ : /provisional/);
      assert.equal(ui.context.riskEl.className, "badge warn");
      assert.match(childrenText, /0 of 2 questions resolved/);
      assert.equal(childrenText.includes("in-scope risk areas controlled"), false);
      assert.equal(ui.context.body.children[1].className, "arv__incomplete");
    }
  }
});

test("approving an incomplete questionnaire requires explicit acknowledgment and keeps canceled work unchanged", async () => {
  const ui = fixture(), confirmations = [], source = fs.readFileSync(path.join(templates, "../static/lightwork-assessment-review.js"), "utf8");
  ui.context.currentCompletion = { answered: 0, total: 2, incomplete: true };
  ui.context.mvConfirm = async message => { confirmations.push(message); return false; };
  vm.runInContext(source.slice(source.indexOf("    async function decide("), source.indexOf("    approveBtn.addEventListener(")), ui.context);
  await ui.context.decide("approved");
  assert.match(confirmations[0], /0 of 2.*resolved/); assert.equal(ui.calls.length, 0);
  assert.equal(ui.context.approveBtn.disabled, false); assert.equal(ui.context.rejectBtn.disabled, false);
});

test("incomplete approval acknowledgment cannot transfer to a different assessment opened while it is pending", async () => {
  const ui = fixture(), source = fs.readFileSync(path.join(templates, "../static/lightwork-assessment-review.js"), "utf8");
  ui.context.currentCompletion = { answered: 0, total: 2, incomplete: true };
  ui.context.mvConfirm = async () => { ui.context.currentId = "another-record"; ui.context.viewGeneration++; return true; };
  vm.runInContext(source.slice(source.indexOf("    async function decide("), source.indexOf("    approveBtn.addEventListener(")), ui.context);
  await ui.context.decide("approved"); assert.equal(ui.calls.length, 0);
});

function descend(root, text) {
  if (root.textContent === text) return root;
  for (const child of root.children || []) { const found = descend(child, text); if (found) return found; }
  return null;
}
function suggestion(question, state = "current_approved") {
  return {answer: "yes", note: "Reviewed rationale", state, confidence: 1, confidence_meaning: "Agreement, not factual certainty.",
    why_reused: "Similar subject and questionnaire", sources: [{assessment_id: "source", source_revision: 2, question_id: question,
      policy_digest: "a".repeat(64), policy_version: 1, current_policy_version: 1, subject: "Prior Acme review", source_date: 1700000000,
      approval_owner: "user:reviewer", state, reasons: [], answer: "yes", note: "Reviewed rationale"}], conflicts: []};
}
test("individual precedent rejection leaves other questions and stored answers unchanged", async () => {
  const ui = editor({...record(), subject: "Acme", type: "pia"});
  ui.context.ANSWER_LABEL = {yes: "Yes"}; ui.context.person = value => value.replace(/^user:/, "");
  const suggestions = {first: suggestion("first", "stale_precedent"), second: suggestion("second")};
  ui.context.fetch = async (url, options) => { ui.calls.push({url, options}); return response({suggestions}); };
  await descend(ui.form, "Find precedent answers").listeners.click();
  assert.ok(descend(ui.form, "Stale precedent - renewed evidence needed"));
  descend(ui.form, "Reject this suggested value").listeners.click();
  assert.ok(descend(ui.form, "This suggested value was rejected. Other question suggestions are unchanged."));
  ui.get("arv-answer-question").value = "q:second"; await ui.get("arv-answer-question").listeners.change();
  assert.ok(descend(ui.form, "Current approved assessment precedent"));
  assert.equal(ui.get("arv-answer-value").value, "");
  assert.equal(ui.calls.some(call => call.options?.method === "PUT"), false);
});
test("using a precedent rechecks its exact saved fragment before changing one draft field", async () => {
  const ui = editor({...record(), subject: "Acme", type: "pia"});
  ui.context.ANSWER_LABEL = {yes: "Yes"}; ui.context.person = value => value;
  const value = suggestion("first");
  ui.context.fetch = async (url, options) => { ui.calls.push({url, options}); return response(url.includes("/fragment/") ? value.sources[0] : {suggestions: {first: value}}); };
  await descend(ui.form, "Find precedent answers").listeners.click();
  await descend(ui.form, "Use this value in my draft").listeners.click();
  assert.match(ui.calls[1].url, /fragment\/source\/first\?revision=2&policy_digest=/);
  assert.equal(ui.get("arv-answer-value").value, "yes");
  assert.equal(ui.get("arv-answer-note").value, "Reviewed rationale");
  assert.equal(ui.context.answerDirty, true);
  assert.equal(ui.renders.length, 0);
});

test("an AI-suggested answer a person changed can go back to the AI's value in the draft only", async () => {
  const rec = {...record(), answers: {first: {answer: "no", note: "Checked by hand"}},
    answer_history: [{question_id: "first", previous_answer: {answer: "yes", note: "From the vendor's SOC 2 report", ai_metadata: {source: "evidence_autopopulation", confidence: 0.82}}}]};
  const ui = editor(rec, {ANSWER_LABEL: {yes: "Yes", no: "No"}, person: (value) => value, human: (value) => value});
  ui.get("arv-answer-question").value = "q:first"; await ui.get("arv-answer-question").listeners.change();
  assert.ok(descend(ui.form, "Suggested by AI before a person changed it: Yes (From the vendor's SOC 2 report)."));
  await descend(ui.form, "Restore the AI suggestion").listeners.click();
  assert.equal(ui.get("arv-answer-value").value, "yes");
  assert.equal(ui.get("arv-answer-note").value, "From the vendor's SOC 2 report");
  assert.equal(ui.context.answerDirty, true);
  assert.equal(ui.calls.some(call => call.options?.method === "PUT"), false, "nothing is saved until the person saves");
  ui.context.mvConfirm = async () => true;  // discard the restored draft to look at another question
  ui.get("arv-answer-question").value = "q:second"; await ui.get("arv-answer-question").listeners.change();
  assert.equal(descend(ui.form, "Restore the AI suggestion"), null, "only the question the AI answered offers it");
});

test("an answer still holding the AI's value offers nothing to restore", async () => {
  const rec = {...record(), answers: {first: {answer: "yes", ai_metadata: {source: "evidence_autopopulation"}}},
    answer_history: [{question_id: "first", previous_answer: {answer: "no", ai_metadata: {source: "evidence_autopopulation"}}}]};
  const ui = editor(rec, {ANSWER_LABEL: {yes: "Yes", no: "No"}, person: (value) => value, human: (value) => value});
  ui.get("arv-answer-question").value = "q:first"; await ui.get("arv-answer-question").listeners.change();
  assert.equal(descend(ui.form, "Restore the AI suggestion"), null);
});
