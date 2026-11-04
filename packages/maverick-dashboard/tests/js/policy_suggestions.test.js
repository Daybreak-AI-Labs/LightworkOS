"use strict";
// Suggested edits to AI use rules (static/lightwork-policy-suggestions.js,
// NOT-4): each suggestion shows exactly what it changes, who or what proposed
// it and why; a person accepts or rejects it with an optional reason; the AI
// assistant drafts one only when asked.
// Run with: node --test tests/js/policy_suggestions.test.js
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const {JSDOM} = require("jsdom");
const pkg = path.resolve(__dirname, "../../maverick_dashboard");
const ui = fs.readFileSync(path.join(pkg, "static/lightwork-ui.js"), "utf8");
const script = fs.readFileSync(path.join(pkg, "static/lightwork-policy-suggestions.js"), "utf8");
const partial = fs.readFileSync(path.join(pkg, "templates/_policy_suggestions.html"), "utf8")
  .replace(/{#[\s\S]*?#}/g, "").replace(/{%[\s\S]*?%}/g, "").replace(/<script[\s\S]*?<\/script>/g, "")
  .replace(/{{ kind }}/g, "ai-policy").replace(/{{ heading }}/g, "h4").replace(/{{ next_step }}/g, "");
const flush = async () => { for (let i = 0; i < 20; i++) await new Promise(setImmediate); };

const SUGGESTION = {id: 4, document_id: "customer-data", document_title: "Customer data rules",
  field: "statement:no-export", field_label: "Rule: no export", proposed_by: "AI assistant (test-model)",
  proposer_kind: "ai", reason: "Cover the UK too.", state: "open", outdated: false,
  diff: [{op: "same", text: "AI must not send customer data outside the "}, {op: "del", text: "EU."}, {op: "ins", text: "EU or the UK."}]};
const LIST = {suggestions: [SUGGESTION], recent: [], can_decide: true, ai_on: true,
  rules: [{id: "customer-data", title: "Customer data rules", parts: [{field: "title", label: "Title"},
    {field: "statement:no-export", label: "Rule: no export"}]}]};

function boot(list, markup = partial) {
  const dom = new JSDOM(`<div id="mv-toasts"></div><div id="mv-toasts-alert"></div><main id="content">${markup}</main>`,
    {url: "https://fixture.invalid/security/assurance", runScripts: "outside-only", pretendToBeVisual: true});
  const w = dom.window, calls = [];
  w.matchMedia = () => ({matches: false, addEventListener() {}, removeEventListener() {}});
  w.eval(ui);
  let current = list;
  w.mvFetchJSON = async (url, opts) => {
    calls.push({url, opts: opts || {}});
    if (url.endsWith("/accept")) { current = {...current, suggestions: []}; return {suggestion: {applied_version: 2}, next_step: "Saved as version 2. Turn it on above when you are ready."}; }
    if (url.endsWith("/reject")) { current = {...current, suggestions: []}; return {suggestion: {state: "rejected"}}; }
    if (url.endsWith("/ai")) return {id: 5};
    return current;
  };
  w.eval(script);
  return {w, d: w.document, calls};
}

test("a suggestion shows what it removes and adds, and who proposed it and why", async () => {
  const {d} = boot(LIST);
  await flush();
  const card = d.getElementById("suggestion-4");
  assert.match(card.querySelector("h5").textContent, /Customer data rules · Rule: no export/);
  assert.match(card.textContent, /Suggested by AI: AI assistant \(test-model\)\. Why: Cover the UK too\./);
  assert.equal(card.querySelector("del").textContent, " removed: EU.");
  assert.equal(card.querySelector("ins").textContent, " added: EU or the UK.");
  const buttons = [...card.querySelectorAll("button")].map((b) => b.textContent);
  assert.deepEqual(buttons, ["Accept change", "Reject change"]);
});

test("accepting sends the optional reason and says which version was saved", async () => {
  const {d, calls} = boot(LIST);
  await flush();
  const card = d.getElementById("suggestion-4");
  card.querySelector("input").value = "Agreed in review.";
  card.querySelector("button").click();
  await flush();
  const sent = calls.find((c) => c.url.endsWith("/4/accept"));
  assert.deepEqual({...sent.opts.body}, {reason: "Agreed in review."});
  assert.match(d.querySelector("[data-suggestion-list]").textContent, /Accepted for “Customer data rules”\. Saved as version 2\./);
  assert.ok(calls.some((c) => c.url === "/api/v1/policy-suggestions?kind=ai-policy"));
});

test("an outdated suggestion can only be rejected, and a viewer sees no buttons", async () => {
  let ui = boot({...LIST, suggestions: [{...SUGGESTION, outdated: true}]});
  await flush();
  const accept = ui.d.querySelector("#suggestion-4 button");
  assert.equal(accept.disabled, true);
  assert.match(ui.d.getElementById("suggestion-4").textContent, /changed since it was suggested/);
  ui = boot({...LIST, can_decide: false, ai_on: false, rules: []});
  await flush();
  assert.equal(ui.d.querySelectorAll("#suggestion-4 button").length, 0);
  assert.equal(ui.d.querySelector("[data-suggestion-ask]").hidden, true);
});

test("the AI assistant is asked only when a person sends the form", async () => {
  const {d, calls} = boot(LIST);
  await flush();
  const form = d.querySelector("[data-suggestion-ask]");
  assert.equal(form.hidden, false);
  assert.equal(calls.filter((c) => c.url.endsWith("/ai")).length, 0);
  assert.deepEqual([...form.elements.field.options].map((o) => o.textContent), ["Title", "Rule: no export"]);
  form.elements.field.value = "title";
  form.elements.instruction.value = "Make it shorter.";
  form.dispatchEvent(new d.defaultView.Event("submit", {cancelable: true}));
  await flush();
  const asked = calls.find((c) => c.url.endsWith("/ai"));
  assert.deepEqual({...asked.opts.body}, {id: "customer-data", field: "title", instruction: "Make it shorter."});
  assert.match(form.querySelector("[data-suggestion-status]").textContent, /Nothing changes until someone accepts it/);
});

test("a data use rule's suggestions load by their kind and offer no AI drafting", async () => {
  const markup = partial.replace('data-kind="ai-policy"', 'data-kind="data-use-rule"').replace(/<form[\s\S]*?<\/form>/, "");
  const {d, calls} = boot({...LIST, ai_on: false, rules: [], suggestions: [{...SUGGESTION, kind: "data-use-rule",
    field: "document", field_label: "Rule", proposer_kind: "person", proposed_by: "ana@corp.com"}]}, markup);
  await flush();
  assert.equal(calls[0].url, "/api/v1/policy-suggestions?kind=data-use-rule");
  assert.equal(d.querySelector("[data-suggestion-ask]"), null);
  assert.match(d.getElementById("suggestion-4").textContent, /Suggested by ana@corp\.com\. Why: Cover the UK too\./);
});
