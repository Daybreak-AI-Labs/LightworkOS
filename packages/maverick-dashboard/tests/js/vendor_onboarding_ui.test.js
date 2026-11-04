// Run with: node --test packages/maverick-dashboard/tests/js/vendor_onboarding_ui.test.js
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { fetchHelpers } = require('./_shell');

function record(id, overrides = {}) {
  return {
    id, revision: 1, vendor_name: `Vendor ${id}`, document_id: `document-${id}`,
    owner: "user:procurement", updated_at: 1800000000,
    project: "VEND", purpose: "Support replies", freshness_days: 365,
    due_at: 1802592000,
    stage: "assessment_ready", outcome: null,
    attention: {state:"due",kind:"requested_completion",requires_attention:false,
      effective_at:1802592000,as_of:1800000000},
    work_item: {
      process: { id: "supplier-evidence-onboarding", version: 1, sha256: "a".repeat(64) },
      supported_deployment: { topology: "single_persistent_application_replica" },
      acceptance_contract: {
        technical: { effect: "one Jira Task matches the exact approved payload" },
        business: { decision: "an authorized person accepts or rejects the verified deliverable" },
      },
      out_of_scope: ["procurement approval or payment", "multi-replica application operation"],
      lifecycle: "Ready", next_action: "review_assessment",
      technical_effect: "not_verified", business_outcome: "pending",
    },
    evidence: { status: "available", version: "v1", extracted: { answers: {} } },
    assessment: {
      status: "pending", result: { answered: 1, total: 1, risk_rating: "low" },
      template_snapshot: { questions: [{ id: "training", text: "Customer training?", section: "Data", guidance: "Check terms." }] },
      answers: { training: { answer: "unknown", note: "" } },
    },
    ...overrides,
  };
}

function response(body, status = 200) {
  return { ok: status >= 200 && status < 300, status, async json() { return body; } };
}

function evidenceExport(caseId, revision, overrides = {}) {
  const reference = "EVR-" + "1".repeat(32);
  return {
    schema: "lightwork.vendor-onboarding.evidence-export.v1",
    prepared_at: 1800000000,
    binding_sha256: "b".repeat(64),
    case: {id:caseId,revision,workflow_schema:"lightwork.vendor-onboarding.v1",
      evidence_sha256:"c".repeat(64),assessment_id:"AIV-reviewed",assessment_revision:2,
      assessment_sha256:"d".repeat(64)},
    decision: {state:"accepted",reviewer:"user:reviewer",rationale:"Reviewed current evidence",decided_at:1800000000},
    claims: [{claim_id:"training",answer:"unknown",note:"No current statement",source_basis:"document",
      evidence_refs:[reference],withheld_evidence_refs:[],citations:[{evidence_ref:reference,quote:"We do not train on customer data.",location:{paragraph:1}}],review_justification:null}],
    manifest: {schema:"lightwork.vendor-onboarding.evidence-export-manifest.v1",
      included:[{reference,dependency_type:"connected_source_evidence",disposition:"included",source_type:"connected_document",
        reviewed_version:"v1",modified_at:1799990000,fresh_until:1809990000,freshness:"current",
        content_sha256:"e".repeat(64),extraction_method:"plain_text"}],withheld:[],included_count:1,withheld_count:0,complete:true},
    limitations:["Source provenance does not establish truth."],
    ...overrides,
  };
}

function approvalCard(overrides = {}) {
  return {
    schema: "lightwork.approval-card.v1",
    binding_sha256: "1".repeat(64),
    authorization: {state: "recommendation_only", authority_required: true,
      prediction_grants_authority: false},
    summary: "Create the reviewed Jira task",
    target: {label: "VEND project", sha256: "2".repeat(64)},
    parameters: {sha256: "3".repeat(64), summary: ["One Task in VEND"]},
    authority: {actor: "user:reviewer", workspace: "tenant-a", role: "operator"},
    inputs: {case_revision: 4},
    credentials: {jira_revision: "jira-v2"},
    budget: {currency: "USD", maximum_dollars: 0.25},
    expires_at: 1800000300,
    consequences: {irreversible: true,
      known_effects: ["Creates one externally persistent Jira task."],
      unresolved_assumptions: ["Jira automation may notify project members."]},
    preview: {before: "No Jira task exists.", after: "The reviewed task exists once."},
    ...overrides,
  };
}

function reconciliationSummary(overrides = {}) {
  return {
    schema: "lightwork.vendor-onboarding.reconciliation-summary.v1",
    attempted_action: {operation_id:"VOP-"+"1".repeat(32),action:"jira.create",
      attempt_count:1,started_at:1799999900,target:{provider:"jira",project:"VEND"}},
    known_observations: [
      {kind:"execution_attempt",state:"recorded",count:1,observed_at:1799999900},
      {kind:"provider_receipt",state:"not_recorded"},
      {kind:"authoritative_readback",state:"no_match",match_count:0,observed_at:1800000000},
    ],
    uncertainty: {state:"unresolved",reason:"no_matching_effect_observed",
      explanation:"No matching Jira task was observed; absence is not proof of no effect."},
    safe_next_check: {kind:"check_status",mode:"read_only",
      label:"Check the original Jira destination again"},
    responsible_operator: {principal:"user:reviewer",business_owner:"user:procurement"},
    resolution: {automatic_compensation_supported:false,unreviewed_replacement_allowed:false,
      requires_separate_review:true,explanation:"Any supported resolution requires a separate reviewed action."},
    ...overrides,
  };
}

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

function fixture(records = [], intercept = null, search = "", returning = null, durableStorage = null) {
  const document = { elements: new Map(), activeElement: null };
  const downloads = [], blobs = new Map();
  let now = 2000;
  class Element {
    constructor(tag) {
      this.tagName = tag.toUpperCase(); this.children = []; this.parentElement = null;
      this.attributes = new Map(); this.listeners = {}; this.dataset = {};
      this.value = ""; this.disabled = false; this._text = "";
    }
    set id(value) { this._id = value; document.elements.set(value, this); }
    get id() { return this._id; }
    set textContent(value) { this._text = String(value); this.children = []; }
    get textContent() { return this._text + this.children.map(child => child.textContent).join(""); }
    append(child) { child.parentElement = this; this.children.push(child); }
    replaceChildren(...children) { this._text = ""; this.children = []; children.forEach(child => this.append(child)); }
    setAttribute(name, value) { this.attributes.set(name, String(value)); }
    getAttribute(name) { return this.attributes.get(name); }
    addEventListener(name, handler) { this.listeners[name] = handler; }
    focus() { if (!this.disabled) document.activeElement = this; }
    click() {
      if (this.tagName === "A") downloads.push({name: this.download, href: this.href, blob: blobs.get(this.href)});
      this.listeners.click?.({target: this});
    }
    remove() { if (this.parentElement) this.parentElement.children = this.parentElement.children.filter(child => child !== this); }
    querySelectorAll(selector) {
      const selectors = selector.split(",").map(part => part.trim());
      const all = this.children.flatMap(child => [child, ...child.querySelectorAll("*")]);
      return all.filter(node => selectors.some(part => {
        if (part === "*") return true;
        if (part === "select[data-question]") return node.tagName === "SELECT" && !!node.dataset.question;
        return node.tagName.toLowerCase() === part;
      }));
    }
  }
  document.createElement = tag => new Element(tag);
  document.getElementById = id => document.elements.get(id) || null;
  const add = (id, tag, parent = null) => {
    const element = document.createElement(tag); element.id = id;
    if (parent) parent.append(element);
    return element;
  };
  const root = add("vendor-onboarding", "section");
  root.dataset.apiBase = "/api/v1/vendor-onboarding";
  root.dataset.workspaceContext = "f".repeat(64);
  const storage = durableStorage || new Map();
  if (returning) storage.set("lightwork:connection-task:v1", JSON.stringify(returning));
  const sessionStorage = {getItem: key => storage.get(key) || null, setItem: (key, value) => storage.set(key, value), removeItem: key => storage.delete(key)};
  const localStorage = {getItem: key => storage.get(key) || null, setItem: (key, value) => storage.set(key, value), removeItem: key => storage.delete(key)};
  const ids = ["message", "case-title", "case-reference", "status", "scope", "evidence", "assessment",
    "corrections", "operation", "operation-record", "outcome", "renewal-status", "history", "cases", "cancellation-status", "page-status", "attention-summary",
    "acceptance-evidence-check", "export-status", "export-manifest"];
  ids.forEach(id => add(`vo-${id}`, "div", root));
  const caseFilter = add("vo-case-filter", "select", root); caseFilter.value = "all";
  add("vo-page-previous", "button", root); add("vo-page-next", "button", root);
  const intake = add("vo-intake", "form", root);
  ["vendor", "document", "project", "freshness", "due", "renewal"].forEach(id => add(`vo-${id}`, "input", intake));
  add("vo-purpose", "textarea", intake);
  add("vo-create", "button", intake);
  ["rationale", "acceptance-reason", "cancellation-reason"].forEach(id => add(`vo-${id}`, "textarea", root));
  add("vo-cancellation-confirm", "input", root);
  add("vo-export-confirm", "input", root);
  add("vo-case-project", "input", root); add("vo-case-purpose", "textarea", root);
  add("vo-case-freshness", "input", root); add("vo-case-due", "input", root);
  ["refresh", "collect", "assess", "renew", "check-renewal", "review-approve", "review-reject",
    "prepare", "approve", "execute", "reconcile", "accept", "reject", "cancel", "save-draft", "export-preview", "export-download"].forEach(id => add(`vo-${id}`, "button", root));
  const calls = [];
  const byId = id => document.getElementById(`vo-${id}`);
  const fetch = async (url, options) => {
    // The workspace member list only supplies display names.
    if (url === "/api/v1/choices/people") return response({people: [{value: "user:procurement", label: "Pat Procurement"}, {value: "user:reviewer", label: "Riley Reviewer"}]});
    const call = { url, ...options, body: options.body === undefined ? undefined : JSON.parse(options.body) };
    calls.push(call);
    if (intercept) {
      const intercepted = intercept(call);
      if (intercepted !== undefined) return intercepted;
    }
    if (options.method !== "GET") throw new Error(`Unexpected mutation ${url}`);
    if (url.endsWith("/cases")) return response({ cases: records });
    const selected = records.find(row => url.endsWith(`/cases/${encodeURIComponent(row.id)}`));
    return response(selected || { detail: "Not found" }, selected ? 200 : 404);
  };
  const urlApi = {createObjectURL(blob) { const ref = `blob:fixture-${blobs.size + 1}`; blobs.set(ref, blob); return ref; }, revokeObjectURL() {}};
  const location = {search, pathname: "/vendor-onboarding", hash: ""};
  const navigations = [];
  const history = {replaceState(_state, _title, target) {
    navigations.push(target);
    location.search = new URL(target, "https://lightwork.test").search;
  }};
  vm.runInNewContext(fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-access-state.js'), 'utf8') + "\n" + fs.readFileSync(
    path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-vendor-onboarding.js"), "utf8",
  ), { document, fetch, Blob, window: {location, history, localStorage, sessionStorage, URL:urlApi,
    mvFetchJSON: fetchHelpers(() => fetch).mvFetchJSON,
    mvErrorText: (failure, action) => "Could not " + action + ". " + ({404: "That item no longer exists.", 503: "This is temporarily unavailable."}[failure.status] || "Please try again.")}, URL, URLSearchParams, performance: { now: () => now }, setTimeout, clearTimeout, requestAnimationFrame: handler => setTimeout(handler, 0) });
  async function settle() {
    for (let turn = 0; turn < 20; turn += 1) {
      await new Promise(resolve => setImmediate(resolve));
      if (root.getAttribute("aria-busy") === "false") return;
    }
    throw new Error("UI did not settle");
  }
  return {
    root, byId, calls, document, settle, storage, downloads, location, navigations,
    advanceTime(milliseconds) { now += milliseconds; },
    caseButton(id) { return byId("cases").children.find(button => button.dataset.caseId === id); },
    async load(id) { this.caseButton(id).listeners.click(); await settle(); },
    async click(id) { byId(id).listeners.click(); await settle(); },
    async submit() { byId("intake").listeners.submit({preventDefault() {}}); await settle(); },
    async filter(value) { byId("case-filter").value = value; byId("case-filter").listeners.change(); await settle(); },
  };
}

test("initial and refreshed lists describe reads accurately and expose selection", async () => {
  const ui = fixture([record("one"), record("two")]);
  await ui.settle();
  assert.match(ui.byId("message").textContent, /^Requests loaded/);
  assert.equal(ui.byId("rationale").disabled, true);
  assert.equal(ui.byId("acceptance-reason").disabled, true);
  assert.match(ui.caseButton("one").textContent, /Owner Pat Procurement/);
  assert.doesNotMatch(ui.caseButton("one").textContent, /user:|assessment_ready/);
  assert.match(ui.caseButton("one").textContent, /Last progress/);
  await ui.load("one");
  assert.match(ui.byId("message").textContent, /^Request loaded/);
  assert.equal(ui.caseButton("one").getAttribute("aria-current"), "true");
  assert.equal(ui.caseButton("two").getAttribute("aria-current"), "false");
  assert.equal(ui.location.search, "?case=one");
  assert.equal(ui.navigations.at(-1), "/vendor-onboarding?case=one");
  assert.equal(ui.byId("case-reference").children.at(-1).tagName, "A");
  assert.equal(ui.byId("case-reference").children.at(-1).href, "/vendor-onboarding?case=one");
  ui.byId("rationale").value = "Current review draft";
  await ui.click("refresh");
  assert.match(ui.byId("message").textContent, /^Requests refreshed/);
  assert.equal(ui.byId("rationale").value, "Current review draft");
  assert.equal(ui.calls.every(call => call.method === "GET"), true);
});

for (const format of ["json", "html"]) test(`${format} vendor session loss clears all private views and cannot re-enable stale actions`, async () => {
  let deny = false;
  const ui = fixture([record("one")], call => deny ? {status:401, ok:false,
    json:async()=> { if(format==="html")throw new Error("not JSON");return {detail:"Sign in"}; }} : undefined);
  await ui.settle(); await ui.load("one");
  ui.byId("purpose").value="private unsent draft";deny=true;
  await ui.click("refresh");
  assert.equal(ui.byId("case-title").textContent,"");assert.equal(ui.byId("cases").children.length,0);
  assert.equal(ui.byId("purpose").value,"");assert.equal(ui.byId("create").disabled,true);
  const count=ui.calls.length;await ui.click("refresh");assert.equal(ui.calls.length,count);
});

test("vendor context change rejects a delayed successful response and locks the old page", async () => {
  let resolve;
  const ui=fixture([record("one")],call=>call.url.endsWith('/cases/one')?new Promise(done=>{resolve=done;}):undefined);
  await ui.settle();ui.caseButton("one").listeners.click();await new Promise(setImmediate);
  ui.root.dataset.workspaceContext="b".repeat(64);resolve(response(record("one")));await ui.settle();
  assert.equal(ui.byId("case-title").textContent,"");assert.equal(ui.byId("refresh").disabled,true);
});

test("vendor action denial preserves readable case and drafts but disables the denied action", async () => {
  const ui=fixture([record("one")],call=>call.method==="POST"?response({detail:{code:"permission_denied",message:"Collection unavailable"}},403):undefined);
  await ui.settle();await ui.load("one");ui.byId("purpose").value="keep this draft";
  await ui.click("collect");
  assert.match(ui.byId("case-title").textContent,/one/);assert.equal(ui.byId("purpose").value,"keep this draft");
  assert.equal(ui.byId("collect").disabled,true);assert.equal(ui.byId("refresh").disabled,false);
  const count=ui.calls.length;await ui.click("collect");assert.equal(ui.calls.length,count);
});

test("prepared action shows exact authority effects assumptions and full payload", async () => {
  const prepared = record("reviewed", {
    stage: "action_prepared",
    operation: {
      state: "prepared",
      approval_card: approvalCard(),
      payload: {project: "VEND", summary: "Review Northstar",
        description: "Use the exact reviewed evidence and scope."},
    },
  });
  const ui = fixture([prepared]);
  await ui.settle();
  await ui.load("reviewed");
  const text = ui.byId("operation").textContent;
  assert.match(text, /Create the reviewed Jira task in VEND project/);
  assert.match(text, /nothing happens until you approve it/);
  assert.match(text, /approving as Riley Reviewer/);
  assert.match(text, /can't be undone automatically/);
  assert.match(text, /Creates one externally persistent Jira task/);
  assert.match(text, /Jira automation may notify project members/);
  assert.match(text, /THE TICKET/);
  assert.doesNotMatch(text, /tenant-a|user:reviewer|2{64}|3{64}|digest/);
  assert.match(text, /Use the exact reviewed evidence and scope/);
  assert.equal(ui.byId("approve").disabled, false);
});

test("an incomplete approval card cannot select or enable a prepared operation", async () => {
  const broken = record("broken-card", {
    stage: "action_prepared",
    operation: {
      state: "prepared",
      approval_card: {...approvalCard(), consequences: {known_effects: []}},
      payload: {project: "VEND", summary: "Review Northstar", description: "Reviewed"},
    },
  });
  const ui = fixture([broken]);
  await ui.settle();
  await ui.load("broken-card");
  assert.match(ui.byId("message").textContent, /prepare and review a fresh operation/i);
  assert.equal(ui.byId("approve").disabled, true);
  assert.equal(ui.byId("operation").textContent, "");
  assert.equal(ui.caseButton("broken-card").getAttribute("aria-current"), "false");
});

test("approval submits the exact card binding displayed to the reviewer", async () => {
  const prepared = record("reviewed", {
    stage: "action_prepared",
    operation: {
      state: "prepared",
      approval_card: approvalCard(),
      payload: {project: "VEND", summary: "Review Northstar", description: "Reviewed"},
    },
  });
  let submitted;
  const ui = fixture([prepared], call => {
    if (!call.url.endsWith("/approve-action")) return undefined;
    submitted = call.body;
    return response({...prepared, revision: 2, stage: "action_approved",
      operation: {...prepared.operation, state: "approved"}});
  });
  await ui.settle();
  await ui.load("reviewed");
  await ui.click("approve");
  assert.deepEqual(submitted, {
    expected_revision: 1,
    confirm: true,
    approval_binding_sha256: "1".repeat(64),
  });
});

test("a server authority denial stays visible and never retries approval", async () => {
  const prepared = record("reviewed", {
    stage: "action_prepared",
    operation: {
      state: "prepared",
      approval_card: approvalCard(),
      payload: {project: "VEND", summary: "Review Northstar", description: "Reviewed"},
    },
  });
  const ui = fixture([prepared], call => call.url.endsWith("/approve-action")
    ? response({detail: {code: "permission_denied",
      message: "Your role cannot approve this operation.",
      next_action: "Ask a workspace administrator to review your access."}}, 403)
    : undefined);
  await ui.settle();
  await ui.load("reviewed");
  await ui.click("approve");

  assert.equal(ui.calls.filter(call => call.url.endsWith("/approve-action")).length, 1);
  assert.match(ui.byId("message").textContent, /role cannot approve/i);
  assert.match(ui.byId("message").textContent, /workspace administrator/i);
  assert.equal(ui.byId("approve").disabled, true);
  await ui.click("approve");
  assert.equal(ui.calls.filter(call => call.url.endsWith("/approve-action")).length, 1);
});

test("bounded queue controls navigate three pages and reset the cursor for a stable filter", async () => {
  const rows = [record("one"), record("two"), record("three"), record("four"), record("five")];
  const ui = fixture(rows, call => {
    const url = new URL(call.url, "https://lightwork.test");
    if (call.method !== "GET" || !url.pathname.endsWith("/cases")) return undefined;
    if (url.searchParams.get("view") === "unresolved") return response({
      schema: "lightwork.vendor-onboarding.case-page.v1", view: "unresolved",
      cases: [rows[3]], has_more: false, next_cursor: null,
    });
    const cursor = url.searchParams.get("cursor") || "";
    const pages = {
      "": {cases: rows.slice(0, 2), has_more: true, next_cursor: "cursor-one"},
      "cursor-one": {cases: rows.slice(2, 4), has_more: true, next_cursor: "cursor-two"},
      "cursor-two": {cases: rows.slice(4), has_more: false, next_cursor: null},
    };
    return response({schema: "lightwork.vendor-onboarding.case-page.v1", view: "all", ...pages[cursor]});
  });
  await ui.settle();
  assert.deepEqual(ui.byId("cases").children.map(item => item.dataset.caseId), ["one", "two"]);
  assert.equal(ui.byId("page-previous").disabled, true);
  assert.equal(ui.byId("page-next").disabled, false);
  await ui.click("page-next");
  assert.deepEqual(ui.byId("cases").children.map(item => item.dataset.caseId), ["three", "four"]);
  assert.match(ui.byId("page-status").textContent, /Page 2/);
  await ui.click("page-next");
  assert.deepEqual(ui.byId("cases").children.map(item => item.dataset.caseId), ["five"]);
  assert.equal(ui.byId("page-next").disabled, true);
  await ui.click("page-previous");
  assert.deepEqual(ui.byId("cases").children.map(item => item.dataset.caseId), ["three", "four"]);
  await ui.filter("unresolved");
  assert.deepEqual(ui.byId("cases").children.map(item => item.dataset.caseId), ["four"]);
  assert.match(ui.calls.at(-1).url, /view=unresolved/);
  assert.doesNotMatch(ui.calls.at(-1).url, /cursor=/);
  assert.equal(ui.byId("page-previous").disabled, true);
});

test("malformed pagination metadata fails closed without enabling navigation", async () => {
  const ui = fixture([], call => call.url.endsWith("/cases") ? response({
    schema: "lightwork.vendor-onboarding.case-page.v1", view: "all", cases: [],
    has_more: true, next_cursor: "private cursor with spaces",
  }) : undefined);
  await ui.settle();
  assert.match(ui.byId("message").textContent, /next page of requests is unavailable/i);
  assert.equal(ui.byId("page-next").disabled, true);
  assert.equal(ui.byId("page-previous").disabled, true);
});

test("a lost intake response reuses one retained submission key before opening the stable case", async () => {
  const rows = [];
  let submissions = 0;
  const stable = record("stable", {stage: "intake", evidence: null, assessment: null});
  const ui = fixture(rows, call => {
    if (call.method !== "POST" || !call.url.endsWith("/cases")) return undefined;
    submissions += 1;
    if (submissions === 1) throw new Error("simulated response loss");
    rows.push(stable);
    return response(stable, 201);
  });
  await ui.settle();
  ui.byId("vendor").value = "Stable intake";
  ui.byId("document").value = "document-stable";
  ui.byId("project").value = "VEND";
  ui.byId("purpose").value = "Recover this request";
  ui.byId("freshness").value = "365";
  await ui.submit();
  assert.match(ui.byId("message").textContent, /response loss/);
  const first = ui.calls.filter(call => call.method === "POST").at(-1).body;
  assert.match(first.submission_key, /^[A-Za-z0-9][A-Za-z0-9_.:-]{15,127}$/);
  assert.ok(ui.storage.has(`lightwork:vendor-intake:v1:${"f".repeat(64)}`));
  assert.equal(JSON.parse(ui.storage.get(`lightwork:vendor-intake:v1:${"f".repeat(64)}`)).fingerprint, undefined);
  await ui.submit();
  const second = ui.calls.filter(call => call.method === "POST").at(-1).body;
  assert.equal(second.submission_key, first.submission_key);
  assert.equal(ui.byId("case-title").textContent, "Vendor stable");
  assert.match(ui.byId("case-reference").textContent, /Link to this request/);
  assert.match(ui.byId("case-reference").children.at(-1).href, /case=stable/);
  assert.equal(ui.storage.has(`lightwork:vendor-intake:v1:${"f".repeat(64)}`), false);
});

test("a lost intake response reuses its durable key after an app restart", async () => {
  const storage = new Map();
  const first = fixture([], call => {
    if (call.method === "POST" && call.url.endsWith("/cases"))
      throw new Error("simulated app shutdown after dispatch");
    return undefined;
  }, "", null, storage);
  await first.settle();
  first.byId("vendor").value = "Restart-safe intake";
  first.byId("project").value = "VEND";
  first.byId("purpose").value = "Preserve one request across restart";
  first.byId("freshness").value = "365";
  await first.submit();
  const original = first.calls.filter(call => call.method === "POST").at(-1).body;

  const stable = record("restart-safe", {stage: "intake", evidence: null, assessment: null});
  const second = fixture([], call => {
    if (call.method === "POST" && call.url.endsWith("/cases")) return response(stable, 201);
    return undefined;
  }, "", null, storage);
  await second.settle();
  second.byId("vendor").value = "Restart-safe intake";
  second.byId("project").value = "VEND";
  second.byId("purpose").value = "Preserve one request across restart";
  second.byId("freshness").value = "365";
  await second.submit();
  const replay = second.calls.filter(call => call.method === "POST").at(-1).body;
  assert.equal(replay.submission_key, original.submission_key);
  assert.equal(second.location.search, "?case=restart-safe");
  assert.equal(storage.has(`lightwork:vendor-intake:v1:${"f".repeat(64)}`), false);
});

test("a stale edit loads and displays the bounded current record without retrying the mutation", async () => {
  const rows = [record("one")];
  const current = record("one", {revision: 2, stage: "pending_review"});
  let mutations = 0;
  const ui = fixture(rows, call => {
    if (!call.url.endsWith("/review")) return undefined;
    mutations += 1; rows[0] = current;
    return response({detail: {
      schema: "lightwork.error.v1", code: "revision_conflict",
      message: "Vendor onboarding case revision changed", retryable: false,
      next_action: "Review the current case.", current: {
        schema: "lightwork.vendor-onboarding.conflict-current.v1",
        id: "one", revision: 2, stage: "pending_review", updated_at: 2000,
        vendor_name: "Vendor one", work_item: {
          lifecycle: "Awaiting approval", next_action: "review_assessment",
          technical_effect: "not_verified", business_outcome: "pending",
        },
      },
    }}, 409);
  });
  await ui.settle(); await ui.load("one");
  ui.byId("rationale").value = "Different tab change";
  await ui.click("review-approve");
  assert.equal(mutations, 1);
  assert.match(ui.byId("message").textContent, /^Someone else updated this request.*latest version.*now open/);
  assert.doesNotMatch(ui.byId("message").textContent, /revision changed/);
  assert.doesNotMatch(ui.byId("status").textContent, /Version/);
  assert.equal(ui.byId("rationale").value, "");
});

test("request details are editable in app and carry the selected revision", async () => {
  let submitted;
  const current = record("one", {stage: "intake", evidence: null, assessment: null});
  const updated = record("one", {
    revision: 2, stage: "intake", evidence: null, assessment: null,
    project: "RISK", purpose: "Review a changed use", freshness_days: 180,
    due_at: 1805184000,
  });
  const ui = fixture([current], call => {
    if (!call.url.endsWith("/draft")) return undefined;
    submitted = call.body;
    return response(updated);
  });
  await ui.settle(); await ui.load("one");
  ui.byId("case-project").value = "RISK";
  ui.byId("case-purpose").value = "Review a changed use";
  ui.byId("case-freshness").value = "180";
  ui.byId("case-due").value = "2027-03-06";
  await ui.click("save-draft");
  assert.equal(submitted.expected_revision, 1);
  assert.deepEqual(submitted, {
    expected_revision: 1,
    project: "RISK",
    purpose: "Review a changed use",
    freshness_days: 180,
    due_at: Date.parse("2027-03-06T12:00:00Z") / 1000,
  });
  assert.doesNotMatch(ui.byId("status").textContent, /Version/);
  assert.equal(ui.byId("case-purpose").value, "Review a changed use");
});

test("a malformed current-record conflict is rejected without replacing the selected version", async () => {
  const rows = [record("one")];
  const ui = fixture(rows, call => call.url.endsWith("/review") ? response({detail: {
    schema: "lightwork.error.v1", code: "revision_conflict", message: "Changed",
    current: {schema: "lightwork.vendor-onboarding.conflict-current.v1", id: "one", revision: 2},
  }}, 409) : undefined);
  await ui.settle(); await ui.load("one");
  ui.byId("rationale").value = "Attempted edit";
  await ui.click("review-approve");
  assert.match(ui.byId("message").textContent, /Someone else changed this request and it couldn.t be reloaded/i);
  assert.doesNotMatch(ui.byId("status").textContent, /Version/);
  assert.equal(ui.calls.filter(call => call.method === "POST").length, 1);
});

test("a linked vendor request reads the exact authorized case without mutating it", async () => {
  const ui = fixture([record("requested"), record("another")], null, "?case=requested");
  await ui.settle();
  assert.match(ui.byId("message").textContent, /Linked request loaded/);
  assert.equal(ui.caseButton("requested").getAttribute("aria-current"), "true");
  assert.equal(ui.calls.length, 2);
  assert.ok(ui.calls.every(call => call.method === "GET"));
});

test("a linked request that is no longer accessible reports failure without selecting another", async () => {
  const ui = fixture([record("another")], null, "?case=missing");
  await ui.settle();
  assert.match(ui.byId("message").textContent, /no longer exists/);
  assert.equal(ui.byId("review-approve").disabled, true);
  assert.ok(ui.calls.every(call => call.method === "GET"));
});

test("switching cases clears decision drafts and updates current-request context", async () => {
  const ui = fixture([record("one"), record("two")]);
  await ui.settle(); await ui.load("one");
  ui.byId("rationale").value = "Only applies to vendor one";
  ui.byId("acceptance-reason").value = "One was accepted";
  ui.byId("answer-training").value = "no";
  ui.byId("note-training").value = "Only applies to vendor one";
  await ui.load("two");
  assert.equal(ui.byId("rationale").value, "");
  assert.equal(ui.byId("acceptance-reason").value, "");
  assert.equal(ui.byId("answer-training").value, "unknown");
  assert.equal(ui.byId("note-training").value, "");
  assert.match(ui.byId("case-reference").children.at(-1).href, /case=two/);
  assert.equal(ui.caseButton("two").getAttribute("aria-current"), "true");
  assert.equal(ui.caseButton("one").getAttribute("aria-current"), "false");
});

test("a connection detour records only the selected request and its workspace context", async () => {
  const ui = fixture([record("requested")]);await ui.settle();await ui.load("requested");
  ui.root.listeners.click({target:{closest:()=>({getAttribute:()=>"/connections"})},preventDefault(){throw new Error("Valid detour must remain usable");}});
  const saved = JSON.parse(ui.storage.get("lightwork:connection-task:v1"));
  assert.equal(saved.case_id,"requested");assert.equal(saved.context,"f".repeat(64));assert.equal(typeof saved.created_at,"number");
  assert.deepEqual(Object.keys(saved).sort(),["case_id","context","created_at"]);assert.ok(ui.calls.every(call=>call.method==="GET"));
});

test("a returned request is never read under a different workspace even if its ID exists there", async () => {
  const ui=fixture([record("same-id")],null,"?case=same-id",{case_id:"same-id",context:"e".repeat(64),created_at:Date.now()});await ui.settle();
  assert.equal(ui.calls.length,0);assert.match(ui.byId("message").textContent,/workspace.*changed/i);assert.equal(ui.byId("execute").disabled,true);
});

test("the selected case explains the promised outcome and support boundary", async () => {
  const ui = fixture([record("one")]);
  await ui.settle(); await ui.load("one");
  assert.match(ui.byId("scope").textContent, /one Jira Task matches the exact approved payload/);
  assert.match(ui.byId("scope").textContent, /authorized person accepts or rejects/);
  assert.match(ui.byId("scope").textContent, /procurement approval or payment/);
  assert.doesNotMatch(ui.byId("scope").textContent, /Supported deployment|single persistent/i);
});

test("cancellation requires an explicit local-only confirmation and preserves uncertain delivery", async () => {
  const rows = [record("one", {stage: "reconciliation_required",
    operation: {state: "reconciliation_required"}, reconciliation:reconciliationSummary()})];
  let submitted;
  const ui = fixture(rows, call => {
    if (!call.url.endsWith("/cancel")) return undefined;
    submitted = call.body;
    rows[0] = {...rows[0], revision: 2, cancellation: {requested_by: "reviewer", requested_at: 1800000000,
      rationale: "Stop local work", dispatch_state_at_cancellation: "possibly_dispatched", effect_reversal: "not_requested"}};
    return response(rows[0]);
  });
  await ui.settle(); await ui.load("one");
  await ui.click("cancel");
  assert.equal(submitted, undefined);
  ui.byId("cancellation-reason").value = "Stop local work";
  await ui.click("cancel");
  assert.equal(submitted, undefined);
  ui.byId("cancellation-confirm").checked = true;
  await ui.click("cancel");
  assert.deepEqual(submitted, {expected_revision: 1, rationale: "Stop local work", confirm: true});
  assert.match(ui.byId("cancellation-status").textContent, /outcome is still uncertain/);
  assert.match(ui.byId("cancellation-status").textContent, /does not delete or reverse/);
  assert.equal(ui.byId("reconcile").disabled, false);
  for (const id of ["cancel", "execute", "accept", "reject", "collect", "prepare"])
    assert.equal(ui.byId(id).disabled, true, id);
});

test("verified cancellation reports retained ticket and offers only current readback", async () => {
  const ui = fixture([record("one", {stage: "cancelled", operation: {
    state: "verified", external_confirmation: {verified: true, key: "VEND-1"}}, cancellation: {
    requested_by: "reviewer", requested_at: 1800000000, rationale: "Priorities changed",
    dispatch_state_at_cancellation: "possibly_dispatched", effect_reversal: "not_requested"},
    attention: {state:"cancelled",kind:"workflow",requires_attention:false,
      effective_at:1800000000,as_of:1800000100}})]);
  await ui.settle(); await ui.load("one");
  assert.match(ui.byId("cancellation-status").textContent, /VEND-1.*remains/);
  assert.match(ui.byId("outcome").textContent, /Cancelled.*no acceptance decision/);
  assert.match(ui.byId("status").textContent, /Attention: Cancelled/);
  assert.equal(ui.byId("reconcile").disabled, false);
  for (const id of ["cancel", "execute", "accept", "reject", "collect", "prepare"])
    assert.equal(ui.byId(id).disabled, true, id);
});

test("changing requests clears the cancellation reason and confirmation", async () => {
  const ui = fixture([record("one"), record("two")]);
  await ui.settle(); await ui.load("one");
  ui.byId("cancellation-reason").value = "Only stop request one";
  ui.byId("cancellation-confirm").checked = true;
  await ui.load("two");
  assert.equal(ui.byId("cancellation-reason").value, "");
  assert.equal(ui.byId("cancellation-confirm").checked, false);
});

test("stale cancellation requests require current-result review without automatic retry", async () => {
  const ui = fixture([record("one", {operation: {state: "approved"}})], call => {
    if (call.url.endsWith("/cancel")) return response({detail: {
      code: "revision_conflict", message: "Request revision changed",
    }}, 409);
  });
  await ui.settle(); await ui.load("one");
  ui.byId("cancellation-reason").value = "Stop this request";
  ui.byId("cancellation-confirm").checked = true;
  await ui.click("cancel");
  assert.match(ui.byId("message").textContent, /Refresh requests, review the current ticket result/);
  assert.equal(ui.calls.filter(call => call.method === "POST").length, 1);
  assert.equal(ui.byId("refresh").disabled, false);
});

test("refreshing or reselecting an unchanged case preserves corrections and submits them for approval", async () => {
  let submitted;
  const ui = fixture([record("one")], call => {
    if (!call.url.endsWith("/review")) return undefined;
    submitted = call.body;
    return response(record("one", { revision: 2 }));
  });
  await ui.settle(); await ui.load("one");
  const answer = ui.byId("answer-training");
  const note = ui.byId("note-training");
  answer.value = "no";
  note.value = "Vendor terms reviewed";
  ui.byId("rationale").value = "Approve with corrected answer";
  ui.advanceTime(3000);
  await ui.click("refresh");
  await ui.load("one");
  ui.advanceTime(2000);
  assert.equal(ui.byId("answer-training"), answer);
  assert.equal(ui.byId("note-training"), note);
  assert.equal(answer.value, "no");
  assert.equal(note.value, "Vendor terms reviewed");
  assert.equal(ui.byId("rationale").value, "Approve with corrected answer");
  await ui.click("review-approve");
  assert.equal(submitted.expected_revision, 1);
  assert.equal(submitted.decision, "approved");
  assert.equal(submitted.rationale, "Approve with corrected answer");
  assert.equal(submitted.review_seconds, 5);
  assert.deepEqual(submitted.corrections, { training: { answer: "no", note: "Vendor terms reviewed" } });
  assert.equal(ui.byId("rationale").value, "");
});

test("reordered assessment object keys preserve the same review draft", async () => {
  const records = [record("one")];
  const ui = fixture(records);
  await ui.settle(); await ui.load("one");
  ui.byId("answer-training").value = "no";
  ui.byId("note-training").value = "Draft correction note";
  ui.byId("rationale").value = "Draft review reason";
  records[0] = record("one", { assessment: {
    answers: { training: { note: "", answer: "unknown" } },
    template_snapshot: { questions: [{ guidance: "Check terms.", section: "Data", text: "Customer training?", id: "training" }] },
    result: { risk_rating: "low", total: 1, answered: 1 },
    status: "pending",
  } });
  await ui.click("refresh");
  assert.equal(ui.byId("answer-training").value, "no");
  assert.equal(ui.byId("note-training").value, "Draft correction note");
  assert.equal(ui.byId("rationale").value, "Draft review reason");
  assert.match(ui.byId("message").textContent, /^Requests refreshed/);
});

for (const change of ["revision", "assessment", "assessment answer"]) {
  test(`refreshing a changed ${change} resets stale drafts and requires a new decision reason`, async () => {
    const records = [record("one")];
    const ui = fixture(records);
    await ui.settle(); await ui.load("one");
    ui.byId("answer-training").value = "no";
    ui.byId("note-training").value = "Review of old evidence";
    ui.byId("rationale").value = "Approval of the old version";
    ui.byId("acceptance-reason").value = "Acceptance of the old version";
    if (change === "revision") records[0] = record("one", { revision: 2 });
    else if (change === "assessment") {
      records[0] = record("one");
      records[0].assessment = { ...records[0].assessment, id: "replacement-assessment" };
    } else {
      records[0] = record("one");
      records[0].assessment.answers.training = { answer: "yes", note: "Updated source" };
    }
    await ui.click("refresh");
    assert.equal(ui.byId("answer-training").value, records[0].assessment.answers.training.answer);
    assert.equal(ui.byId("note-training").value, records[0].assessment.answers.training.note);
    assert.equal(ui.byId("rationale").value, "");
    assert.equal(ui.byId("acceptance-reason").value, "");
    assert.match(ui.byId("message").textContent, /changed.*draft.*reset/i);
    await ui.click("review-approve");
    assert.match(ui.byId("message").textContent, /Enter a review rationale/);
    assert.equal(ui.calls.some(call => call.method === "POST"), false);
  });
}

test("refresh preserves acceptance text only for the same case version", async () => {
  const records = [record("one", { operation: { state: "verified" } })];
  const ui = fixture(records);
  await ui.settle(); await ui.load("one");
  ui.byId("acceptance-reason").value = "Verified current external result";
  await ui.click("refresh");
  assert.equal(ui.byId("acceptance-reason").value, "Verified current external result");
  records[0] = record("one", { revision: 2, operation: { state: "verified" } });
  await ui.click("refresh");
  assert.equal(ui.byId("acceptance-reason").value, "");
  await ui.click("accept");
  assert.match(ui.byId("message").textContent, /Enter an acceptance or rejection reason/);
  assert.equal(ui.calls.some(call => call.method === "POST"), false);
});

test("acceptance evidence invalidation opens the named changed source without reusing the decision", async () => {
  const rows = [record("one", {stage:"execution_completed",operation:{state:"verified"}})];
  const current = record("one", {revision:2,stage:"acceptance_reevaluation_required",operation:{state:"verified"},
    acceptance_evidence_check:{schema:"lightwork.vendor-onboarding.acceptance-evidence-check.v1",
      status:"reevaluation_required",checked_at:1800000000,reviewed_evidence_sha256:"c".repeat(64),
      reviewed_assessment_id:"AIV-reviewed",documents:[{reference:"EVR-"+"1".repeat(32),source:"gdrive",
        document_id:"security-paper",reviewed_version:"v1",current_version:"v2",status:"changed"}]}});
  let attempts = 0;
  const ui = fixture(rows, call => {
    if (!call.url.endsWith("/accept")) return undefined;
    attempts += 1; rows[0] = current;
    return response({detail:{schema:"lightwork.error.v1",code:"evidence_reevaluation_required",
      message:"Reviewed evidence changed.",retryable:false,next_action:"Start reevaluation.",current:{
        schema:"lightwork.vendor-onboarding.conflict-current.v1",id:"one",revision:2,
        stage:"acceptance_reevaluation_required",updated_at:1800000000,vendor_name:"Vendor one",
        work_item:{lifecycle:"Awaiting approval",next_action:"start_reevaluation_request",technical_effect:"verified",business_outcome:"pending"}}}},409);
  });
  await ui.settle(); await ui.load("one");
  ui.byId("acceptance-reason").value = "Accept prior review";
  await ui.click("accept");
  assert.equal(attempts,1);
  assert.match(ui.byId("message").textContent,/verified ticket remains.*prior review cannot be reused/i);
  assert.match(ui.byId("acceptance-evidence-check").textContent,/changed since it was reviewed/i);
  assert.equal(ui.byId("accept").disabled,true);
  assert.equal(ui.byId("reject").disabled,false);
  assert.equal(ui.byId("acceptance-reason").disabled,false);
  assert.equal(ui.byId("renew").disabled,false);
  assert.equal(ui.byId("acceptance-reason").value,"");
});

test("approval evidence invalidation names the source and offers only reevaluation", async () => {
  const prepared = record("one", {stage:"action_pending_approval",operation:{state:"prepared",
    approval_card:approvalCard(),payload:{project:"VEND",summary:"Review Northstar",description:"Reviewed"}}});
  const rows = [prepared];
  const current = record("one", {revision:2,stage:"acceptance_reevaluation_required",
    work_item:{...prepared.work_item,lifecycle:"Awaiting approval",next_action:"start_reevaluation_request",
      technical_effect:"not_verified"},
    acceptance_evidence_check:{schema:"lightwork.vendor-onboarding.acceptance-evidence-check.v1",
      status:"reevaluation_required",checked_at:1800000000,reviewed_evidence_sha256:"c".repeat(64),
      reviewed_assessment_id:"AIV-reviewed",documents:[{reference:"EVR-"+"1".repeat(32),source:"gdrive",
        document_id:"security-paper",reviewed_version:"v1",current_version:"v2",status:"changed"}]}});
  const ui = fixture(rows, call => {
    if (!call.url.endsWith("/approve-action")) return undefined;
    rows[0] = current;
    return response({detail:{schema:"lightwork.error.v1",code:"evidence_reevaluation_required",
      message:"Reviewed evidence changed.",retryable:false,next_action:"Start reevaluation.",current:{
        schema:"lightwork.vendor-onboarding.conflict-current.v1",id:"one",revision:2,
        stage:"acceptance_reevaluation_required",updated_at:1800000000,vendor_name:"Vendor one",
        work_item:{lifecycle:"Awaiting approval",next_action:"start_reevaluation_request",
          technical_effect:"not_verified",business_outcome:"pending"}}}},409);
  });
  await ui.settle(); await ui.load("one"); await ui.click("approve");
  assert.match(ui.byId("message").textContent,/stale prepared action was invalidated.*prior review cannot be reused/i);
  assert.match(ui.byId("acceptance-evidence-check").textContent,/changed since it was reviewed/i);
  for (const id of ["collect","assess","review-approve","review-reject","prepare","approve","execute"])
    assert.equal(ui.byId(id).disabled,true,id);
  assert.equal(ui.byId("renew").disabled,false);
});

test("reviewed evidence export previews its manifest and downloads the exact confirmed binding", async () => {
  const row = record("one", {review_history:[{decision:"approved"}]});
  const bundle = evidenceExport("one",1);
  const ui = fixture([row], call => {
    if (call.url.endsWith("/evidence-export-preview")) return response(bundle);
    if (call.url.endsWith("/evidence-export")) return response(bundle);
    return undefined;
  });
  await ui.settle(); await ui.load("one");
  assert.equal(ui.byId("export-preview").disabled,false);
  assert.equal(ui.byId("export-download").disabled,true);
  await ui.click("export-preview");
  assert.match(ui.byId("export-status").textContent,/1 reviewed claim.*1 evidence source included.*0 left out/i);
  assert.match(ui.byId("export-manifest").textContent,/Document 1: included \(Google Drive document, still valid\)/i);
  assert.doesNotMatch(ui.byId("export-manifest").textContent,/EVR-/);
  assert.equal(ui.byId("export-confirm").disabled,false);
  ui.byId("export-confirm").checked = true; ui.byId("export-confirm").listeners.change();
  assert.equal(ui.byId("export-download").disabled,false);
  await ui.click("export-download");
  const request = ui.calls.find(call => call.url.endsWith("/evidence-export"));
  assert.deepEqual(request.body,{expected_revision:1,expected_export_sha256:"b".repeat(64),confirm:true});
  assert.equal(ui.downloads.length,1);
  assert.equal(ui.downloads[0].name,"lightwork-evidence-one.json");
  assert.equal(ui.downloads[0].blob.type,"application/json");
  assert.deepEqual(JSON.parse(await ui.downloads[0].blob.text()),bundle);
  assert.match(ui.byId("export-status").textContent,/downloaded.*Preview again/i);
  assert.equal(ui.byId("export-download").disabled,true);
});

test("a withheld export source is rendered only as an opaque dependency", async () => {
  const reference = "EVR-" + "2".repeat(32);
  const bundle = evidenceExport("one",1,{
    claims:[{claim_id:"training",answer:"unknown",note:"Source access is unavailable",source_basis:"document",
      evidence_refs:[],withheld_evidence_refs:[reference],citations:[],review_justification:"Human review retained the source-access limitation"}],
    manifest:{schema:"lightwork.vendor-onboarding.evidence-export-manifest.v1",included:[],
      withheld:[{reference,dependency_type:"external_evidence",disposition:"withheld",reason:"current_source_access_unavailable"}],
      included_count:0,withheld_count:1,complete:false},
  });
  const ui = fixture([record("one",{review_history:[{}]})], call =>
    call.url.endsWith("/evidence-export-preview") ? response(bundle) : undefined);
  await ui.settle(); await ui.load("one"); await ui.click("export-preview");
  assert.match(ui.byId("export-status").textContent,/0 evidence sources included.*1 left out/i);
  assert.match(ui.byId("export-manifest").textContent,/Document 1: left out because Lightwork can.t reach it right now/i);
  assert.doesNotMatch(ui.byId("export-manifest").textContent,/private-source|credential|secret/i);
  assert.equal(ui.byId("export-confirm").disabled,false);
});

test("cross-case or malformed export responses fail closed and never create a download", async () => {
  for (const bundle of [
    evidenceExport("other",1),
    evidenceExport("one",1,{manifest:{schema:"lightwork.vendor-onboarding.evidence-export-manifest.v1",
      included:[],withheld:[{reference:"private-source-id",dependency_type:"external_evidence",disposition:"withheld",reason:"current_source_access_unavailable"}],
      included_count:0,withheld_count:1,complete:false}}),
  ]) {
    const ui = fixture([record("one",{review_history:[{}]})], call =>
      call.url.endsWith("/evidence-export-preview") ? response(bundle) : undefined);
    await ui.settle(); await ui.load("one"); await ui.click("export-preview");
    assert.match(ui.byId("message").textContent,/export response was incomplete/i);
    assert.equal(ui.byId("export-download").disabled,true);
    assert.equal(ui.downloads.length,0);
  }
});

test("lost export permission clears the reviewed manifest and blocks download replay", async () => {
  const bundle = evidenceExport("one",1);
  let denied = false;
  const ui = fixture([record("one",{review_history:[{}]})], call => {
    if (call.url.endsWith("/evidence-export-preview")) return response(bundle);
    if (call.url.endsWith("/evidence-export") && denied) return response({detail:{schema:"lightwork.error.v1",
      code:"permission_denied",message:"Evidence export access is unavailable.",retryable:false,next_action:"Review access."}},403);
    return undefined;
  });
  await ui.settle(); await ui.load("one"); await ui.click("export-preview");
  ui.byId("export-confirm").checked=true;ui.byId("export-confirm").listeners.change();denied=true;
  await ui.click("export-download");
  assert.match(ui.byId("message").textContent,/access is unavailable/i);
  assert.equal(ui.byId("export-manifest").textContent,"");
  assert.equal(ui.byId("export-preview").disabled,true);
  assert.equal(ui.byId("export-download").disabled,true);
  assert.equal(ui.downloads.length,0);
});

test("a pending refresh protects draft controls and prevents duplicate refresh or approval", async () => {
  const pending = deferred();
  let refreshing = false;
  const ui = fixture([record("one")], call => refreshing && call.url.endsWith("/cases/one") ? pending.promise : undefined);
  await ui.settle(); await ui.load("one");
  ui.byId("answer-training").value = "no";
  ui.byId("note-training").value = "Unsaved review note";
  ui.byId("rationale").value = "Unsaved reason";
  refreshing = true;
  ui.byId("refresh").listeners.click();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(ui.root.getAttribute("aria-busy"), "true");
  for (const id of ["refresh", "answer-training", "note-training", "rationale", "review-approve"])
    assert.equal(ui.byId(id).disabled, true, id);
  const requests = ui.calls.length;
  ui.byId("refresh").listeners.click();
  ui.byId("review-approve").listeners.click();
  assert.equal(ui.calls.length, requests);
  pending.resolve(response(record("one")));
  await ui.settle();
  assert.equal(ui.root.getAttribute("aria-busy"), "false");
  assert.equal(ui.byId("answer-training").disabled, false);
  assert.equal(ui.byId("answer-training").value, "no");
  assert.equal(ui.byId("note-training").value, "Unsaved review note");
  assert.equal(ui.byId("rationale").value, "Unsaved reason");
});

test("a failed refresh leaves review drafts intact and reports the error", async () => {
  let failRefresh = false;
  const ui = fixture([record("one")], call => failRefresh && call.url.endsWith("/cases/one")
    ? response({ detail: "Case refresh temporarily unavailable" }, 503) : undefined);
  await ui.settle(); await ui.load("one");
  ui.byId("answer-training").value = "no";
  ui.byId("note-training").value = "Unsaved note";
  ui.byId("rationale").value = "Unsaved reason";
  failRefresh = true;
  await ui.click("refresh");
  assert.equal(ui.byId("answer-training").value, "no");
  assert.equal(ui.byId("note-training").value, "Unsaved note");
  assert.equal(ui.byId("rationale").value, "Unsaved reason");
  assert.match(ui.byId("message").textContent, /Could not finish that\. This is temporarily unavailable\./);
  assert.doesNotMatch(ui.byId("message").textContent, /Case refresh/);
  assert.equal(ui.byId("message").getAttribute("role"), "alert");
  assert.equal(ui.byId("refresh").disabled, false);
});

test("structured API failures show customer text without exposing transport details", async () => {
  let failRefresh = false;
  const ui = fixture([record("one")], call => failRefresh && call.url.endsWith("/cases/one")
    ? response({ detail: { schema: "lightwork.error.v1", code: "revision_conflict",
      message: "This request changed. Reload it before deciding.", retryable: false,
      next_action: "Reload the request." } }, 409) : undefined);
  await ui.settle(); await ui.load("one");
  failRefresh = true;
  await ui.click("refresh");
  assert.match(ui.byId("message").textContent, /This request changed/);
  assert.doesNotMatch(ui.byId("message").textContent, /revision_conflict|lightwork\.error/);
});

test("stages gate human review, execution, reconciliation and acceptance separately", async () => {
  const ui = fixture([
    record("review"),
    record("approved", { operation: { state: "approved" } }),
    record("uncertain", { operation: { state: "reconciliation_required" },
      reconciliation:reconciliationSummary() }),
    record("verified", { operation: { state: "verified" } }),
    record("accepted", { operation: { state: "verified" }, outcome: { accepted: true } }),
  ]);
  await ui.settle(); await ui.load("review");
  assert.equal(ui.byId("rationale").disabled, false);
  assert.equal(ui.byId("corrections").querySelectorAll("select")[0].disabled, false);
  assert.equal(ui.byId("execute").disabled, true);
  await ui.load("approved");
  assert.equal(ui.byId("execute").disabled, false);
  assert.equal(ui.byId("accept").disabled, true);
  await ui.load("uncertain");
  assert.equal(ui.byId("reconcile").disabled, false);
  assert.equal(ui.byId("rationale").disabled, true);
  assert.equal(ui.byId("corrections").querySelectorAll("select")[0].disabled, true);
  await ui.load("verified");
  assert.equal(ui.byId("acceptance-reason").disabled, false);
  assert.equal(ui.byId("review-approve").disabled, true);
  await ui.load("accepted");
  assert.equal(ui.byId("acceptance-reason").disabled, true);
  assert.equal(ui.byId("renew").disabled, false);
});

test("reconciliation explains ambiguity, observations, ownership and the separate-action boundary", async () => {
  const ui = fixture([record("uncertain", {
    operation: { state: "reconciliation_required", payload: {project:"VEND",summary:"Reviewed task",description:"Reviewed content"} },
    reconciliation: reconciliationSummary({
      uncertainty: {state:"unresolved",reason:"multiple_matching_effects_observed",
        explanation:"At least three possible Jira tasks matched, so no result was selected."},
      safe_next_check: {kind:"review_ambiguity",mode:"read_only",label:"Review the possible Jira results"},
      known_observations: [
        {kind:"execution_attempt",state:"recorded",count:1,observed_at:1799999900},
        {kind:"provider_receipt",state:"not_recorded"},
        {kind:"authoritative_readback",state:"multiple_matches",match_count_lower_bound:3,observed_at:1800000000},
      ],
    }),
  })]);
  await ui.settle(); await ui.load("uncertain");
  const text = ui.byId("operation").textContent;
  assert.match(text,/NOT SURE WHETHER THE JIRA TICKET WAS CREATED/);
  assert.match(text,/at least 3 matches/);
  assert.match(text,/only looks the ticket up; it cannot create another Jira ticket/);
  assert.match(text,/Person responsible: Riley Reviewer/);
  assert.match(text,/separate reviewed action/);
  assert.equal(ui.byId("reconcile").disabled,false);
  for (const id of ["prepare","approve","execute","accept","reject"])
    assert.equal(ui.byId(id).disabled,true,id);
});

test("lost Jira access disables status lookup and directs the operator to Connections", async () => {
  const detail = reconciliationSummary({
    uncertainty:{state:"unresolved",reason:"current_connection_access_unavailable",
      explanation:"Current Jira access is unavailable; no provider request was made."},
    safe_next_check:{kind:"restore_access",mode:"read_only",
      label:"Restore the original Jira connection access, then check status",href:"/connections"},
  });
  const ui = fixture([record("access-lost", {stage:"reconciliation_required",
    operation:{state:"reconciliation_required"},reconciliation:detail})]);
  await ui.settle(); await ui.load("access-lost");
  assert.equal(ui.byId("reconcile").disabled,true);
  assert.match(ui.byId("operation").textContent,/Open Connections to restore access/);
  assert.equal(ui.calls.filter(call=>call.method === "POST").length,0);
});

test("malformed uncertain-action fields fail closed before enabling a status request", async () => {
  const detail = reconciliationSummary();
  detail.known_observations[2].provider_body = "PRIVATE_PROVIDER_BODY";
  const ui = fixture([record("malformed-uncertainty", {stage:"reconciliation_required",
    operation:{state:"reconciliation_required"},reconciliation:detail})]);
  await ui.settle(); await ui.load("malformed-uncertainty");
  assert.match(ui.byId("message").textContent,/uncertain action status was incomplete/i);
  assert.doesNotMatch(ui.byId("operation").textContent,/PRIVATE_PROVIDER_BODY/);
  assert.equal(ui.byId("reconcile").disabled,true);
  assert.equal(ui.calls.filter(call=>call.method === "POST").length,0);
});

test("a pending request disables edits and prevents a duplicate action", async () => {
  const pending = deferred();
  const ui = fixture([record("one")], call => call.url.endsWith("/collect-evidence") ? pending.promise : undefined);
  await ui.settle(); await ui.load("one");
  ui.byId("collect").listeners.click();
  assert.equal(ui.root.getAttribute("aria-busy"), "true");
  assert.equal(ui.byId("vendor").disabled, true);
  assert.equal(ui.byId("rationale").disabled, true);
  assert.equal(ui.byId("refresh").disabled, true);
  assert.equal(ui.caseButton("one").disabled, true);
  ui.byId("collect").listeners.click();
  assert.equal(ui.calls.filter(call => call.method === "POST").length, 1);
  pending.resolve(response(record("one", { revision: 2 })));
  await ui.settle();
  assert.equal(ui.byId("vendor").disabled, false);
  assert.equal(ui.byId("rationale").disabled, false);
  assert.match(ui.byId("message").textContent, /^Saved/);
});

test("renewal copies intake values without claiming a saved request and focuses an enabled field", async () => {
  const ui = fixture([record("accepted", { outcome: { accepted: true }, operation: { state: "verified" } })]);
  await ui.settle(); await ui.load("accepted");
  const before = ui.calls.length;
  await ui.click("renew");
  assert.equal(ui.calls.length, before);
  assert.equal(ui.byId("renewal").value, "accepted");
  assert.equal(ui.byId("document").value, "document-accepted");
  assert.match(ui.byId("message").textContent, /Renewal details copied.*Create request/);
  assert.equal(ui.byId("document").disabled, false);
  assert.equal(ui.document.activeElement, ui.byId("document"));
});

test("renewal readiness reports a check without implying customer acceptance was saved", async () => {
  const ui = fixture([record("accepted", { outcome: { accepted: true } })], call =>
    call.url.endsWith("/check-renewal") ? response({ classification: "human_fallback", reason: "Evidence changed" }) : undefined);
  await ui.settle(); await ui.load("accepted");
  await ui.click("check-renewal");
  assert.match(ui.byId("message").textContent, /^Renewal readiness checked/);
  assert.match(ui.byId("renewal-status").textContent, /human fallback.*Evidence changed/);
});

test("renewal queue exposes persisted due state and page-level attention", async () => {
  const expired = record("expired", {
    stage: "accepted",
    outcome: {accepted:true,reviewer:"user:reviewer",rationale:"Accepted last year",
      decided_at:1768464000,accepted_at:1768464000,renewal_due_at:1800000000,
      external_confirmation:{key:"VEND-42",confirmed_at:1768463900}},
    attention: {state:"overdue",kind:"evidence_renewal",requires_attention:true,
      effective_at:1800000000,as_of:1800000100},
    operation: {state:"verified",external_confirmation:{key:"VEND-42",confirmed_at:1768463900}},
    work_item: {...record("template").work_item,technical_effect:"verified",business_outcome:"accepted"},
  });
  const ui = fixture([expired], call => {
    const url = new URL(call.url, "https://lightwork.test");
    if (call.method === "GET" && url.pathname.endsWith("/cases") && url.searchParams.get("view") === "renewal")
      return response({schema:"lightwork.vendor-onboarding.case-page.v1",view:"renewal",
        cases:[expired],has_more:false,next_cursor:null});
    return undefined;
  });
  await ui.settle();
  await ui.filter("renewal");
  assert.match(ui.byId("page-status").textContent, /renewal view/);
  assert.match(ui.caseButton("expired").textContent, /Overdue/);
  assert.equal(ui.caseButton("expired").dataset.attention, "true");
  assert.match(ui.byId("attention-summary").textContent, /1 request.*1 accepted.*1 overdue renewal/);
  await ui.load("expired");
  assert.match(ui.byId("renewal-status").textContent, /Renewal status: overdue/);
  assert.match(ui.byId("renewal-status").textContent, /linked request.*fresh review and approval/);
});

test("business rejection stays admitted and shows rationale apart from verified effect", async () => {
  const rejected = record("rejected", {
    stage:"customer_rejected",
    outcome:{accepted:false,reviewer:"user:procurement",rationale:"Does not meet the business need",
      decided_at:1800000000,accepted_at:1800000000,renewal_due_at:null,
      external_confirmation:{key:"VEND-91",confirmed_at:1799999990}},
    attention:{state:"rejected",kind:"business_decision",requires_attention:false,
      effective_at:1800000000,as_of:1800000100},
    operation:{state:"verified",external_confirmation:{key:"VEND-91",confirmed_at:1799999990}},
    work_item:{...record("template").work_item,technical_effect:"verified",business_outcome:"rejected"},
  });
  const ui = fixture([rejected]);
  await ui.settle();
  assert.match(ui.byId("attention-summary").textContent, /1 request.*1 rejected/);
  await ui.load("rejected");
  const outcome = ui.byId("outcome").textContent;
  assert.match(outcome, /Jira ticket: VEND-91/);
  assert.match(outcome, /Customer decision: Rejected/);
  assert.match(outcome, /Decided by: Pat Procurement/);
  assert.match(outcome, /Reason: Does not meet the business need/);
  assert.match(ui.byId("history").textContent, /Rejected.*The Jira ticket stays created/s);
});

test("mismatched admitted page counts fail closed", async () => {
  const ui = fixture([record("one")], call => call.method === "GET" && call.url.endsWith("/cases")
    ? response({schema:"lightwork.vendor-onboarding.case-page.v1",view:"all",cases:[record("one")],
      has_more:false,next_cursor:null,page_counts:{admitted:0,accepted:0,rejected:0,
        needs_reconciliation:0,renewal_attention:0}}) : undefined);
  await ui.settle();
  assert.match(ui.byId("message").textContent, /request totals didn.t add up/);
  assert.equal(ui.byId("message").getAttribute("role"), "alert");
});

test("missing cost remains unmeasured while an explicit zero remains zero", async () => {
  const ui = fixture([record("missing"), record("zero", { metrics: { execution_cost_usd: 0 } })]);
  await ui.settle(); await ui.load("missing");
  assert.match(ui.byId("outcome").textContent, /Cost: not measured/);
  assert.doesNotMatch(ui.byId("outcome").textContent, /Cost: \$0/);
  await ui.load("zero");
  assert.match(ui.byId("outcome").textContent, /Cost: \$0/);
});

test("invalid server response shapes surface actionable errors and leave actions unavailable", async () => {
  for (const [body, status] of [[null, 200], [null, 503], [[], 200], ["unavailable", 503]]) {
    const ui = fixture([], () => response(body, status));
    await ui.settle();
    assert.equal(ui.byId("message").getAttribute("role"), "alert");
    assert.match(ui.byId("message").textContent, /Lightwork didn.t answer/);
    assert.equal(ui.byId("execute").disabled, true);
    assert.equal(ui.byId("refresh").disabled, false);
  }
});

test("incomplete case responses cannot select a new case or enable its actions", async () => {
  const ui = fixture([record("broken")], call => call.url.endsWith("/cases/broken") ? response({ id: "broken" }) : undefined);
  await ui.settle(); await ui.load("broken");
  assert.match(ui.byId("message").textContent, /couldn.t be shown in full/);
  assert.equal(ui.byId("collect").disabled, true);
  assert.equal(ui.caseButton("broken").getAttribute("aria-current"), "false");
});

test("review mutations carry the selected revision and the actual corrected answer", async () => {
  let submitted;
  const ui = fixture([record("one")], call => {
    if (!call.url.endsWith("/review")) return undefined;
    submitted = call.body;
    return response(record("one", { revision: 2 }));
  });
  await ui.settle(); await ui.load("one");
  ui.byId("rationale").value = "Confirm restricted use";
  ui.byId("answer-training").value = "no";
  ui.byId("note-training").value = "Vendor terms reviewed";
  await ui.click("review-approve");
  assert.equal(submitted.expected_revision, 1);
  assert.equal(submitted.decision, "approved");
  assert.deepEqual(submitted.corrections, { training: { answer: "no", note: "Vendor terms reviewed" } });
});


test("a request list that cannot load leaves no queue loader spinning", async () => {
  const ui = fixture([], call => call.url.endsWith("/cases") ? response({detail: "Vendor onboarding is disabled"}, 409) : undefined);
  ui.byId("attention-summary").textContent = "Loading request attention…";
  ui.byId("page-status").textContent = "Loading requests…";
  await ui.settle();
  assert.equal(ui.byId("message").getAttribute("role"), "alert");
  assert.equal(ui.byId("attention-summary").textContent, "");
  assert.equal(ui.byId("page-status").textContent, "Requests could not be loaded. See the message above, then choose Refresh requests.");
});
