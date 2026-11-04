// The /security/assurance governance tools: people pick records and fill in
// fields; the page sends exact requests and never asks for typed data,
// references, version numbers or fingerprints.
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {JSDOM} = require("jsdom");
const {shell} = require('./_shell');

const base = path.join(__dirname, "../../maverick_dashboard");
const D = "d".repeat(64);
const plain = value => JSON.parse(JSON.stringify(value));
const BANNED = /json|sha-?256|digest|principal|revision|idempotency|tenant|endpoint|schema|uuid|ed25519/i;

function pageHtml() {
  let html = fs.readFileSync(path.join(base, "templates/_governance_operations.html"), "utf8").replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
  html = html.replace(/\{% macro[\s\S]*?\{% endmacro %\}/g, "");
  html = html.replace(/\{\{ asset_options\([^)]*\) \}\}/g,
    `<option value="">Choose an AI system</option><option value="MAA-1" data-revision="3" data-digest="${D}" data-version="2.1">Support bot</option>`);
  html = html.replace(/\{\{ version_select\('([^']*)', '([^']*)', '([^']*)'\) \}\}/g,
    (_, label, kind, empty) => `<label>${label}<select class="select" name="version" data-version-options="${kind}"><option value="">${empty}</option></select></label>`);
  html = html.replace("{{ MRA_NAMES|default({}, true)|tojson }}", JSON.stringify({"MAA-1": "Support bot"}));
  html = html.replace("{{ 'true' if gateway_admin else 'false' }}", "true");
  html = html.replace(/\{% else %\}[\s\S]*?\{% endif %\}/g, "");
  html = html.replace(/\{%[\s\S]*?%\}/g, "").replace(/\{\{[\s\S]*?\}\}/g, "");
  return html;
}

async function fixture(t, routes = {}) {
  const html = pageHtml();
  const inline = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  const dom = new JSDOM(`<!doctype html><body>${html.replace(/<script[\s\S]*?<\/script>/g, "")}</body>`,
    {runScripts: "outside-only", url: "https://lightwork.test/security/assurance"});
  t.after(() => dom.window.close());
  const w = dom.window;
  Object.defineProperty(w, "crypto", {value: globalThis.crypto, configurable: true});
  w.TextEncoder = TextEncoder;
  w.mvHuman = value => { const text = String(value ?? "").replace(/[_-]+/g, " ").trim(); return text ? text[0].toUpperCase() + text.slice(1) : ""; };
  w.URL.createObjectURL = () => "blob:test"; w.URL.revokeObjectURL = () => {};
  w.HTMLAnchorElement.prototype.click = () => {};
  const confirms = [];
  let confirmAnswer = true;
  w.mvConfirm = async message => { confirms.push(message); return confirmAnswer; };
  const calls = [];
  w.fetch = async (url, options = {}) => {
    const call = {url: String(url).replace("/api/v1/security/assurance", ""), method: options.method || "GET",
      body: typeof options.body === "string" ? JSON.parse(options.body) : options.body};
    calls.push(call);
    const match = Object.keys(routes).find(key => {
      const [method, route] = key.includes(" ") ? key.split(" ") : ["GET", key];
      return method === call.method && call.url === route;
    });
    const handler = match ? routes[match] : {};
    const value = typeof handler === "function" ? handler(call) : handler;
    if (value instanceof Response) return value;
    return new Response(JSON.stringify(value), {status: 200, headers: {"Content-Type": "application/json"}});
  };
  shell(w);
  w.eval(fs.readFileSync(path.join(base, "static/lightwork-assurance-forms.js"), "utf8"));
  // Exception request/approve/close run through their reviewed controller.
  if (!w.HTMLDialogElement.prototype.showModal) w.HTMLDialogElement.prototype.showModal = function () { this.open = true; };
  w.eval(fs.readFileSync(path.join(base, "static/lightwork-policy-exceptions.js"), "utf8"));
  w.eval(inline);
  const settle = async () => { for (let i = 0; i < 30; i += 1) await new Promise(resolve => setImmediate(resolve)); };
  // File and text fingerprints finish on a worker thread, so wait for the
  // effect itself rather than a fixed number of turns.
  const until = async (check, what = "the page to finish") => {
    for (let i = 0; i < 400; i += 1) { if (check()) return; await new Promise(resolve => setTimeout(resolve, 5)); }
    assert.fail(`timed out waiting for ${what}`);
  };
  await settle();
  const $ = selector => w.document.querySelector(selector);
  const byId = id => w.document.getElementById(id);
  const open = label => { const button = w.document.querySelector(`button[aria-label="Open ${label}"]`); assert.ok(button, `no row for ${label}`); button.click(); };
  const change = (element, value) => { element.value = value; element.dispatchEvent(new w.Event("change", {bubbles: true})); };
  const submit = form => form.dispatchEvent(new w.Event("submit", {cancelable: true, bubbles: true}));
  const field = (root, text) => {
    const label = Array.from(root.querySelectorAll("label")).find(item => item.textContent.trim().startsWith(text));
    assert.ok(label, `no field labelled ${text}`);
    return label.querySelector("input,select,textarea");
  };
  const posted = route => calls.filter(call => call.method !== "GET" && call.url === route);
  const statuses = () => Array.from(w.document.querySelectorAll("[role=status]")).map(node => node.textContent).join("\n");
  return {w, $, byId, open, change, submit, field, settle, until, calls, posted, confirms, statuses,
    setConfirm: value => { confirmAnswer = value; }};
}

const policies = {policies: [{policy_id: "customer-data", status: "active", active_version: 1, revision: 4, versions: [
  {version: 1, title: "Customer data rules", description: "", statements: [{statement_id: "external-pii", text: "Keep personal data internal", effect: "restrict",
    applicability: {risk_tiers: [], jurisdictions: [], data_classes: ["personal"], deployment_types: [], asset_types: [], tags: [], use_case_tags: []}, required_control_ids: []}]},
  {version: 2, title: "Customer data rules, tighter", description: "", statements: [{statement_id: "external-pii", text: "Keep personal data internal", effect: "prohibit",
    applicability: {risk_tiers: [], jurisdictions: [], data_classes: [], deployment_types: [], asset_types: [], tags: [], use_case_tags: []}, required_control_ids: []}]}
]}]};

// The exception controller's current choices for the same workspace.
const choices = {context: "c".repeat(64), revision: 1, notice: "Current exception choices.", assets: [], exceptions: [],
  policies: policies.policies,
  controls: [{value: "manual-review", label: "Manual review", status: "implemented", owner: "Ops"},
             {value: "traffic-cap", label: "Traffic cap", status: "planned", owner: "Ops"}]};

test("choosing rules offers their versions and rules, and turning one on asks first in plain words", async t => {
  const h = await fixture(t, {"/ai-policy-management/policies": policies, "/pickers/policy-exceptions": choices, "POST /ai-policy-management/policies/customer-data/activate": {policy_id: "customer-data"}});
  h.open("Customer data rules, tighter");
  await h.settle();
  const activate = h.byId("ai-policy-activate");
  const versions = Array.from(activate.elements.version.options).map(option => option.textContent);
  assert.deepEqual(versions, ["Choose a version", "Version 2: Customer data rules, tighter", "Version 1: Customer data rules (in use)"]);
  assert.equal(h.$('[data-structured="policy-version-statements"] textarea').value, "Keep personal data internal", "the new-version editor starts from the saved wording");
  h.setConfirm(false);
  h.change(activate.elements.version, "2");
  h.submit(activate); await h.settle();
  assert.equal(h.posted("/ai-policy-management/policies/customer-data/activate").length, 0, "nothing is turned on without confirmation");
  assert.doesNotMatch(h.confirms[0], BANNED);
  h.setConfirm(true);
  h.submit(activate); await h.settle();
  assert.deepEqual(plain(h.posted("/ai-policy-management/policies/customer-data/activate")[0].body), {version: 2, expected_revision: 4});
});

test("an exception is requested from checkboxes, with names made from plain words", async t => {
  const h = await fixture(t, {
    "/ai-policy-management/policies": policies,
    "/pickers/policy-exceptions": choices,
    "POST /ai-policy-management/exceptions": {},
    "POST /pickers/policy-exceptions/original": {confirmed: true, message: "The exception request was recorded.",
      record: {exception_key: "holiday-support-pilot", status: "pending", reason: "Seasonal demand", expires_at: 1798736400}},
  });
  h.open("Customer data rules, tighter");
  await h.settle();
  const form = h.byId("ai-policy-exception-request");
  form.elements.exception_key.value = "Holiday support pilot";
  form.elements.expires_at.value = "2026-12-31T17:00";
  const rule = Array.from(form.querySelectorAll("label")).find(label => label.textContent.trim() === "Keep personal data internal").querySelector("input");
  rule.checked = true;
  form.elements.reason.value = "Seasonal demand";
  // Safeguards are chosen from the recorded list, never typed.
  const controls = Array.from(h.w.document.querySelectorAll("#policy-exception-controls input"));
  assert.equal(controls.length, 2);
  for (const control of controls) control.checked = true;
  h.submit(form); await h.settle();
  // A complete review opens first; nothing is recorded until it is confirmed.
  assert.equal(h.posted("/ai-policy-management/exceptions").length, 0);
  const dialog = h.$("dialog.policy-exception-dialog");
  assert.ok(dialog, "the complete review is shown");
  const reviewed = dialog.querySelector("input[type=checkbox]");
  reviewed.checked = true; reviewed.dispatchEvent(new h.w.Event("change"));
  Array.from(dialog.querySelectorAll("button")).find(button => button.textContent === "Confirm reviewed action").click();
  await h.settle();
  const body = plain(h.posted("/ai-policy-management/exceptions")[0].body);
  assert.match(body.exception_key, /^holiday-support-pilot-[0-9a-f-]{36}$/);
  assert.equal(body.policy_version, 1);
  assert.deepEqual(body.scope, {asset_ids: [], statement_ids: ["external-pii"], risk_tiers: []});
  assert.deepEqual(body.compensating_control_ids, ["manual-review", "traffic-cap"]);
  assert.equal(typeof body.expires_at, "number");
});

test("checking a use against the rules is built from pickers and a refusal is one plain sentence", async t => {
  const h = await fixture(t, {"POST /ai-policy-management/preview": () => new Response('{"detail":"evaluation context: asset_id must be a token"}', {status: 422})});
  const form = h.byId("ai-policy-preview");
  h.change(h.field(form, "AI system"), "MAA-1");
  h.submit(form); await h.settle();
  assert.deepEqual(plain(h.posted("/ai-policy-management/preview")[0].body.context).asset_id, "MAA-1");
  const status = h.byId("ai-policy-preview-status").textContent;
  assert.match(status, /Some of the details need fixing/);
  assert.doesNotMatch(status, /asset_id|token|context/);
});

test("records sent to ServiceNow are chosen from a list and sending asks first", async t => {
  // The choice is only a reference; the server resolves the exact current
  // record and returns a sealed review the send must quote.
  const source = {source_kind: "finding", source_id: "MRF-1"};
  const h = await fixture(t, {
    "/pickers/grc-sources?source_kind=finding": {sources: [{label: "No accountable owner", asset_id: "MAA-1", severity: "high", source}]},
    "POST /grc-outbound/servicenow_irm/preview": {review_token: "sealed-review", message: "Review the complete current record and destination. Nothing has been sent.",
      details: [{label: "Complete summary", value: "No accountable owner"}], technical: {target: "servicenow_irm"}},
    "POST /grc-outbound/servicenow_irm/sync": {status: "delivered", message: "The destination confirmed this exact reviewed record.", state: {}}
  });
  const form = h.byId("grc-outbound-preview");
  const options = Array.from(form.elements.source_choice.options).map(option => option.textContent);
  assert.deepEqual(options, ["Choose a record", "Support bot: No accountable owner (High)"]);
  h.change(form.elements.source_choice, "0");
  h.submit(form); await h.settle();
  assert.deepEqual(plain(h.posted("/grc-outbound/servicenow_irm/preview")[0].body), source);
  assert.match(h.byId("grc-outbound-result").textContent, /No accountable owner/);
  const confirm = h.byId("grc-outbound-confirm"), send = h.byId("grc-outbound-sync");
  send.click(); await h.settle();
  assert.equal(h.posted("/grc-outbound/servicenow_irm/sync").length, 0, "nothing is sent before the review is ticked");
  confirm.checked = true; confirm.dispatchEvent(new h.w.Event("change"));
  h.setConfirm(false);
  send.click(); await h.settle();
  assert.equal(h.posted("/grc-outbound/servicenow_irm/sync").length, 0);
  h.setConfirm(true);
  send.click(); await h.settle();
  assert.deepEqual(plain(h.posted("/grc-outbound/servicenow_irm/sync")[0].body), {review_token: "sealed-review", confirmed: true});
  assert.equal(h.posted("/grc-outbound/servicenow_irm/sync").length, 1);
  assert.match(h.byId("grc-outbound-sync-status").textContent, /confirmed this exact reviewed record/);
});

test("an insurer profile cites only approved evidence of the chosen AI system", async t => {
  const h = await fixture(t, {
    "/pickers/package-forms": {insurability: {measurement_schema: "m1", measurements: ["evaluation"], measurement_units: ["percent"],
      framework_postures: ["implemented"], safeguard_states: ["planned"], severities: ["none"]}, regulated: {nyc_checks: [], naic_checks: []},
      bank_mrm: {section_schema: "s1", sections: []}, conformity: {checklist_sections: {fria: ["scope"]}}},
    "/model-risk/evidence?asset_id=MAA-1": {evidence: [{id: "MRE-1", status: "approved", freshness: "current", result: "passed", payload_sha256: D, evidence_kind: "evaluation"}]},
    "POST /ai-insurability/profiles": {profile_id: "support-2026"}
  });
  const form = h.byId("ai-insurability-create");
  form.elements.profile_id.value = "Support 2026";
  h.change(form.elements.asset_id, "MAA-1"); await h.settle();
  h.field(form, "Framework name").value = "NIST AI RMF";
  h.field(form, "Accountable role").value = "Risk lead";
  form.querySelector("input[type=checkbox][value='MRE-1']").checked = true;
  h.field(form, "Safeguard name").value = "Human review";
  h.field(form, "What this profile does not cover").value = "Voice";
  h.field(form, "Known limitations").value = "Small sample";
  h.field(form, "Steps to follow").value = "Open the report";
  h.submit(form); await h.settle();
  const body = plain(h.posted("/ai-insurability/profiles")[0].body);
  assert.equal(body.profile_id, "support-2026");
  assert.equal(body.asset_id, "MAA-1");
  assert.deepEqual(body.evidence_bindings, [{evidence_id: "MRE-1", digest: D}]);
  assert.deepEqual(body.content.governance_posture.frameworks[0].evidence_ids, ["MRE-1"]);
});

test("agent identity controls use chosen identities and ask before changing Purview", async t => {
  const principal = "prn_" + "1".repeat(32);
  const h = await fixture(t, {
    "/pickers/identity-controls": {available: true, capabilities: ["agent.execute", "purview.classification.write"],
      federation_bindings: [{provider: "okta", principal_ref: principal, provider_subject_id: "sub_" + "2".repeat(32), binding_sha256: D, authority_revision: 2}],
      purview_assets: [], purview_intents: [{intent_id: "IGPW-" + "3".repeat(32), principal_ref: principal, capability_mapping_sha256: D, revision: 5,
        status: "prepared", classification_codes: ["confidential"], created_at: 1800000000}]},
    "POST /identity-governance/controls/capabilities/okta/decision": {decision: {action: "permit"}}
  });
  const workbench = h.byId("ai-identity-control-workbench");
  workbench.open = true; workbench.dispatchEvent(new h.w.Event("toggle")); await h.settle();
  const evaluate = h.byId("ai-identity-control-evaluate");
  assert.equal(evaluate.elements.identity_choice.options[1].textContent, "Agent identity 1 (Okta)");
  h.change(evaluate.elements.identity_choice, "0");
  h.change(evaluate.elements.required_capability, "purview.classification.write");
  h.byId("ai-identity-capability-decision").click(); await h.settle();
  const body = plain(h.posted("/identity-governance/controls/capabilities/okta/decision")[0].body);
  assert.equal(body.principal_ref, principal);
  assert.equal(body.expected_binding_sha256, D);
  assert.equal(body.expected_revision, 2);
  assert.equal(body.required_capability, "purview.classification.write");
  assert.match(h.byId("ai-identity-control-evaluate-status").textContent, /Decision: allowed/);
  const resume = h.byId("ai-identity-purview-resume");
  h.change(resume.elements.intent_choice, "0");
  h.setConfirm(false);
  h.byId("ai-identity-purview-execute").click(); await h.settle();
  const route = "/identity-governance/controls/purview/writebacks/IGPW-" + "3".repeat(32) + "/execute";
  assert.equal(h.posted(route).length, 0, "nothing changes in Purview without confirmation");
  assert.match(h.confirms.at(-1), /Microsoft Purview/);
});

test("a sensor sighting carries the chosen sensor's setup and a repeatable fingerprint", async t => {
  const h = await fixture(t, {
    "/ai-discovery-sensors/sensors?limit=100": {sensors: [{sensor_id: "DSN-" + "4".repeat(32), sensor_name: "office-browsers", sensor_type: "browser_extension",
      sensor_revision: 2, config_sha256: D, status: "active", revision: 7}]},
    ["POST /ai-discovery-sensors/sensors/DSN-" + "4".repeat(32) + "/observations"]: {observation_id: "DSO-1"}
  });
  h.open("Office browsers");
  await h.settle();
  const form = h.byId("ai-discovery-observation-ingest");
  h.field(form, "When it was seen").value = "2026-05-01T09:30";
  h.field(form, "AI service").value = "Chat assistant";
  h.field(form, "Product").value = "Team chat";
  h.field(form, "Provider").value = "Example Vendor";
  h.submit(form);
  const route = "/ai-discovery-sensors/sensors/DSN-" + "4".repeat(32) + "/observations";
  await h.until(() => h.posted(route).length, "the sighting to be sent");
  const body = plain(h.posted(route)[0].body);
  assert.equal(body.sensor_revision, 2);
  assert.equal(body.config_sha256, D);
  assert.match(body.event_sha256, /^[0-9a-f]{64}$/);
  assert.equal(body.ai_service_code, "chat-assistant");
  assert.equal(body.provider_code, "example-vendor");
  assert.deepEqual(body.context_codes, []);
});

test("messages the page writes are plain sentences", async t => {
  const h = await fixture(t, {"/ai-policy-management/policies": policies});
  const text = h.statuses();
  assert.doesNotMatch(text, BANNED);
  assert.doesNotMatch(text, /bounded|projection|control-plane|digest-only|manifest/i);
  assert.equal(h.w.document.querySelectorAll("textarea[name=statements], textarea[name=context], textarea[name=receipt], textarea[name=evidence_bindings], textarea[name=source], textarea[name=observation], textarea[name=report], textarea[name=details]").length, 0);
});

const AI_ACT = "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02024R1689-20260727";
const releaseRoutes = extra => ({
  "/pickers/media-release-references": {references: [
    {context_id: "spring-campaign-2026", last_used_at: 1800000000, deployment_ids: ["production-east"], record_count: 2},
    {context_id: "winter-sale", last_used_at: 1700000000, deployment_ids: ["production-west"], record_count: 1}
  ], count: 2},
  "/model-risk/deployments?asset_id=MAA-1": {deployments: [
    {deployment_id: "production-east", status: "deployed", deployed_at: 1790000000},
    {deployment_id: "production-west", status: "deployed", deployed_at: 1690000000}
  ]},
  ...extra
});

test("a media check picks the release from the ones already used, or adds a new one once", async t => {
  const h = await fixture(t, releaseRoutes({"POST /ai-media-provenance/verify": {provenance_id: "AMP-1"}}));
  const form = h.byId("ai-media-provenance-verify");
  h.change(form.elements.asset_id, "MAA-1"); await h.settle();
  h.change(form.elements.deployment_id, "production-east");
  const release = h.field(form, "Release");
  assert.deepEqual(Array.from(release.options).map(option => option.value), ["", "spring-campaign-2026", "__new__"],
    "only releases used with the chosen deployment, then a way to add one");
  assert.match(release.options[1].textContent, /^spring-campaign-2026 \(last used /);
  assert.equal(release.options[2].textContent, "Add a new release…");

  h.submit(form); await h.settle();
  assert.equal(h.posted("/ai-media-provenance/verify").length, 0, "nothing is sent without a release");
  assert.match(h.byId("ai-media-provenance-verify-status").textContent, /Choose a release/);

  h.change(release, "spring-campaign-2026");
  h.submit(form);
  await h.until(() => h.posted("/ai-media-provenance/verify").length, "the check to be sent");
  const sent = h.posted("/ai-media-provenance/verify")[0].body;
  assert.equal(sent.get("context_id"), "spring-campaign-2026");
  assert.equal(sent.get("deployment_id"), "production-east");

  h.change(release, "__new__");
  const name = h.field(form, "Name of the new release");
  name.value = "summer launch";
  h.submit(form); await h.settle();
  assert.match(h.byId("ai-media-provenance-verify-status").textContent, /without spaces/);
  assert.equal(h.posted("/ai-media-provenance/verify").length, 1, "a malformed name is never sent");
  name.value = "summer-launch-2026";
  h.submit(form);
  await h.until(() => h.posted("/ai-media-provenance/verify").length === 2, "the second check to be sent");
  assert.equal(h.posted("/ai-media-provenance/verify")[1].body.get("context_id"), "summer-launch-2026");
  // The new release is now in the list, here and on the signing form.
  assert.equal(release.value, "summer-launch-2026");
  const signRelease = h.field(h.byId("ai-media-provenance-sign"), "Release");
  assert.ok(Array.from(signRelease.options).some(option => option.value === "summer-launch-2026"));
});

const provisionRoutes = extra => ({
  "/pickers/legal-provisions": {default_official_url: AI_ACT, count: 3, provisions: [
    {regulation: "EU AI Act", provision: "Art. 27(1)(a)", title: "The deployer's processes in which the system will be used", official_url: AI_ACT},
    {regulation: "EU AI Act", provision: "Annex III point 4", title: "High-risk area: Employment (recruitment, screening, task allocation, monitoring)", official_url: AI_ACT},
    {regulation: "GDPR", provision: "Art. 35", title: "Run a DPIA for high-risk processing", official_url: "https://eur-lex.europa.eu/eli/reg/2016/679/oj"}
  ]},
  "/ai-conformity/cases?limit=100": {cases: [{case_id: "EUC-1", revision: 3, asset_binding: {asset_id: "MAA-1"}, workflow_status: "draft", manifest: {complete: false}}]},
  ...extra
});

test("a readiness case cites a provision found by searching the list", async t => {
  const h = await fixture(t, provisionRoutes({"POST /ai-conformity/cases": {case_id: "EUC-2"}}));
  const form = h.byId("ai-conformity-create");
  h.change(form.elements.asset_id, "MAA-1");
  h.submit(form); await h.settle();
  assert.equal(h.posted("/ai-conformity/cases").length, 0);
  assert.match(h.byId("ai-conformity-create-status").textContent, /Choose the legal provision/);
  const search = h.field(form, "Search the list");
  search.value = "employment";
  search.dispatchEvent(new h.w.Event("input"));
  const choice = h.field(form, "Provision");
  assert.deepEqual(Array.from(choice.options).map(option => option.textContent),
    ["Choose a provision", "Annex III point 4 — High-risk area: Employment (recruitment, screening, task allocation, monitoring)", "Other (type it)"]);
  h.change(choice, choice.options[1].value);
  h.submit(form); await h.settle();
  assert.deepEqual(plain(h.posted("/ai-conformity/cases")[0].body.legal_basis), [{provision: "Annex III point 4", official_url: AI_ACT}]);
});

test("a provision not in the list is typed under Other and cited against the AI Act", async t => {
  const h = await fixture(t, provisionRoutes({"POST /ai-conformity/cases/EUC-1/article-43-route": {case_id: "EUC-1"}}));
  h.open("Readiness case for Support bot");
  await h.settle();
  const form = h.byId("ai-conformity-route");
  const choice = h.field(form, "Provision");
  const other = h.field(form, "Provision not in the list");
  assert.equal(other.closest("label").hidden, true, "typing is hidden until Other is chosen");
  h.change(choice, "__other__");
  assert.equal(other.closest("label").hidden, false);
  other.value = "Article 43(2) and Annex VI";
  h.change(form.elements.route, "internal_control_annex_vi");
  h.submit(form);
  await h.until(() => h.posted("/ai-conformity/cases/EUC-1/article-43-route").length, "the route to be saved");
  const body = plain(h.posted("/ai-conformity/cases/EUC-1/article-43-route")[0].body);
  assert.deepEqual(body.citations, [{provision: "Article 43(2) and Annex VI", official_url: AI_ACT}]);
  assert.equal(body.expected_revision, 3);
});

const principal = "prn_" + "1".repeat(32);
const identityControls = extra => ({available: true, capabilities: ["purview.classification.write"],
  federation_bindings: [{provider: "okta", principal_ref: principal, provider_subject_id: "sub_" + "2".repeat(32), binding_sha256: D, authority_revision: 2}],
  purview_assets: [{asset_id: "ast_" + "7".repeat(32), binding_sha256: D, revision: 4, classification_codes: ["confidential"]}],
  purview_intents: [], ...extra});
const openWorkbench = async h => {
  const workbench = h.byId("ai-identity-control-workbench");
  workbench.open = true; workbench.dispatchEvent(new h.w.Event("toggle")); await h.settle();
};
const labelBoxes = form => Array.from(form.querySelectorAll("[data-purview-label-choices] label")).map(label => [label.textContent.trim(), label.querySelector("input").checked]);

test("Purview labels are ticked from the labels Lightwork has seen, and a reading adds more", async t => {
  const h = await fixture(t, {
    "/pickers/identity-controls": identityControls({purview_labels: ["confidential", "regulated"], purview_connected: true}),
    "POST /identity-governance/connectors/purview/collect": {provider: "purview", observed_at: 1800000000, identities: [], grants: [],
      data_classifications: [{entity_type: "table", classification_codes: ["financial"], label_codes: []}]},
    "POST /identity-governance/controls/purview/writebacks/prepare": {intent_id: "IGPW-" + "3".repeat(32)}
  });
  await openWorkbench(h);
  const form = h.byId("ai-identity-purview-prepare");
  h.change(form.elements.identity_choice, "0");
  h.change(form.elements.asset_choice, "0");
  assert.deepEqual(labelBoxes(form), [["Confidential", true], ["Regulated", false]], "the data's current labels start ticked");
  assert.match(form.querySelector("[data-purview-label-note]").textContent, /Tick every label/);

  const collect = h.byId("ai-identity-governance-collect");
  h.change(collect.elements.provider, "purview");
  h.submit(collect); await h.settle();
  assert.deepEqual(labelBoxes(form).map(([text]) => text), ["Confidential", "Financial", "Regulated"]);

  form.querySelector("[data-purview-label-choices] input[value=regulated]").checked = true;
  h.field(form, "Labels not in the list").value = "Payroll";
  h.submit(form);
  const route = "/identity-governance/controls/purview/writebacks/prepare";
  await h.until(() => h.posted(route).length, "the change to be prepared");
  const body = plain(h.posted(route)[0].body);
  assert.deepEqual(body.classification_codes, ["confidential", "payroll", "regulated"]);
  assert.equal(body.asset_id, "ast_" + "7".repeat(32));
  assert.equal(body.expected_source_revision, 4);
});

test("without Purview connected the labels are typed, and a malformed one is refused plainly", async t => {
  const h = await fixture(t, {
    "/pickers/identity-controls": identityControls({purview_assets: [{asset_id: "ast_" + "7".repeat(32), binding_sha256: D, revision: 4, classification_codes: []}],
      purview_labels: [], purview_connected: false}),
    "POST /identity-governance/controls/purview/writebacks/prepare": {intent_id: "IGPW-" + "3".repeat(32)}
  });
  await openWorkbench(h);
  const form = h.byId("ai-identity-purview-prepare");
  assert.equal(form.querySelector("[data-purview-label-note]").textContent,
    "Connect Microsoft Purview to choose from your labels. Until then, type the labels below.");
  assert.equal(labelBoxes(form).length, 0);
  h.change(form.elements.identity_choice, "0");
  h.change(form.elements.asset_choice, "0");
  const typed = h.field(form, "Data labels (type them");
  typed.value = "Confidential, top secret";
  h.submit(form); await h.settle();
  const route = "/identity-governance/controls/purview/writebacks/prepare";
  assert.equal(h.posted(route).length, 0);
  assert.match(h.byId("ai-identity-purview-prepare-status").textContent, /as Microsoft Purview shows it/);
  typed.value = "Confidential, restricted";
  h.submit(form);
  await h.until(() => h.posted(route).length, "the change to be prepared");
  assert.deepEqual(plain(h.posted(route)[0].body.classification_codes), ["confidential", "restricted"]);
});

test("training details offer values already used, and outside numbers are checked before sending", async t => {
  const h = await fixture(t, {
    "/ai-literacy/requirements": {requirements: [{requirement_key: "safe-ai", title: "Safe AI", revision: 2, scope: {role_ids: [], system_ids: []},
      content: {provider_id: "learning-hub", content_id: "responsible-ai-101", content_version: "2026"}}]},
    "PUT /ai-literacy/requirements/new-course": {requirement_key: "new-course"},
    "/ai-literacy/people/10442/status": {summary: {}}
  });
  const options = id => Array.from(h.byId(id).querySelectorAll("option")).map(option => option.value);
  assert.deepEqual(options("ai-literacy-provider-choices"), ["learning-hub"]);
  assert.deepEqual(options("ai-literacy-course-choices"), ["responsible-ai-101"]);
  assert.deepEqual(options("ai-literacy-edition-choices"), ["2026"]);
  const requirement = h.byId("ai-literacy-requirement-upsert");
  assert.equal(h.field(requirement, "Course edition from your learning system").getAttribute("list"), "ai-literacy-edition-choices");
  requirement.elements.requirement_key.value = "New course";
  requirement.elements.title.value = "New course";
  requirement.elements.provider_id.value = "learning-hub";
  requirement.elements.content_id.value = "responsible-ai-101";
  requirement.elements.content_version.value = "2026 spring";
  h.submit(requirement); await h.settle();
  assert.equal(h.posted("/ai-literacy/requirements/new-course").length, 0);
  assert.match(h.byId("ai-literacy-requirement-status").textContent, /without spaces/);
  requirement.elements.content_version.value = "2026";
  h.submit(requirement); await h.settle();
  assert.equal(plain(h.posted("/ai-literacy/requirements/new-course")[0].body).content_version, "2026");

  const person = h.byId("ai-literacy-person-query");
  assert.ok(h.field(person, "Employee number from your HR system"));
  person.elements.person_id.value = "1".repeat(129);
  h.submit(person); await h.settle();
  assert.ok(!h.calls.some(call => call.url.startsWith("/ai-literacy/people/1111")), "an over-long number is never looked up");
  assert.match(h.byId("ai-literacy-person-status").textContent, /at most 128 characters/);
  person.elements.person_id.value = " 10442 ";
  h.submit(person); await h.settle();
  assert.ok(h.calls.some(call => call.url === "/ai-literacy/people/10442/status"));
});

test("a filing reference is copied from the authority and checked before it is recorded", async t => {
  const h = await fixture(t, {
    "/eu-ai-incidents?limit=100": {incidents: [{incident_id: "A73-1", title: "Refund bot outage", asset_id: "MAA-1", status: "reported",
      clock: {status: "running"}, reports: [{report_id: "A73R-1"}], revision: 5}]},
    "POST /eu-ai-incidents/A73-1/reports/A73R-1/submission": {incident_id: "A73-1"}
  });
  h.open("Refund bot outage");
  await h.settle();
  const form = h.byId("article-73-report-submission");
  const reference = h.field(form, "Filing reference the authority gave you");
  reference.value = "DE 2026 42";
  h.submit(form); await h.settle();
  const route = "/eu-ai-incidents/A73-1/reports/A73R-1/submission";
  assert.equal(h.posted(route).length, 0);
  assert.match(h.byId("article-73-submission-status").textContent, /exactly as the authority gave it/);
  reference.value = "DE-2026/0042";
  h.submit(form);
  await h.until(() => h.posted(route).length, "the filing to be recorded");
  assert.equal(plain(h.posted(route)[0].body).submission_reference, "DE-2026/0042");
});

test("refused sections release their responses and leave no table or list at Loading", async t => {
  const html = pageHtml();
  const inline = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  const dom = new JSDOM(`<!doctype html><body>${html.replace(/<script[\s\S]*?<\/script>/g, "")}</body>`,
    {runScripts: "outside-only", url: "https://lightwork.test/security/assurance"});
  t.after(() => dom.window.close());
  const w = dom.window;
  let released = 0;
  Object.defineProperty(w, "crypto", {value: globalThis.crypto, configurable: true});
  w.TextEncoder = TextEncoder;
  w.mvErrorText = (failure, action) => `Could not ${action}. (${failure.status})`;
  // Every section is refused, as on a fresh install where these modules are off.
  w.fetch = async () => ({ok: false, status: 403, body: {cancel: async () => { released += 1; }}, json: async () => ({})});
  shell(w);
  w.eval(fs.readFileSync(path.join(base, "static/lightwork-assurance-forms.js"), "utf8"));
  w.eval(inline);
  for (let i = 0; i < 60; i += 1) await new Promise(resolve => setImmediate(resolve));
  assert.ok(released >= 10, `released ${released} refused responses`);
  const stuck = Array.from(w.document.querySelectorAll("td, li, p, span"))
    .filter(node => node.children.length === 0 && /^Loading\b/.test(node.textContent.trim()))
    .map(node => (node.closest("[id]") || {}).id + ": " + node.textContent.trim());
  assert.deepEqual(stuck, []);
});

test("a failed first read of the exception choices leaves no rules or safeguards at Loading", async t => {
  const h = await fixture(t, {"/pickers/policy-exceptions": () => new Response(JSON.stringify({detail: "Service unavailable"}), {status: 503, headers: {"Content-Type": "application/json"}})});
  await h.settle();
  assert.doesNotMatch(h.byId("policy-exception-controls").textContent, /Loading/);
  assert.match(h.byId("policy-exception-controls").textContent, /Safeguards could not be read\. Use Refresh to try again\./);
  assert.doesNotMatch(h.byId("policy-exception-policy").textContent, /Loading/);
  assert.equal(h.byId("policy-exception-policy").value, "");
});

// A read that worked and found nothing is an answer, not a failure.
const noControls = {...choices, controls: []};
const NO_SAFEGUARDS = /No applicable safeguards are recorded\. Add a control in Security before requesting an exception\./;

test("a request with no recorded safeguards keeps saying so after the form is refused", async t => {
  const h = await fixture(t, {"/ai-policy-management/policies": policies, "/pickers/policy-exceptions": noControls});
  await h.settle();
  assert.match(h.byId("policy-exception-controls").textContent, NO_SAFEGUARDS);
  h.change(h.byId("policy-exception-policy"), "customer-data");
  const form = h.byId("ai-policy-exception-request");
  form.elements.exception_key.value = "Holiday support pilot";
  form.elements.expires_at.value = "2026-12-31T17:00";
  form.elements.reason.value = "Seasonal demand";
  h.submit(form); await h.settle();
  assert.match(h.statuses(), /Choose between one and 128 recorded safeguards\./);
  assert.match(h.byId("policy-exception-controls").textContent, NO_SAFEGUARDS);
  assert.doesNotMatch(h.byId("policy-exception-controls").textContent, /could not be read/);
  assert.equal(h.$("dialog.policy-exception-dialog"), null);
});

test("a refresh that fails after a good read keeps the lists as they were read", async t => {
  let failing = false;
  const h = await fixture(t, {"/ai-policy-management/policies": policies, "/pickers/policy-exceptions": () => failing
    ? new Response(JSON.stringify({detail: "Service unavailable"}), {status: 503, headers: {"Content-Type": "application/json"}})
    : noControls});
  await h.settle();
  failing = true;
  h.byId("policy-exception-refresh").click(); await h.settle();
  assert.match(h.byId("policy-exception-controls").textContent, NO_SAFEGUARDS);
  assert.doesNotMatch(h.byId("policy-exception-controls").textContent, /could not be read/);
  assert.match(h.byId("policy-exception-policy").textContent, /Customer data rules/);
});
