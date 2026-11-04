// Guided forms on /security/assurance: every structured request is built from
// labelled fields and pickers, never typed as data.
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {JSDOM} = require("jsdom");

const source = fs.readFileSync(path.join(__dirname, "../../maverick_dashboard/static/lightwork-assurance-forms.js"), "utf8");
const DIGEST = "a".repeat(64);
// Values built inside the page's window are compared as plain data.
const plain = value => JSON.parse(JSON.stringify(value));
const button = (root, text) => Array.from(root.querySelectorAll("button")).find(item => item.textContent === text);

function setup(t) {
  const dom = new JSDOM("<!doctype html><form id=f class='assurance-form'></form>", {runScripts: "outside-only", url: "https://lightwork.test/"});
  t.after(() => dom.window.close());
  const w = dom.window;
  Object.defineProperty(w, "crypto", {value: globalThis.crypto, configurable: true});
  w.TextEncoder = TextEncoder;
  w.eval(source);
  return {w, F: w.LWAssuranceForms, form: w.document.getElementById("f")};
}
const mount = (h, spec, ctx) => { const node = h.F.build(spec, ctx); h.form.appendChild(node.el); return node; };
const labelled = (root, text) => Array.from(root.querySelectorAll("label")).find(label => label.textContent.trim().startsWith(text));
const control = (root, text) => { const label = labelled(root, text); assert.ok(label, `no field labelled ${text}`); return label.querySelector("input,select,textarea"); };
const set = (w, element, value) => { element.value = value; element.dispatchEvent(new w.Event("change", {bubbles: true})); };
const tick = (root, text) => { const box = labelled(root, text).querySelector("input[type=checkbox]"); box.checked = true; box.dispatchEvent(new box.ownerDocument.defaultView.Event("change", {bubbles: true})); };

test("short names people type become stored names, and saved names are kept exactly", t => {
  const {F} = setup(t);
  assert.equal(F.slug("Chief Risk Officer!"), "chief-risk-officer");
  assert.equal(F.slug("Café  déjà vu"), "cafe-deja-vu");
  assert.equal(F.toName("nist_ai_rmf"), "nist_ai_rmf");
  assert.equal(F.toName("NIST AI RMF"), "nist-ai-rmf");
});

test("the policy context form builds the exact use description from pickers", async t => {
  const h = setup(t);
  const node = mount(h, h.F.specs.policyContext([["MAA-1", "Support bot"]]));
  set(h.w, control(h.form, "AI system"), "MAA-1");
  set(h.w, control(h.form, "Risk level"), "high");
  tick(h.form, "Personal");
  tick(h.form, "European Union");
  control(h.form, "Other kinds of data").value = "Payroll data";
  control(h.form, "Uses").value = "support, Hiring decisions";
  const value = await node.collect();
  assert.deepEqual(plain(value), {
    asset_id: "MAA-1", risk_tier: "high", jurisdictions: ["eu"], data_classes: ["personal", "payroll-data"],
    deployment_types: [], asset_types: [], tags: [], use_case_tags: ["support", "hiring-decisions"]
  });
});

test("a missing AI system is refused with a plain sentence", async t => {
  const h = setup(t);
  const node = mount(h, h.F.specs.policyContext([["MAA-1", "Support bot"]]));
  await assert.rejects(node.collect(), /Choose an option for “AI system”/);
});

test("rules get stable names, keep saved names, and carry their conditions", async t => {
  const h = setup(t);
  const node = mount(h, h.F.specs.policyStatements());
  node.load([{statement_id: "external-pii", text: "Keep personal data internal.", effect: "restrict",
    applicability: {risk_tiers: ["high"], data_classes: ["personal"], jurisdictions: [], deployment_types: [], asset_types: [], tags: [], use_case_tags: []},
    required_control_ids: ["manual-review"]}]);
  button(h.form, "Add another rule").click();
  const texts = h.form.querySelectorAll("textarea");
  texts[1].value = "Review hiring uses";
  const rules = await node.collect();
  assert.equal(rules.length, 2);
  assert.equal(rules[0].statement_id, "external-pii");
  assert.deepEqual(plain(rules[0].applicability.risk_tiers), ["high"]);
  assert.deepEqual(plain(rules[0].required_control_ids), ["manual-review"]);
  assert.equal(rules[1].statement_id, "review-hiring-uses-2");
  assert.equal(rules[1].effect, "review");
});

test("an exception must cover something", async t => {
  const h = setup(t);
  const node = mount(h, h.F.specs.exceptionScope([["MAA-1", "Support bot"]]));
  await assert.rejects(node.collect(), /Choose at least one AI system, rule or risk level/);
  node.child("statement_ids").setOptions([["rule-1", "Keep data internal"]]);
  tick(h.form, "Keep data internal");
  assert.deepEqual(plain((await node.collect()).statement_ids), ["rule-1"]);
});

const insurabilityDefs = {
  measurement_schema: "measurement-v1", measurements: ["evaluation", "drift"], measurement_states: ["measured", "missing", "not_applicable"],
  measurement_units: ["percent", "rate", "score"], framework_postures: ["implemented", "not_assessed"], safeguard_states: ["planned", "verified"],
  severities: ["none", "low", "high"]
};

test("an insurer profile is built from fields, with unmeasured items sent empty and evidence picked from the list", async t => {
  const h = setup(t);
  const pool = new h.F.EvidencePool();
  const node = mount(h, h.F.specs.insurability(insurabilityDefs), {pool});
  pool.set([
    {id: "MRE-1", status: "approved", freshness: "current", result: "passed", payload_sha256: DIGEST, evidence_kind: "evaluation", summary: "Quarterly test"},
    {id: "MRE-2", status: "pending", freshness: "current", payload_sha256: "b".repeat(64)}
  ]);
  assert.equal(h.form.querySelectorAll("fieldset input[type=checkbox][value='MRE-2']").length, 0, "unapproved evidence is never offered");
  control(h.form, "Framework name").value = "NIST AI RMF";
  control(h.form, "Accountable role").value = "Chief risk officer";
  const evaluation = Array.from(h.form.querySelectorAll("fieldset")).find(set => set.querySelector("legend")?.textContent === "Evaluation");
  set(h.w, control(evaluation, "Status"), "measured");
  control(evaluation, "Result").value = "92.5";
  control(evaluation, "Measured from").value = "2026-01-01";
  control(evaluation, "Measured until").value = "2026-03-31";
  control(evaluation, "How many cases").value = "400";
  control(evaluation, "Confidence").value = "0.9";
  evaluation.querySelector("input[type=checkbox][value='MRE-1']").checked = true;
  control(h.form, "Safeguard name").value = "Human review";
  control(h.form, "What this profile does not cover").value = "Voice channel";
  control(h.form, "Known limitations").value = "Small sample";
  control(h.form, "Steps to follow").value = "Open the report\nCompare totals";
  const content = await node.collect();
  assert.equal(content.governance_posture.frameworks[0].framework_id, "nist-ai-rmf");
  assert.equal(content.governance_posture.accountable_role, "chief-risk-officer");
  assert.deepEqual(plain(content.measurements.evaluation), {
    schema: "measurement-v1", state: "measured", unit: "percent", value: 92.5, window_start: Date.UTC(2026, 0, 1) / 1000,
    window_end: Date.UTC(2026, 2, 31) / 1000, sample_count: 400, confidence: 0.9, evidence_ids: ["MRE-1"]
  });
  assert.deepEqual(plain(content.measurements.drift), {schema: "measurement-v1", state: "missing", unit: "percent", value: null,
    window_start: null, window_end: null, sample_count: 0, confidence: null, evidence_ids: []});
  assert.deepEqual(plain(content.incident_summary), {data_state: "missing", as_of: null, open_count: null, closed_count: null, highest_open_severity: null, evidence_ids: []});
  assert.deepEqual(plain(content.verifier_instructions), {schema_version: "v1", steps: ["Open the report", "Compare totals"]});
  assert.deepEqual(plain(pool.bindings(h.F.citedEvidence(content))), [{evidence_id: "MRE-1", digest: DIGEST}]);
});

test("a measured item without evidence is refused before anything is sent", async t => {
  const h = setup(t);
  const pool = new h.F.EvidencePool(); pool.set([]);
  const node = mount(h, h.F.specs.insurability(insurabilityDefs), {pool});
  control(h.form, "Framework name").value = "ISO 42001";
  control(h.form, "Accountable role").value = "Owner";
  const evaluation = Array.from(h.form.querySelectorAll("fieldset")).find(set => set.querySelector("legend")?.textContent === "Evaluation");
  set(h.w, control(evaluation, "Status"), "measured");
  for (const [label, value] of [["Result", "90"], ["Measured from", "2026-01-01"], ["Measured until", "2026-01-02"], ["How many cases", "5"], ["Confidence", "0.5"]]) control(evaluation, label).value = value;
  await assert.rejects(node.collect(), /Choose at least one piece of evidence/);
});

test("bank model-risk sections derive their status from each answer", async t => {
  const h = setup(t);
  const pool = new h.F.EvidencePool();
  pool.set([{id: "MRE-9", status: "approved", freshness: "current", payload_sha256: DIGEST}]);
  const defs = {bank_mrm: {section_schema: "section-v1", sections: [{key: "limitations", fields: [
    {key: "limitations_summary", kind: "text", choices: null}, {key: "residual_risk", kind: "choice", choices: ["high", "low"]}]}]}};
  const node = mount(h, h.F.specs.bankMrm(defs), {pool});
  const summary = Array.from(h.form.querySelectorAll("fieldset")).find(set => set.querySelector("legend")?.textContent === "Limitations summary");
  set(h.w, control(summary, "Status"), "verified");
  control(summary, "Answer").value = "Known gaps are listed.";
  await assert.rejects(node.collect(), /Choose evidence for “Limitations”/);
  h.form.querySelector("input[type=checkbox][value='MRE-9']").checked = true;
  const content = await node.collect();
  assert.deepEqual(plain(content.limitations), {schema: "section-v1", state: "missing", evidence_ids: ["MRE-9"], assertions: [
    {field: "limitations_summary", state: "verified", value: "Known gaps are listed."},
    {field: "residual_risk", state: "missing", value: null}]});
});

test("a checklist item that does not apply keeps only a private fingerprint of the reason", async t => {
  const h = setup(t);
  const pool = new h.F.EvidencePool(); pool.set([]);
  const node = mount(h, h.F.specs.regulated("nyc_ll144", {regulated: {nyc_checks: ["public_summary"]}}), {pool});
  control(h.form, "Assessment from").value = "2026-01-01";
  control(h.form, "Assessment until").value = "2026-06-30";
  const item = Array.from(h.form.querySelectorAll("fieldset")).find(set => set.querySelector("legend")?.textContent === "Public summary");
  set(h.w, control(item, "Status"), "not_applicable");
  control(item, "Why it does not apply").value = "We do not use the tool in New York City.";
  const content = await node.collect();
  assert.match(content.checklist.public_summary.rationale_sha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(plain(content.checklist.public_summary.evidence_ids), []);
  assert.equal(content.independent_auditor.state, "missing");
  assert.equal(content.independent_auditor.assertion_sha256, null);
  assert.equal(JSON.stringify(content).includes("New York City"), false, "the reason text itself is never sent");
});

test("credit reasons are ranked in the order they are listed", async t => {
  const h = setup(t);
  const pool = new h.F.EvidencePool(); pool.set([]);
  const node = mount(h, h.F.specs.regulated("credit_adverse_action", {}), {pool});
  const files = h.form.querySelectorAll("input[type=file]");
  for (const input of files) Object.defineProperty(input, "files", {value: [new h.w.File(["receipt"], "r.bin")]});
  control(h.form, "Reason").value = "Short credit history";
  control(h.form, "Model factor").value = "account age";
  const content = await node.collect();
  assert.equal(content.reason_codes[0].rank, 1);
  assert.equal(content.reason_codes[0].code, "short-credit-history");
  assert.match(content.model_receipt_sha256, /^[0-9a-f]{64}$/);
});

test("the incident report form sends every detail with safe defaults", async t => {
  const h = setup(t);
  const node = mount(h, h.F.specs.reportDetails());
  control(h.form, "AI system name").value = "Support bot";
  const missing = Array.from(h.form.querySelectorAll("fieldset")).find(set => set.querySelector("legend")?.textContent === "Details you do not have yet");
  tick(missing, "Root cause");
  const details = await node.collect();
  assert.equal(details.system_name, "Support bot");
  assert.equal(details.incident_occurred_at, null);
  assert.equal(details.investigation_status, "unknown");
  assert.equal(details.attestation_accepted, false);
  assert.deepEqual(plain(details.known_missing_fields), ["root_cause_conclusion"]);
  assert.deepEqual(plain(details.related_report_references), []);
});

test("an outside tool's result file is read without anyone typing it", async t => {
  const h = setup(t);
  const good = new h.w.File([JSON.stringify({operation: "verification"})], "result.json");
  assert.deepEqual(plain(await h.F.readRecordFile(good, "result")), {operation: "verification"});
  await assert.rejects(h.F.readRecordFile(new h.w.File(["not a record"], "x.txt"), "result"), /isn't a result file Lightwork can read/);
  await assert.rejects(h.F.readRecordFile(null, "result"), /Choose the result file first/);
});

test("values copied from another system keep their spelling and get the server's limits", t => {
  const {F} = setup(t);
  assert.equal(F.checkReference("  spring-campaign-2026 ", "release"), "spring-campaign-2026");
  assert.equal(F.checkReference("DE-2026/0042", "filing"), "DE-2026/0042");
  assert.equal(F.checkReference("10442", "employee"), "10442");
  assert.equal(F.checkReference("2026.1", "edition"), "2026.1");
  assert.equal(F.checkReference("Article 6 and Annex III", "provision"), "Article 6 and Annex III");
  assert.equal(F.checkReference("Confidential", "label"), "confidential");
  assert.throws(() => F.checkReference("spring campaign", "release"), /without spaces/);
  assert.throws(() => F.checkReference("x".repeat(257), "release"), /at most 256 characters/);
  assert.throws(() => F.checkReference("has spaces", "filing"), /exactly as the authority gave it/);
  assert.throws(() => F.checkReference("x".repeat(129), "employee"), /at most 128 characters/);
  assert.throws(() => F.checkReference("2026 spring", "edition"), /without spaces/);
  assert.throws(() => F.checkReference("Art. 6; drop", "provision"), /Type the provision/);
  assert.throws(() => F.checkReference("9lives", "label"), /starting with a letter/);
  assert.throws(() => F.checkReference("   ", "filing"), /Fill in the filing reference/);
});

const PROVISIONS = [
  {regulation: "EU AI Act", provision: "Art. 14", title: "Effective human oversight of a high-risk AI system", official_url: "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02024R1689-20260727"},
  {regulation: "EU AI Act", provision: "Art. 27(1)(a)", title: "The deployer's processes in which the system will be used", official_url: "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02024R1689-20260727"},
  {regulation: "GDPR", provision: "Art. 35", title: "Run a DPIA for high-risk processing", official_url: "https://eur-lex.europa.eu/eli/reg/2016/679/oj"}
];
const provisionMarkup = `<fieldset data-provision-picker><legend>Legal provision</legend>
  <label>Search the list<input type="search" data-provision-search></label>
  <label>Provision<select data-provision-choice></select></label>
  <label data-provision-other hidden>Provision not in the list<input></label></fieldset>`;
const setupProvision = (t, options) => {
  const h = setup(t);
  h.form.insertAdjacentHTML("beforeend", provisionMarkup);
  const picker = h.F.provisionPicker(h.form.querySelector("[data-provision-picker]"), {defaultUrl: "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=AIACT", ...options});
  return {...h, picker, select: control(h.form, "Provision"), search: control(h.form, "Search the list"), typed: control(h.form, "Provision not in the list")};
};
const optionTexts = select => Array.from(select.options).map(option => option.textContent);

test("provisions are chosen from a searchable list grouped by law, with typing as the last resort", async t => {
  const h = setupProvision(t, {required: true});
  assert.deepEqual(optionTexts(h.select), ["Loading provisions…", "Other (type it)"]);
  h.picker.set(PROVISIONS, "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02024R1689-20260727");
  assert.deepEqual(Array.from(h.select.querySelectorAll("optgroup")).map(group => group.label), ["EU AI Act", "GDPR"]);
  assert.equal(optionTexts(h.select).at(-1), "Other (type it)", "typing is offered last");
  h.search.value = "article 27";
  h.search.dispatchEvent(new h.w.Event("input"));
  assert.deepEqual(optionTexts(h.select), ["Choose a provision", "Art. 27(1)(a) — The deployer's processes in which the system will be used", "Other (type it)"]);
  set(h.w, h.select, h.select.options[1].value);
  assert.deepEqual(plain(h.picker.value()), {provision: "Art. 27(1)(a)", official_url: PROVISIONS[1].official_url});
  h.search.value = "dpia";
  h.search.dispatchEvent(new h.w.Event("input"));
  assert.equal(h.select.value, "", "a choice hidden by the search is not sent");
  assert.throws(() => h.picker.value(), /Choose the legal provision/);
  h.search.value = "nothing like this";
  h.search.dispatchEvent(new h.w.Event("input"));
  assert.equal(optionTexts(h.select)[0], "Nothing in the list matches — try other words");
});

test("a provision not in the list is typed only after choosing Other, and is checked", async t => {
  const h = setupProvision(t);
  h.picker.set(PROVISIONS, "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02024R1689-20260727");
  assert.equal(h.picker.value(), null, "an optional provision can be left empty");
  const other = h.form.querySelector("[data-provision-other]");
  assert.equal(other.hidden, true);
  set(h.w, h.select, "__other__");
  assert.equal(other.hidden, false);
  h.typed.value = "Art. 9(2); drop";
  assert.throws(() => h.picker.value(), /Type the provision/);
  h.typed.value = " Article 9(2) ";
  assert.deepEqual(plain(h.picker.value()), {provision: "Article 9(2)", official_url: "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02024R1689-20260727"});
});

const releaseMarkup = `<div data-release-picker>
  <label>Release<select data-release-choice></select></label>
  <label data-release-new hidden>Name of the new release<input></label></div>`;
test("releases are picked from the ones already used, newest first, and a new one is typed once", async t => {
  const h = setup(t);
  h.form.insertAdjacentHTML("beforeend", releaseMarkup + releaseMarkup);
  const [firstRoot, secondRoot] = h.form.querySelectorAll("[data-release-picker]");
  const list = new h.F.ReleaseList();
  const first = h.F.releasePicker(firstRoot, list);
  const second = h.F.releasePicker(secondRoot, list);
  const firstSelect = firstRoot.querySelector("select");
  assert.equal(firstSelect.options[0].textContent, "Loading releases…");
  list.set([
    {context_id: "spring-campaign-2026", last_used_at: 1800000000, deployment_ids: ["production-east"]},
    {context_id: "winter-sale", last_used_at: 1700000000, deployment_ids: ["production-west"]}
  ]);
  assert.deepEqual(Array.from(firstSelect.options).map(option => option.value), ["", "spring-campaign-2026", "winter-sale", "__new__"]);
  first.setDeployment("production-west");
  assert.deepEqual(Array.from(firstSelect.options).map(option => option.value), ["", "winter-sale", "__new__"], "only releases of the chosen deployment");
  assert.throws(() => first.value(), /Choose a release/);
  set(h.w, firstSelect, "__new__");
  assert.equal(firstRoot.querySelector("[data-release-new]").hidden, false);
  const typed = firstRoot.querySelector("[data-release-new] input");
  typed.value = "summer launch";
  assert.throws(() => first.value(), /without spaces/);
  typed.value = "summer-launch-2026";
  assert.equal(first.value(), "summer-launch-2026");
  assert.equal(firstSelect.value, "summer-launch-2026", "the new name is now chosen from the list");
  assert.equal(firstRoot.querySelector("[data-release-new]").hidden, true);
  const secondValues = Array.from(secondRoot.querySelectorAll("option")).map(option => option.value);
  assert.ok(secondValues.includes("summer-launch-2026"), "the other form offers the new name too");
  assert.match(Array.from(secondRoot.querySelectorAll("option")).find(option => option.value === "summer-launch-2026").textContent, /added just now/);
  set(h.w, secondRoot.querySelector("select"), "spring-campaign-2026");
  assert.equal(second.value(), "spring-campaign-2026");
});
