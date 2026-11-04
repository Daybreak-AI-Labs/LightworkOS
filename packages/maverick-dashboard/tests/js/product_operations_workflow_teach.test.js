"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const {JSDOM} = require("jsdom");
const {shell} = require("./_shell");
const base = path.resolve(__dirname, "../../maverick_dashboard");
const turn = () => new Promise(resolve => setImmediate(resolve));
// flow_teach.html inlines the exact-JSON helpers (FDRecipeInputs) before the
// teach script: rules and drafts travel as exact JSON text, so replies are read
// with text(), not json().
const recipeInputs = fs.readFileSync(path.join(base, "templates/flow_designer_inputs.js"), "utf8");
const reply = value => ({ok: true, json: async () => value, text: async () => JSON.stringify(value)});

test("Copilot teaching reaches the existing name, draft and save controls without raw package authoring", async () => {
  const template = fs.readFileSync(path.join(base, "templates/flow_teach.html"), "utf8");
  const dom = new JSDOM(template + '<aside id="mv-copilot"><section id="mv-product-operations">' +
    '<p id="mv-product-operation-status"></p><div id="mv-product-operation-buttons"></div>' +
    '<div id="mv-product-operation-form"></div></section></aside>', {url: "http://testserver/flows/owned/teach", runScripts: "outside-only"});
  const document = dom.window.document, calls = [];
  Object.assign(document.getElementById("flow-teach").dataset, {flow: "owned", lineage: "1", examples: "1"});
  const packageValue = {artifact: {schema: "private_lineage", episodes: []}, bundles: [{private_record: "retained evidence"}]};
  const recipe = {package: packageValue, summary: {runs: 2, actions: ["lookup_customer"], alternatives: 1}, approved: false};
  const refined = {package: {...packageValue, ancestry: "original signed sources retained"},
    summary: {runs: 3, actions: ["lookup_customer"], alternatives: 1}, approved: false};
  const draft = {id: "learned-order-review", name: "Order review (learned)", version: 1};
  const operation = {id: "learning.workflow_teach", label: "Learn from reviewed runs", available: true,
    revision: "source-review", source: "Current reviewed examples", summary: "Prepare a procedure",
    confirmation_required: true, fields: [
      {name: "run_ids", label: "Reviewed examples", kind: "multiselect", required: true,
        choices: [{value: "one", label: "First reviewed example"}, {value: "two", label: "Second reviewed example"}]},
      {name: "tools", label: "Actions", kind: "multiselect", required: true, value: ["lookup_customer"],
        choices: [{value: "lookup_customer", label: "Look up customer"}]},
      {name: "style", label: "What to learn", kind: "select", value: "plain", choices: [{value: "plain", label: "Same actions"}]}]};
  const fetch = async (url, options = {}) => {
    const body = options.body ? JSON.parse(options.body) : null; calls.push({url, body});
    let value;
    if (url === "/api/v1/flows/owned/teach") value = {flow: {id: "owned", name: "Order review", version: 1, revision: "flow-1"}, steps: [], tools: ["lookup_customer"]};
    else if (url.endsWith("/teach/examples")) value = {available: true, runs: [{run_id: "one", status: "accepted", can_learn: true,
      revision: 3, episode: "e".repeat(64), grant: "g".repeat(64)}]};
    else if (url === "/api/v1/flow-teach/approved") value = {recipes: []};
    else if (url.endsWith("/catalog")) value = {schema: 1, selection: {kind: "flow", id: "owned"}, context: "c".repeat(64), operations: [operation]};
    else if (url.endsWith("/prepare")) {
      assert.deepEqual(body.arguments, {run_ids: ["one", "two"], tools: ["lookup_customer"], style: "plain"});
      value = {operation: operation.id, read_only: false, token: "reviewed", expires_at: Date.now() / 1000 + 600, summary: "Prepare the exact examples"};
    } else if (url.endsWith("/execute")) value = {operation: operation.id, status: "confirmed", message: "Learned procedure ready",
      details: {flow_id: "owned", recipe}};
    else if (url.endsWith("/teach/recipe/refine")) {
      assert.deepEqual(body.package, packageValue);
      assert.deepEqual(body.expected_runs, {one: {revision: 3, episode: "e".repeat(64), grant: "g".repeat(64)}});
      assert.equal(options.headers['X-Lightwork-Flow-Version'], "1");
      assert.equal(options.headers['X-Lightwork-Flow-Revision'], "flow-1");
      value = refined;
    } else if (url.endsWith("/teach/recipe/draft")) {
      assert.deepEqual(body.package, refined.package); value = {draft, note: "Review the draft"};
    } else if (url === "/api/v1/flows") {
      assert.deepEqual(body.flow, draft); value = draft;
    } else throw new Error("Unexpected native request: " + url);
    return reply(value);
  };
  shell(dom.window); dom.window.fetch = fetch;  // the shell's helpers send through this fetch
  dom.window.mvConfirm = async () => true;
  const runtime = {window: dom.window, document, CustomEvent: dom.window.CustomEvent,
    URL: dom.window.URL, URLSearchParams, AbortController, setTimeout, clearTimeout, fetch};
  vm.runInNewContext(recipeInputs, runtime);
  vm.runInNewContext(fs.readFileSync(path.join(base, "static/lightwork-flow-teach.js"), "utf8"), runtime);
  vm.runInNewContext(fs.readFileSync(path.join(base, "static/lightwork-product-operations.js"), "utf8"), runtime);
  await turn(); await turn();
  assert.equal(document.querySelector("#rc-runs a").getAttribute("href"), "/flows/owned/runs/one");
  dom.window.LightworkProductOperations.open(); await turn();
  document.querySelector("#mv-product-operation-buttons button").click(); await turn(); await turn();
  document.querySelectorAll('[name="run_ids"] option').forEach(option => { option.selected = true; });
  document.querySelector("#mv-product-operation-form form").dispatchEvent(new dom.window.Event("submit", {bubbles: true, cancelable: true}));
  await turn(); await turn();
  const consent = document.querySelector('#mv-product-operation-form input[type="checkbox"]');
  const apply = Array.from(document.querySelectorAll("#mv-product-operation-form button")).find(button => button.textContent === "Apply reviewed change");
  assert.equal(apply.disabled, true, "nothing applies before the review is ticked");
  consent.checked = true; consent.dispatchEvent(new dom.window.Event("change"));
  apply.click();
  await turn(); await turn();
  assert.equal(document.getElementById("rc-result").hidden, false);
  assert.equal(document.getElementById("rc-name").value, "Order review (learned)");
  assert.doesNotMatch(document.getElementById("mv-product-operation-form").textContent, /private_lineage|retained evidence/);
  document.querySelector('#rc-runs input[name="rc-run"]').checked = true;
  const added = await dom.window.LightworkFlowTeach.perform({flow_id: "owned", version: 1, revision: "flow-1", mode: "recipe_refine"});
  assert.equal(added.status, "learned");
  assert.match(document.getElementById("rc-summary").textContent, /3 runs/);
  document.getElementById("rc-draft").click(); await turn(); await turn();
  assert.equal(document.getElementById("ft-save").hidden, false);
  document.getElementById("ft-save-go").click(); await turn(); await turn();
  assert.equal(document.querySelector("#ft-status a").getAttribute("href"), "/flows/designer/learned-order-review");
  assert.equal(calls.some(call => /\/run$|\/publish$/.test(call.url)), false);
});

test("the shared rule form learns, refines, attaches and saves with the reviewed step revision", async () => {
  const dom = new JSDOM(fs.readFileSync(path.join(base, "templates/flow_teach.html"), "utf8"),
    {url: "http://testserver/flows/owned/teach", runScripts: "outside-only"});
  const document = dom.window.document, calls = [];
  Object.assign(document.getElementById("flow-teach").dataset, {flow: "owned", lineage: "1", examples: "1"});
  const spec = {inputs: {amount: {type: "integer", min: 0, max: 1000}}, output_type: "boolean", constants: [100]};
  const artifact = {spec, example_count: 2, candidates: [{}]};
  const refined = {...artifact, example_count: 4};
  const summary = count => ({rules: 1, examples: count, inputs: [{name: "amount", kind: "integer"}], output_kind: "boolean"});
  const fetch = async (url, options = {}) => {
    const body = options.body ? JSON.parse(options.body) : null; calls.push({url, body});
    let value;
    if (url === "/api/v1/flows/owned/teach") value = {flow: {id: "owned", version: 1, revision: "flow-1"},
      steps: [{id: "decision", label: "Price decision", ready: true, rule: summary(2)}], tools: []};
    else if (url.endsWith("/teach/examples")) value = {available: true, runs: []};
    else if (url.endsWith("/approved")) value = {recipes: []};
    else if (url.endsWith("/rule/learn")) {
      assert.deepEqual(body.examples, [{inputs: {amount: 10}, output: false}, {inputs: {amount: 500}, output: true}]);
      value = {artifact, summary: summary(2)};
    } else if (url.endsWith("/rule/add-examples")) {
      assert.deepEqual(body.artifact, artifact); value = {artifact: refined, summary: summary(4)};
    } else if (url.endsWith("/rule/attach")) {
      assert.equal(body.node_id, "decision"); assert.deepEqual(body.artifact, refined);
      value = {draft: {id: "owned", version: 1, revision: "flow-1"}, note: "Save the reviewed rule"};
    } else if (url === "/api/v1/flows") value = {id: "owned", version: 2};
    else throw new Error("Unexpected native request: " + url);
    if (body && url.includes("/teach/")) {
      assert.equal(options.headers['X-Lightwork-Flow-Version'], "1");
      assert.equal(options.headers['X-Lightwork-Flow-Revision'], "flow-1");
    }
    return reply(value);
  };
  shell(dom.window); dom.window.fetch = fetch;  // the shell's helpers send through this fetch
  dom.window.mvConfirm = async () => true;
  const runtime = {window: dom.window, document, CustomEvent: dom.window.CustomEvent, setTimeout, fetch};
  vm.runInNewContext(recipeInputs, runtime);
  vm.runInNewContext(fs.readFileSync(path.join(base, "static/lightwork-flow-teach.js"), "utf8"), runtime);
  await turn(); await turn();
  document.getElementById("tr-output").value = "boolean";
  document.getElementById("tr-output").dispatchEvent(new dom.window.Event("change"));
  document.getElementById("tr-constants").value = "100";
  const examples = document.querySelectorAll("#tr-examples > div");
  examples[0].querySelector('input[data-kind="integer"]').value = "10";
  examples[0].querySelector('select[data-kind="boolean"]').value = "false";
  examples[1].querySelector('input[data-kind="integer"]').value = "500";
  examples[1].querySelector('select[data-kind="boolean"]').value = "true";
  const review = {flow_id: "owned", version: 1, revision: "flow-1", node_id: "decision", mode: "rule_teach"};
  assert.equal((await dom.window.LightworkFlowTeach.perform(review)).status, "learned");
  assert.equal((await dom.window.LightworkFlowTeach.perform({...review, mode: "rule_refine"})).status, "learned");
  assert.match(document.getElementById("tr-summary").textContent, /4 examples/);
  assert.equal((await dom.window.LightworkFlowTeach.perform({...review, revision: "old"})).status, "stale");
  document.getElementById("tr-attach").click(); await turn(); await turn();
  document.getElementById("ft-save-go").click(); await turn(); await turn();
  assert.match(document.getElementById("ft-status").textContent, /Saved/);
  assert.equal(calls.filter(call => call.url.endsWith("/rule/learn")).length, 1);
  assert.equal(calls.some(call => /\/publish$|\/run$/.test(call.url)), false);
});
