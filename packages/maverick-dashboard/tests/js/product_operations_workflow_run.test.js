"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const {JSDOM} = require("jsdom");

const source = fs.readFileSync(path.resolve(__dirname,
  "../../maverick_dashboard/static/lightwork-product-operations.js"), "utf8");
const turn = () => new Promise(resolve => setImmediate(resolve));

function setup(release = "a".repeat(64), config = {}) {
  // config.confirm marks the listed control as one that changes something itself.
  const dom = new JSDOM('<aside id="mv-copilot"><section id="mv-product-operations">' +
    '<p id="mv-product-operation-status"></p><div id="mv-product-operation-buttons"></div>' +
    '<div id="mv-product-operation-form"></div></section></aside>',
  {url: config.url || "http://testserver/flows/designer/owned"});
  const calls = [], launched = [];
  const catalog = {schema: 1, selection: {kind: "flow", id: "owned"}, context: "c".repeat(64),
    checked_at: 1, operations: [{id: "learning.workflow_run", label: "Run this published workflow",
      available: true, revision: "reviewed-release", source: "Current published workflow",
      summary: "Run the published procedure", confirmation_required: config.confirm === true}]};
  const fetch = async (url, options) => {
    const body = JSON.parse(options.body); calls.push({url, body});
    if (url.endsWith("/propose") && config.proposeFailure) throw Error("private transport detail");
    const response = url.endsWith("/catalog") ? catalog :
      url.endsWith("/prepare") ? {read_only: true, operation: "learning.workflow_run",
        summary: "Run the published procedure", source: "Current published workflow", checked_at: 1,
        details: {flow_id: "owned", release_id: release}} : null;
    assert.ok(response, "Copilot must not post directly to run or execute endpoints");
    return {ok: true, json: async () => response};
  };
  dom.window.LightworkFlowRun = {open: async (id, expected) => {
    launched.push([id, expected]); return {status: "started", run_id: "run-1"};
  }};
  vm.runInNewContext(source, {window: dom.window, document: dom.window.document,
    CustomEvent: dom.window.CustomEvent, URL: dom.window.URL, URLSearchParams,
    AbortController, setTimeout, clearTimeout, fetch});
  return {document: dom.window.document, window: dom.window, calls, launched};
}

test("Copilot reviews the selected learned release before opening the real input form", async () => {
  const ui = setup();
  ui.window.LightworkProductOperations.open(); await turn();
  const catalogButton = ui.document.querySelector('#mv-product-operation-buttons button');
  assert.equal(catalogButton.textContent, 'Run this published workflow');
  catalogButton.click(); await turn(); await turn();
  assert.equal(ui.calls.at(-1).url.endsWith('/prepare'), true);
  assert.deepEqual(ui.calls.at(-1).body.selection, {kind: 'flow', id: 'owned'});
  const launch = Array.from(ui.document.querySelectorAll('#mv-product-operation-form button'))
    .find(button => button.textContent === 'Enter workflow inputs');
  assert.ok(launch); launch.click(); await turn();
  assert.deepEqual(ui.launched, [['owned', 'a'.repeat(64)]]);
  assert.match(ui.document.querySelector('#mv-product-operation-status').textContent, /not a completed business outcome/);
  assert.equal(ui.document.querySelector('#mv-product-operation-form a').getAttribute('href'),
    '/flows/owned/runs/run-1');
  assert.equal(ui.calls.some(call => call.url.endsWith('/execute')), false);
});

test("Copilot refuses an unconfirmed release instead of opening the input form", async () => {
  const ui = setup('invalid-release');
  ui.window.LightworkProductOperations.open(); await turn();
  ui.document.querySelector('#mv-product-operation-buttons button').click(); await turn(); await turn();
  assert.equal(ui.document.querySelector('#mv-product-operation-form button'), null);
  assert.equal(ui.launched.length, 0);
  assert.match(ui.document.querySelector('#mv-product-operation-status').textContent, /could not be confirmed/);
});

test("a failed control suggestion does not claim a control opened or expose transport detail", async () => {
  const ui = setup("a".repeat(64), {proposeFailure: true});
  ui.window.LightworkProductOperations.open(); await turn();
  const outcome = await ui.window.LightworkProductOperations.propose('Run this published workflow');
  assert.equal(outcome, 'unavailable');
  const message = ui.document.querySelector('#mv-product-operation-status').textContent;
  assert.match(message, /could not be completed/);
  assert.doesNotMatch(message, /private transport detail/);
  assert.equal(ui.document.querySelector('#mv-product-operation-form').textContent, '');
});

test("the status line never says controls change nothing when one opens a form or needs confirmation", async () => {
  const plain = setup();
  plain.window.LightworkProductOperations.open(); await turn();
  const text = plain.document.querySelector('#mv-product-operation-status').textContent;
  assert.match(text, /open the page's own form; nothing changes unless you confirm there/);
  assert.doesNotMatch(text, /change nothing/);
  const writes = setup("a".repeat(64), {confirm: true});
  writes.window.LightworkProductOperations.open(); await turn();
  assert.match(writes.document.querySelector('#mv-product-operation-status').textContent,
    /Changes require a separate review and confirmation/);
});

test("the workflow builder's Steps mode offers the same flow control for the flow it has open", async () => {
  const ui = setup("a".repeat(64), {url: "http://testserver/workflow-builder?mode=steps&flow=owned"});
  ui.window.LightworkProductOperations.open(); await turn();
  assert.deepEqual(ui.calls[0].body, {page: "/workflow-builder", selection: {kind: "flow", id: "owned"}});
  ui.document.querySelector('#mv-product-operation-buttons button').click(); await turn(); await turn();
  assert.deepEqual(ui.calls.at(-1).body.selection, {kind: "flow", id: "owned"});
  const launch = Array.from(ui.document.querySelectorAll('#mv-product-operation-form button'))
    .find(button => button.textContent === 'Enter workflow inputs');
  launch.click(); await turn();
  assert.deepEqual(ui.launched, [['owned', 'a'.repeat(64)]]);
});

test("describing a new workflow, or a malformed flow address, selects no flow", async () => {
  for (const url of ["http://testserver/workflow-builder", "http://testserver/workflow-builder?mode=steps",
                     "http://testserver/workflow-builder?mode=steps&flow=..%2Fetc"]) {
    const ui = setup("a".repeat(64), {url});
    ui.window.LightworkProductOperations.open(); await turn();
    assert.deepEqual(ui.calls[0].body.selection, {}, url);
  }
});
