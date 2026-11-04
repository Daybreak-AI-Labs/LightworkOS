"use strict";

const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {fetchHelpers} = require('./_shell');
const vm = require("node:vm");

const script = fs.readFileSync(path.resolve(__dirname,
  "../../maverick_dashboard/templates/flow_hardening_review.js"), "utf8");

function fixture(forms, changing = false) {
  const calls = [], prompts = [], confirmations = [];
  const review = {flow_id: "orders", flow_name: "Order lookup", version: 3, revision: "rev-3",
    node_id: "lookup", node_label: "Find order", from_kind: "agent", to_kind: "action",
    published: true, inferred_tool: "web_search", tool: "web_search", approval_added: true,
    fields: [{name: "query", label: "Query", type: "string", required: true}],
    sources: [{key: "customer", label: "Customer name", origin: "input"}]};
  // The module clears private review drafts when the account or workspace changes.
  const listeners = {};
  const context = {window: {mvFetchJSON: fetchHelpers(() => context.fetch).mvFetchJSON,
      addEventListener(name, callback) { listeners[name] = callback; }},
    document: {addEventListener(name, callback) { listeners[name] = callback; }},
    encodeURIComponent, Number, Error,
    async fetch(url, options = {}) {
      calls.push([url, options]);
      let body;
      if (url.includes("/apply-review")) body = changing && url.includes("&tool=")
        ? {...review, version: 4} : review;
      else if (url.endsWith("/flows/tools")) body = {tools: [{name: "web_search"}]};
      else if (url.endsWith("/apply")) body = {id: "orders", node_id: "lookup", to_kind: "action", version: 4};
      else throw new Error("unexpected request: " + url);
      return {ok: true, status: 200, async json() { return body; }};
    }};
  context.window.mvForm = async (title, fields) => {
    prompts.push({title, fields}); return forms.shift();
  };
  context.window.mvConfirm = async (message) => {confirmations.push(message); return true;};
  vm.runInNewContext(script, context);
  return {api: context.window.LightworkFlowRewrite, calls, prompts, confirmations, listeners};
}

test("review binds a named flow input and sends the current version only after confirmation", async () => {
  const ui = fixture([{tool: "web_search"}, {query: "source:customer"}]);
  const result = await ui.api.review("orders", {node_id: "lookup", to_kind: "action"});
  assert.equal(result.version, 4);
  assert.equal(ui.prompts.length, 2);
  assert.match(ui.confirmations[0], /Published runs keep the current version/);
  assert.match(ui.confirmations[0], /adds an approval/);
  const apply = ui.calls.find(([url]) => url.endsWith("/apply"));
  assert.ok(apply);
  assert.deepEqual(JSON.parse(apply[1].body), {node_id: "lookup", to_kind: "action",
    version: 3, revision: "rev-3", tool: "web_search", params: {query: "{{customer}}"}});
});

test("cancelled or stale review never submits a flow change", async () => {
  const cancelled = fixture([null]);
  assert.equal(await cancelled.api.review("orders", {node_id: "lookup", to_kind: "action"}), null);
  assert.equal(cancelled.calls.some(([url]) => url.endsWith("/apply")), false);

  const stale = fixture([{tool: "web_search"}], true);
  await assert.rejects(stale.api.review("orders", {node_id: "lookup", to_kind: "action"}), /changed/);
  assert.equal(stale.calls.some(([url]) => url.endsWith("/apply")), false);
});
