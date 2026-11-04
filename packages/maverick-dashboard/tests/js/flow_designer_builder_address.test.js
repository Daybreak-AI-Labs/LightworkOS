"use strict";
// A flow saved in the workflow builder's Steps mode keeps the builder's
// address (/workflow-builder?mode=steps&flow=<id>), so a reload, Back and
// Copilot's flow controls stay on that tab; the classic designer keeps its own.
// Run with: node --test tests/js/flow_designer_builder_address.test.js
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const source = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates/flow_designer.js"), "utf8");
const start = source.indexOf("  function canonicalizeSavedFlow(");
const body = source.slice(start, source.indexOf("\n  }\n", start) + 4);

function run(pathname, search, id) {
  const replaced = [], attrs = {};
  const context = {
    window: {location: {pathname, search}, history: {state: null, replaceState: (_s, _t, url) => replaced.push(url)}},
    canvas: {setAttribute: (name, value) => { attrs[name] = value; }},
    draftRecovery: null, initializeRecovery() {}, rootFlow: {name: "Weekly digest"}, nameInput: {value: ""},
    document: {querySelector: () => null},
  };
  vm.runInNewContext(body + "\ncanonicalizeSavedFlow(" + JSON.stringify(id) + ");", context);
  return {replaced, attrs};
}

test("Steps mode keeps the builder address with the saved flow", () => {
  const {replaced, attrs} = run("/workflow-builder", "?mode=steps", "weekly-digest");
  assert.deepEqual(replaced, ["/workflow-builder?mode=steps&flow=weekly-digest"]);
  assert.equal(attrs["data-flow-id"], "weekly-digest");
  assert.deepEqual(run("/workflow-builder", "?mode=steps&flow=weekly-digest", "weekly-digest").replaced, []);
});

test("the classic designer keeps its own address", () => {
  assert.deepEqual(run("/flows/designer", "", "weekly-digest").replaced, ["/flows/designer/weekly-digest"]);
  assert.deepEqual(run("/flows/designer/weekly-digest", "", "weekly-digest").replaced, []);
  assert.deepEqual(run("/flows/designer", "?from_template=x", "weekly-digest").replaced, ["/flows/designer/weekly-digest"]);
});
