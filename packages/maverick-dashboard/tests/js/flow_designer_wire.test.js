"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const wire = require("../../maverick_dashboard/templates/flow_designer_wire.js");
const core = require("../../maverick_dashboard/templates/flow_designer_core.js");

test("wire flow preserves exact receipts and evidence while serializing live controls", () => {
  const controls = { "fd-notify": {checked: true}, "fd-notify-on": {value: "failure"},
    "fd-maxsec": {value: "45"}, "fd-maxdollars": {value: "2.5"},
    "fd-schedule": {value: " 0 9 * * * "}, "fd-tz": {value: " UTC "}, "fd-maxconc": {value: "3"} };
  const rootFlow = {id: "draft", name: "Original", start: "a", version: 3, revision: "revision-3",
    recipe_teaching: {schema: "lightwork.action-choice-teaching.v1"},
    nodes: [{id: "a", kind: "action", tool: "lookup", recipe_step: 0}]};
  const result = wire.toApiFlow({document: {getElementById: id => controls[id]}, rootFlow,
    idInput: {value: " reviewed "}, nameInput: {value: "Reviewed"},
    flowInputs: [{key: "item", type: "text"}, {key: " "}], serializeFlow: core.serializeFlow});
  assert.equal(result.id, "reviewed"); assert.equal(result.schedule, "0 9 * * *");
  assert.equal(result.notify, true); assert.equal(result.notify_on, "failure");
  assert.equal(result.max_seconds, 45); assert.equal(result.max_dollars, 2.5); assert.equal(result.max_concurrent, 3);
  assert.deepEqual(result.inputs, [{key: "item", type: "text"}]);
  assert.equal(result.version, 3); assert.equal(result.revision, "revision-3");
  assert.deepEqual(result.recipe_teaching, rootFlow.recipe_teaching);
  assert.equal(result.nodes[0].recipe_step, 0);
});
