"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const history = require("../../maverick_dashboard/templates/flow_designer_history.js");
const inputs = require("../../maverick_dashboard/templates/flow_designer_inputs.js");

test("history preserves unfinished fields and buffers instead of only wire values", () => {
  const fields = {"fd-schedule": {value: "unfinished schedule"}, "fd-notify": {checked: true}};
  const rootFlow = {id: "flow", name: "Flow", start: "a", nodes: [{id: "a", kind: "action", _paramsRaw: "{"}]};
  const text = history.snapshot({rootFlow, idInput: {value: "draft-id"}, nameInput: {value: "draft name"},
    flowInputs: [{key: ""}], document: {getElementById: id => fields[id]}, recipeInputs: inputs});
  const restored = history.restore(text, rootFlow, null, inputs);
  assert.equal(restored.flow.nodes[0]._paramsRaw, "{");
  assert.equal(restored.settings.schedule, "unfinished schedule");
  assert.equal(restored.settings.notify, true);
  assert.deepEqual(restored.settings.inputs, [{key: ""}]);
});

test("history keeps latest receipts only for the exact saved generation", () => {
  const snap = JSON.stringify({id: "flow", version: 2, revision: "r2", published: false,
    published_version: null, published_revision: "", nodes: [], _editorSettings: {id: "flow"}});
  const current = {id: "flow", version: 3, revision: "r2", published: true,
    published_version: 3, published_revision: "published-3"};
  const same = history.restore(snap, current, null, inputs);
  assert.equal(same.flow.published_revision, "published-3");
  const replacement = history.restore(snap, {...current, revision: "new-generation"}, null, inputs);
  assert.equal(replacement.flow.version, 2);
  assert.equal(replacement.flow.published, false);
});

test("first-save receipts bind only the explicitly captured unsaved history", () => {
  const snap = JSON.stringify({id: "", nodes: [], _editorSettings: {id: ""}});
  const receipt = {id: "saved", version: 1, revision: "created", published: false,
    published_version: null, published_revision: ""};
  const binding = {sourceId: "", snapshots: [snap], receipt};
  const restored = history.restore(snap, {id: "saved", version: 1, revision: "created"}, binding, inputs);
  assert.equal(restored.flow.id, "saved"); assert.equal(restored.settings.id, "saved");
  assert.equal(restored.flow.revision, "created");
  assert.equal(history.restore(snap, {}, {...binding, snapshots: []}, inputs).flow.id, "");
});
