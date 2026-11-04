"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { editableFlow } = require("../../maverick_dashboard/templates/flow_designer_draft.js");

test("draft snapshot keeps unfinished edits without mutating the original", () => {
  const original = {
    id: "review", version: 3, revision: "saved-3", published: true,
    published_version: 2, published_revision: "published-2", _fdEvidence: null,
    nodes: [{ id: "one", kind: "action", tool: "search", _actionRaw: {},
      _actionErrors: {}, _actionKinds: {}, _actionTool: "search",
      body: { nodes: [{ id: "nested", kind: "action", tool: "search",
        _actionRaw: { term: "{" }, _actionErrors: { term: "invalid" }, _actionTool: "search" }] } }],
  };
  const snapshot = editableFlow(original, () => true);

  assert.equal(snapshot.version, undefined);
  assert.equal(snapshot.revision, undefined);
  assert.equal(snapshot.published, undefined);
  assert.equal(snapshot._fdEvidence, undefined);
  assert.equal(snapshot.nodes[0]._actionTool, undefined);
  assert.deepEqual(snapshot.nodes[0].body.nodes[0]._actionRaw, { term: "{" });
  assert.equal(original.version, 3);
  assert.deepEqual(original.nodes[0]._actionRaw, {});
});

test("unvalidated action details and nonempty evidence remain in the draft", () => {
  const original = { id: "review", _fdEvidence: { binding: "receipt" },
    nodes: [{ id: "one", _actionKinds: { n: "number" }, _actionTool: "lookup" }] };
  const snapshot = editableFlow(original, () => false);
  assert.deepEqual(snapshot._fdEvidence, { binding: "receipt" });
  assert.deepEqual(snapshot.nodes[0]._actionKinds, { n: "number" });
  assert.equal(snapshot.nodes[0]._actionTool, "lookup");
});
