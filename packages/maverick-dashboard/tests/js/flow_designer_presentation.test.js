"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const view = require("../../maverick_dashboard/templates/flow_designer_presentation.js");

const context = {
  human: value => String(value), conditionText: value => `condition ${value}`,
  durationText: value => `${value} seconds`, flowNames: { followup: "Follow up" },
  kindLabel: value => `kind ${value}`,
};

test("graph labels and branch ports reflect their actual node data", () => {
  assert.equal(view.summary({ kind: "branch", condition: "approved" }, context), "condition approved");
  assert.equal(view.summary({ kind: "delay", seconds: 30 }, context), "Wait 30 seconds");
  assert.equal(view.summary({ kind: "subflow", flow_ref: "followup" }, context), "Runs Follow up");
  assert.deepEqual(view.ports({ kind: "branch" }, 176), [
    { key: "if_true", x: 50, cls: "t", label: "Yes" },
    { key: "if_false", x: 126, cls: "f", label: "No" },
  ]);
});

test("paused cursor and completed outcomes render consistently", () => {
  const state = { a: { outcome: 1 }, b: { outcome: 0 }, c: { status: "true" } };
  assert.equal(view.runClass("a", "a", state), " run-active");
  assert.equal(view.runBadge("a", "a", state), "⏳");
  assert.equal(view.runClass("b", null, state), " run-err");
  assert.equal(view.runBadge("b", null, state), "🔴");
  assert.equal(view.runBadge("c", null, state), "✓");
  assert.equal(view.runClass("missing", null, state), "");
});
