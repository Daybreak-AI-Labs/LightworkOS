"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const graph = require("../../maverick_dashboard/templates/flow_designer_graph.js");
const core = require("../../maverick_dashboard/templates/flow_designer_core.js");

test("open ends follow reachable decision branches and exclude disconnected steps", () => {
  const flow = { start: "decide", nodes: [
    { id: "decide", kind: "branch", if_true: "approve", if_false: null, next: null },
    { id: "approve", kind: "approval", next: null },
    { id: "orphan", kind: "action", next: null },
  ] };
  assert.deepEqual(graph.openEnds(flow, flow, core, n => n.id), [
    { id: "decide", port: "if_false", label: "If no, after “decide”" },
    { id: "approve", port: "next", label: "After “approve”" },
  ]);
  assert.deepEqual(graph.pathsOf(flow.nodes[0]), [
    { label: "Yes", to: "approve" }, { label: "No", to: null },
  ]);
});

test("linear order stops at cycles and still returns every unvisited step", () => {
  const flow = { start: "a", nodes: [
    { id: "c" }, { id: "a", next: "b" }, { id: "b", next: "a" },
  ] };
  assert.deepEqual(graph.linearOrder(flow, flow).map(n => n.id), ["a", "b", "c"]);
});
