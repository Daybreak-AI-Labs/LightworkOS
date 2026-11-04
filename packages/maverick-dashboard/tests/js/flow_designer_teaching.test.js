"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const core = require("../../maverick_dashboard/templates/flow_designer_core.js");
const schedule = require("../../maverick_dashboard/templates/flow_designer_schedule.js");
const wire = require("../../maverick_dashboard/templates/flow_designer_wire.js");
const clone = value => JSON.parse(JSON.stringify(value));

function flow() {
  return { id: "teaching", name: "Human teaching", start: "approval_0", version: 3, revision: "reviewed-3",
    recipe_teaching: { schema: "lightwork.action-choice-teaching.v1" },
    recipe_lineage: { id: "admitted-parent", package_sha256: "p".repeat(64) },
    learned_recipe: { schema: "lightwork.action-choice.v1", artifact_sha256: "a".repeat(64),
      guard: { artifact: { artifact_sha256: "g".repeat(64), candidate_count: 2 } },
      branches: [{ route: "0", tool: "approve_case" }, { route: "1", tool: "queue_review" }] },
    nodes: [{ id: "approval_0", kind: "approval", next: "action_0" },
      { id: "action_0", kind: "action", recipe_step: 0, tool: "open_case", output: "_recipe_step_0", next: "choice" },
      { id: "choice", kind: "switch", condition: "_recipe_choice.route",
        cases: [{ value: "0", to: "approval_1_0" }, { value: "1", to: "approval_1_1" }] },
      { id: "teaching_review", kind: "approval", next: "teaching_choice", choices: ["route:0", "route:1"], output: "_recipe_teaching_decision" },
      { id: "teaching_choice", kind: "switch", condition: "_recipe_teaching_decision",
        cases: [{ value: "route:0", to: "approval_1_0" }, { value: "route:1", to: "approval_1_1" }] },
      { id: "approval_1_0", kind: "approval", next: "action_1_0" },
      { id: "approval_1_1", kind: "approval", next: "action_1_1" },
      { id: "action_1_0", kind: "action", recipe_step: 1, tool: "approve_case", output: "_recipe_step_1" },
      { id: "action_1_1", kind: "action", recipe_step: 1, tool: "queue_review", output: "_recipe_step_1" }] };
}

function fixture() {
  const context = { FDSchedule: schedule, FDWire: wire, document: { getElementById() { return null; } },
    renderCrumbs() {}, syncScheduleControls() {}, syncSaveButtons() {}, autoLayout() {}, render() {}, renderProps() {}, markClean() {},
    nameInput: {}, idInput: {}, normalizeNode: core.normalizeNode, serializeFlow: core.serializeFlow };
  const source = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates/flow_designer.js"), "utf8");
  const loadStart = source.indexOf("  function fromApiFlow("), loadEnd = source.indexOf("  function autoLayout(", loadStart);
  const saveStart = source.indexOf("  function toApiFlow("), saveEnd = source.indexOf("  function syncScheduleControls(", saveStart);
  assert.ok(loadStart >= 0 && loadEnd > loadStart && saveStart >= 0 && saveEnd > saveStart);
  vm.runInNewContext(source.slice(loadStart, loadEnd) + source.slice(saveStart, saveEnd), context,
    { filename: "flow_designer.js" });
  return context;
}

test("actual designer load and save preserve teaching marker, signed lineage, all routes and approval outputs", () => {
  const context = fixture(), original = flow(), expected = clone(original);
  context.fromApiFlow(original, true);
  original.recipe_teaching.schema = "caller mutation";
  original.recipe_lineage.id = "caller mutation";
  original.learned_recipe.branches.pop();
  context.rootFlow.nodes[1].x = 240;
  context.rootFlow.nodes[1].label = "Completed prefix";
  const saved = clone(context.toApiFlow());
  assert.deepEqual(saved.recipe_teaching, expected.recipe_teaching);
  assert.deepEqual(saved.recipe_lineage, expected.recipe_lineage);
  assert.deepEqual(saved.learned_recipe, expected.learned_recipe);
  assert.deepEqual(saved.nodes[3].choices, ["route:0", "route:1"]);
  assert.equal(saved.nodes[3].output, "_recipe_teaching_decision");
  assert.deepEqual(saved.nodes[4].cases, expected.nodes[4].cases);
  assert.equal(saved.nodes[1].recipe_step, 0);
  assert.deepEqual(saved.nodes.slice(-2).map(node => node.recipe_step), [1, 1]);
  context.fromApiFlow(saved, true);
  assert.deepEqual(clone(context.toApiFlow()), saved, "loading the saved draft must preserve the same wire graph");
});

test("undo snapshots independently preserve the teaching marker and evidence", () => {
  const original = flow(), snapshot = core.cloneFlow(original);
  original.recipe_teaching.schema = "mutated";
  original.learned_recipe.guard.artifact.candidate_count = 1;
  assert.equal(snapshot.recipe_teaching.schema, "lightwork.action-choice-teaching.v1");
  assert.equal(snapshot.learned_recipe.guard.artifact.candidate_count, 2);
  assert.deepEqual(core.serializeFlow(snapshot), snapshot);
});

for (const marker of [[], "malformed", false, { schema: "unexpected", extra: true }]) {
  test(`malformed teaching marker survives to server validation rather than silently disabling protection: ${JSON.stringify(marker)}`, () => {
    const context = fixture(), original = flow(); original.recipe_teaching = marker;
    context.fromApiFlow(original, true);
    assert.deepEqual(clone(context.toApiFlow()).recipe_teaching, marker);
  });
}

test("ordinary drafts do not acquire a teaching marker on designer load and save", () => {
  const context = fixture(), original = flow(); delete original.recipe_teaching;
  context.fromApiFlow(original, true);
  assert.equal("recipe_teaching" in context.toApiFlow(), false);
});

test("nested teaching markers remain visible for authoritative server scope validation", () => {
  const original = { id: "container", nodes: [{ id: "scope", kind: "scope", body: flow() }] };
  const saved = core.serializeFlow(original);
  assert.deepEqual(saved.nodes[0].body.recipe_teaching, flow().recipe_teaching);
  assert.deepEqual(saved.nodes[0].body.recipe_lineage, flow().recipe_lineage);
});
