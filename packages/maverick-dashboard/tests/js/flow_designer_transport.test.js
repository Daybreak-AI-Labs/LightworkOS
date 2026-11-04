"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const transport = require("../../maverick_dashboard/templates/flow_designer_transport.js");

test("transport keeps caller options and never retries a mutation", async () => {
  const calls = [];
  const result = await transport.fetchJson(async (...args) => { calls.push(args); return "answer"; },
    "/api/v1/flows/a", {method: "POST", headers: {"X-Review": "bound"}, body: "{}"});
  assert.equal(result, "answer");
  assert.deepEqual(calls, [["/api/v1/flows/a", {method: "POST", headers: {"X-Review": "bound"}, body: "{}"}]]);
});

test("ambiguous or malformed mutation receipts preserve the recovery instruction", async () => {
  const options = {recipeInputs: null, failText: () => "access denied"};
  await assert.rejects(transport.readMutationResult({ok: true, json: async () => { throw Error("lost"); }}, "Save", options),
    /Save could not be confirmed.*Reload the flow/);
  await assert.rejects(transport.readMutationResult({ok: true, json: async () => []}, "Run", options),
    /Run could not be confirmed.*Check recent runs/);
  await assert.rejects(transport.readMutationResult({ok: false, json: async () => ({})}, "Save", options), /access denied/);
});

test("publication receipts must contain a complete committed version", () => {
  assert.equal(transport.validPublication({published: true, published_version: 1, published_revision: "r1"}), true);
  assert.equal(transport.validPublication({published: true, published_version: 1, published_revision: " "}), false);
  assert.equal(transport.validPublication({published: false, published_version: null, published_revision: ""}), true);
  assert.equal(transport.validPublication({published: false, published_version: 1, published_revision: "r1"}), false);
});
