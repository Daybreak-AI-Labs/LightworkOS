import assert from "node:assert/strict";
import { test } from "node:test";
import { parseStructuredPageContext } from "../index.js";

test("untrusted password controls never expose their values", () => {
  const snapshot = parseStructuredPageContext({ elements: [
    { tag: "input", type: "password", value: "synthetic-password" },
    { tag: "input", type: "PASSWORD", value: "synthetic-password" },
    { tag: "input", type: "text", value: "visible text" },
  ] });
  assert.ok(snapshot);
  assert.equal(snapshot.elements[0].value, undefined);
  assert.equal(snapshot.elements[1].value, undefined);
  assert.equal(snapshot.elements[2].value, "visible text");
});
