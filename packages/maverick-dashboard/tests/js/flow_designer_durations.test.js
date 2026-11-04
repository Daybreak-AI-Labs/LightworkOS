"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const durations = require("../../maverick_dashboard/templates/flow_designer_durations.js");

test("duration choices preserve custom saved values", () => {
  const options = durations.durationOptions(125, "No wait");
  assert.deepEqual(options[0], {v: "0", t: "No wait"});
  assert.deepEqual(options.at(-1), {v: "125", t: "125 seconds"});
  assert.equal(durations.durationOptions(3600, "Never").filter(option => option.v === "3600").length, 1);
});

test("retry choices explain preserved requests beyond the first-wait limit", () => {
  assert.deepEqual(durations.retryWaitOptions(60).at(-1),
    {v: "60", t: "Saved request: 1 minute (first wait: 30 seconds)"});
  assert.deepEqual(durations.retryWaitOptions(-1).at(-1),
    {v: "-1", t: "Saved request: -1 seconds"});
  assert.equal(durations.durationText(86400), "1 day");
  assert.equal(durations.durationText(120), "2 minutes");
});
