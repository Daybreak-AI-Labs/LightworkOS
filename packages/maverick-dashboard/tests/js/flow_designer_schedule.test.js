"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const schedule = require("../../maverick_dashboard/templates/flow_designer_schedule.js");

test("schedule choices round-trip without changing their run times", () => {
  const examples = [
    [{ freq: "hourly", every: 4, minute: 15, days: [] }, "15 */4 * * *"],
    [{ freq: "daily", time: "09:30", days: [] }, "30 9 * * *"],
    [{ freq: "weekdays", time: "17:00", days: [] }, "0 17 * * 1-5"],
    [{ freq: "weekly", time: "08:05", days: ["1", "3"] }, "5 8 * * 1,3"],
    [{ freq: "monthly", time: "12:00", dom: "31", days: [] }, "0 12 31 * *"],
  ];
  for (const [options, cron] of examples) {
    assert.equal(schedule.build(options), cron);
    const parsed = schedule.parse(cron);
    assert.equal(parsed.freq, options.freq);
    assert.equal(schedule.build({ ...parsed, days: parsed.days || [] }), cron);
  }
});

test("custom timetables and unsupported intervals survive editing", () => {
  const cron = "7 */5 * * *";
  assert.deepEqual(schedule.parse(cron), { freq: "custom" });
  assert.equal(schedule.build({ freq: "custom", cron: `  ${cron}  `, days: [] }), cron);
  assert.equal(schedule.words(cron), "a custom timetable");
  assert.deepEqual(schedule.parse("61 9 * * *"), { freq: "custom" });
});

test("calendar names and defaults match the existing picker", () => {
  assert.equal(schedule.words("0 9 * * 1-5"), "weekdays at 9 am");
  assert.equal(schedule.words("0 12 31 * *"), "monthly on the 31st at 12 pm");
  assert.equal(schedule.words("30 8 * * 0,3"), "every Sunday, Wednesday at 8:30 am");
  assert.equal(schedule.build({ freq: "weekly", time: "09:00", days: [] }), "0 9 * * 1");
});
