"use strict";
// The Overview "Where goals stand" chart must count each status on its
// own. Deriving "Queued" as total - done - active - blocked would fold failed,
// cancelled and draft goals into it while clicking it lists only pending ones.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function boardScript() {
  const template = fs.readFileSync(
    path.resolve(__dirname, "../../maverick_dashboard/templates/index.html"), "utf8");
  const script = [...template.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)]
    .map(match => match[1]).find(source => source.includes("bd-mix"));
  assert.ok(script, "index.html must contain its board script");
  return script;
}

function run(data) {
  let render;
  const donuts = [];
  const node = () => ({
    appendChild() {}, set textContent(_v) {}, get textContent() { return ""; },
    classList: { toggle() {} }, set hidden(_v) {},
  });
  const board = {
    attach(config) { render = config.render; },
    kpi: () => node(), area() {}, hbars() {}, empty() {}, el: () => node(),
    bucketWeekly: rows => rows,
    donut(_box, config) { donuts.push(config); },
  };
  vm.runInNewContext(boardScript(), {
    window: { LWBoard: board }, document: { getElementById: () => node() },
    Date, Math,
  });
  render(data);
  return donuts[0];
}

const base = {
  days: 90,
  window: { delivered: 0, delivered_prev: 0 },
  daily: [], domains: [], recent: [],
};

test("failed, cancelled and draft goals are not counted as queued", () => {
  const donut = run({
    ...base,
    totals: { total: 33, active: 0, done: 30, blocked: 2 },
    by_status: { done: 30, blocked: 2, cancelled: 1 },
  });
  const by = Object.fromEntries(donut.segments.map(s => [s.label, s]));
  assert.equal(by.Queued.value, 0);
  assert.equal(by.Cancelled.value, 1);
  assert.equal(by.Cancelled.status, "cancelled");
  assert.equal(by.Failed.value, 0);
  assert.equal(donut.segments.reduce((n, s) => n + s.value, 0), 33);
});

test("each slice filters the recent list by exactly the status it counts", () => {
  const donut = run({
    ...base,
    totals: { total: 7, active: 1, done: 2, blocked: 1 },
    by_status: { done: 2, active: 1, blocked: 1, pending: 1, failed: 1, draft: 1 },
  });
  const by = Object.fromEntries(donut.segments.map(s => [s.label, s]));
  assert.equal(by.Queued.value, 1);
  assert.equal(by.Queued.status, "pending");
  assert.equal(by.Failed.value, 1);
  assert.equal(by.Failed.status, "failed");
  assert.equal(by.Other.value, 1);
  assert.equal(by.Other.status, "");
  assert.equal(donut.segments.reduce((n, s) => n + s.value, 0), 7);
  assert.match(donut.aria, /1 failed/);
  assert.match(donut.aria, /1 queued/);
});

test("an older server without per-status counts still draws a chart", () => {
  const donut = run({ ...base, totals: { total: 4, active: 1, done: 2, blocked: 0 } });
  assert.equal(donut.segments.reduce((n, s) => n + s.value, 0), 4);
});
