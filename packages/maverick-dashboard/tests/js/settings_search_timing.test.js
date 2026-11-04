"use strict";
// Ctrl+K's settings rows arrive within the finder's 350 ms re-rank: the
// settings search waits only briefly after typing (lightwork-settings-search.js).
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const SCRIPT = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-settings-search.js"), "utf8");

test("a typed query asks for settings after a short pause, and only the latest one", async () => {
  const dom = new JSDOM('<dialog id="navfinder-dialog"></dialog>', { url: "https://lightwork.test/help", runScripts: "outside-only" });
  const { window } = dom;
  const delays = [], timers = [], urls = [], shown = [];
  window.setTimeout = (fn, ms) => { delays.push(ms); timers.push(fn); return timers.length; };
  window.clearTimeout = () => {};
  window.fetch = async (url) => { urls.push(String(url)); return { ok: true, json: async () => ({ items: [{ href: "/settings", title: "Theme" }] }) }; };
  const dialog = window.document.getElementById("navfinder-dialog");
  dialog.lightworkFinder = { setSettings: (rows) => shown.push(rows.length) };
  window.eval(SCRIPT);
  const ask = (query) => dialog.dispatchEvent(new window.CustomEvent("lightwork:finder-query", { detail: { reason: "input", query } }));
  ask("the");
  ask("theme");
  assert.ok(delays.every((ms) => ms <= 100), `waits ${delays}`);
  await timers[0]();
  await timers[1]();
  assert.deepEqual(urls, ["/api/v1/settings/search?q=the", "/api/v1/settings/search?q=theme"]);
  assert.equal(shown.at(-1), 1);
  dom.window.close();
});

test("an answer replaced by a newer query or refused is still read, so its request completes", async () => {
  const dom = new JSDOM('<dialog id="navfinder-dialog"></dialog>', { url: "https://lightwork.test/help", runScripts: "outside-only" });
  const { window } = dom;
  const timers = [], read = [], shown = [];
  window.setTimeout = (fn) => { timers.push(fn); return timers.length; };
  window.clearTimeout = () => {};
  window.fetch = async (url) => {
    const query = new URL(String(url), "https://lightwork.test").searchParams.get("q");
    return { ok: query !== "refused", json: async () => { read.push(query); return { items: [{ href: "/settings", title: "Theme" }] }; } };
  };
  const dialog = window.document.getElementById("navfinder-dialog");
  dialog.lightworkFinder = { setSettings: (rows) => shown.push(rows.length) };
  window.eval(SCRIPT);
  const ask = (query) => dialog.dispatchEvent(new window.CustomEvent("lightwork:finder-query", { detail: { reason: "input", query } }));
  ask("the");
  const stale = timers[0]();
  ask("refused");
  await stale;
  await timers[1]();
  assert.deepEqual(read, ["the", "refused"]);
  assert.deepEqual(shown, [0, 0]);
  dom.window.close();
});
