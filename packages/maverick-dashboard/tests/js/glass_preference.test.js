// Run with: node --test packages/maverick-dashboard/tests/js/glass_preference.test.js
"use strict";
// Glass effects is chosen in Display preferences like the theme: the page
// switches at once, the choice is saved, and Undo or a failed save restores it.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const source = fs.readFileSync(
  path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-ui.js"), "utf8");
const wait = async () => { for (let i = 0; i < 6; i++) await new Promise((done) => setImmediate(done)); };

function page({ ok = true } = {}) {
  const dom = new JSDOM(`<!doctype html><html><head>
    <meta name="lightwork-preference-context" content="ctx">
    <meta name="lightwork-preference-revision" content="rev-1">
    </head><body class="theme-dark font-default density-comfortable glass-off">
    <div id="mv-toasts"></div><div id="mv-toasts-alert"></div>
    <details class="prefs" id="prefs-menu" open><summary>Display preferences</summary><div class="prefs__panel">
      <input type="checkbox" id="prefs-device-only" checked>
      <p id="prefs-status"></p><button type="button" id="prefs-undo" hidden>Undo</button>
      <select id="glass-select" data-ui-preference="glass"><option value="off" selected>Off</option><option value="on">On</option></select>
    </div></details></body></html>`, { url: "https://lightwork.test/overview", runScripts: "outside-only" });
  const w = dom.window;
  w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
  const requests = [];
  w.fetch = async (url, options) => {
    requests.push({ url, options });
    if (url === "/api/v1/preferences/display") {
      return { ok, json: async () => (ok ? { value: JSON.parse(options.body).value } : { detail: "No." }) };
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };
  w.eval(source);
  return { w, requests };
}

function choose(w, value) {
  const select = w.document.getElementById("glass-select");
  select.value = value;
  select.dispatchEvent(new w.Event("change", { bubbles: true }));
}

test("choosing Glass effects switches the page at once and saves the choice", async () => {
  const { w, requests } = page();
  const body = w.document.body;
  choose(w, "on");
  assert.ok(body.classList.contains("glass-on"));
  assert.ok(!body.classList.contains("glass-off"));
  await wait();
  const saved = requests.find((r) => r.url === "/api/v1/preferences/display");
  assert.deepEqual(JSON.parse(saved.options.body),
    { key: "glass", value: "on", context: "ctx", expected_revision: "rev-1", device_only: true });
  assert.ok(body.classList.contains("theme-dark") && body.classList.contains("density-comfortable"));
  const undo = w.document.getElementById("prefs-undo");
  assert.equal(undo.hidden, false);
  undo.click();
  assert.ok(body.classList.contains("glass-off") && !body.classList.contains("glass-on"));
  await wait();
  assert.equal(w.document.getElementById("glass-select").value, "off");
  w.close();
});

test("a refused save puts the earlier look back", async () => {
  const { w } = page({ ok: false });
  choose(w, "on");
  await wait();
  assert.ok(w.document.body.classList.contains("glass-off"));
  assert.ok(!w.document.body.classList.contains("glass-on"));
  assert.equal(w.document.getElementById("glass-select").value, "off");
  assert.match(w.document.getElementById("prefs-status").textContent, /not saved/);
  w.close();
});
