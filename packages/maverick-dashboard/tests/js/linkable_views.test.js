// Run with: node --test packages/maverick-dashboard/tests/js/linkable_views.test.js
"use strict";
// Every view has a link that reproduces it. The board time ranges and
// the privacy record tabs keep the chosen tab in the address, an address
// naming a range loads that range, and a finder search has its own ?find=.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const { panelTabs } = require("./_tab_markup");

const root = path.resolve(__dirname, "../../maverick_dashboard");
const read = (name) => fs.readFileSync(path.join(root, name), "utf8");
const tabsScript = read("static/lightwork-tabs.js");
const boardScript = read("static/board.js");
const finderScript = read("static/lightwork-navfinder.js");

test("board time ranges and privacy record tabs keep the chosen tab in the address", () => {
  for (const page of ["index", "oversight", "savings", "spend", "workforce"]) {
    assert.match(read(`templates/${page}.html`), /panel_tabs\('Time range'[^\n]*hash='range-'\)/, page);
  }
  const privacy = read("templates/privacy.html");
  assert.match(privacy, /panel_prefix='pw-tab-', hash='pv-'\)/);
  assert.match(privacy, /panel_prefix='pe-tab-', hash='pe-'\)/);
});

function board(url) {
  const ranges = [["30", "30 days"], ["90", "90 days"], ["180", "6 months"], ["365", "1 year"]];
  const tabs = panelTabs("Time range", ranges, "90", { id: "bd-range", data: "days", controls: false, manual: true, hash: "range-" });
  const dom = new JSDOM(`<main>${tabs}<p id="bd-stamp"></p></main>`, { url, runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window, calls = [];
  w.fetch = async (u) => { calls.push(String(u)); return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } }); };
  w.eval(tabsScript);
  w.mvTabs.init();
  w.eval(boardScript);
  return { w, calls };
}

test("an address naming a time range loads that range, and choosing one updates the address", async () => {
  const { w, calls } = board("https://local.test/spend#range-30");
  w.LWBoard.attach({ board: "spend", render() {} });
  await new Promise((r) => setTimeout(r, 20));
  assert.ok(calls.some((u) => u.endsWith("?days=30")), calls.join(" "));
  assert.ok(!calls.some((u) => u.endsWith("?days=90")), "the default range is not loaded first");
  w.document.getElementById("bd-range-tab-180").click();
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(w.location.hash, "#range-180");
  assert.ok(calls.some((u) => u.endsWith("?days=180")));
  w.close();
});

function finder(url) {
  const markup = `<button id="navfinder-open" aria-expanded="false">Search</button>
    <dialog id="navfinder-dialog"><input id="navfinder-input"><button id="navfinder-close">Close</button>
    <p id="navfinder-count"></p><div id="navfinder-results"><a href="/approvals" data-navfinder-target data-label="Approvals|Approvals" data-heading="" data-search="approvals">Approvals</a></div><p id="navfinder-empty" hidden></p></dialog>`;
  const dom = new JSDOM(markup, { url, runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window;
  w.fetch = async () => new Response("", { status: 404 });
  w.eval(finderScript);
  return new Promise((done) => {
    if (w.document.readyState === "loading") w.document.addEventListener("DOMContentLoaded", () => setTimeout(() => done(w), 0));
    else done(w);
  });
}

test("a finder search has an address that reopens it, and closing the finder removes it", async () => {
  const w = await finder("https://local.test/today?find=approv");
  const input = w.document.getElementById("navfinder-input");
  const dialog = w.document.getElementById("navfinder-dialog");
  assert.equal(input.value, "approv");
  assert.ok(dialog.open || dialog.hasAttribute("open"));
  input.value = "approvals waiting";
  input.dispatchEvent(new w.Event("input"));
  assert.equal(new w.URL(w.location.href).searchParams.get("find"), "approvals waiting");
  w.document.getElementById("navfinder-close").click();
  assert.equal(new w.URL(w.location.href).searchParams.get("find"), null);
  assert.equal(w.location.pathname, "/today");
  w.close();
});

test("a page without a search in its address opens no finder", async () => {
  const w = await finder("https://local.test/today");
  const dialog = w.document.getElementById("navfinder-dialog");
  assert.ok(!(dialog.open || dialog.hasAttribute("open")));
  w.close();
});
