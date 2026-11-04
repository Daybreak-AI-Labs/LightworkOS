"use strict";
// Bulk work on an admin list (window.mvBulk in lightwork-ui.js):
// filter, select all matching, act with a counted confirmation, then undo or
// read a change report. Everything is a native control, so it works by
// keyboard; Ctrl+A in the list selects every matching row.
// Run with: node --test tests/js/bulk_actions.test.js
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const {JSDOM} = require("jsdom");
const root = path.resolve(__dirname, "../../maverick_dashboard");
const source = fs.readFileSync(path.join(root, "static/lightwork-ui.js"), "utf8");
const flush = async () => { for (let i = 0; i < 6; i++) await new Promise(resolve => setImmediate(resolve)); };

function load(rows) {
  const body = rows.map(([id, label]) =>
    `<tr data-bulk-id="${id}" data-bulk-label="${label}"><td>${label}</td><td><button type="button">Open</button></td></tr>`).join("");
  const dom = new JSDOM(`<div id="mv-toasts"></div><div id="mv-toasts-alert"></div><main id="content">
    <table><thead><tr><th>Name</th><th>Actions</th></tr></thead><tbody id="list">${body}</tbody></table></main>`,
  {url: "https://lightwork.test/permissions", runScripts: "outside-only"});
  const w = dom.window;
  w.matchMedia = () => ({matches: false, addEventListener() {}, removeEventListener() {}});
  w.confirms = [];
  w.confirm = message => { w.confirms.push(message); return w.answer !== false; };
  w.eval(source);
  return w;
}

function setup(w, extra) {
  const calls = [], undone = [];
  const bulk = w.mvBulk(Object.assign({
    list: w.document.getElementById("list"), rows: "tr[data-bulk-id]",
    noun: "tool", nouns: "tools", filter: true,
    actions: [{
      label: "Block", verb: "Block", danger: true,
      run: async item => {
        calls.push(item.id);
        if (item.id === "shell") throw Object.assign(new Error("refused"), {status: 409, detail: "Set by your organization."});
        return {undo: async () => { undone.push(item.id); }};
      }
    }]
  }, extra || {}));
  return {bulk, calls, undone};
}
const bar = w => w.document.querySelector(".mv-bulk");
const picks = w => [...w.document.querySelectorAll("#list input[data-bulk-pick]")];
const button = (w, text) => [...bar(w).querySelectorAll("button")].find(b => b.textContent.trim().startsWith(text));

test("every row gets a labelled checkbox and the bar counts the selection", () => {
  const w = load([["web_fetch", "Web fetch"], ["shell", "Shell"], ["email", "Email"]]);
  setup(w);
  assert.equal(picks(w).length, 3);
  assert.equal(w.document.querySelector("thead th").textContent.trim(), "Select");
  const label = w.document.querySelector('label[for="' + picks(w)[0].id + '"]');
  assert.match(label.textContent, /Select Web fetch/);
  assert.ok(bar(w).getAttribute("aria-label").includes("several tools"));
  assert.equal(button(w, "Block").disabled, true, "nothing selected yet");
  picks(w)[1].click();
  assert.match(bar(w).querySelector(".mv-bulk__count").textContent, /1 selected/);
  assert.equal(button(w, "Block").disabled, false);
  w.close();
});

test("the filter narrows the list and select all takes every matching row only", () => {
  const w = load([["web_fetch", "Web fetch"], ["web_search", "Web search"], ["email", "Email"]]);
  setup(w);
  const filter = bar(w).querySelector('input[type="search"]');
  filter.value = "web"; filter.dispatchEvent(new w.Event("input", {bubbles: true}));
  const rows = [...w.document.querySelectorAll("#list tr")];
  assert.deepEqual(rows.map(r => r.hidden), [false, false, true]);
  const all = bar(w).querySelector(".mv-bulk__all input");
  assert.match(all.parentElement.textContent, /Select all 2 matching/);
  all.click();
  assert.deepEqual(picks(w).map(p => p.checked), [true, true, false]);
  assert.match(bar(w).querySelector(".mv-bulk__count").textContent, /2 selected/);
  // Changing the filter drops hidden rows from the selection: nothing out of view is changed.
  picks(w)[2].checked = true;
  filter.value = "search"; filter.dispatchEvent(new w.Event("input", {bubbles: true}));
  assert.deepEqual(picks(w).map(p => p.checked), [false, true, false]);
  w.close();
});

test("Ctrl+A in the list selects all matching rows", () => {
  const w = load([["a", "Alpha"], ["b", "Beta"]]);
  setup(w);
  const target = w.document.querySelector("#list button");
  target.dispatchEvent(new w.KeyboardEvent("keydown", {key: "a", ctrlKey: true, bubbles: true}));
  assert.deepEqual(picks(w).map(p => p.checked), [true, true]);
  w.close();
});

test("the action asks with the count, then reports each row and offers undo", async () => {
  const w = load([["web_fetch", "Web fetch"], ["shell", "Shell"], ["email", "Email"]]);
  const {calls, undone} = setup(w);
  bar(w).querySelector(".mv-bulk__all input").click();
  button(w, "Block").click();
  await flush();
  assert.match(w.confirms[0], /^Block 3 tools\? Web fetch, Shell and Email\./);
  assert.deepEqual(calls, ["web_fetch", "shell", "email"]);
  const report = w.document.querySelector(".mv-bulk__report");
  assert.equal(report.hidden, false);
  assert.equal(w.document.activeElement, report, "the report takes focus");
  assert.match(report.querySelector("h3").textContent, /Block: 2 done, 1 not changed/);
  assert.match(report.textContent, /Shell — not changed: Set by your organization\./);
  const undo = [...report.querySelectorAll("button")].find(b => /Undo these changes/.test(b.textContent));
  assert.ok(undo, "undo is offered when every change can be undone");
  undo.click();
  await flush();
  assert.deepEqual(undone, ["web_fetch", "email"]);
  assert.match(report.querySelector("h3").textContent, /Undone: 2/);
  w.close();
});

test("cancelling the confirmation changes nothing", async () => {
  const w = load([["a", "Alpha"]]);
  const {calls} = setup(w);
  w.answer = false;
  picks(w)[0].click();
  button(w, "Block").click();
  await flush();
  assert.deepEqual(calls, []);
  assert.equal(w.document.querySelector(".mv-bulk__report").hidden, true);
  w.close();
});

test("an action can ask for details first, and without undo the report is the record", async () => {
  const w = load([["a", "Alpha"], ["b", "Beta"]]);
  const seen = [];
  w.mvBulk({
    list: w.document.getElementById("list"), rows: "tr[data-bulk-id]", noun: "request", nouns: "requests",
    actions: [{label: "Send back", verb: "Send back", ask: async items => ({note: "fix " + items.length}),
      run: async (item, extra) => { seen.push(item.id + ":" + extra.note); return {}; }}]
  });
  bar(w).querySelector(".mv-bulk__all input").click();
  button(w, "Send back").click();
  await flush();
  assert.deepEqual(seen, ["a:fix 2", "b:fix 2"]);
  const report = w.document.querySelector(".mv-bulk__report");
  assert.match(report.textContent, /Send back: 2 done/);
  assert.equal([...report.querySelectorAll("button")].some(b => /Undo/.test(b.textContent)), false);
  w.close();
});

test("refresh picks up rows the page rendered again", () => {
  const w = load([["a", "Alpha"]]);
  const {bulk} = setup(w);
  const list = w.document.getElementById("list");
  list.insertAdjacentHTML("beforeend", '<tr data-bulk-id="b" data-bulk-label="Beta"><td>Beta</td><td></td></tr>');
  bulk.refresh();
  assert.equal(picks(w).length, 2);
  assert.match(bar(w).querySelector(".mv-bulk__all").textContent, /Select all 2 matching/);
  w.close();
});
