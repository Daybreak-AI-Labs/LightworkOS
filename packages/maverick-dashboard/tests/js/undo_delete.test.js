"use strict";
// A way back from deletes (window.mvUndo in lightwork-ui.js): the item leaves
// the page at once, a toast offers Undo (and Ctrl+Z) for at least 5 seconds,
// and the delete is sent only when that time is up or the person leaves.
// Run with: node --test tests/js/undo_delete.test.js
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const {JSDOM} = require("jsdom");
const root = path.resolve(__dirname, "../../maverick_dashboard");
const source = fs.readFileSync(path.join(root, "static/lightwork-ui.js"), "utf8");
const flush = () => new Promise(resolve => setImmediate(resolve));

function load() {
  const dom = new JSDOM(`<div id="mv-toasts"></div><div id="mv-toasts-alert"></div><main id="content">
    <ul id="list"><li id="row">Weekly report <button type="button">Delete</button></li></ul></main>`,
  {url: "https://lightwork.test/automations", runScripts: "outside-only"});
  const w = dom.window;
  w.matchMedia = () => ({matches: false, addEventListener() {}, removeEventListener() {}});
  // A controllable clock for the undo window.
  let now = 0, seq = 0;
  const timers = new Map();
  w.Date.now = () => now;
  w.setTimeout = (fn, ms) => { timers.set(++seq, {fn, at: now + (ms || 0)}); return seq; };
  w.clearTimeout = id => { timers.delete(id); };
  w.advance = ms => {
    now += ms;
    for (const [id, t] of [...timers].sort((a, b) => a[1].at - b[1].at)) {
      if (t.at <= now && timers.has(id)) { timers.delete(id); t.fn(); }
    }
  };
  w.eval(source);
  return w;
}
function deleteRow(w, calls, extra) {
  const row = w.document.getElementById("row");
  row.hidden = true;
  return w.mvUndo('Schedule “Weekly report” deleted.', Object.assign({
    action: "delete the schedule",
    run: async keepalive => { calls.push(keepalive); return {ok: true}; },
    undo: () => { row.hidden = false; }
  }, extra || {}));
}
const toast = w => w.document.querySelector(".mv-toast--undo");

test("Undo puts the item back and the delete is never sent", async () => {
  const w = load(), calls = [];
  deleteRow(w, calls);
  assert.match(toast(w).textContent, /Schedule “Weekly report” deleted\. Undo/);
  assert.equal(toast(w).parentElement.id, "mv-toasts", "announced politely");
  w.advance(4999);
  assert.ok(toast(w), "the toast stays for at least 5 seconds");
  toast(w).querySelector("button").click();
  await flush();
  assert.equal(w.document.getElementById("row").hidden, false);
  assert.equal(toast(w), null);
  w.advance(60000); await flush();
  assert.deepEqual(calls, []);
  assert.match(w.document.getElementById("mv-toasts").textContent, /Restored\./);
  w.close();
});

test("Ctrl+Z undoes, but not while typing in a field", async () => {
  const w = load(), calls = [];
  const input = w.document.createElement("input"); w.document.body.appendChild(input);
  deleteRow(w, calls);
  input.dispatchEvent(new w.KeyboardEvent("keydown", {key: "z", ctrlKey: true, bubbles: true}));
  assert.ok(toast(w), "Ctrl+Z in a text field is the field's own undo");
  w.document.body.dispatchEvent(new w.KeyboardEvent("keydown", {key: "z", ctrlKey: true, bubbles: true}));
  assert.equal(toast(w), null);
  assert.equal(w.document.getElementById("row").hidden, false);
  w.advance(60000); await flush();
  assert.deepEqual(calls, []);
  w.close();
});

test("the delete is sent when the window ends, and is held while the toast has focus", async () => {
  const w = load(), calls = [];
  let finished = 0;
  deleteRow(w, calls, {done: () => { finished += 1; }});
  w.advance(3000);
  toast(w).querySelector("button").dispatchEvent(new w.FocusEvent("focusin", {bubbles: true}));
  w.advance(30000); await flush();
  assert.deepEqual(calls, [], "time stops while the person is on the toast");
  toast(w).dispatchEvent(new w.FocusEvent("focusout", {bubbles: true}));
  w.advance(6999); await flush();
  assert.deepEqual(calls, []);
  w.advance(1); await flush();
  assert.deepEqual(calls, [false]);
  assert.equal(finished, 1);
  assert.equal(toast(w), null);
  w.close();
});

test("leaving the page sends the delete with keepalive, and a 'latest' time is never passed", async () => {
  const w = load(), calls = [];
  deleteRow(w, calls);
  w.dispatchEvent(new w.Event("pagehide"));
  await flush();
  assert.deepEqual(calls, [true]);
  const late = [];
  deleteRow(w, late, {latest: 2000});
  toast(w).dispatchEvent(new w.Event("mouseenter"));
  w.advance(2000); await flush();
  assert.deepEqual(late, [false], "a schedule's next run is not reached while the toast is paused");
  w.close();
});

test("a failed delete puts the item back and says so; a second delete sends the first", async () => {
  const w = load();
  const row = w.document.getElementById("row");
  row.hidden = true;
  w.mvUndo("Deleted.", {action: "delete the schedule", run: async () => ({ok: false, status: 503}), undo: () => { row.hidden = false; }});
  w.advance(10000); await flush(); await flush();
  assert.equal(row.hidden, false);
  assert.match(w.document.getElementById("mv-toasts-alert").textContent, /Could not delete the schedule\. This is temporarily unavailable/);
  const first = [], second = [];
  deleteRow(w, first);
  deleteRow(w, second);
  await flush();
  assert.deepEqual(first, [false]);
  assert.deepEqual(second, []);
  assert.equal(w.document.querySelectorAll(".mv-toast--undo").length, 1);
  w.close();
});

test("the most common deletes use the undo window instead of a question", () => {
  const automations = fs.readFileSync(path.join(root, "templates/automations.html"), "utf8");
  for (const fn of ["async function delSchedule(id)", "function delTrigger(name)", "async function delEventTrigger(name)"]) {
    const body = automations.slice(automations.indexOf(fn), automations.indexOf("\n  }", automations.indexOf(fn)) + 4);
    assert.match(body, /deleteWithUndo\(/, fn);
  }
  assert.match(automations, /mvUndo\(message, \{[\s\S]*?keepalive: keepalive/);
  // Skills: the Remove button opens the reviewed removal (exact saved
  // version, retained receipt; lightwork-manual-skill-removal.js). Its last
  // step hides the card and offers Undo; the reviewed removal is sent when
  // that time is up, and an undone removal sends nothing.
  const skills = fs.readFileSync(path.join(root, "templates/skills.html"), "utf8");
  assert.match(skills, /LightworkManualSkillRemoval\.review\(name\)/);
  assert.doesNotMatch(skills, /mvConfirm\('Remove the skill/);
  const removal = fs.readFileSync(path.join(root, "static/lightwork-manual-skill-removal.js"), "utf8");
  assert.match(removal, /window\.mvUndo\('Skill “\{name\}” removed\. Agents stop using it from the next task\.'/);
  assert.match(removal, /run: async function \(keepalive\)[\s\S]*?\/remove'[\s\S]*?keepalive: keepalive[\s\S]*?token: checked\.token/);
  assert.match(removal, /undo: function \(\)[\s\S]*?card\.hidden = false/);
});

test("the toast's words go through the translator, and the name stays as written", async () => {
  const dom = new JSDOM(`<script type="application/json" id="lightwork-i18n-data">${JSON.stringify({language: "fr", locale: "fr", catalog: {
      'Team "{name}" removed. Past tasks stay in your task list.': {text: "Équipe « {name} » retirée. Les tâches passées restent dans votre liste.", lang: "fr"},
      "Undo": {text: "Annuler", lang: "fr"}, "Restored.": {text: "Rétabli.", lang: "fr"}}})}</script>
    <div id="mv-toasts"></div><div id="mv-toasts-alert"></div>`, {url: "https://lightwork.test/fleets", runScripts: "outside-only"});
  const w = dom.window;
  w.matchMedia = () => ({matches: false, addEventListener() {}, removeEventListener() {}});
  w.eval(fs.readFileSync(path.join(root, "static/lightwork-i18n.js"), "utf8"));
  w.eval(source);
  w.mvUndo('Team "{name}" removed. Past tasks stay in your task list.', {values: {name: "<b>Ops</b>"}, run: async () => ({ok: true})});
  const shown = w.document.querySelector(".mv-toast--undo");
  assert.match(shown.textContent, /^Équipe « <b>Ops<\/b> » retirée\. Les tâches passées restent dans votre liste\. Annuler$/);
  assert.equal(shown.querySelector("bdi[data-user-content]").textContent, "<b>Ops</b>", "the name is text, never markup");
  shown.querySelector("button").click();
  await flush();
  assert.match(w.document.getElementById("mv-toasts").textContent, /Rétabli\./);
  w.close();
});

test("a refusal the page already explained puts the item back without a second message", async () => {
  const w = load(), calls = [];
  let failed = 0;
  w.mvFail = () => { failed += 1; };
  deleteRow(w, calls, {run: async keepalive => { calls.push(keepalive); throw {handled: true}; }});
  w.advance(10000); await flush(); await flush();
  assert.deepEqual(calls, [false]);
  assert.equal(w.document.getElementById("row").hidden, false, "the item comes back");
  assert.equal(failed, 0, "no generic failure on top of the page's own explanation");
  deleteRow(w, calls, {run: async () => { throw new Error("offline"); }});
  w.advance(10000); await flush(); await flush();
  assert.equal(failed, 1, "an unexplained failure still shows the shared message");
  w.close();
});
