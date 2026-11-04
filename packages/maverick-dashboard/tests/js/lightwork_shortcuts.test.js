// Run with: node --test packages/maverick-dashboard/tests/js/lightwork_shortcuts.test.js
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const SCRIPT = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-shortcuts.js"), "utf8");

// The dialog as _shortcuts.html renders it for someone who may open Tasks and
// Results but not Approvals or Settings.
const ENTRIES = `
  <div data-shortcut="mod+k" data-shortcut-run="finder"><dt><kbd data-shortcut-mod>Ctrl</kbd> <kbd>K</kbd></dt><dd>Search or run a command</dd></div>
  <div data-shortcut="/" data-shortcut-run="finder"><dt><kbd>/</kbd></dt><dd>Search</dd></div>
  <div data-shortcut="?" data-shortcut-run="shortcuts"><dt><kbd>?</kbd></dt><dd>Show help and shortcuts</dd></div>
  <div data-shortcut="g h" data-shortcut-href="/"><dt>G then H</dt><dd>Go to Home</dd></div>
  <div data-shortcut="g t" data-shortcut-href="/goals"><dt>G then T</dt><dd>Go to Tasks</dd></div>
  <div data-shortcut="g r" data-shortcut-href="/deliverables"><dt>G then R</dt><dd>Go to Results</dd></div>`;

function page() {
  const dom = new JSDOM(`<!doctype html><body>
    <button id="shortcuts-open" aria-expanded="false">Help and shortcuts</button>
    <input id="field"><textarea id="notes"></textarea><select id="choice"><option>a</option></select>
    <div id="editor" contenteditable="true"><p id="inside">text</p></div>
    <div id="readonly" contenteditable="false">fixed</div>
    <a id="link" href="/somewhere">A link</a>
    <dialog id="navfinder-dialog"></dialog>
    <dialog id="shortcuts-dialog"><button id="shortcuts-close">Close</button><button id="shortcuts-finder">Search</button>
      <dl data-shortcut-list>${ENTRIES}</dl>
      <dl data-shortcut-scope="finder"><div data-finder-prefix="&gt;"><dt>&gt;</dt><dd>Commands</dd></div></dl></dialog>
  </body>`, { runScripts: "outside-only", url: "https://lightwork.test/overview" });
  const visits = [];
  const opened = [];
  dom.window.document.getElementById("navfinder-dialog").lightworkFinder = { open(opener) { opened.push(opener); } };
  // Navigation is observed, not performed.
  dom.window.eval(SCRIPT.replace("global.location.assign(href)", "global.__visit(href)"));
  dom.window.__visit = (href) => visits.push(href);
  // The parser may still report "loading"; initialise as DOMContentLoaded would.
  const shortcuts = dom.window.LightworkShortcutsInit(dom.window.document) || dom.window.LightworkShortcuts;
  return { dom, doc: dom.window.document, shortcuts, visits, opened };
}

function press(ui, key, target, extra = {}) {
  const node = target ? ui.doc.getElementById(target) : ui.doc.body;
  const event = new ui.dom.window.KeyboardEvent("keydown", Object.assign({ key, bubbles: true, cancelable: true }, extra));
  node.dispatchEvent(event);
  return event;
}

function dialogOpen(ui) { return ui.doc.getElementById("shortcuts-dialog").hasAttribute("open"); }

test("? opens the dialog and ? closes it again, returning focus", () => {
  const ui = page();
  ui.doc.getElementById("link").focus();
  const event = press(ui, "?", "link", { shiftKey: true });
  assert.equal(event.defaultPrevented, true);
  assert.equal(dialogOpen(ui), true);
  assert.equal(ui.doc.activeElement.id, "shortcuts-close");
  assert.equal(ui.doc.getElementById("shortcuts-open").getAttribute("aria-expanded"), "true");
  press(ui, "?", "shortcuts-close", { shiftKey: true });
  assert.equal(dialogOpen(ui), false);
  assert.equal(ui.doc.activeElement.id, "link");
  ui.dom.window.close();
});

test("the sidebar Help entry and the close button open and close the same dialog", () => {
  const ui = page();
  ui.doc.getElementById("shortcuts-open").click();
  assert.equal(dialogOpen(ui), true);
  ui.doc.getElementById("shortcuts-close").click();
  assert.equal(dialogOpen(ui), false);
  assert.equal(ui.doc.getElementById("shortcuts-open").getAttribute("aria-expanded"), "false");
  ui.dom.window.close();
});

test("shortcuts never fire while typing in a field", () => {
  const ui = page();
  for (const target of ["field", "notes", "choice", "editor", "inside"]) {
    for (const key of ["?", "/", "g", "t"]) {
      const event = press(ui, key, target, { shiftKey: key === "?" });
      assert.equal(event.defaultPrevented, false, `${key} in ${target}`);
    }
  }
  assert.equal(dialogOpen(ui), false);
  assert.deepEqual(ui.visits, []);
  assert.deepEqual(ui.opened, []);
  // contenteditable="false" is not an editing context.
  press(ui, "?", "readonly", { shiftKey: true });
  assert.equal(dialogOpen(ui), true);
  ui.dom.window.close();
});

test("the dialog lists exactly the shortcuts that are bound", () => {
  const ui = page();
  const listed = [...ui.doc.querySelectorAll("[data-shortcut]")].map((node) => node.getAttribute("data-shortcut"));
  assert.deepEqual([...ui.shortcuts.shortcuts()], listed);
  // Every listed go-to entry works ...
  for (const node of ui.doc.querySelectorAll("[data-shortcut-href]")) {
    const [first, second] = node.getAttribute("data-shortcut").split(" ");
    press(ui, first);
    press(ui, second);
  }
  assert.deepEqual(ui.visits, ["/", "/goals", "/deliverables"]);
  // ... and nothing unlisted does: this person may not open Approvals or Settings.
  for (const second of ["a", "s", "x"]) {
    press(ui, "g");
    const event = press(ui, second);
    assert.equal(event.defaultPrevented, false, second);
  }
  assert.deepEqual(ui.visits, ["/", "/goals", "/deliverables"]);
  ui.dom.window.close();
});

test("/ opens the command menu and Ctrl or Cmd+K is listed for it", () => {
  const ui = page();
  ui.doc.getElementById("link").focus();
  const event = press(ui, "/", "link");
  assert.equal(event.defaultPrevented, true);
  assert.equal(ui.opened.length, 1);
  assert.equal(ui.opened[0].id, "link");
  const modK = press(ui, "k", null, { ctrlKey: true });
  assert.equal(modK.defaultPrevented, true);
  assert.equal(ui.opened.length, 2);
  // The command menu's own handler may take Ctrl+K first; then this one stands back.
  const handled = new ui.dom.window.KeyboardEvent("keydown", { key: "k", metaKey: true, bubbles: true, cancelable: true });
  handled.preventDefault();
  ui.doc.body.dispatchEvent(handled);
  assert.equal(ui.opened.length, 2);
  ui.dom.window.close();
});

test("a go-to sequence ignores Shift, modifier chords and expires", () => {
  const ui = page();
  press(ui, "g");
  press(ui, "Shift", null, { shiftKey: true });
  press(ui, "T", null, { shiftKey: true });
  assert.deepEqual(ui.visits, ["/goals"]);
  press(ui, "g", null, { ctrlKey: true });
  press(ui, "t");
  assert.deepEqual(ui.visits, ["/goals"]);
  // A second key after the time limit starts nothing.
  const timers = [];
  ui.dom.window.setTimeout = (callback) => { timers.push(callback); return timers.length; };
  ui.dom.window.clearTimeout = () => {};
  press(ui, "g");
  timers.forEach((callback) => callback());
  press(ui, "t");
  assert.deepEqual(ui.visits, ["/goals"]);
  ui.dom.window.close();
});

test("another open modal, such as a confirmation, keeps the keyboard", () => {
  const ui = page();
  const confirm = ui.doc.createElement("dialog");
  ui.doc.body.appendChild(confirm);
  const original = ui.doc.querySelectorAll.bind(ui.doc);
  ui.doc.querySelectorAll = (selector) => (selector === "dialog:modal" ? [confirm] : original(selector));
  press(ui, "?", null, { shiftKey: true });
  press(ui, "g");
  press(ui, "t");
  assert.equal(dialogOpen(ui), false);
  assert.deepEqual(ui.visits, []);
  ui.dom.window.close();
});

test("the dialog's search button hands over to the command menu", () => {
  const ui = page();
  ui.doc.getElementById("link").focus();
  press(ui, "?", "link", { shiftKey: true });
  ui.doc.getElementById("shortcuts-finder").click();
  assert.equal(dialogOpen(ui), false);
  assert.equal(ui.opened.length, 1);
  // The menu returns focus to where help was opened from, not the dialog.
  assert.equal(ui.opened[0].id, "link");
  ui.dom.window.close();
});
