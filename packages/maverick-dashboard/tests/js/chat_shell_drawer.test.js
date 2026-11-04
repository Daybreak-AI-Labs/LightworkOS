// Run with: node --test packages/maverick-dashboard/tests/js/chat_shell_drawer.test.js
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const shell = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates/chat_base.html"), "utf8");
const start = shell.indexOf("    // Small screens: the Menu button opens the sidebar as a drawer.");
const end = shell.indexOf("    // Filter the recents list as you type.");
const drawer = shell.slice(start, end);

function open(options = {}) {
  const dom = new JSDOM(`<body class="chat-shell">
    <aside class="cs-side" id="cs-side"><button id="cs-menu-close">Close menu</button><a href="/chat">New chat</a>
      <details><summary>Library</summary><a href="/hidden-page">Hidden page</a></details>
      <button id="navfinder-open">Find a page</button></aside>
    <div id="cs-backdrop"></div>
    <main${options.inert ? ' inert' : ''}><button id="cs-menu" aria-expanded="false">Menu</button><button id="background-action">Send</button></main></body>`, { runScripts: "outside-only" });
  let onChange;
  const query = {
    matches: true,
    addEventListener: (_event, callback) => { onChange = callback; },
  };
  dom.window.matchMedia = () => query;
  dom.window.eval(drawer);
  dom.resizeDrawer = (mobile = false) => {
    // Give the exact matchMedia object owned by the drawer its updated state.
    query.matches = mobile;
    onChange();
  };
  dom.resizeDesktop = () => dom.resizeDrawer(false);
  return dom;
}

test("the menu button opens the chat sidebar as a drawer and moves focus into it", () => {
  assert.ok(start > 0 && end > start);
  const dom = open(), doc = dom.window.document;
  doc.getElementById("cs-menu").click();
  assert.ok(doc.body.classList.contains("cs-drawer-open"));
  assert.equal(doc.getElementById("cs-menu").getAttribute("aria-expanded"), "true");
  assert.equal(doc.activeElement.id, "cs-menu-close");
});

test("Escape, the close button and the backdrop close it and return focus to Menu", () => {
  const dom = open(), doc = dom.window.document;
  for (const close of [
    () => doc.dispatchEvent(new dom.window.KeyboardEvent("keydown", { key: "Escape" })),
    () => doc.getElementById("cs-menu-close").click(),
    () => doc.getElementById("cs-backdrop").click(),
  ]) {
    doc.getElementById("cs-menu").click();
    close();
    assert.equal(doc.body.classList.contains("cs-drawer-open"), false);
    assert.equal(doc.getElementById("cs-menu").getAttribute("aria-expanded"), "false");
    assert.equal(doc.activeElement.id, "cs-menu");
  }
});

test("the drawer styles only apply on small screens and the shell carries the form dialog", () => {
  assert.match(shell, /@media \(max-width: 860px\)[\s\S]*body\.cs-drawer-open \.cs-side/);
  assert.ok(shell.includes('<dialog id="mv-form"'));
  assert.ok(!/\.cs-side \{ display: none; \}/.test(shell));
  assert.ok(shell.indexOf('.cs-side__close { display: none;') < shell.indexOf('@media (max-width: 860px)'));
});

test("the drawer keeps keyboard focus in visible navigation and restores the background", () => {
  const dom = open(), doc = dom.window.document;
  const side = doc.getElementById('cs-side'), main = doc.querySelector('main');
  assert.ok(side.hasAttribute('inert'));
  assert.equal(side.getAttribute('aria-hidden'), 'true');
  doc.getElementById('cs-menu').click();
  assert.equal(side.hasAttribute('inert'), false);
  assert.equal(side.hasAttribute('aria-hidden'), false);
  assert.ok(main.hasAttribute('inert'));
  doc.getElementById('navfinder-open').focus();
  const forward = new dom.window.KeyboardEvent('keydown', {key: 'Tab', cancelable: true});
  doc.dispatchEvent(forward);
  assert.ok(forward.defaultPrevented);
  assert.equal(doc.activeElement.id, 'cs-menu-close');
  const backward = new dom.window.KeyboardEvent('keydown', {key: 'Tab', shiftKey: true, cancelable: true});
  doc.dispatchEvent(backward);
  assert.ok(backward.defaultPrevented);
  assert.equal(doc.activeElement.id, 'navfinder-open');
  doc.getElementById('cs-menu-close').click();
  assert.equal(main.hasAttribute('inert'), false);
  assert.ok(side.hasAttribute('inert'));
  assert.equal(doc.activeElement.id, 'cs-menu');
  dom.window.close();
});

test("resizing to desktop clears drawer state without removing preexisting access restrictions", () => {
  const dom = open({inert: true}), doc = dom.window.document;
  doc.getElementById('cs-menu').click();
  dom.resizeDrawer();
  assert.equal(doc.body.classList.contains('cs-drawer-open'), false);
  assert.equal(doc.getElementById('cs-side').hasAttribute('inert'), false);
  assert.equal(doc.querySelector('main').hasAttribute('inert'), true);
  assert.equal(doc.getElementById('cs-menu').getAttribute('aria-expanded'), 'false');
  dom.window.close();
});

test("resizing to a closed mobile drawer moves focus out of hidden navigation", () => {
  const dom = open(), doc = dom.window.document;
  dom.resizeDrawer(false);
  doc.querySelector('a[href="/chat"]').focus();
  dom.resizeDrawer(true);
  assert.equal(doc.activeElement.id, 'cs-menu');
  assert.equal(doc.getElementById('cs-side').getAttribute('aria-hidden'), 'true');
  dom.window.close();
});

test("desktop resize transfers focus from the hidden close control to visible navigation", () => {
  const dom = open(), doc = dom.window.document;
  doc.querySelector('#cs-side a').getClientRects = () => [{}];
  doc.getElementById('cs-menu').click();
  assert.equal(doc.activeElement.id, 'cs-menu-close');
  dom.resizeDesktop();
  assert.equal(doc.body.classList.contains('cs-drawer-open'), false);
  assert.equal(doc.activeElement, doc.querySelector('#cs-side a'));
  assert.equal(doc.querySelector('main').hasAttribute('inert'), false);
  assert.equal(Boolean(doc.querySelector('main').inert), false);
  dom.window.close();
});

test("desktop resize preserves a navigation or handed-off dialog focus target", () => {
  const dom = open(), doc = dom.window.document;
  const link = doc.querySelector('#cs-side a');
  link.getClientRects = () => [{}];
  doc.getElementById('cs-menu').click(); link.focus(); dom.resizeDesktop();
  assert.equal(doc.activeElement, link);
  dom.window.close();
});

test("desktop resize restores visible focus when layout blurs Close before the media event", () => {
  const dom = open(), doc = dom.window.document;
  const link = doc.querySelector('#cs-side a');
  link.getClientRects = () => [{}];
  doc.getElementById('cs-menu').click();
  doc.getElementById('cs-menu-close').blur();
  assert.equal(doc.activeElement, doc.body);
  dom.resizeDesktop();
  assert.equal(doc.activeElement, link);
  assert.equal(doc.body.classList.contains('cs-drawer-open'), false);
  dom.window.close();
});
