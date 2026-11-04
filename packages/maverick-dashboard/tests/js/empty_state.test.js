// Run with: node --test packages/maverick-dashboard/tests/js/empty_state.test.js
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const source = fs.readFileSync(
  path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-ui.js"), "utf8");

function load() {
  const dom = new JSDOM('<div id="mv-toasts"></div><div id="mv-toasts-alert"></div><main id="content"></main>',
    { url: "https://lightwork.test/", runScripts: "outside-only" });
  dom.window.matchMedia = () => ({matches:false, addEventListener() {}, removeEventListener() {}});
  dom.window.eval(source);
  return dom.window;
}

test("script-rendered empty states match the server macro and link one next step", () => {
  const w = load();
  const box = w.mvEmpty("No results yet", "Finished tasks appear here. Start a task to get the first one.",
    { label: "Start a task", href: "/chat" });
  assert.equal(box.className, "mv-empty");
  assert.equal(box.children.length, 3);
  assert.equal(box.querySelector(".mv-empty__title").textContent, "No results yet");
  assert.equal(box.querySelector(".mv-empty__title").tagName, "P");
  assert.match(box.querySelector(".mv-empty__body").textContent, /^Finished tasks appear here\./);
  const action = box.querySelector("a.btn.mv-empty__action");
  assert.equal(action.getAttribute("href"), "/chat");
  assert.equal(action.textContent, "Start a task");
  assert.equal(box.querySelector(".btn--primary"), null);
  w.close();
});

test("a script next step can be a button, and text never becomes markup", () => {
  const w = load();
  let clicked = 0;
  const probe = '<img src=x onerror="window.pwned=1">';
  const box = w.mvEmpty(probe, probe, { label: probe, onClick: () => { clicked += 1; } }, { compact: true });
  w.document.getElementById("content").appendChild(box);
  assert.equal(box.className, "mv-empty mv-empty--compact");
  assert.equal(box.querySelector("img"), null);
  assert.equal(box.querySelector(".mv-empty__title").textContent, probe);
  const button = box.querySelector("button.btn.mv-empty__action");
  assert.equal(button.type, "button");
  button.click();
  assert.equal(clicked, 1);
  assert.equal(w.pwned, undefined);
  w.close();
});

test("no body and no usable action leave just the title", () => {
  const w = load();
  const box = w.mvEmpty("Nothing matches these filters", "", { label: "Clear filters" });
  assert.equal(box.children.length, 1);
  assert.equal(w.mvEmpty("No licences yet").children.length, 1);
  w.close();
});
