// Run with: node --test packages/maverick-dashboard/tests/js/sidebar_areas_open.test.js
"use strict";
// Areas navigation: an area the role's preset opens starts open, the area
// holding the current page is always open, and a person's own choice to close
// an area is remembered over the preset. Classic groups behave as before.
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const {JSDOM} = require("jsdom");

const source = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-ui.js"), "utf8");
const start = source.indexOf("    // Collapsible sidebar groups.");
const end = source.indexOf("    // Approvals badge:", start);
const snippet = source.slice(start, end);

function area(name, open, active) {
  return `<li class="navarea"><a href="/${name}"${active ? ' class="active"' : ""}>${name}</a>` +
    `<button class="navgrp__toggle" data-grp="area:${name}" data-grp-open="${open}" aria-expanded="true"></button>` +
    `<ul class="navgrp__items"><li><a href="/${name}/x">x</a></li></ul></li>`;
}

function render(stored) {
  const dom = new JSDOM(`<ul>${area("Work", "true", false)}${area("Privacy", "false", false)}` +
    `${area("Settings", "false", true)}</ul><div class="navgrp"><button class="navgrp__toggle" data-grp="Govern" aria-expanded="true"></button>` +
    `<ul class="navgrp__items"></ul></div>`, {url: "https://lightwork.test/settings", runScripts: "outside-only"});
  if (stored !== undefined) dom.window.localStorage.setItem("mvk_nav_expanded", JSON.stringify(stored));
  dom.window.eval(snippet);
  const state = name => dom.window.document.querySelector(`[data-grp="${name}"]`).getAttribute("aria-expanded");
  return {state, dom};
}

test("the snippet under test is the sidebar group controller", () => {
  assert.ok(start > -1 && end > start);
  assert.match(snippet, /data-grp-open/);
});

test("preset-open areas and the current area start open; others start closed", () => {
  const {state} = render();
  assert.equal(state("area:Work"), "true");
  assert.equal(state("area:Privacy"), "false");
  assert.equal(state("area:Settings"), "true");
  assert.equal(state("Govern"), "false");
});

test("a person's choice to close a preset-open area wins", () => {
  const {state, dom} = render({"area:Work": false});
  assert.equal(state("area:Work"), "false");
  dom.window.document.querySelector('[data-grp="area:Privacy"]').click();
  assert.equal(state("area:Privacy"), "true");
  assert.equal(JSON.parse(dom.window.localStorage.getItem("mvk_nav_expanded"))["area:Privacy"], true);
});
