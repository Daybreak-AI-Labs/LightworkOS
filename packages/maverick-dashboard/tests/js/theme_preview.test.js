"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const script = fs.readFileSync(path.resolve(__dirname,
  "../../maverick_dashboard/static/lightwork-theme-preview.js"), "utf8");

function preview(extra = "") {
  const dom = new JSDOM(`<section data-setting-id="dashboard.themes"><div data-grid-row>
    ${Object.entries({bg:"#fff",panel:"#fff",text:"#111",accent:"#111"}).map(([key, value]) =>
      `<label data-cell="${key}"><input data-cell-input value="${value}"></label>`).join("")}
    ${extra}</div></section>`, { runScripts: "outside-only" });
  dom.window.eval(script);
  dom.window.document.querySelector("input").dispatchEvent(new dom.window.Event("input", { bubbles: true }));
  return dom;
}

test("omitted semantic colors preview the same derived text colors as runtime", () => {
  const dom = preview(), doc = dom.window.document;
  const panel = doc.querySelector("[data-theme-preview]");
  assert.match(panel.querySelector('[role="status"]').textContent, /meet the checked contrast thresholds/);
  assert.match(panel.textContent, /Omitted optional colours use this theme's text colour/);
  const badges = Array.from(panel.querySelectorAll("p")).filter(node => /^(Warning:|Error:)/.test(node.textContent));
  assert.equal(badges.length, 2);
  assert.ok(badges.every(node => node.style.color === "rgb(17, 17, 17)"));
  assert.equal(panel.querySelector("input").style.borderColor, "rgb(17, 17, 17)");
  assert.equal(doc.body.getAttribute("style"), null);
});

test("explicit low-contrast status colors remain rejected", () => {
  const dom = preview('<label data-cell="warn"><input data-cell-input value="#fff"><input type="checkbox" data-cell-use checked></label>');
  assert.match(dom.window.document.querySelector('[role="status"]').textContent, /warn on bg: 1.00:1/);
});

test("disabled optional color overrides use the same safe omitted default", () => {
  const dom = preview('<label data-cell="warn"><input data-cell-input value="#fff"><input type="checkbox" data-cell-use></label>');
  assert.match(dom.window.document.querySelector('[role="status"]').textContent, /meet the checked contrast thresholds/);
});
