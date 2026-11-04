// Run with: node --test packages/maverick-dashboard/tests/js/module_gate_controls.test.js
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const source = fs.readFileSync(
  path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-ui.js"), "utf8");

// The shape of Consent and preferences and Find Personal Data while their feature
// is off: the whole workbench root is marked off and the module gate sits inside it.
const MARKUP = `
<div id="toasts"></div>
<div id="cp-root" data-feature-enabled="false">
  <div class="mg-banner" role="status" data-module-gate="consent_preferences">
    <strong>Consent preferences is turned off.</strong>
    <span class="mg-actions mg-admin-only"><button type="button" class="btn btn--primary mg-on">Turn on consent preferences</button></span>
    <span class="mg-err" role="alert"></span>
  </div>
  <button type="button" id="cp-policy-new">New policy</button>
  <fieldset id="cp-policy-controls"><input id="cp-policy-name"><select id="cp-kind"></select><textarea id="cp-note"></textarea></fieldset>
  <section id="cp-posture">
    <div class="mg-banner" data-module-gate="consent_registry">
      <button type="button" class="btn btn--primary mg-on" id="registry-on">Turn on consent register</button>
      <span class="mg-err" role="alert"></span>
    </div>
  </section>
</div>
<div id="open-root" data-feature-enabled="true"><button type="button" id="open-btn">Save</button></div>`;

function load(fetchImpl) {
  const dom = new JSDOM(MARKUP, { url: "https://lightwork.test/", runScripts: "outside-only" });
  if (fetchImpl) dom.window.fetch = fetchImpl;
  dom.window.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
  dom.window.eval(source);
  return dom.window;
}

test("a switched-off workbench disables its own controls but never its Turn on button", () => {
  const w = load();
  const d = w.document;
  for (const id of ["cp-policy-new", "cp-policy-name", "cp-kind", "cp-note"]) {
    assert.equal(d.getElementById(id).disabled, true, id);
    assert.match(d.getElementById(id).title, /turned off/, id);
  }
  for (const button of d.querySelectorAll(".mg-on")) {
    assert.equal(button.disabled, false, button.textContent);
    assert.equal(button.hasAttribute("title"), false, button.textContent);
  }
  // aria-disabled on an ancestor reads as disabling everything inside it (to
  // screen readers and to browser automation), so no ancestor of a gate carries it.
  for (const button of d.querySelectorAll(".mg-on")) {
    for (let el = button; el; el = el.parentElement) {
      assert.equal(el.hasAttribute("aria-disabled"), false, el.id || el.className || el.tagName);
    }
  }
  // Containers that hold only the workbench controls still say they are off.
  assert.equal(d.getElementById("cp-policy-controls").getAttribute("aria-disabled"), "true");
  // Pages whose feature is on are untouched.
  assert.equal(d.getElementById("open-btn").disabled, false);
  assert.equal(d.getElementById("open-root").hasAttribute("aria-disabled"), false);
});

test("Turn on inside a switched-off workbench asks the server and reports a refusal in words", async () => {
  const calls = [];
  const w = load((url, init) => {
    calls.push([url, JSON.parse(init.body)]);
    return Promise.resolve({ ok: false, status: 403 });
  });
  const d = w.document;
  d.getElementById("registry-on").click();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.deepEqual(calls, [["/api/v1/features/modules", { section: "consent_registry", enabled: true }]]);
  const message = d.querySelector('[data-module-gate="consent_registry"] .mg-err').textContent;
  assert.match(message, /Only an administrator can turn this on/);
  assert.equal(d.getElementById("registry-on").disabled, false);
});
