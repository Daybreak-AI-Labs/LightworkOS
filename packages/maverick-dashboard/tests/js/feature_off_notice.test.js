// Run with: node --test packages/maverick-dashboard/tests/js/feature_off_notice.test.js
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const source = fs.readFileSync(
  path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-ui.js"), "utf8");

const TOP_GATE = `<div class="mg-banner" id="top-gate" data-module-gate="privacy_automation.public_rights_form">
  <strong>Rights request form is turned off.</strong><span class="mg-err" role="alert"></span></div>`;

function load({ admin = false, fetchImpl } = {}) {
  const dom = new JSDOM(`<!doctype html><body data-global-admin="${admin ? 1 : 0}">
    <div id="mv-toasts"></div><div id="mv-toasts-alert"></div>${TOP_GATE}
    <p id="msg" role="status"></p></body>`, { url: "https://lightwork.test/", runScripts: "outside-only" });
  dom.window.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
  if (fetchImpl) dom.window.fetch = fetchImpl;
  dom.window.eval(source);
  return dom.window;
}

function turnedOff(extra = {}) {
  return {
    status: 403,
    headers: new Headers({
      "X-Lightwork-Reason": "feature-off",
      "X-Lightwork-Feature": "privacy_automation.public_rights_form",
      "X-Lightwork-Feature-Label": "Rights request form",
      "X-Lightwork-Feature-Switch": "module",
      ...extra,
    }),
  };
}

test("a feature that is turned off is never reported as a missing permission", () => {
  const viewer = load();
  assert.equal(viewer.mvErrorText(turnedOff(), "save the property"),
    "Could not save the property. Rights request form is turned off. Ask an administrator to turn on rights request form.");
  const admin = load({ admin: true });
  assert.equal(admin.mvErrorText(turnedOff(), "save the property"),
    "Could not save the property. Rights request form is turned off. You can turn it on in Settings.");
  // A real permission refusal still says so.
  assert.match(viewer.mvErrorText({ status: 403 }, "save the property"), /do not have permission/);
  assert.match(viewer.mvErrorText({ status: 403, headers: new Headers() }, "save it"), /do not have permission/);
});

test("the reason is read from plain header objects and unnamed features", () => {
  const w = load();
  assert.equal(w.mvErrorText({ status: 403, headers: { "x-lightwork-reason": "feature-off" } }),
    "This feature is turned off. Ask an administrator to turn it on.");
});

test("the in-place notice offers Turn on, keeps the page and retires stale notices", async () => {
  const calls = [];
  const w = load({ admin: true, fetchImpl: (url, init) => {
    calls.push([url, JSON.parse(init.body)]);
    return Promise.resolve({ ok: true, status: 200 });
  } });
  const d = w.document;
  assert.equal(w.mvShowFeatureOff(d.getElementById("msg"), turnedOff(), "save the property"), true);
  const gate = d.querySelector("#msg .mg-banner");
  assert.match(gate.textContent, /Could not save the property\. Rights request form is turned off\./);
  const button = gate.querySelector(".mg-on");
  assert.equal(button.textContent, "Turn on rights request form");
  assert.match(gate.querySelector(".mg-nonadmin-note").textContent, /Ask an administrator to turn on rights request form/);
  button.click();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.deepEqual(calls, [["/api/v1/features/modules",
    { section: "privacy_automation.public_rights_form", enabled: true }]]);
  assert.equal(d.querySelector("#msg").textContent, "Rights request form is on now. Try again.");
  assert.equal(d.getElementById("top-gate").hidden, true);
});

test("a feature that cannot be switched on in the app says who can", () => {
  const w = load();
  const msg = w.document.getElementById("msg");
  const failure = turnedOff({ "X-Lightwork-Feature": "privacy_ops", "X-Lightwork-Feature-Label": "The privacy register" });
  failure.headers.delete("X-Lightwork-Feature-Switch");
  assert.equal(w.mvShowFeatureOff(msg, failure, "save"), true);
  assert.equal(msg.querySelector(".mg-on"), null);
  assert.equal(msg.textContent, "Could not save. The privacy register is turned off. Ask an administrator to turn on the privacy register.");
  assert.equal(w.mvShowFeatureOff(msg, { status: 403 }, "save"), false);
});
