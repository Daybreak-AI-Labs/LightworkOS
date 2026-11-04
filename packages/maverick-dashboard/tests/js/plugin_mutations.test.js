// Run with: node --test packages/maverick-dashboard/tests/js/plugin_mutations.test.js
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function client() {
  const window = {};
  const context = { console, window };
  vm.createContext(context);
  const source = fs.readFileSync(
    path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-plugins.js"),
    "utf8",
  );
  vm.runInContext(source, context, { filename: "lightwork-plugins.js" });
  return window.LightworkPluginMutations;
}

class Control {
  constructor(action = "", target = "") {
    this.disabled = false;
    this.attributes = {
      "data-plugin-action": action,
      "data-plugin-target": target,
    };
  }
  getAttribute(name) { return this.attributes[name] || null; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  removeAttribute(name) { delete this.attributes[name]; }
}

function form(names = "") {
  return {
    action: "/plugins/example",
    dataset: {},
    elements: { names: { value: names } },
  };
}

function statusNode() {
  return {
    textContent: "",
    attributes: {},
    setAttribute(name, value) { this.attributes[name] = String(value); },
  };
}

test("every plugin control confirmation names its exact target and impact", () => {
  const api = client();
  const cases = [
    ["enable", "weather", "Turn on “weather”", "start running this plugin"],
    ["disable", "weather", "Turn off “weather”", "stop working"],
    ["reset", "weather", "default for “weather”", "choice made on this page will be removed"],
    ["install", "acme-weather", "Install “acme-weather”", "own setup on this computer"],
    ["install-switch-on", "", "Turn installing on", "any plugin on the approved list"],
    ["install-switch-off", "", "Turn installing off", "No new plugins can be installed"],
  ];
  for (const [action, target, expectedTarget, expectedImpact] of cases) {
    const prompt = api.confirmationFor(form(), new Control(action, target));
    assert.match(prompt, new RegExp(expectedTarget));
    assert.match(prompt, new RegExp(expectedImpact));
    assert.doesNotMatch(prompt, /HTTP|package|plugin-/);
  }
  const labelled = new Control("enable", "acme_weather");
  labelled.attributes["data-plugin-label"] = "Acme weather";
  assert.match(api.confirmationFor(form(), labelled), /Turn on “Acme weather”/);
  const replacement = api.confirmationFor(
    form("alpha.plugin\nbeta-plugin"),
    new Control("replace-approvals", "approved package list"),
  );
  assert.match(replacement, /alpha\.plugin, beta-plugin/);
  assert.match(replacement, /Only these 2 plugin\(s\) can be installed/);
  const clearing = api.confirmationFor(
    form(""),
    new Control("replace-approvals", "approved package list"),
  );
  assert.match(clearing, /empties the list/);
});

test("the approved list is the ticked boxes plus the one new name", () => {
  const api = client();
  const box = (value, checked) => ({ value, checked });
  const fakeForm = {
    querySelectorAll: () => [box("alpha", true), box("beta", false), box("gamma", true)],
    querySelector: () => ({ value: " delta , alpha " }),
  };
  assert.deepEqual([...api.approvedFrom(fakeForm)], ["alpha", "gamma", "delta"]);
});

test("network failure is single-flight, actionable, and restores controls", async () => {
  const api = client();
  const submitter = new Control("enable", "weather");
  const alreadyDisabled = new Control();
  alreadyDisabled.disabled = true;
  const status = statusNode();
  let release;
  const pending = new Promise((resolve, reject) => { release = () => reject(new Error("offline")); });
  const controller = api.createController({
    fetchRequest: () => pending,
    confirmChange: () => true,
    controls: () => [submitter, alreadyDisabled],
    statusNode: status,
    payloadFor: () => {
      assert.equal(submitter.disabled, false);
      assert.equal(alreadyDisabled.disabled, true);
      return "payload";
    },
    reload: () => assert.fail("a failed mutation must not reload"),
  });
  const targetForm = form();
  const first = controller.submit(targetForm, submitter);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(submitter.disabled, true);
  assert.equal(submitter.getAttribute("aria-busy"), "true");
  assert.equal(targetForm.dataset.inFlight, "true");
  const duplicate = await controller.submit(targetForm, submitter);
  assert.equal(duplicate.reason, "in_flight");
  release();
  const result = await first;
  assert.equal(result.reason, "failed");
  assert.match(status.textContent, /could not be reached/);
  assert.match(status.textContent, /Check your connection and try again/);
  assert.equal(status.attributes.role, "alert");
  assert.equal(submitter.disabled, false);
  assert.equal(alreadyDisabled.disabled, true);
  assert.equal(submitter.getAttribute("aria-busy"), null);
  assert.equal(targetForm.dataset.inFlight, undefined);
});

test("server rejection is a plain sentence and remains retryable", async () => {
  const api = client();
  const submitter = new Control("install", "acme-weather");
  const status = statusNode();
  let requests = 0;
  const controller = api.createController({
    fetchRequest: async () => {
      requests += 1;
      return {
        ok: false,
        status: 403,
        headers: { get: () => "application/json" },
        json: async () => ({ detail: "Plugin installation is disabled by policy." }),
      };
    },
    confirmChange: () => true,
    controls: () => [submitter],
    statusNode: status,
    payloadFor: () => "payload",
    reload: () => assert.fail("a rejected mutation must not reload"),
  });
  const targetForm = form();
  const first = await controller.submit(targetForm, submitter);
  assert.equal(first.reason, "failed");
  assert.match(status.textContent, /installing may be switched off/);
  assert.doesNotMatch(status.textContent, /403|HTTP|policy/);
  assert.equal(submitter.disabled, false);
  assert.equal(submitter.getAttribute("aria-busy"), null);
  const retry = await controller.submit(targetForm, submitter);
  assert.equal(retry.reason, "failed");
  assert.equal(requests, 2);
});

test("cancel sends nothing and success reloads after restoring state", async () => {
  const api = client();
  const submitter = new Control("reset", "weather");
  const status = statusNode();
  let accepted = false;
  let requests = 0;
  let reloads = 0;
  const controller = api.createController({
    fetchRequest: async () => {
      requests += 1;
      return { ok: true, status: 200, headers: { get: () => "text/html" } };
    },
    confirmChange: async () => accepted,
    controls: () => [submitter],
    statusNode: status,
    payloadFor: () => "payload",
    reload: () => { reloads += 1; },
  });
  const targetForm = form();
  const cancelled = await controller.submit(targetForm, submitter);
  assert.equal(cancelled.reason, "cancelled");
  assert.equal(requests, 0);
  assert.equal(targetForm.dataset.inFlight, undefined);
  accepted = true;
  const saved = await controller.submit(targetForm, submitter);
  assert.equal(saved.ok, true);
  assert.equal(requests, 1);
  assert.equal(reloads, 1);
  assert.equal(submitter.disabled, false);
  assert.equal(submitter.getAttribute("aria-busy"), null);
  assert.equal(targetForm.dataset.inFlight, undefined);
});
