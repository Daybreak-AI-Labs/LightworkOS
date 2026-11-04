"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function splash(copyResult, invoke) {
  const handlers = {};
  const nodes = Object.fromEntries(
    ["status-text", "trouble", "retry", "copy", "copied", "diagnostics", "refresh-details",
      "prepare-startup-report", "download-startup-report", "startup-report-status", "startup-report",
      "support-details", "save-details"].map((id) => [id, {
      style: {},
      textContent: id === "copied" ? "Copied" : "",
      addEventListener(name, handler) { handlers[`${id}:${name}`] = handler; },
    }]),
  );
  const appended = [];
  const downloads = [];
  const blobs = [];
  const context = {
    window: { location: { replace() {} }, addEventListener() {}, __TAURI__: invoke ? { core: { invoke: (command) => command === "dashboard_readiness" ? new Promise(() => {}) : invoke(command) } } : undefined },
    performance: { now: () => 0 },
    AbortController,
    navigator: {},
    fetch: () => new Promise(() => {}),
    setTimeout: () => 1,
    clearTimeout() {},
    Blob,
    URL: { createObjectURL(blob) { blobs.push(blob); return "blob:fixture"; }, revokeObjectURL() {} },
    document: {
      getElementById: (id) => nodes[id],
      createElement: () => ({ style: {}, select() {}, click() { downloads.push(this.download); } }),
      execCommand: copyResult,
      body: {
        appendChild(node) { appended.push(node); },
        removeChild(node) { appended.splice(appended.indexOf(node), 1); },
      },
    },
  };
  vm.runInNewContext(
    fs.readFileSync(path.join(__dirname, "../ui/app.js"), "utf8"), context,
  );
  return { clickCopy: handlers["copy:click"], feedback: nodes.copied, appended, handlers, nodes, downloads, blobs };
}

test("fallback clipboard rejection reports failure and removes temporary input", () => {
  const app = splash(() => false);
  app.clickCopy();
  assert.match(app.feedback.textContent, /Could not copy/);
  assert.equal(app.feedback.style.opacity, "1");
  assert.equal(app.appended.length, 0);
});

test("fallback clipboard exception remains visible and cleans up", () => {
  const app = splash(() => { throw new Error("clipboard unavailable"); });
  app.clickCopy();
  assert.match(app.feedback.textContent, /Could not copy/);
  assert.equal(app.appended.length, 0);
});

test("successful fallback copy confirms the result", () => {
  const app = splash(() => true);
  app.clickCopy();
  assert.equal(app.feedback.textContent, "Copied");
  assert.equal(app.feedback.style.opacity, "1");
  assert.equal(app.appended.length, 0);
});

test("retry invokes the native launcher once while the request is pending", async () => {
  const calls = [];
  let resolve;
  const app = splash(() => true, (command) => {
    calls.push(command);
    return new Promise((done) => { resolve = done; });
  });
  const pending = app.handlers["retry:click"]();
  assert.equal(app.nodes.retry.disabled, true);
  await app.handlers["retry:click"]();
  assert.deepEqual(calls, ["retry_dashboard"]);
  resolve("Starting");
  await pending;
  assert.equal(app.nodes.retry.disabled, false);
});

test("native launch failure keeps retry available and preserves diagnostic details", async () => {
  const app = splash(() => true, () => Promise.reject("synthetic executable missing"));
  await app.handlers["retry:click"]();
  assert.match(app.nodes["status-text"].textContent, /could not start/);
  assert.doesNotMatch(app.nodes["status-text"].textContent, /executable/);
  assert.equal(app.nodes.diagnostics.textContent, "synthetic executable missing");
  assert.equal(app.nodes.trouble.style.display, "block");
  assert.equal(app.nodes.retry.disabled, false);
});

test("startup details are loaded only by the explicit in-app action", async () => {
  const calls = [];
  const app = splash(() => true, (command) => {
    calls.push(command);
    return Promise.resolve("Synthetic startup output");
  });
  assert.deepEqual(calls, []);
  await app.handlers["refresh-details:click"]();
  assert.deepEqual(calls, ["dashboard_diagnostics"]);
  assert.equal(app.nodes.diagnostics.textContent, "Synthetic startup output");
});

test("startup report requires an explicit prepare and downloads the reviewed bytes", async () => {
  const calls = [];
  const report = { schema: "lightwork.startup-support.v1", process_state: "not_started" };
  const app = splash(() => true, async (command) => { calls.push(command); return report; });
  assert.deepEqual(calls, []);
  app.handlers["download-startup-report:click"]();
  assert.equal(app.downloads.length, 0);
  app.handlers["prepare-startup-report:click"]();
  await new Promise(setImmediate);
  assert.deepEqual(calls, ["startup_support_report"]);
  assert.equal(app.nodes["startup-report"].textContent, JSON.stringify(report, null, 2));
  assert.equal(app.downloads.length, 0);
  app.handlers["download-startup-report:click"]();
  assert.deepEqual(app.downloads, ["Lightwork-startup-support.json"]);
  assert.equal(await app.blobs[0].text(), app.nodes["startup-report"].textContent);
});

test("failed startup report refresh invalidates the old download and hides raw errors", async () => {
  let fail = false;
  const app = splash(() => true, async () => {
    if (fail) throw new Error("private fixture token");
    return { schema: "lightwork.startup-support.v1" };
  });
  app.handlers["prepare-startup-report:click"]();
  await new Promise(setImmediate);
  fail = true;
  app.handlers["prepare-startup-report:click"]();
  assert.equal(app.nodes["download-startup-report"].disabled, true);
  assert.equal(app.nodes["startup-report"].textContent, "");
  await new Promise(setImmediate);
  assert.doesNotMatch(app.nodes["startup-report-status"].textContent, /private/);
  app.handlers["download-startup-report:click"]();
  assert.equal(app.downloads.length, 0);
  assert.equal(app.nodes["prepare-startup-report"].disabled, false);
});

test("creating a support report opens the support details and saving startup messages downloads text", async () => {
  const app = splash(() => true, async (command) => command === "dashboard_diagnostics" ? "Synthetic startup output" : { schema: "lightwork.startup-support.v1" });
  app.handlers["prepare-startup-report:click"]();
  assert.equal(app.nodes["support-details"].open, true);
  await new Promise(setImmediate);
  assert.match(app.nodes["startup-report-status"].textContent, /support report is ready/);
  await app.handlers["refresh-details:click"]();
  app.handlers["save-details:click"]();
  assert.deepEqual(app.downloads, ["Lightwork-startup-messages.txt"]);
  assert.equal(await app.blobs[0].text(), "Synthetic startup output");
  const page = fs.readFileSync(path.join(__dirname, "../ui/index.html"), "utf8");
  assert.match(page, /Details for support/);
  assert.doesNotMatch(page, /reach the dashboard|Refresh details/);
});
