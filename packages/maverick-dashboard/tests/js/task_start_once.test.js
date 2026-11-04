// Run with: node --test packages/maverick-dashboard/tests/js/task_start_once.test.js
// Starting a task: one submit makes one task, and a started task whose page
// is still being set up opens that page instead of saying "Could not start".
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM, VirtualConsole } = require("jsdom");

const source = fs.readFileSync(
  path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-ui.js"), "utf8");
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

function load(respond) {
  const navigations = [];
  const console_ = new VirtualConsole();
  console_.on("jsdomError", (error) => {
    if (/navigation/i.test(String(error && error.message))) navigations.push(error.message);
  });
  const dom = new JSDOM(
    '<div id="mv-toasts"></div><div id="mv-toasts-alert"></div>' +
    '<form action="/chat/send" method="post"><textarea name="title">Summarize vendor spend</textarea>' +
    '<input type="hidden" name="submission_key" value="key-1"><button type="submit">Start</button></form>' +
    '<p id="goal-error" style="display:none"></p>',
    { url: "https://lightwork.test/chat", runScripts: "outside-only", virtualConsole: console_ });
  const w = dom.window;
  w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
  const calls = [];
  w.fetch = (url, options) => {
    if (!String(url).endsWith("/chat/send")) return new Promise(() => {});
    calls.push(options);
    return respond(calls.length);
  };
  w.eval(source);
  w.document.dispatchEvent(new w.Event("DOMContentLoaded"));
  return { w, calls, navigations };
}

const redirected = (status) => ({
  redirected: true, ok: status < 400, status, url: "https://lightwork.test/chat/goal/7",
  headers: { get: () => null }, json: async () => ({ detail: { code: "result_changing", retryable: true } }),
});

for (const status of [200, 409, 503]) {
  test(`a started task opens its page when that page answers ${status}`, async () => {
    const { w, calls, navigations } = load(async () => redirected(status));
    w.document.querySelector("form").dispatchEvent(new w.Event("submit", { cancelable: true }));
    for (let i = 0; i < 5; i += 1) await tick();
    assert.equal(calls.length, 1);
    const error = w.document.getElementById("goal-error");
    assert.equal(error.style.display, "none");
    assert.doesNotMatch(error.textContent, /Could not start/);
    assert.equal(navigations.length, 1, "opens /chat/goal/7");
    // The form stays locked while the task page opens: no second task.
    assert.equal(w.document.querySelector("button").disabled, true);
    w.close();
  });
}

test("a double submit sends one request", async () => {
  let release;
  const { w, calls } = load(() => new Promise((resolve) => { release = resolve; }));
  const form = w.document.querySelector("form");
  form.dispatchEvent(new w.Event("submit", { cancelable: true }));
  form.dispatchEvent(new w.Event("submit", { cancelable: true }));
  await tick();
  assert.equal(calls.length, 1);
  release(redirected(200));
  for (let i = 0; i < 5; i += 1) await tick();
  form.dispatchEvent(new w.Event("submit", { cancelable: true }));
  await tick();
  assert.equal(calls.length, 1, "still one request while the task page opens");
  w.close();
});

test("a real refusal still explains itself and unlocks the form", async () => {
  const { w, calls } = load(async () => ({
    redirected: false, ok: false, status: 429, url: "https://lightwork.test/chat/send",
    headers: { get: (name) => (name === "Retry-After" ? "5" : null) }, json: async () => ({ detail: "slow down" }),
  }));
  w.document.querySelector("form").dispatchEvent(new w.Event("submit", { cancelable: true }));
  for (let i = 0; i < 5; i += 1) await tick();
  assert.equal(calls.length, 1);
  assert.match(w.document.getElementById("goal-error").textContent, /Try again in 5 seconds/);
  assert.equal(w.document.querySelector("button").disabled, false);
  w.close();
});
