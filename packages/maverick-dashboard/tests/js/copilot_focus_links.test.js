// Run with: node --test packages/maverick-dashboard/tests/js/copilot_focus_links.test.js
"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {JSDOM} = require("jsdom");

const base = path.resolve(__dirname, "../../maverick_dashboard");
const read = name => fs.readFileSync(path.join(base, name), "utf8");
const tick = async () => { for (let i = 0; i < 6; i++) await new Promise(resolve => setImmediate(resolve)); };
const response = body => ({ok: true, status: 200, redirected: false, json: async () => body});
const PAGE = '<form><fieldset><legend>Stop tasks that go over a limit</legend>' +
  '<input id="settings-task-budget" type="number"></fieldset></form>' +
  '<h2 id="invite-email">Invite someone by email</h2><div><input type="hidden" name="x"><input id="invite-address" type="email"></div>';

function harness(url, answer) {
  const dom = new JSDOM(PAGE + read("templates/_copilot.html"), {url, runScripts: "outside-only", pretendToBeVisual: true});
  const w = dom.window, d = w.document, asked = [];
  w.HTMLElement.prototype.scrollIntoView = function () {};
  w.fetch = async (url, options = {}) => {
    if (url.includes("/copilot/context")) return response({
      client_context: "a".repeat(64), boundaries: ["Copilot guidance is read-only and never grants authority."],
      suggested_questions: ["What can I do here?"], intro: "I can explain Settings, answer questions about it and take you to the right control. I don't change anything for you.",
      suggestions: ["Set a spending limit", "Connect an AI service", "Choose the AI model"],
      workspace_readiness: {verdict: "ready"}, model_route_status: "ready"});
    if (url === "/api/v1/copilot") { asked.push(JSON.parse(options.body).message); return response(answer); }
    throw Error("Unexpected request " + url);
  };
  w.eval(read("static/lightwork-copilot.js"));
  return {w, d, asked, get: id => d.getElementById(id),
    async open() { d.getElementById("mv-copilot-fab").click(); await tick(); },
    close() { dom.window.close(); }};
}

const BUDGET = {reply: "Enter the amount per task and press Save task limit.", mode: "built_in",
  action_link: {href: "/settings", focus: "settings-task-budget", label: "Open Spending limits"},
  warning: "Nothing was changed. The link opens the page so you can do it yourself."};

test("the panel opens with one short line, not a list of rules", async () => {
  const h = harness("http://localhost/settings", BUDGET);
  await h.open();
  assert.match(h.get("mv-copilot-hello").textContent, /^I can explain Settings/);
  assert.equal(h.get("mv-copilot-tips").hidden, true);
  assert.doesNotMatch(h.get("mv-copilot").textContent, /never grants authority/);
  h.close();
});

test("a suggestion is a task, and one click asks it", async () => {
  const h = harness("http://localhost/settings", BUDGET);
  await h.open();
  const buttons = Array.from(h.d.querySelectorAll(".mv-copilot__prompt")).map(b => b.textContent);
  assert.deepEqual(buttons, ["Set a spending limit", "Connect an AI service", "Choose the AI model"]);
  h.d.querySelector(".mv-copilot__prompt").click(); await tick();
  assert.deepEqual(h.asked, ["Set a spending limit"]);
  const link = h.d.querySelector(".mv-copilot__goto");
  assert.equal(link.getAttribute("href"), "/settings#lw-focus=settings-task-budget");
  assert.equal(link.textContent, "Open Spending limits");
  h.close();
});

test("on the same page the link closes Copilot and focuses the exact control", async () => {
  const h = harness("http://localhost/settings", BUDGET);
  await h.open();
  h.get("mv-copilot-input").value = "Set a spending limit";
  h.get("mv-copilot-form").dispatchEvent(new h.w.Event("submit", {cancelable: true})); await tick();
  h.d.querySelector(".mv-copilot__goto").click(); await tick();
  assert.equal(h.get("mv-copilot").hidden, true);
  assert.equal(h.d.activeElement, h.get("settings-task-budget"));
  h.close();
});

test("arriving from a link focuses the control after a heading and tidies the address", async () => {
  const h = harness("http://localhost/users#lw-focus=invite-email", BUDGET);
  await tick();
  assert.equal(h.d.activeElement, h.get("invite-address"));
  assert.equal(h.w.location.hash, "");
  h.close();
});

test("links outside the closed shape are not rendered", async () => {
  const h = harness("http://localhost/settings", {reply: "Try this.", mode: "built_in",
    action_link: {href: "https://outside.invalid/settings", focus: "x", label: "Open"}});
  await h.open();
  h.get("mv-copilot-input").value = "Where?";
  h.get("mv-copilot-form").dispatchEvent(new h.w.Event("submit", {cancelable: true})); await tick();
  assert.equal(h.d.querySelector(".mv-copilot__goto"), null);
  h.close();
});
