// Run with: node --test packages/maverick-dashboard/tests/js/lightwork_ui_save_feedback.test.js
// A form that posts and reloads the page (data-mv-save) says "Saving…" the
// moment it is sent, so a slow server never looks like a missed click.
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const source = fs.readFileSync(
  path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-ui.js"), "utf8");

function load(forms) {
  const dom = new JSDOM(`<!doctype html><body><div id="mv-toasts"></div><div id="mv-toasts-alert"></div>
    <main>${forms}</main></body>`, { url: "https://lightwork.test/users", runScripts: "outside-only" });
  dom.window.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
  dom.window.HTMLFormElement.prototype.submit = function () {};
  dom.window.HTMLFormElement.prototype.requestSubmit = function (submitter) {
    const event = new dom.window.SubmitEvent("submit", { bubbles: true, cancelable: true, submitter: submitter || null });
    if (this.dispatchEvent(event)) this.submit();
  };
  dom.window.eval(source);
  return dom.window;
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

test("a post-and-reload form says Saving… at once and marks the button busy", async () => {
  const window = load(`<form id="role" method="post" action="/users/set" data-mv-save>
      <select name="role"><option>viewer</option></select></form>
    <button id="save" type="submit" form="role">Save role</button>`);
  const form = window.document.getElementById("role"), button = window.document.getElementById("save");
  form.requestSubmit(button);
  const status = form.querySelector("[data-mv-save-status]");
  assert.ok(status, "a status line is added to the form");
  assert.equal(status.getAttribute("role"), "status");
  assert.equal(status.textContent, "Saving…");
  assert.equal(button.getAttribute("aria-busy"), "true");
  await tick();
  assert.equal(status.textContent, "Saving…", "still saving while the page loads the result");
});

test("a submission another script stops does not claim to be saving", async () => {
  const window = load(`<form id="limit" method="post" action="/spending-limits/workspace" data-mv-save>
      <button id="go" type="submit">Save limit</button></form>`);
  const form = window.document.getElementById("limit"), button = window.document.getElementById("go");
  form.addEventListener("submit", (event) => event.preventDefault());
  form.requestSubmit(button);
  await tick();
  const status = form.querySelector("[data-mv-save-status]");
  assert.ok(!status || status.textContent === "", "no Saving… for a stopped submission");
  assert.equal(button.hasAttribute("aria-busy"), false);
});

test("forms without data-mv-save and same-page forms are left alone", () => {
  const window = load(`<form id="plain" method="post" action="/users/remove">
      <button id="go" type="submit">Remove</button></form>`);
  const form = window.document.getElementById("plain");
  form.requestSubmit(window.document.getElementById("go"));
  assert.equal(form.querySelector("[data-mv-save-status]"), null);
});

test("coming back to the page from history clears an old Saving…", async () => {
  const window = load(`<form id="prefs" method="post" action="/me/preferences" data-mv-save>
      <button id="go" type="submit">Save my choices</button></form>`);
  const form = window.document.getElementById("prefs"), button = window.document.getElementById("go");
  form.requestSubmit(button);
  const pageshow = new window.Event("pageshow");
  Object.defineProperty(pageshow, "persisted", { value: true });
  window.dispatchEvent(pageshow);
  assert.equal(form.querySelector("[data-mv-save-status]").textContent, "");
  assert.equal(button.hasAttribute("aria-busy"), false);
});

test("a read-only button in a saving form (the spending-limit Preview) does not say Saving…", () => {
  const window = load(`<form id="limit" method="post" action="/spending-limits/workspace" data-mv-save>
      <input name="amount" value="10">
      <button id="preview" type="submit" formmethod="get" formnovalidate formaction="/spending-limits">Preview</button>
      <button id="save" type="submit">Save</button></form>`);
  const form = window.document.getElementById("limit");
  form.requestSubmit(window.document.getElementById("preview"));
  assert.equal(form.querySelector("[data-mv-save-status]"), null);
  assert.equal(window.document.getElementById("preview").hasAttribute("aria-busy"), false);
  form.requestSubmit(window.document.getElementById("save"));
  assert.equal(form.querySelector("[data-mv-save-status]").textContent, "Saving…");
});
