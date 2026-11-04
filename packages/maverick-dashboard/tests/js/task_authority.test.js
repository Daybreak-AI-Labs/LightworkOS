"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { fetchHelpers } = require('./_shell');
const source = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-task-authority.js"), "utf8");
const html = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates/chat_goal.html"), "utf8").replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
function fixture(initial = true) {
  const callbacks = {}, focus = {}, root = {dataset: {operate: initial ? "1" : "0", goal: "1"}, textContent: ""};
  const control = {tagName: "SELECT", dataset: initial ? {} : {permissionDisabled: "1"}, disabled: !initial, value: "draft project", closest: () => control};
  const state = {allowed: initial, reason: "", calls: 0, selectors: ""};
  const form = {matches: selector => selector.includes(".goal-project"), requestSubmit() { state.submitted = (state.submitted || 0) + 1; }};
  const document = {hidden: false, body: {}, getElementById: () => root, querySelectorAll: selector => { state.selectors = selector; return [control]; }, addEventListener: (name, callback) => { callbacks[name] = callback; }};
  class Observer { constructor(callback) { state.mutate = callback; } observe() {} }
  const fetch = async () => { state.calls += 1; return {ok: true, json: async () => ({can_operate: state.allowed, reason: state.reason})}; };
  vm.runInNewContext(source, {document, window: {addEventListener: (name, callback) => { focus[name] = callback; },
    mvFetchJSON: fetchHelpers(() => fetch).mvFetchJSON}, MutationObserver: Observer, fetch, WeakMap, WeakSet});
  return {state, root, control, form, callbacks, focus};
}
function event(target) { return {target, prevented: false, preventDefault() { this.prevented = true; }, stopImmediatePropagation() { this.stopped = true; }}; }
test("project selection uses checked submission and initial viewer controls are disabled", () => {
  // The page wires the change in its nonce-stamped script (no inline handler under the CSP).
  assert.doesNotMatch(html, /onchange=/);
  assert.match(html, /projectSelect\.addEventListener\('change', function \(\) \{ this\.form\.requestSubmit\(\); \}\)/);
  assert.doesNotMatch(html, /this\.form\.submit\(\)/);
  for (const id of ["ps-run", "goal-project-sel", "answer-send", "reply-files", "recover-submission-btn"]) {
    const tag = html.match(new RegExp('<(?:button|input|select)[^>]*id="' + id + '"[^>]*>'))[0];
    assert.match(tag, /if not can_operate/);
    assert.match(tag, /disabled data-permission-disabled="1"/);
  }
});
test("mid-session revocation blocks project submit and keeps its entered choice", async () => {
  const ui = fixture(); ui.state.allowed = false; ui.state.reason = "Workspace role changed.";
  const submit = event(ui.form); await ui.callbacks.submit(submit);
  assert.equal(ui.state.calls, 1); assert.equal(ui.state.submitted || 0, 0);
  assert.equal(submit.prevented, true); assert.equal(ui.control.disabled, true);
  assert.equal(ui.control.value, "draft project"); assert.equal(ui.root.textContent, "Workspace role changed.");
  assert.match(ui.state.selectors, /#goal-project-sel/);
});
test("initial permission-disabled controls recover only after a fresh allowed result", async () => {
  const ui = fixture(false); assert.equal(ui.control.disabled, true);
  ui.state.allowed = true; await ui.focus.focus(); assert.equal(ui.control.disabled, false);
  await ui.callbacks.submit(event(ui.form)); assert.equal(ui.state.submitted, 1);
});
test("select opening is not replayed as an artificial click", async () => {
  const ui = fixture(); const click = event(ui.control); await ui.callbacks.click(click);
  assert.equal(click.prevented, false); assert.equal(ui.state.calls, 0);
});
