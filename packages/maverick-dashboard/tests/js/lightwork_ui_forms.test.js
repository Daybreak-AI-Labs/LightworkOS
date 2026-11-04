// Run with: node --test packages/maverick-dashboard/tests/js/lightwork_ui_forms.test.js
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

class Element {
  constructor(tag = "div") {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.listeners = new Map();
    this.attributes = {};
    this.style = {};
    this.value = "";
    this.textContent = "";
    this.isConnected = true;
    this.focused = false;
  }
  appendChild(child) { this.children.push(child); child.parent = this; return child; }
  setAttribute(key, value) { this.attributes[key] = String(value); }
  removeAttribute(key) { delete this.attributes[key]; }
  addEventListener(type, fn) { this.listeners.set(type, fn); }
  removeEventListener(type) { this.listeners.delete(type); }
  dispatch(type) { return this.listeners.get(type)?.({ preventDefault() {} }); }
  showModal() { this.open = true; }
  close() { this.open = false; }
  focus() { this.focused = true; }
  select() {}
  remove() { this.parent.children.splice(this.parent.children.indexOf(this), 1); }
  querySelector() {
    for (const child of this.children) {
      if (["INPUT", "SELECT"].includes(child.tagName)) return child;
      const nested = child.querySelector();
      if (nested) return nested;
    }
    return null;
  }
}

function fixture({ fallback = false, answers = [], copyResult = true, acceptPromptDefault = false } = {}) {
  const elements = new Map([
    "mv-toasts", "mv-toasts-alert", "mv-form", "mv-form-form", "mv-form-fields",
    "mv-form-err", "mv-form-cancel", "mv-form-title", "mv-form-ok",
  ].map((id) => [id, new Element()]));
  if (fallback) elements.get("mv-form").showModal = undefined;
  const body = new Element("body");
  const opener = new Element("button");
  const prompts = [];
  const context = {
    document: {
      getElementById(id) { return elements.get(id) || null; },
      createElement(tag) { return new Element(tag); },
      activeElement: opener,
      body,
      execCommand() {
        if (copyResult instanceof Error) throw copyResult;
        return copyResult;
      },
    },
    navigator: {},
    setTimeout() {},
    prompt(message, defaultValue) {
      prompts.push(message);
      return acceptPromptDefault ? (prompts.length === 1 ? defaultValue : null)
        : answers.length ? answers.shift() : null;
    },
  };
  context.window = context;
  const source = fs.readFileSync(
    path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-ui.js"), "utf8",
  );
  const start = source.indexOf("    // Reusable feedback primitives");
  const end = source.indexOf("    // Halt indicator", start);
  assert.ok(start >= 0 && end > start);
  vm.runInNewContext(source.slice(start, end), context, { filename: "lightwork-ui.js" });
  return { context, elements, body, opener, prompts };
}

test("clearing a required prefilled field keeps the form open and focuses the field", async () => {
  const ui = fixture();
  const result = ui.context.mvForm("Run", [{ key: "reason", required: true, default: "Review" }]);
  const control = ui.elements.get("mv-form-fields").querySelector();
  control.value = "   ";
  control.focused = false;
  ui.elements.get("mv-form-form").dispatch("submit");
  assert.equal(ui.elements.get("mv-form").open, true);
  assert.match(ui.elements.get("mv-form-err").textContent, /Required: reason/);
  assert.equal(control.focused, true);
  control.value = "Approved after review";
  ui.elements.get("mv-form-form").dispatch("submit");
  assert.equal((await result).reason, "Approved after review");
  assert.equal(ui.opener.focused, true);
});

test("number forms accept fractional values and link field help for assistive technology", async () => {
  const ui = fixture();
  const result = ui.context.mvForm("Run", [{ key: "amount", type: "number", required: true, help: "Amount in dollars" }]);
  const control = ui.elements.get("mv-form-fields").querySelector();
  assert.equal(control.step, "any");
  assert.equal(control.required, true);
  assert.equal(control.attributes["aria-describedby"], "mvf-amount-help");
  control.value = "12.50";
  ui.elements.get("mv-form-form").dispatch("submit");
  assert.equal((await result).amount, "12.50");
});

test("prompt fallback retries empty required values and returns boolean false as a boolean", async () => {
  const ui = fixture({ fallback: true, answers: [" ", "Because reviewed", "false"] });
  const values = await ui.context.mvForm("Run", [
    { key: "reason", required: true }, { key: "urgent", type: "bool", default: false },
  ]);
  assert.equal(values.reason, "Because reviewed");
  assert.equal(values.urgent, false);
  assert.equal(ui.prompts.length, 3);
});

for (const [defaultValue, expected] of [
  [false, false], ["false", false], [" FALSE ", false], ["no", false], ["0", false],
  [0, false], [null, false], [undefined, false], ["", false], ["unexpected", false],
  [true, true], ["true", true], [" YES ", true], ["1", true], [1, true],
]) {
  test(`boolean default ${JSON.stringify(defaultValue)} agrees in dialog and prompt`, async () => {
    const fields = [{ key: "notify", type: "bool", default: defaultValue }];
    const ui = fixture();
    const result = ui.context.mvForm("Run", fields);
    const control = ui.elements.get("mv-form-fields").querySelector();
    assert.equal(control.checked, expected);
    ui.elements.get("mv-form-form").dispatch("submit");
    assert.equal((await result).notify, expected);
    const fallback = fixture({ fallback: true, acceptPromptDefault: true });
    assert.equal((await fallback.context.mvForm("Run", fields)).notify, expected);
  });
}

test("prompt fallback retries invalid number and select input rather than submitting it", async () => {
  const ui = fixture({ fallback: true, answers: ["Infinity", "4.25", "other", "review"] });
  const values = await ui.context.mvForm("Run", [
    { key: "amount", type: "number" },
    { key: "mode", type: "select", options: [{ value: "review", label: "Review" }] },
  ]);
  assert.equal(values.amount, "4.25");
  assert.equal(values.mode, "review");
  assert.equal(ui.prompts.length, 4);
});

test("prompt fallback cancellation sends no partially collected fields", async () => {
  const ui = fixture({ fallback: true, answers: ["reviewed", null] });
  assert.equal(await ui.context.mvForm("Run", [{ key: "reason" }, { key: "name" }]), null);
});

for (const copyResult of [false, new Error("clipboard denied")]) {
  test(`clipboard fallback reports failure and removes its textarea: ${String(copyResult)}`, () => {
    const ui = fixture({ copyResult });
    ui.context.mvCopy("record");
    assert.equal(ui.elements.get("mv-toasts").children.length, 0);
    assert.match(ui.elements.get("mv-toasts-alert").children[0].textContent, /Copy failed/);
    assert.equal(ui.body.children.length, 0);
    assert.equal(ui.opener.focused, true);
  });
}

test("clipboard fallback reports success only when the copy command succeeds", () => {
  const ui = fixture();
  ui.context.mvCopy("record");
  assert.match(ui.elements.get("mv-toasts").children[0].textContent, /Copied to clipboard/);
  assert.equal(ui.elements.get("mv-toasts-alert").children.length, 0);
  assert.equal(ui.body.children.length, 0);
});
