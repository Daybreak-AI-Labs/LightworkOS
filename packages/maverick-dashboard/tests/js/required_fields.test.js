// Run with: node --test packages/maverick-dashboard/tests/js/required_fields.test.js
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const source = fs.readFileSync(
  path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-ui.js"), "utf8");
const flush = () => new Promise((done) => setImmediate(done));

function load(body) {
  const dom = new JSDOM(`<!doctype html><html><body><div id="mv-toasts"></div><div id="mv-toasts-alert"></div>${body}` +
    '<dialog id="mv-form"><form id="mv-form-form"><h2 id="mv-form-title"></h2><div id="mv-form-fields"></div>' +
    '<p id="mv-form-err"></p><button type="button" id="mv-form-cancel"></button><button id="mv-form-ok"></button></form></dialog>' +
    "</body></html>", { url: "https://lightwork.test/", runScripts: "outside-only" });
  const w = dom.window;
  w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
  w.HTMLDialogElement.prototype.showModal = function () { this.open = true; };
  w.HTMLDialogElement.prototype.close = function () { this.open = false; };
  w.eval(source);
  return w;
}
const markers = (node) => [...node.querySelectorAll(".mv-required")];

test("every required field gets one hidden-from-assistive-tech Required marker beside its label", () => {
  const w = load(
    '<form><label id="wrap">Work email <input id="email" type="email" required></label>' +
    '<label id="for" for="amount">Daily limit <span class="muted">(dollars)</span></label><input id="amount" required>' +
    '<label id="agree"><input type="checkbox" required> I confirm the change</label>' +
    '<fieldset id="group"><legend>Period</legend><label><input type="radio" name="p" required> Day</label>' +
    '<label><input type="radio" name="p" required> Month</label></fieldset>' +
    '<label id="pick">Action <select required><option>Make a field required</option></select></label>' +
    '<label id="optional">Notes <textarea></textarea></label>' +
    '<input type="hidden" name="token" required></form>');
  const doc = w.document;
  const wrap = doc.getElementById("wrap");
  assert.equal(markers(wrap).length, 1);
  const marker = markers(wrap)[0];
  assert.equal(marker.textContent, "Required");
  assert.equal(marker.getAttribute("aria-hidden"), "true");
  assert.equal(marker.nextElementSibling, doc.getElementById("email")); // between the words and the field
  assert.equal(doc.getElementById("for").lastElementChild.className, "mv-required");
  assert.equal(doc.getElementById("agree").lastElementChild.className, "mv-required"); // after the checkbox's words
  assert.equal(markers(doc.getElementById("group")).length, 1);
  assert.equal(doc.querySelector("#group legend .mv-required").textContent, "Required");
  assert.equal(markers(doc.getElementById("pick")).length, 1); // an option's words are not the label's
  assert.equal(markers(doc.getElementById("optional")).length, 0);
  assert.equal(markers(doc.body).length, 5);
  w.close();
});

test("a label whose words sit in their own element keeps the marker on that line", () => {
  const w = load(
    '<label id="column" style="display:flex;flex-direction:column"><span>Person</span>\n  <select required><option>Ana</option></select></label>' +
    '<label id="amount"><span>Amount</span><span>$ <input type="number" required></span></label>' +
    '<label id="mixed">Owner <span class="muted">(shown on reports)</span> and backup <input required></label>');
  const doc = w.document;
  assert.equal(doc.querySelector("#column > span").textContent, "PersonRequired");
  assert.equal(doc.querySelector("#amount > span").textContent, "AmountRequired");
  // Words written straight into the label: the marker goes just before the field.
  assert.equal(doc.querySelector("#mixed input").previousElementSibling.className, "mv-required");
  w.close();
});

test("labels that already say required are left as written", () => {
  const w = load(
    '<label id="star">Name <span aria-hidden="true">*</span><input required></label>' +
    '<label id="words">Reason (required) <input required></label>' +
    '<label id="pattern">Events (dsar.* for a family) <input required></label>');
  assert.equal(markers(w.document.getElementById("star")).length, 0);
  assert.equal(markers(w.document.getElementById("words")).length, 0);
  assert.equal(markers(w.document.getElementById("pattern")).length, 1); // an asterisk inside words is not a marker
  w.close();
});

test("fields added or changed later are marked once, and lose the marker when no longer required", async () => {
  const w = load('<form id="f"><label id="later">Owner <input id="owner"></label></form>');
  const doc = w.document;
  const form = doc.getElementById("f");
  form.insertAdjacentHTML("beforeend", '<label id="added">Due date <input type="date" required></label>');
  await flush();
  assert.equal(markers(doc.getElementById("added")).length, 1);
  const owner = doc.getElementById("owner");
  owner.required = true; await flush();
  assert.equal(markers(doc.getElementById("later")).length, 1);
  owner.required = false; await flush();
  assert.equal(markers(doc.getElementById("later")).length, 0);
  owner.required = true; await flush();
  assert.equal(markers(doc.getElementById("later")).length, 1);
  // A label rewritten in place (a translation, a renamed field) gets its marker back, once.
  form.insertAdjacentHTML("beforeend", '<label id="renamed" for="site">Site</label><input id="site" required>');
  await flush();
  const renamed = doc.getElementById("renamed");
  renamed.textContent = "Website address"; await flush();
  assert.equal(renamed.textContent, "Website addressRequired");
  assert.equal(markers(renamed).length, 1);
  w.close();
});

test("in-app forms use the same marker instead of a bare asterisk", async () => {
  const w = load("");
  const result = w.mvForm("Approve", [{ key: "reason", label: "Reason", required: true }, { key: "note", label: "Note" }]);
  await flush();
  const labels = [...w.document.querySelectorAll("#mv-form-fields label")];
  assert.equal(labels[0].textContent, "ReasonRequired");
  assert.equal(markers(labels[0]).length, 1);
  assert.equal(markers(labels[1]).length, 0);
  assert.doesNotMatch(w.document.getElementById("mv-form-fields").textContent, /\*/);
  w.document.getElementById("mv-form-cancel").click();
  assert.equal(await result, null);
  w.close();
});
