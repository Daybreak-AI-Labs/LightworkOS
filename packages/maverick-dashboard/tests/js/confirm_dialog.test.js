"use strict";
// The one confirmation dialog (window.mvConfirm in lightwork-ui.js): it says
// what will happen, the buttons name the action, focus starts on the safe
// choice, Esc keeps things as they are, and a workspace-wide removal needs a
// typed word. Also: no native confirm() is left in the dashboard.
// Run with: node --test tests/js/confirm_dialog.test.js
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const {JSDOM} = require("jsdom");
const root = path.resolve(__dirname, "../../maverick_dashboard");
const source = fs.readFileSync(path.join(root, "static/lightwork-ui.js"), "utf8");

function load() {
  const dom = new JSDOM(`<div id="mv-toasts"></div><div id="mv-toasts-alert"></div><main id="content">
    <button id="opener" type="button">Delete</button></main>
    <dialog id="mv-confirm"><p id="mv-confirm-msg"></p><div>
      <button type="button" class="btn btn--ghost" id="mv-confirm-cancel">Cancel</button>
      <button type="button" class="btn btn--primary" id="mv-confirm-ok">Confirm</button></div></dialog>`,
  {url: "https://lightwork.test/automations", runScripts: "outside-only"});
  const w = dom.window;
  w.matchMedia = () => ({matches: false, addEventListener() {}, removeEventListener() {}});
  w.HTMLDialogElement.prototype.showModal = function () { this.open = true; };
  w.HTMLDialogElement.prototype.close = function () { this.open = false; };
  w.eval(source);
  return w;
}

test("a destructive question starts on the safe choice and names both actions", async () => {
  const w = load(), doc = w.document;
  doc.getElementById("opener").focus();
  const answer = w.mvConfirm('Delete the schedule "Weekly report"? It stops running.',
    {okText: "Delete schedule", cancelText: "Keep schedule", danger: true});
  assert.equal(doc.activeElement.id, "mv-confirm-cancel", "focus starts on the safe choice");
  assert.equal(doc.getElementById("mv-confirm-ok").textContent, "Delete schedule");
  assert.equal(doc.getElementById("mv-confirm-cancel").textContent, "Keep schedule");
  assert.ok(doc.getElementById("mv-confirm-ok").classList.contains("btn--danger"));
  assert.match(doc.getElementById("mv-confirm-msg").textContent, /"Weekly report"\? It stops running\./);
  // Esc (the dialog's cancel event) keeps things as they are.
  doc.getElementById("mv-confirm").dispatchEvent(new w.Event("cancel", {cancelable: true}));
  assert.equal(await answer, false);
  assert.equal(doc.activeElement.id, "opener", "focus goes back to the button that asked");
  // The next, ordinary question gets the plain labels and style back.
  const next = w.mvConfirm("Turn on blocking?", {okText: "Turn on blocking"});
  assert.equal(doc.getElementById("mv-confirm-cancel").textContent, "Cancel");
  assert.ok(doc.getElementById("mv-confirm-ok").classList.contains("btn--primary"));
  doc.getElementById("mv-confirm-ok").click();
  assert.equal(await next, true);
  w.close();
});

test("a workspace-wide removal unlocks only after the word is typed", async () => {
  const w = load(), doc = w.document, ok = doc.getElementById("mv-confirm-ok");
  const answer = w.mvConfirm("Remove Acme from the list?", {okText: "Remove workspace", danger: true, typed: "REMOVE"});
  const input = doc.getElementById("mv-confirm-typed-input");
  assert.equal(doc.querySelector('label[for="mv-confirm-typed-input"]').textContent, "Type REMOVE to confirm");
  assert.equal(ok.disabled, true);
  input.value = "remove";
  input.dispatchEvent(new w.Event("input"));
  assert.equal(ok.disabled, true);
  input.value = "REMOVE";
  input.dispatchEvent(new w.Event("input"));
  assert.equal(ok.disabled, false);
  ok.click();
  assert.equal(await answer, true);
  assert.equal(doc.getElementById("mv-confirm-typed"), null, "the typed field goes with the dialog");
  w.close();
});

test("no native confirm() is left in the dashboard's pages and scripts", () => {
  const offenders = [];
  for (const dir of ["static", "templates"]) {
    for (const name of fs.readdirSync(path.join(root, dir))) {
      if (!/\.(js|html)$/.test(name)) continue;
      // lightwork-ui.js holds mvConfirm's own fallback for browsers without <dialog>.
      if (name === "lightwork-ui.js") continue;
      const lines = fs.readFileSync(path.join(root, dir, name), "utf8").split("\n");
      lines.forEach((line, i) => {
        // Elsewhere a native dialog is allowed only as the fallback right behind mvConfirm.
        const near = lines.slice(Math.max(0, i - 2), i + 1).join("\n");
        if (/(window|root|global)\.confirm\(/.test(line) && !/mvConfirm/.test(near)) offenders.push(`${dir}/${name}:${i + 1}`);
      });
    }
  }
  assert.deepEqual(offenders, []);
});
