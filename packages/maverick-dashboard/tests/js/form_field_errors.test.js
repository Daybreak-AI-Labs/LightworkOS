"use strict";
// Form errors measured on the dashboard: Settings refused 7.50 for the
// spending per task with only the browser's bubble ("nearest valid values are
// 7.01 and 7.51"), and the invite email error was the bubble too: neither was
// tied to its field. Run with: node --test tests/js/form_field_errors.test.js
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const {JSDOM} = require("jsdom");
const template = name => fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates", name), "utf8").replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>").replace(/\r\n/g, "\n");

function settingsPage() {
  const source = template("settings.html");
  const marker = source.indexOf("getElementById('settings-task-budget-error')");
  const start = source.lastIndexOf("<script>", marker) + "<script>".length;
  const script = source.slice(start, source.indexOf("</script>", marker));
  const dom = new JSDOM(`<form method="post" action="/settings/budget"><fieldset>
      <label><input type="radio" name="mode" value="configured" checked> Stop a task when it has spent</label>
      <label><span>Amount per task (US dollars)</span>
        <input class="input" id="settings-task-budget" type="number" name="max_dollars" min="0.01" step="0.01" aria-describedby="task-limit-help"></label>
      <p class="mv-form__err" id="settings-task-budget-error" role="alert" hidden></p></fieldset>
      <p id="task-limit-help">Help</p><button type="submit">Save task limit</button></form>`, {runScripts: "outside-only"});
  dom.window.eval(script);
  return dom;
}

test("Settings takes a round amount such as 7.50", () => {
  const dom = settingsPage();
  try {
    const doc = dom.window.document, field = doc.getElementById("settings-task-budget");
    for (const value of ["7.50", "5", "0.01", "12.35"]) {
      field.value = value;
      assert.equal(field.validity.valid, true, value);
    }
  } finally { dom.window.close(); }
});

for (const [value, words] of [["7.505", /two decimal places/], ["0", /at least \$0\.01/]]) {
  test(`Settings explains ${value} next to the field and links the message to it`, () => {
    const dom = settingsPage();
    try {
      const w = dom.window, doc = w.document, form = doc.querySelector("form");
      const field = doc.getElementById("settings-task-budget"), error = doc.getElementById("settings-task-budget-error");
      field.value = value;
      let bubble = 0;
      field.addEventListener("invalid", event => { if (!event.defaultPrevented) bubble += 1; });
      assert.equal(form.checkValidity(), false);
      assert.equal(bubble, 0, "the browser bubble is replaced by the written error");
      assert.equal(error.hidden, false);
      assert.match(error.textContent, words);
      assert.equal(field.getAttribute("aria-invalid"), "true");
      assert.equal(field.getAttribute("aria-describedby"), "settings-task-budget-error task-limit-help");
      assert.equal(doc.activeElement, field);
      // Fixing the value clears the error and restores the help link.
      field.value = "7.50";
      field.dispatchEvent(new w.Event("input", {bubbles: true}));
      assert.equal(error.hidden, true);
      assert.equal(field.hasAttribute("aria-invalid"), false);
      assert.equal(field.getAttribute("aria-describedby"), "task-limit-help");
    } finally { dom.window.close(); }
  });
}

function usersPage() {
  const source = template("users.html");
  const start = source.indexOf("    // A wrong invite address");
  const end = source.indexOf("if (inviteResult) inviteResult.focus();") + "if (inviteResult) inviteResult.focus();".length;
  const dom = new JSDOM(`<section id="invite-result" tabindex="-1"><strong>Invitation created.</strong></section>
    <form method="post" action="/users/invite"><input id="invite-email-input" type="email" name="email" required>
    <button type="submit">Create invite link</button><p id="invite-email-error" role="alert" hidden></p></form>`, {runScripts: "outside-only"});
  dom.window.eval("(function () {" + source.slice(start, end) + "})();");
  return dom;
}

test("the invite result takes focus when the page shows a new link", () => {
  const dom = usersPage();
  try {
    assert.equal(dom.window.document.activeElement, dom.window.document.getElementById("invite-result"));
  } finally { dom.window.close(); }
});

for (const [value, words] of [["", /email address of the person/], ["colleague", /full email address/]]) {
  test(`an invite to "${value}" is explained next to the email field`, () => {
    const dom = usersPage();
    try {
      const w = dom.window, doc = w.document, form = doc.querySelector("form");
      const field = doc.getElementById("invite-email-input"), error = doc.getElementById("invite-email-error");
      field.value = value;
      assert.equal(form.checkValidity(), false);
      assert.equal(error.hidden, false);
      assert.match(error.textContent, words);
      assert.equal(field.getAttribute("aria-invalid"), "true");
      assert.equal(field.getAttribute("aria-describedby"), "invite-email-error");
      assert.equal(doc.activeElement, field);
      field.value = "new@corp.example";
      field.dispatchEvent(new w.Event("input", {bubbles: true}));
      assert.equal(error.hidden, true);
      assert.equal(field.hasAttribute("aria-invalid"), false);
      assert.equal(form.checkValidity(), true);
    } finally { dom.window.close(); }
  });
}
