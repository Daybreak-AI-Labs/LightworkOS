"use strict";
// The one form-field error pattern (mvFieldErrors in lightwork-ui.js, the
// macro in templates/_form_field.html): errors next to each field and in a
// summary that takes focus and links to each field (GOV.UK error summary),
// and nothing typed is lost on an error, a failed request or a reload.
// Run with: node --test tests/js/form_error_summary.test.js
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const {JSDOM} = require("jsdom");
const source = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-ui.js"), "utf8");

function load(body, setup, url) {
  const dom = new JSDOM(`<title>Users · Lightwork</title><div id="mv-toasts"></div><div id="mv-toasts-alert"></div><main id="content">${body}</main>`,
    {url: url || "https://lightwork.test/users", runScripts: "outside-only"});
  dom.window.matchMedia = () => ({matches: false, addEventListener() {}, removeEventListener() {}});
  if (setup) setup(dom.window);
  dom.window.eval(source);
  return dom.window;
}

const INVITE = `<form id="invite" method="post" action="/users/invite" data-mv-validate data-mv-keep="users-invite">
  <div class="mv-field"><label for="email">Email address</label>
    <p class="mv-form__err" id="email-error" hidden></p>
    <input id="email" name="email" type="email" required data-error-required="Enter the email address of the person you are inviting."></div>
  <div class="mv-field"><label for="role">Role</label>
    <select id="role" name="role" required><option value="" disabled selected>Choose a role</option><option value="viewer">Viewer</option></select></div>
  <label for="note">Note (optional)</label><textarea id="note" name="note"></textarea>
  <input type="hidden" name="_expected_tenant" value="t1">
  <button type="submit">Create invite link</button></form>`;

test("an invalid submit ties each error to its field and focuses a summary that links to them", () => {
  const w = load(INVITE), doc = w.document, form = doc.getElementById("invite");
  let sent = 0;
  form.addEventListener("submit", event => { event.preventDefault(); sent += 1; });
  const email = doc.getElementById("email"), note = doc.getElementById("note");
  email.value = "colleague"; note.value = "Starts Monday";
  form.requestSubmit();
  assert.equal(sent, 0, "the page's own submit handler never runs while a field needs fixing");
  const summary = form.querySelector("[data-mv-error-summary]");
  assert.ok(summary && !summary.hidden);
  assert.equal(doc.activeElement, summary, "focus moves to the summary");
  assert.match(summary.textContent, /There is a problem/);
  const links = [...summary.querySelectorAll("a")];
  assert.deepEqual(links.map(a => a.getAttribute("href")), ["#email", "#role"]);
  assert.match(links[0].textContent, /full email address/);
  assert.match(links[1].textContent, /^Choose role\.$/);
  assert.equal(email.getAttribute("aria-invalid"), "true");
  assert.equal(email.getAttribute("aria-describedby"), "email-error");
  const error = doc.getElementById("email-error");
  assert.equal(error.hidden, false);
  assert.match(error.textContent, /^Error: Enter a full email address/);
  assert.match(doc.title, /^Error: Users/);
  // Nothing typed is cleared.
  assert.equal(email.value, "colleague");
  assert.equal(note.value, "Starts Monday");
  // A summary link puts focus in its field.
  links[1].dispatchEvent(new w.MouseEvent("click", {bubbles: true, cancelable: true}));
  assert.equal(doc.activeElement, doc.getElementById("role"));
  w.close();
});

test("the page's own wording wins, fixing a field clears its error, and a clean submit goes through", () => {
  const w = load(INVITE), doc = w.document, form = doc.getElementById("invite");
  let sent = 0;
  form.addEventListener("submit", event => { event.preventDefault(); sent += 1; });
  form.requestSubmit();
  const email = doc.getElementById("email");
  assert.match(doc.getElementById("email-error").textContent, /email address of the person you are inviting/);
  email.value = "new@corp.example";
  email.dispatchEvent(new w.Event("input", {bubbles: true}));
  assert.equal(email.hasAttribute("aria-invalid"), false);
  assert.equal(doc.getElementById("email-error").hidden, true);
  assert.equal(email.hasAttribute("aria-describedby"), false);
  doc.getElementById("role").value = "viewer";
  form.requestSubmit();
  assert.equal(sent, 1);
  assert.equal(form.querySelector("[data-mv-error-summary]").hidden, true);
  assert.doesNotMatch(doc.title, /^Error:/);
  w.close();
});

test("a written error another script already showed is reused, not duplicated", () => {
  const w = load(`<form id="f" data-mv-validate><label for="amount">Amount per task</label>
    <input id="amount" name="amount" type="number" min="0.01" step="0.01" aria-describedby="amount-help">
    <p class="mv-form__err" id="amount-problem" hidden></p><p id="amount-help">Help</p>
    <button type="submit">Save</button></form>`), doc = w.document;
  const field = doc.getElementById("amount"), problem = doc.getElementById("amount-problem");
  // Stream I style: the page words the error itself on 'invalid'.
  field.addEventListener("invalid", event => {
    event.preventDefault();
    problem.textContent = "Use dollars and cents, with at most two decimal places.";
    problem.hidden = false;
    field.setAttribute("aria-describedby", "amount-problem amount-help");
  });
  field.value = "7.505";
  doc.getElementById("f").requestSubmit();
  assert.equal(doc.querySelectorAll(".mv-form__err:not([hidden])").length, 1);
  assert.match(problem.textContent, /^Error: Use dollars and cents/);
  assert.equal(field.getAttribute("aria-describedby"), "amount-problem amount-help");
  assert.match(doc.querySelector("[data-mv-error-summary] a").textContent, /^Use dollars and cents/);
  w.close();
});

test("pages add their own checks, and hidden branches are not checked", () => {
  const w = load(`<form id="f" data-mv-validate>
    <label><input type="radio" name="choice" value="none"> No limit</label>
    <label><input type="radio" name="choice" value="limit" checked> Limit</label>
    <label for="amount">Amount</label><input id="amount" name="amount" type="number">
    <div hidden><label for="unused">Unused</label><input id="unused" name="unused" required></div>
    <button type="submit">Save</button></form>`), doc = w.document, form = doc.getElementById("f");
  form.addEventListener("mv:validate", event => {
    if (form.elements.choice.value === "limit" && !doc.getElementById("amount").value) {
      event.detail.error(doc.getElementById("amount"), "Enter the limit in US dollars, or choose No limit.");
    }
  });
  assert.equal(w.mvFieldErrors.validate(form), false);
  const links = [...form.querySelectorAll("[data-mv-error-summary] a")];
  assert.deepEqual(links.map(a => a.getAttribute("href")), ["#amount"]);
  form.elements.choice.value = "none";
  assert.equal(w.mvFieldErrors.validate(form), true);
  w.close();
});

test("a failed request says so, keeps every value and says it kept them", () => {
  const w = load(INVITE), doc = w.document, form = doc.getElementById("invite");
  doc.getElementById("email").value = "new@corp.example";
  w.mvFieldErrors.fail(form, {status: 401}, "create the invite");
  const summary = form.querySelector("[data-mv-error-summary]");
  assert.equal(doc.activeElement, summary);
  assert.match(summary.textContent, /This was not saved/);
  assert.match(summary.textContent, /sign-in has expired/);
  assert.match(summary.textContent, /What you entered is still here\./);
  assert.equal(doc.getElementById("email").value, "new@corp.example");
  const offline = w.mvFieldErrors.fail(form, new TypeError("Failed to fetch"), "create the invite");
  assert.match(offline.textContent, /could not be reached/);
  w.close();
});

test("what was typed survives a reload in this tab, but never hidden or secret fields", () => {
  let saved;
  {
    const w = load(INVITE + `<form id="secret" data-mv-keep="secret"><label for="pw">Password</label><input id="pw" name="password" type="password">
      <label for="tok">API token</label><input id="tok" name="api_token"></form>`), doc = w.document;
    const email = doc.getElementById("email");
    email.value = "new@corp.example";
    email.dispatchEvent(new w.Event("input", {bubbles: true}));
    doc.getElementById("role").value = "viewer";
    doc.getElementById("role").dispatchEvent(new w.Event("change", {bubbles: true}));
    doc.getElementById("pw").value = "hunter2"; doc.getElementById("pw").dispatchEvent(new w.Event("input", {bubbles: true}));
    doc.getElementById("tok").value = "abc"; doc.getElementById("tok").dispatchEvent(new w.Event("input", {bubbles: true}));
    saved = {...w.sessionStorage};
    w.close();
  }
  const kept = JSON.parse(saved["mv-keep:users-invite"]);
  assert.equal(kept.values.email, "new@corp.example");
  assert.equal(kept.values.role, "viewer");
  assert.equal("_expected_tenant" in kept.values, false);
  assert.doesNotMatch(saved["mv-keep:secret"], /hunter2|abc/);
  // The reload: a fresh page in the same tab gets the values back and says so.
  const w = load(INVITE, win => { for (const [k, v] of Object.entries(saved)) win.sessionStorage.setItem(k, v); });
  const doc = w.document;
  assert.equal(doc.getElementById("email").value, "new@corp.example");
  assert.equal(doc.getElementById("role").value, "viewer");
  const note = doc.querySelector(".mv-keep-note");
  assert.match(note.textContent, /kept what you typed/);
  assert.equal(note.getAttribute("role"), "status");
  // Clear the form empties it and forgets the copy.
  note.querySelector("button").click();
  assert.equal(doc.getElementById("email").value, "");
  assert.equal(w.sessionStorage.getItem("mv-keep:users-invite"), null);
  w.close();
});

test("a page that says the form was saved starts it empty", () => {
  const stored = JSON.stringify({at: Date.now(), values: {email: "old@corp.example"}});
  const w = load(`<p data-mv-keep-done="users-invite">Invitation created.</p>` + INVITE,
    win => win.sessionStorage.setItem("mv-keep:users-invite", stored));
  assert.equal(w.document.getElementById("email").value, "");
  assert.equal(w.sessionStorage.getItem("mv-keep:users-invite"), null);
  w.close();
});

test("a result shown at the form's post address clears the copy kept on the form's page", () => {
  // Measured in the browser: the invite result renders at /users/invite.
  const stored = JSON.stringify({at: Date.now(), values: {email: "old@corp.example"}});
  const w = load(`<section data-mv-keep-done="users-invite">Invitation created.</section>` + INVITE,
    win => win.sessionStorage.setItem("mv-keep:users-invite", stored), "https://lightwork.test/users/invite");
  assert.equal(w.sessionStorage.getItem("mv-keep:users-invite"), null);
  w.close();
});

test("errors the server rendered with the macro take focus on load", () => {
  const w = load(`<form id="f" data-mv-validate><div class="mv-error-summary" id="f-errors" data-mv-error-summary tabindex="-1">
    <h2 id="f-errors-title">There is a problem</h2><ul><li><a href="#email">That address already has an invitation.</a></li></ul></div>
    <label for="email">Email address</label><input id="email" name="email"></form>`);
  assert.equal(w.document.activeElement.id, "f-errors");
  assert.match(w.document.title, /^Error: /);
  w.close();
});

test("a button marked formnovalidate (the spending-limit Preview) submits without the check", () => {
  const w = load(INVITE.replace('<button type="submit">', '<button type="submit" id="preview" formnovalidate formmethod="get">Preview</button><button type="submit">')),
    doc = w.document, form = doc.getElementById("invite");
  let sent = 0;
  form.addEventListener("submit", event => { event.preventDefault(); sent += 1; });
  form.requestSubmit(doc.getElementById("preview"));
  assert.equal(sent, 1, "Preview is not blocked by an empty required field");
  assert.equal(form.querySelector("[data-mv-error-summary]"), null);
  form.requestSubmit();
  assert.equal(sent, 1, "the normal submit still checks the fields");
  w.close();
});
