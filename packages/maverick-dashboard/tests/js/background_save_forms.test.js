"use strict";
// The four forms that used to post the whole page (spending limit, user role,
// daily summary, invite) now save in the background (data-mv-save="background"):
// "Saving…" at once, and on a failed save -- a server error, no connection or
// an expired sign-in -- everything typed stays and the error summary says what
// happened. A save that needs a fresh sign-in still goes to that sign-in, and
// the spending-limit Preview is still a plain GET.
// Run with: node --test tests/js/background_save_forms.test.js
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const {JSDOM} = require("jsdom");
const root = path.resolve(__dirname, "../../maverick_dashboard");
const ui = fs.readFileSync(path.join(root, "static/lightwork-ui.js"), "utf8");
const tick = () => new Promise(resolve => setTimeout(resolve, 0));
const settle = async () => { for (let i = 0; i < 6; i++) await tick(); };

const SUMMARY = id => `<div class="mv-error-summary" id="${id}-errors" data-mv-error-summary tabindex="-1" hidden></div>`;
const FORMS = {
  limit: {url: "https://lightwork.test/spending-limits", what: "save the limit", value: ["amount", "250"],
    html: `<form method="post" data-mv-save="background" data-mv-save-what="save the limit" action="/spending-limits/workspace" id="limit-workspace" data-mv-validate data-mv-keep="limits-workspace">
      ${SUMMARY("limit-workspace")}
      <fieldset><legend>Choose one</legend>
      <label><input type="radio" name="choice" value="none"> No limit</label>
      <label><input type="radio" name="choice" value="limit" checked> Limit spending to
        <input type="number" name="amount" min="0.01" step="0.01" id="limit-workspace-amount" aria-label="Workspace limit amount in dollars"></label>
      <select name="period" aria-label="Workspace limit resets"><option value="day">per day</option><option value="month" selected>per month</option></select></fieldset>
      <button type="submit" id="preview" formmethod="get" formaction="/spending-limits#limit-preview" formnovalidate name="preview" value="workspace">Preview</button>
      <button type="submit" id="go">Save workspace limit</button></form>`},
  role: {url: "https://lightwork.test/users", what: "save the role", value: ["role", "operator"],
    html: `<table><tr><td><form method="post" data-mv-save="background" data-mv-save-what="save the role" action="/users/set" id="role-form-1" data-mv-keep="users-role-user:alice">
      <input type="hidden" name="principal" value="user:alice">
      <label for="role-1">Role for Alice</label>
      <select name="role" id="role-1"><option value="viewer" selected>Viewer</option><option value="operator">Operator</option></select>
      </form></td><td><button type="submit" form="role-form-1" id="go">Save role</button></td></tr></table>`},
  digest: {url: "https://lightwork.test/me", what: "save your choices", value: ["email", "me@company.test"],
    html: `<form method="post" data-mv-save="background" data-mv-save-what="save your choices" action="/me/preferences" id="digest-form" data-mv-validate data-mv-keep="me-preferences">
      ${SUMMARY("digest-form")}
      <label>Your time zone <select name="time_zone"><option>UTC</option><option>Europe/Paris</option></select></label>
      <label>Email address for the summary <input type="email" name="email"></label>
      <label><input type="checkbox" name="digest_enabled"> Send me a daily summary</label>
      <button type="submit" id="go">Save my choices</button></form>`},
  invite: {url: "https://lightwork.test/users", what: "create the invite link", value: ["email", "colleague@company.test"],
    html: `<div id="invite-result-slot"></div>
      <form method="post" data-mv-save="background" data-mv-save-what="create the invite link" data-mv-save-show="invite-result-slot" action="/users/invite" id="invite-form" data-mv-validate data-mv-keep="users-invite">
      ${SUMMARY("invite")}
      <label>Email address <input id="invite-email-input" type="email" name="email" required></label>
      <label>Role <select name="role"><option value="viewer" selected>Viewer</option><option value="admin">Administrator</option></select></label>
      <button type="submit" id="go">Create invite link</button></form>`},
};

function page(name) {
  const spec = FORMS[name];
  const dom = new JSDOM(`<title>Page · Lightwork</title><div id="mv-toasts"></div><div id="mv-toasts-alert"></div>
    <main id="content">${spec.html}</main>`, {url: spec.url, runScripts: "outside-only"});
  const w = dom.window;
  w.matchMedia = () => ({matches: false, addEventListener() {}, removeEventListener() {}});
  w.HTMLFormElement.prototype.submit = function () { w.__nativeSubmits = (w.__nativeSubmits || 0) + 1; };
  // As a browser does: the submit event, then (unless a script stopped it) the native post or GET.
  w.HTMLFormElement.prototype.requestSubmit = function (submitter) {
    const event = new w.SubmitEvent("submit", {bubbles: true, cancelable: true, submitter: submitter || null});
    if (this.dispatchEvent(event)) this.submit();
  };
  w.calls = [];
  w.reply = null;
  w.fetch = (url, options) => { w.calls.push({url, options}); return w.reply(url, options); };
  w.eval(ui);
  w.navigated = [];
  w.mvBackgroundSave.navigate = url => w.navigated.push(url);
  const form = w.document.querySelector("form[data-mv-save]");
  const field = form.elements[spec.value[0]];
  field.value = spec.value[1];
  field.dispatchEvent(new w.Event("change", {bubbles: true}));   // kept in this tab (data-mv-keep)
  return {w, doc: w.document, form, field, spec, button: w.document.getElementById("go")};
}
function response(w, {status = 200, url = "", redirected = false, json = null, text = "", headers = {}} = {}) {
  const value = {ok: status >= 200 && status < 300, status, url, redirected, headers: new w.Headers(headers),
    json: async () => { if (json === null) throw new Error("not JSON"); return json; }, text: async () => text};
  value.clone = () => value;
  return Promise.resolve(value);
}
const summaryText = doc => (doc.querySelector("[data-mv-error-summary]:not([hidden])") || {textContent: ""}).textContent;

for (const name of Object.keys(FORMS)) {
  test(`${name}: the save is the same POST, in the background, and says Saving… at once`, async () => {
    const {w, form, button, spec} = page(name);
    let finish;
    w.reply = () => new Promise(resolve => { finish = resolve; });
    form.requestSubmit(button);
    const status = form.querySelector("[data-mv-save-status]");
    assert.equal(status.textContent, "Saving…");
    assert.equal(button.getAttribute("aria-busy"), "true");
    assert.equal(w.calls.length, 1);
    const {url, options} = w.calls[0];
    assert.equal(new w.URL(url).pathname, form.getAttribute("action"));
    assert.equal(options.method, "POST");
    assert.equal(options.credentials, "same-origin");
    assert.equal(options.headers.Accept, "application/json");
    assert.equal(new w.URLSearchParams(options.body).get(spec.value[0]), spec.value[1]);
    assert.equal(w.__nativeSubmits || 0, 0, "the page is not posted away");
    form.requestSubmit(button);
    assert.equal(w.calls.length, 1, "a second press while saving sends nothing");
    finish(response(w, {status: 200, redirected: true, url: spec.url + "?saved=yes", text: "<p>Saved.</p>"}));
    await settle();
  });

  test(`${name}: a server error keeps what was typed and says what happened`, async () => {
    const {w, doc, form, field, button, spec} = page(name);
    w.reply = () => response(w, {status: 500, json: {detail: "Synthetic failure"}});
    form.requestSubmit(button);
    await settle();
    assert.equal(field.value, spec.value[1]);
    assert.match(summaryText(doc), /This was not saved/);
    assert.match(summaryText(doc), new RegExp(`Could not ${spec.what}\\. Something went wrong on our side`));
    assert.match(summaryText(doc), /What you entered is still here\./);
    assert.equal(doc.activeElement.getAttribute("data-mv-error-summary"), "");
    assert.equal(form.querySelector("[data-mv-save-status]").textContent, "", "no Saving… left behind");
    assert.equal(button.hasAttribute("aria-busy"), false);
    assert.deepEqual(w.navigated, []);
    // The kept copy is still there for a reload.
    assert.ok(w.sessionStorage.getItem("mv-keep:" + form.getAttribute("data-mv-keep")).includes(spec.value[1]));
  });

  test(`${name}: no connection keeps what was typed and says to check the connection`, async () => {
    const {w, doc, form, field, button, spec} = page(name);
    w.reply = () => Promise.reject(new w.TypeError("Failed to fetch"));
    form.requestSubmit(button);
    await settle();
    assert.equal(field.value, spec.value[1]);
    assert.match(summaryText(doc), /Lightwork could not be reached\. Check your connection and try again\./);
    assert.deepEqual(w.navigated, []);
  });

  test(`${name}: an expired sign-in keeps what was typed and says to sign in again`, async () => {
    const {w, doc, form, field, button, spec} = page(name);
    w.reply = () => response(w, {status: 401, json: {detail: "unauthorized"}});
    form.requestSubmit(button);
    await settle();
    assert.equal(field.value, spec.value[1]);
    assert.match(summaryText(doc), /Your sign-in has expired\. Sign in again to continue\./);
    assert.ok(w.sessionStorage.getItem("mv-keep:" + form.getAttribute("data-mv-keep")).includes(spec.value[1]),
      "kept for after signing in");
  });

  test(`${name}: a save that needs a fresh authenticator sign-in still goes there and comes back to this page`, async () => {
    const {w, form, button} = page(name);
    const here = new w.URL(w.location.href);
    w.reply = () => response(w, {status: 403, headers: {"X-Reauthenticate": "/auth/login?fresh=1&return_to=" + encodeURIComponent(form.getAttribute("action"))},
      json: {detail: "This action needs a recent sign-in with your authenticator. Sign in again, then try again.", reauthenticate: "/auth/login?fresh=1&return_to=x"}});
    form.requestSubmit(button);
    await settle();
    assert.equal(w.navigated.length, 1);
    const target = new w.URL(w.navigated[0], w.location.href);
    assert.equal(target.pathname, "/auth/login");
    assert.equal(target.searchParams.get("fresh"), "1");
    assert.equal(target.searchParams.get("return_to"), here.pathname + here.search);
  });
}

test("a sign-in link to another site is never followed", async () => {
  const {w, doc, form, button} = page("role");
  w.reply = () => response(w, {status: 403, headers: {"X-Reauthenticate": "https://evil.example/login"}, json: {detail: "no"}});
  form.requestSubmit(button);
  await settle();
  assert.deepEqual(w.navigated, []);
  assert.match(summaryText(doc), /You do not have permission/);
});

test("a refused value is written next to its field", async () => {
  const {w, doc, form, button} = page("limit");
  const message = "Enter the limit as an amount in dollars, more than $0.";
  w.reply = () => response(w, {status: 422, json: {detail: {schema: "lightwork.error.v1", code: "spending_limit_amount",
    message, field_errors: {amount: message}, next_action: null, retryable: false}}});
  form.requestSubmit(button);
  await settle();
  const amount = doc.getElementById("limit-workspace-amount");
  assert.equal(amount.getAttribute("aria-invalid"), "true");
  assert.deepEqual([...doc.querySelectorAll("[data-mv-error-summary]:not([hidden]) a")].map(a => [a.getAttribute("href"), a.textContent]),
    [["#limit-workspace-amount", message]]);
  assert.equal(amount.value, "250");
});

test("a successful save opens the page the server answered with and forgets the kept copy", async () => {
  const {w, form, button} = page("limit");
  w.reply = () => response(w, {status: 200, redirected: true, url: "https://lightwork.test/spending-limits?saved=workspace", text: "<p>Saved.</p>"});
  form.requestSubmit(button);
  await settle();
  assert.deepEqual(w.navigated, ["https://lightwork.test/spending-limits?saved=workspace"]);
  assert.equal(w.sessionStorage.getItem("mv-keep:limits-workspace"), null);
});

test("the spending-limit Preview is still a plain GET that saves nothing", () => {
  const {w, form} = page("limit");
  w.reply = () => { throw new Error("Preview must not be fetched"); };
  form.requestSubmit(w.document.getElementById("preview"));
  assert.equal(w.calls.length, 0);
  assert.equal(w.__nativeSubmits, 1);
  assert.equal(form.querySelector("[data-mv-save-status]"), null, "no Saving… for a preview");
});

test("invite: the one-time link is shown in place, focused, and the form starts empty", async () => {
  const {w, doc, form, button} = page("invite");
  let saved = 0;
  form.addEventListener("mv:saved", () => { saved += 1; });
  w.reply = () => response(w, {status: 200, url: "https://lightwork.test/users/invite", text:
    `<html><body><main><div id="invite-result-slot"><section class="panel" id="invite-result" tabindex="-1">
      <strong>Invitation for colleague@company.test created.</strong>
      <input id="invite-link" type="text" readonly value="https://lightwork.test/auth/invite/one-time"></section></div>
      <form id="invite-form"></form></main></body></html>`});
  form.requestSubmit(button);
  await settle();
  assert.deepEqual(w.navigated, [], "the one-time link is not lost to a reload");
  assert.equal(doc.getElementById("invite-link").value, "https://lightwork.test/auth/invite/one-time");
  assert.equal(doc.activeElement.id, "invite-result");
  assert.equal(form.elements.email.value, "");
  assert.equal(form.querySelector("[data-mv-save-status]").textContent, "");
  assert.equal(w.sessionStorage.getItem("mv-keep:users-invite"), null);
  assert.equal(saved, 1);
});
