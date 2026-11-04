// Run with: node --test packages/maverick-dashboard/tests/js/session_expiry.test.js
// The sign-in timer: warn two minutes before sign-in ends and offer to stay
// signed in; once it has ended, keep what was typed and come back after
// signing in again. Fake clock: the test owns setTimeout and Date.now.
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM, VirtualConsole } = require("jsdom");
const { shell } = require("./_shell");

const source = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-session.js"), "utf8");
const settle = async () => { for (let i = 0; i < 20; i += 1) await new Promise((r) => setImmediate(r)); };
const T0 = 1_800_000_000;

const POLICY_FORM = `<form id="policy"><input name="title"><textarea name="body"></textarea><input type="password" name="password">
    <input name="api_token"></form>`;
function page({ endsIn = 600, renew = "renew", status, renewReply, storage, confirm = true, formHtml = POLICY_FORM } = {}) {
  const navigations = [];
  const console_ = new VirtualConsole();
  console_.on("jsdomError", (e) => { if (/navigation/i.test(String(e && e.message))) navigations.push(e.message); });
  const dom = new JSDOM(`<head>
    <meta name="lightwork-session-expires" content="${T0 + endsIn}"><meta name="lightwork-session-now" content="${T0}">
    <meta name="lightwork-session-renew" content="${renew}"><meta name="lightwork-session-sign-in" content="/auth/local-login"></head>
    <body><main>${formHtml}</main></body>`,
  { url: "https://lightwork.test/policies/edit?id=4", runScripts: "outside-only", virtualConsole: console_ });
  const w = dom.window;
  let clock = T0 * 1000;
  w.Date.now = () => clock;
  const timers = [];
  w.setTimeout = (fn, ms) => { timers.push({ fn, at: clock + ms }); return timers.length; };
  w.clearTimeout = (id) => { if (timers[id - 1]) timers[id - 1].fn = null; };
  const calls = [], confirms = [];
  w.mvConfirm = async (message, options) => { confirms.push({ message, options }); return confirm; };
  w.mvToast = () => {};
  w.fetch = async (url, options = {}) => {
    calls.push({ url, method: options.method || "GET" });
    if (url === "/auth/session/status") {
      const d = status ? status(clock / 1000) : { signed_in: true, expires_at: T0 + endsIn, now: clock / 1000 };
      return { ok: true, status: 200, json: async () => d };
    }
    if (url === "/auth/session/renew") {
      const d = renewReply ? renewReply(clock / 1000) : { expires_at: clock / 1000 + 30 * 86400 };
      return { ok: d.__status ? false : true, status: d.__status || 200, json: async () => d };
    }
    throw new Error("unexpected " + url);
  };
  if (storage) w.sessionStorage.setItem(storage.key, JSON.stringify(storage.value));
  shell(w);   // the shell's mvFetchJSON, as on every signed-in page
  w.eval(source);
  async function advanceTo(seconds) {
    clock = (T0 + seconds) * 1000;
    for (;;) {
      const due = timers.filter((t) => t.fn && t.at <= clock);
      if (!due.length) break;
      for (const t of due) { const fn = t.fn; t.fn = null; fn(); await settle(); }
    }
    await settle();
  }
  return { w, doc: w.document, calls, confirms, navigations, advanceTo, close: () => w.close() };
}

test("two minutes before sign-in ends, it asks to stay signed in and renews in place", async () => {
  const p = page({ endsIn: 600 });
  try {
    await p.advanceTo(479);
    assert.equal(p.confirms.length, 0, "no warning before the two-minute mark");
    await p.advanceTo(481);
    assert.equal(p.confirms.length, 1);
    assert.match(p.confirms[0].message, /Your sign-in ends in about 2 minutes\./);
    assert.equal(p.confirms[0].options.okText, "Stay signed in");
    assert.ok(p.calls.some((c) => c.url === "/auth/session/renew" && c.method === "POST"));
    // Renewed for 30 days: no further warning or notice for a long time.
    await p.advanceTo(600 + 3600);
    assert.equal(p.confirms.length, 1);
    assert.equal(p.doc.querySelector(".mv-session-notice"), null);
  } finally { p.close(); }
});

test("a session kept going in another tab is not warned about", async () => {
  const p = page({ endsIn: 600, status: (now) => ({ signed_in: true, expires_at: now + 7200, now }) });
  try {
    await p.advanceTo(481);
    assert.equal(p.confirms.length, 0);
  } finally { p.close(); }
});

test("when sign-in ends, typed text is kept and Sign in again returns here", async () => {
  const p = page({ endsIn: 600, confirm: false, status: (now) => (now < T0 + 600 ? { signed_in: true, expires_at: T0 + 600, now } : { signed_in: false }) });
  try {
    const form = p.doc.getElementById("policy");
    form.elements.title.value = "Travel policy";
    form.elements.body.value = "Economy class for flights under six hours.";
    form.elements.password.value = "hunter2-not-kept";
    form.elements.api_token.value = "tok-not-kept";
    await p.advanceTo(481);   // warned; the person chose Not now
    assert.equal(p.confirms.length, 1);
    await p.advanceTo(601);
    const notice = p.doc.querySelector(".mv-session-notice");
    assert.ok(notice);
    assert.equal(notice.getAttribute("role"), "alert");
    assert.match(notice.textContent, /Your sign-in has ended\. What you typed on this page is kept\./);
    const again = notice.querySelector("a");
    assert.equal(again.textContent, "Sign in again");
    assert.equal(again.getAttribute("href"), "/auth/local-login?return_to=%2Fpolicies%2Fedit%3Fid%3D4");
    assert.equal(form.elements.body.value, "Economy class for flights under six hours.", "nothing on screen is cleared");
    const kept = JSON.parse(p.w.sessionStorage.getItem("lightwork.session-kept:/policies/edit?id=4"));
    assert.deepEqual(kept.forms[0].values, { title: "Travel policy", body: "Economy class for flights under six hours." });
  } finally { p.close(); }
});

test("after signing in again, the kept text is put back and the copy is removed", async () => {
  const key = "lightwork.session-kept:/policies/edit?id=4";
  const p = page({ endsIn: 30 * 86400, storage: { key, value: { at: T0 * 1000, forms: [{ key: "#policy", values: { title: "Travel policy", body: "Kept body" } }] } } });
  try {
    const form = p.doc.getElementById("policy");
    assert.equal(form.elements.title.value, "Travel policy");
    assert.equal(form.elements.body.value, "Kept body");
    assert.equal(p.w.sessionStorage.getItem(key), null);
    assert.match(p.doc.querySelector(".mv-session-notice").textContent, /What you typed before is back on this page/);
  } finally { p.close(); }
});

test("a company sign-in signs in again instead of renewing", async () => {
  const p = page({ endsIn: 600, renew: "sign-in" });
  try {
    await p.advanceTo(481);
    assert.equal(p.confirms.length, 1);
    assert.ok(!p.calls.some((c) => c.url === "/auth/session/renew"));
    assert.equal(p.navigations.length, 1, "goes to sign in, with return_to");
  } finally { p.close(); }
});

const CHOICE_FORM = `<form id="policy"><input name="title"><select name="priority"><option value="low">Low</option>
  <option value="high">High</option></select><select name="owner"><option value="">Choose</option><option value="ana">Ana</option></select>
  <textarea name="body"></textarea></form>`;

test("a drop-down choice is put back too, not only the ones left on their empty option", async () => {
  const key = "lightwork.session-kept:/policies/edit?id=4";
  const p = page({ endsIn: 30 * 86400, formHtml: CHOICE_FORM, storage: { key, value: { at: T0 * 1000, forms: [
    { key: "#policy", values: { priority: "high", owner: "ana", title: "Travel policy" } }] } } });
  try {
    const form = p.doc.getElementById("policy");
    assert.equal(form.elements.priority.value, "high", "a choice that started on a real first option");
    assert.equal(form.elements.owner.value, "ana");
    assert.equal(form.elements.title.value, "Travel policy");
  } finally { p.close(); }
});

test("a drop-down with nothing kept for it stays on the option the page gave it", async () => {
  const key = "lightwork.session-kept:/policies/edit?id=4";
  const p = page({ endsIn: 30 * 86400, formHtml: CHOICE_FORM, storage: { key, value: { at: T0 * 1000, forms: [
    { key: "#policy", values: { title: "Kept" } }] } } });
  try {
    const form = p.doc.getElementById("policy");
    assert.equal(form.elements.title.value, "Kept");
    assert.equal(form.elements.priority.value, "low");
    assert.equal(form.elements.owner.value, "");
  } finally { p.close(); }
});

test("the end of sign-in does not take the cursor out of what is being typed, and is announced as an alert", async () => {
  const key = "lightwork.session-kept:/policies/edit?id=4";
  const p = page({ endsIn: 600, confirm: false, storage: { key, value: { at: T0 * 1000, forms: [{ key: "#policy", values: { title: "Kept" } }] } },
    status: (now) => (now < T0 + 600 ? { signed_in: true, expires_at: T0 + 600, now } : { signed_in: false }) });
  try {
    const body = p.doc.getElementById("policy").elements.body;
    body.focus();
    assert.equal(p.doc.querySelector(".mv-session-notice").getAttribute("role"), "status", "the restore notice is a status");
    await p.advanceTo(481);
    await p.advanceTo(601);
    const notice = p.doc.querySelector(".mv-session-notice");
    assert.equal(notice.getAttribute("role"), "alert", "the end of sign-in reuses the notice and must be an alert");
    assert.equal(p.doc.activeElement, body, "typing is not interrupted");
  } finally { p.close(); }
});
