"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const source = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-dsar-detail.js"), "utf8");
const html = `<div id="dsar-page" data-request-id="DSAR-1" data-subject="a@example.com" data-channel="email" data-kind="erasure" data-fulfillment-id="F-1" data-revision="4">
<div id="dsar-status"></div><div id="dsar-worksheet-result"></div><button id="dsar-worksheet"></button>
<button id="dsar-identity"></button><button id="dsar-link"></button><button id="dsar-erase"></button><button id="dsar-close"></button>
<div id="dsar-link-box" hidden><input id="dsar-link-url"><button id="dsar-link-copy"></button></div></div>`;
const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { "Content-Type": "application/json" } });

async function fixture({ formValues, confirm = true, reply, markup = html, hash = "" }) {
  const dom = new JSDOM(markup, { url: "https://lightwork.example/privacy/dsar/DSAR-1" + hash, runScripts: "outside-only" });
  const { window } = dom;
  shell(window);
  const calls = [], forms = [], confirms = [];
  window.mvForm = async (title, fields, opts) => { forms.push({ title, fields, opts }); return formValues.shift(); };
  window.mvPlainDetail = (d) => (typeof d === "string" && /^[A-Z].*\.$/.test(d) ? d : "");
  window.mvConfirm = async (m) => { confirms.push(m); return confirm; };
  window.mvErrorText = (f, action) => `Could not ${action}.`;
  window.fetch = async (url, opts = {}) => { calls.push({ url, ...opts }); return reply(url, opts); };
  window.eval(source);
  const settle = async () => { for (let i = 0; i < 20; i++) await new Promise((d) => setImmediate(d)); };
  return { window, doc: window.document, calls, forms, confirms, settle };
}

test("identity is confirmed through a method dropdown, carrying the record version", async (t) => {
  const ui = await fixture({ formValues: [{ method: "document_check", reference: "ticket 9" }], reply: () => json({}) });
  t.after(() => ui.window.close());
  ui.doc.getElementById("dsar-identity").click(); await ui.settle();
  const methodField = ui.forms[0].fields[0];
  assert.equal(methodField.type, "select");
  assert.ok(methodField.options.every((o) => !/_/.test(o.label)));
  const call = ui.calls[0];
  assert.match(call.url, /fulfillment\/F-1\/identity$/);
  assert.deepEqual(JSON.parse(call.body), { method: "document_check", reference: "ticket 9", revision: 4 });
});

test("the secure link is shown once in a copy box", async (t) => {
  const ui = await fixture({ formValues: [{ hours: "24", single: true }], reply: () => json({ response_path: "/dsar/response/abc", revision: 5 }) });
  t.after(() => ui.window.close());
  ui.doc.getElementById("dsar-link").click(); await ui.settle();
  assert.deepEqual(JSON.parse(ui.calls[0].body), { expires_hours: 24, revision: 4, max_reads: 1 });
  assert.equal(ui.doc.getElementById("dsar-link-box").hidden, false);
  assert.equal(ui.doc.getElementById("dsar-link-url").value, "https://lightwork.example/dsar/response/abc");
});

test("erasure picks the matching person and confirms before erasing", async (t) => {
  const ui = await fixture({
    formValues: [{ who: "0" }],
    reply: (url) => url.endsWith("/people")
      ? json({ people: [{ channel: "slack", user: "someone", person: "someone", channel_label: "Slack" }, { channel: "email", user: "a@example.com", person: "a@example.com", channel_label: "Email" }] })
      : json({ message: "Erased 1 conversation(s) and everything linked to them." }),
  });
  t.after(() => ui.window.close());
  ui.doc.getElementById("dsar-erase").click(); await ui.settle();
  assert.equal(ui.forms[0].fields[0].options.length, 1);
  assert.equal(ui.confirms.length, 1);
  const erase = ui.calls.find((c) => c.url.endsWith("/people/erase"));
  assert.deepEqual(JSON.parse(erase.body), { channel: "email", user: "a@example.com" });
  assert.match(ui.doc.getElementById("dsar-status").textContent, /Erased 1 conversation/);
});

test("an uncertified erasure keeps the request open", async (t) => {
  const ui = await fixture({
    formValues: [{ who: "0" }],
    reply: (url) => url.endsWith("/people")
      ? json({ people: [{ channel: "email", user: "a@example.com", person: "a@example.com", channel_label: "Email" }] })
      : json({ erased: true, clean: false, message: "Erased 1 conversation(s), but these could not be cleaned up: stored AI replies." }),
  });
  t.after(() => ui.window.close());
  ui.doc.getElementById("dsar-erase").click(); await ui.settle();
  const status = ui.doc.getElementById("dsar-status").textContent;
  assert.match(status, /Keep this request open/);
  assert.doesNotMatch(status, /You can now close/);
});

test("closing asks what happened before anything is sent, and errors stay plain", async (t) => {
  const ui = await fixture({ formValues: [{ kind: "no_response" }, {}], reply: () => new Response("x", { status: 500 }) });
  t.after(() => ui.window.close());
  ui.doc.getElementById("dsar-close").click(); await ui.settle();
  assert.equal(ui.forms.length, 2);
  assert.equal(ui.forms[1].opts.okText, "Close request");
  // The first thing sent is the outcome for review; nothing is closed yet.
  assert.match(ui.calls[0].url, /\/privacy\/dsar\/DSAR-1\/handling\/review$/);
  assert.deepEqual(JSON.parse(ui.calls[0].body), { outcome: { kind: "no_response" } });
  assert.equal(ui.calls.length, 1);
  assert.equal(ui.doc.getElementById("dsar-status").textContent, "Could not review the complete outcome.");
});

test("closing warns when the requester's identity was never confirmed", async (t) => {
  const markup = html.replace('data-kind="erasure"', 'data-kind="erasure" data-identity="unverified"');
  const ui = await fixture({ formValues: [null], reply: () => json({}), markup });
  t.after(() => ui.window.close());
  ui.doc.getElementById("dsar-close").click(); await ui.settle();
  assert.match(ui.forms[0].fields[0].help, /identity is not confirmed/);
});

test("cancelling the close form changes nothing", async (t) => {
  const ui = await fixture({ formValues: [null], reply: () => json({}) });
  t.after(() => ui.window.close());
  ui.doc.getElementById("dsar-close").click(); await ui.settle();
  assert.equal(ui.calls.length, 0);
});

test("closing a deletion records the answer date, the erasure result and the proof", async (t) => {
  const outcome = { kind: "answered", answered_on: "2026-10-04", erasure: "erased", reference: "ticket 9" };
  const ui = await fixture({
    formValues: [{ kind: "answered" }, { answered_on: "2026-10-04", erasure: "erased", reference: "ticket 9" }],
    reply: (url) => url.endsWith("/handling/review")
      ? json({ token: "review-1", outcome, summary: "Close DSAR-1 as answered on 2026-10-04." })
      : json({ status: "closed", outcome: { ...outcome, operation_id: "op-1" } }),
  });
  t.after(() => ui.window.close());
  ui.doc.getElementById("dsar-close").click(); await ui.settle();
  const keys = ui.forms[1].fields.map((f) => f.key).join(",");
  assert.equal(keys, "answered_on,erasure,lawful_basis,reference");
  assert.ok(ui.forms[1].fields.find((f) => f.key === "erasure").options.every((o) => !/_/.test(o.label)));
  assert.match(ui.calls[0].url, /\/privacy\/dsar\/DSAR-1\/handling\/review$/);
  assert.deepEqual(JSON.parse(ui.calls[0].body), { outcome });
  assert.deepEqual(ui.confirms, ["Close DSAR-1 as answered on 2026-10-04."]);
  assert.match(ui.calls[1].url, /\/privacy\/dsar\/DSAR-1\/close$/);
  assert.deepEqual(JSON.parse(ui.calls[1].body), { ...outcome, review_token: "review-1" });
  assert.equal(ui.doc.getElementById("dsar-status").textContent, "Your reviewed outcome statement was recorded.");
});

test("keeping someone's data needs the lawful reason before anything is sent", async (t) => {
  const ui = await fixture({
    formValues: [{ kind: "answered" }, { answered_on: "2026-10-04", erasure: "not_erased", reference: "ticket 9" }],
    reply: () => json({}),
  });
  t.after(() => ui.window.close());
  ui.doc.getElementById("dsar-close").click(); await ui.settle();
  assert.equal(ui.calls.length, 0);
  assert.match(ui.doc.getElementById("dsar-status").textContent, /lawful reason/);
});

test("a refused close says what is missing in plain words", async (t) => {
  const ui = await fixture({
    formValues: [{ kind: "refused" }, { answered_on: "2026-10-04", lawful_basis: "x", reference: "y" }],
    reply: () => json({ detail: "The answer date cannot be in the future." }, 422),
  });
  t.after(() => ui.window.close());
  ui.doc.getElementById("dsar-close").click(); await ui.settle();
  assert.equal(ui.doc.getElementById("dsar-status").textContent,
    "Could not review the complete outcome. The answer date cannot be in the future.");
});

test("a list's Close link opens the close form on arrival", async (t) => {
  const ui = await fixture({ formValues: [null], reply: () => json({}), hash: "#close" });
  t.after(() => ui.window.close());
  await ui.settle();
  assert.equal(ui.forms.length, 1);
  assert.equal(ui.forms[0].title, "Close this request");
});

const sendMarkup = `<div id="dsar-page" data-request-id="DSAR-1" data-kind="access" data-fulfillment-state="off">
<div id="dsar-status"></div><button class="dsar-send" data-kind="completion"></button>
<button class="dsar-send" data-kind="acknowledgement"></button></div>`;

test("the completion notice says where its secure link comes from", async (t) => {
  const ui = await fixture({ formValues: [null], reply: () => json({}), markup: sendMarkup });
  t.after(() => ui.window.close());
  ui.doc.querySelector('[data-kind="completion"]').click(); await ui.settle();
  const link = ui.forms[0].fields.find((f) => f.key === "secure_link");
  assert.doesNotMatch(link.label + link.help, /step 3/);
  assert.match(link.help, /turn on answering data requests/);
});

test("an unsent notice says why and what to do next, without setting names", async (t) => {
  const ui = await fixture({
    formValues: [], markup: sendMarkup,
    reply: () => json({ sent: false, reason: "no sending account configured ([email] / EMAIL_USER)",
      problem: "Lightwork has no email account to send from.", next_step: "Contact the requester another way." }),
  });
  t.after(() => ui.window.close());
  ui.doc.querySelector('[data-kind="acknowledgement"]').click(); await ui.settle();
  const status = ui.doc.getElementById("dsar-status").textContent;
  assert.equal(status, "Notice not sent. Lightwork has no email account to send from. Contact the requester another way.");
});

test("the search checklist counts what Lightwork holds, including conversations and goals", async (t) => {
  const ui = await fixture({ formValues: [], reply: () => json({
    platform_holdings: { enabled: true, resolved: true, sections: { conversations: 2, goals: 1, facts: 0, fact_history: 0, audit: 4 } },
    data_map: { enabled: false }, processors: { enabled: false }, documents: { enabled: false } }) });
  t.after(() => ui.window.close());
  ui.doc.getElementById("dsar-worksheet").click(); await ui.settle();
  assert.match(ui.doc.getElementById("dsar-worksheet-result").textContent, /Lightwork itself: 7 record\(s\) found\./);
});

test("the search checklist does not report zero records when the person could not be matched", async (t) => {
  const ui = await fixture({ formValues: [], reply: () => json({
    platform_holdings: { enabled: true, resolved: false, sections: { conversations: 0, goals: 0, facts: 0, fact_history: 0, audit: 0 } },
    data_map: { enabled: false }, processors: { enabled: false }, documents: { enabled: false } }) });
  t.after(() => ui.window.close());
  ui.doc.getElementById("dsar-worksheet").click(); await ui.settle();
  const text = ui.doc.getElementById("dsar-worksheet-result").textContent;
  assert.match(text, /could not match this person to one account/);
  assert.doesNotMatch(text, /0 record\(s\)/);
});
