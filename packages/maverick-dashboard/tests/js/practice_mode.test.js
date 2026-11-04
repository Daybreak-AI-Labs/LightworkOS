"use strict";
// Practice mode: the banner's Back to live and "What practice held back",
// and the Get started switch, through the shared shell helpers.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM, VirtualConsole } = require("jsdom");
const { shell } = require("./_shell");

const script = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-practice.js"), "utf8");
const banner = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates/_practice_banner.html"), "utf8")
  .replace(/\{#[\s\S]*?#\}/g, "").replace(/\{%[\s\S]*?%\}/g, "");

function page(markup, answers) {
  // jsdom does not navigate; a reload shows up as its "not implemented" notice.
  let reloads = 0;
  const virtualConsole = new VirtualConsole();
  virtualConsole.on("jsdomError", (error) => { if (/navigation/i.test(String(error && error.message))) reloads += 1; });
  const dom = new JSDOM(markup, { url: "https://lightwork.example/today", runScripts: "outside-only", virtualConsole });
  const w = dom.window;
  shell(w);
  const calls = [];
  w.fetch = async (url, init = {}) => {
    calls.push({ url, method: init.method || "GET", body: init.body ? JSON.parse(init.body) : null });
    const [status, body] = answers[(init.method || "GET") + " " + url] || [404, { detail: "Not found" }];
    return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  };
  w.eval(script);
  const settle = async () => { for (let i = 0; i < 30; i++) await new Promise((r) => setImmediate(r)); };
  return { w, doc: w.document, calls, settle, reloads: () => reloads };
}

test("Back to live turns practice off and reloads every screen in live mode", async (t) => {
  const ui = page(banner, { "POST /api/v1/practice": [200, { on: false, available: true, reason: "" }] });
  t.after(() => ui.w.close());
  ui.doc.querySelector("[data-practice-leave]").click();
  await ui.settle();
  assert.deepEqual(ui.calls.map((c) => [c.method, c.url, c.body]), [["POST", "/api/v1/practice", { on: false }]]);
  assert.equal(ui.reloads(), 1);
});

test("what practice held back is listed, each row linked to its practice task", async (t) => {
  const ui = page(banner, { "GET /api/v1/practice": [200, { on: true, available: true, reason: "", outbox: [
    { at: 1700000000, kind: "tool", name: "send_email", detail: "{\"to\": \"pat@example.com\"}", goal_id: 4 },
    { at: 1700000100, kind: "webhook", name: "goal.finished", detail: "{}", goal_id: null }] }] });
  t.after(() => ui.w.close());
  const button = ui.doc.querySelector("[data-practice-outbox]");
  button.click();
  await ui.settle();
  const box = ui.doc.getElementById("practice-outbox");
  assert.equal(box.hidden, false);
  assert.equal(button.getAttribute("aria-expanded"), "true");
  const rows = box.querySelectorAll("tbody tr");
  assert.equal(rows.length, 2);
  assert.match(rows[0].textContent, /Use send email/);
  assert.equal(rows[0].querySelector("a").getAttribute("href"), "/chat/goal/4");
  button.click();
  assert.equal(box.hidden, true);
});

test("an empty outbox explains what will appear there", async (t) => {
  const ui = page(banner, { "GET /api/v1/practice": [200, { on: true, available: true, reason: "", outbox: [] }] });
  t.after(() => ui.w.close());
  ui.doc.querySelector("[data-practice-outbox]").click();
  await ui.settle();
  assert.match(ui.doc.getElementById("practice-outbox").textContent, /Nothing was held back yet/);
});

test("a refused start says why and leaves the person live", async (t) => {
  const markup = '<button data-practice-start data-practice-status="s">Start practice mode</button><p id="s" role="status"></p>';
  const ui = page(markup, { "POST /api/v1/practice": [409, { detail: "Practice mode is turned off in Settings." }] });
  t.after(() => ui.w.close());
  const start = ui.doc.querySelector("[data-practice-start]");
  start.click();
  await ui.settle();
  assert.equal(ui.reloads(), 0);
  assert.match(ui.doc.getElementById("s").textContent, /turned off in Settings/);
  assert.equal(start.disabled, false);
});

test("the panel also lists what practice can't do, and why", async (t) => {
  const ui = page(banner, { "GET /api/v1/practice": [200, { on: true, available: true, reason: "", outbox: [], blocked: [
    { what: "Sharing a practice result", why: "Practice results can't be shared: share links and gists are for real results." },
    { what: "Changing settings or spending limits", why: "Settings apply to everyone's live work." }] }] });
  t.after(() => ui.w.close());
  ui.doc.querySelector("[data-practice-outbox]").click();
  await ui.settle();
  const box = ui.doc.getElementById("practice-outbox");
  assert.match(box.querySelector("h2, h3").textContent, /What you can't do in practice/);
  const items = [...box.querySelectorAll("li")].map((li) => li.textContent);
  assert.deepEqual(items, ["Sharing a practice result: Practice results can't be shared: share links and gists are for real results.",
    "Changing settings or spending limits: Settings apply to everyone's live work."]);
});

test("a failed Back to live says why on the stopped marker too", async (t) => {
  const stopped = banner.slice(banner.lastIndexOf("<div id=\"practice-banner\""));
  const ui = page(stopped, { "POST /api/v1/practice": [503, { detail: "Try again shortly." }] });
  t.after(() => ui.w.close());
  const leave = ui.doc.querySelector("[data-practice-leave]");
  leave.click();
  await ui.settle();
  assert.equal(ui.reloads(), 0);
  assert.match(ui.doc.querySelector("[data-practice-status]").textContent, /\S/);
  assert.equal(leave.disabled, false);
});
