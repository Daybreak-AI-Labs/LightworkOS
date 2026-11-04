"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const folder = path.resolve(__dirname, "../../maverick_dashboard");
const source = fs.readFileSync(path.join(folder, "static/lightwork-code.js"), "utf8");
const page = fs.readFileSync(path.join(folder, "templates/code.html"), "utf8");
const watch = page.slice(page.indexOf('<section class="panel" aria-labelledby="code-watch-title"'),
  page.indexOf("</section>", page.indexOf('id="code-watch"')) + 10);
const html = `<div id="ic-root" data-console="code" data-api-url="/api/v1/code/summary" data-can-admin="true" data-enabled="true">
<p id="ic-status"></p><p id="ic-error"></p>
<strong id="ic-repos"></strong><strong id="ic-pending"></strong><strong id="ic-approved"></strong><strong id="ic-merged"></strong>
<table><tbody id="ic-repo-rows"></tbody></table>${watch}<table><tbody id="ic-prop-rows"></tbody></table></div>`;

const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
const SUMMARY = { enabled: true, proposals: [],
  repos: [{ name: "website", default_branch: "main", protect: "block", tests: true, updated_at: 1700000000 }] };
const NOTE = { id: "n1", file: "app.py", line: 2, note: "add input validation", title: "website: add input validation",
  task: "In the website code project.\nFrom app.py:2 (marker AI:)\n\nadd input validation" };

async function fixture({ confirm = true, watching = [] } = {}) {
  const dom = new JSDOM(html, { url: "https://lightwork.example/code", runScripts: "outside-only" });
  const { window } = dom;
  const calls = [], confirms = [];
  window.mvConfirm = async (message) => { confirms.push(message); return confirm; };
  window.mvErrorText = (failure, action) => `Could not ${action}.`;
  window.mvPlainDetail = () => "";
  window.mvHuman = (v) => String(v);
  window.mvWhen = () => "today";
  window.mvToast = () => {};
  window.URL.createObjectURL = () => "blob:x";
  window.URL.revokeObjectURL = () => {};
  window.fetch = async (url, options = {}) => {
    calls.push({ url, method: options.method || "GET", body: options.body ? JSON.parse(options.body) : undefined });
    if (url.endsWith("/summary")) return json(SUMMARY);
    if (url.endsWith("/code/watch")) return json({ watching });
    if (url.includes("/notes/")) return json({ started: true, repo: "website", protect: "block" }, 202);
    if (url.endsWith("/start")) { watching = [{ repo: "website", state: "watching", reason: "", notes: [NOTE], last_scan: 1 }]; return json(watching[0], 202); }
    if (url.endsWith("/stop")) { watching = [{ ...watching[0], state: "stopped", reason: "Stopped." }]; return json(watching[0]); }
    if (url.endsWith("/export")) return new Response("zip", { status: 200, headers: { "Content-Type": "application/zip" } });
    if (url === "/api/v1/goals") return json({ id: 41, title: NOTE.title }, 201);
    return json({});
  };
  const settle = async () => { for (let i = 0; i < 20; i++) await new Promise((done) => setImmediate(done)); };
  shell(window);
  window.eval(source);
  await settle();
  return { window, doc: window.document, calls, confirms, settle };
}
const button = (root, text) => [...root.querySelectorAll("button")].find((b) => b.textContent === text);

test("download a copy asks first and posts the confirmation", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  button(ui.doc.getElementById("ic-repo-rows"), "Download a copy").click();
  await ui.settle();
  assert.match(ui.confirms[0], /not protected/);
  const exp = ui.calls.find((c) => c.url.endsWith("/export"));
  assert.equal(exp.url, "/api/v1/code/repos/website/export");
  assert.deepEqual(exp.body, { confirm: true });
  assert.match(ui.doc.getElementById("ic-status").textContent, /Downloaded a copy of website/);
});

test("a cancelled download does nothing", async (t) => {
  const ui = await fixture({ confirm: false });
  t.after(() => ui.window.close());
  button(ui.doc.getElementById("ic-repo-rows"), "Download a copy").click();
  await ui.settle();
  assert.equal(ui.calls.filter((c) => c.url.endsWith("/export")).length, 0);
});

test("watching lists the notes, and a note starts protected work after confirmation", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  const list = ui.doc.getElementById("code-watch-list");
  assert.match(list.textContent, /not watching any code project/);
  const pick = ui.doc.getElementById("code-watch-repo");
  assert.equal(pick.options.length, 2);
  pick.value = "website";
  ui.doc.getElementById("code-watch-start").click();
  await ui.settle();
  assert.match(ui.confirms[0], /Nothing runs until you start a task from a note/);
  assert.deepEqual(ui.calls.find((c) => c.url.endsWith("/start")).body, { confirm: true });
  assert.match(list.textContent, /website · Watching/);
  assert.match(list.textContent, /add input validationapp\.py, line 2/);
  button(list, "Start a task from this note").click();
  await ui.settle();
  assert.match(ui.confirms[1], /within your spending limits/);
  // Never an ordinary task: the note runs on a private copy under the
  // project's own protection, and any change waits for approval.
  assert.match(ui.confirms[1], /under its protection \(Code never leaves Lightwork\)/);
  assert.match(ui.confirms[1], /waits for your approval/);
  assert.equal(ui.calls.filter((c) => c.url === "/api/v1/goals").length, 0);
  const work = ui.calls.find((c) => c.url.includes("/notes/"));
  assert.equal(work.url, "/api/v1/code/watch/website/notes/n1/start");
  assert.deepEqual(work.body, { confirm: true });
  assert.match(ui.doc.getElementById("ic-status").textContent, /Started work on the note/);
  button(list, "Stop watching").click();
  await ui.settle();
  assert.match(list.textContent, /website · Stopped/);
});
