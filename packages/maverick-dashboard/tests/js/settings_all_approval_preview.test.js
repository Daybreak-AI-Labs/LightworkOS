"use strict";
// Settings > All settings: choosing a level for "Actions that can't be undone"
// (the approval threshold) shows, before saving, how many recorded actions by
// how many agents and specialists would have needed approval at that level in
// the last 30 days -- or that there is not enough history yet.
// Run with: node --test tests/js/settings_all_approval_preview.test.js
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const {JSDOM} = require("jsdom");
const root = path.resolve(__dirname, "../../maverick_dashboard");
const read = name => fs.readFileSync(path.join(root, name), "utf8");
const flush = async () => { for (let i = 0; i < 20; i++) { await new Promise(setImmediate); await new Promise(r => setTimeout(r, 2)); } };
const reply = (status, body) => ({ok: status < 400, status, headers: {get: () => null}, json: async () => body});

const HTML = `<!doctype html><main>
<div role="status" id="settings-all-status" hidden></div>
<input id="settings-all-search"><select id="settings-all-group"><option value="">All</option></select>
<input type="checkbox" id="settings-all-changed"><p id="settings-all-filter-status"></p>
<div id="settings-all-groups"><section class="settings-all-group" data-group="safety"><h2>Safety</h2>
 <div class="settings-all-row" data-setting-id="safety.consent_mode" data-control="select" data-source="default" data-search="approval threshold">
  <strong data-value-text>Ask for risky ones, allow the rest (default)</strong><span data-source-text>Default</span>
  <select data-input data-preview-url="/api/v1/settings/catalog/preview/safety.consent_mode" data-preview-any>
   <option value="" selected>Ask for risky ones, allow the rest (default)</option><option value="ask">Ask a person each time</option>
   <option value="auto-deny">Refuse them all</option></select>
  <div data-preview></div>
  <button data-save>Save</button><button data-reset>Reset to default</button><p data-row-status></p></div>
</section></div><p id="settings-all-empty" hidden></p></main>`;

async function page(handler) {
  const dom = new JSDOM(HTML, {url: "https://lightwork.test/settings/all", runScripts: "outside-only"});
  const w = dom.window, calls = [];
  w.mvErrorText = (failure, action) => "Could not " + action + ".";
  w.mvToast = () => {};
  w.mvFormatTimes = root => root.querySelectorAll("time[data-mv-time]").forEach(t => { t.textContent = "4 Sep 2026"; });
  w.fetch = async (url, init = {}) => { calls.push({url, method: init.method || "GET"}); return handler(url); };
  w.eval(read("static/lightwork-settings-all.js"));
  await flush();
  const row = w.document.querySelector('[data-setting-id="safety.consent_mode"]');
  return {w, calls, row, select: row.querySelector("[data-input]"), box: row.querySelector("[data-preview]")};
}
async function choose(ui, value) {
  ui.select.value = value;
  ui.select.dispatchEvent(new ui.w.Event("change", {bubbles: true}));
  await flush();
  return ui.box.textContent.replace(/\s+/g, " ").trim();
}

test("a level with enough history says how many actions by how many agents and specialists would have needed approval", async () => {
  const ui = await page(() => reply(200, {kind: "approval_checks", enough: true, days: 30, actions: 22, agents: 2, refused: 0,
    checks: 22, recorded: {asked: 6, allowed: 14, refused: 2}, recording_started_at: 1788000000, recording_on: true, minimum: 20}));
  try {
    const text = await choose(ui, "ask");
    assert.equal(ui.calls[0].url, "/api/v1/settings/catalog/preview/safety.consent_mode?value=ask");
    assert.match(text, /In the last 30 days, 22 actions by 2 agents and specialists would have needed approval at this level\./);
    assert.match(text, /6 went to a person, 14 went ahead without asking and 2 were refused/);
    assert.match(text, /Preview only\. Nothing changes until you save\./);
    assert.equal(ui.calls.filter(c => c.method !== "GET").length, 0, "nothing is saved");
  } finally { ui.w.close(); }
});

test("the default level is previewed too, and singular counts read naturally", async () => {
  const ui = await page(() => reply(200, {kind: "approval_checks", enough: true, days: 30, actions: 1, agents: 1, refused: 0,
    checks: 25, recorded: {asked: 1, allowed: 24, refused: 0}, recording_started_at: 1788000000, recording_on: true, minimum: 20}));
  try {
    await choose(ui, "ask");
    const text = await choose(ui, "");
    assert.equal(ui.calls.at(-1).url, "/api/v1/settings/catalog/preview/safety.consent_mode?value=");
    assert.match(text, /1 action by 1 agent or specialist would have needed approval at this level\./);
  } finally { ui.w.close(); }
});

test("refusing everything says how many would have been refused", async () => {
  const ui = await page(() => reply(200, {kind: "approval_checks", enough: true, days: 30, actions: 0, agents: 0, refused: 22,
    checks: 22, recorded: {asked: 6, allowed: 14, refused: 2}, recording_started_at: 1788000000, recording_on: true, minimum: 20}));
  try {
    const text = await choose(ui, "auto-deny");
    assert.match(text, /no actions would have needed approval at this level\. 22 would have been refused\./i);
  } finally { ui.w.close(); }
});

test("under 30 days of records it says when recording started instead of a count", async () => {
  const ui = await page(() => reply(200, {kind: "approval_checks", enough: false, reason: "history", days: 30, checks: 40,
    recording_started_at: 1788000000, recording_on: true, minimum: 20}));
  try {
    const text = await choose(ui, "ask");
    assert.match(text, /Not enough recorded checks yet: recording started 4 Sep 2026; a preview needs 30 days\./);
    assert.ok(ui.box.querySelector('time[data-mv-time="1788000000"][data-mv-time-mode="date"]'));
    assert.doesNotMatch(text, /would have needed approval/);
  } finally { ui.w.close(); }
});

test("too few checks, or none at all, is said plainly", async () => {
  let body = {kind: "approval_checks", enough: false, reason: "count", days: 30, checks: 3,
    recording_started_at: 1788000000, recording_on: true, minimum: 20};
  const ui = await page(() => reply(200, body));
  try {
    let text = await choose(ui, "ask");
    assert.match(text, /Not enough recorded checks yet: recording started 4 Sep 2026; a preview needs 30 days and at least 20 checks \(3 so far in the last 30 days\)\./);
    body = {kind: "approval_checks", enough: false, reason: "history", days: 30, checks: 0,
      recording_started_at: null, recording_on: false, minimum: 20};
    text = await choose(ui, "auto-deny");
    assert.match(text, /Not enough recorded checks yet: none have been recorded; a preview needs 30 days\./);
    assert.match(text, /Keep a record of approval checks is off/);
  } finally { ui.w.close(); }
});
