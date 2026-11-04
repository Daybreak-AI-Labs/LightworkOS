"use strict";
// Settings > All settings: a shorter keep period for records shows, before
// saving, how many records the next clean-up would delete (a trial run), and
// that nothing changes until Save.
// Run with: node --test tests/js/settings_all_retention_preview.test.js
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const {JSDOM} = require("jsdom");
const root = path.resolve(__dirname, "../../maverick_dashboard");
const flush = async () => { for (let i = 0; i < 20; i++) { await new Promise(setImmediate); await new Promise(r => setTimeout(r, 2)); } };

const HTML = `<!doctype html><main>
<div role="status" id="settings-all-status" hidden></div>
<input id="settings-all-search"><select id="settings-all-group"><option value="">All</option></select>
<input type="checkbox" id="settings-all-changed"><p id="settings-all-filter-status"></p>
<div id="settings-all-groups"><section class="settings-all-group" data-group="data-retention"><h2>Data retention</h2>
 <div class="settings-all-row" data-setting-id="retention.events_days" data-control="number" data-source="default" data-search="keep">
  <strong data-value-text>Not set</strong><span data-source-text>Default</span>
  <input type="number" data-input data-preview-url="/api/v1/settings/catalog/preview/retention.events_days">
  <div data-preview></div>
  <button data-save>Save</button><button data-reset>Reset to default</button><p data-row-status></p></div>
</section></div><p id="settings-all-empty" hidden></p></main>`;

test("a keep period shows what the next clean-up would delete, and saves nothing", async () => {
  const dom = new JSDOM(HTML, {url: "https://lightwork.test/settings/all", runScripts: "outside-only"});
  const w = dom.window, calls = [];
  w.mvErrorText = (failure, action) => "Could not " + action + ".";
  w.mvToast = () => {};
  w.fetch = async (url, init = {}) => {
    calls.push({url, method: init.method || "GET"});
    return {ok: true, status: 200, headers: {get: () => null}, json: async () => ({kind: "retention", key: "events_days", days: 30,
      count: 412, unit: "task progress updates", basis: "Counted by a trial run of the clean-up that deletes them. Nothing was deleted."})};
  };
  w.eval(fs.readFileSync(path.join(root, "static/lightwork-settings-all.js"), "utf8"));
  await flush();
  const row = w.document.querySelector('[data-setting-id="retention.events_days"]');
  const input = row.querySelector("[data-input]");
  input.value = "30";
  input.dispatchEvent(new w.Event("change", {bubbles: true}));
  await flush();
  const text = row.querySelector("[data-preview]").textContent.replace(/\s+/g, " ");
  assert.equal(calls[0].url, "/api/v1/settings/catalog/preview/retention.events_days?value=30");
  assert.match(text, /At the next clean-up, 412 task progress updates older than 30 days would be deleted\./);
  assert.match(text, /Nothing was deleted\./);
  assert.match(text, /Preview only\. Nothing changes until you save\./);
  assert.equal(calls.filter(c => c.method !== "GET").length, 0, "nothing is saved");
  w.close();
});
