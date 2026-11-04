// Run with: node --test packages/maverick-dashboard/tests/js/business_agent_collision.test.js
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const source = fs.readFileSync(path.join(__dirname, "../../maverick_dashboard/static/lightwork-business-agent.js"), "utf8");

test("a matching specialist name is explained before any draft is shown", async t => {
  const dom = new JSDOM(`<details id="biz-setup"><form id="biz-form">
    <input id="biz-name" value="HR Screening"><textarea id="biz-what"></textarea>
    <input id="biz-industry"><select id="biz-ai"><option value="plain" selected>Standard outline</option></select>
    <button id="biz-draft" type="submit">Draft</button></form>
    <p id="biz-status" tabindex="-1"></p><div id="biz-review" hidden>
    <div id="biz-summary"></div><input id="biz-docs" type="file">
    <button id="biz-approve"></button><button id="biz-discard"></button></div></details>`,
  { url: "https://lightwork.test/agents", runScripts: "outside-only" });
  t.after(() => dom.window.close());
  const w = dom.window;
  const calls = [];
  const detail = "A specialist called “HR Screening” already exists. Choose another name for the new agent. The existing specialist and its safeguards have not changed.";
  w.fetch = async (url, options) => {
    calls.push({ url, options });
    return { ok: false, status: 409, json: async () => ({ detail }) };
  };
  shell(w);
  w.eval(source);
  w.document.getElementById("biz-form").dispatchEvent(new w.Event("submit", { cancelable: true }));
  for (let i = 0; i < 6; i += 1) await new Promise(resolve => setImmediate(resolve));

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "/api/v1/agents/business-setup/draft");
  assert.equal(w.document.getElementById("biz-status").textContent, detail);
  assert.equal(w.document.getElementById("biz-review").hidden, true);
  assert.equal(w.document.activeElement.id, "biz-status");
});
