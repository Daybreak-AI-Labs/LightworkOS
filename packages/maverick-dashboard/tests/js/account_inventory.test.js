"use strict";
// The account inventory status line says what a turned-off source means in
// plain words ("Automation accounts are turned off"), never a raw state such
// as "Account coverage is incomplete. Automation accounts: disabled".
// Run with: node --test tests/js/account_inventory.test.js
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const {JSDOM} = require("jsdom");
const source = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-account-inventory.js"), "utf8");
const flush = async () => { for (let i = 0; i < 12; i++) await new Promise(setImmediate); };

async function statusFor(body) {
  const dom = new JSDOM(`<ul id="account-inventory-list"></ul><p id="account-inventory-status"></p>
    <button id="account-inventory-refresh"></button>`, {url: "https://fixture.invalid/automations", runScripts: "outside-only"});
  dom.window.fetch = async () => ({ok: true, status: 200, json: async () => body});
  dom.window.eval(source);
  await flush();
  return dom.window.document.getElementById("account-inventory-status").textContent;
}

test("a turned-off source is named in plain words", async () => {
  const text = await statusFor({accounts: [], context: "c", coverage: [
    {domain: "Named connections", state: "available"}, {domain: "Automation accounts", state: "disabled"}]});
  assert.equal(text, "No accounts are connected. Automation accounts are turned off.");
  assert.doesNotMatch(text, /coverage is incomplete|: disabled/);
});

test("an unreadable source says some accounts could not be listed", async () => {
  const text = await statusFor({accounts: [], context: "c", coverage: [
    {domain: "Named connections", state: "unavailable"}, {domain: "Automation accounts", state: "administrator-only"}]});
  assert.equal(text, "Some accounts could not be listed. Named connections could not be read right now. "
    + "Automation accounts are shown only to administrators.");
});
