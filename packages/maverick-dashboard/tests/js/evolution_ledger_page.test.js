"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const source = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-evolution-ledger.js"), "utf8");
const html = `<div id="elv-root" data-api-base="/api/v1/audit/evolution-ledger">
<p id="elv-health-detail"></p><button id="elv-refresh">Refresh</button><p id="elv-error"></p>
<strong id="elv-promotions"></strong><strong id="elv-rollbacks"></strong><strong id="elv-entry-count"></strong>
<span id="elv-table-note"></span><table><tbody id="elv-entries"></tbody></table>
<form id="elv-verify-form"><input type="file" id="elv-receipt" name="receipt"><button type="submit">Check</button></form>
<div id="elv-verdict-box" hidden><p id="elv-verdict"></p><p id="elv-verdict-detail"></p></div>
<ul id="elv-limitations"></ul></div>`;

const SNAP = {
  schema: "lightwork.evolution-ledger-dashboard-snapshot.v1",
  sources: { promotion_ledger: "available" },
  projection: { entries: [{ kind: "promotion", occurred_at: 1700000000, integrity: "hash_chained_local_promotion_ledger",
    approval_status: "not_verifiable_without_private_binding", entry_sha256: "a".repeat(64), promotion_receipt_sha256: "b".repeat(64) }],
    entry_count: 1, total_entries: 1, truncated: false, limitations: ["receipt_integrity_is_not_a_human_approval_verification"] }
};

async function fixture(status = 200) {
  const dom = new JSDOM(html, { url: "https://lightwork.example/audit/evolution-ledger", runScripts: "outside-only" });
  const { window } = dom;
  window.mvErrorText = (failure, action) => `Could not ${action}.`;
  window.TextEncoder = TextEncoder; window.TextDecoder = TextDecoder;
  window.mvHuman = (v) => String(v).replace(/_/g, " ");
  window.mvWhen = () => "14 Nov 2023";
  window.fetch = async (url) => new Response(JSON.stringify(url.endsWith("/snapshot") ? SNAP : { receipt_valid: true, approval_status: "verified" }),
    { status, headers: { "Content-Type": "application/json" } });
  const settle = async () => { for (let i = 0; i < 30; i++) await new Promise((done) => setImmediate(done)); };
  window.eval(source);
  await settle();
  return { window, doc: window.document, settle };
}

test("history renders in plain words with fingerprints tucked away", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  const text = ui.doc.getElementById("elv-entries").textContent;
  assert.match(text, /Adopted a learning change/);
  assert.match(text, /Stored chain checks match/);
  assert.match(text, /cannot be confirmed here/);
  assert.ok(ui.doc.querySelector("#elv-entries details summary"));
  assert.equal(ui.doc.querySelector('#elv-entries a').getAttribute('href'),
    '/api/v1/audit/evolution-ledger/entries/' + 'a'.repeat(64) + '/receipt');
  assert.match(ui.doc.getElementById("elv-limitations").textContent, /do not establish who created or approved a receipt/);
});

test("a failed load shows a plain sentence, not a status code", async (t) => {
  const ui = await fixture(500);
  t.after(() => ui.window.close());
  assert.equal(ui.doc.getElementById("elv-error").textContent, "Could not load the learning history.");
});
