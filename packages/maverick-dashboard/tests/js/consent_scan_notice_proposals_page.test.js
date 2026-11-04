// Run with: node --test packages/maverick-dashboard/tests/js/consent_scan_notice_proposals_page.test.js
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const root = path.resolve(__dirname, "../../maverick_dashboard");
const read = (name) => fs.readFileSync(path.join(root, name), "utf8").replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
const flush = async () => { for (let i = 0; i < 40; i++) { await new Promise(setImmediate); await new Promise((r) => setTimeout(r, 2)); } };
const reply = (status, body) => ({ ok: status < 400, status, json: async () => body });

function rows(role) {
  return [
    { proposal_id: "CSNP-2", version: 2, action: "reconcile", state: "approved", revision: 2, created_at: 1800000100, disclosure_count: 3, classification_counts: { analytics: 2, advertising: 1 }, created_by_me: role === "creator", approval: { revision: 1, revoked: false, approved_by_me: role === "approver" }, is_current: true, is_effective: false },
    { proposal_id: "CSNP-1", version: 1, action: "desired", state: "locally_accepted", revision: 3, created_at: 1800000000, disclosure_count: 2, classification_counts: { analytics: 2 }, created_by_me: false, approval: { revision: 1, revoked: false, approved_by_me: false }, is_current: false, is_effective: true },
  ];
}

async function page(role, options = {}) {
  const html = read("templates/consent_scan_notice_proposals.html").replace(/\{%[\s\S]*?%\}/g, "").replace(/\{\{[\s\S]*?\}\}/g, "");
  const dom = new JSDOM(html, { url: "https://lightwork.test/consent/scan-notice-proposals", runScripts: "outside-only" });
  const w = dom.window, d = w.document, calls = [], confirms = [];
  Object.defineProperty(w, "crypto", { value: crypto.webcrypto });
  w.TextEncoder = TextEncoder;
  Object.assign(d.getElementById("csnp-root").dataset, { enabled: "true", canAdmin: "true" });
  d.querySelectorAll("button").forEach((n) => { n.disabled = false; });
  w.mvConfirm = async (message) => { confirms.push(message); return true; };
  w.mvErrorText = (_f, action) => "Could not " + action + ".";
  w.fetch = async (url, init = {}) => {
    const method = init.method || "GET", body = init.body ? JSON.parse(init.body) : null;
    calls.push({ url, method, body });
    if (url.includes("/proposals?")) return reply(200, { head_revision: 5, items: options.items || rows(role) });
    if (options.conflict && method === "POST") return reply(409, { detail: "scan disclosure-proposal state conflict" });
    return reply(200, {});
  };
  shell(w);
  w.eval(read("static/lightwork-consent-workbench.js"));
  [...read("templates/consent_scan_notice_proposals.html").matchAll(/<script>([\s\S]*?)<\/script>/g)].forEach((m) => w.eval(m[1]));
  await flush();
  const labels = () => [...d.querySelectorAll("#csnp-list tbody tr")].map((tr) => [...tr.querySelectorAll("button")].map((b) => b.textContent));
  const button = (label) => [...d.querySelectorAll("#csnp-list button")].find((b) => b.textContent === label);
  return { dom, w, d, calls, confirms, labels, button, posts: () => calls.filter((c) => c.method === "POST") };
}

test("each person sees only the steps they may take", async () => {
  const creator = await page("creator");
  try {
    assert.match(creator.d.getElementById("csnp-list").textContent, /#2 – Update.*3 trackers \(2 analytics, 1 advertising\).*Approved – waiting to be accepted/);
    assert.deepEqual(creator.labels()[0], ["What changes"]);
    assert.match(creator.d.getElementById("csnp-list").textContent, /In use/);
  } finally { creator.dom.window.close(); }
  const approver = await page("approver");
  try { assert.deepEqual(approver.labels()[0], ["What changes", "Withdraw my approval"]); } finally { approver.dom.window.close(); }
  const third = await page("third");
  try { assert.deepEqual(third.labels()[0], ["What changes", "Accept"]); } finally { third.dom.window.close(); }
});

test("accepting confirms and carries the row and head versions", async () => {
  const ui = await page("third");
  try {
    ui.button("Accept").click();
    await flush();
    assert.match(ui.confirms[0], /Your website and notice text are not changed/);
    const sent = ui.posts().find((c) => c.url.endsWith("/proposals/CSNP-2/accept-local"));
    assert.equal(sent.body.expected_proposal_revision, 2);
    assert.equal(sent.body.expected_head_revision, 5);
    assert.equal(sent.body.acknowledge_local_baseline_only, true);
    assert.ok(sent.body.idempotency_key);
  } finally { ui.dom.window.close(); }
});

test("withdrawing an approval carries both versions", async () => {
  const ui = await page("approver");
  try {
    ui.button("Withdraw my approval").click();
    await flush();
    const sent = ui.posts().find((c) => c.url.endsWith("/approval/revoke"));
    assert.equal(sent.body.expected_proposal_revision, 2);
    assert.equal(sent.body.expected_approval_revision, 1);
  } finally { ui.dom.window.close(); }
});

test("creating a suggestion uses the head version and explains conflicts plainly", async () => {
  const ui = await page("creator", { items: [], conflict: true });
  try {
    ui.d.getElementById("csnp-new").click();
    await flush();
    const sent = ui.posts()[0];
    assert.equal(sent.body.expected_head_revision, 5);
    assert.match(ui.d.getElementById("csnp-status").textContent, /Someone else made one since you opened the page/);
    assert.doesNotMatch(ui.d.getElementById("csnp-status").textContent, /state conflict/);
  } finally { ui.dom.window.close(); }
});
