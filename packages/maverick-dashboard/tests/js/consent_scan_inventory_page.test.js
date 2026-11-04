// Run with: node --test packages/maverick-dashboard/tests/js/consent_scan_inventory_page.test.js
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
const flush = async () => { for (let i = 0; i < 60; i++) { await new Promise(setImmediate); await new Promise((r) => setTimeout(r, 2)); } };
const reply = (status, body) => ({ ok: status < 400, status, json: async () => body });
const KEY = "a".repeat(64);
const FUTURE = Date.now() / 1000 + 86400;

async function page() {
  const html = read("templates/consent_scan_inventory.html").replace(/\{%[\s\S]*?%\}/g, "").replace(/\{\{[\s\S]*?\}\}/g, "");
  const dom = new JSDOM(html, { url: "https://lightwork.test/consent/scan-inventory", runScripts: "outside-only" });
  const w = dom.window, d = w.document, calls = [], confirms = [];
  Object.defineProperty(w, "crypto", { value: crypto.webcrypto });
  w.TextEncoder = TextEncoder;
  Object.assign(d.getElementById("csi-root").dataset, { enabled: "true", canAdmin: "true", canAudit: "true" });
  d.querySelectorAll("button,fieldset").forEach((n) => { n.disabled = false; });
  w.mvConfirm = async (message) => { confirms.push(message); return true; };
  w.mvErrorText = (_f, action) => "Could not " + action + ".";
  w.fetch = async (url, init = {}) => {
    const method = init.method || "GET", body = init.body ? JSON.parse(init.body) : null;
    calls.push({ url, method, body });
    if (url.startsWith("/api/v1/consent/trackers")) return reply(200, { trackers: [{ tracker_id: "site-analytics", vendor_id: "example-analytics", revision: 4 }] });
    if (url.startsWith("/api/v1/consent/policies")) return reply(200, { policies: [{ policy_id: "main", version: 1, purposes: { analytics: "consent" } }] });
    const p = url.replace("/api/v1/consent/scan-inventory", "");
    if (p.startsWith("/properties?")) return reply(200, { items: [{ property_id: "main-website", origins: ["https://www.example.com"], start_urls: ["https://www.example.com/"], revision: 2 }] });
    if (p.startsWith("/schedules?")) return reply(200, { items: [{ schedule_id: "main-website-schedule", property_id: "main-website", interval_seconds: 604800, next_due_at: FUTURE, enabled: true, revision: 1, limits: {}, max_attempts: 3 }] });
    if (p.startsWith("/jobs?")) return reply(200, { items: [{ job_id: "CSI-JOB-1", property_id: "main-website", scheduled_for: 1800000000, status: "dead_letter", attempts: 3, max_attempts: 3, revision: 5 }] });
    if (p.startsWith("/reports?")) return reply(200, { items: [{ report_id: "R-1", property_id: "main-website", completed_at: 1800000000, pages_captured: 3, pages_attempted: 3, finding_count: 1, coverage: { coverage_complete: true } }] });
    if (p.startsWith("/review-requests?")) return reply(200, { items: [
      { request_id: "CSRR-1", property_id: "main-website", status: "pending", requested_by_me: true, created_at: 1800000000, payload: { classification: "analytics", registry_action: "approved", tracker_id: "site-analytics", vendor_id: "example-analytics" } },
      { request_id: "CSRR-2", property_id: "main-website", status: "pending", requested_by_me: false, created_at: 1800000000, payload: { classification: "advertising", registry_action: "blocked", tracker_id: "ads", vendor_id: "ads-co" } },
    ] });
    if (p.includes("/discoveries?")) return reply(200, { items: [{ property_id: "main-website", tracker_key: KEY, last_report_id: "R-1", last_seen_at: 1800000000 }] });
    if (p.includes("/reviews?")) return reply(200, { items: [] });
    if (p === "/reports/R-1") return reply(200, { scanner_report: { findings: [{ tracker_key: KEY, host: "tags.example-analytics.com", kind: "network", first_party: false }] } });
    if (p.endsWith("/scan-now")) return reply(200, { outcomes: [{ succeeded: true, property_id: "main-website", coverage: { coverage_complete: false } }] });
    return reply(200, {});
  };
  shell(w);
  w.eval(read("static/lightwork-consent-workbench.js"));
  [...read("templates/consent_scan_inventory.html").matchAll(/<script>([\s\S]*?)<\/script>/g)].forEach((m) => w.eval(m[1]));
  await flush();
  const button = (host, label) => [...d.querySelectorAll("#" + host + " button")].find((b) => b.textContent === label);
  return { dom, w, d, calls, confirms, button, posts: () => calls.filter((c) => c.method !== "GET") };
}

test("websites, scans and waiting reviews load as plain rows", async () => {
  const ui = await page();
  try {
    assert.match(ui.d.getElementById("csi-sites").textContent, /Main website.*https:\/\/www\.example\.com.*Every week/);
    assert.match(ui.d.getElementById("csi-jobs").textContent, /Did not finish/);
    const approvals = [...ui.d.querySelectorAll("#csi-approvals tbody tr")].map((tr) => [...tr.querySelectorAll("button")].map((b) => b.textContent));
    assert.deepEqual(approvals, [["Withdraw"], ["Approve", "Withdraw"]]);
  } finally { ui.dom.window.close(); }
});

test("scan now confirms, runs on the server and explains partial coverage", async () => {
  const ui = await page();
  try {
    ui.button("csi-sites", "Scan now").click();
    await flush();
    assert.match(ui.confirms[0], /Lightwork will visit https:\/\/www\.example\.com/);
    assert.ok(ui.posts().find((c) => c.url.endsWith("/properties/main-website/scan-now")));
    assert.match(ui.d.getElementById("csi-status").textContent, /1 of 1 scans finished\. 1 could not check every page/);
    assert.equal(ui.calls.some((c) => /claim|lease/.test(c.url)), false);
  } finally { ui.dom.window.close(); }
});

test("a registry review is filed for a second person with values from the lists", async () => {
  const ui = await page();
  try {
    ui.button("csi-sites", "Trackers found").click();
    await flush();
    assert.match(ui.d.getElementById("csi-trackers").textContent, /tags\.example-analytics\.com.*Another company.*Not reviewed/);
    ui.button("csi-trackers", "Review").click();
    await flush();
    const form = ui.d.getElementById("csi-review");
    form.elements.registry_action.value = "approved";
    form.elements.registry_action.dispatchEvent(new ui.w.Event("change"));
    form.elements.tracker_id.value = "site-analytics";
    form.elements.tracker_id.dispatchEvent(new ui.w.Event("change"));
    form.elements.vendor_name.value = "Example Analytics";
    form.querySelector("[name=purpose_ids][value=analytics]").checked = true;
    form.dispatchEvent(new ui.w.Event("submit", { bubbles: true, cancelable: true }));
    await flush();
    const sent = ui.posts().find((c) => c.url.endsWith("/discoveries/" + KEY + "/review-requests"));
    assert.ok(sent);
    assert.equal(sent.body.report_id, "R-1");
    assert.equal(sent.body.tracker_id, "site-analytics");
    assert.equal(sent.body.vendor_id, "example-analytics");
    assert.deepEqual(sent.body.purpose_ids, ["analytics"]);
    assert.equal(sent.body.authority_expected_revision, 4);
    assert.equal(sent.body.expected_version, 0);
    assert.equal("second_reviewer_sha256" in sent.body, false);
  } finally { ui.dom.window.close(); }
});

test("retrying a scan carries the row's version", async () => {
  const ui = await page();
  try {
    ui.button("csi-jobs", "Try again").click();
    await flush();
    const sent = ui.posts().find((c) => c.url.endsWith("/dead-letters/CSI-JOB-1/replay"));
    assert.equal(sent.body.expected_revision, 5);
  } finally { ui.dom.window.close(); }
});
