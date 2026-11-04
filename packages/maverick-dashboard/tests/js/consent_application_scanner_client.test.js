// Run with: node --test packages/maverick-dashboard/tests/js/consent_application_scanner_client.test.js
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { webcrypto } = require("node:crypto");
const { JSDOM } = require("jsdom");

const root = path.resolve(__dirname, "../../maverick_dashboard");
const read = (name) => fs.readFileSync(path.join(root, name), "utf8");
const flush = async () => {
  for (let i = 0; i < 30; i++) {
    await new Promise(setImmediate);
    await new Promise((r) => setTimeout(r, 2));
  }
};

// A streamed JSON reply like the bounded client expects.
function reply(status, value) {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let delivered = false;
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name) => (name.toLowerCase() === "content-length" ? String(bytes.byteLength) : null) },
    body: {
      getReader() {
        return {
          async read() {
            if (delivered) return { done: true };
            delivered = true;
            return { done: false, value: bytes };
          },
          async cancel() {},
        };
      },
    },
  };
}

const APPS = [
  { id: "app-1", display_name: "Example Shop", platform: "android", bundle_id: "com.example.shop", status: "active", revision: 3 },
];
const SCANS = [
  { id: "scan-1", application_id: "app-1", status: "pending_review", revision: 2, scanned_at: 1800000000,
    complete: true, permission_count: 4, privacy_data_type_count: 1, sdk_candidate_count: 2 },
];

async function page(options = {}) {
  const html = read("templates/consent_application_scanner.html")
    .replace(/\{%[\s\S]*?%\}/g, "")
    .replace(/\{\{[\s\S]*?\}\}/g, "");
  const dom = new JSDOM(html, { url: "https://lightwork.test/consent/application-scans", runScripts: "outside-only" });
  const w = dom.window;
  const d = w.document;
  const calls = [];
  const confirms = [];
  Object.defineProperty(w, "crypto", { value: webcrypto });
  w.TextEncoder = TextEncoder;
  w.TextDecoder = TextDecoder;
  const shell = d.getElementById("consent-application-scanner-shell");
  shell.setAttribute("data-api-base", "/api/v1/consent/application-scans");
  shell.setAttribute("data-can-admin", "true");
  shell.setAttribute("data-can-audit", "true");
  d.querySelectorAll("button,fieldset").forEach((n) => { n.disabled = false; });
  w.mvConfirm = async (message) => { confirms.push(message); return options.confirm !== false; };
  w.mvForm = async () => ({ reason: "app-retired" });
  w.mvErrorText = (_failure, action) => "Could not " + action + ".";
  w.fetch = async (url, init = {}) => {
    const method = init.method || "GET";
    const body = init.body ? JSON.parse(init.body) : null;
    calls.push({ url, method, body });
    if (url.endsWith("/readiness")) return options.ready === false ? reply(503, { enabled: false, ready: false }) : reply(200, { enabled: true, ready: true });
    if (url.includes("/applications?")) return reply(200, { applications: APPS });
    if (url.includes("/scans?")) return reply(200, { scans: SCANS });
    if (url.endsWith("/review") && options.reviewConflict) return reply(409, { detail: "scan requester cannot review the same scan" });
    if (url.endsWith("/maintenance/purge")) return reply(200, { inspected: 3, purged: 1, deleted: 0 });
    return reply(200, {});
  };
  w.eval(read("static/lightwork-consent-workbench.js"));
  w.eval(read("static/lightwork-consent-application-scanner.js"));
  await flush();
  const rowButton = (host, label) => [...d.querySelectorAll("#" + host + " button")].find((b) => b.textContent === label);
  return { dom, w, d, calls, confirms, rowButton, posts: () => calls.filter((c) => c.method === "POST") };
}

test("a closed service keeps every control disabled and says so plainly", async () => {
  const ui = await page({ ready: false });
  try {
    assert.equal(ui.d.getElementById("cas-operations").disabled, true);
    assert.equal(ui.d.getElementById("cas-runtime-status").textContent, "App checks are turned off for this workspace.");
    assert.doesNotMatch(ui.d.body.textContent, /HTTP|authority|manifest analysis/);
  } finally { ui.dom.window.close(); }
});

test("apps and results load as rows with plain columns and buttons", async () => {
  const ui = await page();
  try {
    assert.equal(ui.d.getElementById("cas-operations").disabled, false);
    assert.match(ui.d.getElementById("cas-apps").textContent, /Example Shop.*Android.*com\.example\.shop/);
    assert.match(ui.d.getElementById("cas-scans").textContent, /Example Shop.*4 permissions.*Waiting for review/);
    assert.ok(ui.rowButton("cas-apps", "Check files"));
    assert.ok(ui.rowButton("cas-scans", "Review"));
  } finally { ui.dom.window.close(); }
});

test("a review carries the row's version and a chosen reason", async () => {
  const ui = await page();
  try {
    ui.rowButton("cas-scans", "Review").click();
    const form = ui.d.getElementById("cas-review-form");
    assert.equal(form.hidden, false);
    form.elements.decision.value = "accepted";
    form.elements.review_note_code.value = "matches-privacy-notice";
    form.dispatchEvent(new ui.w.Event("submit", { bubbles: true, cancelable: true }));
    await flush();
    const sent = ui.posts().find((c) => c.url.endsWith("/scans/scan-1/review"));
    assert.deepEqual(sent.body, { decision: "accepted", expected_revision: 2, review_note_code: "matches-privacy-notice" });
    assert.equal(ui.d.getElementById("cas-operation-status").textContent, "Review saved.");
  } finally { ui.dom.window.close(); }
});

test("a self-review conflict is explained in a plain sentence", async () => {
  const ui = await page({ reviewConflict: true });
  try {
    ui.rowButton("cas-scans", "Review").click();
    ui.d.getElementById("cas-review-form").dispatchEvent(new ui.w.Event("submit", { bubbles: true, cancelable: true }));
    await flush();
    const status = ui.d.getElementById("cas-operation-status");
    assert.match(status.textContent, /Someone other than the person who uploaded the files must review it/);
    assert.equal(status.getAttribute("role"), "alert");
  } finally { ui.dom.window.close(); }
});

test("removing an app and deleting expired results both confirm first", async () => {
  const ui = await page();
  try {
    ui.rowButton("cas-apps", "Remove").click();
    await flush();
    assert.match(ui.confirms[0], /Remove Example Shop\?/);
    const revoke = ui.posts().find((c) => c.url.endsWith("/applications/app-1/revoke"));
    assert.deepEqual(revoke.body, { expected_revision: 3, reason_code: "app-retired" });
    ui.d.getElementById("cas-purge").click();
    await flush();
    assert.match(ui.confirms[1], /cannot be undone/);
    assert.equal(ui.d.getElementById("cas-operation-status").textContent, "1 expired results deleted.");
  } finally { ui.dom.window.close(); }
});

test("declining the confirmation sends nothing", async () => {
  const ui = await page({ confirm: false });
  try {
    ui.d.getElementById("cas-purge").click();
    await flush();
    assert.equal(ui.posts().length, 0);
  } finally { ui.dom.window.close(); }
});
