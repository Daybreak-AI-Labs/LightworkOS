// Run with: node --test packages/maverick-dashboard/tests/js/policy_publication_links_page.test.js
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
const sha = (text) => crypto.createHash("sha256").update(text).digest("hex");

const ARTIFACTS = [
  { policy_id: "information-security", version: 2, title: "Information Security", approval_mode: "four_eyes", required_approvals: 2, approval_count: 1, rejection_count: 0, ready_to_publish: false, created_at: 1800000100 },
  { policy_id: "information-security", version: 1, title: "Information Security", approval_mode: "four_eyes", required_approvals: 2, approval_count: 2, rejection_count: 0, ready_to_publish: true, created_at: 1800000000 },
];
const LINKS = [{ link_id: "plink-1", policy_id: "information-security", visibility: "private", status: "active", effective_status: "active", revision: 3, pointer_revision: 4, current_version: 1, stable_path: "/api/v1/public/policies/plink-1" }];
const JOBS = [{ job_id: "job-1", action: "publish", link_id: "plink-1", target_version: 1, scheduled_for: 1800000500, state: "failed", attempts: 3, max_attempts: 3 }];

async function page(options = {}) {
  const html = read("templates/policy_publication_links.html").replace(/\{%[\s\S]*?%\}/g, "").replace(/\{\{[\s\S]*?\}\}/g, "");
  const dom = new JSDOM(html, { url: "https://lightwork.test/compliance/policy-links", runScripts: "outside-only" });
  const w = dom.window, d = w.document, calls = [], confirms = [], copies = [];
  Object.defineProperty(w, "crypto", { value: crypto.webcrypto });
  w.TextEncoder = TextEncoder;
  Object.assign(d.getElementById("ppl-root").dataset, { featureEnabled: "true", canAdmin: "true", canAudit: "true" });
  d.querySelectorAll("button,fieldset").forEach((n) => { n.disabled = false; });
  w.mvConfirm = async (message) => { confirms.push(message); return options.confirm !== false; };
  w.mvForm = async () => ({ note: "Checked against the ISO controls" });
  w.mvCopy = (text) => copies.push(text);
  w.mvErrorText = (_f, action) => "Could not " + action + ".";
  w.fetch = async (url, init = {}) => {
    const method = init.method || "GET", body = init.body ? JSON.parse(init.body) : null;
    calls.push({ url, method, body });
    if (url.includes("/artifacts?")) return reply(200, { items: ARTIFACTS });
    if (url.includes("/links?")) return reply(200, { items: LINKS });
    if (url.includes("/jobs?")) return reply(200, { items: JOBS });
    if (url.endsWith("/links") && method === "POST") return reply(201, { link_id: "plink-2", private_capability: "ACCESS-CODE-ONCE" });
    return reply(200, {});
  };
  shell(w);
  w.eval(read("static/lightwork-consent-workbench.js"));
  [...read("templates/policy_publication_links.html").matchAll(/<script>([\s\S]*?)<\/script>/g)].forEach((m) => w.eval(m[1]));
  await flush();
  const button = (host, label) => [...d.querySelectorAll("#" + host + " button")].find((b) => b.textContent === label);
  return { dom, w, d, calls, confirms, copies, button, posts: () => calls.filter((c) => c.method !== "GET") };
}

test("policies, links and scheduled changes load as plain rows", async () => {
  const ui = await page();
  try {
    assert.match(ui.d.getElementById("ppl-policies").textContent, /Information Security.*2.*1 of 2 approvals/);
    assert.match(ui.d.getElementById("ppl-links").textContent, /Only with an access code.*Version 1.*Live/);
    assert.match(ui.d.getElementById("ppl-jobs").textContent, /Publish a version \(version 1\).*Did not run/);
    assert.ok(ui.button("ppl-jobs", "Schedule again"));
  } finally { ui.dom.window.close(); }
});

test("publishing offers only approved versions and carries the link's revision", async () => {
  const ui = await page();
  try {
    ui.button("ppl-links", "Publish a version").click();
    const form = ui.d.getElementById("ppl-publish");
    assert.deepEqual([...form.elements.version.options].map((o) => o.value), ["1"]);
    form.dispatchEvent(new ui.w.Event("submit", { bubbles: true, cancelable: true }));
    await flush();
    assert.match(ui.confirms[0], /Tools with the access code will see it/);
    const sent = ui.posts().find((c) => c.url.endsWith("/links/plink-1/publish"));
    assert.equal(sent.body.version, 1);
    assert.equal(sent.body.expected_pointer_revision, 4);
    assert.ok(sent.body.idempotency_key);
  } finally { ui.dom.window.close(); }
});

test("a new private link shows its access code once with a copy button", async () => {
  const ui = await page();
  try {
    ui.d.getElementById("ppl-new-link").click();
    const form = ui.d.getElementById("ppl-link");
    form.querySelector("[name=visibility][value=private]").checked = true;
    form.dispatchEvent(new ui.w.Event("submit", { bubbles: true, cancelable: true }));
    await flush();
    const sent = ui.posts().find((c) => c.url.endsWith("/links"));
    assert.deepEqual({ policy_id: sent.body.policy_id, visibility: sent.body.visibility }, { policy_id: "information-security", visibility: "private" });
    assert.equal(ui.d.getElementById("ppl-secret").hidden, false);
    assert.equal(ui.d.getElementById("ppl-secret-value").textContent, "ACCESS-CODE-ONCE");
    ui.d.getElementById("ppl-copy-secret").click();
    assert.deepEqual(ui.copies, ["ACCESS-CODE-ONCE"]);
    ui.d.getElementById("ppl-hide-secret").click();
    assert.equal(ui.d.getElementById("ppl-secret-value").textContent, "");
  } finally { ui.dom.window.close(); }
});

test("a review comment is fingerprinted here, never typed as a code", async () => {
  const ui = await page();
  try {
    ui.button("ppl-policies", "Approve").click();
    await flush();
    const sent = ui.posts().find((c) => c.url.endsWith("/artifacts/information-security/versions/2/reviews"));
    assert.equal(sent.body.decision, "approve");
    assert.equal(sent.body.rationale_sha256, sha("lightwork.policy-review-comment.v1\nChecked against the ISO controls"));
  } finally { ui.dom.window.close(); }
});

test("turning a link off and cleaning up history confirm first", async () => {
  const ui = await page();
  try {
    ui.button("ppl-links", "Turn off").click();
    await flush();
    assert.match(ui.confirms[0], /stops working for good/);
    assert.equal(ui.posts().find((c) => c.url.endsWith("/links/plink-1/revoke")).body.expected_revision, 3);
    const retention = ui.d.getElementById("ppl-retention");
    retention.dispatchEvent(new ui.w.SubmitEvent("submit", { bubbles: true, cancelable: true, submitter: retention.querySelector("button[value=access]") }));
    await flush();
    assert.match(ui.confirms[1], /cannot be undone/);
    assert.ok(ui.posts().find((c) => c.url.endsWith("/retention/access")));
  } finally { ui.dom.window.close(); }
});

test("declining a confirmation sends nothing", async () => {
  const ui = await page({ confirm: false });
  try {
    ui.button("ppl-links", "Turn off").click();
    await flush();
    assert.equal(ui.posts().length, 0);
  } finally { ui.dom.window.close(); }
});
