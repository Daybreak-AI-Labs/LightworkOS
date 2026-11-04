// Run with: node --test packages/maverick-dashboard/tests/js/consent_bulk_jobs_page.test.js
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { JSDOM } = require("jsdom");

const root = path.resolve(__dirname, "../../maverick_dashboard");
const read = (name) => fs.readFileSync(path.join(root, name), "utf8");
const flush = async () => { for (let i = 0; i < 60; i++) { await new Promise(setImmediate); await new Promise((r) => setTimeout(r, 2)); } };

function reply(status, value) {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let done = false;
  return {
    ok: status >= 200 && status < 300, status,
    headers: { get: (name) => (name.toLowerCase() === "content-length" ? String(bytes.byteLength) : null) },
    body: { getReader: () => ({ async read() { if (done) return { done: true }; done = true; return { done: false, value: bytes }; }, async cancel() {} }) },
  };
}

const JOBS = [{ job_id: "job-1", operation: "export_receipts", state: "queued", revision: 4, total_items: 2, processed_items: 0, failed_items: 0, cancel_requested: false, created_at: 1800000000 }];

for (const mode of ['complete', 'pause', 'lost-response']) {
  test('a reviewed job handles multiple parts: ' + mode, async () => {
    const ui = await page();
    try {
      const nativeFetch = ui.w.fetch;
      let current = { ...JOBS[0] }, runs = 0, statusReads = 0;
      ui.w.fetch = async (url, init = {}) => {
        if (url.endsWith('/job-1/run')) {
          runs++; current = { ...current, revision: current.revision + 1, processed_items: runs,
            state: runs === 2 ? 'succeeded' : 'running' };
          if (mode === 'pause') [...ui.d.querySelectorAll('button')].find(b => b.textContent === 'Pause after this part').click();
          if (mode === 'lost-response') throw new Error('connection lost after native change');
          return reply(200, current);
        }
        if (url.endsWith('/job-1')) { statusReads++; return reply(200, current); }
        if (url.startsWith('/api/v1/consent/bulk-jobs?')) return reply(200, { jobs: [current] });
        return nativeFetch(url, init);
      };
      ui.button('Run now').click(); await flush();
      assert.equal(runs, mode === 'complete' ? 2 : 1);
      assert.equal(statusReads, mode === 'lost-response' ? 1 : 0);
      assert.match(ui.d.getElementById('cbj-operation-status').textContent,
        mode === 'complete' ? /job finished/ : mode === 'pause' ? /Processing paused/ : /Processing stopped.*Saved progress/);
      assert.equal(ui.d.querySelectorAll('#cbj-job-list button').length > 0, true);
    } finally { ui.dom.window.close(); }
  });
}

async function page(operations, profileFetch) {
  const html = read("templates/consent_bulk_jobs.html").replace(/\{%[\s\S]*?%\}/g, "").replace(/\{\{[\s\S]*?\}\}/g, "");
  const dom = new JSDOM(html, { url: "https://lightwork.test/consent/bulk-jobs", runScripts: "outside-only" });
  const w = dom.window, d = w.document, calls = [], confirms = [];
  Object.defineProperty(w, "crypto", { value: crypto.webcrypto });
  w.TextEncoder = TextEncoder; w.TextDecoder = TextDecoder;
  const shell = d.getElementById("consent-bulk-jobs-shell");
  Object.assign(shell.dataset, { apiBase: "/api/v1/consent/bulk-jobs", canAudit: "true", canAdmin: "true" });
  d.querySelectorAll("button,fieldset").forEach((n) => { n.disabled = false; });
  w.mvConfirm = async (message) => { confirms.push(message); return true; };
  w.mvErrorText = (_f, action) => "Could not " + action + ".";
  w.fetch = async (url, init = {}) => {
    const method = init.method || "GET", body = init.body ? JSON.parse(init.body) : null;
    calls.push({ url, method, body, headers:init.headers });
    if (url.endsWith("/bulk-jobs/status")) return reply(200, { enabled: true, ready: true, operations: operations || { export_receipts: true, edit_preferences: true, delete_subject: true, change_identifier_type: false, reactivate: false, clear_expiration: false } });
    if (url.startsWith("/api/v1/consent/bulk-jobs?")) return reply(200, { jobs: JOBS });
    if (url.endsWith("/credits/detail")) return reply(200, { available: 7, reserved: 1, consumed: 2, revision: 9 });
    if (url.startsWith("/api/v1/consent/profiles")) {
      if (profileFetch) return profileFetch(url, body, init);
      const profiles = [{ profile_id: "customer-1", identity_kind: "known", revision: 3 }, { profile_id: "customer-2", identity_kind: "anonymous", revision: 5 }];
      return reply(200, {profiles: body && body.profile_ids ? profiles.filter(p => body.profile_ids.includes(p.profile_id)) : profiles,
        missing: body && body.profile_ids ? body.profile_ids.filter(id => !profiles.some(p => p.profile_id === id)) : [], next_after:null});
    }
    if (url.startsWith("/api/v1/consent/policies")) return reply(200, { policies: [{ policy_id: "main", version: 2, purposes: { analytics: "consent", marketing: "consent" } }] });
    return reply(201, { job_id: "job-2", revision: 1 });
  };
  w.eval(read("static/lightwork-consent-workbench.js"));
  w.eval(read("static/lightwork-consent-bulk-jobs.js"));
  d.dispatchEvent(new w.Event("DOMContentLoaded"));
  await flush();
  const button = (label) => [...d.querySelectorAll("#cbj-job-list button")].find((b) => b.textContent === label);
  return { dom, w, d, calls, confirms, button, posts: () => calls.filter((c) => c.method === "POST" && c.url.startsWith("/api/v1/consent/bulk-jobs")) };
}

test("people can be selected across server pages and imported beyond 500 with fresh review versions", async () => {
  let revision = 4;
  const ui = await page(undefined, async (url, body) => {
    if (body) return reply(200, {profiles:body.profile_ids.map(id => ({profile_id:id, identity_kind:"known", revision})), missing:[]});
    const following = url.includes("after="), found = url.includes("0604");
    return reply(200, {profiles:[{profile_id:found ? "person-0604" : following ? "person-0051" : "person-0001", revision, identity_kind:"known"}], next_after:following || found ? null : "person-0050"});
  });
  try {
    ui.d.getElementById("cbj-new").click(); await flush();
    const select = () => { const input = ui.d.querySelector("#cbj-people input"); input.checked = true; input.dispatchEvent(new ui.w.Event("change")); };
    select(); ui.d.getElementById("cbj-people-next").click(); await flush(); select();
    assert.match(ui.d.getElementById("cbj-people-count").textContent, /2 people selected/, JSON.stringify(ui.calls));
    ui.d.getElementById("cbj-people-prev").click(); await flush();
    assert.equal(ui.d.querySelector("#cbj-people input").checked, true);
    const file = ui.d.getElementById("cbj-people-file");
    Object.defineProperty(file, "files", {value:[{size:12, async text() { return "person-0604"; }}]});
    file.dispatchEvent(new ui.w.Event("change")); await flush();
    assert.match(ui.d.getElementById("cbj-people-count").textContent, /3 people selected/, ui.d.getElementById("cbj-operation-status").textContent + JSON.stringify(ui.calls));
    assert.match(ui.d.getElementById("cbj-selected-people").textContent, /person-0604/);
    const form = ui.d.getElementById("cbj-create"), radio = form.querySelector("input[value=edit_preferences]");
    radio.checked = true; radio.dispatchEvent(new ui.w.Event("change")); revision = 9;
    form.dispatchEvent(new ui.w.Event("submit", {bubbles:true, cancelable:true})); await flush();
    ui.d.getElementById("cbj-start-reviewed").click(); await flush();
    const admission = ui.posts().find(c => c.url.endsWith("/actions"));
    assert.equal(admission.body.items.length, 3);
    assert.ok(admission.body.items.every(item => item.expected_revision === 9));
  } finally { ui.dom.window.close(); }
});

test("a changed account clears the person list and prevents review", async () => {
  let expired = false;
  const context = "a".repeat(64);
  const ui = await page(undefined, async () => expired ? reply(409, {detail:"changed account"}) : reply(200, {context, profiles:[{profile_id:"person-0001", revision:0}], next_after:"person-0050"}));
  try {
    ui.d.getElementById("consent-bulk-jobs-shell").dataset.requestContext = context;
    ui.d.getElementById("cbj-new").click(); await flush();
    const input = ui.d.querySelector("#cbj-people input"); input.checked = true; input.dispatchEvent(new ui.w.Event("change"));
    expired = true; ui.d.getElementById("cbj-people-next").click(); await flush();
    assert.equal(ui.d.getElementById("cbj-create").hidden, true);
    assert.equal(ui.d.getElementById("cbj-selected-people").textContent, "");
    assert.equal(ui.posts().length, 0);
    assert.equal(ui.calls.find(c => c.url.includes("after=")).headers["X-Lightwork-Profile-Context"], context);
  } finally { ui.dom.window.close(); }
});

test("checked choices remain across older pages and clear when a person is removed", async () => {
  const ui = await page({clear_expiration:true}, async (url, body) => {
    if (url.includes("/export?")) return reply(200, {receipts:[{receipt_id:url.includes("before_sequence") ? "choice-old" : "choice-new",
      profile_id:"person-0604", profile_revision:1, choices:[{purpose_id:"marketing", action:"grant"}]}], next_before_sequence:url.includes("before_sequence") ? null : 10});
    return reply(200, {profiles:[{profile_id:"person-0604", identity_kind:"known", revision:8}], missing:[], next_after:null});
  });
  try {
    ui.d.getElementById("cbj-new").click(); await flush();
    const person = ui.d.querySelector("#cbj-people input"); person.checked = true; person.dispatchEvent(new ui.w.Event("change"));
    ui.d.getElementById("cbj-load-receipts").click(); await flush();
    const choose = () => { const input = ui.d.querySelector("#cbj-receipts input"); input.checked = true; input.dispatchEvent(new ui.w.Event("change")); };
    choose(); ui.d.getElementById("cbj-receipt-older").click(); await flush(); choose();
    assert.match(ui.d.getElementById("cbj-selected-receipts-title").textContent, /2 selected choices/);
    const form = ui.d.getElementById("cbj-create"); form.querySelector("input[value=clear_expiration]").checked = true;
    form.dispatchEvent(new ui.w.Event("submit", {bubbles:true, cancelable:true})); await flush();
    assert.equal(ui.d.querySelectorAll("#cbj-review-rows tr").length, 2);
    assert.match(ui.d.getElementById("cbj-review-rows").textContent, /Marketing: Grant/);
    person.checked = false; person.dispatchEvent(new ui.w.Event("change"));
    assert.equal(ui.d.getElementById("cbj-review").hidden, true);
    assert.equal(ui.d.getElementById("cbj-selected-receipts").textContent, "");
    assert.equal(ui.d.getElementById("cbj-receipt-pages").hidden, true);
    assert.equal(ui.posts().length, 0);
  } finally { ui.dom.window.close(); }
});

test("jobs load as rows and kinds of change that are not set up are disabled", async () => {
  const ui = await page();
  try {
    assert.equal(ui.d.getElementById("cbj-operations").disabled, false);
    assert.match(ui.d.getElementById("cbj-job-list").textContent, /Export consent records.*2.*0 of 2 done.*Waiting/);
    assert.match(ui.d.getElementById("cbj-credit-detail").textContent, /7 records can still be processed/);
    assert.match(ui.d.getElementById("cbj-readiness-detail").textContent, /not set up yet: change how people are identified/);
    assert.equal(ui.d.querySelector("input[name=operation][value=reactivate]").disabled, true);
  } finally { ui.dom.window.close(); }
});

test('older jobs remain reachable and failed paging preserves the current rows', async () => {
  const ui = await page();
  try {
    const original = ui.w.fetch;
    let failOlder = false;
    ui.w.fetch = async (url, init) => {
      if (url.startsWith('/api/v1/consent/bulk-jobs?')) {
        assert.match(url, /limit=50/);
        if (url.includes('before_job_id=')) {
          if (failOlder) throw new Error('read interrupted');
          return reply(200, {jobs:[{...JOBS[0], operation:'clear_expiration'}], next_before_job_id:null});
        }
        return reply(200, {jobs:JOBS, next_before_job_id:'job-1'});
      }
      return original(url, init);
    };
    ui.d.getElementById('cbj-jobs-latest').click(); await flush();
    assert.equal(ui.d.getElementById('cbj-jobs-older').hidden, false);
    failOlder = true; ui.d.getElementById('cbj-jobs-older').click(); await flush();
    assert.match(ui.d.getElementById('cbj-job-list').textContent, /Export consent records/);
    failOlder = false; ui.d.getElementById('cbj-jobs-older').click(); await flush();
    assert.match(ui.d.getElementById('cbj-job-list').textContent, /Remove end dates/);
    assert.equal(ui.d.getElementById('cbj-jobs-older').hidden, true);
    ui.d.getElementById('cbj-jobs-latest').click(); await flush();
    assert.match(ui.d.getElementById('cbj-job-list').textContent, /Export consent records/);
  } finally { ui.dom.window.close(); }
});

test("an export is built from ticked people, not typed items", async () => {
  const ui = await page();
  try {
    ui.d.getElementById("cbj-new").click();
    await flush();
    ui.d.querySelectorAll("#cbj-people input[name=person]").forEach((c) => { c.checked = true; c.dispatchEvent(new ui.w.Event("change")); });
    ui.d.getElementById("cbj-create").elements.receipt_limit.value = "50";
    ui.d.getElementById("cbj-create").dispatchEvent(new ui.w.Event("submit", { bubbles: true, cancelable: true }));
    await flush();
    assert.equal(ui.posts().length, 0);
    assert.match(ui.d.getElementById("cbj-review-rows").textContent, /customer-1.*50.*customer-2.*50/);
    ui.d.getElementById("cbj-start-reviewed").click();
    await flush();
    const sent = ui.posts().find((c) => c.url.endsWith("/bulk-jobs/exports"));
    assert.deepEqual(sent.body.items, [
      { item_id: "item-1", profile_id: "customer-1", receipt_limit: 50 },
      { item_id: "item-2", profile_id: "customer-2", receipt_limit: 50 },
    ]);
    assert.ok(sent.body.idempotency_key);
  } finally { ui.dom.window.close(); }
});

test("changing choices confirms and carries each person's version and the chosen policy", async () => {
  const ui = await page();
  try {
    ui.d.getElementById("cbj-new").click();
    await flush();
    const form = ui.d.getElementById("cbj-create");
    const radio = form.querySelector("input[name=operation][value=edit_preferences]");
    radio.checked = true; radio.dispatchEvent(new ui.w.Event("change"));
    const person = ui.d.querySelector("#cbj-people input[value=customer-2]");
    person.checked = true; person.dispatchEvent(new ui.w.Event("change"));
    form.elements.purpose_id.value = "marketing";
    form.elements.action.value = "deny";
    form.dispatchEvent(new ui.w.Event("submit", { bubbles: true, cancelable: true }));
    await flush();
    assert.equal(ui.posts().length, 0);
    assert.match(ui.d.getElementById("cbj-review-rows").textContent, /customer-2.*Deny Marketing/);
    ui.d.getElementById("cbj-start-reviewed").click();
    await flush();
    assert.match(ui.confirms[0], /Change choices for 1 record\?/);
    const sent = ui.posts().find((c) => c.url.endsWith("/bulk-jobs/actions"));
    const item = sent.body.items[0];
    assert.equal(sent.body.operation, "edit_preferences");
    assert.equal(item.profile_id, "customer-2");
    assert.equal(item.expected_revision, 5);
    assert.equal(item.policy_id, "main");
    assert.equal(item.policy_version, 2);
    assert.equal(item.choices[0].purpose_id, "marketing");
    assert.equal(item.choices[0].action, "deny");
    assert.equal(item.context.asserted_source, "operator");
  } finally { ui.dom.window.close(); }
});

test("choosing nobody explains what to do instead of sending", async () => {
  const ui = await page();
  try {
    ui.d.getElementById("cbj-new").click();
    await flush();
    ui.d.getElementById("cbj-create").dispatchEvent(new ui.w.Event("submit", { bubbles: true, cancelable: true }));
    await flush();
    assert.equal(ui.posts().length, 0);
    assert.equal(ui.d.getElementById("cbj-operation-status").textContent, "Choose at least one person.");
  } finally { ui.dom.window.close(); }
});

test("a lost admission response reads the original job without submitting twice", async () => {
  const ui = await page();
  try {
    const originalFetch = ui.w.fetch;
    let submissions = 0, reference = null;
    ui.w.fetch = async (url, init = {}) => {
      if (url.endsWith('/bulk-jobs/exports')) {
        submissions++;
        reference = JSON.parse(init.body).idempotency_key;
        throw new TypeError('Lost response after admission');
      }
      if (url.endsWith('/requests/check')) {
        assert.equal(JSON.parse(init.body).idempotency_key, reference);
        return reply(200, {found:true, job:JOBS[0]});
      }
      return originalFetch(url, init);
    };
    ui.d.getElementById('cbj-new').click(); await flush();
    const person = ui.d.querySelector('#cbj-people input');
    person.checked = true; person.dispatchEvent(new ui.w.Event('change'));
    ui.d.getElementById('cbj-create').dispatchEvent(new ui.w.Event('submit', {cancelable:true}));
    await flush(); ui.d.getElementById('cbj-start-reviewed').click(); await flush();
    assert.equal(submissions, 1);
    assert.match(ui.d.getElementById('cbj-operation-status').textContent, /original job is waiting.*No job was repeated/);
    assert.equal(ui.d.getElementById('cbj-submission-recovery').hidden, true);
  } finally { ui.dom.window.close(); }
});

test("cancelling a job confirms and carries its version", async () => {
  const ui = await page();
  try {
    ui.button("Cancel").click();
    await flush();
    assert.match(ui.confirms[0], /Changes already made are not undone/);
    const sent = ui.posts().find((c) => c.url.endsWith("/job-1/cancel"));
    assert.equal(sent.body.expected_revision, 4);
  } finally { ui.dom.window.close(); }
});

test('a lost cancellation response reads recorded cancellation without submitting again', async () => {
  const ui = await page();
  try {
    const original = ui.w.fetch;
    let attempts = 0, reads = 0;
    const recorded = { ...JOBS[0], revision: 5, cancel_requested: true, state: 'running' };
    ui.w.fetch = async (url, init = {}) => {
      if (url.endsWith('/job-1/cancel')) { attempts++; throw new Error('lost after cancellation'); }
      if (url.endsWith('/job-1')) { reads++; return reply(200, recorded); }
      if (url.startsWith('/api/v1/consent/bulk-jobs?')) return reply(200, { jobs: [recorded] });
      return original(url, init);
    };
    ui.button('Cancel').click(); await flush();
    assert.equal(attempts, 1); assert.equal(reads, 1);
    assert.match(ui.d.getElementById('cbj-operation-status').textContent, /Cancellation is already recorded/);
    assert.match(ui.d.getElementById('cbj-job-list').textContent, /Cancelling/);
    assert.equal(ui.button('Cancel'), undefined);
  } finally { ui.dom.window.close(); }
});
