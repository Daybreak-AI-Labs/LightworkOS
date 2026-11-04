"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const source = fs.readFileSync(
  path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-red-team-schedules.js"), "utf8");

function page(admin) {
  return `<div id="rts-root" data-api-base="/api/v1/security/assurance/red-team" data-admin="${admin ? 1 : 0}">
<script type="application/json" id="rts-names">{"assets":{"MAA-1":"Loan helper"},"agents":{"runner-one":"Night runner"}}</script>
<table><tbody id="rts-rows"></tbody></table><p id="rts-status"></p>
${admin ? `<button id="rts-run-due" type="button">Run due checks now</button>
<form id="rts-create">
<select name="asset_id"><option value="">Choose</option><option value="MAA-1">Loan helper</option></select>
<select name="external_agent_id"><option value="">Choose</option><option value="runner-one">Night runner</option></select>
<select name="cadence_seconds"><option value="86400">Every day</option><option value="604800" selected>Every week</option></select>
<input type="datetime-local" name="first_run_at">
<input type="hidden" data-auto-reference name="idempotency_key" value="ref-1">
<input type="checkbox" name="safe_target_environment">
<button type="submit">Schedule a check</button><span id="rts-create-status"></span></form>` : ""}</div>`;
}

const SCHEDULE = {
  id: "RTS-1", revision: 4, status: "active", target_asset_id: "MAA-1", external_agent_id: "runner-one",
  cadence_seconds: 604800, next_run_at: 1700000000, run_count: 2, run_claimed: false,
};

async function fixture({ admin = true, items = [SCHEDULE], listStatus = 200, confirm = true, post } = {}) {
  const dom = new JSDOM(page(admin), { url: "https://lightwork.example/security/assurance", runScripts: "outside-only" });
  const { window } = dom;
  const calls = [];
  window.mvErrorText = (failure, action) => `Could not ${action}.`;
  window.mvHuman = (v) => String(v).replace(/_/g, " ");
  window.mvWhen = () => "14 Nov 2023";
  window.mvConfirm = async (message) => { calls.push({ confirm: message }); return confirm; };
  window.fetch = async (url, init = {}) => {
    calls.push({ url, method: init.method || "GET", body: init.body ? JSON.parse(init.body) : null });
    if (!init.method) {
      return new Response(JSON.stringify({ items, count: items.length, truncated: false }),
        { status: listStatus, headers: { "Content-Type": "application/json" } });
    }
    const answer = post ? post(url) : { status: 200, body: {} };
    return new Response(JSON.stringify(answer.body), { status: answer.status, headers: { "Content-Type": "application/json" } });
  };
  const settle = async () => { for (let i = 0; i < 30; i++) await new Promise((done) => setImmediate(done)); };
  shell(window);
  window.eval(source);
  await settle();
  return { window, doc: window.document, calls, settle };
}

test("schedules list in plain words with a cancel button for admins", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  const text = ui.doc.getElementById("rts-rows").textContent;
  assert.match(text, /Loan helper/);
  assert.match(text, /Night runner/);
  assert.match(text, /Every week/);
  assert.match(text, /14 Nov 2023/);
  assert.doesNotMatch(text, /RTS-1|MAA-1|604800/);
  assert.equal(ui.doc.querySelectorAll("#rts-rows button").length, 1);
});

test("viewers see the list without buttons and an empty state that says who can act", async (t) => {
  const ui = await fixture({ admin: false, items: [] });
  t.after(() => ui.window.close());
  assert.match(ui.doc.getElementById("rts-rows").textContent, /Ask an administrator/);
  assert.equal(ui.doc.querySelectorAll("#rts-rows button").length, 0);
});

test("admins get a schedule button in the empty state", async (t) => {
  const ui = await fixture({ items: [] });
  t.after(() => ui.window.close());
  const button = ui.doc.querySelector("#rts-rows button");
  assert.equal(button.textContent, "Schedule a check");
});

test("cancel confirms first and sends the version from the row", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  ui.doc.querySelector("#rts-rows button").click();
  await ui.settle();
  assert.ok(ui.calls.some((c) => c.confirm && /No new checks will start/.test(c.confirm)));
  const cancel = ui.calls.find((c) => c.method === "POST");
  assert.equal(cancel.url, "/api/v1/security/assurance/red-team/schedules/RTS-1/cancel");
  assert.equal(cancel.body.expected_revision, 4);
  assert.ok(cancel.body.rationale.length > 0);
  assert.equal(ui.doc.getElementById("rts-status").textContent, "Scheduled check cancelled.");
});

test("declining the confirmation sends nothing", async (t) => {
  const ui = await fixture({ confirm: false });
  t.after(() => ui.window.close());
  ui.doc.querySelector("#rts-rows button").click();
  await ui.settle();
  assert.equal(ui.calls.filter((c) => c.method === "POST").length, 0);
});

test("run due reports started and failed checks in a sentence", async (t) => {
  const ui = await fixture({ post: () => ({ status: 200, body: { count: 2, failures: [{ schedule_id: "x", reason: "y" }] } }) });
  t.after(() => ui.window.close());
  ui.doc.getElementById("rts-run-due").click();
  await ui.settle();
  const run = ui.calls.find((c) => c.method === "POST");
  assert.equal(run.url, "/api/v1/security/assurance/red-team/schedules/run-due");
  const text = ui.doc.getElementById("rts-status").textContent;
  assert.match(text, /Started 2 checks/);
  assert.match(text, /1 check could not start/);
});

test("scheduling converts the date picker and frequency into the request", async (t) => {
  const ui = await fixture({ post: () => ({ status: 201, body: SCHEDULE }) });
  t.after(() => ui.window.close());
  const form = ui.doc.getElementById("rts-create");
  form.querySelector("[name=asset_id]").value = "MAA-1";
  form.querySelector("[name=external_agent_id]").value = "runner-one";
  form.querySelector("[name=cadence_seconds]").value = "86400";
  form.querySelector("[name=first_run_at]").value = "2030-01-02T03:04";
  form.querySelector("[name=safe_target_environment]").checked = true;
  form.dispatchEvent(new ui.window.Event("submit", { cancelable: true }));
  await ui.settle();
  const made = ui.calls.find((c) => c.method === "POST");
  assert.equal(made.url, "/api/v1/security/assurance/red-team/schedules");
  assert.equal(made.body.cadence_seconds, 86400);
  assert.equal(made.body.idempotency_key, "ref-1");
  assert.equal(made.body.safe_target_environment, true);
  assert.equal(made.body.first_run_at, Math.floor(new Date("2030-01-02T03:04").getTime() / 1000));
  assert.equal(ui.doc.getElementById("rts-create-status").textContent, "Check scheduled.");
});

test("scheduling needs the test-copy confirmation", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  const form = ui.doc.getElementById("rts-create");
  form.querySelector("[name=asset_id]").value = "MAA-1";
  form.querySelector("[name=external_agent_id]").value = "runner-one";
  form.dispatchEvent(new ui.window.Event("submit", { cancelable: true }));
  await ui.settle();
  assert.equal(ui.calls.filter((c) => c.method === "POST").length, 0);
  assert.match(ui.doc.getElementById("rts-create-status").textContent, /test copy/);
});

test("a failed load shows a plain sentence", async (t) => {
  const ui = await fixture({ listStatus: 503 });
  t.after(() => ui.window.close());
  assert.equal(ui.doc.getElementById("rts-rows").textContent.trim(), "Could not load the scheduled checks.");
});
