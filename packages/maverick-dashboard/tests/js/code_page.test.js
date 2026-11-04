"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const source = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-code.js"), "utf8");
const html = `<div id="ic-root" data-console="code" data-api-url="/api/v1/code/summary" data-can-admin="true" data-enabled="true">
<p id="ic-status"></p><p id="ic-error"></p>
<strong id="ic-repos"></strong><strong id="ic-pending"></strong><strong id="ic-approved"></strong><strong id="ic-merged"></strong>
<button id="code-add">Add</button>
<table><tbody id="ic-repo-rows"></tbody></table>
<section id="code-feature"><form id="code-feature-form"><select id="code-feature-repo" name="repo"><option value="">Choose</option></select>
<input id="code-feature-title-input" name="title"><textarea name="description"></textarea>
<select name="max_dollars"><option value="">Usual</option><option value="5">5</option></select><button type="submit">Start</button></form></section>
<button id="code-merge-approved">Merge all</button>
<table><tbody id="ic-prop-rows"></tbody></table>
<section id="code-review" hidden><h2 id="code-review-title">Review</h2><button id="code-review-close">Close</button><div id="code-review-body"></div></section>
</div>`;

const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
const SUMMARY = {
  enabled: true,
  repos: [{ name: "website", default_branch: "main", protect: "block", tests: true, updated_at: 1700000000 }],
  proposals: [
    { id: "0123456789abcdef", repo: "website", title: "Add a button", files: 2, tests: true, review: true, status: "approved", approval_id: 7 },
    { id: "fedcba9876543210", repo: "website", title: "Fix typo", files: 1, tests: false, review: null, status: "pending", approval_id: 8 }  // pragma: allowlist secret
  ]
};

async function fixture({ confirm = true, reply } = {}) {
  const dom = new JSDOM(html, { url: "https://lightwork.example/code", runScripts: "outside-only" });
  const { window } = dom;
  const calls = [];
  const confirms = [];
  window.mvConfirm = async (message) => { confirms.push(message); return confirm; };
  window.mvErrorText = (failure, action) => `Could not ${action}.`;
  window.mvPlainDetail = (detail) => (typeof detail === "string" && /^[A-Z][^_]*[.!?]$/.test(detail) ? detail : "");
  window.mvHuman = (v) => String(v).replace(/_/g, " ");
  window.mvWhen = () => "1 Jan";
  window.mvToast = () => {};
  window.fetch = async (url, options = {}) => {
    calls.push({ url, ...options });
    if (reply) { const r = reply(url, options); if (r) return r; }
    if (url.endsWith("/summary")) return json(SUMMARY);
    if (url.endsWith("/merge")) return json({ merged: true, repo: "website" });
    if (url.includes("/proposals/") && (!options.method || options.method === "GET")) {
      return json({ id: "fedcba9876543210", repo: "website", title: "Fix typo", status: "pending", approval_id: 8,  // pragma: allowlist secret
        files: ["a.py"], tests: { passed: false }, tests_output: "1 failed", review: null, changes: "-a\n+b", changes_cut_short: false });
    }
    return json({});
  };
  const settle = async () => { for (let i = 0; i < 20; i++) await new Promise((done) => setImmediate(done)); };
  shell(window);
  window.eval(source);
  await settle();
  return { window, doc: window.document, calls, confirms, settle };
}

test("projects and changes render in plain words with the right buttons", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  const repoText = ui.doc.getElementById("ic-repo-rows").textContent;
  assert.match(repoText, /Code never leaves Lightwork/);
  assert.match(repoText, /Get latest changes/);
  const props = ui.doc.getElementById("ic-prop-rows");
  assert.match(props.textContent, /Approved, ready to merge/);
  assert.match(props.textContent, /Waiting for approval/);
  const link = [...props.querySelectorAll("a")].find((a) => /approvals queue/.test(a.textContent));
  assert.equal(link.getAttribute("href"), "/approvals#approval-8");
  assert.equal(ui.doc.getElementById("code-feature-repo").options.length, 2);
  assert.equal(ui.doc.getElementById("ic-pending").textContent, "1");
});

test("merge asks first and does nothing when cancelled", async (t) => {
  const ui = await fixture({ confirm: false });
  t.after(() => ui.window.close());
  const merge = [...ui.doc.querySelectorAll("#ic-prop-rows button")].find((b) => b.textContent === "Merge");
  merge.click(); await ui.settle();
  assert.equal(ui.confirms.length, 1);
  assert.equal(ui.calls.some((c) => c.url.endsWith("/merge")), false);
});

test("confirmed merge calls the merge action for that change", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  const merge = [...ui.doc.querySelectorAll("#ic-prop-rows button")].find((b) => b.textContent === "Merge");
  merge.click(); await ui.settle();
  const call = ui.calls.find((c) => c.url.endsWith("/merge"));
  assert.equal(call.url, "/api/v1/code/proposals/0123456789abcdef/merge");
  assert.equal(call.method, "POST");
  assert.match(ui.doc.getElementById("ic-status").textContent, /Merged/);
});

test("a refused merge shows the plain reason from the page's own action", async (t) => {
  const ui = await fixture({ reply: (url) => url.endsWith("/merge") ? json({ detail: "This change is still waiting for a person to approve it in the approvals queue." }, 409) : null });
  t.after(() => ui.window.close());
  const merge = [...ui.doc.querySelectorAll("#ic-prop-rows button")].find((b) => b.textContent === "Merge");
  merge.click(); await ui.settle();
  assert.match(ui.doc.getElementById("ic-error").textContent, /waiting for a person to approve/);
});

test("a refusal with internal wording falls back to a plain sentence", async (t) => {
  const ui = await fixture({ reply: (url) => url.endsWith("/merge") ? json({ detail: "proposal_state_conflict: expected pending" }, 409) : null });
  t.after(() => ui.window.close());
  const merge = [...ui.doc.querySelectorAll("#ic-prop-rows button")].find((b) => b.textContent === "Merge");
  merge.click(); await ui.settle();
  assert.match(ui.doc.getElementById("ic-error").textContent, /^Could not /);
  assert.doesNotMatch(ui.doc.getElementById("ic-error").textContent, /proposal_state_conflict/);
});

test("review shows tests, files and the changed lines behind a disclosure", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  const review = [...ui.doc.querySelectorAll("#ic-prop-rows button")].filter((b) => b.textContent === "Review")[1];
  review.click(); await ui.settle();
  const body = ui.doc.getElementById("code-review-body");
  assert.equal(ui.doc.getElementById("code-review").hidden, false);
  assert.match(body.textContent, /tests failed/);
  assert.match(body.querySelector("details summary").textContent, /changed lines/);
});

test("starting a change confirms and sends the chosen project and limit", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  const form = ui.doc.getElementById("code-feature-form");
  form.elements.repo.value = "website";
  form.elements.title.value = "Add export";
  form.elements.max_dollars.value = "5";
  form.dispatchEvent(new ui.window.Event("submit", { cancelable: true })); await ui.settle();
  const call = ui.calls.find((c) => c.url === "/api/v1/code/features");
  assert.deepEqual(JSON.parse(call.body), { repo: "website", title: "Add export", description: "", max_dollars: 5 });
  assert.match(ui.doc.getElementById("ic-status").textContent, /Started/);
});
