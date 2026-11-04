"use strict";
// The admin lists that take bulk work: approvals (reject or send back,
// never bulk approve), tool policies (block or allow, with undo) and privacy
// requests (assign with undo, confirm receipt). Each wires window.mvBulk to the
// page's own one-item calls. Run with: node --test tests/js/bulk_lists.test.js
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const {JSDOM} = require("jsdom");
const pkg = path.resolve(__dirname, "../../maverick_dashboard");
const read = name => fs.readFileSync(path.join(pkg, name), "utf8").replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>").replace(/\r\n/g, "\n");
const ui = read("static/lightwork-ui.js");
const flush = async () => { for (let i = 0; i < 20; i++) await new Promise(setImmediate); };

function boot(html, url) {
  const dom = new JSDOM(`<div id="mv-toasts"></div><div id="mv-toasts-alert"></div><main id="content">${html}</main>`,
    {url, runScripts: "outside-only", pretendToBeVisual: true});
  const w = dom.window;
  w.matchMedia = () => ({matches: false, addEventListener() {}, removeEventListener() {}});
  w.confirms = [];
  w.confirm = message => { w.confirms.push(message); return true; };
  w.setInterval = () => 1; w.clearInterval = () => {};
  w.eval(ui);
  return w;
}
const bulkButton = (w, text) => [...w.document.querySelectorAll(".mv-bulk button")].find(b => b.textContent.trim() === text);
const selectAll = w => w.document.querySelector(".mv-bulk__all input").click();
const report = w => w.document.querySelector(".mv-bulk__report");

test("approvals: reject several at once with one reason, then undo them all", async () => {
  const queue = read("templates/_approvals_queue.html");
  const card = (id, label) => `<article class="approval-item" data-id="${id}" data-label="${label}" data-risk="low" data-bulk-id="${id}" data-bulk-label="${label} (#${id})" id="approval-${id}">
    <div class="approval-item__head"><h2>${label}</h2><span class="badge approval-outcome" hidden></span></div>
    <p class="approval-item__decided muted" hidden></p>
    <div class="approval-actions"><button type="button" class="btn approval-btn" data-id="${id}" data-action="approve">Approve</button></div>
    <div class="approval-actions approval-actions--decided" hidden><button type="button" class="btn approval-undo" data-id="${id}">Undo</button></div>
  </article>`;
  const w = boot(`<div id="approval-queue">${card(1, "Write file")}${card(2, "Send email")}</div>
    <p id="approval-msg"></p><section id="approval-decided" hidden><div id="approval-decided-list"></div></section>`,
  "https://fixture.invalid/approvals");
  const calls = [];
  w.mvForm = async () => ({reason: "Not this week"});
  w.fetch = async (url, options) => {
    calls.push({url, body: options && options.body});
    if (url.endsWith("/undo")) return {ok: true, status: 200, headers: new w.Headers()};
    return {ok: true, status: 204, headers: new w.Headers({"X-Lightwork-Undo-Seconds": "30", "X-Lightwork-Decided-By": "you"})};
  };
  for (const marker of ["  (function() {\n    const msg = document.getElementById('approval-msg')",
    "  // Reject or send back many requests at once."]) {
    const start = queue.indexOf(marker);
    assert.ok(start > 0, marker);
    w.eval(queue.slice(start, queue.indexOf("</script>", start)));
  }
  const labels = [...w.document.querySelectorAll(".mv-bulk button")].map(b => b.textContent.trim());
  assert.deepEqual(labels.filter(l => /selected$/.test(l)), ["Reject selected", "Send back selected"], "no bulk approve");
  selectAll(w);
  bulkButton(w, "Reject selected").click();
  await flush();
  assert.match(w.confirms[0], /^Reject 2 requests\? Write file \(#1\) and Send email \(#2\)\./);
  assert.deepEqual(calls.map(c => c.url), ["/api/v1/approvals/1/deny", "/api/v1/approvals/2/deny"]);
  assert.equal(JSON.parse(calls[0].body).reason, "Not this week");
  assert.equal(w.document.getElementById("approval-decided-list").children.length, 2, "decided cards move like single decisions");
  assert.match(report(w).textContent, /Reject: 2 done/);
  [...report(w).querySelectorAll("button")].find(b => /Undo these changes/.test(b.textContent)).click();
  await flush();
  assert.deepEqual(calls.slice(2).map(c => c.url), ["/api/v1/approvals/1/undo", "/api/v1/approvals/2/undo"]);
  assert.equal(w.document.getElementById("approval-queue").querySelectorAll("article").length, 2, "back in the queue");
  w.close();
});

test("tool policies: block the filtered tools, a tool set by the organization is reported, undo allows again", async () => {
  const page = read("templates/permissions.html");
  const row = (name, label, action) => `<tr data-tool-name="${name}" data-base-acl-state="ready" data-bulk-id="${name}" data-bulk-label="${label}">
    <td>${label}</td><td><span class="badge perm-overall">Ready</span><span class="badge perm-override">Ready</span></td>
    <td><button class="btn perm-toggle" data-name="${name}" data-label="${label}" data-action="${action}">${action === "disable" ? "Block" : "Allow"}</button></td></tr>`;
  const w = boot(`<p id="perm-msg"></p><table><thead><tr><th>Tool</th><th>Status</th><th>Access</th></tr></thead>
    <tbody id="perm-tool-rows">${row("web_fetch", "Web fetch", "disable")}${row("shell", "Shell", "enable")}</tbody></table>`,
  "https://fixture.invalid/permissions");
  const calls = [];
  w.fetch = async url => {
    if (url.startsWith("/api/v1/policy-preview/tools")) {
      assert.equal(url, "/api/v1/policy-preview/tools?tools=web_fetch%2Cshell");
      return {ok: true, status: 200, headers: new w.Headers(), json: async () => ({recorded: true, calls: 42, tasks: 9, agents: 3, people: 2})};
    }
    calls.push(url);
    if (url.endsWith("/disable")) return {ok: true, status: 204, json: async () => ({})};
    return {ok: true, status: 200, json: async () => ({tool: {name: url.split("/")[5], overlay_blocked: false, base_acl_allowed: true, usable: true, state: "ready"}})};
  };
  const start = page.indexOf("  <script>\n    (function() {\n      const msg = document.getElementById('perm-msg');");
  w.eval(page.slice(start + "  <script>".length, page.indexOf("</script>", start)));
  selectAll(w);
  bulkButton(w, "Block selected").click();
  await flush();
  // The confirmation previews what blocking would have stopped.
  assert.match(w.confirms[0], /^Block 2 tools\? Web fetch and Shell\. In the last 30 days they were used 42 times in 9 tasks by 3 agents and specialists for 2 people\. Tasks stop using them at once\./);
  assert.deepEqual(calls, ["/api/v1/permissions/tools/web_fetch/disable"]);
  assert.match(report(w).textContent, /Block: 1 done, 1 not changed/);
  assert.match(report(w).textContent, /Shell — not changed: It is already blocked\./);
  assert.equal(w.document.querySelector('button[data-name="web_fetch"]').textContent, "Allow");
  [...report(w).querySelectorAll("button")].find(b => /Undo these changes/.test(b.textContent)).click();
  await flush();
  assert.deepEqual(calls.slice(1), ["/api/v1/permissions/tools/web_fetch/enable"]);
  assert.equal(w.document.querySelector('button[data-name="web_fetch"]').textContent, "Block");
  w.close();
});

test("privacy requests: assign to a listed person, undo restores each earlier assignee", async () => {
  const page = read("templates/privacy.html");
  const row = (id, who, assignee) => `<tr data-bulk-id="${id}" data-bulk-label="${who} (${id})" data-acknowledged="no" data-status="open">
    <td>${who}</td><td class="pw-dsar-assignee">${assignee || "Not assigned"}</td></tr>`;
  const w = boot(`<table><thead><tr><th>Person</th><th>Assigned to</th></tr></thead><tbody id="pw-dsar-rows">
    ${row("DSAR-1", "jo@example.com", "")}${row("DSAR-2", "sam@example.com", "Dana")}</tbody></table>
    <script type="application/json" id="pw-dsar-assignees">[{"principal":"user:dana","label":"Dana"},{"principal":"user:lee","label":"Lee"}]</script>`,
  "https://fixture.invalid/privacy");
  const forms = [], posts = [];
  w.mvForm = async (title, fields) => { forms.push(Array.from(fields[0].options, o => o.label)); return {assignee: "user:lee"}; };
  const before = {"DSAR-1": "", "DSAR-2": "user:dana"};
  w.mvFetchJSON = async (url, opts) => {
    const id = url.split("/")[5], body = opts.body || {};
    posts.push(url + " " + JSON.stringify(body));
    const previous = before[id]; before[id] = body.assignee;
    return {id, assignee: body.assignee, previous_assignee: previous};
  };
  const marker = "  // Many requests at once: filter, select all matching, then assign";
  const start = page.indexOf(marker);
  assert.ok(start > 0);
  w.eval(page.slice(start, page.indexOf("  // Incident register: record the notification decision", start)));
  selectAll(w);
  bulkButton(w, "Assign selected").click();
  await flush();
  assert.deepEqual(forms[0], ["Nobody (not assigned)", "Dana", "Lee"], "only people who may work requests");
  assert.equal([...w.document.querySelectorAll(".pw-dsar-assignee")].map(c => c.textContent).join("|"), "Lee|Lee");
  [...report(w).querySelectorAll("button")].find(b => /Undo these changes/.test(b.textContent)).click();
  await flush();
  assert.deepEqual(posts.slice(2), ['/api/v1/privacy/dsar/DSAR-1/assign {"assignee":""}', '/api/v1/privacy/dsar/DSAR-2/assign {"assignee":"user:dana"}']);
  assert.equal([...w.document.querySelectorAll(".pw-dsar-assignee")].map(c => c.textContent).join("|"), "Not assigned|Dana");
  w.close();
});
