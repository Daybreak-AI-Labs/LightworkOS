"use strict";

// Added for the companion preview. Execution is deferred at the user's request.
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {JSDOM} = require("jsdom");

const CONTEXT = "employee-workspace-context";
const script = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-employee-companion.js"), "utf8");
const tick = () => new Promise(resolve => setImmediate(resolve));
const policy = overrides => ({owner: "user:employee@example.test", revision: 3, enabled: true,
  allowed_sources: ["own_tasks"], allowed_tools: ["task_status"], retention_days: 0, ...overrides});
const snapshot = overrides => ({context: CONTEXT, available: true, conversation_available: false,
  status_available: true, history_generation: 0, history_revision: "a".repeat(64),
  active_turn: null, policy: policy(), history: [], tasks: [], ...overrides});
const reply = overrides => ({context: CONTEXT, policy: policy(), history: [], history_generation: 0,
  message: {role: "assistant", kind: "task_status", content: "One task is running.", sources: []}, ...overrides});
const adminSnapshot = overrides => ({context: CONTEXT, available: true,
  employees: [{principal: "user:employee@example.test", label: "Employee One"}],
  policies: [policy()], events: [], ...overrides});
const response = (payload, status = 200) => ({ok: status >= 200 && status < 300, status,
  text: async () => typeof payload === "string" ? payload : JSON.stringify(payload)});

async function setup(queue, admin = false, query = "") {
  const filename = admin ? "employee_companion_admin.html" : "employee_companion.html";
  const template = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates", filename), "utf8")
    .replace(/{%[\s\S]*?%}/g, "")
    .replace(/{{ companion_context \| default\(''\) }}/g, CONTEXT)
    .replace(/{{[\s\S]*?}}/g, "");
  const dom = new JSDOM(template, {url: "https://lightwork.test/companion" + (admin ? "/admin" : "") + query, runScripts: "outside-only"});
  const calls = [];
  dom.window.fetch = async (url, options) => {
    calls.push({url, options});
    const next = queue.shift();
    if (next instanceof Error) throw next;
    if (typeof next === "function") return next(url, options);
    if (next === undefined) throw new Error("Unexpected request");
    return response(next);
  };
  dom.window.eval(script);
  await tick();
  return {dom, window: dom.window, document: dom.window.document, calls,
    el: id => dom.window.document.getElementById(id)};
}
function submit(ui, id) {
  ui.el(id).dispatchEvent(new ui.window.Event("submit", {bubbles: true, cancelable: true}));
}

test("unsaved conversations show both turns safely and bind requests to the rendered account", async t => {
  const ui = await setup([snapshot(), reply({message: {role: "assistant", content: "<img src=x onerror=alert(1)>", sources: [
    {goal_id: 8, href: "javascript:alert(1)", status: "active", checked_at: 1700000000},
    {goal_id: 9, href: "/chat/goal/9", status: "active", checked_at: 1700000000}
  ]}})]);
  t.after(() => ui.dom.window.close());
  ui.el("ec-message").value = "What is running?";
  submit(ui, "ec-message-form");
  await tick();
  assert.match(ui.el("ec-messages").textContent, /What is running\?/);
  assert.match(ui.el("ec-messages").textContent, /<img src=x onerror=alert\(1\)>/);
  assert.equal(ui.el("ec-messages").querySelector("img"), null);
  assert.equal(ui.el("ec-messages").querySelectorAll("a").length, 1);
  assert.equal(ui.el("ec-messages").querySelector("a").getAttribute("href"), "/chat/goal/9");
  assert.match(ui.el("ec-messages").querySelector("a").textContent, /Task 9/);
  assert.equal(ui.calls[0].options.headers["X-Lightwork-Companion-Context"], CONTEXT);
  assert.equal(ui.calls[1].options.headers["X-Lightwork-Companion-Context"], CONTEXT);
  assert.equal(ui.calls[1].options.credentials, "same-origin");
  assert.deepEqual(JSON.parse(ui.calls[1].options.body), {message: "What is running?", mode: "task_status", expected_revision: 3, expected_history_generation: 0});
  assert.equal(ui.el("ec-message").value, "");
  assert.equal(ui.window.localStorage.length, 0);
  assert.equal(ui.el("ec-message-form").closest('[data-draft-recovery="off"]'), ui.el("ec-root"));
});

test("retained answers display only their newly authorized source links", async t => {
  const saved = policy({retention_days: 7});
  const ui = await setup([snapshot({policy: saved}), reply({policy: saved, history: [
    {role: "user", content: "What is running?"}, {role: "assistant", content: "One task is running.", sources: []}
  ], message: {role: "assistant", content: "One task is running.", sources: [
    {goal_id: 2, href: "/chat/goal/2", status: "active", checked_at: 1700000000}
  ]}})]);
  t.after(() => ui.dom.window.close());
  ui.el("ec-message").value = "What is running?";
  submit(ui, "ec-message-form");
  await tick();
  assert.equal(ui.el("ec-messages").querySelector("a").getAttribute("href"), "/chat/goal/2");
});

test("lost access clears private messages and drafts even when denial is an HTML response", async t => {
  const ui = await setup([snapshot({history: [{role: "user", content: "Private question"}]}),
    () => response("<h1>Sign in again</h1>", 401)]);
  t.after(() => ui.dom.window.close());
  ui.el("ec-message").value = "Unsent private question";
  ui.el("ec-refresh").click();
  await tick();
  assert.equal(ui.el("ec-messages").textContent, "");
  assert.equal(ui.el("ec-message").value, "");
  assert.equal(ui.el("ec-message").disabled, true);
  assert.equal(ui.el("ec-refresh").disabled, true);
});

test("changed workspace is terminal and never displays the other workspace response", async t => {
  const ui = await setup([snapshot(), () => response({detail: {code: "companion_context_changed"}}, 409)]);
  t.after(() => ui.dom.window.close());
  ui.el("ec-message").value = "What is running?";
  submit(ui, "ec-message-form");
  await tick();
  assert.equal(ui.el("ec-message").value, "");
  assert.equal(ui.el("ec-send").disabled, true);
  assert.equal(ui.el("ec-refresh").disabled, true);
  assert.match(ui.el("ec-status").textContent, /account, workspace or access changed/);
});

test("failed requests preserve questions and suppress duplicate submissions", async t => {
  let release;
  const pending = new Promise(resolve => { release = resolve; });
  const ui = await setup([snapshot(), () => pending]);
  t.after(() => ui.dom.window.close());
  ui.el("ec-message").value = "What is running?";
  submit(ui, "ec-message-form");
  submit(ui, "ec-message-form");
  assert.equal(ui.calls.length, 2);
  assert.equal(ui.el("ec-send").disabled, true);
  release(response({detail: "Temporary outage"}, 503));
  await tick();
  assert.equal(ui.el("ec-message").value, "What is running?");
  assert.equal(ui.el("ec-send").disabled, false);
  assert.match(ui.el("ec-status").textContent, /could not confirm/);
});

test("clearing history is possible when disabled and removes transient page messages", async t => {
  const ui = await setup([snapshot({available: false, policy: policy({enabled: false}),
    history: [{role: "user", content: "Previous question"}]}), {context: CONTEXT, history: []}]);
  t.after(() => ui.dom.window.close());
  assert.equal(ui.el("ec-send").disabled, true);
  assert.equal(ui.el("ec-clear").disabled, false);
  ui.el("ec-clear").click();
  assert.equal(ui.document.activeElement, ui.el("ec-clear-no"));
  ui.el("ec-clear-yes").click();
  await tick();
  assert.doesNotMatch(ui.el("ec-messages").textContent, /Previous question/);
  assert.equal(ui.calls[1].options.method, "DELETE");
  assert.deepEqual(JSON.parse(ui.calls[1].options.body), {expected_revision: "a".repeat(64)});
  assert.equal(ui.calls[1].options.headers["X-Lightwork-Companion-Context"], CONTEXT);
  assert.equal(ui.document.activeElement, ui.el("ec-clear"));
});

test("a confirmed Copilot clear removes local private text and reads current status", async t => {
  const ui = await setup([snapshot({history: [{role: "user", content: "Private draft"}]}),
    snapshot({history: [], history_generation: 1, history_revision: "b".repeat(64)})]);
  t.after(() => ui.dom.window.close());
  ui.el("ec-message").value = "Unsent private question";
  ui.document.dispatchEvent(new ui.window.CustomEvent("lightwork:product-operation-complete",
    {detail: {operation: "companion.clear_history", status: "confirmed"}}));
  await tick();
  assert.doesNotMatch(ui.el("ec-messages").textContent, /Private draft/);
  assert.equal(ui.el("ec-message").value, "");
  assert.equal(ui.calls.length, 2);
  assert.equal(ui.calls[1].options.method, "GET");
});

test("admin CAS conflict preserves choices and requires explicit reload", async t => {
  const ui = await setup([adminSnapshot(), () => response({detail: "Policy changed"}, 409), adminSnapshot({policies: [policy({revision: 4})]})], true);
  t.after(() => ui.dom.window.close());
  ui.el("ec-owner").value = "user:employee@example.test";
  ui.el("ec-owner").dispatchEvent(new ui.window.Event("change"));
  ui.el("ec-retention-days").value = "7";
  submit(ui, "ec-policy-form");
  await tick();
  assert.equal(ui.el("ec-retention-days").value, "7");
  assert.equal(ui.el("ec-save").disabled, true);
  assert.equal(JSON.parse(ui.calls[1].options.body).expected_revision, 3);
  submit(ui, "ec-policy-form");
  assert.equal(ui.calls.length, 2);
  ui.el("ec-refresh").click();
  await tick();
  assert.equal(ui.el("ec-revision").value, "4");
  assert.equal(ui.el("ec-retention-days").value, "0");
  assert.equal(ui.el("ec-save").disabled, false);
});

test("admin activity only renders approved metadata fields", async t => {
  const ui = await setup([adminSnapshot({events: [{owner: "user:employee@example.test",
    actor: "user:employee@example.test", action: "reply", time: 1700000000,
    message: "Private employee question", response: "Private companion answer", title: "Private task title"}]})], true);
  t.after(() => ui.dom.window.close());
  assert.match(ui.el("ec-events").textContent, /Companion question answered/);
  assert.doesNotMatch(ui.el("ec-events").textContent, /Private/);
  assert.equal(ui.el("ec-policy-form").closest('[data-draft-recovery="off"]'), ui.el("ec-root"));
});

test("AI draft request is bound to history and refresh remains available while it runs", async t => {
  const modelPolicy = policy({allowed_tools: ["task_status", "draft_reply"]});
  const current = snapshot({policy: modelPolicy, conversation_available: true, history_generation: 12});
  let release;
  const pending = new Promise(resolve => { release = resolve; });
  const ui = await setup([current, () => pending, current]);
  t.after(() => ui.dom.window.close());
  const copied = [];
  Object.defineProperty(ui.window.navigator, "clipboard", {value: {writeText: async text => { copied.push(text); }}});
  ui.el("ec-message").value = "Draft a team update";
  submit(ui, "ec-message-form");
  const body = JSON.parse(ui.calls[1].options.body);
  assert.equal(body.mode, "conversation");
  assert.equal(body.expected_history_generation, 12);
  assert.match(body.request_id, /^\d{13}\.[a-f0-9]{32}$/);
  assert.equal(ui.el("ec-send").disabled, true);
  assert.equal(ui.el("ec-refresh").disabled, false);
  assert.equal(ui.document.querySelector("[data-question]").disabled, true);
  ui.el("ec-refresh").click();
  await tick();
  assert.equal(ui.calls.length, 3);
  assert.equal(ui.el("ec-message").value, "Draft a team update");
  release(response(reply({policy: modelPolicy, history_generation: 12, request_id: body.request_id,
    message: {role: "assistant", kind: "draft", content: "<script>Review this draft</script>", sources: [
      {goal_id: 2, href: "/chat/goal/2", status: "active", checked_at: 1700000000}
    ]}})));
  await tick();
  assert.match(ui.el("ec-messages").textContent, /AI draft/);
  assert.match(ui.el("ec-messages").textContent, /Task context provided/);
  assert.equal(ui.el("ec-messages").querySelector("script"), null);
  ui.el("ec-messages").querySelector("button").click();
  await tick();
  assert.deepEqual(copied, ["<script>Review this draft</script>"]);
  assert.equal(ui.el("ec-send").disabled, false);
});

test("ambiguous model failure checks its receipt without resending a paid turn", async t => {
  const modelPolicy = policy({allowed_tools: ["draft_reply"], allowed_sources: []});
  let requestId;
  const ui = await setup([
    snapshot({policy: modelPolicy, conversation_available: true, status_available: false}),
    (_url, options) => { requestId = JSON.parse(options.body).request_id; return response({detail: "Provider connection lost"}, 503); },
    () => response({context: CONTEXT, request: {request_id: requestId, state: "completed"}, history: [], history_generation: 0, active_turn: null})
  ]);
  t.after(() => ui.dom.window.close());
  ui.el("ec-message").value = "Prepare a draft";
  submit(ui, "ec-message-form");
  await tick();
  assert.equal(ui.el("ec-send").disabled, true);
  assert.equal(ui.el("ec-message").value, "Prepare a draft");
  submit(ui, "ec-message-form");
  assert.equal(ui.calls.length, 2);
  ui.el("ec-check-reply").click();
  await tick();
  assert.equal(ui.calls.length, 3);
  assert.equal(ui.calls[2].options.method, "GET");
  assert.match(ui.calls[2].url, /\/requests\//);
  assert.match(ui.el("ec-reply-status").textContent, /cannot be recovered because history is not saved/);
  assert.match(ui.el("ec-reply-status").textContent, /new charge/);
  assert.equal(ui.el("ec-send").textContent, "Start a new reply");
  assert.match(ui.el("ec-retention").textContent, /follow-ups do not include earlier messages/);
});

test("clearing history prevents a late model response from repopulating the conversation", async t => {
  const modelPolicy = policy({allowed_tools: ["draft_reply"]});
  let release;
  const pending = new Promise(resolve => { release = resolve; });
  const ui = await setup([snapshot({policy: modelPolicy, conversation_available: true}), () => pending,
    {context: CONTEXT, history: [], history_generation: 1, active_turn: null}]);
  t.after(() => ui.dom.window.close());
  ui.el("ec-message").value = "Private draft request";
  submit(ui, "ec-message-form");
  ui.el("ec-clear").click();
  ui.el("ec-clear-yes").click();
  await tick();
  release(response(reply({policy: modelPolicy, message: {role: "assistant", kind: "draft", content: "Late private answer", sources: []}})));
  await tick();
  assert.doesNotMatch(ui.el("ec-messages").textContent, /Late private answer|Private draft request/);
  assert.equal(ui.el("ec-send").disabled, false);
});

test("loading an existing active turn requires reconciliation without starting another model call", async t => {
  const id = "1800000000000." + "a".repeat(32);
  const ui = await setup([snapshot({policy: policy({allowed_tools: ["draft_reply"]}), conversation_available: true,
    active_turn: {request_id: id, expires_at: 1800000300}}),
  {context: CONTEXT, request: {request_id: id, state: "pending"}, history: [], history_generation: 0, active_turn: {request_id: id}}]);
  t.after(() => ui.dom.window.close());
  assert.equal(ui.el("ec-send").disabled, true);
  ui.el("ec-check-reply").click();
  await tick();
  assert.equal(ui.calls.length, 2);
  assert.equal(ui.calls.every(call => call.options.method === "GET"), true);
  assert.match(ui.el("ec-reply-status").textContent, /still being prepared/);
});

test("an administrator can allow drafts independently from tasks and sources", async t => {
  const saved = policy({revision: 4, allowed_tools: ["draft_reply"], allowed_sources: []});
  const ui = await setup([adminSnapshot(), {context: CONTEXT, policy: saved}, adminSnapshot({policies: [saved]})], true);
  t.after(() => ui.dom.window.close());
  ui.el("ec-owner").value = saved.owner;
  ui.el("ec-owner").dispatchEvent(new ui.window.Event("change"));
  ui.el("ec-tool").checked = false;
  ui.el("ec-source").checked = false;
  ui.el("ec-draft-tool").checked = true;
  submit(ui, "ec-policy-form");
  await tick();
  const body = JSON.parse(ui.calls[1].options.body);
  assert.deepEqual(body.allowed_tools, ["draft_reply"]);
  assert.deepEqual(body.allowed_sources, []);
  assert.match(ui.el("ec-model-help").textContent, /provider's retention policy/);
});

test("named employee selection opens Copilot only after a native membership refresh and clears on lost access", async t => {
  const ui = await setup([adminSnapshot(), adminSnapshot(), () => response("Sign in", 403)], true);
  t.after(() => ui.dom.window.close());
  const selections = [];
  ui.document.addEventListener("lightwork:copilot-selection", event => selections.push(event.detail.selection));
  const opener = ui.document.createElement("button");opener.id = "mv-copilot-fab";opener.setAttribute("aria-expanded", "false");
  let opened = 0;opener.addEventListener("click", () => {opened += 1;opener.setAttribute("aria-expanded", "true");});
  ui.document.body.appendChild(opener);
  ui.el("ec-owner").value = "user:employee@example.test";
  ui.el("ec-owner").dispatchEvent(new ui.window.Event("change"));
  assert.equal(ui.el("ec-copilot").disabled, false);
  assert.equal(selections[0].kind, "companion_employee");
  assert.equal(selections[0].id, "user:employee@example.test");
  ui.el("ec-copilot").click();await tick();
  assert.equal(opened, 1);assert.equal(ui.calls[1].options.method, "GET");
  ui.el("ec-copilot").click();await tick();
  assert.equal(opened, 1);assert.deepEqual(JSON.parse(JSON.stringify(selections.at(-1))), {});
  assert.equal(ui.el("ec-copilot").disabled, true);assert.equal(ui.el("ec-owner").options.length, 0);
});

test("refresh clears unsaved task-derived text without losing an unsent question", async t => {
  const ui = await setup([snapshot(), reply({message: {role: "assistant", kind: "task_status",
    content: "Previously visible task detail", sources: [{goal_id: 9, href: "/chat/goal/9", status: "active", checked_at: 1700000000}]}}), snapshot()]);
  t.after(() => ui.dom.window.close());
  ui.el("ec-message").value = "What is running?";
  submit(ui, "ec-message-form");
  await tick();
  assert.match(ui.el("ec-messages").textContent, /Previously visible task detail/);
  ui.el("ec-message").value = "Unsent question";
  ui.el("ec-refresh").click();
  await tick();
  assert.doesNotMatch(ui.el("ec-messages").textContent, /Previously visible task detail/);
  assert.equal(ui.el("ec-message").value, "Unsent question");
  assert.match(ui.el("ec-retention").textContent, /Refresh clears unsaved conversation/);
});

test("own companion Copilot handoff checks current access and clears selection on refusal", async t => {
  const ui = await setup([snapshot(), snapshot(), () => response("Sign in", 403)]);
  t.after(() => ui.dom.window.close());
  const selections = [];
  ui.document.addEventListener("lightwork:copilot-selection", event => selections.push(event.detail.selection));
  const opener = ui.document.createElement("button");opener.id = "mv-copilot-fab";opener.setAttribute("aria-expanded", "false");
  let opened = 0;opener.addEventListener("click", () => {opened += 1;opener.setAttribute("aria-expanded", "true");});
  ui.document.body.appendChild(opener);
  ui.el("ec-own-copilot").click();await tick();
  assert.equal(opened, 1);assert.equal(ui.calls[1].options.method, "GET");
  ui.el("ec-own-copilot").click();await tick();
  assert.equal(opened, 1);assert.deepEqual(JSON.parse(JSON.stringify(selections.at(-1))), {});
  assert.equal(ui.el("ec-own-copilot").disabled, true);
});

test("a saved reply link reads that exact answer after navigation without a paid request", async t => {
  const id = "1800000000000." + "a".repeat(32), saved = policy({retention_days: 7});
  const current = snapshot({policy: saved, history: [{role: "assistant", content: "A different newer answer"}]});
  const ui = await setup([current, {...current, request: {request_id: id, state: "completed"},
    retained_reply: {role: "assistant", kind: "draft", content: "Exact saved answer\n<img src=x onerror=alert(1)>"}}], false, "?reply=" + id);
  t.after(() => ui.dom.window.close());await tick();
  assert.equal(ui.calls.length, 2);assert.equal(ui.calls.every(call => call.options.method === "GET"), true);
  assert.equal(ui.el("ec-retained-reply").hidden, false);
  assert.match(ui.el("ec-retained-answer").textContent, /Exact saved answer/);
  assert.equal(ui.el("ec-retained-answer").querySelector("img"), null);
  assert.match(ui.el("ec-reply-status").textContent, /exact saved answer/);
});

test("an unavailable exact reply never substitutes a newer retained answer", async t => {
  const id = "1800000000000." + "b".repeat(32), saved = policy({retention_days: 7});
  const current = snapshot({policy: saved, history: [{role: "assistant", content: "A different newer answer"}]});
  const ui = await setup([current, {...current, request: {request_id: id, state: "completed"}, retained_reply: null}], false, "?reply=" + id);
  t.after(() => ui.dom.window.close());await tick();
  assert.equal(ui.el("ec-retained-reply").hidden, true);assert.equal(ui.el("ec-retained-answer").textContent, "");
  assert.match(ui.el("ec-reply-status").textContent, /exact answer is no longer saved or currently accessible/);
  assert.equal(ui.calls.every(call => call.options.method === "GET"), true);
});

test("refresh rechecks a displayed exact reply before preserving any source-derived answer", async t => {
  const id = "1800000000000." + "c".repeat(32), saved = policy({retention_days: 7});
  const current = snapshot({policy: saved});
  const ui = await setup([current, {...current, request: {request_id: id, state: "completed"},
    retained_reply: {content: "Previously allowed private task facts"}}, current,
  {...current, request: {request_id: id, state: "completed"}, retained_reply: null}], false, "?reply=" + id);
  t.after(() => ui.dom.window.close());await tick();
  assert.match(ui.el("ec-retained-answer").textContent, /Previously allowed/);
  ui.el("ec-refresh").click();await tick();await tick();
  assert.equal(ui.el("ec-retained-reply").hidden, true);assert.equal(ui.el("ec-retained-answer").textContent, "");
  assert.equal(ui.calls.length, 4);assert.equal(ui.calls.every(call => call.options.method === "GET"), true);
});

test("a replayed Copilot clear does not leave the page ahead of the server and ignoring its updates", async t => {
  // The server did not change the generation (it replayed an earlier clear), so what it reports next is
  // equal to what the page already holds; those updates must still be applied.
  const ui = await setup([snapshot({history_generation: 4}),
    snapshot({history_generation: 4, policy: policy({revision: 5}), tasks: [{id: 7, title: "Quarterly review", status: "active"}]})]);
  t.after(() => ui.dom.window.close());
  ui.document.dispatchEvent(new ui.window.CustomEvent("lightwork:product-operation-complete",
    {detail: {operation: "companion.clear_history", status: "replayed"}}));
  await tick();
  assert.equal(ui.calls.length, 2);
  assert.match(ui.document.body.textContent, /Quarterly review/);
});

test("a reply that was in flight when the history was cleared is dropped", async t => {
  let release;
  const slow = () => new Promise(resolve => { release = () => resolve(response(reply({
    message: {role: "assistant", kind: "task_status", content: "Late answer about private history.", sources: []}}))); });
  const ui = await setup([snapshot(), slow, snapshot({history: [], history_generation: 0})]);
  t.after(() => ui.dom.window.close());
  ui.el("ec-message").value = "What is running?";
  submit(ui, "ec-message-form");
  await tick();
  ui.document.dispatchEvent(new ui.window.CustomEvent("lightwork:product-operation-complete",
    {detail: {operation: "companion.clear_history", status: "confirmed"}}));
  await tick();
  release();
  await tick();
  assert.doesNotMatch(ui.el("ec-messages").textContent, /Late answer/);
});
