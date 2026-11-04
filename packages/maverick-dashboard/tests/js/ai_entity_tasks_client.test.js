// Run with: node --test packages/maverick-dashboard/tests/js/ai_entity_tasks_client.test.js
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function client() {
  const window = {};
  const context = { Date, TextDecoder, TextEncoder, console, window };
  vm.createContext(context);
  const source = fs.readFileSync(
    path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-ai-entity-tasks.js"),
    "utf8",
  );
  vm.runInContext(source, context, { filename: "lightwork-ai-entity-tasks.js" });
  return window.LightworkAIEntityTasksClient;
}

function headers(contentLength = null) {
  return {
    get(name) {
      return name.toLowerCase() === "content-length" ? contentLength : null;
    },
  };
}

function streamingResponse(chunks, { contentLength = null, ok = true, status = 200 } = {}) {
  let reads = 0;
  let cancelled = false;
  const reader = {
    async read() {
      const value = chunks[reads];
      reads += 1;
      return value === undefined ? { done: true } : { done: false, value };
    },
    async cancel() { cancelled = true; },
  };
  const body = {
    getReader() { return reader; },
    async cancel() { cancelled = true; },
  };
  return {
    response: { headers: headers(contentLength), body, ok, status },
    state: () => ({ reads, cancelled }),
  };
}

function plain(value) {
  return JSON.parse(JSON.stringify(value));
}

test("declared oversized task response is rejected before body allocation", async () => {
  const api = client();
  const fixture = streamingResponse([new Uint8Array([123])], {
    contentLength: String(api.MAX_RESPONSE_BYTES + 1),
  });

  await assert.rejects(api.readBoundedJson(fixture.response), (error) => {
    assert.equal(error.code, "response_too_large");
    return true;
  });
  assert.deepEqual(fixture.state(), { reads: 0, cancelled: true });
});

test("streaming task response cancels as soon as it crosses 64 KiB", async () => {
  const api = client();
  const fixture = streamingResponse([
    new Uint8Array(api.MAX_RESPONSE_BYTES),
    new Uint8Array([1]),
    new TextEncoder().encode('{"never":"read"}'),
  ]);

  await assert.rejects(api.readBoundedJson(fixture.response), (error) => {
    assert.equal(error.code, "response_too_large");
    return true;
  });
  assert.deepEqual(fixture.state(), { reads: 2, cancelled: true });
});

test("bounded task JSON parses and invalid JSON is never echoed", async () => {
  const api = client();
  const valid = streamingResponse([new TextEncoder().encode('{"ready":true}')]);
  assert.equal((await api.parseResponse(valid.response)).ready, true);

  const secret = "private-task-response-content";
  const invalid = streamingResponse([new TextEncoder().encode(secret)]);
  await assert.rejects(api.parseResponse(invalid.response), (error) => {
    assert.equal(error.code, "response_invalid_json");
    assert.equal(error.message.includes(secret), false);
    assert.equal(error.status, 200);
    return true;
  });
});

test("create payload contains only closed task fields and a future due date", () => {
  const api = client();
  const due = new Date(Date.now() + 3_600_000).toISOString();
  const payload = plain(api.buildCreatePayload({
    entity_id: "inventory:asset-7",
    entity_revision: "8",
    kind: "remediation",
    title: "Review runtime owner",
    description: "Confirm the assigned control owner.",
    assignee_ref: "team:risk",
    collaborator_refs: "team:privacy, team:risk,team:privacy",
    priority: "high",
    due_at: due,
    idempotency_key: "create:asset-7:8",
    tenant_id: "caller-tenant",
    actor_ref: "caller-actor",
    entity_authority_sha256: "f".repeat(64),
  }));

  assert.equal(payload.entity_id, "inventory:asset-7");
  assert.equal(payload.entity_revision, 8);
  assert.deepEqual(payload.collaborator_refs, ["team:privacy", "team:risk"]);
  assert.equal(payload.due_at > Date.now() / 1000, true);
  assert.equal("tenant_id" in payload, false);
  assert.equal("actor_ref" in payload, false);
  assert.equal("entity_authority_sha256" in payload, false);
});

test("update payload expresses explicit clear operations without identity injection", () => {
  const api = client();
  const payload = plain(api.buildUpdatePayload({
    expected_revision: "4",
    idempotency_key: "update:task-4:clear",
    status: "blocked",
    priority: "critical",
    assignee_action: "clear",
    assignee_ref: "ignored:assignee",
    collaborator_action: "clear",
    collaborator_refs: "ignored:collaborator",
    due_action: "clear",
    due_at: "",
    tenant_id: "caller-tenant",
    principal_ref: "caller-principal",
  }));

  assert.deepEqual(payload, {
    expected_revision: 4,
    idempotency_key: "update:task-4:clear",
    status: "blocked",
    priority: "critical",
    assignee_ref: null,
    collaborator_refs: [],
    due_at: null,
  });
  assert.equal("tenant_id" in payload, false);
  assert.equal("principal_ref" in payload, false);
});

test("empty update and malformed collaborator references fail before transport", () => {
  const api = client();
  assert.throws(() => api.buildUpdatePayload({
    expected_revision: "1",
    idempotency_key: "empty:update",
    status: "",
    priority: "",
    assignee_action: "keep",
    collaborator_action: "keep",
    due_action: "keep",
  }), /Select at least one/);
  assert.throws(() => api.splitRefs("good-ref,not allowed"), /valid reference/);
  assert.throws(() => api.splitRefs(
    Array.from({ length: 65 }, (_, index) => "person:" + index).join(","),
  ), /64 collaborators/);
});

// ---- page behaviour (jsdom) -------------------------------------------
const { JSDOM } = require("jsdom");
const {shell: loadShell} = require("./_shell");
const pageTemplate = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates/ai_entity_tasks.html"), "utf8");
const pageSource = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-ai-entity-tasks.js"), "utf8");
const pageBody = pageTemplate.slice(pageTemplate.indexOf('<div class="aet-shell"'), pageTemplate.lastIndexOf("{% endblock %}", pageTemplate.indexOf("{% block scripts_extra %}")))
  .replace("{{ api_base }}", "/api/v1/ai-entity-tasks")
  .replace(/\{\{\s*hero\([^}]*\}\}/, "").replace(/\{%[^%]*%\}/g, "").replace(/\{\{[^}]*\}\}/g, "true");
const TASK = { task_id: "task-1", entity_id: "asset-7", title: "Review owner", status: "open", priority: "medium",
  assignee_ref: "user:local", collaborator_refs: [], due_at: null, revision: 3 };

function streamed(value, status = 200) {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let sent = false;
  return { ok: status < 400, status, headers: { get: () => null },
    body: { getReader: () => ({ async read() { if (sent) return { done: true }; sent = true; return { done: false, value: bytes }; }, async cancel() {} }) },
    async text() { return JSON.stringify(value); } };
}

function page(t) {
  const dom = new JSDOM(`<main>${pageBody}</main>`, { url: "https://lightwork.test/ai-entity-tasks", runScripts: "outside-only" });
  t.after(() => dom.window.close());
  const w = dom.window;
  w.TextDecoder = TextDecoder;
  const calls = [];
  w.fetch = async (url, options = {}) => {
    const key = (options.method || "GET") + " " + url;
    calls.push({ key, body: options.body ? JSON.parse(options.body) : undefined });
    if (key.endsWith("/ai-entity-tasks/status")) return streamed({ ready: true, enabled: true, configured: true });
    if (key.endsWith("/assurance/ai-inventory")) return streamed({ assets: [{ asset_id: "asset-7", revision: 8, status: "present", display_name: "Claims assistant", asset_type: "agent" }] });
    if (key.endsWith("/people/assignable")) return streamed({ items: [{ ref: "user:local", label: "Local operator", is_you: true }, { ref: "person:abc", label: "Dana" }] });
    if (key.includes("/ai-entity-tasks?")) return streamed({ items: [TASK], count: 1 });
    if (key === "GET /api/v1/ai-entity-tasks/task-1") return streamed(TASK);
    if (key.startsWith("PATCH")) return streamed({ ...TASK, status: "in_progress", revision: 4 });
    if (key.startsWith("POST /api/v1/ai-entity-tasks") && !key.includes("operations")) return streamed({ ...TASK, task_id: "task-2" }, 201);
    return streamed({ count: 0, items: [] });
  };
  loadShell(w);
  w.eval(pageSource);
  const settle = async () => { for (let i = 0; i < 40; i += 1) await new Promise((r) => setImmediate(r)); };
  return { w, calls, settle, $: (id) => w.document.getElementById(id) };
}

test("tasks load as a table with names instead of references", async (t) => {
  const h = page(t);
  await h.settle();
  const text = h.$("aet-task-list").textContent;
  assert.match(text, /Review owner/);
  assert.match(text, /Claims assistant \(Agent\)/);
  assert.match(text, /Local operator \(you\)/);
  assert.doesNotMatch(text, /asset-7|task-1|user:local/);
});

test("editing sends only what changed with the task's version", async (t) => {
  const h = page(t);
  await h.settle();
  [...h.$("aet-task-list").querySelectorAll("button")].find((b) => b.textContent === "Edit").click();
  await h.settle();
  assert.equal(h.$("aet-update-panel").hidden, false);
  const form = h.$("aet-update-form");
  form.elements.namedItem("status").value = "in_progress";
  form.dispatchEvent(new h.w.Event("submit", { cancelable: true }));
  await h.settle();
  const patch = h.calls.find((c) => c.key.startsWith("PATCH"));
  assert.equal(patch.body.expected_revision, 3);
  assert.equal(patch.body.status, "in_progress");
  assert.equal("assignee_ref" in patch.body, false);
  assert.equal("due_at" in patch.body, false);
});

test("creating a task pins the AI system version from the picker", async (t) => {
  const h = page(t);
  await h.settle();
  const form = h.$("aet-create-form");
  form.elements.namedItem("entity_id").value = "asset-7";
  form.elements.namedItem("title").value = "Check the model card";
  form.elements.namedItem("assignee_ref").value = "person:abc";
  form.dispatchEvent(new h.w.Event("submit", { cancelable: true }));
  await h.settle();
  const post = h.calls.find((c) => c.key === "POST /api/v1/ai-entity-tasks");
  assert.equal(post.body.entity_id, "asset-7");
  assert.equal(post.body.entity_revision, 8);
  assert.equal(post.body.assignee_ref, "person:abc");
});

// ---- no loader keeps saying "Loading" ---------------------------------------
function settledPage(t, answer, moduleEnabled = "") {
  const dom = new JSDOM(`<main>${pageBody}</main>`, { url: "https://lightwork.test/ai-entity-tasks", runScripts: "outside-only" });
  t.after(() => dom.window.close());
  const w = dom.window;
  w.TextDecoder = TextDecoder;
  w.document.getElementById("ai-entity-task-shell").dataset.moduleEnabled = moduleEnabled;
  w.mvErrorText = (failure, action) => "Could not " + action + ". Try again in a few minutes.";
  const calls = [];
  w.fetch = async (url) => { calls.push(String(url)); return answer(String(url)); };
  loadShell(w);
  w.eval(pageSource);
  const settle = async () => { for (let i = 0; i < 40; i += 1) await new Promise((r) => setImmediate(r)); };
  return { w, calls, settle, text: (id) => w.document.getElementById(id).textContent };
}

test("a failed availability check leaves no task loader spinning", async (t) => {
  const h = settledPage(t, () => streamed({ detail: "unavailable" }, 503));
  await h.settle();
  assert.equal(h.text("aet-readiness"), "Unavailable");
  assert.equal(h.text("aet-list-status"), "Could not load the tasks. Try again in a few minutes.");
  assert.doesNotMatch(h.text("aet-list-status") + h.text("aet-readiness-detail") + h.text("aet-inventory-status"), /Loading|Checking/);
});

test("unfinished setup says when tasks will appear instead of loading forever", async (t) => {
  const h = settledPage(t, () => streamed({ enabled: true, configured: false, ready: false }));
  await h.settle();
  assert.equal(h.text("aet-readiness"), "Setup not finished");
  assert.equal(h.text("aet-list-status"), "Tasks appear here once an administrator finishes the setup.");
  assert.equal(h.text("aet-inventory-status"), "AI systems can be chosen once an administrator finishes the setup.");
});

test("a server that reports the module off says so without pointing at a missing gate", async (t) => {
  const h = settledPage(t, () => streamed({ enabled: false, configured: false, ready: false }));
  await h.settle();
  assert.equal(h.text("aet-readiness-detail"), "AI system tasks are turned off. Ask an administrator to turn them on.");
  assert.equal(h.text("aet-list-status"), "Tasks appear here once AI system tasks are turned on.");
  assert.equal(h.text("aet-inventory-status"), "AI systems can be chosen once AI system tasks are turned on.");
});

test("a turned-off module starts no checks or loads behind its gate", async (t) => {
  const h = settledPage(t, () => { throw new Error("no request expected"); }, "false");
  await h.settle();
  assert.deepEqual(h.calls, []);
});
