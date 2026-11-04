"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const core = require("../../maverick_dashboard/templates/flow_designer_core.js");
const inputs = require("../../maverick_dashboard/templates/flow_designer_inputs.js");
const draft = require("../../maverick_dashboard/templates/flow_designer_draft.js");
const schedule = require("../../maverick_dashboard/templates/flow_designer_schedule.js");
const wire = require("../../maverick_dashboard/templates/flow_designer_wire.js");
const transport = require("../../maverick_dashboard/templates/flow_designer_transport.js");
const historyModule = require("../../maverick_dashboard/templates/flow_designer_history.js");
const source = fs.readFileSync(path.resolve(__dirname,
  "../../maverick_dashboard/templates/flow_designer.js"), "utf8");
const clone = value => JSON.parse(JSON.stringify(value));
function element(tag = "div") {
  return { tagName: tag.toUpperCase(), children: [], attributes: {}, value: "", textContent: "", disabled: false,
    appendChild(child) { child.parentNode = this; this.children.push(child); return child; },
    removeChild(child) { this.children.splice(this.children.indexOf(child), 1); child.parentNode = null; },
    setAttribute(name, value) { this.attributes[name] = value; },
    removeAttribute(name) { delete this.attributes[name]; },
    addEventListener(name, fn) { this[name] = fn; },
    focus() { this.focused = true; },
  };
}
function fixture() {
  const log = element(), input = element("input"), calls = [], painted = [], history = [], messages = [];
  const context = { chatHistory: [], rootFlow: { id: "orders", name: "Orders", version: 2, revision: "saved-2",
      published: true, published_version: 1, published_revision: "published-1",
      start: "lookup", nodes: [{ id: "lookup", kind: "action", tool: "lookup", label: "Original" }] },
    view: { x: 23, y: 42, k: 0.8 }, lastRunId: null, draftGeneration: 0, pendingDraft: null,
    saveInFlight: false, publishInFlight: false, applyInFlight: false, retireInFlight: false, actionFieldsChecking: false,
    FDActionFields: {async ready() {}, check() { return []; }, validDetails() { return true; }}, syncSaveButtons() {},
    FDCore: core, FDRecipeInputs: inputs, FDDraft: draft, FDSchedule: schedule, FDWire: wire, FDTransport: transport, FDHistory: historyModule, rawErrors: [],
    commitRawFields() { return context.rawErrors; },
    draftSnapshot() { return JSON.stringify(context.rootFlow); },
    toApiFlow() { return clone(context.rootFlow); },
    fromApiFlow(flow) { painted.push(clone(flow)); context.rootFlow = clone(flow); },
    pushHistory() { history.push(clone(context.rootFlow)); }, render() {},
    say(text, error = false) { messages.push({ text, error }); },
    document: { createElement: element, getElementById(id) { return id === "fd-chat-input" ? input : log; } },
    apiFetch(url, options) {
      return new Promise((resolve, reject) => calls.push({ url, options, resolve, reject }));
    },
  };
  vm.runInNewContext(source.slice(source.indexOf("  // ---- copilot chat:"),
    source.indexOf("  function chatToggle(")), context);
  function send(text) { input.value = text; context.chatSend(); }
  function finish(index, label, extra = {}) {
    const base = JSON.parse(calls[index].options.body).flow;
    const body = { reply: "Suggestion " + label, flow: { ...base,
      nodes: [{ id: "lookup", kind: "action", tool: "lookup", label }] }, ...extra };
    calls[index].resolve({ ok: true, json: async () => body, text: async () => JSON.stringify(body) });
  }
  function allNodes(node = log) { return [node, ...node.children.flatMap(child => allNodes(child))]; }
  return { context, input, calls, painted, history, messages, send, finish, allNodes,
    buttons: () => allNodes().filter(node => node.tagName === "BUTTON"),
    text: () => allNodes().map(node => node.textContent).join("\n") };
}
const turn = () => new Promise(resolve => setImmediate(resolve));

test("a delayed Copilot reply cannot replace edits made while it was thinking", async () => {
  const ui = fixture(); ui.send("Add an order check");
  ui.context.rootFlow.nodes[0].label = "My later edit";
  ui.finish(0, "Older suggestion"); await turn();
  assert.equal(ui.context.rootFlow.nodes[0].label, "My later edit");
  assert.equal(ui.history.length, 0);
  assert.match(ui.text(), /Suggestion Older suggestion/);
  assert.equal(ui.buttons().find(button => button.textContent === "Update for current workflow").disabled, false);
});
for (const order of [[1, 0], [0, 1]]) test(`only the newest overlapping request applies, completion order ${order}`, async () => {
  const ui = fixture(); ui.send("First instruction"); ui.send("Newer instruction");
  for (const index of order) { ui.finish(index, index ? "Newest" : "Old"); await turn(); }
  assert.equal(ui.context.rootFlow.nodes[0].label, "Newest");
  assert.equal(ui.painted.length, 1);
  assert.equal(ui.history.length, 1);
});
test("a duplicate pending instruction on the same draft does not send twice", () => {
  const ui = fixture(); ui.send("Add an order check"); ui.send("Add an order check");
  assert.equal(ui.calls.length, 1);
});
for (const flag of ["saveInFlight", "publishInFlight", "applyInFlight"]) {
  test(`a reply arriving during ${flag} remains a recoverable suggestion`, async () => {
    const ui = fixture(); ui.send("Add an order check"); ui.context[flag] = true;
    ui.finish(0, "Older suggestion"); await turn();
    assert.equal(ui.painted.length, 0); assert.equal(ui.buttons().length, 1);
  });
}
test("a changed saved revision cannot be reset by an old response", async () => {
  const ui = fixture(); ui.send("Add an order check"); ui.context.rootFlow.revision = "saved-3";
  ui.finish(0, "Older suggestion"); await turn();
  assert.equal(ui.context.rootFlow.revision, "saved-3"); assert.equal(ui.painted.length, 0);
});
test("recovery sends the original instruction against current edits, without clearing an unsent message", async () => {
  const ui = fixture(); ui.send("Add an order check");
  ui.context.rootFlow.nodes[0].label = "My later edit";
  ui.finish(0, "Older suggestion"); await turn();
  ui.input.value = "An unsent thought";
  const button = ui.buttons()[0]; button.click(); button.click();
  assert.equal(ui.calls.length, 2);
  assert.equal(button.disabled, true);
  assert.equal(button.attributes["aria-busy"], "true");
  const request = JSON.parse(ui.calls[1].options.body);
  assert.equal(request.message, "Add an order check");
  assert.equal(request.flow.nodes[0].label, "My later edit");
  assert.match(request.history.find(entry => entry.role === "assistant").content, /not applied/);
  assert.equal(ui.input.value, "An unsent thought");
  ui.finish(1, "Updated suggestion"); await turn();
  assert.equal(ui.context.rootFlow.nodes[0].label, "Updated suggestion");
  assert.equal(ui.history[0].nodes[0].label, "My later edit");
  assert.equal(button.disabled, false);
});
test("a recovered request still cannot overwrite another edit made while it runs", async () => {
  const ui = fixture(); ui.send("Add an order check");
  ui.context.rootFlow.nodes[0].label = "First edit";
  ui.finish(0, "Older suggestion"); await turn(); ui.buttons()[0].click();
  ui.context.rootFlow.nodes[0].label = "Second edit";
  ui.finish(1, "Still stale"); await turn();
  assert.equal(ui.context.rootFlow.nodes[0].label, "Second edit");
  assert.equal(ui.painted.length, 0); assert.equal(ui.buttons().length, 2);
});
test("a failed newest request never revives an older proposal or retries automatically", async () => {
  const ui = fixture(); ui.send("Older"); ui.send("Newer");
  ui.calls[1].reject(new Error("private failure detail")); await turn();
  ui.finish(0, "Old"); await turn();
  assert.equal(ui.painted.length, 0); assert.equal(ui.calls.length, 2);
  assert.doesNotMatch(ui.text(), /private failure/);
  assert.equal(ui.buttons().length, 2);
});
test("an explanation-only response stays useful without changing the canvas", async () => {
  const ui = fixture(); ui.send("Explain the approval");
  ui.context.rootFlow.nodes[0].label = "My edit";
  ui.finish(0, "Explanation", { flow: null }); await turn();
  assert.equal(ui.context.rootFlow.nodes[0].label, "My edit");
  assert.match(ui.text(), /Suggestion Explanation/);
  assert.equal(ui.buttons().length, 0); assert.equal(ui.history.length, 0);
});
test("replies and conversation history remain paired with their instructions", async () => {
  const ui = fixture(); ui.send("First"); ui.send("Second");
  ui.finish(1, "Second"); await turn(); ui.finish(0, "First"); await turn();
  assert.ok(ui.text().indexOf("Suggestion First") < ui.text().indexOf("Suggestion Second"));
  const history = clone(ui.context.chatHistory);
  assert.deepEqual(history.map(item => item.role), ["user", "assistant", "user", "assistant"]);
  assert.equal(history[0].content, "First"); assert.match(history[1].content, /not applied.*Suggestion First/);
  assert.equal(history[2].content, "Second"); assert.match(history[3].content, /Applied.*Suggestion Second/);
});
test("a fresh response keeps current publication receipts and offers one-step undo", async () => {
  const ui = fixture(), before = clone(ui.context.rootFlow), view = clone(ui.context.view);
  ui.send("Rename the step");
  ui.finish(0, "New label", { flow: { id: "orders", name: "Orders", start: "lookup", version: 999,
    nodes: [{ id: "lookup", kind: "action", tool: "lookup", label: "New label" }] } }); await turn();
  assert.equal(ui.painted.length, 1); assert.deepEqual(ui.history, [before]);
  assert.deepEqual(clone(ui.context.view), view);
  for (const key of ["version", "revision", "published", "published_version", "published_revision"])
    assert.equal(ui.context.rootFlow[key], before[key]);
  assert.match(ui.text(), /not|before saving/);
  assert.equal(ui.calls[0].url, "/api/v1/flows/chat");
});
test("a different loaded flow, even with identical data, invalidates the response", async () => {
  const ui = fixture(); ui.send("Add an order check");
  ui.context.rootFlow = clone(ui.context.rootFlow);
  ui.finish(0, "Older suggestion"); await turn(); assert.equal(ui.painted.length, 0);
});
test("buffered invalid edits and top-level form values use the actual editable snapshot", async () => {
  const ui = fixture();
  const controls = { "fd-maxdollars": { value: "5" } };
  const originalGet = ui.context.document.getElementById;
  ui.context.document.getElementById = id => controls[id] || originalGet(id);
  ui.context.idInput = { value: "orders" }; ui.context.nameInput = { value: "Orders" }; ui.context.flowInputs = [];
  vm.runInNewContext(source.slice(source.indexOf("  function draftSnapshot("), source.indexOf("  function markClean(")), ui.context);
  ui.send("Add an order check"); controls["fd-maxdollars"].value = "10";
  ui.context.rootFlow.nodes[0]._paramsRaw = "{unfinished";
  ui.finish(0, "Old"); await turn();
  assert.equal(controls["fd-maxdollars"].value, "10");
  assert.equal(ui.context.rootFlow.nodes[0]._paramsRaw, "{unfinished"); assert.equal(ui.painted.length, 0);
});
for (const reason of ["invalid settings", "pending save", "pending draft"]) test(`request preparation preserves input during ${reason}`, () => {
  const ui = fixture();
  if (reason === "invalid settings") ui.context.rawErrors = ["private_node.params"];
  if (reason === "pending save") ui.context.saveInFlight = true;
  if (reason === "pending draft") ui.context.pendingDraft = {};
  ui.send("Keep my instruction");
  assert.equal(ui.calls.length, 0); assert.equal(ui.input.value, "Keep my instruction");
  assert.doesNotMatch(ui.messages[0].text, /JSON|private_node/);
});
test("a newer Draft operation also makes a delayed Copilot response stale", async () => {
  const ui = fixture(); ui.send("Older copilot request"); ui.context.draftGeneration++;
  ui.finish(0, "Old"); await turn(); assert.equal(ui.painted.length, 0);
});
for (const flow of [{ nodes: [] }, { start: "missing", nodes: [{ id: "one", kind: "action", tool: "lookup" }] }, []]) {
  test(`malformed graph response preserves the draft: ${JSON.stringify(flow)}`, async () => {
    const ui = fixture(); ui.send("Update this"); ui.finish(0, "Malformed", { flow }); await turn();
    assert.equal(ui.painted.length, 0); assert.equal(ui.history.length, 0); assert.equal(ui.buttons().length, 1);
  });
}
test("learned evidence keeps exact float and large integer tokens through the actual chat wire and parser", async () => {
  const ui = fixture();
  const evidence = '{"schema":"lightwork.action-recipe.v1","artifact_sha256":"wire-only-fixture",' +
    '"episodes":[{"amount":1.0,"counter":9007199254740993}]}';
  ui.context.rootFlow = inputs.parseText(JSON.stringify(ui.context.rootFlow).replace(/}$/, ',"learned_recipe":' + evidence + '}'));
  ui.send("Explain this");
  assert.ok(ui.calls[0].options.body.includes(evidence));
  const graph = inputs.flowText(ui.context.rootFlow);
  ui.calls[0].resolve({ ok: true, text: async () => '{"reply":"Same evidence","flow":' + graph + '}',
    json() { throw new Error("must not use type-losing parser"); } }); await turn();
  assert.equal(ui.painted.length, 1);
  assert.ok(inputs.flowText(ui.context.rootFlow).includes(evidence));
});
test("unpreserved learned evidence is refused before a Copilot request, without clearing text", () => {
  const ui = fixture(); ui.context.rootFlow.learned_recipe = { schema: "lightwork.action-recipe.v1", artifact_sha256: "uncached" };
  ui.send("Keep this text");
  assert.equal(ui.calls.length, 0); assert.equal(ui.input.value, "Keep this text");
});

for (const control of ["fd-chat", "fd-undo", "fd-redo"]) test(`${control} is outside every Steps-hidden view container`, () => {
  const template = fs.readFileSync(path.resolve(__dirname,
    "../../maverick_dashboard/templates/flow_designer.html"), "utf8")
    .replace(/<style[\s\S]*?<\/style>/g, "").replace(/<script[\s\S]*?<\/script>/g, "");
  const parents = [], voids = new Set(["input", "br", "hr", "img", "meta", "link"]);
  for (const match of template.matchAll(/<(\/)?([a-z][a-z0-9-]*)(\s[^>]*|)>/gi)) {
    const [, close, tag, attrs] = match;
    if (close) {
      const index = parents.map(parent => parent.tag).lastIndexOf(tag);
      if (index !== -1) parents.splice(index);
    } else {
      if (attrs.includes('id="' + control + '"')) {
        const classes = parents.map(parent => parent.attrs.match(/class="([^"]*)"/)?.[1] || "").join(" ");
        assert.doesNotMatch(classes, /fd__canvas-wrap|fdx-canvastools|fd__props|fd__palette|fdx-rail/);
        if (control === "fd-chat") assert.match(attrs, /hidden/);
        return;
      }
      if (!voids.has(tag)) parents.push({tag, attrs});
    }
  }
  assert.fail("actual template must contain " + control);
});

function drawerFixture() {
  const classes = new Set(), panel = element(), input = element("input"), toggle = element("button");
  panel.hidden = true;
  panel.classList = { contains: key => classes.has(key),
    add: key => classes.add(key), remove: key => classes.delete(key),
    toggle(key, force) { const show = force === undefined ? !classes.has(key) : force;
      if (show) classes.add(key); else classes.delete(key); return show; } };
  input.value = "Keep my unsent message";
  const context = { document: { getElementById: id => ({"fd-chat": panel, "fd-chat-input": input, "fd-chat-toggle": toggle})[id] } };
  vm.runInNewContext(source.slice(source.indexOf("  function chatToggle("), source.indexOf("  function loadTools(")), context);
  return { context, panel, input, toggle };
}
test("Copilot opens accessibly in either view and closes with focus returned to its visible toolbar button", () => {
  const ui = drawerFixture(); ui.context.chatToggle();
  assert.equal(ui.panel.hidden, false); assert.equal(ui.toggle.attributes["aria-expanded"], "true");
  assert.equal(ui.input.focused, true);
  ui.context.chatToggle();
  assert.equal(ui.panel.hidden, true); assert.equal(ui.toggle.attributes["aria-expanded"], "false");
  assert.equal(ui.toggle.focused, true); assert.equal(ui.input.value, "Keep my unsent message");
});
test("Escape from the Copilot input closes only its drawer and preserves the unsent message", () => {
  const ui = drawerFixture(); ui.context.chatToggle(true);
  let prevented = false, stopped = false;
  ui.context.chatKeydown({ key: "Escape", target: ui.input,
    preventDefault() { prevented = true; }, stopPropagation() { stopped = true; } });
  assert.equal(prevented, true); assert.equal(stopped, true);
  assert.equal(ui.panel.hidden, true); assert.equal(ui.toggle.focused, true);
  assert.equal(ui.input.value, "Keep my unsent message");
  ui.context.chatToggle(true); assert.equal(ui.panel.hidden, false);
  assert.equal(ui.input.value, "Keep my unsent message");
});
test("opening for a run explanation never toggles an already open drawer closed", () => {
  const ui = drawerFixture(); ui.context.chatToggle(true); ui.context.chatToggle(true);
  assert.equal(ui.panel.hidden, false); assert.equal(ui.input.focused, true);
  ui.context.chatKeydown({ key: "Enter", preventDefault() { assert.fail("ordinary input must not be intercepted"); } });
  assert.equal(ui.panel.hidden, false);
  ui.context.chatToggle(false); ui.context.chatToggle(false);
  assert.equal(ui.panel.hidden, true);
});

function realEditorFixture() {
  const ui = fixture(), ctx = ui.context, controls = {};
  assert.equal(typeof ctx.FDHistory.snapshot, "function", "use the real history module in the editor fixture");
  for (const id of ["fd-notify", "fd-maxsec", "fd-maxdollars", "fd-schedule", "fd-tz", "fd-maxconc", "fd-test-data"])
    controls[id] = { value: "", checked: false };
  const originalGet = ctx.document.getElementById;
  ctx.document.getElementById = id => controls[id] || (["fd-chat-input", "fd-chat-log"].includes(id) ? originalGet(id) : null);
  Object.assign(ctx, { flowInputs: [], undoStack: [], redoStack: [], pendingSnap: null,
    fd: { dataset: { flowEngineOn: "true", canManageFlows: "true" } },
    idInput: { value: "orders" }, nameInput: { value: "Orders" }, normalizeNode: core.normalizeNode,
    serializeFlow: core.serializeFlow, renderCrumbs() {}, autoLayout() {}, renderProps() {},
    Event: class { constructor(type) { this.type = type; } },
    window: { dispatchEvent(event) { ui.events.push(event.type); } } });
  ui.events = [];
  // Load the real response handler too: mutation transport needs it even when
  // the eventual response succeeds, and it formats actual refusal messages.
  vm.runInNewContext(source.slice(source.indexOf("  var ACTION_WORDS ="),
    source.indexOf("  // Problems in words")), ctx);
  for (const [start, end] of [["snapState", "nodeById"], ["toApiFlow", "fromApiFlow"], ["fromApiFlow", "autoLayout"]])
    vm.runInNewContext(source.slice(source.indexOf("  function " + start + "("), source.indexOf("  function " + end + "(")), ctx);
  vm.runInNewContext(source.slice(source.indexOf("  function draftSnapshot("), source.indexOf("  function markClean(")), ctx);
  ctx.fromApiFlow({ ...ctx.rootFlow, notify: true, max_seconds: 30, max_dollars: 5,
    schedule: "0 9 * * *", timezone: "America/New_York", max_concurrent: 2,
    inputs: [{ key: "customer", type: "text", label: "Customer", required: true }],
    nodes: [{ id: "lookup", kind: "action", tool: "lookup", label: "Original", x: 5, y: 7 }] });
  ui.controls = controls;
  return ui;
}
test("actual Copilot success, Undo and Redo restore every serialized flow setting and input definition", async () => {
  const ui = realEditorFixture(), ctx = ui.context, before = clone(ctx.toApiFlow()), beforeEditor = ctx.draftSnapshot();
  ui.send("Increase the budget and update the schedule");
  const proposed = { ...before, name: "Updated workflow", notify: false, max_seconds: 90, max_dollars: 10,
    schedule: "30 10 * * 1", timezone: "UTC", max_concurrent: 3,
    inputs: [{ key: "limit", type: "number", label: "Limit", required: false, default: 2 }] };
  ui.finish(0, "Settings changed", { flow: proposed }); await turn();
  const after = clone(ctx.toApiFlow());
  assert.equal(after.max_dollars, 10); assert.equal(after.notify, false);
  assert.equal(ctx.undoStack.length, 1);
  ctx.undo();
  assert.deepEqual(clone(ctx.toApiFlow()), before);
  assert.equal(ctx.draftSnapshot(), beforeEditor, "Undo must restore the actual editor's dirty baseline too");
  assert.equal(ui.controls["fd-schedule"].value, "0 9 * * *");
  assert.equal(ui.events.at(-1), "lightwork:flow-loaded");
  ctx.redo(); assert.deepEqual(clone(ctx.toApiFlow()), after);
  assert.equal(ui.controls["fd-schedule"].value, "30 10 * * 1");
});
test("actual editor snapshots preserve unfinished controls, blank input rows and nested parameter text", () => {
  const ui = realEditorFixture(), ctx = ui.context;
  ctx.nameInput.value = ""; ctx.idInput.value = "";
  ui.controls["fd-maxdollars"].value = "0.00";
  ui.controls["fd-maxsec"].value = "";
  ui.controls["fd-schedule"].value = "  0 9 * * *  ";
  ctx.flowInputs.push({key: "", type: "text", label: "Unfinished"});
  ctx.rootFlow.nodes[0]._paramsRaw = "{unfinished";
  ctx.rootFlow.nodes[0].body = {start: "inner", nodes: [{id: "inner", kind: "action", tool: "lookup", _paramsRaw: "{also unfinished"}]};
  const beforeEditor = ctx.draftSnapshot(), snapshot = ctx.snapState();
  ctx.nameInput.value = "Replacement"; ctx.idInput.value = "replacement";
  ui.controls["fd-maxdollars"].value = "10"; ui.controls["fd-maxsec"].value = "40";
  ui.controls["fd-schedule"].value = ""; ctx.flowInputs.pop();
  delete ctx.rootFlow.nodes[0]._paramsRaw;
  ctx.restoreState(snapshot);
  assert.equal(ctx.nameInput.value, ""); assert.equal(ctx.idInput.value, "");
  assert.equal(ui.controls["fd-maxdollars"].value, "0.00");
  assert.equal(ui.controls["fd-maxsec"].value, "");
  assert.equal(ui.controls["fd-schedule"].value, "  0 9 * * *  ");
  assert.equal(ctx.flowInputs[1].label, "Unfinished");
  assert.equal(ctx.rootFlow.nodes[0]._paramsRaw, "{unfinished");
  assert.equal(ctx.rootFlow.nodes[0].body.nodes[0]._paramsRaw, "{also unfinished");
  assert.equal(ctx.draftSnapshot(), beforeEditor, "DOM values and root graph remain independently exact");
});
test("complete Undo and Redo preserve exact learning evidence while restoring changed settings", () => {
  const ui = realEditorFixture(), ctx = ui.context;
  const raw = JSON.stringify(ctx.toApiFlow()).replace(/}$/, ',"learned_recipe":{"schema":"lightwork.action-choice.v1",' +
    '"artifact_sha256":"history-wire-fixture","exact":1.0,"large":9007199254740993},' +
    '"recipe_lineage":{"id":"admitted"},"recipe_teaching":{"schema":"lightwork.action-choice-teaching.v1"}}');
  ctx.fromApiFlow(inputs.parseText(raw)); ctx.pushHistory();
  ui.controls["fd-maxdollars"].value = "10";
  ctx.rootFlow.nodes[0].label = "Changed label";
  ctx.undo();
  assert.equal(ctx.toApiFlow().max_dollars, 5);
  assert.equal(ctx.toApiFlow().nodes[0].label, "Original");
  assert.equal(ctx.toApiFlow().recipe_lineage.id, "admitted");
  assert.equal(ctx.toApiFlow().recipe_teaching.schema, "lightwork.action-choice-teaching.v1");
  assert.match(inputs.flowText(ctx.toApiFlow()), /"exact":1\.0,"large":9007199254740993/);
  ctx.redo();
  assert.equal(ctx.toApiFlow().max_dollars, 10);
  assert.equal(ctx.toApiFlow().nodes[0].label, "Changed label");
  assert.match(inputs.flowText(ctx.toApiFlow()), /"exact":1\.0,"large":9007199254740993/);
});
test("real editor transport formats a rejected mutation without accepting it", async () => {
  const ctx = realEditorFixture().context;
  vm.runInNewContext(source.slice(source.indexOf("  function unconfirmedMutation("), source.indexOf("  function slugify(")), ctx);
  await assert.rejects(ctx.readMutationResult({ok: false, status: 409, json: async () => ({})}, "Save"),
    /This flow was changed since you opened it/);
});
for (const operation of ["save", "publishFlow"]) test(`Undo after actual ${operation} keeps current server receipts for the same saved workflow`, async () => {
  const ui = realEditorFixture(), ctx = ui.context;
  Object.assign(ctx, {syncSaveButtons() {}, markClean() {}, canonicalizeSavedFlow() {}});
  vm.runInNewContext(source.slice(source.indexOf("  function unconfirmedMutation("), source.indexOf("  function inputFields(")), ctx);
  ui.send("Increase the budget");
  ui.finish(0, "Budget ten", {flow: {...ctx.toApiFlow(), max_dollars: 10}}); await turn();
  const operationDone = ctx[operation]();
  await turn();
  const receipt = {id: "orders", version: 3, revision: "saved-2", published: true,
    published_version: 1, published_revision: "published-1"};
  ui.calls[1].resolve({ok: true, text: async () => JSON.stringify(receipt)}); await turn();
  if (operation === "publishFlow") {
    assert.match(ui.calls[2].url, /\/publish$/);
    assert.equal(JSON.parse(ui.calls[2].options.body).revision, "saved-2");
    ui.calls[2].resolve({ok: true, text: async () => JSON.stringify({id: "orders", published: true,
      published_version: 3, published_revision: "published-3"})});
  }
  await operationDone;
  const currentPublication = ctx.rootFlow.published_revision;
  ctx.undo();
  assert.equal(ctx.toApiFlow().max_dollars, 5);
  assert.equal(ctx.toApiFlow().version, 3);
  assert.equal(ctx.toApiFlow().revision, "saved-2");
  assert.equal(ctx.rootFlow.published, true);
  assert.equal(ctx.rootFlow.published_revision, currentPublication);
  assert.equal(ctx.rootFlow.published_version, operation === "publishFlow" ? 3 : 1);
  ctx.redo();
  assert.equal(ctx.toApiFlow().max_dollars, 10);
  assert.equal(ctx.toApiFlow().revision, "saved-2");
  assert.equal(ctx.rootFlow.published_revision, currentPublication);
});
test("Undo across different saved workflows never transfers the current workflow's server receipts", () => {
  const ui = realEditorFixture(), ctx = ui.context;
  ctx.pushHistory();
  ctx.fromApiFlow({...ctx.toApiFlow(), id: "different", version: 9, revision: "different-9",
    published: true, published_version: 8, published_revision: "different-release"});
  ctx.undo();
  assert.equal(ctx.toApiFlow().id, "orders");
  assert.equal(ctx.toApiFlow().version, 2);
  assert.equal(ctx.toApiFlow().revision, "saved-2");
  assert.equal(ctx.rootFlow.published_revision, "published-1");
});
test("Undo never borrows a same-ID replacement generation's receipts", () => {
  const ui = realEditorFixture(), ctx = ui.context;
  ctx.pushHistory();
  ctx.fromApiFlow({...ctx.toApiFlow(), id: "orders", version: 1, revision: "replacement-generation",
    published: true, published_version: 1, published_revision: "replacement-release"});
  ctx.undo();
  assert.equal(ctx.toApiFlow().id, "orders");
  assert.equal(ctx.toApiFlow().version, 2);
  assert.equal(ctx.toApiFlow().revision, "saved-2");
  assert.equal(ctx.rootFlow.published_revision, "published-1");
  ctx.fromApiFlow({...ctx.toApiFlow(), version: 1, revision: "third-generation",
    published: true, published_version: 1, published_revision: "third-release"});
  ctx.redo();
  assert.equal(ctx.toApiFlow().revision, "replacement-generation");
  assert.equal(ctx.rootFlow.published_revision, "replacement-release");
});
for (const assignedId of ["", "new-orders"]) test(`actual first save binds existing unsaved history explicitly (initial id ${JSON.stringify(assignedId)})`, async () => {
  const ui = realEditorFixture(), ctx = ui.context;
  Object.assign(ctx, {syncSaveButtons() {}, markClean() {}, canonicalizeSavedFlow() {}});
  vm.runInNewContext(source.slice(source.indexOf("  function unconfirmedMutation("), source.indexOf("  function inputFields(")), ctx);
  ctx.fromApiFlow({...ctx.toApiFlow(), id: assignedId, name: "New orders", version: 0, revision: "",
    published: false, published_version: 0, published_revision: ""});
  ctx.pushHistory(); ui.controls["fd-maxdollars"].value = "10";
  const saved = ctx.save();
  await turn();
  assert.equal(JSON.parse(ui.calls[0].options.body).flow.version, 0);
  ui.calls[0].resolve({ok: true, text: async () => JSON.stringify({id: "new-orders", version: 1,
    revision: "created-generation", published: false, published_version: null, published_revision: ""})});
  assert.equal(await saved, true);
  ctx.undo();
  assert.equal(ctx.toApiFlow().id, "new-orders");
  assert.equal(ctx.toApiFlow().max_dollars, 5);
  assert.equal(ctx.toApiFlow().version, 1);
  assert.equal(ctx.toApiFlow().revision, "created-generation");
  ctx.fromApiFlow({...ctx.toApiFlow(), version: 1, revision: "replacement-generation",
    published: true, published_version: 1, published_revision: "replacement-release"});
  ctx.redo();
  assert.equal(ctx.toApiFlow().id, "new-orders");
  assert.equal(ctx.toApiFlow().max_dollars, 10);
  assert.equal(ctx.toApiFlow().revision, "created-generation");
  assert.equal(ctx.rootFlow.published, false);
});
