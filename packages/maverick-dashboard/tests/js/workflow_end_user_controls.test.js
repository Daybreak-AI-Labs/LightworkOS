"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const templates = path.resolve(__dirname, "../../maverick_dashboard/templates");
const readTemplate = name => fs.readFileSync(path.join(templates, name), "utf8").replace(/\r\n/g, "\n");
const FDCore = require(path.join(templates, "flow_designer_core.js"));
const FDSchedule = require(path.join(templates, "flow_designer_schedule.js"));

async function receiveTemplateFixture(draft, existing = {}, serverContext = "ctx") {
  const details = { open: false }, title = { value: existing.title || "" };
  const references = {value:"[]"};
  const description = { value: existing.description || "", closest: () => details };
  const notice = { hidden: true }, storage = new Map([["lightwork:template-draft:v1", JSON.stringify(draft)]]);
  let submits = 0;
  const form = { querySelector: selector => selector.includes("connection_references") ? references : selector.includes('name="title"') ? title : description, submit() { submits++; } };
  for (const input of [title, description]) { input.listeners = {}; input.addEventListener = (type, callback) => { input.listeners[type] = callback; }; input.removeEventListener = type => { delete input.listeners[type]; }; }
  const context = { window: {}, Date, fetch: async () => typeof serverContext === "function" ? serverContext(title, description) : ({ ok: true, json: async () => ({ context: serverContext }) }),
    sessionStorage: { getItem: key => storage.get(key), removeItem: key => storage.delete(key) },
    document: { querySelector: () => form, getElementById: () => notice } };
  const source = readTemplate("chat.html");
  // Only the page's copy helpers; the composer's own resize/Enter wiring that
  // follows them is not part of the template handoff.
  const helpers = source.indexOf("  function chatCopy(");
  vm.runInNewContext(source.slice(helpers, source.indexOf("  (function () {", helpers)), context);
  const start = source.indexOf("  (async function receiveTemplateDraft()");
  await vm.runInNewContext(source.slice(start, source.indexOf("  })();", start) + 7), context);
  return { title, description, references, details, notice, storage, submits };
}

test("prepared template becomes a visible ordinary Chat draft once, without submitting", async () => {
  const draft = { title: "Review the report", description: "Full template body".repeat(800), created_at: Date.now(), context: "ctx" };
  const ui = await receiveTemplateFixture(draft);
  assert.equal(ui.title.value, draft.title); assert.equal(ui.description.value, draft.description);
  assert.equal(ui.details.open, true); assert.equal(ui.notice.hidden, false);
  assert.equal(ui.storage.size, 0); assert.equal(ui.submits, 0);
});

test("template handoff never overwrites URL or in-progress drafts", async () => {
  for (const existing of [{ title: "My own goal" }, { description: "My draft instructions" }]) {
    const ui = await receiveTemplateFixture({ title: "Template", description: "Template body", created_at: Date.now(), context: "ctx" }, existing);
    assert.equal(ui.title.value, existing.title || ""); assert.equal(ui.description.value, existing.description || "");
    assert.equal(ui.notice.hidden, true); assert.equal(ui.storage.size, 0); assert.equal(ui.submits, 0);
  }
});

test("prepared templates cannot cross a workspace or account boundary", async () => {
  const ui = await receiveTemplateFixture({ title: "Private template", description: "Private instructions", created_at: Date.now(), context: "workspace-a" }, {}, "workspace-b");
  assert.equal(ui.title.value, ""); assert.equal(ui.description.value, "");
  assert.equal(ui.notice.hidden, false); assert.match(ui.notice.textContent, /could not be verified/);
  assert.equal(ui.storage.size, 0); assert.equal(ui.submits, 0);
});

test("typing and then clearing a Chat draft while context is loading prevents late template injection", async () => {
  const ui = await receiveTemplateFixture({ title: "Template", description: "Template instructions", created_at: Date.now(), context: "ctx" }, {}, async title => {
    title.value = "My own work"; title.listeners.input(); title.value = "";
    return { ok: true, json: async () => ({ context: "ctx" }) };
  });
  assert.equal(ui.title.value, ""); assert.equal(ui.description.value, ""); assert.equal(ui.submits, 0);
});

test("expired, future, malformed and oversized prepared templates are consumed without changing Chat", async () => {
  const base = { title: "Template", description: "Body", created_at: Date.now(), context: "ctx" };
  for (const draft of [null, { ...base, created_at: Date.now() - 600001 }, { ...base, created_at: Date.now() + 60000 }, { ...base, title: "x".repeat(201) }, { ...base, description: "x".repeat(16001) }, { ...base, created_at: "today" }]) {
    const ui = await receiveTemplateFixture(draft);
    assert.equal(ui.title.value, ""); assert.equal(ui.description.value, ""); assert.equal(ui.storage.size, 0); assert.equal(ui.submits, 0);
  }
});

test("oversized template handoff reports how to correct it without truncation or submission", async () => {
  const ui = await receiveTemplateFixture({ title: "Template", description: "X".repeat(16001), created_at: Date.now(), context: "ctx" });
  assert.equal(ui.notice.hidden, false); assert.match(ui.notice.textContent, /shorten.*16,000/);
  assert.equal(ui.title.value, ""); assert.equal(ui.description.value, ""); assert.equal(ui.submits, 0);
});

test("template handoff counts Unicode characters consistently with the goal API", async () => {
  const draft = { title: "🌍".repeat(200), description: "🌍".repeat(16000), created_at: Date.now(), context: "ctx" };
  const ui = await receiveTemplateFixture(draft);
  assert.equal(ui.title.value, draft.title); assert.equal(ui.description.value, draft.description);
  assert.equal(ui.submits, 0);
});

function scheduleFixture(value = "") {
  const custom = { hidden: true };
  const days = ["1", "2", "3", "4", "5", "6", "0"].map(v => ({ value: v, checked: v === "1" }));
  const fields = {
    "fd-schedule": { value },
    "fd-sched-freq": { value: "", querySelector: () => custom },
    "fd-sched-time": { value: "09:00" }, "fd-sched-dom": { value: "1" }, "fd-sched-minute": { value: "0" },
    "fd-tz": { value: "" }, "fd-sched-words": { textContent: "" },
    "fd-sched-days": { hidden: true }, "fd-sched-dom-row": { hidden: true }, "fd-sched-minute-row": { hidden: true },
    "fd-sched-time-row": { hidden: true }, "fd-sched-tz-row": { hidden: true },
  };
  // A changed timetable is one undoable edit (the designer's pushHistory).
  const context = { Intl, FDSchedule, document: { getElementById: id => fields[id], querySelectorAll: () => days }, edits: 0 };
  context.pushHistory = () => { context.edits += 1; };
  const source = readTemplate("flow_designer.js");
  vm.runInNewContext(source.slice(source.indexOf("  // ---- schedule picker"),
    source.indexOf("  function fillTimeZones(")), context);
  return { fields, context, custom, days };
}

function authoringFixture(kind, handoff, fetchImpl = async () => ({ ok: true, json: async () => ({ context: "ctx" }) })) {
  const brief = { value: "" }, listeners = new Map(), messages = [], calls = [];
  const storage = new Map([["lightwork.authoring-handoff", typeof handoff === "string" ? handoff : JSON.stringify(handoff)]]);
  let drafts = 0;
  const loadedFlows = [];
  const context = {
    Date, brief, rootFlow: { id: "", name: "", nodes: [] }, dirty: false,
    FDCore, fromApiFlow(value) { loadedFlows.push(value); context.rootFlow = value; },
    templateWorkspaceStarted: false, playbookWorkspaceStarted: false, fileInput: { files: [] },
    draftIsDirty: () => context.dirty,
    draft() { drafts++; },
    setForm(mode) { context.mode = mode; },
    say: (message, error) => messages.push({ message, error }),
    setStatus: (message, error) => messages.push({ message, error }),
    fetch(...args) { calls.push(args); return fetchImpl(...args); },
    sessionStorage: { getItem: key => storage.get(key), removeItem: key => storage.delete(key) },
    document: {
      getElementById: () => brief,
      addEventListener: (event, listener) => listeners.set(event, listener),
      removeEventListener: event => listeners.delete(event),
    },
  };
  for (const field of ["elName", "elTitle", "elSteps", "pbName", "pbDesc", "pbPersona"]) context[field] = { value: "" };
  const source = readTemplate(kind === "flow" ? "flow_designer.js" : "workflow_builder.html");
  const begin = source.indexOf("async function receiveAuthoringHandoff(");
  const end = source.indexOf(kind === "flow" ? "  buildExamples();" : "    renderExamples();", begin);
  assert.ok(begin >= 0 && end > begin);
  vm.runInNewContext(source.slice(begin, end), context);
  return { context, brief, listeners, messages, calls, storage, loadedFlows, draftCalls: () => drafts };
}

test("Ekko hands an approval-first, unsaved workflow into the designer for review", async () => {
  const flow = { id: "ekko-draft-abc", name: "Recurring report", start: "human-review", version: 0,
    revision: "", nodes: [
      { id: "human-review", kind: "approval", prompt: "Review before work", next: "observed-1" },
      { id: "observed-1", kind: "agent", brief: "Draft the report" },
    ] };
  const ui = authoringFixture("flow", { kind: "flow", brief: "Review this work", context: "ctx",
    created_at: Date.now(), flow });
  await ui.context.receiveAuthoringHandoff(false);
  assert.equal(ui.loadedFlows.length, 1);
  assert.equal(ui.loadedFlows[0].start, "human-review");
  assert.equal(ui.brief.value, "Review this work");
  assert.equal(ui.draftCalls(), 0);
  assert.match(ui.messages.at(-1).message, /Review.*save/);
});

test("Ekko handoff keeps the canvas empty when the suggested review gate is missing", async () => {
  const ui = authoringFixture("flow", { kind: "flow", brief: "Review this work", context: "ctx",
    created_at: Date.now(), flow: { id: "proposal", name: "Proposal", start: "work",
      nodes: [{ id: "work", kind: "agent", brief: "Work before review" }] } });
  await ui.context.receiveAuthoringHandoff(false);
  assert.equal(ui.loadedFlows.length, 0);
  assert.equal(ui.brief.value, "");
  assert.equal(ui.messages.at(-1).error, true);
});

for (const kind of ["agent", "flow"]) {
  const handoff = () => ({ kind, brief: "Draft a review workflow", created_at: Date.now(), context: "ctx" });

  test(`${kind} handoff verifies its workspace, preserves all 8,000 Unicode characters and never drafts automatically`, async () => {
    const data = { ...handoff(), brief: "🌍".repeat(8000) };
    const ui = authoringFixture(kind, data);
    await ui.context.receiveAuthoringHandoff(false);
    assert.equal(ui.brief.value, data.brief);
    assert.equal(ui.calls.length, 1); assert.equal(ui.calls[0][0], "/api/v1/templates/draft-context");
    assert.equal(ui.storage.size, 0); assert.equal(ui.listeners.size, 0); assert.equal(ui.draftCalls(), 0);
    assert.match(ui.messages.at(-1).message, /Review it.*choose Draft/);
    ui.brief.value = "";
    await ui.context.receiveAuthoringHandoff(false);
    assert.equal(ui.calls.length, 1); assert.equal(ui.brief.value, "", "handoff is consumed once");
  });

  test(`${kind} handoff rejects malformed, wrong-kind, expired, future and oversized drafts visibly`, async () => {
    const base = handoff();
    for (const data of ["{", null, { ...base, kind: "other" }, { ...base, brief: {} }, { ...base, brief: " " },
      { ...base, brief: "A".repeat(8001) }, { ...base, created_at: String(Date.now()) },
      { ...base, created_at: Date.now() - 600001 }, { ...base, created_at: Date.now() + 60000 }, { ...base, context: "" }]) {
      const ui = authoringFixture(kind, data);
      await ui.context.receiveAuthoringHandoff(false);
      assert.equal(ui.brief.value, ""); assert.equal(ui.calls.length, 0); assert.equal(ui.storage.size, 0);
      assert.equal(ui.messages.at(-1).error, true); assert.equal(ui.draftCalls(), 0);
    }
  });

  test(`${kind} handoff cannot cross accounts or workspaces or ignore failed context verification`, async () => {
    for (const response of [{ ok: true, json: async () => ({ context: "other" }) },
      { ok: false, json: async () => ({ context: "ctx" }) }, { ok: true, json: async () => null }]) {
      const ui = authoringFixture(kind, handoff(), async () => response);
      await ui.context.receiveAuthoringHandoff(false);
      assert.equal(ui.brief.value, ""); assert.equal(ui.storage.size, 0); assert.equal(ui.listeners.size, 0);
      assert.match(ui.messages.at(-1).message, /could not be verified/); assert.equal(ui.draftCalls(), 0);
    }
  });

  test(`${kind} handoff keeps existing edits and route-provided drafts`, async () => {
    for (const existing of ["brief", "editor", "route"]) {
      const ui = authoringFixture(kind, handoff());
      if (existing === "brief") ui.brief.value = "My own instructions";
      if (existing === "editor") {
        if (kind === "flow") ui.context.rootFlow.nodes.push({ id: "user-step" });
        else ui.context.pbPersona.value = "My own instructions";
      }
      await ui.context.receiveAuthoringHandoff(existing === "route");
      assert.equal(ui.brief.value, existing === "brief" ? "My own instructions" : "");
      assert.equal(ui.calls.length, 0); assert.equal(ui.storage.size, 0); assert.equal(ui.draftCalls(), 0);
    }
  });

  test(`${kind} handoff preserves typing then clearing, file selection and clicks while verification is pending`, async () => {
    for (const event of ["input", "change", "click"]) {
      let resolve;
      const ui = authoringFixture(kind, handoff(), () => new Promise(done => { resolve = done; }));
      const pending = ui.context.receiveAuthoringHandoff(false);
      ui.brief.value = "My own instructions"; ui.listeners.get(event)(); ui.brief.value = "";
      resolve({ ok: true, json: async () => ({ context: "ctx" }) });
      await pending;
      assert.equal(ui.brief.value, ""); assert.equal(ui.listeners.size, 0); assert.equal(ui.draftCalls(), 0);
      assert.match(ui.messages.at(-1).message, /current work was kept/);
    }
  });

  test(`${kind} handoff preserves an editor changed by another async result`, async () => {
    let resolve;
    const ui = authoringFixture(kind, handoff(), () => new Promise(done => { resolve = done; }));
    const pending = ui.context.receiveAuthoringHandoff(false);
    if (kind === "flow") ui.context.dirty = true;
    else ui.context.playbookWorkspaceStarted = true;
    resolve({ ok: true, json: async () => ({ context: "ctx" }) });
    await pending;
    assert.equal(ui.brief.value, ""); assert.equal(ui.draftCalls(), 0);
  });
}

test("a loaded custom timetable is kept exactly and shown as custom", () => {
  const ui = scheduleFixture("*/15 8-17 * * 1-5");
  ui.context.syncScheduleControls();
  assert.equal(ui.fields["fd-sched-freq"].value, "custom");
  assert.equal(ui.custom.hidden, false);
  ui.context.chooseSchedule();
  assert.equal(ui.fields["fd-schedule"].value, "*/15 8-17 * * 1-5");
  assert.match(ui.fields["fd-sched-words"].textContent, /custom timetable/);
});

test("plain schedule choices produce the matching timetable and read back the same way", () => {
  const ui = scheduleFixture("");
  const cases = [["daily", "0 9 * * *"], ["weekdays", "0 9 * * 1-5"], ["weekly", "0 9 * * 1"], ["monthly", "0 9 1 * *"], ["hourly", "0 * * * *"], ["", ""]];
  for (const [freq, expected] of cases) {
    ui.fields["fd-sched-freq"].value = freq;
    ui.context.chooseSchedule();
    assert.equal(ui.fields["fd-schedule"].value, expected);
    ui.context.syncScheduleControls();
    assert.equal(ui.fields["fd-sched-freq"].value, freq);
  }
  assert.equal(ui.context.edits, cases.length, "each changed timetable is one undo step");
  ui.context.chooseSchedule();
  assert.equal(ui.context.edits, cases.length, "choosing the same timetable adds no undo step");
  ui.fields["fd-sched-freq"].value = "weekly";
  ui.days.find(d => d.value === "5").checked = true;
  ui.fields["fd-sched-time"].value = "17:45";
  ui.context.chooseSchedule();
  assert.equal(ui.fields["fd-schedule"].value, "45 17 * * 1,5");
  assert.match(ui.fields["fd-sched-words"].textContent, /every Monday, Friday at 5:45 pm/);
});

test("readable permission chips retain exact identifiers and remove only the selected permission", () => {
  class Element {
    constructor() { this.children = []; this.listeners = {}; this.attributes = {}; this.value = ""; }
    set textContent(value) { this.text = value; this.children = []; }
    get textContent() { return this.text || ""; }
    appendChild(child) { this.children.push(child); }
    querySelectorAll() { return this.children; }
    focus() { this.focused = true; }
    setAttribute(name, value) { this.attributes[name] = value; }
    addEventListener(name, listener) { this.listeners[name] = listener; }
    dispatchEvent(event) { this.listeners[event.type]?.(event); }
  }
  const allow = new Element(), deny = new Element();
  allow.value = "web_search, send_email"; deny.value = "delete_file";
  const allowed = new Element(), blocked = new Element(), browse = new Element();
  const context = { pbAllow: allow, pbDeny: deny, Event, window: {},
    document: { createElement: () => new Element(), querySelector: () => browse,
      getElementById: id => id === "pb-allow-summary" ? allowed : blocked } };
  const source = readTemplate("workflow_builder.html");
  vm.runInNewContext(source.slice(source.indexOf("    function productText("),
    source.indexOf("    function setStatus(")), context);
  const splitStart = source.indexOf("    function splitList(");
  const splitEnd = source.indexOf("\n    }", splitStart) + 6;
  vm.runInNewContext(source.slice(splitStart, splitEnd), context);
  vm.runInNewContext(source.slice(source.indexOf("    function renderToolSelections("),
    source.indexOf("    var pbRisk =")), context);
  context.renderToolSelections();
  assert.equal(allowed.children[0].textContent.includes("web_search"), false);
  assert.equal(allowed.children[0].title, "web_search");
  assert.equal(allow.value, "web_search, send_email");
  allowed.children[0].listeners.click();
  assert.equal(allow.value, "send_email");
  assert.equal(deny.value, "delete_file");
  assert.equal(allowed.children.length, 1);
  assert.equal(allowed.children[0].title, "send_email");
  assert.ok(allowed.children[0].attributes["aria-label"]);
  assert.equal(allowed.children[0].focused, true);
  allowed.children[0].listeners.click();
  assert.equal(allow.value, "");
  assert.equal(browse.focused, true, "removing the final action returns focus to its chooser");
});

test("collapsed chat progress does not repeat raw work-log content and retains error guidance", () => {
  const raw = '{"tool":"internal_connector","params":{"query":"example"}}';
  const events = { children: [{ dataset: { kind: "observation" }, textContent: raw }] };
  const activity = { open: false }, status = { textContent: "active" };
  const now = {}, meta = {}, spin = { style: {} };
  const fields = { "work-activity": activity, events, status, "work-now": now, "work-meta": meta, "work-spin": spin };
  const observers = new Map();
  class MutationObserver {
    constructor(callback) { this.callback = callback; }
    observe(target) { observers.set(target, this.callback); }
  }
  const source = readTemplate("chat_goal.html");
  const start = source.indexOf("    (function () {", source.indexOf('// "Show work" strip'));
  const end = source.indexOf("    })();", start) + "    })();".length;
  const context = { MutationObserver, window: {}, document: { getElementById: id => fields[id] } };
  vm.runInNewContext(source.slice(source.indexOf('    function cgText('), source.indexOf('    // Plain-language failure text')), context);
  vm.runInNewContext(source.slice(start, end), context);
  observers.get(events)();
  assert.equal(now.textContent.includes("internal_connector"), false);
  assert.equal(events.children[0].textContent, raw, "the complete work log remains available");
  assert.equal(activity.open, false);
  events.children.push({ dataset: { kind: "error" }, textContent: "Detailed failure" });
  observers.get(events)();
  assert.match(now.textContent, /issue|attention/i);
  status.textContent = "failed";
  observers.get(status)();
  assert.equal(meta.textContent, "Failed");  // shown as a plain word
  assert.equal(spin.style.display, "none");
});

test("a refused chat follow-up shows the server's plain sentence and never raw validation text", () => {
  const source = readTemplate("chat_goal.html");
  const start = source.indexOf("      function submissionError(");
  const end = source.indexOf("\n      }\n", source.indexOf("function replyFailureText(", start)) + "\n      }\n".length;
  assert.ok(start > 0 && end > start, "the follow-up failure helpers are present");
  const context = {
    window: { mvPlainDetail: text => (typeof text === "string" && /^[A-Z][^_{}]*[.!?]$/.test(text) ? text : "") },
    cgErr: (response, what) => "Could not " + what + ". Generic " + response.status + ".",
  };
  vm.runInNewContext(source.slice(start, end) + "\nthis.replyFailureText = replyFailureText;", context);
  const shorten = "Shorten the message to 20,000 characters or fewer.";
  assert.equal(context.replyFailureText({ status: 422 }, { detail: shorten }), shorten);
  assert.equal(context.replyFailureText({ status: 422 }, { detail: [{ loc: ["body", "message"], msg: "Please review this message." }] }), "Please review this message.");
  assert.equal(context.replyFailureText({ status: 422 }, { detail: [{ loc: ["body", "message"], msg: "field_required" }] }), "Could not send your message. Generic 422.");
  assert.equal(context.replyFailureText({ status: 500 }, {}), "Could not send your message. Generic 500.");
});


test("prepared account references remain separate from the editable brief",async()=>{
 const refs=[{name:"chosen",owner:"user:owner",tenant:"one",connector:"slack_api",revision:"fixed"}];
 const ui=await receiveTemplateFixture({title:"Review",description:"Brief",connection_references:refs,created_at:Date.now(),context:"ctx"});
 assert.deepEqual(JSON.parse(ui.references.value),refs);assert.equal(ui.description.value,"Brief");assert.equal(ui.submits,0);
});
