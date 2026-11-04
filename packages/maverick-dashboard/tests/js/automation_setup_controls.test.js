"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { fetchHelpers } = require('./_shell');
const { webcrypto } = require("node:crypto");
const source = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates/automations.html"), "utf8").replace(/\r\n/g, "\n");

function fixture() {
  const nodes = {}, calls = [], events = [], storage = new Map();
  class Element {
    constructor(tag = "div") { this.tagName = tag; this.children = []; this.listeners = {}; this.dataset = {}; this.value = ""; this.checked = false; this.disabled = false; this.valid = true; }
    set id(value) { this._id = value; nodes[value] = this; }
    get id() { return this._id; }
    set textContent(value) { this.text = value; this.children = []; }
    get textContent() { return (this.text || "") + this.children.map(child => child.textContent).join(""); }
    appendChild(child) { child.parentElement = this; this.children.push(child); return child; }
    addEventListener(type, callback) { this.listeners[type] = callback; }
    setAttribute(name, value) { this[name] = value; }
    focus() { this.focused = true; }
    reportValidity() { return this.valid; }
    querySelector() { return this.submit || (this.submit = new Element("button")); }
    reset() { this.resets = (this.resets || 0) + 1; }
  }
  function get(id) { return nodes[id] || (nodes[id] = new Element()); }
  const document = { getElementById: get, createElement: tag => new Element(tag), createTextNode: text => { const e = new Element(); e.textContent = text; return e; },
    querySelectorAll: () => [], dispatchEvent: event => { events.push(event); return true; } };
  const providers = { providers: [{ name: "github", label: "GitHub" }], connected: ["github"], status: {}, vault_enabled: true, connection_context: "context-a" };
  const reply = data => ({ ok: true, status: 200, json: async () => data });
  const context = { document, URL, Uint8Array, console, Date,
    CustomEvent: function (type, options) { this.type = type; this.detail = options.detail; },
    fetch: async (url, options) => {
      calls.push({ url, options });
      if (url === "/api/v1/oauth/providers") return reply(providers);
      if (url === "/api/v1/templates") return reply({ templates: [{ name: "triage", title: "Triage new requests", params: ["subject"] }] });
      if (url === "/api/v1/flows") return reply({ flows: [{ id: "draft", name: "Draft", published: false }, { id: "ready", name: "Ready flow", published: true }] });
      throw new Error("Unexpected request " + url);
    }, mvToast() {}, mvConfirm: async () => false, fmtWhen: () => "later", delBtn: () => new Element(),
    mvHuman: value => String(value || "").replace(/[_-]+/g, " ").replace(/^./, c => c.toUpperCase()),
    plainError: (_, what) => "Could not " + what + ". Please try again.",
    window: { location: { origin: "https://app.example", href: "https://app.example/automations", assign(url) { this.assigned = url; } },
      history: { replaceState(_, __, url) { this.cleaned = url; } }, crypto: webcrypto,
      sessionStorage: { getItem: key => storage.get(key) || null, setItem: (key, value) => storage.set(key, value), removeItem: key => storage.delete(key) } } };
  context.el = (tag, cls, text = "") => { const e = new Element(tag); e.className = cls; e.textContent = text; return e; };
  context.window.mvFetchJSON = fetchHelpers(() => context.fetch).mvFetchJSON;  // the shell's helper, through this fetch
  // Named connected sources (SharePoint, Salesforce...) have their own module and
  // tests; these guided sources are the page's ordinary ones.
  context.window.LwConnectedEventSource = { create: () => ({ isConnected: () => false, config() { return {}; }, render() {},
    draft() { return {}; }, clear() {}, summary() { return ""; }, async retainOriginal() {}, async original() { return {}; } }) };
  vm.createContext(context);
  return { context, get, nodes, calls, events, storage, providers, reply };
}
async function settle() { await new Promise(resolve => setImmediate(resolve)); }
function eventFixture() {
  const ui = fixture();
  ui.context.evForm = ui.get("auto-event-form");
  ui.get("auto-event-target-kind").value = "template";
  vm.runInContext(source.slice(source.indexOf("    var evList ="), source.indexOf("    async function loadEventTriggers(")), ui.context);
  ui.context.loadEventTriggers = () => {};
  vm.runInContext(source.slice(source.indexOf("    evForm.addEventListener('submit'"), source.indexOf("\n    loadEventTriggers();\n  }")), ui.context);
  return ui;
}

test("guided source fields keep typed values, tucked-away options and per-source drafts", async () => {
  const ui = eventFixture(); await settle();
  ui.get("auto-event-source").value = "file_dir"; ui.context.changeSource();
  ui.get("auto-source-path").value = "inbound"; ui.get("auto-source-path").listeners.input();
  ui.get("auto-source-recursive").checked = true; ui.get("auto-source-recursive").listeners.input();
  assert.deepEqual(JSON.parse(JSON.stringify(ui.context.readSourceConfig())), { path: "inbound", recursive: true });
  // The file pattern is an optional extra, tucked under "More settings".
  assert.ok(ui.get("auto-event-more").children.some(child => child.children.some(c => c.id === "auto-source-glob")));
  ui.get("auto-event-source").value = "rss"; ui.context.changeSource();
  ui.get("auto-source-url").value = "https://example.org/feed.xml"; ui.get("auto-source-url").listeners.input();
  assert.equal(ui.context.readSourceConfig().url, "https://example.org/feed.xml");
  ui.get("auto-event-source").value = "file_dir"; ui.context.changeSource();
  assert.equal(ui.get("auto-source-recursive").checked, true);
  assert.equal(ui.get("auto-source-path").value, "inbound");
  ui.get("auto-event-source").value = "imap_email"; ui.context.changeSource();
  assert.equal(ui.get("auto-source-trusted_authserv_id").required, true);
  assert.equal(ui.get("auto-source-allowed_senders").required, true);
  ui.get("auto-source-trusted_authserv_id").value = "mx.example.org";
  ui.get("auto-source-trusted_authserv_id").listeners.input();
  ui.get("auto-source-allowed_senders").value = "alice@example.org";
  ui.get("auto-source-allowed_senders").listeners.input();
  ui.get("auto-source-port").value = "1993"; ui.get("auto-source-port").listeners.input();
  assert.equal(ui.context.readSourceConfig().port, 1993);
  assert.equal(ui.context.readSourceConfig().allowed_senders, "alice@example.org");
});

test("only guided sources are offered and an RSS feed has a required address", async () => {
  const ui = eventFixture(); await settle();
  ui.context.fetch = async url => {
    if (url === "/api/v1/event-triggers") return ui.reply({ sources: ["custom_source", "rss"], triggers: [] });
    if (url.endsWith("/history?limit=500")) return ui.reply({ history: [] });
    if (url.endsWith("/outcomes")) return ui.reply({ outcomes: {} });
    throw new Error("Unexpected request " + url);
  };
  vm.runInContext(source.slice(source.indexOf("    async function loadEventTriggers("),
    source.indexOf("    async function delEventTrigger(name)")), ui.context);
  await ui.context.loadEventTriggers();
  assert.deepEqual(ui.get("auto-event-source").children.map(option => option.value), ["rss"]);
  assert.match(ui.get("auto-event-source-availability").textContent, /1 additional source is not yet available/);
  // The minimal Element mock does not auto-select the first option as a browser does.
  ui.get("auto-event-source").value = "rss"; ui.context.changeSource();
  assert.equal(ui.get("auto-source-url").required, true);
  assert.equal(ui.get("auto-event-config-advanced").hidden, true);
  assert.equal(ui.get("auto-event-create").disabled, false);
  assert.equal(source.includes('id="auto-event-config"'), false);
  assert.equal(source.includes('id="auto-event-extra-add"'), false);
});

test("no guided source keeps creation unavailable and explains why", async () => {
  const ui = eventFixture(); await settle();
  ui.context.fetch = async url => {
    if (url === "/api/v1/event-triggers") return ui.reply({ sources: ["custom_source"], triggers: [] });
    if (url.endsWith("/history?limit=500")) return ui.reply({ history: [] });
    if (url.endsWith("/outcomes")) return ui.reply({ outcomes: {} });
    throw new Error("Unexpected request " + url);
  };
  vm.runInContext(source.slice(source.indexOf("    async function loadEventTriggers("),
    source.indexOf("    async function delEventTrigger(name)")), ui.context);
  await ui.context.loadEventTriggers();
  assert.equal(ui.get("auto-event-source").children.length, 0);
  assert.equal(ui.get("auto-event-create").disabled, true);
  assert.match(ui.get("auto-event-source-availability").textContent, /No sources can be set up/);
});

test("a form source asks the server to create its private link", async () => {
  const ui = eventFixture(); await settle();
  ui.get("auto-event-source").value = "form"; ui.context.changeSource();
  ui.get("auto-event-name").value = "Vendor Intake Form";
  ui.get("auto-event-template").value = "triage";
  let body;
  ui.context.fetch = async (_, options) => { body = JSON.parse(options.body); return ui.reply({ name: "vendor" }); };
  await ui.get("auto-event-form").listeners.submit({ preventDefault() {} });
  assert.deepEqual(body.config, {});
  assert.notEqual(body.config.token, "vendor-intake-form");
});

test("form creation works without browser crypto because the server mints the link", async () => {
  const ui = eventFixture(); await settle();
  ui.get("auto-event-source").value = "form"; ui.context.changeSource();
  ui.get("auto-event-template").value = "triage";
  ui.context.window.crypto = null;
  let created = false;
  ui.context.fetch = async () => { created = true; return ui.reply({name: "intake"}); };
  await ui.get("auto-event-form").listeners.submit({ preventDefault() {} });
  assert.equal(created, true);
  assert.match(ui.get("auto-event-msg").textContent, /Created/);
});

test("a new form cannot silently submit a manually chosen weak link", async () => {
  const ui = eventFixture(); await settle();
  ui.get("auto-event-source").value = "form"; ui.context.changeSource();
  assert.equal(ui.get("auto-event-config-advanced").hidden, true);
  ui.context.sourceDrafts.form.token = "legacy.link";
  assert.deepEqual(JSON.parse(JSON.stringify(ui.context.readSourceConfig())), {});
  const hint = ui.get("auto-event-formurl");
  assert.match(hint.textContent, /open or copy the private form link/);
  assert.equal(hint.children.length, 0);
});

test("form automations show pending and unavailable submission states", async () => {
  const ui = eventFixture(); await settle();
  ui.context.loadRuns = () => {};
  ui.context.fetch = async url => {
    if (url === "/api/v1/event-triggers") return ui.reply({
      sources: ["form"], triggers: [
        { name: "pending", source: "form", flow: "intake", cursor: "0", pending_submissions: 2 },
        { name: "unknown", source: "form", flow: "intake", cursor: "0", pending_submissions: null }
      ]
    });
    if (url.endsWith("/history?limit=500")) return ui.reply({ history: [] });
    if (url.endsWith("/outcomes")) return ui.reply({ outcomes: {} });
    throw new Error("Unexpected request " + url);
  };
  vm.runInContext(source.slice(source.indexOf("    async function loadEventTriggers("),
    source.indexOf("    async function delEventTrigger(name)")), ui.context);
  await ui.context.loadEventTriggers();
  const entries = ui.get("auto-event-list").children;
  assert.match(entries[0].textContent, /2 submissions are waiting.*Check now/);
  assert.match(entries[1].textContent, /Submission status is unavailable.*Changes are paused/);
});

test("saved form automation exposes a usable open and copy link", async () => {
  const ui = eventFixture(); await settle();
  ui.context.loadRuns = () => {};
  ui.context.fetch = async url => {
    if (url === "/api/v1/event-triggers") return ui.reply({sources: ["form"], triggers: [
      {name: "intake", source: "form", flow: "review", cursor: "0", pending_submissions: 0,
        config: {token: "legacy.link"}}
    ]});
    if (url.endsWith("/history?limit=500")) return ui.reply({history: []});
    if (url.endsWith("/outcomes")) return ui.reply({outcomes: {}});
    throw new Error("Unexpected request " + url);
  };
  let copied = "";
  ui.context.window.navigator = {clipboard: {writeText: async value => { copied = value; }}};
  vm.runInContext(source.slice(source.indexOf("    async function loadEventTriggers("),
    source.indexOf("    async function delEventTrigger(name)")), ui.context);
  await ui.context.loadEventTriggers();
  const actions = ui.get("auto-event-list").children[0].children[1];
  const open = actions.children[0], copy = actions.children[1], status = actions.children[2];
  assert.equal(open.href, "/form/legacy.link");
  assert.equal(open.target, "_blank");
  assert.equal(open.rel, "noopener noreferrer");
  await copy.listeners.click();
  assert.equal(copied, "https://app.example/form/legacy.link");
  assert.equal(status.textContent, "Link copied.");
});

test("a drained form replaces its link only after the owner reviews the consequence", async () => {
  const ui = eventFixture(); await settle();
  ui.context.loadRuns = () => {};
  let token = "legacy.link", submitted, confirmation = "";
  ui.context.mvConfirm = async text => { confirmation = text; return true; };
  ui.context.fetch = async (url, options) => {
    if (url === "/api/v1/event-triggers") return ui.reply({sources: ["form"], triggers: [
      {name: "intake", source: "form", flow: "review", cursor: "0", pending_submissions: 0,
        binding_revision: "old-generation", config: {token}}
    ]});
    if (url.endsWith("/history?limit=500")) return ui.reply({history: []});
    if (url.endsWith("/outcomes")) return ui.reply({outcomes: {}});
    if (url.endsWith("/rotate-form-link")) {
      submitted = {url, options}; token = "form-new";
      return ui.reply({config: {token}});
    }
    throw new Error("Unexpected request " + url);
  };
  vm.runInContext(source.slice(source.indexOf("    async function loadEventTriggers("),
    source.indexOf("    async function delEventTrigger(name)")), ui.context);
  await ui.context.loadEventTriggers();
  const actions = ui.get("auto-event-list").children[0].children[1];
  const replace = actions.children[3];
  assert.equal(replace.textContent, "Replace link");
  assert.equal(replace.disabled, false);
  await replace.listeners.click();
  assert.match(confirmation, /old link will stop working.*already received stay saved/);
  assert.equal(submitted.options.method, "POST");
  assert.deepEqual(JSON.parse(submitted.options.body), {expected_generation: "old-generation"});
  assert.match(ui.get("auto-event-msg").textContent, /old link no longer works.*Copy the new link/);
  assert.equal(ui.get("auto-event-list").children[0].children[1].children[0].href, "/form/form-new");
});

test("a lost replacement response and failed readback cannot expose the stale form link", async () => {
  const ui = eventFixture(); await settle();
  ui.context.loadRuns = () => {};
  ui.context.mvConfirm = async () => true;
  let token = "legacy.link", readbackFails = false, copied = "";
  ui.context.window.navigator = {clipboard: {writeText: async value => { copied = value; }}};
  ui.context.fetch = async url => {
    if (url === "/api/v1/event-triggers") {
      const data = {sources: ["form"], triggers: [
        {name: "intake", source: "form", flow: "review", pending_submissions: 0,
          binding_revision: "old-generation", config: {token}}
      ]};
      // A non-2xx response can still have plausible JSON. It must not be
      // mistaken for a verified registry read.
      return readbackFails ? {ok: false, status: 503, json: async () => data} : ui.reply(data);
    }
    if (url.endsWith("/history?limit=500")) return ui.reply({history: []});
    if (url.endsWith("/outcomes")) return ui.reply({outcomes: {}});
    if (url.endsWith("/rotate-form-link")) {
      token = "form-new";
      readbackFails = true;
      throw new TypeError("Response lost after commit");
    }
    throw new Error("Unexpected request " + url);
  };
  vm.runInContext(source.slice(source.indexOf("    async function loadEventTriggers("),
    source.indexOf("    async function delEventTrigger(name)")), ui.context);
  assert.equal(await ui.context.loadEventTriggers(), true);
  const oldActions = ui.get("auto-event-list").children[0].children[1];
  await oldActions.children[3].listeners.click();
  assert.match(ui.get("auto-event-msg").textContent, /could not be verified.*Refresh this page/);
  assert.equal(oldActions.children[0].hidden, true);
  assert.equal(oldActions.children[1].disabled, true);
  assert.equal(oldActions.children[3].disabled, true);
  await oldActions.children[1].listeners.click();
  assert.equal(copied, "");
  assert.equal(ui.get("auto-event-list").children[0].children[1], oldActions);

  readbackFails = false;
  assert.equal(await ui.context.loadEventTriggers(), true);
  const currentActions = ui.get("auto-event-list").children[0].children[1];
  assert.notEqual(currentActions, oldActions);
  assert.equal(currentActions.children[0].href, "/form/form-new");
  assert.equal(currentActions.children[1].disabled, false);
  await currentActions.children[1].listeners.click();
  assert.equal(copied, "https://app.example/form/form-new");
});

test("forms with waiting or unknown submissions cannot replace their links", async () => {
  const ui = eventFixture(); await settle();
  ui.context.loadRuns = () => {};
  ui.context.fetch = async url => {
    if (url === "/api/v1/event-triggers") return ui.reply({sources: ["form"], triggers: [
      {name: "waiting", source: "form", flow: "review", pending_submissions: 1,
        binding_revision: "rev-1", config: {token: "old-1"}},
      {name: "unknown", source: "form", flow: "review", pending_submissions: null,
        binding_revision: "rev-2", config: {token: "old-2"}}
    ]});
    if (url.endsWith("/history?limit=500")) return ui.reply({history: []});
    if (url.endsWith("/outcomes")) return ui.reply({outcomes: {}});
    throw new Error("Unexpected request " + url);
  };
  vm.runInContext(source.slice(source.indexOf("    async function loadEventTriggers("),
    source.indexOf("    async function delEventTrigger(name)")), ui.context);
  await ui.context.loadEventTriggers();
  for (const row of ui.get("auto-event-list").children) {
    const replace = row.children[1].children.find(button => button.textContent === "Replace link");
    assert.equal(replace.disabled, true);
  }
});

test("a form owner can review received answers and record a do-not-run decision", async () => {
  const ui = eventFixture(); await settle();
  ui.context.loadRuns = () => {};
  ui.context.mvConfirm = async () => true;
  let decided = false, requestBody;
  ui.context.fetch = async (url, options) => {
    if (url === "/api/v1/event-triggers") return ui.reply({sources: ["form"], triggers: [
      {name: "intake", source: "form", flow: "review", pending_submissions: 1,
        binding_revision: "rev-1", config: {token: "link"}}
    ]});
    if (url.endsWith("/history?limit=500")) return ui.reply({history: []});
    if (url.endsWith("/outcomes")) return ui.reply({outcomes: {}});
    if (url === "/api/v1/event-triggers/intake/form-submissions") return ui.reply({
      binding_revision: "rev-1", waiting_total: 1,
      submissions: [{sequence: 1, received_at: 1, fields: {name: "Ada"},
        fields_sha256: "digest", do_not_run: decided, reason: decided ? "Already handled by the team." : ""}]
    });
    if (url.endsWith("/form-submissions/1/do-not-run")) {
      requestBody = JSON.parse(options.body); decided = true; return ui.reply({do_not_run: true});
    }
    throw new Error("Unexpected request " + url);
  };
  vm.runInContext(source.slice(source.indexOf("    async function loadEventTriggers("),
    source.indexOf("    async function delEventTrigger(name)")), ui.context);
  await ui.context.loadEventTriggers();
  const entry = ui.get("auto-event-list").children[0];
  const review = entry.children[1].children.find(button => button.textContent === "Review waiting submissions");
  assert.ok(review);
  await review.listeners.click();
  await settle();
  const panel = entry.children[0].children.at(-1);
  assert.match(panel.textContent, /Ada/);
  const form = panel.children[1].children[2];
  form.children[0].children[0].value = "Already handled by the team.";
  await form.listeners.submit({preventDefault() {}});
  assert.equal(requestBody.expected_generation, "rev-1");
  assert.equal(requestBody.expected_fields_sha256, "digest");
  assert.match(panel.textContent, /Will not run/);
  assert.match(ui.get("auto-event-msg").textContent, /Decision recorded/);
});

test("a form owner confirms an interrupted signed decision using the current binding", async () => {
  const ui = eventFixture(); await settle();
  ui.context.loadRuns = () => {};
  ui.context.mvConfirm = async () => true;
  let repaired = false, requestBody;
  ui.context.fetch = async (url, options) => {
    if (url === "/api/v1/event-triggers") return ui.reply({sources: ["form"], triggers: [
      {name: "intake", source: "form", flow: "review", pending_submissions: 1,
        binding_revision: "rev-1", config: {token: "link"}}
    ]});
    if (url.endsWith("/history?limit=500")) return ui.reply({history: []});
    if (url.endsWith("/outcomes")) return ui.reply({outcomes: {}});
    if (url === "/api/v1/event-triggers/intake/form-submissions") return ui.reply({
      binding_revision: "rev-1", waiting_total: 1,
      interrupted_decision: repaired ? null : {
        sequence: 1, received_at: 1, fields: {name: "Ada"}, fields_sha256: "fields",
        decision_sha256: "decision", reason: "Handled directly with the customer.",
        decided_by: "Alice", decided_at: 1
      },
      submissions: repaired ? [{sequence: 1, received_at: 1, fields: {name: "Ada"},
        fields_sha256: "fields", do_not_run: true, reason: "Handled directly with the customer."}] : []
    });
    if (url.endsWith("/form-submissions/1/recover-decision")) {
      requestBody = JSON.parse(options.body); repaired = true; return ui.reply({do_not_run: true});
    }
    throw new Error("Unexpected request " + url);
  };
  vm.runInContext(source.slice(source.indexOf("    async function loadEventTriggers("),
    source.indexOf("    async function delEventTrigger(name)")), ui.context);
  await ui.context.loadEventTriggers();
  const entry = ui.get("auto-event-list").children[0];
  const review = entry.children[1].children.find(button => button.textContent === "Review waiting submissions");
  await review.listeners.click();
  await settle();
  assert.deepEqual(JSON.parse(JSON.stringify(ui.events.at(-1).detail.selection)),
    {kind: "form_recovery", name: "intake", sequence: 1});
  const panel = entry.children[0].children.at(-1);
  assert.match(panel.textContent, /Ada/);
  assert.match(panel.textContent, /Handled directly with the customer/);
  assert.equal(panel.textContent.includes("Do not run this submission"), false);
  const confirm = panel.children[0].children.find(button => button.textContent === "Confirm recorded decision");
  await confirm.listeners.click();
  assert.deepEqual(JSON.parse(JSON.stringify(requestBody)), {
    expected_generation: "rev-1", expected_fields_sha256: "fields", expected_decision_sha256: "decision"
  });
  assert.match(ui.get("auto-event-msg").textContent, /Decision confirmed/);
  assert.equal(ui.events.at(-1).detail.selection, null);
});

test("a lost recovery response is verified after the form cursor advances", async () => {
  const ui = eventFixture(); await settle();
  ui.context.loadRuns = () => {};
  ui.context.mvConfirm = async () => true;
  let repaired = false;
  ui.context.fetch = async url => {
    if (url === "/api/v1/event-triggers") return ui.reply({sources: ["form"], triggers: [
      {name: "intake", source: "form", flow: "review", pending_submissions: repaired ? 0 : 1,
        binding_revision: "rev-1", config: {token: "link"}}
    ]});
    if (url.endsWith("/history?limit=500")) return ui.reply({history: []});
    if (url.endsWith("/outcomes")) return ui.reply({outcomes: {}});
    if (url === "/api/v1/event-triggers/intake/form-submissions") return ui.reply({
      binding_revision: "rev-1", waiting_total: repaired ? 0 : 1,
      interrupted_decision: repaired ? null : {
        sequence: 1, received_at: 1, fields: {name: "Ada"}, fields_sha256: "fields",
        decision_sha256: "decision", reason: "Handled directly with the customer.",
        decided_by: "Alice", decided_at: 1
      }, submissions: []
    });
    if (url.endsWith("/form-submissions/1/recover-decision")) {
      repaired = true;
      throw new TypeError("response lost after signed completion");
    }
    if (url.endsWith("/form-submissions/1/decision-receipt")) return ui.reply({
      sequence: 1, binding_revision: "rev-1", fields_sha256: "fields",
      decision_sha256: "decision", do_not_run: true
    });
    throw new Error("Unexpected request " + url);
  };
  vm.runInContext(source.slice(source.indexOf("    async function loadEventTriggers("),
    source.indexOf("    async function delEventTrigger(name)")), ui.context);
  await ui.context.loadEventTriggers();
  const entry = ui.get("auto-event-list").children[0];
  await entry.children[1].children.find(button => button.textContent === "Review waiting submissions").listeners.click();
  await settle();
  const panel = entry.children[0].children.at(-1);
  await panel.children[0].children.find(button => button.textContent === "Confirm recorded decision").listeners.click();
  assert.match(ui.get("auto-event-msg").textContent, /Decision confirmed.*moved past/);
  assert.equal(ui.events.at(-1).detail.selection, null);
});

test("catalog picker offers only published flows and retains exact template parameter names", async () => {
  const ui = eventFixture(); await settle();
  assert.deepEqual(ui.get("auto-event-template").children.map(option => option.value), ["", "triage"]);
  ui.get("auto-event-template").value = "triage"; ui.context.renderTargetParams();
  assert.equal(ui.get("auto-event-param-0").dataset.param, "subject");
  ui.get("auto-event-target-kind").value = "flow"; ui.context.renderTargetChoices();
  assert.deepEqual(ui.get("auto-event-template").children.map(option => option.value), ["", "ready"]);
  assert.equal(ui.get("auto-event-params").children.length, 0);
});

test("guided create uses the selected flow contract and suppresses duplicate submissions", async () => {
  const ui = eventFixture(); await settle();
  ui.get("auto-event-source").value = "github_issues"; ui.context.changeSource();
  for (const [key, value] of [["owner", "example"], ["repo", "app"]]) {
    ui.get("auto-source-" + key).value = value; ui.get("auto-source-" + key).listeners.input();
  }
  ui.get("auto-event-target-kind").value = "flow"; ui.get("auto-event-template").value = "ready";
  let resolve, count = 0, body;
  ui.context.fetch = async (_, options) => { count++; body = JSON.parse(options.body); return await new Promise(done => { resolve = done; }); };
  const first = ui.get("auto-event-form").listeners.submit({ preventDefault() {} });
  await ui.get("auto-event-form").listeners.submit({ preventDefault() {} });
  assert.equal(count, 1); assert.equal(body.flow, "ready"); assert.equal("template" in body, false);
  assert.deepEqual(body.config, { owner: "example", repo: "app" });
  resolve(ui.reply({ name: "new-issues" })); await first;
  assert.equal(ui.get("auto-event-form").querySelector().disabled, false);
  assert.equal(ui.get("auto-event-form").resets, 1);
});

test("failed check never claims the source was checked and restores the action", async () => {
  const ui = eventFixture(); await settle();
  ui.context.fetch = async () => ({ ok: false, json: async () => ({ detail: "Access denied" }) });
  const button = ui.get("auto-event-poll"); await button.listeners.click.call(button);
  assert.match(ui.get("auto-event-msg").textContent, /Could not check for new items/); assert.equal(button.disabled, false);
});

test("a check with accepted work still pending does not claim completion", async () => {
  const ui = eventFixture(); await settle();
  ui.context.fetch = async () => ui.reply({ polled: 1, triggers: [{
    name: "intake", new_events: 1, fired: [], fired_flows: [],
    notes: ["flow unavailable: binding is stale"], poll_error: false
  }] });
  const button = ui.get("auto-event-poll"); await button.listeners.click.call(button);
  assert.match(ui.get("auto-event-msg").textContent, /Some submissions are still waiting/);
  assert.equal(button.disabled, false);
});

function loadOAuth(ui) {
  const start = source.indexOf("  var oauthBox ="), end = source.indexOf("  // ---- flows (", start);
  vm.runInContext(source.slice(start, end), ui.context);
}

// Imports moved to their own reviewed module: a chosen export is only read in
// the browser, reviewed completely by the server, and saved as drafts after a
// separate confirmation. Activation is never part of an import.
async function importFixture(review) {
  const { JSDOM } = require("jsdom");
  const { shell } = require("./_shell");
  const partial = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates/_automation_imports.html"), "utf8")
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "");
  const dom = new JSDOM("<!doctype html><body>" + partial + "</body>", { url: "https://app.example/automations", runScripts: "outside-only" });
  const w = dom.window, calls = [];
  w.HTMLElement.prototype.scrollIntoView = () => {};
  const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
  w.fetch = async (url, options = {}) => {
    calls.push({ url, method: options.method || "GET", body: options.body ? JSON.parse(options.body) : undefined });
    if (url === "/api/v1/automation-imports") return json({ context: "ctx", enabled: true, connections: [], timezones: ["UTC"],
      sources: [{ value: "n8n", label: "n8n", live: false }] });
    if (url === "/api/v1/automation-imports/history") return json({ choices: [] });
    if (url === "/api/v1/automation-imports/review") return review(json);
    throw new Error("Unexpected request " + url);
  };
  shell(w);
  w.eval(fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-automation-imports.js"), "utf8"));
  const settle = async () => { for (let i = 0; i < 20; i++) await new Promise(done => setImmediate(done)); };
  await settle();
  const d = w.document, file = d.getElementById("air-file");
  async function choose(...files) {
    Object.defineProperty(file, "files", { value: files, configurable: true });
    file.dispatchEvent(new w.Event("change"));
  }
  function submit() { d.getElementById("air-form").dispatchEvent(new w.Event("submit", { cancelable: true })); }
  d.getElementById("air-source").value = "n8n";
  return { w, d, calls, settle, choose, submit, close: () => w.close() };
}
const reviewRows = [{ label: "Platform", after: "n8n" }, { label: "Automations", after: "Review" },
  { label: "Drafts", after: "Saved as drafts only" }, { label: "Activation", after: "Schedules and starts stay off" }];

test("choosing an export file prepares definitions without starting an import or changing activation choices", async () => {
  const ui = await importFixture(json => json({ context: "ctx", operation: "AIR-" + "a".repeat(32), token: "sealed", changes: reviewRows, existing: [] }));
  await ui.choose({ size: 80, name: "workflows.json", text: async () => '[{"name":"Review","nodes":[]}]' });
  await ui.settle();
  assert.match(ui.d.getElementById("air-status").textContent, /Export selected/);
  assert.equal(ui.calls.some(call => call.method === "POST"), false, "choosing a file submits nothing");
  ui.submit(); await ui.settle();
  const review = ui.calls.find(call => call.url.endsWith("/review"));
  assert.equal(review.body.file_text, '[{"name":"Review","nodes":[]}]');
  assert.equal(review.body.mode, "file");
  assert.equal(Object.keys(review.body).some(key => /activat|schedule/.test(key)), false);
  assert.match(ui.d.getElementById("air-review-box").textContent, /Schedules and starts stay off/);
  assert.equal(ui.calls.some(call => call.url.endsWith("/apply")), false, "a review alone saves nothing");
  ui.close();
});

test("an older file read cannot replace a newer file choice", async () => {
  const ui = await importFixture(json => json({ context: "ctx", operation: "AIR-" + "b".repeat(32), token: "sealed", changes: reviewRows, existing: [] }));
  let resolve;
  await ui.choose({ size: 80, name: "old.json", text: () => new Promise(done => { resolve = done; }) });
  await ui.choose({ size: 80, name: "new.json", text: async () => '{"name":"Newer"}' });
  await ui.settle();
  resolve('{"name":"Old file"}'); await ui.settle();
  ui.submit(); await ui.settle();
  assert.equal(ui.calls.find(call => call.url.endsWith("/review")).body.file_text, '{"name":"Newer"}');
  ui.close();
});

test("a file that is not an export blocks an accidental import", async () => {
  const ui = await importFixture(json => json({ detail: "This file is not an automation export from the chosen platform." }, 422));
  await ui.choose({ size: 600000, name: "huge.json", text: async () => assert.fail("an oversized file is never read") });
  await ui.settle();
  assert.match(ui.d.getElementById("air-error").textContent, /no larger than 512 KB/);
  ui.submit(); await ui.settle();
  assert.equal(ui.calls.some(call => call.method === "POST"), false, "without a readable export nothing is sent");
  await ui.choose({ size: 10, name: "broken.json", text: async () => "null" });
  await ui.settle();
  ui.submit(); await ui.settle();
  assert.match(ui.d.getElementById("air-error").textContent, /not an automation export/);
  assert.equal(ui.d.getElementById("air-review-box").textContent, "");
  assert.equal(ui.calls.some(call => call.url.endsWith("/apply")), false);
  ui.close();
});

test("import network failures release the submit control with a plain message", async () => {
  const ui = await importFixture(() => { throw new TypeError("Failed to fetch"); });
  await ui.choose({ size: 20, name: "workflows.json", text: async () => '{"name":"Review"}' });
  await ui.settle();
  ui.submit(); await ui.settle();
  assert.equal(ui.d.getElementById("air-review").disabled, false);
  const shown = ui.d.getElementById("air-error").textContent;
  assert.ok(shown.length > 0);
  assert.doesNotMatch(shown, /TypeError|Failed to fetch/);
  ui.close();
});

function pending(overrides = {}) {
  return { provider: "github", redirect: "https://app.example/automations", context: "context-a", state: "a".repeat(64), verifier: "v".repeat(64), created: Date.now(), ...overrides };
}
test("account authorization binds provider, return address and random state without putting the verifier in the URL", async () => {
  const ui = fixture(); loadOAuth(ui); await settle();
  ui.get("oauth-provider").value = "github";
  ui.context.fetch = async (_, options) => {
    const body = JSON.parse(options.body);
    return ui.reply({ authorize_url: "https://github.example/authorize?redirect_uri=" + encodeURIComponent(body.redirect_uri) + "&code_challenge_method=S256&code_challenge=challenge", verifier: "v".repeat(64) });
  };
  await ui.get("oauth-get-url").listeners.click.call(ui.get("oauth-get-url"));
  const saved = JSON.parse(ui.storage.get("lightwork.oauth.pending.v1"));
  const url = new URL(ui.context.window.location.assigned);
  assert.equal(url.searchParams.get("state"), saved.state); assert.equal(saved.provider, "github");
  assert.equal(saved.context, "context-a"); assert.equal(url.href.includes(saved.verifier), false);
});

test("valid account return consumes the code once and automatically exchanges the bound provider", async () => {
  const ui = fixture(), saved = pending();
  ui.storage.set("lightwork.oauth.pending.v1", JSON.stringify(saved));
  ui.context.window.location.href += "?code=returned-code&state=" + saved.state;
  const original = ui.context.fetch;
  ui.context.fetch = async (url, options) => {
    if (url.endsWith("/exchange")) { ui.calls.push({ url, options }); return ui.reply({ connected: true, provider: "github" }); }
    return original(url, options);
  };
  loadOAuth(ui); await settle();
  const exchanges = ui.calls.filter(call => call.url.endsWith("/exchange"));
  assert.equal(exchanges.length, 1); assert.equal(exchanges[0].url, "/api/v1/oauth/github/exchange");
  assert.deepEqual(JSON.parse(exchanges[0].options.body), { code: "returned-code", redirect_uri: saved.redirect, verifier: saved.verifier });
  assert.equal(ui.context.window.history.cleaned, "/automations");
  assert.equal(ui.storage.has("lightwork.oauth.pending.v1"), false);
  assert.equal(ui.get("oauth-msg").textContent, "Account connected.");
});

for (const changes of [{ state: "b".repeat(64) }, { context: "another-workspace" }, { redirect: "https://other.example/callback" }, { created: Date.now() - 600001 }]) {
  test("mismatched or expired account return cannot exchange credentials: " + Object.keys(changes)[0], async () => {
    const ui = fixture(); ui.storage.set("lightwork.oauth.pending.v1", JSON.stringify(pending(changes)));
    ui.context.window.location.href += "?code=returned-code&state=" + "a".repeat(64);
    loadOAuth(ui); await settle();
    assert.equal(ui.calls.some(call => call.url.endsWith("/exchange")), false);
    assert.equal(ui.storage.has("lightwork.oauth.pending.v1"), false);
    assert.match(ui.get("oauth-msg").textContent, /expired|match/);
  });
}

test("saved timetables are described in words", () => {
  const ctx = {}; vm.createContext(ctx);
  vm.runInContext(source.slice(source.indexOf("  var DAYS ="), source.indexOf("  function delBtn(")), ctx);
  assert.equal(ctx.cronText("0 9 * * 1-5"), "Weekdays at 9 am");
  assert.equal(ctx.cronText("30 14 * * *"), "Every day at 2:30 pm");
  assert.equal(ctx.cronText("0 8 * * 1,3"), "Every Monday, Wednesday at 8 am");
  assert.equal(ctx.cronText("0 7 1 * *"), "Monthly on the 1st at 7 am");
  assert.equal(ctx.cronText("15 * * * *"), "Every hour at 15 minutes past");
  assert.equal(ctx.cronText("0 9 1 1 *"), "On a custom timetable");
});
