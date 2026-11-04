// Run with: node --test packages/maverick-dashboard/tests/js/lightwork_command_menu.test.js
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const SCRIPT = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-navfinder.js"), "utf8");

const PAGES = [
  ["/goals", "Tasks", "", "", "Work"],
  ["/approvals", "Approvals", "", "approve|approval|decide", "Governance"],
  ["/agent-control-plane", "Agent controls", "", "pause|stop|emergency stop|halt", "Governance"],
  ["/help", "Help and diagnostics", "", "help|docs|support", "Work"],
  ["/users", "Users", "", "invite|people|colleague", "Administration"],
  ["/settings", "Settings", "", "", "Administration"],
];

// As _navfinder.html renders the commands for someone who may use them all.
const COMMANDS = [
  ["new-task", "/chat", "New task", "start a task|create a task|new chat|ask|compose"],
  ["approvals", "/approvals", "Approve or reject…", "approve|reject|approval|approvals|decide|decision|sign off"],
  ["halt", "#halt-pill", "Pause all work (emergency stop)", "pause|stop|emergency stop|halt|stop all work|pause everything"],
  ["invite", "/users#invite-email", "Invite someone", "invite|add user|add a person|new user|colleague"],
  ["setting", "#navfinder-input", "Open setting…", "setting|settings|preference|preferences|option|configure"],
  ["pin", "#navpins", "Pin this page", "pin|unpin|favorite|bookmark|sidebar"],
  ["shortcuts", "#shortcuts-dialog", "Show keyboard shortcuts", "keyboard|shortcuts|keys|hotkeys"],
];

function pageItems() {
  return PAGES.map(([href, label, heading, synonyms, area], index) =>
    `<li role="none"><a id="navfinder-option-0-${index}" href="${href}" role="option" tabindex="-1" aria-selected="false"` +
    ` data-navfinder-target data-label="${label}" data-heading="${heading}" data-synonyms="${synonyms}"` +
    ` data-search="${label} ${area} ${href} ${synonyms.replace(/\|/g, " ")}"><span class="navfinder__label">${label}</span>` +
    `<span class="navfinder__group">${area} › ${label}</span></a></li>`).join("");
}

function commandItems(names) {
  return COMMANDS.filter(([name]) => !names || names.includes(name)).map(([name, href, label, synonyms]) =>
    `<li role="none"><a id="navfinder-action-${name}" href="${href}" role="option" tabindex="-1" aria-selected="false"` +
    ` data-navfinder-action="${name}" data-label="${label}" data-heading="" data-synonyms="${synonyms}"` +
    ` data-search="${label} ${synonyms.replace(/\|/g, " ")}"` +
    (name === "approvals" ? ' data-navfinder-list="/api/v1/approvals"' : "") +
    (name === "pin" ? ' data-label-pin="Pin this page" data-label-unpin="Unpin this page"' : "") +
    `><span class="navfinder__label">${label}</span><span class="navfinder__group">Command</span></a></li>`).join("");
}

function menu({ people = true, records = true, composer = false, armed = false, commands = null, sidebar = "", find = false } = {}) {
  const dom = new JSDOM(`<!doctype html><body class="${armed ? "halt-armed" : ""}">${sidebar}
    <button id="navfinder-open"></button><button id="nav-toggle"></button>
    <a href="#" id="halt-pill" role="button" data-can-halt="true">Running</a>
    ${composer ? '<form action="/chat/send"><textarea name="title" id="composer-field"></textarea></form>' : ""}
    <dialog id="navfinder-dialog"><button id="navfinder-close"></button>
      <div><span id="navfinder-mode" hidden></span><input id="navfinder-input"></div>
      <p id="navfinder-count"></p>
      <ul id="navfinder-results"${find ? ' data-navfinder-find="/nav/finder/find"' : ""}${people ? ' data-navfinder-people="/nav/finder/people"' : ""}${records ? " data-navfinder-records" : ""}>${pageItems()}${commandItems(commands)}</ul>
      <p id="navfinder-empty" hidden>No matching pages. Try a broader search.</p>
      <template id="navfinder-empty-copy"><span data-scope="actions">No matching commands.</span><span data-scope="people">No matching people.</span><span data-scope="approvals">Nothing is waiting for your decision.</span></template>
    </dialog></body>`, { runScripts: "outside-only", url: "https://lightwork.test/overview" });
  const window = dom.window;
  const fetches = [];
  const responses = [];
  window.fetch = (url, options = {}) => {
    fetches.push({ url: String(url), method: (options.method || "GET").toUpperCase() });
    const reply = responses.shift() || { ok: true, json: {} };
    return Promise.resolve({ ok: reply.ok, json: async () => reply.json, text: async () => "" });
  };
  const timers = [];
  window.setTimeout = (callback) => { timers.push(callback); return timers.length; };
  window.clearTimeout = () => {};
  const events = [];
  shell(window);
  window.eval(SCRIPT);
  const doc = window.document;
  doc.getElementById("navfinder-dialog").addEventListener("lightwork:finder-query", (event) => events.push(event.detail));
  const finder = window.LightworkNavFinder.init(doc);
  const pill = doc.getElementById("halt-pill");
  const pillClicks = [];
  pill.addEventListener("click", (event) => { event.preventDefault(); pillClicks.push(event); });
  finder.open();
  const input = doc.getElementById("navfinder-input");
  return {
    dom, window, doc, finder, input, fetches, responses, timers, events, pillClicks,
    type(query) {
      input.value = query;
      input.dispatchEvent(new window.Event("input"));
      return this.visible();
    },
    visible() { return [...finder.visibleOptions()].map((option) => option.getAttribute("href")); },
    key(key) {
      const event = new window.KeyboardEvent("keydown", { key, bubbles: true, cancelable: true });
      input.dispatchEvent(event);
      return event;
    },
    open() { return doc.getElementById("navfinder-dialog").hasAttribute("open"); },
    flush() { return new Promise((resolve) => setImmediate(resolve)); },
  };
}

test("> shows only commands, / only pages, and plain text ranks both together", () => {
  const ui = menu();
  assert.deepEqual(ui.type(">"), COMMANDS.map(([, href]) => href));
  assert.deepEqual(ui.type("/"), PAGES.map(([href]) => href));
  assert.deepEqual(ui.type("/ set"), ["/settings"]);
  // A command and a page that match equally well put the command first.
  assert.deepEqual(ui.type("pause").slice(0, 2), ["#halt-pill", "/agent-control-plane"]);
  assert.deepEqual(ui.type("> pause"), ["#halt-pill"]);
  assert.equal(ui.type("new task")[0], "/chat");
  assert.equal(ui.type("invite")[0], "/users#invite-email");
  // Exact page names still win: "settings" is the Settings page, "help" is Help.
  assert.equal(ui.type("settings")[0], "/settings");
  assert.equal(ui.type("help")[0], "/help");
  assert.equal(ui.doc.getElementById("navfinder-count").textContent, "1 page");
  ui.type("> zzz");
  assert.equal(ui.doc.getElementById("navfinder-empty").hidden, false);
  assert.equal(ui.doc.getElementById("navfinder-empty").textContent, "No matching commands.");
  ui.dom.window.close();
});

test("# hands records search the words without the prefix and hides pages and commands", () => {
  const ui = menu();
  assert.deepEqual(ui.type("#  invoice 12"), []);
  assert.equal(ui.finder.scope(), "records");
  assert.equal(ui.finder.query(), "invoice 12");
  const detail = ui.events[ui.events.length - 1];
  assert.equal(detail.scope, "records");
  assert.equal(detail.text, "invoice 12");
  assert.equal(detail.query, "", "settings are not searched in a records-only search");
  ui.finder.setRecords([{ href: "/chat/goal/12", title: "Invoice 12", kind: "task", id: "12", revision: "", state: "" }]);
  assert.deepEqual(ui.visible(), ["/chat/goal/12"]);
  ui.type("/");
  assert.deepEqual(ui.visible(), PAGES.map(([href]) => href), "records stay out of a pages-only search");
  ui.dom.window.close();
});

test("settings read as commands in a command search", () => {
  const ui = menu();
  ui.type("> theme");
  assert.equal(ui.events[ui.events.length - 1].query, "theme");
  ui.finder.setSettings([{ href: "/settings?focus=settings-theme", title: "Your colour theme", group: "Personal", effective: "", required_role: "" }]);
  const setting = ui.doc.getElementById("navfinder-setting-0");
  assert.deepEqual(ui.visible(), ["/settings?focus=settings-theme"]);
  assert.match(setting.querySelector(".navfinder__label").textContent, /^Open setting: Your colour theme$/);
  ui.type("theme");
  assert.equal(setting.querySelector(".navfinder__label").textContent, "Your colour theme");
  ui.dom.window.close();
});

test("Open setting… switches to a settings search", () => {
  const ui = menu();
  ui.type("open setting");
  assert.equal(ui.visible()[0], "#navfinder-input");
  const enter = ui.key("Enter");
  assert.equal(enter.defaultPrevented, true);
  assert.equal(ui.input.value, ": ");
  assert.equal(ui.finder.scope(), "settings");
  assert.equal(ui.open(), true);
  ui.dom.window.close();
});

test("@ searches people only through the server, and only where it is offered", async () => {
  const ui = menu();
  ui.responses.push({ ok: true, json: { people: [
    { label: "Alice Anders", role: "Operator", href: "/users" },
    { label: "Smuggled", role: "", href: "https://evil.example/" },
  ] } });
  ui.type("@ali");
  assert.deepEqual(ui.visible(), []);
  assert.equal(ui.timers.length, 1);
  ui.timers.shift()();
  await ui.flush();
  assert.deepEqual(ui.fetches.map((call) => [call.method, call.url]), [["GET", "/nav/finder/people?q=ali"]]);
  assert.deepEqual(ui.visible(), ["/users"]);
  assert.equal(ui.doc.getElementById("navfinder-person-0").querySelector("[data-user-content]").textContent, "Alice Anders");
  ui.type("ali");
  assert.deepEqual(ui.visible(), [], "people appear only in a people search");
  ui.dom.window.close();

  const closed = menu({ people: false });
  closed.type("@ali");
  assert.equal(closed.timers.length, 0);
  assert.deepEqual(closed.fetches, []);
  assert.deepEqual([...closed.finder.prefixes()], [">", "/", "#", ":"]);
  closed.dom.window.close();
  const full = menu();
  assert.deepEqual([...full.finder.prefixes()], [">", "/", "#", "@", ":"]);
  full.dom.window.close();
});

test("Pause all work opens the emergency stop's own confirmation and never stops work itself", () => {
  const ui = menu();
  ui.type("pause");
  ui.key("Enter");
  assert.equal(ui.open(), false);
  assert.equal(ui.pillClicks.length, 1, "the stop control was pressed, which asks for confirmation");
  assert.deepEqual(ui.fetches, [], "nothing was sent from the menu");
  ui.dom.window.close();

  // While work is stopped the same press would resume it: the menu says so instead.
  const stopped = menu({ armed: true });
  const toasts = [];
  stopped.window.mvToast = (message) => toasts.push(message);
  stopped.type("> pause");
  stopped.key("Enter");
  assert.equal(stopped.pillClicks.length, 0);
  assert.match(toasts[0], /already stopped/);
  stopped.dom.window.close();
});

test("Approve or reject… lists waiting requests that open their cards, and decides nothing", async () => {
  const ui = menu();
  ui.responses.push({ ok: true, json: {
    approvals: [{ id: 5, action: "file.delete", risk: "high", scope: "Quarterly report" },
                { id: "bad id", action: "x", risk: "low" }],
    flow_approvals: [{ title: "Vendor payment", href: "/flows/7/runs/9?approval_review=1" },
                     { title: "Remote", href: "//evil.example/approve" }],
  } });
  ui.type("approve");
  assert.equal(ui.visible()[0], "/approvals");  // the command (it also lands on Approvals without script)
  ui.key("Enter");
  assert.equal(ui.open(), true);
  assert.equal(ui.finder.scope(), "approvals");
  assert.equal(ui.doc.getElementById("navfinder-mode").hidden, false);
  assert.equal(ui.doc.getElementById("navfinder-count").textContent, "Loading requests waiting for you…");
  await ui.flush();
  assert.deepEqual(ui.visible(), ["/approvals#approval-5", "/flows/7/runs/9?approval_review=1", "/approvals"]);
  assert.equal(ui.doc.getElementById("navfinder-count").textContent, "2 requests waiting");
  assert.equal(ui.doc.getElementById("navfinder-choice-0").querySelector(".navfinder__label").textContent, "File delete");
  assert.deepEqual(ui.fetches.map((call) => [call.method, call.url]), [["GET", "/api/v1/approvals"]]);
  // Typing narrows the list; Escape goes back to the whole menu, then closes it.
  assert.deepEqual(ui.type("vendor"), ["/flows/7/runs/9?approval_review=1"]);
  ui.key("Escape");
  assert.equal(ui.open(), true);
  assert.equal(ui.finder.scope(), "all");
  assert.equal(ui.input.value, "approve");
  assert.equal(ui.doc.getElementById("navfinder-mode").hidden, true);
  assert.equal(ui.doc.querySelectorAll("[id^=navfinder-choice-]").length, 0);
  ui.key("Escape");
  assert.equal(ui.open(), false);
  assert.ok(ui.fetches.every((call) => call.method === "GET"), "no decision was sent");
  ui.dom.window.close();
});

test("Approve or reject… still offers the Approvals page when the list cannot load", async () => {
  const ui = menu();
  ui.responses.push({ ok: false, json: {} });
  ui.type("> approve");
  ui.key("Enter");
  await ui.flush();
  assert.deepEqual(ui.visible(), ["/approvals"]);
  ui.key("Backspace");
  assert.equal(ui.finder.scope(), "actions");
  ui.dom.window.close();
});

test("New task focuses the composer when the page has one, and otherwise follows its link", () => {
  const ui = menu({ composer: true });
  ui.type("new task");
  const enter = ui.key("Enter");
  assert.equal(enter.defaultPrevented, true);
  assert.equal(ui.open(), false);
  assert.equal(ui.doc.activeElement.id, "composer-field");
  ui.dom.window.close();

  const elsewhere = menu();
  let followed = null;
  elsewhere.doc.getElementById("navfinder-results").addEventListener("click", (event) => {
    followed = !event.defaultPrevented ? event.target.closest("a").getAttribute("href") : null;
    event.preventDefault();
  });
  elsewhere.type("new task");
  elsewhere.key("Enter");
  assert.equal(followed, "/chat");
  assert.equal(elsewhere.open(), false);
  elsewhere.dom.window.close();
});

test("Pin this page and Show keyboard shortcuts hand over once the menu has closed", () => {
  const ui = menu();
  const calls = [];
  let pinned = false;
  ui.window.LightworkPins = { isPinned: () => pinned, toggle: () => { calls.push(["pin", ui.open()]); pinned = !pinned; } };
  ui.window.LightworkShortcuts = { open: () => calls.push(["shortcuts", ui.open()]) };
  ui.type("> pin");
  ui.key("Enter");
  ui.finder.open();
  // The label follows the page's current state.
  ui.type("> unpin");
  assert.equal(ui.doc.getElementById("navfinder-action-pin").querySelector(".navfinder__label").textContent, "Unpin this page");
  ui.key("Enter");
  ui.finder.open();
  ui.type("keyboard");
  ui.key("Enter");
  assert.deepEqual(calls, [["pin", false], ["pin", false], ["shortcuts", false]]);
  ui.dom.window.close();
});

test("only the commands rendered for this person exist", () => {
  const ui = menu({ commands: ["setting", "shortcuts"] });
  assert.deepEqual(ui.type(">"), ["#navfinder-input", "#shortcuts-dialog"]);
  assert.deepEqual(ui.type("pause"), ["/agent-control-plane"]);
  assert.deepEqual(ui.type("approve"), ["/approvals"]);
  ui.dom.window.close();
});

test("an empty box starts with the person's pinned and recent pages, which also win ties", () => {
  const sidebar = '<ul data-nav-list="pins"><li><a href="/users">Users</a></li><li><a href="/goals">Tasks</a></li></ul>' +
    '<ul data-nav-list="recent"><li><a href="/settings">Settings</a></li><li><a href="/users">Users</a></li></ul>';
  const ui = menu({ sidebar });
  const all = ui.type("");
  assert.deepEqual(all.slice(0, 3), ["/users", "/goals", "/settings"]);
  assert.deepEqual(all.slice(3, 3 + COMMANDS.length), COMMANDS.map(([, href]) => href));
  assert.deepEqual(all.slice(3 + COMMANDS.length), ["/approvals", "/agent-control-plane", "/help"]);
  // Typing ranks by match first (Settings starts with "s"; "stop" and
  // "support" are synonyms that do); among equal matches -- an "s" inside the
  // name -- pinned pages lead, in pin order, before other pages.
  assert.deepEqual(ui.type("/ s"), ["/settings", "/agent-control-plane", "/help", "/users", "/goals", "/approvals"]);
  ui.dom.window.close();
});

test("plain search also finds people, agents and specialists, approvals and help from the server", async () => {
  const ui = menu({ find: true });
  ui.responses.push({ ok: true, json: { results: [
    { kind: "specialist", title: "Finance", labels: ["Finance", "Finance specialist"], context: "Financial analysis", href: "/agents?name=finance" },
    { kind: "approval", title: "Shell", labels: ["Shell"], context: "High risk", href: "/approvals#approval-7" },
    { kind: "person", title: "Dana Admin", labels: ["Dana Admin"], context: "Administrator", href: "/users?q=Dana%20Admin#people" },
    { kind: "help", title: "Invite a colleague", labels: ["Invite a colleague"], context: "Administrator", href: "/help#how-invite" },
    { kind: "agent", title: "Smuggled", labels: ["Smuggled"], context: "", href: "https://evil.example/" },
    { kind: "secret", title: "Unknown kind", labels: [], context: "", href: "/agents?name=x" },
  ] } });
  ui.type("finance specialist");
  assert.equal(ui.timers.length, 1);
  ui.timers.shift()();
  await ui.flush();
  assert.deepEqual(ui.fetches.map((call) => [call.method, call.url]), [["GET", "/nav/finder/find?q=finance%20specialist"]]);
  // The exact name ranks first; rows the server did not vouch for are dropped.
  assert.equal(ui.visible()[0], "/agents?name=finance");
  assert.ok(!ui.visible().some((href) => href.startsWith("https:") || href === "/agents?name=x"));
  const option = ui.doc.querySelector('[href="/agents?name=finance"]');
  assert.match(option.textContent, /Specialist › Financial analysis/);
  // A narrowed search hides them, and a one-letter search asks for nothing.
  ui.type(">finance specialist");
  assert.ok(!ui.visible().includes("/agents?name=finance"));
  ui.type("f");
  assert.equal(ui.timers.length, 0);
  ui.dom.window.close();
});

test("opening the menu asks the server nothing until words are typed", () => {
  // The pack catalogue warms when the server starts (app._warm_pack_catalogue),
  // so opening adds no request of its own.
  const ui = menu({ find: true });
  assert.deepEqual(ui.fetches, []);
  ui.dom.window.close();
});

test("a match only in an agent's description stays below the named records", async () => {
  const ui = menu({ find: true });
  ui.responses.push({ ok: true, json: { results: [
    { kind: "specialist", title: "Curator", labels: ["Curator", "Curator specialist"], context: "Turns stale drafts into articles", href: "/agents?name=cx_kb_curator" },
  ] } });
  ui.type("stale draft");
  ui.timers.shift()();
  await ui.flush();
  ui.finder.setRecords([{ kind: "task", id: "2", title: "Archive the stale draft files", href: "/chat/goal/2", state: "done", revision: "" }]);
  assert.deepEqual(ui.visible(), ["/chat/goal/2", "/agents?name=cx_kb_curator"]);
  const order = [...ui.doc.querySelectorAll("#navfinder-results a[role=option]:not([hidden])")].map((option) => option.getAttribute("href"));
  assert.deepEqual(order, ["/chat/goal/2", "/agents?name=cx_kb_curator"], "the screen order matches the arrow-key order");
  ui.dom.window.close();
});

test("rows found for earlier words are cleared as soon as the words change", async () => {
  const ui = menu({ find: true });
  ui.responses.push({ ok: true, json: { results: [
    { kind: "help", title: "Invite a colleague", labels: ["Invite a colleague"], context: "Administrator", href: "/help#how-invite" },
  ] } });
  ui.type("invite");
  ui.timers.shift()();
  await ui.flush();
  assert.ok(ui.visible().includes("/help#how-invite"));
  ui.type("activity log");
  assert.ok(!ui.visible().includes("/help#how-invite"), "the earlier answer is gone before the new one arrives");
  ui.dom.window.close();
});

test("a page named like the words stays above an agent with the same name", async () => {
  const ui = menu({ find: true });
  ui.responses.push({ ok: true, json: { results: [
    { kind: "specialist", title: "Approvals", labels: ["Approvals", "Approvals specialist"], context: "", href: "/agents?name=approvals_desk" },
  ] } });
  ui.type("approvals");
  ui.timers.shift()();
  await ui.flush();
  const order = ui.visible();
  assert.ok(order.indexOf("/approvals") < order.indexOf("/agents?name=approvals_desk"), order.join(", "));
  ui.dom.window.close();
});


test("late settings under a stationary pointer cannot replace a keyboard command", () => {
  const ui = menu({composer: true});
  ui.type("> new task");
  ui.finder.setSettings([{href: "/settings/all?id=task-limit", title: "New task limit", group: "Work"}]);
  const setting = ui.doc.getElementById("navfinder-setting-0");
  // Chromium emits mouseenter when asynchronous results appear under the
  // pointer left behind by an earlier click, even without pointer movement.
  setting.dispatchEvent(new ui.window.MouseEvent("mouseenter"));
  assert.equal(ui.input.getAttribute("aria-activedescendant"), "navfinder-action-new-task");
  ui.key("Enter");
  assert.equal(ui.doc.activeElement.id, "composer-field");
  assert.equal(ui.open(), false);
  ui.dom.window.close();
});

test("moving the pointer deliberately selects an arriving setting", () => {
  const ui = menu();
  ui.type("> new task");
  ui.finder.setSettings([{href: "/settings/all?id=task-limit", title: "New task limit", group: "Work"}]);
  const setting = ui.doc.getElementById("navfinder-setting-0");
  let clicks = 0;
  setting.addEventListener("click", event => { event.preventDefault(); clicks += 1; });
  setting.dispatchEvent(new ui.window.MouseEvent("mousemove", {clientX: 100, clientY: 100}));
  assert.equal(ui.input.getAttribute("aria-activedescendant"), setting.id);
  ui.key("Enter");
  assert.equal(clicks, 1);
  ui.dom.window.close();
});
