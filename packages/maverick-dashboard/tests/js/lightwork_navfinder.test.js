// Run with: node --test packages/maverick-dashboard/tests/js/lightwork_navfinder.test.js
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function navFinderClient() {
  const window = {};
  const context = { console, window };
  vm.createContext(context);
  const source = fs.readFileSync(
    path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-navfinder.js"),
    "utf8",
  );
  vm.runInContext(source, context, { filename: "lightwork-navfinder.js" });
  return window.LightworkNavFinder;
}

function keyboard(key, overrides = {}) {
  return Object.assign({
    key,
    ctrlKey: false,
    metaKey: false,
    altKey: false,
    isComposing: false,
    defaultPrevented: false,
    propagationStopped: false,
    preventDefault() { this.defaultPrevented = true; },
    stopPropagation() { this.propagationStopped = true; },
  }, overrides);
}

class ClassList {
  constructor() { this.values = new Set(); }
  add(value) { this.values.add(value); }
  remove(value) { this.values.delete(value); }
  contains(value) { return this.values.has(value); }
}

class Element {
  constructor(document, id = "") {
    this.document = document;
    this.id = id;
    this.attributes = {};
    this.listeners = {};
    this.classList = new ClassList();
    this.hidden = false;
    this.isConnected = true;
    this.parentElement = null;
    this.value = "";
    this.textContent = "";
    this.clickCount = 0;
    this.inertAncestor = false;
  }
  addEventListener(type, callback) {
    if (!this.listeners[type]) this.listeners[type] = [];
    this.listeners[type].push(callback);
  }
  dispatch(type, event = keyboard(type)) {
    event.target = event.target || this;
    event.currentTarget = this;
    for (const callback of this.listeners[type] || []) callback(event);
    return event;
  }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) { return Object.prototype.hasOwnProperty.call(this.attributes, name) ? this.attributes[name] : null; }
  removeAttribute(name) { delete this.attributes[name]; }
  focus() { this.document.activeElement = this; }
  closest(selector) { return selector === "[inert]" && this.inertAncestor ? {} : null; }
  click() {
    this.clickCount += 1;
    this.dispatch("click", keyboard("click"));
  }
  scrollIntoView() { this.scrolled = true; }
}

class Dialog extends Element {
  constructor(document, id) {
    super(document, id);
    this.open = false;
  }
  showModal() {
    this.open = true;
    this.setAttribute("open", "");
  }
  close() {
    this.open = false;
    this.removeAttribute("open");
    this.dispatch("close", keyboard("close"));
  }
}

class Document {
  constructor() {
    this.elements = new Map();
    this.listeners = {};
    this.activeElement = null;
  }
  add(element) {
    this.elements.set(element.id, element);
    return element;
  }
  getElementById(id) { return this.elements.get(id) || null; }
  addEventListener(type, callback) {
    if (!this.listeners[type]) this.listeners[type] = [];
    this.listeners[type].push(callback);
  }
  dispatch(type, event) {
    for (const callback of this.listeners[type] || []) callback(event);
    return event;
  }
}

function fixture() {
  const document = new Document();
  const trigger = document.add(new Element(document, "navfinder-open"));
  const dialog = document.add(new Dialog(document, "navfinder-dialog"));
  const input = document.add(new Element(document, "navfinder-input"));
  const results = document.add(new Element(document, "navfinder-results"));
  const close = document.add(new Element(document, "navfinder-close"));
  const count = document.add(new Element(document, "navfinder-count"));
  const empty = document.add(new Element(document, "navfinder-empty"));
  const navToggle = document.add(new Element(document, "nav-toggle"));
  const content = document.add(new Element(document, "content"));

  const details = [
    ["overview", "Overview General /overview"],
    ["privacy-rights", "Request workflows Privacy /privacy/rights"],
    ["settings", "Settings System /settings"],
  ];
  const options = details.map(([name, search], index) => {
    const parent = new Element(document, `row-${index}`);
    const option = new Element(document, `navfinder-option-${index}`);
    option.parentElement = parent;
    option.setAttribute("data-navfinder-target", "");
    option.setAttribute("data-search", search);
    option.setAttribute("href", `/${name}`);
    return option;
  });
  results.querySelectorAll = (selector) => selector === "[data-navfinder-target]" ? options : [];

  return { document, trigger, dialog, input, results, close, count, empty, navToggle, content, options };
}

test("open, filter, arrows, Enter and Escape preserve accessible state", () => {
  const ui = fixture();
  navFinderClient().init(ui.document);

  ui.trigger.click();
  assert.equal(ui.dialog.open, true);
  assert.equal(ui.document.activeElement, ui.input);
  assert.equal(ui.trigger.getAttribute("aria-expanded"), "true");
  assert.equal(ui.input.getAttribute("aria-expanded"), "true");
  assert.equal(ui.count.textContent, "3 pages");
  assert.equal(ui.input.getAttribute("aria-activedescendant"), ui.options[0].id);

  ui.input.value = "privacy rights";
  ui.input.dispatch("input", keyboard("input"));
  assert.deepEqual(ui.options.map((option) => option.hidden), [true, false, true]);
  assert.equal(ui.count.textContent, "1 page");
  assert.equal(ui.input.getAttribute("aria-activedescendant"), ui.options[1].id);

  ui.input.value = "";
  ui.input.dispatch("input", keyboard("input"));
  ui.dialog.dispatch("keydown", keyboard("ArrowUp", { target: ui.input }));
  assert.equal(ui.options[2].getAttribute("aria-selected"), "true");
  ui.dialog.dispatch("keydown", keyboard("ArrowDown", { target: ui.input }));
  ui.dialog.dispatch("keydown", keyboard("ArrowDown", { target: ui.input }));
  assert.equal(ui.options[1].getAttribute("aria-selected"), "true");

  const enter = ui.dialog.dispatch("keydown", keyboard("Enter", { target: ui.input }));
  assert.equal(enter.defaultPrevented, true);
  assert.equal(ui.options[1].clickCount, 1);
  assert.equal(ui.dialog.open, false);
  assert.equal(ui.document.activeElement, ui.trigger);
  assert.equal(ui.trigger.getAttribute("aria-expanded"), "false");
});

test("listbox key handling does not hijack the dialog close button", () => {
  const ui = fixture();
  navFinderClient().init(ui.document);
  ui.trigger.click();

  const enter = ui.dialog.dispatch("keydown", keyboard("Enter", { target: ui.close }));
  assert.equal(enter.defaultPrevented, false);
  assert.deepEqual(ui.options.map((option) => option.clickCount), [0, 0, 0]);
  assert.equal(ui.dialog.open, true);
});

test("Ctrl/Cmd+K opens globally and Escape restores the invoking focus", () => {
  for (const modifier of ["ctrlKey", "metaKey"]) {
    const ui = fixture();
    navFinderClient().init(ui.document);
    ui.content.focus();

    const shortcut = keyboard("k", { [modifier]: true });
    ui.document.dispatch("keydown", shortcut);
    assert.equal(shortcut.defaultPrevented, true);
    assert.equal(ui.dialog.open, true);
    assert.equal(ui.document.activeElement, ui.input);

    const escape = ui.dialog.dispatch("keydown", keyboard("Escape"));
    assert.equal(escape.defaultPrevented, true);
    assert.equal(escape.propagationStopped, true);
    assert.equal(ui.dialog.open, false);
    assert.equal(ui.document.activeElement, ui.content);
  }
});

test("focus falls back to the mobile nav toggle when the opener becomes inert", () => {
  const ui = fixture();
  navFinderClient().init(ui.document);
  ui.trigger.click();
  ui.trigger.inertAncestor = true;

  ui.close.click();
  assert.equal(ui.dialog.open, false);
  assert.equal(ui.document.activeElement, ui.navToggle);
});

test("an empty filter exposes a status and no active descendant", () => {
  const ui = fixture();
  navFinderClient().init(ui.document);
  ui.trigger.click();
  ui.input.value = "destination-that-does-not-exist";
  ui.input.dispatch("input", keyboard("input"));

  assert.equal(ui.count.textContent, "0 pages");
  assert.equal(ui.empty.hidden, false);
  assert.equal(ui.results.hidden, true);
  assert.equal(ui.input.getAttribute("aria-activedescendant"), null);
});

// Ranking runs over the real listbox markup (served by /nav/finder), so these
// cases use a DOM: matches move in the DOM as well as in arrow-key order.
function rankedFinder(pages, extra = "") {
  const { JSDOM } = require("jsdom");
  const items = pages.map(([href, label, heading = "", synonyms = "", search = ""], index) =>
    `<li role="none"><a id="navfinder-option-0-${index}" href="${href}" role="option" tabindex="-1"` +
    ` aria-selected="false" data-navfinder-target data-label="${label}" data-heading="${heading}"` +
    ` data-synonyms="${synonyms}" data-search="${label} ${heading} ${synonyms.replace(/\|/g, " ")} ${href} ${search}">` +
    `<span class="navfinder__label">${label}</span></a></li>`).join("");
  const dom = new JSDOM(`<!doctype html><button id="navfinder-open"></button><button id="nav-toggle"></button>
    <dialog id="navfinder-dialog"><button id="navfinder-close"></button><input id="navfinder-input">
    <p id="navfinder-count"></p><ul id="navfinder-results">${items}${extra}</ul><p id="navfinder-empty" hidden></p></dialog>`,
    { runScripts: "outside-only" });
  dom.window.eval(fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-navfinder.js"), "utf8"));
  const doc = dom.window.document;
  const finder = dom.window.LightworkNavFinder.init(doc) || doc.getElementById("navfinder-dialog").lightworkFinder;
  const input = doc.getElementById("navfinder-input");
  finder.open();
  return {
    dom, doc, finder, input,
    type(query) {
      input.value = query;
      input.dispatchEvent(new dom.window.Event("input"));
      return [...finder.visibleOptions()].map((option) => option.getAttribute("href"));
    },
    domOrder() {
      return Array.from(doc.querySelectorAll("#navfinder-results > li:not([hidden]) > a")).map((a) => a.getAttribute("href"));
    },
  };
}

const RANKED_PAGES = [
  ["/my-data", "My data", "", "", "Work Operate"],
  ["/me", "My work"],
  ["/approvals", "Approvals", "", "approve|approval|sign-off"],
  ["/audit", "Audit", "Activity log", "audit log|history|export"],
  ["/audit/evolution-ledger", "Evolution Ledger", "Learning history"],
  ["/consent/publish-settings", "Consent Publish Settings", "Website Banner Settings"],
  ["/settings", "Settings"],
  ["/cortex", "Cortex memory diagnostics", "Knowledge"],
  ["/knowledge-access", "Knowledge", "Find knowledge you can use now"],
];

test("an exact label ranks first and Enter opens it", () => {
  const ui = rankedFinder(RANKED_PAGES);
  assert.deepEqual(ui.type("My work").slice(0, 2), ["/me", "/my-data"]);
  assert.equal(ui.type("Settings")[0], "/settings");
  assert.deepEqual(ui.type("knowledge").slice(0, 2), ["/knowledge-access", "/cortex"]);
  ui.type("settings");
  let opened = "";
  ui.doc.getElementById("navfinder-results").addEventListener("click", (event) => {
    event.preventDefault();
    opened = event.target.closest("a").getAttribute("href");
  });
  ui.input.dispatchEvent(new ui.dom.window.KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
  assert.equal(opened, "/settings");
  ui.dom.window.close();
});

test("a page's own heading and plain synonyms find it ahead of passing mentions", () => {
  const ui = rankedFinder(RANKED_PAGES);
  assert.deepEqual(ui.type("Activity log"), ["/audit"]);
  assert.equal(ui.type("approve")[0], "/approvals");
  assert.deepEqual(ui.type("history").slice(0, 2), ["/audit", "/audit/evolution-ledger"]);
  assert.equal(ui.type("activity")[0], "/audit");
  assert.equal(ui.type("Learning history")[0], "/audit/evolution-ledger");
  // Case and extra spaces do not matter.
  assert.deepEqual(ui.type("  activity   LOG "), ["/audit"]);
  ui.dom.window.close();
});

test("prefix beats word start, which beats words inside, which beats an alias-only match", () => {
  const ui = rankedFinder([
    ["/z-alias", "Zebra", "", "", "spend money"],
    ["/inside", "Overspend"],
    ["/word", "Team spend review"],
    ["/prefix", "Spend overview"],
    ["/exact", "Spend"],
  ]);
  assert.deepEqual(ui.type("spend"), ["/exact", "/prefix", "/word", "/inside", "/z-alias"]);
  ui.dom.window.close();
});

test("ranked pages move in the listbox and keep records and settings after them", () => {
  const extra = '<li role="none"><a id="navfinder-record-0" role="option" href="/chat/goal/1">Record</a></li>';
  const ui = rankedFinder(RANKED_PAGES, extra);
  ui.type("settings");
  assert.deepEqual(ui.domOrder(), ["/settings", "/consent/publish-settings", "/chat/goal/1"]);
  assert.equal(ui.input.getAttribute("aria-activedescendant"), ui.doc.querySelector('a[href="/settings"]').id);
  // Clearing the box restores the registry order.
  ui.type("");
  assert.deepEqual(ui.domOrder(), RANKED_PAGES.map(([href]) => href).concat(["/chat/goal/1"]));
  ui.dom.window.close();
});

test("the status counts settings shown as well as pages", () => {
  const ui = rankedFinder(RANKED_PAGES);
  ui.type("settings");
  ui.finder.setSettings([
    { href: "/settings?focus=settings-theme", title: "Your colour theme", group: "Personal / device", effective: "", required_role: "" },
    { href: "/settings/all?group=safety&id=x", title: "Another setting", group: "Safety", effective: "", required_role: "" },
  ]);
  assert.equal(ui.doc.getElementById("navfinder-count").textContent, "2 pages, 2 settings shown");
  // Pages stay first; settings follow in the order the server ranked them.
  assert.deepEqual([...ui.finder.visibleOptions()].map((option) => option.getAttribute("href")),
    ["/settings", "/consent/publish-settings", "/settings?focus=settings-theme", "/settings/all?group=safety&id=x"]);
  ui.dom.window.close();
});
