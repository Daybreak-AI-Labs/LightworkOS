// Run with: node --test packages/maverick-dashboard/tests/js/lightwork_ui_navigation.test.js
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function fixture({ mobile = true, collapsed = false, mainInert = false, headerHeight = 56 } = {}) {
  const document = { activeElement: null, listeners: {} };
  class Element {
    constructor({ inSidebar = false } = {}) {
      this.attributes = new Map();
      this.listeners = {};
      this.inSidebar = inSidebar;
      this.inert = false;
      const classes = new Set();
      this.classList = {
        add(value) { classes.add(value); },
        remove(value) { classes.delete(value); },
        contains(value) { return classes.has(value); },
        toggle(value, enabled = !classes.has(value)) {
          if (enabled) classes.add(value); else classes.delete(value);
          return enabled;
        },
      };
    }
    addEventListener(name, handler) { this.listeners[name] = handler; }
    setAttribute(name, value) { this.attributes.set(name, String(value)); }
    removeAttribute(name) { this.attributes.delete(name); }
    getAttribute(name) { return this.attributes.get(name); }
    hasAttribute(name) { return this.attributes.has(name); }
    toggleAttribute(name, enabled) {
      if (enabled) this.attributes.set(name, ""); else this.attributes.delete(name);
    }
    focus() { document.activeElement = this; }
  }
  const body = new Element();
  const properties = new Map();
  body.style = { setProperty(name, value) { properties.set(name, value); } };
  // The root gets the same measured height: scroll-padding-top reads it there.
  const rootProperties = new Map();
  document.documentElement = { style: { setProperty(name, value) { rootProperties.set(name, value); } } };
  let measuredHeight = headerHeight;
  let onHeaderResize;
  const topbar = { getBoundingClientRect() { return { height: measuredHeight }; } };
  const toggle = new Element();
  const backdrop = new Element();
  const sidebar = new Element();
  const navLink = new Element({ inSidebar: true });
  const skipLink = new Element();
  const firstControl = new Element({ inSidebar: true });
  const main = new Element();
  const footer = new Element();
  if (mainInert) { main.inert = true; main.setAttribute("inert", ""); }
  sidebar.contains = (element) => !!element?.inSidebar;
  sidebar.querySelector = () => firstControl;
  const media = {
    matches: mobile,
    listeners: {},
    addEventListener(name, handler) { this.listeners[name] = handler; },
  };
  document.body = body;
  document.getElementById = (id) => ({
    "nav-toggle": toggle, "nav-backdrop": backdrop, sidebar,
  })[id] || null;
  document.querySelectorAll = (selector) => {
    if (selector === ".sidebar a, .skip-link") return [navLink, skipLink];
    if (selector === "main, body > footer") return [main, footer];
    return [];
  };
  document.querySelector = (selector) => selector === ".topbar" ? topbar : null;
  document.addEventListener = (name, handler) => { document.listeners[name] = handler; };
  const source = fs.readFileSync(
    path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-ui.js"), "utf8",
  );
  const start = source.indexOf("    // Sidebar toggle.");
  // This fixture exercises navigation, not the following appearance controller.
  const appearance = source.indexOf("      var system = window.matchMedia", start);
  const end = source.lastIndexOf("    (function () {", appearance);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  vm.runInNewContext(source.slice(start, end), {
    document,
    window: { matchMedia() { return media; }, addEventListener() {} },
    localStorage: {
      getItem() { return collapsed ? "1" : ""; },
      setItem() {},
    },
    ResizeObserver: class {
      constructor(handler) { onHeaderResize = handler; }
      observe(element) { assert.equal(element, topbar); }
    },
  });
  return {
    document, body, toggle, backdrop, sidebar, main, footer, firstControl, navLink, skipLink, properties, rootProperties,
    resize(matches) { media.matches = matches; media.listeners.change(); },
    resizeHeader(height) { measuredHeight = height; onHeaderResize(); },
  };
}

test("a closed mobile drawer leaves the page accessible and the drawer inert", () => {
  const ui = fixture();
  assert.equal(ui.sidebar.inert, true);
  assert.equal(ui.sidebar.hasAttribute("inert"), true);
  assert.equal(ui.toggle.getAttribute("aria-expanded"), "false");
  assert.equal(ui.main.inert, false);
  assert.equal(ui.footer.inert, false);
});

test("opening the mobile drawer focuses navigation and blocks covered page controls", () => {
  const ui = fixture();
  ui.toggle.focus();
  ui.toggle.listeners.click();
  assert.equal(ui.sidebar.inert, false);
  assert.equal(ui.toggle.getAttribute("aria-expanded"), "true");
  assert.equal(ui.main.inert, true);
  assert.equal(ui.footer.hasAttribute("inert"), true);
  assert.equal(ui.document.activeElement, ui.firstControl);

  ui.document.listeners.keydown({ key: "Escape" });
  assert.equal(ui.sidebar.inert, true);
  assert.equal(ui.main.inert, false);
  assert.equal(ui.footer.hasAttribute("inert"), false);
  assert.equal(ui.document.activeElement, ui.toggle);
});

test("backdrop, navigation and skip-link clicks restore the page after an open drawer", () => {
  for (const closeTarget of ["backdrop", "navLink", "skipLink"]) {
    const ui = fixture();
    ui.toggle.listeners.click();
    ui[closeTarget].listeners.click();
    assert.equal(ui.main.inert, false);
    assert.equal(ui.body.classList.contains("nav-open"), false);
  }
});

test("resizing to desktop clears the drawer state and restores the covered page", () => {
  const ui = fixture();
  ui.toggle.listeners.click();
  ui.resize(false);
  assert.equal(ui.main.inert, false);
  assert.equal(ui.sidebar.inert, false);
  assert.equal(ui.body.classList.contains("nav-open"), false);
  ui.resize(true);
  assert.equal(ui.sidebar.inert, true);
  assert.equal(ui.main.inert, false);
});

test("desktop collapse never blocks the main page", () => {
  const ui = fixture({ mobile: false });
  assert.equal(ui.sidebar.inert, false);
  ui.toggle.listeners.click();
  assert.equal(ui.sidebar.inert, true);
  assert.equal(ui.main.inert, false);
  assert.equal(ui.toggle.getAttribute("aria-expanded"), "false");
});

test("drawer closing preserves a page section that was already inert", () => {
  const ui = fixture({ mainInert: true });
  ui.toggle.listeners.click();
  ui.backdrop.listeners.click();
  assert.equal(ui.main.inert, true);
  assert.equal(ui.main.hasAttribute("inert"), true);
  assert.equal(ui.footer.inert, false);
});

test("navigation tracks wrapped header height without changing the header minimum", () => {
  const ui = fixture({ headerHeight: 94.5 });
  assert.equal(ui.properties.get("--shell-topbar-h"), "95px");
  assert.equal(ui.rootProperties.get("--shell-topbar-h"), "95px");
  ui.resizeHeader(55);
  assert.equal(ui.properties.get("--shell-topbar-h"), "55px");
  assert.equal(ui.rootProperties.get("--shell-topbar-h"), "55px");
  assert.equal(ui.properties.has("--topbar-h"), false);
});
