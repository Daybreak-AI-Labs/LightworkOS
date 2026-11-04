"use strict";
// The shared tab bar (templates/_tabs.html + static/lightwork-tabs.js): tabs
// are links to their views, so the address is the state; the script adds the
// keys of a tab list. Run with: node --test tests/js/tabs.test.js
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const {JSDOM} = require("jsdom");
const script = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-tabs.js"), "utf8");

function fixture() {
  const html = `<main id="content">
    <div class="mv-tabs" role="tablist" aria-label="Task replay views" data-mv-tabs>
      <a class="mv-tab" role="tab" id="t-main" href="/replay" aria-selected="true" tabindex="0">Replay</a>
      <a class="mv-tab" role="tab" id="t-branches" href="/replay?tab=branches" aria-selected="false" tabindex="-1">Branches</a>
      <a class="mv-tab" role="tab" id="t-video" href="/replay?tab=video" aria-selected="false" tabindex="-1">Video</a>
    </div><div role="tabpanel" aria-labelledby="t-main"><button id="inside">Inside</button></div></main>`;
  const dom = new JSDOM(html, {url: "https://fixture.invalid/replay", runScripts: "outside-only", pretendToBeVisual: true});
  const w = dom.window, doc = w.document, opened = [];
  doc.querySelectorAll('[role="tab"]').forEach((tab) => tab.addEventListener("click", (event) => {
    event.preventDefault();
    opened.push(tab.getAttribute("href"));
  }));
  w.eval(script);
  w.mvTabs.init();  // the page may still be loading; the script also binds on DOMContentLoaded
  const key = (target, name) => {
    const event = new w.KeyboardEvent("keydown", {key: name, bubbles: true, cancelable: true});
    target.dispatchEvent(event);
    return event;
  };
  return {w, doc, opened, key, tab: (id) => doc.getElementById(id)};
}

test("arrow keys move focus along the tabs and wrap, with one tab in the Tab order", () => {
  const f = fixture();
  f.tab("t-main").focus();
  assert.equal(f.key(f.tab("t-main"), "ArrowRight").defaultPrevented, true);
  assert.equal(f.doc.activeElement, f.tab("t-branches"));
  assert.deepEqual(["t-main", "t-branches", "t-video"].map((id) => f.tab(id).getAttribute("tabindex")), ["-1", "0", "-1"]);
  f.key(f.tab("t-branches"), "ArrowRight");
  f.key(f.tab("t-video"), "ArrowRight");
  assert.equal(f.doc.activeElement, f.tab("t-main"), "Right on the last tab wraps to the first");
  f.key(f.tab("t-main"), "ArrowLeft");
  assert.equal(f.doc.activeElement, f.tab("t-video"), "Left on the first tab wraps to the last");
  f.key(f.tab("t-video"), "Home");
  assert.equal(f.doc.activeElement, f.tab("t-main"));
  f.key(f.tab("t-main"), "End");
  assert.equal(f.doc.activeElement, f.tab("t-video"));
});

test("moving focus opens nothing; Space opens the focused tab's address", () => {
  const f = fixture();
  f.tab("t-main").focus();
  f.key(f.tab("t-main"), "ArrowRight");
  assert.deepEqual(f.opened, []);
  assert.equal(f.tab("t-main").getAttribute("aria-selected"), "true", "the shown view stays selected");
  assert.equal(f.key(f.tab("t-branches"), " ").defaultPrevented, true);
  assert.deepEqual(f.opened, ["/replay?tab=branches"]);
});

test("other keys and modified arrows are left alone", () => {
  const f = fixture();
  f.tab("t-main").focus();
  assert.equal(f.key(f.tab("t-main"), "a").defaultPrevented, false);
  const event = new f.w.KeyboardEvent("keydown", {key: "ArrowRight", altKey: true, bubbles: true, cancelable: true});
  f.tab("t-main").dispatchEvent(event);
  assert.equal(event.defaultPrevented, false);
  assert.equal(f.doc.activeElement, f.tab("t-main"));
});

test("the bar binds once even when the script runs again", () => {
  const f = fixture();
  f.w.eval(script);
  f.w.mvTabs.init();
  f.tab("t-main").focus();
  f.key(f.tab("t-main"), "ArrowRight");
  assert.equal(f.doc.activeElement, f.tab("t-branches"), "one listener: a second would skip a tab");
});

// ---- panel tabs: views that are panels of one page ------------------------
function panelFixture({ hash = null, manual = false, url = "https://fixture.invalid/security", shared = false } = {}) {
  const keys = ["controls", "risks", "audits"];
  const tabs = keys.map((key, i) => `<button class="mv-tab" type="button" role="tab" id="p-tab-${key}" data-mv-tab="${key}"
    aria-controls="${shared ? "p-list" : "p-panel-" + key}" aria-selected="${i ? "false" : "true"}" tabindex="${i ? "-1" : "0"}">${key}</button>`).join("");
  const panels = shared ? '<div id="p-list" role="tabpanel" aria-labelledby="p-tab-controls">rows</div>'
    : keys.map((key, i) => `<section id="p-panel-${key}" role="tabpanel" aria-labelledby="p-tab-${key}"${i ? " hidden" : ""}>${key}</section>`).join("");
  const html = `<main><div class="mv-tabs" role="tablist" aria-label="Records" data-mv-tabs="panels"${hash === null ? "" : ` data-mv-tabs-hash="${hash}"`}${manual ? ' data-mv-tabs-activation="manual"' : ""}>${tabs}</div>${panels}</main>`;
  const dom = new JSDOM(html, {url, runScripts: "outside-only", pretendToBeVisual: true});
  const w = dom.window, doc = w.document, clicks = [];
  doc.querySelectorAll('[role="tab"]').forEach((tab) => tab.addEventListener("click", () => clicks.push(tab.dataset.mvTab)));
  w.eval(script);
  w.mvTabs.init();
  const key = (target, name) => {
    const event = new w.KeyboardEvent("keydown", {key: name, bubbles: true, cancelable: true});
    target.dispatchEvent(event);
    return event;
  };
  const shown = () => [...doc.querySelectorAll('[role="tabpanel"]')].filter((p) => !p.hidden).map((p) => p.id);
  const selected = () => [...doc.querySelectorAll('[aria-selected="true"]')].map((t) => t.dataset.mvTab);
  return {w, doc, key, shown, selected, clicks, tab: (k) => doc.getElementById("p-tab-" + k)};
}

test("a click on a panel tab selects it and shows only its panel", () => {
  const f = panelFixture();
  f.tab("risks").click();
  assert.deepEqual(f.selected(), ["risks"]);
  assert.deepEqual(f.shown(), ["p-panel-risks"]);
  assert.deepEqual(["controls", "risks", "audits"].map((k) => f.tab(k).getAttribute("tabindex")), ["-1", "0", "-1"]);
  assert.equal(f.w.location.hash, "", "no address unless the bar asks for one");
});

test("arrow, Home and End keys select the tab they move to, through a click the page also hears", () => {
  const f = panelFixture();
  f.tab("controls").focus();
  assert.equal(f.key(f.tab("controls"), "ArrowRight").defaultPrevented, true);
  assert.equal(f.doc.activeElement, f.tab("risks"));
  assert.deepEqual(f.shown(), ["p-panel-risks"]);
  f.key(f.tab("risks"), "End");
  assert.deepEqual(f.selected(), ["audits"]);
  f.key(f.tab("audits"), "ArrowRight");
  assert.deepEqual(f.selected(), ["controls"], "Right on the last tab wraps to the first");
  f.key(f.tab("controls"), "ArrowLeft");
  assert.deepEqual(f.selected(), ["audits"]);
  f.key(f.tab("audits"), "Home");
  assert.deepEqual(f.selected(), ["controls"]);
  assert.deepEqual(f.clicks, ["risks", "audits", "controls", "audits", "controls"]);
  assert.equal(f.key(f.tab("controls"), " ").defaultPrevented, false, "Space is left to the button itself");
});

test("manual activation only moves focus; the button's own click selects", () => {
  const f = panelFixture({manual: true});
  f.tab("controls").focus();
  f.key(f.tab("controls"), "ArrowRight");
  assert.equal(f.doc.activeElement, f.tab("risks"));
  assert.deepEqual(f.selected(), ["controls"]);
  assert.deepEqual(f.clicks, []);
  f.tab("risks").click();
  assert.deepEqual(f.selected(), ["risks"]);
});

test("with an address prefix the selected tab is kept in the address without a Back step, and an address opens its tab", () => {
  const f = panelFixture({hash: "p-", url: "https://fixture.invalid/security#p-audits"});
  assert.deepEqual(f.selected(), ["audits"]);
  assert.deepEqual(f.shown(), ["p-panel-audits"]);
  const before = f.w.history.length;
  f.tab("risks").click();
  assert.equal(f.w.location.hash, "#p-risks");
  f.key(f.tab("risks"), "Home");
  assert.equal(f.w.location.hash, "#p-controls");
  assert.equal(f.w.history.length, before);
  f.w.location.hash = "#p-audits";
  f.w.dispatchEvent(new f.w.HashChangeEvent("hashchange"));
  assert.deepEqual(f.shown(), ["p-panel-audits"]);
  const unknown = panelFixture({hash: "p-", url: "https://fixture.invalid/security#p-nothing"});
  assert.deepEqual(unknown.selected(), ["controls"], "an unknown address leaves the first tab open");
});

test("tabs that filter one shared list keep it shown and name the chosen tab as its label", () => {
  const f = panelFixture({shared: true});
  f.tab("audits").click();
  assert.deepEqual(f.shown(), ["p-list"]);
  assert.equal(f.doc.getElementById("p-list").getAttribute("aria-labelledby"), "p-tab-audits");
  assert.deepEqual(f.selected(), ["audits"]);
});

test("a second copy of the script on the page binds nothing twice", () => {
  const f = panelFixture();
  f.w.eval(script);
  f.tab("controls").focus();
  f.key(f.tab("controls"), "ArrowRight");
  assert.deepEqual(f.selected(), ["risks"], "one listener: a second would skip a tab");
  assert.deepEqual(f.clicks, ["risks"]);
});
