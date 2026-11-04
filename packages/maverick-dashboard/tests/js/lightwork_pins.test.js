// Run with: node --test packages/maverick-dashboard/tests/js/lightwork_pins.test.js
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const SCRIPT = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-pins.js"), "utf8");

function pin(href, label) {
  return `<li data-pin="${href}"><a href="${href}"><svg class="nav-ic"></svg><span class="nav-label">${label}</span></a>` +
    `<span class="navpins__tools" hidden><button type="button" class="navpins__tool" data-pin-op="up" aria-label="Move ${label} up"></button>` +
    `<button type="button" class="navpins__tool" data-pin-op="down" aria-label="Move ${label} down"></button>` +
    `<button type="button" class="navpins__tool" data-pin-op="remove" aria-label="Unpin ${label}"></button></span></li>`;
}

// As _sidebar_nav.html and base.html render them on the Overview page.
function sidebar({ pinned = [["/goals", "Tasks"], ["/deliverables", "Results"]], record = true, toggle = true } = {}) {
  const dom = new JSDOM(`<!doctype html><head>
    <meta name="lightwork-preference-context" content="ctx-1"><meta name="lightwork-preference-revision" content="rev-1"></head><body>
    <div class="navpins" id="navpins" data-nav-pins data-nav-current="/overview" data-nav-current-label="Overview"${record ? " data-nav-record" : ""}>
      <span id="navpins-label">Pinned pages</span>
      <button type="button" id="navpins-edit" aria-expanded="false"${pinned.length ? "" : " hidden"}>Edit</button>
      <ul id="navpins-list">${pinned.map(([href, label]) => pin(href, label)).join("")}</ul>
      <p id="navpins-empty"${pinned.length ? " hidden" : ""}>No pinned pages.</p>
      <p id="navpins-status" role="status"></p>
    </div>
    ${toggle ? '<button type="button" id="page-pin-toggle" data-nav-pin-toggle="/overview" aria-pressed="false">Pin to sidebar</button>' : ""}
  </body>`, { runScripts: "outside-only", url: "https://lightwork.test/overview" });
  const window = dom.window;
  const calls = [];
  const replies = [];
  window.fetch = (url, options = {}) => {
    calls.push({ url: String(url), method: options.method || "GET", body: options.body ? JSON.parse(options.body) : null,
      keepalive: options.keepalive === true });
    const reply = replies.shift() || { ok: true, json: { recorded: true } };
    const call = calls[calls.length - 1];
    call.read = false;
    const read = (value) => { call.read = true; return value; };
    return Promise.resolve({ ok: reply.ok, status: reply.ok ? 200 : 403,
      json: async () => read(reply.json), text: async () => read(JSON.stringify(reply.json)) });
  };
  const toasts = [];
  window.mvToast = (message, options) => toasts.push([message, !!(options && options.error)]);
  window.eval(SCRIPT);
  const pins = window.LightworkPinsInit(window.document) || window.LightworkPins;
  const doc = window.document;
  return {
    dom, window, doc, pins, calls, replies, toasts,
    order() { return [...doc.querySelectorAll("#navpins-list > li")].map((item) => item.getAttribute("data-pin")); },
    flush() { return new Promise((resolve) => setTimeout(resolve, 0)); },
  };
}

const AFTER_ADD = [{ href: "/goals", label: "Tasks", icon: "target" }, { href: "/deliverables", label: "Results", icon: "check" },
                   { href: "/overview", label: "Overview", icon: "overview" }];

test("the page's Pin to sidebar button pins it through the server and shows the new list", async () => {
  const ui = sidebar({ record: false });
  ui.replies.push({ ok: true, json: { pins: AFTER_ADD, pinned: true, revision: "rev-2" } });
  ui.doc.getElementById("page-pin-toggle").click();
  await ui.flush();
  assert.deepEqual(ui.calls.map((call) => [call.method, call.url, call.body]),
    [["POST", "/api/v1/navigation/pins", { op: "add", href: "/overview", context: "ctx-1" }]]);
  assert.deepEqual(ui.order(), ["/goals", "/deliverables", "/overview"]);
  assert.equal(ui.doc.getElementById("page-pin-toggle").getAttribute("aria-pressed"), "true");
  const added = ui.doc.querySelector('li[data-pin="/overview"]');
  assert.equal(added.querySelector("a").className, "active");
  assert.equal(added.querySelector("a").hasAttribute("aria-current"), false);
  assert.equal(added.querySelector('[data-pin-op="remove"]').getAttribute("aria-label"), "Unpin Overview");
  assert.equal(ui.doc.querySelector('meta[name="lightwork-preference-revision"]').content, "rev-2");
  assert.deepEqual(ui.toasts, [["Pinned Overview to the sidebar.", false]]);
  assert.equal(ui.pins.isPinned(), true);
  ui.dom.window.close();
});

test("Edit reveals reorder and unpin buttons that keep focus on the moved page", async () => {
  const ui = sidebar({ record: false });
  const edit = ui.doc.getElementById("navpins-edit");
  edit.click();
  assert.equal(edit.getAttribute("aria-expanded"), "true");
  assert.equal(edit.textContent, "Done");
  assert.ok([...ui.doc.querySelectorAll(".navpins__tools")].every((tools) => !tools.hidden));
  ui.replies.push({ ok: true, json: { pins: [{ href: "/deliverables", label: "Results", icon: "check" },
    { href: "/goals", label: "Tasks", icon: "target" }], revision: "rev-2" } });
  const up = ui.doc.querySelector('li[data-pin="/deliverables"] [data-pin-op="up"]');
  up.click();
  await ui.flush(); await ui.flush();
  assert.deepEqual(ui.calls.map((call) => call.body.op + " " + call.body.href), ["up /deliverables"]);
  assert.deepEqual(ui.order(), ["/deliverables", "/goals"]);
  assert.equal(ui.doc.activeElement, ui.doc.querySelector('li[data-pin="/deliverables"] [data-pin-op="up"]'));
  assert.equal(ui.doc.getElementById("navpins-status").textContent, "Moved Results up.");
  edit.click();
  assert.ok([...ui.doc.querySelectorAll(".navpins__tools")].every((tools) => tools.hidden));
  ui.dom.window.close();
});

test("unpinning the last page shows the empty note and hides Edit", async () => {
  const ui = sidebar({ pinned: [["/goals", "Tasks"]], record: false });
  ui.doc.getElementById("navpins-edit").click();
  ui.replies.push({ ok: true, json: { pins: [], revision: "rev-2" } });
  ui.doc.querySelector('[data-pin-op="remove"]').click();
  await ui.flush(); await ui.flush();
  assert.deepEqual(ui.order(), []);
  assert.equal(ui.doc.getElementById("navpins-empty").hidden, false);
  assert.equal(ui.doc.getElementById("navpins-edit").hidden, true);
  assert.equal(ui.doc.activeElement.id, "navpins-empty");
  assert.equal(ui.doc.getElementById("navpins-status").textContent, "Unpinned Tasks.");
  ui.dom.window.close();
});

test("a refused change leaves the list as it was and says so", async () => {
  const ui = sidebar({ record: false });
  ui.replies.push({ ok: false, json: { detail: "Only pages you can open can be pinned." } });
  ui.doc.getElementById("page-pin-toggle").click();
  await ui.flush(); await ui.flush();
  assert.deepEqual(ui.order(), ["/goals", "/deliverables"]);
  assert.equal(ui.doc.getElementById("page-pin-toggle").getAttribute("aria-pressed"), "false");
  assert.equal(ui.toasts.length, 1);
  assert.equal(ui.toasts[0][1], true);
  ui.dom.window.close();
});

test("an openable page is remembered for Recent pages, once, and only when asked", async () => {
  const recorded = sidebar();
  assert.deepEqual(recorded.calls.map((call) => [call.method, call.url, call.body]),
    [["POST", "/api/v1/navigation/recent", { path: "/overview", context: "ctx-1" }]]);
  // The answer is read: in a browser an unread response never finishes, so
  // the page never settles and navigating away cancels the request.
  await recorded.flush(); await recorded.flush();
  assert.equal(recorded.calls[0].read, true);
  assert.equal(recorded.calls[0].keepalive, false);
  recorded.dom.window.close();
  const quiet = sidebar({ record: false });
  assert.deepEqual(quiet.calls, []);
  quiet.dom.window.close();
});

test("a pin blocked on the way says so as an error and leaves the button and list as they were", async () => {
  const page = sidebar({ record: false });
  page.window.fetch = () => Promise.reject(new TypeError("Failed to fetch"));
  const toggle = page.doc.getElementById("page-pin-toggle");
  toggle.click(); await page.flush(); await page.flush();
  assert.deepEqual(page.order(), ["/goals", "/deliverables"]);
  assert.equal(toggle.getAttribute("aria-pressed"), "false");
  assert.equal(toggle.disabled, false);
  assert.equal(page.toasts.length, 1);
  assert.equal(page.toasts[0][1], true, "shown as an error");
  assert.match(page.toasts[0][0], /pinned pages/i);
  assert.equal(page.doc.getElementById("navpins-status").textContent, page.toasts[0][0]);
  page.dom.window.close();
});
