// Run with: node --test packages/maverick-dashboard/tests/js/sidebar_approvals_badge.test.js
"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const {JSDOM} = require("jsdom");

const source = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-ui.js"), "utf8");
const start = source.indexOf("    // Approvals badge:");
const end = source.indexOf("    // Feature-gated workbenches", start);
const snippet = source.slice(start, end);
const tick = () => new Promise(resolve => setImmediate(resolve));
const LINK = '<a href="/approvals" data-approvals-badge><span class="nav-label">Approvals</span><span class="nav-count" hidden></span></a>';

async function render(reply, {links = 2, i18n = null} = {}) {
  const dom = new JSDOM(`<nav>${LINK.repeat(links)}<a href="/goals"><span class="nav-label">Tasks</span></a></nav>`,
    {url: "https://lightwork.test/goals", runScripts: "outside-only"});
  const w = dom.window, calls = [];
  w.fetch = async (url, options) => {
    calls.push({url, options});
    if (reply instanceof Error) throw reply;
    return reply;
  };
  if (i18n) w.LightworkI18n = i18n;
  w.eval(snippet);
  await tick(); await tick(); await tick();
  return {document: w.document, calls};
}

const ok = waiting => ({ok: true, status: 200, json: async () => ({waiting})});

test("the snippet under test is the sidebar badge controller", () => {
  assert.ok(start > -1 && end > start);
  assert.match(snippet, /\/api\/v1\/approvals\/waiting-count/);
});

test("waiting decisions show a count and an accessible name on every Approvals link", async () => {
  const {document, calls} = await render(ok(3));
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "/api/v1/approvals/waiting-count");
  assert.equal(calls[0].options.cache, "no-store");
  const links = [...document.querySelectorAll("a[data-approvals-badge]")];
  assert.equal(links.length, 2);
  for (const link of links) {
    const badge = link.querySelector(".nav-count");
    assert.equal(badge.hidden, false);
    assert.equal(badge.textContent, "3");
    assert.equal(badge.getAttribute("aria-hidden"), "true");
    assert.equal(link.getAttribute("aria-label"), "Approvals, 3 waiting");
  }
  assert.equal(document.querySelector('a[href="/goals"]').hasAttribute("aria-label"), false);
});

test("nothing waiting, an error or an unreadable reply keeps the badge hidden", async () => {
  for (const reply of [ok(0), {ok: false, status: 403, json: async () => ({})}, new Error("offline"),
    ok(-1), ok("3"), {ok: true, status: 200, json: async () => { throw new Error("bad json"); }}]) {
    const {document} = await render(reply);
    for (const link of document.querySelectorAll("a[data-approvals-badge]")) {
      assert.equal(link.querySelector(".nav-count").hidden, true);
      assert.equal(link.hasAttribute("aria-label"), false);
    }
  }
});

test("large counts stay short and the label follows the interface language", async () => {
  const i18n = {text: (source, values) => source === "{page}, {count} waiting"
    ? `${values.page} : ${values.count} en attente` : source};
  const {document} = await render(ok(250), {links: 1, i18n});
  const link = document.querySelector("a[data-approvals-badge]");
  assert.equal(link.querySelector(".nav-count").textContent, "99+");
  assert.equal(link.getAttribute("aria-label"), "Approvals : 250 en attente");
});

test("a page without an Approvals link asks for nothing", async () => {
  const {calls} = await render(ok(5), {links: 0});
  assert.deepEqual(calls, []);
});
