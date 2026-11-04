// Run with: node --test packages/maverick-dashboard/tests/js/lightwork_ui_formats.test.js
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const static_ = (name) => fs.readFileSync(
  path.resolve(__dirname, "../../maverick_dashboard/static", name), "utf8");
const source = static_("lightwork-ui.js");
const i18nSource = static_("lightwork-i18n.js");
// 2026-10-04 13:01:12 UTC, read by a viewer in London (BST, UTC+1).
const NOW = Date.UTC(2026, 9, 4, 13, 1, 12);
process.env.TZ = "Europe/London";

// `browser` is the reader's regional setting (navigator.languages).
function load(body = "", { language = null, browser = "en-GB" } = {}) {
  const config = language
    ? `<script id="lightwork-i18n-data" type="application/json">${JSON.stringify(
      { language, locale: language === "fr" ? "fr-CA" : "en-US", catalog: {} })}</script>` : "";
  const dom = new JSDOM(`<!doctype html><html><head>${config}</head><body>` +
    `<div id="mv-toasts"></div><div id="mv-toasts-alert"></div>${body}</body></html>`,
    { url: "https://lightwork.test/", runScripts: "outside-only", beforeParse(window) {
      Object.defineProperty(window.navigator, "language", { value: browser, configurable: true });
      Object.defineProperty(window.navigator, "languages", { value: [browser], configurable: true });
    } });
  dom.window.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
  dom.window.Date.now = () => NOW;
  dom.window.eval(source);
  if (language) dom.window.eval(i18nSource);
  return dom.window;
}

test("relative times divide by the unit they name, before and after now", () => {
  const w = load();
  const at = (seconds) => (NOW + seconds * 1000) / 1000;
  const minute = 60, hour = 3600, day = 86400;
  const cases = [
    [30, "in a moment", "just now"],
    [50, "in 50 seconds", "50 seconds ago"],
    [90, "in 2 minutes", "2 minutes ago"],
    [209, "in 3 minutes", "3 minutes ago"],
    [59 * minute, "in 59 minutes", "59 minutes ago"],
    [59 * minute + 50, "in 1 hour", "1 hour ago"],
    [3 * hour, "in 3 hours", "3 hours ago"],
    [2 * day, "in 2 days", "2 days ago"],
    [10 * day, "next week", "last week"],
    [21 * day, "in 3 weeks", "3 weeks ago"],
    [61 * day, "in 2 months", "2 months ago"],
    [731 * day, "in 2 years", "2 years ago"],
  ];
  for (const [seconds, future, past] of cases) {
    assert.equal(w.mvTimeRelative(at(seconds)), future, `${seconds}s ahead`);
    assert.equal(w.mvTimeRelative(at(-seconds)), past, `${seconds}s ago`);
  }
  // Milliseconds and ISO strings name the same moment.
  assert.equal(w.mvTimeRelative(NOW + 209000), "in 3 minutes");
  assert.equal(w.mvTimeRelative(new Date(NOW - 3 * hour * 1000).toISOString()), "3 hours ago");
  for (const missing of [null, undefined, "", "not a time", 0]) assert.equal(w.mvTimeRelative(missing), "");
  w.close();
});

test("absolute times read in the viewer's zone and their browser's regional style", () => {
  const w = load();
  const seconds = NOW / 1000;
  assert.equal(w.mvTimeAbsolute(seconds), "4 Oct 2026, 14:01 BST");
  assert.equal(w.mvTimeAbsolute(NOW), "4 Oct 2026, 14:01 BST");
  assert.equal(w.mvTimeAbsolute(String(seconds)), "4 Oct 2026, 14:01 BST");
  assert.equal(w.mvTimeAbsolute("2026-10-04T13:01:12Z"), "4 Oct 2026, 14:01 BST");
  assert.equal(w.mvWhen(seconds), "4 Oct 2026, 14:01 BST");
  // A schedule's own zone, named in the text; an unknown zone falls back to the viewer's.
  assert.equal(w.mvTimeAbsolute(seconds, "America/New_York"), "4 Oct 2026, 09:01 GMT-4");
  assert.equal(w.mvTimeAbsolute(seconds, "Not/AZone"), "4 Oct 2026, 14:01 BST");
  // A US reader gets month-first dates, a 12-hour clock and US zone names.
  const us = load("", { browser: "en-US" });
  assert.equal(us.mvTimeAbsolute(seconds), "Oct 4, 2026, 2:01 PM GMT+1");
  assert.equal(us.mvTimeAbsolute(seconds, "America/New_York"), "Oct 4, 2026, 9:01 AM EDT");
  assert.equal(us.mvDateAbsolute("2026-10-04"), "Oct 4, 2026");
  us.close();
  // A German browser reads its own style; relative phrases stay in the
  // interface language (English here) so a sentence never mixes languages.
  const de = load("", { browser: "de-DE" });
  assert.equal(de.mvTimeAbsolute(seconds), "4. Okt. 2026, 14:01 GMT+1");
  assert.equal(de.mvDateAbsolute("2026-10-04"), "4. Okt. 2026");
  assert.equal(de.mvTimeRelative(seconds - 180), "3 minutes ago");
  de.close();
  for (const missing of [null, undefined, "", "soon", 0, NaN]) {
    assert.equal(w.mvTimeAbsolute(missing), "", String(missing));
    assert.equal(w.mvWhen(missing), "", String(missing));
  }
  // A calendar date stays that day in every zone; a moment uses the viewer's day.
  assert.equal(w.mvDateAbsolute("2026-10-04"), "4 Oct 2026");
  assert.equal(w.mvDateAbsolute(Date.UTC(2026, 9, 4, 23, 30) / 1000), "5 Oct 2026");
  assert.equal(w.mvDateAbsolute("2026-13-45x"), "");
  assert.equal(w.mvDateAbsolute("2026-09"), "September 2026"); // an accounting month
  w.close();
});

test("server-rendered times become relative, absolute or calendar text", (t) => {
  const seconds = NOW / 1000;
  const w = load(
    `<time id="rel" data-mv-time="${seconds - 180}">x</time>` +
    `<time id="abs" data-mv-time="${seconds}" data-mv-time-mode="absolute">x</time>` +
    `<time id="day" datetime="2026-10-04" data-mv-time="2026-10-04" data-mv-time-mode="date">x</time>` +
    `<span id="both" data-mv-time="${seconds + 7200}" data-mv-time-mode="both">x</span>`);
  t.after(() => w.close()); // stops the once-a-minute relative refresh
  const doc = w.document;
  assert.equal(doc.getElementById("rel").textContent, "3 minutes ago");
  assert.equal(doc.getElementById("rel").title, "4 Oct 2026, 13:58 BST");
  assert.equal(doc.getElementById("abs").textContent, "4 Oct 2026, 14:01 BST");
  assert.equal(doc.getElementById("abs").title, "just now");
  assert.equal(doc.getElementById("day").textContent, "4 Oct 2026");
  assert.equal(doc.getElementById("both").textContent, "4 Oct 2026, 16:01 BST (in 2 hours)");
});

test("server-rendered times follow the reader's browser locale too", (t) => {
  const seconds = NOW / 1000;
  const w = load(
    `<time id="abs" data-mv-time="${seconds}" data-mv-time-mode="absolute">4 Oct 2026, 13:01 UTC</time>` +
    `<time id="day" datetime="2026-10-04" data-mv-time="2026-10-04" data-mv-time-mode="date">4 Oct 2026</time>`,
    { browser: "en-US" });
  t.after(() => w.close());
  assert.equal(w.document.getElementById("abs").textContent, "Oct 4, 2026, 2:01 PM GMT+1");
  assert.equal(w.document.getElementById("day").textContent, "Oct 4, 2026");
});

test("a translated interface uses its own locale, and both shared formatters agree", () => {
  const seconds = NOW / 1000;
  const fr = load("", { language: "fr" });
  const expected = new Intl.DateTimeFormat("fr-CA", { day: "numeric", month: "short", year: "numeric",
    hour: "numeric", minute: "2-digit", timeZoneName: "short" }).format(new Date(NOW));
  assert.equal(fr.mvTimeAbsolute(seconds), expected);
  assert.equal(fr.LightworkI18n.formatDate(seconds), expected);
  assert.equal(fr.mvTimeRelative(seconds - 180), "il y a 3 minutes");
  fr.close();
  // An English interface follows each reader's browser, with one format per
  // reader: both shared formatters give the same text.
  for (const [browser, moment, day] of [
    ["en-GB", "4 Oct 2026, 14:01 BST", "4 Oct 2026"],
    ["en-US", "Oct 4, 2026, 2:01 PM GMT+1", "Oct 4, 2026"],
    ["de-DE", "4. Okt. 2026, 14:01 GMT+1", "4. Okt. 2026"],
  ]) {
    const en = load("", { language: "en", browser });
    assert.equal(en.LightworkI18n.formatDate(seconds), moment, browser);
    assert.equal(en.LightworkI18n.formatDate("2026-10-04"), day, browser);
    assert.equal(en.LightworkI18n.formatDate(seconds), en.mvTimeAbsolute(seconds), browser);
    en.close();
  }
});

test("money reads one way: dollars and cents, separators, never a run of decimals", () => {
  const w = load();
  assert.equal(w.mvMoney(1234.5), "$1,234.50");
  assert.equal(w.mvMoney("0"), "$0.00");
  assert.equal(w.mvMoney(-5), "-$5.00");
  assert.equal(w.mvMoney(0.0004), "under $0.01");
  assert.equal(w.mvMoney(0.003, { decimals: 4 }), "$0.0030");
  assert.equal(w.mvMoney(75, { currency: "eur" }), "EUR 75.00");
  for (const missing of [null, undefined, "", "n/a", NaN, Infinity, true]) assert.equal(w.mvMoney(missing), "", String(missing));
  w.close();
  const fr = load("", { language: "fr" });
  assert.equal(fr.mvMoney(1234.5), new Intl.NumberFormat("fr-CA", { style: "currency", currency: "USD",
    minimumFractionDigits: 2, maximumFractionDigits: 2 }).format(1234.5));
  fr.close();
  // English pages keep "$" even when the browser prefers another English region.
  const en = load("", { language: "en" });
  assert.equal(en.mvMoney(1234.5), "$1,234.50");
  en.close();
});

test("server-rendered times follow the interface locale once it is known", async (t) => {
  const seconds = NOW / 1000;
  const page = load(`<time id="t" data-mv-time="${seconds}" data-mv-time-mode="absolute">x</time>`, { language: "fr" });
  t.after(() => page.close());
  await new Promise((done) => setImmediate(done)); // the runtime translates once the document has loaded
  const expected = new Intl.DateTimeFormat("fr-CA", { day: "numeric", month: "short", year: "numeric",
    hour: "numeric", minute: "2-digit", timeZoneName: "short" }).format(new Date(NOW));
  assert.equal(page.document.getElementById("t").textContent, expected);
});
