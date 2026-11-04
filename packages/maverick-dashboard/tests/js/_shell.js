"use strict";
// The shell's shared helpers (lightwork-ui.js: mvFetchJSON, mvStatus,
// mvErrorText …) load before every page script, as in base.html. Page tests
// call shell(window) before evaluating the page script; stand-ins a test has
// already put on the window for the other helpers (window.mv…) are kept.
const fs = require("node:fs");
const path = require("node:path");
const ui = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-ui.js"), "utf8");
function shell(w) {
  const kept = Object.fromEntries(Object.keys(w).filter((key) => key.startsWith("mv")).map((key) => [key, w[key]]));
  if (typeof w.matchMedia !== "function") w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} });
  w.eval(ui);
  Object.assign(w, kept);
  return w;
}
module.exports = { shell, ui };
// For tests that run a page script in a bare vm context (no DOM): the shared
// fetch helpers, sending through whatever fetch the context holds at call
// time. Use as context.window.mvFetchJSON = fetchHelpers(() => context.fetch).mvFetchJSON.
function fetchHelpers(getFetch) {
  const { JSDOM } = require("jsdom");
  const w = shell(new JSDOM("", { url: "https://lightwork.test/", runScripts: "outside-only" }).window);
  w.fetch = (...args) => getFetch()(...args);
  return { mvFetchJSON: w.mvFetchJSON, mvErrorText: w.mvErrorText, mvPlainDetail: w.mvPlainDetail, mvStatus: w.mvStatus };
}
module.exports.fetchHelpers = fetchHelpers;
