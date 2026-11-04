// Run with: node --test packages/maverick-dashboard/tests/js/tab_bars_pages.test.js
"use strict";
// Per-page keys for the pages whose tab bars moved onto the shared panel tab
// bar (_tabs.html panel_tabs + lightwork-tabs.js): Learning sections, the
// privacy record and estate tabs, the task filter and the workspace worklist
// filter. Each runs the page's own script (where it still has one) with the
// shared script, on the markup panel_tabs renders (tests/test_tab_bars.py
// checks the rendered pages have that structure). Security, Settings and the
// board time range have their own files.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const { panelTabs, tabPanel, press } = require("./_tab_markup");

const root = path.resolve(__dirname, "../../maverick_dashboard");
const read = (name) => fs.readFileSync(path.join(root, name), "utf8").replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
const tabsScript = read("static/lightwork-tabs.js");

function dom(html, url) {
  const d = new JSDOM(`<!doctype html><body><main>${html}</main></body>`, { url, runScripts: "outside-only", pretendToBeVisual: true });
  return d.window;
}
function shared(w) { w.eval(tabsScript); w.mvTabs.init(); }
const shown = (w) => [...w.document.querySelectorAll('[role="tabpanel"]')].filter((p) => !p.hidden).map((p) => p.id);
const chosen = (w) => [...w.document.querySelectorAll('[role="tab"][aria-selected="true"]')].map((t) => t.dataset.mvTab);
const roving = (w) => [...w.document.querySelectorAll('[role="tab"]')].filter((t) => t.tabIndex === 0).map((t) => t.dataset.mvTab);

// ---- Learning: three sections, each a Back step ---------------------------
const learning = read("templates/learning.html");
const learningScript = (() => {
  const at = learning.indexOf("var tabs = Array.from(document.querySelectorAll('[data-learning-tab]'));");
  const start = learning.lastIndexOf("<script>", at) + "<script>".length;
  return learning.slice(start, learning.indexOf("</script>", at));
})();
const LEARN = { data: "learning-tab", tabPrefix: "learning-tab-", panelPrefix: "learning-" };
function learningPage(url) {
  const keys = [["overview", "Overview"], ["controls", "Learning controls"], ["review", "Review &amp; restore"]];
  const panels = keys.map(([key]) => `<section class="lrn__pane" ${tabPanel(key, "overview", LEARN)} tabindex="0"><h2 id="h-${key}">${key}</h2></section>`).join("");
  const w = dom(panelTabs("Learning sections", keys, "overview", LEARN) + panels, url);
  w.Element.prototype.scrollIntoView = function () {};  // jsdom has no layout
  w.eval(learningScript);
  shared(w);
  return w;
}

test("Learning: the template uses the shared bar and its script no longer handles keys", () => {
  assert.match(learning, /panel_tabs\('Learning sections', \[\('overview', 'Overview'\), \('controls', 'Learning controls'\), \('review', 'Review & restore'\)\], 'overview',\s+data='learning-tab', tab_prefix='learning-tab-', panel_prefix='learning-'\)/);
  assert.doesNotMatch(learningScript, /keydown|ArrowRight/);
});

test("Learning: arrow, Home and End keys open a section and add a Back step for it", () => {
  const w = learningPage("https://lightwork.test/learning");
  const d = w.document, before = w.history.length;
  assert.deepEqual(shown(w), ["learning-overview"]);
  d.getElementById("learning-tab-overview").focus();
  press(w, d.getElementById("learning-tab-overview"), "ArrowRight");
  assert.equal(d.activeElement, d.getElementById("learning-tab-controls"));
  assert.deepEqual(shown(w), ["learning-controls"]);
  assert.equal(w.location.hash, "#learning-controls");
  press(w, d.getElementById("learning-tab-controls"), "End");
  assert.deepEqual(chosen(w), ["review"]);
  press(w, d.getElementById("learning-tab-review"), "ArrowRight");
  assert.deepEqual(shown(w), ["learning-overview"], "Right on the last section wraps to the first");
  press(w, d.getElementById("learning-tab-overview"), "ArrowLeft");
  assert.deepEqual(shown(w), ["learning-review"]);
  press(w, d.getElementById("learning-tab-review"), "Home");
  assert.deepEqual(roving(w), ["overview"]);
  assert.equal(w.history.length, before + 5, "each section is a Back step, as before");
  w.close();
});

test("Learning: an address naming a section, or anything inside one, opens it", () => {
  const w = learningPage("https://lightwork.test/learning#h-review");
  assert.deepEqual(shown(w), ["learning-review"]);
  assert.deepEqual(chosen(w), ["review"]);
  w.close();
});

// ---- Privacy: record types and estate registers ---------------------------
const privacy = read("templates/privacy.html");
test("Privacy: both bars are the shared bar, with the page's ids kept and no tab script of its own", () => {
  assert.match(privacy, /panel_tabs\('Record types',[\s\S]*?'dpa', tab_prefix='pw-tabbtn-', panel_prefix='pw-tab-'\)/);
  assert.match(privacy, /panel_tabs\('Estate registers',[\s\S]*?'vendors', tab_prefix='pe-tabbtn-', panel_prefix='pe-tab-'\)/);
  assert.doesNotMatch(privacy, /showTab|showPane|button\[data-pane\]|\[role="tablist"\] button\[data-tab\]/);
});

test("Privacy: the record tabs and the estate tabs each switch only their own panels", () => {
  const RECORDS = { tabPrefix: "pw-tabbtn-", panelPrefix: "pw-tab-" }, ESTATE = { tabPrefix: "pe-tabbtn-", panelPrefix: "pe-tab-" };
  const records = ["dpa", "ai", "ropa", "dsar", "paper", "lineage", "incidents"], estate = ["vendors", "consent", "datamap"];
  const html = panelTabs("Record types", records.map((k) => [k, k]), "dpa", RECORDS) +
    records.map((k) => `<div ${tabPanel(k, "dpa", RECORDS)}></div>`).join("") +
    panelTabs("Estate registers", estate.map((k) => [k, k]), "vendors", ESTATE) +
    estate.map((k) => `<div ${tabPanel(k, "vendors", ESTATE)}></div>`).join("");
  const w = dom(html, "https://lightwork.test/privacy"), d = w.document;
  shared(w);
  assert.deepEqual(shown(w), ["pw-tab-dpa", "pe-tab-vendors"]);
  d.getElementById("pw-tabbtn-dpa").focus();
  press(w, d.getElementById("pw-tabbtn-dpa"), "End");
  assert.deepEqual(shown(w), ["pw-tab-incidents", "pe-tab-vendors"]);
  press(w, d.getElementById("pw-tabbtn-incidents"), "ArrowLeft");
  assert.deepEqual(shown(w), ["pw-tab-lineage", "pe-tab-vendors"]);
  press(w, d.getElementById("pe-tabbtn-vendors"), "ArrowRight");
  assert.deepEqual(shown(w), ["pw-tab-lineage", "pe-tab-consent"]);
  d.getElementById("pe-tabbtn-datamap").click();
  assert.deepEqual(shown(w), ["pw-tab-lineage", "pe-tab-datamap"]);
  assert.deepEqual(roving(w), ["lineage", "datamap"]);
  assert.equal(w.location.hash, "", "these tabs keep no address, as before");
  w.close();
});

// ---- Tasks: the status filter over the task list --------------------------
const goals = read("templates/goals.html");
const goalsScript = goals.slice(goals.indexOf("<script>") + 8, goals.indexOf("</script>"));
test("Tasks: arrow keys choose a filter, show only its rows and keep it in the address", () => {
  const items = [["all", "All", ""], ["running", "Running", "running active pending"], ["waiting", "Waiting for you", "blocked awaiting_approval"],
    ["failed", "Failed", "failed"], ["done", "Done", "done"]];
  const html = '<input id="run-search-q">' + panelTabs("Show tasks", items, "all", { id: "g-filter", data: "g-filter", controls: "run-list" }) +
    '<div class="g-list" id="run-list" role="tabpanel" aria-labelledby="g-filter-tab-all"><div class="g-row" data-status="done"></div><div class="g-row" data-status="failed"></div><div class="g-row" data-status="blocked"></div></div>' +
    '<p id="run-search-status"></p><button id="run-search-retry"></button>' +
    // As goals.html renders them: older-work search and Show more tasks.
    '<button id="run-search-older" hidden></button><button id="run-more" data-next-offset="" hidden></button>';
  const w = dom(html, "https://lightwork.test/goals"), d = w.document;
  w.fetch = async () => ({ ok: true, status: 200, json: async () => [] });
  w.eval(goalsScript);
  shared(w);
  const visible = () => [...d.querySelectorAll(".g-row")].filter((r) => !r.hidden).map((r) => r.dataset.status);
  d.getElementById("g-filter-tab-all").focus();
  press(w, d.getElementById("g-filter-tab-all"), "End");
  assert.deepEqual(chosen(w), ["done"]);
  assert.deepEqual(visible(), ["done"]);
  assert.equal(w.location.search, "?status=done");
  press(w, d.getElementById("g-filter-tab-done"), "ArrowLeft");
  assert.deepEqual(visible(), ["failed"]);
  press(w, d.getElementById("g-filter-tab-failed"), "ArrowLeft");
  assert.deepEqual(visible(), ["blocked"]);
  assert.deepEqual(shown(w), ["run-list"], "the list stays shown");
  assert.equal(d.getElementById("run-list").getAttribute("aria-labelledby"), "g-filter-tab-waiting");
  press(w, d.getElementById("g-filter-tab-waiting"), "Home");
  assert.deepEqual(visible(), ["done", "failed", "blocked"]);
  assert.equal(w.location.search, "");
  assert.doesNotMatch(goalsScript, /aria-pressed/);
  w.close();
});

// ---- Workspace worklist filter (privacy, security, finance) ---------------
const catalog = read("templates/_workspace_memory_catalog.html");
const worklistScript = catalog.slice(catalog.indexOf("  // Client-side worklist filters"), catalog.indexOf("  // Assign an assessment"));
test("Worklist: the filter is the shared bar and its keys filter the rows", () => {
  const items = [["all", "All (3)"], ["pending_review", "Needs review (1)"], ["high", "High risk (1)"], ["mine", "Mine (1)"]];
  const html = panelTabs("Filter worklist", items, "all", { id: "pw-filter", data: "filter", controls: "pw-worklist", cls: "pw-filters" }) +
    '<div id="pw-worklist" role="tabpanel" aria-labelledby="pw-filter-tab-all"><table id="pw-table"><tbody>' +
    '<tr data-status="pending_review" data-residual="low"></tr><tr data-status="approved" data-residual="high"></tr><tr data-status="approved" data-residual="low" data-mine="1"></tr>' +
    "</tbody></table></div>";
  const w = dom(html, "https://lightwork.test/privacy"), d = w.document;
  w.eval("(function () {\n" + worklistScript + "\n})();");
  shared(w);
  const rows = () => [...d.querySelectorAll("#pw-table tbody tr")].map((tr) => tr.style.display !== "none");
  d.getElementById("pw-filter-tab-all").focus();
  press(w, d.getElementById("pw-filter-tab-all"), "ArrowRight");
  assert.deepEqual(chosen(w), ["pending_review"]);
  assert.deepEqual(rows(), [true, false, false]);
  press(w, d.getElementById("pw-filter-tab-pending_review"), "ArrowRight");
  assert.deepEqual(rows(), [false, true, false]);
  press(w, d.getElementById("pw-filter-tab-high"), "End");
  assert.deepEqual(rows(), [false, false, true]);
  press(w, d.getElementById("pw-filter-tab-mine"), "Home");
  assert.deepEqual(rows(), [true, true, true]);
  assert.deepEqual(roving(w), ["all"]);
  assert.doesNotMatch(worklistScript, /aria-pressed/);
  w.close();
});
