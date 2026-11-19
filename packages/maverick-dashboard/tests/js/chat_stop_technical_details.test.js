// Run with: node --test packages/maverick-dashboard/tests/js/chat_stop_technical_details.test.js
// A stopped task shows administrators the run's exact stop text under
// "Technical details". Live updates carry only the plain stop (no technical
// text), and the page used to replace the exact text with the plain message.
"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const {JSDOM} = require("jsdom");

const page = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates/chat_goal.html"), "utf8");
const start = page.indexOf("      function renderStop(stop) {");
const end = page.indexOf("\n      }\n", start) + "\n      }\n".length;
const renderStop = page.slice(start, end);

const RAW = "Stopped: this goal hit your time limit (1 minute).\nYour recorded work and usage are kept.";
const SERVER_STOP = {kind: "time_limit", message: "This task reached its time limit of 1 minute. Its recorded work is kept.",
  action: "Start it again with a longer time limit.", link: null, link_label: null, technical: RAW};

function boot({showTechnical = true} = {}) {
  const dom = new JSDOM(`<div id="halt-card" data-stop-kind="time_limit"><div id="halt-title"></div><p id="halt-reason"></p>
    <span id="halt-action-text"></span><a id="halt-action-link"></a>
    <details id="halt-technical"><pre id="halt-technical-text">${RAW}</pre></details></div>`, {runScripts: "outside-only"});
  const w = dom.window;
  w.eval(`var haltCard = document.getElementById('halt-card'), haltReasonEl = document.getElementById('halt-reason');
    var specialistSetupKinds = new Set(), currentStatus = 'blocked', SHOW_TECHNICAL = ${showTechnical};
    var lastStop = ${JSON.stringify(showTechnical ? SERVER_STOP : {...SERVER_STOP, technical: undefined})};
    var renderedStop = lastStop;
    var lastResult = ${JSON.stringify(SERVER_STOP.message)};
    function cgCopy(node, text) { node.textContent = text; }
    function setStatus() {}
    ${renderStop}`);
  return w;
}
const live = {kind: SERVER_STOP.kind, message: SERVER_STOP.message, action: SERVER_STOP.action, link: null, link_label: null};

test("the snippet under test is the halt card renderer", () => {
  assert.ok(start > 0 && end > start);
  assert.match(renderStop, /halt-technical-text/);
});

test("a live update of the same stop keeps the exact technical details", () => {
  const w = boot();
  w.renderStop(live);
  assert.equal(w.document.getElementById("halt-technical-text").textContent, RAW);
  assert.equal(w.document.getElementById("halt-technical").hidden, false);
});

test("a different stop that arrives live hides details it cannot show, never the plain message", () => {
  const w = boot();
  w.renderStop({kind: "spending_limit", message: "This task reached its spending limit of $1.00."});
  const technical = w.document.getElementById("halt-technical");
  assert.equal(technical.hidden, true);
  assert.notEqual(w.document.getElementById("halt-technical-text").textContent, SERVER_STOP.message);
});

test("people without technical access still see no technical details", () => {
  const w = boot({showTechnical: false});
  w.renderStop(live);
  assert.equal(w.document.getElementById("halt-technical").hidden, true);
});
