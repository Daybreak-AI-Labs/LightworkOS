"use strict";
// Pages keep a check on document and a clear of private content on window. A
// Copilot selection change reaches document only, so it never wipes them; a
// change of the account, role, suites or permitted actions (the server's
// context digest) bubbles, so window listeners clear too.
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const {JSDOM} = require("jsdom");

const source = fs.readFileSync(path.resolve(__dirname,
  "../../maverick_dashboard/static/lightwork-product-operations.js"), "utf8");

test("a Copilot selection change does not reach window listeners", () => {
  const dom = new JSDOM('<aside id="mv-copilot" hidden><section id="mv-product-operations">' +
    '<p id="mv-product-operation-status"></p><div id="mv-product-operation-buttons"></div>' +
    '<div id="mv-product-operation-form"></div></section></aside>', {url: "http://testserver/settings/all"});
  const w = dom.window, heard = {document: 0, window: 0};
  vm.runInNewContext(source, {window: w, document: w.document, CustomEvent: w.CustomEvent, URL: w.URL,
    URLSearchParams, AbortController, setTimeout, clearTimeout, fetch: async () => { throw Error("no network"); }});
  w.document.addEventListener("lightwork:copilot-context-changed", () => { heard.document += 1; });
  w.addEventListener("lightwork:copilot-context-changed", () => { heard.window += 1; });
  w.document.dispatchEvent(new w.CustomEvent("lightwork:copilot-selection", {detail: {selection: {kind: "setting"}}}));
  assert.deepEqual(heard, {document: 1, window: 0});
  dom.window.close();
});


test("a change of the server's context reaches window listeners too", async () => {
  const dom = new JSDOM('<aside id="mv-copilot"><section id="mv-product-operations">' +
    '<p id="mv-product-operation-status"></p><div id="mv-product-operation-buttons"></div>' +
    '<div id="mv-product-operation-form"></div></section></aside>', {url: "http://testserver/flows/designer/owned"});
  const w = dom.window, heard = {document: 0, window: 0};
  let digest = "a".repeat(64);
  const fetch = async () => ({ok: true, json: async () => ({schema: 1, selection: {kind: "flow", id: "owned"},
    context: digest, checked_at: 1, operations: []})});
  vm.runInNewContext(source, {window: w, document: w.document, CustomEvent: w.CustomEvent, URL: w.URL,
    URLSearchParams, AbortController, setTimeout, clearTimeout, fetch});
  w.document.addEventListener("lightwork:copilot-context-changed", () => { heard.document += 1; });
  w.addEventListener("lightwork:copilot-context-changed", () => { heard.window += 1; });
  const turn = () => new Promise(resolve => setImmediate(resolve));
  w.LightworkProductOperations.open(); await turn(); await turn();
  assert.deepEqual(heard, {document: 0, window: 0});
  digest = "b".repeat(64);   // the person's role changed
  w.LightworkProductOperations.open(); await turn(); await turn();
  assert.deepEqual(heard, {document: 1, window: 1});
  dom.window.close();
});


async function catalogChange(before, after) {
  const dom = new JSDOM('<aside id="mv-copilot"><section id="mv-product-operations">' +
    '<p id="mv-product-operation-status"></p><div id="mv-product-operation-buttons"></div>' +
    '<div id="mv-product-operation-form"></div></section></aside>', {url: "http://testserver/flows/designer/owned"});
  const w = dom.window, heard = {document: 0, window: 0};
  let current = before;
  const fetch = async () => ({ok: true, json: async () => ({schema: 1, selection: {kind: "flow", id: "owned"},
    checked_at: 1, operations: [], ...current})});
  vm.runInNewContext(source, {window: w, document: w.document, CustomEvent: w.CustomEvent, URL: w.URL,
    URLSearchParams, AbortController, setTimeout, clearTimeout, fetch});
  w.document.addEventListener("lightwork:copilot-context-changed", () => { heard.document += 1; });
  w.addEventListener("lightwork:copilot-context-changed", () => { heard.window += 1; });
  const turn = () => new Promise(resolve => setImmediate(resolve));
  w.LightworkProductOperations.open(); await turn(); await turn();
  current = after;
  w.LightworkProductOperations.open(); await turn(); await turn();
  dom.window.close();
  return heard;
}

test("turning a Copilot action family on or off reaches document listeners only", async () => {
  // The context digest covers the permitted actions; the access digest does
  // not. Pages that drop private drafts on window keep them.
  const heard = await catalogChange({context: "a".repeat(64), access: "x".repeat(64)},
                                    {context: "b".repeat(64), access: "x".repeat(64)});
  assert.deepEqual(heard, {document: 1, window: 0});
});

test("an account or access change reaches window listeners too", async () => {
  const heard = await catalogChange({context: "a".repeat(64), access: "x".repeat(64)},
                                    {context: "b".repeat(64), access: "y".repeat(64)});
  assert.deepEqual(heard, {document: 1, window: 1});
});


test("choosing another agent in the limits form loads that agent's own limits", async () => {
  // The other fields hold one agent's current limits, so the form cannot be
  // reviewed for another agent until that agent's limits are loaded.
  const dom = new JSDOM('<aside id="mv-copilot"><section id="mv-product-operations">' +
    '<p id="mv-product-operation-status"></p><div id="mv-product-operation-buttons"></div>' +
    '<div id="mv-product-operation-form"></div></section></aside>', {url: "http://testserver/trust"});
  const w = dom.window, catalogs = [];
  const agents = {"first-agent": 100, "second-agent": 1};
  const fetch = async (url, options) => {
    const body = JSON.parse(options.body);
    assert.ok(url.endsWith("/catalog"), "the form must not be reviewed before the agent's limits load");
    catalogs.push(body.selection);
    const chosen = body.selection.agent in agents ? body.selection.agent : "first-agent";
    return {ok: true, json: async () => ({schema: 1, selection: body.selection, context: "c".repeat(64),
      checked_at: 1, operations: [{id: "trust.agents.edit", label: "Change an outside agent's limits",
        available: true, revision: chosen, source: "Current outside agents", summary: "Limits",
        confirmation_required: true, fields: [
          {name: "agent", label: "Agent", kind: "select", value: chosen,
           choices: Object.keys(agents).map(value => ({value, label: value}))},
          {name: "max_dollars", label: "Spending limit", kind: "number", value: agents[chosen]}]}]})};
  };
  vm.runInNewContext(source, {window: w, document: w.document, CustomEvent: w.CustomEvent, URL: w.URL,
    URLSearchParams, AbortController, setTimeout, clearTimeout, fetch});
  const turn = () => new Promise(resolve => setImmediate(resolve));
  w.LightworkProductOperations.open(); await turn(); await turn();
  w.document.querySelector("#mv-product-operation-buttons button").click(); await turn(); await turn();
  const form = () => w.document.querySelector("#mv-product-operation-form form");
  assert.equal(form().elements.namedItem("max_dollars").value, "100");
  const choice = form().elements.namedItem("agent");
  choice.options[1].selected = true; choice.dispatchEvent(new w.Event("change"));
  const buttons = Array.from(form().querySelectorAll("button"));
  const load = buttons.find(button => button.textContent === "Load selected agent’s current limits");
  assert.ok(load && !load.hidden);
  assert.equal(buttons.find(button => button.type === "submit").disabled, true);
  load.click(); await turn(); await turn(); await turn();
  assert.deepEqual(catalogs.at(-1), {agent: "second-agent"});
  assert.equal(form().elements.namedItem("max_dollars").value, "1");
  assert.equal(form().elements.namedItem("agent").selectedOptions[0].textContent, "second-agent");
  dom.window.close();
});
