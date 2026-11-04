"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { JSDOM } = require("jsdom");
const canvas = require("../../maverick_dashboard/templates/flow_designer_canvas.js");
const core = require("../../maverick_dashboard/templates/flow_designer_core.js");
const presentation = require("../../maverick_dashboard/templates/flow_designer_presentation.js");

test("canvas renders accessible nodes, edge hit targets and restores keyboard focus", () => {
  const dom = new JSDOM('<svg xmlns="http://www.w3.org/2000/svg"><g id="viewport"><g id="edges"></g><g id="nodes"></g></g></svg>');
  const document = dom.window.document, viewport = document.getElementById("viewport");
  const edges = document.getElementById("edges"), nodes = document.getElementById("nodes");
  const flow = {start: "a", nodes: [
    {id: "a", kind: "action", label: "Look up", x: 0, y: 0, next: "b"},
    {id: "b", kind: "approval", label: "Review", x: 0, y: 150, next: null},
    {id: "c", kind: "action", label: "Unused", x: 220, y: 0, next: null},
  ]};
  function el(tag, attrs, text) {
    const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
    if (text) node.textContent = text;
    return node;
  }
  const state = {flow, view: {x: 40, y: 20, k: 1}, selected: "b", multiSel: {}, selectedEdge: {from: "a", port: "next"},
    proposals: {}, width: 176, height: 64, icons: {}};
  const helpers = {core, el, nodeById: id => flow.nodes.find(node => node.id === id),
    ports: node => presentation.ports(node, 176), runClass: () => "", runBadge: () => "",
    summary: node => node.label, kindLabel: kind => kind, truncate: value => value};
  const targets = {document, viewport, edges, nodes};
  canvas.render(state, targets, helpers);
  assert.equal(edges.querySelector(".fd-edge-hit").getAttribute("data-edge-from"), "a");
  assert.ok(edges.querySelector(".fd-edge.selected"));
  const selected = nodes.querySelector('g[data-node="b"]');
  assert.equal(selected.getAttribute("aria-pressed"), "true");
  assert.match(selected.getAttribute("aria-label"), /Press Enter to edit; use arrow keys to move/);
  assert.match(nodes.querySelector('g[data-node="c"]').getAttribute("aria-label"), /not connected and will never run/);
  selected.focus();
  assert.equal(document.activeElement, selected);
  canvas.render(state, targets, helpers);
  assert.equal(document.activeElement.getAttribute("data-node"), "b");
  dom.window.close();
});

test("minimap contains the visible viewport and handles an empty graph", () => {
  const dom = new JSDOM('<svg xmlns="http://www.w3.org/2000/svg"><g id="fd-minimap"></g></svg>');
  const document = dom.window.document, bounds = {getBoundingClientRect: () => ({width: 800, height: 400})};
  const view = {x: 40, y: 20, k: 1};
  function el(tag, attrs) {
    const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
    return node;
  }
  canvas.renderMinimap({nodes: []}, view, bounds, 176, 64, 160, 110, 8, document, el);
  const viewport = document.querySelector(".mini-view");
  assert.ok(viewport); assert.ok(Number(viewport.getAttribute("width")) > 0);
  assert.ok(Number(viewport.getAttribute("height")) > 0);
  assert.ok(Number(viewport.getAttribute("x")) >= 8);
  assert.ok(Number(viewport.getAttribute("y")) >= 8);
  dom.window.close();
});
