"use strict";
// With no workspace selected the Activity log's protection panel said
// "This was changed since you opened it. Refresh the page", and refreshing never
// helped. The panel now says what is missing and links to the workspace picker.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function auditScript() {
  const template = fs.readFileSync(
    path.resolve(__dirname, "../../maverick_dashboard/templates/audit.html"), "utf8");
  const script = [...template.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)]
    .map(match => match[1]).find(source => source.includes("loadCustody"));
  assert.ok(script, "audit.html must contain its client script");
  return script;
}

function element() {
  return {
    children: [], attributes: {}, disabled: false, hidden: false, _text: "",
    get textContent() { return this._text; },
    set textContent(value) { this._text = String(value); this.children = []; },
    appendChild(child) { this.children.push(child); return child; },
    addEventListener() {}, setAttribute(name, value) { this.attributes[name] = value; },
  };
}

async function loadPanel(statusResponse, { search = "" } = {}) {
  const ids = ["aud-action-result", "audit-custody-refresh", "audit-custody-status",
    "audit-custody-enabled", "audit-custody-checkpoint", "audit-custody-worm", "audit-custody-siem"];
  const nodes = Object.fromEntries(ids.map(id => [id, element()]));
  for (const id of ids.slice(3)) nodes[id]._text = "stale";
  nodes["aud-format"] = { options: [] };
  const json = (value, status = 200) => ({
    ok: status < 400, status, json: async () => value,
  });
  const context = {
    document: {
      getElementById: id => nodes[id] || null,
      createElement: () => element(),
      querySelectorAll: () => [],
      // The page starts once the shell's helpers have loaded.
      addEventListener: (type, listener) => { if (type === "DOMContentLoaded") listener(); },
    },
    window: {
      location: { pathname: "/audit", search, origin: "https://lightwork.example" },
      // The shared helpers' contracts, reduced: generic 409 text; a server
      // sentence is shown only when it is plain (no "tenant" jargon).
      mvErrorText: (failure, action) => failure.status === 409
        ? `Could not ${action}. This was changed since you opened it. Refresh the page and try again.`
        : `Could not ${action}. Something went wrong.`,
      mvPlainDetail: detail => /^[A-Z][^_]*\.$/.test(detail || "") && !/tenant/i.test(detail) ? detail : "",
    },
    fetch: async url => url.endsWith("/api/v1/audit/unified/status")
      ? statusResponse(json) : json({ download_allowed: true }),
    URL, Date, Array, Promise,
  };
  vm.runInNewContext(auditScript(), context);
  await new Promise(resolve => setImmediate(resolve));
  await new Promise(resolve => setImmediate(resolve));
  return nodes;
}

const NO_WORKSPACE = json => json({ detail: "select an active tenant before using unified audit" }, 409);

test("no workspace selected: says what is missing and links to the picker, not 'refresh'", async () => {
  const nodes = await loadPanel(NO_WORKSPACE);
  const status = nodes["audit-custody-status"];
  assert.doesNotMatch(status.textContent, /changed since you opened it|Refresh the page/);
  assert.equal(status.children.length, 1);
  const link = status.children[0];
  assert.equal(link.textContent, "Choose a workspace to see its protection status.");
  assert.equal(link.href, "/workspace/tenant?next=%2Faudit");
  // The stale figures are cleared rather than left looking current.
  for (const id of ["audit-custody-enabled", "audit-custody-checkpoint", "audit-custody-worm", "audit-custody-siem"]) {
    assert.equal(nodes[id].textContent, "—");
  }
  assert.equal(nodes["audit-custody-refresh"].disabled, false);
});

test("the picker sends the person back to the same filtered view", async () => {
  const nodes = await loadPanel(NO_WORKSPACE, { search: "?day=2026-09-30" });
  assert.equal(nodes["audit-custody-status"].children[0].href,
    "/workspace/tenant?next=%2Faudit%3Fday%3D2026-09-30");
});

test("other 409s keep the server's own sentence when it is plain, else the generic text", async () => {
  let nodes = await loadPanel(json => json({ detail: "Another administrator is changing this right now." }, 409));
  assert.equal(nodes["audit-custody-status"].textContent, "Another administrator is changing this right now.");
  nodes = await loadPanel(json => json({ detail: "lease_lost" }, 409));
  assert.match(nodes["audit-custody-status"].textContent, /Could not load the protection status\. This was changed/);
});

test("a response with no body still falls back to the generic message", async () => {
  const nodes = await loadPanel(() => ({ ok: false, status: 503, json: async () => { throw new Error("no body"); } }));
  assert.match(nodes["audit-custody-status"].textContent, /Could not load the protection status\. Something went wrong\./);
});

test("a ready workspace still shows its protection status", async () => {
  const nodes = await loadPanel(json => json({ custody: { ready: true, enabled: true,
    checkpoint_enabled: true, worm_enabled: false, siem_enabled: false } }));
  assert.equal(nodes["audit-custody-enabled"].textContent, "Ready");
  assert.equal(nodes["audit-custody-worm"].textContent, "Off");
  assert.match(nodes["audit-custody-status"].textContent, /Extra protection is set up for this workspace/);
});
