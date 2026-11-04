// Run with: node --test packages/maverick-dashboard/tests/js/permissions_mutations.test.js
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

class Element {
  constructor(tag = "div") {
    this.tagName = tag;
    this.dataset = {};
    this.style = {};
    this.attributes = {};
    this.listeners = {};
    this.children = [];
    this.textContent = "";
    this.disabled = false;
  }
  setAttribute(name, value) { this.attributes[name] = value; }
  removeAttribute(name) { delete this.attributes[name]; }
  addEventListener(type, callback) { this.listeners[type] = callback; }
  appendChild(child) { this.children.push(child); }
  querySelectorAll(tag) {
    return this.children.flatMap((child) => [
      ...(child.tagName === tag ? [child] : []), ...child.querySelectorAll(tag),
    ]);
  }
  click() { return this.listeners.click(); }
}

const template = fs.readFileSync(path.resolve(__dirname,
  "../../maverick_dashboard/templates/permissions.html"), "utf8").replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
const scripts = [...template.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((match) => match[1]);

function response(body, { status = 200, invalid = false } = {}) {
  return { status, ok: status >= 200 && status < 300, async json() {
    if (invalid) throw new SyntaxError("invalid JSON");
    return body;
  } };
}

function toolFixture(result, action = "enable") {
  const button = new Element("button");
  button.dataset = { name: "shell", action };
  button.textContent = action === "enable" ? "Allow" : "Block";
  const badges = new Map([".perm-base-acl", ".perm-override", ".perm-overall"].map((key) => [key, new Element()]));
  const row = { dataset: { baseAclState: "ready", toolUsable: "false" }, querySelector(key) { return badges.get(key); } };
  button.closest = () => row;
  const message = new Element();
  let requests = 0;
  // The page wires its bulk bar once the shared helpers load; none are
  // loaded here, so each button's own handler is exercised alone.
  const context = {
    window: {},
    document: { getElementById() { return message; }, querySelectorAll() { return [button]; }, addEventListener() {} },
    async fetch() { requests += 1; return result; },
  };
  vm.runInNewContext(scripts[1], context);
  return { button, message, badges, row, requests: () => requests };
}

const tool = { name: "shell", overlay_blocked: false, base_acl_allowed: true,
  usable: false, state: "readiness_unknown", reason: "Provider readiness is unknown." };

for (const result of [response({}, { invalid: true }), response({}), response(null), response({}, { status: 204 }), response({ tool: { ...tool, name: "another-tool" } })]) {
  test(`clearing a block requires the matching effective tool state: ${JSON.stringify(result)}`, async () => {
    const ui = toolFixture(result);
    await ui.button.click();
    assert.match(ui.message.textContent, /Could not confirm/);
    assert.equal(ui.button.dataset.action, "enable");
    assert.equal(ui.button.textContent, "Allow");
    assert.equal(ui.button.disabled, false);
    assert.equal(ui.row.dataset.toolUsable, "false");
    assert.equal(ui.badges.get(".perm-override").textContent, "");
  });
}

test("a confirmed clear preserves unknown readiness and offers only the admitted policy action", async () => {
  const ui = toolFixture(response({ tool }));
  await ui.button.click();
  assert.equal(ui.button.dataset.action, "disable");
  assert.equal(ui.badges.get(".perm-overall").textContent, "Not checked yet");
  assert.equal(ui.row.dataset.toolUsable, "false");
});

test("the documented no-content disable response still adds a block", async () => {
  const ui = toolFixture(response(null, { status: 204 }), "disable");
  await ui.button.click();
  assert.equal(ui.button.dataset.action, "enable");
  assert.equal(ui.badges.get(".perm-override").textContent, "Blocked");
  assert.match(ui.message.textContent, /is now blocked/);
});

test("a repeated tool action while pending sends one mutation", async () => {
  const ui = toolFixture(response({ tool }));
  const first = ui.button.click();
  const duplicate = ui.button.click();
  await Promise.all([first, duplicate]);
  assert.equal(ui.requests(), 1);
});

async function turn() { await new Promise((resolve) => setImmediate(resolve)); }

async function sandboxFixture(mutation, { selected = "local", confirmed = true } = {}) {
  const rows = new Element(), error = new Element();
  const requests = [], confirmations = [];
  let reloads = 0;
  const context = {
    document: {
      getElementById(id) { return id === "sbx-rows" ? rows : error; },
      createElement(tag) { return new Element(tag); },
    },
    location: { reload() { reloads += 1; } },
    async mvConfirm(message) { confirmations.push(message); return confirmed; },
    confirm(message) { confirmations.push(message); return confirmed; },
    async fetch(url, options) {
      if (options) { requests.push(JSON.parse(options.body)); return mutation; }
      return response({ backend: selected, backends: {
        docker: { available: true }, podman: { available: false }, local: { available: true },
      } });
    },
  };
  context.window = context;
  vm.runInNewContext(scripts[0].replace(/var canManageSandbox = [^;]+;/, "var canManageSandbox = true;"), context);
  await turn();
  return { rows, error, requests, confirmations, reloads: () => reloads };
}

test("sandbox switching suppresses repeated clicks and restores unavailable choices after an unconfirmed result", async () => {
  let resolve;
  const pending = new Promise((done) => { resolve = done; });
  const ui = await sandboxFixture(pending);
  const [docker, podman] = ui.rows.querySelectorAll("button");
  docker.click(); docker.click();
  assert.equal(ui.requests.length, 1);
  assert.equal(docker.disabled, true);
  resolve(response({ backend: "podman" }));
  await turn();
  assert.equal(ui.reloads(), 0);
  assert.match(ui.error.textContent, /Could not confirm/);
  assert.equal(docker.disabled, false);
  assert.equal(podman.disabled, true);
});

test("a local sandbox switch requires confirmation and sends its explicit acknowledgement", async () => {
  const ui = await sandboxFixture(response({ backend: "local" }), { selected: "docker" });
  const local = ui.rows.querySelectorAll("button").find((button) => button.textContent === "Use this computer");
  await local.click();
  await turn();
  assert.equal(ui.confirmations.length, 1);
  assert.deepEqual(ui.requests, [{ backend: "local", acknowledge_local_risk: true }]);
  assert.equal(ui.reloads(), 1);
});

test("cancelling the local sandbox confirmation sends no mutation", async () => {
  const ui = await sandboxFixture(response({ backend: "local" }), { selected: "docker", confirmed: false });
  const local = ui.rows.querySelectorAll("button").find((button) => button.textContent === "Use this computer");
  await local.click();
  assert.equal(ui.requests.length, 0);
  assert.equal(ui.reloads(), 0);
});
