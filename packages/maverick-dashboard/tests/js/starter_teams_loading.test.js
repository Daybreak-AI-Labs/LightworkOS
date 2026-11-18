"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const root = path.resolve(__dirname, "../../maverick_dashboard");
const template = ["starter_teams.html", "_starter_team_schedules.html"]
  .map(file => fs.readFileSync(path.join(root, "templates", file), "utf8")).join("\n");

function page(handle) {
  const requests = [], nodes = new Map();
  const eventTarget = obj => Object.assign(obj, {
    listeners: new Map(),
    addEventListener(type, fn) { this.listeners.set(type, fn); },
    dispatchEvent(event) { return this.listeners.get(event.type)?.(event); },
  });
  class Event {
    constructor(type, properties = {}) { Object.assign(this, {type}, properties); }
  }
  function element(tag) {
    return eventTarget({
      tag, children: [], value: "", textContent: "", dataset: {},
      hidden: false, disabled: false, close() {}, contains() { return false; },
      appendChild(child) {
        if (this.tag === "select" && !this.children.length) this.value = child.value;
        this.children.push(child);
      },
      replaceChildren(...children) { this.children = []; this.value = ""; children.forEach(child => this.appendChild(child)); },
    });
  }
  for (const [,tag,id] of template.matchAll(/<(\w+) [^>]*\bid="([^"]+)"/g))
    nodes.set(id, element(tag));
  const document = eventTarget({getElementById: id => nodes.get(id) ?? null, createElement: element});
  const window = eventTarget({
    location: {hash: ""},
    mvFetchJSON(url, options) { requests.push({url, options}); return Promise.resolve().then(() => handle(url, options)); },
  });
  const storage = new Map();
  const sessionStorage = {getItem: key => storage.get(key), removeItem: key => storage.delete(key)};
  const state = vm.createContext({document, window, sessionStorage, CustomEvent: Event});
  for (const file of ["lightwork-starter-team-schedules.js", "lightwork-starter-teams.js"])
    vm.runInContext(fs.readFileSync(path.join(root, "static", file), "utf8"), state);
  return {nodes, requests, settle: () => new Promise(resolve => setImmediate(resolve))};
}

const catalog = {context: "workspace-a", teams: [], setups: [], preview_only: true};
const team = {id: "one", title: "One", acceptance: [], connections: [], stop_conditions: [], blocked_actions: []};
const inventory = "/api/v1/starter-teams", schedules = "/api/v1/starter-team-schedules";

test("preview-only startup requests one catalogue and never calls schedules", async () => {
  let release;
  const response = new Promise(resolve => { release = resolve; });
  const app = page(() => response);
  await app.settle();
  assert.deepEqual(app.requests.map(item => item.url), [inventory]);
  assert.equal(app.requests[0].options.timeout, 10000);
  release({...catalog, teams: [team]});
  await app.settle();
  assert.deepEqual(app.requests.map(item => item.url), [inventory]);
  assert.equal(app.nodes.get("st-schedules-panel").hidden, true);
  assert.equal(app.nodes.get("st-preview-panel").hidden, false);
  assert.equal(app.nodes.get("st-preview-submit").disabled, false);
});

test("an empty catalogue explains department access and offers a reachable retry", async () => {
  const app = page(() => catalog);
  await app.settle();
  assert.match(app.nodes.get("st-message").textContent, /No teams.*Choose another workspace.*department access/);
  assert.equal(app.nodes.get("st-catalog-retry").hidden, false);
  assert.equal(app.nodes.get("st-catalog-retry").disabled, false);
  assert.equal(app.nodes.get("st-preview-submit").disabled, true);
  assert.equal(app.nodes.get("st-preview-panel").hidden, true);
  assert.deepEqual(app.requests.map(item => item.url), [inventory]);
});

test("a timed-out catalogue can be retried without starting schedules", async () => {
  let attempt = 0;
  const app = page(() => {
    if (!attempt++) throw new Error("Loading teams took too long.");
    return {...catalog, teams: [team]};
  });
  await app.settle();
  assert.match(app.nodes.get("st-message").textContent, /took too long.*Retry/);
  assert.equal(app.nodes.get("st-catalog-retry").hidden, false);
  assert.equal(app.nodes.get("st-catalog-retry").disabled, false);
  app.nodes.get("st-catalog-retry").dispatchEvent({type: "click"});
  await app.settle();
  assert.deepEqual(app.requests.map(item => item.url), [inventory, inventory]);
  assert.equal(app.nodes.get("st-preview-panel").hidden, false);
  assert.equal(app.nodes.get("st-catalog-retry").hidden, true);
});

test("local workflow starts schedules after the catalogue and reuses its results", async () => {
  const app = page(url => url === inventory
    ? {...catalog, preview_only: false, teams: [team]}
    : {context: catalog.context, schedules: []});
  await app.settle();
  assert.deepEqual(app.requests.map(item => item.url), [inventory, schedules]);
  assert.equal(app.nodes.get("st-schedules-panel").hidden, false);
  assert.match(app.nodes.get("sts-message").textContent, /0 reviewed schedules/);
  app.nodes.get("sts-refresh").dispatchEvent({type: "click"});
  await app.settle();
  assert.deepEqual(app.requests.map(item => item.url), [inventory, schedules, schedules]);
});

test("the generic synthetic example is separate from the licensed catalogue", async () => {
  const app = page(url => url === inventory
    ? {...catalog, synthetic_demo: {id: "generic_synthetic_demo", label: "Generic synthetic example"}}
    : {mode: "synthetic_preview", saved: false, output: {deliverable: "Generic example", findings: []}});
  await app.settle();
  assert.match(app.nodes.get("st-message").textContent, /No teams.*generic synthetic example/);
  assert.equal(app.nodes.get("st-team").disabled, true);
  assert.equal(app.nodes.get("st-preview-panel").hidden, true);
  assert.equal(app.nodes.get("st-generic-demo").hidden, false);
  assert.equal(app.nodes.get("st-generic-submit").disabled, false);
  app.nodes.get("st-generic-submit").dispatchEvent({type: "click"});
  await app.settle();
  assert.deepEqual(app.requests.map(item => [item.options.method, item.url]), [
    ["GET", inventory], ["GET", inventory + "/preview/generic_synthetic_demo"],
  ]);
  assert.match(app.nodes.get("st-generic-result").children[0].children[1].textContent, /not saved/);
});

test("a synthetic example is never enabled just because the catalogue is empty", async () => {
  const app = page(() => catalog);
  await app.settle();
  assert.equal(app.nodes.get("st-generic-demo").hidden, true);
  assert.equal(app.nodes.get("st-generic-submit").disabled, true);
  app.nodes.get("st-generic-submit").dispatchEvent({type: "click"});
  await app.settle();
  assert.deepEqual(app.requests.map(item => item.url), [inventory]);
});
