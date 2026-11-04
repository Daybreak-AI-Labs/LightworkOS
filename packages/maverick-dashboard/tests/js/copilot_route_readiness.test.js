"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {JSDOM} = require("jsdom");

const base = path.resolve(__dirname, "../../maverick_dashboard");
const read = name => fs.readFileSync(path.join(base, name), "utf8");
const tick = async () => {
  await new Promise(resolve => setImmediate(resolve));
  await new Promise(resolve => setImmediate(resolve));
};
const response = body => ({ok: true, status: 200, redirected: false, json: async () => body});

function harness(context, answer) {
  const dom = new JSDOM(read("templates/_copilot.html"), {
    url: "http://localhost/start", runScripts: "outside-only"
  });
  const w = dom.window, d = w.document;
  w.fetch = async url => {
    if (url.includes("/copilot/context")) return response(context);
    if (url === "/api/v1/copilot") return response(answer);
    throw Error("Unexpected request " + url);
  };
  w.eval(read("static/lightwork-copilot.js"));
  return {
    get: id => d.getElementById(id),
    async open() { d.getElementById("mv-copilot-fab").click(); await tick(); },
    async ask() {
      d.getElementById("mv-copilot-input").value = "What can I do here?";
      d.getElementById("mv-copilot-form").dispatchEvent(new w.Event("submit", {cancelable: true}));
      await tick();
    },
    close() { dom.window.close(); }
  };
}

const readiness = {
  verdict: "needs_test",
  reason: "The saved provider connection has not been tested.",
  next_action: {href: "/providers", label: "Test the connection"}
};

test("unknown model pricing keeps the Models recovery link and explains the block", async () => {
  const model = {
    client_context: "a".repeat(64), boundaries: [], suggested_questions: [],
    model_route_status: "pricing",
    model_route_reason: "The selected AI model has no confirmed price.",
    provider_setup: {
      href: "/settings#settings-models", label: "Choose a model with known pricing in Settings"
    },
    workspace_readiness: readiness
  };
  const h = harness(model, {
    reply: "Here is the page guide.", mode: "built_in",
    model_route_status: model.model_route_status,
    model_route_reason: model.model_route_reason,
    provider_setup: model.provider_setup
  });
  await h.open();
  assert.equal(h.get("mv-copilot-provider-setup").getAttribute("href"), "/settings#settings-models");
  assert.match(h.get("mv-copilot-hello").textContent, /no confirmed price/);
  assert.doesNotMatch(h.get("mv-copilot-hello").textContent, /Connect an AI service/);
  await h.ask();
  assert.equal(h.get("mv-copilot-provider-setup").getAttribute("href"), "/settings#settings-models");
  h.close();
});

test("missing provider still shows the connection action", async () => {
  const h = harness({
    client_context: "a".repeat(64), boundaries: [], suggested_questions: [],
    model_route_status: "provider",
    provider_setup: {href: "/settings#settings-integrations", label: "Configure a model provider"},
    workspace_readiness: readiness
  });
  await h.open();
  assert.equal(h.get("mv-copilot-provider-setup").getAttribute("href"), "/providers");
  assert.match(h.get("mv-copilot-hello").textContent, /Connect an AI service/);
  h.close();
});
