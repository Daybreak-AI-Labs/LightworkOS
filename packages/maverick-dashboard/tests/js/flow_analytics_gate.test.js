"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const templates = path.resolve(__dirname, "../../maverick_dashboard/templates");
const read = (name) => fs.readFileSync(path.join(templates, name), "utf8");

function open({ enabled, admin }) {
  const html = read("flow_analytics.html")
    .replace('{% include "_dash_helpers.js" %}', read("_dash_helpers.js"))
    .replace("{{ 'true' if flows_enabled else 'false' }}", String(enabled))
    .replace("{{ 'true' if can_manage_flows else 'false' }}", String(admin));
  return new JSDOM(html, {
    url: "https://lightwork.example/flows/analytics", runScripts: "dangerously",
    beforeParse(window) {
      window.fetch = async () => ({ status: 403, ok: false, json: async () => ({}) });
    },
  });
}

for (const scenario of [
  { enabled: false, admin: true, message: /Workflows are turned off/, link: true },
  { enabled: false, admin: false, message: /Ask an administrator/, link: false },
  { enabled: true, admin: true, message: /do not have access/, link: false },
]) {
  test(`workflow results gate: enabled=${scenario.enabled}, admin=${scenario.admin}`, async () => {
    const dom = open(scenario);
    try {
      await new Promise((resolve) => setTimeout(resolve, 0));
      const msg = dom.window.document.getElementById("fa-msg");
      assert.match(msg.textContent, scenario.message);
      assert.equal(msg.querySelector("a")?.getAttribute("href") || null,
        scenario.link ? "/learning#lrn-flows-on" : null);
    } finally { dom.window.close(); }
  });
}
