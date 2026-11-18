// Run with: node --test packages/maverick-dashboard/tests/js/single_computer_sections.test.js
// A single-computer feature on a shared deployment answers its opening read
// with {available: false, message}. The page shows that message, never a
// stuck "Checking..." line or a generic failure.
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const { shell } = require("./_shell");

const folder = path.resolve(__dirname, "../../maverick_dashboard");
const MESSAGE = "This feature needs a single-computer installation of Lightwork, so it is not available on this shared deployment.";
const settle = async () => { for (let i = 0; i < 40; i++) await new Promise((r) => setImmediate(r)); };

async function section(template, script, replies) {
  const markup = fs.readFileSync(path.join(folder, "templates", template), "utf8")
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "").replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, "");
  const dom = new JSDOM("<!doctype html><body>" + markup + "</body>", { url: "https://lightwork.example/research", runScripts: "outside-only" });
  const { window } = dom;
  const calls = [];
  window.fetch = async (url) => {
    const pathname = new URL(url, window.location).pathname;
    calls.push(pathname);
    return new Response(JSON.stringify(replies[pathname] || {}), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  shell(window);
  window.eval(fs.readFileSync(path.join(folder, "static", script), "utf8"));
  await settle();
  return { window, calls, el: (id) => window.document.getElementById(id) };
}

test("the release section shows the single-computer message", async (t) => {
  const ui = await section("_local_flow_release.html", "lightwork-local-flow-release.js", {
    "/api/v1/research/local-flow-release": { available: false, message: MESSAGE, context: "c".repeat(64), enabled: true, flows: [], prepared: null },
  });
  t.after(() => ui.window.close());
  assert.equal(ui.el("local-flow-release-status").textContent, MESSAGE);
  assert.equal(ui.el("local-flow-release-form").querySelector('[type="submit"]').disabled, true);
});

test("the generated-tool section shows the single-computer message", async (t) => {
  const ui = await section("_generated_tool_removal.html", "lightwork-generated-tool-removal.js", {
    "/api/v1/generated-tool-removals": { available: false, message: MESSAGE, context: "c".repeat(64), choices: [] },
  });
  t.after(() => ui.window.close());
  assert.equal(ui.el("gtr-status").textContent, MESSAGE);
  assert.ok(!ui.calls.includes("/api/v1/generated-tool-removals/history"));
});
