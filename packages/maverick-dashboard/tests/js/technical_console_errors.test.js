// Run with: node --test packages/maverick-dashboard/tests/js/technical_console_errors.test.js
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const dir = path.resolve(__dirname, "../../maverick_dashboard");
const shell = fs.readFileSync(path.join(dir, "static/lightwork-ui.js"), "utf8");
// The advanced-operations consoles share one shape: Check availability, an
// operation picker with JSON boxes, and a result area.
const CONSOLES = [
  ["compliance_scope_actions.html", "csa"], ["compliance_scoping.html", "cs"],
  ["privacy_notice_governance.html", "png"], ["privacy_rights_consumer_delivery.html", "prcd"],
  ["privacy_rights_orchestration.html", "pro"],
];
const RAW = /HTTP|Error:|\b[45]\d\d\b|privacy_ops|SyntaxError|Unexpected token|JSON\.parse/;
const settle = async () => { for (let i = 0; i < 20; i++) await new Promise((done) => setImmediate(done)); };

function load(file, prefix, reply) {
  const template = fs.readFileSync(path.join(dir, "templates", file), "utf8").replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
  const start = template.indexOf(`<details class="panel" id="${prefix}-technical">`);
  const block = template.slice(start, template.indexOf("</details>", template.indexOf("<script>", start)));
  assert.ok(start >= 0, file);
  const script = block.slice(block.indexOf("<script>") + 8, block.lastIndexOf("</script>"));
  const markup = block.replace(/<script>[\s\S]*<\/script>/, "").replace(/{%[\s\S]*?%}/g, "").replace(/{{[\s\S]*?}}/g, "");
  const dom = new JSDOM(`<div id="mv-toasts"></div><div id="mv-toasts-alert"></div>${markup}</details>`,
    { url: "https://lightwork.example/", runScripts: "outside-only" });
  const w = dom.window;
  w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
  w.fetch = async () => reply();
  w.eval(shell);
  w.eval(script);
  return { w, doc: w.document, output: () => w.document.getElementById(`${prefix}-output`).textContent };
}
const json = (body, status) => () => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

for (const [file, prefix] of CONSOLES) {
  test(`${file}: request failures read as plain sentences`, async () => {
    const cases = [
      [json({ detail: "privacy_ops is not enabled" }, 403), "Could not complete the request. You do not have permission to do this. Ask an administrator."],
      [json({ detail: "Choose a later review date." }, 422), "Choose a later review date."],
      [() => new Response("<html>Bad gateway</html>", { status: 502 }), "Lightwork's reply could not be read. Refresh the page and try again."],
      [() => { throw new TypeError("Failed to fetch"); }, "Could not complete the request. Lightwork could not be reached. Check your connection and try again."],
    ];
    for (const [reply, expected] of cases) {
      const ui = load(file, prefix, reply);
      ui.doc.getElementById(`${prefix}-load-status`).click();
      await settle();
      assert.equal(ui.output(), expected);
      assert.doesNotMatch(ui.output(), RAW);
      ui.w.close();
    }
  });

  test(`${file}: typed JSON mistakes say which boxes to fix`, async () => {
    const ui = load(file, prefix, json({ ok: true }, 200));
    ui.doc.getElementById(`${prefix}-path-values`).value = "{plan: 1";
    ui.doc.getElementById(`${prefix}-confirm`).checked = true;
    ui.doc.getElementById(`${prefix}-submit`).click();
    await settle();
    assert.match(ui.output(), /must be valid JSON\. Check the quotes, commas and brackets, then try again\.$/);
    assert.doesNotMatch(ui.output(), RAW);
    ui.w.close();
  });
}
