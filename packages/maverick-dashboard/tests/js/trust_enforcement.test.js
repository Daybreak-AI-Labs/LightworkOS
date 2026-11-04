"use strict";
// The Trust page's Blocking switch: turning blocking off asks first and then
// sends the confirmation the server requires; turning it on needs none.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const folder = path.resolve(__dirname, "../../maverick_dashboard");
const template = fs.readFileSync(path.join(folder, "templates/trust.html"), "utf8").replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
// The page script is inline; fill its two data slots the way the server does.
const script = template.slice(template.lastIndexOf("<script>") + "<script>".length,
  template.lastIndexOf("</script>"))
  .replace("{{ agents | tojson }}", "[]")
  .replace("{{ tool_choices | tojson }}", "[]");

async function fixture(enforced, { answer = true, status = 200 } = {}) {
  const markup = '<!doctype html><main id="content"><button type="button" id="tr-enforce" data-enforced="' +
    (enforced ? "true" : "false") + '">Blocking</button>' +
    '<details><summary>Show the key</summary><p id="tr-key-text"></p></details>' +
    '<button type="button" id="tr-key-copy">Copy</button><button type="button" id="tr-key-download">Download</button></main>';
  const dom = new JSDOM(markup, { url: "https://lightwork.example/trust", runScripts: "outside-only" });
  const { window } = dom;
  const ui = { window, calls: [], confirms: [], toasts: [] };
  window.fetch = async (url, options = {}) => {
    ui.calls.push({ url, options });
    return new window.Response(JSON.stringify({ enforced: !enforced }), { status, headers: { "Content-Type": "application/json" } });
  };
  window.Response = Response;
  window.mvConfirm = async (message) => { ui.confirms.push(message); return answer; };
  window.mvToast = (text) => ui.toasts.push(text);
  window.mvErrorText = (failure, action) => "Could not " + action + ".";
  window.mvFail = () => {};
  window.setTimeout = () => 0;
  window.eval(script);
  ui.settle = async () => { for (let i = 0; i < 10; i++) await new Promise((done) => setImmediate(done)); };
  return ui;
}

test("turning blocking off asks first and sends the confirmation", async (t) => {
  const ui = await fixture(true);
  t.after(() => ui.window.close());
  ui.window.document.getElementById("tr-enforce").click();
  await ui.settle();
  assert.equal(ui.confirms.length, 1);
  assert.match(ui.confirms[0], /Turn off blocking/);
  assert.equal(ui.calls.length, 1);
  assert.deepEqual(JSON.parse(ui.calls[0].options.body), { enforced: false, confirm: true });
  assert.deepEqual(ui.toasts, ["Blocking turned off."]);
});

test("cancelling the question changes nothing", async (t) => {
  const ui = await fixture(true, { answer: false });
  t.after(() => ui.window.close());
  ui.window.document.getElementById("tr-enforce").click();
  await ui.settle();
  assert.equal(ui.calls.length, 0);
});

test("turning blocking on sends no confirmation", async (t) => {
  const ui = await fixture(false);
  t.after(() => ui.window.close());
  ui.window.document.getElementById("tr-enforce").click();
  await ui.settle();
  assert.deepEqual(JSON.parse(ui.calls[0].options.body), { enforced: true, confirm: false });
});
