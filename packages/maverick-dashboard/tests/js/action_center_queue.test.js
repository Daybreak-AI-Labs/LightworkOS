// Run with: node --test packages/maverick-dashboard/tests/js/action_center_queue.test.js
"use strict";
// Smoke test for the Action Center's background-work panel (_action_center_body.html):
// the page script builds the failed-work table with the shared el(tag, cls,
// text) order, so text lands in cells and classes on the right elements.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const root = path.resolve(__dirname, "../../maverick_dashboard");
const template = fs.readFileSync(path.join(root, "templates/_action_center_body.html"), "utf8").replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
const ui = fs.readFileSync(path.join(root, "static/lightwork-ui.js"), "utf8");
const start = template.indexOf('<div class="panel" id="ac-queue">');
const end = template.indexOf("</script>", start) + "</script>".length;
const block = template.slice(start, end);
const markup = block.slice(0, block.indexOf("<script>"));
const script = block.slice(block.indexOf("<script>") + "<script>".length, block.lastIndexOf("</script>"));

function json(status, body) {
  return { ok: status >= 200 && status < 300, status, headers: new Map(), json: async () => body, text: async () => JSON.stringify(body) };
}
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

async function page(reply) {
  const dom = new JSDOM(`<!doctype html><body><main>${markup}</main></body>`, { url: "https://lightwork.test/action-center", runScripts: "outside-only" });
  const w = dom.window, calls = [];
  w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
  w.eval(ui);   // the shell's shared helpers load before page scripts, as in base.html
  w.mvWhen = () => "5 minutes ago";
  w.fetch = async (url, options) => { calls.push({ url, options }); return reply(url); };
  w.eval(script);
  for (let i = 0; i < 5; i += 1) await flush();
  return { w, d: w.document, calls };
}

test("the background-work panel lists failed work in a table with plain cells", async () => {
  const { w, d, calls } = await page(() => json(200, {
    waiting: 2, running: 1, finished: 9, failed: 1,
    failed_items: [{ what: "Scheduled task", title: "Weekly report", problem: "The provider timed out.", attempts: 3,
      failed_at: "2026-10-05T10:00:00Z", needs_operator: true, detail: "TimeoutError at step 4" }],
  }));
  assert.equal(calls[0].url, "/api/v1/queue/summary");
  assert.equal(d.getElementById("ac-queue-counts").textContent, "2 waiting · 1 running · 9 finished · 1 failed");
  const heads = [...d.querySelectorAll("#ac-queue-failed th")].map((th) => th.textContent);
  assert.deepEqual(heads, ["What", "Problem", "Tries", "When", ""]);
  assert.ok([...d.querySelectorAll("#ac-queue-failed th")].every((th) => th.scope === "col"));
  const cells = [...d.querySelectorAll("#ac-queue-failed tbody td")];
  assert.equal(cells[0].textContent, "Scheduled task: Weekly report");
  assert.match(cells[1].textContent, /^The provider timed out\. An operator must resume it on the server\.$/);
  assert.equal(cells[1].querySelector("span").className, "muted");
  assert.equal(cells[2].textContent, "3");
  assert.equal(cells[3].textContent, "5 minutes ago");
  assert.equal(cells[4].querySelector("summary").textContent, "Technical details");
  assert.equal(cells[4].querySelector("p").className, "muted");
  assert.equal(cells[4].querySelector("p").textContent, "TimeoutError at step 4");
  const copy = cells[4].querySelector("button");
  assert.equal(copy.className, "btn btn--ghost");
  assert.equal(copy.textContent, "Copy for support");
  assert.equal(copy.type, "button");
  w.close();
});

test("with nothing failed the panel says so, and a failed load shows plain words", async () => {
  const empty = await page(() => json(200, { waiting: 0, running: 0, finished: 0, failed: 0, failed_items: [] }));
  const note = empty.d.querySelector("#ac-queue-failed p");
  assert.equal(note.textContent, "Nothing has failed. Failed work appears here with what went wrong.");
  assert.equal(note.className, "muted");
  empty.w.close();
  const broken = await page(() => json(500, { detail: "Traceback: KeyError" }));
  const counts = broken.d.getElementById("ac-queue-counts").textContent;
  assert.match(counts, /^Could not load background work\./);
  assert.doesNotMatch(counts, /Traceback|500/);
  broken.w.close();
});
