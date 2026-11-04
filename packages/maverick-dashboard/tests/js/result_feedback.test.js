"use strict";
// One-tap feedback on the Results page (lightwork-result-feedback.js).
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const { shell } = require("./_shell");

const SCRIPT = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-result-feedback.js"), "utf8");
const settle = async () => { for (let i = 0; i < 12; i++) await new Promise((resolve) => setImmediate(resolve)); };

function page(reply) {
  const dom = new JSDOM(`<div data-result-feedback data-goal="7"><button data-rating="up" aria-pressed="false">up</button>
    <button data-rating="down" aria-pressed="false">down</button><span data-feedback-msg></span></div>`,
    { url: "https://lightwork.test/deliverables", runScripts: "outside-only" });
  const calls = [];
  dom.window.fetch = async (url, init = {}) => {
    calls.push({ url: String(url), method: init.method || "GET", body: init.body ? JSON.parse(init.body) : null });
    return reply(calls.at(-1));
  };
  shell(dom.window);
  dom.window.eval(SCRIPT);
  const doc = dom.window.document;
  return { dom, doc, calls, async click(rating) { await settle(); doc.querySelector(`[data-rating="${rating}"]`).click(); },
    msg() { return doc.querySelector("[data-feedback-msg]").textContent; } };
}
const json = (value, status = 200) => ({ ok: status < 300, status, headers: new Map([["content-type", "application/json"]]), json: async () => value, text: async () => JSON.stringify(value) });
const current = { context: "c".repeat(64), revision: "r".repeat(64), eligible: true, feedback: null };

test("one tap saves the rating against the current answer and says how it is used", async () => {
  const p = page((call) => call.method === "GET" ? json(current) : json({ feedback: { rating: "up" }, acknowledgement: "Thanks. Saved with this task." }));
  await p.click("up");
  await settle();
  const post = p.calls.find((call) => call.method === "POST");
  assert.equal(post.url, "/api/v1/goals/7/answer-feedback");
  assert.equal(post.body.rating, "up");
  assert.equal(post.body.revision, current.revision);
  assert.equal(post.body.expected_context, current.context);
  assert.match(post.body.operation_id, /^[a-f0-9]{32}$/);
  assert.equal(p.msg(), "Thanks. Saved with this task.");
  assert.equal(p.doc.querySelector('[data-rating="up"]').getAttribute("aria-pressed"), "true");
  p.dom.window.close();
});

test("a lost reply is retried with the same operation, so it never counts twice", async () => {
  let fail = true;
  const p = page((call) => {
    if (call.method === "GET") return json(current);
    if (fail) { fail = false; throw new TypeError("Failed to fetch"); }
    return json({ feedback: { rating: "down" }, acknowledgement: "Thanks." });
  });
  await p.click("down");
  await settle();
  assert.notEqual(p.msg(), "Thanks.");
  await p.click("down");
  await settle();
  const posts = p.calls.filter((call) => call.method === "POST");
  assert.equal(posts.length, 2);
  assert.equal(posts[0].body.operation_id, posts[1].body.operation_id);
  assert.match(p.msg(), /Thanks\. Say what was wrong/);
  assert.equal(p.doc.querySelector("[data-feedback-msg] a").getAttribute("href"), "/chat/goal/7#feedback");
  p.dom.window.close();
});

test("a result that cannot be rated says where to go instead", async () => {
  const p = page(() => json({ ...current, eligible: false }));
  await p.click("up");
  await settle();
  assert.equal(p.calls.filter((call) => call.method === "POST").length, 0);
  assert.equal(p.msg(), "This result cannot be rated here. Open it to give feedback.");
  p.dom.window.close();
});

function runPage(reply) {
  const dom = new JSDOM(`<div data-flow-run-feedback data-run="run-9" hidden><button data-rating="up" aria-pressed="false">up</button>
    <button data-rating="down" aria-pressed="false">down</button><span data-feedback-msg></span></div>`,
    { url: "https://lightwork.test/flows/f/runs/run-9", runScripts: "outside-only" });
  const calls = [];
  dom.window.fetch = async (url, init = {}) => {
    calls.push({ url: String(url), method: init.method || "GET", body: init.body ? JSON.parse(init.body) : null });
    return reply(calls.at(-1));
  };
  shell(dom.window);
  dom.window.eval(SCRIPT);
  const doc = dom.window.document;
  return { dom, doc, calls, box: doc.querySelector("[data-flow-run-feedback]"), msg() { return doc.querySelector("[data-feedback-msg]").textContent; } };
}

test("a finished flow run shows its saved rating and one tap replaces it", async () => {
  const p = runPage((call) => call.method === "GET" ? json({ eligible: true, rating: "up" }) : json({ eligible: true, rating: call.body.rating }));
  await settle();
  assert.equal(p.calls[0].url, "/api/v1/flows/runs/run-9/feedback");
  assert.equal(p.box.hidden, false);
  assert.equal(p.doc.querySelector('[data-rating="up"]').getAttribute("aria-pressed"), "true");
  p.doc.querySelector('[data-rating="down"]').click();
  await settle();
  const put = p.calls.find((call) => call.method === "PUT");
  assert.deepEqual(put.body, { rating: "down" }, "only the rating is sent: no written text");
  assert.equal(p.doc.querySelector('[data-rating="down"]').getAttribute("aria-pressed"), "true");
  assert.equal(p.doc.querySelector('[data-rating="up"]').getAttribute("aria-pressed"), "false");
  assert.equal(p.msg(), "Thanks. Saved with this run.");
  p.dom.window.close();
});

test("a flow run still working stays without the rating until it finishes", async () => {
  let finished = false;
  const p = runPage(() => json({ eligible: finished, rating: null }));
  await settle();
  assert.equal(p.box.hidden, true);
  finished = true;
  p.doc.dispatchEvent(new p.dom.window.CustomEvent("lightwork:flow-run-finished"));
  await settle();
  assert.equal(p.box.hidden, false);
  p.dom.window.close();
});
