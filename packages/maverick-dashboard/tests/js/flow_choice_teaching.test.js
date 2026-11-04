"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.listeners = {}; this.attributes = {}; this.style = {}; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return (this.text || "") + this.children.map(child => child.textContent).join(""); }
  set innerHTML(_value) { assert.fail("teaching values must use textContent, never HTML interpretation"); }
  appendChild(child) { this.children.push(child); return child; }
  setAttribute(key, value) { this.attributes[key] = value; }
  addEventListener(event, callback) { this.listeners[event] = callback; }
}

function run() {
  return { status: "paused_approval", cursor: "teaching_review", prompt: "Choose this completed case's continuation",
    approval_card_status: "current", approval_binding_sha256: "a".repeat(64),
    human: { choices: ["route:0", "route:1"], form: [], approval_card: {
      summary: "Review the exact completed case", target: { label: "Teaching choice", sha256: "b".repeat(64) },
      authority: { actor: "reviewer", workspace: "workspace-a", role: "operator" },
      parameters: { summary: ["Case: actual-case-23"] }, consequences: {}, budget: {},
      preview: { before: "One case exists", after: "Selected continuation still needs approval" }, expires_at: 2000000000,
    } }, teaching_review: { status: "current", question: {
      observation: { inputs: { amount: 7, legacy: false }, prefix_result: { case_id: "actual-case-23" } },
      question_sha256: "c".repeat(64), options: [
        { route: "0", tool: "approve_case", arguments: { case_id: "actual-case-23", total: 7 } },
        { route: "1", tool: "queue_review", arguments: { case_id: "actual-case-23", reason: "Manual review" } },
      ],
    } } };
}

function fixture(snapshot, reply = { ok: true, body: {} }) {
  const box = new Element("div"), messages = [], calls = [], polls = [], rendered = [];
  const context = { flowNodes: [], runId: "run/teaching", flowId: "flow", window: {}, document: {
    createElement: tag => new Element(tag), getElementById: id => id === "fr-actions" ? box : null,
  }, say: message => messages.push(message), poll: count => polls.push(count),
  renderRun: run => rendered.push(run), assignedReviewOnly: false,
  api: async (url, options) => { calls.push({ url, method: options.method, body: JSON.parse(options.body) });
    if (reply.error) throw new Error(reply.error);
    return { ok: reply.ok, json: async () => reply.body }; },
  };
  const source = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates/flow_run.html"), "utf8");
  const start = source.indexOf("  function renderActions("), end = source.indexOf("  function retry(", start);
  assert.ok(start >= 0 && end > start);
  // The one-request-at-a-time guard every decision button now goes through.
  const guardStart = source.indexOf("  var sending = false"), guardEnd = source.indexOf("  function say(", guardStart);
  assert.ok(guardStart >= 0 && guardEnd > guardStart);
  vm.runInNewContext(source.slice(guardStart, guardEnd), context, { filename: "flow_run.html" });
  vm.runInNewContext(source.slice(start, end), context, { filename: "flow_run.html" });
  context.renderActions(snapshot);
  function all(element = box) { return [element, ...element.children.flatMap(child => all(child))]; }
  return { box, messages, calls, polls, rendered, context, all,
    buttons: () => all().filter(element => element.tag === "button"),
    async click(text) {
      const button = all().find(element => element.tag === "button" && element.textContent === text);
      assert.ok(button, "missing visible button: " + text);
      button.listeners.click();
      await new Promise(resolve => setImmediate(resolve));
    },
  };
}

test("teaching displays exact observations, tools and JSON arguments as literal text", () => {
  const snapshot = run();
  snapshot.teaching_review.question.options[0].tool = '<img src=x onerror="throw 1">';
  snapshot.teaching_review.question.options[1].arguments.reason = '</pre><script>throw 1</script> {{secret("opaque")}}';
  const ui = fixture(snapshot);
  const pre = ui.all().filter(element => element.tag === "pre").map(element => element.textContent);
  assert.deepEqual(pre, [JSON.stringify(snapshot.teaching_review.question.observation, null, 2),
    ...snapshot.teaching_review.question.options.map(option => JSON.stringify(option.arguments, null, 2))]);
  assert.ok(ui.all().some(element => element.tag === "h4" && element.textContent === snapshot.teaching_review.question.options[0].tool));
  assert.equal(ui.all().filter(element => ["img", "script"].includes(element.tag)).length, 0);
  assert.match(ui.box.textContent, /separate approval before it runs/);
  assert.match(ui.box.textContent, /Question commitment: c{64}/);
  assert.equal(ui.calls.length, 0, "rendering must not dispatch or answer");
});

for (const [route, tool] of [["0", "approve_case"], ["1", "queue_review"]]) {
  test(`Choose ${tool} submits only route:${route}, empty inputs and the current approval binding`, async () => {
    const snapshot = run(), ui = fixture(snapshot);
    assert.deepEqual(ui.buttons().map(button => button.textContent), ["Choose approve_case", "Choose queue_review", "Reject"]);
    await ui.click("Choose " + tool);
    assert.deepEqual(ui.calls, [{ url: "/api/v1/flows/runs/run%2Fteaching/resume", method: "POST",
      body: { decision: "route:" + route, inputs: {}, approval_binding_sha256: snapshot.approval_binding_sha256 } }]);
    // The decided run stays on screen while the page follows it until its state changes.
    assert.deepEqual(ui.rendered, [snapshot]);
    assert.deepEqual(ui.polls, [60]);
    assert.match(ui.messages.at(-1), /continuing/);
  });
}

test("Reject submits a rejection, never a route or fabricated example", async () => {
  const snapshot = run(), ui = fixture(snapshot);
  await ui.click("Reject");
  assert.equal(ui.calls[0].body.decision, "rejected");
  assert.deepEqual(Object.keys(ui.calls[0].body).sort(), ["approval_binding_sha256", "decision", "inputs"]);
  assert.equal(ui.messages.at(-1), "Rejected.");
});

for (const unavailable of [undefined, null, { status: "unavailable" }, { status: "redacted" },
  { status: "current" }, { status: "current", question: { options: [] } },
  { status: "current", question: { options: [{ route: "0", tool: "approve_case", arguments: {} }] } }]) {
  test(`teaching cannot be approved without both verified options: ${JSON.stringify(unavailable)}`, () => {
    const snapshot = run();
    if (unavailable === undefined) delete snapshot.teaching_review;
    else snapshot.teaching_review = unavailable;
    const ui = fixture(snapshot);
    assert.equal(ui.buttons().filter(button => button.textContent !== 'Reload').length, 0,
      "missing/redacted teaching data must not fall back to generic approval or opaque routes");
    assert.match(ui.box.textContent, /unavailable|cannot be approved|cannot submit/);
    assert.equal(ui.calls.length, 0);
  });
}

for (const change of [snapshot => { snapshot.approval_card_status = "stale"; },
  snapshot => { snapshot.approval_binding_sha256 = ""; }, snapshot => { delete snapshot.human.approval_card; }]) {
  test("exact teaching options do not override unavailable approval authority", () => {
    const snapshot = run(); change(snapshot);
    const ui = fixture(snapshot);
    assert.equal(ui.buttons().filter(button => button.textContent !== 'Reload').length, 0);
    assert.equal(ui.calls.length, 0);
  });
}

test("a stale server rejection stays visible without claiming the route resumed", async () => {
  const ui = fixture(run(), { ok: false, body: { detail: "The reviewed prefix changed; request a fresh review." } });
  await ui.click("Choose approve_case");
  assert.equal(ui.messages.at(-1), "The reviewed prefix changed; request a fresh review.");
  assert.equal(ui.calls.length, 1);
  // A refused decision does not follow the run as if it had resumed.
  assert.deepEqual(ui.polls, []);
  assert.deepEqual(ui.rendered, []);
});

test("network failure reports unavailable resume rather than success", async () => {
  const ui = fixture(run(), { error: "disconnected" });
  await ui.click("Choose queue_review");
  assert.equal(ui.messages.at(-1), "Could not resume. Refresh the page and try again.");
  assert.deepEqual(ui.polls, []);
});

test("ordinary approval retains its generic approval button", async () => {
  const snapshot = run(); snapshot.cursor = "approval_1_0"; snapshot.human.choices = [];
  delete snapshot.teaching_review;
  const ui = fixture(snapshot);
  assert.deepEqual(ui.buttons().map(button => button.textContent), ["Approve", "Reject"]);
  await ui.click("Approve");
  assert.equal(ui.calls[0].body.decision, "approved");
});

test("an update to unavailable teaching evidence removes all previously clickable choices", () => {
  const snapshot = run(), ui = fixture(snapshot);
  assert.equal(ui.buttons().length, 3);
  snapshot.teaching_review = { status: "redacted" };
  ui.context.renderActions(snapshot);
  assert.equal(ui.buttons().filter(button => button.textContent !== 'Reload').length, 0);
  assert.equal(ui.calls.length, 0);
});
