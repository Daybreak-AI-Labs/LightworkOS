"use strict";
// A task waiting for a person's decision showed "Try again when you are ready"
// and a reply box labelled as the answer, but the reply started a new task and
// the decision stayed open forever. The decision card (the Approvals page's
// own component) now appears on the task's page, for that task only.
// Run with: node --test tests/js/chat_goal_decision.test.js
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const {JSDOM} = require("jsdom");
const script = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-decisions.js"), "utf8");
const flush = async () => { for (let i = 0; i < 12; i++) await new Promise(setImmediate); };

function decision(id, goal) {
  return {id, goal_id: goal, area_label: "Running commands", question: "Retry the command?", recommended: 1,
          reason: "You asked for its output.", expires_at: 1795099999, can_answer: true, why_not: "", restart_note: "",
          options: [{number: 1, label: "Retry", effect: "Runs it again."}, {number: 2, label: "Report it", effect: "Says it did not run."}]};
}

test("the task page shows only that task's decisions and answers through the same API", async () => {
  const dom = new JSDOM(`<section id="decision-requests" data-goal="10" hidden>
      <div data-decision-list></div><p role="status" data-decision-status></p></section>`,
    {url: "https://fixture.invalid/chat/goal/10", runScripts: "outside-only"});
  const w = dom.window, calls = [];
  w.mvFetchJSON = async (url, options) => {
    calls.push([url, options && options.body]);
    if (url === "/api/v1/decisions") return {decisions: [decision(1, 10), decision(2, 11)]};
    return {message: "Your choice was sent. The task continues."};
  };
  w.eval(script); await flush();
  const root = w.document.getElementById("decision-requests");
  assert.equal(root.hidden, false);
  const cards = root.querySelectorAll("article.approval-item");
  assert.equal(cards.length, 1);
  assert.equal(cards[0].id, "decision-1");
  cards[0].querySelector("input[value='2']").checked = true;
  cards[0].querySelector("form").dispatchEvent(new w.Event("submit", {cancelable: true}));
  await flush();
  assert.equal(JSON.stringify(calls[1]), JSON.stringify(["/api/v1/decisions/1/answer", {option: 2, note: ""}]));
  assert.match(cards[0].textContent, /The task continues/);
});

test("with no decision for this task the section stays hidden", async () => {
  const dom = new JSDOM(`<section id="decision-requests" data-goal="10" hidden>
      <div data-decision-list></div><p role="status" data-decision-status></p></section>`,
    {url: "https://fixture.invalid/chat/goal/10", runScripts: "outside-only"});
  dom.window.mvFetchJSON = async () => ({decisions: [decision(2, 11)]});
  dom.window.eval(script); await flush();
  assert.equal(dom.window.document.getElementById("decision-requests").hidden, true);
});
