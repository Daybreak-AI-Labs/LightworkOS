// Run with: node --test packages/maverick-dashboard/tests/js/flow_designer_steps.test.js
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const dir = path.resolve(__dirname, "../../maverick_dashboard/templates");
const read = (name) => fs.readFileSync(path.join(dir, name), "utf8").replace(/\r\n/g, "\n");
const raw = (text) => text.replace(/\{% raw %\}|\{% endraw %\}/g, "");

// The page body with its Jinja pieces resolved the simple way (no server).
function pageHtml(options = {}) {
  let html = read("flow_designer.html");
  html = html.slice(html.indexOf("{% block content %}") + 19, html.lastIndexOf("{% endblock %}"));
  html = html.replace(/\{% call hero[\s\S]*?\{% endcall %\}/, "")
    .replace(/\{% for d in range\(1, 29\) %\}[\s\S]*?\{% endfor %\}/, '<option value="1">1st</option><option value="15">15th</option>')
    .replace(/\{% from [^%]*%\}/g, "")
    .replace(/\{\{ \(seed_flow or none\) \| tojson \}\}/, "null")
    .replace("{{ 'true' if flows_enabled else 'false' }}", options.flowOn ? "true" : "false")
    .replace("{{ 'true' if can_manage_flows else 'false' }}", options.canManage ? "true" : "false")
    .replace(/\{\{[^}]*\}\}/g, "")
    .replace('{% include "flow_designer_core.js" %}', () => raw(read("flow_designer_core.js")))
    .replace('{% include "flow_designer_durations.js" %}', () => raw(read("flow_designer_durations.js")))
    .replace('{% include "flow_designer_schedule.js" %}', () => raw(read("flow_designer_schedule.js")))
    .replace('{% include "flow_designer_draft.js" %}', () => raw(read("flow_designer_draft.js")))
    .replace('{% include "flow_designer_presentation.js" %}', () => raw(read("flow_designer_presentation.js")))
    .replace('{% include "flow_designer_canvas.js" %}', () => raw(read("flow_designer_canvas.js")))
    .replace('{% include "flow_designer_graph.js" %}', () => raw(read("flow_designer_graph.js")))
    .replace('{% include "flow_designer_wire.js" %}', () => raw(read("flow_designer_wire.js")))
    .replace('{% include "flow_designer_transport.js" %}', () => raw(read("flow_designer_transport.js")))
    .replace('{% include "flow_designer_history.js" %}', () => raw(read("flow_designer_history.js")))
    .replace('{% include "flow_designer_inputs.js" %}', () => raw(read("flow_designer_inputs.js")))
    .replace('{% include "flow_designer_action_fields.js" %}', () => raw(read("flow_designer_action_fields.js")))
    .replace('{% include "flow_hardening_review.js" %}', () => raw(read("flow_hardening_review.js")))
    .replace('{% include "flow_designer.js" %}', () => raw(read("flow_designer.js")));
  return "<!doctype html><html><body><p id=\"fd-state\"></p>" + html + "</body></html>";
}

function open(options = {}) {
  const calls = [];
  const dom = new JSDOM(pageHtml(options), {
    url: "https://app.example/flows/designer", runScripts: "dangerously", pretendToBeVisual: true,
    beforeParse(window) {
      window.fetch = async (url, requestOptions) => {
        calls.push({ url, options: requestOptions });
        if (url.startsWith("/api/v1/workflow-action-fields/")) {
          // Each action's settings come from its own current field contract.
          const tool = decodeURIComponent(url.slice("/api/v1/workflow-action-fields/".length));
          const listed = [options.toolResponse ? options.toolResponse("") : null,
            options.toolResponse ? options.toolResponse("offset=2") : null].flatMap((r) => (r ? r.tools : []));
          const known = listed.concat([{ name: "slack_post_message", params: ["channel_id", "text"] }]);
          const params = (known.find((item) => item.name === tool) || { params: [] }).params;
          return { ok: true, status: 200, json: async () => ({ tool, revision: "fields-1", schema: {
            type: "object", required: params,
            properties: Object.fromEntries(params.map((key) => [key, { type: "string" }])) } }) };
        }
        const body = url.startsWith("/api/v1/people/assignable") ? { items: [{ ref: "user:ana", label: "Ana Diaz" }] }
          : url.startsWith("/api/v1/flows/tools") ? (options.toolResponse ? options.toolResponse(url) : { tools: [{ name: "slack_post_message", description: "Post to Slack", params: ["channel_id", "text"], category: "chat" }], categories: ["chat"] })
          : url === "/api/v1/flows" ? { flows: [{ id: "onboard-customer", name: "Onboard a customer", inputs: [{ key: "customer_name", label: "Customer name" }] }] }
          : url.startsWith("/api/v1/flows/gallery") ? { flows: [] } : {};
        if (url.startsWith("/api/v1/flows/gallery") && options.galleryStatus === 403) {
          return { ok: false, status: 403,
            headers: { get: () => (options.galleryFeatureOff ?? !options.flowOn) ? "workflows" : null },
            json: async () => ({}) };
        }
        if (url === "/api/v1/flows/draft" && options.draftStatus === 403) {
          return { ok: false, status: 403,
            headers: { get: () => options.draftFeatureOff ? "workflows" : null },
            json: async () => ({ detail: "Workflows are turned off." }) };
        }
        return { ok: true, status: 200, json: async () => body };
      };
      window.mvHuman = (v) => String(v || "").replace(/[_.-]+/g, " ").replace(/^./, (c) => c.toUpperCase());
      window.mvConfirm = async () => true;
      window.HTMLElement.prototype.getBBox = () => ({ x: 0, y: 0, width: 0, height: 0 });
      window.SVGElement && (window.SVGElement.prototype.getBoundingClientRect = () => ({ left: 0, top: 0, width: 800, height: 600 }));
    },
  });
  return { dom, w: dom.window, doc: dom.window.document, calls };
}
const settle = () => new Promise((r) => setTimeout(r, 20));

test("disabled workflows lead administrators to the exact control", async () => {
  const { dom, doc, calls } = open({ flowOn: false, canManage: true, galleryStatus: 403 });
  try {
    await settle();
    assert.ok(calls.some((call) => call.url === "/api/v1/flows/gallery"), JSON.stringify(calls));
    const msg = doc.getElementById("fd-msg");
    assert.match(msg.textContent, /Workflows are turned off/);
    assert.equal(msg.querySelector("a")?.getAttribute("href"), "/learning#lrn-flows-on");
  } finally { dom.window.close(); }
});

test("permission denial does not offer an unavailable enable control", async () => {
  const { dom, doc } = open({ flowOn: true, canManage: false, galleryStatus: 403 });
  try {
    await settle();
    const msg = doc.getElementById("fd-msg");
    assert.match(msg.textContent, /do not have access/);
    assert.equal(msg.querySelector("a"), null);
  } finally { dom.window.close(); }
});

test("disabled workflows tell non-administrators who can turn them on", async () => {
  const { dom, doc } = open({ flowOn: false, canManage: false, galleryStatus: 403 });
  try {
    await settle();
    const msg = doc.getElementById("fd-msg");
    assert.match(msg.textContent, /person who manages this installation/);
    assert.equal(msg.querySelector("a"), null);
  } finally { dom.window.close(); }
});

test("a workflow turned off after opening the editor is not described as a permission problem", async () => {
  const { dom, doc } = open({ flowOn: true, canManage: true, draftStatus: 403, draftFeatureOff: true });
  try {
    await settle();
    doc.getElementById("fd-nl").value = "Welcome a new customer";
    doc.getElementById("fd-draft").click();
    await settle();
    assert.match(doc.getElementById("fd-msg").textContent, /Workflows are turned off/);
  } finally { dom.window.close(); }
});

test("steps can be added, changed and reordered without the canvas", async () => {
  const { dom, w, doc } = open();
  try {
    await settle();
    const add = () => Array.from(doc.querySelectorAll("#fd-simple-body button")).find((b) => b.textContent === "Add step");
    doc.getElementById("fd-steps-add-kind").value = "agent"; add().click(); await settle();
    doc.getElementById("fd-steps-add-kind").value = "approval"; add().click(); await settle();
    const cards = doc.querySelectorAll("#fd-simple-body .fd-scard");
    assert.equal(cards.length, 2);
    // The chosen step's settings open in the side rail with plain labels.
    const rail = doc.querySelector(".fdx-rail");
    assert.ok(rail.contains(doc.getElementById("fd-props")));
    const text = doc.getElementById("fd-props").textContent;
    assert.match(text, /What should the person approve\?/);
    assert.match(text, /Who should be asked/);
    assert.match(text, /Stop waiting after/);
    assert.ok(Array.from(doc.querySelectorAll("#fd-props option")).some((o) => o.textContent === "Ana Diaz"));
    // Move the approval above the AI task.
    Array.from(doc.querySelectorAll("#fd-simple-body button")).find((b) => b.textContent === "Move up").click();
    await settle();
    const order = JSON.parse(JSON.stringify(w.__fdEngine.order().map((s) => s.kind)));
    assert.deepEqual(order, ["approval", "agent"]);
    assert.equal(w.__fdLiveFlow().start, w.__fdEngine.order()[0].id);
  } finally { dom.window.close(); }
});

test("a wait step offers duration choices and keeps the selected seconds", async () => {
  const { dom, w, doc } = open();
  try {
    await settle();
    await stepsHelpers(doc).addKind("delay");
    const field = Array.from(doc.querySelectorAll("#fd-props .field"))
      .find((item) => item.textContent.includes("How long to wait"));
    const select = field.querySelector("select");
    assert.ok(Array.from(select.options).some((option) => option.textContent === "5 minutes"));
    select.value = "300";
    select.dispatchEvent(new w.Event("change"));
    assert.equal(w.__fdLiveFlow().nodes.find((node) => node.kind === "delay").seconds, 300);
  } finally { dom.window.close(); }
});

test("approval and waiting questions can insert a run answer from the editor", async () => {
  const { dom, w, doc } = open();
  try {
    await settle();
    Array.from(doc.querySelectorAll("#fd-props button"))
      .find((button) => button.textContent === "Add a question").click();
    const question = doc.querySelector('#fd-props [aria-label="Question 1"]');
    question.value = "Vendor";
    question.dispatchEvent(new w.Event("input"));

    const steps = stepsHelpers(doc);
    for (const [kind, label] of [
      ["approval", "What should the person approve?"],
      ["wait_event", "Waiting for (shown while paused)"],
    ]) {
      await steps.addKind(kind);
      const promptField = Array.from(doc.querySelectorAll("#fd-props .field"))
        .find((field) => field.textContent.includes(label));
      assert.ok(promptField, kind + " question should be editable");
      const pill = Array.from(promptField.querySelectorAll(".fd__pill"))
        .find((button) => button.textContent === "+ Vendor");
      assert.ok(pill, kind + " should offer the run's Vendor answer");
      pill.click();
      assert.match(w.__fdLiveFlow().nodes.find((node) => node.kind === kind).prompt || "",
        /\{\{vendor\}\}/);
    }
  } finally { dom.window.close(); }
});

test("an action step is chosen from a list and its settings are labelled boxes", async () => {
  const { dom, w, doc } = open();
  try {
    await settle();
    doc.getElementById("fd-steps-add-kind").value = "action";
    Array.from(doc.querySelectorAll("#fd-simple-body button")).find((b) => b.textContent === "Add step").click();
    await settle();
    const sel = doc.getElementById("fd-tool-select");
    assert.equal(sel.tagName, "SELECT");
    sel.value = "slack_post_message"; sel.dispatchEvent(new w.Event("change"));
    await settle();
    const labels = Array.from(doc.querySelectorAll("#fd-props label")).map((l) => l.textContent);
    assert.ok(labels.includes("Channel id") || labels.includes("Channel ID"));
    assert.ok(!doc.getElementById("fd-props").textContent.includes("Params (JSON)"));
  } finally { dom.window.close(); }
});

test("action browsing loads the next page without losing the selected action or entered settings", async () => {
  const action = (name) => ({ name, description: name, params: ["text"], category: "chat" });
  const { dom, w, doc, calls } = open({ toolResponse(url) {
    return url.includes("offset=2")
      ? { tools: [action("teams_message")], categories: ["chat"], total: 3, next_offset: null }
      : { tools: [action("slack_post_message"), action("email")], categories: ["chat"], total: 3, next_offset: 2 };
  } });
  try {
    await settle();
    doc.getElementById("fd-steps-add-kind").value = "action";
    Array.from(doc.querySelectorAll("#fd-simple-body button")).find((b) => b.textContent === "Add step").click();
    const sel = doc.getElementById("fd-tool-select");
    sel.value = "slack_post_message"; sel.dispatchEvent(new w.Event("change"));
    await settle();  // the chosen action's field contract loads before its boxes appear
    const textLabel = Array.from(doc.querySelectorAll("#fd-props label")).find((label) => label.textContent === "Text");
    const text = doc.getElementById(textLabel.htmlFor);
    text.value = "Keep this message"; text.dispatchEvent(new w.Event("input"));
    Array.from(doc.querySelectorAll("#fd-props button")).find((button) => button.textContent === "Show more actions").click();
    await settle();
    assert.ok(calls.some((call) => call.url.includes("offset=2")));
    assert.equal(doc.getElementById("fd-tool-select").value, "slack_post_message");
    assert.ok(Array.from(doc.getElementById("fd-tool-select").options).some((item) => item.value === "teams_message"));
    assert.equal(w.__fdLiveFlow().nodes[0].params.text, "Keep this message");
    assert.match(doc.getElementById("fd-props").textContent, /3 of 3 actions shown/);
    assert.equal(Array.from(doc.querySelectorAll("#fd-props button")).some((button) => button.textContent === "Show more actions"), false);
  } finally { dom.window.close(); }
});

test("the schedule picker writes the timetable from plain choices", async () => {
  const { dom, w, doc } = open();
  try {
    await settle();
    const freq = doc.getElementById("fd-sched-freq");
    freq.value = "weekly"; freq.dispatchEvent(new w.Event("change"));
    doc.querySelector('#fd-sched-days input[value="3"]').checked = true;
    doc.querySelector('#fd-sched-days input[value="3"]').dispatchEvent(new w.Event("change"));
    const time = doc.getElementById("fd-sched-time"); time.value = "14:30"; time.dispatchEvent(new w.Event("change"));
    assert.equal(doc.getElementById("fd-schedule").value, "30 14 * * 1,3");
    assert.match(doc.getElementById("fd-sched-words").textContent, /every Monday, Wednesday at 2:30 pm/);
    assert.equal(doc.getElementById("fd-sched-days").hidden, false);
    assert.equal(doc.getElementById("fd-tz").tagName, "SELECT");
    assert.ok(doc.getElementById("fd-tz").options.length > 5);
    freq.value = "monthly"; freq.dispatchEvent(new w.Event("change"));
    assert.equal(doc.getElementById("fd-schedule").value, "30 14 1 * *");
    assert.equal(w.__fdLiveFlow().schedule, "30 14 1 * *");
  } finally { dom.window.close(); }
});

// Reachability of the live flow from its first step, over every way out of a step.
function reachable(w) {
  const flow = JSON.parse(JSON.stringify(w.__fdLiveFlow()));
  const byId = Object.fromEntries(flow.nodes.map((n) => [n.id, n]));
  const seen = new Set(), queue = flow.start ? [flow.start] : [];
  while (queue.length) {
    const n = byId[queue.shift()];
    if (!n || seen.has(n.id)) continue;
    seen.add(n.id);
    for (const key of ["next", "if_true", "if_false", "on_error", "on_expire"]) if (n[key]) queue.push(n[key]);
    for (const c of n.cases || []) if (c.to) queue.push(c.to);
  }
  return { flow, byId, seen };
}

function stepsHelpers(doc) {
  const add = () => Array.from(doc.querySelectorAll("#fd-simple-body button")).find((b) => b.textContent === "Add step");
  const where = () => doc.getElementById("fd-steps-add-where");
  return {
    where,
    async addKind(kind, choose) {
      doc.getElementById("fd-steps-add-kind").value = kind;
      if (choose) {
        const sel = where();
        assert.ok(sel, "the Steps view must ask where the new step goes");
        const option = Array.from(sel.options).find((o) => o.textContent === choose);
        assert.ok(option, "missing choice: " + choose + " in " + Array.from(sel.options).map((o) => o.textContent));
        sel.value = option.value;
      }
      add().click();
      await settle();
    },
  };
}

test("a step added after a Decision goes on the chosen Yes or No path instead of being left unconnected", async () => {
  const { dom, w, doc } = open();
  try {
    await settle();
    const steps = stepsHelpers(doc);
    await steps.addKind("agent");
    // A plain chain needs no question: the new step simply follows the last one.
    assert.equal(steps.where(), null);
    await steps.addKind("branch");
    // After a Decision the person is asked which path the next step belongs to.
    assert.deepEqual(Array.from(steps.where().options).map((o) => o.textContent),
      ["If yes, after “Decision”", "If no, after “Decision”"]);
    await steps.addKind("approval", "If yes, after “Decision”");
    // The next add starts on the path just worked on, not back at the first open end.
    assert.equal(steps.where().selectedOptions[0].textContent, "After “Approval”");
    await steps.addKind("agent", "After “Approval”");
    await steps.addKind("setvar", "If no, after “Decision”");

    const { flow, byId, seen } = reachable(w);
    const branch = flow.nodes.find((n) => n.kind === "branch");
    const approval = flow.nodes.find((n) => n.kind === "approval");
    assert.equal(branch.if_true, approval.id);
    assert.equal(byId[approval.id].next, flow.nodes.filter((n) => n.kind === "agent")[1].id);
    assert.equal(byId[branch.if_false].kind, "setvar");
    // Every step is reachable from the first step.
    assert.deepEqual([...seen].sort(), flow.nodes.map((n) => n.id).sort());
    // Once both paths lead somewhere, only the end of each path is still open.
    assert.ok(Array.from(steps.where().options).every((o) => !/Decision/.test(o.textContent)));
  } finally { dom.window.close(); }
});

test("adding with no explicit place after a Decision still connects the step to a path", async () => {
  const { dom, w, doc } = open();
  try {
    await settle();
    const steps = stepsHelpers(doc);
    await steps.addKind("branch");
    w.__fdEngine.add("approval");
    await settle();
    const { flow, seen } = reachable(w);
    assert.equal(flow.nodes.length, 2);
    assert.deepEqual([...seen].sort(), flow.nodes.map((n) => n.id).sort());
  } finally { dom.window.close(); }
});

test("the Steps list says which steps will never run and where each Decision path leads", async () => {
  const { dom, w, doc } = open();
  try {
    await settle();
    const steps = stepsHelpers(doc);
    await steps.addKind("agent");
    await steps.addKind("branch");
    await steps.addKind("approval", "If yes, after “Decision”");
    const cards = () => Array.from(doc.querySelectorAll("#fd-simple-body .fd-scard"));
    const decision = cards().find((c) => /Decision/.test(c.textContent));
    assert.match(decision.textContent, /If yes: step 3 “Approval”/);
    assert.match(decision.textContent, /If no: ends the flow/);
    assert.doesNotMatch(cards().map((c) => c.textContent).join(" "), /never run/);

    // Disconnect the approval from the Decision from the step settings.
    const decisionCard = decision; decisionCard.click(); await settle();
    const yes = Array.from(doc.querySelectorAll("#fd-props select")).find((s) => /If yes, go to/.test(s.closest(".field").textContent));
    yes.value = ""; yes.dispatchEvent(new w.Event("change")); await settle();
    const lonely = cards().find((c) => /Approval/.test(c.textContent));
    assert.match(lonely.textContent, /Not connected, so this step never runs/);
  } finally { dom.window.close(); }
});

test("the page offers no code boxes or developer wording", () => {
  const html = read("flow_designer.html"), js = read("flow_designer.js");
  for (const phrase of ["Params (JSON)", "Input data (JSON)", "Schedule expression (cron)", "POST /webhook/run", "_break",
    "saved flow id", "[webhooks]", "[flows]", "{{issue_body}}", "Fix invalid JSON", "Make start"]) {
    assert.ok(!html.includes(phrase) && !js.includes(phrase), phrase);
  }
});
