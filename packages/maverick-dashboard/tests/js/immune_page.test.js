"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');

const source = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-immune-console.js"), "utf8");
const html = `<div id="mv-toasts"></div><div id="mv-toasts-alert"></div><div id="ic-root" data-console="immune" data-api-url="/api/v1/immune/summary" data-can-admin="true" data-can-global-admin="true">
<p id="ic-status"></p><p id="ic-error"></p>
<strong id="ic-trifectas"></strong><strong id="ic-exfil"></strong><strong id="ic-ifc-events"></strong><strong id="ic-replays"></strong>
<table><tbody id="ic-comp-rows"></tbody></table><p id="ic-ifc-mode"></p><table><tbody id="ic-ifc-rows"></tbody></table>
<span id="ic-over-state"></span><div id="ic-over-controls"></div>
<form id="ic-canary-form" hidden><select id="ic-canary-class" name="decision_class"><option value="">Any</option></select><select name="count"><option value="1">1</option></select><button type="submit">Plant</button></form>
<form id="ic-drill-form"><select id="ic-drill-person" name="person"><option value="">Choose</option></select><select id="ic-drill-class" name="decision_class"><option value="">Choose</option></select>
<input type="radio" name="passed" value="true"><input type="radio" name="passed" value="false"><button type="submit">Save</button></form>
<table><tbody id="ic-over-rows"></tbody></table><table><tbody id="ic-drill-rows"></tbody></table>
<span id="ic-twin-state"></span><div id="ic-twin-controls"></div><table><tbody id="ic-recorded-rows"></tbody></table>
<button id="ic-awareness">Check</button><table><tbody id="ic-twin-rows"></tbody></table>
</div>`;

const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
const SUMMARY = {
  goal_titles: { "7": "Pay March invoices" },
  composition: { available: true, by_kind: { trifecta: 1 }, trifectas: [{ path: ["sales_bot"], witness: { sensitive: ["sales_bot", "crm_read"], mutate: ["sales_bot", "crm_write"], external: ["sales_bot", "email_send"] }, sink_risk: "high" }] },
  ifc: { available: true, mode: "block", events: 1, recent: [{ goal_id: 7, tool: "email_send", labels: ["data:sql_query"], explicit: [], outcome: "blocked" }] },
  oversight: { available: true, canaries_enabled: false, canary: [{ person: "user:amy", person_label: "Amy", class: "wire_funds", caught: 3, missed: 1, assured: 0.41, authority: false }], drill: [] },
  twin: { available: true, recording: true, replays: [{ production_goal: 7, twin_goal: 9, watched: false, twin_status: "done", served: 3, recorded: 3, approximate: 0, unmatched: 0, result_similarity: 0.93 }] }
};
const CHOICES = { canaries: false, twin_record: true, decision_classes: ["wire_funds"], recorded_goals: [{ id: 7, title: "Pay March invoices", status: "done" }], people: [{ value: "user:amy", label: "Amy" }] };

async function fixture({ confirm = true, down = false, markup = html } = {}) {
  const dom = new JSDOM(markup, { url: "https://lightwork.example/immune", runScripts: "outside-only" });
  const { window } = dom;
  const calls = [];
  const confirms = [];
  window.mvConfirm = async (message) => { confirms.push(message); return confirm; };
  window.mvErrorText = (failure, action) => `Could not ${action}.`;
  window.mvHuman = (v) => { const s = String(v).replace(/_/g, " "); return s.charAt(0).toUpperCase() + s.slice(1); };
  window.mvToast = () => {};
  window.fetch = async (url, options = {}) => {
    calls.push({ url, ...options });
    if (down && url.endsWith("/summary")) return json({ detail: "unavailable" }, 503);
    if (url.endsWith("/summary")) return json(SUMMARY);
    if (url.endsWith("/choices")) return json(CHOICES);
    if (url.endsWith("/settings")) return json({ canaries: true, twin_record: true });
    if (options.method === "DELETE") return json({ deleted: true });
    return json({});
  };
  const settle = async () => { for (let i = 0; i < 20; i++) await new Promise((done) => setImmediate(done)); };
  shell(window);
  window.eval(source);
  await settle();
  return { window, doc: window.document, calls, confirms, settle };
}

test("summary renders with task titles, names and plain labels", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  assert.match(ui.doc.getElementById("ic-comp-rows").textContent, /Email send \(Sales bot\)/);
  assert.match(ui.doc.getElementById("ic-ifc-rows").textContent, /Pay March invoices/);
  assert.match(ui.doc.getElementById("ic-ifc-mode").textContent, /blocked from leaving/);
  assert.match(ui.doc.getElementById("ic-over-rows").textContent, /Amy/);
  assert.match(ui.doc.getElementById("ic-twin-rows").textContent, /93%/);
  assert.equal(ui.doc.getElementById("ic-drill-person").options.length, 2);
  assert.doesNotMatch(ui.doc.body.textContent, /user:amy|data:sql_query/);
});

test("turning reviewer tests on asks first and saves the switch", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  const on = [...ui.doc.querySelectorAll("#ic-over-controls button")].find((b) => /Turn reviewer tests on/.test(b.textContent));
  on.click(); await ui.settle();
  assert.equal(ui.confirms.length, 1);
  const call = ui.calls.find((c) => c.url.endsWith("/immune/settings"));
  assert.deepEqual(JSON.parse(call.body), { canaries: true });
});

test("deleting a recording leaves at once with Undo, and Undo sends nothing", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  const del = [...ui.doc.querySelectorAll("#ic-recorded-rows button")].find((b) => b.textContent === "Delete recording");
  const row = del.closest("tr");
  del.click(); await ui.settle();
  assert.equal(ui.confirms.length, 0, "one action: no question first");
  assert.equal(row.hidden, true);
  const toast = ui.doc.querySelector(".mv-toast--undo");
  assert.match(toast.textContent, /Recording for .* deleted\. Past re-run results are kept\./);
  toast.querySelector("button").click(); await ui.settle();
  assert.equal(row.hidden, false);
  assert.equal(ui.calls.some((c) => c.method === "DELETE"), false);
});

test("a drill result posts the chosen person, kind and result", async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  const form = ui.doc.getElementById("ic-drill-form");
  form.elements.person.value = "user:amy";
  form.elements.decision_class.value = "wire_funds";
  form.querySelector("input[value=false]").checked = true;
  form.dispatchEvent(new ui.window.Event("submit", { cancelable: true })); await ui.settle();
  const call = ui.calls.find((c) => c.url.endsWith("/immune/drills"));
  assert.deepEqual(JSON.parse(call.body), { person: "user:amy", decision_class: "wire_funds", passed: false });
});

test("a summary that cannot load leaves no table on Loading", async (t) => {
  const loading = html.replace(/<tbody id="(ic-[a-z-]+)"><\/tbody>/g, '<tbody id="$1"><tr><td colspan="5">Loading.</td></tr></tbody>');
  const ui = await fixture({ down: true, markup: loading });
  t.after(() => ui.window.close());
  const bodies = [...ui.doc.querySelectorAll("tbody")];
  assert.ok(bodies.length >= 6);
  for (const body of bodies) {
    assert.doesNotMatch(body.textContent, /Loading/);
    assert.match(body.textContent, /Could not be loaded\. Reload the page to try again\./);
  }
});
