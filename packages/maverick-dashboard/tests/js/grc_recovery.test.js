"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {JSDOM} = require("jsdom");
const script = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-grc-recovery.js"), "utf8");
const tick = () => new Promise(resolve => setImmediate(resolve));
function setup(replies) {
  const dom = new JSDOM(`<form id="gov-grc-recovery"><select name="delivery" required><option value="">Choose</option><option value="held-record" data-revision="3" selected>Finding</option></select><input name="remote_id"><textarea name="note" required></textarea><button type="button" id="gov-grc-inspect">Inspect</button><button type="button" id="gov-grc-confirm" disabled>Confirm</button><button type="button" id="gov-grc-keep-held">Keep held</button><div id="gov-grc-comparison" tabindex="-1"></div><p id="gov-grc-recovery-status" role="status"></p></form>`, {url:"https://lightwork.test", runScripts:"outside-only"});
  const calls = [], w = dom.window, d = w.document;
  w.fetch = async (url, options) => {
    calls.push({url, body:JSON.parse(options.body)});
    const value = replies.shift();
    if (value instanceof Error) throw value;
    return typeof value === "function" ? value() : {ok:true, status:200, json:async()=>value};
  };
  w.eval(script);
  return {dom, w, d, calls, form:d.getElementById("gov-grc-recovery"), click:async id=>{d.getElementById(id).click(); await tick();}};
}
const result = matched => ({revision:4, inspection:{matched, evidence_sha256:"a".repeat(64), remote_id:matched?"sys0001":null, detail:matched?"Exactly one record matches.":"No exact match. Delivery remains held.", fields:[{name:"description", expected:"<img src=x onerror=alert(1)>", actual:"<img src=x onerror=alert(1)>", matches:matched}]}});

test("review renders safe comparisons, binds the current revision and requires a note before explicit confirmation", async () => {
  const ui = setup([result(true), {revision:5,status:"delivered"}]);
  await ui.click("gov-grc-inspect");
  assert.equal(ui.calls.length, 1);
  assert.equal(ui.d.getElementById("gov-grc-confirm").disabled, false);
  assert.equal(ui.d.querySelector("img"), null);
  assert.equal(ui.d.activeElement.id, "gov-grc-comparison");
  await ui.click("gov-grc-confirm");
  assert.equal(ui.calls.length, 1);
  ui.form.elements.note.value = "Reviewed the record.";
  await ui.click("gov-grc-confirm");
  assert.equal(ui.calls[1].body.expected_revision, 4);
  assert.equal(ui.calls[1].body.evidence_sha256, "a".repeat(64));
  assert.equal(ui.form.elements.delivery.value, "");
  assert.match(ui.d.getElementById("gov-grc-recovery-status").textContent, /No content was resent/);
  ui.dom.window.close();
});

test("unmatched delivery only permits a review note and keeps the held record", async () => {
  const ui = setup([result(false), {revision:5,status:"dispatch_unconfirmed"}]);
  await ui.click("gov-grc-inspect");
  assert.equal(ui.d.getElementById("gov-grc-confirm").disabled, true);
  ui.form.elements.note.value = "Waiting for provider confirmation.";
  await ui.click("gov-grc-keep-held");
  assert.equal(Object.hasOwn(ui.calls[1].body,"evidence_sha256"), false);
  assert.equal(ui.form.elements.delivery.value, "held-record");
  assert.match(ui.d.getElementById("gov-grc-recovery-status").textContent, /remains held/);
  ui.dom.window.close();
});

test("lost acknowledgement retains the note and invalidates the previous comparison without automatic retries", async () => {
  const ui = setup([result(true), new Error("Connection lost; reload the delivery.")]);
  await ui.click("gov-grc-inspect");
  ui.form.elements.note.value = "Retain this review.";
  await ui.click("gov-grc-confirm");
  await tick();
  assert.equal(ui.calls.length, 2);
  assert.equal(ui.form.elements.note.value, "Retain this review.");
  assert.equal(ui.form.elements.note.disabled, false);
  assert.equal(ui.d.getElementById("gov-grc-confirm").disabled, true);
  assert.equal(ui.form.getAttribute("aria-busy"), "false");
  assert.equal(ui.d.getElementById("gov-grc-comparison").textContent, "");
  ui.dom.window.close();
});

for (const code of [401,403]) test(`permission failure ${code} clears private comparison before parsing and requires reload`, async () => {
  const ui = setup([result(true), () => ({ok:false,status:code,json:async()=>{throw new Error("HTML sign-in response");}})]);
  await ui.click("gov-grc-inspect");
  ui.form.elements.note.value = "Private review note";
  ui.form.elements.remote_id.value = "private-record-id";
  await ui.click("gov-grc-confirm");
  assert.equal(ui.d.getElementById("gov-grc-comparison").textContent, "");
  assert.equal(ui.form.elements.note.value, "");
  assert.equal(ui.form.elements.remote_id.value, "");
  assert.equal(ui.form.elements.delivery.value, "");
  assert.doesNotMatch(ui.form.textContent, /Finding|private-record-id/);
  assert.equal(ui.d.getElementById("gov-grc-confirm").disabled, true);
  assert.equal(ui.d.getElementById("gov-grc-inspect").disabled, true);
  assert.match(ui.d.getElementById("gov-grc-recovery-status").textContent, /session or permissions changed/);
  await ui.click("gov-grc-inspect");
  assert.equal(ui.calls.length, 2);
  ui.dom.window.close();
});

test("editing the external record discards the previous verification", async () => {
  const ui = setup([result(true)]);
  await ui.click("gov-grc-inspect");
  ui.form.elements.remote_id.value = "sys-other";
  ui.form.elements.remote_id.dispatchEvent(new ui.w.Event("input"));
  assert.equal(ui.d.getElementById("gov-grc-confirm").disabled, true);
  assert.equal(ui.d.getElementById("gov-grc-comparison").textContent, "");
  assert.equal(ui.calls.length, 1);
  ui.dom.window.close();
});
