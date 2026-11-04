"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const {JSDOM} = require("jsdom");
const {shell} = require("./_shell");
const script = fs.readFileSync(path.resolve(__dirname,"../../maverick_dashboard/static/lightwork-action-center.js"),"utf8");
const tick = () => new Promise(resolve=>setImmediate(resolve));
function value(extra={}) {
  return {context:"current-account", revision:3, items:[{id:"item1",kind:"assessment",title:"Review <script>alert(1)</script>",assignment:"mine",read:false,overdue:true,due_at:10,reason:"Review due",assessment_id:"assessment-1",source_version:"a".repeat(64),snoozed:false}],
    coverage:[{kind:"assessment",status:"current"},{kind:"approval",status:"unavailable"}],
    counts:{unread:1,overdue:1,snoozed:0},total:1,limit:50,has_more:false, ...extra};
}
function reconciliation() {
  return {
    schema:"lightwork.vendor-onboarding.reconciliation-summary.v1",
    attempted_action:{operation_id:"VOP-"+"1".repeat(32),action:"jira.create",attempt_count:1,
      started_at:80,target:{provider:"jira",project:"VEND"}},
    known_observations:[
      {kind:"execution_attempt",state:"recorded",count:1,observed_at:80},
      {kind:"provider_receipt",state:"not_recorded"},
      {kind:"authoritative_readback",state:"no_match",match_count:0,observed_at:85},
    ],
    uncertainty:{state:"unresolved",reason:"no_matching_effect_observed",
      explanation:"No matching Jira task was observed; absence is not proof of no effect."},
    safe_next_check:{kind:"check_status",mode:"read_only",label:"Check the original Jira destination again"},
    responsible_operator:{principal:"user:alice",business_owner:"procurement"},
    resolution:{automatic_compensation_supported:false,unreviewed_replacement_allowed:false,
      requires_separate_review:true,explanation:"Any supported resolution requires a separate reviewed action."},
  };
}
async function setup(replies) {
  const dom = new JSDOM(`<div id="action-center" data-context="current-account"><form id="ac-filters"><select name="view"><option value="active">Active</option><option value="snoozed">Snoozed</option></select><select name="kind"><option value="all">All</option></select><select name="assignment"><option value="all">All</option></select><button type="submit">Refresh</button></form><div id="ac-items"></div><ul id="ac-coverage"></ul><p id="ac-summary"></p><p id="ac-status"></p><p id="ac-page"></p><button id="ac-previous">Previous</button><button id="ac-next">Next</button></div>`, {url:"https://lightwork.test", runScripts:"outside-only"});
  const w = dom.window, calls = [], d = w.document;
  w.fetch = async (url, options) => {
    calls.push({url, options});
    const result = replies.shift();
    if (result instanceof Error) throw result;
    if (typeof result === "function") return result();
    return {ok:true, status:200, json:async()=>result};
  };
  shell(w); w.eval(script); await tick();
  return {dom,w,d,calls,button:text=>[...d.querySelectorAll("button")].find(el=>el.textContent===text)};
}

test("inbox escapes source titles, reports missing sources, and opens the governed review", async () => {
  const ui = await setup([value()]);
  assert.equal(ui.d.querySelector("script"), null);
  assert.match(ui.d.getElementById("ac-coverage").textContent,/Approvals could not be loaded/);
  assert.match(ui.d.getElementById("ac-summary").textContent,/1 overdue/);
  let reviewed;
  ui.w.mvAssessmentReview = {open:id=>{reviewed=id;}};
  ui.button("Review assessment").click();
  assert.equal(reviewed,"assessment-1");
  assert.equal(ui.calls.length,1);
  assert.equal(ui.calls[0].options.headers["X-Lightwork-Action-Context"],"current-account");
  ui.dom.window.close();
});

test("uncertain external action explains observations and offers only a read-only check", async () => {
  const item = {
    id:"reconciliation1", kind:"vendor_reconciliation", title:"Resolve uncertain Jira task for Northstar AI",
    assignment:"mine", read:false, overdue:false, reason:"No matching Jira task was observed; absence is not proof of no effect.",
    href:"/third-party/vendor-onboarding?case=VON-uncertain", source_version:"b".repeat(64), snoozed:false,
    reconciliation:reconciliation()
  };
  const ui = await setup([value({items:[item],coverage:[{kind:"vendor_reconciliation",status:"current"}],
    counts:{unread:1,overdue:0,snoozed:0}})]);
  const text = ui.d.getElementById("ac-items").textContent;
  assert.match(text,/What Lightwork tried: Create a Jira issue/);
  assert.match(text,/Checked Jira: no matching issue found · 0 matches/);
  assert.match(text,/read-only and cannot create another Jira task/);
  assert.match(text,/Who looks after this: alice/);
  assert.match(text,/separate reviewed action/);
  assert.equal(ui.d.querySelector("img"),null);
  assert.equal(ui.d.querySelector("a.btn--primary").getAttribute("href"),item.href);
  ui.dom.window.close();
});

test("known multiple matches retain a lower bound without claiming an exact count", async () => {
  const detail = reconciliation();
  detail.known_observations[2] = {kind:"authoritative_readback",state:"multiple_matches",
    match_count_lower_bound:3,observed_at:85};
  detail.uncertainty = {state:"unresolved",reason:"multiple_matching_effects_observed",
    explanation:"At least three Jira tasks may match, so no result was selected."};
  detail.safe_next_check = {kind:"review_ambiguity",mode:"read_only",
    label:"Review possible Jira results before any separate resolution"};
  const item = {id:"reconciliation2",kind:"vendor_reconciliation",title:"Resolve uncertain Jira task",
    assignment:"mine",read:false,overdue:false,reason:detail.uncertainty.explanation,
    href:"/third-party/vendor-onboarding?case=VON-uncertain",source_version:"b".repeat(64),snoozed:false,
    reconciliation:detail};
  const ui = await setup([value({items:[item],coverage:[{kind:"vendor_reconciliation",status:"current"}],
    counts:{unread:1,overdue:0,snoozed:0}})]);
  assert.match(ui.d.getElementById("ac-items").textContent,/at least 3 matches/);
  assert.doesNotMatch(ui.d.getElementById("ac-items").textContent,/multiple matches · 3 matches/i);
  ui.dom.window.close();
});

test("lost Jira authority offers the in-app connection path and no retry write control", async () => {
  const detail = reconciliation();
  detail.uncertainty = {state:"unresolved",reason:"current_connection_access_unavailable",
    explanation:"Current Jira access is unavailable; no provider request was made."};
  detail.safe_next_check = {kind:"restore_access",mode:"read_only",
    label:"Restore the original Jira connection access, then check status",href:"/connections"};
  const item = {id:"reconciliation3",kind:"vendor_reconciliation",title:"Resolve uncertain Jira task",
    assignment:"mine",read:false,overdue:false,reason:detail.uncertainty.explanation,
    href:"/third-party/vendor-onboarding?case=VON-uncertain",source_version:"c".repeat(64),snoozed:false,
    reconciliation:detail};
  const ui = await setup([value({items:[item],coverage:[{kind:"vendor_reconciliation",status:"current"}],
    counts:{unread:1,overdue:0,snoozed:0}})]);
  const links = [...ui.d.querySelectorAll("a")];
  assert.equal(links.find(link=>link.textContent === "Resolve connection access").getAttribute("href"),"/connections");
  assert.equal(ui.button("Retry"),undefined);
  assert.match(ui.d.getElementById("ac-items").textContent,/read-only and cannot create another Jira task/);
  assert.equal(ui.calls.length,1);
  ui.dom.window.close();
});

test("malformed reconciliation projections clear the queue without rendering private fields or controls", async () => {
  const mutations = [
    detail=>{detail.known_observations[0]=null;},
    detail=>{detail.known_observations[2].provider_body="PRIVATE_PROVIDER_BODY";},
    detail=>{detail.attempted_action.target.project="VEND<img src=x>";},
    detail=>{detail.resolution.requires_separate_review=false;},
  ];
  for (const mutate of mutations) {
    const detail = reconciliation(); mutate(detail);
    const item = {id:"broken",kind:"vendor_reconciliation",title:"Uncertain action",assignment:"mine",
      read:false,overdue:false,reason:"Uncertain",href:"/vendor",source_version:"d".repeat(64),snoozed:false,
      reconciliation:detail};
    const ui = await setup([value({items:[item],coverage:[{kind:"vendor_reconciliation",status:"current"}],
      counts:{unread:1,overdue:0,snoozed:0}})]);
    assert.equal(ui.d.querySelectorAll("article").length,0);
    assert.match(ui.d.getElementById("ac-status").textContent,/details were incomplete/i);
    assert.doesNotMatch(ui.d.body.textContent,/PRIVATE_PROVIDER_BODY/);
    assert.equal(ui.d.querySelector("img"),null);
    assert.equal(ui.calls.length,1);
    ui.dom.window.close();
  }
});

test("read preference is an explicit context/version-bound action and repeated clicks do not duplicate it", async () => {
  let resolve;
  const ui = await setup([value(), ()=>new Promise(done=>{resolve=done;}), value()]);
  const button = ui.button("Mark read"); button.click(); button.click();
  assert.equal(ui.calls.length,2);
  const body = JSON.parse(ui.calls[1].options.body);
  assert.equal(body.expected_revision,3);
  assert.equal(body.source_version,"a".repeat(64));
  assert.equal(body.read,true);
  assert.equal(body.snoozed_until,0);
  assert.equal(button.disabled,true);
  resolve({ok:true,status:200,json:async()=>({revision:4})}); await tick(); await tick();
  assert.equal(ui.calls.length,3);
  assert.equal(ui.d.getElementById("action-center").getAttribute("aria-busy"),"false");
  ui.dom.window.close();
});

test("lost preference acknowledgement keeps the action visible and never retries automatically", async () => {
  const ui = await setup([value(),new TypeError("Failed to fetch")]);  // how a browser reports a lost connection
  ui.button("Snooze for one day").click(); await tick();
  assert.equal(ui.calls.length,2);
  assert.match(ui.d.getElementById("ac-status").textContent,/could not be reached/);
  assert.equal(ui.d.querySelectorAll("article").length,1);
  const body = JSON.parse(ui.calls[1].options.body);
  assert.ok(body.snoozed_until>Date.now()/1000+86000);
  ui.dom.window.close();
});

test("account mismatch removes stale business content and requires reload", async () => {
  const ui = await setup([value(),value({context:"another-account"})]);
  ui.d.getElementById("ac-filters").dispatchEvent(new ui.w.Event("submit",{bubbles:true,cancelable:true}));
  await tick();
  assert.equal(ui.d.querySelectorAll("article").length,0);
  assert.match(ui.d.getElementById("ac-status").textContent,/account or workspace changed/);
  ui.dom.window.close();
});

test("filters reset pagination and empty partial coverage does not claim the queue is clear", async () => {
  const ui = await setup([value({has_more:true,total:51}), value({items:[],total:0})]);
  ui.d.getElementById("ac-filters").elements.view.value="snoozed";
  ui.d.getElementById("ac-filters").dispatchEvent(new ui.w.Event("change",{bubbles:true}));
  await tick();
  assert.match(ui.calls[1].url,/view=snoozed/);
  assert.match(ui.calls[1].url,/offset=0/);
  assert.match(ui.d.getElementById("ac-items").textContent,/incomplete or unavailable/);
  ui.dom.window.close();
});

for (const code of [401,403]) test(`HTML ${code} clears private actions before parsing and locks the expired view`,async()=>{
  let parsed=false;const ui=await setup([value(),()=>({ok:false,status:code,json:async()=>{parsed=true;throw new Error('HTML');}})]);
  ui.button('Mark read').click();await tick();
  assert.equal(parsed,false);assert.equal(ui.d.getElementById('ac-items').textContent,'');
  assert.equal(ui.d.getElementById('ac-summary').textContent,'');assert.equal(ui.button('Refresh').disabled,true);
  ui.d.getElementById('ac-filters').dispatchEvent(new ui.w.Event('submit',{cancelable:true}));await tick();assert.equal(ui.calls.length,2);
  assert.match(ui.d.getElementById('ac-status').textContent,/sign in|access.*changed/i);ui.w.close();
});

test('keyboard position follows the acknowledged updated preference control',async()=>{
  const updated=value();updated.items[0].read=true;
  const ui=await setup([value(),{revision:4},updated]);const button=ui.button('Mark read');button.focus();button.click();await tick();await tick();
  assert.equal(ui.d.activeElement,ui.button('Mark unread'));ui.w.close();
});

test('removing the final filtered item focuses the empty result status',async()=>{
  const ui=await setup([value(),{revision:4},value({items:[],total:0})]);ui.button('Mark read').focus();ui.button('Mark read').click();await tick();await tick();
  assert.equal(ui.d.activeElement,ui.d.getElementById('ac-status'));ui.w.close();
});

test("a module that is turned off is not reported as a load error", async () => {
  const ui = await setup([value({coverage:[{kind:"assessment",status:"current"},{kind:"connection_attention",status:"disabled"}],
    items:[], counts:{unread:0,overdue:0,snoozed:0}, total:0})]);
  assert.equal(ui.d.getElementById("ac-coverage").textContent, "");
  assert.match(ui.d.getElementById("ac-items").textContent, /all caught up/);
  ui.dom.window.close();
});
