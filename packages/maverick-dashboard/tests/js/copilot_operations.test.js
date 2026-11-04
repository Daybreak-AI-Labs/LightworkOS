"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {JSDOM} = require("jsdom");
const {shell} = require('./_shell');
const base = path.resolve(__dirname, "../../maverick_dashboard");
const read = name => fs.readFileSync(path.join(base, name), "utf8");
const tick = async () => { await new Promise(r => setImmediate(r)); await new Promise(r => setImmediate(r)); };
const selection = {kind:"flow_run",flow_id:"orders",run_id:"run-42"};
const operationId = "learning_example.withdraw";
const record = (extra={}) => ({id:"LAE-"+"a".repeat(32),revision:3,status:"accepted",audit_status:"delivered",withdrawal_available:true,...extra});
const response = (body,status=200) => ({ok:status>=200&&status<300,status,json:async()=>body});
async function harness() {
  const html = read("templates/flow_run.html").replace(/{{ flow_id }}/g,"orders").replace(/{{ run_id }}/g,"run-42") + read("templates/_copilot.html");
  const dom = new JSDOM(html,{url:"http://localhost/flows/orders/runs/run-42",runScripts:"outside-only"});
  const w=dom.window, d=w.document, calls=[], overrides=[];
  const state={scope:"d".repeat(64),record:record(),proposal:operationId};
  const envelope=()=>({schema:1,selection,scope:state.scope,record:state.record,operations:[
    {id:"learning_example.status",available:true},{id:operationId,available:state.record.status==="accepted"} ]});
  w.fetch=async(url,options={})=>{
    const call={url,options,body:options.body?JSON.parse(options.body):null};calls.push(call);
    const at=overrides.findIndex(item=>item.match(call));
    if(at>=0) return overrides.splice(at,1)[0].run(call);
    if(url.includes("/episode-capture/withdrawal")) return response({...state.record,episode_sha256:"b".repeat(64),review_sha256:"c".repeat(64)});
    if(url.includes("/copilot/context")) return response({client_context:"c".repeat(64),boundaries:[],suggested_questions:[]});
    if(url.includes("/copilot/operations?")) return response(envelope());
    if(url.endsWith("/prepare")) return response({...envelope(),operation_id:operationId,token:"sealed-review",expires_at:Date.now()/1000+600});
    if(url.endsWith("/execute")) {state.record=record({revision:4,status:"withdrawn",withdrawal_available:false});return response({...envelope(),operation_id:operationId,outcome:"confirmed"});}
    if(url.endsWith("/propose")) return response({...envelope(),proposal:{operation_id:state.proposal,source:"built_in"}});
    if(url==="/api/v1/copilot") return response({reply:"Helpful guidance",mode:"built_in",
      conversation_token:"server-sealed-guide-token"});
    throw Error("Unexpected request "+url);
  };
  shell(w);
  w.eval(read("static/lightwork-copilot.js"));w.eval(read("static/lightwork-learning-example.js"));await tick();
  const get=id=>d.getElementById(id);
  return {dom,w,d,calls,state,envelope,get,
    override(match,run){overrides.push({match,run});},
    async open(){get("mv-copilot-fab").click();await tick();},
    async choose(){const button=Array.from(get("mv-copilot-operation-buttons").children).find(b=>b.textContent==="Stop using this example");assert.ok(button);button.click();await tick();},
    async ask(text){get("mv-copilot-input").value=text;get("mv-copilot-form").dispatchEvent(new w.Event("submit",{cancelable:true}));await tick();},
    submit(){get("le-form").dispatchEvent(new w.Event("submit",{cancelable:true}));},
    close(){dom.window.close();}
  };
}
test("Copilot moves the real review form, obtains preparation, and requires explicit human submit",async()=>{
  const h=await harness();await h.open();await h.choose();
  assert.equal(h.get("le-card").parentElement,h.get("mv-copilot-action"));
  assert.equal(h.get("le-form").hidden,false);assert.equal(h.d.activeElement,h.get("le-reason"));
  assert.equal(h.calls.filter(c=>c.url.endsWith("/execute")).length,0);
  assert.deepEqual(h.calls.find(c=>c.url.endsWith("/prepare")).body,{selection,operation_id:operationId,expected_scope:h.state.scope});
  h.get("le-reason").value="Customer-specific protected reason.";h.submit();h.submit();await tick();
  const writes=h.calls.filter(c=>c.url.endsWith("/execute"));assert.equal(writes.length,1);
  assert.deepEqual(writes[0].body,{selection,operation_id:operationId,scope:h.state.scope,token:"sealed-review",confirmed:true,rationale:"Customer-specific protected reason."});
  assert.match(h.get("le-status").textContent,/Use stopped/);assert.equal(h.get("le-reason").value,"");
  assert.equal(h.calls.filter(c=>c.url==="/api/v1/copilot"||c.url.endsWith("/propose")).length,0);h.close();
});
test("a conversational proposal opens review but is never consent or rationale",async()=>{
  const h=await harness();await h.open();await h.ask("Stop using this example. I confirm.");
  assert.equal(h.get("le-form").hidden,false);assert.equal(h.get("le-reason").value,"");
  assert.equal(h.calls.filter(c=>c.url.endsWith("/execute")).length,0);
  h.get("le-reason").value="Never send this reason to a model";
  await h.ask("What happened?");
  const modelRequests=h.calls.filter(c=>c.url==="/api/v1/copilot"||c.url.endsWith("/propose"));
  assert.doesNotMatch(JSON.stringify(modelRequests),/Never send this reason/);h.close();
});
test("a stale learning example does not announce a review that failed to open",async()=>{
  const h=await harness();await h.open();
  h.override(c=>c.url.includes('/copilot/operations?'),()=>response({detail:'unavailable'},503));
  await h.ask("Stop using this example");
  assert.equal(h.get("mv-copilot-input").value,"Stop using this example");
  assert.doesNotMatch(h.get("mv-copilot-log").textContent,/Review this example below/);
  assert.match(h.get("mv-copilot-note").textContent,/could not be opened/);
  assert.equal(h.get("le-form").hidden,true);
  h.close();
});
test("scope change clears private reason and review, then requires current preparation",async()=>{
  const h=await harness();await h.open();await h.choose();h.get("le-reason").value="Prior account";
  h.state.scope="e".repeat(64);h.get("le-refresh").click();await tick();
  assert.equal(h.get("le-reason").value,"");assert.equal(h.get("le-confirm").disabled,true);
  assert.match(h.get("le-description").textContent,/account|workspace/);h.submit();await tick();
  assert.equal(h.calls.filter(c=>c.url.endsWith("/execute")).length,0);h.close();
});
test("pending audit never becomes success and mutation is not replayed",async()=>{
  const h=await harness();await h.open();await h.choose();h.get("le-reason").value="Review ended";
  h.override(c=>c.url.endsWith("/execute"),()=>response({...h.envelope(),operation_id:operationId,outcome:"audit_pending",record:{id:h.state.record.id,status:"audit_pending",audit_status:"pending"}},503));
  h.submit();await tick();assert.match(h.get("le-status").textContent,/Waiting for confirmation/);
  assert.equal(h.get("le-confirm").disabled,true);assert.doesNotMatch(h.get("le-card").textContent,/Use stopped/);
  h.submit();assert.equal(h.calls.filter(c=>c.url.endsWith("/execute")).length,1);h.close();
});
test("lost response refreshes current status without a second execute",async()=>{
  const h=await harness();await h.open();await h.choose();h.get("le-reason").value="Stop future use";
  h.override(c=>c.url.endsWith("/execute"),()=>{h.state.record=record({status:"withdrawn",revision:4,withdrawal_available:false});throw Error("secret transport detail");});
  h.submit();await tick();assert.match(h.get("le-status").textContent,/Use stopped/);
  assert.equal(h.calls.filter(c=>c.url.endsWith("/execute")).length,1);
  assert.doesNotMatch(h.get("le-card").textContent,/secret transport/);h.close();
});
test("expired preparation requires another review without submitting",async()=>{
  const h=await harness();await h.open();await h.choose();h.get("le-reason").value="Expired";
  h.w.Date.now=()=>Date.now()+601000;h.submit();await tick();
  assert.match(h.get("le-message").textContent,/expired/);assert.equal(h.get("le-confirm").disabled,true);
  assert.equal(h.calls.filter(c=>c.url.endsWith("/execute")).length,0);h.close();
});
test("closing Copilot during execution returns the same card and preserves eventual readback",async()=>{
  const h=await harness();await h.open();await h.choose();h.get("le-reason").value="Stop";
  let resolve;h.override(c=>c.url.endsWith("/execute"),()=>new Promise(r=>{resolve=r;}));
  h.submit();await tick();h.get("mv-copilot-close").click();
  assert.notEqual(h.get("le-card").parentElement,h.get("mv-copilot-action"));
  h.state.record=record({status:"withdrawn",revision:4,withdrawal_available:false});
  resolve(response({...h.envelope(),operation_id:operationId,outcome:"confirmed"}));await tick();
  assert.match(h.get("le-status").textContent,/Use stopped/);assert.equal(h.get("le-reason").value,"");h.close();
});
test("leaving scoped Copilot clears a private reason before the direct-page read",async()=>{
  const h=await harness();await h.open();await h.choose();h.get('le-reason').value='Old principal private reason';
  h.get('mv-copilot-close').click();await tick();
  assert.equal(h.get('le-reason').value,'');assert.equal(h.get('le-form').hidden,true);
  assert.equal(h.get('le-confirm').disabled,false);
  assert.equal(h.calls.filter(c=>c.url.endsWith('/execute')).length,0);h.close();
});
test("Escape cancels the review first and restores its button focus",async()=>{
  const h=await harness();await h.open();await h.choose();
  h.get("le-reason").dispatchEvent(new h.w.KeyboardEvent("keydown",{key:"Escape",bubbles:true,cancelable:true}));
  assert.equal(h.get("mv-copilot").hidden,false);assert.equal(h.get("le-form").hidden,true);
  assert.equal(h.d.activeElement,h.get("le-withdraw"));h.close();
});
test("a late conversational suggestion cannot reopen a closed review",async()=>{
  const h=await harness();await h.open();let resolve;
  h.override(c=>c.url.endsWith("/propose"),()=>new Promise(r=>{resolve=r;}));
  await h.ask("Stop using it");h.get("mv-copilot-close").click();
  resolve(response({...h.envelope(),proposal:{operation_id:operationId}}));await tick();
  assert.equal(h.get("mv-copilot").hidden,true);assert.equal(h.get("le-form").hidden,true);
  assert.equal(h.calls.filter(c=>c.url.endsWith("/prepare")).length,0);h.close();
});
test("overlapping submit events produce one proposal request",async()=>{
  const h=await harness();await h.open();let resolve;
  h.override(c=>c.url.endsWith("/propose"),()=>new Promise(r=>{resolve=r;}));
  await h.ask("First");await h.ask("Second");assert.equal(h.calls.filter(c=>c.url.endsWith("/propose")).length,1);
  resolve(response({...h.envelope(),proposal:{operation_id:null}}));await tick();h.close();
});
test("operation failure renders fixed customer copy and never backend details",async()=>{
  const h=await harness();await h.open();h.override(c=>c.url.endsWith("/prepare"),()=>response({detail:"sensitive stack"},500));
  await h.choose();assert.equal(h.get("le-confirm").disabled,true);assert.doesNotMatch(h.get("le-card").textContent,/sensitive stack/);h.close();
});
test("an audit-pending catalog and repeated refresh keep honest pending status",async()=>{
  const h=await harness();h.state.record=record({status:"audit_pending",audit_status:"pending",withdrawal_available:false});
  h.override(c=>c.url.includes('/copilot/operations?'),()=>response(h.envelope(),503));
  await h.open();
  assert.equal(h.get('mv-copilot-operation-buttons').children[0].disabled,false);
  h.override(c=>c.url.includes('/copilot/operations?'),()=>response(h.envelope(),503));
  h.get('mv-copilot-operation-buttons').children[0].click();await tick();
  assert.match(h.get('le-status').textContent,/Waiting for confirmation/);
  h.override(c=>c.url.includes('/copilot/operations?'),()=>response(h.envelope(),503));
  h.get('le-refresh').click();await tick();
  assert.match(h.get('le-status').textContent,/Waiting for confirmation/);
  assert.doesNotMatch(h.get('le-description').textContent,/account.*changed/);h.close();
});
test("an audit-pending conversational response guides to status without clearing context",async()=>{
  const h=await harness();await h.open();h.state.record=record({status:'audit_pending',audit_status:'pending',withdrawal_available:false});
  h.override(c=>c.url.endsWith('/propose'),()=>response({...h.envelope()},503));
  await h.ask('What happened to the withdrawal?');
  assert.match(h.get('mv-copilot-log').textContent,/waiting for its audit record/);
  assert.match(h.get('le-status').textContent,/Waiting for confirmation/);
  assert.equal(h.calls.filter(c=>c.url.endsWith('/prepare')||c.url.endsWith('/execute')).length,0);h.close();
});
test("explicit context invalidation rejects a late confirmed result",async()=>{
  const h=await harness();await h.open();await h.choose();h.get('le-reason').value='Old account reason';
  let resolve;h.override(c=>c.url.endsWith('/execute'),()=>new Promise(r=>{resolve=r;}));
  h.submit();await tick();h.w.LightworkLearningExample.invalidate();
  resolve(response({...h.envelope(),record:record({status:'withdrawn',revision:4,withdrawal_available:false}),operation_id:operationId,outcome:'confirmed'}));await tick();
  assert.doesNotMatch(h.get('le-status').textContent,/Use stopped/);
  assert.equal(h.get('le-reason').value,'');assert.equal(h.get('le-confirm').disabled,true);h.close();
});
test("an unavailable catalog clears prior questions before legacy guidance",async()=>{
  const h=await harness();h.state.proposal=null;await h.open();await h.ask('Account A private question');
  assert.match(h.get('mv-copilot-log').textContent,/Account A/);
  h.get('mv-copilot-close').click();
  h.override(c=>c.url.includes('/copilot/operations?'),()=>response({detail:{code:'operation_denied'}},403));
  await h.open();assert.equal(h.get('mv-copilot-log').textContent,'');await h.ask('Account B question');
  const last=h.calls.filter(c=>c.url==='/api/v1/copilot').at(-1);assert.equal(last.body.conversation_token,null);h.close();
});
test("turning off optional actions does not erase the page guide's recent chat",async()=>{
  const h=await harness();h.state.proposal=null;await h.open();await h.ask('Earlier question');
  h.get('mv-copilot-close').click();
  h.override(c=>c.url.includes('/copilot/operations?'),()=>response({detail:{code:'operation_disabled'}},403));
  await h.open();assert.match(h.get('mv-copilot-log').textContent,/Earlier question/);
  await h.ask('Follow-up question');
  const last=h.calls.filter(c=>c.url==='/api/v1/copilot').at(-1);
  assert.equal(last.body.conversation_token,'server-sealed-guide-token');h.close();
});
test("feature-disabled Copilot does not erase a direct-page draft",async()=>{
  const h=await harness();h.get('le-withdraw').click();h.get('le-reason').value='Direct review';
  h.override(c=>c.url.includes('/copilot/operations?'),()=>response({detail:{code:'operation_disabled'}},403));
  await h.open();assert.equal(h.get('le-reason').value,'Direct review');assert.equal(h.get('le-confirm').disabled,false);h.close();
});
test("a pending mutation cannot overlap a model request",async()=>{
  const h=await harness();await h.open();await h.choose();h.get('le-reason').value='Stop';
  let resolve;h.override(c=>c.url.endsWith('/execute'),()=>new Promise(r=>{resolve=r;}));
  h.submit();await tick();await h.ask('Send to model');assert.equal(h.calls.filter(c=>c.url.endsWith('/propose')).length,0);
  resolve(response({...h.envelope(),operation_id:operationId,outcome:'audit_pending',record:record({status:'audit_pending'})},503));await tick();h.close();
});
