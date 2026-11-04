"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict");
const fs=require("node:fs"),path=require("node:path");
const {JSDOM}=require("jsdom");
const {shell} = require('./_shell');
const folder=path.resolve(__dirname,"../../maverick_dashboard/templates");
const template=fs.readFileSync(path.join(folder,"connections.html"),"utf8");
const script=fs.readFileSync(path.join(folder,"../static/lightwork-connections.js"),"utf8");
async function fixture(records=[],intercept=()=>undefined) {
  const html=template.replace(/\{%[\s\S]*?%\}/g, '').replace(/\{\{[\s\S]*?\}\}/g, '').replace('data-can-manage=""', 'data-can-manage="true"');
  const dom=new JSDOM(html,{url:"https://lightwork.example/connections",runScripts:"outside-only"});
  const {window}=dom,calls=[];window.mvConfirm=async()=>true;
  window.lightworkConnectionImpact={review:async()=> 'c'.repeat(64)};
  window.fetch=async(url,options={})=>{calls.push({url,...options});const result=await intercept(url,options);if(result!==undefined)return result;return new Response(JSON.stringify(options.method==="POST"?{name:JSON.parse(options.body).name,revision:"b".repeat(32)}:url.endsWith("/catalog")?{connectors:[]}:{connections:records,context:"fixture-account"}),{headers:{"Content-Type":"application/json"}});};
  const el=id=>window.document.getElementById("cx-"+id);
  async function settle(){for(let i=0;i<15;i++)await new Promise(done=>setImmediate(done));}
  function change(id,value){el(id).value=value;el(id).dispatchEvent(new window.Event("change",{bubbles:true}));}
  shell(window);
  window.eval(script);await settle();return{window,calls,el,change,settle};
}
test("AWS discovery credentials use guided fields, stay outside drafts, and clear after acknowledged save",async t=>{
  const ui=await fixture();t.after(()=>ui.window.close());ui.change("preset","aws_s3");
  assert.equal(ui.el("form").dataset.draftRecovery,"off");assert.equal(ui.el("aws").hidden,false);
  assert.equal(ui.el("save-test").hidden,true);ui.el("base").value="https://bucket.s3.us-east-1.amazonaws.com";
  // The region accepts a validated value and suggests supported examples.
  const regionPicker=ui.el("aws-region");assert.equal(regionPicker.tagName,"INPUT");
  assert.equal(regionPicker.getAttribute("list"),"cx-aws-regions");
  for(const [name,value] of Object.entries({access:"synthetic-access",secret:"synthetic-secret",region:"us-east-1",session:"synthetic-session"}))ui.el("aws-"+name).value=value; // pragma: allowlist secret -- synthetic credential fixture
  // Even a programmatic trigger cannot substitute a generic root probe for a scope test.
  ui.el("save-test").click();await ui.settle();
  const writes=ui.calls.filter(call=>call.method==="POST");assert.equal(writes.length,1);assert.equal(writes[0].url,"/api/v1/connections");
  const body=JSON.parse(writes[0].body);assert.equal(body.connector,"aws_s3");assert.equal(body.access,"owner");
  assert.deepEqual(JSON.parse(body.token),{access_key_id:"synthetic-access",secret_access_key:"synthetic-secret",region:"us-east-1",session_token:"synthetic-session"});
  for(const name of ["access","secret","region","session"])assert.equal(ui.el("aws-"+name).value,"");
  assert.equal(ui.el("token").value,"");
});
test("incomplete AWS credentials fail visibly before any save and retain the entered value",async t=>{
  const ui=await fixture();t.after(()=>ui.window.close());ui.change("preset","aws_s3");ui.el("aws-secret").value="synthetic-secret"; // pragma: allowlist secret -- synthetic credential fixture
  ui.el("form").dispatchEvent(new ui.window.Event("submit",{cancelable:true,bubbles:true}));await ui.settle();
  assert.equal(ui.calls.some(call=>call.method==="POST"),false);assert.match(ui.el("msg").textContent,/region together/);
  assert.equal(ui.el("aws-secret").value,"synthetic-secret");
});
test("editing a discovery connection preserves its sealed token and revision and does not claim scope readiness",async t=>{
  const record={name:"bucket",connector:"aws_s3",base_url:"https://bucket.s3.us-east-1.amazonaws.com",has_token:true,revision:"a".repeat(32),access:"owner",allowed_principals:[],last_test:{authenticated:true}};
  const ui=await fixture([record]);t.after(()=>ui.window.close());
  assert.doesNotMatch(ui.el("list").textContent,/readiness verified/);assert.match(ui.el("list").textContent,/Check exact source access in Privacy scanning/);
  const buttons=ui.el("list").querySelectorAll("button");assert.equal(buttons[1].textContent,"Check source access");buttons[0].click();
  ui.el("form").dispatchEvent(new ui.window.Event("submit",{cancelable:true,bubbles:true}));await ui.settle();
  const body=JSON.parse(ui.calls.find(call=>call.method==="POST").body);assert.equal(body.expected_revision,record.revision);assert.equal(Object.hasOwn(body,"token"),false);
});

test('account-setup denial clears the legacy secret form and a late connection list cannot restore private rows',async t=>{let held=false,release;const record={name:'private',connector:'slack',has_token:true,revision:'a'.repeat(32)};const ui=await fixture([record],(url,options)=>held&&!options.method?new Promise(resolve=>release=resolve):undefined);t.after(()=>ui.window.close());ui.el('token').value='synthetic-unsaved-token';held=true;ui.window.document.dispatchEvent(new ui.window.Event('lightwork:connection-saved'));await ui.settle();ui.window.document.dispatchEvent(new ui.window.Event('lightwork:connection-access-lost'));release(new Response(JSON.stringify({connections:[record]})));await ui.settle();assert.equal(ui.el('list').textContent,'');assert.equal(ui.el('token').value,'');assert.equal(ui.el('token').disabled,true);ui.el('form').dispatchEvent(new ui.window.Event('submit',{cancelable:true,bubbles:true}));await ui.settle();assert.equal(ui.calls.some(call=>call.method==='POST'),false);});
