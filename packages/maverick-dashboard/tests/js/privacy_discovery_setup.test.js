"use strict";
const {test}=require("node:test"), assert=require("node:assert/strict");
const fs=require("node:fs"), path=require("node:path");
const {JSDOM}=require("jsdom");
const {shell: loadShell} = require("./_shell");
const folder=path.resolve(__dirname,"../../maverick_dashboard");
const markup=fs.readFileSync(path.join(folder,"templates/privacy_data_discovery.html"),"utf8").replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,"");
const helpers=fs.readFileSync(path.join(folder,"static/lightwork-record-workflows.js"),"utf8");
const source=fs.readFileSync(path.join(folder,"static/lightwork-privacy-data-discovery.js"),"utf8");
const reference="connection:cmdb:"+"a".repeat(32);
const key={name:"privacy-inventory",revision:2,reference:"evidence-key:privacy-inventory:2"};
const setup={providers:[{provider:"servicenow_cmdb",kind:"structured",resource_ref_contract:"one_admitted_cmdb_table"}],
  connections:[{name:"CMDB <img src=x>",provider:"servicenow_cmdb",origin:"https://tenant.service-now.com",reference}],evidence_keys:[key]};
const saved={source_id:"customers",kind:"structured",provider:"servicenow_cmdb",origin:"https://tenant.service-now.com",resource_ref:"cmdb_ci",credential_env:reference,evidence_key_env:key.reference,revision:4,state:"active"};

async function fixture(intercept=()=>undefined, sources=[]) {
  const dom=new JSDOM(markup,{url:"https://lightwork.example/privacy/data-discovery",runScripts:"outside-only"}), {window}=dom;
  const document=window.document,root=document.getElementById("pdd-root"),calls=[];
  Object.assign(root.dataset,{canAdmin:"true",canOperate:"true",canAudit:"true",featureEnabled:"true",apiBase:"/api/v1/privacy/data-discovery"});
  window.TextEncoder=TextEncoder;window.TextDecoder=TextDecoder;
  const ui={answer:true,confirms:[]};
  window.mvConfirm=async message=>{ui.confirms.push(message);return ui.answer;};
  window.mvForm=async()=>null;
  window.HTMLElement.prototype.scrollIntoView=()=>{};
  window.fetch=async(url,opts={})=>{
    const call={url:new URL(url,window.location),method:"GET",...opts};calls.push(call);
    let body=await intercept(call);
    const p=call.url.pathname;
    if(body===undefined) body=p.endsWith("/setup")?setup:p.endsWith("/sources")?{items:sources}:p.endsWith("/jobs")||p.endsWith("/reports")||p.endsWith("/reviews")?{items:[]}:{};
    return new Response(JSON.stringify(body),{headers:{"Content-Type":"application/json"}});
  };
  loadShell(window);window.eval(helpers);window.eval(source);
  async function settle(){for(let i=0;i<25;i++)await new Promise(done=>setImmediate(done));}
  const el=id=>document.getElementById("pdd-"+id);
  function rowButton(container,label){return [...el(container).querySelectorAll("button")].find(b=>b.textContent===label);}
  await settle();
  return Object.assign(ui,{dom,window,document,calls,el,settle,rowButton});
}

test("adding a source uses a saved connection and protection key, never a credential value",async t=>{
  const ui=await fixture();t.after(()=>ui.window.close());
  ui.el("new-source").click();await ui.settle();
  assert.equal(ui.el("source-panel").hidden,false);
  const providerSelect=ui.el("provider");providerSelect.value="servicenow_cmdb";
  providerSelect.dispatchEvent(new ui.window.Event("change",{bubbles:true}));
  const connection=ui.el("connection");
  assert.equal(connection.querySelector("img"),null);
  assert.ok([...connection.options].some(o=>o.value===reference&&o.textContent==="CMDB <img src=x>"));
  connection.value=reference;ui.el("name").value="Customers";ui.el("resource").value="cmdb_ci";
  ui.el("source-form").dispatchEvent(new ui.window.Event("submit",{bubbles:true,cancelable:true}));await ui.settle();
  const put=ui.calls.find(call=>call.method==="PUT"&&call.url.pathname.endsWith("/sources/customers"));assert.ok(put);
  const body=JSON.parse(put.body);
  assert.equal(body.credential_env,reference);assert.equal(body.evidence_key_env,key.reference);
  assert.equal(body.origin,"https://tenant.service-now.com");assert.equal(body.expected_revision,0);
  assert.ok(!("credential_value" in body));assert.ok(!("evidence_key_value" in body));
  assert.equal(ui.calls.filter(call=>call.url.pathname.includes("/evidence-keys/")).length,0);
});

test("replacing the protection key needs confirmation and never updates sources",async t=>{
  let writes=0;
  const ui=await fixture(call=>{if(call.url.pathname.includes("/evidence-keys/")){writes++;return{...key,revision:3};}});
  t.after(()=>ui.window.close());
  ui.answer=false;ui.el("rotate-key").click();await ui.settle();assert.equal(writes,0);
  ui.answer=true;ui.el("rotate-key").click();await ui.settle();assert.equal(writes,1);
  const put=ui.calls.find(call=>call.url.pathname.includes("/evidence-keys/"));
  assert.equal(JSON.parse(put.body).expected_revision,2);
  assert.equal(ui.calls.filter(call=>call.method==="PUT"&&call.url.pathname.includes("/sources/")).length,0);
  assert.match(ui.el("status").textContent,/Existing sources were not changed/);
});

test("test access asks first and sends only the saved version",async t=>{
  const ui=await fixture(call=>call.url.pathname.endsWith("/test-access")?{access:"readable"}:undefined,[saved]);
  t.after(()=>ui.window.close());
  ui.answer=false;ui.rowButton("sources","Test access").click();await ui.settle();
  assert.equal(ui.calls.filter(call=>call.method==="POST").length,0);
  ui.answer=true;ui.rowButton("sources","Test access").click();await ui.settle();
  const post=ui.calls.find(call=>call.method==="POST");
  assert.deepEqual(JSON.parse(post.body),{confirm:true,expected_revision:4});
  assert.match(ui.el("status").textContent,/can read this source/);
});

test("removing a source is confirmed and carries the row's version",async t=>{
  const ui=await fixture(undefined,[saved]);t.after(()=>ui.window.close());
  ui.answer=false;ui.rowButton("sources","Remove").click();await ui.settle();
  assert.equal(ui.calls.filter(call=>call.method==="POST").length,0);
  ui.answer=true;ui.rowButton("sources","Remove").click();await ui.settle();
  const post=ui.calls.find(call=>call.method==="POST"&&call.url.pathname.endsWith("/state"));
  const body=JSON.parse(post.body);assert.equal(body.state,"revoked");assert.equal(body.expected_revision,4);
});

test("a failed load shows a plain sentence, not a status code",async t=>{
  const ui=await fixture(call=>{if(call.url.pathname.endsWith("/sources"))throw new TypeError("offline");});
  t.after(()=>ui.window.close());
  assert.doesNotMatch(ui.el("status").textContent,/HTTP|\b[45]\d\d\b|detail/);
  assert.match(ui.el("status").textContent,/load your data sources/);
});
