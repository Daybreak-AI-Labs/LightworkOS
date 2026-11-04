"use strict";
const {test}=require("node:test");
const assert=require("node:assert/strict");
const fs=require("node:fs"),path=require("node:path");
const {webcrypto}=require("node:crypto");
const {JSDOM}=require("jsdom");
const {shell} = require('./_shell');
const root=path.resolve(__dirname,"../../maverick_dashboard");
const read=name=>fs.readFileSync(path.join(root,name),"utf8");
const flush=async()=>{for(let i=0;i<30;i++){await new Promise(setImmediate);await new Promise(r=>setTimeout(r,2));}};
const reply=(status,body)=>({ok:status<400,status,json:async()=>body});
const D="a".repeat(64),R="b".repeat(64);

async function page(options={}){
  const source=read("templates/consent_delivery.html");
  const html=source.replace(/\{%[\s\S]*?%\}/g,"").replace(/\{\{[\s\S]*?\}\}/g,"");
  const dom=new JSDOM(html,{url:"https://lightwork.test/consent/delivery",runScripts:"outside-only"});
  const w=dom.window,d=w.document,calls=[],confirms=[];
  Object.defineProperty(w,"crypto",{value:webcrypto});w.TextEncoder=TextEncoder;
  const rootNode=d.getElementById("cd-root");rootNode.disabled=false;
  Object.assign(rootNode.dataset,{canAdmin:"true",canAudit:"true",canOperate:"true"});
  d.querySelectorAll("button").forEach(b=>{b.disabled=false;});
  w.mvConfirm=async message=>{confirms.push(message);return options.confirm!==false;};
  w.mvForm=async()=>options.form||null;
  w.mvErrorText=(failure,action)=>"Could not "+action+".";
  const destination={destination_id:"crm",origin:"https://crm.example.com",status:"active",active_key_id:"key-a",revision:4,max_attempts:6,default_retention_seconds:2592000,keys:[{key_id:"key-a",status:"active"},{key_id:"key-old",status:"retired"}]};
  w.fetch=async(url,init={})=>{
    const method=init.method||"GET",body=init.body?JSON.parse(init.body):null;calls.push({url,method,body});
    if(url.endsWith("/managed"))return reply(200,{context:"c".repeat(64),keys:[{key_id:"key-a",label:"CRM signing key"},{key_id:"key-b",label:"Mail signing key"}],worker:{enabled:false,running_here:false},subscription:null});
    if(url.includes("/destinations?"))return reply(200,{items:[destination],truncated:false});
    if(url.endsWith("/status")&&url.includes("destination-adapters"))return reply(200,{destinations:[{destination_id:"salesforce",provider_id:"salesforce",credential_reference_present:true}],reconciliation_supported:{salesforce:true},transport_factory_installed:true});
    if(url.endsWith("/status"))return reply(200,{counts:{queued:2,leased:1,delivered:9,dead_letter:1},retention_due:{delivered:3},audit_chain:{valid:true,events:12}});
    if(url.includes("/dead-letters?"))return reply(200,{items:[{message_id:"message-1",destination_id:"crm",attempts:6,revision:7,last_error_code:"timeout",updated_at:1800000000}]});
    if(url.includes("/audit?"))return reply(200,{events:[{sequence:1,event_type:"destination_enrolled",details:{destination_id:"crm"},created_at:1800000000}]});
    if(url.endsWith("/ambiguous"))return reply(200,{items:[{provider_id:"salesforce",message_sha256:D,request_sha256:R,attempts:2,updated_at:1800000000}]});
    if(url.endsWith("/reconcile"))return reply(200,{disposition:"applied"});
    if(url.endsWith("/dispatch"))return reply(200,{synchronized:{messages_queued:2},dispatched:{delivered:2,retry_scheduled:1}});
    return reply(201,{});
  };
  shell(w);
  w.eval(read("static/lightwork-consent-workbench.js"));
  w.eval([...source.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].at(-1)[1]);
  await flush();
  const button=(scope,label)=>[...d.querySelectorAll(scope+" button")].find(b=>b.textContent===label);
  return {dom,w,d,calls,confirms,button,posts:()=>calls.filter(c=>c.method!=="GET")};
}

test("destinations, totals, failures and history load as plain rows",async()=>{
  const ui=await page();
  try{
    assert.match(ui.d.getElementById("cd-destination-table").textContent,/Crm.*https:\/\/crm\.example\.com.*Available.*CRM signing key/);
    assert.match(ui.d.getElementById("cd-managed-status").textContent,/No automatic subscription is authorized/);
    assert.equal(ui.d.getElementById("cd-count-waiting").textContent,"3");
    assert.equal(ui.d.getElementById("cd-count-old").textContent,"3");
    assert.match(ui.d.getElementById("cd-dead-table").textContent,/The system took too long to answer/);
    assert.match(ui.d.getElementById("cd-history-table").textContent,/Destination added/);
    assert.match(ui.d.getElementById("cd-history-check").textContent,/all 12 entries are intact/);
  }finally{ui.dom.window.close();}
});

test("a destination is added from a name, an address and a saved signing key; the reference is generated",async()=>{
  const ui=await page();
  try{
    ui.d.getElementById("cd-destination-new").click();
    const form=ui.d.getElementById("cd-destination"),f=form.elements;
    assert.deepEqual([...f.signing_key_id.options].map(o=>o.textContent),["CRM signing key","Mail signing key","Existing deployment key 1"]);
    f.destination_name.value="Email Platform";f.origin.value="mail.example.com/path";f.signing_key_id.value="key-b";
    form.dispatchEvent(new ui.w.Event("submit",{bubbles:true,cancelable:true}));await flush();
    const post=ui.posts()[0];
    assert.equal(post.url,"/api/v1/consent/delivery/destinations/email-platform");
    assert.equal(post.body.origin,"https://mail.example.com");
    assert.equal(post.body.signing_key_id,"key-b");
    assert.equal(post.body.default_retention_seconds,2592000);assert.equal(post.body.max_attempts,6);
    assert.ok(post.body.idempotency_key);
  }finally{ui.dom.window.close();}
});

test("sending contacts external systems only after a confirmation naming them",async()=>{
  for(const confirm of [false,true]){
    const ui=await page({confirm});
    try{
      ui.d.getElementById("cd-dispatch").click();await flush();
      assert.match(ui.confirms[0],/contact https:\/\/crm\.example\.com over the internet/);
      const sent=ui.posts().filter(c=>c.url.endsWith("/dispatch"));
      assert.equal(sent.length,confirm?1:0);
      if(confirm){assert.deepEqual(sent[0].body.destination_ids,["crm"]);assert.match(ui.d.getElementById("cd-run-result").textContent,/delivered 2 updates\. 1 will be retried/);}
    }finally{ui.dom.window.close();}
  }
});

test("row actions carry the row's version and fingerprints; stopping a destination confirms",async()=>{
  const ui=await page();
  try{
    ui.button("#cd-dead-table","Try again").click();await flush();
    const replay=ui.posts().find(c=>c.url.endsWith("/replay"));
    assert.equal(replay.url,"/api/v1/consent/delivery/dead-letters/message-1/replay");assert.equal(replay.body.expected_revision,7);
    ui.button("#cd-destination-table","Stop sending").click();await flush();
    assert.match(ui.confirms.at(-1),/Stop sending consent updates to Crm\?/);
    assert.equal(ui.posts().find(c=>c.url.endsWith("/revoke")).body.expected_revision,4);
    ui.d.getElementById("cd-adapter-status").click();await flush();
    assert.match(ui.d.getElementById("cd-provider-grid").textContent,/Ready to send and confirm deliveries/);
    ui.button("#cd-ambiguous-table","Check again").click();await flush();
    const check=ui.posts().find(c=>c.url.endsWith("/reconcile"));
    assert.deepEqual(check.body,{message_sha256:D,request_sha256:R});
    assert.match(ui.d.getElementById("cd-status").textContent,/confirmed the update arrived/);
  }finally{ui.dom.window.close();}
});
