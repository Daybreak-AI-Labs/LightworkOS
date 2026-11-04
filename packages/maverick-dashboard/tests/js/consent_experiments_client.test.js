// Run with: node --test packages/maverick-dashboard/tests/js/consent_experiments_client.test.js
"use strict";
const {test}=require("node:test");
const assert=require("node:assert/strict");
const fs=require("node:fs"),path=require("node:path");
const {webcrypto,createHash}=require("node:crypto");
const {JSDOM}=require("jsdom");
const {shell} = require('./_shell');
const root=path.resolve(__dirname,"../../maverick_dashboard");
const read=name=>fs.readFileSync(path.join(root,name),"utf8").replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
const flush=async()=>{for(let i=0;i<40;i++){await new Promise(setImmediate);await new Promise(r=>setTimeout(r,2));}};
const reply=(status,body)=>({ok:status<400,status,json:async()=>body});
const H=value=>createHash("sha256").update(value).digest("hex");

function experiment(state,revision){
  return {state,revision,definition:{experiment_id:"spring-test",starts_at:1800000000,ends_at:1800900000,
    variants:[{variant_id:"original",content_ref:"public-layout:stacked",is_control:true},{variant_id:"test-inline",content_ref:"public-layout:inline",is_control:false}]}};
}
async function page(options={}){
  const source=read("templates/consent_experiments.html");
  const html=source.replace(/\{%[\s\S]*?%\}/g,"").replace(/\{\{[\s\S]*?\}\}/g,"");
  const dom=new JSDOM(html,{url:"https://lightwork.test/consent/experiments",runScripts:"outside-only"});
  const w=dom.window,d=w.document,calls=[],confirms=[];
  Object.defineProperty(w,"crypto",{value:webcrypto});w.TextEncoder=TextEncoder;
  const rootNode=d.getElementById("ce-root");rootNode.disabled=false;Object.assign(rootNode.dataset,{canAdmin:"true",canAudit:"true"});
  d.querySelectorAll("button").forEach(b=>{b.disabled=false;});
  w.mvConfirm=async message=>{confirms.push(message);return options.confirm!==false;};
  w.mvErrorText=(failure,action)=>"Could not "+action+". ("+failure.status+")";
  const items=options.items||[experiment("draft",0)];
  w.fetch=async(url,init={})=>{
    const method=init.method||"GET",body=init.body?JSON.parse(init.body):null;calls.push({url,method,body});
    if(url.startsWith("/api/v1/consent/experiments?"))return reply(200,{items,truncated:false});
    if(url.includes("/catalog/properties"))return reply(200,{items:[{property_id:"main-site",publication_revision:1}]});
    if(url.includes("/catalog/rule-groups"))return reply(200,{items:[{resource_id:"main-rules",version:2}]});
    if(url.includes("/variant-content"))return reply(200,{items:["stacked","inline","compact"].map(layout=>({locale:"en-US",layout,content_ref:"public-layout:"+layout,content_sha256:H(layout),title:"Your privacy"}))});
    if(url.endsWith("/analysis"))return reply(200,{look_number:1,max_analysis_looks:5,winner_variant_id:"test-inline",cells:[{variant_id:"original",exposures:200,outcomes:150,successes:60,conversion_rate:0.4,confidence_interval:[0.3,0.5],minimum_sample_met:true},{variant_id:"test-inline",exposures:210,outcomes:160,successes:96,conversion_rate:0.6,confidence_interval:[0.5,0.7],minimum_sample_met:true}]});
    if(url.endsWith("/assign"))return reply(200,{variant_id:"original",reason:"legal_signal_precedence"});
    if(options.fail&&method==="POST")return reply(options.fail,{detail:"expected revision 3 != 4"});
    return reply(201,{});
  };
  shell(w);
  w.eval(read("static/lightwork-consent-workbench.js"));
  w.eval([...source.matchAll(/<script>([\s\S]*?)<\/script>/g)].at(-1)[1]);
  await flush();
  const button=label=>[...d.querySelectorAll("#ce-table button")].find(b=>b.textContent===label);
  return {dom,w,d,calls,confirms,button,posts:()=>calls.filter(c=>c.method==="POST")};
}

test("experiments load as rows whose buttons follow the lifecycle state",async()=>{
  const ui=await page({items:[experiment("active",2)]});
  try{
    const table=ui.d.getElementById("ce-table").textContent;
    assert.match(table,/Spring test.*Running.*Buttons stacked vs Buttons side by side/);
    assert.ok(ui.button("Pause")&&ui.button("Stop")&&ui.button("Check results"));
    assert.equal(ui.button("Approve"),undefined);assert.equal(ui.button("Resume"),undefined);
  }finally{ui.dom.window.close();}
});

test("a lifecycle change confirms first and carries the row's version",async()=>{
  for(const confirm of [false,true]){
    const ui=await page({confirm,items:[experiment("active",2)]});
    try{
      ui.button("Stop").click();await flush();
      assert.match(ui.confirms[0],/Stop “Spring test”\? Everyone will see the original/);
      const sent=ui.posts();
      assert.equal(sent.length,confirm?1:0);
      if(confirm){assert.equal(sent[0].url,"/api/v1/consent/experiments/spring-test/kill");assert.equal(sent[0].body.expected_revision,2);assert.ok(sent[0].body.idempotency_key.length>=8);}
    }finally{ui.dom.window.close();}
  }
});

test("a refused change shows a plain sentence, never the server detail",async()=>{
  const ui=await page({fail:409});
  try{
    ui.button("Approve").click();await flush();
    const text=ui.d.getElementById("ce-status").textContent;
    assert.match(text,/Could not update the experiment\. \(409\)/);assert.doesNotMatch(text,/revision/);
  }finally{ui.dom.window.close();}
});

test("results read as a plain summary with a winner callout",async()=>{
  const ui=await page({items:[experiment("active",2)]});
  try{
    ui.button("Check results").click();await flush();
    const text=ui.d.getElementById("ce-results").textContent;
    assert.match(text,/The “Buttons side by side” version helped more people save their choices\./);
    assert.match(text,/60%/);assert.match(text,/Check 1 of 5/);
  }finally{ui.dom.window.close();}
});

test("a new experiment is built from choices: layouts, dates and attached reviews become the request",async()=>{
  const ui=await page({items:[]});
  try{
    ui.d.getElementById("ce-new").click();await flush();
    const form=ui.d.getElementById("ce-create"),f=form.elements;
    f.experiment_name.value="Spring test";
    f.property_id.value="main-site";f.property_id.dispatchEvent(new ui.w.Event("change"));
    f.rule_group.value="main-rules|2";f.rule_group.dispatchEvent(new ui.w.Event("change"));await flush();
    assert.equal(f.control_layout.value,"stacked");
    const files=[...form.querySelectorAll("input[type=file]")];assert.equal(files.length,4);
    files.forEach((input,i)=>Object.defineProperty(input,"files",{value:[new ui.w.File(["review "+i],"review-"+i+".pdf")]}));
    form.dispatchEvent(new ui.w.Event("submit",{bubbles:true,cancelable:true}));await flush();
    const create=ui.posts()[0];
    assert.equal(create.url,"/api/v1/consent/experiments");
    const body=create.body;
    assert.equal(body.experiment_id,"spring-test");assert.equal(body.metric_id,"preference-completion");
    assert.deepEqual(body.variants.map(v=>[v.variant_id,v.allocation_bps,v.content_ref,v.content_sha256,v.is_control]),
      [["original",5000,"public-layout:stacked",H("stacked"),true],["test-inline",5000,"public-layout:inline",H("inline"),false]]);
    assert.equal(body.variants[0].accessibility_evidence_sha256,H("review 0"));
    assert.equal(body.variants[1].equal_choice_evidence_sha256,H("review 3"));
    assert.ok(Number.isInteger(body.starts_at)&&body.ends_at>body.starts_at);
    assert.equal(body.alpha,0.05);assert.equal(body.traffic_bps,10000);assert.deepEqual(body.audience,{country_codes:[],channels:["web"]});
  }finally{ui.dom.window.close();}
});

test("trying an experiment explains the outcome in plain words",async()=>{
  const ui=await page();
  try{
    const form=ui.d.getElementById("ce-assignment");form.elements.gpc.checked=true;
    form.dispatchEvent(new ui.w.Event("submit",{bubbles:true,cancelable:true}));await flush();
    assert.deepEqual(ui.posts()[0].body.context.privacy_signals,["gpc"]);
    assert.match(ui.d.getElementById("ce-assignment-result").textContent,/would see: Buttons stacked \(original\)\. Their browser asks not to be tracked/);
  }finally{ui.dom.window.close();}
});
