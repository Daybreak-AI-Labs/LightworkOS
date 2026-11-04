"use strict";
const {test}=require("node:test");
const assert=require("node:assert/strict");
const fs=require("node:fs"),path=require("node:path");
const {webcrypto}=require("node:crypto");
const {JSDOM}=require("jsdom");
const {shell} = require('./_shell');
const root=path.resolve(__dirname,"../../maverick_dashboard");
const read=name=>fs.readFileSync(path.join(root,name),"utf8").replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
const flush=async()=>{for(let i=0;i<30;i++){await new Promise(setImmediate);await new Promise(r=>setTimeout(r,2));}};
const reply=(status,body)=>({ok:status<400,status,json:async()=>body});
const D=c=>c.repeat(64);
const catalog={catalog_id:"profile-catalog-abc",version:1,property_id:"main-site",state:"published",revision:2,policy_id:"web",policy_version:1,created_at:1800000000,
  definitions:[{preference_id:"newsletter"},{preference_id:"email_frequency"}]};

async function page(options={}){
  const source=read("templates/consent_profile_data.html");
  const html=source.replace(/\{%[\s\S]*?%\}/g,"").replace(/\{\{[\s\S]*?\}\}/g,"");
  const dom=new JSDOM(html,{url:"https://lightwork.test/consent/profile-data",runScripts:"outside-only"});
  const w=dom.window,d=w.document,calls=[],confirms=[];
  Object.defineProperty(w,"crypto",{value:webcrypto});w.TextEncoder=TextEncoder;
  const rootNode=d.getElementById("cpd-root");rootNode.disabled=false;Object.assign(rootNode.dataset,{canAdmin:"true",canAudit:"true"});
  d.querySelectorAll("button").forEach(b=>{b.disabled=false;});
  w.mvConfirm=async message=>{confirms.push(message);return true;};
  w.mvErrorText=(failure,action)=>"Could not "+action+".";
  w.fetch=async(url,init={})=>{
    const method=init.method||"GET",body=init.body?JSON.parse(init.body):null;calls.push({url,method,body});
    if(url.includes("/catalogs?"))return reply(200,{items:options.catalogs||[catalog]});
    if(url.includes("/journeys?"))return reply(200,{items:options.journeys||[]});
    if(url.includes("/public-clients?"))return reply(200,{items:[{credential_id:"key-1",property_id:"main-site",browser_origin:"https://www.example.com",status:"active",jurisdiction:"global",country_code:"US",default_locale:"en-US"}]});
    if(url.includes("/contract?"))return reply(200,{catalog_id:"profile-catalog-new",journey_id:"profile-journey-new",property_id:"main-site",publication_sha256:D("a"),bundle_sha256:D("b"),configuration_sha256:D("c"),policy_id:"web",policy_version:1,policy_sha256:D("d"),
      questions:[{preference_id:"newsletter",version:2,title:"Newsletter",value_type:"single_select",required:false,option_ids:["monthly","weekly"]}]});
    if(url.includes("/consent/policies"))return reply(200,{policies:[{policy_id:"web",version:1,purposes:{analytics:"consent",marketing:"consent"}}]});
    return reply(201,{});
  };
  shell(w);
  w.eval(read("static/lightwork-consent-workbench.js"));
  w.eval([...source.matchAll(/<script>([\s\S]*?)<\/script>/g)].at(-1)[1]);
  await flush();
  return {dom,w,d,calls,confirms,posts:()=>calls.filter(c=>c.method==="POST")};
}

test("a question set is built from the published questions of a chosen website key",async()=>{
  const ui=await page({catalogs:[]});
  try{
    ui.d.getElementById("cpd-catalog-new").click();await flush();
    const form=ui.d.getElementById("cpd-catalog");
    form.elements.credential_id.value="key-1";form.elements.credential_id.dispatchEvent(new ui.w.Event("change"));await flush();
    assert.match(ui.d.getElementById("cpd-questions").textContent,/Newsletter/);
    form.dispatchEvent(new ui.w.Event("submit",{bubbles:true,cancelable:true}));await flush();
    const body=ui.posts()[0].body;
    assert.equal(body.catalog_id,"profile-catalog-new");assert.equal(body.configuration_sha256,D("c"));
    assert.deepEqual(body.definitions[0],{preference_id:"newsletter",definition_version:2,label_ref:"newsletter",value_type:"single_select",
      options:[{value_id:"monthly",label_ref:"monthly"},{value_id:"weekly",label_ref:"weekly"}],required:false,expires_after_seconds:null,retention_seconds:31536000});
    assert.equal(body.expected_latest_version,0);
  }finally{ui.dom.window.close();}
});

test("an asking plan uses the paired plan reference, chosen questions and a purpose condition",async()=>{
  const ui=await page();
  try{
    [...ui.d.querySelectorAll("#cpd-catalogs button")].find(b=>b.textContent==="Create asking plan").click();await flush();
    const step=ui.d.querySelector("#cpd-steps > fieldset");
    step.querySelector('[value="newsletter"]').checked=true;step.querySelector("[name=step_condition]").value="marketing";
    const form=ui.d.getElementById("cpd-journey");form.dispatchEvent(new ui.w.Event("submit",{bubbles:true,cancelable:true}));await flush();
    const body=ui.posts()[0].body;
    assert.equal(body.journey_id,"profile-journey-abc");assert.equal(body.catalog_version,1);
    assert.deepEqual(body.stages,[{stage_id:"step-1",priority:1000,prompt_label_ref:"step-1",preference_ids:["newsletter"],condition:{source:"purpose",key:"marketing",operator:"equals",value:"grant"}}]);
    assert.deepEqual([body.max_prompts,body.cooldown_seconds,body.frequency_cap,body.frequency_window_seconds],[1,86400,3,2592000]);
  }finally{ui.dom.window.close();}
});

test("plan lifecycle buttons follow its state and confirm with the row's version",async()=>{
  const ui=await page({journeys:[{journey_id:"profile-journey-abc",version:1,catalog_id:"profile-catalog-abc",catalog_version:1,property_id:"main-site",state:"active",revision:3,max_prompts:1,frequency_cap:3,frequency_window_seconds:2592000,stages:[{preference_ids:["newsletter"]}]}]});
  try{
    const labels=[...ui.d.querySelectorAll("#cpd-journeys button")].map(b=>b.textContent);
    assert.deepEqual(labels,["Pause","Stop","Roll back"]);
    [...ui.d.querySelectorAll("#cpd-journeys button")].find(b=>b.textContent==="Pause").click();await flush();
    assert.match(ui.confirms[0],/Pause asking on Main site\?/);
    const sent=ui.posts()[0];assert.equal(sent.url,"/api/v1/consent/profile-data/journeys/profile-journey-abc/versions/1/pause");assert.equal(sent.body.expected_revision,3);
  }finally{ui.dom.window.close();}
});
