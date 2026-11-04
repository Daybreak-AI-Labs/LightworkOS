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
const CONTEXT="c".repeat(64);

async function page(options={}){
  const html=read("templates/consent_publishing.html").replace(/\{%[\s\S]*?%\}/g,"").replace(/\{\{[\s\S]*?\}\}/g,"");
  const dom=new JSDOM(html,{url:"https://lightwork.test/consent/publishing",runScripts:"outside-only"});
  const w=dom.window,d=w.document,calls=[],confirms=[];
  Object.defineProperty(w,"crypto",{value:webcrypto});w.TextEncoder=TextEncoder;
  d.getElementById("cpp-root").dataset.canAdmin="true";d.getElementById("cpp-root").disabled=false;
  d.querySelectorAll("button").forEach(b=>{b.disabled=false;});
  w.mvConfirm=async message=>{confirms.push(message);return options.confirm!==false;};
  w.mvErrorText=(failure,action)=>"Could not "+action+".";
  const property={property_id:"main-website",kind:"web",consent_group_id:"customers",web_domains:["www.example.com"],origin_allowlist:["https://www.example.com"],mobile_bundle_ids:[],platform:null,revision:3,publication_revision:2};
  const translations=options.translations||[];
  w.fetch=async(url,init={})=>{
    const method=init.method||"GET",body=init.body?JSON.parse(init.body):null;calls.push({url,method,body});
    const u=new URL(url,"https://lightwork.test");
    if(u.pathname.endsWith("/catalog/properties"))return reply(200,{items:[property],total:1,next_offset:null});
    if(u.pathname.endsWith("/catalog/rule-groups"))return reply(200,{items:[{resource_id:"main-rules",version:4,current_version:4,locale:""}],total:1,next_offset:null});
    if(u.pathname.endsWith("/catalog/translations"))return reply(200,{items:translations,total:translations.length,next_offset:null});
    if(u.pathname.includes("/catalog/translations/"))return reply(200,{payload:{messages:{"purpose.old.title":"Old"}}});
    if(u.pathname.includes("/catalog/"))return reply(200,{items:[],total:0,next_offset:null});
    if(u.pathname.endsWith("/history"))return reply(200,{items:[{publication_id:"publication-b",publication_revision:2,action:"publish",created_at:1800000100},{publication_id:"publication-a",publication_revision:1,action:"publish",created_at:1800000000}]});
    if(u.pathname==="/api/v1/consent/withdrawal-requests")return reply(200,{context:CONTEXT,requests:[]});
    if(u.pathname==="/api/v1/consent/withdrawal-requests/review")return reply(200,{context:CONTEXT,operation:"withdrawal-op-1",token:"sealed-review",
      changes:Array.from({length:8},(_,i)=>({label:i?"Detail "+i:"Website",after:i?"Value "+i:"Main website"}))});
    if(u.pathname==="/api/v1/consent/withdrawal-requests/apply"){
      if(options.withdrawStatus)return reply(options.withdrawStatus,{detail:"publication revision is 3, expected 2"});
      return reply(200,{context:CONTEXT,confirmed:true,message:"The banner was withdrawn.",current:"No banner",notice:"Main website"});
    }
    return reply(201,{ok:true});
  };
  shell(w);
  w.eval(read("static/lightwork-consent-workbench.js"));
  w.eval(read("static/lightwork-consent-publishing.js"));
  await flush();
  const button=(scope,label)=>[...d.querySelectorAll(scope+" button")].find(b=>b.textContent===label);
  return {dom,w,d,calls,confirms,button,posts:()=>calls.filter(c=>c.method!=="GET")};
}

test("websites load as rows and a new website is saved from plain fields",async()=>{
  const ui=await page();
  try{
    assert.match(ui.d.getElementById("cpp-property-table").textContent,/Main website/);
    ui.d.getElementById("cpp-property-new").click();
    const f=ui.d.getElementById("cpp-property").elements;
    f.property_name.value="Help Center";f.group_name.value="Customers";f.web_domains.value="https://help.example.com/\nshop.example.com";
    ui.d.getElementById("cpp-property").dispatchEvent(new ui.w.Event("submit",{bubbles:true,cancelable:true}));await flush();
    const put=ui.posts()[0];
    assert.equal(put.method,"PUT");assert.equal(put.url,"/api/v1/consent/publishing/properties/help-center");
    assert.deepEqual(put.body.web_domains,["help.example.com","shop.example.com"]);
    assert.deepEqual(put.body.origin_allowlist,["https://help.example.com","https://shop.example.com"]);
    assert.equal(put.body.consent_group_id,"customers");assert.equal(put.body.expected_revision,0);
    assert.ok(put.body.idempotency_key.length>=8);
  }finally{ui.dom.window.close();}
});

test("publishing uses the revisions of the chosen row and only after confirmation",async()=>{
  for(const confirm of [false,true]){
    const ui=await page({confirm});
    try{
      ui.button("#cpp-property-table","Preview and publish").click();await flush();
      assert.equal(ui.d.getElementById("cpp-promotion").elements.rule_group.value,"main-rules|4");
      ui.d.getElementById("cpp-publish").click();await flush();
      assert.match(ui.confirms[0],/Publish to Main website\?/);
      const sent=ui.posts().filter(c=>c.url.endsWith("/publish"));
      if(!confirm){assert.equal(sent.length,0);continue;}
      assert.equal(sent.length,1);
      assert.equal(sent[0].body.rule_group_id,"main-rules");assert.equal(sent[0].body.rule_group_version,4);
      assert.equal(sent[0].body.expected_property_revision,3);assert.equal(sent[0].body.expected_publication_revision,2);
    }finally{ui.dom.window.close();}
  }
});

test("withdraw and restore confirm first and carry the row's references",async()=>{
  const ui=await page();
  try{
    // Withdrawal opens a complete server review; nothing changes until the
    // reviewed banner is confirmed, and the apply quotes that exact review.
    ui.button("#cpp-property-table","Withdraw").click();await flush();
    const review=ui.posts().find(c=>c.url.endsWith("/withdrawal-requests/review"));
    assert.deepEqual(review.body,{website:"main-website",context:CONTEXT});
    assert.equal(ui.d.getElementById("cpp-withdrawal-review").hidden,false);
    assert.match(ui.d.getElementById("cpp-withdrawal-changes").textContent,/Main website/);
    assert.equal(ui.posts().filter(c=>c.url.endsWith("/apply")).length,0,"nothing is withdrawn before confirmation");
    ui.d.getElementById("cpp-withdrawal-confirm").click();await flush();
    const apply=ui.posts().find(c=>c.url.endsWith("/withdrawal-requests/apply"));
    assert.deepEqual(apply.body,{operation:"withdrawal-op-1",token:"sealed-review",confirmed:true});
    ui.button("#cpp-property-table","History").click();await flush();
    const restore=[...ui.d.querySelectorAll("#cpp-history button")].filter(b=>b.textContent==="Restore this version");
    assert.equal(restore.length,1,"only earlier versions can be restored");
    restore[0].click();await flush();
    const rollback=ui.posts().find(c=>c.url.endsWith("/rollback"));
    assert.equal(rollback.body.target_publication_id,"publication-a");
    assert.match(ui.confirms.at(-1),/Restore version 1/);
  }finally{ui.dom.window.close();}
});

test("stale withdrawal gives refresh guidance without exposing revisions; other failures use the shared error",async()=>{
  for(const [code,expected] of [[409,/refused\. Read its original result, then review current banner settings/],[503,/original response is uncertain\. Use Read original result/]]){
    const ui=await page({withdrawStatus:code});
    try{
      ui.button("#cpp-property-table","Withdraw").click();await flush();
      ui.d.getElementById("cpp-withdrawal-confirm").click();await flush();
      const status=ui.d.getElementById("cpp-withdrawal-status");
      assert.equal(status.getAttribute("role"),"alert");
      assert.match(status.textContent,expected);
      assert.doesNotMatch(status.textContent,/revision|expected 2|409|503/);
      assert.equal(ui.posts().filter(c=>c.url.endsWith("/withdrawal-requests/apply")).length,1);
    }finally{ui.dom.window.close();}
  }
});

test("a new use of data stores its words in the language pack, then saves the reference",async()=>{
  const ui=await page({translations:[{resource_id:"consent-text",locale:"en-US",version:2,current_version:2}]});
  try{
    ui.d.getElementById("cpp-resource-new").click();await flush();
    const form=ui.d.getElementById("cpp-resource"),f=form.elements;
    f.resource_name.value="Email marketing";f.title.value="Marketing emails";f.description.value="News and offers";
    form.dispatchEvent(new ui.w.Event("submit",{bubbles:true,cancelable:true}));await flush();
    const [translation,purpose]=ui.posts();
    assert.equal(translation.url,"/api/v1/consent/publishing/translations/consent-text/en-US/versions");
    assert.equal(translation.body.version,3);assert.equal(translation.body.expected_current_version,2);
    assert.equal(translation.body.messages["purpose.email-marketing.title"],"Marketing emails");
    assert.equal(translation.body.messages["purpose.old.title"],"Old","existing text is kept");
    assert.equal(purpose.url,"/api/v1/consent/publishing/purposes/email-marketing/versions");
    assert.deepEqual({v:purpose.body.version,e:purpose.body.expected_current_version,t:purpose.body.title_key,b:purpose.body.lawful_basis},{v:1,e:0,t:"purpose.email-marketing.title",b:"consent"});
  }finally{ui.dom.window.close();}
});
