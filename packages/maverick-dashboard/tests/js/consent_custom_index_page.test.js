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
const reply=(status,body)=>({ok:status<400,status,headers:{get:()=>null},text:async()=>JSON.stringify(body),json:async()=>body});

async function page(options={}){
  const html=read("templates/consent_custom_indexes.html").replace(/\{%[\s\S]*?%\}/g,"").replace(/\{\{[\s\S]*?\}\}/g,"");
  const dom=new JSDOM(html,{url:"https://lightwork.test/consent/custom-indexes",runScripts:"outside-only"});
  const w=dom.window,d=w.document,calls=[],confirms=[];
  Object.defineProperty(w,"crypto",{value:webcrypto});w.TextEncoder=TextEncoder;w.TextDecoder=TextDecoder;
  Object.assign(d.getElementById("custom-index-shell").dataset,{apiBase:"/api/v1/consent/custom-indexes",canAdmin:"true",canAudit:"true"});
  d.querySelectorAll("button,fieldset").forEach(n=>{n.disabled=false;});
  w.mvConfirm=async message=>{confirms.push(message);return true;};
  w.mvErrorText=(failure,action)=>"Could not "+action+".";
  const indexes=options.indexes||[{index_id:"search-email-frequency",element_name:"email_frequency",state:"ready",revision:3,entry_count:12,built_at:1800000000},
    {index_id:"search-newsletter",element_name:"newsletter",state:"stale",revision:2,entry_count:4,built_at:1790000000}];
  w.fetch=async(url,init={})=>{
    const method=init.method||"GET",body=init.body?JSON.parse(init.body):null;calls.push({url,method,body});
    if(url.endsWith("/status"))return reply(200,{enabled:true,ready:true});
    if(url.includes("/profile-data/catalogs"))return reply(200,{items:[{state:"published",definitions:[
      {preference_id:"email_frequency",value_type:"single_select",options:[{value_id:"monthly"},{value_id:"weekly"}]},
      {preference_id:"newsletter",value_type:"boolean",options:[]},{preference_id:"topics",value_type:"multi_select",options:[{value_id:"sport"},{value_id:"news"}]}]}]});
    if(url.startsWith("/api/v1/consent/custom-indexes?"))return reply(200,{items:indexes,next_cursor:null});
    if(url.endsWith("/search"))return reply(200,{profile_ids:["customer-1","customer-2"],next_cursor:null});
    return reply(200,{});
  };
  shell(w);
  w.eval(read("static/lightwork-consent-workbench.js"));
  w.eval(read("static/lightwork-consent-custom-index.js"));
  await flush();
  const button=label=>[...d.querySelectorAll("#custom-index-table button")].find(b=>b.textContent===label);
  return {dom,w,d,calls,confirms,button,posts:()=>calls.filter(c=>c.method==="POST")};
}

test("searchable questions load as rows whose buttons follow their state",async()=>{
  const ui=await page();
  try{
    const text=ui.d.getElementById("custom-index-table").textContent;
    assert.match(text,/Email frequency.*Ready to search/);assert.match(text,/Newsletter.*Needs rebuilding/);
    assert.ok(ui.button("Search"));assert.ok(ui.button("Rebuild"));
    assert.equal([...ui.d.querySelectorAll("#custom-index-table button")].filter(b=>b.textContent==="Search").length,1);
  }finally{ui.dom.window.close();}
});

test("a search uses the published answers as a selector and lists the people found",async()=>{
  const ui=await page();
  try{
    ui.button("Search").click();
    const select=ui.d.querySelector('#custom-index-search-value select[name="value"]');
    assert.deepEqual([...select.options].map(o=>o.textContent),["Monthly","Weekly"]);
    select.value="weekly";
    ui.d.getElementById("custom-index-search-form").dispatchEvent(new ui.w.Event("submit",{bubbles:true,cancelable:true}));await flush();
    const sent=ui.posts()[0];
    assert.equal(sent.url,"/api/v1/consent/custom-indexes/search-email-frequency/search");assert.deepEqual(sent.body,{value:"weekly",limit:100});
    assert.match(ui.d.getElementById("custom-index-results").textContent,/2 people found\..*customer-1/);
  }finally{ui.dom.window.close();}
});

test("rebuild and remove carry the row's version; remove confirms first",async()=>{
  const ui=await page();
  try{
    [...ui.d.querySelectorAll("#custom-index-table button")].find(b=>b.getAttribute("aria-label")==="Rebuild: Newsletter").click();await flush();
    const build=ui.posts().find(c=>c.url.endsWith("/build"));assert.equal(build.body.expected_revision,2);
    [...ui.d.querySelectorAll("#custom-index-table button")].find(b=>b.getAttribute("aria-label")==="Remove: Email frequency").click();await flush();
    assert.match(ui.confirms[0],/Stop searching “Email frequency”\?/);
    assert.equal(ui.posts().find(c=>c.url.endsWith("/revoke")).body.expected_revision,3);
  }finally{ui.dom.window.close();}
});

test("a new searchable question is picked from published questions not yet searchable",async()=>{
  const ui=await page();
  try{
    ui.d.getElementById("custom-index-new").click();
    const select=ui.d.getElementById("custom-index-element-name");
    assert.deepEqual([...select.options].map(o=>o.value),["topics"]);
    ui.d.getElementById("custom-index-create-form").dispatchEvent(new ui.w.Event("submit",{bubbles:true,cancelable:true}));await flush();
    const body=ui.posts()[0].body;assert.equal(body.index_id,"search-topics");assert.equal(body.element_name,"topics");assert.ok(body.idempotency_key);
  }finally{ui.dom.window.close();}
});

// ---- no loader keeps saying "Loading" ---------------------------------------
async function statusPage(status,moduleEnabled="true"){
  const html=read("templates/consent_custom_indexes.html").replace(/\{%[\s\S]*?%\}/g,"").replace(/\{\{[\s\S]*?\}\}/g,"");
  const dom=new JSDOM(html,{url:"https://lightwork.test/consent/custom-indexes",runScripts:"outside-only"});
  const w=dom.window,d=w.document,calls=[];
  Object.defineProperty(w,"crypto",{value:webcrypto});w.TextEncoder=TextEncoder;w.TextDecoder=TextDecoder;
  Object.assign(d.getElementById("custom-index-shell").dataset,{apiBase:"/api/v1/consent/custom-indexes",canAdmin:"true",canAudit:"true",moduleEnabled});
  d.getElementById("custom-index-table").innerHTML='<p class="muted">Loading…</p>';
  w.mvErrorText=(failure,action)=>"Could not "+action+". Try again later.";
  w.fetch=async url=>{calls.push(url);return status();};
  shell(w);
  w.eval(read("static/lightwork-consent-workbench.js"));
  w.eval(read("static/lightwork-consent-custom-index.js"));
  await flush();
  return {dom,d,calls,table:()=>d.getElementById("custom-index-table").textContent};
}

test("a failed availability check replaces the table's Loading with what happened",async()=>{
  const ui=await statusPage(()=>reply(503,{detail:"unavailable"}));
  try{assert.equal(ui.table(),"Could not load searchable questions. Try again later.");}finally{ui.dom.window.close();}
});

test("searching that is on but not ready says when questions will appear",async()=>{
  const ui=await statusPage(()=>reply(200,{enabled:true,ready:false}));
  try{assert.equal(ui.table(),"Searchable questions appear here once an administrator finishes the setup.");}finally{ui.dom.window.close();}
});

test("a turned-off module starts no checks and shows no red sentence under its gate",async()=>{
  const ui=await statusPage(()=>{throw new Error("no request expected");},"false");
  try{
    assert.deepEqual(ui.calls,[]);
    assert.equal(ui.d.getElementById("custom-index-runtime-status").textContent,"");
  }finally{ui.dom.window.close();}
});
