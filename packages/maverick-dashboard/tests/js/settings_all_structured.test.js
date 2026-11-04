"use strict";
// Settings > All settings: the structured controls -- several choices from a
// searched list, an address with a part for each workspace, a document
// imported from a file, a fingerprint worked out from an uploaded file, the
// preview of what a governance level changes, and rows named from a long list.
const {test}=require("node:test");
const assert=require("node:assert/strict");
const fs=require("node:fs"),path=require("node:path");
const {JSDOM}=require("jsdom");
const {shell} = require('./_shell');
const {reviewedSaving} = require('./_settings_review');
const root=path.resolve(__dirname,"../../maverick_dashboard");
const read=name=>fs.readFileSync(path.join(root,name),"utf8");
const flush=async()=>{for(let i=0;i<20;i++){await new Promise(setImmediate);await new Promise(r=>setTimeout(r,2));}};
const reply=(status,body)=>({ok:status<400,status,headers:{get:()=>null},json:async()=>body});

const GRID=JSON.stringify({kind:"grid",columns:[{key:"max_risk",label:"Riskiest tools allowed",kind:"select",choices:[{value:"",label:"No extra limit"},{value:"low",label:"Low risk only"}],default:""}],
  key_choices:[],row_label:"Person",item_label:"Person",rows:[],key_choices_url:"/api/v1/settings/catalog/choices/security.users"}).replace(/'/g,"&#39;");

// Markup mirrors templates/settings_all.html for each structured control.
const HTML=`<!doctype html><main>
<div role="status" id="settings-all-status" hidden></div>
<input id="settings-all-search"><select id="settings-all-group"><option value="">All</option></select>
<input type="checkbox" id="settings-all-changed"><p id="settings-all-filter-status"></p>
<div id="settings-all-groups">
<section class="settings-all-group" data-group="security"><h2>Security</h2>
 <div class="settings-all-row" data-setting-id="security.denied_tools" data-control="picks" data-source="default" data-search="tools blocked">
  <strong data-value-text>Not set</strong><span data-source-text>Default</span>
  <div class="settings-all-picks" data-picks data-label="Tools blocked everywhere" data-choices-url="/api/v1/settings/catalog/choices/security.denied_tools" data-choices='[]'>
   <ul data-pick-list></ul><p data-picks-empty>No tools are blocked everywhere.</p>
   <input type="search" data-pick-search><select data-pick-select><option value="">Search above, then choose</option></select>
   <button data-pick-add>Add</button></div>
  <button data-save>Save</button><button data-reset>Reset to default</button><p data-row-status></p></div>
 <div class="settings-all-row" data-setting-id="audit.unified.custody.siem_destination_template" data-control="text" data-source="default" data-search="siem">
  <strong data-value-text>Not set</strong><span data-source-text>Default</span>
  <input type="text" data-input value="https://siem.example.com/ingest">
  <select data-segment-at data-at="0"></select>
  <button data-save>Save</button><button data-reset>Reset to default</button><p data-row-status></p></div>
 <div class="settings-all-row" data-setting-id="ai_benchmark_exchange.trust_roots" data-control="document" data-source="default" data-search="trust">
  <strong data-value-text>Not set</strong><span data-source-text>Default</span>
  <div data-document><p data-document-text>Nothing imported yet.</p><ul data-document-items></ul>
   <input type="file" data-document-file></div>
  <button data-save>Save</button><button data-reset>Reset to default</button><p data-row-status></p></div>
 <div class="settings-all-row" data-setting-id="ai_media_provenance.c2patool_executable_sha256" data-control="fingerprint" data-source="default" data-search="fingerprint">
  <strong data-value-text>Not set</strong><span data-source-text>Default</span>
  <div data-fingerprint><input type="hidden" data-input value=""><strong data-fingerprint-shown>Not set</strong>
   <input type="file" data-fingerprint-file></div>
  <button data-save>Save</button><button data-reset>Reset to default</button><p data-row-status></p></div>
 <div class="settings-all-row" data-setting-id="governance.profile" data-control="select" data-source="default" data-search="governance level">
  <strong data-value-text>Not chosen</strong><span data-source-text>Default</span>
  <select data-input data-preview-url="/api/v1/settings/catalog/preview/governance.profile">
   <option value="" selected>Not chosen</option><option value="regulated">Regulated</option></select>
  <div data-preview></div>
  <button data-save>Save</button><button data-reset>Reset to default</button><p data-row-status></p></div>
 <div class="settings-all-row" data-setting-id="security.users" data-control="table" data-source="default" data-search="person">
  <strong data-value-text>Not set</strong><span data-source-text>Default</span>
  <div data-grid data-grid-state='${GRID}'><table><tbody data-grid-body></tbody></table><p data-grid-empty>None yet.</p>
   <input type="search" data-grid-keysearch><select data-grid-newkey><option value="">Choose one</option></select>
   <button data-grid-add>Add rules for this person</button></div>
  <button data-save>Save</button><button data-reset>Reset to default</button><p data-row-status></p></div>
</section></div><p id="settings-all-empty" hidden></p></main>`;

async function page(handler,warnings){
  const dom=new JSDOM(HTML,{url:"https://lightwork.test/settings/all",runScripts:"outside-only"});
  const w=dom.window,d=w.document,calls=[],confirms=[];
  w.mvConfirm=async message=>{confirms.push(message);return true;};
  reviewedSaving(w,{confirms,warnings});
  w.mvErrorText=(failure,action)=>"Could not "+action+".";
  w.mvToast=()=>{};
  w.fetch=async(url,init={})=>{
    let body=null;
    if(typeof init.body==="string")body=JSON.parse(init.body);else if(init.body)body={raw:init.body};
    calls.push({url,method:init.method||"GET",body});
    return handler(url,body,calls.length);
  };
  shell(w);
  w.eval(read("static/lightwork-settings-all.js"));
  await flush();
  return {dom,w,d,calls,confirms};
}
const row=(ui,id)=>ui.d.querySelector('[data-setting-id="'+id+'"]');
const click=async(node)=>{node.click();await flush();};
const choose=async(ui,input,file)=>{
  Object.defineProperty(input,"files",{value:[file],configurable:true});
  input.dispatchEvent(new ui.w.Event("change",{bubbles:true}));await flush();
};
const saved=(ui,id,extra)=>reply(200,{changed:[id],groups:[{settings:[{id,source:"here",source_text:"Set here",...extra}]}]});

test("several tools are searched, chosen and saved as a list",async()=>{
  const ui=await page(url=>url.includes("/choices/")
    ?reply(200,{choices:[{value:"shell",label:"Shell"},{value:"browser",label:"Browser"}]})
    :saved(ui,"security.denied_tools",{picks:[{value:"shell",label:"Shell"}],value_text:"Shell"}));
  try{
    const r=row(ui,"security.denied_tools");
    const search=r.querySelector("[data-pick-search]");
    search.value="she";search.dispatchEvent(new ui.w.Event("input",{bubbles:true}));await flush();
    const select=r.querySelector("[data-pick-select]");
    assert.deepEqual([...select.options].map(o=>o.value),["","shell"]);
    select.value="shell";
    await click(r.querySelector("[data-pick-add]"));
    assert.equal(r.querySelector("[data-picks-empty]").hidden,true);
    await click(r.querySelector("[data-save]"));
    const save=ui.calls.find(c=>c.method==="POST");
    assert.deepEqual(save.body.changes,[{id:"security.denied_tools",value:["shell"]}]);
    assert.equal(r.querySelectorAll("[data-pick-item]").length,1);
    await click(r.querySelector("[data-pick-remove]"));
    assert.equal(r.querySelector("[data-picks-empty]").hidden,false);
  }finally{ui.dom.window.close();}
});

test("the workspace part goes where the person picks it",async()=>{
  const ui=await page((url,body)=>saved(ui,"audit.unified.custody.siem_destination_template",{value:"https://siem.example.com/ingest",segment_at:1,value_text:"x"}));
  try{
    const r=row(ui,"audit.unified.custody.siem_destination_template");
    const at=r.querySelector("[data-segment-at]");
    assert.deepEqual([...at.options].map(o=>o.textContent),["Before “ingest”","At the end of the address"]);
    assert.equal(at.value,"0");
    await click(r.querySelector("[data-save]"));
    assert.equal(ui.calls[0].body.changes[0].value,"https://siem.example.com/{tenant_sha256}/ingest");
    at.value="1";at.dispatchEvent(new ui.w.Event("change",{bubbles:true}));
    await click(r.querySelector("[data-save]"));
    assert.equal(ui.calls[1].body.changes[0].value,"https://siem.example.com/ingest/{tenant_sha256}");
    assert.equal(at.value,"1");
  }finally{ui.dom.window.close();}
});

test("a document is imported from the chosen file, never saved empty",async()=>{
  const summary={text:"Version 1: 1 trusted key",items:[{label:"Trusted key",fingerprint:"ABCD 1234 …"}]};
  const ui=await page(()=>saved(ui,"ai_benchmark_exchange.trust_roots",{document:summary,value_text:summary.text}));
  try{
    const r=row(ui,"ai_benchmark_exchange.trust_roots");
    await click(r.querySelector("[data-save]"));
    assert.equal(ui.calls.length,0);
    assert.equal(r.querySelector("[data-row-status]").textContent,"Choose the file to import first.");
    await choose(ui,r.querySelector("[data-document-file]"),{name:"roots.json",size:20,text:async()=>'{"version":1}'});
    assert.match(r.querySelector("[data-row-status]").textContent,/Ready to import “roots.json”/);
    await click(r.querySelector("[data-save]"));
    assert.deepEqual(ui.calls[0].body.changes,[{id:"ai_benchmark_exchange.trust_roots",value:'{"version":1}'}]);
    assert.equal(r.querySelector("[data-document-text]").textContent,"Version 1: 1 trusted key");
    assert.match(r.querySelector("[data-document-items]").textContent,/ABCD 1234/);
    await click(r.querySelector("[data-save]"));
    assert.equal(ui.calls.length,1); // imported: nothing pending any more
  }finally{ui.dom.window.close();}
});

test("a fingerprint is worked out from the uploaded file, then saved",async()=>{
  const digest="ab".repeat(32);
  const ui=await page(url=>url.includes("/fingerprint")
    ?reply(200,{fingerprint:digest,shown:"ABAB ABAB ABAB ABAB …"})
    :saved(ui,"ai_media_provenance.c2patool_executable_sha256",{value:digest,value_text:"ABAB ABAB ABAB ABAB …"}));
  try{
    const r=row(ui,"ai_media_provenance.c2patool_executable_sha256");
    const file={name:"c2patool",size:5,marker:"the file"};
    await choose(ui,r.querySelector("[data-fingerprint-file]"),file);
    assert.equal(ui.calls[0].url,"/api/v1/settings/catalog/fingerprint?setting_id=ai_media_provenance.c2patool_executable_sha256");
    assert.equal(ui.calls[0].body.raw,file);
    assert.equal(r.querySelector("[data-fingerprint-shown]").textContent,"ABAB ABAB ABAB ABAB …");
    await click(r.querySelector("[data-save]"));
    assert.deepEqual(ui.calls[1].body.changes,[{id:"ai_media_provenance.c2patool_executable_sha256",value:digest}]);
  }finally{ui.dom.window.close();}
});

test("choosing a governance level shows what it changes before saving",async()=>{
  const ui=await page(()=>reply(200,{items:[{id:"retention.audit_days",label:"Keep the activity record for",now:"No limit",new:"365 days",lowers:true}],unchanged:3,kept:["Sign the activity record"]}));
  try{
    const r=row(ui,"governance.profile");
    const select=r.querySelector("[data-input]");
    select.value="regulated";select.dispatchEvent(new ui.w.Event("change",{bubbles:true}));await flush();
    assert.equal(ui.calls[0].url,"/api/v1/settings/catalog/preview/governance.profile?value=regulated");
    const text=r.querySelector("[data-preview]").textContent;
    assert.match(text,/Keep the activity record for: No limit → 365 days \(lowers a protection\)/);
    assert.match(text,/Left as they are \(set by your server\): Sign the activity record\./);
  }finally{ui.dom.window.close();}
});

test("a level's learning systems are named in the review before going ahead",async()=>{
  const learning=changes=>changes.some(c=>c.id==="governance.profile")
    ?[{label:"Learn from recent work on a schedule",kind:"learning",warning:"This learning system will be turned on."}]:[];
  const ui=await page(()=>saved(ui,"governance.profile",{value:"regulated",value_text:"Regulated"}),learning);
  try{
    const r=row(ui,"governance.profile");
    r.querySelector("[data-input]").value="regulated";
    await click(r.querySelector("[data-save]"));
    assert.match(ui.confirms[0],/^Learn from recent work on a schedule: This learning system will be turned on\./);
    assert.doesNotMatch(ui.confirms[0],/lowers a protection/);
    assert.equal(ui.calls.length,1);assert.equal(ui.calls[0].body.confirm,true);
  }finally{ui.dom.window.close();}
});

test("a row is named by searching a long list of people",async()=>{
  const ui=await page(()=>reply(200,{choices:[{value:"telegram:1",label:"1 on Telegram"},{value:"slack:U2",label:"U2 on Slack"}]}));
  try{
    const r=row(ui,"security.users");
    const search=r.querySelector("[data-grid-keysearch]");
    search.value="slack";search.dispatchEvent(new ui.w.Event("input",{bubbles:true}));await flush();
    assert.equal(ui.calls[0].url,"/api/v1/settings/catalog/choices/security.users");
    const pick=r.querySelector("[data-grid-newkey]");
    assert.deepEqual([...pick.options].map(o=>o.value),["","slack:U2"]);
    pick.value="slack:U2";
    await click(r.querySelector("[data-grid-add]"));
    assert.equal(r.querySelector("[data-grid-row] [data-row-label]").textContent,"U2 on Slack");
  }finally{ui.dom.window.close();}
});
