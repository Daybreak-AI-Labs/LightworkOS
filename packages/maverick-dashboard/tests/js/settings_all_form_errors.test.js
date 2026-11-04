"use strict";
// The shared form-field pattern on Settings > All settings, e.g. approval rules: a table value that
// can't be saved is named next to its row and in a summary that takes focus,
// the title starts with "Error: ", nothing is sent and nothing typed is lost.
const {test}=require("node:test");
const assert=require("node:assert/strict");
const fs=require("node:fs"),path=require("node:path");
const {JSDOM}=require("jsdom");
const {shell}=require("./_shell");
const root=path.resolve(__dirname,"../../maverick_dashboard");
const read=name=>fs.readFileSync(path.join(root,name),"utf8");
const flush=async()=>{for(let i=0;i<20;i++){await new Promise(setImmediate);await new Promise(r=>setTimeout(r,2));}};
const attr=value=>JSON.stringify(value).replace(/'/g,"\\u0027");

const APPROVERS={kind:"grid",row_label:"Risk level",item_label:"Risk level",
  key_choices:[{value:"high",label:"High"},{value:"critical",label:"Critical"}],
  columns:[{key:"people",label:"People who must approve",kind:"number",minimum:1,maximum:5,integer:true,unit:"people",required:true,choices:[]}],
  rows:[{name:"high",label:"High",cells:{people:2}}]};
const RULES={kind:"rules",item_label:"Rule",
  columns:[{key:"delegate_to",label:"Send to",kind:"select",required:true,choices:[{value:"user:ada",label:"Ada"}]},
    {key:"min_risk",label:"For risk",kind:"select",default:"",choices:[{value:"",label:"Any risk"},{value:"high",label:"High and above"}]}],
  rows:[]};
function gridRow(id,state){
  const addKey=state.kind==="grid"?`<select data-grid-newkey><option value="">Choose one</option>${state.key_choices.map(k=>`<option value="${k.value}">${k.label}</option>`).join("")}</select>`:"";
  return `<div class="settings-all-row" data-setting-id="${id}" data-control="${state.kind==="grid"?"table":"rules"}" data-source="default" data-search="${id}">
  <strong data-value-text>None</strong><span data-source-text>Default</span>
  <div data-grid data-grid-state='${attr(state)}'><table><tbody data-grid-body></tbody></table><p data-grid-empty>None</p>${addKey}<button data-grid-add>Add</button></div>
  <button data-save>Save</button><button data-reset>Reset to default</button><p data-row-status></p></div>`;
}
async function page(){
  const dom=new JSDOM(`<!doctype html><title>All settings · Lightwork</title><main><div role="status" id="settings-all-status" hidden></div>
    <input id="settings-all-search"><select id="settings-all-group"><option value="">All</option></select><input type="checkbox" id="settings-all-changed">
    <div id="settings-all-groups"><section class="settings-all-group" data-group="security"><h2>Security</h2>
    ${gridRow("security.approvals_required_by_risk",APPROVERS)}${gridRow("approval.delegation",RULES)}</section></div><p id="settings-all-empty" hidden></p></main>`,
    {url:"https://lightwork.test/settings/all",runScripts:"outside-only"});
  const w=dom.window,calls=[];
  w.fetch=async(url,init={})=>{calls.push({url,method:init.method||"GET"});return {ok:true,status:200,headers:{get:()=>null},json:async()=>({choices:[]})};};
  shell(w);
  w.eval(read("static/lightwork-settings-all.js"));
  await flush();
  return {w,d:w.document,calls,posts:()=>calls.filter(c=>c.method==="POST")};
}
const row=(ui,id)=>ui.d.querySelector('[data-setting-id="'+id+'"]');
const summary=ui=>[...ui.d.querySelectorAll("#settings-all-errors:not([hidden]) a")].map(a=>[a.getAttribute("href"),a.textContent]);

test("approvers per risk: an empty or out-of-range number is explained, focused and kept",async()=>{
  const ui=await page();
  try{
    const r=row(ui,"security.approvals_required_by_risk");
    const people=r.querySelector('[data-cell="people"] input');
    assert.equal(people.required,true);assert.equal(people.step,"1");
    people.value="7";
    r.querySelector("[data-save]").click();await flush();
    assert.deepEqual(summary(ui),[["#"+people.id,"Enter “People who must approve” for High from 1 to 5."]]);
    assert.equal(ui.d.activeElement.id,"settings-all-errors");
    assert.equal(ui.d.title,"Error: All settings · Lightwork");
    assert.equal(people.getAttribute("aria-invalid"),"true");
    assert.ok(people.getAttribute("aria-describedby").split(" ").includes(r.querySelector("[data-row-status]").id));
    assert.match(r.querySelector("[data-row-status]").textContent,/from 1 to 5\. Nothing was saved\./);
    assert.equal(people.value,"7");
    assert.deepEqual(ui.posts(),[]);
    people.value="2.5";
    r.querySelector("[data-save]").click();await flush();
    assert.deepEqual(summary(ui)[0][1],"Enter a whole number for “People who must approve” for High.");
  }finally{ui.w.close();}
});

test("approval rules: a rule with nobody to send it to is caught before anything is sent",async()=>{
  const ui=await page();
  try{
    const r=row(ui,"approval.delegation");
    r.querySelector("[data-grid-add]").click();await flush();
    const to=r.querySelector('[data-cell="delegate_to"] select');
    to.value="";
    r.querySelector("[data-save]").click();await flush();
    assert.deepEqual(summary(ui),[["#"+to.id,"Choose “Send to” in rule 1."]]);
    assert.deepEqual(ui.posts(),[]);
    // Fixing it clears the summary and the title on the next save.
    to.value="user:ada";
    r.querySelector("[data-save]").click();await flush();
    assert.equal(ui.d.getElementById("settings-all-errors").hidden,true);
    assert.equal(ui.d.title,"All settings · Lightwork");
    assert.equal(to.getAttribute("aria-invalid"),null);
  }finally{ui.w.close();}
});
