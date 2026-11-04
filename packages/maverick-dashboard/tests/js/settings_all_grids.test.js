"use strict";
// Settings > All settings: the row editors for tools per chat app, spending per
// AI service and approval rules (``grid`` tables and ``rules``).
const {test}=require("node:test");
const assert=require("node:assert/strict");
const fs=require("node:fs"),path=require("node:path");
const {JSDOM}=require("jsdom");
const {shell} = require('./_shell');
const root=path.resolve(__dirname,"../../maverick_dashboard");
const read=name=>fs.readFileSync(path.join(root,name),"utf8");
const flush=async()=>{for(let i=0;i<20;i++){await new Promise(setImmediate);await new Promise(r=>setTimeout(r,2));}};
const reply=(status,body)=>({ok:status<400,status,headers:{get:()=>null},json:async()=>body});
const attr=value=>JSON.stringify(value).replace(/'/g,"\\u0027");

const ACL={kind:"grid",row_label:"Chat app",item_label:"Chat app",
  key_choices:[{value:"slack",label:"Slack"},{value:"telegram",label:"Telegram"}],
  columns:[
    {key:"denied_tools",label:"Blocked tools",kind:"picks",choices:[],choices_url:"/api/v1/settings/catalog/choices/security.channels?column=denied_tools"},
    {key:"allowed_tools",label:"Only these tools",kind:"picks",choices:[],choices_url:"/api/v1/settings/catalog/choices/security.channels?column=allowed_tools"},
    {key:"max_risk",label:"Riskiest tools allowed",kind:"select",default:"",choices:[{value:"",label:"No extra limit"},{value:"low",label:"Low risk only"},{value:"medium",label:"Up to medium risk"}]}],
  rows:[{name:"slack",label:"Slack",cells:{denied_tools:[{value:"shell",label:"Shell"}],allowed_tools:[],max_risk:{value:"",label:"No extra limit"}}}]};
const CAPS={kind:"grid",row_label:"AI service",item_label:"AI service",
  key_choices:[{value:"anthropic",label:"Anthropic (Claude)"}],
  columns:[{key:"cap",label:"Most to spend",kind:"number",minimum:0.01,maximum:10000000,step:"any",unit:"dollars",choices:[]}],rows:[]};
const RULES={kind:"rules",item_label:"Rule",
  columns:[
    {key:"delegate_to",label:"Send to",kind:"select",required:true,choices:[{value:"user:ada",label:"Ada"}]},
    {key:"min_risk",label:"For risk",kind:"select",default:"",choices:[{value:"",label:"Any risk"},{value:"high",label:"High and above"}]},
    {key:"tool_glob",label:"For tool",kind:"pick",default:"*",choices:[],choices_url:"/api/v1/settings/catalog/choices/approval.delegation?column=tool_glob"}],
  rows:[]};

function gridRow(id,state,empty){
  const addKey=state.kind==="grid"
    ?`<select data-grid-newkey><option value="">Choose one</option>${state.key_choices.map(k=>`<option value="${k.value}">${k.label}</option>`).join("")}</select>`:"";
  return `<div class="settings-all-row" data-setting-id="${id}" data-control="${state.kind==="grid"?"table":"rules"}" data-source="default" data-search="${id}">
  <strong data-value-text>None</strong><span data-source-text>Default</span>
  <div data-grid data-grid-state='${attr(state)}'><table><tbody data-grid-body></tbody></table>
  <p data-grid-empty>${empty}</p>${addKey}<button data-grid-add>Add</button></div>
  <button data-save>Save</button><button data-reset>Reset to default</button><p data-row-status></p></div>`;
}
const HTML=`<!doctype html><main>
<div role="status" id="settings-all-status" hidden></div>
<input id="settings-all-search"><select id="settings-all-group"><option value="">All</option></select>
<input type="checkbox" id="settings-all-changed"><p id="settings-all-filter-status"></p>
<div id="settings-all-groups"><section class="settings-all-group" data-group="safety"><h2>Safety</h2>
${gridRow("security.channels",ACL,"No chat app has its own tool rules yet.")}
${gridRow("budget.provider_caps",CAPS,"No AI service has a spending limit yet.")}
${gridRow("approval.delegation",RULES,"No rules yet.")}
</section></div><p id="settings-all-empty" hidden></p></main>`;

// Saving goes through the complete protected review (lightwork-settings-review.js
// and lightwork-settings-catalog-requests.js). The stand-ins show the person the
// review's warnings (recorded in ``confirms``), accept it, and save the reviewed
// plan with its sealed token, as the real pair does.
async function page(handler,warnings){
  const dom=new JSDOM(HTML,{url:"https://lightwork.test/settings/all",runScripts:"outside-only"});
  const w=dom.window,d=w.document,calls=[],confirms=[];
  w.mvConfirm=async message=>{confirms.push(message);return true;};
  w.mvReviewSettings=async(changes,revision)=>{
    (warnings?warnings(changes):[]).forEach(item=>confirms.push(item.label+": "+item.warning));
    return {changes,revision,token:"sealed-review",operation:"0".repeat(32),context:"c".repeat(64)};
  };
  w.LightworkSettingsCatalog={save:async plan=>{
    const response=await w.fetch("/api/v1/settings/catalog",{method:"POST",body:JSON.stringify({changes:plan.changes,
      expected_revision:plan.revision,reviewed_token:plan.token,confirm:true})});
    return {response,data:await response.json()};
  }};
  w.mvErrorText=(failure,action)=>"Could not "+action+".";
  w.mvToast=()=>{};
  w.fetch=async(url,init={})=>{
    const body=init.body?JSON.parse(init.body):null;calls.push({url,method:init.method||"GET",body});
    return handler(url,body,calls.length);
  };
  shell(w);
  w.eval(read("static/lightwork-settings-all.js"));
  await flush();
  return {dom,w,d,calls,confirms};
}
const row=(ui,id)=>ui.d.querySelector('[data-setting-id="'+id+'"]');
const click=async(node)=>{node.click();await flush();};
const TOOLS=[{value:"mcp_*",label:"Every tool from outside tool servers"},{value:"shell",label:"Shell"},
  {value:"http_fetch",label:"Http fetch"},{value:"write_file",label:"Write file"}];

test("tools per chat app: saved rows are drawn, and the page sends every column",async()=>{
  const ui=await page(url=>url.indexOf("/choices/")!==-1?reply(200,{choices:TOOLS})
    :reply(200,{changed:["security.channels"],groups:[]}));
  try{
    const r=row(ui,"security.channels");
    const first=r.querySelector("[data-grid-row]");
    assert.equal(first.querySelector("[data-row-label]").textContent,"Slack");
    assert.match(first.querySelector('[data-cell="denied_tools"]').textContent,/Shell/);
    assert.equal(r.querySelector("[data-grid-empty]").hidden,true);
    // Every control the page draws is labelled.
    r.querySelectorAll("[data-grid-row] select, [data-grid-row] input, [data-grid-row] button")
      .forEach(node=>assert.ok(node.getAttribute("aria-label"),node.outerHTML));
    // Add a second app, then block a tool found by searching the live list.
    await click(r.querySelector("[data-grid-add]"));
    assert.match(r.querySelector("[data-row-status]").textContent,/Choose one from the list first/);
    r.querySelector("[data-grid-newkey]").value="telegram";
    await click(r.querySelector("[data-grid-add]"));
    const added=r.querySelectorAll("[data-grid-row]")[1];
    assert.equal(added.dataset.name,"telegram");
    const cell=added.querySelector('[data-cell="denied_tools"]');
    const search=cell.querySelector("[data-pick-search]");
    search.value="http";search.dispatchEvent(new ui.w.Event("input",{bubbles:true}));await flush();
    const pick=cell.querySelector("[data-pick-select]");
    assert.deepEqual([...pick.options].map(o=>o.value),["","http_fetch"]);
    pick.value="http_fetch";
    await click(cell.querySelector("[data-pick-add]"));
    added.querySelector('[data-cell="max_risk"] select').value="low";
    await click(r.querySelector("[data-save]"));
    const save=ui.calls.find(c=>c.method==="POST");
    assert.deepEqual(save.body.changes,[{id:"security.channels",value:[
      {name:"slack",denied_tools:["shell"],allowed_tools:[],max_risk:""},
      {name:"telegram",denied_tools:["http_fetch"],allowed_tools:[],max_risk:"low"}]}]);
  }finally{ui.dom.window.close();}
});

test("unblocking a tool shows its warning in the review, then saves the reviewed change once",async()=>{
  const ui=await page((url,body)=>body&&body.confirm&&body.reviewed_token==="sealed-review"
    ?reply(200,{changed:["security.channels"],groups:[{settings:[{id:"security.channels",value:null,
      value_text:"1 chat app",source:"here",source_text:"Set here",
      grid:Object.assign({},ACL,{rows:[{name:"slack",label:"Slack",cells:{denied_tools:[],allowed_tools:[],max_risk:{value:"",label:"No extra limit"}}}]})}]}]})
    :reply(409,{detail:"confirmation required"}),
  changes=>changes.some(c=>c.id==="security.channels")
    ?[{label:"Tools allowed in each chat app",warning:"Agents will be able to use more tools."}]:[]);
  try{
    const r=row(ui,"security.channels");
    await click(r.querySelector('[data-cell="denied_tools"] [data-pick-remove]'));
    await click(r.querySelector("[data-save]"));
    assert.equal(ui.confirms.length,1);
    assert.match(ui.confirms[0],/Tools allowed in each chat app: Agents will be able to use more tools/);
    const posts=ui.calls.filter(c=>c.method==="POST");
    assert.equal(posts.length,1);assert.equal(posts[0].body.confirm,true);
    assert.deepEqual(posts[0].body.changes,[{id:"security.channels",value:[
      {name:"slack",denied_tools:[],allowed_tools:[],max_risk:""}]}]);
    // The server's answer redraws the rows.
    assert.equal(r.querySelectorAll("[data-pick-item]").length,0);
    assert.equal(r.querySelector("[data-value-text]").textContent,"1 chat app");
  }finally{ui.dom.window.close();}
});

test("spending per AI service sends the amount as a number",async()=>{
  const ui=await page(()=>reply(200,{changed:["budget.provider_caps"],groups:[]}));
  try{
    const r=row(ui,"budget.provider_caps");
    assert.equal(r.querySelector("[data-grid-empty]").hidden,false);
    r.querySelector("[data-grid-newkey]").value="anthropic";
    await click(r.querySelector("[data-grid-add]"));
    assert.equal(r.querySelector("[data-grid-empty]").hidden,true);
    const amount=r.querySelector('[data-cell="cap"] input');
    assert.match(amount.getAttribute("aria-label"),/Most to spend for Anthropic/);
    amount.value="50";
    await click(r.querySelector("[data-save]"));
    assert.deepEqual(ui.calls[0].body.changes,[{id:"budget.provider_caps",value:[{name:"anthropic",cap:50}]}]);
  }finally{ui.dom.window.close();}
});

test("approval rules: a new rule starts on any tool, a person is chosen, removal empties the list",async()=>{
  const ui=await page(url=>url.indexOf("/choices/")!==-1
    ?reply(200,{choices:[{value:"*",label:"Any tool"},{value:"shell",label:"Shell"}]})
    :reply(200,{changed:["approval.delegation"],groups:[]}));
  try{
    const r=row(ui,"approval.delegation");
    await click(r.querySelector("[data-grid-add]"));
    const rule=r.querySelector("[data-grid-row]");
    assert.equal(rule.querySelector('[data-cell="tool_glob"] select').value,"*");
    assert.equal(rule.querySelector('[data-cell="tool_glob"] select').selectedOptions[0].textContent,"Any tool");
    rule.querySelector('[data-cell="delegate_to"] select').value="user:ada";
    rule.querySelector('[data-cell="min_risk"] select').value="high";
    await click(r.querySelector("[data-save]"));
    assert.deepEqual(ui.calls[0].body.changes,[{id:"approval.delegation",
      value:[{delegate_to:"user:ada",min_risk:"high",tool_glob:"*"}]}]);
    await click(rule.querySelector("[data-grid-remove]"));
    assert.equal(r.querySelector("[data-grid-empty]").hidden,false);
    await click(r.querySelector("[data-save]"));
    assert.deepEqual(ui.calls.filter(c=>c.method==="POST")[1].body.changes,[{id:"approval.delegation",value:[]}]);
  }finally{ui.dom.window.close();}
});
