"use strict";
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

// Markup mirrors templates/settings_all.html for four representative rows.
const HTML=`<!doctype html><main>
<div role="status" id="settings-all-status" hidden></div>
<input id="settings-all-search"><select id="settings-all-group"><option value="">All</option><option value="safety">Safety</option><option value="modules">Modules</option></select>
<input type="checkbox" id="settings-all-changed"><p id="settings-all-filter-status"></p>
<div id="settings-all-groups">
<section class="settings-all-group" data-group="safety"><h2>Safety</h2>
 <div class="settings-all-row" data-setting-id="safety.profile" data-control="select" data-source="default" data-search="safety level screening">
  <strong data-value-text>Balanced</strong><span data-source-text>Default</span>
  <select data-input id="p"><option value="strict">Strict</option><option value="balanced" selected>Balanced</option><option value="off">Off</option></select>
  <button data-save>Save</button><button data-reset>Reset to default</button><p data-row-status></p></div>
 <div class="settings-all-row" data-setting-id="sandbox.timeout" data-control="number" data-source="here" data-search="time limit command">
  <strong data-value-text>60 seconds</strong><span data-source-text>Set here</span>
  <input type="number" data-input value="60"><button data-save>Save</button><button data-reset>Reset to default</button><p data-row-status></p></div>
 <div class="settings-all-row" data-setting-id="notifications.ntfy_topic" data-control="secret" data-source="default" data-search="ntfy topic">
  <span data-secret-state>Not set</span><button data-secret-replace>Add</button><input type="password" data-input hidden>
  <button data-save>Save</button><button data-reset>Reset to default</button><p data-row-status></p></div>
 <div class="settings-all-row" data-setting-id="webhooks.outbound" data-control="list" data-source="default" data-search="task events addresses">
  <ul class="settings-all-list-items"></ul><button data-list-add>Add an address</button>
  <button data-save>Save</button><button data-reset>Reset to default</button><p data-row-status></p></div>
 <p><button data-save-group="safety">Save changes in Safety</button><button data-reset-group="safety">Reset all in Safety</button></p>
</section>
<section class="settings-all-group" data-group="modules"><h2>Modules</h2>
 <div class="settings-all-row" data-module="policy_packs" data-search="policy packs module">
  <span class="settings-all-label">Policy packs</span><strong data-value-text>Off</strong>
  <input type="checkbox" data-module-toggle><p data-row-status></p></div>
</section></div><p id="settings-all-empty" hidden></p></main>`;

function stateFor(id,over){
  return {groups:[{settings:[Object.assign({id,value:null,value_text:"x",source:"here",source_text:"Set here"},over||{})]}]};
}

async function page(handler,warnings){
  const dom=new JSDOM(HTML,{url:"https://lightwork.test/settings/all",runScripts:"outside-only"});
  const w=dom.window,d=w.document,calls=[],confirms=[];
  w.mvConfirm=async message=>{confirms.push(message);return true;};
  reviewedSaving(w,{confirms,warnings});
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

test("saving one setting sends its value and shows where it now comes from",async()=>{
  const ui=await page((url,body)=>reply(200,{changed:[body.changes[0].id],restart:false,...stateFor("safety.profile",{value:"strict",value_text:"Strict"})}));
  try{
    row(ui,"safety.profile").querySelector("select").value="strict";
    await click(row(ui,"safety.profile").querySelector("[data-save]"));
    // Sent once, after the complete review, with the review's sealed token.
    assert.deepEqual(ui.calls[0].body,{changes:[{id:"safety.profile",value:"strict"}],reviewed_token:"sealed-review",confirm:true});
    assert.equal(ui.calls[0].url,"/api/v1/settings/catalog");
    assert.equal(row(ui,"safety.profile").querySelector("[data-value-text]").textContent,"Strict");
    assert.equal(row(ui,"safety.profile").querySelector("[data-source-text]").textContent,"Set here");
    assert.match(row(ui,"safety.profile").querySelector("[data-row-status]").textContent,/Saved/);
  }finally{ui.dom.window.close();}
});

test("a weakening change shows its warning in the review before anything is sent",async()=>{
  const weaker=changes=>changes.some(c=>c.id==="safety.profile"&&c.value==="off")
    ?[{label:"Safety level",warning:"Agents will be screened less strictly."}]:[];
  const ui=await page(()=>reply(200,{changed:["safety.profile"],...stateFor("safety.profile",{value:"off"})}),weaker);
  try{
    row(ui,"safety.profile").querySelector("select").value="off";
    await click(row(ui,"safety.profile").querySelector("[data-save]"));
    assert.equal(ui.confirms.length,1);
    assert.match(ui.confirms[0],/Safety level: Agents will be screened less strictly/);
    assert.equal(ui.calls.length,1);assert.equal(ui.calls[0].body.confirm,true);
  }finally{ui.dom.window.close();}
});

test("a refused value shows the page's own sentence, never a raw status",async()=>{
  const ui=await page(()=>reply(400,{detail:"x",message:"Time limit for each command: enter at least 5."}));
  try{
    row(ui,"sandbox.timeout").querySelector("input").value="1";
    await click(row(ui,"sandbox.timeout").querySelector("[data-save]"));
    const text=row(ui,"sandbox.timeout").querySelector("[data-row-status]").textContent;
    assert.equal(text,"Time limit for each command: enter at least 5.");
    assert.doesNotMatch(text,/400|HTTP/);
  }finally{ui.dom.window.close();}
});

test("secrets are only sent after Replace, and the field is cleared afterwards",async()=>{
  const ui=await page(()=>reply(200,{changed:["notifications.ntfy_topic"],...stateFor("notifications.ntfy_topic",{is_set:true,value_text:"Set"})}));
  try{
    const r=row(ui,"notifications.ntfy_topic");
    await click(r.querySelector("[data-save]"));
    assert.equal(ui.calls.length,0);
    await click(r.querySelector("[data-secret-replace]"));
    const input=r.querySelector("[data-input]");
    assert.equal(input.hidden,false);
    input.value="topic-123";
    await click(r.querySelector("[data-save]"));
    assert.deepEqual(ui.calls[0].body.changes,[{id:"notifications.ntfy_topic",value:"topic-123"}]);
    assert.equal(input.value,"");assert.equal(input.hidden,true);
    assert.equal(r.querySelector("[data-secret-state]").textContent,"Set");
  }finally{ui.dom.window.close();}
});

test("the address list editor adds rows and the group save sends only changed settings",async()=>{
  const ui=await page(()=>reply(200,{changed:["webhooks.outbound"],restart:true,groups:[]}));
  try{
    const r=row(ui,"webhooks.outbound");
    await click(r.querySelector("[data-list-add]"));
    const item=r.querySelector("[data-list-item]");
    assert.ok(item&&ui.d.querySelector('label[for="'+item.id+'"]'));
    item.value="https://hooks.example/a";
    await click(ui.d.querySelector('[data-save-group="safety"]'));
    assert.deepEqual(ui.calls[0].body.changes,[{id:"webhooks.outbound",value:["https://hooks.example/a"]}]);
    assert.match(ui.d.getElementById("settings-all-status").textContent,/configuration status.*services that need a restart/);
  }finally{ui.dom.window.close();}
});

test("reset all confirms and resets only settings that are not already default",async()=>{
  const ui=await page(()=>reply(200,{changed:["sandbox.timeout"],groups:[]}));
  try{
    await click(ui.d.querySelector('[data-reset-group="safety"]'));
    assert.equal(ui.confirms.length,1);
    assert.deepEqual(ui.calls[0].body.changes,[{id:"sandbox.timeout",reset:true}]);
  }finally{ui.dom.window.close();}
});

test("module switches call the module service and search filters rows",async()=>{
  const ui=await page(()=>reply(200,{section:"policy_packs",enabled:true}));
  try{
    const toggle=ui.d.querySelector("[data-module-toggle]");
    toggle.checked=true;toggle.dispatchEvent(new ui.w.Event("change",{bubbles:true}));await flush();
    assert.equal(ui.calls[0].url,"/api/v1/features/modules");
    assert.deepEqual(ui.calls[0].body,{section:"policy_packs",enabled:true});
    assert.equal(ui.d.querySelector('[data-module="policy_packs"] [data-value-text]').textContent,"On");
    const search=ui.d.getElementById("settings-all-search");
    search.value="ntfy";search.dispatchEvent(new ui.w.Event("input"));
    assert.equal(row(ui,"notifications.ntfy_topic").hidden,false);
    assert.equal(row(ui,"safety.profile").hidden,true);
    assert.equal(ui.d.querySelector('[data-group="modules"]').hidden,true);
    assert.match(ui.d.getElementById("settings-all-filter-status").textContent,/1 setting shown/);
  }finally{ui.dom.window.close();}
});

// ---- guided forms: publisher keys, tables, parts of a group -----------------
const FORMS=`<!doctype html><main>
<div role="status" id="settings-all-status" hidden></div>
<input id="settings-all-search"><select id="settings-all-group"><option value="">All</option></select>
<input type="checkbox" id="settings-all-changed"><p id="settings-all-filter-status"></p>
<div id="settings-all-groups">
<section class="settings-all-group" data-group="safety"><h2>Safety</h2>
 <select data-subgroup-pick><option value="">Everything</option><option value="safety-skill-publishers">Skill publishers</option><option value="safety-limits">Limits</option></select>
 <h3 data-subgroup-head="safety-skill-publishers">Skill publishers</h3>
 <div class="settings-all-row" data-setting-id="skills.trusted_pubkeys" data-control="keys" data-source="here" data-subgroup="safety-skill-publishers" data-search="trusted skill publishers">
  <strong data-value-text>1 trusted key</strong><span data-source-text>Set here</span>
  <div data-keys><ul data-key-list><li data-key-item data-key="aa11"><span>Publisher key, fingerprint <strong>AAAA BBBB</strong></span><button data-key-remove>Remove</button></li></ul>
  <p data-keys-empty hidden>No publishers are trusted yet.</p>
  <input type="file" data-key-file><textarea data-key-paste></textarea><button data-key-add>Add this key</button></div>
  <button data-save>Save</button><button data-reset>Reset to default</button><p data-row-status></p></div>
 <p data-subgroup-actions="safety-skill-publishers"><button data-save-subgroup="safety-skill-publishers">Save Skill publishers</button></p>
 <h3 data-subgroup-head="safety-limits">Limits</h3>
 <div class="settings-all-row" data-setting-id="rate_limits.other" data-control="table" data-source="default" data-subgroup="safety-limits" data-search="usage limits other tools">
  <strong data-value-text>None</strong><span data-source-text>Default</span>
  <div data-table data-row-kind="rate" data-choices-url="/api/v1/settings/catalog/choices/rate_limits.other">
   <table><tbody data-table-body></tbody></table><p data-table-empty>No other limits yet.</p>
   <input type="search" data-table-search><select data-table-pick><option value="">Search above</option></select><button data-table-add>Add a limit</button></div>
  <button data-save>Save</button><button data-reset>Reset to default</button><p data-row-status></p></div>
 <div class="settings-all-row" data-setting-id="mcp_sidecar.tools" data-control="table" data-source="default" data-subgroup="safety-limits" data-search="reviewed tools">
  <strong data-value-text>None</strong><span data-source-text>Default</span>
  <div data-table data-row-kind="risk"><table><tbody data-table-body></tbody></table><p data-table-empty>No tools are offered yet.</p>
   <input type="text" data-table-newname><select data-table-newrisk><option value="low">Low risk</option><option value="high" selected>High risk</option></select><button data-table-add>Add a tool</button></div>
  <button data-save>Save</button><button data-reset>Reset to default</button><p data-row-status></p></div>
 <p data-subgroup-actions="safety-limits"><button data-save-subgroup="safety-limits">Save Limits</button></p>
</section></div><p id="settings-all-empty" hidden></p></main>`;

async function formsPage(handler){
  const dom=new JSDOM(FORMS,{url:"https://lightwork.test/settings/all",runScripts:"outside-only"});
  const w=dom.window,d=w.document,calls=[],confirms=[];
  w.mvConfirm=async message=>{confirms.push(message);return true;};
  reviewedSaving(w,{confirms});
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

test("publisher keys: paste adds a key, remove drops one, save sends kept and new keys",async()=>{
  const ui=await formsPage(()=>reply(200,{changed:["skills.trusted_pubkeys"],...stateFor("skills.trusted_pubkeys",
    {key_items:[{value:"bb22",fingerprint:"CCCC DDDD"}],value_text:"1 trusted key"})}));
  try{
    const r=row(ui,"skills.trusted_pubkeys");
    await click(r.querySelector("[data-key-add]"));
    assert.match(r.querySelector("[data-row-status]").textContent,/Paste the publisher key first/);
    r.querySelector("[data-key-paste]").value="ssh-ed25519 AAAA publisher";
    await click(r.querySelector("[data-key-add]"));
    assert.match(r.textContent,/New publisher key/);
    await click(r.querySelector("[data-key-remove]"));
    await click(r.querySelector("[data-save]"));
    assert.deepEqual(ui.calls[0].body.changes,[{id:"skills.trusted_pubkeys",value:["ssh-ed25519 AAAA publisher"]}]);
    // The page redraws the list from the server: fingerprints only.
    assert.match(r.querySelector("[data-key-list]").textContent,/CCCC DDDD/);
    assert.doesNotMatch(r.querySelector("[data-key-list]").textContent,/ssh-ed25519/);
    assert.equal(r.querySelector("[data-keys-empty]").hidden,true);
  }finally{ui.dom.window.close();}
});

test("usage limits: the tool picker loads live choices, search narrows it, rows are sent",async()=>{
  const ui=await formsPage(url=>url.indexOf("/choices/")!==-1
    ?reply(200,{choices:[{value:"mcp_*",label:"Every tool from outside tool servers"},{value:"wiki_search",label:"Wiki search"}]})
    :reply(200,{changed:["rate_limits.other"],groups:[]}));
  try{
    const r=row(ui,"rate_limits.other");
    await click(r.querySelector("[data-table-add]"));
    assert.match(r.querySelector("[data-row-status]").textContent,/Find and choose a tool first/);
    const search=r.querySelector("[data-table-search]");
    search.value="wiki";search.dispatchEvent(new ui.w.Event("input",{bubbles:true}));await flush();
    const pick=r.querySelector("[data-table-pick]");
    assert.deepEqual([...pick.options].map(o=>o.value),["","wiki_search"]);
    pick.value="wiki_search";
    await click(r.querySelector("[data-table-add]"));
    const tr=r.querySelector("[data-table-row]");
    assert.equal(tr.querySelector("[data-row-label]").textContent,"Wiki search");
    assert.ok(tr.querySelector("[data-count]").getAttribute("aria-label"));
    tr.querySelector("[data-count]").value="5";tr.querySelector("[data-period]").value="3600";
    await click(ui.d.querySelector('[data-save-subgroup="safety-limits"]'));
    const save=ui.calls.find(c=>c.method==="POST");
    assert.deepEqual(save.body.changes,[{id:"rate_limits.other",value:[{name:"wiki_search",count:5,seconds:3600}]}]);
  }finally{ui.dom.window.close();}
});

test("reviewed tools: names are checked in the page and the risk level is sent",async()=>{
  const ui=await formsPage(()=>reply(200,{changed:["mcp_sidecar.tools"],groups:[]}));
  try{
    const r=row(ui,"mcp_sidecar.tools");
    r.querySelector("[data-table-newname]").value="bad name";
    await click(r.querySelector("[data-table-add]"));
    assert.match(r.querySelector("[data-row-status]").textContent,/letters, numbers/);
    r.querySelector("[data-table-newname]").value="search.docs";
    r.querySelector("[data-table-newrisk]").value="low";
    await click(r.querySelector("[data-table-add]"));
    assert.equal(r.querySelector("[data-table-empty]").hidden,true);
    await click(r.querySelector("[data-save]"));
    assert.deepEqual(ui.calls[0].body.changes,[{id:"mcp_sidecar.tools",value:[{name:"search.docs",risk:"low"}]}]);
  }finally{ui.dom.window.close();}
});

test("choosing one part of a group shows only that part and its save button",async()=>{
  const ui=await formsPage(()=>reply(200,{}));
  try{
    const pick=ui.d.querySelector("[data-subgroup-pick]");
    pick.value="safety-limits";pick.dispatchEvent(new ui.w.Event("change",{bubbles:true}));
    assert.equal(row(ui,"skills.trusted_pubkeys").hidden,true);
    assert.equal(row(ui,"rate_limits.other").hidden,false);
    assert.equal(ui.d.querySelector('[data-subgroup-head="safety-skill-publishers"]').hidden,true);
    assert.equal(ui.d.querySelector('[data-subgroup-actions="safety-skill-publishers"]').hidden,true);
    assert.equal(ui.d.querySelector('[data-subgroup-actions="safety-limits"]').hidden,false);
  }finally{ui.dom.window.close();}
});
