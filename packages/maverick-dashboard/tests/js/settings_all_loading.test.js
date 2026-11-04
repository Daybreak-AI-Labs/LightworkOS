"use strict";
const {test}=require("node:test");
const assert=require("node:assert/strict");
const fs=require("node:fs"),path=require("node:path");
const {JSDOM}=require("jsdom");
const {reviewedSaving}=require('./_settings_review');
const root=path.resolve(__dirname,"../../maverick_dashboard");
const read=name=>fs.readFileSync(path.join(root,name),"utf8");
const flush=async()=>{for(let i=0;i<20;i++){await new Promise(setImmediate);await new Promise(r=>setTimeout(r,2));}};
const reply=(status,body)=>({ok:status<400,status,headers:{get:()=>null},json:async()=>body,text:async()=>body});

// Markup mirrors templates/settings_all.html as it first arrives: the list of
// groups, none of their settings (the rows come from /settings/all/rows).
const section=(slug,name,parts)=>`<section class="settings-all-group" data-group="${slug}" data-loaded="0"><h2 id="group-${slug}">${name}</h2>
 <p data-group-load><a href="/settings/all?group=${slug}#group-${slug}" data-load-group="${slug}">Show the settings in ${name}</a></p>
 ${parts?`<select data-subgroup-pick><option value="">Everything</option>${parts.map(p=>`<option value="${p}">${p}</option>`).join("")}</select>`:""}
 <div data-group-rows><div data-rows=""></div></div>
 <p><button data-save-group="${slug}">Save changes in ${name}</button><button data-reset-group="${slug}">Reset all in ${name}</button></p></section>`;
const HTML=`<!doctype html><main>
<div role="status" id="settings-all-status" hidden></div>
<form id="settings-all-filter-form"><input id="settings-all-search" name="q"><select id="settings-all-group" name="group"><option value="">All</option><option value="safety">Safety</option><option value="privacy">Privacy</option><option value="modules">Modules</option></select>
<input type="checkbox" id="settings-all-changed" name="changed" value="1"><button type="submit">Find</button></form><p id="settings-all-filter-status"></p>
<div id="settings-all-groups" data-rows-url="/settings/all/rows">
${section("safety","Safety",["safety-limits","safety-approvals"])}
${section("privacy","Privacy")}
<section class="settings-all-group" data-group="modules"><h2>Modules</h2>
 <div class="settings-all-row" data-module="policy_packs" data-search="policy packs module"><span class="settings-all-label">Policy packs</span>
  <strong data-value-text>Off</strong><input type="checkbox" data-module-toggle><p data-row-status></p></div></section>
</div><p id="settings-all-empty" hidden></p></main>`;

// Rows as templates/_settings_all_row.html renders them.
const rowHtml=(id,group,order,extra)=>`<div class="settings-all-row" data-setting-id="${id}" data-control="select" data-source="${(extra&&extra.source)||"default"}" data-warning=""
 data-in-group="${group}" data-order="${order}" ${extra&&extra.part?`data-subgroup="${extra.part}"`:""} data-search="${(extra&&extra.search)||id}">
 <strong data-value-text>A</strong><span data-source-text>Default</span>
 <select data-input><option value="a" selected>A</option><option value="b">B</option></select>
 <button data-save>Save</button><button data-reset>Reset to default</button><p data-row-status></p></div>`;
const part=(slug,order,rows)=>`<div data-part="${slug}" data-part-order="${order}"><h3 data-subgroup-head="${slug}">${slug}</h3>
 <div data-rows="${slug}">${rows}</div><p data-subgroup-actions="${slug}"><button data-save-subgroup="${slug}">Save ${slug}</button></p></div>`;
const fragment=(complete,groups)=>`<div data-rows-fragment data-complete="${complete}">${groups}</div>`;
const SAFETY=fragment("safety",`<div data-fragment-group="safety"><div data-rows="">${rowHtml("safety.profile","safety",0,{search:"safety level"})}</div>
 ${part("safety-limits",1,rowHtml("rate_limits.default","safety",1,{part:"safety-limits",search:"usage limit retention",source:"here"})+rowHtml("rate_limits.window","safety",2,{part:"safety-limits",search:"usage window"}))}
 ${part("safety-approvals",2,rowHtml("approval.timeout","safety",3,{part:"safety-approvals",search:"approval wait"}))}</div>`);
const FOUND=fragment("",`<div data-fragment-group="safety"><div data-rows=""></div>
 ${part("safety-limits",1,rowHtml("rate_limits.default","safety",1,{part:"safety-limits",search:"usage limit retention",source:"here"}))}</div>
 <div data-fragment-group="privacy"><div data-rows="">${rowHtml("privacy.retention_days","privacy",7,{search:"keep records retention"})}</div></div>`);

async function page(handler,url){
  const dom=new JSDOM(HTML,{url:url||"https://lightwork.test/settings/all",runScripts:"outside-only"});
  const w=dom.window,d=w.document,calls=[],confirms=[];
  w.mvConfirm=async message=>{confirms.push(message);return true;};
  reviewedSaving(w,{confirms});
  w.mvErrorText=(failure,action)=>"Could not "+action+".";
  w.mvToast=()=>{};
  w.fetch=async(url,init={})=>{
    const body=init.body?JSON.parse(init.body):null;calls.push({url,method:init.method||"GET",body});
    return handler(url,body,calls.length);
  };
  w.eval(read("static/lightwork-settings-all.js"));
  await flush();
  return {dom,w,d,calls,confirms};
}
const rows=ui=>[...ui.d.querySelectorAll(".settings-all-row[data-setting-id]")].map(r=>r.dataset.settingId);
const serve=(url)=>url.indexOf("group=safety")!==-1?reply(200,SAFETY):url.indexOf("q=")!==-1?reply(200,FOUND):reply(404,{});

test("the page arrives without settings and lists every group with its Show button",async()=>{
  const ui=await page(serve);
  try{
    assert.deepEqual(ui.calls,[]);
    assert.equal(ui.d.querySelector('[data-group="safety"]').hidden,false);
    assert.equal(ui.d.querySelector('[data-group="privacy"]').hidden,false);
    assert.equal(ui.d.getElementById("settings-all-empty").hidden,true);
  }finally{ui.dom.window.close();}
});

test("opening a group loads its settings in page order, parts included, ready to save",async()=>{
  const ui=await page((url,body)=>url.startsWith("/settings/all/rows")?serve(url)
    :reply(200,{changed:["rate_limits.window"],groups:[{settings:[{id:"rate_limits.window",value:"b",value_text:"B",source:"here",source_text:"Set here"}]}]}));
  try{
    ui.d.querySelector('[data-load-group="safety"]').click();await flush();
    assert.equal(ui.calls[0].url,"/settings/all/rows?group=safety");
    const safety=ui.d.querySelector('[data-group="safety"]');
    assert.equal(safety.dataset.loaded,"1");
    assert.equal(safety.querySelector("[data-group-load]").hidden,true);
    assert.deepEqual(rows(ui),["safety.profile","rate_limits.default","rate_limits.window","approval.timeout"]);
    assert.deepEqual([...safety.querySelectorAll("[data-part]")].map(p=>p.dataset.part),["safety-limits","safety-approvals"]);
    assert.equal(safety.querySelector('[data-subgroup-head="safety-limits"]').hidden,false);
    // Opening it again asks nothing more.
    ui.d.querySelector('[data-load-group="safety"]').click();await flush();
    assert.equal(ui.calls.length,1);
    const r=ui.d.querySelector('[data-setting-id="rate_limits.window"]');
    r.querySelector("select").value="b";
    ui.d.querySelector('[data-save-subgroup="safety-limits"]').click();await flush();
    const post=ui.calls.find(c=>c.method==="POST");
    assert.deepEqual(post.body.changes,[{id:"rate_limits.window",value:"b"}]);
    assert.equal(r.querySelector("[data-source-text]").textContent,"Set here");
  }finally{ui.dom.window.close();}
});

test("a search asks the server for matches in every group, once per search",async()=>{
  const ui=await page(serve);
  try{
    ui.d.getElementById("settings-all-search").value="Retention";
    ui.d.getElementById("settings-all-filter-form").dispatchEvent(new ui.w.Event("submit",{cancelable:true}));
    await flush();
    assert.equal(ui.calls[0].url,"/settings/all/rows?q=retention");
    assert.deepEqual(rows(ui),["rate_limits.default","privacy.retention_days"]);
    assert.equal(ui.d.getElementById("settings-all-filter-status").textContent,"2 settings shown.");
    assert.equal(ui.d.querySelector('[data-subgroup-head="safety-limits"]').hidden,false);
    ui.d.getElementById("settings-all-filter-form").dispatchEvent(new ui.w.Event("submit",{cancelable:true}));
    await flush();
    assert.equal(ui.calls.length,1);
    // Loading the whole group keeps the row already there (and its edits) once.
    const found=ui.d.querySelector('[data-setting-id="rate_limits.default"]');
    found.querySelector("select").value="b";
    ui.d.getElementById("settings-all-search").value="";
    ui.d.querySelector('[data-load-group="safety"]').click();await flush();
    assert.deepEqual(rows(ui),["safety.profile","rate_limits.default","rate_limits.window","approval.timeout","privacy.retention_days"]);
    assert.equal(ui.d.querySelector('[data-setting-id="rate_limits.default"]'),found);
    assert.equal(found.querySelector("select").value,"b");
    assert.equal(ui.d.querySelectorAll('[data-part="safety-limits"]').length,1);
  }finally{ui.dom.window.close();}
});

test("typing a search waits a moment, then asks the server",async()=>{
  const ui=await page(serve);
  try{
    const box=ui.d.getElementById("settings-all-search");
    box.value="retention";box.dispatchEvent(new ui.w.Event("input",{bubbles:true}));
    assert.equal(ui.d.getElementById("settings-all-empty").hidden,true);
    await new Promise(r=>setTimeout(r,320));await flush();
    assert.deepEqual(ui.calls.map(c=>c.url),["/settings/all/rows?q=retention"]);
    assert.deepEqual(rows(ui),["rate_limits.default","privacy.retention_days"]);
  }finally{ui.dom.window.close();}
});

test("changed-only asks the server each time, and choosing a group loads just that group",async()=>{
  const ui=await page(serve);
  try{
    const only=ui.d.getElementById("settings-all-changed");
    only.checked=true;only.dispatchEvent(new ui.w.Event("change"));await flush();
    only.checked=false;only.dispatchEvent(new ui.w.Event("change"));await flush();
    only.checked=true;only.dispatchEvent(new ui.w.Event("change"));await flush();
    assert.deepEqual(ui.calls.map(c=>c.url),["/settings/all/rows?q=&changed=1","/settings/all/rows?q=&changed=1"]);
    only.checked=false;only.dispatchEvent(new ui.w.Event("change"));await flush();
    const pick=ui.d.getElementById("settings-all-group");
    pick.value="safety";pick.dispatchEvent(new ui.w.Event("change"));await flush();
    assert.equal(ui.calls.at(-1).url,"/settings/all/rows?group=safety");
    assert.equal(ui.d.querySelector('[data-group="privacy"]').hidden,true);
    assert.equal(ui.d.querySelector('[data-group="safety"]').hidden,false);
    assert.equal(ui.d.getElementById("settings-all-filter-status").textContent,"4 settings shown.");
  }finally{ui.dom.window.close();}
});

test("reset all loads the whole group first, then resets every setting not at its default",async()=>{
  const ui=await page((url,body)=>url.startsWith("/settings/all/rows")?serve(url):reply(200,{changed:["rate_limits.default"],groups:[]}));
  try{
    ui.d.querySelector('[data-reset-group="safety"]').click();await flush();
    assert.equal(ui.calls[0].url,"/settings/all/rows?group=safety");
    assert.equal(ui.confirms.length,1);
    const post=ui.calls.find(c=>c.method==="POST");
    assert.deepEqual(post.body.changes,[{id:"rate_limits.default",reset:true}]);
  }finally{ui.dom.window.close();}
});

test("a link to a group opens that group",async()=>{
  const ui=await page(serve,"https://lightwork.test/settings/all#group-safety");
  try{
    assert.deepEqual(ui.calls.map(c=>c.url),["/settings/all/rows?group=safety"]);
    assert.equal(ui.d.querySelector('[data-group="safety"]').dataset.loaded,"1");
    assert.equal(ui.d.querySelector('[data-setting-id="safety.profile"]').hidden,false);
  }finally{ui.dom.window.close();}
});

test("a group that cannot be loaded says so and keeps its Show button",async()=>{
  const ui=await page(()=>reply(503,{}));
  try{
    ui.d.querySelector('[data-load-group="privacy"]').click();await flush();
    assert.equal(ui.d.getElementById("settings-all-status").textContent,"Could not load these settings.");
    assert.equal(ui.d.querySelector('[data-group="privacy"]').dataset.loaded,"0");
    assert.equal(ui.d.querySelector('[data-group="privacy"] [data-group-load]').hidden,false);
  }finally{ui.dom.window.close();}
});
