"use strict";
// Settings > All settings: the "Check this location" and "Test connection"
// buttons, the location (path) control, and the sign-in lock-out wording.
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

// Markup mirrors templates/settings_all.html for a location, an address and a secret row.
const HTML=`<!doctype html><main>
<div role="status" id="settings-all-status" hidden></div>
<input id="settings-all-search"><select id="settings-all-group"><option value="">All</option></select>
<input type="checkbox" id="settings-all-changed"><p id="settings-all-filter-status"></p>
<div id="settings-all-groups">
<section class="settings-all-group" data-group="security"><h2>Security</h2>
 <div class="settings-all-row" data-setting-id="auth.saml.sp_key_file" data-control="path" data-source="default" data-search="private key file">
  <strong data-value-text>Not set</strong><span data-source-text>Default</span>
  <input type="text" data-input value="">
  <button data-save>Save</button><button data-test>Check this location</button><button data-reset>Reset to default</button><p data-row-status></p></div>
 <div class="settings-all-row" data-setting-id="auth.oidc.enabled" data-control="toggle" data-source="default" data-search="company sign-in">
  <strong data-value-text>Off</strong><span data-source-text>Default</span>
  <input type="checkbox" data-input>
  <button data-save>Save</button><button data-test>Test connection</button><button data-reset>Reset to default</button><p data-row-status></p></div>
 <div class="settings-all-row" data-setting-id="world_model.dsn" data-control="secret" data-source="default" data-search="shared database connection">
  <span data-secret-state>Not set</span><button data-secret-replace>Add</button><input type="password" data-input hidden>
  <button data-save>Save</button><button data-test>Test connection</button><button data-reset>Reset to default</button><p data-row-status></p></div>
</section></div><p id="settings-all-empty" hidden></p></main>`;

async function page(handler,review={}){
  const dom=new JSDOM(HTML,{url:"https://lightwork.test/settings/all",runScripts:"outside-only"});
  const w=dom.window,d=w.document,calls=[],confirms=[];
  w.mvConfirm=async message=>{confirms.push(message);return true;};
  reviewedSaving(w,{confirms,...review});
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

test("checking a location sends the typed location and shows the server's sentence",async()=>{
  const ui=await page(()=>reply(200,{ok:false,message:"Nothing was found at that location on the server."}));
  try{
    const r=row(ui,"auth.saml.sp_key_file");
    r.querySelector("[data-input]").value="/etc/lightwork/sp.key";
    await click(r.querySelector("[data-test]"));
    assert.equal(ui.calls[0].url,"/api/v1/settings/catalog/test");
    assert.deepEqual(ui.calls[0].body,{id:"auth.saml.sp_key_file",value:"/etc/lightwork/sp.key"});
    assert.equal(r.querySelector("[data-row-status]").textContent,"Nothing was found at that location on the server.");
    assert.equal(r.querySelector("[data-test]").disabled,false);
  }finally{ui.dom.window.close();}
});

test("a location is saved like text",async()=>{
  const ui=await page((url,body)=>reply(200,{changed:[body.changes[0].id],groups:[{settings:[{id:"auth.saml.sp_key_file",value:"/etc/lightwork/sp.key",value_text:"/etc/lightwork/sp.key",source:"here",source_text:"Set here"}]}]}));
  try{
    const r=row(ui,"auth.saml.sp_key_file");
    r.querySelector("[data-input]").value="/etc/lightwork/sp.key";
    await click(r.querySelector("[data-save]"));
    assert.deepEqual(ui.calls[0].body.changes,[{id:"auth.saml.sp_key_file",value:"/etc/lightwork/sp.key"}]);
    assert.equal(r.querySelector("[data-input]").value,"/etc/lightwork/sp.key");
  }finally{ui.dom.window.close();}
});

test("testing a switch tests what is saved; a secret is sent only after Replace",async()=>{
  const ui=await page(()=>reply(200,{ok:true,message:"Lightwork reached your sign-in provider and read its sign-in details."}));
  try{
    await click(row(ui,"auth.oidc.enabled").querySelector("[data-test]"));
    assert.deepEqual(ui.calls[0].body,{id:"auth.oidc.enabled",value:null});
    assert.match(row(ui,"auth.oidc.enabled").querySelector("[data-row-status]").textContent,/reached your sign-in provider/);
    const secret=row(ui,"world_model.dsn");
    await click(secret.querySelector("[data-test]"));
    assert.equal(ui.calls[1].body.value,null);
    await click(secret.querySelector("[data-secret-replace]"));
    secret.querySelector("[data-input]").value="postgres://db.example.com/lightwork"; // pragma: allowlist secret
    await click(secret.querySelector("[data-test]"));
    assert.equal(ui.calls[2].body.value,"postgres://db.example.com/lightwork");
  }finally{ui.dom.window.close();}
});

test("a failed check never shows a raw status",async()=>{
  const ui=await page(()=>({ok:false,status:500,headers:{get:()=>null},json:async()=>{throw new Error("no body");}}));
  try{
    await click(row(ui,"auth.oidc.enabled").querySelector("[data-test]"));
    const text=row(ui,"auth.oidc.enabled").querySelector("[data-row-status]").textContent;
    assert.equal(text,"Could not run the check.");
    assert.doesNotMatch(text,/500|HTTP/);
  }finally{ui.dom.window.close();}
});

test("a sign-in change that could lock people out is explained in plain words before saving",async()=>{
  const access=changes=>changes.some(c=>c.id==="auth.oidc.enabled")
    ?[{label:"Your access",kind:"access",warning:"You will be signed out of Lightwork and will need to sign in again with your company sign-in."}]:[];
  const ui=await page(()=>reply(200,{changed:["auth.oidc.enabled"],groups:[]}),{warnings:access});
  try{
    const r=row(ui,"auth.oidc.enabled");
    r.querySelector("[data-input]").checked=true;
    await click(r.querySelector("[data-save]"));
    assert.equal(ui.confirms.length,1);
    assert.match(ui.confirms[0],/^Your access: You will be signed out/);
    assert.doesNotMatch(ui.confirms[0],/lowers a protection/);
    assert.equal(ui.calls.length,1);assert.equal(ui.calls[0].body.confirm,true);
  }finally{ui.dom.window.close();}
});

test("a refused lock-out shows the server's explanation",async()=>{
  const message="Nobody can sign in to Lightwork yet, so this would lock you out. Set up and test a sign-in method first, then change this.";
  const ui=await page(()=>reply(200,{changed:[],groups:[]}),{refuse:()=>({detail:message,message,lockout:true})});
  try{
    const r=row(ui,"auth.oidc.enabled");
    r.querySelector("[data-input]").checked=true;
    await click(r.querySelector("[data-save]"));
    assert.equal(ui.confirms.length,0);
    assert.equal(ui.calls.length,0);
    assert.equal(r.querySelector("[data-row-status]").textContent,message);
  }finally{ui.dom.window.close();}
});

// ---- rules with a password per row (linked servers) ------------------------
const attr=value=>JSON.stringify(value).replace(/'/g,"\\u0027");
const PEERS={kind:"rules",item_label:"Linked server",
  columns:[
    {key:"name",label:"Server name",kind:"text",required:true,max_length:64,choices:[]},
    {key:"target",label:"Address and port",kind:"text",required:true,max_length:260,choices:[]},
    {key:"token",label:"Shared password",kind:"secret",max_length:512,choices:[]}],
  rows:[{cells:{name:"west-1",target:"west.example.com:50052",token:{is_set:true}}}]};
const PEER_HTML=`<!doctype html><main>
<div role="status" id="settings-all-status" hidden></div>
<input id="settings-all-search"><select id="settings-all-group"><option value="">All</option></select>
<input type="checkbox" id="settings-all-changed"><p id="settings-all-filter-status"></p>
<div id="settings-all-groups"><section class="settings-all-group" data-group="server"><h2>Server</h2>
 <div class="settings-all-row" data-setting-id="federation.peers" data-control="rules" data-source="here" data-search="linked servers">
  <strong data-value-text>1 linked server</strong><span data-source-text>Set here</span>
  <div data-grid data-grid-state='${attr(PEERS)}'><table><tbody data-grid-body></tbody></table>
  <p data-grid-empty>No servers are linked yet.</p><button data-grid-add>Add a linked server</button></div>
  <button data-save>Save</button><button data-reset>Reset to default</button><p data-row-status></p></div>
</section></div><p id="settings-all-empty" hidden></p></main>`;

test("a row's saved password is never shown, and an empty box keeps it",async()=>{
  const dom=new JSDOM(PEER_HTML,{url:"https://lightwork.test/settings/all",runScripts:"outside-only"});
  const w=dom.window,d=w.document,calls=[];
  w.mvConfirm=async()=>true;w.mvErrorText=(f,a)=>"Could not "+a+".";w.mvToast=()=>{};
  reviewedSaving(w);
  w.fetch=async(url,init={})=>{calls.push(JSON.parse(init.body));return reply(200,{changed:["federation.peers"],groups:[]});};
  shell(w);
  w.eval(read("static/lightwork-settings-all.js"));
  await flush();
  try{
    const secret=d.querySelector('[data-cell="token"] [data-cell-input]');
    assert.equal(secret.type,"password");
    assert.equal(secret.value,"");
    assert.match(secret.placeholder,/Leave empty to keep it/);
    assert.ok(secret.getAttribute("aria-label"));
    d.querySelector('[data-cell="target"] [data-cell-input]').value="west2.example.com:50052";
    d.querySelector("[data-save]").click();await flush();
    assert.deepEqual(calls[0].changes[0].value,[{name:"west-1",target:"west2.example.com:50052",token:""}]);
  }finally{dom.window.close();}
});

// ---- named rows with colour pickers (your own colour themes) ---------------
const THEMES={kind:"named",row_label:"Theme name",item_label:"Theme",
  columns:[
    {key:"bg",label:"Page background",kind:"color",required:true,choices:[]},
    {key:"warn",label:"Warnings",kind:"color",required:false,choices:[]}],
  rows:[{name:"midnight",label:"midnight",cells:{bg:"#101020",warn:null}}]};
const THEME_HTML=`<!doctype html><main>
<div role="status" id="settings-all-status" hidden></div>
<input id="settings-all-search"><select id="settings-all-group"><option value="">All</option></select>
<input type="checkbox" id="settings-all-changed"><p id="settings-all-filter-status"></p>
<div id="settings-all-groups"><section class="settings-all-group" data-group="people"><h2>People</h2>
 <div class="settings-all-row" data-setting-id="dashboard.themes" data-control="table" data-source="here" data-search="themes">
  <strong data-value-text>1 theme</strong><span data-source-text>Set here</span>
  <div data-grid data-grid-state='${attr(THEMES)}'><table><tbody data-grid-body></tbody></table>
  <p data-grid-empty>No colour themes of your own yet.</p>
  <input type="text" data-grid-newname><button data-grid-add>Add a theme</button></div>
  <button data-save>Save</button><button data-reset>Reset to default</button><p data-row-status></p></div>
</section></div><p id="settings-all-empty" hidden></p></main>`;

test("themes: rows are named by the person and colours come from colour pickers",async()=>{
  const dom=new JSDOM(THEME_HTML,{url:"https://lightwork.test/settings/all",runScripts:"outside-only"});
  const w=dom.window,d=w.document,calls=[];
  w.mvConfirm=async()=>true;w.mvErrorText=(f,a)=>"Could not "+a+".";w.mvToast=()=>{};
  reviewedSaving(w);
  w.fetch=async(url,init={})=>{calls.push(JSON.parse(init.body));return reply(200,{changed:["dashboard.themes"],groups:[]});};
  shell(w);
  w.eval(read("static/lightwork-settings-all.js"));
  await flush();
  try{
    const r=d.querySelector('[data-setting-id="dashboard.themes"]');
    const first=r.querySelector("[data-grid-row]");
    assert.equal(first.querySelector("[data-row-label]").textContent,"midnight");
    assert.equal(first.querySelector('[data-cell="bg"] [data-cell-input]').type,"color");
    assert.equal(first.querySelector('[data-cell="bg"] [data-cell-use]'),null);
    assert.equal(first.querySelector('[data-cell="warn"] [data-cell-use]').checked,false);
    r.querySelector("[data-grid-add]").click();await flush();
    assert.match(r.querySelector("[data-row-status]").textContent,/Type a name first/);
    r.querySelector("[data-grid-newname]").value="sunrise";
    r.querySelector("[data-grid-add]").click();await flush();
    const added=r.querySelectorAll("[data-grid-row]")[1];
    assert.equal(added.dataset.name,"sunrise");
    added.querySelector('[data-cell="bg"] [data-cell-input]').value="#ffeedd";
    added.querySelector('[data-cell="warn"] [data-cell-use]').checked=true;
    added.querySelector('[data-cell="warn"] [data-cell-input]').value="#aa0000";
    r.querySelector("[data-save]").click();await flush();
    assert.deepEqual(calls[0].changes[0].value,[
      {name:"midnight",bg:"#101020",warn:""},{name:"sunrise",bg:"#ffeedd",warn:"#aa0000"}]);
  }finally{dom.window.close();}
});
