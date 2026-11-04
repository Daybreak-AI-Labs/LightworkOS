"use strict";
const {test}=require("node:test");
const assert=require("node:assert/strict");
const fs=require("node:fs"),path=require("node:path");
const {webcrypto}=require("node:crypto");
const {JSDOM}=require("jsdom");
const {shell: loadShell} = require('./_shell');
const root=path.resolve(__dirname,"../../maverick_dashboard");
const read=name=>fs.readFileSync(path.join(root,name),"utf8");
const flush=async()=>{for(let i=0;i<30;i++){await new Promise(setImmediate);await new Promise(r=>setTimeout(r,2));}};
const reply=(status,body)=>({ok:status<400,status,headers:{get:()=>null},text:async()=>JSON.stringify(body),json:async()=>body});
function expandLoops(source){
  return source.replace(/\{% for value, label in \[([\s\S]*?)\] %\}([\s\S]*?)\{% endfor %\}/g,(_m,list,body)=>
    [...list.matchAll(/\('([a-z-]+)','([^']+)'\)/g)].map(([,value,label])=>body.replace(/\{%[\s\S]*?%\}[\s\S]*?\{% endif %\}/,"").replaceAll("{{ value }}",value).replaceAll("{{ label }}",label)).join(""));
}
const ui_={enabled:true,title:"T",body:"B",submit_label:"S",success_message:"M"};
async function page(options={}){
  const html=expandLoops(read("templates/consent_global_opt_out.html")).replace(/\{%[\s\S]*?%\}/g,"").replace(/\{\{[\s\S]*?\}\}/g,"");
  const dom=new JSDOM(html,{url:"https://lightwork.test/consent/global-opt-out",runScripts:"outside-only"});
  const w=dom.window,d=w.document,calls=[],confirms=[],ui_opts=[];
  Object.defineProperty(w,"crypto",{value:webcrypto});w.TextEncoder=TextEncoder;
  const shell=d.getElementById("global-opt-out-shell");
  shell.setAttribute("data-api-base","/api/v1/consent/global-opt-out");shell.setAttribute("data-can-admin","true");shell.setAttribute("data-can-audit","true");
  d.querySelectorAll("button,fieldset").forEach(n=>{n.disabled=false;});
  w.mvConfirm=async(message,opts)=>{confirms.push(message);ui_opts.push(opts);return !options.decline;};
  w.mvErrorText=(failure,action)=>"Could not "+action+".";
  const items=options.items||[{configuration_id:"cfg-1",application_ref:"key-1",locale:"en-US",mobile_ui:ui_,email_ui:{...ui_,enabled:false},supported_devices:["browser"],supported_services:["website"],state:"draft",revision:2,updated_at:1800000000,expires_at:null}];
  w.fetch=async(url,init={})=>{
    const method=init.method||"GET",body=init.body?JSON.parse(init.body):null;calls.push({url,method,body});
    if(url.endsWith("/status"))return reply(200,{enabled:true,readiness:{ready:true}});
    if(url.includes("/public-clients?"))return reply(200,{items:[{credential_id:"key-1",property_id:"main-site",browser_origin:"https://www.example.com",status:"active"},{credential_id:"key-2",property_id:"shop",browser_origin:"https://shop.example.com",status:"active"}]});
    if(url.includes("/configurations?"))return reply(200,{items});
    if(options.conflict&&method!=="GET")return reply(409,{detail:{code:"authority_stale",message:"stale publication binding"}});
    return reply(201,{});
  };
  loadShell(w);
  w.eval(read("static/lightwork-consent-workbench.js"));
  w.eval(read("static/lightwork-consent-global-opt-out.js"));
  await flush();
  return {dom,w,d,calls,confirms,confirmOptions:ui_opts,posts:()=>calls.filter(c=>c.method!=="GET")};
}
const rowButton=(ui,label)=>[...ui.d.querySelectorAll("#goo-table button")].find(b=>b.textContent===label);

test("set-ups load as rows named by their website key",async()=>{
  const ui=await page();
  try{
    assert.match(ui.d.getElementById("goo-table").textContent,/Main site · https:\/\/www\.example\.com.*Mobile app.*English \(United States\).*Draft/);
    assert.ok(rowButton(ui,"Switch on")&&rowButton(ui,"Edit")&&rowButton(ui,"Switch off"));
  }finally{ui.dom.window.close();}
});

test("a new set-up picks an unused key and turns the date into a time",async()=>{
  const ui=await page();
  try{
    ui.d.getElementById("goo-new").click();
    const keys=[...ui.d.getElementById("goo-application-ref").options].map(o=>o.value);
    assert.deepEqual(keys,["key-2"]);
    ["browser","ios","android"].forEach(v=>{ui.d.querySelector('[name="supported_devices"][value="'+v+'"]').checked=true;});
    ui.d.querySelector('[name="supported_services"][value="website"]').checked=true;
    ui.d.getElementById("goo-expires-at").value="2099-01-31";
    ui.d.getElementById("goo-config-form").dispatchEvent(new ui.w.Event("submit",{bubbles:true,cancelable:true}));await flush();
    const sent=ui.posts()[0];
    assert.equal(sent.url,"/api/v1/consent/global-opt-out/configurations");assert.equal(sent.body.application_ref,"key-2");
    assert.equal(sent.body.expected_revision,0);assert.ok(Number.isInteger(sent.body.expires_at)&&sent.body.expires_at>4070000000);
    assert.deepEqual(sent.body.supported_devices,["browser","ios","android"]);
  }finally{ui.dom.window.close();}
});

test("switching on confirms and carries the row's version; a stale binding is explained plainly",async()=>{
  const ui=await page({conflict:true});
  try{
    rowButton(ui,"Switch on").click();await flush();
    assert.match(ui.confirms[0],/Switch on opt-out for Main site/);
    const sent=ui.posts()[0];assert.equal(sent.url,"/api/v1/consent/global-opt-out/configurations/cfg-1/activate");assert.equal(sent.body.expected_revision,2);
    const status=ui.d.getElementById("goo-operation-status").textContent;
    assert.match(status,/no longer matches your published banner/);assert.doesNotMatch(status,/stale publication/);
  }finally{ui.dom.window.close();}
});

test("editing sends the whole set-up with the row's version",async()=>{
  const ui=await page();
  try{
    rowButton(ui,"Edit").click();
    assert.equal(ui.d.getElementById("goo-application-ref").disabled,true);
    ui.d.getElementById("goo-config-form").dispatchEvent(new ui.w.Event("submit",{bubbles:true,cancelable:true}));await flush();
    const sent=ui.posts()[0];
    assert.equal(sent.method,"PUT");assert.equal(sent.url,"/api/v1/consent/global-opt-out/configurations/cfg-1");
    assert.equal(sent.body.expected_revision,2);assert.equal("application_ref" in sent.body,false);
    assert.deepEqual(sent.body.email_ui,{...ui_,enabled:false});
  }finally{ui.dom.window.close();}
});

test("editing a draft saves without asking",async()=>{
  const ui=await page();
  try{
    rowButton(ui,"Edit").click();
    ui.d.getElementById("goo-config-form").dispatchEvent(new ui.w.Event("submit",{bubbles:true,cancelable:true}));await flush();
    assert.equal(ui.confirms.length,0);assert.equal(ui.posts().length,1);
  }finally{ui.dom.window.close();}
});

const activeItem={configuration_id:"cfg-1",application_ref:"key-1",locale:"en-US",mobile_ui:ui_,email_ui:{...ui_,enabled:false},supported_devices:["browser"],supported_services:["website"],state:"active",revision:3,updated_at:1800000000,expires_at:null};

test("editing a switched-on set-up asks first in plain words",async()=>{
  const ui=await page({items:[activeItem]});
  try{
    rowButton(ui,"Edit").click();
    ui.d.getElementById("goo-config-form").dispatchEvent(new ui.w.Event("submit",{bubbles:true,cancelable:true}));await flush();
    assert.equal(ui.confirms.length,1);
    assert.match(ui.confirms[0],/^Update opt-out for Main site.*It is switched on, so people will see the new messages and choices right away\.$/);
    assert.doesNotMatch(ui.confirms[0],/rebind|binding|configuration|governed/i);
    assert.equal(ui.confirmOptions[0].okText,"Update");
    const sent=ui.posts()[0];assert.equal(sent.method,"PUT");assert.equal(sent.body.expected_revision,3);
  }finally{ui.dom.window.close();}
});

test("declining the question leaves a switched-on set-up unchanged",async()=>{
  const ui=await page({items:[activeItem],decline:true});
  try{
    rowButton(ui,"Edit").click();
    ui.d.getElementById("goo-config-form").dispatchEvent(new ui.w.Event("submit",{bubbles:true,cancelable:true}));await flush();
    assert.equal(ui.confirms.length,1);assert.equal(ui.posts().length,0);
    assert.equal(ui.d.getElementById("goo-config-panel").hidden,false);
  }finally{ui.dom.window.close();}
});

// ---- no loader keeps saying "Loading" ---------------------------------------
async function statusPage(status,moduleEnabled="true"){
  const html=expandLoops(read("templates/consent_global_opt_out.html")).replace(/\{%[\s\S]*?%\}/g,"").replace(/\{\{[\s\S]*?\}\}/g,"");
  const dom=new JSDOM(html,{url:"https://lightwork.test/consent/global-opt-out",runScripts:"outside-only"});
  const w=dom.window,d=w.document,calls=[];
  Object.defineProperty(w,"crypto",{value:webcrypto});w.TextEncoder=TextEncoder;
  const shell=d.getElementById("global-opt-out-shell");
  shell.setAttribute("data-api-base","/api/v1/consent/global-opt-out");shell.setAttribute("data-can-admin","true");shell.setAttribute("data-can-audit","true");
  shell.setAttribute("data-module-enabled",moduleEnabled);
  d.getElementById("goo-table").innerHTML='<p class="muted">Loading…</p>';
  w.mvErrorText=(failure,action)=>"Could not "+action+". Try again later.";
  w.fetch=async url=>{calls.push(url);return status();};
  loadShell(w);
  w.eval(read("static/lightwork-consent-workbench.js"));
  w.eval(read("static/lightwork-consent-global-opt-out.js"));
  await flush();
  return {dom,d,calls,table:()=>d.getElementById("goo-table").textContent};
}

test("a failed availability check replaces the opt-out list's Loading with what happened",async()=>{
  const ui=await statusPage(()=>reply(503,{detail:"unavailable"}));
  try{assert.equal(ui.table(),"Could not load opt-out set-ups. Try again later.");}finally{ui.dom.window.close();}
});

test("opt-out that is on but not ready says when set-ups will appear",async()=>{
  const ui=await statusPage(()=>reply(200,{enabled:true,readiness:{ready:false}}));
  try{assert.equal(ui.table(),"Opt-out set-ups appear here once your banner is published and a website or app key exists.");}finally{ui.dom.window.close();}
});

test("a turned-off opt-out module starts no checks and shows no red sentence under its gate",async()=>{
  const ui=await statusPage(()=>{throw new Error("no request expected");},"false");
  try{
    assert.deepEqual(ui.calls,[]);
    assert.equal(ui.d.getElementById("goo-runtime-status").textContent,"");
  }finally{ui.dom.window.close();}
});
