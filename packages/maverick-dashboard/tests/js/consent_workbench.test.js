"use strict";
const {test}=require("node:test");
const assert=require("node:assert/strict");
const fs=require("node:fs"),path=require("node:path");
const {webcrypto,createHash}=require("node:crypto");
const {JSDOM}=require("jsdom");
const {shell} = require('./_shell');
const source=fs.readFileSync(path.resolve(__dirname,"../../maverick_dashboard/static/lightwork-consent-workbench.js"),"utf8");
function load(){
  const dom=new JSDOM('<div id="host"></div><p id="msg"></p>',{url:"https://lightwork.test/consent",runScripts:"outside-only"});
  Object.defineProperty(dom.window,"crypto",{value:webcrypto});dom.window.TextEncoder=TextEncoder;
  shell(dom.window);
  dom.window.eval(source);
  return {dom,w:dom.window,CW:dom.window.LightworkConsentWorkbench};
}

test("the JSON client fails closed and carries the status for a plain message",async()=>{
  const {dom,w,CW}=load();
  try{
    const call=CW.client("/api/v1/x");
    w.fetch=async()=>({ok:true,status:200,json:async()=>{throw new Error("secret body");}});
    await assert.rejects(call("/a"),error=>error.message===CW.INVALID&&error.status===0);
    w.fetch=async()=>({ok:false,status:409,json:async()=>({detail:"revision 4 != 5"})});
    await assert.rejects(call("/a"),error=>error.status===409);
    let sent;w.fetch=async(url,options)=>{sent={url,options};return {ok:true,status:200,json:async()=>({ok:1})};};
    assert.deepEqual(await call("/b",{method:"POST",json:{a:1}}),{ok:1});
    assert.equal(sent.url,"/api/v1/x/b");assert.equal(sent.options.body,'{"a":1}');
    w.mvErrorText=(failure,action)=>"Could not "+action+" ("+failure.status+")";
    CW.fail(w.document.getElementById("msg"),{status:409},"save");
    assert.equal(w.document.getElementById("msg").textContent,"Could not save (409)");
    assert.equal(w.document.getElementById("msg").getAttribute("role"),"alert");
  }finally{dom.window.close();}
});

test("names, dates and fingerprints are derived rather than typed",async()=>{
  const {dom,CW}=load();
  try{
    assert.equal(CW.slug("Email Marketing & Ads"),"email-marketing-ads");
    assert.match(CW.slug("!!!","policy"),/^policy-[0-9a-f]{8}$/);
    const seconds=CW.toSeconds("2026-03-04T05:06");
    assert.equal(CW.toInput(seconds),"2026-03-04T05:06");
    assert.equal(CW.toInput(CW.toSeconds("2026-03-04"),true),"2026-03-04");
    assert.ok(Number.isNaN(CW.toSeconds("")));
    assert.equal(await CW.sha256("abc"),createHash("sha256").update("abc").digest("hex"));
    assert.equal(CW.labelFor(CW.COUNTRIES,"GB"),"United Kingdom");
  }finally{dom.window.close();}
});

test("record tables give each row its own labelled buttons and empty states offer the next step",()=>{
  const {dom,w,CW}=load();
  try{
    const host=w.document.getElementById("host"),ran=[];
    CW.table(host,[{id:"a"},{id:"b"}],{label:"Things",name:row=>row.id,columns:[{label:"Name",value:row=>row.id}],
      actions:[{label:"Open",run:row=>ran.push(row.id)},{label:"Remove",kind:"danger",when:row=>row.id==="b",run:()=>{}}]});
    const buttons=[...host.querySelectorAll("button")];
    assert.deepEqual(buttons.map(b=>b.getAttribute("aria-label")),["Open: a","Open: b","Remove: b"]);
    buttons[1].click();assert.deepEqual(ran,["b"]);
    CW.table(host,[],{columns:[],empty:{title:"Nothing yet.",body:"Add one.",action:{label:"Add",run:()=>ran.push("add")}}});
    assert.match(host.textContent,/Nothing yet\.Add one\./);
    host.querySelector("button").click();assert.equal(ran.at(-1),"add");
  }finally{dom.window.close();}
});
