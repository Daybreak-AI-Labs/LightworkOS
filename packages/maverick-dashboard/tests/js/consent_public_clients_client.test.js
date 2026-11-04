"use strict";
const {test}=require("node:test");
const assert=require("node:assert/strict");
const fs=require("node:fs"),path=require("node:path");
const {webcrypto,createHash}=require("node:crypto");
const {JSDOM}=require("jsdom");
const {shell} = require('./_shell');
const root=path.resolve(__dirname,"../../maverick_dashboard");
const read=name=>fs.readFileSync(path.join(root,name),"utf8").replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
const flush=async()=>{for(let i=0;i<30;i++){await new Promise(setImmediate);await new Promise(r=>setTimeout(r,2));}};
const reply=(status,body)=>({ok:status<400,status,json:async()=>body});

async function page(options={}){
  const source=read("templates/consent_public_clients.html");
  const html=source.replace(/\{%[\s\S]*?%\}/g,"").replace(/\{\{[\s\S]*?\}\}/g,"");
  const dom=new JSDOM(html,{url:"https://lightwork.example/consent/public-clients",runScripts:"outside-only"});
  const w=dom.window,d=w.document,calls=[],confirms=[],copies=[];
  Object.defineProperty(w,"crypto",{value:webcrypto});w.TextEncoder=TextEncoder;
  const rootNode=d.getElementById("pcc-root");rootNode.disabled=false;Object.assign(rootNode.dataset,{canAdmin:"true",canAudit:"true"});
  d.querySelectorAll("button").forEach(b=>{b.disabled=false;});
  w.mvConfirm=async message=>{confirms.push(message);return options.confirm!==false;};
  w.mvForm=async()=>({reason:"device-lost"});w.mvCopy=text=>copies.push(text);
  w.mvErrorText=(failure,action)=>"Could not "+action+".";
  w.fetch=async(url,init={})=>{
    const method=init.method||"GET",body=init.body?JSON.parse(init.body):null;calls.push({url,method,body});
    if(url.startsWith("/api/v1/consent/public-clients?"))return reply(200,{items:[{credential_id:"client-1",property_id:"main-site",client_kind:"browser",browser_origin:"https://www.example.com",default_locale:"en-US",status:"active",revision:2,updated_at:1800000000}]});
    if(url.includes("/public-clients/profiles?"))return reply(200,{items:[{profile_id:"visitor-9",property_id:"main-site",profile_status:"active",created_at:1800000000}]});
    if(url.includes("/catalog/properties"))return reply(200,{items:[{property_id:"main-site",kind:"web",origin_allowlist:["https://www.example.com"],publication_revision:1}]});
    if(url.includes("/catalog/rule-groups"))return reply(200,{items:[{resource_id:"main-rules",version:3}]});
    if(url.includes("/consent/policies"))return reply(200,{policies:[{policy_id:"web-policy",version:2}]});
    if(method==="POST"&&url==="/api/v1/consent/public-clients")return options.conflict?reply(409,{detail:"published configuration cannot authorize this client: stale"}):reply(201,{client_credential:"lwcp_secret-once"});
    return reply(200,{});
  };
  shell(w);
  w.eval(read("static/lightwork-consent-workbench.js"));
  w.eval([...source.matchAll(/<script>([\s\S]*?)<\/script>/g)].at(-1)[1]);
  await flush();
  return {dom,w,d,calls,confirms,copies,posts:()=>calls.filter(c=>c.method==="POST")};
}
async function create(ui){
  ui.d.getElementById("pcc-new").click();await flush();
  const form=ui.d.getElementById("pcc-create");
  form.dispatchEvent(new ui.w.Event("submit",{bubbles:true,cancelable:true}));await flush();
}

test("a key is created from choices and shown once with ready-to-paste code for this server",async()=>{
  const ui=await page();
  try{
    await create(ui);
    const body=ui.posts()[0].body;
    assert.deepEqual([body.property_id,body.client_kind,body.browser_origin,body.rule_group_id,body.rule_group_version,body.policy_id,body.policy_version,body.jurisdiction,body.country_code,body.default_locale],
      ["main-site","browser","https://www.example.com","main-rules",3,"web-policy",2,"global","US","en-US"]);
    assert.equal(ui.d.getElementById("pcc-secret").hidden,false);
    assert.equal(ui.d.getElementById("pcc-secret-value").textContent,"lwcp_secret-once");
    [...ui.d.querySelectorAll("#pcc-secret button")].find(b=>b.textContent==="Copy website code").click();
    assert.match(ui.copies[0],/https:\/\/lightwork\.example\/api\/v1\/public\/consent"/);assert.match(ui.copies[0],/lwcp_secret-once/);
  }finally{ui.dom.window.close();}
});

test("a key that does not match the publication is explained without server wording",async()=>{
  const ui=await page({conflict:true});
  try{
    await create(ui);
    const text=ui.d.getElementById("pcc-status").textContent;
    assert.match(text,/do not match what is published/);assert.doesNotMatch(text,/authorize/);
    assert.equal(ui.d.getElementById("pcc-secret").hidden,true);
  }finally{ui.dom.window.close();}
});

test("revoking a key or a person's access confirms and carries the row's references",async()=>{
  const ui=await page();
  try{
    [...ui.d.querySelectorAll("#pcc-table button")].find(b=>b.textContent==="Revoke").click();await flush();
    assert.match(ui.confirms[0],/Revoke this key for https:\/\/www\.example\.com\?/);
    const revoke=ui.posts().find(c=>c.url.endsWith("/client-1/revoke"));assert.deepEqual(revoke.body,{expected_revision:2});
    [...ui.d.querySelectorAll("#pcc-profiles button")].find(b=>b.textContent==="Revoke access").click();await flush();
    const profile=ui.posts().find(c=>c.url.endsWith("/profiles/visitor-9/revoke"));
    assert.equal(profile.body.property_id,"main-site");
    assert.equal(profile.body.evidence_sha256,createHash("sha256").update("public-profile-revocation\0device-lost\0main-site\0visitor-9").digest("hex"));
  }finally{ui.dom.window.close();}
});
