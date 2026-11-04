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
// Expand the template's one tracker loop the way Jinja would.
function expandTrackerLoop(source){
  return source.replace(/\{% for tracker, label in \[([\s\S]*?)\] %\}([\s\S]*?)\{% endfor %\}/,(_m,list,body)=>
    [...list.matchAll(/\("([a-z_]+)", "([^"]+)"\)/g)].map(([,tracker,label])=>body.replaceAll("{{ tracker }}",tracker).replaceAll("{{ label }}",label)).join(""));
}
const settings={sdk_version:"0.1.7",geolocation_reconsent:[{jurisdiction:"US",reconsent_after_days:365}],analytics_tracking_enabled:true,
  analytics_category_assignments:[{tracker:"google_analytics",category:"analytics"}],common_trackers:["google_analytics"],cookie_same_site:"lax",
  cookie_domain_separation:"host_only",spa_reload_on_route_change:false,csp_nonce_required:false,automatic_refresh_seconds:null};

async function page(options={}){
  const html=expandTrackerLoop(read("templates/consent_publish_settings.html")).replace(/\{%[\s\S]*?%\}/g,"").replace(/\{\{[\s\S]*?\}\}/g,"");
  const dom=new JSDOM(html,{url:"https://lightwork.test/consent/publish-settings",runScripts:"outside-only"});
  const w=dom.window,d=w.document,calls=[],confirms=[];
  Object.defineProperty(w,"crypto",{value:webcrypto});w.TextEncoder=TextEncoder;w.TextDecoder=TextDecoder;
  const shell=d.getElementById("publish-settings-shell");
  Object.assign(shell.dataset,{apiBase:"/api/v1/consent/publish-settings",canAdmin:"true",canAudit:"true",sdkVersion:"0.1.7"});
  d.querySelectorAll("button,fieldset").forEach(n=>{n.disabled=false;});
  w.mvConfirm=async message=>{confirms.push(message);return true;};
  w.mvErrorText=(failure,action)=>"Could not "+action+".";
  const head={property_id:"main-site",revision:4,state:"active",latest_version_id:"v2",active_version_id:"v2"};
  w.fetch=async(url,init={})=>{
    const method=init.method||"GET",body=init.body?JSON.parse(init.body):null;calls.push({url,method,body});
    if(url.endsWith("/status"))return reply(200,{enabled:true,ready:true});
    if(url.includes("/catalog/properties"))return reply(200,{items:[{property_id:"main-site",kind:"web"},{property_id:"app",kind:"mobile"}]});
    if(url.endsWith("/properties/main-site"))return reply(200,head);
    if(url.includes("/properties/main-site/versions?"))return reply(200,{items:[{version_id:"v2",version_number:2,settings,created_at:1800000100},{version_id:"v1",version_number:1,settings,created_at:1800000000}]});
    if(url.includes("/operations/history"))return reply(200,{items:[{event_type:"activated",occurred_at:1800000100}]});
    return reply(201,{});
  };
  loadShell(w);
  w.eval(read("static/lightwork-consent-workbench.js"));
  w.eval(read("static/lightwork-consent-publish-settings.js"));
  await flush();
  return {dom,w,d,calls,confirms,posts:()=>calls.filter(c=>c.method==="POST")};
}

test("the website is chosen from a list and its versions load as rows",async()=>{
  const ui=await page();
  try{
    const options=[...ui.d.getElementById("publish-settings-property-id").options].map(o=>o.value);
    assert.deepEqual(options,["main-site"]);
    const table=ui.d.getElementById("publish-settings-versions-table").textContent;
    assert.match(table,/Live/);assert.match(table,/Earlier version/);
    assert.match(ui.d.getElementById("publish-settings-history-table").textContent,/Settings switched on/);
    assert.equal(ui.d.getElementById("publish-settings-withdraw").hidden,false);
  }finally{ui.dom.window.close();}
});

test("going back to an earlier version confirms and carries the current head revision",async()=>{
  const ui=await page();
  try{
    [...ui.d.querySelectorAll("#publish-settings-versions-table button")].find(b=>b.textContent==="Go back to this").click();await flush();
    assert.match(ui.confirms[0],/Go back to version 1 on Main site\?/);
    const sent=ui.posts()[0];
    assert.equal(sent.url,"/api/v1/consent/publish-settings/properties/main-site/rollback");
    assert.equal(sent.body.expected_head_revision,4);assert.equal(sent.body.target_version_id,"v1");
  }finally{ui.dom.window.close();}
});

test("new settings start from the live version and are built from checkboxes and selectors",async()=>{
  const ui=await page();
  try{
    ui.d.getElementById("publish-settings-new").click();
    const meta=ui.d.querySelector('input[name="common_trackers"][value="meta_pixel"]');meta.checked=true;
    ui.d.querySelector('select[data-tracker="meta_pixel"]').value="advertising";
    ui.d.getElementById("publish-settings-geo-add").click();
    const rows=ui.d.querySelectorAll("#publish-settings-geolocation .cw-row");rows[1].querySelector('[name="geolocation_reconsent"]').value="CA-QC";rows[1].querySelector('[name="geolocation_reconsent_days"]').value="180";
    ui.d.getElementById("publish-settings-create-form").dispatchEvent(new ui.w.Event("submit",{bubbles:true,cancelable:true}));await flush();
    const body=ui.posts()[0].body;
    assert.equal(body.expected_head_revision,4);
    assert.deepEqual(body.settings.common_trackers,["google_analytics","meta_pixel"]);
    assert.deepEqual(body.settings.analytics_category_assignments,[{tracker:"google_analytics",category:"analytics"},{tracker:"meta_pixel",category:"advertising"}]);
    assert.deepEqual(body.settings.geolocation_reconsent,[{jurisdiction:"CA-QC",reconsent_after_days:180},{jurisdiction:"US",reconsent_after_days:365}]);
    assert.equal(body.settings.sdk_version,"0.1.7");
  }finally{ui.dom.window.close();}
});
