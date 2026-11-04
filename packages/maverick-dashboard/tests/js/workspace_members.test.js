"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),{JSDOM}=require("jsdom");
const file=path.resolve(__dirname,"../../maverick_dashboard/static/lightwork-workspace-members.js"),source=fs.readFileSync(file,"utf8");
async function fixture(){
  const dom=new JSDOM('<section id="wm-root" data-tenant="tenant-a"><p id="wm-status"></p><button id="wm-refresh">Refresh</button><ul id="wm-list"></ul><form id="wm-form"><input id="wm-principal"><select id="wm-role"><option value="operator">Operator</option><option value="viewer">Viewer</option></select><button>Save</button></form></section>',{url:"https://lightwork.example/users",runScripts:"outside-only"}),{window}=dom,calls=[];
  window.mvConfirm=async()=>true;window.fetch=async(url,options={})=>{calls.push({url,...options});return options.method?new Response(null,{status:204}):new Response('{"user:reviewer":"operator"}');};
  window.eval(fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-access-state.js'), 'utf8'));window.eval(source);const el=id=>window.document.getElementById("wm-"+id);async function settle(){for(let i=0;i<10;i++)await new Promise(done=>setImmediate(done));}
  return{window,calls,el,settle};
}
test("workspace membership uses the existing explicit-tenant role API and demands confirmation",async t=>{
  const ui=await fixture();t.after(()=>ui.window.close());ui.el("principal").value="user:reviewer";ui.el("role").value="viewer";
  const submit=()=>ui.el("form").dispatchEvent(new ui.window.Event("submit",{bubbles:true,cancelable:true}));ui.window.mvConfirm=async()=>false;submit();await ui.settle();assert.equal(ui.calls.length,0);
  ui.window.mvConfirm=async()=>true;submit();await ui.settle();const write=ui.calls[0];assert.equal(write.method,"PUT");assert.equal(write.url,"/api/v1/admin/tenants/tenant-a/roles/user%3Areviewer");assert.equal(write.headers["X-Lightwork-Expected-Tenant"],"tenant-a");assert.deepEqual(JSON.parse(write.body),{role:"viewer"});
});
test("workspace removal stays explicit and failure preserves the form",async t=>{
  const ui=await fixture();t.after(()=>ui.window.close());ui.el("refresh").click();await ui.settle();ui.window.mvConfirm=async()=>false;ui.el("list").querySelectorAll("button")[1].click();await ui.settle();assert.equal(ui.calls.some(row=>row.method==="DELETE"),false);
  ui.el("principal").value="user:reviewer";ui.window.mvConfirm=async()=>true;ui.window.fetch=async()=>new Response('{"detail":"Membership unavailable"}',{status:503});ui.el("form").dispatchEvent(new ui.window.Event("submit",{bubbles:true,cancelable:true}));await ui.settle();assert.equal(ui.el("principal").value,"user:reviewer");assert.match(ui.el("status").textContent,/Could not save this workspace member/);assert.doesNotMatch(ui.el("status").textContent,/Membership unavailable|503/);
});

for(const status of [401,403])for(const format of ["json","html"])for(const operation of ["refresh","save","remove"]){
  test(`workspace ${operation} clears private data and locks editing after ${format} ${status}`,async t=>{
    const ui=await fixture();t.after(()=>ui.window.close());
    ui.el("refresh").click();await ui.settle();assert.match(ui.el("list").textContent,/A colleague/);assert.doesNotMatch(ui.el("list").textContent,/user:/);
    ui.el("principal").value="user:private-colleague";ui.el("role").value="viewer";
    const failures=[];ui.window.fetch=async(url,options={})=>{
      failures.push({url,...options});
      return new Response(format==="json"?'{"detail":"Access changed"}':"<html>Sign in</html>",{status});
    };
    const submit=()=>ui.el("form").dispatchEvent(new ui.window.Event("submit",{bubbles:true,cancelable:true}));
    if(operation==="refresh")ui.el("refresh").click();
    else if(operation==="save")submit();
    else ui.el("list").querySelectorAll("button")[1].click();
    await ui.settle();
    assert.equal(failures.length,1);assert.equal(ui.el("list").textContent,"");assert.equal(ui.el("principal").value,"");
    assert.match(ui.el("status").textContent,/sign in again.*reload/i);
    assert.ok(Array.from(ui.window.document.querySelectorAll("button,input,select")).every(control=>control.disabled));
    ui.el("principal").value="user:retry";submit();ui.el("refresh").dispatchEvent(new ui.window.Event("click"));await ui.settle();
    assert.equal(failures.length,1,"a locked screen must require a new authenticated page load");
  });
}

test("a workspace picker retargets membership calls while the stale-tab header stays the rendered workspace",async t=>{
  const dom=new JSDOM('<section id="wm-root" data-tenant="tenant-a" data-expected="tenant-a" data-labels=\'{"user:reviewer":"rev@example.com"}\'><select id="wm-tenant"><option value="tenant-a" selected>A</option><option value="tenant-b">B</option></select><p id="wm-status"></p><button id="wm-refresh">Refresh</button><ul id="wm-list"></ul><form id="wm-form"><input id="wm-principal"><select id="wm-role"><option value="operator">Operator</option><option value="viewer">Viewer</option></select><button>Save</button></form></section>',{url:"https://lightwork.example/users",runScripts:"outside-only"}),{window}=dom,calls=[];
  t.after(()=>window.close());window.mvConfirm=async()=>true;window.fetch=async(url,options={})=>{calls.push({url,...options});return options.method?new Response(null,{status:204}):new Response('{"user:reviewer":"operator"}');};
  window.eval(fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-access-state.js'), 'utf8'));window.eval(source);const el=id=>window.document.getElementById("wm-"+id);const settle=async()=>{for(let i=0;i<10;i++)await new Promise(done=>setImmediate(done));};
  el("refresh").click();await settle();assert.match(el("list").textContent,/rev@example.com/);assert.doesNotMatch(el("list").textContent,/user:reviewer/);assert.equal(calls[0].url,"/api/v1/admin/tenants/tenant-a/roles");
  el("tenant").value="tenant-b";el("tenant").dispatchEvent(new window.Event("change"));assert.equal(el("list").textContent,"");assert.match(el("status").textContent,/members of B/);await settle();assert.equal(calls.filter(row=>!row.method).pop().url,"/api/v1/admin/tenants/tenant-b/roles");
  el("principal").value="user:reviewer";el("role").value="viewer";el("form").dispatchEvent(new window.Event("submit",{bubbles:true,cancelable:true}));await settle();
  const write=calls.find(row=>row.method==="PUT");assert.equal(write.url,"/api/v1/admin/tenants/tenant-b/roles/user%3Areviewer");assert.equal(write.headers["X-Lightwork-Expected-Tenant"],"tenant-a");
});

test("an empty rendered workspace sends no stale-tab header",async t=>{
  const dom=new JSDOM('<section id="wm-root" data-tenant="tenant-a" data-expected=""><p id="wm-status"></p><button id="wm-refresh">Refresh</button><ul id="wm-list"></ul><form id="wm-form"><input id="wm-principal"><select id="wm-role"><option value="operator">Operator</option></select><button>Save</button></form></section>',{url:"https://lightwork.example/users",runScripts:"outside-only"}),{window}=dom,calls=[];
  t.after(()=>window.close());window.fetch=async(url,options={})=>{calls.push({url,...options});return new Response('{}');};
  window.eval(fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-access-state.js'), 'utf8'));window.eval(source);window.document.getElementById("wm-refresh").click();for(let i=0;i<10;i++)await new Promise(done=>setImmediate(done));
  assert.equal(calls.length,1);assert.equal("X-Lightwork-Expected-Tenant" in calls[0].headers,false);
});

test("a delayed membership read cannot repaint after the page workspace changes",async t=>{
  const ui=await fixture();t.after(()=>ui.window.close());let resolve;
  ui.window.fetch=()=>new Promise(done=>{resolve=done;});
  ui.el("refresh").click();await new Promise(setImmediate);
  ui.window.document.getElementById("wm-root").dataset.tenant="tenant-b";
  resolve(new Response('{"user:old-private-member":"operator"}'));await ui.settle();
  assert.equal(ui.el("list").textContent,"");assert.equal(ui.el("refresh").disabled,true);
});

test("workspace admin picker shows only the selected workspace's members and protects own role",async t=>{
  const dom=new JSDOM('<section id="wm-root" data-tenant="acme" data-expected="acme"><select id="wm-tenant"><option value="acme" selected>Acme</option><option value="beta">Beta</option></select><p id="wm-status"></p><button id="wm-refresh">Refresh</button><ul id="wm-list"></ul><form id="wm-form"><select id="wm-principal"><option value="">Choose a colleague</option></select><select id="wm-role"><option value="">Choose a role</option></select><button>Save</button></form></section>',{url:"https://lightwork.example/users",runScripts:"outside-only"}),{window}=dom;
  t.after(()=>window.close());const root=window.document.getElementById("wm-root"),el=id=>window.document.getElementById("wm-"+id);
  root.dataset.globalAdmin="false";root.dataset.you="user:owner";
  root.dataset.labels=JSON.stringify({"user:owner":"Owner","user:acme":"Acme member","user:beta":"Beta member"});
  root.dataset.roleLabels=JSON.stringify({admin:"Administrator",viewer:"Viewer"});
  root.dataset.rolePermissions=JSON.stringify({admin:["admin","view"],viewer:["view"]});
  root.dataset.roleOptions=JSON.stringify({acme:["admin","viewer"],beta:["admin"]});
  window.fetch=async url=>new Response(url.includes("/beta/")?'{"user:owner":"admin","user:beta":"viewer"}':'{"user:owner":"admin","user:acme":"viewer"}');
  window.eval(fs.readFileSync(path.resolve(__dirname,"../../maverick_dashboard/static/lightwork-access-state.js"),"utf8"));window.eval(source);
  const settle=async()=>{for(let i=0;i<10;i++)await new Promise(done=>setImmediate(done));};
  el("refresh").click();await settle();
  assert.deepEqual(Array.from(el("principal").options).map(option=>option.value),["","user:acme","user:owner"]);
  assert.equal(el("list").querySelector("button[aria-label=\"Clear Owner's role in Acme\"]").disabled,true);
  el("tenant").value="beta";el("tenant").dispatchEvent(new window.Event("change"));await settle();
  assert.deepEqual(Array.from(el("principal").options).map(option=>option.value),["","user:beta","user:owner"]);
  assert.deepEqual(Array.from(el("role").options).map(option=>option.value),["","admin"]);
});

test("workspace invite roles follow the selected workspace's authority",t=>{
  const dom=new JSDOM('<select id="wi-tenant"><option value="acme" selected>Acme</option><option value="beta">Beta</option></select><select id="wi-role"><option value="viewer" selected>Viewer</option></select><section id="wm-root" data-tenant="acme" data-global-admin="false" data-role-options=\'{"acme":["viewer"],"beta":["admin","viewer"]}\' data-role-labels=\'{"admin":"Administrator","viewer":"Viewer"}\'><select id="wm-tenant"><option value="acme">Acme</option></select><p id="wm-status"></p><button id="wm-refresh">Refresh</button><ul id="wm-list"></ul><form id="wm-form"><select id="wm-principal"></select><select id="wm-role"></select></form></section>',{url:"https://lightwork.example/users",runScripts:"outside-only"}),{window}=dom;
  t.after(()=>window.close());window.fetch=async()=>new Response("{}");
  window.eval(fs.readFileSync(path.resolve(__dirname,"../../maverick_dashboard/static/lightwork-access-state.js"),"utf8"));window.eval(source);
  const tenant=window.document.getElementById("wi-tenant"),role=window.document.getElementById("wi-role");
  assert.deepEqual(Array.from(role.options).map(option=>option.value),["viewer"]);
  tenant.value="beta";tenant.dispatchEvent(new window.Event("change"));
  assert.deepEqual(Array.from(role.options).map(option=>option.value),["admin","viewer"]);
  tenant.value="acme";tenant.dispatchEvent(new window.Event("change"));
  assert.deepEqual(Array.from(role.options).map(option=>option.value),["viewer"]);
});
