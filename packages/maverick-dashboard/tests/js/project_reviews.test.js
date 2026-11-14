"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path");
const {JSDOM}=require("jsdom"),folder=path.resolve(__dirname,"../../maverick_dashboard");
const markup=fs.readFileSync(path.join(folder,"templates/project_reviews.html"),"utf8").replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,"");
const source=fs.readFileSync(path.join(folder,"static/lightwork-project-reviews.js"),"utf8");
const snapshot={goal_id:7,title:"Captured <img src=x>",result:"Sensitive <img src=x onerror=alert(1)> result",suite:"finance"};
const packet={id:"PRP-one",revision:1,source_version:"a".repeat(64),snapshot,owner:"user:owner",reviewer:"user:reviewer",project_name:"Project",status:"pending",due_at:2000000000,note:"Review this.",history:[{actor:"user:owner",action:"sent",at:1000,note:"Review this."}],stale:false,can_respond:true};
async function fixture({principal="user:owner",intercept=()=>undefined,fragment="",setup=()=>{}}={}){
  const dom=new JSDOM(markup,{url:"https://lightwork.example/project-reviews"+fragment,runScripts:"outside-only"}),{window}=dom,calls=[];
  window.document.getElementById("pr-root").dataset.context="context-one";window.TextEncoder=TextEncoder;window.mvConfirm=async()=>true;
  window.fetch=async(url,options={})=>{const call={url:new URL(url,window.location),...options};calls.push(call);const injected=await intercept(call);if(injected instanceof Response)return injected;let data=injected;
    if(data===undefined){const route=call.url.pathname;
      if(route.endsWith("/preview"))data={snapshot,source_version:packet.source_version};
      else if(route.endsWith("/projects/1"))data={team:{revision:2,members:["user:reviewer"]},eligible_members:["user:reviewer"],goals:[{id:7,title:"Result",status:"done"}]};
      else if(route.includes("/packets/"))data=packet;
      else if(route.endsWith("/packets"))data=packet;
      else data={context:"context-one",principal,projects:principal==="user:owner"?[{id:1,name:"Project"}]:[],items:[{...packet,title:snapshot.title}],counts:{total:1,pending:1,overdue:0},total:1,offset:0,limit:50,has_more:false};
    }return new Response(JSON.stringify(data),{headers:{"Content-Type":"application/json"}});
  };
  const el=id=>window.document.getElementById("pr-"+id);async function settle(){for(let i=0;i<20;i++)await new Promise(done=>setImmediate(done));}
  async function click(id){el(id).click();await settle();}
  function change(id,value){el(id).value=value;el(id).dispatchEvent(new window.Event("input",{bubbles:true}));el(id).dispatchEvent(new window.Event("change",{bubbles:true}));}
  function submit(id){el(id).dispatchEvent(new window.Event("submit",{cancelable:true,bubbles:true}));}
  setup(window);window.eval(source);await settle();return{window,calls,el,settle,click,change,submit};
}
async function preview(ui){ui.change("project","1");await ui.settle();ui.change("goal","7");await ui.click("preview");ui.change("reviewer","user:reviewer");ui.change("due",new Date(Date.now()+86400000).toISOString().slice(0,16));ui.change("note","Review the explicit limitations.");}
test("sharing needs a current preview and explicit confirmation, and keeps the exact captured version",async t=>{
  const ui=await fixture();t.after(()=>ui.window.close());assert.equal(ui.el("send-button").disabled,true);ui.submit("send");await ui.settle();assert.equal(ui.calls.some(row=>row.method==="POST"),false);
  await preview(ui);assert.equal(ui.el("preview-text").querySelector("img"),null);assert.match(ui.el("preview-text").textContent,/Sensitive/);
  ui.window.mvConfirm=async()=>false;ui.submit("send");await ui.settle();assert.equal(ui.calls.some(row=>row.method==="POST"),false);
  ui.window.mvConfirm=async()=>true;ui.submit("send");await ui.settle();const write=ui.calls.find(row=>row.method==="POST"),body=JSON.parse(write.body);
  assert.equal(body.source_version,packet.source_version);assert.equal(body.expected_team_revision,2);assert.equal(body.goal_id,7);assert.equal(write.headers["X-Lightwork-Review-Context"],"context-one");assert.match(ui.el("status").textContent,/No task was started or approved/);
});
test("an uncertain send preserves input and exact retry identity while refusing duplicate clicks",async t=>{
  let release,writes=0;const blocked=new Promise(done=>release=done);
  const ui=await fixture({intercept:async call=>{if(call.method==="POST"){writes++;await blocked;throw new Error("Connection interrupted");}}});t.after(()=>ui.window.close());await preview(ui);
  ui.submit("send");await new Promise(done=>setImmediate(done));ui.submit("send");assert.equal(ui.el("send-button").disabled,true);release();await ui.settle();assert.equal(writes,1);
  assert.equal(ui.el("note").value,"Review the explicit limitations.");ui.submit("send");await ui.settle();const bodies=ui.calls.filter(row=>row.method==="POST").map(row=>row.body);assert.equal(bodies.length,2);assert.equal(bodies[0],bodies[1]);
});
test("same packet refresh keeps an unsaved review comment; changed packet version resets the decision",async t=>{
  let revision=1;const ui=await fixture({principal:"user:reviewer",intercept:call=>call.url.pathname.includes("/packets/")?{...packet,revision}:undefined});t.after(()=>ui.window.close());
  ui.el("inbox").querySelector("button").click();await ui.settle();ui.change("response-note","A correction still being written.");ui.change("action","approve");await ui.click("refresh");assert.equal(ui.el("response-note").value,"A correction still being written.");assert.equal(ui.el("action").value,"approve");
  revision=2;await ui.click("refresh");assert.equal(ui.el("response-note").value,"A correction still being written.");assert.equal(ui.el("action").value,"comment");assert.equal(ui.el("result").querySelector("img"),null);assert.match(ui.el("status").textContent,/check it against the current result/i);
});
test("stale packets cannot be approved in the UI and revoked packet reads clear prior content",async t=>{
  let revoked=false;const ui=await fixture({principal:"user:reviewer",intercept:call=>call.url.pathname.includes("/packets/")?(revoked?new Response('{"detail":"Access revoked"}',{status:404}):{...packet,stale:true}):undefined});t.after(()=>ui.window.close());
  ui.el("inbox").querySelector("button").click();await ui.settle();assert.equal(ui.el("action").querySelector('option[value="approve"]').disabled,true);assert.match(ui.el("stale").textContent,/source task changed/i);
  revoked=true;await ui.click("refresh");assert.equal(ui.el("packet").hidden,true);assert.equal(ui.el("result").textContent,"");assert.match(ui.el("status").textContent,/no longer exists/);
});

test("failed refresh authorization clears prior packet and project content",async t=>{
  let denied=false;const ui=await fixture({intercept:call=>denied&&call.url.pathname==="/api/v1/project-reviews"?new Response('{"detail":"Workspace changed"}',{status:409}):undefined});t.after(()=>ui.window.close());await preview(ui);ui.el("inbox").querySelector("button").click();await ui.settle();
  denied=true;await ui.click("refresh");assert.equal(ui.el("inbox").textContent,"");assert.equal(ui.el("result").textContent,"");assert.equal(ui.el("preview-text").textContent,"");assert.equal(ui.el("owner").hidden,true);assert.equal(ui.el("packet").hidden,true);assert.equal(ui.el("response-button").disabled,true);
  assert.equal(ui.calls.every(call=>call.cache==="no-store"),true);
});

for(const code of [401,403])test(`HTML ${code} on a write erases private review state and locks controls`,async t=>{
  let denied=false;const ui=await fixture({intercept:call=>denied&&call.method==='POST'?new Response('<h1>Sign in</h1>',{status:code,headers:{'Content-Type':'text/html'}}):undefined});t.after(()=>ui.window.close());
  await preview(ui);ui.el('inbox').querySelector('button').click();await ui.settle();ui.change('response-note','Sensitive unfinished review');denied=true;ui.submit('respond');await ui.settle();
  for(const id of ['inbox','result','preview-text','history','packet-note'])assert.equal(ui.el(id).textContent,'',id);
  assert.equal(ui.el('note').value,'');assert.equal(ui.el('response-note').value,'');assert.equal(ui.el('project').options.length,0);
  assert.equal(ui.el('refresh').disabled,true);assert.equal(ui.el('response-button').disabled,true);assert.match(ui.el('status').textContent,/sign in|access.*changed/i);
});

test('unfinished review notes warn before leaving and a cancelled packet switch retains the original draft',async t=>{
  const ui=await fixture({principal:'user:reviewer',intercept:call=>call.url.pathname==='/api/v1/project-reviews'?{context:'context-one',principal:'user:reviewer',projects:[],items:[{...packet,title:'First'},{...packet,id:'PRP-two',title:'Second'}],counts:{total:2,pending:2,overdue:0},total:2,offset:0,limit:50,has_more:false}:call.url.pathname.endsWith('PRP-two')?{...packet,id:'PRP-two'}:undefined});t.after(()=>ui.window.close());ui.el('inbox').querySelector('button').click();await ui.settle();
  ui.change('response-note','Keep this reasoning');const event=new ui.window.Event('beforeunload',{cancelable:true});ui.window.dispatchEvent(event);assert.equal(event.defaultPrevented,true);
  ui.window.mvConfirm=async()=>false;const before=ui.calls.length;ui.el('inbox').querySelectorAll('button')[1].click();await ui.settle();
  assert.equal(ui.el('response-note').value,'Keep this reasoning');assert.equal(ui.calls.length,before);
  ui.window.mvConfirm=async()=>true;ui.el('inbox').querySelectorAll('button')[1].click();await ui.settle();assert.equal(ui.el('response-note').value,'');
  const discarded=new ui.window.Event('beforeunload',{cancelable:true});ui.window.dispatchEvent(discarded);assert.equal(discarded.defaultPrevented,false);
});

test('an acknowledged review comment no longer triggers the unfinished-note warning',async t=>{const ui=await fixture({principal:'user:reviewer'});t.after(()=>ui.window.close());ui.el('inbox').querySelector('button').click();await ui.settle();ui.change('response-note','Reviewed the limitations.');ui.submit('respond');await ui.settle();const event=new ui.window.Event('beforeunload',{cancelable:true});ui.window.dispatchEvent(event);assert.equal(event.defaultPrevented,false);});

test('an interrupted packet refresh keeps the unfinished comment for an explicit retry without leaving a writable stale review',async t=>{let failed=false;const ui=await fixture({principal:'user:reviewer',intercept:call=>failed&&call.url.pathname.includes('/packets/')?new Response('{"detail":"Synthetic interruption"}',{status:503}):undefined});t.after(()=>ui.window.close());ui.el('inbox').querySelector('button').click();await ui.settle();ui.change('response-note','Keep the reasoning in progress');failed=true;await ui.click('refresh');assert.equal(ui.el('packet').hidden,true);assert.equal(ui.el('response-button').disabled,true);const writes=ui.calls.filter(call=>call.method==='POST').length;ui.submit('respond');await ui.settle();assert.equal(ui.calls.filter(call=>call.method==='POST').length,writes);failed=false;await ui.click('refresh');assert.equal(ui.el('packet').hidden,false);assert.equal(ui.el('response-note').value,'Keep the reasoning in progress');assert.equal(ui.el('response-button').disabled,false);});

test("packet fragments read only the exact permitted record after the context checked inbox",async t=>{
  const identifier="PRP-"+"c".repeat(32);
  const ui=await fixture({principal:"user:reviewer",fragment:"#packet="+identifier,intercept:call=>call.url.pathname.endsWith(identifier)?{...packet,id:identifier}:undefined});t.after(()=>ui.window.close());
  assert.equal(ui.calls[0].url.pathname,"/api/v1/project-reviews");assert.equal(ui.calls[1].url.pathname,"/api/v1/project-reviews/packets/"+identifier);assert.equal(ui.calls[1].headers["X-Lightwork-Review-Context"],"context-one");assert.match(ui.el("result").textContent,/Sensitive/);assert.equal(ui.calls.some(call=>call.method==="POST"),false);
  const denied=await fixture({fragment:"#packet="+identifier,intercept:call=>call.url.pathname.endsWith(identifier)?new Response('{"detail":"Access revoked"}',{status:404}):undefined});t.after(()=>denied.window.close());assert.equal(denied.el("packet").hidden,true);assert.equal(denied.el("result").textContent,"");assert.match(denied.el("status").textContent,/no longer exists/);
  const changed=await fixture({fragment:"#packet="+identifier,intercept:call=>call.url.pathname==="/api/v1/project-reviews"?{context:"other-account"}:undefined});t.after(()=>changed.window.close());assert.equal(changed.calls.length,1);assert.equal(changed.el("result").textContent,"");
  const invalid=await fixture({fragment:"#packet=../../secrets"});t.after(()=>invalid.window.close());assert.equal(invalid.calls.length,1);
});

test("sharing asks through the shared dialog and refuses when it is missing; people show by name",async t=>{
  assert.equal(/window\.confirm\s*\(/.test(source),false);
  const ui=await fixture();t.after(()=>ui.window.close());delete ui.window.mvConfirm;await preview(ui);
  assert.match(ui.el("reviewer").textContent,/reviewer/);assert.equal(/user:/.test(ui.el("reviewer").textContent),false);
  ui.submit("send");await ui.settle();assert.equal(ui.calls.some(row=>row.method==="POST"),false);
});

const installLocale=require('./helpers/recovery_review_i18n');
const fr=text=>({text,lang:'fr'});
const reviewCatalog={
  'Choose your project':fr('Choisissez votre projet'),
  'Pending':fr('En attente'),
  'Review list is up to date. Only reviews you can open are shown.':fr('La liste des révisions est à jour.'),
  'Share exactly the captured result shown above with {name}?':fr('Partager le résultat capturé avec {name} ?'),
  'Share for review':fr('Partager pour révision'),
  'Reviewer: {name}':fr('Réviseur : {name}'),
  'Cancel':fr('Annuler'),
};
test('project review keeps stored text opaque when it equals a translated control',async t=>{
  const captured={...snapshot,title:'Choose your project',result:'Choose your project <img src=x> مرحبا'};
  const ui=await fixture({setup:w=>installLocale(w,{catalog:reviewCatalog}),intercept:call=>call.url.pathname.includes('/packets/')?{...packet,snapshot:captured,note:'Choose your project'}:undefined});t.after(()=>ui.window.close());
  assert.equal(ui.el('project').firstElementChild.textContent,'Choisissez votre projet');assert.equal(ui.el('project').firstElementChild.lang,'fr');
  ui.el('inbox').querySelector('button').click();await ui.settle();
  assert.equal(ui.el('packet-title').textContent,'Choose your project');assert.equal(ui.el('packet-title').lang,'und');assert.equal(ui.el('packet-note').lang,'und');
  assert.equal(ui.el('result').textContent,captured.result);assert.equal(ui.el('result').querySelector('img'),null);
  assert.match(ui.el('packet-summary').textContent,/En attente/);assert.equal(ui.el('packet-summary').querySelector('bdi').lang,'und');
  ui.window.LightworkI18n.translate();assert.equal(ui.el('packet-note').textContent,'Choose your project');assert.equal(ui.el('result').textContent,captured.result);
});
test('translated sharing confirmation isolates exact recipient and cancellation causes no write',async t=>{
  const recipient='user:<img src=x> مرحبا';
  const ui=await fixture({setup:w=>installLocale(w,{catalog:reviewCatalog}),intercept:call=>call.url.pathname.endsWith('/projects/1')?{team:{revision:2,members:[recipient]},eligible_members:[recipient],goals:[{id:7,title:'Result',status:'done'}]}:undefined});t.after(()=>ui.window.close());
  await preview(ui);ui.change('reviewer',recipient);ui.submit('send');await ui.settle();
  const doc=ui.window.document,msg=doc.getElementById('mv-confirm-msg');assert.equal(doc.getElementById('mv-confirm').open,true);assert.equal(msg.lang,'fr');assert.match(msg.textContent,/Partager/);assert.equal(msg.querySelector('bdi').textContent,'<img src=x> مرحبا');assert.equal(msg.querySelector('bdi').lang,'und');assert.equal(msg.querySelector('img'),null);
  doc.getElementById('mv-confirm-cancel').click();await ui.settle();assert.equal(ui.calls.some(call=>call.method==='POST'),false);assert.equal(ui.el('note').value,'Review the explicit limitations.');
});
test('an unknown review network error stays opaque and refresh restores the translated status',async t=>{
  let broken=false;const ui=await fixture({setup:w=>installLocale(w,{catalog:reviewCatalog}),intercept:()=>{if(broken)throw new Error('Choose your project');}});t.after(()=>ui.window.close());
  broken=true;await ui.click('refresh');assert.equal(ui.el('status').textContent,'Choose your project');assert.equal(ui.el('status').lang,'und');
  broken=false;await ui.click('refresh');assert.equal(ui.el('status').textContent,'La liste des révisions est à jour.');assert.equal(ui.el('status').lang,'fr');assert.equal(ui.el('status').hasAttribute('data-user-content'),false);
});


test("sharing rejects past and current due dates before confirmation or a write",async t=>{
  const ui=await fixture();t.after(()=>ui.window.close());await preview(ui);
  const due=new Date(ui.el("due").value).getTime();let confirmations=0;
  ui.window.mvConfirm=async()=>{confirmations++;return true;};
  for(const now of [due+1000,due]){
    ui.window.Date.now=()=>now;ui.submit("send");await ui.settle();
    assert.equal(confirmations,0);assert.equal(ui.calls.some(row=>row.method==="POST"),false);
    assert.match(ui.el("status").textContent,/future due date/);
  }
  ui.window.Date.now=()=>due-1000;ui.submit("send");await ui.settle();
  assert.equal(confirmations,1);assert.equal(ui.calls.filter(row=>row.method==="POST").length,1);
});
