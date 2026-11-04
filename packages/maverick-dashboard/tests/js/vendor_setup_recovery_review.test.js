'use strict';
// Independent recovery regressions; all responses/identities are synthetic.
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),{JSDOM}=require('jsdom');
const folder=path.resolve(__dirname,'../../maverick_dashboard');
const markup=fs.readFileSync(path.join(folder,'templates/vendor_onboarding.html'),'utf8').replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,'');
function snapshot(){return {context:'a'.repeat(64),configuration:'b'.repeat(64),revision:0,
  principal:'user:reviewer',modules_enabled:true,connections_enabled:true,
  binding:{resource_owner:'',ticket_connection:'',document_connection:''},owner_locked:false,
  eligible_owners:['user:reviewer'],connections:[
    {name:'jira-review',connector:'jira',revision:'j1',has_token:true},
    {name:'drive-review',connector:'gdrive',revision:'d1',has_token:true}],
  readiness:{state:'setup_required',configuration_complete:false,actions:[],
    deployment:{supported:true,message:'Synthetic supported profile.'},live_provider_verified:false}};}
async function fixture(t,intercept){
  const dom=new JSDOM(markup,{url:'https://app.example/third-party/vendor-onboarding',runScripts:'outside-only'});
  t.after(()=>dom.window.close());
  const w=dom.window,calls=[],uncaught=[],el=id=>w.document.getElementById('vs-'+id);
  w.addEventListener('error',event=>uncaught.push(event.message));
  t.after(()=>assert.deepEqual(uncaught,[]));
  w.fetch=async(url,options)=>{if(String(url).includes('/api/v1/choices/people'))return new Response(JSON.stringify({people:[{value:'user:other',label:'Olive Other'}]}),{headers:{'Content-Type':'application/json'}});calls.push({url,options});const value=await intercept(options);
    return value instanceof Response?value:new Response(JSON.stringify(value),{headers:{'Content-Type':'application/json'}});};
  w.eval(fs.readFileSync(path.join(folder,'static/lightwork-vendor-setup.js'),'utf8'));
  const settle=async()=>{for(let i=0;i<8;i++)await new Promise(resolve=>setImmediate(resolve));};
  await settle();return{w,calls,el,settle};
}
function choose(ui){
  ui.el('resource-owner').value='user:reviewer';ui.el('ticket').value='jira-review';ui.el('document').value='drive-review';
  ui.el('confirm').checked=true;ui.el('confirm').dispatchEvent(new ui.w.Event('change',{bubbles:true}));
}
const rejection=detail=>new Response(JSON.stringify({detail}),{status:422});

test('validation labels only exact body fields and never displays rejected metadata',async t=>{
  const ui=await fixture(t,options=>options.method==='PUT'?rejection([
    {loc:['body','document'],msg:'PRIVATE_MESSAGE',input:'PRIVATE_INPUT',ctx:{error:'PRIVATE_CONTEXT'}},
    {loc:['query','ticket'],msg:'private query'},
    {loc:['body','resource_owner','nested'],msg:'private nested'},
    {loc:['body','document'],input:'PRIVATE_DUPLICATE'},
  ]):snapshot());
  choose(ui);ui.el('save').click();await ui.settle();
  const status=ui.el('status').textContent;
  assert.match(status,/Google Drive connection/);
  assert.doesNotMatch(status,/Jira connection|Vendor review owner|PRIVATE_|private query|private nested/);
  assert.equal((status.match(/Google Drive connection/g)||[]).length,1);
  assert.equal(ui.el('ticket').value,'jira-review');assert.equal(ui.el('document').value,'drive-review');
  assert.equal(ui.el('confirm').checked,false);assert.equal(ui.el('save').disabled,true);
});

test('string validation details cannot echo a raw rejected value',async t=>{
  const ui=await fixture(t,options=>options.method==='PUT'?rejection('Invalid owner: PRIVATE_RAW_VALUE'):snapshot());
  choose(ui);ui.el('save').click();await ui.settle();
  assert.doesNotMatch(ui.el('status').textContent,/PRIVATE_RAW_VALUE/);
  assert.match(ui.el('status').textContent,/Refresh/);
  assert.equal(ui.el('resource-owner').value,'user:reviewer');
});

test('in-flight duplicate submissions and refresh cannot send another mutation',async t=>{
  let finish;
  const ui=await fixture(t,options=>options.method==='PUT'?new Promise(resolve=>{finish=resolve;}):snapshot());
  choose(ui);ui.el('save').click();
  ui.el('form').dispatchEvent(new ui.w.Event('submit',{bubbles:true,cancelable:true}));
  ui.el('refresh').click();await ui.settle();
  assert.equal(ui.calls.filter(call=>call.options.method==='PUT').length,1);
  assert.equal(ui.calls.length,2);assert.equal(ui.el('confirm').disabled,true);
  finish(new Response('Unavailable',{status:503}));await ui.settle();
  assert.equal(ui.el('save').disabled,true);assert.equal(ui.el('confirm').checked,false);
  assert.equal(ui.el('refresh').disabled,false);assert.equal(ui.el('ticket').value,'jira-review');
});

test('blocked readback cannot restore or authorize the retained draft even at the same revision',async t=>{
  let current=snapshot();
  const ui=await fixture(t,options=>{if(options.method==='PUT')throw new TypeError('Network interrupted');return current;});
  choose(ui);ui.el('save').click();await ui.settle();
  current={...snapshot(),connections:[],eligible_owners:[],readiness:{
    state:'blocked',configuration_complete:false,actions:[],live_provider_verified:false,
    deployment:{supported:false,message:'Synthetic deployment is unsupported.'}}};
  ui.el('refresh').click();await ui.settle();
  assert.equal(ui.el('ticket').value,'');assert.equal(ui.el('document').value,'');
  assert.equal(ui.el('resource-owner').value,'');assert.equal(ui.el('confirm').disabled,true);
  ui.el('confirm').checked=true;ui.el('confirm').dispatchEvent(new ui.w.Event('change',{bubbles:true}));
  ui.el('form').dispatchEvent(new ui.w.Event('submit',{bubbles:true,cancelable:true}));
  assert.equal(ui.el('save').disabled,true);assert.equal(ui.el('enable').disabled,true);
  assert.match(ui.el('status').textContent,/Resolve the deployment issue/);
  assert.equal(ui.calls.filter(call=>call.options.method==='PUT').length,1);
});

test('context conflict during readback clears private draft and requires page reload',async t=>{
  let first=true;
  const ui=await fixture(t,options=>{
    if(first){first=false;return snapshot();}
    if(options.method==='PUT')throw new TypeError('Lost response');
    return new Response(JSON.stringify({detail:'Your account or workspace changed. Reload setup.'}),{status:409});
  });
  choose(ui);ui.el('save').click();await ui.settle();ui.el('refresh').click();await ui.settle();
  for(const id of ['resource-owner','ticket','document'])assert.equal(ui.el(id).options.length,0);
  assert.equal(ui.el('owner').textContent,'');assert.equal(ui.el('refresh').disabled,true);
  assert.equal(ui.el('save').disabled,true);assert.equal(ui.el('confirm').checked,false);
  assert.match(ui.el('status').textContent,/Reload the page/);
});

for(const defect of ['missing revision','oversized credential revision'])test('malformed successful readback clears draft: '+defect,async t=>{
  let current=snapshot();
  const ui=await fixture(t,options=>{if(options.method==='PUT')throw new TypeError('Lost response');return current;});
  choose(ui);ui.el('save').click();await ui.settle();
  current=snapshot();if(defect==='missing revision')delete current.revision;
  else current.connections[0].revision='x'.repeat(65);
  ui.el('refresh').click();await ui.settle();
  for(const id of ['resource-owner','ticket','document'])assert.equal(ui.el(id).options.length,0);
  assert.equal(ui.el('save').disabled,true);assert.equal(ui.el('confirm').checked,false);
  assert.equal(ui.calls.filter(call=>call.options.method==='PUT').length,1);
});
