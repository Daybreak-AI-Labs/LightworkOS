'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{JSDOM}=require('jsdom');
const folder=path.resolve(__dirname,'../../maverick_dashboard');
const markup=fs.readFileSync(path.join(folder,'templates/vendor_onboarding.html'),'utf8').replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,'');
const readiness={state:'setup_required',configuration_complete:false,actions:[{id:'owner',label:'Choose a vendor review owner.',href:'#vs-resource-owner'}],deployment:{supported:true,message:'One persistent Lightwork installation.'},live_provider_verified:false};
const initial={context:'a'.repeat(64),configuration:'b'.repeat(64),revision:0,binding:{resource_owner:''},owner_locked:false,owner_source:'initial',eligible_owners:['user:other','user:owner'],principal:'user:owner',modules_enabled:true,connections:[{name:'jira',connector:'jira',revision:'j1',has_token:true},{name:'drive',connector:'gdrive',revision:'d1',has_token:true}],readiness};
async function fixture(intercept=()=>initial){
  const dom=new JSDOM(markup,{url:'https://app.example/vendor-onboarding',runScripts:'outside-only'}),calls=[],w=dom.window;
  w.fetch=async(url,options)=>{if(String(url).includes('/api/v1/choices/people'))return new Response(JSON.stringify({people:[{value:'user:other',label:'Olive Other'}]}),{headers:{'Content-Type':'application/json'}});calls.push({url,options});const value=await intercept(url,options);return value instanceof Response?value:new Response(JSON.stringify(value),{headers:{'Content-Type':'application/json'}});};
  w.eval(fs.readFileSync(path.join(folder,'static/lightwork-vendor-setup.js'),'utf8'));
  async function settle(){for(let i=0;i<8;i++)await new Promise(r=>setImmediate(r));}
  const el=id=>w.document.getElementById('vs-'+id);
  await settle();return{w,calls,el,settle};
}
function choose(ui) {
  ui.el('resource-owner').value='user:other';ui.el('ticket').value='jira';ui.el('document').value='drive';
  confirm(ui);
}
function confirm(ui) {
  ui.el('confirm').checked=true;ui.el('confirm').dispatchEvent(new ui.w.Event('change',{bubbles:true}));
}

test('field validation retains valid choices and names the field without echoing rejected input',async t=>{
  let reject=true;const ui=await fixture((url,options)=>options.method==='PUT'&&reject?
    new Response(JSON.stringify({detail:[{loc:['body','ticket'],msg:'Invalid identifier',input:'private-rejected-value'}]}),{status:422}):initial);
  t.after(()=>ui.w.close());choose(ui);ui.el('save').click();await ui.settle();
  assert.equal(ui.el('resource-owner').value,'user:other');assert.equal(ui.el('document').value,'drive');
  assert.match(ui.el('status').textContent,/Jira connection/);assert.doesNotMatch(ui.el('status').textContent,/private-rejected-value/);
  assert.equal(ui.el('confirm').checked,false);assert.equal(ui.el('save').disabled,true);
  reject=false;ui.el('refresh').click();await ui.settle();
  assert.equal(ui.el('resource-owner').value,'user:other');assert.equal(ui.el('document').value,'drive');
  assert.equal(ui.el('save').disabled,true);confirm(ui);ui.el('save').click();await ui.settle();
  assert.equal(ui.calls.filter(c=>c.options.method==='PUT').length,2);
});

test('interrupted save requires readback and explicit confirmation without losing same-authority draft',async t=>{
  let fail=true;const ui=await fixture((url,options)=>{if(options.method==='PUT'&&fail)throw new TypeError('Failed to fetch');return initial;});
  t.after(()=>ui.w.close());choose(ui);ui.el('save').click();ui.el('form').dispatchEvent(new ui.w.Event('submit',{bubbles:true,cancelable:true}));await ui.settle();
  assert.equal(ui.calls.filter(c=>c.options.method==='PUT').length,1);
  assert.equal(ui.el('ticket').value,'jira');assert.equal(ui.el('document').value,'drive');assert.equal(ui.el('resource-owner').value,'user:other');
  assert.match(ui.el('status').textContent,/Refresh/);assert.equal(ui.el('confirm').checked,false);
  confirm(ui);ui.el('save').click();await ui.settle();assert.equal(ui.calls.length,2);
  fail=false;ui.el('refresh').click();await ui.settle();assert.equal(ui.el('confirm').checked,false);
  assert.equal(ui.el('resource-owner').value,'user:other');assert.equal(ui.el('document').value,'drive');
  assert.equal(ui.calls.filter(c=>c.options.method==='PUT').length,1);
  confirm(ui);ui.el('save').click();await ui.settle();assert.equal(ui.calls.filter(c=>c.options.method==='PUT').length,2);
});

test('a lost response after commit reads canonical saved choices without resubmission',async t=>{
  let current=initial;const ui=await fixture((url,options)=>{
    if(options.method==='PUT') {
      current={...initial,revision:1,owner_locked:true,binding:{resource_owner:'user:other',ticket_connection:'jira',document_connection:'drive'}};
      throw new TypeError('Failed to fetch');
    }
    return current;
  });t.after(()=>ui.w.close());choose(ui);ui.el('save').click();await ui.settle();
  ui.el('refresh').click();await ui.settle();
  assert.equal(ui.el('resource-owner').value,'user:other');assert.equal(ui.el('resource-owner').disabled,true);
  assert.equal(ui.el('ticket').value,'jira');assert.equal(ui.el('document').value,'drive');
  assert.match(ui.el('status').textContent,/Current saved settings/);assert.equal(ui.el('confirm').checked,false);
  assert.equal(ui.calls.filter(c=>c.options.method==='PUT').length,1);
  ui.el('save').click();assert.equal(ui.calls.filter(c=>c.options.method==='PUT').length,1);
});

test('refresh clears revoked owner and rotated connection while retaining an unchanged valid choice',async t=>{
  let changed=false;const ui=await fixture(()=>changed?{...initial,eligible_owners:['user:owner'],connections:initial.connections.map(row=>row.connector==='jira'?{...row,revision:'j2'}:row)}:initial);
  t.after(()=>ui.w.close());choose(ui);changed=true;ui.el('refresh').click();await ui.settle();
  assert.equal(ui.el('resource-owner').value,'');assert.equal(ui.el('ticket').value,'');assert.equal(ui.el('document').value,'drive');
  assert.match(ui.el('status').textContent,/Choose again: vendor review owner, Jira connection/);
  assert.equal(ui.el('confirm').checked,false);assert.equal(ui.calls.length,2);
});

test('repeated unavailable refreshes keep the original draft but never writable authority',async t=>{
  let unavailable=false;const ui=await fixture(()=>unavailable?new Response('Unavailable',{status:503}):initial);
  t.after(()=>ui.w.close());choose(ui);unavailable=true;
  for(let n=0;n<2;n++) {ui.el('refresh').click();await ui.settle();assert.equal(ui.el('resource-owner').value,'user:other');assert.equal(ui.el('confirm').checked,false);assert.equal(ui.el('save').disabled,true);}
  unavailable=false;ui.el('refresh').click();await ui.settle();
  assert.equal(ui.el('ticket').value,'jira');assert.equal(ui.el('document').value,'drive');assert.equal(ui.el('resource-owner').value,'user:other');
  assert.equal(ui.el('confirm').checked,false);assert.equal(ui.calls.filter(c=>c.options.method!=='GET').length,0);
});

test('malformed success and changed context cannot retain prior choices',async t=>{
  for(const next of [new Response('<html>broken response</html>'),{...initial,revision:undefined},{...initial,connections:[{...initial.connections[0],revision:undefined}]},{...initial,context:'c'.repeat(64)}]) {
    let changed=false;const ui=await fixture(()=>changed?next:initial);t.after(()=>ui.w.close());choose(ui);changed=true;
    ui.el('refresh').click();await ui.settle();assert.equal(ui.el('ticket').options.length,0);assert.equal(ui.el('resource-owner').options.length,0);assert.equal(ui.el('save').disabled,true);
  }
});

test('context conflict clears private choices immediately and locks a stale-context refresh',async t=>{
  let conflict=false;const ui=await fixture(()=>conflict?new Response(JSON.stringify({detail:'Your account or workspace changed. Reload setup.'}),{status:409}):initial);
  t.after(()=>ui.w.close());choose(ui);conflict=true;ui.el('save').click();await ui.settle();
  assert.equal(ui.el('resource-owner').options.length,0);assert.equal(ui.el('ticket').options.length,0);assert.equal(ui.el('confirm').checked,false);
  ui.el('refresh').click();await ui.settle();assert.equal(ui.el('refresh').disabled,true);assert.match(ui.el('status').textContent,/Reload the page/);
});
test('selection changes clear confirmation and submission binds exact displayed generations',async t=>{
  const ui=await fixture();t.after(()=>ui.w.close());assert.equal(ui.calls.length,1);assert.equal(ui.el('save').disabled,true);
  ui.el('resource-owner').value='user:other';ui.el('resource-owner').dispatchEvent(new ui.w.Event('change',{bubbles:true}));
  ui.el('ticket').value='jira';ui.el('confirm').checked=true;ui.el('confirm').dispatchEvent(new ui.w.Event('change',{bubbles:true}));
  ui.el('document').value='drive';ui.el('document').dispatchEvent(new ui.w.Event('change',{bubbles:true}));assert.equal(ui.el('confirm').checked,false);
  ui.el('confirm').checked=true;ui.el('confirm').dispatchEvent(new ui.w.Event('change',{bubbles:true}));ui.el('save').click();await ui.settle();
  assert.deepEqual(JSON.parse(ui.calls[1].options.body),{confirm:true,context:initial.context,configuration:initial.configuration,ticket:'jira',ticket_revision:'j1',document:'drive',document_revision:'d1',expected_revision:0,resource_owner:'user:other'});assert.equal(ui.el('confirm').checked,false);
});
test('failed refresh clears credentials and changed account cannot retain prior setup',async t=>{
  let mode=0;const ui=await fixture(()=>mode===1?new Response('<h1>Sign in</h1>',{status:401}):mode===2?{...initial,context:'c'.repeat(64)}:initial);t.after(()=>ui.w.close());
  mode=2;ui.el('refresh').click();await ui.settle();assert.equal(ui.el('ticket').options.length,0);assert.equal(ui.el('refresh').disabled,true);assert.match(ui.el('status').textContent,/account or workspace changed/);
  const other=await fixture(()=>mode===1?new Response('<h1>Sign in</h1>',{status:401}):initial);t.after(()=>other.w.close());mode=1;other.el('refresh').click();await other.settle();assert.equal(other.el('ticket').options.length,0);assert.equal(other.el('save').disabled,true);
  assert.equal(other.el('resource-owner').options.length,0);assert.equal(other.el('owner').textContent,'');
});

test('fresh owner choice is explicit and changes require a fresh confirmation',async t=>{
  const ui=await fixture();t.after(()=>ui.w.close());assert.equal(ui.el('resource-owner').value,'');
  assert.equal(ui.el('resource-owner').options[1].textContent,'Olive Other');assert.equal(ui.el('resource-owner').options[1].value,'user:other');
  ui.el('ticket').value='jira';ui.el('confirm').checked=true;ui.el('confirm').dispatchEvent(new ui.w.Event('change',{bubbles:true}));
  assert.equal(ui.el('save').disabled,true);ui.el('save').click();assert.equal(ui.calls.length,1);
  ui.el('resource-owner').value='user:other';ui.el('resource-owner').dispatchEvent(new ui.w.Event('change',{bubbles:true}));
  assert.equal(ui.el('confirm').checked,false);assert.equal(ui.el('save').disabled,true);
  ui.el('confirm').checked=true;ui.el('confirm').dispatchEvent(new ui.w.Event('change',{bubbles:true}));
  assert.equal(ui.el('save').disabled,false);
});

test('existing owner is fixed while reviewed connection updates keep its exact identity',async t=>{
  const fixed={...initial,revision:2,owner_locked:true,owner_source:'saved',eligible_owners:[],binding:{resource_owner:'user:historical',ticket_connection:'jira'}};
  const ui=await fixture(()=>fixed);t.after(()=>ui.w.close());
  assert.equal(ui.el('resource-owner').disabled,true);assert.equal(ui.el('resource-owner').value,'user:historical');
  assert.equal(ui.el('resource-owner').selectedOptions[0].textContent,'historical');assert.doesNotMatch(ui.el('owner').textContent,/user:/);
  assert.match(ui.el('owner').textContent,/cannot transfer ownership/);
  ui.el('confirm').checked=true;ui.el('confirm').dispatchEvent(new ui.w.Event('change',{bubbles:true}));ui.el('save').click();await ui.settle();
  assert.equal(JSON.parse(ui.calls[1].options.body).resource_owner,'user:historical');
  assert.equal(JSON.parse(ui.calls[1].options.body).expected_revision,2);
  const legacy=await fixture(()=>({...fixed,binding:{...fixed.binding,resource_owner:'Procurement team'}}));t.after(()=>legacy.w.close());
  assert.equal(legacy.el('resource-owner').selectedOptions[0].textContent,'Procurement team');assert.match(legacy.el('owner').textContent,/Procurement team/);
});

test('unsupported deployment disables setup writes and malformed readiness clears prior controls',async t=>{
  const blocked={...initial,readiness:{...readiness,state:'blocked',deployment:{supported:false,message:'Deployment needs attention.'},actions:[{id:'deployment',label:'Use one persistent installation.',href:'#vs-deployment'}]}};
  const ui=await fixture(()=>blocked);t.after(()=>ui.w.close());
  assert.match(ui.el('readiness-summary').textContent,/Deployment needs attention/);
  assert.equal(ui.el('status').textContent,'Resolve the deployment issue above before changing setup.');
  assert.equal(ui.el('save').disabled,true);assert.equal(ui.el('enable').disabled,true);assert.equal(ui.el('confirm').disabled,true);
  ui.el('enable').click();assert.equal(ui.calls.length,1);
  const broken=await fixture(()=>({...initial,readiness:undefined}));t.after(()=>broken.w.close());
  assert.match(broken.el('status').textContent,/readiness was incomplete/);assert.equal(broken.el('save').disabled,true);
  assert.equal(broken.el('ticket').options.length,0);
});

test('setup checklist renders text safely and failed refresh removes stale readiness',async t=>{
  let fail=false;const ui=await fixture(()=>fail?new Response('Unavailable',{status:503}):{...initial,readiness:{...readiness,actions:[{id:'owner',label:'Choose <img src=x> owner',href:'#vs-resource-owner'}]}});t.after(()=>ui.w.close());
  assert.equal(ui.el('next-actions').querySelector('img'),null);assert.match(ui.el('next-actions').textContent,/<img src=x>/);
  fail=true;ui.el('refresh').click();await ui.settle();
  assert.equal(ui.el('next-actions').children.length,0);assert.equal(ui.el('readiness-summary').textContent,'Setup has not been confirmed.');
  assert.equal(ui.el('deployment').textContent,'Deployment status has not been confirmed.');
});

test('turning vendor onboarding off needs its own consent and a confirmation, and keeps the saved setup',async t=>{
  const ui=await fixture((url,options)=>String(url).endsWith('/disable')?{...initial,modules_enabled:false}:initial);t.after(()=>ui.w.close());
  assert.equal(ui.el('off').hidden,false);assert.equal(ui.el('disable').disabled,true);
  ui.el('off-confirm').checked=true;ui.el('off-confirm').dispatchEvent(new ui.w.Event('change'));assert.equal(ui.el('disable').disabled,false);
  let asked='';ui.w.mvConfirm=async message=>{asked=message;return false;};ui.el('disable').click();await ui.settle();
  assert.match(asked,/Nothing is deleted/);assert.equal(ui.calls.some(c=>String(c.url).endsWith('/disable')),false);
  ui.w.mvConfirm=async()=>true;ui.el('disable').click();await ui.settle();
  const call=ui.calls.find(c=>String(c.url).endsWith('/disable'));const body=JSON.parse(call.options.body);
  assert.equal(body.confirm,true);assert.equal(body.context,initial.context);assert.equal(body.configuration,initial.configuration);
  assert.equal(ui.el('off').hidden,true);assert.equal(ui.el('enable').disabled,true);assert.equal(ui.el('off-confirm').checked,false);
});
