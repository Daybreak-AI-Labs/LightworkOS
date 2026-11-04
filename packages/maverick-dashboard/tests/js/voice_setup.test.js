'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),{JSDOM}=require('jsdom');
const {shell} = require('./_shell');
const folder=path.resolve(__dirname,'../../maverick_dashboard');
const markup=fs.readFileSync(path.join(folder,'templates/settings.html'),'utf8').replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,'');
const script=path.join(folder,'static/lightwork-voice-setup.js');
const context='a'.repeat(64),otherContext='b'.repeat(64);
const model={id:'base',sha256:'c'.repeat(64),size_bytes:147951465,source_url:'https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-base.bin'};
const base={context,enabled:true,model,configuration:{managed_path:false,auto_fetch:false,backend:'local'},model_state:'missing',engine_available:true,can_download:true,reason:null,job:null};
const job=(state='downloading',received=100)=>({id:'job-0123456789abcdef',state,received_bytes:received,total_bytes:model.size_bytes,error:null});
function response(value,status=200){return new Response(JSON.stringify(value),{status,headers:{'Content-Type':'application/json'}});}
async function fixture(intercept=()=>undefined,setup=()=>{}){
  const dom=new JSDOM(markup,{url:'https://lightwork.example/settings#settings-voice',runScripts:'outside-only'}),{window}=dom,calls=[],timers=[];
  window.setTimeout=fn=>{timers.push(fn);return timers.length;};window.clearTimeout=id=>{timers[id-1]=null;};
  window.fetch=async(url,options={})=>{const call={url,options};calls.push(call);const value=await intercept(call);return value instanceof Response?value:response(value===undefined?base:value);};
  shell(window);setup(window);if(fs.existsSync(script))window.eval(fs.readFileSync(script,'utf8'));
  async function settle(){for(let i=0;i<12;i++)await new Promise(done=>setImmediate(done));}
  const el=id=>window.document.getElementById('voice-setup-'+id);
  async function click(id){el(id).click();await settle();}
  function consent(){el('confirm').checked=true;el('confirm').dispatchEvent(new window.Event('change',{bubbles:true}));}
  async function poll(){const callback=timers.find(Boolean);assert.ok(callback,'active job schedules a status read');timers[timers.indexOf(callback)]=null;await callback();await settle();}
  await settle();return{window,calls,el,settle,click,consent,poll,timers};
}
test('setup only reads until explicit consent and binds one request to the exact disclosed model',async t=>{
  let release;const pending=new Promise(done=>{release=done;});
  const ui=await fixture(async call=>{if(call.options.method==='POST'){await pending;return{...base,job:job()};}});t.after(()=>ui.window.close());
  assert.match(ui.el('technical').textContent,/147,951,465/);assert.match(ui.el('technical').textContent,/huggingface.co/);
  assert.equal(ui.el('start').disabled,true);assert.equal(ui.calls.length,1);
  ui.el('start').dispatchEvent(new ui.window.Event('click'));await ui.settle();assert.equal(ui.calls.length,1);
  ui.consent();ui.el('start').click();await ui.settle();assert.equal(ui.el('start').disabled,true);
  ui.el('start').dispatchEvent(new ui.window.Event('click'));release();await ui.settle();
  const writes=ui.calls.filter(c=>c.options.method==='POST');assert.equal(writes.length,1);
  assert.equal(writes[0].url,'/api/v1/voice/setup/download');assert.equal(writes[0].options.headers['X-Lightwork-Voice-Context'],context);
  assert.deepEqual(JSON.parse(writes[0].options.body),{confirm:true,model:model.id,sha256:model.sha256,size_bytes:model.size_bytes});
  assert.equal(ui.el('confirm').checked,false);assert.equal(ui.el('progress').hidden,false);assert.equal(ui.el('cancel').disabled,false);
});
test('reload reads an existing job and cancellation waits for server acknowledgement',async t=>{
  let current={...base,job:job()};const ui=await fixture(call=>{if(call.url.endsWith('/cancel'))current={...base,job:job('cancelling')};return current;});t.after(()=>ui.window.close());
  assert.match(ui.el('status').textContent,/Downloading/);assert.equal(ui.calls.length,1);assert.equal(ui.el('start').disabled,true);
  await ui.click('cancel');const cancel=ui.calls.find(c=>c.url.endsWith('/cancel'));assert.deepEqual(JSON.parse(cancel.options.body),{job_id:job().id});
  assert.match(ui.el('status').textContent,/Cancelling/);assert.equal(ui.el('cancel').disabled,true);
  current={...base,job:job('cancelled')};await ui.poll();assert.match(ui.el('status').textContent,/cancelled/);assert.equal(ui.el('start').disabled,true);
  ui.consent();assert.equal(ui.el('start').disabled,false);
});
test('complete bytes do not claim verification or speech readiness before the worker finishes',async t=>{
  let current={...base,engine_available:false,model_state:'present_unverified',job:job('checking',model.size_bytes)};
  const ui=await fixture(()=>current);t.after(()=>ui.window.close());assert.match(ui.el('status').textContent,/Checking/);assert.match(ui.el('readiness').textContent,/not available/);
  assert.doesNotMatch(ui.el('status').textContent,/ready to transcribe/i);
  current={...current,model_state:'verified',job:job('ready',model.size_bytes)};await ui.poll();
  assert.match(ui.el('status').textContent,/verified/);assert.match(ui.el('readiness').textContent,/not available/);
  assert.equal(ui.el('progress').hidden,true);
});
test('failed setup requires new consent; service failure requires refresh before retrying',async t=>{
  let broken=false,current={...base,job:{...job('failed'),error:'Synthetic connection interruption'}};
  const ui=await fixture(()=>broken?new Response('<h1>Unavailable</h1>',{status:503}):current);t.after(()=>ui.window.close());
  assert.match(ui.el('status').textContent,/Synthetic connection interruption/);ui.consent();broken=true;await ui.click('start');
  assert.equal(ui.el('confirm').checked,false);assert.equal(ui.el('start').disabled,true);assert.match(ui.el('status').textContent,/Refresh/);
  broken=false;current={...base,job:job()};await ui.click('refresh');assert.equal(ui.el('cancel').disabled,false);
  assert.equal(ui.calls.filter(c=>c.options.method==='POST').length,1,'refresh never resubmits a download');
});
for(const status of [401,403])test('HTML '+status+' clears private status before parsing and prevents further actions',async t=>{
  let expired=false;const ui=await fixture(()=>expired?new Response('<h1>Sign in</h1>',{status}):{...base,job:job()});t.after(()=>ui.window.close());
  ui.consent();expired=true;await ui.click('refresh');
  for(const name of ['model','model-details','technical','policy','readiness','progress-text'])assert.equal(ui.el(name).textContent,'');
  assert.equal(ui.el('confirm').checked,false);assert.equal(ui.el('progress').hidden,true);assert.match(ui.el('status').textContent,/reload/i);
  for(const name of ['start','cancel','refresh','confirm'])assert.equal(ui.el(name).disabled,true);
  const count=ui.calls.length;ui.el('start').dispatchEvent(new ui.window.Event('click'));ui.el('refresh').dispatchEvent(new ui.window.Event('click'));await ui.settle();assert.equal(ui.calls.length,count);
});
test('changed account or configuration invalidates reviewed consent until reload',async t=>{
  let changed=false;const ui=await fixture(()=>({...base,context:changed?otherContext:context}));t.after(()=>ui.window.close());ui.consent();changed=true;await ui.click('refresh');
  assert.equal(ui.el('start').disabled,true);assert.equal(ui.el('confirm').checked,false);assert.equal(ui.el('model-details').textContent,'');assert.match(ui.el('status').textContent,/changed.*reload/i);
});
test('fixed catalog and disabled deployment state cannot become arbitrary downloads',async t=>{
  for(const value of [{...base,model:{...model,source_url:'https://attacker.example/model'}},{...base,model:{...model,id:'../escape'}},{...base,model:{...model,size_bytes:-1}}]){
    const ui=await fixture(()=>value);try{assert.equal(ui.el('start').disabled,true);assert.match(ui.el('status').textContent,/verified|unavailable/i);}finally{ui.window.close();}
  }
  const ui=await fixture(()=>({...base,can_download:false,configuration:{...base.configuration,managed_path:true},reason:'This model is deployment managed.'}));t.after(()=>ui.window.close());
  assert.match(ui.el('status').textContent,/deployment managed/);assert.equal(ui.el('confirm').disabled,true);ui.consent();ui.el('start').dispatchEvent(new ui.window.Event('click'));await ui.settle();assert.equal(ui.calls.length,1);
});
test('a late polling result cannot replace the acknowledged cancellation state',async t=>{
  let release,gets=0;const pending=new Promise(done=>{release=done;});
  const ui=await fixture(async call=>{if(call.options.method==='GET'&&++gets>1){await pending;return{...base,job:job()};}return{...base,job:job(call.url.endsWith('/cancel')?'cancelling':'downloading')};});t.after(()=>ui.window.close());
  const callback=ui.timers.find(Boolean);callback();await ui.settle();await ui.click('cancel');assert.match(ui.el('status').textContent,/Cancelling/);
  assert.equal(ui.calls.filter(call=>call.options.method==='GET')[1].options.signal.aborted,true,'cancel does not wait for a blocked status poll');
  release();await ui.settle();assert.match(ui.el('status').textContent,/Cancelling/);assert.equal(ui.el('cancel').disabled,true);
});
test('leaving the page clears private setup state and requires fresh access when returning',async t=>{
  const ui=await fixture(()=>({...base,job:job()}));t.after(()=>ui.window.close());ui.window.dispatchEvent(new ui.window.Event('pagehide'));
  assert.equal(ui.el('model-details').textContent,'');assert.equal(ui.el('refresh').disabled,true);assert.equal(ui.el('cancel').disabled,true);assert.match(ui.el('status').textContent,/Reload/);
  assert.equal(ui.timers.filter(Boolean).length,0);
});
test('HTTP context conflict cannot trap the user in refreshes using an obsolete context',async t=>{
  let conflict=false;const ui=await fixture(()=>conflict?response({detail:'The workspace changed.'},409):base);t.after(()=>ui.window.close());
  ui.consent();conflict=true;await ui.click('refresh');assert.equal(ui.el('refresh').disabled,true);assert.equal(ui.el('technical').textContent,'');assert.match(ui.el('status').textContent,/reload/i);
});
test('later file changes invalidate readiness and a network-policy denial explains disabled setup',async t=>{
  let current={...base,model_state:'verified',job:job('ready',model.size_bytes)};const ui=await fixture(()=>current);t.after(()=>ui.window.close());
  assert.equal(ui.el('try').hidden,false);current={...current,model_state:'present_unverified'};await ui.click('refresh');
  assert.equal(ui.el('try').hidden,true);assert.match(ui.el('status').textContent,/changed or is missing/);assert.equal(ui.el('start').disabled,true);
  current={...current,job:{...job('failed'),error:'The previously verified model changed or was removed. Check it again before using local speech.'}};await ui.click('refresh');
  assert.match(ui.el('status').textContent,/changed or was removed/);ui.consent();assert.equal(ui.el('start').disabled,false,'invalidated verification can be explicitly checked without a restart');
  current={...base,can_download:false,reason:'Network policy blocks the model source.'};await ui.click('refresh');
  assert.match(ui.el('status').textContent,/Network policy blocks/);assert.equal(ui.el('confirm').disabled,true);
});

const installLocale=require('./helpers/recovery_review_i18n');
test('voice setup localizes progress and model copy but keeps backend errors and provenance opaque',async t=>{
  const fr=text=>({text,lang:'fr'}),catalog={
    'Standard multilingual model':fr('Modèle multilingue standard'),
    'Downloading model…':fr('Téléchargement du modèle.'),
    'Setup failed. {reason}':fr('Échec de la configuration. {reason}'),
    '{received} MB of {total} MB ({percent}). Lightwork checks the file before using it.':fr('{received} Mo sur {total} Mo ({percent}). Lightwork vérifie le fichier.'),
    '{model} · {bytes} bytes · {source} · SHA-256: {hash} · Configured speech backend: {backend}':fr('{model} · {bytes} octets · {source} · SHA-256 : {hash} · Moteur : {backend}'),
  };
  let current={...base,job:job('downloading',1500000)};
  const ui=await fixture(()=>current,w=>installLocale(w,{catalog}));t.after(()=>ui.window.close());
  assert.equal(ui.el('model').textContent,'Modèle multilingue standard');assert.equal(ui.el('model').lang,'fr');assert.equal(ui.el('status').textContent,'Téléchargement du modèle.');assert.match(ui.el('progress-text').textContent,/1,5 Mo/);
  const values=Array.from(ui.el('technical').querySelectorAll('bdi'),node=>node.textContent);assert.ok(values.includes(model.source_url));assert.ok(values.includes(model.sha256));assert.ok(values.includes('local'));assert.match(ui.el('technical').textContent,/147.951.465/);
  current={...base,job:{...job('failed'),error:'Standard multilingual model <img src=x> مرحبا'}};await ui.poll();
  assert.match(ui.el('status').textContent,/Échec/);assert.equal(ui.el('status').querySelector('bdi').textContent,current.job.error);assert.equal(ui.el('status').querySelector('bdi').lang,'und');assert.equal(ui.el('status').querySelector('img'),null);
  assert.equal(ui.calls.every(call=>call.options.method==='GET'),true);
});
