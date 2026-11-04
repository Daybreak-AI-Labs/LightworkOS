'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {webcrypto}=require('node:crypto');
const {JSDOM}=require('jsdom');
const {shell} = require('./_shell');
const source=fs.readFileSync(path.resolve(__dirname,'../../maverick_dashboard/static/lightwork-draft-recovery.js'),'utf8');
const guided=fs.readFileSync(path.resolve(__dirname,'../../maverick_dashboard/static/lightwork-guided-actions.js'),'utf8');
const tick=()=>new Promise(resolve=>setImmediate(resolve));
async function fixture(options={}) {
  const dom=new JSDOM('<meta name="lightwork-draft-context" content="account-workspace"><form id="editor"><textarea id="brief"></textarea></form>',{url:'https://lightwork.test/editor',runScripts:'outside-only'});
  const w=dom.window,d=w.document,requests=[],writes=[];
  Object.defineProperty(w,'crypto',{value:webcrypto});w.TextEncoder=TextEncoder;
  let data={context:'account-workspace',revision:options.revision||0,payload:options.remote||null};
  let fail=options.fail||false,lastOperation=null;
  w.confirm=()=>true;
  w.fetch=async(url,config)=>{
    const request={url,...config};if(config.body)request.payload=JSON.parse(config.body);requests.push(request);
    if(options.fetchHook) await options.fetchHook(request);
    if(config.method==='PUT') {
      writes.push(request.payload);
      if(fail==='before')throw new Error('offline');
      if(JSON.stringify(request.payload)!==JSON.stringify(lastOperation)) {
        if(request.payload.expected_revision!==data.revision)return {ok:false,status:409,json:async()=>({detail:'A newer recovery copy exists.'})};
        data={...data,revision:data.revision+1,payload:request.payload.payload};lastOperation=request.payload;
      }
      if(fail==='after'){fail=false;throw new Error('response lost');}
    }
    return {ok:true,json:async()=>({...data,slot:url.split('/').pop()})};
  };
  const input=d.getElementById('brief');input.value=options.initial||'';
  let restores=0;
  w.eval(source);
  const recovery=w.mvDraftRecovery.create({key:'editor',host:d.getElementById('editor'),read:()=>({brief:input.value}),restore:payload=>{restores++;input.value=payload.brief;}});
  if(options.beforeReady) options.beforeReady({w,input,recovery});
  await recovery.ready;
  function button(label){return [...recovery.panel.querySelectorAll('button')].find(button=>button.textContent===label);}
  async function click(label){button(label).click();await tick();await tick();}
  function edit(value){input.value=value;input.dispatchEvent(new w.Event('input',{bubbles:true}));}
  return {dom,w,d,input,recovery,requests,writes,button,click,edit,get restores(){return restores;},get data(){return data;},set data(value){data={...data,...value};}};
}

test('restart offers a recovery copy but never changes the editor or submits on its own',async()=>{
  const ui=await fixture({remote:{brief:'unfinished'},revision:1,initial:'current'});
  assert.equal(ui.input.value,'current');assert.equal(ui.restores,0);assert.equal(ui.writes.length,0);
  await ui.click('Restore recovery copy');assert.equal(ui.input.value,'unfinished');assert.equal(ui.restores,1);assert.equal(ui.writes.length,0);ui.dom.window.close();
});

test('edits while a restore is awaiting confirmation are preserved',async()=>{
  const ui=await fixture({remote:{brief:'old'},revision:1});
  ui.w.mvConfirm=async()=>{ui.edit('new typing');return true;};
  await ui.click('Restore recovery copy');assert.equal(ui.input.value,'new typing');assert.equal(ui.restores,0);ui.dom.window.close();
});

test('a newer remote copy cannot be overwritten by Keep current or discarded without another review',async()=>{
  for(const action of ['Keep current draft','Discard recovery copy','Restore recovery copy']){
    const ui=await fixture({remote:{brief:'first'},revision:1,initial:'local'});
    ui.w.mvConfirm=async()=>{ui.data={revision:2,payload:{brief:'another tab'}};return true;};
    await ui.click(action);assert.equal(ui.writes.length,0);assert.equal(ui.restores,0);assert.equal(ui.data.payload.brief,'another tab');ui.dom.window.close();
  }
});

test('failed autosave keeps work and reuses the identical request on retry',async()=>{
  const ui=await fixture({fail:'before'});ui.edit('unfinished');await ui.recovery.save();
  assert.equal(ui.input.value,'unfinished');assert.equal(ui.button('Retry recovery').hidden,false);
  await ui.click('Retry recovery');assert.deepEqual(ui.writes[1],ui.writes[0]);assert.equal(ui.writes[0].expected_revision,0);ui.dom.window.close();
});

test('nested serialized credentials never reach recovery transport or its comparison preview',async()=>{
  const ui=await fixture({remote:{brief:'clean'},revision:1});
  ui.edit(JSON.stringify({nodes:[{params:{accessToken:'private-credential'}}]}));
  await ui.click('Keep current draft');assert.equal(ui.writes.length,0);assert.doesNotMatch(ui.recovery.panel.textContent,/private-credential/);ui.dom.window.close();
});

test('account or workspace mismatch rejects restore before editor mutation',async()=>{
  const ui=await fixture({remote:{brief:'private'},revision:1});ui.data={context:'different-account'};
  await ui.click('Restore recovery copy');assert.equal(ui.restores,0);assert.equal(ui.input.value,'');ui.dom.window.close();
});

test('edits made during initial recovery lookup are saved after that lookup',async()=>{
  const ui=await fixture({beforeReady:({w,input})=>{input.value='edited while loading';input.dispatchEvent(new w.Event('input',{bubbles:true}));}});
  await ui.recovery.save();assert.equal(ui.writes[0].payload.brief,'edited while loading');ui.dom.window.close();
});

test('a lost save response retries the exact operation before saving later edits',async()=>{
  const ui=await fixture({fail:'after'});ui.edit('first');await ui.recovery.save();assert.equal(ui.data.revision,1);
  ui.edit('later edits');await ui.click('Retry recovery');assert.deepEqual(ui.writes[1],ui.writes[0]);
  await ui.recovery.save();assert.equal(ui.data.revision,2);assert.equal(ui.data.payload.brief,'later edits');ui.dom.window.close();
});

test('storage retirement reviews current counts and sends the exact context/version without changing the editor',async()=>{
  const ui=await fixture({initial:'keep my work'}),calls=[];
  const summary={context:'account-workspace',version:'a'.repeat(64),capacity:2,saved:1,discarded:1,available:0};
  let confirmed='';ui.w.mvConfirm=async(message)=>{confirmed=message;return true;};
  ui.w.fetch=async(url,options)=>{calls.push({url,...options});return {ok:true,status:200,json:async()=>options.method==='POST'?{...summary,version:'b'.repeat(64),discarded:0,available:1,retired:1}:summary};};
  await ui.click('Refresh storage summary');
  assert.match(ui.recovery.panel.textContent,/1 saved recovery copies, 1 discarded copies/);
  assert.equal(calls.length,1);assert.equal(ui.button('Free discarded recovery space').disabled,false);
  await ui.click('Free discarded recovery space');
  assert.match(confirmed,/1 already discarded/);
  assert.equal(calls[1].url,'/api/v1/drafts/storage/retire');
  assert.equal(calls[1].headers['X-Lightwork-Draft-Context'],'account-workspace');
  assert.deepEqual(JSON.parse(calls[1].body),{expected_version:summary.version});
  assert.equal(ui.input.value,'keep my work');assert.equal(ui.writes.length,0);
  assert.equal(ui.button('Free discarded recovery space').disabled,true);
  ui.dom.window.close();
});

test('storage denial and stale confirmation invalidate retirement until a fresh summary is reviewed',async()=>{
  for(const status of [403,409]){
    const ui=await fixture(),calls=[];
    ui.w.fetch=async(url,options)=>{calls.push({url,...options});return options.method==='POST'?{ok:false,status,json:async()=>{if(status===403)throw new Error('HTML denial');return {detail:'Recovery storage changed.'};}}:{ok:true,status:200,json:async()=>({context:'account-workspace',version:'a'.repeat(64),capacity:1,saved:0,discarded:1,available:0})};};
    await ui.click('Refresh storage summary');await ui.click('Free discarded recovery space');
    assert.equal(ui.button('Free discarded recovery space').disabled,true);
    assert.match(ui.recovery.panel.textContent,status===403?/Your access changed/:/Recovery storage changed/);
    assert.doesNotMatch(ui.recovery.panel.textContent,/1 discarded copies/);
    assert.equal(calls.length,2);ui.dom.window.close();
  }
});

test('guided recovery keeps raw request references and separate resource drafts without submitting',async()=>{
  const dom=new JSDOM('<form id="resource"><select id="kind" name="kind"><option value="first" data-guided-endpoint="/first">First</option><option value="second" data-guided-endpoint="/second">Second</option></select><label>Details<textarea name="payload" data-guided-selector="kind">{"expected_revision":7,"idempotency_key":"exact-request"}</textarea></label><input type="password" name="password" value="not-stored"><button>Save</button></form>',{url:'https://lightwork.test/resource',runScripts:'outside-only'});
  const w=dom.window,d=w.document,adapters=[];let submits=0;
  d.querySelector('form').addEventListener('submit',()=>{submits++;});
  w.mvDraftRecovery={create:options=>{adapters.push(options);return {};}};
  w.fetch=async()=>({ok:true,json:async()=>({paths:{'/first':{post:{requestBody:{content:{'application/json':{schema:{type:'object'}}}}}},'/second':{post:{requestBody:{content:{'application/json':{schema:{type:'object'}}}}}}},components:{schemas:{}}})});
  shell(w);  // guided actions read their definitions through the shell's mvFetchJSON
  w.mvDraftRecovery={create:options=>{adapters.push(options);return {};}};
  w.eval(guided);await tick();
  const adapter=adapters[0],raw=d.querySelector('textarea[name=payload]'),select=d.getElementById('kind');
  select.value='second';select.dispatchEvent(new w.Event('change',{bubbles:true}));raw.value='{"expected_revision":2,"idempotency_key":"second-request"}';raw.dispatchEvent(new w.Event('change',{bubbles:true}));
  const saved=JSON.parse(JSON.stringify(adapter.read()));assert.equal(saved.fields.password,undefined);
  raw.value='{}';adapter.restore(saved);assert.equal(raw.value,'{"expected_revision":2,"idempotency_key":"second-request"}');
  select.value='first';select.dispatchEvent(new w.Event('change',{bubbles:true}));assert.equal(JSON.parse(raw.value).idempotency_key,'exact-request');assert.equal(submits,0);dom.window.close();
});

test('the comparison is a readable field-by-field view, not raw data',async()=>{
  const ui=await fixture({remote:{brief:'unfinished',format:1,variants:{a:1}},revision:1,initial:'current'});
  ui.d.getElementById('brief').setAttribute('aria-label','Task brief');
  ui.edit('current draft');await tick();
  const details=ui.recovery.panel.querySelector('details');
  Object.defineProperty(details,'open',{value:true});details.dispatchEvent(new ui.w.Event('toggle'));
  const text=details.textContent;
  assert.match(text,/1 field differs/);
  // One section per changed field, named by its label, with each side's own value
  // (kept whole and wrapped by the stylesheet) -- never the stored record.
  const fields=details.querySelectorAll('.draft-recovery__field');
  assert.equal(fields.length,1);
  assert.equal(fields[0].querySelector('h4').textContent,'Task brief');
  const values=[...fields[0].querySelectorAll('pre')].map(value=>[value.getAttribute('aria-label'),value.textContent]);
  assert.deepEqual(values,[['Recovery copy','unfinished'],['Current draft','current draft']]);
  assert.doesNotMatch(text,/[{}"]|variants|format/);
  ui.dom.window.close();
});

test('request failures show plain sentences, never server text or browser errors',async()=>{
  const ui=await fixture({fail:'before'});
  ui.edit('new work');await new Promise(resolve=>setTimeout(resolve,700));await tick();
  assert.match(ui.recovery.panel.textContent,/Lightwork is not responding/);
  assert.doesNotMatch(ui.recovery.panel.textContent,/offline/);
  ui.dom.window.close();
  const other=await fixture();
  other.w.fetch=async()=>({ok:false,status:500,json:async()=>({detail:'sqlite3.OperationalError: database is locked'})});
  other.w.mvErrorText=(failure,action)=>'Could not '+action+'. Something went wrong on our side.';
  other.edit('more work');await new Promise(resolve=>setTimeout(resolve,700));await tick();
  assert.match(other.recovery.panel.textContent,/Could not save the recovery copy\. Something went wrong on our side/);
  assert.doesNotMatch(other.recovery.panel.textContent,/sqlite|OperationalError/);
  other.dom.window.close();
});

// Chat's compact row said "Checking draft recovery…" for 18-109 ms on every
// load. A check that answers within 300 ms now never shows the loading words;
// a slow one still says so.
async function compactRow(delayMs,frameMs,inertMs){
  const dom=new JSDOM('<meta name="lightwork-draft-context" content="account-workspace"><form id="editor"><textarea id="brief"></textarea></form>',{url:'https://lightwork.test/chat',runScripts:'outside-only'});
  const w=dom.window,d=w.document;Object.defineProperty(w,'crypto',{value:webcrypto});w.TextEncoder=TextEncoder;
  const labels=[];
  w.fetch=async url=>{await new Promise(resolve=>setTimeout(resolve,delayMs));return {ok:true,json:async()=>({context:'account-workspace',revision:0,payload:null,slot:url.split('/').pop()})};};
  if(frameMs!==undefined)w.requestAnimationFrame=callback=>setTimeout(callback,frameMs);
  if(inertMs){d.getElementById('editor').setAttribute('inert','');setTimeout(()=>d.getElementById('editor').removeAttribute('inert'),inertMs);}
  w.eval(source);
  const recovery=w.mvDraftRecovery.create({key:'chat',compact:true,host:d.getElementById('editor'),read:()=>({brief:''}),restore:()=>{}});
  const summary=recovery.panel.querySelector('.draft-recovery__compact > summary');
  new w.MutationObserver(()=>labels.push(summary.textContent)).observe(summary,{childList:true,characterData:true,subtree:true});
  labels.push(summary.textContent);
  await recovery.ready;await tick();
  return {dom,labels,summary};
}
test('a quick recovery check never shows the loading words in the compact row',async()=>{
  const ui=await compactRow(20);
  assert.ok(!ui.labels.includes('Checking draft recovery…'),JSON.stringify(ui.labels));
  assert.equal(ui.summary.textContent,'Draft recovery ready');ui.dom.window.close();
});
test('a slow recovery check says it is checking, long enough to read',async()=>{
  const ui=await compactRow(450);
  assert.ok(ui.labels.includes('Checking draft recovery…'),JSON.stringify(ui.labels));
  // Shown at 300 ms and answered at 450 ms: the words stay 500 ms, not 150.
  assert.equal(ui.summary.textContent,'Checking draft recovery…');
  await new Promise(resolve=>setTimeout(resolve,500));
  assert.equal(ui.summary.textContent,'Draft recovery ready');ui.dom.window.close();
});

// A busy phone painted the words up to 200 ms after they were set, so they
// were on screen for 283 ms, not 500: the 500 ms count from the first frame.
test('the checking words stay 500 ms from the frame that shows them',async()=>{
  const started=Date.now();
  const ui=await compactRow(450,200);   // set at 300 ms, first frame at about 500 ms
  await new Promise(resolve=>setTimeout(resolve,Math.max(0,900-(Date.now()-started))));
  assert.equal(ui.summary.textContent,'Checking draft recovery…');
  await new Promise(resolve=>setTimeout(resolve,300));
  assert.equal(ui.summary.textContent,'Draft recovery ready');ui.dom.window.close();
});

// While the page is still inert (not yet usable) the words cannot be seen;
// the 500 ms start once it is usable.
test('the checking words stay 500 ms from when the page can show them',async()=>{
  const started=Date.now();
  const ui=await compactRow(450,20,600);   // set at 300 ms, page usable at 600 ms
  await new Promise(resolve=>setTimeout(resolve,Math.max(0,1000-(Date.now()-started))));
  assert.equal(ui.summary.textContent,'Checking draft recovery…');
  await new Promise(resolve=>setTimeout(resolve,250));
  assert.equal(ui.summary.textContent,'Draft recovery ready');ui.dom.window.close();
});

// A recovery problem opens Chat's compact row by itself, with no input from
// the person. Opening it in place grew the docked composer from 331 to 544 px
// and pushed the conversation up (layout shift 0.17-0.19 on phones), so the
// opened row floats above the composer instead of resizing the dock.
test('the compact row opens above the composer without resizing it',async()=>{
  const ui=await compactRow(20);
  const body=ui.summary.nextElementSibling;
  assert.equal(body.style.position,'absolute');
  assert.match(body.style.bottom,/100%/);
  assert.equal(ui.summary.parentElement.style.position,'relative');
  ui.dom.window.close();
});
