'use strict';
const test=require('node:test'), assert=require('node:assert/strict'), fs=require('node:fs'), path=require('node:path');
const {JSDOM}=require('jsdom');
const {shell} = require('./_shell');
const base=path.resolve(__dirname,'../../maverick_dashboard');
const html=fs.readFileSync(path.join(base,'templates/_task_saved_views.html'),'utf8').replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
const source=fs.readFileSync(path.join(base,'static/lightwork-task-views.js'),'utf8');
const tick=()=>new Promise(resolve=>setImmediate(resolve));
const response=(data,status=200)=>({ok:status>=200&&status<300,status,json:async()=>data});
function page(handler) {
  const dom=new JSDOM(html,{url:'https://local.test/goals',runScripts:'outside-only'}),w=dom.window,d=w.document,calls=[],timers=[];
  const state={context:'a'.repeat(64),revision:'0'.repeat(64),views:[],other_views:0};
  w.LightworkTaskFilters={current:()=>({q:'quarterly report',status:'failed'})};
  w.fetch=async(url,options={})=>{calls.push({url,options});return handler ? handler(url,options,state) : response(state);};
  w.setTimeout=callback=>{timers.push(callback);return timers.length;};w.clearTimeout=()=>{};
  shell(w);
  w.eval(source);
  return {dom,w,d,calls,state,expire(){timers.at(-1)();},prepare(label='Quarterly'){
    d.getElementById('task-view-name').value=label;
    d.getElementById('task-views-form').dispatchEvent(new w.Event('submit',{cancelable:true,bubbles:true}));
  }};
}

test('saving requires explicit review and duplicate confirms cannot repeat a pending write',async()=>{
  let release;const ui=page((url,options,state)=>options.method ? new Promise(resolve=>{release=resolve;}) : response(state));
  await tick();ui.prepare();assert.equal(ui.calls.length,1);
  assert.match(ui.d.getElementById('task-view-review-copy').textContent,/quarterly report/);
  const confirm=ui.d.getElementById('task-view-confirm');confirm.click();confirm.click();await tick();
  assert.equal(ui.calls.filter(row=>row.options.method).length,1);
  assert.equal(ui.d.getElementById('task-view-name').disabled,true);
  const sent=JSON.parse(ui.calls.at(-1).options.body);assert.equal(sent.expected_revision,'0'.repeat(64));assert.equal(sent.status,'failed');
  release(response({...ui.state,revision:'1'.repeat(64),saved:'Quarterly'}));await tick();await tick();
  assert.match(ui.d.getElementById('task-views-status').textContent,/available on your account/);
  assert.equal(ui.d.getElementById('task-view-name').disabled,false);ui.dom.window.close();
});

test('unknown save retains draft and read-only refresh never repeats a mutation',async()=>{
  const ui=page((url,options,state)=>{if(options.method){state.revision='1'.repeat(64);state.views=[{name:'Quarterly',params:{q:'quarterly report',status:'failed'},status_label:'Failed'}];return new Promise(()=>{});}return response(state);});
  await tick();ui.prepare();ui.d.getElementById('task-view-confirm').click();await tick();ui.expire();await tick();
  assert.equal(ui.d.getElementById('task-view-name').value,'Quarterly');assert.match(ui.d.getElementById('task-views-status').textContent,/timed out/);
  ui.d.getElementById('task-views-refresh').click();await tick();await tick();
  assert.equal(ui.calls.filter(row=>row.options.method).length,1);
  assert.match(ui.d.getElementById('task-views-status').textContent,/does not identify who saved it/);ui.dom.window.close();
});

test('stale save preserves the local name and requires a fresh review',async()=>{
  const ui=page((url,options,state)=>options.method ? response({detail:'stale'},409) : response(state));
  await tick();ui.prepare('My unfinished name');ui.d.getElementById('task-view-confirm').click();await tick();await tick();
  assert.equal(ui.d.getElementById('task-view-name').value,'My unfinished name');
  assert.equal(ui.d.getElementById('task-view-review').hidden,true);assert.match(ui.d.getElementById('task-views-status').textContent,/changed/);ui.dom.window.close();
});

test('revoked authority clears saved-view content and locks stale controls',async()=>{
  const ui=page((url,options,state)=>options.method ? response({},403) : response(state));
  await tick();ui.prepare('Private text');ui.d.getElementById('task-view-confirm').click();await tick();await tick();
  assert.equal(ui.d.getElementById('task-view-name').value,'');assert.equal(ui.d.getElementById('task-view-name').disabled,true);
  assert.equal(ui.d.getElementById('task-views-list').textContent,'');ui.dom.window.close();
});

test('stored names render as text and destination is rebuilt from typed filters',async()=>{
  const ui=page((url,options,state)=>response({...state,views:[{name:'<img src=x onerror=alert(1)>',href:'https://outside.invalid',params:{q:'<private>',status:'done'},status_label:'Done'}]}));
  await tick();assert.equal(ui.d.querySelectorAll('img').length,0);
  const link=ui.d.querySelector('#task-views-list a');assert.equal(link.origin,'https://local.test');assert.equal(link.pathname,'/goals');assert.equal(new URL(link.href).searchParams.get('q'),'<private>');ui.dom.window.close();
});

test('task page restores typed URL filters and binds real filter selection to Copilot',async()=>{
  const template=fs.readFileSync(path.join(base,'templates/goals.html'),'utf8').replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
  const script=template.slice(template.indexOf('<script>')+8,template.indexOf('</script>'));
  const dom=new JSDOM('<input id="run-search-q"><div id="run-list"><div class="g-row" data-status="done"></div><div class="g-row" data-status="failed"></div></div><p id="run-search-status"></p><button id="run-search-retry"></button><button id="run-search-older" hidden></button><button id="run-more" data-next-offset="" hidden></button><button data-g-filter=""></button><button data-g-filter="failed"></button>',
    {url:'https://local.test/goals?status=failed',runScripts:'outside-only'});
  const w=dom.window,selections=[];w.document.addEventListener('lightwork:copilot-selection',event=>selections.push(event.detail.selection));w.eval(script);
  assert.equal(w.document.querySelector('[data-status="done"]').hidden,true);
  assert.equal(w.LightworkTaskFilters.current().status,'failed');assert.equal(selections.at(-1).filters.status,'failed');
  w.document.getElementById('run-search-q').dispatchEvent(new w.Event('input'));
  assert.equal(w.document.querySelector('[data-status="done"]').hidden,true);dom.window.close();
});

test('choosing a filter or typing a search updates the address without adding history',async()=>{
  const template=fs.readFileSync(path.join(base,'templates/goals.html'),'utf8').replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
  const script=template.slice(template.indexOf('<script>')+8,template.indexOf('</script>'));
  const dom=new JSDOM('<input id="run-search-q"><div id="run-list"><div class="g-row" data-status="done"></div><div class="g-row" data-status="failed"></div></div><p id="run-search-status"></p><button id="run-search-retry"></button><button id="run-search-older" hidden></button><button id="run-more" data-next-offset="" hidden></button><button data-g-filter=""></button><button data-g-filter="failed"></button><button data-g-filter="done"></button>',
    {url:'https://local.test/goals?status=done&view=mine#top',runScripts:'outside-only'});
  const w=dom.window,d=w.document;w.fetch=async()=>({ok:true,status:200,json:async()=>[]});w.eval(script);
  const before=w.history.length;
  d.querySelector('[data-g-filter="failed"]').click();
  assert.equal(w.location.search,'?status=failed&view=mine');assert.equal(w.location.hash,'#top');
  d.querySelector('[data-g-filter=""]').click();
  assert.equal(w.location.search,'?view=mine');
  d.getElementById('run-search-q').value='quarterly report';d.getElementById('run-search-q').dispatchEvent(new w.Event('input'));
  await new Promise(resolve=>setTimeout(resolve,450));
  assert.equal(new URL(w.location.href).searchParams.get('q'),'quarterly report');
  assert.equal(w.history.length,before);dom.window.close();
});
