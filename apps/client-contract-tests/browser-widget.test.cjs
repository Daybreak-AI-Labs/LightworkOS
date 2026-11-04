const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {webcrypto} = require('node:crypto');
const {JSDOM} = require('jsdom');
const root = path.resolve(__dirname, '../..');
const read = name => fs.readFileSync(path.join(root, name), 'utf8');
const flush = async () => { for(let i=0;i<25;i++) await new Promise(setImmediate); };
async function waitFor(condition, description) {
  const deadline = Date.now() + 10000;
  while (!condition()) {
    assert.ok(Date.now() < deadline, 'Timed out waiting for ' + description);
    await new Promise(setImmediate);
  }
}
const hasTimer = (timers, ms) => [...timers.timers.values()].some(timer => timer.ms === ms);
const deferred = () => { let resolve; const promise = new Promise(r => {resolve=r;}); return {promise,resolve}; };
function clock() {
  let seq=0;
  const timers = new Map(), history = [];
  return {timers, history, setTimeout(fn, ms) {history.push(ms); timers.set(++seq,{fn,ms}); return seq;},
    clearTimeout(id) {timers.delete(id);},
    fire(ms) {for(const [id,timer] of [...timers]) if(timer.ms===ms) {timers.delete(id);timer.fn();}}};
}
function storage(initial={}) {
  const values = {...initial};
  return {values, async get(key) {return typeof key==='string' ? {[key]:values[key]} : {...key,...values};},
    async set(value) {Object.assign(values,structuredClone(value));}};
}
function worker(fetch, initial={}) {
  const local=storage({base:'http://127.0.0.1:8765',token:'fixture-token',...initial}), session=storage();
  const timers=clock(); let listener;
  const chrome={storage:{local,session},runtime:{onMessage:{addListener(fn) {listener=fn;}}}};
  vm.runInNewContext(read('extensions/browser/background.js'),{chrome,fetch,crypto:webcrypto,TextEncoder,TextDecoder,
    AbortController,setTimeout:timers.setTimeout,clearTimeout:timers.clearTimeout,console});
  return {local,session,timers,call(msg) {return new Promise(resolve=>listener(msg,{},resolve));}};
}
const response = (data,status=200) => ({ok:status>=200&&status<300,status,text:async()=>JSON.stringify(data)});

test('worker fences duplicate writes and persists a confirmed id even if popup closes',async()=>{
  const pending=deferred(); let calls=0;
  const fixture=worker(async()=>{calls++;return pending.promise;});
  const identity=await fixture.call({type:'identity'});
  const first=fixture.call({type:'chat',scope:identity.scope,title:'goal',description:'brief'});
  await waitFor(() => calls === 1, 'the first goal request');
  const duplicate=await fixture.call({type:'chat',scope:identity.scope,title:'goal',description:'brief'});
  assert.equal(duplicate.kind,'pending'); assert.equal(calls,1);
  pending.resolve(response({id:42,status:'pending'}));
  assert.equal((await first).goal.id,42);
  assert.equal(fixture.session.values.activeWatch.goalId,42);
  assert.equal(fixture.local.values['pendingGoal:'+identity.scope],null);
});

test('worker timeout aborts transport, records unknown and never automatically retries a write',async()=>{
  let signal,calls=0;
  const fixture=worker(async(_url,options)=>{signal=options.signal;calls++;return new Promise(()=>{});});
  const first=fixture.call({type:'chat',title:'goal',description:'brief'});
  await waitFor(() => calls === 1 && hasTimer(fixture.timers, 15000), 'the timed goal request');
  fixture.timers.fire(15000);
  assert.equal((await first).kind,'unknown'); assert.equal(signal.aborted,true);
  const identity=await fixture.call({type:'identity'});
  assert.equal(fixture.local.values['pendingGoal:'+identity.scope].state,'unknown');
  assert.equal((await fixture.call({type:'chat',title:'goal'})).kind,'unknown');
  assert.equal(calls,1); assert.equal(fixture.timers.timers.size,0);
});

test('worker refuses wrong identity, off-loopback base and redirect following',async()=>{
  const calls=[];
  const fixture=worker(async(...args)=>{calls.push(args);return response({events:[],next_id:0,has_more:false,terminal:false});});
  const identity=await fixture.call({type:'identity'});
  fixture.local.values.token='replacement';
  assert.equal((await fixture.call({type:'events',scope:identity.scope,goalId:1,since:0})).kind,'context');
  assert.equal(calls.length,0);
  await fixture.call({type:'events',goalId:1,since:0});
  assert.equal(calls[0][1].redirect,'error');
  fixture.local.values.base='https://remote.invalid';
  assert.equal((await fixture.call({type:'events',goalId:1,since:0})).kind,'configuration');
  assert.equal(calls.length,1);
});

test('worker missing start id is unknown while definitive access refusal is not success',async()=>{
  for(const [body,status,kind] of [[{},200,'unknown'],[{},401,'access'],[{},403,'access'],[{},503,'unknown']]) {
    const fixture=worker(async()=>response(body,status));
    const result=await fixture.call({type:'chat',title:'goal'});
    assert.equal(result.ok,false); assert.equal(result.kind,kind);
  }
});

async function popup(handler, saved, tabs) {
  const dom=new JSDOM(read('extensions/browser/popup.html'),{url:'https://extension.test',runScripts:'outside-only'});
  await new Promise(resolve=>dom.window.document.addEventListener('DOMContentLoaded',resolve,{once:true}));
  const timers=clock(), local=storage({base:'http://127.0.0.1:8765',token:'fixture'}),session=storage({activeWatch:saved});
  const messages=[];
  const chrome={storage:{local,session},runtime:{lastError:null,sendMessage(msg,callback){
    messages.push(structuredClone(msg)); Promise.resolve(handler(msg)).then(callback);
  }},tabs:tabs||{query:async()=>[],sendMessage(){}}};
  Object.assign(dom.window,{chrome,setTimeout:timers.setTimeout,clearTimeout:timers.clearTimeout});
  dom.window.eval(read('extensions/browser/client-protocol.js'));
  dom.window.eval(read('extensions/browser/popup.js'));
  dom.window.document.dispatchEvent(new dom.window.Event('DOMContentLoaded'));
  await flush();
  return {dom,timers,messages,local,session,doc:dom.window.document,close(){dom.window.dispatchEvent(new dom.window.Event('pagehide'));dom.window.close();}};
}
const watch = {scope:'scope1',goalId:1,cursor:0,events:[],complete:false,status:'active',result:''};
const identity = {ok:true,scope:'scope1',pending:null};

test('popup drains all 401 terminal events using server cursor and displays one terminal result',async()=>{
  const fixture=await popup(msg=>{
    if(msg.type==='identity') return identity;
    const end=Math.min(401,msg.since+200);
    return {ok:true,scope:'scope1',data:{status:'done',result:'FINAL',next_id:end,has_more:end<401,terminal:end===401,
      events:Array.from({length:end-msg.since},(_,i)=>({id:msg.since+i+1,agent:'agent',content:'event-'+(msg.since+i+1)}))}};
  },watch);
  fixture.timers.fire(0); await flush();
  assert.deepEqual(fixture.messages.filter(m=>m.type==='events').map(m=>m.since),[0,200,400]);
  assert.equal(fixture.session.values.activeWatch.cursor,401);
  assert.equal(fixture.doc.querySelectorAll('.evt').length,402);
  assert.equal(fixture.doc.querySelector('#log').textContent.split('FINAL').length,2);
  assert.equal(fixture.timers.timers.size,0);
  fixture.close();
});

test('popup access denial clears cached content and stops polling even for restored terminal history',async()=>{
  const fixture=await popup(msg=>msg.type==='identity'?identity:{ok:false,kind:'access',status:403,error:'Denied'},
    {...watch,complete:true,events:[{id:1,agent:'private',content:'OLD PRIVATE'}],cursor:1});
  fixture.timers.fire(0); await flush();
  assert.equal(fixture.doc.querySelector('#log').textContent,'');
  assert.equal(fixture.session.values.activeWatch,null);
  assert.equal(fixture.timers.timers.size,0);
  fixture.close();
});

test('popup submission guard preserves draft when no start acknowledgement arrives',async()=>{
  const pending=deferred();
  const fixture=await popup(msg=>msg.type==='identity'?identity:pending.promise,null);
  const input=fixture.doc.querySelector('#prompt'); input.value='my full draft';
  fixture.doc.querySelector('#send').click(); fixture.doc.querySelector('#send').click();
  await waitFor(() => fixture.messages.filter(m=>m.type==='chat').length === 1 && hasTimer(fixture.timers, 17000), 'the popup request and its deadline');
  fixture.timers.fire(17000); await flush();
  assert.equal(input.value,'my full draft');
  assert.equal(fixture.doc.querySelector('#send').disabled,true);
  assert.match(fixture.doc.querySelector('#status').textContent,/not confirmed/);
  pending.resolve({ok:true,scope:'scope1',goal:{id:4,status:'pending'}}); await flush();
  assert.equal(fixture.session.values.activeWatch,null);
  fixture.close();
});

test('popup waits for both worker requests of a page send before calling the start unconfirmed',async()=>{
  const policy={revision:'r1',form_values:false,page_structure:false,model:'fixture-model'};
  // The worker checks the sharing policy and then starts the goal; each request has its own deadline.
  let calls=0; const pending=deferred();
  const fixture=worker(async()=>{calls++; return calls===1 ? response(policy) : pending.promise;});
  const chat=fixture.call({type:'chat',title:'goal',description:'brief',capturePolicy:{revision:'r1',form_values:false,page_structure:false}});
  await waitFor(() => calls === 2 && hasTimer(fixture.timers, 15000), 'the goal request after policy checking');
  const workerWorstCase=fixture.timers.history.filter(ms=>ms===15000).length*15000;
  assert.equal(workerWorstCase,30000);
  fixture.timers.fire(15000); await chat;
  // The popup must wait at least that long for the same message.
  const tabs={query:async()=>[{id:7}],sendMessage(_id,_msg,callback){callback({title:'T',url:'https://page.example/',selection:'',structured:null});}};
  const answered=deferred();
  const popupFixture=await popup(msg=>msg.type==='identity'?identity:msg.type==='capturePolicy'?{ok:true,scope:'scope1',data:policy}:answered.promise,null,tabs);
  popupFixture.doc.querySelector('#send-page').click(); await flush();
  popupFixture.doc.querySelector('#page-confirm').click(); await flush();
  const chatMessage=popupFixture.messages.find(m=>m.type==='chat');
  assert.ok(chatMessage&&chatMessage.capturePolicy,'a page send carries its policy check');
  const popupWait=Math.max(...popupFixture.timers.history);
  assert.ok(popupWait>workerWorstCase,'popup gave up after '+popupWait+' ms but the worker may need '+workerWorstCase);
  // A slow dashboard (10 s per request) must not be reported as an unconfirmed start while it is still working.
  popupFixture.timers.fire(17000); await flush();
  assert.equal(popupFixture.doc.querySelector('#status').textContent,'starting…');
  answered.resolve({ok:true,scope:'scope1',goal:{id:5,status:'pending'}}); await flush();
  assert.equal(popupFixture.session.values.activeWatch.goalId,5);
  assert.doesNotMatch(popupFixture.doc.querySelector('#status').textContent,/not confirmed|unconfirmed/);
  assert.equal(popupFixture.doc.querySelector('#clear-pending').hidden,true);
  popupFixture.close();
});

test('popup disposal cancels the owned read and rejects its late content',async()=>{
  const pending=deferred();
  const fixture=await popup(msg=>msg.type==='identity'?identity:msg.type==='cancel'?{ok:true}:pending.promise,watch);
  fixture.timers.fire(0); await flush();
  fixture.dom.window.dispatchEvent(new fixture.dom.window.Event('pagehide'));
  assert.equal(fixture.messages.filter(m=>m.type==='cancel').length,1);
  pending.resolve({ok:true,scope:'scope1',data:{status:'done',result:'LATE',next_id:0,has_more:false,terminal:true,events:[]}});
  await flush(); assert.doesNotMatch(fixture.doc.querySelector('#log').textContent,/LATE/);
  fixture.close();
});

test('changing connection rejects an old start acknowledgement and keeps the new scope',async()=>{
  const pending=deferred();let current='scope1';
  const fixture=await popup(msg=>msg.type==='identity'?{ok:true,scope:current,pending:null}:
    msg.type==='chat'?pending.promise:{ok:true},null);
  fixture.doc.querySelector('#prompt').value='original draft';
  fixture.doc.querySelector('#send').click();await flush();
  current='scope2';fixture.doc.querySelector('#token').value='replacement';
  fixture.doc.querySelector('#save').click();await flush();
  pending.resolve({ok:true,scope:'scope1',goal:{id:991,status:'pending'}});await flush();
  assert.equal(fixture.session.values.activeWatch,null);
  assert.doesNotMatch(fixture.doc.querySelector('#status').textContent,/991/);
  assert.equal(fixture.doc.querySelector('#prompt').value,'original draft');fixture.close();
});

async function widget(fetch, retained, attributes) {
  const dom=new JSDOM('<!doctype html><body></body>',{url:'http://127.0.0.1:8765/page',runScripts:'outside-only'});
  const timers=clock();
  Object.assign(dom.window,{fetch,AbortController,TextDecoder,setTimeout:timers.setTimeout,clearTimeout:timers.clearTimeout});
  if(retained) dom.window.localStorage.setItem('lightwork.pending-chat.v1:http://127.0.0.1:8765',retained);
  if(attributes) { // the embedding <script> tag the widget reads its settings from
    const tag=dom.window.document.createElement('script');
    for(const [name,value] of Object.entries(attributes)) tag.setAttribute(name,value);
    Object.defineProperty(dom.window.document,'currentScript',{get:()=>tag});
  }
  dom.window.eval(read('extensions/chat-widget/maverick-chat-widget.js'));
  const form=dom.window.document.querySelector('form'), input=form.querySelector('input'),send=form.querySelector('button');
  function submit(){form.dispatchEvent(new dom.window.Event('submit',{cancelable:true}));}
  return {dom,timers,form,input,send,submit,check:[...dom.window.document.querySelectorAll('button')].find(b=>b.textContent==='Check start status'),close(){dom.window.dispatchEvent(new dom.window.Event('pagehide'));dom.window.close();}};
}

test('chat widget preserves a long instruction in details within the title contract',async()=>{
  let body;
  const fixture=await widget(async(_url,options)=>{body=options.body;return {ok:true,status:200,redirected:true,url:'http://127.0.0.1:8765/chat/goal/42'};});
  try {
    const instruction='🙂'.repeat(201);
    fixture.input.value=instruction;fixture.submit();await flush();
    assert.equal(Array.from(body.get('title')).length,200);
    assert.equal(body.get('description'),instruction);
    assert.match(fixture.dom.window.document.body.textContent,/Goal accepted/);
  }finally{fixture.close();}
});

test('direct validation refusal displays its correction and keeps the draft editable',async()=>{
  const fixture=await widget(async()=>({ok:false,status:422,redirected:false,json:async()=>({detail:'Shorten the details before starting the goal.'})}));
  try {
    fixture.input.value='draft';fixture.submit();await flush();
    assert.match(fixture.dom.window.document.body.textContent,/Shorten the details/);
    assert.equal(fixture.input.value,'draft');assert.equal(fixture.send.disabled,false);
    assert.equal(fixture.dom.window.localStorage.length,0);
  }finally{fixture.close();}
});

test('widget requires exact same-origin goal redirect, retaining drafts on login or alternate 200 pages',async()=>{
  for(const url of ['http://127.0.0.1:8765/login','http://other.invalid/chat/goal/42','http://127.0.0.1:8765/chat/goal/42/other']) {
    const fixture=await widget(async()=>({ok:true,status:200,redirected:true,url}));
    fixture.input.value='important draft'; fixture.submit(); await flush();
    assert.equal(fixture.input.value,'important draft'); assert.equal(fixture.send.disabled,true);
    assert.doesNotMatch(fixture.dom.window.document.body.textContent,/Goal accepted|Started\./);
    fixture.close();
  }
  const fixture=await widget(async()=>({ok:true,status:200,redirected:true,url:'http://127.0.0.1:8765/chat/goal/42'}));
  fixture.input.value='goal'; fixture.submit(); await flush();
  assert.match(fixture.dom.window.document.body.textContent,/Goal accepted/);
  assert.equal(fixture.input.value,''); assert.equal(fixture.send.disabled,false);
  fixture.close();
});

test('a cross-origin data-maverick-url is refused with its real reason before anything is stored or sent',async()=>{
  let calls=0;
  const fixture=await widget(async()=>{calls++;return new Promise(()=>{});},undefined,{'data-maverick-url':'https://dashboard.example'});
  fixture.input.value='goal';fixture.submit();await flush();
  const text=fixture.dom.window.document.body.textContent;
  assert.equal(calls,0);assert.equal(fixture.input.value,'goal');
  assert.equal(fixture.dom.window.localStorage.length,0);
  assert.match(text,/refused before sending/);assert.match(text,/own origin/);assert.match(text,/https:\/\/dashboard\.example/);
  assert.doesNotMatch(text,/request identity/);
  assert.equal(fixture.send.disabled,false);
  fixture.close();
});

test('widget never-submitted acknowledgement times out and duplicate submits remain fenced',async()=>{
  let calls=0,signal;
  const fixture=await widget(async(_url,options)=>{calls++;signal=options.signal;return new Promise(()=>{});});
  fixture.input.value='goal'; fixture.submit(); fixture.submit();
  await waitFor(() => calls === 1 && hasTimer(fixture.timers, 15000), 'the widget request and its deadline');
  assert.equal(calls,1); fixture.timers.fire(15000); await flush();
  assert.equal(signal.aborted,true); assert.equal(fixture.input.value,'goal');
  assert.equal(fixture.send.disabled,true); assert.equal(fixture.timers.timers.size,0);
  fixture.close();
});

test('browser replay projection visibly bounds old event history without losing cursor',()=>{
  const protocol=require('../../extensions/browser/client-protocol.js');
  let state={cursor:0,events:[]};
  for(let page=0;page<6;page++) state=protocol.page(state,{status:'done',has_more:page<5,terminal:page===5,
    next_id:(page+1)*200,events:Array.from({length:200},(_,index)=>({id:page*200+index+1,content:'x'}))});
  assert.equal(state.cursor,1200); assert.equal(state.events.length,1000); assert.equal(state.trimmed,true);
  assert.equal(state.complete,true);
  assert.throws(()=>protocol.page(state,{next_id:1200,events:[],has_more:true,terminal:false}));
});

test('extension recovers accepted lost response after worker restart by the same durable key, without POST replay',async()=>{
  const contract=require('./contracts/goal-submission-recovery-v1.json');
  const calls=[];
  const fixture=worker(async(url,options)=>{calls.push({url,options});return new Promise(()=>{});});
  const identity=await fixture.call({type:'identity'});
  const first=fixture.call({type:'chat',scope:identity.scope,title:contract.title,description:contract.description});
  await waitFor(() => calls.length === 1 && hasTimer(fixture.timers, 15000), 'the goal request and its deadline');
  fixture.timers.fire(15000); assert.equal((await first).kind,'unknown');
  assert.equal(calls.length,contract.write_count_after_interruption);
  const key=calls[0].options.headers['Idempotency-Key'];
  assert.equal(typeof key,'string');
  const restarted=worker(async(url,options)=>{calls.push({url,options});return response(contract.receipt);},fixture.local.values);
  const resolved=await restarted.call({type:'reconcile',scope:identity.scope});
  assert.equal(resolved.goal.id,contract.receipt.goal.id);
  assert.deepEqual(calls.map(c=>c.options.method),['POST','GET']);
  assert.equal(calls[1].options.headers['Idempotency-Key'],key);
  assert.equal(restarted.session.values.activeWatch.goalId,contract.receipt.goal.id);
  assert.equal(restarted.local.values['pendingGoal:'+identity.scope],null);
});

test('unavailable reconciliation remains held and changed credentials cannot query another request key',async()=>{
  const calls=[];
  const fixture=worker(async(url,options)=>{calls.push(options);return response({},503);});
  const identity=await fixture.call({type:'identity'});
  await fixture.call({type:'chat',scope:identity.scope,title:'goal'});
  assert.equal((await fixture.call({type:'reconcile',scope:identity.scope})).ok,false);
  assert.equal((await fixture.call({type:'clearPending',scope:identity.scope,reviewed:true})).ok,false);
  assert.ok(fixture.local.values['pendingGoal:'+identity.scope]);
  fixture.local.values.token='different-user';
  assert.equal((await fixture.call({type:'reconcile',scope:identity.scope})).kind,'context');
  assert.deepEqual(calls.map(c=>c.method),['POST','GET']);
});

test('widget retains submission key across reload and performs only a bounded receipt read',async()=>{
  let postedKey;
  const fixture=await widget(async(_url,options)=>{postedKey=options.body.get('submission_key');return new Promise(()=>{});});
  fixture.input.value='goal';fixture.submit();
  await waitFor(() => hasTimer(fixture.timers, 15000), 'the widget request deadline');
  fixture.timers.fire(15000);await flush();
  assert.equal(fixture.dom.window.localStorage.getItem('lightwork.pending-chat.v1:http://127.0.0.1:8765'),postedKey);
  fixture.close();
  const reads=[];
  const restarted=await widget(async(url,options)=>{reads.push({url,options});return new Response(JSON.stringify({state:'accepted',goal:{id:93,status:'pending'}}));},postedKey);
  assert.equal(restarted.send.disabled,true);
  restarted.check.click();await flush();
  assert.equal(reads.length,1);assert.equal(reads[0].options.method,'GET');
  assert.equal(reads[0].options.headers['Idempotency-Key'],postedKey);
  assert.match(restarted.dom.window.document.body.textContent,/Goal accepted/);
  assert.equal(restarted.send.disabled,false);
  assert.equal(restarted.dom.window.localStorage.getItem('lightwork.pending-chat.v1:http://127.0.0.1:8765'),null);
  restarted.close();
});

test('late POST response cannot replace a reconciled widget goal',async()=>{
  const late=deferred();
  const fixture=await widget(async(_url,options)=>options.method==='POST'?late.promise:
    new Response(JSON.stringify({state:'accepted',goal:{id:22,status:'pending'}})));
  fixture.input.value='goal';fixture.submit();
  await waitFor(() => hasTimer(fixture.timers, 15000), 'the widget request deadline');
  fixture.timers.fire(15000);await flush();
  fixture.check.click();await flush();
  late.resolve({ok:true,status:200,redirected:true,url:'http://127.0.0.1:8765/chat/goal/999'});await flush();
  const links=[...fixture.dom.window.document.querySelectorAll('a')].map(a=>a.href);
  assert.ok(links.some(v=>v.endsWith('/chat/goal/22')));
  assert.ok(!links.some(v=>v.endsWith('/chat/goal/999')));fixture.close();
});

test('widget denied, missing, oversized or unsupported receipt never clears the retained identity',async()=>{
  for(const result of [new Response('{}',{status:401}),new Response('{}',{status:404}),
    new Response('x'.repeat(17000)),{ok:true,status:200,body:null,text:()=>assert.fail('unbounded fallback')}]) {
    const fixture=await widget(async()=>result,'same-key');
    fixture.check.click();await flush();
    assert.equal(fixture.send.disabled,true);
    assert.equal(fixture.dom.window.localStorage.getItem('lightwork.pending-chat.v1:http://127.0.0.1:8765'),'same-key');
    assert.doesNotMatch(fixture.dom.window.document.body.textContent,/Goal accepted/);
    fixture.close();
  }
});

test('widget persistence failure prevents network dispatch',async()=>{
  let calls=0;
  const fixture=await widget(async()=>{calls++;return new Promise(()=>{});});
  fixture.dom.window.Storage.prototype.setItem=function(){throw new Error('storage unavailable');};
  fixture.input.value='goal';fixture.submit();await flush();
  assert.equal(calls,0);assert.equal(fixture.input.value,'goal');
  assert.match(fixture.dom.window.document.body.textContent,/refused before sending/);fixture.close();
});
