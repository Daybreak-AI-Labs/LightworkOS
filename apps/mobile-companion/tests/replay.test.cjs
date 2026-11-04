const {test} = require('node:test');
const assert = require('node:assert/strict');
const {React,act,create,source,deferred,text} = require('./helpers.cjs');
const sharedReplay = require('../../client-contract-tests/contracts/goal-events-v1.json');
const settings={baseUrl:'http://127.0.0.1:8765',token:'fixture',cacheScope:'11111111-1111-4111-8111-111111111111'};
function timers() {
  let seq=0;
  const timeouts=new Map(),intervals=new Map();
  return {timeouts,intervals,
    setTimeout(fn,ms){timeouts.set(++seq,{fn,ms});return seq;}, clearTimeout(id){timeouts.delete(id);},
    setInterval(fn){intervals.set(++seq,fn);return seq;},clearInterval(id){intervals.delete(id);},
    fire(ms){for(const [id,timer] of [...timeouts]) if(timer.ms===ms){timeouts.delete(id);timer.fn();}}};
}
const page=(since,total=401)=>({status:'done',result:'FINAL',next_id:Math.min(total,since+200),
  has_more:since+200<total,terminal:since+200>=total,
  events:Array.from({length:Math.min(200,total-since)},(_,i)=>({id:since+i+1,agent:'agent',kind:'output',content:'event-'+(since+i+1),ts:1}))});

test('mobile replay consumes the shared dashboard page fixture',async()=>{
  const calls=[];
  const replay=source('src/runReplay.ts',{'./api':{ApiError:Error,getGoalEvents:async(_cfg,_id,since)=>{
    calls.push(since);return sharedReplay.pages[calls.length-1];
  }}});
  const result=await replay.createRunReplay(settings,7).poll(new AbortController().signal);
  assert.deepEqual(calls,[0,2]);
  assert.equal(result.next_id,3);assert.equal(result.terminal,true);
  assert.deepEqual(Array.from(result.events,event=>event.id),[1,2,3]);
});

test('API owns its timeout and external cancellation, without retrying',async()=>{
  for(const mode of ['timeout','cancel']) {
    const clock=timers(); let sent,calls=0;
    const api=source('src/api.ts',{...clock,fetch:async(_url,options)=>{calls++;sent=options.signal;return new Promise(()=>{});}});
    const parent=new AbortController();
    const pending=api.listGoals(settings,50,parent.signal);
    if(mode==='timeout') clock.fire(15000); else parent.abort();
    await assert.rejects(pending);
    assert.equal(sent.aborted,true); assert.equal(calls,1); assert.equal(clock.timeouts.size,0);
  }
});

test('API preserves access-denial status and refuses redirect following',async()=>{
  let options;
  const api=source('src/api.ts',{fetch:async(_url,value)=>{options=value;return {ok:false,status:403};}});
  await assert.rejects(api.listGoals(settings),error=>api.isAccessDenied(error)&&error.status===403);
  assert.equal(options.redirect,'error');
});

test('API bounds declared and streamed bodies before JSON parsing and closes the reader',async()=>{
  let textReads=0;
  const declared=source('src/api.ts',{fetch:async()=>({ok:true,headers:{get:()=>String(5*1024*1024)},
    text:async()=>{textReads++;return '{}';}})});
  await assert.rejects(declared.listGoals(settings),error=>error.kind==='protocol');
  assert.equal(textReads,0);
  let cancelled=0,released=0;
  const streamed=source('src/api.ts',{fetch:async()=>({ok:true,body:{getReader:()=>({
    read:async()=>({done:false,value:new Uint8Array(4*1024*1024+1)}),
    cancel:async()=>{cancelled++;},releaseLock(){released++;}})}})});
  await assert.rejects(streamed.listGoals(settings),error=>error.kind==='protocol');
  assert.equal(cancelled,1);assert.equal(released,1);
});

test('unsupported native Fetch refuses before a request and never consumes unbounded text',async()=>{
  let calls=0,textReads=0;
  const unsupported=source('src/api.ts',{Response:class {},fetch:async()=>{calls++;throw new Error('must not fetch');}});
  await assert.rejects(unsupported.listGoals(settings),error=>error.kind==='unsupported');
  assert.equal(calls,0);
  const mismatched=source('src/api.ts',{fetch:async()=>({ok:true,text:async()=>{textReads++;return '[]';}})});
  await assert.rejects(mismatched.listGoals(settings),error=>error.kind==='unsupported');
  assert.equal(textReads,0);
});

test('API cancellation owns a pending body reader as well as the fetch signal',async()=>{
  const body=deferred(),reading=deferred();let cancelled=0,released=0;
  const api=source('src/api.ts',{fetch:async()=>({ok:true,body:{getReader:()=>({read:()=>{reading.resolve();return body.promise;},
    cancel:async()=>{cancelled++;body.resolve({done:true});},releaseLock(){released++;}})}})});
  const parent=new AbortController();const request=api.listGoals(settings,50,parent.signal);
  await reading.promise;parent.abort();
  await assert.rejects(request);await Promise.resolve();
  assert.equal(cancelled,1);assert.equal(released,1);
});

test('mobile replay drains 401 events once and keeps the cursor on reconnect/navigation',async()=>{
  const calls=[];
  const replay=source('src/runReplay.ts',{'./api':{ApiError:Error,getGoalEvents:async(cfg,id,since)=>{
    calls.push({cfg,id,since});return page(since);
  }}});
  const instance=replay.runReplay(settings,7),signal=new AbortController().signal;
  const result=await instance.poll(signal);
  assert.deepEqual(calls.map(c=>c.since),[0,200,400]);
  assert.equal(result.events.length,401);assert.equal(result.terminal,true);assert.equal(result.result,'FINAL');
  assert.equal(replay.runReplay(settings,7),instance);
  await instance.poll(signal);
  assert.equal(calls.at(-1).since,401);
  await replay.runReplay({...settings,token:'replacement'},7).poll(signal);
  assert.equal(calls.at(-3).since,0);
});

test('a late aborted mobile replay cannot replace newer events',async()=>{
  const old=deferred();let calls=0;
  const replay=source('src/runReplay.ts',{'./api':{ApiError:Error,getGoalEvents:async(_cfg,_id,since)=>{
    if(++calls===1) return old.promise;
    return page(since,1);
  }}}).createRunReplay(settings,7);
  const first=new AbortController(),second=new AbortController();
  const pending=replay.poll(first.signal);first.abort();
  assert.equal((await replay.poll(second.signal)).events.length,1);
  old.resolve({...page(0,1),result:'OLD'});
  await assert.rejects(pending,/Obsolete/);
  const current=await replay.poll(second.signal);
  assert.equal(current.result,'FINAL');assert.equal(current.events.length,1);
});

test('mobile replay bounds display without skipping server cursors and refuses stuck pages',async()=>{
  const replay=source('src/runReplay.ts',{'./api':{ApiError:Error,getGoalEvents:async(_cfg,_id,since)=>page(since,1200)}})
    .createRunReplay(settings,1);
  const result=await replay.poll(new AbortController().signal);
  assert.equal(result.next_id,1200);assert.equal(result.events.length,1000);assert.equal(result.truncated,true);
  const broken=source('src/runReplay.ts',{'./api':{ApiError:Error,getGoalEvents:async()=>({events:[],next_id:0,has_more:true,terminal:false})}})
    .createRunReplay(settings,1);
  await assert.rejects(broken.poll(new AbortController().signal),/could not read/);
});

function hook(clock,continuePolling) {
  const {usePolling}=source('src/poll.ts',clock);
  function Probe({fetcher}){return React.createElement('snapshot',usePolling(fetcher,1000,continuePolling));}
  return Probe;
}
const snapshot=app=>app.root.findByType('snapshot').props;
test('poller aborts superseded and unmounted requests and clears owned deadlines',async()=>{
  const clock=timers(),signals=[],pending=deferred(),Probe=hook(clock);
  let app;
  await act(async()=>{app=create(React.createElement(Probe,{fetcher:signal=>{signals.push(signal);return pending.promise;}}));});
  await act(async()=>{snapshot(app).refresh();});
  assert.equal(signals[0].aborted,true);assert.equal(signals[1].aborted,false);
  await act(async()=>{app.unmount();});
  assert.equal(signals[1].aborted,true);assert.equal(clock.timeouts.size,0);assert.equal(clock.intervals.size,0);
  pending.resolve('late');
});

for(const mode of ['access','unsupported']) test(`poller ${mode} clears retained data and stops automatic retry`,async()=>{
  const clock=timers(),Probe=hook(clock);let calls=0,app;
  const fetcher=async()=>{if(++calls===1)return 'PRIVATE';throw Object.assign(new Error(mode),{status:mode==='access'?403:undefined,kind:mode});};
  await act(async()=>{app=create(React.createElement(Probe,{fetcher}));});
  assert.equal(snapshot(app).data,'PRIVATE');
  await act(async()=>{snapshot(app).refresh();});
  assert.equal(snapshot(app).data,null);assert.equal(snapshot(app).accessDenied,mode==='access');
  assert.equal(snapshot(app).unsupported,mode==='unsupported');
  await act(async()=>{for(const tick of clock.intervals.values()){tick();tick();}});
  assert.equal(calls,2);
  await act(async()=>{app.unmount();});
});

test('poller stops terminal replay only after the supplied backlog contract says complete',async()=>{
  const clock=timers(),Probe=hook(clock,data=>!data.terminal);let calls=0,app;
  const fetcher=async()=>({terminal:++calls===2});
  await act(async()=>{app=create(React.createElement(Probe,{fetcher}));});
  await act(async()=>{for(const tick of clock.intervals.values())tick();});
  await act(async()=>{for(const tick of clock.intervals.values())tick();});
  assert.equal(calls,2);
  await act(async()=>{app.unmount();});
});

for(const screen of ['RunsListScreen','GlanceScreen']) for(const mode of ['access','unsupported']) test(`${screen} never labels ${mode} as cached offline success`,async()=>{
  const allowed=[];
  const component=source(`src/screens/${screen}.tsx`,{
    '../poll':{usePolling:()=>({data:null,error:mode==='access'?'HTTP 403':'Unsupported mobile transport: update the app build',accessDenied:mode==='access',unsupported:mode==='unsupported'})},
    '../offlineCache':{useCachedBundle:(_settings,enabled)=>{allowed.push(enabled);return null;},saveBundle:async()=>{},offlineBanner:()=> 'offline'},
  })[screen];
  let app;
  await act(async()=>{app=create(React.createElement(component,{settings,onOpenRun:()=>{}}));});
  assert.ok(allowed.every(value=>!value));
  assert.match(text(app),mode==='access'?/Access problem/:/Update needed/);assert.doesNotMatch(text(app),/offline/);
  app.unmount();
});
