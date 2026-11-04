const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {EventEmitter} = require('node:events');
const ts = require('typescript');
const root = path.resolve(__dirname,'../..');
const sharedReplay = require('./contracts/goal-events-v1.json');
function source(file,context={}) {
  const compiled=ts.transpileModule(fs.readFileSync(path.join(root,file),'utf8'),{
    compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022,esModuleInterop:true}});
  const module={exports:{}};
  vm.runInNewContext(compiled.outputText,{module,exports:module.exports,require,URL,Buffer,console,setTimeout,clearTimeout,...context});
  return module.exports;
}
function fixture(cursor=0) {
  const timers=new Map(),connections=[],events=[],cursors=[],notices=[],stops=[];let seq=0;
  const clock={setTimeout(fn,ms){timers.set(++seq,{fn,ms});return seq;},clearTimeout(id){timers.delete(id);}};
  const {watchEvents}=source('apps/vscode-extension/src/eventWatch.ts',clock);
  const connect=(url,options,receive)=>{
    const request=new EventEmitter();request.destroyed=false;
    request.destroy=()=>{request.destroyed=true;};
    const response=new EventEmitter();response.statusCode=200;response.headers={'content-type':'text/event-stream'};
    response.destroyed=false;response.destroy=()=>{response.destroyed=true;};response.resume=()=>{};
    connections.push({url,options,request,response,receive});
    return request;
  };
  const stop=watchEvents({url:new URL('http://127.0.0.1:8765/api/v1/goals/42/events/stream'),headers:{Authorization:'Bearer fixture'},cursor,
    connect,onEvent:value=>events.push(value),onCursor:value=>cursors.push(value),onNotice:value=>notices.push(value),
    onStop:(reason,terminal)=>stops.push({reason,terminal})});
  const fire=ms=>{for(const [id,timer] of [...timers])if(timer.ms===ms){timers.delete(id);timer.fn();}};
  const send=value=>connections.at(-1).response.emit('data',Buffer.from(value));
  const open=()=>connections.at(-1).receive(connections.at(-1).response);
  return {stop,timers,connections,events,cursors,notices,stops,fire,send,open};
}
const event=id=>`id: ${id}\ndata: ${JSON.stringify({id,content:'event-'+id})}\n\n`;

test('SSE viewer accepts event and terminal fields from the shared dashboard fixture',()=>{
  const f=fixture();f.open();
  for(const page of sharedReplay.pages) for(const item of page.events)
    f.send(`id: ${item.id}\ndata: ${JSON.stringify(item)}\n\n`);
  const last=sharedReplay.pages.at(-1);
  f.send(`event: end\ndata: ${JSON.stringify({terminal:last.terminal,next_id:last.next_id,status:last.status})}\n\n`);
  assert.deepEqual(f.cursors,[1,2,3]);assert.equal(f.stops[0].terminal,true);
});

test('SSE viewer renders 401 events and ends exactly once after matching terminal acknowledgement',()=>{
  const f=fixture();f.open();
  for(let id=1;id<=401;id++)f.send(event(id));
  f.send('event: end\ndata: {"terminal":true,"next_id":401,"status":"done"}\n\n');
  f.connections[0].response.emit('end');f.connections[0].request.emit('error',new Error('late'));
  assert.equal(f.events.length,401);assert.equal(f.cursors.at(-1),401);
  assert.equal(f.stops.length,1);assert.equal(f.stops[0].terminal,true);assert.equal(f.timers.size,0);
});

test('disconnect and lifetime timeout reconnect from last rendered id without duplicate data',()=>{
  const f=fixture();f.open();f.send(event(17));
  f.connections[0].response.emit('end');f.connections[0].request.emit('error',new Error('same failure'));
  assert.equal(f.timers.size,1);f.fire(1000);
  assert.equal(f.connections.length,2);assert.equal(f.connections[1].url.searchParams.get('since'),'17');
  assert.equal(f.connections[1].options.headers['Last-Event-ID'],'17');
  f.open();f.send(event(17)+event(21));assert.equal(f.events.length,2);
  f.send('event: timeout\ndata: {}\n\n');f.fire(1000);
  assert.equal(f.connections.at(-1).url.searchParams.get('since'),'21');
  f.stop();assert.equal(f.timers.size,0);
});

test('connect and idle deadlines are owned while normal server heartbeats keep an idle stream alive',()=>{
  const f=fixture();f.fire(10000);
  assert.equal(f.connections[0].request.destroyed,true);f.fire(1000);f.open();
  const first=[...f.timers.keys()][0];f.send(': heartbeat\n\n');
  assert.equal(f.timers.has(first),false);assert.equal([...f.timers.values()][0].ms,45000);
  f.fire(45000);assert.equal(f.connections[1].response.destroyed,true);
  f.stop();assert.equal(f.timers.size,0);
});

for(const status of [401,403,404,302])test(`HTTP ${status} stops without reconnect`,()=>{
  const f=fixture();f.connections[0].response.statusCode=status;f.open();
  assert.equal(f.stops.length,1);assert.equal(f.timers.size,0);assert.equal(f.connections[0].request.destroyed,true);
});

test('SSE disposal closes socket and all timers; late events cannot append',()=>{
  const f=fixture();f.open();f.send(event(1));f.stop();
  f.send(event(2));f.connections[0].response.emit('end');
  assert.equal(f.events.length,1);assert.equal(f.timers.size,0);
  assert.equal(f.connections[0].response.destroyed,true);assert.equal(f.connections[0].request.destroyed,true);
});

test('SSE parser handles fragmented CRLF and UTF8 without losing cursor',()=>{
  const f=fixture();f.open();
  const bytes=Buffer.from('id: 7\r\ndata: {"content":"café"}\r\n\r\n');
  for(let i=0;i<bytes.length;i++)f.connections[0].response.emit('data',bytes.subarray(i,i+1));
  assert.equal(f.cursors.at(-1),7);assert.match(f.events[0],/café/);f.stop();
});

test('SSE oversized frame and unmatched terminal cursor fail explicitly',()=>{
  const first=fixture();first.open();first.send('x'.repeat(262145));
  assert.match(first.stops[0].reason,/bound/);assert.equal(first.timers.size,0);
  const second=fixture();second.open();second.send('event: end\ndata: {"terminal":true,"next_id":9}\n\n');
  assert.equal(second.stops[0].terminal,false);assert.match(second.stops[0].reason,/cursor/);
});

test('VS Code halt and clear require checked state, exact zero exit, and no signal',async()=>{
  for(const mode of ['missing','nonzero','signal','empty','wrong-state','halt','unhalt']) {
    const commands=new Map(),information=[],errors=[];
    const vscode={TreeItem:class{},EventEmitter:class{event=()=>{};fire(){};dispose(){};},
      workspace:{getConfiguration:()=>({get:(_key,fallback)=>fallback}),workspaceFolders:[],onDidChangeConfiguration:()=>({dispose(){}})},
      commands:{registerCommand(name,fn){commands.set(name,fn);return{dispose(){}};}},
      window:{registerTreeDataProvider:()=>({dispose(){}}),createOutputChannel:()=>({appendLine(){},show(){},dispose(){}}),
        showErrorMessage:async message=>{errors.push(message);},showInformationMessage:message=>information.push(message)}};
    const spawn=(_cli,args)=>{
      if(mode==='missing')throw new Error('not found');
      const child=new EventEmitter();child.stdout=new EventEmitter();child.stderr=new EventEmitter();child.kill=()=>{};
      queueMicrotask(()=>{
        assert.equal(args[1],'--json');
        if(mode!=='empty')child.stdout.emit('data',Buffer.from(JSON.stringify({command:args[0],acknowledged:true,
          scope:'local',work_stopped:false,halt_file_present:mode==='wrong-state'?false:args[0]==='halt'})));
        child.emit('close',mode==='nonzero'?1:mode==='signal'?null:0,mode==='signal'?'SIGTERM':null);
      });
      return child;
    };
    const extension=source('apps/vscode-extension/src/extension.ts',{require:name=>name==='vscode'?vscode:
      name==='./ownedCli'?source('apps/vscode-extension/src/ownedCli.ts',{require:name=>name==='child_process'?{spawn}:require(name)}):name==='./dashboardConnection'?{DashboardConnections:class{dispose(){}}}:name==='./eventWatch'?{watchEvents(){}}:require(name)});
    extension.activate({subscriptions:[]});await commands.get(mode==='unhalt'?'maverick.unhalt':'maverick.halt')();
    if(mode==='halt'||mode==='unhalt') {
      assert.equal(information.length,1);assert.equal(errors.length,0);
      assert.match(information[0],mode==='halt'?/checkpoint/:/not restart/);
    } else {assert.equal(information.length,0);assert.equal(errors.length,1);}
  }
});

test('synchronous connection rejection clears owned timer and reports one failure',()=>{
  const timers=new Set(),stops=[];
  const {watchEvents}=source('apps/vscode-extension/src/eventWatch.ts',{
    setTimeout(){const timer={};timers.add(timer);return timer;},clearTimeout(timer){timers.delete(timer);}});
  watchEvents({url:new URL('http://127.0.0.1'),headers:{},cursor:0,connect(){throw new Error('invalid transport');},
    onEvent(){},onCursor(){},onNotice(){},onStop:reason=>stops.push(reason)});
  assert.equal(timers.size,0);assert.equal(stops.length,1);
});

for(const address of ['http://dashboard.example','http://localhost.evil.example','http://192.168.1.5']) test(`remote token transport rejects ${address} before any request`,()=>{
  const {watchEvents}=source('apps/vscode-extension/src/eventWatch.ts'); let requests=0; const stops=[];
  watchEvents({url:new URL(address),headers:{authorization:'Bearer secret'},cursor:0,
    connect(){requests++;throw new Error('must not connect');},onEvent(){},onCursor(){},onNotice(){},onStop:reason=>stops.push(reason)});
  assert.equal(requests,0);assert.equal(stops.length,1);
});
for(const address of ['https://dashboard.example','http://127.0.0.1','http://localhost','http://[::1]']) test(`explicit safe token transport permits ${address}`,()=>{
  const {assertDashboardTransport}=source('apps/vscode-extension/src/eventWatch.ts');
  assert.doesNotThrow(()=>assertDashboardTransport(new URL(address),true));
});
