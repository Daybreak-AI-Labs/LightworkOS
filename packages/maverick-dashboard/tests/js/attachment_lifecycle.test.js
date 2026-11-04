'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {shell} = require('./_shell');
const {JSDOM} = require('jsdom');
const source = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/templates/chat_goal.html'), 'utf8');
const start = source.indexOf('// Attachments panel:');
const script = source.slice(start, source.indexOf('</script>', start)).replace('{{ goal.id }}', '4');
const settle = async () => {for(let i=0;i<15;i++) await new Promise(resolve=>setImmediate(resolve));};
function response(body,status=200){return {ok:status===200,status,redirected:false,json:async()=>body};}
function page(handler){
  const dom = new JSDOM('<details id="attachments-panel"><span id="attachments-count"></span><ul id="attachments-list"></ul><button id="attach-add-btn">Add</button><input type="file" id="attach-add" multiple><p id="attach-msg"></p></details><textarea id="answer-input">Unsent text</textarea>',{url:'https://lightwork.invalid/chat/goal/4',runScripts:'outside-only',pretendToBeVisual:true});
  const w=dom.window, intervals=new Map(), deadlines=new Map();let next=0;
  w.setInterval=(fn)=>{intervals.set(++next,fn);return next;};w.clearInterval=id=>intervals.delete(id);
  w.setTimeout=(fn,ms)=>{deadlines.set(++next,{fn,ms});return next;};w.clearTimeout=id=>deadlines.delete(id);
  w.cgNumber=String;w.cgText=String;w.cgCopy=(node,text,values={})=>{node.textContent=text.replace(/\{(\w+)\}/g,(_,key)=>String(values[key]));};w.cgErr=()=> 'Files unavailable';
  shell(w);w.fetch=handler;w.eval(script);
  return {dom,w,doc:w.document,intervals,deadlines,files(names){const input=w.document.getElementById('attach-add');Object.defineProperty(input,'files',{configurable:true,value:names.map(name=>new w.File(['sample'],name))});input.dispatchEvent(new w.Event('change'));},stop(){w.dispatchEvent(new w.Event('pagehide'));dom.window.close();}};
}
test('late completion refreshes attachment list after the initial companion polling window',async()=>{
  let items=[];const p=page(async()=>response(items));await settle();
  const poll=[...p.intervals.values()][0];for(let i=0;i<6;i++){poll();await settle();}assert.equal(p.intervals.size,0);
  items=[{id:8,filename:'Finished review.csv',size_bytes:20}];
  p.doc.dispatchEvent(new p.w.CustomEvent('lightwork:task-projection',{detail:{terminal:true,status:'done'}}));await settle();
  assert.equal(p.doc.querySelector('#attachments-list a').textContent,'Finished review.csv');
  assert.equal(p.doc.getElementById('answer-input').value,'Unsent text');p.stop();
});
test('partial batch retries only failed files and retains the in-flight third file',async()=>{
  const uploads=[];let finishThird;
  const p=page(async(_url,options)=>{
    if(options.method!=='POST')return response([]);
    const name=options.body.get('file').name;uploads.push(name);
    if(name==='second.txt'&&uploads.length===2)return response({},503);
    if(name==='third.txt')return new Promise(resolve=>{finishThird=()=>resolve(response({id:3}));});
    return response({id:1});
  });await settle();p.files(['first.txt','second.txt','third.txt']);await settle();
  assert.deepEqual(uploads,['first.txt','second.txt','third.txt']);
  assert.match(p.doc.body.textContent,/first\.txt \u2014 Complete/);assert.match(p.doc.body.textContent,/second\.txt \u2014 Failed/);assert.match(p.doc.body.textContent,/third\.txt \u2014 Uploading/);
  finishThird();await settle();p.doc.querySelector('ul[aria-label="Upload progress"] button').click();await settle();
  assert.deepEqual(uploads,['first.txt','second.txt','third.txt','second.txt']);
  assert.equal(p.doc.getElementById('answer-input').value,'Unsent text');p.stop();
});
test('access loss clears selected and listed filenames and ignores late upload acknowledgement',async()=>{
  let finish,signal;const p=page(async(_url,options)=>{
    if(options.method!=='POST')return response([{id:1,filename:'Private old.txt',size_bytes:1}]);
    signal=options.signal;return new Promise(resolve=>{finish=resolve;});
  });await settle();p.files(['Private pending.txt']);await settle();
  p.doc.dispatchEvent(new p.w.CustomEvent('lightwork:task-access-lost'));
  assert.equal(signal.aborted,true);assert.doesNotMatch(p.doc.body.textContent,/Private/);
  finish(response({id:2}));await settle();assert.doesNotMatch(p.doc.body.textContent,/Private/);
  assert.equal(p.doc.getElementById('attach-add-btn').disabled,true);assert.equal(p.intervals.size,0);p.stop();
});
test('bounded attachment read aborts and clears unconfirmed metadata',async()=>{
  let attempts=0,signal;const p=page(async(_url,options)=>{attempts++;if(attempts===1)return response([{id:1,filename:'Private.txt',size_bytes:1}]);signal=options.signal;return new Promise((_resolve,reject)=>signal.addEventListener('abort',()=>reject(new p.w.DOMException('Aborted','AbortError'))));});await settle();
  p.doc.dispatchEvent(new p.w.CustomEvent('lightwork:task-projection',{detail:{terminal:true}}));await settle();
  const deadline=[...p.deadlines.values()].find(item=>item.ms===12000);assert.ok(deadline);deadline.fn();await settle();assert.equal(signal.aborted,true);
  assert.doesNotMatch(p.doc.getElementById('attachments-list').textContent,/Private/);p.stop();
});
test('404 makes the attachment panel read-only and removes private progress',async()=>{
  let status=200;const p=page(async()=>response(status===200?[{id:1,filename:'Private.txt',size_bytes:1}]:{},status));await settle();status=404;
  p.w.dispatchEvent(new p.w.Event('focus'));await settle();assert.doesNotMatch(p.doc.body.textContent,/Private/);assert.equal(p.doc.getElementById('attach-add').disabled,true);p.stop();
});
