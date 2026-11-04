'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const {shell} = require('./_shell');
const script = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-deliverable-sharing.js'),'utf8');
const settle=async()=>{for(let i=0;i<15;i++)await new Promise(resolve=>setImmediate(resolve));};
function response(body,status=200){return {ok:status===200,status,redirected:false,json:async()=>body};}
function page(handler,{canOperate=true,done=true}={}){
  const panel='<section id="answer-panel" data-status="'+(done?'done':'running')+'">'+(done?'<textarea id="saved-answer-source">Saved result</textarea>':'')+'</section>';
  const dom=new JSDOM(panel+'<div class="goal-share" data-goal="4" data-can-operate="'+(canOperate?'1':'0')+'"><select id="share-scope"><option value="result" selected>Saved answer</option><option value="conversation">Full conversation</option></select><button id="share-create">Review share link</button><input id="share-url"><button id="share-copy" hidden>Copy link</button><p id="share-msg"></p><ul id="share-list"></ul></div>',{url:'https://lightwork.invalid/chat/goal/4',runScripts:'outside-only',pretendToBeVisual:true});
  shell(dom.window);dom.window.fetch=handler;dom.window.mvErrorText=()=> 'Unable to manage link';dom.window.mvRenderError=(node,error)=>{node.textContent=error.message;};dom.window.mvConfirm=async()=>true;dom.window.eval(script);
  return {dom,doc:dom.window.document,stop(){dom.window.dispatchEvent(new dom.window.Event('pagehide'));dom.window.close();}};
}
const preview={audience:'Anyone with the link',scope:'Only selected saved result',source:{title:'Private title',result:'Private result',sha256:'digest',artifacts:[]},allowed_lifetimes:[3600,86400,604800]};
const conversationPreview={audience:'Anyone with the link',scope:'Reviewed conversation',source:{title:'Private title',sha256:'other-digest',transcript:[{role:'user',text:'Private earlier question'},{role:'assistant',text:'Private earlier answer'}],artifacts:[]},allowed_lifetimes:[3600,86400,604800]};
const isPreview=url=>url.includes('/preview?scope=');

test('a completed saved result makes the sharing review available without reloading',async()=>{
  const p=page(async()=>response({links:[]}),{done:false});await settle();
  const button=p.doc.getElementById('share-create');
  assert.equal(button.hidden,true);assert.equal(button.disabled,true);
  const panel=p.doc.getElementById('answer-panel');panel.dataset.status='done';
  panel.append(p.doc.createElement('textarea'));panel.lastChild.id='saved-answer-source';
  p.doc.dispatchEvent(new p.dom.window.CustomEvent('lightwork:answer-panel-updated'));
  assert.equal(button.hidden,false);assert.equal(button.disabled,false);
  p.doc.dispatchEvent(new p.dom.window.CustomEvent('lightwork:task-projection',{detail:{status:'running'}}));
  assert.equal(button.hidden,true);assert.equal(button.disabled,true);p.stop();
});

test('view-only sharing surface makes no private link requests',async()=>{
  let calls=0;const p=page(async()=>{calls++;return response({links:[]});},{canOperate:false});
  await settle();p.doc.getElementById('share-create').click();await settle();
  assert.equal(calls,0);assert.equal(p.doc.getElementById('share-confirm'),null);p.stop();
});
test('404 clears private link metadata and disables further disclosure',async()=>{
  let status=200;const p=page(async()=>response(status===200?{links:[{id:1,label:'Private review',state:'active',expires_at:1}]}:{},status));await settle();assert.match(p.doc.body.textContent,/Private review/);
  p.doc.getElementById('share-url').value='https://example.test/private-token';status=404;p.dom.window.dispatchEvent(new p.dom.window.Event('focus'));await settle();
  assert.doesNotMatch(p.doc.body.textContent,/Private review/);assert.equal(p.doc.getElementById('share-url').value,'');assert.equal(p.doc.getElementById('share-create').disabled,true);p.stop();
});
test('access loss during preview blocks a late private result from repopulating review',async()=>{
  let finish,signal;const p=page(async(url,options)=>{if(!isPreview(url))return response({links:[]});signal=options.signal;return new Promise(resolve=>{finish=resolve;});});await settle();
  p.doc.getElementById('share-create').click();await settle();p.doc.dispatchEvent(new p.dom.window.CustomEvent('lightwork:task-access-lost'));assert.equal(signal.aborted,true);
  finish(response(preview));await settle();assert.doesNotMatch(p.doc.body.textContent,/Private result|Private title/);assert.equal(p.doc.getElementById('share-confirm'),null);assert.equal(p.doc.getElementById('share-create').disabled,true);p.stop();
});
test('review alone never creates a link and permission loss removes an already shown preview',async()=>{
  const calls=[];const p=page(async(url,options)=>{calls.push([url,options.method]);return response(isPreview(url)?preview:{links:[]});});await settle();p.doc.getElementById('share-create').click();await settle();
  assert.match(p.doc.body.textContent,/Private result/);assert.ok(calls.some(([url])=>url.endsWith('/preview?scope=result')));
  assert.equal(calls.filter(([url,method])=>method==='POST'&&!isPreview(url)).length,0);
  p.doc.dispatchEvent(new p.dom.window.CustomEvent('lightwork:task-access-lost'));assert.doesNotMatch(p.doc.body.textContent,/Private result/);assert.equal(p.doc.getElementById('share-confirm'),null);p.stop();
});

test('explicit conversation review also clears on access loss without publishing',async()=>{
  const calls=[];const p=page(async(url,options)=>{calls.push([url,options.method]);return response(isPreview(url)?conversationPreview:{links:[]});});await settle();
  p.doc.getElementById('share-scope').value='conversation';p.doc.getElementById('share-create').click();await settle();
  assert.ok(calls.some(([url])=>url.endsWith('/preview?scope=conversation')));
  assert.match(p.doc.querySelector('.share-review').textContent,/Private earlier question[\s\S]*Private earlier answer/);
  assert.equal(calls.filter(([url,method])=>method==='POST'&&!isPreview(url)).length,0);
  p.doc.dispatchEvent(new p.dom.window.CustomEvent('lightwork:task-access-lost'));
  assert.doesNotMatch(p.doc.body.textContent,/Private earlier question|Private earlier answer/);
  assert.equal(p.doc.getElementById('share-confirm'),null);p.stop();
});

test('a refused revoke shows the error and permits an explicit retry while access remains',async()=>{
  const calls=[];const p=page(async(url,options)=>{
    calls.push([url,options.method]);
    if(url.endsWith('/7/revoke'))return response({detail:'Could not record revocation'},503);
    return response({links:[{id:7,label:'Current link',state:'active',expires_at:1}]});
  });await settle();
  const button=p.doc.querySelector('.share-revoke');button.click();await settle();
  assert.equal(button.disabled,false);
  assert.match(p.doc.getElementById('share-msg').textContent,/Unable to manage link/);
  assert.equal(calls.filter(([url])=>url.endsWith('/7/revoke')).length,1);
  button.click();await settle();
  assert.equal(calls.filter(([url])=>url.endsWith('/7/revoke')).length,2);p.stop();
});

test('a revoke rejected after access loss clears private data and cannot be retried',async()=>{
  const calls=[];const p=page(async(url,options)=>{
    calls.push([url,options.method]);
    if(url.endsWith('/7/revoke'))return response({},403);
    return response({links:[{id:7,label:'Private current link',state:'active',expires_at:1}]});
  });await settle();
  const button=p.doc.querySelector('.share-revoke');button.click();await settle();
  assert.equal(button.disabled,true);
  assert.equal(p.doc.querySelector('.share-revoke'),null);
  assert.equal(p.doc.getElementById('share-create').disabled,true);
  assert.doesNotMatch(p.doc.body.textContent,/Private current link/);
  assert.match(p.doc.getElementById('share-msg').textContent,/access changed/);
  button.click();p.dom.window.dispatchEvent(new p.dom.window.Event('focus'));await settle();
  assert.equal(calls.filter(([url])=>url.endsWith('/7/revoke')).length,1);p.stop();
});
