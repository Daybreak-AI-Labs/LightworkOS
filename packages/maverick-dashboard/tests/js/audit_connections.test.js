"use strict";
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {JSDOM}=require('jsdom');
const {shell} = require('./_shell');
const tick=()=>new Promise(resolve=>setTimeout(resolve,0));
const response=(body,status=200)=>({ok:status>=200&&status<300,status,json:async()=>body});
const source=fs.readFileSync(path.join(__dirname,'../../maverick_dashboard/static/lightwork-connections.js'),'utf8');
const raw=fs.readFileSync(path.join(__dirname,'../../maverick_dashboard/templates/connections.html'),'utf8');
function fixture(fetch){
  const html=raw.replace(/\{%[\s\S]*?%\}/g,'').replace(/\{\{[\s\S]*?\}\}/g,'').replace('data-can-manage=""','data-can-manage="true"');
  const dom=new JSDOM(html,{url:'http://localhost/connections',runScripts:'outside-only'});
  dom.window.lightworkConnectionImpact={review:async()=> 'a'.repeat(64)};
  shell(dom.window);dom.window.fetch=fetch;dom.window.mvConfirm=async()=>true;dom.window.eval(source);return dom;
}
const record={name:'friendly-account',connector:'long_tail',revision:'original',has_token:true,base_url:'https://service.example',access:'owner',allowed_principals:[]};

test('outage never appears as an empty inventory and disables mutations',async()=>{
  const dom=fixture(async url=>response(url.endsWith('/catalog')?{connectors:[]}:{},503));await tick();await tick();
  const d=dom.window.document;assert.equal(d.getElementById('cx-empty').hidden,true);
  assert.match(d.getElementById('cx-inventory-status').textContent,/unavailable/);
  assert.equal(d.querySelector('#cx-form button[type="submit"]').disabled,true);dom.window.close();
});

test('conflict cannot inherit a revision from refreshed inventory; known long-tail binding survives',async()=>{
  let version='original',writes=[];
  const dom=fixture(async(url,options={})=>{
    if(url.endsWith('/catalog'))return response({connectors:[{name:'long_tail',label:'Long tail',key_setup_supported:true}]});
    if(options.method==='POST'){writes.push(JSON.parse(options.body));version='newer';return response({},409);}
    return response({connections:[{...record,revision:version}],context:'workspace'});
  });await tick();await tick();const w=dom.window,d=w.document;
  d.querySelector('#cx-list button').click();d.getElementById('cx-tenant-access').checked=true;
  const submit=()=>d.getElementById('cx-form').dispatchEvent(new w.Event('submit',{cancelable:true}));
  submit();submit();await tick();await tick();submit();
  assert.equal(writes.length,1);assert.equal(writes[0].expected_revision,'original');assert.equal(writes[0].connector,'long_tail');
  assert.equal(d.getElementById('cx-conflict').hidden,false);assert.match(d.getElementById('cx-conflict-draft').textContent,/tenant/);
  d.getElementById('cx-reload-edit').click();await tick();await tick();submit();await tick();
  assert.equal(writes[1].expected_revision,'newer');dom.window.close();
});

test('access loss prevents a late successful list restoring private rows',async()=>{
  let resolve;const pending=new Promise(done=>resolve=done);
  const dom=fixture(url=>url.endsWith('/catalog')?Promise.resolve(response({connectors:[]})):pending);
  dom.window.document.dispatchEvent(new dom.window.Event('lightwork:connection-access-lost'));
  resolve(response({connections:[record],context:'workspace'}));await tick();await tick();
  assert.equal(dom.window.document.getElementById('cx-list').children.length,0);dom.window.close();
});


test('unknown adapters remain read-only rather than changing binding on submit',async()=>{
  let writes=0;
  const dom=fixture(async(url,options={})=>{
    if(options.method==='POST')writes++;
    return response(url.endsWith('/catalog')?{connectors:[]}:{connections:[record],context:'workspace'});
  });await tick();await tick();const d=dom.window.document;
  d.querySelector('#cx-list button').click();
  assert.equal(d.querySelector('#cx-form button[type="submit"]').disabled,true);
  d.getElementById('cx-form').dispatchEvent(new dom.window.Event('submit',{cancelable:true}));
  await tick();assert.equal(writes,0);dom.window.close();
});

test('a failure before anything is sent keeps the typed credentials and the page usable', async () => {
  let writes = 0;
  const dom = fixture(async (url, options = {}) => {
    if (options.method === 'POST') writes++;
    return response(url.endsWith('/catalog') ? {connectors: [{name: 'long_tail', label: 'Long tail', key_setup_supported: true}]}
                                              : {connections: [record], context: 'workspace'});
  });
  await tick(); await tick();
  const w = dom.window, d = w.document;
  d.querySelector('#cx-list button').click();
  d.getElementById('cx-token').value = 'a-new-secret-key';
  w.lightworkConnectionImpact.review = async () => { throw new Error('Workspace changed. Reopen this page before saving.'); };
  d.getElementById('cx-form').dispatchEvent(new w.Event('submit', {cancelable: true}));
  await tick(); await tick();
  assert.equal(writes, 0, 'nothing may be sent');
  assert.equal(d.getElementById('cx-token').value, 'a-new-secret-key', 'the typed key is kept');
  assert.match(d.getElementById('cx-msg').textContent, /Workspace changed/);
  assert.doesNotMatch(d.getElementById('cx-msg').textContent, /not confirmed/);
  assert.equal(d.querySelector('#cx-form button[type="submit"]').disabled, false, 'the page is not locked');
  dom.window.close();
});

test('a follow-up check that fails after a recorded save is reported as such and refreshes the list', async () => {
  const lists = [];
  const dom = fixture(async (url, options = {}) => {
    if (url.endsWith('/catalog')) return response({connectors: [{name: 'long_tail', label: 'Long tail', key_setup_supported: true}]});
    if (url.endsWith('/test')) return response({detail: 'The service did not answer.'}, 409);
    if (options.method === 'POST') return response({name: 'brand-new', revision: 'r1'});
    lists.push(url);
    return response({connections: [], context: 'workspace'});
  });
  await tick(); await tick();
  const w = dom.window, d = w.document, loadedBefore = lists.length;
  d.getElementById('cx-name').value = 'brand-new';
  d.getElementById('cx-connector').value = 'long_tail';
  d.getElementById('cx-token').value = 'a-new-secret-key';
  d.getElementById('cx-base').value = 'https://service.example';
  d.getElementById('cx-save-test').click();
  await tick(); await tick(); await tick();
  assert.match(d.getElementById('cx-msg').textContent, /saved, but the follow-up service check could not be completed/);
  assert.equal(d.getElementById('cx-conflict').hidden, true, 'a failed check is not an edit conflict');
  assert.ok(lists.length > loadedBefore, 'the list is read again after the save');
  dom.window.close();
});
