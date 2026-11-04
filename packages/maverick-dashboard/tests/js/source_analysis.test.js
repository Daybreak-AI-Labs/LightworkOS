'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {JSDOM}=require('jsdom');
const read=name=>fs.readFileSync(path.resolve(__dirname,'../../maverick_dashboard/static/'+name),'utf8');
const tick=()=>new Promise(resolve=>setImmediate(resolve)),context='a'.repeat(64);
async function fixture(hash=''){
 const dom=new JSDOM(`<section id="knowledge-access" data-context="${context}" data-tenant="tenant" data-actor="user:alice"><form id="sa-form"><input id="sa-title"><textarea id="sa-description"></textarea><button id="sa-start" type="submit"></button><button id="sa-recover" type="button"></button></form><p id="sa-status"></p><p id="sa-policy"></p><ul id="sa-sources"></ul><div id="sa-output"></div></section>`,{url:'https://app.test/knowledge-access'+hash,runScripts:'outside-only'});
 const w=dom.window,d=w.document,calls=[];let handler=async()=>({ok:true,status:200,json:async()=>({context,enabled:true,max_dollars:1,max_wall_seconds:60})});
 w.fetch=async(url,options)=>{calls.push({url,options});return handler(url,options);};w.mvConfirm=async()=>true;
 w.eval(read('lightwork-access-state.js'));w.eval(read('lightwork-source-analysis.js'));await tick();
 function choose(purpose='business'){w.dispatchEvent(new w.CustomEvent('lightwork:source-selected',{detail:{context,purpose,title:'Current policy',fresh_until:1900000000,reference:{kind:'dataset',asset_id:'policy',version:'v1',manifest_sha256:'b'.repeat(64),schema:'lightwork.research-registry-ref.v1'}}}));}
 return {w,d,calls,choose,set handler(value){handler=value;}};
}
test('selected context uses native task API once and exact references',async()=>{
 const f=await fixture();f.choose();f.d.getElementById('sa-title').value='Review policy';f.d.getElementById('sa-description').value='Explain changes';
 f.handler=async(url)=>({ok:true,status:200,json:async()=>url.endsWith('task-policy')?{context,enabled:true,max_dollars:1,max_wall_seconds:60}:{id:42,status:'pending'}});
 f.d.getElementById('sa-form').dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await tick();await tick();
 const posts=f.calls.filter(row=>row.options.method==='POST');assert.equal(posts.length,1);const body=JSON.parse(posts[0].options.body);assert.equal(body.knowledge_context.context,context);assert.equal(body.knowledge_context.references[0].version,'v1');assert.match(posts[0].options.headers['Idempotency-Key'],/^[a-f0-9]{32}$/);assert.match(f.d.getElementById('sa-status').textContent,/Task 42/);
});
test('unknown acknowledgement keeps identity and disables duplicate start',async()=>{
 const f=await fixture();f.choose();f.d.getElementById('sa-title').value='Review';f.d.getElementById('sa-description').value='Explain';
 f.handler=async(url)=>{if(url.endsWith('/goals'))throw Error('offline');return {ok:true,status:200,json:async()=>({context,enabled:true,max_dollars:1,max_wall_seconds:60})};};
 f.d.getElementById('sa-form').dispatchEvent(new f.w.Event('submit',{bubbles:true,cancelable:true}));await tick();await tick();
 assert.equal(f.d.getElementById('sa-start').disabled,true);assert.equal(f.d.getElementById('sa-recover').hidden,false);assert.match(f.d.getElementById('sa-status').textContent,/No paid attempt is retried/);assert.ok(f.w.sessionStorage.getItem('lightwork.source-analysis.pending.'+context));
});
test('source-analysis result is text-only and cleared when private access changes',async()=>{
 const f=await fixture();f.handler=async()=>({ok:true,status:200,json:async()=>({context,title:'Analysis',message:'Current',result:'<img src=x onerror=alert(1)>',purpose:'business',references:[]})});f.w.location.hash='#analysis=42';f.w.dispatchEvent(new f.w.HashChangeEvent('hashchange'));await tick();await tick();
 assert.match(f.d.getElementById('sa-output').textContent,/<img/);assert.equal(f.d.querySelector('#sa-output img'),null);f.w.dispatchEvent(new f.w.CustomEvent('lightwork:knowledge-cleared'));assert.equal(f.d.getElementById('sa-output').textContent,'');
});
