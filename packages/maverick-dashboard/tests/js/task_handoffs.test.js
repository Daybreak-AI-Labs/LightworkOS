"use strict";
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {JSDOM}=require('jsdom');
const {shell} = require('./_shell');
const root=path.resolve(__dirname,'../../maverick_dashboard');
const script=fs.readFileSync(path.join(root,'static/lightwork-task-handoffs.js'),'utf8');
const template=fs.readFileSync(path.join(root,'templates/task_handoffs.html'),'utf8');
const tick=async()=>{for(let i=0;i<12;i++)await new Promise(resolve=>setImmediate(resolve));};
const preview={recipient:'user:recipient',source_id:4,instruction:'Only selected work',commitments:'None known',max_dollars:2,source_cost_dollars:1,open_questions:0,closed_task_ids:[4],expires_at:2000000000,items:[],consequences:['Explicit acceptance required'],bundle_id:'DLB-one',review_version:'a'.repeat(64),title:'Next'};
const row={id:'HOF-one',revision:1,state:'offered',preview,can_accept:true,can_withdraw:false};
function page(bundle='',query='') {
 const dom=new JSDOM(template.replace('{{ handoff_context }}','context').replace('{{ handoff_bundle }}',bundle),{url:'https://lightwork.invalid/task-handoffs'+query,runScripts:'outside-only'});
 const calls=[];let handler=async()=>({ok:true,status:200,json:async()=>({context:'context',items:[{id:row.id,title:'Next',state:'offered'}]})});
 dom.window.fetch=async(url,opts)=>{calls.push({url,opts,body:opts.body?JSON.parse(opts.body):null});return handler(url,opts);};
 dom.window.mvBusinessError=value=>value.detail||null;
 shell(dom.window);
 dom.window.eval(script);
 return {dom,doc:dom.window.document,calls,set(fn){handler=fn;},json(body){return {ok:true,status:200,json:async()=>({context:'context',...body})};}};
}
test('unconfirmed offer keeps exact save reference and locks reviewed fields through retry',async()=>{
 const p=page('DLB-one');await tick();const form=p.doc.getElementById('handoff-form');
 for(const [key,value] of Object.entries({title:'Next',instruction:'Only selected work',commitments:'None known',max_dollars:2}))form.elements.namedItem(key).value=value;
 p.set(async()=>p.json({preview}));form.dispatchEvent(new p.dom.window.Event('submit',{bubbles:true,cancelable:true}));await tick();
 p.set(async()=>{throw new Error('Connection lost');});const button=p.doc.getElementById('handoff-offer');button.click();await tick();
 const sent=p.calls.at(-1).body;assert.ok(sent.operation_id);assert.equal(form.elements.namedItem('instruction').disabled,true);assert.equal(button.hidden,false);
 p.set(async()=>p.json({handoff:{...row,can_accept:false,can_withdraw:true}}));button.click();await tick();
 assert.deepEqual(p.calls.at(-1).body,sent);assert.equal(form.elements.namedItem('instruction').disabled,false);p.dom.window.close();
});
test('uncertain accept cannot be relabelled as decline and replayed under another choice',async()=>{
 const p=page();await tick();p.set(async()=>p.json({handoff:row}));p.doc.querySelector('#handoff-list button').click();await tick();
 p.set(async()=>{throw new Error('Connection lost');});const buttons=p.doc.querySelectorAll('#handoff-actions button');buttons[0].click();await tick();
 const count=p.calls.length, sent=p.calls.at(-1).body;assert.equal(sent.action,'accept');buttons[1].click();await tick();
 assert.equal(p.calls.length,count);assert.match(p.doc.getElementById('handoff-status').textContent,/exact previous unconfirmed/);
 p.set(async()=>p.json({handoff:{...row,state:'accepted',can_accept:false,acceptance:{successor_id:8}}}));buttons[0].click();await tick();
 assert.deepEqual(p.calls.at(-1).body,sent);assert.equal(p.doc.querySelector('#handoff-actions a').getAttribute('href'),'/chat/goal/8');p.dom.window.close();
});
test('workspace change clears the selected private preview',async()=>{
 const p=page();await tick();p.set(async()=>p.json({handoff:row}));p.doc.querySelector('#handoff-list button').click();await tick();
 p.set(async()=>({ok:true,status:200,json:async()=>({context:'other',items:[]})}));p.doc.getElementById('handoff-refresh').click();await tick();
 assert.equal(p.doc.getElementById('handoff-detail').hidden,true);assert.equal(p.doc.getElementById('handoff-content').textContent,'');p.dom.window.close();
});
test('My data deep link reads the exact current handoff without starting or accepting work',async()=>{
 const p=page('','?open=HOF-one');p.set(async()=>p.json({handoff:row}));await tick();
 assert.equal(p.doc.getElementById('handoff-detail').hidden,false);
 assert.equal(p.calls.at(-1).url,'/api/v1/task-handoffs/HOF-one');
 assert.ok(p.calls.every(call=>!call.body));p.dom.window.close();
});
test('unavailable handoff deep link does not render private contents or retry mutation',async()=>{
 const p=page('','?open=HOF-other');p.set(async()=>({ok:false,status:404,json:async()=>({detail:'This handoff is unavailable.'})}));await tick();
 assert.equal(p.doc.getElementById('handoff-detail').hidden,true);
 assert.equal(p.doc.getElementById('handoff-content').textContent,'');
 assert.ok(p.calls.every(call=>!call.body));p.dom.window.close();
});
