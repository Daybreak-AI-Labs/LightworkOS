"use strict";
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {JSDOM}=require('jsdom');
const root=path.resolve(__dirname,'../../maverick_dashboard');
const script=fs.readFileSync(path.join(root,'static/lightwork-conversation-inbox.js'),'utf8');
const panel=fs.readFileSync(path.join(root,'templates/_conversation_inbox_panel.html'),'utf8').replace('{{ goal.id }}','4').replace('{{ conversation_context }}','context').replace("{{ '1' if can_operate else '0' }}",'1');
const shell='<div id="conversation-send-options"><select id="conversation-send-mode"><option value="guidance">Guidance</option><option value="queue">Queue</option><option value="independent">Independent</option></select><label id="conversation-independent-context-label"></label><select id="conversation-independent-context"><option value="none">None</option><option value="conversation_snapshot">Snapshot</option></select><p id="conversation-send-explanation"></p></div><form id="answer-form"><textarea id="answer-input" name="message"></textarea><input id="reply-files" name="files" type="file" multiple><button id="answer-send" type="button">Send</button></form>';
const tick=async()=>{for(let i=0;i<14;i++)await new Promise(resolve=>setImmediate(resolve));};
const item={id:'CI-one',revision:1,mode:'queue',text:'Saved next work',files:[{id:'file-one',filename:'first.txt',mime:'text/plain',size_bytes:3},{id:'file-two',filename:'second.txt',mime:'text/plain',size_bytes:5}],state:'queued',message:'Waiting for current task',goal_id:null,acknowledgement:null,created_at:1};
function state(items=[]){return {context:'context',root_id:4,enabled:true,policy:{modes:['guidance','queue','independent'],max_pending:30,max_files:10,max_file_bytes:4194304,max_total_bytes:4194304},items,defaults:{mode:'queue',detail:'detailed'},target:{id:4,title:'Current task',description:'Original task brief',status:'active'},guidance_review_version:'current-review'};}
function page(initial=state(), pointer=null, catalog=null){const dom=new JSDOM(panel+shell,{url:'https://lightwork.invalid/chat/goal/4',runScripts:'outside-only'});const calls=[];let current=initial,allowed=true,handler=null,clears=0;
 dom.window.fetch=async(url,options={})=>{calls.push({url:String(url),options});if(String(url).endsWith('/permissions'))return {ok:true,status:200,json:async()=>({can_operate:allowed})};if(handler)return handler(String(url),options);return {ok:true,status:200,json:async()=>current};};
 dom.window.mvBusinessError=body=>body.detail&&body.detail.schema==='lightwork.error.v1'?body.detail:null;
 const form=dom.window.document.getElementById('answer-form');form.mvRecovery={clear:async()=>{clears++;}};
 if(pointer)dom.window.sessionStorage.setItem('lightwork:pending-message:context:4',pointer);
 if(catalog){const payload=dom.window.document.createElement('script');payload.id='lightwork-i18n-data';payload.type='application/json';payload.textContent=JSON.stringify({language:'fr',locale:'fr-CA',catalog});dom.window.document.head.append(payload);dom.window.eval(fs.readFileSync(path.join(root,'static/lightwork-i18n.js'),'utf8'));}
 dom.window.eval(script);
 return {dom,doc:dom.window.document,calls,api:dom.window.mvConversationInbox,form,set(fn){handler=fn;},allow(value){allowed=value;},current(value){current=value;handler=null;},get clears(){return clears;},response(value,status=200){return {ok:status>=200&&status<300,status,json:async()=>value};}};
}
function button(p,text){return Array.from(p.doc.querySelectorAll('button')).find(node=>node.textContent===text);}
function compose(p,text='Send while current task runs'){p.doc.getElementById('answer-input').value=text;}
function formBody(call){return Object.fromEntries(call.options.body.entries());}
test('active-task message gets durable queue receipt without stopping task or waiting for completion',async()=>{const p=page();await tick();p.api.updateComposer({asking:false,running:true,status:'active'});assert.equal(p.doc.getElementById('answer-send').disabled,false);compose(p);p.set(async(url,options)=>p.response({...state([{...item,text:'Send while current task runs',files:[]}]),item:{...item,text:'Send while current task runs',files:[]}}));await p.api.send(p.form);assert.equal(formBody(p.calls.at(-1)).mode,'queue');assert.equal(p.clears,1);assert.equal(p.doc.getElementById('answer-input').value,'');assert.match(p.doc.getElementById('conversation-inbox-items').textContent,/Queued; not started/);p.dom.window.close();});
test('unknown send keeps exact FormData and operation reference until explicit retry acknowledges it',async()=>{const p=page();await tick();compose(p);p.set(async()=>{throw new Error('Network unavailable');});await p.api.send(p.form);const first=p.calls.at(-1).options.body;assert.equal(p.doc.getElementById('answer-input').disabled,true);assert.equal(p.clears,0);p.set(async()=>p.response({...state([item]),item:{...item,text:'Send while current task runs',files:[]}}));await p.api.send(p.form);assert.equal(p.calls.at(-1).options.body,first);assert.equal(p.clears,1);assert.equal(p.doc.getElementById('answer-input').disabled,false);p.dom.window.close();});
test('newer composer text survives an acknowledged earlier payload',async()=>{const p=page();await tick();compose(p,'First');let finish;p.set(async()=>new Promise(resolve=>{finish=resolve;}));const sending=p.api.send(p.form);await tick();compose(p,'Newer draft');finish(p.response({...state([item]),item}));await sending;assert.equal(p.doc.getElementById('answer-input').value,'Newer draft');assert.equal(p.clears,0);p.dom.window.close();});
test('guidance requires separate explicit decision with current reviewed task and consumed context',async()=>{const guidance={...item,mode:'guidance',state:'needs_decision',text:'Add a constraint'},consumed={...item,id:'CI-old',mode:'guidance',state:'consumed',acknowledgement:{text:'Earlier instruction',files:[],checkpoint:'turn-2',at:1}};const p=page(state([guidance,consumed]));await tick();button(p,'Review guidance before approving').click();assert.match(p.doc.getElementById('conversation-inbox-guidance-review').textContent,/Original task brief/);assert.match(p.doc.getElementById('conversation-inbox-guidance-review').textContent,/Earlier instruction/);assert.equal(p.calls.filter(call=>call.options.method==='PATCH').length,0);p.set(async()=>p.response({...state([{...guidance,state:'guidance_ready'}]),item:{...guidance,state:'guidance_ready'}}));p.doc.getElementById('conversation-inbox-append').click();await tick();const body=JSON.parse(p.calls.at(-1).options.body);assert.equal(body.action,'approve_guidance');assert.equal(body.decision,'append');assert.equal(body.expected_review,'current-review');p.dom.window.close();});
test('editing pending files keeps only explicit retained IDs and snapshots before controls lock',async()=>{const p=page(state([item]));await tick();button(p,'Edit pending text or files').click();p.doc.querySelector('#conversation-inbox-edit-files input').checked=false;p.doc.getElementById('conversation-inbox-edit-text').value='Revised';p.set(async()=>p.response({...state([{...item,revision:2,text:'Revised',files:[item.files[1]]}]),item:{...item,revision:2}}));p.doc.getElementById('conversation-inbox-edit').dispatchEvent(new p.dom.window.Event('submit',{bubbles:true,cancelable:true}));await tick();const body=formBody(p.calls.at(-1));assert.equal(body.text,'Revised');assert.equal(body.keep_files,'["file-two"]');assert.equal(body.expected_revision,'1');p.dom.window.close();});
test('role revocation keeps text and refuses mutation before send',async()=>{const p=page();await tick();compose(p,'Private unsent text');p.allow(false);await p.api.send(p.form);assert.equal(p.calls.filter(call=>call.options.method==='POST').length,0);assert.equal(p.doc.getElementById('answer-input').value,'Private unsent text');assert.equal(p.clears,0);p.dom.window.close();});
test('reload with opaque operation pointer only checks receipt and never resubmits automatically',async()=>{const p=page(state(),'original-operation-one');await tick();assert.ok(p.calls.some(call=>call.url.endsWith('/receipts/original-operation-one')));assert.equal(p.calls.filter(call=>call.options.method==='POST'||call.options.method==='PATCH').length,0);p.dom.window.close();});
test('explicit independent context and goal link do not merge separate work into current task',async()=>{const p=page();await tick();compose(p,'Separate analysis');p.doc.getElementById('conversation-send-mode').value='independent';p.doc.getElementById('conversation-independent-context').value='none';p.set(async()=>p.response({...state([{...item,mode:'independent',state:'submitted',goal_id:12}]),item:{...item,mode:'independent',state:'submitted',goal_id:12}}));await p.api.send(p.form);assert.equal(formBody(p.calls.at(-1)).independent_context,'none');assert.equal(p.doc.querySelector('#conversation-inbox-items a').getAttribute('href'),'/chat/goal/12');p.dom.window.close();});

test('a later conflict cannot clear an already uncertain operation reference',async()=>{const p=page();await tick();compose(p);p.set(async()=>{throw new Error('Network unavailable');});await p.api.send(p.form);const reference=formBody(p.calls.at(-1)).operation_id;p.set(async()=>p.response({detail:{schema:'lightwork.error.v1',message:'Different payload for existing operation'}},409));await p.api.send(p.form);assert.equal(p.dom.window.sessionStorage.getItem('lightwork:pending-message:context:4'),reference);assert.equal(p.doc.getElementById('answer-input').value,'Send while current task runs');assert.equal(p.clears,0);p.dom.window.close();});
test('receipt for another payload keeps the restored edited composer draft',async()=>{const p=page();await tick();compose(p,'Edited restored draft');p.set(async()=>p.response({...state([item]),item:{...item,text:'Original accepted text',files:[]}}));await p.api.send(p.form);assert.equal(p.doc.getElementById('answer-input').value,'Edited restored draft');assert.equal(p.clears,0);p.dom.window.close();});


test('receipt lookup never clears a same-name same-size replacement attachment without matching its bytes',async()=>{const p=page();await tick();compose(p,'Attached');const replacement=new p.dom.window.File(['new'],'same.txt',{type:'text/plain'});Object.defineProperty(p.doc.getElementById('reply-files'),'files',{value:[replacement]});p.set(async()=>{throw new Error('Network unavailable');});await p.api.send(p.form);p.set(async()=>p.response({...state(),received:true,item:{...item,text:'Attached',files:[{id:'old',filename:'same.txt',size_bytes:3,sha256:'different'}]}}));p.doc.getElementById('conversation-inbox-receipt').click();await tick();assert.equal(p.clears,0);assert.equal(p.doc.getElementById('answer-input').value,'Attached');p.dom.window.close();});
test('pending file removals trigger navigation protection and cannot move another message into the editor',async()=>{const p=page(state([item,{...item,id:'CI-two',text:'Other message'}]));await tick();const edits=Array.from(p.doc.querySelectorAll('button')).filter(node=>node.textContent==='Edit pending text or files');edits[0].click();p.doc.querySelector('#conversation-inbox-edit-files input').checked=false;const leaving=new p.dom.window.Event('beforeunload',{cancelable:true});p.dom.window.dispatchEvent(leaving);assert.equal(leaving.defaultPrevented,true);edits[1].click();assert.equal(p.doc.getElementById('conversation-inbox-edit-text').value,item.text);assert.match(p.doc.getElementById('conversation-inbox-status').textContent,/another pending message/);p.dom.window.close();});
test('policy with no enabled modes leaves the background composer unavailable',async()=>{const initial=state();initial.policy.modes=[];const p=page(initial);await tick();assert.equal(p.api.available,false);compose(p);await p.api.send(p.form);assert.equal(p.calls.filter(call=>call.options.method==='POST').length,0);p.dom.window.close();});
test('new message echoes reviewed erasure generation and closed execution disables new sends',async()=>{const initial=state();initial.generation=3;const p=page(initial);await tick();compose(p);p.set(async()=>p.response({...initial,item:{...item,text:'Send while current task runs',files:[]}}));await p.api.send(p.form);assert.equal(formBody(p.calls.at(-1)).expected_generation,'3');p.current({...initial,execution_closed:true});p.doc.getElementById('conversation-inbox-refresh').click();await tick();assert.equal(p.api.available,false);p.dom.window.close();});


test('closed source permits freshly authorized pending cancellation without reopening execution',async()=>{const initial={...state([item]),execution_closed:true,can_cancel:true};const p=page(initial);await tick();p.allow(false);p.set(async(url,options)=>options.method==='PATCH'?p.response({...initial,item:{...item,state:'cancelled'},items:[{...item,state:'cancelled'}]}):p.response(initial));button(p,'Cancel this pending message').click();await tick();assert.equal(JSON.parse(p.calls.at(-1).options.body).action,'cancel');assert.equal(p.api.available,false);assert.match(p.doc.getElementById('conversation-inbox-items').textContent,/Cancelled before consumption/);p.dom.window.close();});


test('brief balances compact message cards while detailed opens exact acknowledgements',async()=>{for(const detail of ['brief','balanced','detailed']){const initial=state([{...item,acknowledgement:{text:'Read payload',files:[],checkpoint:'turn-1',at:1}}]);initial.defaults.detail=detail;const p=page(initial);await tick();const sections=p.doc.querySelectorAll('.conversation-message details');assert.equal(sections[0].open,detail!=='brief');assert.equal(sections[1].open,detail==='detailed');p.dom.window.close();}});


test('independent work binds the explicitly shown snapshot instead of a later polling update',async()=>{const initial=state();initial.target.snapshot_version='original-snapshot';initial.target.result='Original saved result';const p=page(initial);await tick();compose(p,'Separate work');p.doc.getElementById('conversation-send-mode').value='independent';const choice=p.doc.getElementById('conversation-independent-context');choice.value='conversation_snapshot';choice.dispatchEvent(new p.dom.window.Event('change'));assert.match(p.doc.getElementById('conversation-inbox-snapshot-review').textContent,/Original saved result/);const fresh={...initial,target:{...initial.target,snapshot_version:'later-snapshot',result:'Changed result'}};p.current(fresh);p.doc.getElementById('conversation-inbox-refresh').click();await tick();p.set(async()=>p.response({detail:{schema:'lightwork.error.v1',message:'Snapshot changed'}},409));await p.api.send(p.form);assert.equal(formBody(p.calls.at(-1)).expected_snapshot,'original-snapshot');assert.equal(p.doc.getElementById('answer-input').value,'Separate work');p.dom.window.close();});


test('partial task admission offers cancellation instead of rewriting its durable request',async()=>{const blocked={...item,state:'blocked',goal_id:9,may_edit:false};const p=page(state([blocked]));await tick();assert.equal(button(p,'Edit pending text or files'),undefined);assert.ok(button(p,'Cancel this pending message'));p.dom.window.close();});

test('localized guidance review preserves exact employee text, attachments and acknowledged payloads',async()=>{
 const catalog={
   'Guidance for this task':{text:'Consignes pour cette tâche',lang:'fr'},
   'Waiting for your guidance decision':{text:'En attente de votre décision',lang:'fr'},
   '{mode} — {state}':{text:'{mode} — {state}',lang:'fr'},
   'Review guidance before approving':{text:'Vérifier avant d’approuver',lang:'fr'},
   'Save':{text:'Enregistrer',lang:'fr'},
   '{name} — {bytes} bytes':{text:'{name} — {bytes} octets',lang:'fr'},
 };
 const exact='Save <img src=x> مرحبا';
 const guidance={...item,mode:'guidance',state:'needs_decision',text:exact,files:[{id:'private',filename:'Save',size_bytes:12345}]};
 const old={...item,id:'old',mode:'guidance',state:'consumed',acknowledgement:{text:'Save',files:[],checkpoint:'first',at:1}};
 const initial=state([guidance,old]);initial.target.description='Save';
 const p=page(initial,null,catalog);await tick();
 const heading=p.doc.querySelector('.conversation-message h3');assert.equal(heading.lang,'fr');assert.match(heading.textContent,/Consignes pour cette tâche/);
 assert.equal(p.doc.querySelector('.conversation-message details p').textContent,exact);
 assert.equal(p.doc.querySelector('.conversation-message details p').lang,'und');
 assert.equal(p.doc.querySelector('.conversation-message li bdi').textContent,'Save');
 assert.match(p.doc.querySelector('.conversation-message li').textContent,/12\s?345 octets/);
 button(p,'Vérifier avant d’approuver').click();
 const review=p.doc.getElementById('conversation-inbox-guidance-review');
 assert.ok([...review.querySelectorAll('[data-user-content]')].some(node=>node.textContent==='Save'));
 assert.ok([...review.querySelectorAll('[data-user-content]')].some(node=>node.textContent===exact));
 assert.equal(review.querySelector('img'),null);assert.equal(p.calls.filter(call=>call.options.method==='PATCH').length,0);
 p.dom.window.close();
});

test('during a run the composer says in plain words what each kind of message will do',async()=>{const p=page();await tick();p.api.updateComposer({asking:false,running:true,status:'active'});const chooser=p.doc.getElementById('conversation-send-mode'),explanation=p.doc.getElementById('conversation-send-explanation');assert.equal(p.doc.getElementById('conversation-send-options').hidden,false);
  const said={};for(const mode of ['guidance','queue','independent']){chooser.value=mode;p.api.updateComposer({asking:false,running:true,status:'active'});said[mode]=explanation.textContent;}
  assert.match(said.guidance,/reads it at its next safe point/);assert.match(said.guidance,/doesn't start a new task/);
  assert.match(said.queue,/starts when the current task finishes/);assert.match(said.independent,/separate task now/);
  for(const text of Object.values(said))assert.doesNotMatch(text,/billable|runner|consumes|snapshot/);p.dom.window.close();});
test('an explicit workspace off says plainly that sending during a task is off',async()=>{const p=page({...state(),enabled:false});await tick();assert.equal(p.api.available,false);assert.equal(p.api.disabledByPolicy,true);assert.match(p.doc.getElementById('conversation-inbox-status').textContent,/^Sending messages during a task is turned off for this workspace\./);p.dom.window.close();});
test('the plain explanation is translated',async()=>{const english="Lightwork saves this note for the current task. You check it once more, then the task reads it at its next safe point. It doesn't start a new task or undo steps already done.";const p=page(state(),null,{[english]:{text:'Note enregistrée.',lang:'fr'}});await tick();p.doc.getElementById('conversation-send-mode').value='guidance';p.api.updateComposer({asking:false,running:true,status:'active'});assert.equal(p.doc.getElementById('conversation-send-explanation').textContent,'Note enregistrée.');p.dom.window.close();});

test('an answer that cannot be read is an unconfirmed result, never a change of account', async () => {
  const p = page(); await tick(); compose(p, 'Private text the answer must not erase');
  p.set(async () => ({ok: true, status: 200, redirected: false, json: async () => { throw new SyntaxError('truncated'); }}));
  await p.api.send(p.form);
  assert.equal(p.doc.getElementById('answer-input').value, 'Private text the answer must not erase');
  assert.ok(p.dom.window.sessionStorage.getItem('lightwork:pending-message:context:4'), 'the receipt reference must survive');
  assert.doesNotMatch(p.doc.getElementById('conversation-inbox-status').textContent, /account or workspace changed/);
  assert.match(p.doc.getElementById('conversation-inbox-status').textContent, /unconfirmed/);
  assert.equal(p.clears, 0);
  p.dom.window.close();
});

test('an edit locked by an unconfirmed save opens fully again after it is resolved', async () => {
  const p = page(state([item])); await tick();
  button(p, 'Edit pending text or files').click();
  p.doc.getElementById('conversation-inbox-edit-text').value = 'Revised';
  p.set(async () => { throw new Error('Network unavailable'); });
  p.doc.getElementById('conversation-inbox-edit').dispatchEvent(new p.dom.window.Event('submit', {bubbles: true, cancelable: true}));
  await tick();
  assert.equal(p.doc.getElementById('conversation-inbox-edit-new-files').disabled, true);
  p.set(async () => p.response({...state([{...item, revision: 2, text: 'Revised'}]), item: {...item, revision: 2, text: 'Revised'}}));
  p.doc.getElementById('conversation-inbox-edit').dispatchEvent(new p.dom.window.Event('submit', {bubbles: true, cancelable: true}));
  await tick();
  button(p, 'Edit pending text or files').click();
  assert.equal(p.doc.getElementById('conversation-inbox-edit-text').readOnly, false);
  assert.equal(p.doc.getElementById('conversation-inbox-edit-new-files').disabled, false);
  p.dom.window.close();
});

test('naming an operation does not need a secure browser context', async () => {
  const p = page(); await tick(); compose(p);
  Object.defineProperty(p.dom.window.crypto, 'randomUUID', {value: undefined, configurable: true});
  p.set(async () => p.response({...state([{...item, files: []}]), item: {...item, text: 'Send while current task runs', files: []}}));
  await p.api.send(p.form);
  assert.match(formBody(p.calls.at(-1)).operation_id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  p.dom.window.close();
});

test('a page restored from the browser cache refreshes and keeps polling', async () => {
  const p = page(); await tick();
  p.dom.window.dispatchEvent(new p.dom.window.Event('pagehide'));
  const before = p.calls.filter(call => call.url.endsWith('/4')).length;
  const restored = new p.dom.window.Event('pageshow'); restored.persisted = true;
  p.dom.window.dispatchEvent(restored);
  await tick();
  assert.ok(p.calls.filter(call => call.url.endsWith('/4')).length > before, 'a restored page reads the inbox again');
  p.dom.window.close();
});
