const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const {JSDOM}=require('jsdom');
const {shell} = require('./_shell');
const root=path.join(__dirname,'../../maverick_dashboard');
const code=fs.readFileSync(path.join(root,'static/lightwork-personal-data.js'),'utf8');
function boot(reply){
  const html=fs.readFileSync(path.join(root,'templates/personal_data.html'),'utf8').replace(/{%[\s\S]*?%}/g,'').replace(/{{[\s\S]*?}}/g,'');
  const dom=new JSDOM(html,{url:'https://local.example/my-data',runScripts:'outside-only'}),w=dom.window;
  const state={context:'a'.repeat(64),identity:{channels:['dashboard'],links:[],challenges:[]},sharing:{shared_source:'',revision:1},scopes:[{id:'own',channel:'dashboard',user_id:'employee',recall:false,revision:1,notes:[]}],policy:{personal_recall:false,effective_learning:{}},can_review_deletion:false};
  w.document.getElementById('pd-bootstrap').textContent=JSON.stringify(state);
  shell(w);let calls=0;w.fetch=async()=>{calls++;return reply(state);};w.confirm=()=>true;w.eval(code);
  const privateEditor=w.document.createElement('textarea');privateEditor.value='Unfinished private correction';w.document.getElementById('pd-memory').append(privateEditor);
  w.document.getElementById('pd-stores').textContent='Private retained account inventory';
  return {dom,w,privateEditor,calls:()=>calls};
}
const settle=()=>new Promise(resolve=>setTimeout(resolve,15));
for(const status of [401,403])test(`My data clears private data before parsing an HTML ${status} and blocks another action`,async()=>{
  let parsed=false;const {dom,w,privateEditor,calls}=boot(()=>({status,ok:false,json:async()=>{parsed=true;throw Error('HTML sign-in page');}}));
  w.document.getElementById('pd-refresh').click();await settle();
  assert.equal(parsed,false);assert.equal(w.document.getElementById('pd-memory').textContent,'');
  assert.equal(w.document.getElementById('pd-stores').textContent,'');assert.equal(privateEditor.isConnected,false);assert.equal(privateEditor.value,'');
  assert.equal(w.document.getElementById('pd-bootstrap').textContent,'{}');
  assert.match(w.document.getElementById('pd-status').textContent,/Private data was cleared/);
  w.document.getElementById('pd-refresh').click();await settle();assert.equal(calls(),1);dom.window.close();
});
for(const mismatch of ['response','request'])test(`My data locks on a proven ${mismatch} context change`,async()=>{
  const {dom,w}=boot(state=>mismatch==='response'?{status:200,ok:true,json:async()=>({...state,context:'b'.repeat(64)})}:{status:409,ok:false,json:async()=>({detail:'Your account or workspace changed. Refresh before changing personal data.'})});
  w.document.getElementById('pd-refresh').click();await settle();
  assert.equal(w.document.getElementById('pd-memory').textContent,'');assert.equal(w.document.getElementById('pd-refresh').disabled,true);dom.window.close();
});
for(const kind of ['network','service','revision'])test(`My data preserves unfinished edits after a ${kind} failure`,async()=>{
  const {dom,w,privateEditor}=boot(()=>{if(kind==='network')throw Error('Synthetic network interruption');return {status:kind==='service'?503:409,ok:false,json:async()=>({detail:kind==='service'?'Temporarily unavailable':'The preference revision changed. Review its current state.'})};});
  w.document.getElementById('pd-refresh').click();await settle();
  assert.equal(privateEditor.isConnected,true);assert.equal(privateEditor.value,'Unfinished private correction');
  assert.equal(w.document.getElementById('pd-refresh').disabled,false);assert.match(w.document.getElementById('pd-status').textContent,/editor text has been kept/);dom.window.close();
});
