const test=require('node:test'), assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {JSDOM}=require('jsdom');
const source=fs.readFileSync(path.join(__dirname,'../../maverick_dashboard/static/lightwork-template-connections.js'),'utf8');
const tick=()=>new Promise(resolve=>setTimeout(resolve,0));
function page(fetch){const dom=new JSDOM('<label data-parameter-row="account"><select data-connected-account required></select></label>',{url:'http://localhost/templates',runScripts:'outside-only'});dom.window.fetch=fetch;dom.window.eval(source);return dom;}
const response=(choices,context='same')=>({ok:true,status:200,json:async()=>({context,choices})});
test('exact selected generation survives refresh; rotation never selects replacement',async()=>{
 let value='first';const dom=page(async()=>response([{name:'<private account>',connector:'slack_api',value}]));await tick();
 const select=dom.window.document.querySelector('select');assert.equal(select.options[1].textContent,'<private account> (slack_api)');assert.equal(select.querySelector('private'),null);
 select.value='first';dom.window.document.querySelector('button').click();await tick();assert.equal(select.value,'first');
 value='rotated';dom.window.document.querySelector('button').click();await tick();assert.equal(select.value,'');assert.equal(select.checkValidity(),false);dom.window.close();
});
test('permission refusal clears private account choices and locks retry',async()=>{
 let revoked=false;const dom=page(async()=>revoked?{status:403}:response([{name:'private',connector:'slack_api',value:'pin'}]));await tick();revoked=true;dom.window.document.querySelector('button').click();await tick();
 assert.equal(dom.window.document.querySelector('select').options.length,0);assert.equal(dom.window.document.querySelector('button').disabled,true);assert.ok(!dom.window.document.body.textContent.includes('private'));dom.window.close();
});
test('workspace switch refuses late private results',async()=>{
 let done;const dom=page(()=>new Promise(resolve=>done=resolve));dom.window.document.dispatchEvent(new dom.window.Event('lightwork:workspace-changed'));done(response([{name:'private',connector:'slack_api',value:'pin'}]));await tick();
 assert.equal(dom.window.document.querySelector('select').options.length,0);assert.ok(!dom.window.document.body.textContent.includes('private'));dom.window.close();
});
test('unavailable or malformed response is retryable, never a valid empty account list',async()=>{
 let broken=true;const dom=page(async()=>broken?{ok:false,status:503,json:async()=>({})}:response([]));await tick();const select=dom.window.document.querySelector('select');assert.equal(select.validationMessage,'Account selection is unavailable. Refresh the page and try again.');assert.equal(dom.window.document.querySelector('button').disabled,false);
 broken=false;dom.window.document.querySelector('button').click();await tick();assert.equal(select.value,'');assert.equal(select.options.length,1);dom.window.close();
});

test('encrypted composer recovery retains exact selections and old text-only drafts clear them',()=>{
 const dom=new JSDOM('<div data-draft-host><section data-draft-panel inert></section><form action="/chat/send"><input name="title"><textarea name="description"></textarea><input name="connection_references" value="[]"></form><p data-draft-note></p></div>',{url:'http://localhost/chat',runScripts:'outside-only'});
 let options;dom.window.mvDraftRecovery={create:value=>{options=value;return {};}};
 dom.window.eval(fs.readFileSync(path.join(__dirname,'../../maverick_dashboard/static/lightwork-chat-drafts.js'),'utf8'));
 const pin=JSON.stringify([{name:'selected',revision:'exact-generation',connector:'gdrive',owner:'user:employee',tenant:'team'}]);
 const field=dom.window.document.querySelector('[name="connection_references"]');field.value=pin;
 assert.equal(options.read().connection_references,pin);field.value='[]';options.restore({title:'Restored',description:'Review',connection_references:pin});assert.equal(field.value,pin);
 options.restore({title:'Older draft',description:'Unbound'});assert.equal(field.value,'[]');dom.window.close();
});
