const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {JSDOM}=require('jsdom'),base=path.resolve(__dirname,'../../maverick_dashboard');
const html=fs.readFileSync(path.join(base,'templates/_connection_setup.html'),'utf8'),source=fs.readFileSync(path.join(base,'static/lightwork-connection-setup.js'),'utf8');
const context='a'.repeat(64),state='b'.repeat(43),key='lightwork:connection-consent:v1',origin='https://lightwork.example',nativeTicket='ab'.repeat(256)+'.'+'c'.repeat(64);
const profiles=[{id:'google-drive',label:'Google Drive evidence',provider:'google',connector:'gdrive',origin:'https://www.googleapis.com',scopes:['https://www.googleapis.com/auth/drive.readonly']},{id:'jira-cloud',label:'Jira Cloud reviewed delivery',provider:'atlassian',connector:'jira',origin:'https://api.atlassian.com',scopes:['read:jira-work','write:jira-work','offline_access']}];
function overview(extra={}){return{context,workspace_context:'f'.repeat(64),can_manage_applications:true,enabled:true,connections_enabled:true,desktop_return_available:false,callback_uri:origin+'/connections',profiles,applications:[{provider:'google',registration_scope:'workspace',client_id:'synthetic-client',revision:'c'.repeat(32),has_secret:true}],connections:[],live_provider_verified:false,...extra};}
async function fixture(t,{data=overview(),query='',stored=null,task=null,draft=null,intercept=()=>undefined,blockedStorage=false,nativeInvoke=null}={}){const dom=new JSDOM(html,{url:(nativeInvoke?'http://127.0.0.1:8765':origin)+'/connections'+query,runScripts:'outside-only'});t.after(()=>dom.window.close());const w=dom.window,calls=[];if(nativeInvoke)w.__TAURI__={core:{invoke:nativeInvoke}};w.eval(fs.readFileSync(path.join(base,'static/lightwork-native-account-return.js'),'utf8'));if(stored)w.sessionStorage.setItem(key,JSON.stringify(stored));if(task)w.sessionStorage.setItem('lightwork:connection-task:v1',JSON.stringify(task));if(draft)w.sessionStorage.setItem('lightwork:connection-draft:v1',JSON.stringify(draft));if(blockedStorage)w.Storage.prototype.setItem=()=>{throw new Error('Storage blocked');};
  w.fetch=async(url,options={})=>{const call={url,options,body:options.body?JSON.parse(options.body):undefined,atSearch:w.location.search};calls.push(call);const injected=await intercept(call);if(injected!==undefined)return injected;let result=data;if(url.endsWith('/desktop-return/prepare'))result={prepare_ticket:nativeTicket,expires_in:600};if(url.endsWith('/authorize'))result={state,expires_in:600,authorize_url:'https://accounts.google.com/o/oauth2/v2/auth?'+new URLSearchParams({state,redirect_uri:data.callback_uri})};if(url.endsWith('/cancel'))result={context,cancelled:true};if(url.endsWith('/enable'))result={enabled:true,reload_required:true};if(url.endsWith('/exchange'))result={context,connection:{name:'drive'},live_provider_verified:false};return new Response(JSON.stringify(result),{headers:{'Content-Type':'application/json'}});};
  const el=id=>w.document.getElementById('cs-'+id);const settle=async()=>{for(let i=0;i<16;i++)await new Promise(resolve=>setImmediate(resolve));};const change=(id,value)=>{el(id).value=value;el(id).dispatchEvent(new w.Event('input',{bubbles:true}));el(id).dispatchEvent(new w.Event('change',{bubbles:true}));};const check=id=>{el(id).checked=true;el(id).dispatchEvent(new w.Event('change'));};const submit=async id=>{el(id).dispatchEvent(new w.Event('submit',{bubbles:true,cancelable:true}));await settle();};w.eval(fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-access-state.js'), 'utf8'));w.eval(source);await settle();return{w,calls,el,settle,change,check,submit};}

test('provider consent is explicit, fixed and stores only its state/context match in this tab',async t=>{const h=await fixture(t);h.change('name','team-drive');await h.submit('authorize');assert.equal(h.calls.length,1);h.check('authorize-confirm');await h.submit('authorize');assert.equal(h.calls[1].body.expected_revision,'');assert.equal(h.calls[1].body.context,context);assert.deepEqual(JSON.parse(h.w.sessionStorage.getItem(key)),{state,context});assert.equal(h.el('provider-link').getAttribute('href').startsWith('https://accounts.google.com/'),true);assert.equal(h.calls.some(call=>call.url.endsWith('/exchange')),false);});
test('application-only 403 preserves account views and leaves separately authorized account sign-in available',async t=>{
  const h=await fixture(t,{intercept:call=>call.url.endsWith('/application')?new Response('<h1>Denied</h1>',{status:403}):undefined});
  h.change('name','preserved-drive');h.change('client-id','synthetic-client');h.check('app-confirm');await h.submit('application');
  assert.equal(h.el('name').value,'preserved-drive');assert.notEqual(h.el('profile').options.length,0);
  assert.equal(h.el('app-save').disabled,true);assert.equal(h.el('refresh').disabled,false);
  h.check('authorize-confirm');assert.equal(h.el('authorize-button').disabled,false);
});
test('a callback is scrubbed before fetch, consumed once and exchanged only after explicit finish consent',async t=>{const h=await fixture(t,{query:'?code=synthetic-code&state='+state+'&scope=private-scope',stored:{state,context}});assert.equal(h.w.location.search,'');assert.equal(h.calls[0].atSearch,'');assert.equal(h.w.sessionStorage.getItem(key),null);assert.equal(h.calls[0].options.headers['X-Lightwork-Connection-Context'],context);assert.equal(h.el('return').hidden,false);h.el('finish').click();await h.settle();assert.equal(h.calls.length,1);h.check('finish-confirm');h.el('finish').click();await h.settle();assert.equal(h.calls.find(call=>call.url.endsWith('/exchange')).body.code,'synthetic-code');assert.equal(h.el('return').hidden,true);assert.match(h.el('status').textContent,/No workflow was run/);});
for(const query of ['?code=synthetic-code&state=wrong','?code=one&code=two&state='+state,'?error=access_denied&error_description=secret-provider-body&state='+state])test('unmatched or denied callbacks are consumed without echoing sensitive provider data: '+query.split('&')[0],async t=>{const h=await fixture(t,{query,stored:{state,context}});assert.equal(h.w.location.search,'');assert.equal(h.w.sessionStorage.getItem(key),null);assert.equal(h.el('return').hidden,true);assert.equal(h.el('status').textContent.includes('secret-provider-body'),false);const cancellations=h.calls.filter(call=>call.url.endsWith('/cancel'));assert.equal(cancellations.length,query.includes('error=')?1:0);});
test('a different current workspace cannot replace the original callback context',async t=>{const h=await fixture(t,{data:overview({context:'d'.repeat(64)}),query:'?code=synthetic-code&state='+state,stored:{state,context}});assert.equal(h.el('return').hidden,true);assert.equal(h.el('refresh').disabled,true);assert.match(h.el('status').textContent,/workspace changed/);assert.equal(h.calls.length,1);});
for(const status of [401,403])test(`HTML ${status} clears private application and callback state before reading its body`,async t=>{let denied=false,parsed=false;const h=await fixture(t,{query:'?code=synthetic-code&state='+state,stored:{state,context},intercept:call=>denied?{status,ok:false,text:async()=>{parsed=true;return '<h1>Login</h1>';}}:undefined});h.change('client-secret','synthetic-private-app-secret');denied=true;h.el('refresh').click();await h.settle();assert.equal(parsed,false);assert.equal(h.el('client-secret').value,'');assert.equal(h.el('client-id').value,'');assert.equal(h.el('connections').textContent,'');assert.equal(h.el('return').hidden,true);assert.equal(h.el('refresh').disabled,true);assert.equal(h.el('finish').disabled,true);});
test('an uncertain exchange is never retried and cannot retain the authorization code for a later click',async t=>{let writes=0;const h=await fixture(t,{query:'?code=synthetic-code&state='+state,stored:{state,context},intercept:call=>call.url.endsWith('/exchange')?(writes++,new Response('<h1>Unavailable</h1>',{status:503})):undefined});h.check('finish-confirm');h.el('finish').click();h.el('finish').click();await h.settle();assert.equal(writes,1);assert.equal(h.el('return').hidden,true);assert.equal(h.el('finish').disabled,true);assert.match(h.el('status').textContent,/will not be retried/);});
test('registration keeps the exact current revision and clears its secret after a failed save',async t=>{const h=await fixture(t,{intercept:call=>call.url.endsWith('/application')?new Response('<h1>Unavailable</h1>',{status:503}):undefined});h.change('client-id','replacement-client');h.change('client-secret','synthetic-secret');h.check('app-confirm');await h.submit('application');const call=h.calls.find(call=>call.url.endsWith('/application'));assert.equal(call.body.expected_revision,'c'.repeat(32));assert.equal(call.body.client_secret,'synthetic-secret');assert.equal(h.el('client-secret').value,'');assert.equal(h.el('client-id').value,'replacement-client');assert.equal(h.el('app-confirm').checked,false);assert.equal(h.w.sessionStorage.length,0);});
test('reconnection uses the selected named connection revision and retains its reviewed destination',async t=>{const h=await fixture(t,{data:overview({connections:[{name:'existing',revision:'e'.repeat(32),oauth:{profile:'google-drive',renewal_state:'pending'}}]})});h.change('existing','existing');assert.equal(h.el('name').readOnly,true);h.check('authorize-confirm');await h.submit('authorize');const call=h.calls.find(call=>call.url.endsWith('/authorize'));assert.equal(call.body.expected_revision,'e'.repeat(32));assert.equal(call.body.name,'existing');assert.match(h.el('connections').textContent,/not confirmed; reconnect/);});
test('unapproved destinations and blocked session storage cannot expose a provider continuation link',async t=>{for(const options of [{intercept:call=>call.url.endsWith('/authorize')?new Response(JSON.stringify({state,expires_in:600,authorize_url:'https://attacker.test/?state='+state})):undefined},{blockedStorage:true}]){const h=await fixture(t,options);h.change('name','team-drive');h.check('authorize-confirm');await h.submit('authorize');assert.equal(h.el('departure').hidden,true);assert.equal(h.el('provider-link').hasAttribute('href'),false);}});
test('enabling account authorization needs separate consent and then a deliberate reload',async t=>{const h=await fixture(t,{data:overview({enabled:false,applications:[]})});assert.equal(h.el('options').hidden,true);h.el('enable-button').click();await h.settle();assert.equal(h.calls.length,1);h.check('enable-confirm');h.el('enable-button').click();await h.settle();assert.equal(h.calls.length,2);assert.equal(h.el('enable-button').disabled,true);assert.match(h.el('refresh').textContent,/Reload/);assert.equal(h.el('refresh').disabled,false);});

const task=()=>({context:'f'.repeat(64),case_id:'vendor-case-42',created_at:Date.now()});
const draft=()=>({context,profile:'google-drive',name:'original-drive',existing:'',revision:'',site:'',created_at:Date.now()});
test('denial restores the reviewed non-secret connection choice and a same-workspace return to the original task',async t=>{
  const h=await fixture(t,{query:'?error=access_denied&error_description=private-provider-message&state='+state,stored:{state,context},task:task(),draft:draft()});
  assert.equal(h.w.location.search,'');assert.equal(h.calls[0].atSearch,'');assert.equal(h.el('name').value,'original-drive');
  assert.equal(h.el('task-return').hidden,false);assert.equal(h.el('task-link').getAttribute('href'),'/third-party/vendor-onboarding?case=vendor-case-42');
  assert.match(h.el('status').textContent,/denied/);assert.equal(h.el('authorize-confirm').checked,false);assert.equal(h.el('authorize-button').disabled,true);
  assert.equal(h.calls.filter(call=>call.url.endsWith('/cancel')).length,1);assert.equal(h.el('retry').hidden,false);assert.equal(h.w.document.body.textContent.includes('private-provider-message'),false);
});
test('a failed status refresh keeps input read-only until a fresh read and never repeats authorization',async t=>{
  let unavailable=false;const h=await fixture(t,{task:task(),intercept:call=>unavailable&&call.options.method==='GET'?new Response('Unavailable',{status:503}):undefined});
  h.change('name','preserved-drive');h.check('authorize-confirm');unavailable=true;h.el('refresh').click();await h.settle();
  assert.equal(h.el('name').value,'preserved-drive');assert.equal(h.el('authorize-confirm').checked,false);h.check('authorize-confirm');assert.equal(h.el('authorize-button').disabled,true);
  unavailable=false;h.el('refresh').click();await h.settle();assert.equal(h.el('name').value,'preserved-drive');assert.equal(h.el('authorize-confirm').checked,false);
  assert.equal(h.el('task-return').hidden,false);assert.equal(h.calls.some(call=>call.options.method!=='GET'),false);
});
test('a different workspace or invalid stored task cannot produce a return link',async t=>{
  for(const value of [{...task(),context:'e'.repeat(64)},{...task(),case_id:'//attacker.test'},{...task(),created_at:Date.now()-86400001}]){
    const h=await fixture(t,{task:value});assert.equal(h.el('task-return').hidden,true);assert.equal(h.el('task-link').hasAttribute('href'),false);
    assert.equal(h.w.sessionStorage.getItem('lightwork:connection-task:v1'),null);
  }
});
test('customer connection setup uses the installed registration and cannot open or submit operator controls',async t=>{
  const h=await fixture(t,{data:overview({can_manage_applications:false,applications:[{provider:'google',configured:true,registration_scope:'workspace'}]})});
  assert.equal(h.el('app-details').hidden,true);assert.equal(h.el('app-save').disabled,true);h.check('app-confirm');await h.submit('application');
  assert.equal(h.calls.length,1);h.change('name','customer-drive');h.check('authorize-confirm');await h.submit('authorize');assert.equal(h.calls.length,2);
  const missing=await fixture(t,{data:overview({can_manage_applications:false,applications:[]})});assert.equal(missing.el('app-details').hidden,true);
  assert.match(missing.el('profile-status').textContent,/installation administrator/i);assert.doesNotMatch(missing.el('profile-status').textContent,/register your/i);
  const disabled=await fixture(t,{data:overview({enabled:false,can_manage_applications:false,applications:[]})});assert.equal(disabled.el('enable').hidden,true);assert.equal(disabled.el('options').hidden,true);assert.match(disabled.el('status').textContent,/installation administrator.*enable/i);
});
test('saved connection shows provider account, Lightwork owner, workspace and scope status',async t=>{
  const connection={name:'jira-production',revision:'e'.repeat(32),owner:'user:owner@example.test',oauth:{profile:'jira-cloud',renewal_state:'ready',site_url:'https://customer.atlassian.net',identity:{provider:'atlassian',subject:'account-42',display_name:'Alex Reviewer',email:'alex@example.test',account_status:'active'},workspace:{provider_id:'f13718a7-c4a3-49ac-8db9-20f1da1a3af9',name:'Customer Jira',url:'https://customer.atlassian.net'},requested_scopes:['read:me','read:jira-work','write:jira-work','offline_access'],granted_scopes:['read:me','read:jira-work','write:jira-work','offline_access'],scope_status:'token_response'}};
  const h=await fixture(t,{data:overview({connections:[connection]})});const text=h.el('connections').textContent;
  assert.match(text,/Connected as Alex Reviewer · alex@example.test/);assert.match(text,/Set up by: owner@example.test/);assert.doesNotMatch(text,/user:owner/);assert.match(text,/Provider workspace: Customer Jira/);assert.match(text,/Access the provider gave:.*Read Jira issues and projects/);assert.equal(h.el('connections').querySelector('details')!==null,true);
});

const nativeCallback='http://127.0.0.1:8766/connections',nativeHandle='d'.repeat(64);
function nativeOverview(){return overview({callback_uri:'http://127.0.0.1:8765/connections',desktop_return_enabled:true,desktop_return_available:true,desktop_callback_uri:nativeCallback,applications:[{provider:'google',configured:true,registration_scope:'workspace',desktop_return:true,client_id:'synthetic-client',revision:'c'.repeat(32),has_secret:true}]});}
function nativeAuthorize(){return new Response(JSON.stringify({state,expires_in:600,native_launch_ticket:nativeTicket,authorize_url:'https://accounts.google.com/o/oauth2/v2/auth?'+new URLSearchParams({state,redirect_uri:nativeCallback,response_type:'code',client_id:'synthetic-client',code_challenge:state,code_challenge_method:'S256'})}));}
test('native return stays in the signed-in page and requires explicit Finish before the only exchange',async t=>{
  const commands=[];const h=await fixture(t,{data:nativeOverview(),task:task(),intercept:call=>call.url.endsWith('/authorize')?nativeAuthorize():undefined,nativeInvoke:async(command,payload)=>{
    commands.push({command,payload});if(command==='prepare_oauth_return')return{handle:nativeHandle,context,callback_uri:nativeCallback,return_profile:'desktop-loopback-v1',expires_in:600};
    if(command==='consume_oauth_return')return{outcome:'returned',context,state,code:'synthetic-native-code'};return null;
  }});
  h.change('name','native-drive');h.check('authorize-confirm');await h.submit('authorize');
  assert.equal(commands[0]?.command,'prepare_oauth_return');const authorizeCall=h.calls.find(call=>call.url.endsWith('/authorize'));assert.equal(authorizeCall.body.return_profile,'desktop-loopback-v1');assert.equal(authorizeCall.body.native_handle,nativeHandle);assert.equal(authorizeCall.body.prepare_ticket,nativeTicket);
  assert.equal(h.el('provider-link').getAttribute('href'),'#');h.el('provider-link').click();await new Promise(resolve=>setTimeout(resolve,25));await h.settle();
  assert.equal(h.w.location.href,'http://127.0.0.1:8765/connections');assert.equal(h.el('return').hidden,false);assert.equal(h.el('finish').disabled,true);
  assert.equal(h.calls.filter(call=>call.url.endsWith('/exchange')).length,0);assert.equal(h.w.document.body.textContent.includes('synthetic-native-code'),false);
  h.check('finish-confirm');h.el('finish').click();await h.settle();const exchanges=h.calls.filter(call=>call.url.endsWith('/exchange'));
  assert.equal(exchanges.length,1);assert.equal(exchanges[0].body.return_profile,'desktop-loopback-v1');assert.equal(exchanges[0].body.code,'synthetic-native-code');
  assert.equal(h.el('task-return').hidden,false);assert.equal(h.w.sessionStorage.getItem(key),null);
});
test('a second click on the disabled browser link cannot relaunch or cancel the active native attempt',async t=>{
  const commands=[];const h=await fixture(t,{data:nativeOverview(),task:task(),intercept:call=>call.url.endsWith('/authorize')?nativeAuthorize():undefined,nativeInvoke:async(command,payload)=>{
    commands.push({command,payload});if(command==='prepare_oauth_return')return{handle:nativeHandle,context,callback_uri:nativeCallback,return_profile:'desktop-loopback-v1',expires_in:600};if(command==='consume_oauth_return')return{outcome:'pending',context};return null;
  }});
  h.change('name','native-drive');h.check('authorize-confirm');await h.submit('authorize');h.el('provider-link').click();await h.settle();
  assert.equal(h.el('provider-link').hasAttribute('href'),false);h.el('provider-link').click();await h.settle();
  assert.equal(commands.filter(call=>call.command==='launch_oauth_return').length,1);assert.equal(commands.filter(call=>call.command==='cancel_oauth_return').length,0);assert.equal(h.calls.filter(call=>call.url.endsWith('/cancel')).length,0);assert.equal(h.el('departure').hidden,false);assert.match(h.el('status').textContent,/Waiting for the provider/);
});
test('occupied native return port blocks authorization before any provider URL or backend consent is created',async t=>{
  const h=await fixture(t,{data:nativeOverview(),task:task(),nativeInvoke:async()=>{throw new Error('synthetic-private-native-detail');}});
  h.change('name','preserved-drive');h.check('authorize-confirm');await h.submit('authorize');assert.equal(h.calls.filter(call=>call.url.endsWith('/authorize')).length,0);assert.equal(h.calls.filter(call=>call.url.endsWith('/desktop-return/prepare')).length,1);
  assert.equal(h.el('name').value,'preserved-drive');assert.equal(h.el('departure').hidden,true);assert.equal(h.el('task-return').hidden,false);
  assert.match(h.el('status').textContent,/port is unavailable/);assert.doesNotMatch(h.el('status').textContent,/private-native-detail/);
});

test('failed system-browser launch closes native state and retires the exact server consent',async t=>{
  const commands=[];const h=await fixture(t,{data:nativeOverview(),task:task(),intercept:call=>call.url.endsWith('/authorize')?nativeAuthorize():undefined,nativeInvoke:async(command,payload)=>{
    commands.push({command,payload});if(command==='prepare_oauth_return')return{handle:nativeHandle,context,callback_uri:nativeCallback,return_profile:'desktop-loopback-v1',expires_in:600};if(command==='launch_oauth_return')throw new Error('synthetic-private-launch');return null;
  }});
  h.change('name','native-drive');h.check('authorize-confirm');await h.submit('authorize');h.el('provider-link').click();await h.settle();
  const cancellations=h.calls.filter(call=>call.url.endsWith('/cancel'));assert.equal(cancellations.length,1);assert.equal(cancellations[0].body.state,state);assert.equal(cancellations[0].body.return_profile,'desktop-loopback-v1');
  assert.equal(commands.filter(call=>call.command==='launch_oauth_return').length,1);assert.equal(commands.filter(call=>call.command==='cancel_oauth_return').length,1);assert.equal(h.el('departure').hidden,true);assert.equal(h.el('retry').hidden,false);assert.equal(h.el('refresh').disabled,false);assert.doesNotMatch(h.el('status').textContent,/synthetic-private-launch/);
});

test('explicit native cancellation retires the exact server consent after closing the listener and keeps the original task',async t=>{
  const commands=[];const h=await fixture(t,{data:nativeOverview(),task:task(),intercept:call=>call.url.endsWith('/authorize')?nativeAuthorize():call.url.endsWith('/cancel')?new Response(JSON.stringify({context,cancelled:true})):undefined,nativeInvoke:async(command,payload)=>{
    commands.push({command,payload});if(command==='prepare_oauth_return')return{handle:nativeHandle,context,callback_uri:nativeCallback,return_profile:'desktop-loopback-v1',expires_in:600};return null;
  }});
  h.change('name','native-drive');h.check('authorize-confirm');await h.submit('authorize');h.el('cancel-departure').click();await h.settle();
  const cancelled=h.calls.filter(call=>call.url.endsWith('/cancel'));assert.equal(cancelled.length,1);
  assert.equal(cancelled[0].body.state,state);assert.equal(cancelled[0].body.return_profile,'desktop-loopback-v1');
  assert.equal(commands.filter(call=>call.command==='cancel_oauth_return').length,1);assert.equal(h.el('departure').hidden,true);
  assert.equal(h.el('task-return').hidden,false);assert.equal(h.el('name').value,'native-drive');assert.equal(h.calls.some(call=>call.url.endsWith('/exchange')),false);
});

test('an uncertain server cancellation drops native authority and does not claim durable cancellation',async t=>{
  const h=await fixture(t,{data:nativeOverview(),task:task(),intercept:call=>call.url.endsWith('/authorize')?nativeAuthorize():call.url.endsWith('/cancel')?new Response('Unavailable',{status:503}):undefined,nativeInvoke:async command=>command==='prepare_oauth_return'?{handle:nativeHandle,context,callback_uri:nativeCallback,return_profile:'desktop-loopback-v1',expires_in:600}:null});
  h.change('name','native-drive');h.check('authorize-confirm');await h.submit('authorize');h.el('cancel-departure').click();await h.settle();
  assert.equal(h.el('departure').hidden,true);assert.equal(h.el('return').hidden,true);assert.match(h.el('status').textContent,/closed locally.*cancellation could not be confirmed/i);assert.equal(h.el('authorize-button').disabled,true);
});

test('failed native cancellation keeps the cancel control and retries before server retirement',async t=>{
  let failClose=true;const commands=[];const h=await fixture(t,{data:nativeOverview(),task:task(),intercept:call=>call.url.endsWith('/authorize')?nativeAuthorize():undefined,nativeInvoke:async(command)=>{commands.push(command);if(command==='prepare_oauth_return')return{handle:nativeHandle,context,callback_uri:nativeCallback,return_profile:'desktop-loopback-v1',expires_in:600};if(command==='cancel_oauth_return'&&failClose)throw new Error('synthetic-private-close');return null;}});
  h.change('name','native-drive');h.check('authorize-confirm');await h.submit('authorize');h.el('cancel-departure').click();await h.settle();
  assert.equal(h.el('departure').hidden,false);assert.equal(h.el('cancel-departure').disabled,false);assert.equal(h.el('provider-link').hasAttribute('href'),false);assert.match(h.el('status').textContent,/could not be closed/i);assert.doesNotMatch(h.el('status').textContent,/private-close/);assert.equal(h.calls.filter(call=>call.url.endsWith('/cancel')).length,0);
  failClose=false;h.el('cancel-departure').click();await h.settle();assert.equal(h.el('departure').hidden,true);assert.equal(h.calls.filter(call=>call.url.endsWith('/cancel')).length,1);assert.equal(commands.filter(command=>command==='cancel_oauth_return').length,2);
});

// The native sign-in return settles through several timers and promises; under
// load a fixed short wait is not enough, so wait for the state being checked.
async function until(h,predicate){const deadline=Date.now()+5000;while(!predicate()&&Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,5));await h.settle();}
test('refresh retries a transiently failed native-denial retirement without losing its state',async t=>{
  let cancelPosts=0;const h=await fixture(t,{data:nativeOverview(),task:task(),intercept:call=>call.url.endsWith('/authorize')?nativeAuthorize():call.url.endsWith('/cancel')&&++cancelPosts===1?new Response('Unavailable',{status:503}):undefined,nativeInvoke:async command=>{if(command==='prepare_oauth_return')return{handle:nativeHandle,context,callback_uri:nativeCallback,return_profile:'desktop-loopback-v1',expires_in:600};if(command==='consume_oauth_return')return{outcome:'denied',context};return null;}});
  h.change('name','native-drive');h.check('authorize-confirm');await h.submit('authorize');h.el('provider-link').click();await until(h,()=>/could not be retired/.test(h.el('status').textContent));
  assert.equal(cancelPosts,1);assert.match(h.el('status').textContent,/could not be retired/);assert.notEqual(h.w.sessionStorage.getItem('lightwork:connection-retirement:v1'),null);assert.equal(h.el('authorize-button').disabled,true);
  h.el('refresh').click();await h.settle();assert.equal(cancelPosts,2);assert.equal(h.w.sessionStorage.getItem('lightwork:connection-retirement:v1'),null);assert.equal(h.el('retry').hidden,false);assert.equal(h.el('refresh').disabled,false);
});

test('thirty-two verified native denials retire every consent and remain retryable',async t=>{
  const h=await fixture(t,{data:nativeOverview(),task:task(),intercept:call=>call.url.endsWith('/authorize')?nativeAuthorize():undefined,nativeInvoke:async command=>{if(command==='prepare_oauth_return')return{handle:nativeHandle,context,callback_uri:nativeCallback,return_profile:'desktop-loopback-v1',expires_in:600};if(command==='consume_oauth_return')return{outcome:'denied',context};return null;}});
  h.change('name','native-drive');
  for(let index=0;index<32;index++){h.check('authorize-confirm');await h.submit('authorize');h.el('provider-link').click();await until(h,()=>!h.el('retry').hidden);assert.equal(h.el('retry').hidden,false);assert.equal(h.el('departure').hidden,true);if(index<31)h.el('retry').click();}
  assert.equal(h.calls.filter(call=>call.url.endsWith('/authorize')).length,32);assert.equal(h.calls.filter(call=>call.url.endsWith('/cancel')).length,32);assert.equal(h.el('name').value,'native-drive');assert.equal(h.el('task-return').hidden,false);assert.match(h.el('status').textContent,/retry now|denied/i);
});

test('turning account connections off needs its own consent, a confirmation and a reload, and sends the chosen scope',async t=>{
  const off=call=>call.url.endsWith('/disable')?new Response(JSON.stringify({enabled:false,connections_enabled:call.body.scope!=='all',reload_required:true})):undefined;
  const h=await fixture(t,{intercept:off});
  assert.equal(h.el('disable').hidden,false);assert.equal(h.el('disable-button').disabled,true);
  h.el('disable-button').click();await h.settle();assert.equal(h.calls.length,1);
  h.check('disable-confirm');let asked='';h.w.mvConfirm=async message=>{asked=message;return false;};
  h.el('disable-button').click();await h.settle();assert.match(asked,/Nothing is deleted/);assert.equal(h.calls.some(call=>call.url.endsWith('/disable')),false);
  h.w.mvConfirm=async()=>true;h.check('disable-confirm');h.check('disable-scope-all');
  h.el('disable-button').click();await h.settle();
  const call=h.calls.find(call=>call.url.endsWith('/disable'));assert.equal(call.body.scope,'all');assert.equal(call.body.confirm,true);assert.equal(call.body.context,context);
  assert.match(h.el('status').textContent,/Nothing was deleted/);assert.match(h.el('refresh').textContent,/Reload/);assert.equal(h.el('disable-button').disabled,true);
});
test('only installation administrators see the turn-off controls, and desktop returns turn off separately',async t=>{
  const customer=await fixture(t,{data:overview({can_manage_applications:false})});assert.equal(customer.el('disable').hidden,true);assert.equal(customer.el('native-disable').hidden,true);
  const off=await fixture(t,{data:overview({enabled:false})});assert.equal(off.el('disable').hidden,true);
  const h=await fixture(t,{data:overview({desktop_return_enabled:true,desktop_return_available:true}),intercept:call=>call.url.endsWith('/desktop-return/disable')?new Response(JSON.stringify({enabled:false,reload_required:true})):undefined});
  assert.equal(h.el('native-disable').hidden,false);h.check('native-disable-confirm');h.el('native-disable-button').click();await h.settle();
  const call=h.calls.find(call=>call.url.endsWith('/desktop-return/disable'));assert.equal(call.body.confirm,true);assert.equal(h.calls.some(call=>call.url.endsWith('/connection-setup/disable')),false);
  assert.match(h.el('status').textContent,/Accounts already connected keep working/);
});

test('without a named sign-in the panel says so plainly and does not report lost access',async t=>{
  const message='Connecting an account by signing in to it needs a named Lightwork sign-in, so each connected account belongs to a person. Connections that use a key work without it. You can set up named sign-in now.';
  const h=await fixture(t,{data:{account_sign_in_available:false,can_set_up_sign_in:true,message}});
  assert.equal(h.el('status').textContent,message);
  assert.doesNotMatch(h.el('status').textContent,/Sign in again|access changed/i);
  assert.equal(h.el('options').hidden,true);assert.equal(h.el('enable').hidden,true);assert.equal(h.el('refresh').hidden,true);
  assert.equal(h.el('signin-link').hidden,false);assert.equal(h.el('signin-link').getAttribute('href'),'/start');
  // The page treats lost access as a lock; this is not that: nothing cleared, no further requests.
  assert.equal(h.w.document.getElementById('connection-setup').dataset.accessDenied,undefined);
  assert.equal(h.calls.length,1);
});
test('the set-up link appears only where named sign-in can actually be set up from this app',async t=>{
  const h=await fixture(t,{data:{account_sign_in_available:false,can_set_up_sign_in:false,message:'Connecting an account by signing in to it needs a named Lightwork sign-in. Ask whoever manages Lightwork sign-in to set it up.'}});
  assert.equal(h.el('signin-link').hidden,true);assert.match(h.el('status').textContent,/Ask whoever manages/);
  const normal=await fixture(t);assert.equal(normal.el('signin-link').hidden,true);
});
