'use strict';
const{test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{JSDOM}=require('jsdom');
const folder=path.resolve(__dirname,'../../maverick_dashboard'),html=fs.readFileSync(path.join(folder,'templates/task_file_recovery.html'),'utf8').replace('{{ goal.id }}','12').replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,'');
const context='a'.repeat(64),version='b'.repeat(64),state={context,capture_enabled:true,has_history:true,can_enable:true,goal_id:12};
const preview={context,goal_id:12,version,operation:{},files:[{path:'draft.txt',diff:'-task draft\n+original',current:{exists:true,bytes:10,sha256:'c'.repeat(64)},restored:{exists:true,bytes:8,sha256:'d'.repeat(64)}}]};
async function fixture(intercept,setup=()=>{}){const dom=new JSDOM(html,{url:'https://app.example/chat/goal/12/files',runScripts:'outside-only'}),w=dom.window,calls=[];w.fetch=async(url,options)=>{calls.push({url,options});const result=intercept?await intercept(url,options):url.endsWith('/preview')?preview:state;return result instanceof Response?result:new Response(JSON.stringify(result));};w.mvConfirm=async()=>true;setup(w);w.eval(fs.readFileSync(path.join(folder,'static/lightwork-task-file-recovery.js'),'utf8'));const settle=async()=>{for(let i=0;i<8;i++)await new Promise(r=>setImmediate(r));};await settle();return{w,calls,settle,el:id=>w.document.getElementById('tf-'+id)};}
test('opening and previewing never restores; confirmed action binds exact reviewed version',async t=>{let posted;const ui=await fixture((url,options)=>{if(options.method==='POST'){posted=JSON.parse(options.body);return{context,operation:{state:'complete',...posted}};}return url.endsWith('/preview')?preview:state;});t.after(()=>ui.w.close());assert.equal(ui.calls.length,1);ui.el('preview').click();await ui.settle();assert.equal(ui.el('restore').disabled,true);assert.match(ui.el('files').textContent,/original/);ui.el('confirm').checked=true;ui.el('confirm').dispatchEvent(new ui.w.Event('change'));ui.el('restore').click();await ui.settle();assert.equal(posted.version,version);assert.equal(posted.context,context);assert.equal(posted.confirm,true);assert.match(ui.el('status').textContent,/restored/);assert.equal(ui.el('files').children.length,0);});
test('refresh clears confirmation; an interrupted request is reused after reload',async t=>{const retained={...preview,operation:{state:'applying',version:'e'.repeat(64),request_id:'interrupted-request'}};let payload;const ui=await fixture((url,options)=>{if(options.method==='POST'){payload=JSON.parse(options.body);return new Response('synthetic temporary failure',{status:503});}return url.endsWith('/preview')?retained:state;});t.after(()=>ui.w.close());ui.el('preview').click();await ui.settle();ui.el('confirm').checked=true;ui.el('confirm').dispatchEvent(new ui.w.Event('change'));ui.el('restore').click();await ui.settle();assert.equal(payload.request_id,'interrupted-request');assert.equal(payload.version,'e'.repeat(64));assert.equal(ui.el('confirm').checked,false);ui.el('refresh').click();await ui.settle();assert.equal(ui.el('files').children.length,0);assert.equal(ui.el('restore').disabled,true);});
test('HTML auth loss and changed workspace clear private file previews and lock actions',async t=>{let failure=false;const ui=await fixture(url=>failure?new Response('<h1>Sign in</h1>',{status:401}):url.endsWith('/preview')?preview:state);t.after(()=>ui.w.close());ui.el('preview').click();await ui.settle();failure=true;ui.el('refresh').click();await ui.settle();assert.equal(ui.el('files').children.length,0);assert.equal(ui.el('preview').disabled,true);assert.equal(ui.el('refresh').disabled,true);const other=await fixture(url=>url.endsWith('/preview')?{...preview,context:'f'.repeat(64)}:state);t.after(()=>other.w.close());other.el('preview').click();await other.settle();assert.equal(other.el('files').children.length,0);assert.equal(other.el('restore').disabled,true);});
test('an administrator can turn file protection off after confirming, and saved copies are kept',async t=>{let on=true,posted=null;const ui=await fixture((url,options)=>{if(options.method==='POST'&&url.endsWith('/disable')){posted=JSON.parse(options.body);on=false;return{context,capture_enabled:false,strict:false};}return{...state,capture_enabled:on};});t.after(()=>ui.w.close());
  assert.equal(ui.el('disable-panel').hidden,false);assert.equal(ui.el('enable-panel').hidden,true);assert.equal(ui.el('disable').disabled,true);
  ui.el('disable-confirm').checked=true;ui.el('disable-confirm').dispatchEvent(new ui.w.Event('change'));let asked='';ui.w.mvConfirm=async message=>{asked=message;return false;};ui.el('disable').click();await ui.settle();
  assert.match(asked,/Copies already kept stay/);assert.equal(posted,null);ui.w.mvConfirm=async()=>true;ui.el('disable-confirm').checked=true;ui.el('disable-confirm').dispatchEvent(new ui.w.Event('change'));ui.el('disable').click();await ui.settle();
  assert.equal(posted.confirm,true);assert.equal(posted.context,context);assert.match(ui.el('status').textContent,/were not deleted/);assert.equal(ui.el('disable-panel').hidden,true);assert.equal(ui.el('enable-panel').hidden,false);});
test('people who cannot change installation settings see no turn-off control',async t=>{const ui=await fixture(()=>({...state,can_enable:false}));t.after(()=>ui.w.close());assert.equal(ui.el('disable-panel').hidden,true);});
test('restoring asks for a plain confirmation first; declining sends nothing',async t=>{let posted=null,asked='';const ui=await fixture((url,options)=>{if(options.method==='POST'){posted=JSON.parse(options.body);return{context,operation:{state:'complete',...posted}};}return url.endsWith('/preview')?preview:state;});t.after(()=>ui.w.close());ui.w.mvConfirm=async message=>{asked=message;return false;};ui.el('preview').click();await ui.settle();ui.el('confirm').checked=true;ui.el('confirm').dispatchEvent(new ui.w.Event('change'));ui.el('restore').click();await ui.settle();assert.match(asked,/new files this task made are removed/);assert.equal(posted,null);});

const installLocale=require('./helpers/recovery_review_i18n');
const fr=(text)=>({text,lang:'fr'});
const restoreMessage='Put back the reviewed files? Each file listed goes back to its saved original, and new files this task made are removed.';
const recoveryCatalog={
  'Restore files':fr('Restaurer les fichiers'),
  'Restore reviewed files':fr('Restaurer les fichiers examinés'),
  'File fingerprints':fr('Empreintes des fichiers'),
  'Now: {size}':fr('Actuellement : {size}'),
  'Review each listed change before confirming.':fr('Vérifiez chaque modification avant de confirmer.'),
  'Saved originals are available. Stop this task and any task using the same folder, then review the changes.':fr('Arrêtez les tâches avant de vérifier les modifications.'),
  'Current task access is unavailable. Sign in and reload this task.':fr('Connectez-vous et rechargez cette tâche.'),
  [restoreMessage]:fr('Restaurer les fichiers examinés ? Les fichiers créés par cette tâche seront supprimés.'),
  'Cancel':fr('Annuler'),
};
test('recovery translates controls and actual confirmation while filenames and diffs remain opaque',async t=>{
  const data={...preview,files:[{...preview.files[0],path:'Restore files',diff:'Restore files <img src=x> مرحبا',current:{...preview.files[0].current,bytes:1536}}]};
  const ui=await fixture(url=>url.endsWith('/preview')?data:state,w=>installLocale(w,{catalog:recoveryCatalog}));t.after(()=>ui.w.close());
  ui.el('preview').click();await ui.settle();
  assert.equal(ui.el('files').querySelector('h2').textContent,'Restore files');assert.equal(ui.el('files').querySelector('h2').lang,'und');
  assert.equal(ui.el('files').querySelector('pre').textContent,data.files[0].diff);assert.equal(ui.el('files').querySelector('pre').dir,'auto');assert.equal(ui.el('files').querySelector('img'),null);
  assert.equal(ui.el('files').querySelector('summary').textContent,'Empreintes des fichiers');
  assert.match(ui.el('files').textContent,/1,5/);assert.equal(ui.el('restore').lang,'fr');
  ui.w.LightworkI18n.translate();assert.equal(ui.el('files').querySelector('h2').textContent,'Restore files');
  ui.el('confirm').checked=true;ui.el('confirm').dispatchEvent(new ui.w.Event('change'));ui.el('restore').click();await ui.settle();
  const doc=ui.w.document;assert.equal(doc.getElementById('mv-confirm').open,true);assert.match(doc.getElementById('mv-confirm-msg').textContent,/seront supprimés/);assert.equal(doc.getElementById('mv-confirm-msg').lang,'fr');
  doc.getElementById('mv-confirm-cancel').click();await ui.settle();assert.equal(ui.calls.some(row=>row.options.method==='POST'),false);
});
test('opaque recovery errors cannot poison later translated success or denial status',async t=>{
  let code=200;const ui=await fixture(url=>code===422?new Response(JSON.stringify({detail:'Restore files'}),{status:422}):code===401?new Response('sign in',{status:401}):state,w=>installLocale(w,{catalog:recoveryCatalog}));t.after(()=>ui.w.close());
  code=422;ui.el('refresh').click();await ui.settle();assert.equal(ui.el('status').textContent,'Restore files');assert.equal(ui.el('status').lang,'und');
  code=200;ui.el('refresh').click();await ui.settle();assert.equal(ui.el('status').lang,'fr');assert.match(ui.el('status').textContent,/Arrêtez/);assert.equal(ui.el('status').hasAttribute('data-user-content'),false);
  code=401;ui.el('refresh').click();await ui.settle();assert.equal(ui.el('status').textContent,'Connectez-vous et rechargez cette tâche.');assert.equal(ui.el('refresh').disabled,true);
});
test('Arabic recovery uses honest English fallback regions and preserves RTL filenames',async t=>{
  const data={...preview,files:[{...preview.files[0],path:'مرحبا Restore files'}]};
  const ui=await fixture(url=>url.endsWith('/preview')?data:state,w=>installLocale(w,{language:'ar',catalog:{}}));t.after(()=>ui.w.close());
  ui.el('preview').click();await ui.settle();assert.equal(ui.el('restore').lang,'en');assert.equal(ui.el('restore').dir,'ltr');assert.equal(ui.el('files').querySelector('h2').lang,'und');assert.equal(ui.el('files').querySelector('h2').textContent,data.files[0].path);
});
