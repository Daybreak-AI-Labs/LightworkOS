'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const source = name => fs.readFileSync(path.join(__dirname, '../../maverick_dashboard/static/', name), 'utf8');
const copy = {
  'Emergency stop': 'Arrêt d’urgence',
  'STOPPED — click to resume': 'ARRÊTÉ — cliquer pour reprendre',
  'Stop status unavailable': 'État d’arrêt indisponible',
  'Checking stop status…': 'Vérification de l’état d’arrêt…',
  'Stop work on this server? Work covered by this emergency stop pauses at its next step and waits for an authorized resume.': 'Arrêter le travail sur ce serveur ? Le travail couvert par cet arrêt d’urgence se met en pause à l’étape suivante et attend une reprise autorisée.',
  'Stop work across connected workers? Work covered by this emergency stop pauses at its next step and waits for an authorized resume.': 'Arrêter le travail sur les exécutants connectés ? Le travail couvert par cet arrêt d’urgence se met en pause à l’étape suivante et attend une reprise autorisée.',
  'Stop work': 'Arrêter le travail',
  'Cancel': 'Annuler',
  'Your workspace changed in another tab. Changes here are paused. Keep any draft you need, then reopen this page in the current workspace.': 'Votre espace de travail a changé dans un autre onglet. Les modifications ici sont suspendues. Conservez les brouillons nécessaires, puis rouvrez cette page dans l’espace de travail actuel.',
  'Reopen in current workspace': 'Rouvrir dans l’espace de travail actuel',
  'Required: {fields}': 'Obligatoire : {fields}',
  '{count} page': '{count} page',
  '{count} pages': '{count} pages',
  '{count} record shown': '{count} enregistrement affiché',
  '{count} records shown': '{count} enregistrements affichés',
  'Setting': 'Paramètre',
  'Copied to clipboard': 'Copié dans le presse-papiers',
  '{count} matching recent title.': '{count} titre récent correspondant.',
  '{count} matching recent titles.': '{count} titres récents correspondants.',
  'No recent titles match. Open task search for older chats or a match in task contents.': 'Aucun titre récent ne correspond. Ouvrez la recherche de tâches pour rechercher d’anciennes discussions ou du contenu de tâche.',
};
const tick = () => new Promise(resolve => setImmediate(resolve));
function page(html='', {language='fr', workspace=false, pendingRuntime=false, flash=null, fetch=async()=>({ok:true,json:async()=>({})})}={}) {
  const dom = new JSDOM(`<!doctype html><html lang="en"><head>${workspace ? '<meta name="lightwork-workspace-tenant" content="owned">' : ''}</head><body>${html}<div id="mv-toasts"></div><div id="mv-toasts-alert"></div><dialog id="mv-confirm"><p id="mv-confirm-msg"></p><button id="mv-confirm-cancel"></button><button id="mv-confirm-ok"></button></dialog></body></html>`, {url:'https://local.test/chat/goal/1',runScripts:'outside-only'});
  const w=dom.window, doc=w.document;
  w.matchMedia=()=>({matches:false,addEventListener(){},removeEventListener(){}});
  w.fetch=fetch;w.Headers=Headers;w.Request=Request;w.Response=Response;
  w.HTMLDialogElement.prototype.showModal=function(){this.open=true;};
  w.HTMLDialogElement.prototype.close=function(){this.open=false;};
  const config=doc.createElement('script');config.id='lightwork-i18n-data';config.type='application/json';
  config.textContent=JSON.stringify({language,locale:language==='fr'?'fr-CA':'ar-EG',catalog:language==='fr'?Object.fromEntries(Object.entries(copy).map(([s,text])=>[s,{text,lang:'fr'}])):{}});
  doc.head.appendChild(config);
  if (flash !== null) w.sessionStorage.setItem('lightwork.flash-toast', flash);
  if (!pendingRuntime) w.eval(source('lightwork-i18n.js'));
  w.eval(source('lightwork-ui.js'));
  return dom;
}

test('pending localization verifies halt immediately and later translates only its current state', async()=>{
  const calls=[];
  let completeRead;
  const pendingRead=new Promise(resolve=>{completeRead=resolve;});
  const dom=page('<a id="halt-pill" data-can-halt="true"><span id="halt-label">Checking from server</span></a>'+
    '<p data-mv-toast="Saved receipt."></p><form method="post" action="/api/v1/save"><textarea name="draft">Keep this draft</textarea></form>',
  {workspace:true,pendingRuntime:true,flash:'Retained receipt.',fetch:async(url,options)=>{
    calls.push({url,options});return pendingRead;
  }});
  const w=dom.window,doc=w.document;
  try {
    assert.equal(w.LightworkI18n,undefined);
    assert.equal(calls.length,1);
    const label=doc.getElementById('halt-label'),pill=doc.getElementById('halt-pill');
    assert.equal(label.textContent,'Checking stop status\u2026');
    assert.equal(label.dataset.i18n,'Checking stop status\u2026');
    assert.equal(label.lang,'en');assert.equal(label.dir,'ltr');
    assert.equal(pill.getAttribute('aria-disabled'),'true');
    assert.equal(doc.querySelectorAll('.mv-toast').length,0);
    assert.equal(w.sessionStorage.getItem('lightwork.flash-toast'),'Retained receipt.');
    const form=doc.querySelector('form');
    form.addEventListener('submit',event=>event.preventDefault());
    form.dispatchEvent(new w.Event('submit',{bubbles:true,cancelable:true}));
    assert.equal(form.querySelector('[name="_expected_tenant"]').value,'owned');
    assert.equal(form.querySelector('textarea').value,'Keep this draft');
    completeRead({ok:true,json:async()=>({active:false,scope:'local'})});
    await tick();
    assert.equal(calls.length,1);
    assert.equal(calls[0].url,'/api/v1/halt');
    assert.equal(calls[0].options.method,undefined);
    assert.equal(label.textContent,'Emergency stop');
    assert.equal(label.dataset.i18n,'Emergency stop');
    assert.equal(label.lang,'en');assert.equal(label.dir,'ltr');
    assert.equal(pill.getAttribute('aria-disabled'),'false');
    w.eval(source('lightwork-i18n.js'));
    doc.dispatchEvent(new w.Event('DOMContentLoaded'));
    assert.equal(label.textContent,copy['Emergency stop']);
    assert.equal(label.lang,'fr');
    assert.equal(pill.getAttribute('aria-disabled'),'false');
    assert.deepEqual(Array.from(doc.querySelectorAll('.mv-toast'),node=>node.textContent),['Saved receipt.','Retained receipt.']);
    assert.equal(w.sessionStorage.getItem('lightwork.flash-toast'),null);
    doc.dispatchEvent(new w.Event('DOMContentLoaded'));
    await tick();
    assert.equal(calls.length,1);
    assert.equal(doc.querySelectorAll('.mv-toast').length,2);
  } finally {w.close();}
});

test('failed localization download never postpones halt verification and keeps fallback English',async()=>{
  let calls=0;
  const dom=page('<a id="halt-pill" data-can-halt="true"><span id="halt-label"></span></a>',
    {pendingRuntime:true,flash:'Retained receipt.',fetch:async()=>{calls++;return {ok:true,json:async()=>({active:false,scope:'local'})};}});
  const w=dom.window,doc=w.document;
  try {
    assert.equal(calls,1);
    const label=doc.getElementById('halt-label'),pill=doc.getElementById('halt-pill');
    assert.equal(label.textContent,'Checking stop status\u2026');
    assert.equal(label.lang,'en');assert.equal(label.dir,'ltr');
    assert.equal(pill.getAttribute('aria-disabled'),'true');
    await tick();
    assert.equal(w.LightworkI18n,undefined);
    assert.equal(calls,1);
    assert.equal(label.textContent,'Emergency stop');
    assert.equal(label.dataset.i18n,'Emergency stop');
    assert.equal(label.lang,'en');assert.equal(label.dir,'ltr');
    assert.equal(pill.getAttribute('aria-disabled'),'false');
    assert.equal(doc.querySelector('.mv-toast').textContent,'Retained receipt.');
    assert.equal(w.sessionStorage.getItem('lightwork.flash-toast'),null);
    doc.dispatchEvent(new w.Event('DOMContentLoaded'));
    await tick();
    assert.equal(calls,1);
    assert.equal(doc.querySelectorAll('.mv-toast').length,1);
  } finally {w.close();}
});

test('localized workspace warning still blocks mutations and retains the untouched draft', async()=>{
  let calls=0;
  const dom=page('<textarea id="draft" data-user-content dir="auto" lang="und"></textarea>', {workspace:true,fetch:async()=>{calls++;return {ok:true};}});
  const w=dom.window, doc=w.document;
  const draft='Emergency stop <img src=x> العربية';doc.getElementById('draft').value=draft;
  w.dispatchEvent(new w.StorageEvent('storage',{key:'lightwork-workspace-changed',newValue:'other'}));
  const alert=doc.querySelector('section[role=alert]');
  assert.equal(alert.lang,'fr');assert.match(alert.textContent,/autre onglet/);
  assert.equal(alert.querySelector('a').textContent,copy['Reopen in current workspace']);
  assert.equal(alert.querySelector('a').href,w.location.href);
  await assert.rejects(w.fetch('/api/v1/save',{method:'POST'}),/Workspace changed/);
  assert.equal(calls,0);assert.equal(doc.getElementById('draft').value,draft);
  dom.window.close();
});

for (const scope of ['local','cluster']) test(`localized ${scope} stop review keeps authority and exact scope`, async()=>{
  const calls=[];
  const dom=page('<a id="halt-pill" data-can-halt="true"><span id="halt-label"></span></a>',{fetch:async(url,options)=>{calls.push({url,options});return {ok:true,json:async()=>({active:false,scope,cluster_halt:false})};}});
  const w=dom.window,doc=w.document;await tick();
  assert.equal(doc.getElementById('halt-label').textContent,copy['Emergency stop']);
  assert.equal(doc.getElementById('halt-label').lang,'fr');
  doc.getElementById('halt-pill').click();await tick();
  const consequence=doc.getElementById('mv-confirm-msg');
  assert.equal(consequence.lang,'fr');assert.match(consequence.textContent,scope==='local'?/ce serveur/:/exécutants connectés/);
  assert.match(consequence.textContent,/étape suivante/);assert.match(consequence.textContent,/reprise autorisée/);
  assert.equal(doc.getElementById('mv-confirm-ok').textContent,'Arrêter le travail');
  doc.getElementById('mv-confirm-cancel').click();await tick();
  assert.equal(calls.length,1);assert.equal(calls[0].options.method,undefined);
  dom.window.close();
});

test('Arabic fallback stop status declares English, without a invented translation',async()=>{
  const dom=page('<span id="halt-pill" data-can-halt="false"><span id="halt-label"></span></span>',{language:'ar',fetch:async()=>({ok:true,json:async()=>({active:false,scope:'local'})})});
  await tick();const label=dom.window.document.getElementById('halt-label');
  assert.equal(label.textContent,'Emergency stop');assert.equal(label.lang,'en');assert.equal(label.dir,'ltr');
  assert.equal(dom.window.document.getElementById('halt-pill').getAttribute('aria-disabled'),'true');
  dom.window.close();
});

test('finder searches translated labels and English aliases; records remain original content',()=>{
  const dom=page('<button id="navfinder-open"></button><dialog id="navfinder-dialog"><button id="navfinder-close"></button><input id="navfinder-input"><p id="navfinder-count"></p><p id="navfinder-empty"></p><ul id="navfinder-results"><li><a id="allowed" href="/goals" data-navfinder-target data-search="Tâches Tasks jobs Work">Tâches</a></li></ul></dialog>');
  const w=dom.window,doc=w.document;w.eval(source('lightwork-navfinder.js'));
  const controller=w.LightworkNavFinder.init(doc)||doc.getElementById('navfinder-dialog').lightworkFinder;
  controller.open();const input=doc.getElementById('navfinder-input');
  for(const query of ['tâches','tasks','jobs']) {input.value=query;controller.filter();assert.equal(controller.visibleOptions().length,1);}
  const original='Emergency stop <img src=x onerror=alert(1)> العربية';
  controller.setRecords([{href:'/goals/1',title:original,kind:'task',id:'1',revision:'2',state:'private'}]);
  const label=doc.querySelector('#navfinder-record-0 .navfinder__label');
  assert.equal(label.textContent,original);assert.equal(label.lang,'und');assert.equal(label.dir,'auto');assert.equal(label.querySelector('img'),null);
  assert.equal(doc.getElementById('navfinder-count').textContent,'1 page, 1 enregistrement affiché');
  assert.equal(doc.getElementById('navfinder-count').lang,'fr');
  controller.setSettings([{href:'/preferences',title:'Emergency stop',group:original,effective:'owned',required_role:'viewer'}]);
  assert.equal(doc.querySelector('#navfinder-setting-0 .navfinder__group span').textContent,'Paramètre');
  assert.equal(doc.querySelector('#navfinder-setting-0 .navfinder__group bdi').textContent,original+' - owned - viewer');
  assert.equal(doc.querySelector('#navfinder-setting-0 .navfinder__label').textContent,'Emergency stop');
  assert.equal(doc.querySelector('img'),null);
  dom.window.close();
});

test('clipboard and timestamps use interface locale while copied content remains verbatim',async()=>{
  const dom=page(),w=dom.window;let copied;
  w.navigator.clipboard={writeText:async value=>{copied=value;}};
  const original='Emergency stop العربية';w.mvCopy(original);await tick();
  assert.equal(copied,original);const toast=w.document.querySelector('.mv-toast');
  assert.equal(toast.textContent,'Copié dans le presse-papiers');assert.equal(toast.lang,'fr');
  assert.equal(w.mvWhen(1760000000),new Intl.DateTimeFormat('fr-CA',{day:'numeric',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit',timeZoneName:'short'}).format(new Date(1760000000000)));
  assert.equal(w.mvWhen(NaN),'');assert.equal(w.mvWhen(null),'');
  dom.window.close();
});

test('recent-chat filtering searches original titles, excluding translated pin labels',()=>{
  const dom=page('<input id="cs-filter"><p id="cs-filter-status"></p><ul id="cs-list"><li><a data-conversation-root="1"><span>Épinglé :</span><bdi data-user-content>Alpha العربية</bdi></a></li><li><a data-conversation-root="2"><bdi data-user-content>Alpha Tasks</bdi></a></li></ul>');
  const template=fs.readFileSync(path.join(__dirname,'../../maverick_dashboard/templates/chat_base.html'),'utf8');
  const start=template.indexOf('    // Filter the recents list as you type.');
  dom.window.eval(template.slice(start,template.indexOf('</script>',start)));
  const w=dom.window,doc=w.document,input=doc.getElementById('cs-filter'),status=doc.getElementById('cs-filter-status');
  input.value='Alpha';input.dispatchEvent(new w.Event('input'));
  assert.equal(status.textContent,'2 titres récents correspondants.');assert.equal(status.lang,'fr');
  input.value='Épinglé';input.dispatchEvent(new w.Event('input'));
  assert.match(status.textContent,/Aucun titre/);assert.equal(doc.querySelectorAll('#cs-list li:not([hidden])').length,0);
  input.value='العربية';input.dispatchEvent(new w.Event('input'));
  assert.equal(status.textContent,'1 titre récent correspondant.');
  assert.equal(doc.querySelector('[data-user-content]').textContent,'Alpha العربية');
  input.value='';input.dispatchEvent(new w.Event('input'));assert.equal(status.textContent,'');
  dom.window.close();
});

test('a quiet toast is shown without being read a second time', async()=>{
  const dom=page('',{language:'ar'});
  const w=dom.window,doc=w.document;
  try {
    w.mvToast('Write file authorized.',{quiet:true});
    w.mvToast('Saved.');
    const [quiet,spoken]=doc.querySelectorAll('#mv-toasts .mv-toast');
    assert.equal(quiet.textContent,'Write file authorized.');
    assert.equal(quiet.getAttribute('aria-hidden'),'true');
    assert.equal(spoken.hasAttribute('aria-hidden'),false);
  } finally {w.close();}
});
