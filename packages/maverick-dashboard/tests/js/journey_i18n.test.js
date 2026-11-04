const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const {shell} = require('./_shell');
const script = fs.readFileSync(path.join(__dirname, '../../maverick_dashboard/static/lightwork-i18n.js'), 'utf8');

function page(language='fr', locale='fr-CA') {
  const catalog = {
    'Save': {text:'Enregistrer',lang:'fr'},
    'Hi {name}': {text:'Bonjour {name}',lang:'fr'},
    '{count} review': {text:'{count} révision',lang:'fr'},
    '{count} reviews': {text:'{count} révisions',lang:'fr'},
    'Complete this field.': {text:'Renseignez ce champ.',lang:'fr'},
    'This action could not be completed. {reason}': {text:'Cette action n’a pas pu être effectuée. {reason}',lang:'fr'},
    'You do not have permission to do this. Ask an administrator.': {text:'Vous n’avez pas l’autorisation nécessaire. Demandez un accès à un administrateur.',lang:'fr'},
    'Review publication': {text:'Vérifier la publication',lang:'fr'},
    'Restore as draft': {text:'Restaurer comme brouillon',lang:'fr'},
    'No content changes.': {text:'Aucune modification du contenu.',lang:'fr'},
    'Working through the steps…': {text:'Exécution des étapes…',lang:'fr'},
    'An issue needs attention — open Show work for details.': {text:'Un problème nécessite votre attention.',lang:'fr'},
    '{count} step': {text:'{count} étape',lang:'fr'},
    '{count} steps': {text:'{count} étapes',lang:'fr'},
  };
  const dom = new JSDOM('<!doctype html><html lang="en"><head></head><body><div id="message"></div><div data-user-content dir="auto" lang="und"><span id="user" data-i18n="Save">Save</span></div><dialog id="dialog"><table><tr><th data-i18n="Save">Save</th><td data-user-content lang="und" dir="auto">مرحبا Save</td></tr></table></dialog><div id="stream" data-user-content dir="auto" lang="und"></div></body></html>', {runScripts:'outside-only'});
  const config=dom.window.document.createElement('script');config.id='lightwork-i18n-data';config.type='application/json';config.textContent=JSON.stringify({language,locale,catalog});dom.window.document.head.appendChild(config);
  shell(dom.window);
  dom.window.eval(script);
  return dom;
}

test('only explicitly marked product regions translate, including new dialogs',()=>{
  const dom=page(), doc=dom.window.document, api=dom.window.LightworkI18n;
  api.translate();
  assert.equal(doc.querySelector('th').textContent,'Enregistrer');
  assert.equal(doc.querySelector('th').lang,'fr');
  assert.equal(doc.getElementById('user').textContent,'Save');
  assert.equal(doc.querySelector('td').textContent,'مرحبا Save');
  doc.getElementById('stream').append('Save');api.translate();
  assert.equal(doc.getElementById('stream').textContent,'Save');
  api.set(doc.getElementById('message'),'Missing translation');
  assert.equal(doc.getElementById('message').lang,'en');
  dom.window.close();
});

test('live work summary localizes product status without changing streamed evidence',async()=>{
  const dom=page(),w=dom.window,doc=w.document;
  doc.body.insertAdjacentHTML('beforeend','<details id="work-activity"><p id="work-now"></p><p id="work-meta"></p><span id="work-spin"></span></details><div id="events" data-steps="1200"><div data-kind="observation">Save {"original":"مرحبا"}</div></div><span id="status" data-status="running">Working</span>');
  const source=fs.readFileSync(path.join(__dirname,'../../maverick_dashboard/templates/chat_goal.html'),'utf8');
  shell(w);
  w.eval(source.slice(source.indexOf('    function cgText('),source.indexOf('    // Plain-language failure text')));
  const start=source.indexOf('    (function () {',source.indexOf('// "Show work" strip'));
  w.eval(source.slice(start,source.indexOf('    })();',start)+'    })();'.length));
  const original=doc.getElementById('events').textContent;
  doc.getElementById('events').append(doc.createElement('div'));
  doc.getElementById('events').lastChild.dataset.kind='observation';
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(doc.getElementById('work-now').textContent,'Exécution des étapes…');
  assert.equal(doc.getElementById('work-now').lang,'fr');
  assert.equal(doc.getElementById('work-meta').textContent,new Intl.NumberFormat('fr-CA').format(1200)+' étapes');
  assert.equal(doc.getElementById('events').textContent,original);
  dom.window.close();
});

test('classified request failures keep their language when shown by a status controller',()=>{
  const dom=page(),w=dom.window;
  w.matchMedia=()=>({matches:false,addEventListener(){},removeEventListener(){}});
  shell(w);
  w.eval(fs.readFileSync(path.join(__dirname,'../../maverick_dashboard/static/lightwork-ui.js'),'utf8'));
  const result=w.mvErrorText({status:403},'publish this draft');
  assert.equal(result,'Cette action n’a pas pu être effectuée. Vous n’avez pas l’autorisation nécessaire. Demandez un accès à un administrateur.');
  w.LightworkI18n.set(w.document.getElementById('message'),result);
  assert.equal(w.document.getElementById('message').lang,'fr');
  assert.doesNotMatch(result,/403|Could not/);
  dom.window.close();
});

test('workflow review localizes actions while preserving stored labels, choices and diffs',async()=>{
  const dom=page(),w=dom.window,doc=w.document;
  w.history.replaceState=()=>{};
  doc.body.insertAdjacentHTML('beforeend','<section id="workflow-versions"><div id="workflow-versions-content"></div><p id="workflow-versions-status"></p><button id="workflow-versions-refresh"></button></section>');
  const records={context:'owner',current:'v2',published:'v1',params:['answer'],parameter_schema:{fields:{answer:{label:'Save',type:'enum',choices:['Save','مرحبا'],required:true}}},can_publish:true,effect:'Existing schedules keep their reviewed content and version. Publishing affects only new schedules; migration is never automatic.',schedules:[],generation:2,fixtures:[],versions:[{label:'Save مرحبا',version:'v1',current:false,published:true,diff:['+Save <img src=x> مرحبا']}]};
  const calls=[];w.fetch=async(url,options)=>{calls.push({url,options});return {ok:true,status:200,json:async()=>records};};
  shell(w);
  w.eval(fs.readFileSync(path.join(__dirname,'../../maverick_dashboard/static/lightwork-workflow-versions.js'),'utf8'));
  doc.dispatchEvent(new w.CustomEvent('lightwork:workflow-saved',{detail:{name:'verbatim'}}));
  await new Promise(resolve=>setImmediate(resolve));
  const content=doc.getElementById('workflow-versions-content');
  const buttons=[...content.querySelectorAll('button')];
  assert.equal(buttons.find(b=>b.textContent==='Vérifier la publication').lang,'fr');
  assert.equal(buttons.find(b=>b.textContent==='Restaurer comme brouillon').lang,'fr');
  assert.equal(content.querySelector('label bdi').childNodes[0].textContent,'Save');  // the shell then adds the required marker
  assert.equal(content.querySelector('option[value="Save"]').textContent,'Save');
  assert.equal(content.querySelector('summary bdi').textContent,'Save مرحبا');
  assert.equal(content.querySelector('ins').textContent,'+Save <img src=x> مرحبا\n');
  assert.equal(content.querySelector('ins').lang,'und');
  assert.equal(content.querySelector('img'),null);
  assert.equal(calls.length,1);assert.equal(calls[0].options.method,'GET');
  dom.window.close();
});

test('parameters remain escaped, verbatim and bidi-isolated',()=>{
  const dom=page(), doc=dom.window.document;
  const original='<img src=x onerror=alert(1)> مرحبا';
  dom.window.LightworkI18n.set(doc.getElementById('message'),'Hi {name}',{name:original});
  assert.equal(doc.getElementById('message').textContent,'Bonjour '+original);
  assert.equal(doc.querySelector('img'),null);
  assert.equal(doc.querySelector('bdi').textContent,original);
  assert.equal(doc.querySelector('bdi').dir,'auto');
  assert.equal(doc.querySelector('bdi').lang,'und');
  dom.window.close();
});

test('regional number, currency, dates and plural rules use selected locale',()=>{
  const dom=page(),api=dom.window.LightworkI18n;
  assert.equal(api.number(12345.5),new Intl.NumberFormat('fr-CA').format(12345.5));
  assert.equal(api.number(3,{style:'currency',currency:'EUR'}),new Intl.NumberFormat('fr-CA',{style:'currency',currency:'EUR'}).format(3));
  assert.equal(api.plural('{count} review','{count} reviews',1),'1 révision');
  assert.equal(api.plural('{count} review','{count} reviews',2),'2 révisions');
  assert.equal(api.formatDate('2026-09-30'),new Intl.DateTimeFormat('fr-CA',{dateStyle:'medium'}).format(new Date(2026,8,30)));
  assert.equal(api.formatDate('1760000000'),api.formatDate(1760000000));
  dom.window.close();
});

test('Arabic retains English fallback regions while source remains independently directed',()=>{
  const dom=page('ar','ar-EG'),doc=dom.window.document;
  dom.window.LightworkI18n.set(doc.getElementById('message'),'Review before starting');
  assert.equal(doc.getElementById('message').lang,'en');
  assert.equal(doc.getElementById('message').dir,'ltr');
  assert.equal(doc.getElementById('stream').dir,'auto');
  dom.window.close();
});

test('required-field errors localize without modifying drafts and clear on input',()=>{
  const dom=page(),doc=dom.window.document,form=doc.createElement('form');
  form.innerHTML='<textarea required lang="und" dir="auto" data-user-content></textarea>';
  doc.body.appendChild(form);dom.window.LightworkI18n.validation(form);
  const field=form.querySelector('textarea');
  assert.equal(form.checkValidity(),false);
  assert.equal(field.validationMessage,'Renseignez ce champ.');
  assert.equal(form.querySelector('[role=alert]').lang,'fr');
  field.value='Save مرحبا';field.dispatchEvent(new dom.window.Event('input',{bubbles:true}));
  assert.equal(form.checkValidity(),true);
  assert.equal(field.value,'Save مرحبا');
  assert.equal(form.querySelector('[role=alert]').hidden,true);
  dom.window.close();
});
