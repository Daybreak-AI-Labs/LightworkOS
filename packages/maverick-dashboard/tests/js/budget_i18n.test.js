const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const {JSDOM} = require('jsdom');
const base = path.join(__dirname, '../../maverick_dashboard');
const rows = JSON.parse(execFileSync(process.env.PYTHON || 'python', ['-c',
  'import ast,json,sys; t=ast.parse(open(sys.argv[1],encoding="utf8").read()); print(json.dumps(ast.literal_eval(next(n.value for n in t.body if isinstance(n,ast.Assign)))))',
  path.join(base, 'i18n_journey_budget.py')], {encoding:'utf8'}));
const shell = fs.readFileSync(path.join(base, 'static/lightwork-ui.js'), 'utf8');
const shared = fs.readFileSync(path.join(base, 'static/lightwork-i18n.js'), 'utf8');
const script = fs.readFileSync(path.join(base, 'static/lightwork-budget-guidance.js'), 'utf8');
const locales = {fr:'fr-FR', de:'de-DE', ja:'ja-JP', zh:'zh-CN', ar:'ar'};
const settle = async () => {for (let i=0;i<4;i++) await new Promise(resolve=>setImmediate(resolve));};

function preview() {
  return {context:'owner-workspace',goal_id:7,observed_at:1790784000,reset_at:'2026-10-01T00:00:00+00:00',
    effective:{max_dollars:1234.5,max_wall_seconds:60},headroom_complete:true,headroom:4.5,binding_ceiling:'provider:Available',admission_allowed:false,
    notice:'These are current policy ceilings and advisory headroom, not a price quote or provider invoice. Admission rechecks policy and durable reservations at dispatch. Ledger figures are not additive.',
    increase_owner:'An installation administrator controls task/provider ceilings; the workspace administrator controls its assigned allowance.',
    person:{cap:10,confirmed:2,reserved:1,unknown:0,remaining:7,basis:'Acknowledged usage plus own pending organization reservations for the UTC day.'},
    workspace:{state:'not_bound',message:'No workspace allowance is bound to this runtime.'},
    provider_coverage:"Configured provider ceilings and this task's recorded providers; a future route may use another provider.",
    providers:[{provider:'Available',state:'blocked',period:'2026-09',cap:10,remaining:4.5,basis:'Shared provider authority; other-workspace amounts and receipts are private.'}],
    task_receipts:[{reference:'PR-<receipt>',provider:'Available',period:'2026-09',state:'settled',projected:1,actual:.5,currency:'USD',cost_basis:'observed'}],
    forecast:{state:'available',price_basis:'Schedule ceilings are limits, not predicted prices; this forecast does not add them to charges.',items:[{
      title:'Available <img src=x> مرحبا',href:'/automations',due_at:1790787600,risk:'Admission currently blocked',detail:'Admission rechecks current policy at the next start. A paused or uncertain occurrence is never automatically replayed.'}]},
    warnings_state:'available',warnings:[{label:'provider:available allowance crossed 95%; review scheduled work'}]};
}

function page(language='fr', {launch=false, fail=false}={}) {
  const dom=new JSDOM('<!doctype html><html><head></head><body>'+ (launch
    ? '<details data-budget-launch data-goal="7"><p role="status"></p><div data-budget-summary></div><button></button></details>'
    : '<section id="budget-guidance" data-goal="7"><form id="budget-preview-form"><input name="max_dollars" value="12.50" type="number"><button type="submit"></button></form><p id="budget-status" role="status"></p><div id="budget-preview"></div><div id="budget-forecast"></div><div id="budget-cases"></div></section>')+'</body></html>',
  {runScripts:'outside-only',url:'https://lightwork.example/budget'});
  const w=dom.window,doc=w.document,index=['en','fr','de','ja','zh'].indexOf(language),catalog={};
  for (const row of rows) catalog[row[0]]={text:row[index<0?0:index],lang:index<0?'en':language};
  const config=doc.createElement('script');config.id='lightwork-i18n-data';config.textContent=JSON.stringify({language,locale:locales[language],catalog});doc.head.appendChild(config);
  const calls=[],value=preview();
  w.fetch=async(url,options={})=>{
    calls.push({url,options});
    if (fail === 'network') throw new TypeError('Failed to fetch');
    if (fail) return {ok:false,status:409,json:async()=>({detail:{schema:'lightwork.error.v1',code:'budget_account_changed',message:'Your account changed. Refresh the budget preview.'}})};
    const data=url.includes('/preview?') ? value : {context:value.context,admin:true,items:[{id:'BAC-original',revision:3,provider:'Available',period:'2026-09',state:'assigned',assigned_to:'Requested',_audit_pending:true,verification:'Pending installation administrator review; no reservation was released.'}]};
    return {ok:true,status:200,json:async()=>data};
  };
  w.matchMedia=()=>({matches:false,addEventListener(){},removeEventListener(){}});
  w.eval(shell);w.eval(shared);w.eval(script);return {dom,w,doc,calls,value,catalog};
}

for (const language of ['fr','de','ja','zh']) {
  test('budget controls and closed accounting copy render in '+language,async()=>{
    const {dom,doc,catalog}=page(language);await settle();
    const controls=[...doc.querySelectorAll('#budget-preview button,#budget-cases button,#budget-cases a')];
    assert.equal(controls.length,6);
    assert.ok(controls.every(element=>element.lang===language));
    assert.equal(controls[0].textContent,catalog['Request accounting help'].text);
    const product=[...doc.querySelectorAll('[data-product-copy]')];
    assert.ok(product.length>15);
    assert.ok(product.every(element=>element.lang===language), product.filter(e=>e.lang!==language).map(e=>e.textContent).join('\n'));
    const amount=new Intl.NumberFormat(locales[language],{style:'currency',currency:'USD',minimumFractionDigits:2,maximumFractionDigits:2}).format(1234.5);
    assert.ok(doc.getElementById('budget-preview').textContent.includes(amount));
    assert.ok(doc.getElementById('budget-preview').textContent.includes(new Intl.NumberFormat(locales[language],{style:'percent'}).format(.95)));
    assert.equal(doc.querySelector('#budget-preview h2[data-user-content]').textContent,'Available');
    const title=doc.querySelector('#budget-forecast a');
    assert.equal(title.textContent,'Available <img src=x> مرحبا');
    assert.equal(title.lang,'und');assert.equal(title.dir,'auto');assert.equal(doc.querySelector('img'),null);
    assert.equal(doc.querySelector('#budget-cases h3 bdi').textContent,'Available');
    assert.ok([...doc.querySelectorAll('#budget-cases bdi')].some(e=>e.textContent==='Requested'&&e.lang==='und'));
    dom.window.close();
  });
}

test('localized actions preserve numeric request, original period, revision and provider',async()=>{
  const {dom,doc,calls}=page('de');await settle();
  assert.ok(calls[0].url.includes('max_dollars=12.50'));
  doc.querySelector('#budget-preview button').click();await settle();
  let request=calls.find(call=>call.options.method==='POST');
  assert.deepEqual(JSON.parse(request.options.body),{provider:'Available',period:'2026-09',goal_id:7,context:'owner-workspace'});
  const verify=[...doc.querySelectorAll('#budget-cases button')].find(e=>e.textContent===rows.find(r=>r[0]==='Verify original-period accounting')[2]);
  verify.click();await settle();
  request=calls.filter(call=>call.options.method==='POST').at(-1);
  assert.deepEqual(JSON.parse(request.options.body),{expected_revision:3,action:'verify',context:'owner-workspace'});
  dom.window.close();
});

test('structured error translates known copy without changing the API code',async()=>{
  const {dom,doc,catalog}=page('fr',{fail:true});await settle();
  assert.equal(doc.getElementById('budget-status').textContent,catalog['Your account changed. Refresh the budget preview.'].text);
  assert.equal(doc.getElementById('budget-status').lang,'fr');
  dom.window.close();
});

test('a dropped connection reads as one plain sentence, never the browser error',async()=>{
  const {dom,doc,catalog}=page('fr',{fail:'network'});await settle();
  assert.equal(doc.getElementById('budget-status').textContent,catalog['Budget details could not be refreshed. Try again in a moment.'].text);
  assert.doesNotMatch(doc.getElementById('budget-status').textContent,/fetch|TypeError/);
  dom.window.close();
});

test('Arabic budget copy remains an honest English fallback',async()=>{
  const {dom,doc}=page('ar');await settle();
  assert.ok([...doc.querySelectorAll('[data-product-copy]')].every(e=>e.lang==='en'));
  assert.equal(doc.querySelector('#budget-preview button').textContent,'Request accounting help');
  dom.window.close();
});

test('launch-only preview localizes without requiring the full budget page',async()=>{
  const {dom,doc,calls}=page('ja',{launch:true});await settle();
  assert.equal(calls.length,1);
  assert.equal(doc.querySelector('[data-budget-summary] a').lang,'ja');
  assert.equal(doc.querySelector('[role=status]').lang,'ja');
  dom.window.close();
});

test('unknown server copy remains explicit English while unknown notices remain source content',async()=>{
  const {dom,doc,value}=page('fr');value.person.message='New product sentence not yet translated';value.warnings=[{label:'Available'}];await settle();
  const unknown=[...doc.querySelectorAll('[data-product-copy]')].find(e=>e.textContent===value.person.message);
  assert.equal(unknown.lang,'en');
  const notice=doc.querySelector('#budget-preview p[data-user-content]');
  assert.equal(notice.textContent,'Available');assert.equal(notice.lang,'und');
  dom.window.close();
});
