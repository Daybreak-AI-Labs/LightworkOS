'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path');
const {JSDOM} = require('jsdom');
const script = fs.readFileSync(path.resolve(__dirname,'../../maverick_dashboard/static/lightwork-outcome-pilots.js'),'utf8');
const templateFor = enabled => fs.readFileSync(path.resolve(__dirname,'../../maverick_dashboard/templates/outcome_pilots.html'),'utf8').replace(/{%[\s\S]*?%}/g,'').replace('{{ pilot_context }}','alice').replace("{{ 'true' if pilot_enabled else 'false' }}",enabled);
const template = templateFor('true');
const tick = () => new Promise(resolve => setImmediate(resolve));
function report() {
  return {context:'alice',id:'OPL-test',title:'<script>bad</script>',customer:'Example',workflow:'Review',criteria:'Good evidence',revision:2,
    admission:{status:'complete',expected_count:4,admitted_count:4,manifest_sha256:'b'.repeat(64),completion_sha256:'c'.repeat(64)},
    evidence_readiness:{reported_effort_comparison_ready:false,frozen_criteria_review_ready:false,
      reported_cost_comparison_ready:false,causal_release_lift_qualified:false,
      next_steps:['Review every planned case.']},
    groups:{all:{accepted:0,planned:4,paired:0,unavailable:0,reported_minutes_difference:null,reported_cost_difference:null}},limitations:['Operator reported.'],
    cases:[{id:'1',label:'A case',allocation:'holdout',status:'unmeasured',measurement:null,
      source:{href:'/chat/goal/1',version:'a'.repeat(64),accepted:false,runtime_cost_usd:null}}]};
}
async function setup(next, enabled='true') {
  const dom = new JSDOM(enabled==='true'?template:templateFor(enabled),{url:'https://lightwork.test',runScripts:'outside-only'});
  const w=dom.window,d=w.document,calls=[];
  w.HTMLElement.prototype.scrollIntoView=()=>{};  // browsers scroll the review into view; jsdom has no layout
  w.fetch=async(url,options)=>{
    calls.push({url,options});
    if (calls.length===1) return {ok:true,json:async()=>({context:'alice',items:[{id:'OPL-test',title:'A pilot',cases:4}]})};
    if (calls.length===2) return {ok:true,json:async()=>({context:'alice',items:Array.from({length:4},(_,i)=>({kind:'goal',reference:String(i+1),label:'Task '+(i+1)})),coverage:[{kind:'vendor',status:'unavailable'}]})};
    const value=next.shift();
    if (value instanceof Error) throw value;
    if (typeof value==='function') return value();
    return {ok:true,json:async()=>value};
  };
  w.eval(script);await tick();
  return {dom,w,d,calls};
}
function pickPilot(ui,id) {
  const picker=ui.d.getElementById('op-review-reference');
  picker.append(new ui.w.Option('A pilot',id));picker.value=id;
}
async function open(ui) {
  ui.d.getElementById('op-selected').value='OPL-test';
  ui.d.getElementById('op-selected').dispatchEvent(new ui.w.Event('change'));await tick();
}
// Every pilot write is a complete review first, then a separately confirmed
// save of that exact sealed review.
const CONTROLS='/api/v1/outcome-pilot-controls';
function reviewReply(kind){return {context:'alice',operation:'e'.repeat(32),token:'sealed-'+kind,changes:[{label:'Proposed change',after:'The exact '+kind+' request'}]};}
function savedReply(href='/outcome-pilots?pilot=OPL-test'){return {context:'alice',confirmed:true,message:'The original request is recorded. No work was repeated.',href};}
async function confirmSave(ui){
  const host=ui.d.getElementById('op-guided-review'),box=host.querySelector('[data-review-confirm]');
  box.checked=true;box.dispatchEvent(new ui.w.Event('change'));
  host.querySelector('[data-save-review]').click();for(let i=0;i<6;i++)await tick();
}
const sent=call=>JSON.parse(call.options.body);
test('the cohort value report keeps its own field state and never marks pilot work unsaved',async()=>{
  const ui=await setup([report()]);await open(ui);
  const leaving=()=>{const event=new ui.w.Event('beforeunload',{cancelable:true});ui.w.dispatchEvent(event);return event.defaultPrevented;};
  const cohort=ui.d.getElementById('ov-pilot');
  cohort.append(new ui.w.Option('A pilot','OPL-test'));cohort.value='OPL-test';
  cohort.dispatchEvent(new ui.w.Event('change',{bubbles:true}));
  ui.d.getElementById('ov-baseline-form').querySelector('input,select,textarea').dispatchEvent(new ui.w.Event('input',{bubbles:true}));
  assert.equal(leaving(),false);
  // Entered pilot work still guards the page, so the check above is meaningful.
  ui.d.querySelector('#op-report input[name="baseline_minutes"]').dispatchEvent(new ui.w.Event('input',{bubbles:true}));
  assert.equal(leaving(),true);
  ui.dom.window.close();
});

test('record picker, missing coverage, source titles and unknown values render honestly',async()=>{
  const ui=await setup([report()]);await open(ui);
  assert.equal(ui.d.querySelectorAll('#op-planned-cases select').length,4);
  assert.match(ui.d.getElementById('op-source-coverage').textContent,/unavailable/);
  assert.equal(ui.d.querySelector('#op-report script'),null);
  assert.match(ui.d.getElementById('op-report').textContent,/<script>bad<\/script>/);
  assert.equal(ui.d.querySelector('#op-report input[name="baseline_minutes"]').value,'');
  assert.match(ui.d.getElementById('op-report').textContent,/provider invoice unverified/);
  assert.match(ui.d.getElementById('op-report').textContent,/complete for all 4 planned cases/);
  assert.match(ui.d.getElementById('op-report').textContent,/The reported effort difference is partial/);
  assert.match(ui.d.getElementById('op-report').textContent,/Review every planned case/);
  ui.dom.window.close();
});
test('lost save keeps measurements and exact retry identity without automatic retry',async()=>{
  const ui=await setup([report(),reviewReply('observe'),new Error('Connection interrupted')]);await open(ui);
  const form=ui.d.querySelector('#op-report form');
  form.elements.evidence.value='Timing sheet row 5';form.elements.note.value='Observed work';form.elements.baseline_minutes.value='45';
  form.dispatchEvent(new ui.w.Event('submit',{cancelable:true,bubbles:true}));await tick();await tick();
  assert.equal(ui.calls.length,4);
  assert.equal(ui.calls[3].url,CONTROLS+'/review');
  const review=sent(ui.calls[3]);
  assert.deepEqual([review.kind,review.pilot,review.case],['observe','OPL-test','1']);
  assert.equal(review.values.baseline_minutes,45);assert.equal(review.values.review_minutes,null);
  await confirmSave(ui);
  assert.equal(ui.calls.length,5);
  assert.deepEqual(sent(ui.calls[4]),{token:'sealed-observe',confirmed:true});
  assert.equal(form.elements.baseline_minutes.value,'45');
  assert.equal(form.elements.review_minutes.value,'');
  assert.match(ui.d.getElementById('op-status').textContent,/original result is not confirmed/);
  assert.match(ui.d.getElementById('op-guided-review').textContent,/not responding.*Saving was not repeated/);
  // Only the opaque original reference is kept, to read its outcome later.
  assert.deepEqual(JSON.parse(ui.w.sessionStorage.getItem('lightwork-pilot-original')),
    {kind:'observe',operation:'e'.repeat(32),pilot:'OPL-test',case:'1'});
  for(let i=0;i<5;i++)await tick();
  assert.equal(ui.calls.length,5,'a lost save is never repeated automatically');
  ui.dom.window.close();
});
test('account switch clears old report and refuses the new response',async()=>{
  const ui=await setup([report(),{...report(),context:'bob'}]);await open(ui);
  ui.d.getElementById('op-refresh').click();await tick();
  assert.equal(ui.d.getElementById('op-report').children.length,0);
  assert.equal(ui.d.getElementById('op-export').disabled,true);
  assert.match(ui.d.getElementById('op-status').textContent,/account or workspace changed/);
  ui.dom.window.close();
});
test('pending save disables fields and duplicate submissions',async()=>{
  let finish;
  const ui=await setup([report(),()=>new Promise(resolve=>{finish=resolve;}),savedReply(),report()]);await open(ui);
  const form=ui.d.querySelector('#op-report form');form.elements.evidence.value='Timing';form.elements.note.value='Observed';
  form.dispatchEvent(new ui.w.Event('submit',{cancelable:true,bubbles:true}));
  form.dispatchEvent(new ui.w.Event('submit',{cancelable:true,bubbles:true}));
  assert.equal(ui.calls.length,4);
  assert.equal(form.elements.note.disabled,true);
  finish({ok:true,json:async()=>reviewReply('observe')});await tick();await tick();
  assert.equal(ui.calls.length,4,'a prepared review saves nothing by itself');
  await confirmSave(ui);
  assert.equal(ui.calls.length,6);
  assert.equal(ui.calls[4].url,CONTROLS+'/save');
  assert.equal(ui.d.getElementById('outcome-pilots').getAttribute('aria-busy'),'false');
  ui.dom.window.close();
});

test('protected plan sends an explicit learning mode and attributed prior-exposure statement',async()=>{
  const ui=await setup([reviewReply('plan'),savedReply(),{context:'alice',items:[{id:'OPL-test',title:'Pilot',cases:4}]},report()]);
  const form=ui.d.getElementById('op-plan');
  for(const name of ['title','customer','workflow','criteria'])form.elements[name].value='Representative pilot '+name;
  [...ui.d.querySelectorAll('#op-planned-cases select')].forEach((select,index)=>{select.value='goal:'+(index+1);});
  ui.d.getElementById('op-learning-mode').value='exclude_local_learning';
  form.dispatchEvent(new ui.w.Event('submit',{bubbles:true,cancelable:true}));await tick();
  assert.equal(ui.calls.length,2);assert.match(ui.d.getElementById('op-status').textContent,/prior-exposure/);
  ui.d.getElementById('op-prior-exposure').value='Checked local source history; provider prior exposure is unverified.';
  form.dispatchEvent(new ui.w.Event('submit',{bubbles:true,cancelable:true}));await tick();await tick();
  const body=sent(ui.calls[2]);assert.equal(body.kind,'plan');
  assert.equal(body.values.learning_mode,'exclude_local_learning');assert.match(body.values.prior_exposure_statement,/provider prior exposure/);
  assert.equal(body.values.cases.length,4);
  await confirmSave(ui);
  assert.equal(ui.calls[3].url,CONTROLS+'/save');
  assert.equal(ui.d.getElementById('op-selected').value,'OPL-test');
  ui.dom.window.close();
});

test('improvement pilot chooses a governed candidate and keeps release lift unqualified',async()=>{
  const bound={...report(),release_binding:{candidate_id:'candidate-one'},case_exposure_verified:false,causal_lift_qualified:false};
  const ui=await setup([
    {context:'alice',available:true,readiness:{status:'ready',next_action:'Choose a candidate. Its deployed baseline is checked again.'},
      items:[{candidate_id:'candidate-one',target_id:'installed-lightwork',state:'authorized'}]},
    reviewReply('plan'),savedReply(),
    {context:'alice',items:[{id:'OPL-test',title:'Pilot',cases:4}]},
    bound,
    {context:'alice',deployment_state:'candidate_active',promotion_state:'canary',case_exposure_verified:false,
      causal_lift_qualified:false,review_href:'/research'},
  ]);
  const selections=[];
  ui.d.addEventListener('lightwork:copilot-selection',event=>selections.push(event.detail.selection));
  ui.d.getElementById('op-candidate-refresh').click();await tick();
  const picker=ui.d.getElementById('op-candidate');picker.value='candidate-one';
  picker.dispatchEvent(new ui.w.Event('change'));
  const form=ui.d.getElementById('op-plan');
  for(const name of ['title','customer','workflow','criteria'])form.elements[name].value='Improvement '+name;
  ui.d.getElementById('op-prior-exposure').value='Checked task inputs and local history; provider exposure remains unknown.';
  [...ui.d.querySelectorAll('#op-planned-cases select')].forEach((select,index)=>{select.value='goal:'+(index+1);});
  form.dispatchEvent(new ui.w.Event('submit',{bubbles:true,cancelable:true}));await tick();await tick();
  const create=ui.calls.find(call=>call.url===CONTROLS+'/review');
  assert.equal(sent(create).values.candidate_id,'candidate-one');
  assert.equal(sent(create).values.learning_mode,'exclude_local_learning');
  await confirmSave(ui);
  assert.equal(selections.at(-1).kind,'outcome_pilot');
  assert.equal(selections.at(-1).id,'OPL-test');
  assert.match(ui.d.getElementById('op-report').textContent,/do not establish a causal release improvement/);
  ui.d.querySelector('#op-report section button').click();await tick();
  assert.match(ui.d.getElementById('op-report').textContent,/candidate is currently deployed/);
  assert.match(ui.calls.at(-1).url,/OPL-test\/release-status$/);
  ui.d.getElementById('op-selected').value='';
  ui.d.getElementById('op-selected').dispatchEvent(new ui.w.Event('change'));await tick();
  assert.equal(Object.keys(selections.at(-1)).length,0);
  ui.dom.window.close();
});

test('plan checks release readiness on opening and keeps normal pilots usable through setup changes',async()=>{
  const unavailable={context:'alice',available:false,
    items:[{candidate_id:'must-not-render',target_id:'installed-lightwork',state:'authorized'}],
    readiness:{status:'setup_required',release_decisions:false,deployed_release_check:false,
      next_action:'Ask an installation administrator to connect release controls. You can still plan a normal workflow pilot.'}};
  const ready={context:'alice',available:true,items:[{candidate_id:'candidate-one',target_id:'installed-lightwork',state:'authorized'}],
    readiness:{status:'ready',release_decisions:true,deployed_release_check:true,
      next_action:'Choose a candidate. Its deployed baseline is checked again when you freeze the plan.'}};
  const ui=await setup([unavailable,ready,unavailable]);
  const form=ui.d.getElementById('op-plan'), picker=ui.d.getElementById('op-candidate');
  form.elements.title.value='Keep my plan';
  const details=ui.d.getElementById('op-plan-details');Object.defineProperty(details,'open',{value:true});
  details.dispatchEvent(new ui.w.Event('toggle'));await tick();
  assert.match(ui.calls[2].url,/release-candidates$/);
  assert.equal(picker.disabled,true);
  assert.deepEqual([...picker.options].map(option=>option.value),['']);
  assert.match(ui.d.getElementById('op-candidate-status').textContent,/normal workflow pilot/);
  assert.equal(form.elements.title.disabled,false);
  ui.d.getElementById('op-candidate-refresh').click();await tick();
  assert.equal(picker.disabled,false);
  assert.equal(picker.options.length,2);
  picker.value='candidate-one';picker.dispatchEvent(new ui.w.Event('change'));
  assert.equal(ui.d.getElementById('op-learning-mode').value,'exclude_local_learning');
  ui.d.getElementById('op-candidate-refresh').click();await tick();
  assert.equal(picker.disabled,true);
  assert.equal(picker.value,'');
  assert.equal(form.elements.title.value,'Keep my plan');
  ui.dom.window.close();
});

test('duplicate-pilot conflict keeps the complete plan and exact retry reference',async()=>{
  const conflict=()=>({ok:false,status:409,json:async()=>({detail:'One or more selected work items already belongs to an active or frozen pilot in this tenant. No allocation model is configured.'})});
  const ui=await setup([conflict]);
  const form=ui.d.getElementById('op-plan');
  form.elements.title.value='Competing customer pilot';form.elements.customer.value='Private customer';
  form.elements.workflow.value='Review evidence';form.elements.criteria.value='Every citation is current';
  [...ui.d.querySelectorAll('#op-planned-cases select')].forEach((select,index)=>{select.value='goal:'+(index+1);});
  form.dispatchEvent(new ui.w.Event('submit',{bubbles:true,cancelable:true}));await tick();
  assert.equal(form.elements.title.value,'Competing customer pilot');
  assert.equal(form.elements.customer.value,'Private customer');
  assert.equal(ui.d.querySelectorAll('#op-planned-cases select').length,4);
  assert.ok([...ui.d.querySelectorAll('#op-planned-cases select')].every(select=>select.value));
  // The refused review admitted nothing, so there is no original to retry.
  assert.equal(ui.calls.filter(call=>call.url===CONTROLS+'/save').length,0);
  assert.equal(ui.w.sessionStorage.getItem('lightwork-pilot-original'),null);
  assert.match(ui.d.getElementById('op-status').textContent,/No allocation model is configured/);
  assert.match(ui.d.getElementById('op-status').textContent,/entered work is kept/);
  assert.equal(form.elements.title.disabled,false);ui.dom.window.close();
});

test('independent review binds exact evidence and needs a separate confirmation',async()=>{
  const packet={...report(),learning_policy:{prior_exposure_statement:'Local inputs checked; external training unknown.',automatic_local_exclusion_enforced:true,evidence_version:'c'.repeat(64)}};
  const ui=await setup([packet,reviewReply('review'),savedReply()]);
  pickPilot(ui,'OPL-test');ui.d.getElementById('op-review-load').click();await tick();
  const form=ui.d.querySelector('#op-independent-report form');form.querySelector('textarea').value='Independent policy receipts and their limits checked.';
  form.dispatchEvent(new ui.w.Event('submit',{bubbles:true,cancelable:true}));await tick();assert.equal(ui.calls.length,3);
  form.querySelector('input[type="checkbox"]').checked=true;form.dispatchEvent(new ui.w.Event('submit',{bubbles:true,cancelable:true}));await tick();await tick();
  assert.equal(ui.calls[3].url,CONTROLS+'/review');
  const body=sent(ui.calls[3]);assert.deepEqual([body.kind,body.pilot],['review','OPL-test']);
  assert.equal(body.values.confirm,true);assert.equal(body.values.evidence_version,'c'.repeat(64));assert.equal(body.values.expected_revision,2);
  assert.equal(ui.calls.length,4,'recording needs the separate confirmation of the complete review');
  await confirmSave(ui);
  assert.deepEqual(sent(ui.calls[4]),{token:'sealed-review',confirmed:true});
  assert.match(ui.d.getElementById('op-independent-report').textContent,/Independent review recorded/);
  ui.dom.window.close();
});

test('HTML access loss during independent review clears private report, prepared inputs and picker labels',async()=>{
  const ui=await setup([report(),()=>({ok:false,status:403,json:async()=>{throw new SyntaxError('HTML');}})]);await open(ui);
  ui.d.getElementById('op-prior-exposure').value='Private trial notes';pickPilot(ui,'OPL-test');ui.d.getElementById('op-review-load').click();await tick();
  assert.equal(ui.d.getElementById('op-report').textContent,'');assert.equal(ui.d.getElementById('op-prior-exposure').value,'');assert.equal(ui.d.getElementById('op-selected').options.length,0);
  assert.equal(ui.d.getElementById('op-review-load').disabled,true);ui.dom.window.close();
});

test('structured account-context conflict still clears private pilot inputs',async()=>{
  const changed=()=>({ok:false,status:409,json:async()=>({detail:{code:'pilot_context_changed',message:'The account or workspace changed. Reload the pilot page.'}})});
  const ui=await setup([changed]);
  ui.d.getElementById('op-prior-exposure').value='Private trial notes';
  pickPilot(ui,'OPL-test');ui.d.getElementById('op-review-load').click();await tick();
  assert.equal(ui.d.getElementById('op-prior-exposure').value,'');
  assert.equal(ui.d.getElementById('op-review-reference').value,'');
  assert.equal(ui.d.getElementById('op-review-load').disabled,true);
  assert.match(ui.d.getElementById('op-status').textContent,/account or workspace changed/);ui.dom.window.close();
});

test('pilot picker can load a later context-filtered page',async()=>{
  const dom = new JSDOM(template,{url:'https://lightwork.test',runScripts:'outside-only'});
  const w=dom.window,d=w.document,calls=[];
  w.fetch=async(url,options)=>{
    calls.push({url,options});
    if (url === '/api/v1/outcome-pilots/sources') return {ok:true,json:async()=>({
      context:'alice',items:[],coverage:[],
    })};
    if (url.includes('cursor=OPL-page-one.json')) return {ok:true,json:async()=>({
      context:'alice',partial:false,page:{has_more:false,next_cursor:null},
      items:[{id:'OPL-page-two',title:'Reachable older pilot',cases:4}],
    })};
    if (url.startsWith('/api/v1/outcome-pilots?')) return {ok:true,json:async()=>({
      context:'alice',partial:true,page:{has_more:true,next_cursor:'OPL-page-one.json'},
      items:[{id:'OPL-page-one',title:'First pilot',cases:4}],
    })};
    throw new Error('Unexpected URL: '+url);
  };
  w.eval(script);await tick();await tick();
  const more=d.getElementById('op-load-more');
  assert.equal(more.hidden,false);
  more.click();await tick();await tick();
  assert.deepEqual([...d.getElementById('op-selected').options].map(option=>option.value),[
    '', 'OPL-page-one', 'OPL-page-two',
  ]);
  assert.equal(more.hidden,true);
  assert.ok(calls.some(call=>call.url.includes('cursor=OPL-page-one.json')));
  dom.window.close();
});

test('a code-like server detail is replaced by a plain sentence',()=>{
  const source=require('node:fs').readFileSync(require('node:path').resolve(__dirname,'../../maverick_dashboard/static/lightwork-outcome-pilots.js'),'utf8');
  assert.equal(source.includes("e.loc.slice(1)"),false);
  assert.match(source,/const readable = raw && /);
});

test('reviewers choose a pilot from the waiting list instead of typing a reference',async()=>{
  const ui=await setup([{context:'alice',items:[
    {id:'OPL-one',title:'Invoice triage',frozen_at:1800000000,decision:null},
    {id:'OPL-two',title:'Supplier checks',frozen_at:1800000500,decision:'needs_more_evidence'},
    {id:'not a pilot',title:'Injected',frozen_at:1,decision:null}]}]);
  const panel=ui.d.getElementById('op-review-panel');
  assert.equal(ui.d.getElementById('op-review-reference').tagName,'SELECT');
  Object.defineProperty(panel,'open',{value:true});panel.dispatchEvent(new ui.w.Event('toggle'));for(let i=0;i<10;i++)await tick();
  const labels=[...ui.d.getElementById('op-review-reference').options].map(option=>option.textContent);
  assert.equal(labels.length,3);assert.equal(labels[0],'Choose a pilot');
  assert.match(labels[1],/^Invoice triage · planned /);assert.match(labels[2],/already reviewed \(more evidence requested\)/);
  assert.match(ui.calls.at(-1).url,/independent-review$/);
  assert.doesNotMatch(ui.d.getElementById('op-review-panel').textContent,/OPL-|reference shared/);
  ui.dom.window.close();
});

test('a person who cannot review is told who can, without clearing the page',async()=>{
  const ui=await setup([()=>({ok:false,status:403,json:async()=>({detail:'A different named global administrator must review this pilot.'})})]);
  const panel=ui.d.getElementById('op-review-panel');
  ui.d.getElementById('op-prior-exposure').value='Kept notes';
  Object.defineProperty(panel,'open',{value:true});panel.dispatchEvent(new ui.w.Event('toggle'));for(let i=0;i<10;i++)await tick();
  assert.match(ui.d.getElementById('op-review-note').textContent,/Only an administrator who did not create a pilot/);
  assert.equal(ui.d.getElementById('op-prior-exposure').value,'Kept notes');
  for(let i=0;i<10;i++)await tick();
  ui.dom.window.close();
});
test('opening the plan while the page is still loading checks release readiness once loading finishes',async()=>{
  const dom=new JSDOM(template,{url:'https://lightwork.test',runScripts:'outside-only'});
  const w=dom.window,d=w.document,calls=[];let release;const listed=new Promise(resolve=>{release=resolve;});
  const readiness={context:'alice',available:false,items:[],
    readiness:{status:'setup_required',release_decisions:false,deployed_release_check:false,
      next_action:'Ask an installation administrator to connect release controls. You can still plan a normal workflow pilot.'}};
  w.fetch=async url=>{
    calls.push(url);
    if (/release-candidates$/.test(url)) return {ok:true,json:async()=>readiness};
    if (/\/sources$/.test(url)) return {ok:true,json:async()=>({context:'alice',items:[],coverage:[]})};
    await listed;return {ok:true,json:async()=>({context:'alice',items:[]})};
  };
  w.eval(script);await tick();
  const details=d.getElementById('op-plan-details');Object.defineProperty(details,'open',{value:true});
  details.dispatchEvent(new w.Event('toggle'));await tick();
  assert.equal(calls.some(url=>/release-candidates$/.test(url)),false);
  release();for(let i=0;i<10;i++)await tick();
  assert.equal(calls.filter(url=>/release-candidates$/.test(url)).length,1);
  assert.match(d.getElementById('op-candidate-status').textContent,/normal workflow pilot/);
  dom.window.close();
});
test('saving pilot work leaves the cohort value report fields in their own states',async()=>{
  const ui=await setup([]);
  const own=ui.d.querySelector('[data-own-controls]');assert.ok(own);
  const fields=[...own.querySelectorAll('button,input,select,textarea')];assert.ok(fields.length);
  const before=fields.map(field=>field.disabled);assert.ok(before.includes(true));
  const form=ui.d.getElementById('op-plan');form.elements.title.value='Unchanged';
  ui.d.getElementById('op-candidate-refresh').click();for(let i=0;i<6;i++)await tick();
  assert.deepEqual(fields.map(field=>field.disabled),before);
  ui.dom.window.close();
});
const valueFields=ui=>[...ui.d.querySelector('[data-own-controls]').querySelectorAll('button,input,select,textarea')];
test('the cohort value report closes with the page when workspace or access changes',async()=>{
  for (const lose of [
    async ui=>{ui.d.dispatchEvent(new ui.w.CustomEvent('lightwork:workspace-changed',{detail:{}}));},
    async ui=>{await open(ui);},  // the answer to this request is a refusal
  ]) {
    const ui=await setup([()=>({ok:false,status:403,json:async()=>({detail:'Access changed.'})})]);
    const fields=valueFields(ui);assert.ok(fields.length);
    assert.ok(fields.some(field=>!field.disabled),'some report controls start usable');
    await lose(ui);for(let i=0;i<6;i++)await tick();
    assert.deepEqual(fields.filter(field=>!field.disabled).map(field=>field.id||field.name||field.tagName),[]);
    assert.equal(ui.d.getElementById('outcome-pilots').dataset.valueLocked,'true');
    // Later pilot work finishing cannot reopen it.
    ui.d.getElementById('op-candidate-refresh').click();for(let i=0;i<6;i++)await tick();
    assert.equal(fields.some(field=>!field.disabled),false);
    ui.dom.window.close();
  }
});
test('the cohort value report stays closed while workflow pilots are turned off',async()=>{
  const ui=await setup([],'false');for(let i=0;i<6;i++)await tick();
  const fields=valueFields(ui);assert.ok(fields.length);
  assert.deepEqual(fields.filter(field=>!field.disabled).map(field=>field.id||field.name||field.tagName),[]);
  assert.equal(ui.d.getElementById('outcome-pilots').dataset.valueLocked,'true');
  assert.match(ui.d.getElementById('op-status').textContent,/turned off/);
  ui.dom.window.close();
});
