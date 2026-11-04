'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{JSDOM}=require('jsdom');
const folder=path.resolve(__dirname,'../../maverick_dashboard'),read=name=>fs.readFileSync(path.join(folder,name),'utf8');
const source={id:'ACO-'+'c'.repeat(32),version:'b'.repeat(64),provider:'openai',source_account_id:'synthetic-account',source_record_id:'<img src=x> invoice',currency:'USD',net_cost:'10.000000001',correction_count:1,period_start:'2026-08-01',period_end:'2026-09-01',receipts:[],observations:[]};
const report=()=>({context:'alice',id:'OPL-test',revision:2,title:'Synthetic pilot',customer:'Example',workflow:'Review',criteria:'Good evidence',groups:{},limitations:[],
  cases:[1,2].map(id=>({id:String(id),label:'Case '+id,allocation:'holdout',status:'unmeasured',measurement:null,source:{href:'/chat/goal/'+id,version:'a'.repeat(64),accepted:false,runtime_cost_usd:null,sample:false}})),
  provider_costs:{status:'current',current_totals_by_currency:{},allocations:[]}});
async function fixture(intercept=()=>undefined){
  const dom=new JSDOM(read('templates/outcome_pilots.html').replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,''),{url:'https://lightwork.test',runScripts:'outside-only'}),{window:w}=dom,d=w.document,calls=[];
  d.getElementById('outcome-pilots').dataset.context='alice';d.getElementById('outcome-pilots').dataset.enabled='true';
  w.fetch=async(url,options)=>{const call={url:new URL(url,w.location),...options};calls.push(call);let value=await intercept(call);if(value instanceof Error)throw value;if(value instanceof Response)return value;
    if(value===undefined){const route=call.url.pathname;if(route.endsWith('/sources'))value={context:'alice',items:[],coverage:[],specialists:[]};else if(route.endsWith('/provider-costs'))value=call.method==='PUT'?{context:'alice',id:'OPL-test',revision:3}:{context:'alice',items:[source],total:1,next_offset:null};else if(route.endsWith('/OPL-test'))value=report();else value={context:'alice',items:[{id:'OPL-test',title:'Pilot',cases:2}]};}
    return new Response(JSON.stringify(value),{headers:{'Content-Type':'application/json'}});
  };
  const settle=async()=>{for(let i=0;i<10;i++)await new Promise(done=>setImmediate(done));};
  w.eval(read('static/lightwork-outcome-pilot-costs.js'));w.eval(read('static/lightwork-outcome-pilots.js'));await settle();
  const chosen=d.getElementById('op-selected');chosen.value='OPL-test';chosen.dispatchEvent(new w.Event('change'));await settle();
  const fill=(el,value)=>{el.value=value;el.dispatchEvent(new w.Event('input',{bubbles:true}));};
  return{w,d,calls,settle,fill,close:()=>w.close()};
}
async function select(ui){const form=ui.d.getElementById('op-cost-form');[...form.querySelectorAll('button')].find(e=>e.textContent==='Find billing receipts').click();await ui.settle();const select=form.querySelector('select');select.value=source.id;select.dispatchEvent(new ui.w.Event('change'));ui.fill(form.querySelector('textarea'),'Reviewed synthetic attribution, not live invoice acceptance.');return form;}
function submit(ui,form){form.dispatchEvent(new ui.w.Event('submit',{cancelable:true,bubbles:true}));}

test('allocation derives amounts from a selected source, requires review and sends exact shares only',async t=>{
  const ui=await fixture();t.after(ui.close);const form=await select(ui);assert.equal(form.querySelector('img'),null);assert.match(form.textContent,/<img src=x>/);assert.equal(form.querySelector('input[name="cost"]'),null);
  const percentages=form.querySelectorAll('input[type="number"]');ui.fill(percentages[0],'25.01');ui.fill(percentages[1],'74.99');submit(ui,form);await ui.settle();assert.equal(ui.calls.some(c=>c.method==='PUT'),false);
  form.querySelector('input[type="checkbox"]').checked=true;submit(ui,form);await ui.settle();const write=ui.calls.find(c=>c.method==='PUT'),body=JSON.parse(write.body);assert.equal(body.billing_version,source.version);assert.equal(body.observation_id,source.id);assert.deepEqual(body.shares.map(s=>s.basis_points),[2501,7499]);assert.equal(body.shares[0].source_version,'a'.repeat(64));assert.equal(Object.hasOwn(body,'cost'),false);assert.equal(write.headers['X-Lightwork-Pilot-Context'],'alice');
});

test('changed attribution resets review, over-allocation cannot save, and a lost response keeps exact retry inputs',async t=>{
  let writes=0;const ui=await fixture(call=>{if(call.method==='PUT'){writes++;return new Error('Connection interrupted');}});t.after(ui.close);const form=await select(ui),percent=form.querySelectorAll('input[type="number"]'),confirm=form.querySelector('input[type="checkbox"]');
  confirm.checked=true;ui.fill(percent[0],'70');assert.equal(confirm.checked,false);ui.fill(percent[1],'70');confirm.checked=true;submit(ui,form);await ui.settle();assert.equal(writes,0);assert.match(form.textContent,/exceed 100%/);
  ui.fill(percent[1],'30');confirm.checked=true;submit(ui,form);await ui.settle();assert.equal(writes,1);assert.equal(percent[0].value,'70');submit(ui,form);await ui.settle();assert.equal(writes,2);const requests=ui.calls.filter(c=>c.method==='PUT');assert.equal(requests[0].body,requests[1].body);assert.match(ui.d.getElementById('op-status').textContent,/not responding\. Keep your inputs/);
});

test('pending allocation uses shared busy protection and blocks duplicate writes',async t=>{
  let finish;const ui=await fixture(call=>call.method==='PUT'?new Promise(resolve=>finish=resolve):undefined);t.after(ui.close);const form=await select(ui);ui.fill(form.querySelector('input[type="number"]'),'100');form.querySelector('input[type="checkbox"]').checked=true;
  submit(ui,form);submit(ui,form);assert.equal(ui.calls.filter(c=>c.method==='PUT').length,1);assert.equal(form.querySelector('textarea').disabled,true);finish({context:'alice',id:'OPL-test',revision:3});await ui.settle();assert.equal(ui.d.getElementById('outcome-pilots').getAttribute('aria-busy'),'false');
});

test('financial access loss clears provider details; stale coverage stays explicit',async t=>{
  let denied=false;const ui=await fixture(call=>denied&&call.url.pathname.endsWith('/provider-costs')?new Response('{"detail":"Billing access revoked"}',{status:403}):undefined);t.after(ui.close);const form=await select(ui);denied=true;[...form.querySelectorAll('button')].find(e=>e.textContent==='Find billing receipts').click();await ui.settle();assert.equal(ui.d.getElementById('op-report').textContent,'');assert.equal(ui.d.body.textContent.includes('synthetic-account'),false);assert.equal(ui.d.getElementById('op-cost-form'),null);assert.equal(ui.d.getElementById('op-export').disabled,true);
  const partial=await fixture(call=>call.url.pathname.endsWith('/OPL-test')?{...report(),provider_costs:{...report().provider_costs,status:'partial',allocations:[{status:'source_unavailable'}]}}:undefined);t.after(partial.close);assert.match(partial.d.getElementById('op-provider-costs').textContent,/coverage is partial/);assert.match(partial.d.getElementById('op-provider-costs').textContent,/Unknown costs are not zero/);
});

test('complete cost coverage is separately reviewed and never turns missing costs into zero',async t=>{
  const coverage={status:'needs_review',can_confirm:true,version:'d'.repeat(64),currency:'USD',planned_cases:4,covered_cases:4,accepted_outcomes:1,provider_cost_per_accepted_outcome:null,explanation:'Include failed attempts and rejections.'};
  const ui=await fixture(call=>call.url.pathname.endsWith('/OPL-test')?{...report(),provider_costs:{...report().provider_costs,coverage}}:undefined);t.after(ui.close);
  const form=ui.d.getElementById('op-cost-coverage-form');assert.match(ui.d.getElementById('op-cost-coverage').textContent,/Not measured/);ui.fill(form.querySelector('textarea'),'All four cases including three rejected results were reviewed.');submit(ui,form);await ui.settle();assert.equal(ui.calls.some(c=>c.method==='PUT'),false);
  form.querySelector('input[type="checkbox"]').checked=true;submit(ui,form);await ui.settle();const write=ui.calls.find(c=>c.method==='PUT');assert.match(write.url.pathname,/provider-costs\/coverage$/);const body=JSON.parse(write.body);assert.equal(body.coverage_version,coverage.version);assert.equal(body.currency,'USD');assert.equal(body.confirm,true);assert.equal(Object.hasOwn(body,'accepted_outcomes'),false);
  const missing=await fixture(call=>call.url.pathname.endsWith('/OPL-test')?{...report(),provider_costs:{...report().provider_costs,coverage:{...coverage,status:'incomplete',can_confirm:false,covered_cases:3}}}:undefined);t.after(missing.close);const blocked=missing.d.getElementById('op-cost-coverage-form');assert.equal(blocked.querySelector('button').disabled,true);assert.match(missing.d.getElementById('op-cost-coverage').textContent,/Missing costs are not zero/);
});

test('a saved allocation redraws the report with the current allocated cost',async t=>{
  let saved=false;const ui=await fixture(call=>{if(call.method==='PUT'){saved=true;return undefined;}if(saved&&call.url.pathname.endsWith('/OPL-test'))return {...report(),revision:3,provider_costs:{...report().provider_costs,current_totals_by_currency:{USD:'10.000000001'}}};});t.after(ui.close);
  const form=await select(ui);ui.fill(form.querySelector('input[type="number"]'),'100');form.querySelector('input[type="checkbox"]').checked=true;submit(ui,form);await ui.settle();
  assert.equal(saved,true);assert.match(ui.d.getElementById('op-provider-costs').textContent,/Current allocated provider cost: USD 10\.000000001/);assert.match(ui.d.getElementById('op-status').textContent,/Saved\. The current report is shown below\./);
});
