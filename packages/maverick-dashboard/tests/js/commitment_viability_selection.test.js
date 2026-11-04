'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path');
const {JSDOM} = require('jsdom');
const {shell} = require('./_shell');

const script = fs.readFileSync(path.resolve(__dirname,
  '../../maverick_dashboard/static/lightwork-commitment-viability.js'), 'utf8');
const tick = () => new Promise(resolve => setImmediate(resolve));
const reply = body => ({ok:true, status:200, json:async()=>body});
const review = (id, title) => ({context:'local', id, title, revision:1,
  assessment:{status:'feasible', stale_source_ids:[], evaluated_at:1, components:[]},
  model:{options:[{id:'option', units:1, kind:'capacity', ready_at:1, expires_at:2,
    cost_note:'', owner_confirmation:false}], commitments:[]},
  labels:{}, sources:[], proposals:[], audit_status:'recorded', owner_can_confirm:false});

function setup(project = item => item) {
  const ids = ['cmv-message','cmv-report-title','cmv-lifecycle-note','cmv-report-state','cmv-report-explanation',
    'cmv-source-note','cmv-components','cmv-gaps','cmv-options','cmv-proposals','cmv-sources'];
  const dom = new JSDOM(`<div id="cmv-enabled" data-context="local">
    <select id="cmv-select"><option value="">Choose a review</option></select>
    <button id="cmv-open"></button><button id="cmv-refresh"></button>
    <button id="cmv-more"></button><button id="cmv-reassess"></button>
    <details id="cmv-new-details"><p id="cmv-copy-note" hidden></p><form id="cmv-new">
      <input name="title"><input name="order_a_name"><input name="order_a_due_at">
      <input name="order_a_material_units"><input type="checkbox" name="order_a_uses_capacity">
      <input name="order_b_name"><input name="order_b_due_at">
      <input name="order_b_material_units"><input type="checkbox" name="order_b_uses_capacity">
      <input name="capacity_name"><input name="capacity_units"><input name="material_name">
      <input name="stock_units"><select name="stock_certainty"><option value="unknown">Unknown</option>
        <option value="confirmed">Confirmed</option></select>
      <input name="option_name"><select name="option_kind"><option value="material">Material</option>
        <option value="capacity">Capacity</option></select><input name="option_units">
      <input name="option_ready_at"><input name="option_expires_at"><input name="option_cost_note">
      <input name="option_lead_hours"><textarea name="basis"></textarea><input name="review_by">
    </form></details>
    <section id="cmv-report" hidden>${ids.map(id=>`<div id="${id}"></div>`).join('')}
      <details id="cmv-trace-details"><form id="cmv-trace"><select name="running_order"></select>
        <select name="blocked_order"></select><textarea name="basis"></textarea></form></details>
      <details id="cmv-archive-details"><summary></summary><form id="cmv-archive">
        <input type="checkbox" name="confirm_finished"></form></details></section></div>`,
  {url:'http://testserver/commitment-reviews',runScripts:'outside-only'});
  const w = dom.window, d = w.document, calls = [], selections = [];
  let releaseRead = null;
  w.fetch = async (url, options) => {
    calls.push({url, method:options.method});
    if (url.includes('?')) return reply({context:'local', items:[
      {id:'a',title:'First review'},{id:'b',title:'Second review'}],
    page:{has_more:false,next_cursor:''}});
    if (url.endsWith('/a') && releaseRead) return new Promise(resolve => {
      const release = releaseRead; releaseRead = null;
      release(() => resolve(reply(review('a','First review'))));
    });
    return reply(project(review(url.endsWith('/a')?'a':'b',url.endsWith('/a')?'First review':'Second review')));
  };
  d.addEventListener('lightwork:copilot-selection', event => selections.push(event.detail.selection));
  shell(w);
  w.eval(script);
  return {dom,w,d,calls,selections,delayNextRead:callback => {releaseRead=callback;}};
}

test('switch, refresh and delayed read cannot leave a different review actionable', async () => {
  const ui=setup(), d=ui.d, select=d.getElementById('cmv-select');
  await tick();
  select.value='b'; select.dispatchEvent(new ui.w.Event('change'));
  d.getElementById('cmv-open').click(); await tick();
  assert.equal(d.getElementById('cmv-report-title').textContent,'Second review');
  d.getElementById('cmv-trace').elements.basis.value='Second review observation';
  select.value='a'; // Programmatic selection changes do not dispatch a change event.
  d.getElementById('cmv-trace').dispatchEvent(new ui.w.Event('submit',{bubbles:true,cancelable:true}));
  assert.equal(d.getElementById('cmv-report').hidden,true);
  assert.equal(d.getElementById('cmv-trace').elements.basis.value,'');
  assert.equal(ui.calls.some(call=>call.method==='POST'),false);
  select.value='b'; select.dispatchEvent(new ui.w.Event('change'));
  d.getElementById('cmv-open').click(); await tick();
  d.getElementById('cmv-trace').elements.basis.value='Another second review observation';
  select.value='a'; select.dispatchEvent(new ui.w.Event('change'));
  assert.equal(d.getElementById('cmv-report').hidden,true);
  assert.equal(d.getElementById('cmv-trace').elements.basis.value,'');
  assert.equal(select.value,'a');
  assert.equal(Object.keys(ui.selections.at(-1)).length,0);
  d.getElementById('cmv-trace').dispatchEvent(new ui.w.Event('submit',{bubbles:true,cancelable:true}));
  assert.equal(ui.calls.some(call=>call.method==='POST'),false);

  let release;
  ui.delayNextRead(callback => {release=callback;});
  d.getElementById('cmv-open').click(); await tick();
  select.value='b'; select.dispatchEvent(new ui.w.Event('change'));
  release(); await tick(); await tick();
  assert.equal(d.getElementById('cmv-report').hidden,true);
  assert.equal(select.value,'b');

  d.getElementById('cmv-open').click(); await tick();
  assert.equal(d.getElementById('cmv-report-title').textContent,'Second review');
  d.getElementById('cmv-refresh').click();
  assert.equal(d.getElementById('cmv-report').hidden,true);
  assert.equal(Object.keys(ui.selections.at(-1)).length,0);
  await tick();
  assert.equal(select.value,'b');
  assert.equal(d.getElementById('cmv-report').hidden,true);
  ui.dom.window.close();
});

test('reported capacity gap opens a fresh choice form without copying old evidence', async () => {
  const due = Math.floor(Date.now()/1000) + 86400;
  const ui = setup(item => {
    if (item.id !== 'b') return item;
    item.labels = {a:'Alpha', b:'Beta', press:'Finishing line', material:'Component'};
    item.model.commitments = [
      {id:'a', due_at:due, demands:[{kind:'capacity',key:'press',units:1},
        {kind:'material',key:'material',units:2}]},
      {id:'b', due_at:due, demands:[{kind:'capacity',key:'press',units:1},
        {kind:'material',key:'material',units:2}]},
    ];
    item.model.lots = [{kind:'capacity',key:'press',units:1},
      {kind:'material',key:'material',units:3,certainty:'confirmed'}];
    item.resource_gaps = [{commitment_ids:['a','b'],kind:'capacity',key:'press',
      first_shortfall_at:due, confirmed_shortfall_units:1, remaining_shortfall_units:1,
      remaining_first_shortfall_at:due, conditional_source_ids:[], option_ids:[]}];
    return item;
  });
  await tick();
  const d = ui.d;
  d.getElementById('cmv-select').value = 'b';
  d.getElementById('cmv-open').click(); await tick();
  assert.match(d.getElementById('cmv-gaps').textContent,/still needs up to 1 more Finishing line units/);
  d.querySelector('#cmv-gaps button').click();
  const form = d.getElementById('cmv-new');
  assert.equal(d.getElementById('cmv-new-details').open,true);
  assert.equal(d.getElementById('cmv-copy-note').hidden,false);
  assert.equal(form.elements.option_kind.value,'capacity');
  assert.equal(form.elements.option_units.value,'1');
  assert.equal(form.elements.order_a_name.value,'Alpha');
  assert.equal(form.elements.basis.value,'');
  assert.equal(d.activeElement,form.elements.option_name);
  ui.dom.window.close();
});
