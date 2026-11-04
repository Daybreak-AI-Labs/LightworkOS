'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const {shell} = require('./_shell');
const script = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-project-workspaces.js'), 'utf8');
const templates = path.resolve(__dirname, '../../maverick_dashboard/templates');
// The page includes the workspace controls it shares with Projects.
const template = fs.readFileSync(path.join(templates, 'project_workspaces.html'), 'utf8')
  .replace('{% include "_project_workspace_body.html" %}', () => fs.readFileSync(path.join(templates, '_project_workspace_body.html'), 'utf8'));
const settle = async () => { for (let i = 0; i < 15; i++) await new Promise(resolve => setImmediate(resolve)); };

function page() {
  // The title comes from the shared page header macro; stand in its <h1>.
  const html = template.replace(/\{\{ hero\([\s\S]*?\) \}\}/, '<h1 id="pw-title">Project workspaces</h1>').replace(/\{%[\s\S]*?%\}/g, '').replace(/\{\{ project_id or '' \}\}/g, '1').replace(/\{\{ project_context \}\}/g, 'current-context').replace(/\{\{[\s\S]*?\}\}/g, '');
  const dom = new JSDOM(html, {url:'https://lightwork.invalid/project-workspaces/1', runScripts:'outside-only'});
  const state = {context:'current-context', workspace:{project_id:1, name:'Current project', revision:1, owner:'user:owner', can_edit:true,
    outcome:'Saved outcome', criteria:['Checked'], labels:[], default_view:'list', members:[], milestones:[], context:[], latest_accepted:null,
    editor:{milestones:[], context:[]}}, choices:{goals:[{id:2,title:'Named task',result_available:true}], reviews:[], members:['user:colleague']}, defaults:{revision:0,structure:null}};
  const requests = [], clears = [], recoveries = {};
  let change = async () => ({ok:true, status:200, json:async () => ({status:'confirmed',context:state.context})}), receipt = false;
  dom.window.mvConfirm = async () => true;
  dom.window.mvDraftRecovery = {create(options) { recoveries[options.key] = options; return {clear:async () => { clears.push(options.key); return true; }, dispose() {}}; }};
  dom.window.fetch = async (url, options) => {
    const body = options.body ? JSON.parse(options.body) : null; requests.push({url,body,options});
    if (url.endsWith('/prepare')) return {ok:true,status:200,json:async () => ({revision:state.workspace.revision,summary:'Review exact values',changes:[{label:'Outcome',before:state.workspace.outcome,after:body.payload.outcome || 'New planning'}]})};
    if (url.endsWith('/change')) return change(options);
    if (url.endsWith('/receipt')) return {ok:true,status:200,json:async () => ({confirmed:receipt})};
    return {ok:true,status:200,json:async () => structuredClone(state)};
  };
  shell(dom.window);
  dom.window.eval(script);
  const doc = dom.window.document;
  function edit(value) { const input = doc.getElementById('pw-outcome-input'); input.value = value; input.dispatchEvent(new dom.window.Event('input', {bubbles:true})); }
  function review() { doc.getElementById('pw-details-form').dispatchEvent(new dom.window.Event('submit', {cancelable:true})); }
  function confirm() { doc.getElementById('pw-confirm-choice').checked = true; doc.getElementById('pw-confirm').click(); }
  return {dom,doc,state,requests,clears,recoveries,edit,review,confirm,setChange(value) {change=value;},setReceipt(value) {receipt=value;}};
}

test('review is separate from mutation and editing invalidates prepared confirmation', async () => {
  const p = page(); await settle(); p.edit('Reviewed draft'); p.review(); await settle();
  assert.equal(p.requests.filter(row => row.url.endsWith('/change')).length, 0);
  assert.match(p.doc.getElementById('pw-change-list').textContent, /Reviewed draft/);
  p.edit('Newer unsaved draft'); p.confirm(); await settle();
  assert.equal(p.requests.filter(row => row.url.endsWith('/change')).length, 0);
  assert.equal(p.doc.getElementById('pw-outcome-input').value, 'Newer unsaved draft');
  p.dom.window.close();
});

test('refresh preserves dirty fields and recovery has a stable account-scoped project key', async () => {
  const p = page(); await settle(); p.edit('Unsaved current editor');
  p.state.workspace.outcome = 'Changed in another tab'; p.doc.getElementById('pw-refresh').click(); await settle();
  assert.equal(p.doc.getElementById('pw-outcome').textContent, 'Changed in another tab');
  assert.equal(p.doc.getElementById('pw-outcome-input').value, 'Unsaved current editor');
  assert.ok(p.recoveries['project-workspace:1:details']);
  assert.equal(p.clears.length, 0); p.dom.window.close();
});

test('unconfirmed mutation never repeats automatically and exact retry preserves request identity', async () => {
  const p = page(); await settle(); p.edit('Reviewed draft'); p.review(); await settle();
  p.setChange(async () => ({ok:false,status:503,json:async () => ({detail:'Storage response unavailable'})})); p.confirm(); await settle();
  let writes = p.requests.filter(row => row.url.endsWith('/change')); assert.equal(writes.length, 1);
  assert.equal(p.doc.getElementById('pw-check').hidden, false);
  p.doc.getElementById('pw-check').click(); await settle();
  assert.equal(p.requests.filter(row => row.url.endsWith('/change')).length, 1);
  assert.equal(p.doc.getElementById('pw-retry-exact').hidden, false);
  const original = writes[0].body;
  p.setChange(async () => ({ok:true,status:200,json:async () => ({status:'replayed',context:'current-context'})}));
  p.doc.getElementById('pw-retry-exact').click(); await settle();
  writes = p.requests.filter(row => row.url.endsWith('/change')); assert.equal(writes.length, 2); assert.deepEqual(writes[1].body, original);
  p.dom.window.close();
});

test('acknowledged earlier save never clears a newer in-flight edit or recovery copy', async () => {
  const p = page(); await settle(); p.edit('Sent earlier draft'); p.review(); await settle();
  let release; p.setChange(() => new Promise(resolve => {release=resolve;})); p.confirm(); await settle();
  p.edit('Newer draft while save in flight'); release({ok:true,status:200,json:async () => ({status:'confirmed',context:'current-context'})}); await settle();
  assert.equal(p.doc.getElementById('pw-outcome-input').value, 'Newer draft while save in flight'); assert.equal(p.clears.length, 0);
  p.dom.window.close();
});

test('cancel ends the owned wait and leaves mutation uncertain until receipt recovery', async () => {
  const p = page(); await settle(); p.edit('Pending draft'); p.review(); await settle();
  p.setChange(options => new Promise((resolve,reject) => options.signal.addEventListener('abort', () => reject(new Error('aborted')))));
  p.confirm(); await settle(); p.doc.getElementById('pw-cancel').click(); await settle();
  assert.equal(p.doc.getElementById('pw-check').hidden, false); assert.equal(p.requests.filter(row => row.url.endsWith('/change')).length, 1);
  p.setReceipt(true); p.doc.getElementById('pw-check').click(); await settle();
  assert.equal(p.doc.getElementById('pw-review-panel').hidden, true); assert.equal(p.clears.length, 1); p.dom.window.close();
});

test('changed authenticated context hides private projection and clears editable plaintext', async () => {
  const p = page(); await settle(); p.edit('Private old-account draft'); p.state.context='another-account-context'; p.doc.getElementById('pw-refresh').click(); await settle();
  assert.equal(p.doc.getElementById('pw-workspace').hidden, true); assert.equal(p.doc.getElementById('pw-outcome-input').value, '');
  assert.match(p.doc.getElementById('pw-status').textContent, /account or workspace changed/); p.dom.window.close();
});

test('the project list opens each plan where the page says plans live', async () => {
  const body = fs.readFileSync(path.join(templates, '_project_workspace_body.html'), 'utf8').replace(/\{#[\s\S]*?#\}/g, '');
  const listing = {context:'current-context', projects:[{project_id:7, name:'Close', outcome:'', owned:true}]};
  for (const [planHref, expected] of [['/projects/{id}?tab=plan', '/projects/7?tab=plan'], ['', '/project-workspaces/7']]) {
    const attribute = planHref ? ` data-plan-href="${planHref}"` : '';
    const dom = new JSDOM(`<div id="pw-root" data-project="" data-context="current-context"${attribute}><h2 id="pw-title">Plans</h2>${body}</div>`,
      {url:'https://lightwork.invalid/projects', runScripts:'outside-only'});
    dom.window.mvDraftRecovery = {create() { return {clear:async () => true, dispose() {}}; }};
    dom.window.fetch = async () => ({ok:true, status:200, json:async () => structuredClone(listing)});
    shell(dom.window);
    dom.window.eval(script);
    await settle();
    assert.equal(dom.window.document.querySelector('#pw-list a').getAttribute('href'), expected);
  }
});
