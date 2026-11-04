'use strict';
const {test} = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), {JSDOM} = require('jsdom');
const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(resolve => setImmediate(resolve)); };

test('notification access denial clears private destination, receipt and task labels', async t => {
  const names = ['mode','timezone','digest_time','quiet_start','quiet_end','quiet_enabled','critical_exceptions','watch_all_projects','mentions'];
  const nodes = ['personal-notification-status','personal-notification-error','personal-notification-items','personal-notification-save-status',
    'personal-notification-refresh','notification-project-watches','notification-mutes','personal-background-status','personal-external-status',
    'personal-delivery-receipts','personal-external-links','personal-critical-policy','notification-add-mute','notification-reload-preferences'];
  const dom = new JSDOM('<form id="notification-preferences">' + names.map(name => '<input name="'+name+'">').join('')
    + '<button type="submit">Save</button><select id="notification-mute-task"></select><select id="notification-mute-duration"><option value="3600">Hour</option></select></form>'
    + nodes.map(id => '<div id="'+id+'"></div>').join(''), {url:'https://dashboard.example.test/notifications', runScripts:'outside-only', pretendToBeVisual:true});
  t.after(() => dom.window.close());
  const state = {context:'same-account', revision:'a'.repeat(64), checked_at:1, delivery_note:'Ready', items:[], tasks:[{id:1,title:'PRIVATE TASK'}],
    projects:[], preferences:{mode:'immediate',timezone:'UTC',digest_time:'09:00',quiet_start:'22:00',quiet_end:'08:00',events:[],muted_tasks:{},external_links:[]},
    private_delivery:{note:'Ready',channels:[{id:'b'.repeat(32),channel:'slack',sender_id:'PRIVATE SENDER',available:true,receipts:[{at:1,message:'PRIVATE RECEIPT'}]}]}};
  let calls=0;
  dom.window.fetch = async () => ++calls === 1 ? {ok:true,json:async()=>state} : {ok:false,status:403,json:async()=>({detail:'Access changed'})};
  dom.window.setInterval = () => 1; dom.window.clearInterval = () => {};
  dom.window.eval(fs.readFileSync(path.resolve(__dirname,'../../maverick_dashboard/static/lightwork-personal-notifications.js'),'utf8'));
  await settle();
  assert.match(dom.window.document.body.textContent, /PRIVATE SENDER/);
  dom.window.document.getElementById('personal-notification-refresh').click(); await settle();
  assert.doesNotMatch(dom.window.document.body.textContent, /PRIVATE TASK|PRIVATE SENDER|PRIVATE RECEIPT/);
  assert.equal(dom.window.document.getElementById('notification-preferences').hidden, true);
});

test('each alert shows why, what and by when, and mutes from the alert with an undo', async t => {
  const names = ['mode','timezone','digest_time','quiet_start','quiet_end','quiet_enabled','critical_exceptions','watch_all_projects','mentions'];
  const nodes = ['personal-notification-status','personal-notification-error','personal-notification-items','personal-notification-save-status',
    'personal-notification-refresh','notification-project-watches','notification-mutes','personal-background-status','personal-external-status',
    'personal-delivery-receipts','personal-external-links','personal-critical-policy','notification-add-mute','notification-reload-preferences',
    'personal-notification-mute-status'];
  const dom = new JSDOM('<form id="notification-preferences">' + names.map(name => '<input name="'+name+'">').join('')
    + '<button type="submit">Save</button><select id="notification-mute-task"></select><select id="notification-mute-duration"><option value="3600">Hour</option></select></form>'
    + nodes.map(id => '<div id="'+id+'"></div>').join(''), {url:'https://dashboard.example.test/notifications', runScripts:'outside-only', pretendToBeVisual:true});
  t.after(() => dom.window.close());
  const prefs = {mode:'immediate',timezone:'UTC',digest_time:'09:00',quiet_start:'22:00',quiet_end:'08:00',events:[],muted_tasks:{},muted_agents:{},external_links:[]};
  const item = {id:'a'.repeat(64), title:'Quarterly review', href:'/chat/goal/3#question-panel', label:'Needs your answer',
    reason:'You started this task', action:"Answer the agent's question so the task can continue", due_at:null,
    due_label:'Due', no_due:'The task waits until you answer', waiting_since:1, goal_id:3, agent:'finance_ap', agent_label:'finance ap', seen_at:null};
  const base = {context:'same-account', revision:'a'.repeat(64), checked_at:1, delivery_note:'Ready', tasks:[{id:3,title:'Quarterly review'}],
    projects:[], private_delivery:{note:'Ready', channels:[]}};
  const posted = [];
  dom.window.fetch = async (url, options) => {
    if (options && options.body) posted.push([url, JSON.parse(options.body)]);
    if (String(url).endsWith('/mute')) return {ok:true, json:async()=>({...base, items:[], preferences:{...prefs, muted_tasks:{'3':2e9}},
      muted:{scope:'task', key:'3', label:'Quarterly review', until:2e9}})};
    return {ok:true, json:async()=>({...base, items:[item], preferences:prefs})};
  };
  dom.window.setInterval = () => 1; dom.window.clearInterval = () => {};
  dom.window.mvTimeAbsolute = () => 'ABSOLUTE'; dom.window.mvTimeRelative = () => '10 minutes ago';
  dom.window.eval(fs.readFileSync(path.resolve(__dirname,'../../maverick_dashboard/static/lightwork-personal-notifications.js'),'utf8'));
  await settle();
  const doc = dom.window.document;
  const article = doc.querySelector('#personal-notification-items article');
  assert.equal(article.querySelector('a').getAttribute('href'), '/chat/goal/3#question-panel');
  assert.equal(article.querySelector('.personal-alert__why .badge').textContent, 'You started this task');
  assert.match(article.querySelector('.personal-alert__next').textContent,
    /Answer the agent's question so the task can continue\. The task waits until you answer\. Asked 10 minutes ago\./);
  const buttons = Array.from(article.querySelectorAll('button')).map(b => b.textContent);
  assert.deepEqual(buttons, ['Mark seen', 'Mute this task', 'Mute alerts from this agent']);
  Array.from(article.querySelectorAll('button')).find(b => b.textContent === 'Mute this task').click();
  await settle();
  assert.deepEqual(posted.at(-1), ['/api/v1/notifications/personal/mute', {context:'same-account', item_id:'a'.repeat(64), scope:'task'}]);
  const status = doc.getElementById('personal-notification-mute-status');
  assert.match(status.textContent, /Muted alerts for Quarterly review until ABSOLUTE\./);
  status.querySelector('button').click();
  await settle();
  assert.deepEqual(posted.at(-1), ['/api/v1/notifications/personal/unmute', {context:'same-account', scope:'task', key:'3'}]);
});

test('saving notification preferences says "Saving…", then the truth, and a failure keeps the draft', async t => {
  const names = ['mode','timezone','digest_time','quiet_start','quiet_end','quiet_enabled','critical_exceptions','watch_all_projects','mentions'];
  const nodes = ['personal-notification-status','personal-notification-error','personal-notification-items','personal-notification-save-status',
    'personal-notification-refresh','notification-project-watches','notification-mutes','personal-background-status','personal-external-status',
    'personal-delivery-receipts','personal-external-links','personal-critical-policy','notification-add-mute','notification-reload-preferences',
    'personal-notification-mute-status'];
  const dom = new JSDOM('<form id="notification-preferences">' + names.map(name => '<input name="'+name+'">').join('')
    + '<button type="submit">Save</button><select id="notification-mute-task"></select><select id="notification-mute-duration"><option value="3600">Hour</option></select></form>'
    + nodes.map(id => '<div id="'+id+'"></div>').join(''), {url:'https://dashboard.example.test/notifications', runScripts:'outside-only', pretendToBeVisual:true});
  t.after(() => dom.window.close());
  const state = {context:'same-account', revision:'a'.repeat(64), checked_at:1, delivery_note:'Ready', items:[], tasks:[], projects:[],
    preferences:{mode:'immediate',timezone:'UTC',digest_time:'09:00',quiet_start:'22:00',quiet_end:'08:00',events:[],muted_tasks:{},external_links:[]},
    private_delivery:{note:'Ready',channels:[]}};
  const pending = [];
  dom.window.fetch = (url, options) => new Promise(resolve => { pending.push({options, resolve}); });
  dom.window.setInterval = () => 1; dom.window.clearInterval = () => {};
  dom.window.eval(fs.readFileSync(path.resolve(__dirname,'../../maverick_dashboard/static/lightwork-personal-notifications.js'),'utf8'));
  const doc = dom.window.document, form = doc.getElementById('notification-preferences');
  const saveStatus = doc.getElementById('personal-notification-save-status');
  const submit = () => form.dispatchEvent(new dom.window.Event('submit', {cancelable:true}));
  pending.shift().resolve({ok:true, status:200, json:async()=>state}); await settle();
  // A successful save.
  submit(); await settle();
  assert.equal(saveStatus.textContent, 'Saving…');
  pending.shift().resolve({ok:true, status:200, json:async()=>state}); await settle();
  assert.match(saveStatus.textContent, /were saved/);
  // The next save fails: the earlier "saved" must not stay next to the button.
  form.elements.timezone.value = 'Europe/Paris';
  submit(); await settle();
  assert.equal(saveStatus.textContent, 'Saving…');
  pending.shift().resolve({ok:false, status:500, json:async()=>({detail:'Internal Server Error'})}); await settle();
  assert.doesNotMatch(saveStatus.textContent, /were saved/);
  assert.match(saveStatus.textContent, /not saved/i);
  assert.equal(form.elements.timezone.value, 'Europe/Paris');
  assert.equal(doc.getElementById('personal-notification-error').hidden, false);
  assert.equal(pending.length, 0);
});

test('a task waiting on your answer can be stopped from its alert in one action', async t => {
  const names = ['mode','timezone','digest_time','quiet_start','quiet_end','quiet_enabled','critical_exceptions','watch_all_projects','mentions'];
  const nodes = ['personal-notification-status','personal-notification-error','personal-notification-items','personal-notification-save-status',
    'personal-notification-refresh','notification-project-watches','notification-mutes','personal-background-status','personal-external-status',
    'personal-delivery-receipts','personal-external-links','personal-critical-policy','notification-add-mute','notification-reload-preferences',
    'personal-notification-mute-status'];
  const dom = new JSDOM('<form id="notification-preferences">' + names.map(name => '<input name="'+name+'">').join('')
    + '<button type="submit">Save</button><select id="notification-mute-task"></select><select id="notification-mute-duration"><option value="3600">Hour</option></select></form>'
    + nodes.map(id => '<div id="'+id+'"></div>').join(''), {url:'https://dashboard.example.test/notifications', runScripts:'outside-only', pretendToBeVisual:true});
  t.after(() => dom.window.close());
  const prefs = {mode:'immediate',timezone:'UTC',digest_time:'09:00',quiet_start:'22:00',quiet_end:'08:00',events:[],muted_tasks:{},muted_agents:{},external_links:[]};
  const item = {id:'c'.repeat(64), title:'Quarterly review', href:'/chat/goal/3#question-panel', label:'Needs your answer', category:'needs-decision',
    reason:'You started this task', action:"Answer the agent's question so the task can continue", due_at:null,
    due_label:'Due', no_due:'The task waits until you answer', waiting_since:1, goal_id:3, seen_at:null};
  const finished = {...item, id:'d'.repeat(64), category:'completed', label:'Finished'};
  const base = {context:'same-account', revision:'a'.repeat(64), checked_at:1, delivery_note:'Ready', tasks:[{id:3,title:'Quarterly review'}],
    projects:[], private_delivery:{note:'Ready', channels:[]}};
  const calls = [];
  dom.window.fetch = async (url, options) => {
    calls.push([String(url), options && options.method]);
    if (String(url).endsWith('/cancel')) return {ok:true, status:204, json:async()=>({})};
    return {ok:true, json:async()=>({...base, items:[item, finished], preferences:prefs})};
  };
  dom.window.setInterval = () => 1; dom.window.clearInterval = () => {};
  dom.window.eval(fs.readFileSync(path.resolve(__dirname,'../../maverick_dashboard/static/lightwork-personal-notifications.js'),'utf8'));
  await settle();
  const [waiting, done] = dom.window.document.querySelectorAll('#personal-notification-items article');
  assert.deepEqual(Array.from(done.querySelectorAll('button')).map(b => b.textContent), ['Mark seen', 'Mute this task']);
  const stop = Array.from(waiting.querySelectorAll('button')).find(b => b.textContent === 'Stop task');
  assert.ok(stop, 'Stop task is offered on the waiting task');
  stop.click(); await settle();
  assert.ok(calls.some(([url, method]) => url === '/api/v1/goals/3/cancel' && method === 'POST'));
  assert.match(dom.window.document.getElementById('personal-notification-mute-status').textContent, /Task stopped\. Open it/);
});
