'use strict';
const {test} = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), {JSDOM} = require('jsdom');
const {shell} = require('./_shell');
const folder = path.resolve(__dirname, '../../maverick_dashboard');
const markup = '<div id="settings-sections">' + fs.readFileSync(path.join(folder, 'templates/_maintenance_ops.html'), 'utf8')
  .replace(/\{#[\s\S]*?#\}/g, '').replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '') + '</div>';
const script = fs.readFileSync(path.join(folder, 'static/lightwork-maintenance-ops.js'), 'utf8');

function response(value, status = 200) {
  return new Response(JSON.stringify(value), {status, headers: {'Content-Type': 'application/json'}});
}
const SERVICES = {services: [
  {kind: 'worker', label: 'Background worker', about: 'Runs scheduled and queued tasks.', running: true, since: 1, last_error: '', log: ['ready']},
  {kind: 'channels', label: 'Chat channel server', about: 'Receives messages.', running: false, since: null, last_error: 'Stopped unexpectedly (exit code 3).', log: []}]};

let DASHBOARD = {label: 'This app', about: 'The dashboard you are using now.', running: true, since: 1,
  can_restart: false, note: 'This copy was started by hand, so nothing would start it again.'};

async function fixture(route, {confirm = true} = {}) {
  const dom = new JSDOM(markup, {url: 'https://lightwork.example/settings', runScripts: 'outside-only'});
  const {window} = dom, calls = [], confirms = [];
  shell(window);
  window.fetch = async (url, options = {}) => {
    calls.push({url, options});
    if (url === '/api/v1/admin/services') return response(Object.assign({}, SERVICES, {dashboard: DASHBOARD}));
    if (url === '/api/v1/admin/tenants') return response([{id: 'acme', display_name: 'Acme'}]);
    if (url.endsWith('/release-checks')) return response({releases: ['0.1.7'], current_release: '0.1.7', measured: true});
    if (url.endsWith('/task-records')) return response({summary: 'Nothing scheduled.', scheduled: null, last_result: null});
    return route(url, options);
  };
  window.mvConfirm = async (message) => { confirms.push(message); return confirm; };
  window.mvErrorText = (failure, action) => 'Could not ' + action + '.';
  window.mvPlainDetail = (detail) => (typeof detail === 'string' && /^[A-Z].*\.$/.test(detail) ? detail : '');
  window.mvWhen = () => 'today';
  window.mvHuman = (v) => String(v);
  window.eval(script);
  const settle = async () => { for (let i = 0; i < 20; i++) await new Promise((done) => setImmediate(done)); };
  await settle();
  return {window, document: window.document, calls, confirms, settle};
}

test('services load with plain status and stopping asks first', async (t) => {
  const ui = await fixture((url) => response({service: {}}));
  t.after(() => ui.window.close());
  const box = ui.document.querySelector('[data-ops-out="services"]');
  assert.match(box.textContent, /Running since today/);
  assert.match(box.textContent, /Stopped unexpectedly/);
  const stop = [...box.querySelectorAll('button')].find((b) => b.textContent === 'Stop');
  assert.equal(stop.getAttribute('aria-label'), 'Stop Background worker');
  stop.click();
  await ui.settle();
  assert.match(ui.confirms[0], /Stop Background worker/);
  const sent = ui.calls.find((c) => c.url === '/api/v1/admin/services/stop');
  assert.deepEqual(JSON.parse(sent.options.body), {service: 'worker', confirm: true});
});

test('a cancelled stop sends nothing', async (t) => {
  const ui = await fixture(() => response({}), {confirm: false});
  t.after(() => ui.window.close());
  [...ui.document.querySelectorAll('[data-ops-out="services"] button')].find((b) => b.textContent === 'Stop').click();
  await ui.settle();
  assert.equal(ui.calls.some((c) => c.url.endsWith('/stop')), false);
});

test('whole configuration shows values, sources and where to change them', async (t) => {
  const ui = await fixture((url) => response({summary: '2 settings are in effect.', unreadable: false, sections: [
    {name: 'Safety', keys: [{setting: 'How strict screening is', where: 'Safety', value: 'strict', source: 'Installation settings file',
      href: '/settings/all#group-safety', link_label: 'Change in All settings'}]},
    {name: 'Grpc', keys: [{setting: 'Port', where: 'Grpc', value: '50051', source: 'Installation settings file', href: '', link_label: ''}]}]}));
  t.after(() => ui.window.close());
  ui.document.querySelector('[data-ops-run="config"]').click();
  await ui.settle();
  const out = ui.document.querySelector('[data-ops-out="config"]');
  assert.equal(out.querySelectorAll('details').length, 2);
  assert.equal(out.querySelector('a').getAttribute('href'), '/settings/all#group-safety');
  assert.match(out.textContent, /Only in the installation settings file/);
});

test('settings file update is offered only when there is something to rewrite, and confirms', async (t) => {
  const ui = await fixture((url, options) => {
    if (url.endsWith('/settings-file/update')) return response({summary: '1 setting name was updated.', backup: 'config.toml.bak-1', technical: []});
    return response({summary: '1 setting name will be updated.', can_update: true, technical: [{text: 'renamed a -> b'}]});
  });
  t.after(() => ui.window.close());
  ui.document.querySelector('[data-ops-run="settings-file"]').click();
  await ui.settle();
  const update = [...ui.document.querySelectorAll('[data-ops-out="config"] button')].find((b) => b.textContent === 'Update the settings file');
  update.click();
  await ui.settle();
  assert.match(ui.confirms[0], /backup copy/);
  assert.match(ui.document.querySelector('[data-ops-out="config"]').textContent, /kept as a backup copy/);
});

test('workspace pickers fill from the workspace list and older records preview before assigning', async (t) => {
  const ui = await fixture((url) => {
    if (url.endsWith('/older-records/preview')) return response({total: 4, summary: '4 older records would be assigned to this workspace.', rows: [{records: 'Goals', count: 4}]});
    if (url.endsWith('/older-records/assign')) return response({job: {id: 'j1', state: 'done', result: {summary: 'Assigned 4 older records to the workspace.'}}});
    return response({});
  });
  t.after(() => ui.window.close());
  const form = ui.document.querySelector('[data-ops-form="older-records"]');
  assert.equal(form.elements.workspace.options.length, 2);
  form.elements.workspace.value = 'acme';
  form.dispatchEvent(new ui.window.Event('submit', {cancelable: true}));
  await ui.settle();
  const assign = ui.document.querySelector('[data-ops-run="older-assign"]');
  assert.equal(assign.hidden, false);
  assign.click();
  await ui.settle();
  assert.match(ui.confirms[0], /Assign every older record/);
  assert.match(ui.document.querySelector('[data-ops-out="older-records"]').textContent, /Assigned 4 older records/);
});

test('refusals show the server sentence when it is plain', async (t) => {
  const ui = await fixture(() => response({detail: 'This installation\'s program files are read-only, so components can\'t be prepared here.'}, 409));
  t.after(() => ui.window.close());
  ui.document.querySelector('[data-ops-run="components"]').click();
  await ui.settle();
  assert.match(ui.document.querySelector('[data-ops-status="upkeep"]').textContent, /read-only/);
});

test('background maintenance shows an activity-record failure after work finishes', async (t) => {
  const ui = await fixture((url) => {
    if (url.endsWith('/connection-components')) return response({job: {id: 'j1', state: 'done',
      record_warning: true, result: {summary: 'Prepared 1 connection component.', prepared: ['Task connection']}}});
    return response({});
  });
  t.after(() => ui.window.close());
  ui.document.querySelector('[data-ops-run="components"]').click();
  await ui.settle();
  assert.match(ui.document.querySelector('[data-ops-out="upkeep"]').textContent, /Prepared 1 connection component/);
  assert.match(ui.document.querySelector('[data-ops-status="upkeep"]').textContent, /could not be added to the activity record/);
});

test('this app shows why it cannot restart, or restarts after confirming when supervised', async (t) => {
  let ui = await fixture(() => response({}));
  t.after(() => ui.window.close());
  let box = ui.document.querySelector('[data-ops-out="services"]');
  assert.match(box.textContent, /started by hand/);
  assert.equal([...box.querySelectorAll('button')].some((b) => b.getAttribute('aria-label') === 'Restart This app'), false);
  DASHBOARD = Object.assign({}, DASHBOARD, {can_restart: true, note: 'Kubernetes starts this app again automatically after it stops.'});
  ui = await fixture((url) => response({restarting: true, summary: 'Restarting. This page reconnects when the app is back.'}));
  box = ui.document.querySelector('[data-ops-out="services"]');
  [...box.querySelectorAll('button')].find((b) => b.getAttribute('aria-label') === 'Restart This app').click();
  await ui.settle();
  assert.match(ui.confirms[0], /Kubernetes starts this app again/);
  assert.deepEqual(JSON.parse(ui.calls.find((c) => c.url.endsWith('/dashboard/restart')).options.body), {confirm: true});
  assert.match(ui.document.querySelector('[data-ops-status="services"]').textContent, /Restarting/);
  ui.window.close();
});

test('every workspace clean-up previews, then confirms and follows the job', async (t) => {
  const extra = '<form data-maintenance-cleanup><select name="days"><option value="90" selected>90</option></select>' +
    '<select name="activity_days"><option value="30" selected>30</option></select></form>' +
    '<div data-ops-cleanup-all><button data-ops-run="cleanup-all">See</button><button data-ops-run="cleanup-all-go" hidden>Remove</button>' +
    '<p data-ops-status="cleanup-all"></p><div data-ops-out="cleanup-all"></div></div>';
  const dom = new JSDOM(markup.replace('</div>', extra + '</div>'), {url: 'https://lightwork.example/settings', runScripts: 'outside-only'});
  const {window} = dom, calls = [], confirms = [];
  shell(window);
  t.after(() => window.close());
  window.fetch = async (url, options = {}) => {
    calls.push({url, options});
    if (url === '/api/v1/admin/services') return response(SERVICES);
    if (url === '/api/v1/admin/tenants') return response([]);
    if (url.endsWith('/release-checks')) return response({releases: []});
    if (url.endsWith('/task-records')) return response({summary: '', scheduled: null, last_result: null});
    if (url.includes('/all-workspaces-cleanup?')) return response({summary: 'Across 2 workspaces: 3 conversations and 4 activity entries would be removed.', total_conversations: 3, total_activity: 4,
      workspaces: [{workspace: 'Acme', empty: false, conversations: 3, activity: 4}, {workspace: 'Beta', empty: true}]});
    return response({job: {id: 'c1', state: 'done', result: {summary: 'Removed 3 conversations and 4 activity entries across 2 workspaces.', workspaces: []}}});
  };
  window.mvConfirm = async (m) => { confirms.push(m); return true; };
  window.mvErrorText = (f, a) => 'Could not ' + a + '.';
  window.mvWhen = () => 'today';
  window.eval(script);
  const settle = async () => { for (let i = 0; i < 20; i++) await new Promise((done) => setImmediate(done)); };
  await settle();
  window.document.querySelector('[data-ops-run="cleanup-all"]').click();
  await settle();
  assert.match(calls.find((c) => c.url.includes('/all-workspaces-cleanup?')).url, /days=90&activity_days=30/);
  assert.match(window.document.querySelector('[data-ops-out="cleanup-all"]').textContent, /No records yet/);
  const go = window.document.querySelector('[data-ops-run="cleanup-all-go"]');
  assert.equal(go.hidden, false);
  go.click();
  await settle();
  assert.match(confirms[0], /every workspace/);
  assert.deepEqual(JSON.parse(calls.find((c) => c.options.method === 'POST').options.body), {days: 90, activity_days: 30, confirm: true});
  assert.match(window.document.querySelector('[data-ops-out="cleanup-all"]').textContent, /Removed 3 conversations/);
});

test('a program its setting has turned off links to the setting instead of starting', async (t) => {
  const saved = SERVICES.services;
  SERVICES.services = saved.concat([{kind: 'profiling', label: 'Performance profiling', about: 'Records where this app spends its time.',
    running: false, since: null, last_error: '', log: [], setting_driven: true, wanted: false,
    settings_href: '/settings/all#group-server-deployment'}]);
  t.after(() => { SERVICES.services = saved; });
  const ui = await fixture(() => response({}));
  t.after(() => ui.window.close());
  const box = ui.document.querySelector('[data-ops-out="services"]');
  assert.match(box.textContent, /Turned off in All settings/);
  const link = box.querySelector('a[aria-label="Turn on Performance profiling in All settings"]');
  assert.equal(link.getAttribute('href'), '/settings/all#group-server-deployment');
  assert.equal([...box.querySelectorAll('button')].some((b) => b.getAttribute('aria-label') === 'Start Performance profiling'), false);
});
