'use strict';
const {test} = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), {JSDOM} = require('jsdom');
const {shell} = require('./_shell');
const folder = path.resolve(__dirname, '../../maverick_dashboard');

function read(name) { return fs.readFileSync(path.join(folder, name), 'utf8'); }
function body(template, start, end) {
  const text = read(template).replace(/\{%[\s\S]*?%\}/g, '').replace(/\{\{[\s\S]*?\}\}/g, '')
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '');
  const from = text.indexOf(start), to = end ? text.indexOf(end, from) : text.length;
  return text.slice(from, to);
}
function response(value, status = 200) {
  return new Response(JSON.stringify(value), {status, headers: {'Content-Type': 'application/json'}});
}
async function fixture(markup, script, route, {confirm = true, url = 'https://lightwork.example/'} = {}) {
  const dom = new JSDOM('<main>' + markup + '</main>', {url, runScripts: 'outside-only'});
  const {window} = dom, calls = [], confirms = [], opened = [];
  shell(window);
  window.fetch = async (u, options = {}) => { calls.push({url: u, options}); return route(u, options); };
  window.mvConfirm = async (message) => { confirms.push(message); return confirm; };
  window.mvErrorText = (failure, action) => 'Could not ' + action + '.';
  window.mvPlainDetail = (detail) => (typeof detail === 'string' && /^[A-Z].*\.$/.test(detail) ? detail : '');
  window.mvWhen = () => 'today';
  window.mvHuman = (v) => String(v);
  window.open = (u) => opened.push(u);
  window.eval(read('static/' + script));
  const settle = async () => { for (let i = 0; i < 20; i++) await new Promise((done) => setImmediate(done)); };
  await settle();
  return {window, document: window.document, calls, confirms, opened, settle};
}
// The shell's shared helpers (mvFetchJSON) load before page scripts, as in
// base.html; this fixture's own stand-ins for the other helpers are kept.
function withShell(window) {
  const kept = Object.fromEntries(Object.keys(window).filter((k) => k.startsWith('mv')).map((k) => [k, window[k]]));
  if (!window.matchMedia) window.matchMedia = () => ({matches: false, addEventListener() {}, removeEventListener() {}});
  window.eval(fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-ui.js'), 'utf8'));
  Object.assign(window, kept);
}
function submit(ui, form) { form.dispatchEvent(new ui.window.Event('submit', {cancelable: true})); }

test('one-step client setup sends the form and shows the link once', async (t) => {
  // The create form carries the optional administrator invitation; the roles
  // list and the copy button come from tenant-ops, the submit from tenants.
  const markup = body('templates/tenants.html', '<form id="tenant-add"', '<details class="tenants-why">');
  const ui = await fixture(markup, 'lightwork-tenant-ops.js', (url) => {
    if (url.endsWith('/roles')) return response({roles: [{value: 'admin', label: 'Admin'}, {value: 'viewer', label: 'Viewer'}], invitations_on: true});
    if (url.endsWith('/onboard')) return response({summary: 'Created Acme and invited owner@acme.example as its admin.', invite_link: 'https://x/auth/invite/inv_1'});
    throw new Error('unexpected request ' + url);
  });
  t.after(() => ui.window.close());
  withShell(ui.window);
  ui.window.eval(read('static/lightwork-tenants.js'));
  const form = ui.document.getElementById('tenant-add');
  assert.equal(form.querySelector('[data-onboard-roles]').options.length, 2);
  form.elements.display_name.value = 'Acme';
  form.elements.admin_email.value = 'owner@acme.example';
  submit(ui, form);
  await ui.settle();
  assert.equal(ui.calls.filter((c) => c.url.endsWith('/admin/tenants')).length, 0);
  const sent = JSON.parse(ui.calls.find((c) => c.url.endsWith('/onboard')).options.body);
  assert.deepEqual(sent, {display_name: 'Acme', plan: 'free', max_daily_dollars: 0, admin_email: 'owner@acme.example', role: 'admin'});
  assert.equal(ui.document.getElementById('tenant-onboard-link').value, 'https://x/auth/invite/inv_1');
  assert.equal(ui.document.getElementById('tenant-onboard-out').hidden, false);
});

test('key re-protection previews, confirms and never shows the key', async (t) => {
  const markup = body('templates/tenants.html', '<details class="panel tenants-advanced" id="tenant-keys-panel">', '<style>');
  const ui = await fixture(markup, 'lightwork-tenant-ops.js', (url) => {
    if (url.endsWith('/roles')) return response({roles: [], invitations_on: true});
    if (url.endsWith('/keys/preview')) return response({summary: '1 workspace would be re-protected with the new key; 0 already use it.', total: 1, rows: [{workspace: 'Acme', result: 'Would be re-protected'}], technical: []});
    if (url.endsWith('/keys/rotate')) return response({job: {id: 'k1', state: 'done', result: {summary: 'Re-protected 1 workspace with the new key.', rows: [], technical: []}}});
    return response({});
  });
  t.after(() => ui.window.close());
  const form = ui.document.getElementById('tenant-keys');
  const file = (text) => new ui.window.File([text], 'key.txt', {type: 'text/plain'});
  Object.defineProperty(form.elements.current_key, 'files', {value: [file('a'.repeat(64))]});
  Object.defineProperty(form.elements.new_key, 'files', {value: [file('b'.repeat(64))]});
  submit(ui, form);
  await ui.settle();
  const rotate = ui.document.getElementById('tenant-keys-rotate');
  assert.equal(rotate.hidden, false);
  assert.doesNotMatch(ui.document.body.textContent, /aaaaaaaa/);
  rotate.click();
  await ui.settle();
  assert.match(ui.confirms[0], /Keep the current key/);
  const sent = JSON.parse(ui.calls.find((c) => c.url.endsWith('/keys/rotate')).options.body);
  assert.equal(sent.confirm, true);
  assert.match(ui.document.getElementById('tenant-keys-out').textContent, /Re-protected 1 workspace/);
});

test('key re-protection does not hide a missing activity record', async (t) => {
  const markup = body('templates/tenants.html', '<details class="panel tenants-advanced" id="tenant-keys-panel">', '<style>');
  const ui = await fixture(markup, 'lightwork-tenant-ops.js', (url) => {
    if (url.endsWith('/keys/preview')) return response({summary: '1 workspace would be re-protected.', total: 1,
      rows: [{workspace: 'Acme', result: 'Would be re-protected'}]});
    if (url.endsWith('/keys/rotate')) return response({job: {id: 'k2', state: 'done', record_warning: true,
      result: {summary: 'Re-protected 1 workspace.', failed: 0, rows: []}}});
    return response({});
  });
  t.after(() => ui.window.close());
  const form = ui.document.getElementById('tenant-keys');
  const file = (value) => new ui.window.File([value], 'key.txt', {type: 'text/plain'});
  Object.defineProperty(form.elements.current_key, 'files', {value: [file('a'.repeat(64))]});
  Object.defineProperty(form.elements.new_key, 'files', {value: [file('b'.repeat(64))]});
  submit(ui, form);
  await ui.settle();
  ui.document.getElementById('tenant-keys-rotate').click();
  await ui.settle();
  assert.match(ui.document.getElementById('tenant-keys-msg').textContent, /could not be added to the activity record/);
  assert.match(ui.document.getElementById('tenant-keys-msg').textContent, /Keep the current key/);
});

test('stripe send is offered after a preview and confirmed first', async (t) => {
  const markup = '<select name="workspace"></select>' + body('templates/billing.html', '<div class="panel" id="stripe-billing">', '{% endif %}');
  const ui = await fixture(markup.replace('<select class="select" name="workspace" required>', '<select class="select" name="workspace" required><option value="acme">Acme</option>'),
    'lightwork-billing-ops.js', (url) => {
      if (url.includes('/stripe/preview')) return response({summary: 'The plan fee is set up in Stripe.', can_sync: true,
        review_id: 'review-1', sha256: 'a'.repeat(64), review_expires: Date.now() / 1000 + 600, workspace: 'acme', plan: 'free', snapshot: {}});
      if (url.endsWith('/stripe/sync')) return response({message: 'Acme is set up in Stripe.', attempt: 'attempt-1',
        updated_at: Date.now() / 1000, stages: {}, dispatches: [], state: 'complete',
        receipt_href: '/api/v1/admin/billing-ops/stripe/receipt?workspace=acme', reconciliation_href: 'https://dashboard.stripe.com/'});
      return response({ready: true, summary: 'Stripe billing is ready.', facts: []});
    });
  t.after(() => ui.window.close());
  const form = ui.document.getElementById('stripe-form');
  submit(ui, form);
  await ui.settle();
  const sync = ui.document.getElementById('stripe-sync');
  assert.equal(sync.hidden, false);
  sync.click();
  await ui.settle();
  assert.match(ui.confirms[0], /Send exactly this reviewed billing change to Stripe/);
  const sent = JSON.parse(ui.calls.find((c) => c.url.endsWith('/stripe/sync')).options.body);
  assert.equal(sent.confirm, true);
  assert.equal(sent.review_id, 'review-1');
  assert.equal(sent.sha256, 'a'.repeat(64));
});

test('bug report lists stopped tasks and copies only the reviewed local draft', async (t) => {
  const markup = body('templates/support.html', '<section class="panel" id="issue-report"', '</section>') + '</section>';
  const ui = await fixture(markup, 'lightwork-support-ops.js', (url) => {
    if (url.includes('/tasks?')) return response({tasks: [{id: 7, title: 'Quarterly summary', when: 1}], next_offset: null});
    return response({title: 'Quarterly summary', body: 'Reviewed local draft.', summary: 'The report is ready.'});
  });
  t.after(() => ui.window.close());
  const copied = [];
  Object.defineProperty(ui.window.navigator, 'clipboard', {value: {writeText: async (text) => copied.push(text)}});
  const select = ui.document.getElementById('issue-report-task');
  assert.equal(select.options.length, 2);
  select.value = '7';
  submit(ui, ui.document.getElementById('issue-report-form'));
  await ui.settle();
  assert.equal(ui.document.getElementById('issue-report-preview').hidden, false);
  const copy = ui.document.getElementById('issue-report-copy');
  const download = ui.document.getElementById('issue-report-download');
  assert.equal(copy.disabled, true);
  assert.equal(download.disabled, true);
  assert.equal(ui.calls.filter((c) => c.url.endsWith('/review')).length, 0);
  assert.deepEqual(ui.opened, []);
  const confirmed = ui.document.getElementById('issue-report-confirm');
  confirmed.checked = true;
  confirmed.dispatchEvent(new ui.window.Event('change'));
  await ui.settle();
  assert.deepEqual(JSON.parse(ui.calls.find((c) => c.url.endsWith('/review')).options.body),
    {task: 7, title: 'Quarterly summary', body: 'Reviewed local draft.'});
  assert.equal(copy.disabled, false);
  assert.equal(download.disabled, false);
  copy.click();
  await ui.settle();
  assert.deepEqual(copied, ['Quarterly summary\n\nReviewed local draft.']);
  assert.match(ui.document.getElementById('issue-report-status').textContent, /Reviewed draft copied/);
  assert.equal(ui.window.location.href, 'https://lightwork.example/');
  assert.deepEqual(ui.opened, []);
  assert.equal(ui.calls.filter((c) => c.url.endsWith('/review')).length, 1);
});

test('bug report keeps changed and uncopied drafts visible for another review or download', async (t) => {
  const markup = body('templates/support.html', '<section class="panel" id="issue-report"', '</section>') + '</section>';
  let reviews = 0;
  const ui = await fixture(markup, 'lightwork-support-ops.js', (url) => {
    if (url.includes('/tasks?')) return response({tasks: [{id: 7, title: 'Stopped task', when: 1}], next_offset: null});
    if (url.endsWith('/review')) {
      reviews++;
      return response({title: 'Stopped task', body: 'Secret [REDACTED]'});
    }
    return response({title: 'Stopped task', body: 'Secret value', summary: 'Review this draft.'});
  });
  t.after(() => ui.window.close());
  Object.defineProperty(ui.window.navigator, 'clipboard', {value: {writeText: async () => { throw new Error('permission denied'); }}});
  ui.document.execCommand = () => false;
  const get = (id) => ui.document.getElementById(id);
  get('issue-report-task').value = '7';
  submit(ui, get('issue-report-form'));
  await ui.settle();
  const check = () => { get('issue-report-confirm').checked = true; get('issue-report-confirm').dispatchEvent(new ui.window.Event('change')); };
  check(); await ui.settle();
  assert.equal(reviews, 1);
  assert.equal(get('issue-report-body').value, 'Secret [REDACTED]');
  assert.equal(get('issue-report-confirm').checked, false);
  assert.equal(get('issue-report-copy').disabled, true);
  assert.match(get('issue-report-status').textContent, /Review the updated draft/);
  check(); await ui.settle();
  assert.equal(get('issue-report-copy').disabled, false);
  get('issue-report-copy').click(); await ui.settle();
  assert.match(get('issue-report-status').textContent, /browser blocked copying/);
  assert.equal(get('issue-report-body').value, 'Secret [REDACTED]');
  assert.equal(get('issue-report-download').disabled, false);
  get('issue-report-body').value = 'Another edit';
  get('issue-report-body').dispatchEvent(new ui.window.Event('input'));
  assert.equal(get('issue-report-copy').disabled, true);
  assert.equal(get('issue-report-download').disabled, true);
});

test('savings and performance additions draw plain rows', async (t) => {
  const markup = body('templates/_value_report.html', '<div class="section-head">') + body('templates/perf.html', '<div class="panel" id="ops-charts">', '{% endblock %}');
  const ui = await fixture(markup, 'lightwork-insights-ops.js', (url) => {
    if (url.includes('value-report')) return response({learning: 'Over 2 learning checkpoints, lessons cover 3 more.', record: 'The activity record is signed.', vendors: [{vendor: 'Acme agents', delivered: 4, failed: 1}]});
    return response({days: 7, tasks: [{day: '2026-09-28', finished: 2, stopped: 1}], tools: [{tool: 'read_file', uses: 3, typical_ms: 1.2, slow_ms: 4, slowest_ms: 9}]});
  });
  t.after(() => ui.window.close());
  assert.match(ui.document.getElementById('value-report-out').textContent, /cover 3 more/);
  assert.match(ui.document.getElementById('value-report-vendors').textContent, /Acme agents/);
  assert.match(ui.document.getElementById('ops-charts-tasks').textContent, /Sep 28, 2026/);
  assert.match(ui.document.getElementById('ops-charts-tools').textContent, /read_file/);
});

test('a prepared settings file is checked before it can be installed', async (t) => {
  const markup = body('templates/setup_guide.html', '<div class="panel" id="guide-file">', '<p><a class="btn btn--ghost" href="/start">');
  const ui = await fixture(markup, 'lightwork-setup-guide.js', (url) => {
    if (url.endsWith('/check')) return response({valid: true, review: 'review-1', summary: 'The file is valid and ready to install.', technical: []});
    return response({installed: true, summary: 'Installed the settings file.'});
  });
  t.after(() => ui.window.close());
  const input = ui.document.getElementById('guide-file-input');
  Object.defineProperty(input, 'files', {value: [new ui.window.File(['[safety]'], 'settings.toml')]});
  const install = ui.document.getElementById('guide-file-install');
  assert.equal(install.hidden, true);
  submit(ui, ui.document.getElementById('guide-file-form'));
  await ui.settle();
  assert.equal(install.hidden, false);
  install.click();
  await ui.settle();
  assert.match(ui.confirms[0], /backup copy/);
  assert.ok(ui.calls.some((c) => c.url.endsWith('/install?confirm=true&review=review-1')));
  assert.equal(ui.document.getElementById('guide-file-status').textContent, 'Installed the settings file.');
});
