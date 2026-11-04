'use strict';
const {test} = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), {JSDOM} = require('jsdom');
const folder = path.resolve(__dirname, '../../maverick_dashboard');
const markup = fs.readFileSync(path.join(folder, 'templates/settings.html'), 'utf8')
  .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '');
const script = fs.readFileSync(path.join(folder, 'static/lightwork-settings-admin.js'), 'utf8');

function response(value, status = 200) {
  return new Response(JSON.stringify(value), {status, headers: {'Content-Type': 'application/json'}});
}

// The shell's shared helpers (mvFetchJSON, mvStatus) load before page
// scripts, as in base.html; this fixture's own stand-ins are kept.
function withShell(window) {
  const kept = Object.fromEntries(Object.keys(window).filter((k) => k.startsWith('mv')).map((k) => [k, window[k]]));
  if (!window.matchMedia) window.matchMedia = () => ({matches: false, addEventListener() {}, removeEventListener() {}});
  window.eval(fs.readFileSync(path.join(folder, 'static/lightwork-ui.js'), 'utf8'));
  Object.assign(window, kept);
}

async function fixture(route, {confirm = true, typed = 'acme'} = {}) {
  const dom = new JSDOM(markup, {url: 'https://lightwork.example/settings', runScripts: 'outside-only'});
  const {window} = dom, calls = [], confirms = [], copies = [], forms = [];
  window.fetch = async (url, options = {}) => { calls.push({url, options}); return route(url, options); };
  window.mvConfirm = async (message) => { confirms.push(message); return confirm; };
  window.mvForm = async (title, fields) => { forms.push({title, fields}); return typed === null ? null : {organisation: typed}; };
  window.mvCopy = (text) => copies.push(text);
  window.mvErrorText = (failure, action) => 'Could not ' + action + '.';
  window.mvWhen = () => 'today';
  withShell(window);
  window.eval(script);
  const settle = async () => { for (let i = 0; i < 12; i++) await new Promise((done) => setImmediate(done)); };
  return {window, document: window.document, calls, confirms, copies, forms, settle};
}

test('secret settings use the reviewed change form', () => {
  assert.match(markup, /id="wh-form"/);
  assert.match(markup, /id="wh-confirm"[^>]*disabled/);
  assert.match(markup, /id="wh-secret"[^>]*type="password"/);
  assert.doesNotMatch(markup, /id="webhook-generate"/);
});

test('secret changes cannot bypass review through the general settings controls', async (t) => {
  const ui = await fixture(() => response({detail: 'boom'}, 500));
  t.after(() => ui.window.close());
  assert.equal(ui.document.getElementById('webhook-generate'), null);
  assert.equal(ui.document.getElementById('wh-save').disabled, true);
  assert.equal(ui.calls.length, 0);
});

test('readiness check lists each switch with a fix button', async (t) => {
  const ui = await fixture(() => response({ready: false, checks: [
    {key: 'provider', label: 'AI provider connected', ok: false, detail: 'No AI provider key is saved yet.',
     fix_label: 'Add a provider key', fix_href: '/settings#settings-integrations'},
    {key: 'encryption', label: 'Stored data is encrypted', ok: true, detail: 'Saved records are encrypted on disk.',
     fix_label: '', fix_href: ''}]}));
  t.after(() => ui.window.close());
  ui.document.querySelector('[data-maintenance-run="readiness"]').click();
  await ui.settle();
  const list = ui.document.querySelector('[data-maintenance-out="readiness"]');
  assert.equal(list.children.length, 2);
  assert.match(list.textContent, /Not ready/);
  assert.equal(list.querySelector('a').textContent, 'Add a provider key');
  assert.match(ui.document.querySelector('[data-maintenance-status="readiness"]').textContent, /need attention/);
});

test('a paused schedule is resumed only from its full review on Automations', async (t) => {
  const ui = await fixture((url, options) => {
    if (url.endsWith('/resume')) return response({resumed: true, next: 9});
    return response({counts: [{state: 'Stopped', count: 1}], stopped: [
      {id: 7, attempts: 3, what: 'Run a task', when: 1, needs_decision: true, technical: 'x'}]});
  });
  t.after(() => ui.window.close());
  ui.document.querySelector('[data-maintenance-run="queue"]').click();
  await ui.settle();
  const out = ui.document.querySelector('[data-maintenance-out="queue"]');
  // Settings no longer resumes in place: it links to the schedule's review,
  // which shows the attempt count and confirms before anything runs again.
  assert.equal([...out.querySelectorAll('button')].some((b) => b.textContent === 'Resume schedule'), false);
  const review = [...out.querySelectorAll('a')].find((a) => a.textContent === 'Review this schedule');
  assert.ok(review);
  assert.equal(review.getAttribute('href'), '/automations?recover_schedule=7');
  assert.equal(ui.calls.some((c) => c.url.endsWith('/resume')), false);
});

test('forms marked for confirmation do not submit when cancelled', async (t) => {
  const ui = await fixture(() => response({}), {confirm: false});
  t.after(() => ui.window.close());
  const form = ui.document.querySelector('form[data-confirm]');
  let submitted = false;
  form.submit = () => { submitted = true; };
  form.requestSubmit = () => { submitted = true; };
  form.dispatchEvent(new ui.window.Event('submit', {cancelable: true}));
  await ui.settle();
  assert.equal(submitted, false);
  assert.equal(ui.confirms.length, 1);
});

test('encryption explains a shared database instead of claiming older records are encrypted', async (t) => {
  const note = 'Older records are kept in a shared database that this page cannot check or encrypt.';
  const ui = await fixture(() => response({enabled: true, older_unprotected: null, older_note: note}));
  t.after(() => ui.window.close());
  ui.document.querySelector('[data-maintenance-run="encryption"]').click();
  await ui.settle();
  const box = ui.document.querySelector('[data-maintenance-out="encryption"]');
  assert.match(box.textContent, /shared database/);
  assert.doesNotMatch(box.textContent, /All older records are encrypted/);
  assert.ok(![...box.querySelectorAll('button')].some((b) => b.textContent === 'Encrypt older records'));
});

test('a one-button check shows plain rows and keeps kernel wording in technical details', async (t) => {
  const ui = await fixture(() => response({passed: false, summary: '1 protection for a regulated deployment is not in place.',
    checks: [{label: 'Saved data is encrypted', ok: false}],
    technical: [{level: 'fail', text: 'At-rest encryption: enable [encryption] at_rest'}]}));
  t.after(() => ui.window.close());
  ui.document.querySelector('[data-maintenance-run="enterprise"]').click();
  await ui.settle();
  assert.equal(ui.calls[0].url, '/api/v1/admin/system/enterprise-check');
  assert.match(ui.document.querySelector('[data-maintenance-out="enterprise"]').textContent, /Saved data is encrypted.*Not in place/);
  assert.match(ui.document.querySelector('[data-maintenance-status="enterprise"]').textContent, /not in place/);
  const details = ui.document.querySelector('[data-maintenance-details="enterprise"]');
  assert.equal(details.hidden, false);
  assert.equal(details.open, false);
  assert.match(details.textContent, /at_rest/);
});

const PREVIEW = {organisation: 'acme', files: 7, keeps_activity_record: true,
  areas: [{label: 'Tasks and conversations', files: 4}, {label: 'Saved memory', files: 3}]};

test('local data review explains the offline boundary and never sends an erase', async (t) => {
  const ui = await fixture((url) => {
    if (url.includes('/client/erase/preview')) return response(PREVIEW);
    return response({bound: true, organisation: 'acme', enforced: false, summary: 'This installation holds data for one organisation: acme.', technical: []});
  });
  t.after(() => ui.window.close());
  ui.document.querySelector('[data-maintenance-run="client"]').click();
  await ui.settle();
  const review = [...ui.document.querySelectorAll('[data-maintenance-out="client"] button')].find((b) => b.textContent === 'Review local data');
  assert.ok(review);
  review.click();
  await ui.settle();
  const preview = ui.calls.find((c) => c.url.includes('/client/erase/preview'));
  assert.match(preview.url, /keep_activity_record=true/);
  assert.match(ui.document.querySelector('[data-maintenance-out="client"]').textContent, /Tasks and conversations.*4 files.*Saved memory.*3 files/);
  assert.match(ui.document.querySelector('[data-maintenance-status="client"]').textContent, /cannot safely erase local data/);
  assert.match(ui.document.querySelector('[data-maintenance-status="client"]').textContent, /Connected services and exported copies/);
  assert.equal(ui.calls.filter((c) => c.url.endsWith('/client/erase')).length, 0);
});

test('a failed local data preview does not offer a destructive action', async (t) => {
  const ui = await fixture((url) => {
    if (url.includes('/client/erase/preview')) return response({detail: 'The local file inventory is unavailable.'}, 503);
    return response({bound: true, organisation: 'acme', summary: 'ok', technical: []});
  });
  t.after(() => ui.window.close());
  ui.window.mvPlainDetail = (detail) => detail;
  ui.document.querySelector('[data-maintenance-run="client"]').click();
  await ui.settle();
  [...ui.document.querySelectorAll('[data-maintenance-out="client"] button')]
    .find((b) => b.textContent === 'Review local data').click();
  await ui.settle();
  assert.equal(ui.calls.filter((c) => c.url.endsWith('/client/erase')).length, 0);
  assert.match(ui.document.querySelector('[data-maintenance-status="client"]').textContent, /inventory is unavailable/);
});

test('the organisation download is prepared in the background, then offered as a link', async (t) => {
  let polls = 0;
  const ui = await fixture((url, options) => {
    if (url.endsWith('/client/export') && options.method === 'POST') return response({job: 'a'.repeat(32), state: 'running'}, 202);
    if (url.includes('/client/export/')) { polls += 1; return response({state: polls > 1 ? 'ready' : 'running', message: ''}); }
    return response({bound: false, organisation: '', summary: 'Not set up for one organisation.', technical: []});
  });
  t.after(() => ui.window.close());
  ui.window.setTimeout = (fn) => setImmediate(fn);
  ui.document.querySelector('[data-maintenance-run="client"]').click();
  await ui.settle();
  [...ui.document.querySelectorAll('[data-maintenance-out="client"] button')].find((b) => b.textContent === 'Download all data').click();
  await ui.settle(); await ui.settle();
  const link = [...ui.document.querySelectorAll('[data-maintenance-out="client"] a')].find((a) => a.textContent === 'Save the file');
  assert.ok(link, 'download link appears once ready');
  assert.match(link.getAttribute('href'), /\/client\/export\/a{32}\/download$/);
  assert.match(ui.document.querySelector('[data-maintenance-status="client"]').textContent, /ready/);
});

test('tidy up shows the counts first and removes only after confirming', async (t) => {
  const ui = await fixture((url, options) => {
    if (options.method === 'POST') return response({conversations: 2, activity: 5, duplicate_checks: 0});
    return response({conversations: 2, activity: 5, days: 180, activity_days: 30});
  });
  t.after(() => ui.window.close());
  const form = ui.document.querySelector('[data-maintenance-cleanup]');
  form.elements.days.value = '180';
  form.dispatchEvent(new ui.window.Event('submit', {cancelable: true}));
  await ui.settle();
  assert.equal(ui.calls[0].url, '/api/v1/admin/system/cleanup/preview?days=180&activity_days=30');
  assert.equal(ui.calls.length, 1);
  assert.match(ui.document.querySelector('[data-maintenance-status="cleanup"]').textContent, /Nothing has been removed yet/);
  [...ui.document.querySelectorAll('[data-maintenance-out="cleanup"] button')].find((b) => b.textContent === 'Remove these records').click();
  await ui.settle();
  assert.match(ui.confirms[0], /cannot be brought back/);
  const post = ui.calls.find((c) => c.options.method === 'POST');
  assert.deepEqual(JSON.parse(post.options.body), {days: 180, activity_days: 30, confirm: true});
  assert.match(ui.document.querySelector('[data-maintenance-status="cleanup"]').textContent, /Removed 2 conversations and 5 activity entries/);
});

test('tidy up says a legal hold applies and offers no removal when the preview is held', async (t) => {
  const ui = await fixture((url, options) => {
    if (options.method === 'POST') throw new Error('removal must not be offered');
    return response({conversations: 0, activity: 0, days: 180, activity_days: 30, held: true});
  });
  t.after(() => ui.window.close());
  const form = ui.document.querySelector('[data-maintenance-cleanup]');
  form.dispatchEvent(new ui.window.Event('submit', {cancelable: true}));
  await ui.settle();
  assert.equal(ui.calls.length, 1);
  assert.match(ui.document.querySelector('[data-maintenance-status="cleanup"]').textContent, /A legal hold applies to this workspace/);
  assert.equal(ui.document.querySelector('[data-maintenance-out="cleanup"] button'), null);
});

test('a refused request shows the server sentence only when it is plain', async (t) => {
  const ui = await fixture(() => response({detail: 'Choose a workspace first. Nothing was changed.'}, 409));
  t.after(() => ui.window.close());
  ui.window.mvPlainDetail = (text) => (/^[A-Z].*\.$/.test(text) && !/_/.test(text) ? text : '');
  const form = ui.document.querySelector('[data-maintenance-cleanup]');
  form.dispatchEvent(new ui.window.Event('submit', {cancelable: true}));
  await ui.settle();
  assert.equal(ui.document.querySelector('[data-maintenance-status="cleanup"]').textContent, 'Choose a workspace first. Nothing was changed.');
});
