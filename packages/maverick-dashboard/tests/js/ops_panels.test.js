'use strict';
// lightwork-ops-panels.js: the buttons for operations that also exist on the
// command line. Each panel is loaded from its real partial template.
const {test} = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), {JSDOM} = require('jsdom');
const {shell} = require('./_shell');
const folder = path.resolve(__dirname, '../../maverick_dashboard');
const script = fs.readFileSync(path.join(folder, 'static/lightwork-ops-panels.js'), 'utf8');

// A partial with its Jinja tags resolved for an administrator.
function partial(name) {
  return fs.readFileSync(path.join(folder, 'templates', name), 'utf8')
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/\{\{[^}]*\}\}/g, 'true')
    .replace(/\{%[\s\S]*?%\}/g, '')
    .replace(/\{#[\s\S]*?#\}/g, '');
}
function response(value, status = 200) {
  return new Response(JSON.stringify(value), {status, headers: {'Content-Type': 'application/json'}});
}
const ME = {can: {view: true, operate: true, audit: true, admin: true, installation_admin: true}};

async function fixture(markup, route, {confirm = true, form = null} = {}) {
  const dom = new JSDOM('<!doctype html><body>' + markup + '</body>', {url: 'https://lightwork.example/', runScripts: 'outside-only'});
  const {window} = dom, calls = [], confirms = [], forms = [];
  shell(window);
  window.fetch = async (url, options = {}) => {
    calls.push({url, options, body: options.body ? JSON.parse(options.body) : null});
    if (url === '/api/v1/account/me') return response(ME);
    return route(url, options);
  };
  window.mvConfirm = async (message) => { confirms.push(message); return confirm; };
  window.mvForm = async (title, fields) => { forms.push({title, fields}); return typeof form === 'function' ? form(fields) : form; };
  window.mvErrorText = (failure, action) => 'Could not ' + action + '.';
  window.mvPlainDetail = (text) => (typeof text === 'string' && /^[A-Z][^_]*\.$/.test(text) ? text : '');
  window.mvHuman = (value) => String(value).replace(/_/g, ' ');
  window.mvWhen = () => 'today';
  window.setTimeout = (fn) => setImmediate(fn);
  window.eval(script);
  const settle = async () => { for (let i = 0; i < 20; i++) await new Promise((done) => setImmediate(done)); };
  await settle();
  return {window, document: window.document, calls, confirms, forms, settle};
}
const posts = (ui, suffix) => ui.calls.filter((c) => c.options.method === 'POST' && c.url.endsWith(suffix));

// ---- activity log checkpoints ------------------------------------------------

const CHECKPOINTS = {total: 1, problem: '', days: [{day: '2026-01-02', has_checkpoint: false}, {day: '2026-01-01', has_checkpoint: true}],
  checkpoints: [{sequence: 1, day: '2026-01-01', kind: 'Checkpoint', entries: 3, created_at: '2026-01-01T10:00:00+00:00',
    latest: true, can_retire: true}]};

test('checkpoints list days to choose, offer a receipt per row and publish after confirming', async (t) => {
  const ui = await fixture(partial('_ops_audit_checkpoints.html'), (url) => {
    if (url.endsWith('/publish')) return response({published: true, sequence: 2, day: '2026-01-02'});
    return response(CHECKPOINTS);
  });
  t.after(() => ui.window.close());
  const days = [...ui.document.querySelectorAll('#ops-ckpt-day option')].map((o) => o.value);
  assert.deepEqual(days, ['2026-01-02', '2026-01-01']);
  // Each day reads in the shared date format; the value stays the calendar day.
  assert.equal(ui.document.querySelector('#ops-ckpt-day option').textContent, 'Jan 2, 2026');
  const receipt = ui.document.querySelector('#ops-ckpt-rows a');
  assert.equal(receipt.getAttribute('href'), '/api/v1/audit/checkpoints/1/receipt');
  assert.match(ui.document.getElementById('ops-ckpt-rows').textContent, /Jan 1, 2026.*Checkpoint.*3/);
  ui.document.getElementById('ops-ckpt-publish').click();
  await ui.settle();
  assert.match(ui.confirms[0], /Publish the checkpoint of Jan 2, 2026/);
  assert.deepEqual(posts(ui, '/publish')[0].body, {day: '2026-01-02', after_erasure: false});
  assert.match(ui.document.getElementById('ops-ckpt-result').textContent, /Published checkpoint 2 for Jan 2, 2026/);
});

test('retiring a checkpoint asks first and sends only the row it showed', async (t) => {
  const ui = await fixture(partial('_ops_audit_checkpoints.html'), (url) => {
    if (url.endsWith('/retire')) return response({retired: true, day: '2026-01-01'});
    return response(CHECKPOINTS);
  }, {confirm: false});
  t.after(() => ui.window.close());
  const retire = [...ui.document.querySelectorAll('#ops-ckpt-rows button')].find((b) => b.textContent === 'Retire');
  retire.click();
  await ui.settle();
  assert.match(ui.confirms[0], /cannot be undone/);
  assert.equal(posts(ui, '/retire').length, 0);
});

test('a failed check lists plain problems and keeps the technical wording collapsed', async (t) => {
  const ui = await fixture(partial('_ops_audit_checkpoints.html'), (url) => {
    if (url.endsWith('/verify')) return response({intact: false, none_yet: false, pinned: false,
      problems: ['Checkpoint 1: the activity log for that day no longer matches it.'], technical: ['1: prefix_mismatch: x']});
    return response(CHECKPOINTS);
  });
  t.after(() => ui.window.close());
  ui.document.getElementById('ops-ckpt-verify').click();
  await ui.settle();
  const result = ui.document.getElementById('ops-ckpt-result');
  assert.match(result.textContent, /no longer matches/);
  assert.equal(result.querySelector('details').open, false);
});

// ---- security --------------------------------------------------------------------

test('security fixes are listed first and applied only after confirming', async (t) => {
  let applied = 0;
  const ui = await fixture(partial('_ops_security.html'), (url) => {
    if (url.endsWith('/posture')) return response({summary: '1 defense is off.', technical: [],
      defenses: [{key: 'shield', label: 'Harmful requests are screened', on: false, href: '/safety'}]});
    if (url.endsWith('/fixes/apply')) { applied += 1; return response({applied: true, message: 'Fixed.'}); }
    return response({summary: '1 gap found.', automatic_fixes_on: true, fixes: [{control: 'Tamper-evident audit',
      label: 'Make the activity log tamper-evident', automatic: true, can_apply: true, href: '/compliance', why_not: '', technical: ''}]});
  });
  t.after(() => ui.window.close());
  assert.match(ui.document.getElementById('ops-sec-defenses').textContent, /Off.*Harmful requests are screened/);
  assert.equal(ui.document.querySelector('#ops-sec-defenses a').getAttribute('href'), '/safety');
  ui.document.getElementById('ops-sec-fixes-load').click();
  await ui.settle();
  assert.equal(applied, 0);
  [...ui.document.querySelectorAll('#ops-sec-fixes button')].find((b) => b.textContent === 'Apply this fix').click();
  await ui.settle();
  assert.match(ui.confirms[0], /recorded in the activity log/);
  assert.deepEqual(posts(ui, '/fixes/apply')[0].body, {control: 'Tamper-evident audit', confirm: true});
});

test('the sweep refuses a start date after the end date without asking the server', async (t) => {
  const ui = await fixture(partial('_ops_security.html'), () => response({summary: 'ok', defenses: [], technical: []}));
  t.after(() => ui.window.close());
  ui.document.getElementById('ops-sec-since').value = '2026-02-01';
  ui.document.getElementById('ops-sec-until').value = '2026-01-01';
  ui.document.getElementById('ops-sec-sweep').click();
  await ui.settle();
  assert.equal(posts(ui, '/sweep').length, 0);
  assert.match(ui.document.getElementById('ops-sec-sweep-out').textContent, /start date must be before/);
});

// ---- a person's uploaded documents ---------------------------------------------------

const PEOPLE = '<select id="cmp-person"><option value="">Choose</option>' +
  '<option value="1" data-channel="slack" data-user="U1" data-name="Ada Lovelace" selected>Ada Lovelace (Slack, 1 conversation)</option></select>';

test('erasing documents previews the count and needs the person\'s name typed', async (t) => {
  const ui = await fixture(PEOPLE + partial('_ops_person_documents.html'), (url) => {
    if (url.endsWith('/check')) return response({remaining: 3, clean: false, message: '3 pieces are still held.'});
    return response({erased: 3, remaining: 0, clean: true, message: 'Erased 3 pieces of uploaded documents. None are left.'});
  }, {form: () => ({name: 'ada lovelace'})});
  t.after(() => ui.window.close());
  ui.document.getElementById('ops-docs-erase').click();
  await ui.settle();
  assert.match(ui.confirms[0], /Erase 3 pieces of uploaded documents about Ada Lovelace/);
  assert.match(ui.forms[0].title, /Type the person/);
  assert.deepEqual(posts(ui, '/documents/erase')[0].body,
    {channel: 'slack', user: 'U1', confirm: true, confirm_name: 'ada lovelace'});
  assert.match(ui.document.getElementById('ops-docs-result').textContent, /None are left/);
});

test('a mistyped name erases nothing', async (t) => {
  const ui = await fixture(PEOPLE + partial('_ops_person_documents.html'),
    () => response({remaining: 2, clean: false, message: '2 pieces are still held.'}), {form: () => ({name: 'Ada'})});
  t.after(() => ui.window.close());
  ui.document.getElementById('ops-docs-erase').click();
  await ui.settle();
  assert.equal(posts(ui, '/documents/erase').length, 0);
  assert.match(ui.document.getElementById('ops-docs-result').textContent, /does not match/);
});

// ---- privacy tools ---------------------------------------------------------------------

test('the breach planner asks in a form and shows who to tell', async (t) => {
  const ui = await fixture(partial('_ops_privacy.html'), (url) => {
    if (url.endsWith('/regimes')) return response({regimes: [{regime: 'eu_gdpr', name: 'EU GDPR'}, {regime: 'us_ca', name: 'California'}]});
    return response({obligations: [{name: 'EU GDPR', authority: 'Supervisory authority', authority_due_at: 1767312000}], notice: 'Not legal advice.'});
  }, {form: () => ({'law:eu_gdpr': true, 'law:us_ca': false, people: '12', discovered: '2026-01-01', sensitive: true, malicious: false})});
  t.after(() => ui.window.close());
  ui.document.getElementById('ops-breach-plan').click();
  await ui.settle();
  const body = posts(ui, '/breach/plan')[0].body;
  assert.deepEqual(body.jurisdictions, ['eu_gdpr']);
  assert.equal(body.subjects_affected, 12);
  assert.equal(body.sensitive, true);
  assert.ok(body.discovered_at > 0);
  assert.match(ui.document.getElementById('ops-breach-out').textContent, /Supervisory authority/);
});

test('the breach planner leaves an omitted count unknown', async (t) => {
  const ui = await fixture(partial('_ops_privacy.html'), (url) => {
    if (url.endsWith('/regimes')) return response({regimes: [{regime: 'us_ca', name: 'California'}]});
    return response({subjects_affected: null, obligations: [], notice: 'Not legal advice.'});
  }, {form: () => ({'law:us_ca': true})});
  t.after(() => ui.window.close());
  ui.document.getElementById('ops-breach-plan').click();
  await ui.settle();
  assert.equal(posts(ui, '/breach/plan')[0].body.subjects_affected, null);
  assert.match(ui.document.getElementById('ops-breach-out').textContent, /count not provided/);
});

test('a bucket scan asks for the bucket and sends the row\'s version', async (t) => {
  const row = '<button class="ops-dm-scan" data-asset="DMA-1" data-revision="4" data-name="Exports" data-kind="bucket">Scan the files</button>';
  const ui = await fixture(row + partial('_ops_privacy.html'),
    () => response({sampled: 1, skipped: 0, categories: ['email'], revision: 5, message: 'Read 1 file. Found: email.'}),
    {form: (fields) => ({bucket: fields[0].default, folder: 'hr/'})});
  t.after(() => ui.window.close());
  ui.document.querySelector('.ops-dm-scan').click();
  await ui.settle();
  assert.deepEqual(posts(ui, '/scan-files')[0].body, {revision: 4, bucket: 'exports', folder: 'hr/'});
  assert.equal(ui.document.querySelector('.ops-dm-scan').getAttribute('data-revision'), '5');
  assert.match(ui.document.getElementById('ops-dm-scan-msg').textContent, /Exports: Read 1 file/);
});

// ---- AI governance ---------------------------------------------------------------------

test('the insurance pack is prepared in the background, then offered as a link', async (t) => {
  let polls = 0;
  const ui = await fixture(partial('_ops_ai_governance.html'), (url, options) => {
    if (url.endsWith('/assets')) return response({assets: [{id: 'MRO-1', name: 'Screening model'}]});
    if (url.endsWith('/gateway')) return response({enabled: false, callers: [], summary: 'The AI gateway is off.', results: {}});
    if (url.endsWith('/underwriting-pack') && options.method === 'POST') return response({job: 'b'.repeat(32), state: 'running'}, 202);
    polls += 1;
    return response({state: polls > 1 ? 'ready' : 'running', message: ''});
  });
  t.after(() => ui.window.close());
  assert.deepEqual([...ui.document.querySelectorAll('#ops-pack-asset option')].map((o) => o.textContent), ['Every AI system', 'Screening model']);
  ui.document.getElementById('ops-pack-start').click();
  await ui.settle(); await ui.settle();
  const link = ui.document.querySelector('#ops-pack-link a');
  assert.ok(link, 'download link offered when ready');
  assert.equal(link.getAttribute('href'), '/api/v1/governance-ops/underwriting-pack/' + 'b'.repeat(32) + '/download');
});

test('the fairness check sends the groups entered', async (t) => {
  const ui = await fixture(partial('_ops_ai_governance.html'), (url) => {
    if (url.endsWith('/assets')) return response({assets: []});
    if (url.endsWith('/gateway')) return response({enabled: true, callers: [], summary: 'On.', results: {}});
    return response({passed: false, saved: false, lowest_ratio: 0.5, summary: 'These groups are chosen much less often: B.',
      groups: [{group: 'A', rate: 0.8, ratio: 1, passes: true}, {group: 'B', rate: 0.4, ratio: 0.5, passes: false}]});
  });
  t.after(() => ui.window.close());
  const rows = ui.document.querySelectorAll('#ops-fair-groups .ops-row');
  [['A', 8, 10], ['B', 4, 10]].forEach((values, i) => {
    const inputs = rows[i].querySelectorAll('input');
    values.forEach((v, j) => { inputs[j].value = String(v); });
  });
  ui.document.getElementById('ops-fair-run').click();
  await ui.settle();
  assert.deepEqual(posts(ui, '/fairness')[0].body.groups, [{name: 'A', selected: 8, total: 10}, {name: 'B', selected: 4, total: 10}]);
  assert.match(ui.document.getElementById('ops-explain-out').textContent, /Below four-fifths/);
});

test('regulatory alerts fill the rule choices and create records only after confirming', async (t) => {
  const ui = await fixture(partial('_ops_regulatory_feed.html'), (url) => {
    if (url.endsWith('/preview')) return response({alerts: 2, regimes: [{value: 'eu_ai_act', label: 'EU AI Act'}], domains: []});
    if (url.endsWith('/assets')) return response({assets: []});
    return response({alerts: 2, matched: 1, failed: 0, stale_evidence: 1, summary: '1 of 2 alerts matched your rule.', technical: []});
  });
  t.after(() => ui.window.close());
  ui.document.getElementById('ops-feed-look').click();
  await ui.settle();
  assert.equal(ui.document.getElementById('ops-feed-form').hidden, false);
  ui.document.querySelector('#ops-feed-regimes option').selected = true;
  ui.document.getElementById('ops-feed-run').click();
  await ui.settle();
  assert.match(ui.confirms[0], /Create impact records/);
  assert.deepEqual(posts(ui, '/regulatory-feed/sync')[0].body,
    {queue: 'accepted', regimes: ['eu_ai_act'], domains: [], asset_ids: [], send_notices: false, confirm: true});
  assert.match(ui.document.getElementById('ops-feed-msg').textContent, /matched your rule/);
});

// ---- safety monitoring -------------------------------------------------------------------

test('a written reviewer test is placed only after confirming', async (t) => {
  const ui = await fixture(partial('_ops_immune.html'), (url) => {
    if (url.endsWith('/choices')) return response({people: [{value: 'user:bo', label: 'Bo'}], decision_classes: ['payments']});
    return response({planted: 1, message: 'The test approval is in the approvals queue.'});
  });
  t.after(() => ui.window.close());
  const form = ui.document.getElementById('ops-canary-form');
  form.elements.action.value = 'Pay invoice';
  form.elements.detail.value = 'Pay Acme';
  form.elements.decision_class.value = 'payments';
  form.elements.flaw.value = 'Changed account';
  form.elements.requested_by.value = 'user:bo';
  form.dispatchEvent(new ui.window.Event('submit', {cancelable: true}));
  await ui.settle();
  assert.match(ui.confirms[0], /not told it is a test/);
  assert.deepEqual(posts(ui, '/canaries/written')[0].body, {action: 'Pay invoice', detail: 'Pay Acme',
    decision_class: 'payments', flaw: 'Changed account', risk: 'medium', requested_by: 'user:bo', undoable: true});
});

test('a written reviewer test can imitate a request that takes effect at once', async (t) => {
  const ui = await fixture(partial('_ops_immune.html'), (url) => {
    if (url.endsWith('/choices')) return response({people: [], decision_classes: ['merges']});
    return response({planted: 1, message: 'The test approval is in the approvals queue.'});
  });
  t.after(() => ui.window.close());
  const form = ui.document.getElementById('ops-canary-form');
  form.elements.action.value = 'Merge branch';
  form.elements.detail.value = 'Merge feature into main';
  form.elements.decision_class.value = 'merges';
  form.elements.flaw.value = 'Skips the tests';
  form.elements.undoable.value = 'no';
  form.dispatchEvent(new ui.window.Event('submit', {cancelable: true}));
  await ui.settle();
  assert.equal(posts(ui, '/canaries/written')[0].body.undoable, false);
});

// ---- checkpoint folder and pinned keys (installation administrators) -----------

function checkpointRoute(settings, saved) {
  return (url, options) => {
    if (url.endsWith('/checkpoints/settings')) return response(settings);
    if (url.includes('/checkpoints/settings/')) { saved.push({url, body: JSON.parse(options.body)}); return response({saved: true, message: 'Saved.'}); }
    return response(CHECKPOINTS);
  };
}
const ONE_KEY = {folder: '/srv/worm', default_folder: false, signing_on: true, own_key_pinned: true, max_keys: 20,
  keys: [{fingerprint: 'AAAA BBBB CCCC DDDD', own: true}]};

test('keys are shown by fingerprint, and unpinning the last one asks first', async (t) => {
  const saved = [];
  const ui = await fixture(partial('_ops_audit_checkpoints.html'), checkpointRoute(ONE_KEY, saved), {confirm: false});
  t.after(() => ui.window.close());
  assert.match(ui.document.getElementById('ops-ckpt-where').textContent, /kept in \/srv\/worm.*1 pinned key/);
  assert.equal(ui.document.getElementById('ops-ckpt-folder').value, '/srv/worm');
  assert.match(ui.document.getElementById('ops-ckpt-keys').textContent, /This installation's key, fingerprint AAAA BBBB CCCC DDDD/);
  [...ui.document.querySelectorAll('#ops-ckpt-keys button')].find((b) => b.textContent === 'Unpin').click();
  await ui.settle();
  assert.match(ui.confirms[0], /Unpin the last key/);
  assert.equal(saved.length, 0);
});

test('pinning a second key and moving the folder are confirmed and say so to the server', async (t) => {
  const saved = [];
  const ui = await fixture(partial('_ops_audit_checkpoints.html'), checkpointRoute(ONE_KEY, saved));
  t.after(() => ui.window.close());
  ui.document.getElementById('ops-ckpt-key-paste').value = 'ssh-ed25519 AAAA';
  ui.document.getElementById('ops-ckpt-key-add').click();
  await ui.settle();
  assert.match(ui.confirms[0], /Also accept checkpoints signed with this key/);
  assert.deepEqual(saved[0].body, {key: 'ssh-ed25519 AAAA', confirm: true});
  ui.document.getElementById('ops-ckpt-folder').value = '/srv/other';
  ui.document.getElementById('ops-ckpt-folder-save').click();
  await ui.settle();
  assert.match(ui.confirms[1], /Keep checkpoints in \/srv\/other/);
  assert.deepEqual(saved[1].body, {folder: '/srv/other', confirm: true});
  assert.match(ui.document.getElementById('ops-ckpt-settings-msg').textContent, /Saved/);
});

test('the first pinned key needs no extra confirmation', async (t) => {
  const saved = [];
  const none = {...ONE_KEY, folder: '', default_folder: true, keys: [], own_key_pinned: false};
  const ui = await fixture(partial('_ops_audit_checkpoints.html'), checkpointRoute(none, saved));
  t.after(() => ui.window.close());
  assert.match(ui.document.getElementById('ops-ckpt-where').textContent, /beside each workspace's activity log.*any key/);
  ui.document.getElementById('ops-ckpt-key-own').click();
  await ui.settle();
  assert.equal(ui.confirms.length, 0);
  assert.deepEqual(saved[0].body, {own_key: true, confirm: false});
});

test('the data path check sends the what-if settings chosen', async (t) => {
  const ui = await fixture(partial('_ops_immune.html'), (url) => {
    if (url.endsWith('/choices')) return response({people: [], decision_classes: []});
    return response({assistants: 3, chains: [], total: 0, shown: 0, summary: 'Checked 3 assistants.'});
  });
  t.after(() => ui.window.close());
  ui.document.getElementById('ops-network-levels').value = 'on';
  ui.document.getElementById('ops-network-grounding').value = 'off';
  ui.document.getElementById('ops-network-run').click();
  await ui.settle();
  assert.deepEqual(posts(ui, '/network/check')[0].body, {shared_messaging: false, levels: true, grounding: false});
  ui.document.getElementById('ops-network-levels').value = '';
  ui.document.getElementById('ops-network-run').click();
  await ui.settle();
  assert.equal(posts(ui, '/network/check')[1].body.levels, null);
});
