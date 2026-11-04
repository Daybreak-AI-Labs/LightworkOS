'use strict';
const {test} = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), {JSDOM} = require('jsdom');
const folder = path.resolve(__dirname, '../../maverick_dashboard');
const read = name => fs.readFileSync(path.join(folder, name), 'utf8').replace(/\r\n?/g, '\n');
const script = read('static/lightwork-tool-ops.js');

function template(name) {
  return read('templates/' + name)
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/{% if not [^%]*%}disabled{% endif %}/g, '')  // rendered for an administrator
    .replace(/{%[\s\S]*?%}/g, '').replace(/{{[\s\S]*?}}/g, '');
}
function slice(name, start, end) {
  const text = template(name);
  const from = text.indexOf(start);
  const to = text.indexOf(end, from);
  assert.ok(from >= 0 && to > from, name + ': ' + start);
  return text.slice(from, to + end.length);
}
function response(value, status = 200) {
  return new Response(JSON.stringify(value), {status, headers: {'Content-Type': 'application/json'}});
}
const ADMIN = {can: {installation_admin: true}};

// The shell's shared helpers (mvFetchJSON) load before page scripts, as in
// base.html; this fixture's own stand-ins for the other helpers are kept.
function withShell(window) {
  const kept = Object.fromEntries(Object.keys(window).filter((k) => k.startsWith('mv')).map((k) => [k, window[k]]));
  if (!window.matchMedia) window.matchMedia = () => ({matches: false, addEventListener() {}, removeEventListener() {}});
  window.eval(read('static/lightwork-ui.js'));
  Object.assign(window, kept);
}

async function fixture(markup, route, {confirm = true} = {}) {
  const dom = new JSDOM('<!doctype html><body>' + markup + '</body>', {url: 'https://lightwork.example/', runScripts: 'outside-only'});
  const {window} = dom, calls = [], confirms = [];
  window.fetch = async (url, options = {}) => {
    calls.push({url, options, body: options.body ? JSON.parse(options.body) : undefined});
    if (url === '/api/v1/account/me') return response(ADMIN);
    return route(url, options);
  };
  window.mvConfirm = async (message) => { confirms.push(message); return confirm; };
  window.mvErrorText = (failure, action) => 'Could not ' + action + '.';
  window.mvPlainDetail = (text) => (typeof text === 'string' && /^[A-Z][^_]*\.$/.test(text) ? text : '');
  window.mvHuman = (value) => String(value).replace(/[_-]/g, ' ');
  window.mvWhen = () => 'today';
  window.URL.createObjectURL = () => 'blob:x';
  window.URL.revokeObjectURL = () => {};
  withShell(window);
  window.eval(script);
  const settle = async () => { for (let i = 0; i < 20; i++) await new Promise((done) => setImmediate(done)); };
  await settle();
  return {window, document: window.document, calls, confirms, settle};
}
const posts = (calls, end) => calls.filter((c) => c.url.endsWith(end));
const button = (root, text) => [...root.querySelectorAll('button')].find((b) => b.textContent === text);

const PREVIEW = {name: 'weekly-status', triggers: ['weekly status'], tools: ['http_fetch'], instructions: '# Steps\n1. Summarise.',
  instructions_cut_short: false, signed: false, ok: true, problems: [], suggestions: ['It does not list the tools it uses.'],
  fingerprint: 'f'.repeat(64), technical: [{text: "no 'tools_needed:' declared"}], can_add: true};

// Suggested skills change only through a reviewed, confirmed request whose
// original result stays readable.
const CONTEXT = 'c'.repeat(64);
function reviewed(action) {
  return response({context: CONTEXT, operation: (action === 'admit' ? 'a' : 'b').repeat(32), token: 'sealed-' + action,
    message: action === 'admit' ? 'Review the exact skill.' : 'Review the exact removal.',
    changes: [{label: 'Full instructions', after: 'Check the renewal date with the account owner.'}]});
}
async function confirmReview(ui, label) {
  const review = ui.document.getElementById('to-learned-review');
  const box = review.querySelector('input[type="checkbox"]');
  box.checked = true; box.dispatchEvent(new ui.window.Event('change'));
  button(review, label).click();
  await ui.settle();
}

test('a completed-work suggestion stays a draft until an administrator reviews and adds it', async (t) => {
  const markup = slice('skills.html', '<section class="panel sk-section" aria-labelledby="to-learned-title"', '</section>');
  const candidate = {name: 'renewal-timing', triggers: ['review customer renewals'], tools: [],
    instructions: '# Steps\n1. Check the renewal date with the account owner.\n2. Report the result.',
    source_tasks: [17], fingerprint: 'a'.repeat(64), ok: true, problems: [], suggestions: []};
  let added = false;
  const ui = await fixture(markup, (url, options) => {
    if (url.endsWith('/learned-candidates')) return response({context: CONTEXT, can_add: true, blocked: '',
      suggestions: added ? [] : [candidate], added: added ? [{name: 'renewal-timing', fingerprint: 'b'.repeat(64),
        recall_ready: true, use_tracking: true, uses: 1, status: 'Available for matching new tasks.'}] : []});
    if (url.endsWith('/learned-requests')) return response({context: CONTEXT, requests: []});
    if (url.endsWith('/review')) return reviewed(JSON.parse(options.body).action);
    if (url.endsWith('/admit')) { added = true; return response({context: CONTEXT, confirmed: true, action: 'admit',
      result: {name: 'renewal-timing'}, message: 'Added renewal timing.'}); }
    if (url.endsWith('/withdraw')) { added = false; return response({context: CONTEXT, confirmed: true, action: 'withdraw',
      result: {name: 'renewal-timing'}, message: 'Removed renewal timing.'}); }
    return response({});
  });
  t.after(() => ui.window.close());
  assert.equal(posts(ui.calls, '/admit').length, 0);
  assert.match(ui.document.getElementById('to-learned-list').textContent, /Check the renewal date/);
  assert.equal(ui.document.querySelector('#to-learned-list a').getAttribute('href'), '/chat/goal/17');
  button(ui.document.getElementById('to-learned-list'), 'Review adding this skill').click();
  await ui.settle();
  assert.deepEqual(posts(ui.calls, '/review')[0].body, {action: 'admit', fingerprint: candidate.fingerprint,
    publish_name: 'renewal-timing', context: CONTEXT});
  assert.equal(posts(ui.calls, '/admit').length, 0, 'a review alone adds nothing');
  await confirmReview(ui, 'Add reviewed skill');
  assert.deepEqual(posts(ui.calls, '/admit')[0].body, {fingerprint: candidate.fingerprint, confirm: true,
    review_token: 'sealed-admit', publish_name: 'renewal-timing'});
  assert.match(ui.document.getElementById('to-learned-added').textContent, /renewal timing/);
  assert.match(ui.document.getElementById('to-learned-added').textContent, /Used on 1 later task/);
  button(ui.document.getElementById('to-learned-added'), 'Review removal').click();
  await ui.settle();
  await confirmReview(ui, 'Remove reviewed skill');
  assert.deepEqual(posts(ui.calls, '/withdraw')[0].body, {fingerprint: 'b'.repeat(64), confirm: true,
    review_token: 'sealed-withdraw'});
  assert.match(ui.document.getElementById('to-learned-status').textContent, /Removed renewal timing/);
});

test('a lost readback does not claim a suggested skill is ready', async (t) => {
  const markup = slice('skills.html', '<section class="panel sk-section" aria-labelledby="to-learned-title"', '</section>');
  const row = {name: 'renewal-timing', triggers: ['review renewal'], tools: [],
    instructions: '# Steps\n1. Review it.', source_tasks: [17], fingerprint: 'a'.repeat(64),
    ok: true, problems: [], suggestions: []};
  const ui = await fixture(markup, (url) => {
    if (url.endsWith('/learned-candidates')) return response({context: CONTEXT, can_add: true, blocked: '', suggestions: [row], added: []});
    if (url.endsWith('/learned-requests')) return response({context: CONTEXT, requests: []});
    if (url.endsWith('/review')) return reviewed('admit');
    if (url.endsWith('/admit')) return response({detail: 'unavailable'}, 503);
    return response({});
  });
  t.after(() => ui.window.close());
  button(ui.document.getElementById('to-learned-list'), 'Review adding this skill').click();
  await ui.settle();
  await confirmReview(ui, 'Add reviewed skill');
  assert.equal(posts(ui.calls, '/admit').length, 1);
  const status = ui.document.getElementById('to-learned-status').textContent;
  assert.match(status, /may have completed\. Check the original result/);
  assert.doesNotMatch(status, /Added|ready/);
  assert.equal(ui.document.getElementById('to-learned-original').disabled, false, 'the original result stays readable');
});

test('a skill is checked and shown before it can be added, then added after confirmation', async (t) => {
  const markup = slice('skills.html', '<details class="sk-more" id="to-skill-install">', '</details>');
  const ui = await fixture(markup, (url) => {
    if (url.endsWith('/source-preview')) return response(PREVIEW);
    if (url.endsWith('/source-install')) return response({name: 'weekly-status', triggers: ['weekly status'], tools_needed: []}, 201);
    return response({});
  });
  t.after(() => ui.window.close());
  const added = [];
  ui.window.lwAppendSkill = (s) => added.push(s.name);
  const github = ui.document.querySelector('input[value="github"]');
  github.checked = true;
  github.dispatchEvent(new ui.window.Event('change'));
  assert.equal(ui.document.getElementById('to-skill-gh').hidden, false);
  ui.document.getElementById('to-skill-gh-project').value = 'https://github.com/acme/skills';
  ui.document.getElementById('to-skill-gh-file').value = 'weekly/SKILL.md';
  ui.document.getElementById('to-skill-check').click();
  await ui.settle();
  assert.deepEqual(posts(ui.calls, '/source-preview')[0].body, {source: 'gh:acme/skills:weekly/SKILL.md'});
  const preview = ui.document.getElementById('to-skill-preview');
  assert.match(preview.textContent, /weekly status/);
  assert.match(preview.textContent, /Tools it can use: http fetch\./);
  assert.match(preview.textContent, /Suggestions:It does not list the tools it uses\./);
  assert.equal(posts(ui.calls, '/source-install').length, 0);  // nothing added by the check
  button(preview, 'Add this skill').click();
  await ui.settle();
  assert.match(ui.confirms[0], /Only continue if you trust where it came from/);
  assert.deepEqual(posts(ui.calls, '/source-install')[0].body, {source: 'gh:acme/skills:weekly/SKILL.md', fingerprint: 'f'.repeat(64), confirm: true});
  assert.deepEqual(added, ['weekly-status']);
  assert.match(ui.document.getElementById('skill-install-msg').textContent, /Added weekly status/);
});

test('a skill with problems cannot be added and a bad address is caught before asking', async (t) => {
  const markup = slice('skills.html', '<details class="sk-more" id="to-skill-install">', '</details>');
  const ui = await fixture(markup, () => response({...PREVIEW, ok: false, problems: ['It has no name.'], can_add: false}));
  t.after(() => ui.window.close());
  ui.document.getElementById('to-skill-url').value = 'http://insecure.example/s.md';
  ui.document.getElementById('to-skill-check').click();
  await ui.settle();
  assert.match(ui.document.getElementById('skill-install-msg').textContent, /starting with https/);
  assert.equal(ui.calls.filter((c) => c.url !== '/api/v1/account/me').length, 0);
  ui.document.getElementById('to-skill-url').value = 'https://example.com/s.md';
  ui.document.getElementById('to-skill-check').click();
  await ui.settle();
  assert.match(ui.document.getElementById('skill-install-msg').textContent, /cannot be added yet: 1 problem/);
  assert.equal(button(ui.document.getElementById('to-skill-preview'), 'Add this skill'), undefined);
});

test('when adding skills from a web address is off, the check says so plainly and shows nothing to add', async (t) => {
  // The server's own sentence, read from the route, through the page's real plain-sentence filter.
  const api = read('tools_ops_api.py');
  const off = /_INSTALL_OFF = \(([\s\S]*?)\)\n/.exec(api)[1].match(/"([^"]*)"/g).map((q) => q.slice(1, -1)).join('');
  const ui = await fixture(slice('skills.html', '<details class="sk-more" id="to-skill-install">', '</details>'),
    () => response({detail: off}, 403));
  t.after(() => ui.window.close());
  const lib = read('static/lightwork-ui.js');
  const filter = /var JARGON = [\s\S]*?window\.mvPlainDetail = function \(detail\) \{[\s\S]*?return text;\n\s*\};/.exec(lib)[0];
  ui.window.eval(filter);
  ui.document.getElementById('to-skill-url').value = 'https://example.com/s.md';
  ui.document.getElementById('to-skill-check').click();
  await ui.settle();
  assert.equal(ui.document.getElementById('skill-install-msg').textContent, off);
  assert.match(off, /turned off/);
  assert.equal(ui.document.getElementById('to-skill-preview').textContent, '');
  assert.equal(posts(ui.calls, '/source-install').length, 0);
});

test('skills that rarely help are listed, then removed only after confirmation', async (t) => {
  const markup = slice('skills.html', '<section class="panel sk-section" aria-labelledby="to-tidy-title">', '</section>') +
    '<div data-skill="dud"></div><div data-skill="good"></div>';
  const row = {name: 'dud', uses: 20, wins: 0, losses: 20, win_rate: 0, weight: 0.5, last_used: 1};
  const ui = await fixture(markup, (url) => url.endsWith('/tidy-preview') ? response({skills: [row]}) : response({removed: ['dud'], skipped: 0}));
  t.after(() => ui.window.close());
  ui.document.getElementById('to-tidy-uses').value = '10';
  ui.document.getElementById('to-tidy-check').click();
  await ui.settle();
  assert.deepEqual(posts(ui.calls, '/tidy-preview')[0].body, {min_uses: 10, max_success: 0.2});
  assert.match(ui.document.getElementById('to-tidy-out').textContent, /dud200200%Lowered to 50%/);
  button(ui.document.getElementById('to-tidy-out'), 'Remove 1 skill').click();
  await ui.settle();
  assert.match(ui.confirms[0], /cannot be undone/);
  assert.deepEqual(posts(ui.calls, '/skills/tidy')[0].body, {min_uses: 10, max_success: 0.2, names: ['dud'], confirm: true});
  assert.equal(ui.document.querySelector('[data-skill="dud"]'), null);
  assert.ok(ui.document.querySelector('[data-skill="good"]'));
});

test('add-on versions are listed plainly, pinned and reloaded only after confirmation', async (t) => {
  const markup = slice('plugins.html', '<section class="panel" aria-labelledby="to-versions-title">', '</section>');
  const versions = {pinned: false, ok: true, summary: 'Add-on versions are not pinned yet.', rule: 'Differences are not checked when add-ons load.',
    addons: [{name: 'acme-tools', approved: '', installed: '1.0.0', state: 'unpinned', label: 'Not pinned yet'}]};
  const ui = await fixture(markup, (url) => {
    if (url.endsWith('/versions/pin')) return response({...versions, pinned: 1, summary: 'Every add-on matches its approved version.',
      addons: [{...versions.addons[0], approved: '1.0.0', state: 'match', label: 'Matches the approved version'}]});
    if (url.endsWith('/reload')) return response({reloaded_parts: 3, technical: []});
    return response(versions);
  });
  t.after(() => ui.window.close());
  assert.match(ui.document.getElementById('to-versions').textContent, /acme-tools—1\.0\.0Not pinned yet/);
  ui.document.getElementById('to-versions-pin').click();
  await ui.settle();
  assert.match(ui.confirms[0], /approved ones/);
  assert.deepEqual(posts(ui.calls, '/versions/pin')[0].body, {confirm: true});
  assert.match(ui.document.getElementById('to-versions').textContent, /Matches the approved version/);
  button(ui.document.getElementById('to-versions'), 'Reload').click();
  await ui.settle();
  assert.match(ui.confirms[1], /Reload the add-on “acme-tools”/);
  assert.deepEqual(posts(ui.calls, '/plugins/reload')[0].body, {addon: 'acme-tools', confirm: true});
  assert.match(ui.document.getElementById('to-versions-status').textContent, /3 parts/);
});

test('a cancelled pin changes nothing', async (t) => {
  const markup = slice('plugins.html', '<section class="panel" aria-labelledby="to-versions-title">', '</section>');
  const ui = await fixture(markup, () => response({pinned: false, ok: true, summary: 'x', rule: '', addons: []}), {confirm: false});
  t.after(() => ui.window.close());
  ui.document.getElementById('to-versions-pin').click();
  await ui.settle();
  assert.equal(posts(ui.calls, '/versions/pin').length, 0);
});

test('add-on use and the starter download read plainly', async (t) => {
  const markup = slice('plugins.html', '<section class="panel" aria-labelledby="to-plugin-usage-title">', '</section>') +
    slice('plugins.html', '<section class="panel" aria-labelledby="to-starter-title">', '</section>');
  const ui = await fixture(markup, (url) => {
    if (url.endsWith('/plugins/usage')) return response({counting: false, tools: [{tool: 'get_forecast', addon: 'acme-tools', calls: 4, last_used: 1}]});
    return new Response('zip', {status: 200, headers: {'Content-Type': 'application/zip'}});
  });
  t.after(() => ui.window.close());
  assert.match(ui.document.getElementById('to-plugin-usage').textContent, /get forecastacme-tools4today/);
  assert.match(ui.document.getElementById('to-plugin-usage-status').textContent, /Counting is off/);
  const form = ui.document.getElementById('to-starter-form');
  form.elements.name.value = 'Weather Tools';
  form.elements.kind.value = 'persona';
  form.dispatchEvent(new ui.window.Event('submit', {cancelable: true}));
  await ui.settle();
  assert.deepEqual(posts(ui.calls, '/plugins/starter')[0].body, {name: 'Weather Tools', kind: 'persona'});
  assert.match(ui.document.getElementById('to-starter-status').textContent, /Nothing was installed/);
});

test('a connector change is previewed from pickers and nothing is changed', async (t) => {
  const markup = slice('connections.html', '<section aria-labelledby="to-connectors-title" id="to-connectors-panel" hidden>', '</section>');
  const ui = await fixture(markup, (url) => {
    if (url.endsWith('/governed-connectors')) return response({enabled: true, can_read_prior: true, available: ['salesforce'],
      connectors: [{name: 'salesforce', change_risk: 'High', needs_approval: true, can_address_records: true}]});
    return response({summary: 'Lightwork would change Amount on the Opportunity record 006 in Salesforce.', risk: 'High',
      needs_approval: true, changed_anything: false, read_current_values: true, can_undo: true, money_at_stake: 120000,
      undo_note: 'Lightwork holds what it needs to undo this change.', technical: [{text: 'would PATCH salesforce/…'}]});
  });
  t.after(() => ui.window.close());
  assert.equal(ui.document.getElementById('to-connectors-panel').hidden, false);
  assert.match(ui.document.getElementById('to-connectors').textContent, /salesforceHighYes/);
  const form = ui.document.getElementById('to-change-form');
  assert.equal(form.hidden, false);
  form.elements.record_type.value = 'Opportunity';
  form.elements.record_id.value = '006000000000001AAA';
  const field = ui.document.querySelector('#to-change-fields .to-field');
  const [name, kind, value] = field.querySelectorAll('input, select');
  name.value = 'Amount'; kind.value = 'number'; value.value = '120000';
  form.dispatchEvent(new ui.window.Event('submit', {cancelable: true}));
  await ui.settle();
  assert.deepEqual(posts(ui.calls, '/governed-connectors/preview')[0].body, {connector: 'salesforce', change: 'update',
    record_type: 'Opportunity', record_id: '006000000000001AAA', fields: [{name: 'Amount', kind: 'number', value: '120000'}],
    read_current_values: true});
  const out = ui.document.getElementById('to-change-out').textContent;
  assert.match(out, /Could be undoneYes/);
  assert.match(out, /Nothing was changed\./);
  form.elements.change.value = 'create';
  form.elements.change.dispatchEvent(new ui.window.Event('change'));
  assert.equal(ui.document.getElementById('to-change-record-wrap').hidden, true);
});

test('the connectors panel stays hidden from people who are not installation administrators', async (t) => {
  const markup = slice('connections.html', '<section aria-labelledby="to-connectors-title" id="to-connectors-panel" hidden>', '</section>');
  const dom = new JSDOM('<!doctype html><body>' + markup + '</body>', {url: 'https://lightwork.example/', runScripts: 'outside-only'});
  const calls = [];
  dom.window.fetch = async (url) => { calls.push(url); return response({can: {installation_admin: false}}); };
  withShell(dom.window);
  dom.window.eval(script);
  for (let i = 0; i < 20; i++) await new Promise((done) => setImmediate(done));
  t.after(() => dom.window.close());
  assert.equal(dom.window.document.getElementById('to-connectors-panel').hidden, true);
  assert.deepEqual(calls, ['/api/v1/account/me']);
});

test('ratings download is offered to installation administrators', async (t) => {
  const markup = slice('templates_market.html', '<section class="panel tplm__ratings" id="to-ratings"', '</section>');
  const ui = await fixture(markup, () => new Response('{}', {status: 200}));
  t.after(() => ui.window.close());
  assert.equal(ui.document.getElementById('to-ratings').hidden, false);
  ui.document.getElementById('to-ratings-download').click();
  await ui.settle();
  assert.ok(ui.calls.some((c) => c.url === '/api/v1/templates/ratings-export'));
  assert.match(ui.document.getElementById('to-ratings-status').textContent, /comments stay here/);
});
