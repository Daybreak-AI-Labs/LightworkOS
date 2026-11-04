'use strict';
const {test} = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), {JSDOM} = require('jsdom');
const {shell} = require('./_shell');
const folder = path.resolve(__dirname, '../../maverick_dashboard');
const script = fs.readFileSync(path.join(folder, 'static/lightwork-feature-actions.js'), 'utf8');

function template(name) {
  return fs.readFileSync(path.join(folder, 'templates', name), 'utf8')
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '');
}
// The block of a template between two markers (the panel this change added).
function slice(name, start, end) {
  const text = template(name);
  const from = text.indexOf(start);
  const to = text.indexOf(end, from);
  assert.ok(from >= 0 && to > from, name + ': ' + start);
  return text.slice(from, to + end.length);
}
function response(value, status = 200, headers = {}) {
  return new Response(JSON.stringify(value), {status, headers: {'Content-Type': 'application/json', ...headers}});
}
const ME = {name: 'Ada', role: 'Administrator', departments: [], all_departments: true, tools: 'Every tool',
  role_source: 'Current workspace role', access_owner: 'Installation administrator', department_source: 'Current workspace policy',
  allowed_tool_names: [], allowed_tool_summary: 'Every tool', blocked_tool_names: [], tool_policy_source: 'Installation policy',
  profile: 'Enterprise', enterprise_boundary: true, privacy_scope: 'Private task content requires owner access.',
  blocked_tools: 0, risk: 'No limit', limits_enforced: true, installation_admin: true,
  abilities: [{label: 'See work and results', allowed: true}, {label: 'Change settings and manage people', allowed: false}],
  can: {view: true, operate: true, audit: false, admin: true, installation_admin: true}};

async function fixture(markup, route, {confirm = true} = {}) {
  const dom = new JSDOM('<!doctype html><body>' + markup + '</body>', {url: 'https://lightwork.example/', runScripts: 'outside-only'});
  const {window} = dom, calls = [], confirms = [];
  shell(window);
  window.fetch = async (url, options = {}) => {
    calls.push({url, options});
    if (url === '/api/v1/account/me') return response(ME);
    return route(url, options);
  };
  window.mvConfirm = async (message) => { confirms.push(message); return confirm; };
  window.mvErrorText = (failure, action) => 'Could not ' + action + '.';
  window.mvPlainDetail = (text) => (typeof text === 'string' && /^[A-Z][^_]*\.$/.test(text) ? text : '');
  window.mvHuman = (value) => String(value).replace(/_/g, ' ');
  window.URL.createObjectURL = () => 'blob:x';
  window.URL.revokeObjectURL = () => {};
  window.eval(script);
  const settle = async () => { for (let i = 0; i < 20; i++) await new Promise((done) => setImmediate(done)); };
  await settle();
  return {window, document: window.document, calls, confirms, settle};
}
function choose(window, input, name, text, type) {
  const file = new window.File([text], name, {type: type || 'application/octet-stream'});
  Object.defineProperty(input, 'files', {value: [file], configurable: true});
  input.dispatchEvent(new window.Event('change'));
}
const nonAccount = (calls) => calls.filter((c) => c.url !== '/api/v1/account/me');

test('your account lists role, departments and abilities in words', async (t) => {
  const ui = await fixture(template('account.html').split('{% block content %}')[1], () => response({}));
  t.after(() => ui.window.close());
  const text = ui.document.getElementById('fa-account').textContent;
  assert.match(text, /Signed in asAda/);
  assert.match(text, /DepartmentsAll departments/);
  assert.match(text, /Yes See work and results/);
  assert.match(text, /No Change settings and manage people/);
});

test('controls needing a permission the person lacks stay hidden', async (t) => {
  const markup = '<div id="a" data-fa-needs="operate" hidden></div><div id="b" data-fa-needs="audit" hidden></div>';
  const ui = await fixture(markup, () => response({}));
  t.after(() => ui.window.close());
  assert.equal(ui.document.getElementById('a').hidden, false);
  assert.equal(ui.document.getElementById('b').hidden, true);
});

test('add to knowledge posts the text with its source and reports success', async (t) => {
  const markup = slice('cortex.html', '<section aria-labelledby="fa-cortex-h"', '</section>')
    .replace(/{%[^%]*%}/g, '');
  const ui = await fixture(markup, () => response({ok: true, reason: 'ok'}));
  t.after(() => ui.window.close());
  const form = ui.document.getElementById('fa-cortex-add');
  // The page lists the default place plus existing document groups to keep it with.
  form.elements.collection.innerHTML = '<option value="cortex">Company brain</option><option value="policies">Policies</option>';
  form.elements.collection.value = 'policies';
  form.elements.text.value = 'Refunds within 30 days.';
  form.elements.source.value = 'Refund policy';
  form.dispatchEvent(new ui.window.Event('submit', {cancelable: true}));
  await ui.settle();
  const call = nonAccount(ui.calls)[0];
  assert.equal(call.url, '/api/v1/cortex/deposit');
  assert.deepEqual(JSON.parse(call.options.body), {text: 'Refunds within 30 days.', kind: 'knowledge', source: 'Refund policy', collection: 'policies'});
  assert.match(ui.document.getElementById('fa-cortex-status').textContent, /Added/);
});

test('column names are checked without saving and flagged ones listed', async (t) => {
  const markup = '<textarea id="fa-dm-columns">email, order_total\ndate_of_birth</textarea><button id="fa-dm-check"></button>' +
    '<span id="fa-dm-check-status"></span><div id="fa-dm-check-out"></div>';
  const ui = await fixture(markup, () => response({flagged: {email: ['contact'], date_of_birth: ['identity']}}));
  t.after(() => ui.window.close());
  ui.document.getElementById('fa-dm-check').click();
  await ui.settle();
  const call = nonAccount(ui.calls)[0];
  assert.deepEqual(JSON.parse(call.options.body), {columns: ['email', 'order_total', 'date_of_birth']});
  assert.match(ui.document.getElementById('fa-dm-check-status').textContent, /2 columns of 3/);
  assert.match(ui.document.getElementById('fa-dm-check-out').textContent, /date of birth|date_of_birth/);
});

test('sharing lessons previews the file and adds only after confirming', async (t) => {
  const markup = slice('learning.html', '<div data-fa-needs="installation_admin" hidden>', '</section>') + '</div>';
  const ui = await fixture(markup, (url) => {
    if (url.endsWith('/preview')) return response({usable: true, count: 2, lessons: ['Check totals', 'Ask first'], summary: 'This file holds 2 lessons.', technical: []});
    if (url.endsWith('/import')) return response({added: 2});
    return response({});
  });
  t.after(() => ui.window.close());
  choose(ui.window, ui.document.getElementById('fa-lessons-file'), 'lessons.json', '{}', 'application/json');
  await ui.settle();
  assert.match(ui.document.getElementById('fa-lessons-out').textContent, /Check totals/);
  assert.equal(nonAccount(ui.calls).filter((c) => c.url.endsWith('/import')).length, 0);
  [...ui.document.querySelectorAll('#fa-lessons-out button')].find((b) => b.textContent === 'Add these lessons').click();
  await ui.settle();
  assert.match(ui.confirms[0], /Add 2 lessons/);
  assert.equal(nonAccount(ui.calls).filter((c) => c.url.endsWith('/import')).length, 1);
  assert.match(ui.document.getElementById('fa-lessons-status').textContent, /Added 2 lessons/);
});

test('a published lesson with incomplete activity evidence is not shown as clean success', async (t) => {
  const markup = slice('learning.html', '<div data-fa-needs="installation_admin" hidden>', '</section>') + '</div>';
  const ui = await fixture(markup, (url) => {
    if (url.endsWith('/preview')) return response({usable: true, count: 1, lessons: ['Check totals'], summary: 'Ready.', technical: []});
    if (url.endsWith('/import')) return response({added: 1, audit_complete: false, message: 'The lesson was added, but the activity record is incomplete.'}, 202);
    return response({});
  });
  t.after(() => ui.window.close());
  choose(ui.window, ui.document.getElementById('fa-lessons-file'), 'lessons.json', '{}', 'application/json');
  await ui.settle();
  const add = [...ui.document.querySelectorAll('#fa-lessons-out button')].find((b) => b.textContent === 'Add these lessons');
  add.click();
  await ui.settle();
  assert.match(ui.document.getElementById('fa-lessons-status').textContent, /activity record is incomplete/);
  assert.doesNotMatch(ui.document.getElementById('fa-lessons-status').textContent, /Added 1 lesson/);
  assert.equal(add.disabled, true);
});

test('an untrusted lesson file offers no add button', async (t) => {
  const markup = slice('learning.html', '<div data-fa-needs="installation_admin" hidden>', '</section>') + '</div>';
  const ui = await fixture(markup, () => response({usable: false, count: 0, lessons: [], summary: 'This file comes from an installation you have not chosen to trust yet.', technical: [{text: 'untrusted peer key'}]}));
  t.after(() => ui.window.close());
  choose(ui.window, ui.document.getElementById('fa-lessons-file'), 'lessons.json', '{}');
  await ui.settle();
  assert.match(ui.document.getElementById('fa-lessons-status').textContent, /not chosen to trust/);
  assert.equal(ui.document.querySelectorAll('#fa-lessons-out button').length, 0);
  assert.equal(ui.document.querySelector('#fa-lessons-out details').open, false);
});

test('loading customizations shows what will be loaded, then confirms', async (t) => {
  const markup = slice('roles.html', '<div data-fa-needs="admin" hidden>', '</section>') + '</div>';
  const ui = await fixture(markup, (url) => {
    if (url.endsWith('/preview')) return response({items: [{kind: 'Role', name: 'Coder', ok: true}, {kind: 'Role', name: 'Bad', ok: false}], usable: 1, skipped: 1, summary: '1 customization can be loaded; 1 will be skipped.', technical: []});
    return response({specialists: 0, roles: 1, skipped: 1, technical: []});
  }, {confirm: false});
  t.after(() => ui.window.close());
  choose(ui.window, ui.document.getElementById('fa-custom-file'), 'c.zip', 'PK', 'application/zip');
  await ui.settle();
  assert.match(ui.document.getElementById('fa-custom-out').textContent, /CoderWill be loaded/);
  assert.match(ui.document.getElementById('fa-custom-out').textContent, /BadWill be skipped/);
  [...ui.document.querySelectorAll('#fa-custom-out button')].find((b) => b.textContent === 'Load these customizations').click();
  await ui.settle();
  assert.match(ui.confirms[0], /replaced/);
  assert.equal(nonAccount(ui.calls).filter((c) => c.url.endsWith('/load')).length, 0);  // cancelled
});

test('the tool server list is searchable, shows what a server starts, and adding one confirms the consequence', async (t) => {
  const markup = slice('mcp.html', '<section class="panel" id="fa-registry"', '</section>');
  const fp = 'a'.repeat(64);
  const ui = await fixture(markup, (url) => {
    if (url.endsWith('/add')) return response({added: 'weather'});
    if (url.endsWith('/preview')) return response({name: 'weather', online: true, address: 'https://mcp.example.com/weather',
      program: '', arguments: [], settings: [], extra_headers: ['X-Region'], program_checked: false, fingerprint: fp});
    if (url.endsWith('/tools')) return response({tools: [{name: 'forecast', description: "Tomorrow's weather"}]});
    return response({configured: true, servers: [
      {name: 'weather', summary: 'Forecasts', verified: true, online: true},
      {name: 'files', summary: 'Local files', verified: false, online: false}]});
  });
  t.after(() => ui.window.close());
  ui.document.getElementById('fa-registry-load').click();
  await ui.settle();
  const search = ui.document.getElementById('fa-registry-search');
  assert.equal(search.hidden, false);
  search.value = 'forecast';
  search.dispatchEvent(new ui.window.Event('input'));
  const rows = ui.document.querySelectorAll('#fa-registry-out tbody tr');
  assert.equal(rows.length, 1);
  rows[0].querySelector('button').click();
  await ui.settle();
  const box = ui.document.getElementById('fa-registry-preview');
  assert.match(box.textContent, /Web address it connects tohttps:\/\/mcp\.example\.com\/weather/);
  assert.match(box.textContent, /Extra details sent with each requestX-Region/);
  assert.equal(nonAccount(ui.calls).filter((c) => c.url.endsWith('/mcp-registry/add')).length, 0);  // looking adds nothing
  [...box.querySelectorAll('button')].find((b) => b.textContent === 'Ask which tools it offers').click();
  await ui.settle();
  assert.match(ui.confirms[0], /Nothing is added/);
  assert.deepEqual(JSON.parse(nonAccount(ui.calls).find((c) => c.url.endsWith('/tools')).options.body), {name: 'weather', fingerprint: fp, confirm: true});
  assert.match(box.textContent, /forecastTomorrow's weather/);
  [...box.querySelectorAll('button')].find((b) => b.textContent === 'Add this tool server').click();
  await ui.settle();
  assert.match(ui.confirms[1], /another company's computers/);
  const add = nonAccount(ui.calls).find((c) => c.url.endsWith('/mcp-registry/add'));
  assert.deepEqual(JSON.parse(add.options.body), {name: 'weather', fingerprint: fp});
});

test('a local tool server that is handed every server setting says so before it is added', async (t) => {
  const markup = slice('mcp.html', '<section class="panel" id="fa-registry"', '</section>');
  const preview = {name: 'files', online: false, address: '', program: '/opt/mcp/files', arguments: [], settings: ['FILES_ROOT'],
    extra_headers: [], program_checked: true, fingerprint: 'a'.repeat(64)};
  let gets = true;
  const ui = await fixture(markup, (url) => {
    if (url.endsWith('/preview')) return response({...preview, gets_every_server_setting: gets});
    return response({configured: true, servers: [{name: 'files', summary: 'Local files', verified: false, online: false}]});
  });
  t.after(() => ui.window.close());
  ui.document.getElementById('fa-registry-load').click();
  await ui.settle();
  ui.document.querySelector('#fa-registry-out tbody tr button').click();
  await ui.settle();
  const box = ui.document.getElementById('fa-registry-preview');
  assert.match(box.textContent, /Also givenEvery setting of this server, including its passwords and keys/);
  gets = false;
  ui.document.querySelector('#fa-registry-out tbody tr button').click();
  await ui.settle();
  assert.doesNotMatch(box.textContent, /Also given/);
});

test('screening test shows caught and wrongly stopped rates in words', async (t) => {
  const markup = slice('safety.html', '<section class="panel" aria-labelledby="fa-calibration-title">', '</section>');
  const ui = await fixture(markup, () => response({cases: 40, thresholds: {high: {recall: 0.9, precision: 1, fp_rate: 0.05}}, rule_hits: {injection: 3}}));
  t.after(() => ui.window.close());
  ui.document.getElementById('fa-calibration-run').click();
  await ui.settle();
  const out = ui.document.getElementById('fa-calibration-out').textContent;
  assert.match(out, /Relaxed90%5%/);
  assert.match(ui.document.getElementById('fa-calibration-status').textContent, /40 example messages/);
});

test('independence levels and spending groups read in words', async (t) => {
  const markup = slice('workforce.html', '<section class="panel" aria-labelledby="fa-autonomy-title">', '</section>') +
    slice('spend.html', '<section class="panel" aria-labelledby="fa-tags-title">', '</section>');
  const ui = await fixture(markup, (url) => {
    if (url.startsWith('/api/v1/cost/by-tag')) return response({buckets: [{tag: '(untagged)', cost: 1.5, runs: 3}]});
    return response({levels_enabled: false, autonomy_posture: {observe: 1, suggest: 2, request: 0, auto: 0}, packs_onboarding: 0,
      graduation_candidates: [{name: 'finance_clerk', sample: 20, approve_rate: 0.95, confidence: 0.9, reason: 'clean record'}]});
  });
  t.after(() => ui.window.close());
  // Levels are off in this fixture: one plain line, no per-level counts that
  // would read as a real split of the workforce.
  assert.match(ui.document.getElementById('fa-autonomy-status').textContent, /Independence levels are turned off/);
  assert.doesNotMatch(ui.document.getElementById('fa-autonomy').textContent, /Suggest: 2|Watch only: 1|Ask before acting|Still learning/);
  assert.match(ui.document.getElementById('fa-autonomy').textContent, /finance clerk2095%/);
  ui.document.getElementById('fa-tags-run').click();
  await ui.settle();
  assert.match(ui.document.getElementById('fa-tags-out').textContent, /Not labelled/);
});

test('independence levels show each level count once the levels are on', async (t) => {
  const markup = slice('workforce.html', '<section class="panel" aria-labelledby="fa-autonomy-title">', '</section>');
  const ui = await fixture(markup, () => response({levels_enabled: true, autonomy_posture: {observe: 1, suggest: 2, request: 3, auto: 4},
    packs_onboarding: 5, graduation_candidates: []}));
  t.after(() => ui.window.close());
  const text = ui.document.getElementById('fa-autonomy').textContent;
  assert.match(text, /Watch only: 1/);
  assert.match(text, /Suggest: 2/);
  assert.match(text, /Ask before acting: 3/);
  assert.match(text, /Act on their own: 4/);
  assert.match(text, /Still learning the ropes: 5/);
  assert.match(ui.document.getElementById('fa-autonomy-status').textContent, /own level of independence/);
});

test('a graduation candidate can be granted only after confirmation and a fresh server check', async (t) => {
  const markup = slice('workforce.html', '<section class="panel" aria-labelledby="fa-autonomy-title">', '</section>');
  let granted = false;
  const ui = await fixture(markup, (url, options) => {
    if (url === '/api/v1/agents/finance_clerk/graduate') {
      granted = true;
      return response({autonomy: {onboarding: false}});
    }
    return response({levels_enabled: true, can_manage: true,
      autonomy_posture: {suggest: 1}, packs_onboarding: granted ? 0 : 1,
      graduation_candidates: granted ? [] : [{name: 'finance_clerk', sample: 20, approve_rate: 0.95,
        confidence: 0.9, reason: 'clean record', generation: 'a'.repeat(64), can_grant: true}]});
  });
  t.after(() => ui.window.close());
  const grant = [...ui.document.querySelectorAll('#fa-autonomy button')].find((button) => /Grant independence/.test(button.textContent));
  assert.ok(grant);
  grant.click();
  await ui.settle();
  const mutation = nonAccount(ui.calls).find((call) => call.url === '/api/v1/agents/finance_clerk/graduate');
  assert.ok(mutation);
  assert.equal(mutation.options.method, 'POST');
  assert.deepEqual(JSON.parse(mutation.options.body), {expected_generation: 'a'.repeat(64)});
  assert.equal(ui.confirms.length, 1);
  assert.doesNotMatch(ui.document.getElementById('fa-autonomy').textContent, /Grant independence/);
});

test('an Act policy explains why aggregate approvals cannot grant independence', async (t) => {
  const markup = slice('workforce.html', '<section class="panel" aria-labelledby="fa-autonomy-title">', '</section>');
  const ui = await fixture(markup, () => response({levels_enabled: true, can_manage: true,
    autonomy_posture: {suggest: 1}, packs_onboarding: 1,
    graduation_candidates: [{name: 'finance_clerk', sample: 100, approve_rate: 1,
      confidence: 1, reason: 'clean record', generation: 'a'.repeat(64), can_grant: false,
      grant_block_reason: 'This specialist is set to Act on its own for high actions. Its overall approval record cannot prove those actions are safe.'}]}));
  t.after(() => ui.window.close());
  const panel = ui.document.getElementById('fa-autonomy');
  assert.match(panel.textContent, /overall approval record cannot prove/);
  assert.ok(panel.querySelector('a[href="/agents?name=finance_clerk#agent-autonomy"]'));
  assert.doesNotMatch(panel.textContent, /Grant independence/);
});

test('a skill file is checked and problems stay in technical details', async (t) => {
  const markup = '<input type="file" id="fa-skill-file"><p id="fa-skill-status"></p><div id="fa-skill-out"></div>';
  const ui = await fixture(markup, () => response({ok: false, errors: ['frontmatter missing name'], warnings: []}));
  t.after(() => ui.window.close());
  choose(ui.window, ui.document.getElementById('fa-skill-file'), 'SKILL.md', '# hi', 'text/markdown');
  await ui.settle();
  const call = nonAccount(ui.calls)[0];
  assert.equal(call.url, '/api/v1/skills/validate');
  assert.match(ui.document.getElementById('fa-skill-status').textContent, /1 problem must be fixed/);
  assert.match(ui.document.querySelector('#fa-skill-out details').textContent, /frontmatter/);
});
