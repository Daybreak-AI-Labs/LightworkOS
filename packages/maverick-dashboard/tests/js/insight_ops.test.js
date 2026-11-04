'use strict';
const {test} = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), {JSDOM} = require('jsdom');
const {shell} = require('./_shell');
const folder = path.resolve(__dirname, '../../maverick_dashboard');
const script = fs.readFileSync(path.join(folder, 'static/lightwork-insight-ops.js'), 'utf8');

function template(name) {
  return fs.readFileSync(path.join(folder, 'templates', name), 'utf8')
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/{%[\s\S]*?%}/g, '').replace(/{{[\s\S]*?}}/g, '7');
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
async function fixture(markup, route) {
  const dom = new JSDOM('<!doctype html><body>' + markup + '</body>', {url: 'https://lightwork.example/', runScripts: 'outside-only'});
  const {window} = dom, calls = [];
  shell(window);
  window.fetch = async (url, options = {}) => {
    calls.push({url, body: options.body ? JSON.parse(options.body) : undefined});
    return route(url, options);
  };
  window.mvErrorText = (failure, action) => 'Could not ' + action + '.';
  window.mvPlainDetail = (text) => (typeof text === 'string' && /^[A-Z][^_]*\.$/.test(text) ? text : '');
  window.mvHuman = (value) => String(value).replace(/_/g, ' ');
  window.mvWhen = () => 'today';
  window.eval(script);
  const settle = async () => { for (let i = 0; i < 20; i++) await new Promise((done) => setImmediate(done)); };
  await settle();
  return {window, document: window.document, calls, settle};
}
const CHOICES = {available: true, can_write_queries: false,
  metrics: [{value: 'spend', label: 'Money spent'}, {value: 'tasks', label: 'Tasks'}],
  groups: [{value: 'none', label: 'All together'}, {value: 'status', label: 'Task status'}]};

test('a question is built from pickers and answered as a plain table', async (t) => {
  const markup = slice('spend.html', '<section class="panel" aria-labelledby="io-ask-title">', '</section>');
  const ui = await fixture(markup, (url) => url.endsWith('/choices') ? response(CHOICES) :
    response({question: 'Money spent by task status', metric: 'spend', rows: [{group: 'done', value: 12.5}, {group: 'needs_review', value: 3}]}));
  t.after(() => ui.window.close());
  const form = ui.document.getElementById('io-ask-form');
  assert.equal(form.hidden, false);
  assert.equal(ui.document.getElementById('io-query').hidden, true);  // typed questions: installation administrators only
  form.elements.group.value = 'status';
  form.elements.since.value = '2026-01-01';
  form.dispatchEvent(new ui.window.Event('submit', {cancelable: true}));
  await ui.settle();
  assert.deepEqual(ui.calls[1].body, {metric: 'spend', group: 'status', since: '2026-01-01', until: null});
  const out = ui.document.getElementById('io-ask-out').textContent;
  assert.match(out, /Task statusMoney spent/);
  assert.match(out, /done\$12\.50/);
  assert.match(out, /needs review\$3\.00/);
});

test('a missing add-on and typed questions are handled in words', async (t) => {
  const markup = slice('spend.html', '<section class="panel" aria-labelledby="io-ask-title">', '</section>');
  let ui = await fixture(markup, () => response({...CHOICES, available: false}));
  assert.match(ui.document.getElementById('io-ask-status').textContent, /not installed/);
  assert.equal(ui.document.getElementById('io-ask-form').hidden, true);
  ui.window.close();
  ui = await fixture(markup, (url) => url.endsWith('/choices') ? response({...CHOICES, can_write_queries: true}) :
    response({columns: ['n'], rows: [['3']], more: false}));
  t.after(() => ui.window.close());
  assert.equal(ui.document.getElementById('io-query').hidden, false);
  ui.document.getElementById('io-query-text').value = 'SELECT count(*) AS n FROM goals';
  ui.document.getElementById('io-query-run').click();
  await ui.settle();
  assert.deepEqual(ui.calls[1].body, {query: 'SELECT count(*) AS n FROM goals'});
  assert.match(ui.document.getElementById('io-query-out').textContent, /n3/);
});

test('task health shows the score and its parts', async (t) => {
  const markup = '<button id="task-health-check" data-goal="7">Check</button><p id="task-health-status"></p><div id="task-health-out"></div>';
  const ui = await fixture(markup, () => response({score: 60, grade: 'D', finished: false, status: 'failed', tokens_used: 1500,
    parts: [{label: 'Starting score (the task did not finish)', points: 40}, {label: 'Tool errors and retries', points: -8}]}));
  t.after(() => ui.window.close());
  ui.document.getElementById('task-health-check').click();
  await ui.settle();
  assert.equal(ui.calls[0].url, '/api/v1/goals/7/health');
  assert.match(ui.document.getElementById('task-health-status').textContent, /60 out of 100 \(grade D\)\. The task has not finished/);
  assert.match(ui.document.getElementById('task-health-out').textContent, /Tool errors and retries-8/);
});

test('recorded steps are shown, filtered by kind, and a missing recording is explained', async (t) => {
  const markup = slice('replay.html', '<section class="panel" aria-labelledby="io-steps-title">', '</section>');
  let answer = {recording: true, damaged: false, kinds: ['plan', 'tool_call'], total: 2, matching: 2,
    steps: [{step: 1, kind: 'plan', who: 'planner', time: 1, text: 'Split the work'}, {step: 2, kind: 'tool_call', who: 'worker', time: 2, text: 'Fetched figures'}]};
  const ui = await fixture(markup, () => response(answer));
  t.after(() => ui.window.close());
  ui.document.getElementById('io-steps-show').click();
  await ui.settle();
  assert.equal(ui.calls[0].url, '/api/v1/goals/7/recorded-steps?kind=');
  const kind = ui.document.getElementById('io-steps-kind');
  assert.equal(kind.disabled, false);
  assert.deepEqual([...kind.options].map((o) => o.textContent), ['Every kind of step', 'plan', 'tool call']);
  assert.match(ui.document.getElementById('io-steps-out').textContent, /2todaytool callworkerFetched figures/);
  kind.value = 'tool_call';
  answer = {...answer, matching: 1, steps: [answer.steps[1]]};
  ui.document.getElementById('io-steps-show').click();
  await ui.settle();
  assert.equal(ui.calls[1].url, '/api/v1/goals/7/recorded-steps?kind=tool_call');
  assert.match(ui.document.getElementById('io-steps-status').textContent, /1 step of this kind, out of 2 recorded steps/);
  answer = {recording: false, steps: [], kinds: [], total: 0};
  ui.document.getElementById('io-steps-show').click();
  await ui.settle();
  assert.match(ui.document.getElementById('io-steps-status').textContent, /recording is turned off/);
});
