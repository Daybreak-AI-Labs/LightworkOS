'use strict';
const {test} = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), {JSDOM} = require('jsdom');
const {shell} = require('./_shell');
const folder = path.resolve(__dirname, '../../maverick_dashboard');
const script = fs.readFileSync(path.join(folder, 'static/lightwork-code-sandbox.js'), 'utf8');

function panel() {
  const text = fs.readFileSync(path.join(folder, 'templates', 'chat_goal.html'), 'utf8');
  const from = text.indexOf('<details class="more" id="code-sandbox"');
  const to = text.indexOf('</details>', from);
  assert.ok(from >= 0 && to > from);
  return text.slice(from, to + 10).replace(/{{[\s\S]*?}}/g, '7');
}
function response(value, status = 200) {
  return new Response(JSON.stringify(value), {status, headers: {'Content-Type': 'application/json'}});
}
const LIMITS = {code_characters: 20000, output_characters: 8000, steps_per_session: 200, seconds_per_step: 30, idle_minutes: 30, open_sessions: 2};

async function fixture(route, {confirm = true} = {}) {
  const dom = new JSDOM('<!doctype html><body>' + panel() + '</body>', {url: 'https://lightwork.example/', runScripts: 'outside-only'});
  const {window} = dom, calls = [], confirms = [];
  shell(window);
  window.fetch = async (url, options = {}) => {
    calls.push({url, method: options.method || 'GET', body: options.body ? JSON.parse(options.body) : undefined});
    return route(url, options);
  };
  window.mvConfirm = async (message) => { confirms.push(message); return confirm; };
  window.mvErrorText = (failure, action) => 'Could not ' + action + '.';
  window.mvPlainDetail = (text) => (typeof text === 'string' && /^[A-Z][^_]*\.$/.test(text) ? text : '');
  window.mvWhen = () => 'today';
  window.eval(script);
  const settle = async () => { for (let i = 0; i < 20; i++) await new Promise((done) => setImmediate(done)); };
  await settle();
  const details = window.document.getElementById('code-sandbox');
  details.open = true;
  details.dispatchEvent(new window.Event('toggle'));
  await settle();
  return {window, document: window.document, calls, confirms, settle};
}
const button = (root, text) => [...root.querySelectorAll('button')].find((b) => b.textContent === text);

test('nothing loads until the panel is opened, then a session is started, run and closed', async (t) => {
  let sessions = [];
  const ui = await fixture((url, options) => {
    if (url.endsWith('/code') && options.method === 'GET') return response({enabled: true, allowed: true, on_this_computer: false, limits: LIMITS, sessions});
    if (url.endsWith('/code/sessions')) { sessions = [{id: 'abcdef0123456789', open: true, steps: 0, started: 1}]; return response({id: 'abcdef0123456789'}, 201); }
    if (url.endsWith('/run')) return response({ok: true, output: '42\n', problems: '', cut_short: false, not_kept: ['helper'], seconds: 0.2});
    if (url.endsWith('/close')) { sessions = [{id: 'abcdef0123456789', open: false, steps: 1, started: 1}]; return response({closed: true}); }
    if (url.endsWith('/log')) return response({closed: true, steps: [{step: 1, time: 1, ok: true, seconds: 0.2, code: 'print(6 * 7)', not_kept: [], cut_short: false}]});
    return response({});
  });
  t.after(() => ui.window.close());
  assert.equal(ui.calls[0].url, '/api/v1/goals/7/code');
  const body = ui.document.getElementById('code-sandbox-body');
  button(body, 'Start a code session').click();
  await ui.settle();
  assert.equal(ui.calls.filter((c) => c.url.endsWith('/code/sessions')).length, 1);
  ui.document.getElementById('code-sandbox-code').value = 'print(6 * 7)';
  button(body, 'Run').click();
  await ui.settle();
  const run = ui.calls.find((c) => c.url.endsWith('/run'));
  assert.equal(run.url, '/api/v1/goals/7/code/sessions/abcdef0123456789/run');
  assert.deepEqual(run.body, {code: 'print(6 * 7)'});
  assert.match(body.textContent, /Finished in 0\.2 seconds: print\(6 \* 7\)42/);
  assert.match(body.textContent, /Not kept for the next step: helper\./);
  button(body, 'Close session').click();
  await ui.settle();
  assert.match(ui.confirms[0], /Its log stays with the task/);
  assert.ok(ui.calls.some((c) => c.url.endsWith('/close')));
  button(body, 'Show log').click();
  await ui.settle();
  assert.match(body.textContent, /1todayFinished0\.2print\(6 \* 7\)/);
});

test('a refused or failing step is explained, and a cancelled close keeps the session', async (t) => {
  const ui = await fixture((url, options) => {
    if (url.endsWith('/code') && options.method === 'GET') return response({enabled: true, allowed: true, limits: LIMITS,
      sessions: [{id: 'abcdef0123456789', open: true, steps: 2, started: 1}]});
    if (url.endsWith('/run')) return response({ok: false, output: '', problems: 'ZeroDivisionError: division by zero', cut_short: false, not_kept: [], seconds: 0.1});
    return response({});
  }, {confirm: false});
  t.after(() => ui.window.close());
  const body = ui.document.getElementById('code-sandbox-body');
  button(body, 'Run').click();
  await ui.settle();
  assert.match(ui.document.getElementById('code-sandbox-status').textContent, /Write some code first/);
  ui.document.getElementById('code-sandbox-code').value = '1 / 0';
  button(body, 'Run').click();
  await ui.settle();
  assert.match(body.textContent, /Stopped with an error/);
  assert.match(body.querySelector('details').textContent, /What went wrongZeroDivisionError/);
  button(body, 'Close session').click();
  await ui.settle();
  assert.equal(ui.calls.filter((c) => c.url.endsWith('/close')).length, 0);
});

test('turned off or not allowed says so in words', async (t) => {
  let ui = await fixture(() => response({enabled: false, sessions: []}));
  assert.match(ui.document.getElementById('code-sandbox-status').textContent, /turned off/);
  ui.window.close();
  ui = await fixture(() => response({enabled: true, allowed: false, on_this_computer: true, limits: LIMITS, sessions: []}));
  t.after(() => ui.window.close());
  assert.match(ui.document.getElementById('code-sandbox-status').textContent, /only installation administrators/);
  assert.equal(ui.document.getElementById('code-sandbox-body').textContent, '');
});
