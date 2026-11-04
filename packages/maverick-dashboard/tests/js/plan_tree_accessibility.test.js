'use strict';

const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const template = fs.readFileSync(path.join(__dirname, '../../maverick_dashboard/templates/plan_tree.html'), 'utf8').replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
const controller = template.match(/<script>([\s\S]*?)<\/script>/)[1].replace('{{ goal.id }}', '7');
const snapshot = '<ul><li><a href="/chat/goal/7">Root task - active $1.25</a><ul><li><a href="/chat/goal/8">Child task - pending $0.50</a></li></ul></li></ul>';
const tree = {id: 7, title: 'Root task', status: 'active', dollars: 1.25,
  children: [{id: 8, title: 'Child task', status: 'pending', dollars: 0.5, children: []}]};
const response = value => ({ok: true, status: 200, json: async () => value});
const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(resolve => setImmediate(resolve)); };

function fixture(t, {fetch = async () => response(tree), cytoscape, scripts = true} = {}) {
  const html = template.replace(/<script\b[^>]*>[\s\S]*?<\/script>/g, '')
    .replace(/\{%[\s\S]*?%\}|\{#[\s\S]*?#\}/g, '')
    .replace(/\{\{ goal.title \}\}/g, 'Root task').replace('{{ tree_html | safe }}', snapshot);
  const dom = new JSDOM(html, {url: 'https://dashboard.test/goals/7/plan', runScripts: 'outside-only', pretendToBeVisual: true});
  t.after(() => dom.window.close());
  const {window} = dom, timers = new Map(), calls = [];
  let timerId = 0;
  window.setTimeout = (callback, delay) => { const id = ++timerId; timers.set(id, {callback, delay}); return id; };
  window.clearTimeout = id => timers.delete(id);
  window.fetch = (url, options) => { calls.push({url, options}); return fetch(url, options); };
  if (cytoscape) window.cytoscape = cytoscape;
  if (scripts) window.eval(controller);
  return {window, timers, calls, list: window.document.getElementById('plan-tree-list'),
    status: window.document.getElementById('plan-tree-status'),
    refresh: () => window.document.querySelector('#plan-tree-status + button').click()};
}

test('without scripts the server snapshot remains linked and accurately labelled', t => {
  const ui = fixture(t, {scripts: false});
  assert.equal(ui.list.querySelectorAll('a').length, 2);
  assert.match(ui.list.textContent, /\$1\.25(?!\d)/);
  assert.equal(ui.status.textContent, 'Plan captured when this page loaded.');
  assert.doesNotMatch(ui.window.document.body.textContent, /This map updates live|Loading/);
});

for (const graph of ['CDN unavailable', 'initialization failure', 'layout failure', 'working graph']) {
  test(`live text preserves costs, relationships and task links with ${graph}`, async t => {
    let graphElements;
    const cytoscape = graph === 'CDN unavailable' ? undefined : () => {
      if (graph === 'initialization failure') throw Error('No graph context');
      return {on() {}, elements: () => ({remove() {}}), add(elements) { graphElements = elements; },
        layout: () => ({run() { if (graph === 'layout failure') throw Error('Layout failed'); }}), destroy() {}};
    };
    const ui = fixture(t, {cytoscape});
    await settle();
    assert.equal(ui.list.querySelector('ul > li > ul > li > a').getAttribute('href'), '/chat/goal/8');
    assert.equal(ui.list.querySelector('a').textContent, 'Root task \u2014 active  $1.25');
    assert.equal(ui.list.querySelectorAll('a')[1].textContent, 'Child task \u2014 pending  $0.50');
    if (graph === 'working graph') assert.equal(graphElements[0].data.label, 'Root task  $1.25');
    else assert.equal(ui.window.document.getElementById('plan-tree').hidden, true);
    assert.match(ui.status.textContent, /^Live \u2014 active\. Refreshed /);
  });
}

test('first refresh failure labels the retained page snapshot as stale and retry recovers', async t => {
  let failing = true;
  const ui = fixture(t, {fetch: async () => { if (failing) throw Error('Offline'); return response(tree); }});
  await settle();
  assert.equal(ui.list.querySelectorAll('a').length, 2);
  assert.match(ui.status.textContent, /Showing the plan captured when this page loaded; it may be out of date/);
  assert.doesNotMatch(ui.status.textContent, /No current plan was loaded/);
  failing = false; ui.refresh(); await settle();
  assert.match(ui.status.textContent, /^Live \u2014 active\. Refreshed /);
});

test('refreshed text keeps the focused step and reports stale data after a later failure', async t => {
  let current = tree;
  const ui = fixture(t, {fetch: async () => { if (!current) throw Error('Offline'); return response(current); }});
  await settle();
  ui.list.querySelectorAll('a')[1].focus();
  current = {...tree, children: [{...tree.children[0], status: 'done', dollars: 0.75}]};
  ui.refresh(); await settle();
  assert.equal(ui.window.document.activeElement.getAttribute('href'), '/chat/goal/8');
  assert.match(ui.window.document.activeElement.textContent, /done  \$0\.75(?!\d)/);
  current = null; ui.refresh(); await settle();
  assert.match(ui.status.textContent, /Showing older data from /);
  assert.match(ui.list.textContent, /\$0\.75(?!\d)/);
});

for (const status of [401, 403]) {
  test(`${status} clears private plan state and stops polling until explicit retry`, async t => {
    const ui = fixture(t, {fetch: async () => ({ok: false, status})});
    await settle();
    assert.equal(ui.list.children.length, 0);
    assert.equal(ui.timers.size, 0);
    assert.match(ui.status.textContent, status === 401 ? /Sign in again/ : /no longer available/);
    ui.window.dispatchEvent(new ui.window.Event('online')); await settle();
    assert.equal(ui.calls.length, 1);
    ui.refresh(); await settle();
    assert.equal(ui.calls.length, 2);
  });
}

test('a stalled native-style fetch reaches the deadline with retained snapshot and explicit retry', async t => {
  const ui = fixture(t, {fetch: (_url, {signal}) => new Promise((_resolve, reject) => {
    signal.addEventListener('abort', () => reject(Object.assign(new Error('Aborted'), {name: 'AbortError'})));
  })});
  const deadline = [...ui.timers.values()].find(timer => timer.delay === 12000);
  assert.ok(deadline);
  deadline.callback(); await settle();
  assert.equal(ui.calls[0].options.signal.aborted, true);
  assert.match(ui.status.textContent, /Plan refresh timed out/);
  assert.match(ui.status.textContent, /may be out of date.*Refresh plan/);
  assert.equal(ui.list.querySelectorAll('a').length, 2);
});

test('hidden views pause polls and reconnect cannot overlap an active request', async t => {
  let resolveFetch;
  const ui = fixture(t, {fetch: () => new Promise(resolve => { resolveFetch = resolve; })});
  ui.window.dispatchEvent(new ui.window.Event('online')); ui.refresh();
  assert.equal(ui.calls.length, 1);
  resolveFetch(response(tree)); await settle();
  Object.defineProperty(ui.window.document, 'visibilityState', {value: 'hidden', configurable: true});
  ui.window.document.dispatchEvent(new ui.window.Event('visibilitychange'));
  assert.equal(ui.timers.size, 0);
  ui.window.dispatchEvent(new ui.window.Event('online')); assert.equal(ui.calls.length, 1);
  Object.defineProperty(ui.window.document, 'visibilityState', {value: 'visible', configurable: true});
  ui.window.document.dispatchEvent(new ui.window.Event('visibilitychange'));
  ui.window.dispatchEvent(new ui.window.Event('online'));
  assert.equal(ui.calls.length, 2);
  resolveFetch(response(tree)); await settle();
});
