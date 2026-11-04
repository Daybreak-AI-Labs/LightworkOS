'use strict';
// "Get help from a person" carries the page, its task or run and the last
// error reference; nothing else (lightwork-help-menu.js).
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

function load(stored) {
  const store = new Map(stored ? [['lw-last-failure-reference', stored]] : []);
  global.sessionStorage = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, v) };
  global.document = { querySelector: () => null, querySelectorAll: () => [], getElementById: () => null,
    addEventListener() {} };
  global.location = { pathname: '/goals', hash: '' };
  global.window = { fetch: undefined, addEventListener() {} };
  const file = path.join(__dirname, '../../maverick_dashboard/static/lightwork-help-menu.js');
  delete require.cache[require.resolve(file)];
  return require(file);
}

test('a task page carries its task number and the last error reference', () => {
  const menu = load('lw-failure-' + 'ab'.repeat(16));
  assert.deepEqual(menu.context('/chat/goal/42'), { from: '/chat/goal/42', task: '42', failure: 'lw-failure-' + 'ab'.repeat(16) });
  assert.equal(menu.requestHref('/chat/goal/42'),
    '/help?from=%2Fchat%2Fgoal%2F42&task=42&failure=lw-failure-' + 'ab'.repeat(16) + '#get-help');
});

test('a run page carries its run reference; other pages only their address', () => {
  const menu = load('');
  assert.deepEqual(menu.context('/flows/runs/run_7-b'), { from: '/flows/runs/run_7-b', run: 'run_7-b' });
  assert.deepEqual(menu.context('/approvals'), { from: '/approvals' });
});

test('a stored value that is not an error reference is ignored', () => {
  const menu = load('<script>');
  assert.deepEqual(menu.context('/goals'), { from: '/goals' });
});
