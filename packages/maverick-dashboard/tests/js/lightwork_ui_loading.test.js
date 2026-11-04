// Run with: node --test packages/maverick-dashboard/tests/js/lightwork_ui_loading.test.js
'use strict';
// mvLoading: the one loading state. A quick answer never flashes a loader,
// a shown loader stays long enough to be read, the region is marked busy, and
// a wait that never ends turns into an error with Try again.
const {test, mock} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const source = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-ui.js'), 'utf8');

function load() {
  const dom = new JSDOM('<!doctype html><html><head></head><body><main id="content"><section id="list"><p>Old rows</p></section></main></body></html>',
    {url: 'https://lightwork.test/goals', runScripts: 'outside-only'});
  const w = dom.window;
  w.matchMedia = () => ({matches: false, addEventListener() {}, removeEventListener() {}});
  // The page's timers run on node's mocked clock.
  w.setTimeout = (fn, ms) => setTimeout(fn, ms);
  w.Date = Date;
  w.clearTimeout = id => clearTimeout(id);
  w.eval(source);
  return w;
}
const shown = w => w.document.querySelector('#list [data-mv-loading]');
const flush = async () => { for (let i = 0; i < 5; i++) await Promise.resolve(); };

test('a quick answer shows no loader at all, only a busy region', async () => {
  mock.timers.enable({apis: ['setTimeout', 'Date']});
  try {
    const w = load(), list = w.document.getElementById('list');
    const wait = w.mvLoading(list, {text: 'Loading tasks…'});
    assert.equal(list.getAttribute('aria-busy'), 'true');
    mock.timers.tick(250);
    assert.equal(shown(w), null, 'nothing visible under the delay');
    const finished = wait.done(); await flush();
    mock.timers.tick(1000); await finished;
    assert.equal(shown(w), null);
    assert.equal(list.hasAttribute('aria-busy'), false);
    assert.equal(list.textContent, 'Old rows', 'the page content is left alone');
    w.close();
  } finally { mock.timers.reset(); }
});

test('a shown loader stays long enough to read, then goes', async () => {
  mock.timers.enable({apis: ['setTimeout', 'Date']});
  try {
    const w = load(), list = w.document.getElementById('list');
    const wait = w.mvLoading(list, {text: 'Loading tasks…'});
    mock.timers.tick(300);
    assert.equal(shown(w).textContent, 'Loading tasks…');
    let gone = false; const finished = wait.done().then(() => { gone = true; });
    mock.timers.tick(100); await flush();
    assert.equal(gone, false, 'not removed 100 ms after it appeared');
    assert.ok(shown(w));
    mock.timers.tick(400); await finished;
    assert.equal(gone, true);
    assert.equal(shown(w), null);
    assert.equal(list.hasAttribute('aria-busy'), false);
    w.close();
  } finally { mock.timers.reset(); }
});

test('a wait that never ends becomes an error with Try again', async () => {
  mock.timers.enable({apis: ['setTimeout', 'Date']});
  try {
    const w = load(), list = w.document.getElementById('list');
    let retried = 0;
    w.mvLoading(list, {text: 'Loading tasks…', action: 'load the tasks', timeout: 20000, retry: () => { retried += 1; }});
    mock.timers.tick(300); mock.timers.tick(19700); await flush();
    const error = list.querySelector('[data-mv-loading-error]');
    assert.ok(error, 'an error replaces the loader');
    assert.equal(shown(w), null);
    assert.equal(error.getAttribute('role'), 'alert');
    assert.match(error.textContent, /^Could not load the tasks\. It took too long\. Try again\./);
    assert.equal(list.hasAttribute('aria-busy'), false);
    const again = error.querySelector('button');
    assert.equal(again.textContent, 'Try again');
    again.click();
    assert.equal(retried, 1);
    assert.equal(list.querySelector('[data-mv-loading-error]'), null, 'Try again clears the error');
    w.close();
  } finally { mock.timers.reset(); }
});

test('a failed request shows the plain error, and an answer after the timeout is ignored', async () => {
  mock.timers.enable({apis: ['setTimeout', 'Date']});
  try {
    const w = load(), list = w.document.getElementById('list');
    const wait = w.mvLoading(list, {action: 'load the tasks'});
    mock.timers.tick(10); await wait.fail({status: 503});
    const error = list.querySelector('[data-mv-loading-error]');
    assert.equal(error.firstChild.textContent, 'Could not load the tasks. This is temporarily unavailable. Try again in a few minutes.');
    assert.equal(error.querySelector('button'), null, 'no Try again without a retry');
    assert.equal(wait.active(), false);
    await wait.done();
    assert.ok(list.querySelector('[data-mv-loading-error]'), 'a later done() does not hide the error');
    w.close();
  } finally { mock.timers.reset(); }
});

test('the default text is Loading…, and a second loader on the same region replaces the first', async () => {
  mock.timers.enable({apis: ['setTimeout', 'Date']});
  try {
    const w = load(), list = w.document.getElementById('list');
    w.mvLoading(list); const second = w.mvLoading(list);
    mock.timers.tick(300);
    assert.equal(list.querySelectorAll('[data-mv-loading]').length, 1);
    assert.equal(shown(w).textContent, 'Loading…');
    const finished = second.done(); mock.timers.tick(500); await finished;
    assert.equal(list.querySelectorAll('[data-mv-loading]').length, 0);
    assert.equal(list.hasAttribute('aria-busy'), false);
    w.close();
  } finally { mock.timers.reset(); }
});
