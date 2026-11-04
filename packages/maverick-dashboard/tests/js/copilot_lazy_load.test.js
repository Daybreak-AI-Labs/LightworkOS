// Run with: node --test packages/maverick-dashboard/tests/js/copilot_lazy_load.test.js
'use strict';
// The Copilot's two scripts (about 27 KB compressed) no longer download with
// the page: on a slow phone link they shared the bandwidth the stylesheet and
// the page's first paint needed. lightwork-ui.js loads them when the page is
// idle, or at once when someone opens the Copilot first; that open waits for
// them and then happens, so no click or key press is lost.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const ui = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-ui.js'), 'utf8');

function load() {
  const dom = new JSDOM(`<!doctype html><html><head></head><body><main id="content">
    <button type="button" data-copilot-toggle id="page-trigger">Ask Copilot</button></main>
    <button id="mv-copilot-fab" type="button" aria-expanded="false"
      data-operations-src="/static/lightwork-product-operations.js?v=1" data-copilot-src="/static/lightwork-copilot.js?v=2">Copilot</button>
    <section id="mv-copilot" hidden></section></body></html>`, {url: 'https://lightwork.test/goals', runScripts: 'outside-only'});
  const w = dom.window;
  w.matchMedia = () => ({matches: false, addEventListener() {}, removeEventListener() {}});
  w.eval(ui);
  const scripts = () => [...w.document.querySelectorAll('script[src]')];
  // Stand in for the real files: the Copilot binds its own click handler.
  const finish = () => {
    for (const script of scripts()) {
      if (script.src.includes('lightwork-copilot.js')) {
        w.document.getElementById('mv-copilot-fab').addEventListener('click', () => { w.opened = (w.opened || 0) + 1; });
      }
      script.dispatchEvent(new w.Event('load'));
    }
  };
  return {dom, w, scripts, finish};
}

test('nothing of the Copilot downloads with the page', () => {
  const page = load();
  assert.deepEqual(page.scripts(), []);
  page.dom.window.close();
});

test('opening the Copilot first loads both scripts in order, then opens it once', () => {
  const page = load();
  const fab = page.w.document.getElementById('mv-copilot-fab');
  fab.click();
  assert.deepEqual(page.scripts().map(s => new URL(s.src).pathname), ['/static/lightwork-product-operations.js', '/static/lightwork-copilot.js']);
  assert.ok(page.scripts().every(s => s.async === false), 'they run in order');
  assert.equal(fab.getAttribute('aria-busy'), 'true');
  fab.click();   // a second press while loading neither loads twice nor opens twice
  assert.equal(page.scripts().length, 2);
  page.finish();
  assert.equal(page.w.opened, 1);
  assert.equal(fab.hasAttribute('aria-busy'), false);
  fab.click();
  assert.equal(page.w.opened, 2, 'once loaded, clicks reach the Copilot directly');
  page.dom.window.close();
});

test('a page button that opens the Copilot is kept too, and a selection made meanwhile is handed over', () => {
  const page = load();
  const selection = {selection: {kind: 'approval', id: 7}};
  page.w.document.dispatchEvent(new page.w.CustomEvent('lightwork:copilot-selection', {detail: selection}));
  page.w.document.getElementById('page-trigger').click();
  assert.equal(page.scripts().length, 2);
  assert.deepEqual(page.w.LightworkCopilotEarlySelection, selection);
  page.dom.window.close();
});

test('an idle page loads the Copilot after it has loaded', async () => {
  const page = load();
  page.w.requestIdleCallback = callback => setTimeout(callback, 0);
  page.w.dispatchEvent(new page.w.Event('load'));
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(page.scripts().length, 2);
  page.dom.window.close();
});

test('both Copilot scripts start from a selection made before they loaded', () => {
  for (const name of ['lightwork-copilot.js', 'lightwork-product-operations.js']) {
    const source = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/' + name), 'utf8');
    assert.match(source, /LightworkCopilotEarlySelection/, name);
  }
});

test('a Copilot already on the page is left alone: its clicks are not held', () => {
  const page = load();
  const fab = page.w.document.getElementById('mv-copilot-fab');
  fab.addEventListener('click', () => { page.w.opened = (page.w.opened || 0) + 1; });
  fab.dataset.copilotReady = 'true';
  fab.click();
  assert.equal(page.w.opened, 1);
  assert.equal(page.scripts().length, 0);
  page.dom.window.close();
});

test('the Copilot marks itself ready once it handles its own button', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-copilot.js'), 'utf8');
  assert.match(source, /fab\.dataset\.copilotReady = "true"/);
});
