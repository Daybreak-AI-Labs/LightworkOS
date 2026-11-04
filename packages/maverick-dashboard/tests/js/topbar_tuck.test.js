// Run with: node --test packages/maverick-dashboard/tests/js/topbar_tuck.test.js
'use strict';
// On a phone the top bar is two rows (109 px) of controls that cannot share
// one 44 px row. It no longer covers that much of every screen while reading:
// scrolling down tucks it away, and scrolling up, focusing into it or opening
// the menu brings every control back. Wider screens keep it fixed in place.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const ui = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-ui.js'), 'utf8');
const css = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork.css'), 'utf8');

function page({phone = true} = {}) {
  const dom = new JSDOM(`<!doctype html><html><body>
    <header class="topbar"><button id="nav-toggle" class="topbar__menu" aria-expanded="false">Menu</button>
      <span class="topbar__controls"><a class="iconbtn" id="settings" href="/settings">Settings</a></span></header>
    <div class="nav-backdrop" id="nav-backdrop"></div><nav id="sidebar" class="sidebar"></nav>
    <main id="content"><a id="link" href="#x">Link</a></main></body></html>`,
  {url: 'https://lightwork.test/approvals', runScripts: 'outside-only', pretendToBeVisual: true});
  const w = dom.window;
  w.matchMedia = query => ({matches: phone && /max-width: (560|880)px/.test(query), media: query,
    addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {}});
  w.eval(ui);
  let y = 0;
  Object.defineProperty(w, 'scrollY', {get: () => y, configurable: true});
  const scrollTo = async to => { y = to; w.dispatchEvent(new w.Event('scroll')); await new Promise(r => setTimeout(r, 40)); };
  const tucked = () => w.document.body.classList.contains('topbar-tucked');
  return {dom, w, scrollTo, tucked};
}

test('scrolling down a phone page tucks the bar away; scrolling up brings it back', async () => {
  const p = page();
  await p.scrollTo(400);
  assert.equal(p.tucked(), true);
  await p.scrollTo(396);   // a few pixels of jitter change nothing
  assert.equal(p.tucked(), true);
  await p.scrollTo(300);
  assert.equal(p.tucked(), false);
  await p.scrollTo(600);
  assert.equal(p.tucked(), true);
  await p.scrollTo(0);
  assert.equal(p.tucked(), false, 'always shown at the top of the page');
  p.dom.window.close();
});

test('focusing a control in the bar, or an open menu, keeps it shown', async () => {
  const p = page();
  await p.scrollTo(400);
  p.w.document.getElementById('settings').focus();
  assert.equal(p.tucked(), false);
  p.w.document.getElementById('settings').blur();
  p.w.document.body.classList.add('nav-open');
  await p.scrollTo(800);
  assert.equal(p.tucked(), false);
  p.dom.window.close();
});

test('a wide screen never tucks the bar', async () => {
  const p = page({phone: false});
  await p.scrollTo(400);
  assert.equal(p.tucked(), false);
  p.dom.window.close();
});

test('Shift+Tab back towards the bar shows it before focus arrives, so the page does not jump', async () => {
  const p = page();
  await p.scrollTo(400);
  assert.equal(p.tucked(), true);
  p.w.document.dispatchEvent(new p.w.KeyboardEvent('keydown', {key: 'Tab', shiftKey: true, bubbles: true}));
  assert.equal(p.tucked(), false);
  p.dom.window.close();
});

test('the tucked bar moves out of view at once, on phones only', () => {
  assert.match(css, /body\.topbar-tucked \.topbar \{[^}]*transform: translateY\(-100%\)/);
  // No slide: a moving bar would put a control half in view as focus reaches it.
  assert.doesNotMatch(css, /\.topbar \{[^}]*transition: transform/);
});
