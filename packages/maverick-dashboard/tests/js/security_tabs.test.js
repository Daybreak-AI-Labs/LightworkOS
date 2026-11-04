// Run with: node --test packages/maverick-dashboard/tests/js/security_tabs.test.js
'use strict';
// Security records use the shared panel tab bar (_tabs.html panel_tabs with
// hash='sec-', lightwork-tabs.js); the page script no longer has its own.
const test = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path');
const {JSDOM} = require('jsdom');
const {panelTabs, tabPanel, press} = require('./_tab_markup');

const root = path.resolve(__dirname, '../../maverick_dashboard');
const template = fs.readFileSync(path.join(root, 'templates/security.html'), 'utf8').replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
const tabsScript = fs.readFileSync(path.join(root, 'static/lightwork-tabs.js'), 'utf8');
const start = template.indexOf('<script>\n(function () {');
// The page script, without its server-only hunter block (rendered for admins).
const script = template.slice(start + 8, template.indexOf('</script>', start))
  .replace(/\{% if security_can_manage_hunters %\}[\s\S]*?\{% endif %\}/, '');
const KEYS = ['controls', 'evidence', 'risks', 'poams', 'vendors', 'policies', 'incidents', 'audits'];

function page(url) {
  const tabs = panelTabs('Security record types', KEYS.map((key) => [key, key]), 'controls', {id: 'sec', hash: 'sec-'});
  const panels = KEYS.map((key) => `<section ${tabPanel(key, 'controls', {id: 'sec'})}></section>`).join('');
  const dom = new JSDOM(`<main>${tabs}${panels}</main>`, {url, runScripts: 'outside-only', pretendToBeVisual: true});
  dom.window.eval(script);
  dom.window.eval(tabsScript);
  dom.window.mvTabs.init();  // deferred in the page; jsdom may still report loading
  return dom;
}
const open = (dom) => [...dom.window.document.querySelectorAll('[role="tabpanel"]')].filter((panel) => !panel.hidden).map((panel) => panel.id.replace('sec-panel-', ''));

test('the page script leaves the record tabs to the shared bar', () => {
  assert.doesNotMatch(script, /data-sec-tab|activateTab|ArrowRight/);
  assert.match(template, /panel_tabs\('Security record types'[\s\S]*?id='sec', hash='sec-'\)/);
});

test('a security tab opens from its address and choosing a tab updates the address', () => {
  const dom = page('https://local.test/security#sec-incidents');
  const w = dom.window, d = w.document, before = w.history.length;
  assert.deepEqual(open(dom), ['incidents']);
  assert.equal(d.getElementById('sec-tab-incidents').getAttribute('aria-selected'), 'true');
  d.getElementById('sec-tab-risks').click();
  assert.equal(w.location.hash, '#sec-risks');
  assert.deepEqual(open(dom), ['risks']);
  press(w, d.getElementById('sec-tab-risks'), 'End');
  assert.equal(w.location.hash, '#sec-audits');
  assert.equal(d.activeElement, d.getElementById('sec-tab-audits'));
  press(w, d.getElementById('sec-tab-audits'), 'ArrowRight');
  assert.deepEqual(open(dom), ['controls'], 'Right on the last tab wraps to the first');
  press(w, d.getElementById('sec-tab-controls'), 'ArrowLeft');
  assert.deepEqual(open(dom), ['audits']);
  press(w, d.getElementById('sec-tab-audits'), 'Home');
  assert.deepEqual(open(dom), ['controls']);
  assert.equal(w.history.length, before);
  w.location.hash = '#sec-vendors';
  w.dispatchEvent(new w.HashChangeEvent('hashchange'));
  assert.deepEqual(open(dom), ['vendors']);
  assert.deepEqual([...d.querySelectorAll('[role="tab"]')].filter((t) => t.tabIndex === 0).map((t) => t.id), ['sec-tab-vendors']);
  dom.window.close();
});

test('an unknown tab address leaves the first tab open', () => {
  const dom = page('https://local.test/security#sec-nothing');
  assert.deepEqual(open(dom), ['controls']);
  dom.window.close();
});
