'use strict';
// Settings paints one group from the first frame. The server names it on the
// sections element; a group named in the address (/settings#settings-access)
// is applied by a small script before the sections are parsed, and the page
// script then takes over the tabs without a visible change.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const {panelTabs, press} = require('./_tab_markup');
const tabsScript = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-tabs.js'), 'utf8');

const template = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/templates/settings.html'), 'utf8').replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
const earlyScript = (() => {
  const sections = template.indexOf('<div id="settings-sections"');
  assert.ok(sections > 0, 'sections element found');
  const start = template.indexOf('<script>', sections) + '<script>'.length;
  assert.ok(start < template.indexOf('data-settings-group=', sections), 'the script comes before the first section');
  return template.slice(start, template.indexOf('</script>', start));
})();
const pageScript = (() => {
  const marker = "var forms = Array.prototype.slice.call(document.querySelectorAll('form[action^=\"/settings\"]'));";
  const at = template.indexOf(marker);
  const start = template.lastIndexOf('<script>', at) + '<script>'.length;
  return template.slice(start, template.indexOf('</script>', at));
})();

const GROUPS = ['general', 'models', 'integrations', 'controls', 'access', 'maintenance'];
// The settings tab bar as _tabs.html panel_tabs renders it.
function tabs(selected) {
  return panelTabs('Settings sections', GROUPS.map(group => [group, group]), selected,
    {id: 'settings', data: 'settings-tab', controls: 'settings-sections'});
}
function sections(active) {
  return `<div id="settings-sections" data-settings-active="${active}" role="tabpanel" aria-labelledby="settings-tab-${active}">` + GROUPS.map(group =>
    `<div class="section-head" data-settings-group="${group}"><h2>${group}</h2></div><div class="panel" data-settings-group="${group}"><p data-settings-search-item>${group} setting</p></div>`).join('') + '</div>';
}
function load(hash, serverGroup = 'general') {
  const html = `<main><section class="settings-index" data-initial-group="${serverGroup}"><input id="settings-search">${tabs(serverGroup)}` +
    `<p id="settings-filter-status" role="status"></p></section>${sections(serverGroup)}</main>`;
  const dom = new JSDOM(html, {url: 'https://lightwork.example/settings' + hash, runScripts: 'outside-only'});
  dom.window.eval(earlyScript);
  return dom;
}
const selectedTabs = doc => Array.from(doc.querySelectorAll('[data-settings-tab][aria-selected="true"]'), tab => tab.dataset.settingsTab);

for (const [hash, group] of [['#settings-access', 'access'], ['#features', 'controls'], ['#settings-maintenance', 'maintenance'], ['#providers', 'integrations']]) {
  test(`${hash} paints the ${group} group and selects its tab before the sections are parsed`, () => {
    const dom = load(hash);
    const doc = dom.window.document;
    assert.equal(doc.getElementById('settings-sections').dataset.settingsActive, group);
    assert.deepEqual(selectedTabs(doc), [group]);
    assert.equal(doc.querySelector(`[data-settings-tab="${group}"]`).tabIndex, 0);
    dom.window.close();
  });
}

for (const hash of ['', '#api-keys', '#settings-', '#constructor', '#settings-model-prices']) {
  test(`"${hash}" keeps the group the server chose`, () => {
    const dom = load(hash, 'integrations');
    const doc = dom.window.document;
    assert.equal(doc.getElementById('settings-sections').dataset.settingsActive, 'integrations');
    assert.deepEqual(selectedTabs(doc), ['integrations']);
    dom.window.close();
  });
}

// Writing a fragment while the page loads made Chrome scroll to it when
// loading finished (scrollY 739) and start Tab there instead of the skip link.
test('loading Settings without a fragment writes none', () => {
  const dom = load('');
  const writes = [];
  const original = dom.window.history.replaceState.bind(dom.window.history);
  dom.window.history.replaceState = (state, title, url) => { writes.push(url); return original(state, title, url); };
  dom.window.eval(pageScript);
  dom.window.eval(tabsScript);
  dom.window.mvTabs.init();
  assert.deepEqual(writes, []);
  assert.equal(dom.window.location.hash, '');
  // Clearing a search returns to the group without writing one either.
  const search = dom.window.document.getElementById('settings-search');
  search.value = 'models'; search.dispatchEvent(new dom.window.Event('input'));
  search.value = ''; search.dispatchEvent(new dom.window.Event('input'));
  assert.deepEqual(writes, []);
  dom.window.close();
});

test('a deep link keeps its own address and still opens its group', () => {
  const dom = load('#features');
  dom.window.eval(pageScript);
  dom.window.eval(tabsScript);
  dom.window.mvTabs.init();
  assert.equal(dom.window.location.hash, '#features');
  assert.deepEqual(selectedTabs(dom.window.document), ['controls']);
  dom.window.close();
});

test('a person switching groups is remembered in the address', () => {
  const dom = load('');
  const doc = dom.window.document;
  dom.window.eval(pageScript);
  dom.window.eval(tabsScript);
  dom.window.mvTabs.init();
  doc.querySelector('[data-settings-tab="access"]').click();
  assert.equal(dom.window.location.hash, '#settings-access');
  press(dom.window, doc.querySelector('[data-settings-tab="access"]'), 'ArrowRight');
  assert.equal(dom.window.location.hash, '#settings-maintenance');
  assert.equal(doc.activeElement, doc.querySelector('[data-settings-tab="maintenance"]'));
  assert.deepEqual(selectedTabs(doc), ['maintenance']);
  assert.equal(doc.getElementById('settings-sections').getAttribute('aria-labelledby'), 'settings-tab-maintenance');
  press(dom.window, doc.querySelector('[data-settings-tab="maintenance"]'), 'Home');
  assert.equal(dom.window.location.hash, '#settings-general');
  press(dom.window, doc.querySelector('[data-settings-tab="general"]'), 'ArrowLeft');
  assert.equal(dom.window.location.hash, '#settings-maintenance', 'Left on the first tab wraps to the last');
  press(dom.window, doc.querySelector('[data-settings-tab="maintenance"]'), 'End');
  assert.deepEqual([...doc.querySelectorAll('[role="tab"]')].filter(tab => tab.tabIndex === 0).map(tab => tab.dataset.settingsTab), ['maintenance']);
  dom.window.close();
});

test('the page script takes over the painted group without switching it', () => {
  const dom = load('#settings-access');
  const doc = dom.window.document;
  dom.window.eval(pageScript);
  dom.window.eval(tabsScript);
  dom.window.mvTabs.init();
  const root = doc.getElementById('settings-sections');
  assert.equal(root.hasAttribute('data-settings-active'), false, 'the tabs now drive the hidden attributes');
  const shown = new Set(Array.from(doc.querySelectorAll('[data-settings-group]')).filter(node => !node.hidden).map(node => node.dataset.settingsGroup));
  assert.deepEqual([...shown], ['access']);
  assert.deepEqual(selectedTabs(doc), ['access']);
  // Clicking a tab still switches groups.
  doc.querySelector('[data-settings-tab="models"]').click();
  const now = new Set(Array.from(doc.querySelectorAll('[data-settings-group]')).filter(node => !node.hidden).map(node => node.dataset.settingsGroup));
  assert.deepEqual([...now], ['models']);
  assert.equal(dom.window.location.hash, '#settings-models');
  dom.window.close();
});

// The section index is styled by the shared stylesheet in the head. Its rules
// used to arrive in a style block at the end of the body, so the index grew
// from 157 to 249 px while the page parsed and pushed the sections down
// (layout shift 0.163 on Settings).
test('the settings index is styled before it is parsed', () => {
  const css = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork.css'), 'utf8');
  for (const rule of ['.settings-index {', '#settings-filter-status {', '.settings-all-link {']) {
    assert.ok(css.includes(rule), `${rule} is in lightwork.css`);
  }
  const after = template.slice(template.indexOf('<section class="settings-index"'));
  assert.doesNotMatch(after, /<style>[^<]*\.settings-index\s*[{,>]/, 'no settings-index rule arrives after the section');
  assert.doesNotMatch(after, /#settings-filter-status\s*\{|\.settings-all-link\s*\{/);
});
