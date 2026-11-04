'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const script = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-copilot.js'), 'utf8');
const settle = async () => { for (let i = 0; i < 12; i++) await new Promise(resolve => setImmediate(resolve)); };

function page() {
  const dom = new JSDOM('<button id="mv-copilot-fab"></button><section id="mv-copilot" hidden><button id="mv-copilot-close"></button><ul id="mv-copilot-tips"></ul><div id="mv-copilot-prompts"></div><div id="mv-copilot-log"></div><button id="mv-copilot-clear"></button><form id="mv-copilot-form"><textarea id="mv-copilot-input"></textarea><button id="mv-copilot-send"></button></form><p id="mv-copilot-note"></p><a id="mv-copilot-provider-setup"></a><div id="mv-copilot-action"></div></section>', {url: 'https://lightwork.invalid/chat', runScripts: 'outside-only'});
  let scope = 'a'.repeat(64), calls = 0, answer = async () => ({ok: false, status: 503, json: async () => ({})});
  dom.window.fetch = async url => {
    if (String(url).includes('/copilot/context')) return {ok: true, status: 200, json: async () => ({client_context: scope})};
    calls++; return answer();
  };
  dom.window.eval(script);
  const doc = dom.window.document;
  doc.getElementById('mv-copilot-fab').click();
  return {dom, doc, setScope(value) {scope = value;}, setAnswer(value) {answer = value;}, calls: () => calls,
    send(value) {doc.getElementById('mv-copilot-input').value = value; doc.getElementById('mv-copilot-form').dispatchEvent(new dom.window.Event('submit', {cancelable: true}));}};
}

test('a failed Copilot question remains editable and explicit retry keeps one visible user turn', async () => {
  const p = page(); await settle(); p.send('Keep this private question'); await settle();
  assert.equal(p.doc.getElementById('mv-copilot-input').value, 'Keep this private question');
  assert.equal(p.doc.getElementById('mv-copilot-input').readOnly, false);
  p.send('Keep this private question'); await settle();
  assert.equal(p.calls(), 2);
  assert.equal(p.doc.querySelectorAll('.mv-copilot__msg--user').length, 1);
  p.dom.window.close();
});

test('changing the authenticated workspace clears the private failed draft before another model call', async () => {
  const p = page(); await settle(); p.send('Old workspace question'); await settle();
  p.setScope('b'.repeat(64)); p.send('Old workspace question'); await settle();
  assert.equal(p.calls(), 1);
  assert.equal(p.doc.getElementById('mv-copilot-input').value, '');
  assert.equal(p.doc.getElementById('mv-copilot-log').textContent, '');
  p.dom.window.close();
});

test('closing the panel prevents a late response from clearing a newer draft', async () => {
  const p = page(); await settle(); let release;
  p.setAnswer(() => new Promise(resolve => {release = resolve;}));
  p.send('Earlier question'); await settle();
  p.doc.getElementById('mv-copilot-close').click();
  p.doc.getElementById('mv-copilot-fab').click();
  p.doc.getElementById('mv-copilot-input').value = 'New draft';
  release({ok: true, status: 200, json: async () => ({reply: 'Late response'})}); await settle();
  assert.equal(p.doc.getElementById('mv-copilot-input').value, 'New draft');
  assert.doesNotMatch(p.doc.getElementById('mv-copilot-log').textContent, /Late response/);
  p.dom.window.close();
});

test('Copilot shows a local page link for refused actions and rejects external destinations', async () => {
  const p = page(); await settle();
  p.setAnswer(async () => ({ok: true, status: 200, json: async () => ({
    mode: 'built_in', reply: 'No action was taken.',
    warning: 'No action was taken. Use the page controls if available.',
    action_link: {href: '/goals', label: 'Open Goals'}
  })}));
  p.send('Cancel my task'); await settle();
  assert.match(p.doc.getElementById('mv-copilot-note').textContent, /No action was taken/);
  const link = p.doc.querySelector('.mv-copilot__msg--bot a');
  assert.equal(link?.getAttribute('href'), '/goals');
  assert.equal(link?.textContent, 'Open Goals');

  p.setAnswer(async () => ({ok: true, status: 200, json: async () => ({
    mode: 'built_in', reply: 'No action was taken.',
    action_link: {href: '//external.invalid/goals', label: 'Open Goals'}
  })}));
  p.send('Cancel another task'); await settle();
  assert.equal(p.doc.querySelectorAll('.mv-copilot__msg--bot a').length, 1);
  p.dom.window.close();
});

test('Copilot shows the truthful fallback notice when a model claims an action was done', async () => {
  const p = page(); await settle();
  p.setAnswer(async () => ({ok: true, status: 200, json: async () => ({
    mode: 'built_in_fallback', reply: 'No action was taken by this guide.',
    warning: 'Copilot could not verify that claim, so it showed the page guide instead. No action was taken.'
  })}));
  p.send('What happened with my theme?'); await settle();
  assert.match(p.doc.getElementById('mv-copilot-note').textContent, /No action was taken/);
  assert.doesNotMatch(p.doc.getElementById('mv-copilot-note').textContent, /provider is not available/);
  p.dom.window.close();
});
