'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');
const {shell: loadShell} = require("./_shell");

const folder = path.resolve(__dirname, '../../maverick_dashboard');
const html = fs.readFileSync(path.join(folder, 'templates/task_file_recovery.html'), 'utf8')
  .replace(/\{\{ goal\.id \}\}/g, '12').replace(/\{%[^%]*%\}/g, '').replace(/\{\{[^}]*\}\}/g, '')
  .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '');
const script = fs.readFileSync(path.join(folder, 'static/lightwork-task-changes.js'), 'utf8');
const listing = {
  context: 'a'.repeat(64), available: true, left_out: 2, more: 0, incomplete: false,
  files: [
    { name: 'notes.txt', change: 'edited', shortened: false, lines: [
      { kind: 'gap', text: '' }, { kind: 'same', text: 'first' }, { kind: 'remove', text: 'old line' }, { kind: 'add', text: '<b>new line</b>' }] },
    { name: 'logo.png', change: 'binary', shortened: false, lines: [] }
  ]
};

async function fixture(reply) {
  const dom = new JSDOM(html, { url: 'https://app.example/chat/goal/12/files', runScripts: 'outside-only' });
  const w = dom.window, calls = [];
  w.mvErrorText = (failure, action) => 'Could not ' + action + '. Plain message.';
  w.fetch = async (url, options) => { calls.push({ url, options }); const out = await reply(url, options); return out instanceof Response ? out : new Response(JSON.stringify(out)); };
  loadShell(w);
  w.eval(script);
  const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(r => setImmediate(r)); };
  return { w, calls, settle, el: id => w.document.getElementById('tc-' + id) };
}

test('nothing is requested until the person asks; changes render as text with plain labels', async t => {
  const ui = await fixture(() => listing);
  t.after(() => ui.w.close());
  assert.equal(ui.calls.length, 0);
  ui.el('show').click();
  await ui.settle();
  assert.equal(ui.calls.length, 1);
  assert.equal(ui.calls[0].url, '/api/v1/task-files/12/changes');
  assert.equal(ui.calls[0].options.method, undefined);
  const files = ui.el('files');
  assert.equal(files.querySelectorAll('article').length, 2);
  assert.match(files.textContent, /Removed: .*old line/);
  assert.match(files.textContent, /Added: .*<b>new line<\/b>/);
  assert.equal(files.querySelector('b'), null, 'file text is never parsed as markup');
  assert.match(files.textContent, /isn’t text/);
  assert.match(ui.el('status').textContent, /2 files changed\. 2 recorded changes point outside/);
  assert.equal(ui.el('show').disabled, false);
});

test('an unavailable view shows the server sentence; an empty history says what to do', async t => {
  const refused = await fixture(() => ({ available: false, message: 'This task works in a folder on another computer, so its changes can’t be shown here.', files: [] }));
  t.after(() => refused.w.close());
  refused.el('show').click();
  await refused.settle();
  assert.match(refused.el('status').textContent, /another computer/);
  assert.equal(refused.el('files').children.length, 0);
  const empty = await fixture(() => ({ available: true, files: [], left_out: 0, more: 0, incomplete: false }));
  t.after(() => empty.w.close());
  empty.el('show').click();
  await empty.settle();
  assert.match(empty.el('status').textContent, /No file changes were recorded/);
  assert.match(empty.el('status').textContent, /Review changes to restore/);
});

test('errors and unexpected shapes never show raw server text', async t => {
  const denied = await fixture(() => new Response(JSON.stringify({ detail: 'insufficient role for this action' }), { status: 403 }));
  t.after(() => denied.w.close());
  denied.el('show').click();
  await denied.settle();
  assert.equal(denied.el('status').textContent, 'Could not show what changed. Plain message.');
  const odd = await fixture(() => ({ available: true, files: [{ name: 'x', change: 'exploded', lines: [] }] }));
  t.after(() => odd.w.close());
  odd.el('show').click();
  await odd.settle();
  assert.match(odd.el('status').textContent, /couldn’t be checked/);
  assert.equal(odd.el('files').children.length, 0);
});
