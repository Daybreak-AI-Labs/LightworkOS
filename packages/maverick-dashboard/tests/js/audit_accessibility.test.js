'use strict';
const {test} = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), {JSDOM} = require('jsdom');
const folder = path.resolve(__dirname, '../../maverick_dashboard');
const settle = async () => { for (let n = 0; n < 8; n++) await new Promise(done => setImmediate(done)); };

function readingFixture(text) {
  const dom = new JSDOM('<div id="result"></div><button id="read-aloud"></button>', {url: 'https://dashboard.test', runScripts: 'outside-only'});
  const window = dom.window;
  window.document.getElementById('result').textContent = text;
  const spoken = [], cancelled = [];
  window.SpeechSynthesisUtterance = function (value) { this.text = value; };
  window.speechSynthesis = {speak(value) { spoken.push(value); }, cancel() { cancelled.push(true); }, pause() {}, resume() {}};
  window.eval(fs.readFileSync(path.join(folder, 'static/lightwork-read-aloud.js'), 'utf8'));
  window.lwReadAloud(window.document.getElementById('read-aloud'));
  return {dom, window, spoken, cancelled, button: window.document.getElementById('read-aloud')};
}

test('stop cancels a pending voice fetch and ignores its late audio', async t => {
  const ui = readingFixture('An answer'); t.after(() => ui.dom.window.close());
  let release, signal;
  ui.window.fetch = (_url, options) => { signal = options.signal; return new Promise(resolve => { release = resolve; }); };
  ui.button.click(); ui.button.click();
  assert.equal(signal.aborted, true);
  release({ok: false}); await settle();
  assert.equal(ui.spoken.length, 0);
  assert.equal(ui.button.getAttribute('aria-pressed'), 'false');
});

test('browser fallback completes every long-text part and remains stoppable', async t => {
  const answer = 'a'.repeat(7100), ui = readingFixture(answer); t.after(() => ui.dom.window.close());
  ui.window.fetch = async () => { throw Error('unreachable'); };
  ui.button.click(); await settle();
  assert.equal(ui.spoken[0].text.length, 3000);
  ui.spoken[0].onend(); ui.spoken[1].onend(); ui.spoken[2].onend();
  assert.equal(ui.spoken.map(part => part.text).join(''), answer);
  assert.equal(ui.button.getAttribute('aria-pressed'), 'false');
  ui.button.click(); await settle(); ui.button.click();
  assert.ok(ui.cancelled.length > 0);
  assert.equal(ui.button.getAttribute('aria-label'), 'Read the result aloud');
});

test('white-on-white preview warns while preserving the editor palette', () => {
  const cells = ['bg', 'panel', 'text', 'accent'].map(key => `<td data-cell="${key}"><input data-cell-input value="#ffffff"></td>`).join('');
  const dom = new JSDOM(`<div data-setting-id="dashboard.themes"><table><tr data-grid-row>${cells}</tr></table></div>`, {runScripts: 'outside-only'});
  const {window} = dom;
  window.eval(fs.readFileSync(path.join(folder, 'static/lightwork-theme-preview.js'), 'utf8'));
  window.document.querySelector('input').dispatchEvent(new window.Event('input', {bubbles: true}));
  assert.match(window.document.querySelector('[role="status"]').textContent, /Improve contrast before saving/);
  assert.equal(window.document.body.style.background, '');
  dom.window.close();
});

test('answer replacement cancels pending audio and binds the new result once without autoplay', async t => {
  const ui = readingFixture('Previous answer'); t.after(() => ui.dom.window.close());
  let release, signal, requests = 0;
  ui.window.fetch = (_url, options) => {
    requests += 1; signal = options.signal;
    return new Promise(resolve => { release = resolve; });
  };
  ui.button.click();
  ui.window.document.dispatchEvent(new ui.window.Event('lightwork:answer-panel-before-update'));
  assert.equal(signal.aborted, true);
  ui.window.document.body.innerHTML = '<div id="result">Current answer</div><button id="read-aloud" data-voice-only="1"></button>';
  ui.window.document.dispatchEvent(new ui.window.Event('lightwork:answer-panel-updated'));
  ui.window.document.dispatchEvent(new ui.window.Event('lightwork:answer-panel-updated'));
  assert.equal(requests, 1);
  assert.equal(ui.window.document.querySelectorAll('[role="status"]').length, 1);
  release({ok: false}); await settle();
  assert.equal(ui.spoken.length, 0);
  ui.window.fetch = async () => { throw Error('unreachable'); };
  ui.window.document.getElementById('read-aloud').click(); await settle();
  assert.equal(ui.spoken[0].text, 'Current answer');
});
