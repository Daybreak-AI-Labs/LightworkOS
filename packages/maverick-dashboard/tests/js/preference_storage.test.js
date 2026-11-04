'use strict';
// A browser that refuses to keep a session reference must still be able to save preferences.
const test = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path');
const {JSDOM} = require('jsdom');
const assets = path.join(__dirname, '../../maverick_dashboard/static');
const wait = async () => { for (let i = 0; i < 10; i++) await new Promise(resolve => setImmediate(resolve)); };

function load(storage) {
  const initial = {values: {interface_language: 'en', output_style: 'concise', favorites: [], today_cards: []}, sources: {interface_language: 'personal', output_style: 'personal', custom_style: 'personal'}, locked: [], context: 'scope', revision: 'r1', destinations: {}, effective_by_scope: {}};
  const dom = new JSDOM('<form id="preference-form"><select id="preference-scope"><option value="personal">Personal</option></select>' +
    '<select data-pref="interface_language"><option value="en">English</option></select>' +
    '<select data-pref="output_style"><option value="concise">Concise</option><option value="detailed">Detailed</option></select>' +
    '<textarea data-pref="custom_style"></textarea><p id="preference-preview" lang="und" data-user-content></p><p id="preference-status"></p>' +
    '<button type="button" id="preference-compare">Compare</button><button type="submit">Save</button></form><section id="preference-original" hidden>' +
    '<button type="button" id="preference-original-read">Check original save</button><button type="button" id="preference-original-new" hidden>Start a fresh review</button>' +
    '<p id="preference-original-status" role="status"></p></section>', {url: 'https://lightwork.invalid/preferences', runScripts: 'outside-only'});
  const w = dom.window, doc = w.document;
  for (const [id, value] of Object.entries({'preference-data': initial, 'preference-thread': null, 'preference-styles': {}, 'lightwork-i18n-data': {language: 'en', locale: 'en'}})) {
    const script = doc.createElement('script'); script.id = id; script.type = 'application/json'; script.textContent = JSON.stringify(value); doc.head.append(script);
  }
  Object.defineProperty(w, 'sessionStorage', {value: storage, configurable: true});
  const requests = [];
  w.mvConfirm = async () => true;
  w.fetch = async (url, options = {}) => {
    requests.push({url, method: options.method || 'GET'});
    return {ok: true, status: 200, json: async () => ({...initial, revision: 'r2', values: {...initial.values, output_style: 'detailed'}})};
  };
  w.eval(fs.readFileSync(path.join(assets, 'lightwork-i18n.js'), 'utf8'));
  w.eval(fs.readFileSync(path.join(assets, 'lightwork-preferences.js'), 'utf8'));
  return {dom, doc, requests};
}

const refusing = {getItem() { return null; }, setItem() { throw new DOMException('Access is denied for this document.', 'SecurityError'); }, removeItem() { throw new DOMException('denied', 'SecurityError'); }};

test('a browser that refuses session storage still saves, and does not call a request never sent unconfirmed', async () => {
  const {dom, doc, requests} = load(refusing);
  const style = doc.querySelector('[data-pref="output_style"]');
  style.value = 'detailed'; style.dispatchEvent(new dom.window.Event('change', {bubbles: true}));
  doc.getElementById('preference-form').dispatchEvent(new dom.window.Event('submit', {bubbles: true, cancelable: true}));
  await wait();
  assert.ok(requests.some(request => request.method === 'POST'), 'the save is sent');
  assert.doesNotMatch(doc.getElementById('preference-status').textContent, /Could not confirm/);
  assert.match(doc.getElementById('preference-status').textContent, /Preferences saved/);
  dom.window.close();
});
