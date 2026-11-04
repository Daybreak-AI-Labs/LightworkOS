'use strict';
// English pages load no translation catalog (it is identity for English and
// cost 36 KB compressed of render-blocking script on every page). Messages the
// preferences page writes itself must still reach the reader without one.
const test = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path');
const {JSDOM} = require('jsdom');
const assets = path.join(__dirname, '../../maverick_dashboard/static');
const wait = async () => { for (let i = 0; i < 8; i++) await new Promise(resolve => setImmediate(resolve)); };

function load(serverReply) {
  const initial = {values: {interface_language: 'en', favorites: [], today_cards: []}, sources: {}, locked: [], context: 'scope', revision: 'r1', destinations: {}, effective_by_scope: {}};
  const dom = new JSDOM('<form id="preference-form"><select id="preference-scope"><option value="personal">Personal</option></select>' +
    '<select data-pref="interface_language"><option value="en">English</option></select><select data-pref="output_style"><option value="concise">Concise</option></select>' +
    '<textarea data-pref="custom_style"></textarea><p id="preference-preview" lang="und" data-user-content></p><p id="preference-status"></p>' +
    '<button type="button" id="preference-compare">Compare</button><button type="submit">Save</button></form><section id="preference-original" hidden><button type="button" id="preference-original-read">Check original save</button><button type="button" id="preference-original-new" hidden>Start a fresh review</button><p id="preference-original-status" role="status"></p></section>', {url: 'https://lightwork.invalid/preferences', runScripts: 'outside-only'});
  const w = dom.window, doc = w.document;
  for (const [id, value] of Object.entries({'preference-data': initial, 'preference-thread': null, 'preference-styles': {}, 'lightwork-i18n-data': {language: 'en', locale: 'en'}})) {
    const script = doc.createElement('script'); script.id = id; script.type = 'application/json'; script.textContent = JSON.stringify(value); doc.head.append(script);
  }
  w.mvConfirm = async () => true;
  w.fetch = async () => serverReply;
  w.eval(fs.readFileSync(path.join(assets, 'lightwork-i18n.js'), 'utf8'));
  w.eval(fs.readFileSync(path.join(assets, 'lightwork-preferences.js'), 'utf8'));
  return dom;
}

test('without a catalog, a changed account still says so in plain English', async () => {
  const dom = load({ok: true, json: async () => ({context: 'other', locked: []})});
  dom.window.document.getElementById('preference-compare').click(); await wait();
  assert.equal(dom.window.document.getElementById('preference-status').textContent,
    'Your account or workspace changed. Save this draft separately before reloading.');
  dom.window.close();
});

test('without a catalog, an unknown server message still gives the safe fallback', async () => {
  const dom = load({ok: false, json: async () => ({})});
  dom.window.document.getElementById('preference-compare').click(); await wait();
  assert.equal(dom.window.document.getElementById('preference-status').textContent,
    'Current preferences could not be read. Your draft remains available. Refresh the page and try again.');
  dom.window.close();
});
