const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const script = fs.readFileSync(path.join(__dirname, '../../maverick_dashboard/static/lightwork-i18n.js'), 'utf8');

function load(catalog) {
  const dom = new JSDOM('<!doctype html><script id="lightwork-i18n-data" type="application/json">{"language":"fr","locale":"fr-CA"}</script><p data-i18n="Save"></p>', {runScripts:'outside-only'});
  if (catalog) dom.window.LightworkJourneyCatalog = catalog;
  dom.window.eval(script);
  dom.window.LightworkI18n.translate();
  return dom;
}

test('synchronously loaded matching catalog retains copy, membership and fallback language', () => {
  const dom = load({language:'fr',catalog:{Save:{text:'Enregistrer',lang:'fr'}}});
  const api = dom.window.LightworkI18n, node = dom.window.document.querySelector('p');
  assert.equal(node.textContent, 'Enregistrer');
  assert.equal(node.lang, 'fr');
  assert.equal(api.has('Save'), true);
  api.set(node, 'Unknown copy');
  assert.equal(node.textContent, 'Unknown copy');
  assert.equal(node.lang, 'en');
  dom.window.close();
});

for (const catalog of [null, {language:'de',catalog:{Save:{text:'Speichern',lang:'de'}}}]) {
  test('missing or mismatched catalog degrades to truthful English without blocking controls', () => {
    const dom = load(catalog), node = dom.window.document.querySelector('p');
    assert.equal(node.textContent, 'Save');
    assert.equal(node.lang, 'en');
    assert.equal(dom.window.LightworkI18n.has('Save'), false);
    assert.equal(dom.window.LightworkI18n.locale, 'fr-CA');
    dom.window.close();
  });
}
