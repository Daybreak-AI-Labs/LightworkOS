const {test} = require('node:test');
const assert = require('node:assert/strict');
const {React, act, create, source, native, connection, text} = require('./helpers.cjs');

test('device language persists only after a successful write and failed save keeps previous choice', async () => {
  let stored = 'en', reject = false, observed;
  const language = source('src/language.ts', {'@react-native-async-storage/async-storage': {
    getItem: async () => stored, setItem: async (_key, value) => {if (reject) throw Error('storage unavailable'); stored = value;},
  }});
  function Probe() {observed = language.useLanguage(); return null;}
  let tree;
  await act(async () => {tree = create(React.createElement(Probe));});
  await act(async () => {await language.saveLanguage('fr');});
  assert.equal(observed.value, 'fr'); assert.equal(language.msg('Tasks'), 'Tâches');
  assert.equal(language.messageLanguage('Tasks'), 'fr');
  assert.equal(language.messageLanguage('Full English consequence'), 'en');
  assert.equal(language.formattedNumber(1234.5), new Intl.NumberFormat('fr').format(1234.5));
  reject = true;
  await assert.rejects(language.saveLanguage('de'));
  assert.equal(language.currentLanguage(), 'fr'); assert.equal(stored, 'fr');
  await act(async () => tree.unmount());
});

test('Arabic stays an explicit English product fallback and never machine-completes the community seed', async () => {
  const language = source('src/language.ts', {'@react-native-async-storage/async-storage': {
    getItem: async () => 'en', setItem: async () => {},
  }});
  await language.saveLanguage('ar');
  assert.equal(language.msg('Confirm Stop request'), 'Confirm Stop request');
  assert.equal(language.messageLanguage('Confirm Stop request'), 'en');
  assert.equal(language.formattedNumber(1234), new Intl.NumberFormat('ar').format(1234));
});

test('known control names used as task titles remain verbatim under another UI language', async () => {
  const language = source('src/language.ts', {'@react-native-async-storage/async-storage': {
    getItem: async () => 'fr', setItem: async () => {},
  }});
  await language.saveLanguage('fr');
  const {RunsListScreen} = source('src/screens/RunsListScreen.tsx', {
    '../language': language, './language': language,
    '../poll': {usePolling: () => ({data: [{id: 1, title: 'Tasks', status: 'running', result: 'Settings'}], refresh() {}})},
  });
  let tree;
  await act(async () => {tree = create(React.createElement(RunsListScreen, {settings: connection, onOpenRun() {}}));});
  const words = tree.root.findAllByType('Text').map(row => row.props.children);
  assert.ok(words.includes('Tâches')); assert.ok(words.includes('Tasks')); assert.ok(words.includes('Settings'));
  assert.match(text(tree), /fr/);
  await act(async () => tree.unmount());
});

test('invalid saved language is visible and remains recoverable without changing connection data', async () => {
  let observed, key;
  const language = source('src/language.ts', {'@react-native-async-storage/async-storage': {
    getItem: async () => 'not-a-language', setItem: async (saved) => {key = saved;},
  }});
  function Probe() {observed = language.useLanguage(); return null;}
  let tree;
  await act(async () => {tree = create(React.createElement(Probe));});
  assert.match(observed.error, /could not be read/);
  await act(async () => {await language.saveLanguage('en');});
  assert.equal(observed.error, ''); assert.equal(key, 'lightwork.display.language.v1');
  await act(async () => {native.AppState.emit('active'); tree.unmount();});
});
