const {test} = require('node:test');
const assert = require('node:assert/strict');
const {React, act, create, source, native} = require('./helpers.cjs');

test('explicit appearance ignores OS changes and a failed save retains the previous choice', async () => {
  let stored = 'dark', reject = false, observed;
  const original = native.useColorScheme;
  native.useColorScheme = () => 'light';
  const appearance = source('src/theme.ts', {'@react-native-async-storage/async-storage': {
    getItem: async () => stored,
    setItem: async (_key, value) => { if (reject) throw Error('storage unavailable'); stored = value; },
  }});
  function Probe() { observed = {choice: appearance.useAppearance().value, palette: appearance.useTheme()}; return null; }
  let tree;
  try {
    await act(async () => { tree = create(React.createElement(Probe)); });
    assert.equal(observed.choice, 'dark');
    assert.equal(observed.palette.background, '#111820');
    reject = true;
    await assert.rejects(appearance.saveAppearance('light'));
    assert.equal(observed.choice, 'dark');
    reject = false;
    await act(async () => { await appearance.saveAppearance('system'); });
    assert.equal(observed.palette.background, '#ffffff');
    native.useColorScheme = () => 'dark';
    await act(async () => { tree.update(React.createElement(Probe)); });
    assert.equal(observed.palette.background, '#111820');
  } finally {
    if (tree) tree.unmount();
    native.useColorScheme = original;
  }
});
