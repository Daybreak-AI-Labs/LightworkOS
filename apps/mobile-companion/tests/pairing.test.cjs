const {test} = require('node:test');
const assert = require('node:assert/strict');
const {React, act, create, source, deferred, button, text, native} = require('./helpers.cjs');

test('pairing sends expiring proof in headers and never in a navigation URL', async () => {
  const calls = [];
  const api = source('src/api.ts', {fetch: async (url, options) => {calls.push([url, options]); return new Response('{}');}});
  await api.beginPairing('https://dashboard.example.test', 'My phone');
  await api.pollPairing('https://dashboard.example.test', 'synthetic-pairing-proof');
  assert.equal(calls[0][1].headers.Authorization, undefined);
  assert.equal(calls[0][1].method, 'POST');
  assert.equal(calls[1][1].headers.Authorization, 'Bearer synthetic-pairing-proof');
  assert.equal(calls[1][0], 'https://dashboard.example.test/api/v1/devices/pairing/poll');
});

test('changing address cancels pending pairing and rejects delayed credentials', async () => {
  const pending = deferred(); let signal; const saves = [];
  const {PairingPanel} = source('src/components/PairingPanel.tsx', {'../api': {
    beginPairing: async () => ({pairing_token: 'synthetic', code: 'ABCDEFGHIJKL', expires_at: Date.now() / 1000 + 100}),
    pollPairing: (address, proof, active) => {signal = active; return pending.promise;},
  }});
  const props = {address: 'https://one.example.test', label: 'Phone', disabled: false, onPaired: async (...args) => saves.push(args)};
  let app;
  await act(async () => {app = create(React.createElement(PairingPanel, props));});
  await act(async () => {button(app, 'Start device pairing').props.onPress();});
  await act(async () => {button(app, 'Check pairing approval').props.onPress();});
  await act(async () => {app.update(React.createElement(PairingPanel, {...props, address: 'https://two.example.test'}));});
  assert.equal(signal.aborted, true);
  await act(async () => {pending.resolve({status: 'approved', token: 'old-token', device: {id: 'old-device'}});});
  assert.equal(saves.length, 0);
  assert.doesNotMatch(text(app), /ABCDEFGHIJKL/);
  app.unmount();
});

test('backgrounding cancels a check without saving a late result', async () => {
  const pending = deferred(); let signal, saves = 0;
  const {PairingPanel} = source('src/components/PairingPanel.tsx', {'../api': {
    beginPairing: async () => ({pairing_token: 'synthetic', code: 'ABCDEFGHIJKL', expires_at: Date.now() / 1000 + 100}),
    pollPairing: (address, proof, active) => {signal = active; return pending.promise;},
  }});
  let app;
  await act(async () => {app = create(React.createElement(PairingPanel, {address: 'https://one.example.test', label: 'Phone', disabled: false, onPaired: async () => {saves++;}}));});
  await act(async () => {button(app, 'Start device pairing').props.onPress();});
  await act(async () => {button(app, 'Check pairing approval').props.onPress();});
  await act(async () => {native.AppState.emit('background');});
  assert.equal(signal.aborted, true);
  await act(async () => {pending.resolve({status: 'approved', token: 'old-token', device: {id: 'old-device'}}); native.AppState.emit('active');});
  assert.equal(saves, 0);
  app.unmount();
});

test('pairing does not report saved until secure storage callback resolves', async () => {
  const saving = deferred();
  const {PairingPanel} = source('src/components/PairingPanel.tsx', {'../api': {
    beginPairing: async () => ({pairing_token: 'synthetic', code: 'ABCDEFGHIJKL', expires_at: Date.now() / 1000 + 100}),
    pollPairing: async () => ({status: 'approved', token: 'new-token', device: {id: 'new-device'}}),
  }});
  let app;
  await act(async () => {app = create(React.createElement(PairingPanel, {address: 'https://one.example.test', label: 'Phone', disabled: false, onPaired: () => saving.promise}));});
  await act(async () => {button(app, 'Start device pairing').props.onPress();});
  await act(async () => {button(app, 'Check pairing approval').props.onPress();});
  assert.doesNotMatch(text(app), /connection saved securely/);
  await act(async () => {saving.reject(new Error('Secure storage locked.'));});
  assert.match(text(app), /Secure storage locked/);
  assert.match(text(app), /Check pairing approval/);
  app.unmount();
});
