const { test } = require('node:test');
const assert = require('node:assert/strict');
const { React, act, create, source, deferred, connection, newer, text, tab, button } = require('./helpers.cjs');
const address = app => app.root.findAllByType('TextInput').find(input => input.props.accessibilityLabel === 'Dashboard address');
const mocks = settings => ({ './src/settings': settings, '../settings': settings });

test('connection problems read plainly and offer Try again and Check settings', async () => {
  const { ConnectionNotice } = source('src/components/ConnectionNotice.tsx');
  const api = source('src/api.ts');
  let retries = 0, opened = 0, app;
  await act(async () => { app = create(React.createElement(ConnectionNotice, {
    message: api.statusMessage(403), accessDenied: true,
    onRetry() { retries++; }, onOpenSettings() { opened++; },
  })); });
  assert.match(text(app), /Access problem/);
  assert.match(text(app), /Ask your administrator/);
  assert.doesNotMatch(text(app), /HTTP|403|\/api\//);
  await act(async () => { button(app, 'Try again').props.onPress(); });
  await act(async () => { button(app, 'Check settings').props.onPress(); });
  assert.deepEqual([retries, opened], [1, 1]);
  app.unmount();
});

test('an out-of-date app build is told to update and offered no retry loop', async () => {
  const { ConnectionNotice } = source('src/components/ConnectionNotice.tsx');
  const api = source('src/api.ts');
  let app;
  await act(async () => { app = create(React.createElement(ConnectionNotice, {
    message: api.UNSUPPORTED_BUILD, unsupported: true, onRetry() {},
  })); });
  assert.match(text(app), /Update needed/);
  assert.equal(button(app, 'Try again'), undefined);
  app.unmount();
});

test('every dashboard status becomes a plain sentence without codes', () => {
  const api = source('src/api.ts');
  for (const status of [400, 401, 403, 404, 429, 500, 503]) {
    const message = api.statusMessage(status);
    assert.doesNotMatch(message, /\d{3}|HTTP|GET|\/api/);
    assert.match(message, /\.$/);
  }
});

test('fresh installs open the connection setup without tabs until saved', async () => {
  let current = { baseUrl: 'http://127.0.0.1:8765', token: '', needsSetup: true }, saved = null, app;
  const App = source('App.tsx', mocks({
    loadSettings: async () => current,
    saveSettings: async value => { saved = value; current = { ...value }; },
  })).default;
  await act(async () => { app = create(React.createElement(App)); });
  assert.match(text(app), /Connect to Lightwork/);
  assert.equal(tab(app, 'Tasks'), undefined);
  assert.equal(address(app).props.value, '');
  await act(async () => { address(app).props.onChangeText('lightwork.example.test'); });
  await act(async () => { await button(app, 'Save and connect').props.onPress(); });
  assert.equal(saved.baseUrl, 'https://lightwork.example.test');
  assert.ok(tab(app, 'Tasks'));
  assert.equal(app.root.findByType('RunsListScreen').props.settings.baseUrl, 'https://lightwork.example.test');
  app.unmount();
});

test('tabs use plain names', async () => {
  let app;
  const App = source('App.tsx', mocks({ loadSettings: async () => connection })).default;
  await act(async () => { app = create(React.createElement(App)); });
  for (const name of ['Tasks', 'Overview', 'Settings']) assert.ok(tab(app, name), name);
  app.unmount();
});

test('startup keychain errors remain visible and retryable', async () => {
  let calls = 0;
  const App = source('App.tsx', mocks({ loadSettings: async () => {
    if (++calls === 1) throw new Error('synthetic locked store');
    return connection;
  } })).default;
  let app;
  await act(async () => { app = create(React.createElement(App)); });
  assert.match(text(app), /Could not open your connection settings/);
  await act(async () => { button(app, 'Retry loading settings').props.onPress(); });
  assert.equal(app.root.findByType('RunsListScreen').props.settings, connection);
  app.unmount();
});

test('settings load failure prevents overwriting unread values and permits retry', async () => {
  let calls = 0;
  const { SettingsScreen } = source('src/screens/SettingsScreen.tsx', mocks({
    loadSettings: async () => { if (++calls === 1) throw new Error('synthetic locked store'); return connection; },
    saveSettings: async () => assert.fail('must not overwrite unread settings'),
  }));
  let app;
  await act(async () => { app = create(React.createElement(SettingsScreen, { onSaved() {} })); });
  assert.match(text(app), /Could not open your saved settings/);
  assert.equal(address(app).props.editable, false);
  assert.equal(button(app, 'Save').props.disabled, true);
  await act(async () => { button(app, 'Retry loading settings').props.onPress(); });
  assert.equal(address(app).props.value, connection.baseUrl);
  assert.equal(address(app).props.editable, true);
  app.unmount();
});

test('save failure retains entered values and retry success confirms the save', async () => {
  let saves = 0, callbacks = 0;
  const { SettingsScreen } = source('src/screens/SettingsScreen.tsx', mocks({
    loadSettings: async () => connection,
    saveSettings: async () => { if (++saves === 1) throw new Error('synthetic write failure'); },
  }));
  let app;
  await act(async () => { app = create(React.createElement(SettingsScreen, { onSaved() { callbacks++; } })); });
  await act(async () => { address(app).props.onChangeText(newer.baseUrl); });
  await act(async () => { await button(app, 'Save').props.onPress(); });
  assert.match(text(app), /Could not save your settings/);
  assert.equal(address(app).props.value, newer.baseUrl);
  assert.equal(callbacks, 0);
  await act(async () => { await button(app, 'Save').props.onPress(); });
  assert.match(text(app), /Saved\./);
  assert.equal(callbacks, 1);
  app.unmount();
});

test('repeated save presses remain single-flight until persistence settles', async () => {
  const pending = deferred();
  let saves = 0, app;
  const { SettingsScreen } = source('src/screens/SettingsScreen.tsx', mocks({
    loadSettings: async () => connection, saveSettings: () => { saves++; return pending.promise; },
  }));
  await act(async () => { app = create(React.createElement(SettingsScreen, { onSaved() {} })); });
  const save = button(app, 'Save').props.onPress;
  let first;
  await act(async () => { first = save(); save(); });
  assert.equal(saves, 1);
  assert.equal(button(app, 'Saving…').props.disabled, true);
  await act(async () => { pending.resolve(); await first; });
  assert.equal(button(app, 'Save').props.disabled, false);
  app.unmount();
});

test('invalid address stays editable with actionable guidance and no false save', async () => {
  let saves = 0, callbacks = 0, app;
  const { SettingsScreen } = source('src/screens/SettingsScreen.tsx', mocks({
    loadSettings: async () => connection, saveSettings: async () => { saves++; },
  }));
  await act(async () => { app = create(React.createElement(SettingsScreen, { onSaved() { callbacks++; } })); });
  await act(async () => { address(app).props.onChangeText('http://remote.example.test'); });
  await act(async () => { await button(app, 'Save').props.onPress(); });
  assert.equal(saves, 0);
  assert.equal(callbacks, 0);
  assert.match(text(app), /starts with https:\/\//);
  assert.doesNotMatch(text(app), /Saved\./);
  assert.equal(address(app).props.value, 'http://remote.example.test');
  await act(async () => { address(app).props.onChangeText(newer.baseUrl); });
  await act(async () => { await button(app, 'Save').props.onPress(); });
  assert.equal(saves, 1);
  assert.equal(callbacks, 1);
  assert.match(text(app), /Saved\./);
  app.unmount();
});

test('confirmation stays mounted during the post-save connection refresh', async () => {
  const refresh = deferred();
  let calls = 0, app;
  const App = source('App.tsx', mocks({
    loadSettings: async () => ++calls === 3 ? refresh.promise : connection,
    saveSettings: async () => {},
  })).default;
  await act(async () => { app = create(React.createElement(App)); });
  await act(async () => { tab(app, 'Settings').props.onPress(); });
  await act(async () => { await button(app, 'Save').props.onPress(); });
  assert.match(text(app), /Saved\./);
  assert.ok(address(app));
  assert.ok(app.root.findAllByType('TextInput').find(input => input.props.accessibilityLabel === 'Access token'));
  await act(async () => { refresh.resolve(newer); });
  assert.match(text(app), /Saved\./);
  app.unmount();
});

for (const failure of [false, true]) {
  test(`older post-save reload ${failure ? 'failure' : 'success'} cannot replace the newest connection`, async () => {
    const stale = deferred();
    let calls = 0, app;
    const App = source('App.tsx', mocks({
      loadSettings: async () => ++calls === 3 ? stale.promise : calls === 4 ? newer : connection,
      saveSettings: async () => {},
    })).default;
    await act(async () => { app = create(React.createElement(App)); });
    await act(async () => { tab(app, 'Settings').props.onPress(); });
    await act(async () => { await button(app, 'Save').props.onPress(); });
    await act(async () => { address(app).props.onChangeText(newer.baseUrl); });
    await act(async () => { await button(app, 'Save').props.onPress(); });
    await act(async () => { tab(app, 'Tasks').props.onPress(); });
    assert.equal(app.root.findByType('RunsListScreen').props.settings, newer);
    await act(async () => { failure ? stale.reject(new Error('obsolete read failure')) : stale.resolve(connection); });
    assert.doesNotMatch(text(app), /Could not open your connection settings/);
    assert.equal(app.root.findByType('RunsListScreen').props.settings, newer);
    app.unmount();
  });
}

test('callbacks retained after App unmount cannot start another settings read', async () => {
  let calls = 0, app;
  const App = source('App.tsx', mocks({ loadSettings: async () => { calls++; return connection; } })).default;
  await act(async () => { app = create(React.createElement(App)); });
  await act(async () => { tab(app, 'Settings').props.onPress(); });
  const onSaved = app.root.find(node => node.type.name === 'SettingsScreen').props.onSaved;
  await act(async () => { app.unmount(); });
  const before = calls;
  await act(async () => { onSaved(); });
  assert.equal(calls, before);
});

test('a save finishing after leaving Settings updates the still-mounted App', async () => {
  const saved = deferred();
  let current = connection, app, operation;
  const App = source('App.tsx', mocks({
    loadSettings: async () => current,
    saveSettings: async () => { await saved.promise; current = newer; },
  })).default;
  await act(async () => { app = create(React.createElement(App)); });
  await act(async () => { tab(app, 'Settings').props.onPress(); });
  await act(async () => { operation = button(app, 'Save').props.onPress(); });
  await act(async () => { tab(app, 'Tasks').props.onPress(); });
  await act(async () => { saved.resolve(); await operation; });
  assert.equal(app.root.findByType('RunsListScreen').props.settings, newer);
  app.unmount();
});
