const {test} = require('node:test');
const assert = require('node:assert/strict');
const {React, act, create, source, deferred, connection, newer, text, button, native} = require('./helpers.cjs');

test('edited connection cannot inherit a delayed successful test', async () => {
  const pending = deferred();
  const {SettingsScreen} = source('src/screens/SettingsScreen.tsx', {
    '../settings': {loadSettings: async () => connection, saveSettings: async () => {}},
    '../api': {getActive: () => pending.promise},
  });
  let app;
  await act(async () => { app = create(React.createElement(SettingsScreen, {onSaved() {}})); });
  await act(async () => { button(app, 'Test connection').props.onPress(); });
  await act(async () => { app.root.findAllByType('TextInput').find(input => input.props.accessibilityLabel === 'Dashboard address').props.onChangeText(newer.baseUrl); });
  await act(async () => { pending.resolve({goals: []}); });
  assert.doesNotMatch(text(app), /Connected\. Save/);
  app.unmount();
});

test('explicit reset clears only application keys and refuses a locked store', async () => {
  const values = new Map([['maverick.connection.v1', '{'], ['unrelated-secret', 'preserve']]);
  let locked = false, purges = 0;
  const settings = source('src/settings.ts', {
    'expo-secure-store': {
      getItemAsync: async key => { if (locked) throw Error('locked'); return values.get(key) ?? null; },
      deleteItemAsync: async key => { values.delete(key); },
    },
    './offlineCache': {purgeBundle: async () => {}, purgeAppBundles: async () => { purges++; }},
  });
  await assert.rejects(settings.loadSettings(), settings.InvalidSavedConnection);
  locked = true;
  await assert.rejects(settings.resetSettings());
  assert.equal(values.get('maverick.connection.v1'), '{');
  locked = false;
  await settings.resetSettings();
  assert.equal(values.has('maverick.connection.v1'), false);
  assert.equal(values.get('unrelated-secret'), 'preserve');
  assert.equal(purges, 1);
});

test('retired cache cannot be recreated by an old in-flight write', async () => {
  const values = new Map(), write = deferred();
  const storage = {
    getItem: async key => values.get(key) ?? null,
    setItem: async (key, value) => { await write.promise; values.set(key, value); },
    removeItem: async key => { values.delete(key); },
  };
  const cache = source('src/offlineCache.ts', {'@react-native-async-storage/async-storage': storage});
  const scope = '10000000-0000-4000-8000-000000000001';
  const saving = cache.saveBundle({schema: 'maverick-offline/1', as_of:Date.now()/1000, goals: [], cache_policy:{allowed:true,max_age_seconds:86400,max_bytes:2097152,revision:'a'.repeat(64)}}, connection.baseUrl, scope);
  await Promise.resolve();
  const purging = cache.purgeBundle(scope);
  write.resolve(); await Promise.all([saving,purging]);
  assert.equal(values.size, 0);
});

test('background transition aborts current request and resume cannot publish its old response', async () => {
  const pending = deferred(); let snapshot, signal, calls = 0;
  const {usePolling} = source('src/poll.ts');
  function Probe() {
    const fetcher = React.useCallback(active => { signal = active; return ++calls === 1 ? pending.promise : Promise.resolve('fresh'); }, []);
    snapshot = usePolling(fetcher, 5000);
    return null;
  }
  let app;
  await act(async () => { app = create(React.createElement(Probe)); });
  await act(async () => { native.AppState.emit('background'); });
  assert.equal(signal.aborted, true);
  await act(async () => { native.AppState.emit('active'); pending.resolve('stale'); });
  assert.equal(snapshot.data, 'fresh');
  assert.equal(calls, 2);
  app.unmount();
});


test('named profiles retain separate credentials and remove only the chosen profile', async () => {
  const values = new Map();
  const settings = source('src/settings.ts', {
    'expo-secure-store': {
      getItemAsync: async key => values.get(key) ?? null,
      setItemAsync: async (key, value) => { values.set(key, value); },
      deleteItemAsync: async key => { values.delete(key); },
    },
    './offlineCache': {purgeBundle: async () => {}, purgeAppBundles: async () => {}},
  });
  await settings.saveProfile('First workspace', connection);
  await settings.saveProfile('Second workspace', newer);
  const profiles = await settings.listProfiles();
  assert.equal(profiles.profiles.length, 2);
  const first = profiles.profiles.find(profile => profile.name === 'First workspace');
  await settings.activateProfile(first.id);
  assert.equal((await settings.loadSettings()).token, connection.token);
  await settings.removeProfile(first.id);
  assert.equal((await settings.loadSettings()).needsSetup, true);
  const remaining = await settings.listProfiles();
  assert.equal(remaining.profiles.length, 1);
  await settings.activateProfile(remaining.profiles[0].id);
  assert.equal((await settings.loadSettings()).token, newer.token);
});

function profileStore(initial = {}) {
  const values = new Map(Object.entries(initial));
  const settings = source('src/settings.ts', {
    'expo-secure-store': {
      getItemAsync: async key => values.get(key) ?? null,
      setItemAsync: async (key, value) => { values.set(key, value); },
      deleteItemAsync: async key => { values.delete(key); },
    },
    './offlineCache': {purgeBundle: async () => {}, purgeAppBundles: async () => {}},
  });
  return {values, settings};
}
const third = {baseUrl: 'https://third.example.test', token: 'synthetic-third-token'};
const LEGACY = 'maverick.connection.v1';

test('removing every saved connection does not bring an older single connection back', async () => {
  const {values, settings} = profileStore({[LEGACY]: JSON.stringify(connection)});
  await settings.saveProfile('New workspace', newer);
  assert.deepEqual(Array.from((await settings.listProfiles()).profiles, profile => profile.name).sort(), ['New workspace', 'Previous connection']);
  for (const profile of (await settings.listProfiles()).profiles) await settings.removeProfile(profile.id);
  await settings.saveProfile('Third workspace', third);
  assert.deepEqual(Array.from((await settings.listProfiles()).profiles, profile => profile.name), ['Third workspace']);
  assert.equal(JSON.stringify([...values.values()]).includes(connection.token), false);
});

test('removing the imported older connection removes its token from the device, and only then', async () => {
  const {values, settings} = profileStore({[LEGACY]: JSON.stringify(connection)});
  await settings.saveProfile('New workspace', newer);
  const profiles = (await settings.listProfiles()).profiles;
  await settings.removeProfile(profiles.find(profile => profile.name === 'New workspace').id);
  assert.equal(values.has(LEGACY), true);
  await settings.removeProfile(profiles.find(profile => profile.name === 'Previous connection').id);
  assert.equal(values.has(LEGACY), false);
});

test('the first profile of an older install still imports the older connection once', async () => {
  const {settings} = profileStore({[LEGACY]: JSON.stringify(connection)});
  await settings.saveProfile('New workspace', newer);
  await settings.saveProfile('Third workspace', third);
  const names = Array.from((await settings.listProfiles()).profiles, profile => profile.name);
  assert.deepEqual(names.sort(), ['New workspace', 'Previous connection', 'Third workspace']);
});

