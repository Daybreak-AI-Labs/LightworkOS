const { test } = require('node:test');
const assert = require('node:assert/strict');
const { source, deferred, connection, newer } = require('./helpers.cjs');

const RECORD = 'maverick.connection.v1';
function fixture(initial = {}) {
  const values = new Map(Object.entries(initial));
  const secure = {
    getItemAsync: async key => values.get(key) ?? null,
    deleteItemAsync: async key => { values.delete(key); },
    setItemAsync: async (key, value) => { values.set(key, value); },
  };
  return { values, secure, load: () => source('src/settings.ts', { 'expo-secure-store': secure }) };
}
const legacy = { 'maverick.baseUrl': connection.baseUrl, 'maverick.token': connection.token };
const plain = value => ({ baseUrl: value.baseUrl, token: value.token });

test('fresh installs retain empty-token defaults', async () => {
  const settings = fixture().load();
  const loaded = await settings.loadSettings();
  assert.deepEqual(plain(loaded), { baseUrl: settings.DEFAULT_BASE_URL, token: '' });
  assert.equal(loaded.needsSetup, true);
});

test('legacy connection remains readable without migration writes', async () => {
  const f = fixture(legacy);
  f.secure.setItemAsync = async () => assert.fail('reading legacy settings must not write');
  const loaded = await f.load().loadSettings();
  assert.deepEqual(plain(loaded), connection);
  assert.equal(loaded.needsSetup, undefined);
});

test('failed migration save preserves the complete previous connection', async () => {
  const f = fixture(legacy);
  const write = f.secure.setItemAsync;
  f.secure.setItemAsync = async (key, value) => {
    if (key !== 'maverick.baseUrl') throw new Error('synthetic keychain rejection');
    await write(key, value);
  };
  const settings = f.load();
  await assert.rejects(settings.saveSettings(newer));
  assert.deepEqual(plain(await settings.loadSettings()), connection);
});

test('successful migration stores one trimmed connection record and prefers it to legacy keys', async () => {
  const f = fixture(legacy);
  const writes = [];
  const write = f.secure.setItemAsync;
  f.secure.setItemAsync = async (key, value) => { writes.push(key); await write(key, value); };
  const settings = f.load();
  await settings.saveSettings({ baseUrl: ` ${newer.baseUrl} `, token: ` ${newer.token} ` });
  assert.deepEqual(writes, [RECORD]);
  assert.deepEqual(plain(JSON.parse(f.values.get(RECORD))), newer);
  assert.deepEqual(plain(await f.load().loadSettings()), newer);
});

test('failed update retains the complete committed connection', async () => {
  const f = fixture({ ...legacy, [RECORD]: JSON.stringify(newer) });
  f.secure.setItemAsync = async () => { throw new Error('synthetic rejection'); };
  const settings = f.load();
  await assert.rejects(settings.saveSettings(connection));
  assert.deepEqual(plain(await settings.loadSettings()), newer);
});

test('invalid connection changes never replace the saved address and token', async () => {
  const f = fixture({ [RECORD]: JSON.stringify(connection) });
  const settings = f.load();
  for (const baseUrl of ['', 'not an address', 'http://remote.example.test',
    'ftp://localhost',
    'https://user:password@example.test', // pragma: allowlist secret - synthetic invalid URL fixture
    'https://example.test?redirect=elsewhere', 'https://example.test#fragment']) {
    await assert.rejects(settings.saveSettings({ baseUrl, token: newer.token }));
    assert.deepEqual(plain(await settings.loadSettings()), connection);
  }
  await assert.rejects(settings.saveSettings({ ...newer, token: 'invalid\nheader' }));
  assert.deepEqual(plain(await settings.loadSettings()), connection);
});

test('valid HTTPS and loopback HTTP addresses can still be saved', async () => {
  const settings = fixture().load();
  for (const baseUrl of ['https://dashboard.example.test/team', 'http://localhost:8765',
    'http://127.0.0.1:8765', 'http://[::1]:8765']) {
    await settings.saveSettings({ baseUrl, token: newer.token });
    assert.equal((await settings.loadSettings()).baseUrl, baseUrl);
  }
});

test('malformed primary record fails closed instead of restoring stale legacy credentials', async () => {
  for (const raw of ['{', 'null', '[]', '{}', '{"baseUrl":"https://new.example.test","token":5}']) {
    await assert.rejects(fixture({ ...legacy, [RECORD]: raw }).load().loadSettings());
  }
});

test('keychain read errors are not treated as missing credentials', async () => {
  const f = fixture(legacy);
  f.secure.getItemAsync = async () => { throw new Error('synthetic locked store'); };
  await assert.rejects(f.load().loadSettings());
});

test('overlapping saves and reads complete in call order', async () => {
  const f = fixture(legacy);
  const firstWrite = deferred(), enteredWrite = deferred();
  const write = f.secure.setItemAsync;
  let calls = 0;
  f.secure.setItemAsync = async (key, value) => {
    if (++calls === 1) { enteredWrite.resolve(); await firstWrite.promise; }
    await write(key, value);
  };
  const settings = f.load();
  const first = settings.saveSettings(connection);
  const second = settings.saveSettings(newer);
  const after = settings.loadSettings();
  await enteredWrite.promise;
  assert.equal(calls, 1);
  firstWrite.resolve();
  await Promise.all([first, second]);
  assert.deepEqual(plain(await after), newer);
});

test('a rejected operation does not poison subsequent saves and reads', async () => {
  const f = fixture(legacy);
  const write = f.secure.setItemAsync;
  let calls = 0;
  f.secure.setItemAsync = async (key, value) => {
    if (++calls === 1) throw new Error('synthetic transient rejection');
    await write(key, value);
  };
  const settings = f.load();
  const failed = assert.rejects(settings.saveSettings(connection));
  const successful = settings.saveSettings(newer);
  await Promise.all([failed, successful]);
  assert.deepEqual(plain(await settings.loadSettings()), newer);
});

test('each saved credential pair gets a persisted opaque cache scope', async () => {
  const settings = fixture(legacy).load();
  await settings.saveSettings(connection);
  const first = await settings.loadSettings();
  await settings.saveSettings({ ...connection, token: newer.token });
  const second = await settings.loadSettings();
  assert.match(first.cacheScope, /^[0-9a-f-]{36}$/i);
  assert.match(second.cacheScope, /^[0-9a-f-]{36}$/i);
  assert.notEqual(first.cacheScope, second.cacheScope);
  assert.equal((await settings.loadSettings()).cacheScope, second.cacheScope);
});

test('missing UUID support leaves caching disabled while settings remain usable', async () => {
  const f = fixture();
  const settings = source('src/settings.ts', { 'expo-secure-store': f.secure, expo: null });
  await settings.saveSettings(newer);
  const loaded = await settings.loadSettings();
  assert.deepEqual(plain(loaded), newer);
  assert.equal(loaded.cacheScope, undefined);
});
