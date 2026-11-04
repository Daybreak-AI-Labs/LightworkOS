const {test} = require('node:test');
const assert = require('node:assert/strict');
const {source, native, deferred, connection} = require('./helpers.cjs');

test('packaged native requests use only the bounded bridge and preserve explicit auth/status', async () => {
  const before = native.Platform.OS; native.Platform.OS = 'ios';
  const calls = [];
  try {
    const api = source('src/api.ts', {'expo-modules-core': {requireOptionalNativeModule: () => ({
      request: async (...args) => {calls.push(args); return {status: 200, body: '[]'};}, cancel() {},
    })}, fetch: () => assert.fail('ambient Fetch cannot send the native credential')});
    assert.equal((await api.listGoals(connection)).goals.length, 0);
    assert.equal(calls[0][1], 'https://old.example.test/api/v1/goals?limit=50&offset=0&status=');
    assert.equal(calls[0][3].Authorization, 'Bearer synthetic-old-token');
  } finally {native.Platform.OS = before;}
});

test('native requests cancel the owned bridge operation and never publish a late reply', async () => {
  const before = native.Platform.OS; native.Platform.OS = 'android';
  const result = deferred(), cancelled = [];
  try {
    const api = source('src/api.ts', {'expo-modules-core': {requireOptionalNativeModule: () => ({
      request: () => result.promise, cancel: id => cancelled.push(id),
    })}});
    const controller = new AbortController();
    const pending = api.listGoals(connection, 50, controller.signal);
    controller.abort();
    await assert.rejects(pending, /cancelled/);
    assert.equal(cancelled.length, 1);
    result.resolve({status: 200, body: '[{"title":"late private data"}]'});
  } finally {native.Platform.OS = before;}
});

test('Expo Go without the native bridge fails before any network effect', async () => {
  const before = native.Platform.OS; native.Platform.OS = 'ios';
  try {
    const api = source('src/api.ts', {fetch: () => assert.fail('must not use unbounded native Fetch')});
    await assert.rejects(api.listGoals(connection), error => error.kind === 'unsupported');
  } finally {native.Platform.OS = before;}
});

test('native denial remains an access error and native failures cannot expose secrets', async () => {
  const before = native.Platform.OS; native.Platform.OS = 'android';
  try {
    const api = source('src/api.ts', {'expo-modules-core': {requireOptionalNativeModule: () => ({
      request: async () => ({status: 403, body: ''}), cancel() {},
    })}});
    await assert.rejects(api.listGoals(connection), error => api.isAccessDenied(error));
    const transport = source('src/nativeTransport.ts', {'expo-modules-core': {requireOptionalNativeModule: () => ({
      request: async () => {throw Object.assign(Error('synthetic-secret.example Bearer private'), {code: 'E_REDIRECT'});}, cancel() {},
    })}});
    await assert.rejects(transport.nativeRequest(connection.baseUrl, 'GET', {}, undefined, new AbortController().signal),
      error => /redirected/.test(error.message) && !/synthetic-secret|Bearer/.test(error.message));
  } finally {native.Platform.OS = before;}
});

test('the native bridge hands over the task-list continuation headers', async () => {
  const before = native.Platform.OS; native.Platform.OS = 'ios';
  try {
    const api = source('src/api.ts', {'expo-modules-core': {requireOptionalNativeModule: () => ({
      request: async () => ({status: 200, body: '[]', headers: {'pagination-has-more': 'true', 'pagination-next-before-id': '40'}}),
      cancel() {},
    })}});
    assert.deepEqual(JSON.parse(JSON.stringify(await api.listGoals(connection))), {goals: [], hasMore: true, nextBeforeId: 40});
    const older = source('src/api.ts', {'expo-modules-core': {requireOptionalNativeModule: () => ({
      request: async () => ({status: 200, body: '[]'}), cancel() {},
    })}});
    assert.deepEqual(JSON.parse(JSON.stringify(await older.listGoals(connection))), {goals: [], hasMore: null, nextBeforeId: null},
      'an app built before the bridge returned headers falls back to the page length');
  } finally {native.Platform.OS = before;}
});
