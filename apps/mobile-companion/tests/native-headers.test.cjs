const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {source, native, connection} = require('./helpers.cjs');

// Both native bridges refuse any request header outside a fixed allowlist.
// A header the JavaScript client sends but a bridge does not list makes every
// such request fail on installed apps (the named-workspace task actions did),
// so the lists are read from the native sources and checked against what the
// client actually sends.
const module_ = path.resolve(__dirname, '../modules/lightwork-transport');
function kotlinAllowlist() {
  const code = fs.readFileSync(path.join(module_, 'android/src/main/java/ai/lightwork/transport/LightworkTransportModule.kt'), 'utf8');
  const match = code.match(/require\(key\.lowercase\(\) in setOf\(([^)]*)\)\)/);
  assert.ok(match, 'the Android bridge checks each request header against setOf(...)');
  return [...match[1].matchAll(/"([^"]+)"/g)].map(item => item[1]).sort();
}
function swiftAllowlist() {
  const code = fs.readFileSync(path.join(module_, 'ios/LightworkTransportModule.swift'), 'utf8');
  const match = code.match(/guard \[([^\]]*)\]\.contains\(key\.lowercased\(\)\)/);
  assert.ok(match, 'the iOS bridge checks each request header against [...].contains(key.lowercased())');
  return [...match[1].matchAll(/"([^"]+)"/g)].map(item => item[1]).sort();
}

// Every header shape apiRequest produces: reads, the offline bundle, pairing
// (no token), and action POSTs for a device paired to a named workspace.
async function sentHeaderNames() {
  const before = native.Platform.OS; native.Platform.OS = 'android';
  const sent = new Set();
  try {
    const api = source('src/api.ts', {'expo-modules-core': {requireOptionalNativeModule: () => ({
      request: async (_id, _url, _method, headers) => {
        Object.keys(headers).forEach(name => sent.add(name.toLowerCase()));
        return {status: 200, body: '{}'};
      },
      cancel() {},
    })}});
    const paired = {...connection, pairedDevice: {id: 'device-1', generation: 1, expires_at: 0, enrollment_expires_at: 0,
      principal: 'user:synthetic', tenant: 'synthetic-workspace', actions: true}};
    await api.getGoal(paired, 7);
    await api.getOfflineBundle(paired).catch(() => {});
    await api.beginPairing(connection.baseUrl, 'Phone');
    await api.prepareDeviceAction(paired, {goal_id: 7, action: 'stop', context: 'c', revision: 'r', arguments: {}});
    await api.executeDeviceAction(paired, 'synthetic-review-token');
  } finally {native.Platform.OS = before;}
  return [...sent].sort();
}

test('the Android and iOS bridges allow exactly the same request headers', () => {
  assert.deepEqual(kotlinAllowlist(), swiftAllowlist());
  assert.deepEqual(kotlinAllowlist(), ['accept', 'authorization', 'content-type', 'origin',
    'x-lightwork-expected-tenant', 'x-lightwork-offline-policy']);
});

test('every header the client sends is allowed by both native bridges', async () => {
  const sent = await sentHeaderNames();
  assert.ok(sent.includes('x-lightwork-expected-tenant'), 'named-workspace actions say which workspace they expect');
  for (const allowlist of [kotlinAllowlist(), swiftAllowlist()]) {
    assert.deepEqual(sent.filter(name => !allowlist.includes(name)), [], 'a bridge would refuse these headers');
  }
});

// The bridges return only the response headers the client reads: the task
// list's continuation. Nothing else (cookies, server details) crosses over.
test('both bridges return exactly the task-list continuation response headers', () => {
  const kotlin = fs.readFileSync(path.join(module_, 'android/src/main/java/ai/lightwork/transport/LightworkTransportModule.kt'), 'utf8');
  const swift = fs.readFileSync(path.join(module_, 'ios/LightworkTransportModule.swift'), 'utf8');
  const names = code => [...(code.match(/(?:RESPONSE_HEADERS|responseHeaders) = (?:listOf\(|\[)([^)\]]*)/) || [, ''])[1].matchAll(/"([^"]+)"/g)].map(item => item[1]);
  assert.deepEqual(names(kotlin), ['pagination-has-more', 'pagination-next-before-id']);
  assert.deepEqual(names(swift), ['pagination-has-more', 'pagination-next-before-id']);
  // ...and hand them to JavaScript with the reply.
  assert.match(kotlin, /"headers" to exposed/);
  assert.match(swift, /"headers": headers/);
});
