// Run with: node --test packages/maverick-dashboard/tests/js/privacy_data_discovery_client.test.js
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function client() {
  const window = {};
  const context = { TextDecoder, TextEncoder, Uint8Array, console, window };
  vm.createContext(context);
  vm.runInContext(
    fs.readFileSync(
      path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-privacy-data-discovery.js"),
      "utf8",
    ),
    context,
  );
  return window.LightworkPrivacyDataDiscoveryClient;
}

test("closed input helpers reject credentials, traversal, and invalid digests", () => {
  const api = client();
  assert.equal(api.identifier("source-1", "Source", false), "source-1");
  assert.equal(api.environmentReference("PRIVACY_SOURCE_TOKEN", "Credential"), "PRIVACY_SOURCE_TOKEN");
  assert.equal(api.digest("a".repeat(64), "Digest"), "a".repeat(64));
  assert.throws(() => api.identifier("../tenant-b", "Source", false), /invalid/);
  assert.throws(() => api.environmentReference("sk-live-secret", "Credential"), /environment-variable/);
  assert.throws(() => api.digest("A".repeat(64), "Digest"), /lowercase/);
});

test("bounded JSON input accepts only an object within the byte cap", () => {
  const api = client();
  assert.deepEqual(
    JSON.parse(JSON.stringify(api.parseBoundedObject('{"max_records":100}', "Limits"))),
    { max_records: 100 },
  );
  assert.throws(() => api.parseBoundedObject("[]", "Limits"), /JSON object/);
  assert.throws(() => api.parseBoundedObject("x".repeat(api.MAX_INPUT_BYTES + 1), "Limits"), /byte bound/);
});

test("declared and streamed oversized responses are cancelled", async () => {
  const api = client();
  let declaredCancelled = false;
  await assert.rejects(
    api.readBoundedJson({
      status: 200,
      headers: { get: () => String(api.MAX_RESPONSE_BYTES + 1) },
      body: { cancel: async () => { declaredCancelled = true; } },
    }),
    /safety limit/,
  );
  assert.equal(declaredCancelled, true);

  let reads = 0;
  let streamCancelled = false;
  await assert.rejects(
    api.readBoundedJson({
      status: 200,
      headers: { get: () => null },
      body: {
        getReader() {
          return {
            async read() {
              reads += 1;
              return { done: false, value: new Uint8Array(reads === 1 ? api.MAX_RESPONSE_BYTES : 1) };
            },
            async cancel() { streamCancelled = true; },
          };
        },
      },
    }),
    /safety limit/,
  );
  assert.equal(streamCancelled, true);
});

test("browser client uses safe DOM sinks and same-origin credentials", () => {
  const source = fs.readFileSync(
    path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-privacy-data-discovery.js"),
    "utf8",
  );
  assert.match(source, /credentials: "same-origin"/);
  // The status line is written through the shell's mvStatus, a textContent sink.
  assert.match(source, /window\.mvStatus\(statusEl, text\)/);
  assert.match(source, /pdd-work/);
  assert.match(source, /\/remediation\/work/);
  assert.match(source, /can\.audit|canAudit/);
  assert.match(source, /clientBound/);
  assert.doesNotMatch(source, /\.innerHTML\s*=/);
  assert.doesNotMatch(source, /eval\s*\(/);
  assert.doesNotMatch(source, /tenant_id\s*:/);
});
