// Run with: node --test packages/maverick-dashboard/tests/js/privacy_drop_management_client.test.js
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function client() {
  const window = {};
  const context = { TextDecoder, TextEncoder, console, window };
  vm.createContext(context);
  const source = fs.readFileSync(
    path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-privacy-drop-management.js"),
    "utf8",
  );
  vm.runInContext(source, context, { filename: "lightwork-privacy-drop-management.js" });
  return window.LightworkPrivacyDROPClient;
}

function headers(contentLength = null) {
  return {
    get(name) {
      return name.toLowerCase() === "content-length" ? contentLength : null;
    },
  };
}

function streamingResponse(chunks, { contentLength = null, ok = true, status = 200 } = {}) {
  let reads = 0;
  let cancelled = false;
  const reader = {
    async read() {
      const value = chunks[reads];
      reads += 1;
      return value === undefined ? { done: true } : { done: false, value };
    },
    async cancel() { cancelled = true; },
  };
  const body = {
    getReader() { return reader; },
    async cancel() { cancelled = true; },
  };
  return {
    response: { headers: headers(contentLength), body, ok, status },
    state: () => ({ reads, cancelled }),
  };
}

test("declared oversized response is rejected before reading its body", async () => {
  const api = client();
  const fixture = streamingResponse([new Uint8Array([123])], {
    contentLength: String(api.MAX_RESPONSE_BYTES + 1),
  });

  await assert.rejects(api.readBoundedJson(fixture.response), (error) => {
    assert.equal(error.code, "response_too_large");
    return true;
  });
  assert.deepEqual(fixture.state(), { reads: 0, cancelled: true });
});

test("streaming response cancels immediately after crossing the byte ceiling", async () => {
  const api = client();
  const fixture = streamingResponse([
    new Uint8Array(api.MAX_RESPONSE_BYTES),
    new Uint8Array([1]),
    new TextEncoder().encode('{"sentinel":true}'),
  ]);

  await assert.rejects(api.readBoundedJson(fixture.response), (error) => {
    assert.equal(error.code, "response_too_large");
    return true;
  });
  assert.deepEqual(fixture.state(), { reads: 2, cancelled: true });
});

test("bounded UTF-8 JSON parses without using response.json", async () => {
  const api = client();
  const fixture = streamingResponse([new TextEncoder().encode('{"ready":true}')]);

  const value = await api.readBoundedJson(fixture.response);

  assert.equal(value.ready, true);
  assert.equal(fixture.state().cancelled, false);
});

test("invalid JSON fails with a generic error that does not echo the body", async () => {
  const api = client();
  const secret = "private-case-content";
  const fixture = streamingResponse([new TextEncoder().encode(secret)]);

  await assert.rejects(api.readBoundedJson(fixture.response), (error) => {
    assert.equal(error.code, "response_invalid_json");
    assert.equal(error.message.includes(secret), false);
    return true;
  });
});

test("missing streaming body fails closed instead of allocating an unbounded fallback", async () => {
  const api = client();
  let textCalled = false;
  const response = {
    headers: headers(),
    body: null,
    async text() { textCalled = true; return "{}"; },
  };

  await assert.rejects(api.readBoundedJson(response), (error) => {
    assert.equal(error.code, "response_invalid_json");
    return true;
  });
  assert.equal(textCalled, false);
});

test("empty 2xx response is rejected instead of becoming a completed empty object", async () => {
  const api = client();
  const fixture = streamingResponse([]);

  await assert.rejects(api.parseResponse(fixture.response), (error) => {
    assert.equal(error.code, "response_invalid_json");
    assert.equal(error.status, 200);
    return true;
  });
});

test("malformed 2xx response fails without echoing the response body", async () => {
  const api = client();
  const secret = "private-drop-response-content";
  const fixture = streamingResponse([new TextEncoder().encode(secret)]);

  await assert.rejects(api.parseResponse(fixture.response), (error) => {
    assert.equal(error.code, "response_invalid_json");
    assert.equal(error.message.includes(secret), false);
    assert.equal(error.status, 200);
    return true;
  });
});

test("valid JSON error detail remains available to the operator", async () => {
  const api = client();
  const fixture = streamingResponse(
    [new TextEncoder().encode('{"detail":"Revision conflict."}')],
    { ok: false, status: 409 },
  );

  await assert.rejects(api.parseResponse(fixture.response), (error) => {
    assert.equal(error.message, "Revision conflict.");
    assert.equal(error.status, 409);
    return true;
  });
});
