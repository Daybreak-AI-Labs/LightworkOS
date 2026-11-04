// Run with: node --test packages/maverick-dashboard/tests/js/consent_web_publish_settings_client.test.js
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
    path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-consent-publish-settings.js"),
    "utf8",
  );
  vm.runInContext(source, context, { filename: "lightwork-consent-publish-settings.js" });
  return window.LightworkConsentPublishSettingsClient;
}

function headers(contentLength = null) {
  return { get(name) { return name.toLowerCase() === "content-length" ? contentLength : null; } };
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
  return {
    response: {
      headers: headers(contentLength),
      body: { getReader() { return reader; }, async cancel() { cancelled = true; } },
      ok,
      status,
    },
    state: () => ({ reads, cancelled }),
  };
}

function plain(value) { return JSON.parse(JSON.stringify(value)); }

function validInput() {
  return {
    expected_head_revision: "0",
    idempotency_key: "create:website:1",
    sdk_version: "2.4.1",
    geolocation_reconsent: "US=365\nCA-QC=180",
    analytics_tracking_enabled: true,
    analytics_category_assignments: "google_analytics=analytics",
    common_trackers: ["google_analytics"],
    cookie_same_site: "lax",
    cookie_domain_separation: "host_only",
    spa_reload_on_route_change: true,
    csp_nonce_required: true,
    automatic_refresh_seconds: "300",
  };
}

test("declared oversized projection is rejected before allocation", async () => {
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

test("streaming projection cancels immediately after the 512 KiB bound", async () => {
  const api = client();
  const fixture = streamingResponse([
    new Uint8Array(api.MAX_RESPONSE_BYTES),
    new Uint8Array([1]),
    new TextEncoder().encode('{"never":"read"}'),
  ]);
  await assert.rejects(api.readBoundedJson(fixture.response), (error) => {
    assert.equal(error.code, "response_too_large");
    return true;
  });
  assert.deepEqual(fixture.state(), { reads: 2, cancelled: true });
});

test("create payload is closed and strips all authority and nonce-value injection", () => {
  const api = client();
  const payload = plain(api.buildCreatePayload({
    ...validInput(),
    tenant_id: "caller-tenant",
    principal_ref: "caller-principal",
    property_revision: 99,
    property_sha256: "a".repeat(64),
    publication_revision: 88,
    publication_sha256: "b".repeat(64),
    csp_nonce: "runtime-secret",
  }));
  assert.deepEqual(payload, {
    expected_head_revision: 0,
    idempotency_key: "create:website:1",
    settings: {
      sdk_version: "2.4.1",
      geolocation_reconsent: [
        { jurisdiction: "CA-QC", reconsent_after_days: 180 },
        { jurisdiction: "US", reconsent_after_days: 365 },
      ],
      analytics_tracking_enabled: true,
      analytics_category_assignments: [
        { tracker: "google_analytics", category: "analytics" },
      ],
      common_trackers: ["google_analytics"],
      cookie_same_site: "lax",
      cookie_domain_separation: "host_only",
      spa_reload_on_route_change: true,
      csp_nonce_required: true,
      automatic_refresh_seconds: 300,
    },
  });
  assert.equal(JSON.stringify(payload).includes("runtime-secret"), false);
  assert.equal("property_revision" in payload, false);
});

test("tracker assignments and geolocation rules are unique and closed", () => {
  const api = client();
  assert.throws(() => api.buildCreatePayload({
    ...validInput(),
    geolocation_reconsent: "US=365\nUS=180",
  }), /unique bounded jurisdictions/);
  assert.throws(() => api.buildCreatePayload({
    ...validInput(),
    analytics_category_assignments: "meta_pixel=advertising",
  }), /enabled common tracker/);
  assert.throws(() => api.buildCreatePayload({
    ...validInput(),
    common_trackers: ["caller_tracker"],
  }), /common trackers are listed twice or not recognized/);
});

test("boolean and semver fields remain strict", () => {
  const api = client();
  assert.throws(() => api.buildCreatePayload({
    ...validInput(), analytics_tracking_enabled: "true",
  }), /must be true or false/);
  assert.throws(() => api.buildCreatePayload({
    ...validInput(), sdk_version: "latest",
  }), /semantic versioning/);
  assert.throws(() => api.buildCreatePayload({
    ...validInput(), automatic_refresh_seconds: "29",
  }), /outside its allowed range/);
});

test("request JSON is bounded at 64 KiB and invalid JSON is not echoed", async () => {
  const api = client();
  assert.throws(() => api.boundedBody({ value: "x".repeat(api.MAX_REQUEST_BYTES) }), (error) => {
    assert.equal(error.code, "request_too_large");
    return true;
  });
  const secret = "private-invalid-response";
  const fixture = streamingResponse([new TextEncoder().encode(secret)]);
  await assert.rejects(api.parseResponse(fixture.response), (error) => {
    assert.equal(error.code, "response_invalid_json");
    assert.equal(error.message.includes(secret), false);
    return true;
  });
});
