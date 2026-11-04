// Run with: node --test packages/maverick-dashboard/tests/js/consent_bulk_jobs_client.test.js
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function client() {
  const window = {};
  const context = { Date, Set, TextDecoder, TextEncoder, console, window };
  vm.createContext(context);
  const source = fs.readFileSync(
    path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-consent-bulk-jobs.js"),
    "utf8",
  );
  vm.runInContext(source, context, { filename: "lightwork-consent-bulk-jobs.js" });
  return window.LightworkConsentBulkJobsClient;
}

function headers(contentLength = null) {
  return {
    get(name) { return name.toLowerCase() === "content-length" ? contentLength : null; },
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

function plain(value) { return JSON.parse(JSON.stringify(value)); }

function editItem() {
  return {
    item_id: "edit-1",
    profile_id: "profile-1",
    expected_revision: 2,
    policy_id: "policy-1",
    policy_version: 3,
    context: {
      jurisdiction: "us",
      country_code: "US",
      region_code: "NY",
      collection_point: "admin",
      asserted_source: "operator",
    },
    choices: [{ purpose_id: "analytics", action: "deny" }],
  };
}

test("declared oversized response is rejected before allocation", async () => {
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

test("streaming response cancels immediately after 64 KiB", async () => {
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

test("invalid JSON is rejected without echoing its content", async () => {
  const api = client();
  const secret = "private-consent-response";
  const fixture = streamingResponse([new TextEncoder().encode(secret)]);
  await assert.rejects(api.parseResponse(fixture.response), (error) => {
    assert.equal(error.code, "response_invalid_json");
    assert.equal(error.message.includes(secret), false);
    return true;
  });
});

test("receipt export validation explains the supported limits without echoing input", async () => {
  const api = client();
  const cases = [
    ["receipt_limit", "500 records"],
    ["after_sequence", "saved position"],
  ];
  for (const [field, expected] of cases) {
    const fixture = streamingResponse([new TextEncoder().encode(JSON.stringify({
      detail: [{ loc: ["body", "items", 0, field], type: "extra_forbidden", input: "private-subject-value" }],
    }))], { ok: false, status: 422 });
    await assert.rejects(api.parseResponse(fixture.response), (error) => {
      assert.match(error.message, new RegExp(expected));
      assert.equal(error.message.includes("private-subject-value"), false);
      return true;
    });
  }
  assert.throws(() => api.parseItems(JSON.stringify([{
    item_id: "export-1", profile_id: "profile-1", after_sequence: 1,
  }]), "export_receipts"), /saved position/);
});

test("export payload is closed and excludes authority injection", () => {
  const api = client();
  const built = plain(api.buildExportPayload({
    items_json: JSON.stringify([
      { item_id: "export-1", profile_id: "profile-1", receipt_limit: 100 },
    ]),
    scheduled_for: "2033-05-18T03:33:20Z",
    idempotency_key: "create-export-1",
    tenant_id: "attacker",
    actor_sha256: "f".repeat(64),
    worker_sha256: "e".repeat(64),
    database_path: "C:/attacker",
    provider: { url: "https://example.invalid" },
  }));
  assert.deepEqual(built.items, [
    { item_id: "export-1", profile_id: "profile-1", receipt_limit: 100 },
  ]);
  assert.equal(built.scheduled_for, 2000000000);
  for (const forbidden of [
    "tenant_id", "actor_sha256", "worker_sha256", "database_path", "provider",
  ]) {
    assert.equal(forbidden in built, false);
  }
});

test("edit and reactivate payloads preserve only their exact item schemas", () => {
  const api = client();
  const edit = plain(api.buildActionPayload({
    operation: "edit_preferences",
    items_json: JSON.stringify([editItem()]),
    idempotency_key: "create-edit-1",
  }));
  assert.equal(edit.operation, "edit_preferences");
  assert.equal(edit.items[0].expected_revision, 2);
  assert.equal(edit.items[0].context.asserted_source, "operator");
  assert.deepEqual(edit.items[0].choices, [{
    purpose_id: "analytics",
    action: "deny",
    channel: "all",
    vendor_id: "all",
    expires_at: null,
  }]);

  const reactivateItem = {
    item_id: "reactivate-1",
    profile_id: "profile-1",
    expected_revision: 3,
    receipt_id: "receipt-1",
    reactivation_at: 2000000100,
  };
  const reactivate = plain(api.buildActionPayload({
    operation: "reactivate",
    items_json: JSON.stringify([reactivateItem]),
    idempotency_key: "create-reactivate-1",
  }));
  assert.equal(reactivate.items[0].reactivation_at, 2000000100);
});

test("delete, identifier change, and clear-expiration use closed contracts", () => {
  const api = client();
  const cases = [
    ["delete_subject", {
      item_id: "delete-1", profile_id: "profile-1", expected_revision: 3,
      reason_code: "subject_request",
    }],
    ["change_identifier_type", {
      item_id: "identity-1", profile_id: "profile-1", expected_revision: 3,
      identity_kind: "anonymous", subject_sha256: "a".repeat(64),
    }],
    ["clear_expiration", {
      item_id: "expiration-1", profile_id: "profile-1", expected_revision: 3,
      receipt_id: "receipt-1",
    }],
  ];
  for (const [operation, item] of cases) {
    const built = plain(api.buildActionPayload({
      operation,
      items_json: JSON.stringify([item]),
      idempotency_key: "create-" + operation,
    }));
    assert.equal(built.operation, operation);
    assert.equal(built.items[0].item_id, item.item_id);
    assert.equal(Object.keys(built.items[0]).length, Object.keys(item).length);
  }
});

test("schema rejects extra fields, duplicates, invalid digests and oversized input", () => {
  const api = client();
  const extra = editItem();
  extra.tenant_id = "attacker";
  assert.throws(() => api.parseItems(JSON.stringify([extra]), "edit_preferences"), /unsupported field/);
  assert.throws(() => api.parseItems(JSON.stringify([
    { item_id: "same", profile_id: "profile-1" },
    { item_id: "same", profile_id: "profile-2" },
  ]), "export_receipts"), /unique/);
  assert.throws(() => api.parseItems(JSON.stringify([{
    item_id: "identity-1", profile_id: "profile-1", expected_revision: 1,
    identity_kind: "known", subject_sha256: "not-a-digest",
  }]), "change_identifier_type"), /lowercase SHA-256/);
  assert.throws(() => api.parseItems(JSON.stringify([{
    item_id: "export-1", profile_id: "profile-1", receipt_limit: 501,
  }]), "export_receipts"), /1 to 500/);
  assert.throws(() => api.parseItems(" ".repeat(api.MAX_JSON_INPUT_BYTES + 1), "export_receipts"), /too much detail for one submission/);
});
