import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { webcrypto } from "node:crypto";

if (globalThis.CryptoKey === undefined) {
  Object.defineProperty(globalThis, "CryptoKey", { value: webcrypto.CryptoKey });
}

const { LightworkCTVConsentClient, WebCryptoReceiptVerifier, _conformance } = await import(
  "../web/lightwork-consent-native.js"
);

const digest = async (value) => _conformance.sha256Hex(value);

test("canonical JSON is compact, sorted, and rejects non-finite values", () => {
  assert.equal(
    _conformance.canonicalize({ z: [2, { b: true, a: "x" }], a: 1 }),
    '{"a":1,"z":[2,{"a":"x","b":true}]}',
  );
  assert.throws(() => _conformance.canonicalize({ value: Number.NaN }), /finite/);
  assert.throws(() => _conformance.canonicalize(new Date()), /plain JSON/);
});

test("Tizen/webOS client signs and drains an exact bounded operation", async () => {
  const keys = await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
  const receiptKeys = await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
  const authority = {
    application_ref: "living-room-prod",
    application_authority_sha256: await digest("app-authority"),
    tenant_id: "tenant-one",
    application_id: "com.example.livingroom",
    platform: "webos",
    device_id: "CP-DEV-example",
    device_revision: 1,
    key_revision: 1,
    sdk_version: 4,
    public_client_revision: 2,
    public_client_record_sha256: await digest("client"),
    publication_sha256: await digest("publication"),
    publication_bundle_sha256: await digest("bundle"),
    configuration_sha256: await digest("configuration"),
    policy_id: "policy-one",
    policy_version: 3,
    policy_sha256: await digest("policy"),
    standards_contract_sha256: await digest("standards"),
  };
  for (const invalid of [
    { sdk_version: 1_000_001 },
    { application_id: "com.example/invalid" },
    { application_ref: "invalid ref" },
    { device_revision: 2_147_483_648 },
  ]) {
    assert.throws(() => new LightworkCTVConsentClient({ authority: { ...authority, ...invalid } }), TypeError);
  }
  const pending = [];
  const acknowledgements = [];
  const transmitted = [];
  let serverAuthority = authority;
  let counter = 0;
  const outbox = {
    async append(message) { pending.push(message); },
    async due(limit) { return pending.slice(0, limit); },
    async acknowledge(requestId, requestSHA256) {
      acknowledgements.push({ requestId, requestSHA256 });
      pending.splice(pending.findIndex((item) => item.requestId === requestId), 1);
    },
    async retry() {},
    async removeAll() { pending.length = 0; },
    async reserveCounter() { counter += 1; return counter; },
    async replace(requestId, requestSHA256, replacement) {
      const index = pending.findIndex((item) => item.requestId === requestId && item.requestSHA256 === requestSHA256);
      assert.notEqual(index, -1);
      pending.splice(index, 1, replacement);
    },
  };
  const transport = {
    async post(path, bytes, maximum) {
      assert.equal(path, "/api/v1/public/consent/native/dispatch");
      assert.ok(bytes.byteLength < maximum);
      transmitted.push(Buffer.from(bytes).toString("hex"));
      const envelope = JSON.parse(new TextDecoder().decode(bytes));
      const { signature_hex: signatureHex, ...body } = envelope;
      const signature = Uint8Array.from(signatureHex.match(/.{2}/g), (value) => Number.parseInt(value, 16));
      assert.equal(
        await crypto.subtle.verify(
          "Ed25519",
          keys.publicKey,
          signature,
          new TextEncoder().encode(_conformance.canonicalize(body)),
        ),
        true,
      );
      assert.equal(envelope.tenant_id, "tenant-one");
      assert.equal(envelope.platform, "webos");
      if (envelope.operation === "record_preferences") {
        assert.equal(envelope.payload.choices[0].action, "deny");
      }
      if (transmitted.length === 1) throw new Error("response lost after server claim");
      const result = { status: "accepted" };
      const signedReceipt = {
        schema: "lightwork.native-consent-receipt.v1",
        application_ref: serverAuthority.application_ref,
        application_authority_sha256: serverAuthority.application_authority_sha256,
        tenant_sha256: await digest(serverAuthority.tenant_id),
        device_id: serverAuthority.device_id,
        device_revision: serverAuthority.device_revision,
        request_id: envelope.request_id,
        request_sha256: await digest(_conformance.canonicalize(body)),
        operation: envelope.operation,
        result,
        result_sha256: await digest(_conformance.canonicalize(result)),
        publication_sha256: serverAuthority.publication_sha256,
        configuration_sha256: serverAuthority.configuration_sha256,
        policy_sha256: serverAuthority.policy_sha256,
        key_id: "receipt-key",
        key_revision: 1,
        completed_at: 1000,
      };
      const signedBytes = new TextEncoder().encode(_conformance.canonicalize(signedReceipt));
      const receiptSignature = new Uint8Array(await crypto.subtle.sign("Ed25519", receiptKeys.privateKey, signedBytes));
      return new TextEncoder().encode(JSON.stringify({
        ...signedReceipt,
        signature_hex: [...receiptSignature].map((item) => item.toString(16).padStart(2, "0")).join(""),
        signed_payload_b64url: Buffer.from(signedBytes).toString("base64url"),
      }));
    },
  };
  const client = new LightworkCTVConsentClient({
    authority,
    privateKey: keys.privateKey,
    transport,
    outbox,
    receiptVerifier: new WebCryptoReceiptVerifier({ "receipt-key": receiptKeys.publicKey }),
    authorityRefresher: {
      async refresh({ path, currentAuthority, admittedSDKVersion, maximumRequestBytes, maximumResponseBytes }) {
        assert.equal(path, "/api/v1/public/consent/native/refresh");
        assert.deepEqual(currentAuthority, authority);
        assert.equal(admittedSDKVersion, 5);
        assert.equal(maximumRequestBytes, 128 * 1024);
        assert.equal(maximumResponseBytes, 512 * 1024);
        const next = {
          ...currentAuthority,
          application_authority_sha256: await digest("app-authority-v2"),
          device_revision: currentAuthority.device_revision + 1,
          sdk_version: admittedSDKVersion,
          public_client_revision: currentAuthority.public_client_revision + 1,
          public_client_record_sha256: await digest("client-v2"),
        };
        serverAuthority = next;
        return next;
      },
    },
    clock: () => 1000,
  });
  const requestId = await client.preferences({
    profileCredentialSHA256: await digest("profile"),
    expectedRevision: 0,
    idempotencyKey: "preference-one",
    choices: [{
      purpose_id: "analytics",
      action: "deny",
      channel: "ctv",
      vendor_id: "all",
      expires_at: null,
    }],
  });
  assert.equal(pending.length, 1);
  await client.drain();
  assert.equal(pending.length, 1);
  await client.drain();
  assert.equal(pending.length, 0);
  assert.equal(acknowledgements[0].requestId, requestId);
  assert.equal(transmitted[0], transmitted[1], "ambiguous retry must reuse exact signed bytes");
  const staleQueuedRequestID = await client.configuration();
  assert.equal(pending[0].deviceRevision, 1);
  const refreshed = await client.refreshAuthority({ admittedSDKVersion: 5 });
  assert.equal(refreshed.device_revision, 2);
  assert.equal(refreshed.key_revision, 1);
  assert.equal(refreshed.sdk_version, 5);
  await client.drain();
  assert.equal(pending.length, 0);
  assert.notEqual(acknowledgements.at(-1).requestId, staleQueuedRequestID);
  const refreshedEnvelope = JSON.parse(Buffer.from(transmitted.at(-1), "hex").toString("utf8"));
  assert.equal(refreshedEnvelope.device_revision, 2);
  assert.equal(refreshedEnvelope.sdk_version, 5);
});

test("opaque TCF/GPP strings require matching digests", async () => {
  const wire = "DBABLA~CPXxRfAPXxRfAAfKABENB-CgAAAAAAAAAAYgAAAAAAAA";
  const normalized = await _conformance.normalizeSignals({
    gpc: true,
    do_not_sell_or_share: true,
    standards_contract_sha256: await digest("standards"),
    purposes: ["sharing", "sale"],
    gpp_string: wire,
    gpp_string_sha256: await digest(wire),
  });
  assert.deepEqual(normalized.purposes, ["sale", "sharing"]);
  await assert.rejects(
    _conformance.normalizeSignals({ ...normalized, gpp_string_sha256: undefined }),
    /incomplete/,
  );
});

test("Apple, Android, and Roku contracts require exact replay and verified receipts", async () => {
  const sources = await Promise.all([
    readFile(new URL("../apple/LightworkConsent.swift", import.meta.url), "utf8"),
    readFile(new URL("../android/LightworkConsent.kt", import.meta.url), "utf8"),
    readFile(new URL("../roku/LightworkConsent.brs", import.meta.url), "utf8"),
  ]);
  for (const source of sources) {
    for (const contract of [
      "reserveCounter", "requestSha", "signedEnvelope", "replace", "ReceiptVerifier",
      "refreshAuthority", "AuthorityRefresher", "deviceRevision",
      "bootstrap_profile", "current_preferences", "link_profile", "revoke_profile",
    ]) {
      assert.ok(source.toLowerCase().includes(contract.toLowerCase()), `missing ${contract}`);
    }
  }
});

test("authority refresh request and response contracts are closed", async () => {
  const schema = JSON.parse(await readFile(
    new URL("../protocol/native-consent-authority-refresh-v1.schema.json", import.meta.url),
    "utf8",
  ));
  assert.equal(schema.additionalProperties, false);
  assert.equal(schema.properties.request.additionalProperties, false);
  assert.equal(schema.properties.response.additionalProperties, false);
  assert.ok(schema.properties.request.required.includes("expected_revision"));
  assert.ok(schema.properties.request.required.includes("attestation_nonce"));
  assert.ok(schema.properties.response.properties.device.required.includes("public_key_hex"));
});
