import assert from "node:assert/strict";
import test from "node:test";
import { webcrypto } from "node:crypto";
import { LightworkCTVConsentClient, WebCryptoReceiptVerifier, _conformance } from "../web/lightwork-consent-native.js";

if (globalThis.CryptoKey === undefined) {
  Object.defineProperty(globalThis, "CryptoKey", { value: webcrypto.CryptoKey });
}

const digest = "a".repeat(64);
const authority = {
  application_ref: "living-room", application_authority_sha256: digest,
  tenant_id: "tenant-one", application_id: "com.example.livingroom", platform: "webos",
  device_id: "device-one", device_revision: 1, key_revision: 1, sdk_version: 1,
  public_client_revision: 1, public_client_record_sha256: digest,
  publication_sha256: digest, publication_bundle_sha256: digest, configuration_sha256: digest,
  policy_id: "policy-one", policy_version: 1, policy_sha256: digest,
  standards_contract_sha256: digest,
};

test("authority rotation during signing preserves the signed envelope metadata", async (t) => {
  const keys = await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
  const nextKeys = await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
  const pending = [];
  const outbox = {
    async append(message) { pending.push(message); }, async due() { return pending; },
    async acknowledge() {}, async retry() {}, async removeAll() {},
    async reserveCounter() { return 1; }, async replace() {},
  };
  const client = new LightworkCTVConsentClient({ authority, privateKey: keys.privateKey,
    outbox, transport: { async post() {} }, receiptVerifier: { async verify() {} },
    authorityRefresher: { async refresh() {} }, clock: () => 1000 });
  const originalSign = crypto.subtle.sign.bind(crypto.subtle);
  let started, release;
  const entered = new Promise(resolve => { started = resolve; });
  const gate = new Promise(resolve => { release = resolve; });
  t.mock.method(crypto.subtle, "sign", async (...args) => {
    started();
    await gate;
    return originalSign(...args);
  });
  const queued = client.configuration();
  await entered;
  client.replaceAuthority({ ...authority, device_revision: 2, key_revision: 2 }, nextKeys.privateKey);
  release();
  await queued;
  const message = pending[0];
  const envelope = JSON.parse(new TextDecoder().decode(message.signedEnvelope));
  assert.equal(envelope.device_revision, 1);
  assert.equal(message.deviceRevision, envelope.device_revision);
  assert.equal(message.applicationAuthoritySHA256, envelope.application_authority_sha256);
  const { signature_hex, ...body } = envelope;
  assert.equal(await crypto.subtle.verify("Ed25519", keys.publicKey,
    Buffer.from(signature_hex, "hex"), new TextEncoder().encode(_conformance.canonicalize(body))), true);
});

test("signed receipts require an object result before acknowledging work", async () => {
  const keys = await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
  const verifier = new WebCryptoReceiptVerifier({ "receipt-key": keys.publicKey });
  const expected = { authority, requestId: "request-one", requestSHA256: digest, operation: "configuration" };
  async function receipt(result) {
    const body = {
      schema: "lightwork.native-consent-receipt.v1", application_ref: authority.application_ref,
      application_authority_sha256: digest, tenant_sha256: await _conformance.sha256Hex(authority.tenant_id),
      device_id: authority.device_id, device_revision: 1, request_id: expected.requestId,
      request_sha256: digest, operation: expected.operation, result, result_sha256: digest,
      publication_sha256: digest, configuration_sha256: digest, policy_sha256: digest,
      key_id: "receipt-key", key_revision: 1, completed_at: 1000,
    };
    const bytes = new TextEncoder().encode(JSON.stringify(body));
    const signature = await crypto.subtle.sign("Ed25519", keys.privateKey, bytes);
    return new TextEncoder().encode(JSON.stringify({
      signed_payload_b64url: Buffer.from(bytes).toString("base64url"),
      signature_hex: Buffer.from(signature).toString("hex"),
    }));
  }
  for (const result of [null, [], "accepted"]) {
    await assert.rejects(verifier.verify(await receipt(result), expected));
  }
  assert.deepEqual((await verifier.verify(await receipt({ value: 1.5 }), expected)).result, { value: 1.5 });
});
