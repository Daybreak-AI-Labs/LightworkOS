// Run with: node --test packages/maverick-dashboard/tests/js/consent_native_admin_client.test.js
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

function source() {
  return fs.readFileSync(
    path.resolve(
      __dirname,
      "../../maverick_dashboard/static/lightwork-consent-native-admin.js",
    ),
    "utf8",
  );
}

test("client bounds same-origin JSON and omits ambient authority for public keys", () => {
  const text = source();
  assert.match(text, /maxResponseBytes = 512 \* 1024/);
  assert.match(text, /maxRequestBytes = 128 \* 1024/);
  assert.match(text, /parsed\.origin !== window\.location\.origin/);
  assert.match(text, /credentials: publicMetadata \? "omit" : "same-origin"/);
  assert.match(text, /response\.body\.getReader/);
  assert.match(text, /await reader\.cancel\(\)/);
  assert.match(text, /new TextEncoder\(\)\.encode\(settings\.body\)/);
  assert.match(text, /replaceChildren\(/);
  assert.doesNotMatch(text, /\.innerHTML\s*=/);
  assert.doesNotMatch(text, /eval\s*\(/);
  assert.doesNotMatch(text, /document\.cookie/);
  assert.doesNotMatch(text, /localStorage/);
});

test("mutations carry only selectors and versions taken from the chosen row", () => {
  const text = source();
  assert.match(text, /expected_revision: 0/);
  assert.match(text, /expected_directory_revision: app\.directory_revision/);
  assert.match(text, /expected_revision: device\.revision, evidence_sha256: evidence/);
  assert.match(text, /mutation\("\/applications", body\)/);
  assert.match(text, /"\/receipt-key\/rotate"/);
  assert.match(text, /encodeURIComponent\(identifier\(device\.device_id\)\) \+ "\/revoke"/);
  // Device key rotation is the device's own job; the admin page never builds it.
  assert.doesNotMatch(text, /\/rotate",\s*\{\s*expected_revision/);
  assert.doesNotMatch(text, /attestation_material_b64url/);
  assert.doesNotMatch(text, /tenant_id\s*:/);
  assert.doesNotMatch(text, /principal_ref\s*:/);
  assert.doesNotMatch(text, /receipt_key_secret/);
});

test("removing a device asks for a reason and confirms the consequence", () => {
  const text = source();
  assert.match(text, /window\.mvForm\("Remove device access"/);
  assert.match(text, /CW\.confirm\(\s*"Remove "/);
  assert.match(text, /This cannot be undone/);
  assert.doesNotMatch(text, /window\.confirm|window\.alert|window\.prompt/);
  assert.doesNotMatch(text, /"HTTP "/);
  assert.doesNotMatch(text, /JSON\.stringify\(payload, null, 2\)/);
});
