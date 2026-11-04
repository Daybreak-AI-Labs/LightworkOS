// Run with: node --test packages/maverick-dashboard/tests/js/consent_sdk_signing.test.js
// The consent script checks signed configurations when a website opts in, and
// uses short-lived visitor sessions when the consent service asks for them.
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { TextEncoder } = require("node:util");

const REFUSAL = "consent configuration is not signed by a trusted key";
const SCHEMA = "lightwork.consent-configuration-signature.v1";
const SOURCE = fs.readFileSync(
  path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-consent-sdk.js"), "utf8");

// Sorted, compact, ASCII JSON: what the server signs (strings and integers only here).
function canonical(value) {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value && typeof value === "object") {
    return "{" + Object.keys(value).sort().map((key) => JSON.stringify(key) + ":" + canonical(value[key])).join(",") + "}";
  }
  return JSON.stringify(value);
}

function sha256(text) {
  return crypto.createHash("sha256").update(text).digest("hex");
}

function keyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const raw = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
  return { privateKey, file: { key_id: "lwcp-" + sha256(Buffer.from(raw, "hex")).slice(0, 24), public_key: raw } };
}

function signedConfiguration(keys, changes) {
  const served = {
    schema: "lightwork.public-consent-configuration.v1",
    allowed: true,
    property: { property_id: "web-main", kind: "web", consent_group_id: "consumer", revision: 1 },
    publication: { publication_id: "publication-1", publication_sha256: "1".repeat(64), bundle_sha256: "2".repeat(64) },
    rule: { rule_id: "global", rule_sha256: "3".repeat(64), locale: "en-US" },
    configuration: {
      consent_mode: "opt_in",
      purposes: [{ id: "analytics", version: 1, title: "Analytics", lawful_basis: "consent" }],
      notice: { id: "notice", version: 1, title: "Your choices", body: "Choose.", document_sha256: "4".repeat(64) },
    },
    policy_id: "public-consent",
    policy_version: 1,
    policy_sha256: "5".repeat(64),
  };
  served.configuration_sha256 = sha256(canonical({
    publication_sha256: served.publication.publication_sha256,
    property_id: served.property.property_id,
    property_revision: served.property.revision,
    consent_group_id: served.property.consent_group_id,
    rule_id: served.rule.rule_id,
    rule_sha256: served.rule.rule_sha256,
    locale: served.rule.locale,
    configuration: served.configuration,
  }));
  const statement = {
    schema: SCHEMA, algorithm: "Ed25519", key_id: keys.file.key_id,
    publication_key_id: keys.file.key_id, property_id: "web-main",
    publication_sha256: served.publication.publication_sha256,
    configuration_sha256: served.configuration_sha256, policy_id: served.policy_id,
    policy_version: served.policy_version, policy_sha256: served.policy_sha256,
  };
  served.signature = {
    schema: SCHEMA, algorithm: "Ed25519", key_id: keys.file.key_id, statement: statement,
    signature: crypto.sign(null, Buffer.from(canonical(statement)), keys.privateKey).toString("hex"),
  };
  if (changes) changes(served);
  return served;
}

function sdk(routes, options) {
  const requests = [];
  const context = {
    crypto: crypto.webcrypto, TextEncoder, console,
    btoa: (value) => Buffer.from(value, "binary").toString("base64"),
    localStorage: { getItem: () => null, setItem: () => {} },
    fetch: async (url, init) => {
      const route = url.replace("https://consent.test/api/v1/public/consent", "");
      requests.push({ route, method: init.method || "GET", headers: Object.assign({}, init.headers) });
      const [status, body] = routes(route, init.headers, requests.length);
      return { ok: status >= 200 && status < 300, status, headers: { get: () => null },
        text: async () => JSON.stringify(body) };
    },
  };
  context.window = context;
  vm.createContext(context);
  vm.runInContext(SOURCE, context, { filename: "lightwork-consent-sdk.js" });
  const consent = new context.LightworkConsent(Object.assign({
    endpoint: "https://consent.test/api/v1/public/consent",
    clientCredential: "c".repeat(40),
  }, options || {}));
  return { consent, requests };
}

function serving(configuration) {
  return (route) => (route === "/configuration" ? [200, configuration] : [404, { detail: "not found" }]);
}

test("a signed configuration from a trusted key is accepted", async () => {
  const keys = keyPair();
  const { consent } = sdk(serving(signedConfiguration(keys)), { publicationKeys: [keys.file] });
  const loaded = await consent.loadConfiguration();
  assert.equal(loaded.configuration.notice.title, "Your choices");
  assert.equal(consent.configuration, loaded);
});

test("an opted-in site refuses unsigned, tampered or foreign configurations", async () => {
  const keys = keyPair();
  const other = keyPair();
  const cases = {
    unsigned: signedConfiguration(keys, (served) => { delete served.signature; }),
    "changed content": signedConfiguration(keys, (served) => { served.configuration.notice.title = "Different"; }),
    "changed policy": signedConfiguration(keys, (served) => { served.policy_sha256 = "6".repeat(64); }),
    "changed statement": signedConfiguration(keys, (served) => { served.signature.statement.policy_version = 2; }),
    "bad signature": signedConfiguration(keys, (served) => { served.signature.signature = "0".repeat(128); }),
    "extra field": signedConfiguration(keys, (served) => { served.signature.statement.note = "x"; }),
  };
  for (const [name, configuration] of Object.entries(cases)) {
    const { consent } = sdk(serving(configuration), { publicationKeys: keys.file });
    await assert.rejects(consent.loadConfiguration(), { message: REFUSAL }, name);
    assert.equal(consent.configuration, null, name);
  }
  const { consent } = sdk(serving(signedConfiguration(other)), { publicationKeys: [keys.file] });
  await assert.rejects(consent.loadConfiguration(), { message: REFUSAL });
  // During a key change a site may trust both keys.
  const both = sdk(serving(signedConfiguration(other)), { publicationKeys: [keys.file, other.file] });
  await both.consent.loadConfiguration();
});

test("a site that does not opt in keeps today's unsigned behaviour", async () => {
  const keys = keyPair();
  const unsigned = signedConfiguration(keys, (served) => { delete served.signature; });
  const { consent } = sdk(serving(unsigned));
  assert.equal((await consent.loadConfiguration()).policy_id, "public-consent");
});

test("publication keys must be the downloaded key files", () => {
  for (const bad of [[], [{ key_id: "x", public_key: "y" }], { key_id: "lwcp-" + "0".repeat(24) }, "key"]) {
    assert.throws(() => sdk(serving({}), { publicationKeys: bad }));
  }
});

test("a session is started when the service asks for one, then sent on every request", async () => {
  const routes = (route, headers) => {
    if (route === "/sessions") return [201, { session_token: "lwcs_" + "a".repeat(43), expires_at: 1, ttl_seconds: 600 }];
    if (headers["X-Lightwork-Consent-Session"] !== "lwcs_" + "a".repeat(43)) return [401, { detail: "consent session required" }];
    return [200, { policy_id: "public-consent" }];
  };
  const { consent, requests } = sdk(routes);
  await consent.loadConfiguration();
  await consent.loadConfiguration();
  assert.deepEqual(requests.map((item) => item.route), ["/configuration", "/sessions", "/configuration", "/configuration"]);
  assert.equal(requests[1].headers["X-Lightwork-Consent-Session"], undefined);
  assert.equal(requests[1].headers.Authorization, "ConsentPublic " + "c".repeat(40));
});

test("a session is renewed before it ends, and a new one starts if renewal is refused", async () => {
  let issued = 0;
  const routes = (route, headers) => {
    if (route === "/sessions") { issued += 1; return [201, { session_token: "lwcs_new" + "b".repeat(40) + issued, expires_at: 1, ttl_seconds: 600 }]; }
    if (route === "/sessions/renew") {
      return headers["X-Lightwork-Consent-Session"] === "lwcs_new" + "b".repeat(40) + "1"
        ? [201, { session_token: "lwcs_renewed" + "c".repeat(36), expires_at: 1, ttl_seconds: 600 }]
        : [401, { detail: "consent session expired or invalid" }];
    }
    if (!headers["X-Lightwork-Consent-Session"]) return [401, { detail: "consent session required" }];
    return [200, { policy_id: "public-consent" }];
  };
  const { consent, requests } = sdk(routes);
  await consent.loadConfiguration();
  consent.sessionRenewAt = 0;  // the renewal point has passed
  await consent.loadConfiguration();
  assert.equal(requests.at(-1).headers["X-Lightwork-Consent-Session"], "lwcs_renewed" + "c".repeat(36));
  assert.equal(requests.at(-2).route, "/sessions/renew");
  consent.sessionRenewAt = 0;
  await consent.loadConfiguration();  // renewal of this token is refused: start again
  assert.deepEqual(requests.slice(-3).map((item) => item.route), ["/sessions/renew", "/sessions", "/configuration"]);
  assert.equal(requests.at(-1).headers["X-Lightwork-Consent-Session"], "lwcs_new" + "b".repeat(40) + "2");
});
