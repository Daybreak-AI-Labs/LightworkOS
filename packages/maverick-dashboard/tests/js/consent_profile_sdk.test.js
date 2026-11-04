// Run with: node --test packages/maverick-dashboard/tests/js/consent_profile_sdk.test.js
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { TextEncoder } = require("node:util");

class FakeElement {
  constructor(tagName) {
    this.tagName = tagName.toUpperCase();
    this.children = [];
    this.attributes = new Map();
    this.listeners = new Map();
    this.parentNode = null;
    this.textContent = "";
    this.checked = false;
    this.disabled = false;
    this.name = "";
    this.type = "";
    this.value = "";
    this.styleValues = new Map();
    this.style = {
      setProperty: (name, value) => { this.styleValues.set(name, String(value)); },
    };
  }

  appendChild(child) {
    child.parentNode = this;
    this.children.push(child);
    return child;
  }

  replaceChildren(...children) {
    this.children.forEach((child) => { child.parentNode = null; });
    this.children = [];
    children.forEach((child) => this.appendChild(child));
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  addEventListener(name, handler) {
    this.listeners.set(name, handler);
  }

  dispatchEvent(event) {
    const handler = this.listeners.get(event.type);
    if (handler) handler.call(this, event);
    return true;
  }

  remove() {
    if (!this.parentNode) return;
    this.parentNode.children = this.parentNode.children.filter((child) => child !== this);
    this.parentNode = null;
  }
}

function descendants(node) {
  return node.children.flatMap((child) => [child, ...descendants(child)]);
}

function sdkContext() {
  const events = [];
  const storage = new Map();
  const context = {
    Blob,
    URL,
    TextEncoder,
    crypto: crypto.webcrypto,
    btoa: (value) => Buffer.from(value, "binary").toString("base64"),
    console,
    document: { createElement: (tag) => new FakeElement(tag) },
    Element: FakeElement,
    CustomEvent: class CustomEvent {
      constructor(name, options) {
        this.type = name;
        this.detail = options ? options.detail : undefined;
      }
    },
    dispatchEvent: (event) => { events.push(event); },
    fetch: () => { throw new Error("unexpected network request"); },
    localStorage: {
      getItem: (key) => storage.get(key) || null,
      setItem: (key, value) => storage.set(key, value),
    },
    location: { href: "https://www.example.com/" },
    navigator: {},
  };
  context.window = context;
  vm.createContext(context);
  const source = fs.readFileSync(
    path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-consent-sdk.js"),
    "utf8",
  );
  vm.runInContext(source, context, { filename: "lightwork-consent-sdk.js" });
  return { context, events };
}

function configuration() {
  return {
    configuration_sha256: "a".repeat(64),
    configuration: {
      custom_preferences: [
        {
          id: "required-bool",
          version: 1,
          value_type: "boolean",
          required: true,
          option_ids: [],
          title: "Required choice",
          description: "Choose whether this value applies.",
        },
        {
          id: "locale",
          version: 1,
          value_type: "single_select",
          required: false,
          option_ids: ["eu", "us"],
          title: "Region preference",
          description: "Choose a closed region reference.",
        },
      ],
    },
  };
}

function prompt() {
  return {
    assignment_id: "prompt-12345678",
    assigned_at: 1_800_000_000,
    eligible: true,
    reason: "assigned",
    prompts: [
      {
        stage_id: "foundation",
        preference_id: "required-bool",
        definition_version: 1,
        label_ref: "required-bool",
        value_type: "boolean",
        required: true,
        options: [],
      },
      {
        stage_id: "foundation",
        preference_id: "locale",
        definition_version: 1,
        label_ref: "locale",
        value_type: "single_select",
        required: false,
        options: [
          { value_id: "eu", label_ref: "eu" },
          { value_id: "us", label_ref: "us" },
        ],
      },
    ],
  };
}

test("progressive prompt is certified, inserted, saved, and completed through closed controls", {timeout: 5_000}, async () => {
  const { context } = sdkContext();
  const sdk = new context.LightworkConsent({
    endpoint: "https://consent.lightwork.test/api/v1/public/consent",
    clientCredential: "client-credential-12345678",
  });
  sdk.configuration = configuration();
  sdk.profileCredential = "profile-credential-12345678";
  const calls = [];
  sdk._request = async (route, options = {}) => {
    calls.push({ route, options });
    if (route === "/profile-data/prompt") return prompt();
    if (route === "/profile-data") return { current: [], active_values: {} };
    if (route === "/profile-data/prompt/interactions") {
      return {
        assignment_id: options.body.assignment_id,
        outcome: options.body.outcome,
        recorded: true,
      };
    }
    if (route.startsWith("/profile-data/preferences/")) {
      return {
        preference_id: route.split("/").pop(),
        revision: 1,
        value: options.body.value,
      };
    }
    throw new Error("unexpected route " + route);
  };

  const container = new FakeElement("div");
  const panel = await sdk.renderProgressivePrompt(container);
  assert.ok(panel instanceof FakeElement);
  assert.equal(container.children.length, 1);
  assert.equal(calls[0].route, "/profile-data/prompt");
  assert.equal(calls[1].options.body.outcome, "inserted");

  const inputs = descendants(panel).filter((node) => node.tagName === "INPUT");
  assert.equal(inputs[0].name, "required-bool");
  assert.equal(inputs[0].type, "checkbox");
  assert.equal(inputs[1].name, "locale");
  assert.equal(inputs[1].type, "radio");
  inputs[1].checked = true;
  const save = descendants(panel).find(
    (node) => node.tagName === "BUTTON" && node.textContent === "Save profile choices",
  );
  assert.ok(save);
  const completed = new Promise((resolve) => {
    container.addEventListener("lightwork-profile-prompt-completed", resolve);
  });
  save.listeners.get("click")();
  const completedEvent = await completed;
  assert.equal(completedEvent.detail.assignment_id, "prompt-12345678");

  const writes = calls.filter((call) =>
    call.route.startsWith("/profile-data/preferences/") && call.options.method === "PUT",
  );
  assert.deepEqual(
    writes.map((call) => [call.route.split("/").pop(), call.options.body.value]),
    [["required-bool", false], ["locale", "eu"]],
  );
  assert.equal(container.children.length, 0);
});

test("mismatched prompt options fail control without mutating the DOM", async () => {
  const { context } = sdkContext();
  const sdk = new context.LightworkConsent({
    endpoint: "https://consent.lightwork.test/api/v1/public/consent",
    clientCredential: "client-credential-12345678",
  });
  sdk.configuration = configuration();
  sdk.profileCredential = "profile-credential-12345678";
  sdk._request = async () => {
    const invalid = prompt();
    invalid.prompts[1].options[0].value_id = "attacker-option";
    return invalid;
  };
  const container = new FakeElement("div");
  assert.equal(await sdk.renderProgressivePrompt(container), null);
  assert.equal(container.children.length, 0);
});

test("trust center renders only closed granted sections and derives export idempotency", async () => {
  const { context } = sdkContext();
  const sdk = new context.LightworkConsent({
    endpoint: "https://consent.lightwork.test/api/v1/public/consent",
    clientCredential: "client-credential-12345678",
  });
  sdk.profileCredential = "profile-credential-12345678";
  const sectionPins = {
    publication: "d6e2c71325b08c07ae6b173f1582c3e99eccf31541261728a1c3de0c61aa2019",
    consent: "6c5767328e1377d327b1b2ff4c161321b8b543bba74713cd737792a77ccf3720",
    profile_data: "80ff3af33d2a617b6da0726e20757cb08bfa16811d604ae64c6ae7b7f1ae4c65",
    rights: "b15bd98085111d4d6fd6ebafdcedb9913da5b29f7a291f721265303f97775a7b",
  };
  const snapshot = {
    schema: "lightwork.consumer-trust-center.v1",
    tenant_sha256: "a".repeat(64),
    property_id: "property-web",
    profile_ref_sha256: "b".repeat(64),
    context_revision: 2,
    context_sha256: "c".repeat(64),
    capabilities: ["active_publication", "consent_history", "profile_data", "rights_cases"],
    source_pins: sectionPins,
    sections: {
      publication: {
        notice: {id: "notice-main", version: 3},
        branding: {
          theme_token_id: "brand-default",
          version: 2,
          resource_sha256: "5".repeat(64),
          display_name: "Café 😀",
          heading: "Café Privacy Trust Center",
          description: "Manage choices for São Paulo.",
          primary_color: "174b3f",
          primary_text_color: "ffffff",
          surface_color: "ffffff",
          text_color: "16211d",
          branding_sha256: "5d82578b2d78f444c880a08006527a2c85a1bb3a080e98e653bca409f2eae60b",
        },
        source_sha256: sectionPins.publication,
      },
      consent: {receipts: [{receipt_id: "receipt-one"}], source_sha256: sectionPins.consent},
      profile_data: {
        current_records: [{preference_id: "region", status: "active"}],
        source_sha256: sectionPins.profile_data,
      },
      rights: {
        cases: [{case_id: "case-one", status: "closed"}],
        authorization_scope: "explicit_case_refs_only",
        completeness_claimed: false,
        source_sha256: sectionPins.rights,
      },
    },
    generated_at: 1_800_000_000,
    retained_until: 1_800_100_000,
    boundaries: {network_io: false},
    snapshot_sha256: "5bc1f44b8d84e13a2549217d3c7c008c517bff05d1d3473472114af3835c4374",
  };
  const calls = [];
  sdk._request = async (route, options = {}) => {
    calls.push({route, options});
    if (route === "/trust-center") return snapshot;
    if (route === "/trust-center/exports") {
      return {payload: {schema: "lightwork.consumer-trust-center-export.v1"}};
    }
    throw new Error("unexpected route " + route);
  };

  const container = new FakeElement("div");
  const panel = await sdk.renderTrustCenter(container);
  assert.ok(panel instanceof FakeElement);
  const text = descendants(panel).map((node) => node.textContent).join(" ");
  assert.match(text, /Published privacy configuration/);
  assert.match(text, /Notice notice-main · version 3/);
  assert.match(text, /Café Privacy Trust Center/);
  assert.match(text, /Café 😀/);
  assert.match(text, /Consent history/);
  assert.match(text, /Volunteered profile data/);
  assert.match(text, /Privacy rights requests/);
  assert.match(text, /completeness is not claimed/);
  assert.equal(panel.attributes.get("data-lightwork-theme"), "brand-default");
  assert.equal(panel.styleValues.get("--lightwork-primary"), "#174b3f");
  assert.equal(panel.styleValues.get("background-color"), "#ffffff");
  assert.equal(calls[0].route, "/trust-center");

  await sdk.exportTrustCenter();
  assert.equal(calls[1].route, "/trust-center/exports");
  assert.match(calls[1].options.body.idempotency_key, /^sdk-trust-export-[0-9a-f]{48}$/);
  assert.deepEqual(Object.keys(calls[1].options.body), ["idempotency_key"]);

  snapshot.sections.publication.branding.heading = "Tampered heading";
  await assert.rejects(sdk.getTrustCenter(), /outside the closed contract/);
  snapshot.sections.publication.branding.heading = "Café Privacy Trust Center";

  snapshot.sections.publication.notice.version = 4;
  await assert.rejects(sdk.getTrustCenter(), /outside the closed contract/);
  snapshot.sections.publication.notice.version = 3;

  snapshot.generated_at += 1;
  await assert.rejects(sdk.getTrustCenter(), /outside the closed contract/);
});

test("published branding digest is verified before banner DOM mutation", async () => {
  const { context } = sdkContext();
  const sdk = new context.LightworkConsent({
    endpoint: "https://consent.lightwork.test/api/v1/public/consent",
    clientCredential: "client-credential-12345678",
  });
  const branding = {
    theme_token_id: "brand-default",
    version: 2,
    resource_sha256: "5".repeat(64),
    display_name: "Café 😀",
    heading: "Café Privacy Trust Center",
    description: "Manage choices for São Paulo.",
    primary_color: "174b3f",
    primary_text_color: "ffffff",
    surface_color: "ffffff",
    text_color: "16211d",
    branding_sha256: "5d82578b2d78f444c880a08006527a2c85a1bb3a080e98e653bca409f2eae60b",
  };
  sdk.configuration = {
    rule: {locale: "en-US"},
    configuration: {
      branding,
      template: {
        title: "Privacy choices",
        body: "Control analytics.",
        actions: {accept_all: "Accept", reject_all: "Reject", save_preferences: "Save"},
      },
      notice: {
        title: "Your privacy choices",
        body: "Choose whether analytics may be used.",
      },
      purposes: [],
    },
  };
  sdk.preferences = {preferences: []};
  sdk.getPreferences = async () => sdk.preferences;
  sdk.getExperimentAssignment = async () => null;
  const container = new FakeElement("div");
  const panel = await sdk.renderBanner(container);
  assert.equal(panel.attributes.get("data-lightwork-theme"), "brand-default");
  assert.equal(panel.styleValues.get("--lightwork-primary"), "#174b3f");

  branding.description = "Tampered description";
  await assert.rejects(sdk.renderBanner(container), /outside the closed contract/);
  assert.equal(container.children[0], panel);
});

test("rights package redemption keeps reauthentication out of JSON and returns bounded bytes", async () => {
  const { context } = sdkContext();
  const sdk = new context.LightworkConsent({
    endpoint: "https://consent.lightwork.test/api/v1/public/consent",
    clientCredential: "client-credential-12345678",
  });
  sdk.profileCredential = "profile-credential-12345678";
  const calls = [];
  const bytes = Uint8Array.from([1, 2, 3, 4]);
  context.fetch = async (url, options) => {
    calls.push({url, options});
    return {
      ok: true,
      status: 200,
      headers: {get: (name) => name.toLowerCase() === "content-length" ? "4" : null},
      arrayBuffer: async () => bytes.buffer,
      text: async () => "",
    };
  };
  const capabilityValue = "lwrcd1." + "c".repeat(43);
  const receipt = "reauth-receipt-" + "r".repeat(32);
  const blob = await sdk.redeemRightsPackage(capabilityValue, receipt);
  assert.equal(blob.size, 4);
  assert.equal(calls[0].url.endsWith("/rights-deliveries/redeem"), true);
  assert.deepEqual(JSON.parse(calls[0].options.body), {capability: capabilityValue});
  assert.equal(calls[0].options.headers["X-Lightwork-Reauthentication-Receipt"], receipt);
  assert.equal(calls[0].options.headers["X-Lightwork-Profile-Credential"], sdk.profileCredential);
  await assert.rejects(
    sdk.redeemRightsPackage("case-attacker", receipt),
    /capability is invalid/,
  );
});

test("rights intake SDK sends only a closed rights contract and validates signed status", async () => {
  const { context, events } = sdkContext();
  const sdk = new context.LightworkConsent({
    endpoint: "https://consent.lightwork.test/api/v1/public/consent",
    clientCredential: "client-credential-12345678",
  });
  sdk.profileCredential = "profile-credential-12345678";
  const calls = [];
  const status = {
    payload: {
      schema: "lightwork.privacy-rights-intake-status.v1",
      tenant_sha256: "d".repeat(64),
      case_id: "rights-case-1",
      rights: ["access", "erasure"],
      status: "open",
      identity_status: "verified",
      destructive_approval_required: true,
      provider_operations_verified: false,
      estate_completeness_claimed: false,
    },
    signing_key_ref: "kms:rights-status/key-one",
    signing_key_revision: 1,
    signing_key_authority_sha256: "a".repeat(64),
    signature: "b".repeat(64),
    evidence_sha256: "c".repeat(64),
  };
  sdk._request = async (route, options = {}) => {
    calls.push({route, options});
    return JSON.parse(JSON.stringify(status));
  };

  const created = await sdk.createRightsRequest(
    ["access", "erasure"],
    "person-confirmed-request-1",
  );
  assert.equal(created.payload.case_id, "rights-case-1");
  assert.equal(calls[0].route, "/rights-requests");
  assert.deepEqual(calls[0].options.body.rights, ["access", "erasure"]);
  assert.equal(calls[0].options.body.expected_revision, 0);
  assert.match(calls[0].options.body.idempotency_key, /^sdk-rights-create-[0-9a-f]{48}$/);
  assert.deepEqual(Object.keys(calls[0].options.body).sort(), [
    "expected_revision", "idempotency_key", "rights",
  ]);
  assert.equal(JSON.stringify(calls[0]).includes("tenant_id"), false);
  assert.equal(JSON.stringify(calls[0]).includes("source_ids"), false);
  assert.equal(JSON.stringify(calls[0]).includes("identity_token"), false);
  assert.equal(events.at(-1).type, "lightwork-rights-request");

  const current = await sdk.getRightsRequestStatus("rights-case-1");
  assert.equal(current.payload.identity_status, "verified");
  assert.equal(calls[1].route, "/rights-requests/rights-case-1");
  await assert.rejects(
    sdk.createRightsRequest(["erasure", "erasure"], "duplicate-right"),
    /selection is invalid/,
  );
  await assert.rejects(
    sdk.createRightsRequest(["attacker-defined-right"], "unknown-right"),
    /selection is invalid/,
  );
  status.signature = "tampered";
  await assert.rejects(
    sdk.getRightsRequestStatus("rights-case-1"),
    /outside the closed contract/,
  );
});

test("rights intake reuses a persisted operation after an ambiguous response", async () => {
  const { context } = sdkContext();
  const options = {
    endpoint: "https://consent.lightwork.test/api/v1/public/consent",
    clientCredential: "client-credential-12345678",
  };
  const status = {
    payload: {
      schema: "lightwork.privacy-rights-intake-status.v1",
      tenant_sha256: "d".repeat(64),
      case_id: "rights-case-retried",
      rights: ["access"],
      status: "open",
      identity_status: "verified",
    },
    signing_key_ref: "kms:rights-status/key-one",
    signing_key_revision: 1,
    signing_key_authority_sha256: "a".repeat(64),
    signature: "b".repeat(64),
    evidence_sha256: "c".repeat(64),
  };
  const keys = [];
  const first = new context.LightworkConsent(options);
  first.profileCredential = "profile-credential-12345678";
  first._request = async (_route, request) => {
    keys.push(request.body.idempotency_key);
    throw new Error("connection ended after the server may have committed");
  };
  await assert.rejects(first.createRightsRequest(["access"]), /connection ended/);

  const recovered = new context.LightworkConsent(options);
  recovered.profileCredential = "profile-credential-12345678";
  recovered._request = async (_route, request) => {
    keys.push(request.body.idempotency_key);
    return status;
  };
  const receipt = await recovered.createRightsRequest(["access"]);
  assert.equal(receipt.payload.case_id, "rights-case-retried");
  assert.equal(keys.length, 2);
  assert.equal(keys[0], keys[1]);
});

test("identity pairing SDK uses PKCE and never accepts authority selectors", async () => {
  const { context } = sdkContext();
  const sdk = new context.LightworkConsent({
    endpoint: "https://consent.lightwork.test/api/v1/public/consent",
    clientCredential: "client-credential-12345678",
  });
  sdk.profileCredential = "profile-credential-12345678";
  const calls = [];
  const pairingCode = "lwcp1." + "c".repeat(43);
  const oidcNonce = "n".repeat(43);
  sdk._request = async (route, options = {}) => {
    calls.push({route, options});
    if (route === "/identity/pairings") {
      return {pairing_code: pairingCode, oidc_nonce: oidcNonce, expires_at: 1_800_000_300};
    }
    if (route === "/identity/pairings/authorize") {
      return {status: "authorized", expires_at: 1_800_000_300};
    }
    if (route === "/identity/pairings/redeem") return {status: "redeemed", linked: true};
    if (route === "/identity/pairings/revoke") return {status: "revoked"};
    throw new Error("unexpected route " + route);
  };

  const started = await sdk.beginIdentityPairing();
  assert.equal(started.pairingCode, pairingCode);
  assert.equal(started.oidcNonce, oidcNonce);
  assert.match(started.codeVerifier, /^[A-Za-z0-9_-]{43}$/);
  const expectedChallenge = crypto.createHash("sha256")
    .update(started.codeVerifier, "ascii").digest("base64url");
  assert.equal(calls[0].options.body.code_challenge, expectedChallenge);
  assert.deepEqual(Object.keys(calls[0].options.body), ["code_challenge"]);

  await sdk.authorizeIdentityPairing(
    started.pairingCode,
    started.oidcNonce,
    "signed-oidc-token-that-is-long-enough-123456",
  );
  assert.deepEqual(Object.keys(calls[1].options.body).sort(), [
    "oidc_nonce", "oidc_token", "pairing_code",
  ]);
  await sdk.redeemIdentityPairing(started.pairingCode, started.codeVerifier);
  assert.deepEqual(Object.keys(calls[2].options.body).sort(), [
    "code_verifier", "pairing_code",
  ]);
  await sdk.revokeIdentityPairing(started.pairingCode, "person-cancelled");
  assert.deepEqual(Object.keys(calls[3].options.body).sort(), [
    "pairing_code", "reason_sha256",
  ]);
  assert.equal(calls.some((call) => JSON.stringify(call).includes("tenant_id")), false);
  assert.equal(calls.some((call) => JSON.stringify(call).includes("property_id")), false);
  assert.equal(calls.some((call) => JSON.stringify(call).includes("profile_id")), false);
});
