/* Production contract for Tizen/webOS consent clients. Requires WebCrypto
 * Ed25519, platform-attested device enrollment, an exact-origin bounded HTTPS
 * transport, and an IndexedDB-compatible transactional outbox. No ambient
 * cookie, bearer credential, or exportable device private key is accepted. */

const MAX_PAYLOAD_BYTES = 128 * 1024;
const MAX_RESPONSE_BYTES = 512 * 1024;
const ENVELOPE_TTL_SECONDS = 120;
const PLATFORMS = new Set(["tizen", "webos"]);
const OPERATIONS = new Set([
  "bootstrap_profile", "configuration", "current_preferences", "link_profile",
  "privacy_signals", "record_preferences", "revoke_profile", "rights_request",
]);
const RIGHTS = new Set([
  "access", "erasure", "objection", "opt_out", "portability", "rectification", "restriction",
]);
const ACTIONS = new Set(["deny", "grant", "revoke", "withdraw"]);
const DIGEST = /^[0-9a-f]{64}$/;
const SIGNATURE = /^[0-9a-f]{128}$/;
const REFERENCE = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const APPLICATION_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,254}$/;
const WIRE = /^[A-Za-z0-9._~+\-/=]{1,8192}$/;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

const AUTHORITY_FIELDS = Object.freeze([
  "application_ref", "application_authority_sha256", "tenant_id", "application_id",
  "platform", "device_id", "device_revision", "key_revision", "sdk_version",
  "public_client_revision", "public_client_record_sha256", "publication_sha256",
  "publication_bundle_sha256", "configuration_sha256", "policy_id", "policy_version",
  "policy_sha256", "standards_contract_sha256",
]);

const RECEIPT_FIELDS = new Set([
  "schema", "application_ref", "application_authority_sha256", "tenant_sha256",
  "device_id", "device_revision", "request_id", "request_sha256", "operation", "result",
  "result_sha256", "publication_sha256", "configuration_sha256", "policy_sha256",
  "key_id", "key_revision", "completed_at",
]);

function canonicalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("numbers must be finite");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  throw new TypeError("only finite plain JSON is supported");
}

async function sha256Hex(value) {
  const bytes = typeof value === "string" ? encoder.encode(value) : value;
  if (!(bytes instanceof Uint8Array)) throw new TypeError("digest input must be bytes");
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((item) => item.toString(16).padStart(2, "0")).join("");
}

function hex(bytes) {
  return [...bytes].map((item) => item.toString(16).padStart(2, "0")).join("");
}

function unhex(value) {
  if (!SIGNATURE.test(value)) throw new TypeError("signature is invalid");
  return Uint8Array.from(value.match(/.{2}/g), (item) => Number.parseInt(item, 16));
}

function decodeBase64URL(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new TypeError("signed payload encoding is invalid");
  }
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  if (binary.length < 1 || binary.length > MAX_RESPONSE_BYTES) throw new RangeError("signed payload is outside its bound");
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function requireDigest(value, label) {
  if (typeof value !== "string" || !DIGEST.test(value)) throw new TypeError(`${label} is invalid`);
  return value;
}

function requireRef(value, label) {
  if (typeof value !== "string" || !REFERENCE.test(value)) throw new TypeError(`${label} is invalid`);
  return value;
}

function requireRevision(value, label, { allowZero = false } = {}) {
  const minimum = allowZero ? 0 : 1;
  if (!Number.isSafeInteger(value) || value < minimum || value > 2_147_483_647) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function requireWireTimestamp(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`${label} is invalid`);
  return value;
}

function closedObject(value, allowed, required, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError(`${label} must be an object`);
  }
  const keys = Object.keys(value);
  if (keys.some((key) => !allowed.has(key)) || [...required].some((key) => !keys.includes(key))) {
    throw new TypeError(`${label} has unknown or missing fields`);
  }
  return value;
}

function validatePrivateKey(privateKey) {
  if (!(privateKey instanceof CryptoKey) || privateKey.type !== "private" || privateKey.extractable !== false || privateKey.algorithm.name !== "Ed25519") {
    throw new TypeError("a non-exported WebCrypto Ed25519 private key is required");
  }
  return privateKey;
}

function validateAuthority(value) {
  const input = closedObject(value, new Set(AUTHORITY_FIELDS), new Set(AUTHORITY_FIELDS), "authority");
  if (!PLATFORMS.has(input.platform)) throw new TypeError("platform is unsupported");
  if (typeof input.application_id !== "string" || !APPLICATION_ID.test(input.application_id)) {
    throw new TypeError("application id is invalid");
  }
  for (const name of ["device_revision", "key_revision", "sdk_version", "public_client_revision", "policy_version"]) {
    requireRevision(input[name], name);
  }
  if (input.sdk_version > 1_000_000) throw new TypeError("sdk_version is invalid");
  for (const name of [
    "application_authority_sha256", "public_client_record_sha256", "publication_sha256",
    "publication_bundle_sha256", "configuration_sha256", "policy_sha256", "standards_contract_sha256",
  ]) requireDigest(input[name], name);
  for (const name of ["application_ref", "tenant_id", "device_id", "policy_id"]) requireRef(input[name], name);
  return Object.freeze(Object.fromEntries(AUTHORITY_FIELDS.map((name) => [name, input[name]])));
}

function normalizeChoices(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 128) throw new TypeError("choices are invalid");
  const seen = new Set();
  const choices = value.map((candidate) => {
    const row = closedObject(
      candidate,
      new Set(["purpose_id", "action", "channel", "vendor_id", "expires_at"]),
      new Set(["purpose_id", "action"]),
      "choice",
    );
    const action = row.action;
    if (!ACTIONS.has(action)) throw new TypeError("choice action is invalid");
    const expiresAt = row.expires_at == null ? null : requireWireTimestamp(row.expires_at, "choice expiry");
    if (expiresAt != null && (action === "revoke" || action === "withdraw")) {
      throw new TypeError("negative choice cannot expire");
    }
    const normalized = {
      purpose_id: requireRef(row.purpose_id, "purpose"),
      action,
      channel: requireRef(row.channel ?? "all", "channel"),
      vendor_id: requireRef(row.vendor_id ?? "all", "vendor"),
      expires_at: expiresAt,
    };
    const identity = `${normalized.purpose_id}\u0000${normalized.channel}\u0000${normalized.vendor_id}`;
    if (seen.has(identity)) throw new TypeError("choice scope repeats");
    seen.add(identity);
    return normalized;
  });
  const compareASCII = (left, right) => left < right ? -1 : left > right ? 1 : 0;
  choices.sort((left, right) =>
    compareASCII(left.purpose_id, right.purpose_id) ||
    compareASCII(left.channel, right.channel) ||
    compareASCII(left.vendor_id, right.vendor_id));
  return choices;
}

async function normalizeSignals(value) {
  const allowed = new Set([
    "gpc", "do_not_sell_or_share", "tcf_string", "tcf_string_sha256", "gpp_string",
    "gpp_string_sha256", "standards_contract_sha256", "purposes",
  ]);
  const row = closedObject(
    value,
    allowed,
    new Set(["gpc", "do_not_sell_or_share", "standards_contract_sha256", "purposes"]),
    "privacy signals",
  );
  if (typeof row.gpc !== "boolean" || typeof row.do_not_sell_or_share !== "boolean") {
    throw new TypeError("privacy signal flags are invalid");
  }
  if (!Array.isArray(row.purposes) || row.purposes.length < 1 || row.purposes.length > 128) {
    throw new TypeError("privacy signal purposes are invalid");
  }
  const purposes = [...new Set(row.purposes.map((item) => requireRef(item, "purpose")))].sort();
  if (purposes.length !== row.purposes.length) throw new TypeError("privacy signal purposes repeat");
  const result = {
    gpc: row.gpc,
    do_not_sell_or_share: row.do_not_sell_or_share,
    standards_contract_sha256: requireDigest(row.standards_contract_sha256, "standards contract"),
    purposes,
  };
  for (const name of ["tcf", "gpp"]) {
    const wire = row[`${name}_string`];
    const digest = row[`${name}_string_sha256`];
    if ((wire == null) !== (digest == null)) throw new TypeError(`${name} signal is incomplete`);
    if (wire != null) {
      if (typeof wire !== "string" || !WIRE.test(wire)) throw new TypeError(`${name} signal is outside its bound`);
      const exactDigest = requireDigest(digest, `${name} digest`);
      if (await sha256Hex(wire) !== exactDigest) throw new TypeError(`${name} digest changed`);
      result[`${name}_string`] = wire;
      result[`${name}_string_sha256`] = exactDigest;
    }
  }
  if (!row.gpc && !row.do_not_sell_or_share && result.tcf_string == null && result.gpp_string == null) {
    throw new TypeError("at least one privacy signal is required");
  }
  return result;
}

async function normalizeOperationPayload(operation, value) {
  if (!OPERATIONS.has(operation)) throw new TypeError("operation is unsupported");
  if (operation === "configuration") {
    closedObject(value, new Set(), new Set(), "configuration payload");
    return {};
  }
  if (operation === "bootstrap_profile") {
    const fields = new Set(["subject_sha256", "profile_credential_sha256", "idempotency_key"]);
    const row = closedObject(value, fields, fields, "bootstrap payload");
    return {
      subject_sha256: requireDigest(row.subject_sha256, "subject"),
      profile_credential_sha256: requireDigest(row.profile_credential_sha256, "profile capability"),
      idempotency_key: requireRef(row.idempotency_key, "idempotency key"),
    };
  }
  if (operation === "current_preferences") {
    const fields = new Set(["profile_credential_sha256"]);
    const row = closedObject(value, fields, fields, "current preferences payload");
    return { profile_credential_sha256: requireDigest(row.profile_credential_sha256, "profile capability") };
  }
  if (operation === "record_preferences") {
    const fields = new Set(["profile_credential_sha256", "expected_revision", "idempotency_key", "choices"]);
    const row = closedObject(value, fields, fields, "preference payload");
    return {
      profile_credential_sha256: requireDigest(row.profile_credential_sha256, "profile capability"),
      expected_revision: requireRevision(row.expected_revision, "expected revision", { allowZero: true }),
      idempotency_key: requireRef(row.idempotency_key, "idempotency key"),
      choices: normalizeChoices(row.choices),
    };
  }
  if (operation === "privacy_signals") {
    const fields = new Set(["profile_credential_sha256", "expected_revision", "idempotency_key", "signals"]);
    const row = closedObject(value, fields, fields, "privacy signal payload");
    return {
      profile_credential_sha256: requireDigest(row.profile_credential_sha256, "profile capability"),
      expected_revision: requireRevision(row.expected_revision, "expected revision", { allowZero: true }),
      idempotency_key: requireRef(row.idempotency_key, "idempotency key"),
      signals: await normalizeSignals(row.signals),
    };
  }
  if (operation === "link_profile") {
    const fields = new Set([
      "profile_credential_sha256", "target_profile_credential_sha256",
      "pairing_authorization_sha256", "scope", "idempotency_key",
    ]);
    const row = closedObject(value, fields, fields, "profile link payload");
    const source = requireDigest(row.profile_credential_sha256, "profile capability");
    const target = requireDigest(row.target_profile_credential_sha256, "target profile capability");
    if (source === target || !new Set(["device", "household"]).has(row.scope)) {
      throw new TypeError("profile link is invalid");
    }
    return {
      profile_credential_sha256: source,
      target_profile_credential_sha256: target,
      pairing_authorization_sha256: requireDigest(row.pairing_authorization_sha256, "pairing authorization"),
      scope: row.scope,
      idempotency_key: requireRef(row.idempotency_key, "idempotency key"),
    };
  }
  if (operation === "rights_request") {
    const fields = new Set(["profile_credential_sha256", "rights", "expected_revision", "idempotency_key"]);
    const row = closedObject(value, fields, fields, "rights request payload");
    if (!Array.isArray(row.rights) || row.rights.length < 1 || new Set(row.rights).size !== row.rights.length ||
        !row.rights.every((item) => RIGHTS.has(item)) || row.expected_revision !== 0) {
      throw new TypeError("rights request is invalid");
    }
    return {
      profile_credential_sha256: requireDigest(row.profile_credential_sha256, "profile capability"),
      rights: [...row.rights].sort(),
      expected_revision: 0,
      idempotency_key: requireRef(row.idempotency_key, "idempotency key"),
    };
  }
  const fields = new Set(["profile_credential_sha256", "evidence_sha256", "idempotency_key"]);
  const row = closedObject(value, fields, fields, "profile revocation payload");
  return {
    profile_credential_sha256: requireDigest(row.profile_credential_sha256, "profile capability"),
    evidence_sha256: requireDigest(row.evidence_sha256, "revocation evidence"),
    idempotency_key: requireRef(row.idempotency_key, "idempotency key"),
  };
}

export class WebCryptoReceiptVerifier {
  constructor(trustedPublicKeys) {
    if (!trustedPublicKeys || typeof trustedPublicKeys !== "object") throw new TypeError("receipt trust roots are unavailable");
    this.trustedPublicKeys = new Map(Object.entries(trustedPublicKeys));
  }

  async verify(response, expected) {
    if (!(response instanceof Uint8Array) || response.byteLength < 1 || response.byteLength > MAX_RESPONSE_BYTES) {
      throw new RangeError("response is outside its bound");
    }
    const wrapper = JSON.parse(decoder.decode(response));
    const signedBytes = decodeBase64URL(wrapper.signed_payload_b64url);
    const body = JSON.parse(decoder.decode(signedBytes));
    closedObject(body, RECEIPT_FIELDS, RECEIPT_FIELDS, "receipt");
    if (body.schema !== "lightwork.native-consent-receipt.v1" || !OPERATIONS.has(body.operation)) {
      throw new TypeError("receipt contract is invalid");
    }
    const keyID = requireRef(body.key_id, "receipt key id");
    const keyRevision = requireRevision(body.key_revision, "receipt key revision");
    const trustRef = `${keyID}:${keyRevision}`;
    const publicKey = this.trustedPublicKeys.get(trustRef) ?? (keyRevision === 1 ? this.trustedPublicKeys.get(keyID) : null);
    if (!(publicKey instanceof CryptoKey) || publicKey.type !== "public" || publicKey.algorithm.name !== "Ed25519") {
      throw new TypeError("receipt trust root is unavailable");
    }
    if (!await crypto.subtle.verify("Ed25519", publicKey, unhex(wrapper.signature_hex), signedBytes)) {
      throw new Error("receipt signature did not verify");
    }
    // The detached signed bytes cover the result object itself. The digest is
    // validated as metadata but not re-serialized in JavaScript, avoiding
    // Python/ECMAScript float spelling differences in legitimate results.
    requireDigest(body.result_sha256, "result digest");
    const exact = {
      application_ref: expected.authority.application_ref,
      application_authority_sha256: expected.authority.application_authority_sha256,
      tenant_sha256: await sha256Hex(expected.authority.tenant_id),
      device_id: expected.authority.device_id,
      device_revision: expected.authority.device_revision,
      request_id: expected.requestId,
      request_sha256: expected.requestSHA256,
      operation: expected.operation,
      publication_sha256: expected.authority.publication_sha256,
      configuration_sha256: expected.authority.configuration_sha256,
      policy_sha256: expected.authority.policy_sha256,
    };
    for (const [name, value] of Object.entries(exact)) {
      if (body[name] !== value) throw new Error("receipt authority was rebound");
    }
    requireWireTimestamp(body.completed_at, "receipt completion");
    return body;
  }
}

export class LightworkCTVConsentClient {
  constructor({
    authority,
    privateKey,
    transport,
    outbox,
    receiptVerifier,
    authorityRefresher,
    clock = () => Date.now() / 1000,
  }) {
    this.authority = validateAuthority(authority);
    this.privateKey = validatePrivateKey(privateKey);
    if (!transport || typeof transport.post !== "function") throw new TypeError("transport is unavailable");
    const outboxMethods = ["append", "due", "acknowledge", "retry", "removeAll", "reserveCounter", "replace"];
    if (!outbox || !outboxMethods.every((name) => typeof outbox[name] === "function")) {
      throw new TypeError("transactional bounded durable outbox is unavailable");
    }
    if (!receiptVerifier || typeof receiptVerifier.verify !== "function") {
      throw new TypeError("receipt verification authority is unavailable");
    }
    if (!authorityRefresher || typeof authorityRefresher.refresh !== "function") {
      throw new TypeError("attested authority refresh is unavailable");
    }
    this.transport = transport;
    this.outbox = outbox;
    this.receiptVerifier = receiptVerifier;
    this.authorityRefresher = authorityRefresher;
    this.clock = clock;
  }

  replaceAuthority(next, nextPrivateKey = null) {
    const authority = validateAuthority(next);
    for (const name of ["tenant_id", "application_ref", "application_id", "device_id", "platform"]) {
      if (authority[name] !== this.authority[name]) throw new Error("authority changed identity");
    }
    if (authority.device_revision < this.authority.device_revision || authority.key_revision < this.authority.key_revision) {
      throw new Error("authority rolled back");
    }
    if (authority.device_revision === this.authority.device_revision &&
        canonicalize(authority) !== canonicalize(this.authority)) {
      throw new Error("authority changed without a device revision");
    }
    if (authority.key_revision !== this.authority.key_revision && nextPrivateKey == null) {
      throw new Error("rotated authority requires its new private key");
    }
    if (authority.key_revision === this.authority.key_revision && nextPrivateKey != null) {
      throw new Error("a replacement private key requires a key revision");
    }
    if (nextPrivateKey != null) this.privateKey = validatePrivateKey(nextPrivateKey);
    this.authority = authority;
  }

  async refreshAuthority({ admittedSDKVersion = null } = {}) {
    if (admittedSDKVersion != null) {
      requireRevision(admittedSDKVersion, "admitted SDK version");
      if (admittedSDKVersion > 1_000_000) throw new TypeError("admitted SDK version is invalid");
    }
    const current = this.authority;
    // The host refresher obtains new platform attestation over the existing
    // install subject and device key, uses a new nonce, sends no ambient
    // credentials, and validates the nested authority/device response before
    // returning the flattened authority used by the signing client.
    const next = validateAuthority(await this.authorityRefresher.refresh({
      path: "/api/v1/public/consent/native/refresh",
      currentAuthority: current,
      admittedSDKVersion,
      maximumRequestBytes: MAX_PAYLOAD_BYTES,
      maximumResponseBytes: MAX_RESPONSE_BYTES,
    }));
    if (this.authority !== current) throw new Error("authority refresh raced");
    if (next.device_revision !== current.device_revision + 1 ||
        next.key_revision !== current.key_revision) {
      throw new Error("authority refresh returned an invalid revision");
    }
    const expectedSDK = admittedSDKVersion ?? current.sdk_version;
    if (next.sdk_version !== expectedSDK) throw new Error("authority refresh rebound the SDK version");
    this.replaceAuthority(next);
    return this.authority;
  }

  configuration() { return this.queue("configuration", {}); }
  bootstrapProfile({ subjectSHA256, profileCredentialSHA256, idempotencyKey }) {
    return this.queue("bootstrap_profile", {
      subject_sha256: subjectSHA256,
      profile_credential_sha256: profileCredentialSHA256,
      idempotency_key: idempotencyKey,
    }, idempotencyKey);
  }
  currentPreferences(profileCredentialSHA256) {
    return this.queue("current_preferences", { profile_credential_sha256: profileCredentialSHA256 });
  }
  preferences({ profileCredentialSHA256, expectedRevision, choices, idempotencyKey }) {
    return this.queue("record_preferences", {
      profile_credential_sha256: profileCredentialSHA256,
      expected_revision: expectedRevision,
      idempotency_key: idempotencyKey,
      choices,
    }, idempotencyKey);
  }
  privacySignals({ profileCredentialSHA256, expectedRevision, signals, idempotencyKey }) {
    return this.queue("privacy_signals", {
      profile_credential_sha256: profileCredentialSHA256,
      expected_revision: expectedRevision,
      idempotency_key: idempotencyKey,
      signals,
    }, idempotencyKey);
  }
  linkProfile({ profileCredentialSHA256, targetProfileCredentialSHA256, pairingAuthorizationSHA256, scope, idempotencyKey }) {
    return this.queue("link_profile", {
      profile_credential_sha256: profileCredentialSHA256,
      target_profile_credential_sha256: targetProfileCredentialSHA256,
      pairing_authorization_sha256: pairingAuthorizationSHA256,
      scope,
      idempotency_key: idempotencyKey,
    }, idempotencyKey);
  }
  rightsRequest({ profileCredentialSHA256, rights, idempotencyKey }) {
    return this.queue("rights_request", {
      profile_credential_sha256: profileCredentialSHA256,
      rights,
      expected_revision: 0,
      idempotency_key: idempotencyKey,
    }, idempotencyKey);
  }
  revokeProfile({ profileCredentialSHA256, evidenceSHA256, idempotencyKey }) {
    return this.queue("revoke_profile", {
      profile_credential_sha256: profileCredentialSHA256,
      evidence_sha256: evidenceSHA256,
      idempotency_key: idempotencyKey,
    }, idempotencyKey);
  }

  async queue(operation, payload, downstreamIdempotencyKey = null) {
    const normalized = await normalizeOperationPayload(operation, payload);
    const createdAt = requireWireTimestamp(Math.floor(this.clock()), "creation time");
    const message = await this.#materialize(
      `native-${crypto.randomUUID().toLowerCase()}`,
      operation,
      normalized,
      downstreamIdempotencyKey,
      createdAt,
    );
    await this.outbox.append(message);
    return message.requestId;
  }

  async drain(limit = 32) {
    const boundedLimit = Number.isSafeInteger(limit) ? Math.max(1, Math.min(limit, 128)) : 32;
    for (const original of await this.outbox.due(boundedLimit)) {
      let message = original;
      try {
        this.#validateQueued(message);
        const now = requireWireTimestamp(Math.floor(this.clock()), "drain time");
        if (message.expiresAt < now ||
            message.deviceRevision !== this.authority.device_revision ||
            message.applicationAuthoritySHA256 !== this.authority.application_authority_sha256) {
          const replacement = await this.#materialize(
            `native-${crypto.randomUUID().toLowerCase()}`,
            message.operation,
            await normalizeOperationPayload(message.operation, message.payload),
            message.downstreamIdempotencyKey,
            message.createdAt,
          );
          await this.outbox.replace(message.requestId, message.requestSHA256, replacement);
          message = replacement;
        }
        const response = await this.transport.post(
          "/api/v1/public/consent/native/dispatch",
          message.signedEnvelope,
          MAX_RESPONSE_BYTES,
        );
        await this.receiptVerifier.verify(response, {
          authority: this.authority,
          requestId: message.requestId,
          requestSHA256: message.requestSHA256,
          operation: message.operation,
        });
        await this.outbox.acknowledge(message.requestId, message.requestSHA256);
      } catch (error) {
        await this.outbox.retry(message.requestId, await sha256Hex(error?.constructor?.name || "Error"));
      }
    }
  }

  async revokeLocalDevice() { await this.outbox.removeAll(this.authority.device_id); }

  #validateQueued(message) {
    if (!message || message.deviceId !== this.authority.device_id || !REFERENCE.test(message.requestId) ||
        !DIGEST.test(message.requestSHA256) || !(message.signedEnvelope instanceof Uint8Array) ||
        message.signedEnvelope.byteLength < 1 || message.signedEnvelope.byteLength > MAX_PAYLOAD_BYTES ||
        !OPERATIONS.has(message.operation) || !Number.isSafeInteger(message.expiresAt) ||
        !Number.isSafeInteger(message.deviceRevision) || message.deviceRevision < 1 ||
        !DIGEST.test(message.applicationAuthoritySHA256)) {
      throw new TypeError("queued consent envelope is invalid");
    }
  }

  async #materialize(requestId, operation, payload, downstreamIdempotencyKey, createdAt) {
    const counter = await this.outbox.reserveCounter(this.authority.device_id);
    if (!Number.isSafeInteger(counter) || counter < 1) throw new Error("durable monotonic counter is unavailable");
    const issuedAt = requireWireTimestamp(Math.floor(this.clock()), "issue time");
    const body = {
      schema: "lightwork.native-consent-envelope.v1",
      ...this.authority,
      request_id: requireRef(requestId, "request id"),
      counter,
      issued_at: issuedAt,
      expires_at: issuedAt + ENVELOPE_TTL_SECONDS,
      operation,
      payload,
    };
    const canonical = encoder.encode(canonicalize(body));
    if (canonical.byteLength < 1 || canonical.byteLength > MAX_PAYLOAD_BYTES) throw new RangeError("envelope is outside its bound");
    const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", this.privateKey, canonical));
    if (signature.byteLength !== 64) throw new Error("signer failed");
    const signedEnvelope = encoder.encode(canonicalize({ ...body, signature_hex: hex(signature) }));
    if (signedEnvelope.byteLength > MAX_PAYLOAD_BYTES) throw new RangeError("signed envelope is outside its bound");
    return Object.freeze({
      requestId: body.request_id,
      operation,
      payload,
      downstreamIdempotencyKey,
      createdAt,
      deviceId: this.authority.device_id,
      deviceRevision: this.authority.device_revision,
      applicationAuthoritySHA256: this.authority.application_authority_sha256,
      expiresAt: body.expires_at,
      requestSHA256: await sha256Hex(canonical),
      signedEnvelope,
    });
  }
}

export const _conformance = Object.freeze({
  canonicalize,
  normalizeChoices,
  normalizeOperationPayload,
  normalizeSignals,
  sha256Hex,
});
