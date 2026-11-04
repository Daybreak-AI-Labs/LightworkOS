// Run with: node --test packages/maverick-dashboard/tests/js/governance_json_response_contracts.test.js
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");
const { fetchHelpers } = require("./_shell");

// The third-party lifecycle, collaboration and intelligence pages now load
// their records through lightwork-record-workflows.js (LwRecords.call), which
// fails closed on malformed JSON and turns errors into plain sentences; their
// behaviour is covered by the page workflow tests.
const JSON_CLIENTS = [
  ["consent_delivery.html", "call", ["/probe"]],
  ["consent_experiments.html", "call", ["/probe"]],
  ["consent_public_clients.html", "call", ["/probe"]],
  ["consent_publishing.html", "call", ["/probe"]],
  ["policy_publication_links.html", "call", ["/probe"]],
  ["consent_scan_notice_proposals.html", "call", ["/probe"]],
  ["consent_profile_data.html", "request", ["/probe"]],
  ["data_use_governance.html", "call", ["/probe"]],
  ["consent_scan_inventory.html", "call", ["/probe"]],
  ["data_use_providers.html", "call", ["/probe"]],
  ["consent_preferences.html", "call", ["/probe"]],
  ["ekko.html", "request", ["/probe"]],
];

// Pages rebuilt for non-technical readers say the same thing in plain words.
const UNREADABLE_REPLY = "Lightwork's reply could not be read. Refresh the page and try again.";
const MALFORMED_MESSAGE = {
  "ekko.html": "Lightwork sent back a reply this page could not read. Try again.",
  "compliance_scoping.html": UNREADABLE_REPLY,
  "compliance_scope_actions.html": UNREADABLE_REPLY,
  "privacy_rights_consumer_delivery.html": UNREADABLE_REPLY,
  "privacy_notice_governance.html": UNREADABLE_REPLY,
  "privacy_rights_orchestration.html": UNREADABLE_REPLY,
};

const TEXT_CLIENTS = [
  "consumer_trust_center_authority.html",
  "compliance_scoping.html",
  "compliance_scope_actions.html",
  "privacy_rights_consumer_delivery.html",
  "privacy_notice_governance.html",
  "privacy_rights_orchestration.html",
].map((file) => [file, "run", ["GET", "/probe", {}]]);

function extractScript(file, functionName) {
  const template = fs.readFileSync(
    path.resolve(__dirname, "../../maverick_dashboard/templates", file),
    "utf8",
  );
  const scripts = [...template.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/gi)].map(
    (match) => {
      const external = match[1].match(/\bsrc\s*=\s*["'](\/static\/[^"']+)["']/i);
      if (!external) return match[2];
      return fs.readFileSync(
        path.resolve(__dirname, "../../maverick_dashboard", external[1].slice(1)),
        "utf8",
      );
    },
  );
  const selected = scripts.find((source) =>
    new RegExp(`async\\s+function\\s+${functionName}\\b`).test(source)
  );
  assert.ok(selected, `${file} must contain the ${functionName} client`);
  let source = selected.replace(
    /\{\{\s*"true"\s*if\s*consent_scan_notice_proposals_enabled\s*else\s*"false"\s*\}\}/g,
    "false",
  );
  if (file === "ekko.html") {
    source = source.replace(/\s*renderStatus\(initial\);\s*refresh\(\);/, "\n");
  }
  return source;
}

function instrument(source, functionName, file) {
  const classicClose = source.lastIndexOf("})();");
  const alternateClose = source.lastIndexOf("}());");
  const windowClose = source.lastIndexOf("}(typeof window");
  const close = Math.max(classicClose, alternateClose, windowClose);
  if (close === -1) {
    return `${source}\nglobalThis.__requestUnderTest=${functionName};\n`;
  }
  return `${source.slice(0, close)}globalThis.__requestUnderTest=${functionName};\n${source.slice(close)}`;
}

function streamedJsonBody(text) {
  const bytes = new TextEncoder().encode(text);
  return {
    headers: {
      get(name) {
        return String(name).toLowerCase() === "content-length"
          ? String(bytes.byteLength)
          : null;
      },
    },
    body: {
      getReader() {
        let delivered = false;
        return {
          async read() {
            if (delivered) return { done: true, value: undefined };
            delivered = true;
            return { done: false, value: bytes };
          },
          async cancel() {},
        };
      },
      async cancel() {},
    },
  };
}

function harness(file, functionName, args) {
  const elements = new Map();
  const listeners = new Map();
  function element(id) {
    if (elements.has(id)) return elements.get(id);
    const controls = new Proxy({}, {
      get(_target, name) { return element(`${id}:${String(name)}`); },
    });
    const item = {
      id,
      value: "status",
      textContent: "",
      innerHTML: "",
      checked: false,
      disabled: false,
      hidden: false,
      selectedIndex: 0,
      dataset: { method: "GET", path: "/status" },
      options: [{ dataset: { method: "GET", path: "/status" } }],
      elements: controls,
      classList: { add() {}, remove() {}, toggle() {} },
      addEventListener(type, listener) { listeners.set(`${id}:${type}`, listener); },
      querySelectorAll() { return []; },
      querySelector() { return element(`${id}:query`); },
      replaceChildren() {},
      add() {},
      appendChild() {},
      append() {},
      setAttribute() {},
      removeAttribute() {},
      focus() {},
      closest() { return item; },
    };
    elements.set(id, item);
    return item;
  }

  const validBootResponse = {
    ok: true,
    status: 200,
    ...streamedJsonBody("{}"),
    async json() { return {}; },
    async text() { return "{}"; },
  };
  const helpers = fetchHelpers(() => context.fetch);
  const context = {
    console,
    crypto: webcrypto,
    TextEncoder,
    TextDecoder,
    Uint8Array,
    document: {
      readyState: "complete",
      getElementById: element,
      querySelector() { return element("document:query"); },
      querySelectorAll() { return []; },
      createElement() { return element("document:created"); },
      // Page-level event wiring (draft loaded, recording status) is inert here.
      addEventListener(type, listener) { listeners.set(`document:${type}`, listener); },
    },
    // agents.html watches its drafts list for changes; nothing changes here.
    MutationObserver: class { observe() {} disconnect() {} },
    // agents.html builds its AI model choices as <option> elements.
    Option: class { constructor(text, value) { this.text = text; this.value = value; this.disabled = false; } },
    window: {
      confirm() { return true; },
      addEventListener() {},
      // The shell's fetch helper, sending through the context's fetch.
      mvFetchJSON: (...args) => helpers.mvFetchJSON(...args),
      // Pages show a server message only when it is already a plain sentence.
      mvPlainDetail(detail) { return typeof detail === "string" && /^[A-Z][^_{}<>]*[.!?]$/.test(detail) ? detail : ""; },
    },
    confirm() { return true; },
    mvToast() {},
    // agents.html shares these page helpers from its first script block.
    mountToolPicks() {},
    mountToolPick() {},
    plainError(_failure, what) { return "Could not " + what + ". Please try again."; },
    fetch: async () => validBootResponse,
    setTimeout() { return 0; },
    clearTimeout() {},
  };
  vm.createContext(context);
  if (file === "consent_preferences.html") {
    element("cp-policy-form").elements.purposes.value = '{"analytics":"consent"}';
    vm.runInContext(fs.readFileSync(path.resolve(__dirname,
      "../../maverick_dashboard/static/lightwork-consent-policy-editor.js"), "utf8"), context);
  }
  const source = instrument(extractScript(file, functionName), functionName, file);
  vm.runInContext(source, context, { filename: file });
  // The consent pages' clients are the shared consent client (CW.client),
  // loaded after the page script so the page itself does not start here.
  if (/LightworkConsentWorkbench\.client\(/.test(source)) {
    vm.runInContext(fs.readFileSync(path.resolve(__dirname,
      "../../maverick_dashboard/static/lightwork-consent-workbench.js"), "utf8"), context);
  }
  return {
    invoke(response) {
      context.fetch = async () => response;
      context.__args = args;
      return vm.runInContext("__requestUnderTest(...__args)", context);
    },
    element,
  };
}

for (const [file, functionName, args] of [...JSON_CLIENTS, ...TEXT_CLIENTS]) {
  const usesText = functionName === "run";

  test(`${file} rejects malformed 2xx without exposing its body`, async () => {
    const secret = `private-response-content-for-${file}`;  // pragma: allowlist secret
    const response = {
      ok: true,
      status: 200,
      ...streamedJsonBody(secret),
      async json() { throw new Error(secret); },
      async text() { return secret; },
    };

    await assert.rejects(harness(file, functionName, args).invoke(response), (error) => {
      assert.equal(error.message, MALFORMED_MESSAGE[file] || "The reply from the server could not be read. Try again.");
      assert.equal(error.message.includes(secret), false);
      return true;
    });
  });

  test(`${file} preserves a valid JSON error detail`, async () => {
    // A readable sentence (pages filter out code-like server text).
    const detail = `Reviewed conflict for ${file.replace(/[^a-z]+/g, " ").trim()}.`;
    const response = {
      ok: false,
      status: 409,
      ...streamedJsonBody(JSON.stringify({ detail })),
      async json() { return { detail }; },
      async text() { return JSON.stringify({ detail }); },
    };

    await assert.rejects(harness(file, functionName, args).invoke(response), (error) => {
      assert.equal(error.message, detail);
      return true;
    });
    assert.equal(usesText || functionName === "call" || functionName === "request", true);
  });
}

// Plain-language pages: failures read as fixed sentences. They still fail
// closed on malformed 2xx replies and never echo a response body or a raw
// server detail.
test("agents.html rejects malformed 2xx without exposing its body", async () => {
  const secret = "private-response-content-for-agents";  // pragma: allowlist secret
  const response = { ok: true, status: 200, ...streamedJsonBody(secret),
    async json() { throw new Error(secret); }, async text() { return secret; } };
  await assert.rejects(harness("agents.html", "call", ["GET", "/probe"]).invoke(response), (error) => {
    assert.match(error.message, /could not be confirmed/);
    assert.equal(error.message.includes(secret), false);
    return true;
  });
});

test("agents.html turns an error reply into a plain sentence", async () => {
  const detail = "Reviewed conflict for agents.html.";
  const response = { ok: false, status: 409, ...streamedJsonBody(JSON.stringify({ detail })),
    async json() { return { detail }; }, async text() { return JSON.stringify({ detail }); } };
  await assert.rejects(harness("agents.html", "call", ["GET", "/probe"]).invoke(response), (error) => {
    assert.equal(error.message.includes(detail), false);
    assert.match(error.message, /^Could not /);
    return true;
  });
});

test("redact.html marks malformed 2xx as failed without exposing its body", async () => {
  const secret = "private-redaction-response-content";  // pragma: allowlist secret
  const client = harness("redact.html", "preview", [null]);
  await client.invoke({
    ok: true,
    status: 200,
    async json() { throw new Error(secret); },
  });

  const message = client.element("proof-badge").textContent;
  assert.equal(message, "Could not read the result. Try again.");
  assert.equal(message.includes(secret), false);
  assert.equal(client.element("proof-badge").className, "badge failure");
});

test("redact.html shows a plain sentence instead of the server detail", async () => {
  const client = harness("redact.html", "preview", [null]);
  await client.invoke({
    ok: false,
    status: 422,
    async json() { return { detail: "Reviewed redaction error." }; },
  });

  assert.equal(client.element("proof-badge").textContent, "Could not check the text. Try again.");
  assert.equal(client.element("proof-badge").className, "badge failure");
});
