// Run with: node --test packages/maverick-dashboard/tests/js/agent_control_plane_client.test.js
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

class FakeElement {
  constructor(tagName, ownerDocument) {
    this.tagName = String(tagName || "div").toUpperCase();
    this.ownerDocument = ownerDocument;
    this.children = [];
    this.parentNode = null;
    this.dataset = {};
    this.attributes = new Map();
    this.listeners = new Map();
    this.disabled = false;
    this.className = "";
    this.type = "";
    this.value = "";
    this._textContent = "";
  }

  appendChild(child) {
    child.parentNode = this;
    this.children.push(child);
    return child;
  }

  set textContent(value) {
    this._textContent = String(value);
    if (value === "") {
      this.children.forEach((child) => { child.parentNode = null; });
      this.children = [];
    }
  }

  get textContent() {
    return this._textContent;
  }

  get firstChild() {
    return this.children[0] || null;
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  removeAttribute(name) {
    this.attributes.delete(name);
  }

  addEventListener(name, handler) {
    this.listeners.set(name, handler);
  }

  contains(candidate) {
    if (candidate === this) return true;
    return this.children.some((child) => child.contains(candidate));
  }

  querySelectorAll(selector) {
    const found = [];
    const visit = (element) => {
      const isButtonPrincipal = selector === "button[data-acp-principal]" &&
        element.tagName === "BUTTON" && element.dataset.acpPrincipal !== undefined;
      const isButtonReadiness = selector === "button[data-requires-control-plane]" &&
        element.tagName === "BUTTON" && element.dataset.requiresControlPlane !== undefined;
      const isOptionReadiness = selector === "option[data-requires-control-plane]" &&
        element.tagName === "OPTION" && element.dataset.requiresControlPlane !== undefined;
      if (isButtonPrincipal || isButtonReadiness || isOptionReadiness) found.push(element);
      element.children.forEach(visit);
    };
    this.children.forEach(visit);
    return found;
  }

  focus() {
    this.ownerDocument.activeElement = this;
  }
}

function jsonResponse(payload, ok = true, status = ok ? 200 : 503) {
  const body = JSON.stringify(payload);
  return {
    ok,
    status,
    headers: {
      get: (name) => name.toLowerCase() === "content-length"
        ? String(Buffer.byteLength(body, "utf8"))
        : null,
    },
    text: async () => body,
  };
}

const CAPTURED_AT = 123.5;

function statusPayload(overrides = {}) {
  const base = {
    schema: "lightwork.agent-control-plane-status.v1",
    captured_at: CAPTURED_AT,
    enabled: true,
    halted: false,
    halt_scope: "observed-process-and-configured-authorities",
    native: { principals: 2, running_goals: 2, suspended: 1, contained: 0 },
    external: { agents: 1, active: 0, suspended: 0, contained: 1 },
    trust_enforced: true,
    external_agents_enabled: true,
  };
  return {
    ...base,
    ...overrides,
    native: { ...base.native, ...(overrides.native || {}) },
    external: { ...base.external, ...(overrides.external || {}) },
  };
}

function rosterPayload() {
  return {
    captured_at: CAPTURED_AT,
    total: 3,
    count: 3,
    offset: 0,
    limit: 100,
    has_more: false,
    next_offset: null,
    items: [
      {
        principal: "agent:contained",
        kind: "external",
        state: "contained",
        running_goals: 0,
        revoked: true,
        contained: true,
        deny_tools: [],
        allow_tools: ["review"],
        max_wall_seconds: 45,
      },
      {
        principal: "user:suspended",
        kind: "native",
        state: "suspended",
        running_goals: 1,
        revoked: true,
        contained: false,
      },
      {
        principal: "user:active",
        kind: "native",
        state: "running",
        running_goals: 1,
        revoked: false,
        contained: false,
      },
    ],
  };
}

function addOption(document, select, value, requiresRuntime) {
  const option = document.createElement("option");
  option.value = value;
  option.disabled = Boolean(requiresRuntime);
  if (requiresRuntime) option.dataset.requiresControlPlane = "true";
  select.appendChild(option);
}

function harness({
  statusOk = true,
  enabled = true,
  nativeContained = 0,
  haltScope = "local",
  mvForm = async () => null,
  mvConfirm = async () => false,
  rosterFetch = null,
  principalFetch = null,
  haltFetch = null,
  requestTimeoutMs = null,
  formValues = {},
} = {}) {
  const elements = new Map();
  const document = {
    activeElement: null,
    createElement(tagName) {
      return new FakeElement(tagName, document);
    },
    getElementById(id) {
      return elements.get(id) || null;
    },
  };
  const define = (id, tagName = "div") => {
    const element = document.createElement(tagName);
    elements.set(id, element);
    return element;
  };
  const root = define("acp-root");
  root.dataset.apiBase = "/api/v1/agent-control-plane";
  root.dataset.canOperate = "true";
  root.dataset.canAudit = "true";
  root.dataset.canAdmin = "true";
  root.dataset.canHalt = "true";
  root.dataset.haltScope = haltScope;
  if (requestTimeoutMs !== null) {
    root.dataset.requestTimeoutMs = String(requestTimeoutMs);
  }

  [
    "acp-state", "acp-output", "acp-operation-state", "acp-rows",
    "acp-roster-title", "acp-roster-page", "acp-native", "acp-external",
    "acp-suspended", "acp-health-title", "acp-health-detail",
  ].forEach((id) => define(id));
  [
    "acp-roster-prev", "acp-roster-next", "acp-clear-halt", "acp-refresh",
    "acp-load-roster", "acp-verb-submit",
  ].forEach((id) => define(id, "button"));
  ["acp-verb-controls", "acp-attenuate-controls", "acp-halt-controls"]
    .forEach((id) => define(id, "fieldset"));
  ["acp-verb-form", "acp-attenuate-form", "acp-halt-form"]
    .forEach((id) => define(id, "form"));
  elements.get("acp-verb-form").formValues = {
    principal: "user:active", verb: "suspend", reason: "incident response",
    ...(formValues.verb || {}),
  };
  elements.get("acp-attenuate-form").formValues = {
    principal: "agent:contained", deny_tools: "", max_risk: "",
    max_dollars: "", max_wall_seconds: "", ...(formValues.attenuate || {}),
  };
  elements.get("acp-halt-form").formValues = {
    reason: "incident response", ...(formValues.halt || {}),
  };
  const select = define("acp-verb-select", "select");
  ["suspend", "resume", "contain", "release"].forEach(
    (value) => addOption(document, select, value, true),
  );
  addOption(document, select, "ledger", false);
  select.value = "suspend";

  const requests = [];
  let haltActive = false;
  const context = {
    console,
    document,
    FormData: class {
      constructor(element) {
        this.values = element && element.formValues ? element.formValues : {};
      }
      get(name) {
        return Object.prototype.hasOwnProperty.call(this.values, name)
          ? this.values[name]
          : "";
      }
    },
    fetch: async (url, options) => {
      requests.push({ url, options });
      if (url.startsWith("/api/v1/agent-control-plane/snapshot?limit=100&offset=")) {
        if (rosterFetch) return rosterFetch(url, options);
        return statusOk
          ? jsonResponse({
            status: statusPayload({
              enabled,
              halted: haltActive,
              native: { contained: nativeContained },
            }),
            agents: rosterPayload(),
          })
          : jsonResponse({ detail: "control plane dependency is unavailable" }, false);
      }
      if (url === "/api/v1/halt") {
        if (haltFetch) return haltFetch(url, options);
        if (options && options.method === "POST") {
          haltActive = true;
          return jsonResponse({});
        }
        if (options && options.method === "DELETE") {
          haltActive = false;
          return jsonResponse({});
        }
        return jsonResponse({
          active: haltActive,
          scope: haltScope,
          ...(haltScope === "cluster" ? { cluster_halt: haltActive } : {}),
        });
      }
      if (url.includes("/api/v1/agent-control-plane/principals/") && principalFetch) {
        return principalFetch(url, options);
      }
      throw new Error(`unexpected request: ${url}`);
    },
    setTimeout,
    clearTimeout,
    AbortController,
    TextDecoder,
    Uint8Array,
    URLSearchParams,
    mvForm,
    mvConfirm,
  };
  context.window = context;
  vm.createContext(context);
  const source = fs.readFileSync(
    path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-agent-control-plane.js"),
    "utf8",
  );
  vm.runInContext(source, context, { filename: "lightwork-agent-control-plane.js" });
  return { context, document, elements, requests };
}

async function settle() {
  for (let index = 0; index < 8; index += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
}

function actionButtons(row) {
  return row.children[5].children[0].children;
}

test("row actions are mutually exclusive, target-labeled, and focus-restoring", async () => {
  const { document, elements } = harness();
  await settle();
  const rows = elements.get("acp-rows").children;

  assert.deepEqual(actionButtons(rows[0]).map((button) => button.textContent), ["End isolation", "View history"]);
  assert.deepEqual(actionButtons(rows[1]).map((button) => button.textContent), ["Resume", "View history"]);
  assert.deepEqual(
    actionButtons(rows[2]).map((button) => button.textContent),
    ["Pause", "Isolate", "View history"],
  );
  assert.equal(
    actionButtons(rows[2])[0].attributes.get("aria-label"),
    "Pause active",
  );
  assert.match(rows[0].children[4].textContent, /Only these tools: Review/);
  assert.match(rows[0].children[4].textContent, /Time limit: 45 seconds/);

  const oldSuspend = actionButtons(rows[2])[0];
  oldSuspend.focus();
  elements.get("acp-load-roster").listeners.get("click")({
    currentTarget: elements.get("acp-load-roster"),
  });
  await settle();
  assert.notEqual(document.activeElement, oldSuspend);
  assert.equal(document.activeElement.dataset.acpPrincipal, "user:active");
  assert.equal(document.activeElement.dataset.acpVerb, "suspend");
});

test("snapshot failure disables plane mutations while preserving verified halt", async () => {
  const { elements, requests } = harness({ statusOk: false });
  await settle();
  const rows = elements.get("acp-rows").children;

  assert.equal(rows.length, 1);
  assert.match(rows[0].children[0].textContent, /Couldn't load the list/);
  assert.equal(elements.get("acp-attenuate-controls").disabled, true);
  assert.equal(elements.get("acp-halt-controls").disabled, false);
  assert.equal(elements.get("acp-clear-halt").disabled, false);
  assert.equal(elements.get("acp-state").textContent, "Unavailable");
  assert.match(elements.get("acp-health-detail").textContent, /Something went wrong/);
  assert.doesNotMatch(elements.get("acp-health-detail").textContent, /dependency|503|HTTP/);
  assert.ok(requests.some(({ url }) => url.endsWith("/snapshot?limit=100&offset=0")));
});

test("an incomplete status contract fails closed before rendering mutations", async () => {
  const incomplete = statusPayload();
  delete incomplete.trust_enforced;
  const { elements } = harness({
    rosterFetch: async () => jsonResponse({
      status: incomplete,
      agents: rosterPayload(),
    }),
  });
  await settle();

  assert.equal(elements.get("acp-attenuate-controls").disabled, true);
  assert.match(elements.get("acp-health-detail").textContent, /returned something unexpected/);
  assert.match(
    elements.get("acp-rows").children[0].children[0].textContent,
    /Couldn't load the list/,
  );
});

test("status and roster from different scans are rejected", async () => {
  const agents = rosterPayload();
  agents.captured_at = CAPTURED_AT + 1;
  const { elements } = harness({
    rosterFetch: async () => jsonResponse({
      status: statusPayload(),
      agents,
    }),
  });
  await settle();

  assert.equal(elements.get("acp-attenuate-controls").disabled, true);
  assert.match(elements.get("acp-health-detail").textContent, /returned something unexpected/);
});

test("halt authority uncertainty also disables principal mutations", async () => {
  const { elements } = harness({
    haltFetch: async () => jsonResponse(
      { detail: "halt authority is unavailable" }, false, 503,
    ),
  });
  await settle();

  for (const row of elements.get("acp-rows").children) {
    for (const button of actionButtons(row)) {
      assert.equal(button.disabled, button.textContent !== "View history");
    }
  }
  assert.equal(elements.get("acp-attenuate-controls").disabled, true);
  assert.equal(elements.get("acp-halt-controls").disabled, true);
});

test("unverified readiness cannot be bypassed by dispatching a form submit", async () => {
  const { document, elements, requests } = harness({
    mvConfirm: async () => true,
    haltFetch: async () => jsonResponse(
      { detail: "halt authority is unavailable" }, false, 503,
    ),
    formValues: { attenuate: { max_risk: "low" } },
  });
  await settle();

  elements.get("acp-attenuate-form").listeners.get("submit")({
    preventDefault() {},
    currentTarget: elements.get("acp-attenuate-form"),
    submitter: document.createElement("button"),
  });
  await settle();

  assert.match(elements.get("acp-operation-state").textContent, /has not confirmed the current state/);
  assert.equal(requests.some(({ url }) => url.includes("/attenuate")), false);
});

test("a disabled runtime keeps mutation controls fail closed without blocking ledger", async () => {
  const { elements } = harness({ enabled: false });
  await settle();

  for (const row of elements.get("acp-rows").children) {
    for (const button of actionButtons(row)) {
      assert.equal(button.disabled, button.textContent !== "View history");
    }
  }
  assert.equal(elements.get("acp-attenuate-controls").disabled, true);
  assert.equal(elements.get("acp-halt-controls").disabled, false);
  assert.equal(elements.get("acp-state").textContent, "View only");
});

test("reason-dialog cancellation is neutral and duplicate clicks stay single-flight", async () => {
  let formCalls = 0;
  let resolveForm;
  const formResult = new Promise((resolve) => { resolveForm = resolve; });
  const { elements, requests } = harness({
    mvForm: async () => {
      formCalls += 1;
      return formResult;
    },
  });
  await settle();
  const suspend = actionButtons(elements.get("acp-rows").children[2])[0];

  suspend.listeners.get("click")();
  suspend.listeners.get("click")();
  await settle();
  assert.equal(formCalls, 1);
  resolveForm(null);
  await settle();

  assert.equal(requests.filter(({ options }) => options && options.method === "POST").length, 0);
  assert.equal(elements.get("acp-operation-state").textContent, "");
});

test("emergency controls mutate only the hardened halt endpoint and verify with GET", async () => {
  const { document, elements, requests } = harness({ mvConfirm: async () => true });
  await settle();
  const submitter = document.createElement("button");

  elements.get("acp-halt-form").listeners.get("submit")({
    preventDefault() {},
    currentTarget: elements.get("acp-halt-form"),
    submitter,
  });
  await settle();
  assert.ok(requests.some(({ url, options }) =>
    url === "/api/v1/halt" && options && options.method === "POST"));
  assert.match(elements.get("acp-operation-state").textContent, /All agents are stopped/);

  elements.get("acp-clear-halt").listeners.get("click")({
    currentTarget: elements.get("acp-clear-halt"),
  });
  await settle();
  assert.ok(requests.some(({ url, options }) =>
    url === "/api/v1/halt" && options && options.method === "DELETE"));
  assert.ok(requests.filter(({ url, options }) =>
    url === "/api/v1/halt" && (!options || !options.method)).length >= 3);
  assert.equal(
    requests.some(({ url }) => url.includes("/agent-control-plane/halt") || url.includes("clear-halt")),
    false,
  );
});

test("halt verification uses one post-mutation GET from the serialized refresh", async () => {
  let getCalls = 0;
  const { document, elements } = harness({
    mvConfirm: async () => true,
    haltFetch: async (_url, options) => {
      if (options && options.method === "POST") { return jsonResponse({}); }
      getCalls += 1;
      return jsonResponse({ active: getCalls > 1, scope: "local" });
    },
  });
  await settle();

  elements.get("acp-halt-form").listeners.get("submit")({
    preventDefault() {},
    currentTarget: elements.get("acp-halt-form"),
    submitter: document.createElement("button"),
  });
  await settle();

  assert.equal(getCalls, 2);
  assert.match(elements.get("acp-operation-state").textContent, /All agents are stopped/);
});

test("overlapping roster refreshes collapse and stale results never render", async () => {
  let resolveFirst;
  let rosterCalls = 0;
  const first = new Promise((resolve) => { resolveFirst = resolve; });
  const fresh = rosterPayload();
  fresh.total = 1;
  fresh.count = 1;
  fresh.items = [{
    principal: "user:fresh",
    kind: "native",
    state: "running",
    running_goals: 1,
    revoked: false,
    contained: false,
  }];
  const { elements } = harness({
    rosterFetch: async () => {
      rosterCalls += 1;
      return rosterCalls === 1 ? first : jsonResponse({
        status: statusPayload({
          native: { principals: 1, running_goals: 1, suspended: 0, contained: 0 },
          external: { agents: 0, active: 0, suspended: 0, contained: 0 },
        }),
        agents: fresh,
      });
    },
  });
  await new Promise((resolve) => setImmediate(resolve));

  const reload = elements.get("acp-load-roster");
  reload.listeners.get("click")({ currentTarget: reload });
  reload.listeners.get("click")({ currentTarget: reload });
  resolveFirst(jsonResponse({
    status: statusPayload(),
    agents: rosterPayload(),
  }));
  await settle();

  assert.equal(rosterCalls, 2);
  assert.equal(elements.get("acp-rows").children.length, 1);
  assert.equal(elements.get("acp-rows").children[0].children[0].textContent, "fresh");
});

test("one combined snapshot drives status and roster and counts native containment", async () => {
  const { elements, requests } = harness({ nativeContained: 2 });
  await settle();

  assert.equal(elements.get("acp-suspended").textContent, "1 / 3");
  assert.equal(
    requests.filter(({ url }) => url.includes("/agent-control-plane/snapshot?")).length,
    1,
  );
  assert.equal(
    requests.some(({ url }) => url.endsWith("/agent-control-plane/status") ||
      url.includes("/agent-control-plane/agents?")),
    false,
  );
});

test("protected resume conflict preserves its structured result and audit state", async () => {
  const { elements, requests } = harness({
    mvConfirm: async () => true,
    principalFetch: async (url, options) => {
      assert.ok(url.endsWith("/principals/resume"));
      assert.equal(options.method, "POST");
      assert.deepEqual(JSON.parse(options.body), { principal: "user:suspended" });
      return jsonResponse({
        verb: "resume",
        principal: "user:suspended",
        ok: false,
        code: "protected_containment",
        detail: "resume refused: principal is security-contained; use release",
        notes: [],
        audit_written: true,
      }, false, 409);
    },
  });
  await settle();

  actionButtons(elements.get("acp-rows").children[1])[0].listeners.get("click")();
  await settle();

  assert.match(elements.get("acp-operation-state").textContent, /Not done: Resume suspended/);
  assert.match(
    elements.get("acp-operation-state").textContent,
    /It was recorded in the history/,
  );
  assert.match(elements.get("acp-output").textContent, /protected_containment/);
  assert.equal(
    requests.filter(({ options }) => options && options.method === "POST").length,
    1,
  );
});

test("structured FastAPI validation errors are announced with their field", async () => {
  const { elements } = harness({
    mvConfirm: async () => true,
    principalFetch: async () => jsonResponse({
      detail: [{
        type: "string_too_long",
        loc: ["body", "reason"],
        msg: "String should have at most 200 characters",
      }],
    }, false, 422),
  });
  await settle();

  actionButtons(elements.get("acp-rows").children[1])[0].listeners.get("click")();
  await settle();

  assert.match(
    elements.get("acp-operation-state").textContent,
    /Some of the details need fixing/,
  );
});

test("a failed mutation never claims state was re-read when refresh also fails", async () => {
  let snapshotCalls = 0;
  const { elements } = harness({
    mvConfirm: async () => true,
    rosterFetch: async () => {
      snapshotCalls += 1;
      return snapshotCalls === 1
        ? jsonResponse({ status: statusPayload(), agents: rosterPayload() })
        : jsonResponse({ detail: "roster authority is unavailable" }, false, 503);
    },
    principalFetch: async () => jsonResponse(
      { detail: "mutation transport failed" }, false, 503,
    ),
  });
  await settle();

  actionButtons(elements.get("acp-rows").children[1])[0].listeners.get("click")();
  await settle();

  assert.match(elements.get("acp-operation-state").textContent, /list could not be refreshed/);
  assert.doesNotMatch(elements.get("acp-operation-state").textContent, /was re-read/);
});

test("empty attenuation is rejected locally without a POST", async () => {
  const { document, elements, requests } = harness({ mvConfirm: async () => true });
  await settle();

  elements.get("acp-attenuate-form").listeners.get("submit")({
    preventDefault() {},
    currentTarget: elements.get("acp-attenuate-form"),
    submitter: document.createElement("button"),
  });
  await settle();

  assert.match(elements.get("acp-operation-state").textContent, /Choose at least one limit/);
  assert.equal(requests.some(({ url }) => url.includes("/attenuate")), false);
});

test("halt reason uses the API's 200-character bound before sending", async () => {
  const { document, elements, requests } = harness({
    mvConfirm: async () => true,
    formValues: { halt: { reason: "x".repeat(201) } },
  });
  await settle();

  elements.get("acp-halt-form").listeners.get("submit")({
    preventDefault() {},
    currentTarget: elements.get("acp-halt-form"),
    submitter: document.createElement("button"),
  });
  await settle();

  assert.match(elements.get("acp-operation-state").textContent, /under 200 characters/);
  assert.equal(requests.some(({ url, options }) =>
    url === "/api/v1/halt" && options && options.method === "POST"), false);
});

test("fail-soft audit result is announced precisely", async () => {
  const { elements } = harness({
    mvForm: async () => ({ reason: "incident" }),
    principalFetch: async () => jsonResponse({
      verb: "suspend",
      principal: "user:active",
      ok: true,
      code: null,
      detail: "revoked; the next tool call is denied",
      notes: ["control action audit row was not written"],
      audit_written: false,
    }),
  });
  await settle();

  actionButtons(elements.get("acp-rows").children[2])[0].listeners.get("click")();
  await settle();

  assert.match(
    elements.get("acp-operation-state").textContent,
    /Warning: it was not recorded in the history/,
  );
});

test("cluster halt status without an explicit cluster verdict stays disabled", async () => {
  const { elements } = harness({
    haltScope: "cluster",
    haltFetch: async () => jsonResponse({ active: false, scope: "cluster" }),
  });
  await settle();

  assert.equal(elements.get("acp-halt-controls").disabled, true);
  assert.equal(elements.get("acp-clear-halt").disabled, true);
  assert.equal(elements.get("acp-state").textContent, "Unknown");
  for (const row of elements.get("acp-rows").children) {
    for (const button of actionButtons(row)) {
      assert.equal(button.disabled, button.textContent !== "View history");
    }
  }
});

test("an empty terminal page renders a sane zero range", async () => {
  const terminal = {
    captured_at: CAPTURED_AT,
    total: 3,
    count: 0,
    offset: 3,
    limit: 100,
    has_more: false,
    next_offset: null,
    items: [],
  };
  const { elements } = harness({
    rosterFetch: async () => jsonResponse({
      status: statusPayload({
        native: { principals: 3, running_goals: 0, suspended: 0, contained: 0 },
        external: { agents: 0, active: 0, suspended: 0, contained: 0 },
      }),
      agents: terminal,
    }),
  });
  await settle();

  assert.match(elements.get("acp-roster-page").textContent, /Showing 0–0 of 3/);
});

test("a stale second page recovers when the bounded roster becomes empty", async () => {
  let calls = 0;
  const firstItems = Array.from({ length: 100 }, (_unused, index) => ({
    principal: `user:page-${index}`,
    kind: "native",
    state: "running",
    running_goals: 1,
    revoked: false,
    contained: false,
  }));
  const { elements, requests } = harness({
    rosterFetch: async () => {
      calls += 1;
      return calls === 1
        ? jsonResponse({
          status: statusPayload(),
          agents: {
            captured_at: CAPTURED_AT,
            total: 101,
            count: 100,
            offset: 0,
            limit: 100,
            has_more: true,
            next_offset: 100,
            items: firstItems,
          },
        })
        : jsonResponse({
          status: statusPayload(),
          agents: {
            captured_at: CAPTURED_AT,
            total: 0,
            count: 0,
            offset: 0,
            limit: 100,
            has_more: false,
            next_offset: null,
            items: [],
          },
        });
    },
  });
  await settle();

  const next = elements.get("acp-roster-next");
  next.listeners.get("click")({ currentTarget: next });
  await settle();

  assert.ok(requests.some(({ url }) => url.endsWith("offset=100")));
  assert.match(elements.get("acp-roster-page").textContent, /Showing 0–0 of 0/);
  assert.equal(elements.get("acp-roster-prev").disabled, true);
});

test("changing between mutation and ledger recomputes Apply eligibility", async () => {
  const { elements } = harness({ statusOk: false });
  await settle();

  const select = elements.get("acp-verb-select");
  const submit = elements.get("acp-verb-submit");
  assert.equal(submit.disabled, true);

  select.value = "ledger";
  select.listeners.get("change")();
  assert.equal(submit.disabled, false);

  select.value = "suspend";
  select.listeners.get("change")();
  assert.equal(submit.disabled, true);
});

test("the latest concurrent ledger read owns the Last operation panel", async () => {
  const pending = new Map();
  const { elements } = harness({
    principalFetch: (url) => new Promise((resolve) => { pending.set(url, resolve); }),
  });
  await settle();

  const agentLedger = actionButtons(elements.get("acp-rows").children[0])[1];
  const userLedger = actionButtons(elements.get("acp-rows").children[1])[1];
  agentLedger.listeners.get("click")();
  userLedger.listeners.get("click")();
  await settle();

  const newerUrl = [...pending.keys()].find((url) => url.includes("user%3Asuspended"));
  const olderUrl = [...pending.keys()].find((url) => url.includes("agent%3Acontained"));
  pending.get(newerUrl)(jsonResponse({ count: 1, items: [{ source: "newer" }] }));
  await settle();
  assert.match(elements.get("acp-operation-state").textContent, /History for suspended/);

  pending.get(olderUrl)(jsonResponse({ count: 1, items: [{ source: "older" }] }));
  await settle();
  assert.match(elements.get("acp-operation-state").textContent, /History for suspended/);
  assert.doesNotMatch(elements.get("acp-output").textContent, /older/);
});

test("a roster refresh error does not steal unrelated focus", async () => {
  let calls = 0;
  const { document, elements } = harness({
    rosterFetch: async () => {
      calls += 1;
      if (calls > 1) { throw new Error("roster offline"); }
      return jsonResponse({ status: statusPayload(), agents: rosterPayload() });
    },
  });
  await settle();

  const outside = document.createElement("button");
  outside.focus();
  const reload = elements.get("acp-load-roster");
  reload.listeners.get("click")({ currentTarget: reload });
  await settle();

  assert.equal(document.activeElement, outside);
  assert.match(elements.get("acp-roster-page").textContent, /Couldn't load the list/);
});

test("refresh marks visible health stale until the snapshot settles", async () => {
  let calls = 0;
  let releaseRefresh;
  const { elements } = harness({
    rosterFetch: () => {
      calls += 1;
      if (calls === 1) {
        return Promise.resolve(jsonResponse({ status: statusPayload(), agents: rosterPayload() }));
      }
      return new Promise((resolve) => { releaseRefresh = resolve; });
    },
  });
  await settle();

  const refresh = elements.get("acp-refresh");
  refresh.listeners.get("click")({ currentTarget: refresh });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(elements.get("acp-state").textContent, "Checking");
  assert.equal(elements.get("acp-verb-submit").disabled, true);

  releaseRefresh(jsonResponse({ status: statusPayload(), agents: rosterPayload() }));
  await settle();
  assert.equal(elements.get("acp-state").textContent, "Ready");
});

test("a stalled request times out and leaves controls fail closed", async () => {
  const { elements } = harness({
    requestTimeoutMs: 10,
    rosterFetch: (_url, options) => new Promise((_resolve, reject) => {
      options.signal.addEventListener("abort", () => {
        const error = new Error("aborted");
        error.name = "AbortError";
        reject(error);
      });
    }),
  });
  await new Promise((resolve) => setTimeout(resolve, 30));
  await settle();

  assert.match(elements.get("acp-health-detail").textContent, /took too long/);
  assert.equal(elements.get("acp-verb-submit").disabled, true);
  assert.equal(elements.get("acp-state").textContent, "Unavailable");
});

test("fallback response limits count UTF-8 bytes rather than JS characters", async () => {
  const multibyteBody = JSON.stringify({ value: "é".repeat(1100000) });
  const { elements } = harness({
    rosterFetch: async () => ({
      ok: true,
      status: 200,
      headers: { get: () => null },
      text: async () => multibyteBody,
    }),
  });
  await settle();

  assert.match(elements.get("acp-health-detail").textContent, /returned something unexpected/);
  assert.equal(elements.get("acp-verb-submit").disabled, true);
});

test("opaque identity-provider subjects use body transport without canonicalization", async () => {
  const subject = "user:auth0|tenant/alice 名";
  const { document, elements } = harness({
    mvConfirm: async () => true,
    formValues: { verb: { principal: subject, verb: "resume", reason: "" } },
    principalFetch: async (url, options) => {
      assert.ok(url.endsWith("/principals/resume"));
      assert.deepEqual(JSON.parse(options.body), { principal: subject });
      return jsonResponse({
        verb: "resume", principal: subject, ok: true, code: null,
        detail: "revocation lifted", notes: [], audit_written: true,
      });
    },
  });
  await settle();

  elements.get("acp-verb-form").listeners.get("submit")({
    preventDefault() {},
    currentTarget: elements.get("acp-verb-form"),
    submitter: document.createElement("button"),
  });
  await settle();

  assert.match(elements.get("acp-operation-state").textContent, /Done: Resume/);
  assert.match(elements.get("acp-output").textContent, /auth0\|tenant\/alice 名/);
});

test("malformed roster control fields fail closed before action rendering", async () => {
  const malformed = rosterPayload();
  malformed.items[0].allow_tools = "review";
  const { elements } = harness({
    rosterFetch: async () => jsonResponse({ status: statusPayload(), agents: malformed }),
  });
  await settle();

  assert.equal(elements.get("acp-state").textContent, "Unavailable");
  assert.match(elements.get("acp-health-detail").textContent, /returned something unexpected/);
  assert.match(elements.get("acp-rows").children[0].children[0].textContent, /Couldn't load the list/);
});

test("a newer ledger result cannot be overwritten by an older mutation", async () => {
  const pending = new Map();
  const { elements } = harness({
    mvConfirm: async () => true,
    principalFetch: (url) => new Promise((resolve) => { pending.set(url, resolve); }),
  });
  await settle();

  const resume = actionButtons(elements.get("acp-rows").children[1])[0];
  const ledgerButton = actionButtons(elements.get("acp-rows").children[0])[1];
  resume.listeners.get("click")();
  ledgerButton.listeners.get("click")();
  await settle();

  const ledgerUrl = [...pending.keys()].find((url) => url.includes("/principals/ledger?"));
  const mutationUrl = [...pending.keys()].find((url) => url.endsWith("/principals/resume"));
  pending.get(ledgerUrl)(jsonResponse({ count: 1, items: [{ source: "newer ledger" }] }));
  await settle();
  assert.match(elements.get("acp-operation-state").textContent, /History for contained/);

  pending.get(mutationUrl)(jsonResponse({
    verb: "resume", principal: "user:suspended", ok: true, code: null,
    detail: "revocation lifted", notes: [], audit_written: true,
  }));
  await settle();
  assert.match(elements.get("acp-operation-state").textContent, /History for contained/);
  assert.match(elements.get("acp-output").textContent, /newer ledger/);
});

test("a declared oversized response is cancelled before body allocation", async () => {
  let cancelled = false;
  const { elements } = harness({
    rosterFetch: async () => ({
      ok: true,
      status: 200,
      headers: { get: () => String(2 * 1024 * 1024 + 1) },
      body: { cancel: async () => { cancelled = true; } },
      text: async () => { throw new Error("body must not be read"); },
    }),
  });
  await settle();

  assert.equal(cancelled, true);
  assert.match(elements.get("acp-health-detail").textContent, /returned something unexpected/);
});

test("a chunked response is cancelled as soon as its byte budget is exceeded", async () => {
  let cancelled = false;
  let index = 0;
  const chunks = [new Uint8Array(2 * 1024 * 1024), new Uint8Array([1])];
  const { elements } = harness({
    rosterFetch: async () => ({
      ok: true,
      status: 200,
      headers: { get: () => null },
      body: {
        getReader: () => ({
          read: async () => index < chunks.length
            ? { done: false, value: chunks[index++] }
            : { done: true, value: undefined },
          cancel: async () => { cancelled = true; },
        }),
      },
      text: async () => { throw new Error("streaming path required"); },
    }),
  });
  await settle();

  assert.equal(cancelled, true);
  assert.match(elements.get("acp-health-detail").textContent, /returned something unexpected/);
});

test("timeout aborts a response whose streamed body stalls", async () => {
  let aborted = false;
  const { elements } = harness({
    requestTimeoutMs: 10,
    rosterFetch: async (_url, options) => ({
      ok: true,
      status: 200,
      headers: { get: () => null },
      body: {
        getReader: () => ({
          read: () => new Promise((_resolve, reject) => {
            options.signal.addEventListener("abort", () => {
              aborted = true;
              reject(new Error("body read aborted"));
            });
          }),
          cancel: async () => {},
        }),
      },
      text: async () => { throw new Error("streaming path required"); },
    }),
  });
  await new Promise((resolve) => setTimeout(resolve, 30));
  await settle();

  assert.equal(aborted, true);
  assert.match(elements.get("acp-health-detail").textContent, /took too long/);
  assert.equal(elements.get("acp-verb-submit").disabled, true);
});

test("row buttons offer Limit for outside agents and plain labels only", async () => {
  const payload = rosterPayload();
  payload.items[0] = { ...payload.items[0], contained: false, revoked: false, state: "active", label: "Vega assistant" };
  const { elements } = harness({
    rosterFetch: async () => jsonResponse({ status: statusPayload(), agents: payload }),
  });
  await settle();
  const row = elements.get("acp-rows").children[0];
  assert.equal(row.children[0].textContent, "Vega assistant");
  assert.equal(row.children[1].textContent, "Outside agent");
  assert.equal(row.children[2].children[0].textContent, "Active");
  assert.deepEqual(actionButtons(row).map((button) => button.textContent),
    ["Pause", "Isolate", "Limit", "View history"]);
  const text = elements.get("acp-rows").children.map((r) => r.children.map((c) => c.textContent).join(" ")).join(" ");
  assert.doesNotMatch(text, /principal|agent:|user:|missing_trust|ledger/i);
});
