// Run with: node --test packages/maverick-dashboard/tests/js/no_code_grc_studio_client.test.js
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { JSDOM } = require("jsdom");

const base = path.resolve(__dirname, "../../maverick_dashboard");
const source = fs.readFileSync(path.join(base, "static/lightwork-no-code-grc-studio.js"), "utf8");
const template = fs.readFileSync(path.join(base, "templates/no_code_grc_studio.html"), "utf8");
const shell = template.slice(template.indexOf('<div class="grcs-shell"'), template.indexOf("{% endblock %}", template.indexOf('<div class="grcs-shell"')))
  .replace(/\{%[\s\S]*?%\}/g, "")
  .replace("{{ api_base }}", "/api/v1/compliance/grc-studio")
  .replace(/\{\{ 'true' if studio_can_\w+ else 'false' \}\}/g, "true")
  .replace(/\{\{[\s\S]*?\}\}/g, "");

function client() {
  const window = {};
  const context = { TextDecoder, TextEncoder, console, window };
  vm.createContext(context);
  vm.runInContext(source, context);
  return window.LightworkNoCodeGRCStudioClient;
}

function plain(value) { return JSON.parse(JSON.stringify(value)); }

const FIELD = {
  field_id: "severity", label_ref: "severity", field_type: "single_choice", required: true,
  sensitivity: "internal", options: ["low", "high"], reference_kind: null, default: "low",
};
const BLUEPRINT = {
  schema: "lightwork.no-code-grc-blueprint.v1", studio_id: "supplier-review", name_ref: "supplier-review",
  description_ref: null,
  objects: [{ object_id: "supplier", kind: "vendor", label_ref: "supplier", description_ref: null, fields: [FIELD] }],
  forms: [{ form_id: "intake", object_id: "supplier", title_ref: "intake", sections: [{ section_id: "basics", label_ref: "basics", field_ids: ["severity"] }] }],
  rules: [], collector_bindings: [], report_views: [],
};
function row(overrides) {
  return {
    studio_id: "supplier-review", version: 1, revision: 3, state: "draft", blueprint: BLUEPRINT,
    blueprint_sha256: "b".repeat(64), integrity_sha256: "c".repeat(64), updated_at: 1800000000,
    ...overrides,
  };
}

test("names become stored references and back into words", () => {
  const api = client();
  assert.equal(api.slug("Supplier Review 2026"), "supplier-review-2026");
  assert.equal(api.human("supplier-review-2026"), "Supplier review 2026");
  assert.throws(() => api.slug("  !!  "), /letters or numbers/);
  assert.deepEqual(plain(api.listOf("Low, Medium,High", "choice", 10, 1)), ["low", "medium", "high"]);
  assert.throws(() => api.listOf("Low, low", "choice", 10, 1), /only be listed once/);
});

test("answers are converted per field type with plain errors", () => {
  const api = client();
  assert.equal(api.parseAnswer({ ...FIELD, field_type: "boolean", options: [] }, "Yes"), true);
  assert.equal(api.parseAnswer({ ...FIELD, field_type: "integer", options: [] }, "12"), 12);
  assert.equal(api.parseAnswer(FIELD, "High"), "high");
  assert.throws(() => api.parseAnswer(FIELD, "Medium"), /not one of the choices/);
  assert.throws(() => api.parseAnswer({ ...FIELD, field_type: "integer", options: [] }, "1.5"), /whole number/);
  assert.throws(() => api.conditionValue(FIELD, "greater_than", "high"), /only work for numbers/);
  assert.equal(api.conditionValue(FIELD, "is_set", "ignored"), null);
});

test("the composer emits the exact closed blueprint root", () => {
  const api = client();
  const state = plain(api.emptyComposerState());
  state.objects.push(plain(BLUEPRINT.objects[0]));
  const blueprint = plain(api.buildBlueprintFromComposer({
    studio_id: "supplier-review", name: "Supplier review", description: "", tenant_id: "attacker",
  }, state));
  assert.deepEqual(Object.keys(blueprint).sort(), [
    "collector_bindings", "description_ref", "forms", "name_ref", "objects", "report_views", "rules", "schema", "studio_id",
  ]);
  assert.equal(blueprint.name_ref, "supplier-review");
  assert.equal(blueprint.description_ref, null);
  const empty = plain(api.emptyComposerState());
  assert.throws(() => api.buildBlueprintFromComposer({ studio_id: "x", name: "X" }, empty), /record type/);
});

test("loading rejects an open root and accepts a downloaded copy", () => {
  const api = client();
  assert.equal(plain(api.loadComposerState(BLUEPRINT)).metadata.name, "Supplier review");
  assert.equal(plain(api.loadComposerState({ schema: "export", blueprint: BLUEPRINT })).metadata.studio_id, "supplier-review");
  assert.throws(() => api.loadComposerState({ ...BLUEPRINT, eval: "process" }), /not a blueprint/);
});

test("save and lifecycle requests carry the row's exact version checks", () => {
  const api = client();
  const created = plain(api.buildSavePayload({ mode: "create", latestVersion: 2 }, BLUEPRINT, "ui-1"));
  assert.equal(created.method, "POST");
  assert.deepEqual(Object.keys(created.body).sort(), ["blueprint", "expected_latest_version", "operation_id"]);
  assert.equal(created.body.expected_latest_version, 2);
  const replaced = plain(api.buildSavePayload({ mode: "replace", row: row() }, BLUEPRINT, "ui-2"));
  assert.equal(replaced.method, "PATCH");
  assert.equal(replaced.path, "/studios/supplier-review/versions/1");
  assert.equal(replaced.body.expected_revision, 3);
  const review = plain(api.buildLifecycleRequest("reject", row({ state: "in_review" }), { reason: "needs-changes" }, "ui-3"));
  assert.equal(review.path, "/studios/supplier-review/versions/1/review");
  assert.equal(review.body.accepted, false);
  assert.equal(review.body.rationale_ref, "needs-changes");
  const first = plain(api.buildLifecycleRequest("publish", row({ state: "approved" }), { pointer: null }, "ui-4"));
  assert.equal(first.body.expected_active_version, 0);
  assert.equal(first.body.expected_active_blueprint_sha256, null);
  const restore = plain(api.buildRollbackRequest(row({ state: "superseded" }),
    { active_version: 2, active_blueprint_sha256: "d".repeat(64), revision: 4 }, "audit-finding", "ui-5"));
  assert.equal(restore.body.target_version, 1);
  assert.equal(restore.body.expected_target_blueprint_sha256, "b".repeat(64));
  assert.equal(restore.body.expected_pointer_revision, 4);
  assert.throws(() => api.buildRollbackRequest(row(), null, "x", "ui-6"), /no live version/);
});

test("row buttons follow the version's status and the person's permissions", () => {
  const api = client();
  const everyone = { operate: true, audit: true, admin: true };
  assert.deepEqual(plain(api.rowActions(row(), everyone)), ["view", "edit", "submit", "copy", "download", "history"]);
  assert.ok(api.rowActions(row({ state: "in_review" }), everyone).includes("accept"));
  assert.ok(api.rowActions(row({ state: "superseded" }), everyone).includes("restore"));
  assert.deepEqual(plain(api.rowActions(row({ state: "approved" }), { operate: false, audit: false, admin: false })), ["view"]);
});

test("projection requests take the live row's version and never caller material", () => {
  const api = client();
  const live = row({ state: "published", version: 3 });
  assert.deepEqual(plain(api.projectionChoices(BLUEPRINT)), [{ value: "questionnaire:intake", label: "Form: Intake" }]);
  const payload = plain(api.buildProjectionPayload(live, "questionnaire:intake", { target_id: "vendor-portal", target_revision: "4", provider_url: "https://attacker.invalid" }));
  assert.deepEqual(Object.keys(payload).sort(), [
    "definition_id", "expected_active_version", "expected_blueprint_sha256", "projection_kind", "studio_id", "target_id", "target_revision",
  ]);
  assert.equal(payload.expected_active_version, 3);
  assert.throws(() => api.buildProjectionPayload(live, "questionnaire:intake", { target_id: "https://x", target_revision: "1" }), /Choose a destination/);
});

test("oversized responses are cancelled and failures carry only a status", async () => {
  const api = client();
  let cancelled = false;
  await assert.rejects(api.readBoundedJson({
    headers: { get: () => String(api.MAX_RESPONSE_BYTES + 1) }, body: { cancel: async () => { cancelled = true; } },
  }), /too large/);
  assert.equal(cancelled, true);
  let reads = 0;
  let streamCancelled = false;
  await assert.rejects(api.readBoundedJson({
    headers: { get: () => null }, ok: true, status: 200,
    body: { getReader() { return {
      async read() { reads += 1; return { done: false, value: new Uint8Array(reads === 1 ? api.MAX_RESPONSE_BYTES : 1) }; },
      async cancel() { streamCancelled = true; },
    }; } },
  }), /too large/);
  assert.equal(streamCancelled, true);
  const failure = await api.readBoundedJson({ headers: { get: () => null }, ok: false, status: 409, text: async () => '{"detail":"GRC studio action conflicts"}' })
    .catch((error) => error);
  assert.equal(failure.status, 409);
  assert.equal(failure.technical, "GRC studio action conflicts");
});

const DRAFTS = "/api/v1/compliance/grc-draft-changes";
const DRAFT_CONTEXT = "c".repeat(64);

function page(t, rows, extra = {}) {
  const dom = new JSDOM(`<main id="content">${shell}</main>`, { url: "https://lightwork.test/compliance/grc-studio", runScripts: "outside-only" });
  t.after(() => dom.window.close());
  const w = dom.window;
  w.TextDecoder = TextDecoder;
  w.TextEncoder = TextEncoder;
  const calls = [];
  w.mvConfirm = async () => true;
  w.mvForm = async (_title, fields) => Object.fromEntries(fields.map((field) => [field.key, field.default]));
  w.mvErrorText = (failure, action) => "Could not " + action + ". (" + failure.status + ")";
  const respond = (value, status = 200) => ({ ok: status < 400, status, headers: { get: () => null }, text: async () => JSON.stringify(value) });
  w.fetch = async (url, options = {}) => {
    const key = (options.method || "GET") + " " + String(url).replace("/api/v1/compliance/grc-studio", "");
    calls.push({ key, body: options.body ? JSON.parse(options.body) : undefined });
    if (extra[key]) return respond(extra[key]);
    if (key === "GET /status") return respond({ enabled: true, configured: true, ready: true, runtime_projection_preview_configured: false });
    if (key === "GET ?limit=1000") return respond({ items: rows });
    if (key === "GET /operations/recovery/backups") return respond({ items: [{ backup_id: "grc-1-abc", created_at: 1800000000 }] });
    if (key === "GET /studios/supplier-review/active") return respond({ detail: "not found" }, 404);
    if (key.endsWith("/submit") || key.endsWith("/publish")) return respond({ ...rows[0], revision: 4 });
    if (key === "POST /studios/supplier-review/versions") return respond({ ...rows[0], version: 2 });
    // Saving a draft goes through its own complete review (grc-draft-changes).
    if (key === "GET " + DRAFTS) return respond({ context: DRAFT_CONTEXT });
    if (key === "POST " + DRAFTS + "/review") return respond({ context: DRAFT_CONTEXT, token: "sealed-draft",
      changes: [{ label: "Version", before: "1", after: "2" }] });
    if (key === "POST " + DRAFTS + "/save") return respond({ context: DRAFT_CONTEXT, confirmed: true, message: "Saved as draft version 2.",
      name: "Supplier review", version: 2, revision: 1 });
    return respond({ detail: "GRC studio action conflicts with current state" }, 409);
  };
  w.eval(source);
  const settle = async () => { for (let i = 0; i < 30; i += 1) await new Promise((r) => setImmediate(r)); };
  return { w, calls, settle, $: (id) => w.document.getElementById(id) };
}

test("the register loads on open with plain rows and working row buttons", async (t) => {
  const h = page(t, [row(), row({ version: 2, state: "approved", updated_at: 1800000100 })]);
  await h.settle();
  assert.equal(h.$("grcs-operations").disabled, false);
  assert.equal(h.$("grcs-status-mark").textContent, "Ready to build");
  assert.match(h.$("grcs-readiness-detail").textContent, /questionnaire builder below to bring supported form questions into a reviewed questionnaire\. Evidence checks and reports need their own supported destination/);
  const text = h.$("grcs-version-list").textContent;
  assert.match(text, /Supplier review/);
  assert.match(text, /Draft/);
  assert.match(text, /Approved/);
  assert.doesNotMatch(text, /[0-9a-f]{64}|revision|supplier-review/);
  const send = h.$("grcs-version-list").querySelector('button[aria-label="Send for review: Supplier review version 1"]');
  assert.ok(send);
  send.click();
  await h.settle();
  const submit = h.calls.find((call) => call.key.endsWith("/versions/1/submit"));
  assert.equal(submit.body.expected_revision, 3);
  assert.match(submit.body.operation_id, /^ui-/);
  assert.match(h.$("grcs-operation-status").textContent, /Sent for review/);
  const publish = h.$("grcs-version-list").querySelector('button[aria-label="Publish: Supplier review version 2"]');
  publish.click();
  await h.settle();
  const published = h.calls.find((call) => call.key.endsWith("/versions/2/publish"));
  assert.equal(published.body.expected_active_version, 0);
  assert.match(h.$("grcs-operation-status").textContent, /Published in this studio/);
  assert.match(h.$("grcs-backup-list").textContent, /Check it|20/);
});

test("building with pickers saves the next version and errors stay plain", async (t) => {
  const h = page(t, [row({ state: "published" })]);
  await h.settle();
  h.$("grcs-new").click();
  await h.settle();
  h.$("grcs-name").value = "Supplier review";
  h.$("grcs-object-name").value = "Supplier";
  h.$("grcs-add-object").click();
  h.$("grcs-field-name").value = "Risk level";
  h.$("grcs-field-options").value = "Low, High";
  h.$("grcs-add-field").click();
  assert.equal(h.$("grcs-field-object").value, "supplier");
  assert.match(h.$("grcs-field-list").textContent, /Risk level/);
  h.$("grcs-builder-form").dispatchEvent(new h.w.Event("submit", { cancelable: true }));
  await h.settle();
  assert.match(h.$("grcs-operation-status").textContent, /already exists/);
  // A new version of the existing blueprint takes the next version number.
  h.$("grcs-version-list").querySelector('button[aria-label="New version from this: Supplier review version 1"]').click();
  await h.settle();
  h.$("grcs-builder-form").dispatchEvent(new h.w.Event("submit", { cancelable: true }));
  await h.settle();
  // Saving first shows the complete reviewed change; nothing is saved yet.
  const reviewed = h.calls.find((call) => call.key === "POST " + DRAFTS + "/review");
  assert.equal(reviewed.body.studio, "supplier-review");
  assert.equal(reviewed.body.body.expected_latest_version, 1);
  assert.equal(h.$("grcs-save-review").hidden, false);
  assert.equal(h.calls.filter((call) => call.key === "POST " + DRAFTS + "/save").length, 0);
  h.$("grcs-save-confirm").checked = true;
  h.$("grcs-save-confirm").dispatchEvent(new h.w.Event("change"));
  h.$("grcs-save-apply").click();
  await h.settle();
  const saved = h.calls.find((call) => call.key === "POST " + DRAFTS + "/save");
  assert.deepEqual(saved.body, { token: "sealed-draft", confirmed: true });
  assert.match(h.$("grcs-operation-status").textContent, /draft version 2/);
});

test("collectors and destinations are chosen from lists, not typed", async (t) => {
  const digest = "a".repeat(64);
  const h = page(t, [row({ state: "published" })], {
    "GET /sources": {
      // Approved evidence sources, with the result fields and controls they support.
      collectors: [{ collector_id: "cloud-config-scan", collector_version: 3, collector_integrity_sha256: digest,
        label: "Cloud config scan", definition_id: "cloud-config-scan",
        outputs: [{ path: ["status"], label: "Check result", type: "text_ref" }],
        controls: [{ value: "oidc_auth", label: "Company sign-in" }] }],
      destinations: [
        { target_kind: "questionnaire", target_id: "vendor-portal", target_revision: 7, label: "Vendor portal" },
        { target_kind: "report", target_id: "board-pack", target_revision: 2, label: null },
      ],
      destinations_listed: true,
    },
  });
  await h.settle();
  const collector = h.$("grcs-collector-choice");
  assert.equal(collector.options.length, 2);
  assert.equal(collector.options[1].textContent, "Cloud config scan · approved version 3");
  collector.value = "cloud-config-scan:3:" + digest;
  collector.dispatchEvent(new h.w.Event("change"));
  // The exact reference travels in hidden fields; nobody types it.
  for (const id of ["grcs-collector-id", "grcs-collector-version", "grcs-collector-digest"]) assert.equal(h.$(id).type, "hidden");
  assert.equal(h.$("grcs-collector-id").value, "cloud-config-scan");
  assert.equal(h.$("grcs-collector-version").value, "3");
  assert.equal(h.$("grcs-collector-digest").value, digest);
  assert.deepEqual([...h.$("grcs-source-path").options].map((option) => option.textContent), ["Choose a result field", "Check result"]);
  assert.match(h.$("grcs-control-refs").textContent, /Company sign-in/);
  const target = h.$("grcs-projection-target");
  // Only destinations that accept the chosen kind (a form) are offered.
  assert.deepEqual([...target.options].map((option) => option.textContent), ["Choose a destination", "Vendor portal (version 7)"]);
  target.value = "0";
  target.dispatchEvent(new h.w.Event("change"));
  const form = h.$("grcs-projection-form");
  assert.equal(form.elements.target_id.value, "vendor-portal");
  assert.equal(form.elements.target_revision.value, "7");
  assert.equal(form.elements.target_id.closest("details").open, false);
});

test("without a destination list the page says who to ask", async (t) => {
  const h = page(t, [row({ state: "published" })], {
    "GET /sources": { collectors: [], destinations: [], destinations_listed: false },
  });
  await h.settle();
  assert.match(h.$("grcs-collector-note").textContent, /Set up an evidence source in Continuous evidence and have a different administrator approve it/);
  assert.match(h.$("grcs-projection-target-note").textContent, /Ask your administrator/);
  assert.doesNotMatch(h.$("grcs-projection-target-note").textContent, /fingerprint|revision|[0-9a-f]{64}/);
});

// ---- no loader keeps saying "Loading" ---------------------------------------
function statusPage(t, status, moduleEnabled = "") {
  const dom = new JSDOM(`<main id="content">${shell}</main>`, { url: "https://lightwork.test/compliance/grc-studio", runScripts: "outside-only" });
  t.after(() => dom.window.close());
  const w = dom.window;
  w.TextDecoder = TextDecoder;
  w.TextEncoder = TextEncoder;
  w.document.getElementById("grc-studio-shell").dataset.moduleEnabled = moduleEnabled;
  for (const [id, text] of [["grcs-list-status", "Loading your blueprints…"], ["grcs-backup-status", "Loading backups…"]]) w.document.getElementById(id).textContent = text;
  for (const [id, text] of [["grcs-collector-choice", "Loading collectors…"], ["grcs-projection-target", "Loading destinations…"]]) w.document.getElementById(id).options[0].textContent = text;
  w.mvErrorText = (failure, action) => "Could not " + action + ". Try again in a few minutes.";
  const calls = [];
  w.fetch = async (url) => { calls.push(String(url)); return status(); };
  w.eval(source);
  const settle = async () => { for (let i = 0; i < 30; i += 1) await new Promise((r) => setImmediate(r)); };
  const body = () => w.document.querySelector("main").textContent + [...w.document.querySelectorAll("option")].map((o) => o.textContent).join(" ");
  return { calls, settle, body, $: (id) => w.document.getElementById(id) };
}
const answer = (value, status = 200) => () => ({ ok: status < 400, status, headers: { get: () => null }, text: async () => JSON.stringify(value) });

test("a studio that isn't set up settles every loader instead of loading forever", async (t) => {
  const h = statusPage(t, answer({ enabled: true, configured: false, ready: false }));
  await h.settle();
  assert.equal(h.$("grcs-list-status").textContent, "Nothing to show until the studio is ready.");
  assert.equal(h.$("grcs-collector-choice").options[0].textContent, "Not available until the studio is ready");
  assert.equal(h.$("grcs-projection-target").options[0].textContent, "Not available until the studio is ready");
  assert.equal(h.$("grcs-backup-status").textContent, "Backups appear here once the studio is ready.");
  assert.doesNotMatch(h.body(), /Loading|Checking/);
});

test("a failed availability check says what happened in every loader", async (t) => {
  const h = statusPage(t, answer({ detail: "unavailable" }, 503));
  await h.settle();
  assert.equal(h.$("grcs-status-mark").textContent, "Not available");
  assert.equal(h.$("grcs-list-status").textContent, "Could not load your blueprints. Try again in a few minutes.");
  assert.equal(h.$("grcs-version-list").textContent, "");
  assert.doesNotMatch(h.body(), /Loading|Checking/);
});

test("a server that reports the studio off asks for it to be turned on, not set up", async (t) => {
  const h = statusPage(t, answer({ enabled: false, configured: false, ready: false }));
  await h.settle();
  assert.equal(h.$("grcs-readiness-detail").textContent, "Ask an administrator to turn on the no-code GRC studio for this workspace.");
});

test("a turned-off studio starts no checks or loads behind its gate", async (t) => {
  const h = statusPage(t, () => { throw new Error("no request expected"); }, "false");
  await h.settle();
  assert.deepEqual(h.calls, []);
});
