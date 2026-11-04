(function (global) {
  "use strict";

  var MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
  var MAX_FILE_BYTES = 2 * 1024 * 1024;
  var BLUEPRINT_SCHEMA = "lightwork.no-code-grc-blueprint.v1";
  var ID = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
  var OP = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$/;
  var FINGERPRINT = /^[0-9a-f]{64}$/;
  var ROOT_KEYS = ["schema", "studio_id", "name_ref", "description_ref", "objects", "forms", "rules", "collector_bindings", "report_views"];
  var COLLECTIONS = ["objects", "forms", "rules", "collector_bindings", "report_views"];

  var STATE_LABEL = {
    draft: "Draft", in_review: "Waiting for review", reviewed: "Reviewed", approved: "Approved",
    published: "Live", superseded: "Replaced by a newer version", rejected: "Sent back"
  };
  var STATE_BADGE = {
    draft: "idle", in_review: "warn", reviewed: "running", approved: "running",
    published: "ok", superseded: "paused", rejected: "failed"
  };
  var EVENT_LABEL = {
    version_created: "Created", draft_replaced: "Draft changed", submitted_for_review: "Sent for review",
    review_accepted: "Review accepted", review_rejected: "Sent back by the reviewer", version_approved: "Approved",
    version_published: "Published", version_superseded: "Replaced by a newer version",
    version_superseded_by_rollback: "Replaced when an earlier version was restored",
    version_reactivated: "Restored", version_imported: "Brought in from a copy"
  };
  var TYPE_LABEL = {
    single_choice: "Pick one", multi_choice: "Pick several", boolean: "Yes or no", integer: "Whole number",
    decimal: "Number", date: "Date", timestamp: "Date and time", text_ref: "Short text",
    record_ref: "Link to a record", evidence_ref: "Link to evidence", digest: "File fingerprint"
  };
  var KIND_LABEL = {
    risk: "Risk", control: "Control", asset: "Asset", vendor: "Supplier", policy: "Policy", issue: "Issue",
    assessment: "Assessment", evidence: "Evidence", custom: "Other"
  };
  var OPERATOR_LABEL = {
    equals: "is", not_equals: "is not", greater_than: "is more than", greater_or_equal: "is at least",
    less_than: "is less than", less_or_equal: "is at most", contains: "includes", is_set: "is answered"
  };
  var PROJECTION_LABEL = { questionnaire: "Form", collector: "Evidence link", report: "Report" };

  function problem(message) {
    var error = new Error(message);
    error.plain = true;
    return error;
  }

  function human(value) {
    var text = String(value === null || value === undefined ? "" : value).replace(/[_.-]+/g, " ").trim();
    return text ? text.charAt(0).toUpperCase() + text.slice(1) : "";
  }

  function slug(value, what) {
    var text = String(value || "").trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 100);
    if (!text || !ID.test(text)) {
      throw problem("Give " + (what || "it") + " a name that uses letters or numbers.");
    }
    return text;
  }

  function listOf(value, what, maximum, minimum) {
    var items = String(value || "").split(",").map(function (item) { return item.trim(); }).filter(Boolean)
      .map(function (item) { return slug(item, what); });
    if (items.length < (minimum || 0)) { throw problem("Add at least one " + what + "."); }
    if (items.length > maximum) { throw problem("Use at most " + maximum + " " + what + "s."); }
    if (new Set(items).size !== items.length) { throw problem("Each " + what + " can only be listed once."); }
    return items;
  }

  function copy(value) { return JSON.parse(JSON.stringify(value)); }

  function emptyComposerState() {
    return { objects: [], forms: [], rules: [], collector_bindings: [], report_views: [] };
  }

  function operationId() {
    if (global.crypto && typeof global.crypto.randomUUID === "function") { return "ui-" + global.crypto.randomUUID(); }
    return "ui-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 12);
  }

  // Turns what a person typed into the stored value for one field.
  function parseAnswer(field, text, label) {
    var raw = String(text === undefined || text === null ? "" : text).trim();
    var name = "“" + human(field.label_ref || field.field_id) + "”";
    if (!raw) { return null; }
    switch (field.field_type) {
      case "boolean":
        if (/^(yes|true|y)$/i.test(raw)) { return true; }
        if (/^(no|false|n)$/i.test(raw)) { return false; }
        throw problem("Answer yes or no for " + name + ".");
      case "integer":
        if (!/^-?\d{1,13}$/.test(raw)) { throw problem("Enter a whole number for " + name + "."); }
        return Number(raw);
      case "decimal": {
        var number = Number(raw);
        if (!/^-?\d+(\.\d+)?$/.test(raw) || !Number.isFinite(number) || Math.abs(number) > 1e12) {
          throw problem("Enter a number for " + name + ".");
        }
        return number;
      }
      case "timestamp": {
        var parsed = Date.parse(raw);
        if (!Number.isFinite(parsed) || parsed <= 0) { throw problem("Enter a date and time for " + name + "."); }
        return Math.floor(parsed / 1000);
      }
      case "date":
        if (!/^\d{4}-\d{2}-\d{2}$/.test(raw) || !Number.isFinite(Date.parse(raw))) {
          throw problem("Enter the date for " + name + " as year-month-day, for example 2026-03-31.");
        }
        return raw;
      case "single_choice":
      case "multi_choice": {
        var choice = slug(raw, label || "the answer");
        if ((field.options || []).indexOf(choice) < 0) {
          throw problem("“" + raw + "” is not one of the choices for " + name + ".");
        }
        return choice;
      }
      case "digest":
        if (!FINGERPRINT.test(raw)) { throw problem("Enter the 64-character file fingerprint for " + name + "."); }
        return raw;
      default:
        return slug(raw, label || "the answer");
    }
  }

  function conditionValue(field, operator, text) {
    var name = "“" + human(field.label_ref || field.field_id) + "”";
    if (operator === "is_set") { return null; }
    if (operator === "contains" && field.field_type !== "multi_choice") {
      throw problem("“Includes” only works for fields where people pick several answers.");
    }
    if (field.field_type === "multi_choice" && operator !== "contains") {
      throw problem("For " + name + ", choose “includes” or “answered”.");
    }
    if (["greater_than", "greater_or_equal", "less_than", "less_or_equal"].indexOf(operator) >= 0 &&
        ["integer", "decimal", "timestamp"].indexOf(field.field_type) < 0) {
      throw problem("“More than” and “less than” only work for numbers and dates with times.");
    }
    var value = parseAnswer(field, text);
    if (value === null) { throw problem("Enter the answer to compare " + name + " with."); }
    return value;
  }

  function buildBlueprintFromComposer(metadata, state) {
    if (!state || COLLECTIONS.some(function (key) { return !Array.isArray(state[key]); })) {
      throw problem("The builder was reset. Start again.");
    }
    var studioId = String(metadata.studio_id || "");
    if (!ID.test(studioId)) { throw problem("Give the blueprint a name that uses letters or numbers."); }
    var blueprint = {
      schema: BLUEPRINT_SCHEMA,
      studio_id: studioId,
      name_ref: slug(metadata.name, "the blueprint"),
      description_ref: String(metadata.description || "").trim() ? slug(metadata.description, "the description") : null,
      objects: copy(state.objects),
      forms: copy(state.forms),
      rules: copy(state.rules),
      collector_bindings: copy(state.collector_bindings),
      report_views: copy(state.report_views)
    };
    if (!blueprint.objects.length) { throw problem("Add at least one record type first."); }
    var empty = blueprint.objects.filter(function (item) { return !item.fields.length; });
    if (empty.length) { throw problem("Add at least one field to “" + human(empty[0].label_ref) + "”."); }
    return blueprint;
  }

  function loadComposerState(value) {
    var source = value && value.schema !== BLUEPRINT_SCHEMA && value.blueprint ? value.blueprint : value;
    var keys = Object.keys(source || {}).sort();
    var expected = ROOT_KEYS.slice().sort();
    if (keys.length !== expected.length || keys.some(function (key, index) { return key !== expected[index]; }) ||
        source.schema !== BLUEPRINT_SCHEMA || !ID.test(String(source.studio_id || "")) || !ID.test(String(source.name_ref || ""))) {
      throw problem("That file is not a blueprint from this studio.");
    }
    COLLECTIONS.forEach(function (key) {
      if (!Array.isArray(source[key])) { throw problem("That file is not a blueprint from this studio."); }
    });
    var state = {};
    COLLECTIONS.forEach(function (key) { state[key] = copy(source[key]); });
    return {
      metadata: {
        studio_id: source.studio_id,
        name: human(source.name_ref),
        description: source.description_ref ? human(source.description_ref) : ""
      },
      state: state
    };
  }

  // target: {mode: "create", latestVersion} or {mode: "replace", row}
  function buildSavePayload(target, blueprint, opId) {
    if (!OP.test(String(opId || ""))) { throw problem("Refresh the page and try again."); }
    if (target.mode === "replace") {
      var row = target.row || {};
      return {
        method: "PATCH",
        path: "/studios/" + encodeURIComponent(row.studio_id) + "/versions/" + row.version,
        body: { blueprint: blueprint, expected_revision: row.revision, expected_integrity_sha256: row.integrity_sha256, operation_id: opId }
      };
    }
    return {
      method: "POST",
      path: "/studios/" + encodeURIComponent(blueprint.studio_id) + "/versions",
      body: { blueprint: blueprint, expected_latest_version: Number(target.latestVersion) || 0, operation_id: opId }
    };
  }

  function casBody(row, opId) {
    return { expected_revision: row.revision, expected_integrity_sha256: row.integrity_sha256, operation_id: opId };
  }

  function buildLifecycleRequest(action, row, options, opId) {
    var base = "/studios/" + encodeURIComponent(row.studio_id) + "/versions/" + row.version + "/";
    var body = casBody(row, opId);
    if (action === "submit") { return { path: base + "submit", body: body }; }
    if (action === "accept" || action === "reject") {
      body.accepted = action === "accept";
      body.rationale_ref = slug(options.reason, "the reason");
      return { path: base + "review", body: body };
    }
    if (action === "approve") {
      body.approval_ref = slug(options.reason, "the approval");
      return { path: base + "approve", body: body };
    }
    if (action === "publish") {
      var pointer = options.pointer;
      body.expected_active_version = pointer ? pointer.active_version : 0;
      body.expected_active_blueprint_sha256 = pointer ? pointer.active_blueprint_sha256 : null;
      body.expected_pointer_revision = pointer ? pointer.revision : 0;
      return { path: base + "publish", body: body };
    }
    throw problem("That action is not available. Refresh the page to see the latest.");
  }

  function buildRollbackRequest(row, pointer, reason, opId) {
    if (!pointer) { throw problem("This blueprint has no live version to switch away from."); }
    return {
      path: "/studios/" + encodeURIComponent(row.studio_id) + "/rollback",
      body: {
        target_version: row.version,
        expected_target_blueprint_sha256: row.blueprint_sha256,
        expected_active_version: pointer.active_version,
        expected_active_blueprint_sha256: pointer.active_blueprint_sha256,
        expected_pointer_revision: pointer.revision,
        rationale_ref: slug(reason, "the reason"),
        operation_id: opId
      }
    };
  }

  function buildProjectionPayload(liveRow, definition, values, opId) {
    var parts = String(definition || "").split(":");
    if (parts.length !== 2 || !PROJECTION_LABEL[parts[0]] || !ID.test(parts[1])) { throw problem("Choose what to send."); }
    var target = String(values.target_id || "").trim();
    if (!ID.test(target)) { throw problem("Choose a destination from the list."); }
    var revision = Number(values.target_revision);
    if (!Number.isSafeInteger(revision) || revision < 1) { throw problem("Choose a destination from the list. The details entered by hand are incomplete."); }
    var payload = {
      studio_id: liveRow.studio_id,
      projection_kind: parts[0],
      definition_id: parts[1],
      target_id: target,
      target_revision: revision,
      expected_active_version: liveRow.version,
      expected_blueprint_sha256: liveRow.blueprint_sha256
    };
    if (opId) { payload.operation_id = opId; }
    return payload;
  }

  function projectionChoices(blueprint) {
    var choices = [];
    (blueprint && blueprint.forms || []).forEach(function (item) { choices.push({ value: "questionnaire:" + item.form_id, label: "Form: " + human(item.title_ref) }); });
    (blueprint && blueprint.collector_bindings || []).forEach(function (item) { choices.push({ value: "collector:" + item.binding_id, label: "Evidence link: " + human(item.binding_id) }); });
    (blueprint && blueprint.report_views || []).forEach(function (item) { choices.push({ value: "report:" + item.view_id, label: "Report: " + human(item.title_ref) }); });
    return choices;
  }

  // Which buttons a version row offers to this person.
  function rowActions(row, permissions) {
    var actions = ["view"];
    if (row.state === "draft" && permissions.operate) { actions.push("edit", "submit"); }
    if (row.state === "in_review" && permissions.audit) { actions.push("accept", "reject"); }
    if (row.state === "reviewed" && permissions.admin) { actions.push("approve"); }
    if (row.state === "approved" && permissions.admin) { actions.push("publish"); }
    if (row.state === "superseded" && permissions.admin) { actions.push("restore"); }
    if (permissions.operate && row.blueprint) { actions.push("copy"); }
    if (permissions.audit) { actions.push("download", "history"); }
    return actions;
  }

  async function readBoundedJson(response) {
    var advertised = Number(response.headers.get("content-length") || "0");
    if (advertised > MAX_RESPONSE_BYTES) {
      if (response.body && typeof response.body.cancel === "function") { await response.body.cancel(); }
      throw problem("That is too large to show here. Narrow the search or choose fewer records.");
    }
    var text;
    if (response.body && typeof response.body.getReader === "function") {
      var reader = response.body.getReader();
      var decoder = new TextDecoder();
      var total = 0;
      var parts = [];
      while (true) {
        var read = await reader.read();
        if (read.done) { break; }
        total += read.value.byteLength;
        if (total > MAX_RESPONSE_BYTES) {
          await reader.cancel();
          throw problem("That is too large to show here. Narrow the search or choose fewer records.");
        }
        parts.push(decoder.decode(read.value, { stream: true }));
      }
      parts.push(decoder.decode());
      text = parts.join("");
    } else {
      text = await response.text();
      if (new TextEncoder().encode(text).length > MAX_RESPONSE_BYTES) { throw problem("That is too large to show here. Narrow the search or choose fewer records."); }
    }
    var payload = null;
    try { payload = text ? JSON.parse(text) : {}; } catch (_error) { payload = null; }
    if (!response.ok) {
      var failure = new Error("request failed");
      failure.status = response.status;
      failure.technical = payload && typeof payload.detail === "string" ? payload.detail : "";
      throw failure;
    }
    if (!payload || typeof payload !== "object") { throw problem("Lightwork sent back something unexpected. Refresh the page and try again."); }
    return payload;
  }

  global.LightworkNoCodeGRCStudioClient = {
    MAX_RESPONSE_BYTES: MAX_RESPONSE_BYTES,
    STATE_LABEL: STATE_LABEL,
    buildBlueprintFromComposer: buildBlueprintFromComposer,
    buildLifecycleRequest: buildLifecycleRequest,
    buildProjectionPayload: buildProjectionPayload,
    buildRollbackRequest: buildRollbackRequest,
    buildSavePayload: buildSavePayload,
    conditionValue: conditionValue,
    emptyComposerState: emptyComposerState,
    human: human,
    listOf: listOf,
    loadComposerState: loadComposerState,
    parseAnswer: parseAnswer,
    projectionChoices: projectionChoices,
    readBoundedJson: readBoundedJson,
    rowActions: rowActions,
    slug: slug
  };

  if (typeof document === "undefined") { return; }
  var shell = document.getElementById("grc-studio-shell");
  if (!shell) { return; }
  var apiBase = shell.dataset.apiBase;
  var permissions = {
    operate: shell.dataset.canOperate === "true",
    audit: shell.dataset.canAudit === "true",
    admin: shell.dataset.canAdmin === "true"
  };
  function $(id) { return document.getElementById(id); }
  var operations = $("grcs-operations");
  var statusMark = $("grcs-status-mark");
  var readiness = $("grcs-readiness");
  var readinessDetail = $("grcs-readiness-detail");
  var operationStatus = $("grcs-operation-status");
  var operationOutput = $("grcs-operation-output");
  var listStatus = $("grcs-list-status");
  var versionList = $("grcs-version-list");
  var builderPanel = $("grcs-builder-panel");
  var builderForm = $("grcs-builder-form");
  var composerState = emptyComposerState();
  var editing = { mode: "create", studioId: null, row: null };
  var allRows = [];
  var status = {};

  // ---------- small helpers ----------
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) { node.className = cls; }
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    return node;
  }
  function when(ts) {
    if (typeof global.mvWhen === "function") { return global.mvWhen(ts); }
    return ts ? (window.mvTimeAbsolute ? window.mvTimeAbsolute(ts) : new Date(ts * 1000).toLocaleString()) : "";
  }
  function plainError(error, action) {
    if (error && error.plain) { return error.message; }
    if (typeof global.mvErrorText === "function") { return global.mvErrorText(error, action); }
    return "Could not " + action + ". Try again.";
  }
  function report(message, technical) {
    operationStatus.textContent = message;
    operationOutput.textContent = technical === undefined ? "" : (typeof technical === "string" ? technical : JSON.stringify(technical, null, 2));
  }
  function fail(error, action) {
    var message = plainError(error, action);
    report(message, error && error.technical ? error.technical : "");
    if (typeof global.mvToast === "function") { global.mvToast(message, { error: true }); }
    if (error && error.status === 409) { loadVersions(); }
    return message;
  }
  function confirmed(message, okText) {
    if (typeof global.mvConfirm === "function") { return Promise.resolve(global.mvConfirm(message, { okText: okText })); }
    return Promise.resolve(global.confirm ? global.confirm(message) : false);
  }
  function ask(title, fields) {
    if (typeof global.mvForm === "function") { return Promise.resolve(global.mvForm(title, fields)); }
    var out = {};
    fields.forEach(function (field) { out[field.key] = field.default; });
    return Promise.resolve(out);
  }
  async function request(path, options) {
    var current = draftGeneration, controller = new AbortController(), timeout = setTimeout(function () { controller.abort(); }, 20000);
    draftCalls.add(controller);
    var settings = Object.assign({ credentials: "same-origin", signal: controller.signal, headers: { Accept: "application/json" } }, options || {});
    if (settings.body !== undefined && typeof settings.body !== "string") { settings.body = JSON.stringify(settings.body); settings.headers["Content-Type"] = "application/json"; }
    try { var response = await fetch(apiBase + path, settings); var result = await readBoundedJson(response); if (current !== draftGeneration) { throw problem("The account or workspace changed before the reply. Private details were cleared."); } return result; }
    finally { clearTimeout(timeout); draftCalls.delete(controller); }
  }
  function button(label, handler, cls, aria) {
    var node = el("button", cls || "btn btn--ghost", label);
    node.type = "button";
    if (aria) { node.setAttribute("aria-label", aria); }
    node.addEventListener("click", function () {
      if (node.disabled) { return; }
      node.disabled = true;
      Promise.resolve().then(handler).catch(function (error) { fail(error, "finish that"); })
        .then(function () { node.disabled = false; });
    });
    return node;
  }
  function download(name, value) {
    var blob = new Blob([JSON.stringify(value, null, 2)], { type: "application/json" });
    var url = URL.createObjectURL(blob);
    var link = document.createElement("a");
    link.href = url; link.download = name;
    document.body.appendChild(link); link.click(); link.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 0);
  }
  function readFile(input) {
    return new Promise(function (resolve, reject) {
      var file = input.files && input.files[0];
      input.value = "";
      if (!file) { resolve(null); return; }
      if (file.size > MAX_FILE_BYTES) { reject(problem("That file is too large. Choose a file under 2 MB.")); return; }
      var reader = new FileReader();
      reader.onload = function () {
        try { resolve(JSON.parse(String(reader.result || ""))); } catch (_error) { reject(problem("That file could not be read. Choose a file saved from this studio.")); }
      };
      reader.onerror = function () { reject(problem("That file could not be read. Choose it again, or try a different file.")); };
      reader.readAsText(file);
    });
  }
  function nameOf(row) {
    var ref = row && row.blueprint && row.blueprint.name_ref;
    return human(ref || (row && row.studio_id));
  }
  function latestVersion(studioId) {
    return allRows.filter(function (row) { return row.studio_id === studioId; })
      .reduce(function (max, row) { return Math.max(max, Number(row.version) || 0); }, 0);
  }
  function liveRow(studioId) {
    return allRows.find(function (row) { return row.studio_id === studioId && row.state === "published"; }) || null;
  }
  async function activePointer(studioId) {
    try {
      var result = await request("/studios/" + encodeURIComponent(studioId) + "/active");
      return result.pointer || null;
    } catch (error) {
      if (error && error.status === 404) { return null; }
      throw error;
    }
  }

  // ---------- availability ----------
  async function loadStatus() {
    statusMark.className = "badge idle";
    statusMark.textContent = "Checking";
    readiness.textContent = "Checking…";
    try {
      status = await request("/status");
      var ready = status.enabled === true && status.configured === true && status.ready === true;
      var connected = status.runtime_projection_apply_configured === true;
      operations.disabled = !ready;
      statusMark.className = "badge " + (ready ? "ok" : "failed");
      statusMark.textContent = ready ? "Ready to build" : "Not ready";
      readiness.textContent = ready ? "You can build and approve blueprints here." : (status.enabled ? "The studio is not set up yet." : "The studio is turned off.");
      readinessDetail.textContent = ready ? (connected
        ? "Destinations are connected. Check the specific destination before applying a published blueprint to it."
        : "Publishing makes a blueprint active in this studio. Use the questionnaire builder below to bring supported form questions into a reviewed questionnaire. Evidence checks and reports need their own supported destination.")
        : status.enabled ? "Ask an administrator to finish setting up the no-code GRC studio for this workspace."
          : "Ask an administrator to turn on the no-code GRC studio for this workspace.";
      $("grcs-projection-panel").hidden = !(ready && status.runtime_projection_preview_configured === true);
      $("grcs-projection-apply").disabled = !permissions.admin || status.runtime_projection_apply_configured !== true;
      if (ready) {
        await loadVersions();
        if (permissions.admin) { loadBackups(); }
        if (permissions.operate) { await currentDraftContext(); }
      } else {
        settleLoaders("Nothing to show until the studio is ready.");
      }
    } catch (error) {
      operations.disabled = true;
      statusMark.className = "badge failed";
      statusMark.textContent = "Not available";
      readiness.textContent = "The studio could not be reached. Check your connection and try again.";
      readinessDetail.textContent = plainError(error, "check the studio");
      settleLoaders(plainError(error, "load your blueprints"));
    }
  }
  // Nothing below loads until the studio is ready: say so in every loader
  // instead of leaving "Loading…" there.
  function settleLoaders(listText) {
    listStatus.textContent = listText;
    versionList.replaceChildren();
    fillSelect($("grcs-collector-choice"), [], "Not available until the studio is ready");
    fillSelect($("grcs-projection-target"), [], "Not available until the studio is ready");
    if (permissions.admin) { $("grcs-backup-status").textContent = "Backups appear here once the studio is ready."; }
  }

  // ---------- register ----------
  async function loadVersions() {
    listStatus.textContent = "Loading your blueprints…";
    try {
      var payload = await request("?limit=1000");
      allRows = Array.isArray(payload.items) ? payload.items : [];
      fillStudioFilter();
      renderVersions();
      fillProjection();
    } catch (error) {
      listStatus.textContent = plainError(error, "load your blueprints");
    }
    await loadSources();
  }

  // ---------- collectors and destinations to choose from ----------
  var sources = { collectors: [], destinations: [], listed: false, loaded: false };
  function collectorKey(item) { return item.collector_id + ":" + item.collector_version + ":" + item.collector_integrity_sha256; }
  function selectedCollector() { var key = $("grcs-collector-choice").value; return sources.collectors.find(function (item) { return collectorKey(item) === key; }); }
  async function loadSources() {
    var current = draftGeneration;
    try {
      var payload = await request("/sources");
      if (current !== draftGeneration) { return; }
      if (draftContext && payload.context !== draftContext) { privateBoundary(); throw problem("Your account, workspace or access changed. Read the current evidence choices again."); }
      sources = {
        collectors: Array.isArray(payload.collectors) ? payload.collectors.filter(function (item) {
          return item && ID.test(String(item.collector_id || "")) && Number.isSafeInteger(item.collector_version) &&
            item.collector_version > 0 && FINGERPRINT.test(String(item.collector_integrity_sha256 || "")) &&
            typeof item.label === "string" && Array.isArray(item.outputs) && Array.isArray(item.controls);
        }) : [],
        destinations: Array.isArray(payload.destinations) ? payload.destinations.filter(function (item) {
          return item && PROJECTION_LABEL[item.target_kind] && ID.test(String(item.target_id || "")) &&
            Number.isSafeInteger(item.target_revision) && item.target_revision > 0;
        }) : [],
        listed: payload.destinations_listed === true,
        loaded: true, notice: payload.collectors_notice || ""
      };
    } catch (error) {
      if (current !== draftGeneration) { return; }
      if (error && (error.status === 401 || error.status === 403)) { privateBoundary(); return; }
      sources = { collectors: [], destinations: [], listed: false, loaded: false };
    }
    fillCollectorChoices();
    fillTargetChoices();
  }
  function fillCollectorChoices() {
    var select = $("grcs-collector-choice");
    var note = $("grcs-collector-note");
    fillSelect(select, sources.collectors.map(function (item, index) {
      return { value: collectorKey(item), label: item.label + " · approved version " + item.collector_version };
    }), sources.collectors.length ? "Choose an approved source" : "No approved sources available");
    note.textContent = sources.notice || (sources.collectors.length ? "" : (sources.loaded
      ? "Set up an evidence source in Continuous evidence and have a different administrator approve it. It will appear here before its first blueprint link."
      : "Current evidence choices could not be verified. Your entered blueprint is kept; refresh the current choices before adding a link."));
    useCollector(true);
  }
  function useCollector(keepChoices) {
    var item = selectedCollector(), field = $("grcs-source-path"), controls = $("grcs-control-refs");
    var kept = keepChoices === true ? Array.from(controls.querySelectorAll("input:checked")).map(function (input) { return input.value; }) : [];
    $("grcs-collector-id").value = item ? item.collector_id : "";
    $("grcs-collector-version").value = item ? String(item.collector_version) : "";
    $("grcs-collector-digest").value = item ? item.collector_integrity_sha256 : "";
    if (keepChoices !== true) { field.value = ""; }
    fillSelect(field, item ? item.outputs.map(function (output) { return { value: output.path.join(","), label: output.label }; }) : [], "Choose a result field");
    controls.replaceChildren(el("legend", null, "Controls this link supports"));
    (item ? item.controls : []).forEach(function (control) {
      var label = el("label", "grcs-check"), input = document.createElement("input");
      input.type = "checkbox"; input.value = control.value; input.checked = kept.indexOf(control.value) >= 0;
      label.append(input, el("span", null, control.label)); controls.appendChild(label);
    });
    if (!item || !item.controls.length) { controls.appendChild(el("p", "muted", item ? "This source has no supported named controls for a blueprint link." : "Choose a source first.")); }
  }
  function fillTargetChoices() {
    var select = $("grcs-projection-target");
    var note = $("grcs-projection-target-note");
    var kind = String($("grcs-projection-definition").value || "").split(":")[0];
    var matching = [];
    sources.destinations.forEach(function (item, index) {
      if (!kind || item.target_kind === kind) {
        matching.push({ value: String(index), label: (item.label || human(item.target_id)) + " (version " + item.target_revision + ")" });
      }
    });
    fillSelect(select, matching, matching.length ? "Choose a destination" : "No destinations to choose from");
    note.textContent = matching.length ? "" : (sources.listed
      ? "No connected destination accepts this kind of item yet."
      : "Your installation does not list its destinations here. Ask your administrator for the destination, then enter it under Technical details.");
    useTarget();
  }
  function useTarget() {
    var form = $("grcs-projection-form");
    var item = sources.destinations[Number($("grcs-projection-target").value)];
    if ($("grcs-projection-target").value === "" || !item) { return; }
    form.elements.target_id.value = item.target_id;
    form.elements.target_revision.value = String(item.target_revision);
  }

  function fillStudioFilter() {
    var select = $("grcs-filter-studio");
    var chosen = select.value;
    var seen = {};
    select.replaceChildren(new Option("All blueprints", ""));
    allRows.forEach(function (row) {
      if (seen[row.studio_id]) { return; }
      seen[row.studio_id] = true;
      select.appendChild(new Option(nameOf(row), row.studio_id));
    });
    select.value = seen[chosen] ? chosen : "";
  }

  function renderVersions() {
    var studio = $("grcs-filter-studio").value;
    var state = $("grcs-filter-state").value;
    var rows = allRows.filter(function (row) { return (!studio || row.studio_id === studio) && (!state || row.state === state); });
    rows.sort(function (a, b) { return (b.updated_at || 0) - (a.updated_at || 0); });
    versionList.replaceChildren();
    $("grcs-list-count").textContent = allRows.length + (allRows.length === 1 ? " version" : " versions");
    if (!rows.length) {
      var tr = el("tr"); var td = el("td", null, allRows.length ? "No versions match these filters." : "No blueprints yet." + (permissions.operate ? " Choose “Start a new blueprint” to build one." : ""));
      td.colSpan = 5; tr.appendChild(td); versionList.appendChild(tr);
      listStatus.textContent = "";
      return;
    }
    rows.forEach(function (row) {
      var tr = el("tr");
      var th = el("th", null, nameOf(row)); th.scope = "row"; tr.appendChild(th);
      tr.appendChild(el("td", null, "Version " + row.version));
      var badgeCell = el("td"); badgeCell.appendChild(el("span", "badge " + (STATE_BADGE[row.state] || "idle"), STATE_LABEL[row.state] || human(row.state)));
      tr.appendChild(badgeCell);
      tr.appendChild(el("td", null, when(row.updated_at)));
      var actions = el("td"); var box = el("div", "grcs-actions", null);
      var label = nameOf(row) + " version " + row.version;
      rowActions(row, permissions).forEach(function (action) {
        var spec = ACTIONS[action];
        if (spec) { box.appendChild(button(spec.label, function () { return spec.run(row); }, spec.cls, spec.label + ": " + label)); }
      });
      actions.appendChild(box); tr.appendChild(actions);
      versionList.appendChild(tr);
    });
    listStatus.textContent = "Showing " + rows.length + " of " + allRows.length + ".";
  }

  function summaryOf(blueprint) {
    var parts = [];
    var fields = (blueprint.objects || []).reduce(function (sum, item) { return sum + (item.fields || []).length; }, 0);
    parts.push((blueprint.objects || []).length + " record types with " + fields + " fields");
    parts.push((blueprint.forms || []).length + " forms");
    parts.push((blueprint.rules || []).length + " rules");
    parts.push((blueprint.report_views || []).length + " reports");
    if ((blueprint.collector_bindings || []).length) { parts.push(blueprint.collector_bindings.length + " evidence links"); }
    return parts.join(", ");
  }

  function showBlueprint(row) {
    var panel = $("grcs-view-panel");
    var body = $("grcs-view-body");
    var blueprint = row.blueprint || {};
    $("grcs-view-title").textContent = nameOf(row) + " — version " + row.version;
    body.replaceChildren();
    body.appendChild(el("p", null, (STATE_LABEL[row.state] || human(row.state)) + ". " + summaryOf(blueprint) + "."));
    (blueprint.objects || []).forEach(function (object) {
      body.appendChild(el("h3", null, human(object.label_ref) + " (" + (KIND_LABEL[object.kind] || human(object.kind)) + ")"));
      var list = el("ul");
      (object.fields || []).forEach(function (field) {
        var bits = [TYPE_LABEL[field.field_type] || human(field.field_type)];
        if (field.required) { bits.push("required"); }
        if (field.options && field.options.length) { bits.push("choices: " + field.options.map(human).join(", ")); }
        list.appendChild(el("li", null, human(field.label_ref) + " — " + bits.join(", ")));
      });
      body.appendChild(list);
    });
    if ((blueprint.rules || []).length) {
      body.appendChild(el("h3", null, "Rules"));
      var rules = el("ul");
      blueprint.rules.forEach(function (rule) { rules.appendChild(el("li", null, describeRule(rule))); });
      body.appendChild(rules);
    }
    if ((blueprint.report_views || []).length) {
      body.appendChild(el("h3", null, "Reports"));
      var reports = el("ul");
      blueprint.report_views.forEach(function (view) { reports.appendChild(el("li", null, human(view.title_ref) + " — columns: " + view.columns.map(human).join(", "))); });
      body.appendChild(reports);
    }
    panel.hidden = false;
    $("grcs-view-title").focus();
  }

  var ACTIONS = {
    view: { label: "View", run: showBlueprint },
    edit: { label: "Edit", run: function (row) { openBuilder({ mode: "replace", row: row }); } },
    copy: { label: "New version from this", run: function (row) { openBuilder({ mode: "create", row: row }); } },
    submit: { label: "Send for review", cls: "btn", run: function (row) {
      return confirmed("Send “" + nameOf(row) + "” version " + row.version + " for review? You won't be able to change it while it's being reviewed.", "Send for review")
        .then(function (ok) { if (ok) { return lifecycle("submit", row, {}, "send it for review", "Sent for review."); } });
    } },
    accept: { label: "Accept review", cls: "btn", run: function (row) {
      return ask("Accept the review of " + nameOf(row), [{ key: "reason", label: "Your conclusion", type: "select", default: "meets-requirements", options: [
        { value: "meets-requirements", label: "It meets our requirements" },
        { value: "meets-requirements-with-notes", label: "It meets our requirements, with minor notes" }
      ] }]).then(function (values) { if (values) { return lifecycle("accept", row, values, "accept the review", "Review accepted. An administrator can now approve it."); } });
    } },
    reject: { label: "Send back", cls: "btn btn--danger", run: function (row) {
      return ask("Send " + nameOf(row) + " back", [{ key: "reason", label: "Why", type: "select", default: "needs-changes", options: [
        { value: "needs-changes", label: "It needs changes" },
        { value: "missing-fields", label: "Fields are missing" },
        { value: "rules-incorrect", label: "The rules are wrong" },
        { value: "not-needed", label: "It is not needed" }
      ] }]).then(function (values) { if (values) { return lifecycle("reject", row, values, "send it back", "Sent back to the author."); } });
    } },
    approve: { label: "Approve", cls: "btn btn--primary", run: function (row) {
      return ask("Approve " + nameOf(row), [{ key: "reason", label: "Approval basis", type: "select", default: "approved-for-release", options: [
        { value: "approved-for-release", label: "Approved for release" },
        { value: "approved-by-change-board", label: "Approved by the change board" }
      ] }]).then(function (values) { if (values) { return lifecycle("approve", row, values, "approve it", "Approved. It can now be published."); } });
    } },
    publish: { label: "Publish", cls: "btn btn--primary", run: function (row) {
      return confirmed("Publish “" + nameOf(row) + "” version " + row.version + "? It replaces the version active in this studio straight away.", "Publish")
        .then(async function (ok) {
          if (!ok) { return; }
          var pointer = await activePointer(row.studio_id);
          return lifecycle("publish", row, { pointer: pointer }, "publish it", status.runtime_projection_apply_configured === true
            ? "Published. Version " + row.version + " is now active."
            : "Published in this studio. Other questionnaires, evidence checks and reports are not connected yet.");
        });
    } },
    restore: { label: "Restore this version", cls: "btn", run: function (row) {
      return ask("Restore " + nameOf(row) + " version " + row.version, [{ key: "reason", label: "Why restore it", type: "select", default: "newer-version-has-problems", options: [
        { value: "newer-version-has-problems", label: "The newer version has problems" },
        { value: "requested-by-owner", label: "The owner asked for it" },
        { value: "audit-finding", label: "An audit finding" }
      ] }]).then(async function (values) {
        if (!values) { return; }
        var pointer = await activePointer(row.studio_id);
        var built = buildRollbackRequest(row, pointer, values.reason, operationId());
        try {
          var result = await request(built.path, { method: "POST", body: built.body });
          report("Restored. Version " + row.version + " is live again.", result);
          await loadVersions();
        } catch (error) { fail(error, "restore this version"); }
      });
    } },
    download: { label: "Download a copy", run: async function (row) {
      try {
        var result = await request("/operations/export", { method: "POST", body: { studio_id: row.studio_id, version: row.version, operation_id: operationId() } });
        download(row.studio_id + "-version-" + row.version + ".json", result);
        report("Downloaded a copy of " + nameOf(row) + " version " + row.version + ".");
      } catch (error) { fail(error, "download a copy"); }
    } },
    history: { label: "History", run: async function (row) {
      try {
        var result = await request("/studios/" + encodeURIComponent(row.studio_id) + "/versions/" + row.version + "/history");
        var list = $("grcs-history-list"); list.replaceChildren();
        (result.items || []).forEach(function (item) {
          var snapshot = item.snapshot || {};
          var tr = el("tr");
          tr.appendChild(el("td", null, when(snapshot.updated_at)));
          tr.appendChild(el("td", null, EVENT_LABEL[item.event_type] || human(item.event_type)));
          tr.appendChild(el("td", null, STATE_LABEL[snapshot.state] || human(snapshot.state)));
          list.appendChild(tr);
        });
        if (!list.children.length) { var tr = el("tr"); var td = el("td", null, "Nothing recorded yet. Entries appear here once the form is used."); td.colSpan = 3; tr.appendChild(td); list.appendChild(tr); }
        $("grcs-history-title").textContent = "History of " + nameOf(row) + " version " + row.version;
        $("grcs-history-panel").hidden = false;
        $("grcs-history-title").focus();
      } catch (error) { fail(error, "load the history"); }
    } }
  };

  async function lifecycle(action, row, options, what, done) {
    var built = buildLifecycleRequest(action, row, options, operationId());
    try {
      var result = await request(built.path, { method: "POST", body: built.body });
      report(done, result);
      await loadVersions();
    } catch (error) {
      if (error && error.status === 403) {
        fail(problem("Could not " + what + ". The person who built or reviewed a version can't also review or approve it, and some steps need an administrator."));
      } else {
        fail(error, what);
      }
    }
  }

  // ---------- builder ----------
  function openBuilder(options) {
    ++draftEditRevision; clearReview();
    var row = options && options.row;
    composerState = emptyComposerState();
    editing = { mode: "create", studioId: null, row: null };
    builderForm.reset();
    if (row && row.blueprint) {
      var loaded = loadComposerState(row.blueprint);
      composerState = loaded.state;
      $("grcs-name").value = loaded.metadata.name;
      $("grcs-description").value = loaded.metadata.description;
      editing = { mode: options.mode, studioId: row.studio_id, row: options.mode === "replace" ? row : null };
    }
    $("grcs-name").readOnly = Boolean(editing.studioId);
    $("grcs-builder-title").textContent = editing.mode === "replace" ? "Edit " + nameOf(row) + " (draft version " + row.version + ")" :
      editing.studioId ? "New version of " + nameOf(row) : "New blueprint";
    $("grcs-builder-mode").textContent = editing.mode === "replace" ? "Saving updates this draft." :
      editing.studioId ? "Saving creates version " + (latestVersion(editing.studioId) + 1) + " as a draft." : "Saving creates the first draft.";
    builderPanel.hidden = false;
    $("grcs-save-baseline").hidden = editing.mode !== "replace";
    renderComposer();
    $("grcs-builder-title").focus();
  }

  function objectById(id) { return composerState.objects.find(function (item) { return item.object_id === id; }) || null; }
  function fieldById(object, id) { return object ? object.fields.find(function (item) { return item.field_id === id; }) || null : null; }
  function needObject(selectId) {
    var object = objectById($(selectId).value);
    if (!object) { throw problem("Add a record type first (step 1)."); }
    return object;
  }
  function needField(object, selectId, what) {
    var field = fieldById(object, $(selectId).value);
    if (!field) { throw problem("Choose " + (what || "a field") + ". Add fields to “" + human(object.label_ref) + "” in step 2 first."); }
    return field;
  }

  function fillSelect(select, options, emptyText) {
    var chosen = select.value;
    select.replaceChildren();
    if (emptyText) { select.appendChild(new Option(emptyText, "")); }
    options.forEach(function (option) { select.appendChild(new Option(option.label, option.value)); });
    if (options.some(function (option) { return option.value === chosen; })) { select.value = chosen; }
  }

  function fillChecks(fieldset, object, name) {
    var checked = {};
    fieldset.querySelectorAll("input:checked").forEach(function (input) { checked[input.value] = true; });
    Array.prototype.slice.call(fieldset.querySelectorAll("label")).forEach(function (node) { node.remove(); });
    (object ? object.fields : []).forEach(function (field) {
      var label = el("label", "grcs-check", null);
      var input = document.createElement("input");
      input.type = "checkbox"; input.name = name; input.value = field.field_id; input.checked = Boolean(checked[field.field_id]);
      label.appendChild(input); label.appendChild(el("span", null, human(field.label_ref)));
      fieldset.appendChild(label);
    });
    if (!object || !object.fields.length) {
      var hint = el("label", "muted", "Add fields in step 2 first.");
      fieldset.appendChild(hint);
    }
  }

  function refreshSelectors() {
    var objects = composerState.objects.map(function (item) { return { value: item.object_id, label: human(item.label_ref) }; });
    document.querySelectorAll(".grcs-object-select").forEach(function (select) { fillSelect(select, objects); });
    document.querySelectorAll(".grcs-field-select").forEach(function (select) {
      var object = objectById($(select.dataset.objectSelect).value);
      var fields = object ? object.fields.map(function (field) { return { value: field.field_id, label: human(field.label_ref) }; }) : [];
      fillSelect(select, fields, select.dataset.empty || "");
    });
    fillChecks($("grcs-section-fields"), objectById($("grcs-form-object").value), "section_field");
    fillChecks($("grcs-view-columns"), objectById($("grcs-view-object").value), "view_column");
  }

  function listItem(text, removeLabel, onRemove) {
    var li = el("li");
    li.appendChild(el("span", null, text));
    li.appendChild(button("Remove", function () { onRemove(); renderComposer(); }, "btn btn--ghost", removeLabel));
    return li;
  }
  function renderList(id, items, emptyText) {
    var target = $(id); target.replaceChildren();
    if (!items.length) { target.appendChild(el("li", "muted", emptyText)); return; }
    items.forEach(function (item) { target.appendChild(item); });
  }
  function describeRule(rule) {
    var conditions = rule.when.conditions.map(function (condition) {
      return human(condition.field_id) + " " + (OPERATOR_LABEL[condition.operator] || human(condition.operator)) +
        (condition.value === null ? "" : " " + (typeof condition.value === "boolean" ? (condition.value ? "yes" : "no") : human(condition.value)));
    }).join(rule.when.mode === "any" ? " or " : " and ");
    var actions = rule.then.map(function (action) {
      if (action.action_type === "set_required") { return (action.value ? "require " : "make optional ") + human(action.target_field_id); }
      if (action.action_type === "set_visibility") { return (action.value ? "show " : "hide ") + human(action.target_field_id); }
      if (action.action_type === "set_default") { return "fill in " + human(action.target_field_id) + " with " + human(action.value); }
      if (action.action_type === "set_severity") { return "set severity to " + human(action.value); }
      return "create the task " + human(action.value);
    }).join(", ");
    return human(rule.rule_id) + ": when " + conditions + ", " + actions + ".";
  }

  function usedBy(objectId) {
    return composerState.forms.concat(composerState.rules, composerState.collector_bindings, composerState.report_views)
      .some(function (item) { return item.object_id === objectId; });
  }

  function renderComposer() {
    renderList("grcs-object-list", composerState.objects.map(function (item, index) {
      return listItem(human(item.label_ref) + " — " + (KIND_LABEL[item.kind] || human(item.kind)) + ", " + item.fields.length + " fields",
        "Remove record type " + human(item.label_ref), function () {
          if (usedBy(item.object_id)) { throw problem("Remove the forms, rules, reports and evidence links that use “" + human(item.label_ref) + "” first."); }
          composerState.objects.splice(index, 1);
        });
    }), "No record types yet.");
    var fieldItems = [];
    composerState.objects.forEach(function (object) {
      object.fields.forEach(function (field, index) {
        fieldItems.push(listItem(human(object.label_ref) + ": " + human(field.label_ref) + " — " + (TYPE_LABEL[field.field_type] || human(field.field_type)) + (field.required ? ", required" : ""),
          "Remove field " + human(field.label_ref), function () { object.fields.splice(index, 1); }));
      });
    });
    renderList("grcs-field-list", fieldItems, "No fields yet. Add the first field above.");
    renderList("grcs-form-list", composerState.forms.map(function (item, index) {
      return listItem(human(item.title_ref) + " — " + item.sections.map(function (section) { return human(section.label_ref); }).join(", "),
        "Remove form " + human(item.title_ref), function () { composerState.forms.splice(index, 1); });
    }), "No forms yet. Add a form above to collect answers.");
    renderList("grcs-rule-list", composerState.rules.map(function (item, index) {
      return listItem(describeRule(item), "Remove rule " + human(item.rule_id), function () { composerState.rules.splice(index, 1); });
    }), "No rules yet. Add a rule above to check answers.");
    renderList("grcs-view-list", composerState.report_views.map(function (item, index) {
      return listItem(human(item.title_ref) + " — " + item.columns.length + " columns", "Remove report " + human(item.title_ref), function () { composerState.report_views.splice(index, 1); });
    }), "No reports yet. Add a report above to show results.");
    renderList("grcs-binding-list", composerState.collector_bindings.map(function (item, index) {
      return listItem(human(item.binding_id) + " — fills " + item.field_mappings.map(function (mapping) { return human(mapping.target_field_id); }).join(", "),
        "Remove evidence link " + human(item.binding_id), function () { composerState.collector_bindings.splice(index, 1); });
    }), "No evidence links yet. Choose an approved source above to link its recorded results.");
    refreshSelectors();
    toggleFieldType();
    toggleActionType();
  }

  function toggleFieldType() {
    var type = $("grcs-field-type").value;
    $("grcs-field-options-label").hidden = ["single_choice", "multi_choice"].indexOf(type) < 0;
    $("grcs-field-reference-label").hidden = ["record_ref", "evidence_ref"].indexOf(type) < 0;
  }
  function toggleActionType() {
    var type = $("grcs-action-type").value;
    $("grcs-action-target-label").hidden = type === "severity" || type === "task";
    $("grcs-action-value-label").hidden = ["default", "severity", "task"].indexOf(type) < 0;
  }

  function added(message) { report(message); }

  function addObject() {
    var name = $("grcs-object-name").value;
    var id = slug(name, "the record type");
    if (objectById(id)) { throw problem("There is already a record type called “" + human(id) + "”."); }
    composerState.objects.push({ object_id: id, kind: $("grcs-object-kind").value, label_ref: id, description_ref: null, fields: [] });
    $("grcs-object-name").value = "";
    renderComposer();
    $("grcs-field-object").value = id; $("grcs-form-object").value = id; $("grcs-rule-object").value = id; $("grcs-view-object").value = id; $("grcs-binding-object").value = id;
    refreshSelectors();
    added("Added the record type “" + human(id) + "”. Now add its fields in step 2.");
  }

  function addField() {
    var object = needObject("grcs-field-object");
    var id = slug($("grcs-field-name").value, "the field");
    if (fieldById(object, id)) { throw problem("“" + human(object.label_ref) + "” already has a field called “" + human(id) + "”."); }
    var type = $("grcs-field-type").value;
    var choice = ["single_choice", "multi_choice"].indexOf(type) >= 0;
    var options = choice ? listOf($("grcs-field-options").value, "choice", 256, 1) : [];
    var field = {
      field_id: id, label_ref: id, field_type: type, required: $("grcs-field-required").checked,
      sensitivity: $("grcs-field-sensitivity").value, options: options,
      reference_kind: ["record_ref", "evidence_ref"].indexOf(type) >= 0 ? $("grcs-field-reference").value : null,
      default: null
    };
    var starting = $("grcs-field-default").value;
    if (String(starting).trim()) {
      if (type === "multi_choice" || type === "timestamp") { throw problem("This type of answer can't have a starting answer. Leave it blank."); }
      field.default = parseAnswer(field, starting);
    }
    object.fields.push(field);
    ["grcs-field-name", "grcs-field-options", "grcs-field-default"].forEach(function (key) { $(key).value = ""; });
    $("grcs-field-required").checked = false;
    renderComposer();
    added("Added the field “" + human(id) + "” to “" + human(object.label_ref) + "”.");
  }

  function checkedValues(fieldset) {
    return Array.prototype.map.call(fieldset.querySelectorAll("input:checked"), function (input) { return input.value; });
  }

  function addForm() {
    var object = needObject("grcs-form-object");
    var formId = slug($("grcs-form-name").value, "the form");
    var sectionId = slug($("grcs-section-name").value, "the section");
    var fields = checkedValues($("grcs-section-fields"));
    if (!fields.length) { throw problem("Tick at least one field for this section."); }
    var existing = composerState.forms.find(function (item) { return item.form_id === formId; });
    if (existing) {
      if (existing.object_id !== object.object_id) { throw problem("The form “" + human(formId) + "” is for “" + human(existing.object_id) + "”. Choose that record type or use a different form name."); }
      if (existing.sections.some(function (item) { return item.section_id === sectionId; })) { throw problem("That form already has a section called “" + human(sectionId) + "”."); }
      var used = {};
      existing.sections.forEach(function (section) { section.field_ids.forEach(function (id) { used[id] = true; }); });
      var repeated = fields.filter(function (id) { return used[id]; });
      if (repeated.length) { throw problem("“" + human(repeated[0]) + "” is already in another section of this form."); }
      existing.sections.push({ section_id: sectionId, label_ref: sectionId, field_ids: fields });
    } else {
      composerState.forms.push({ form_id: formId, object_id: object.object_id, title_ref: formId, sections: [{ section_id: sectionId, label_ref: sectionId, field_ids: fields }] });
    }
    $("grcs-section-name").value = "";
    renderComposer();
    added("Added the section “" + human(sectionId) + "” to the form “" + human(formId) + "”.");
  }

  function uniqueAction(rule, base) {
    var id = base.slice(0, 100); var n = 2;
    while (rule && rule.then.some(function (item) { return item.action_id === id; })) { id = base.slice(0, 96) + "-" + n; n += 1; }
    return id;
  }

  function addRule() {
    var object = needObject("grcs-rule-object");
    var ruleId = slug($("grcs-rule-name").value, "the rule");
    var mode = $("grcs-rule-mode").value === "any" ? "any" : "all";
    var whenField = needField(object, "grcs-condition-field", "the field to check");
    var operator = $("grcs-condition-operator").value;
    var condition = { field_id: whenField.field_id, operator: operator, value: conditionValue(whenField, operator, $("grcs-condition-value").value) };
    var kind = $("grcs-action-type").value;
    var existing = composerState.rules.find(function (item) { return item.rule_id === ruleId; });
    var action;
    if (kind === "severity" || kind === "task") {
      var text = $("grcs-action-value").value;
      if (!String(text).trim()) { throw problem(kind === "task" ? "Name the follow-up task." : "Enter the severity, for example High."); }
      var value = slug(text, kind === "task" ? "the task" : "the severity");
      action = { action_id: uniqueAction(existing, (kind === "task" ? "task-" : "severity-") + value), action_type: kind === "task" ? "emit_task_ref" : "set_severity", target_field_id: null, value: value };
    } else {
      var target = needField(object, "grcs-action-target", "the field to change");
      var types = { require: ["set_required", true], optional: ["set_required", false], show: ["set_visibility", true], hide: ["set_visibility", false] };
      if (kind === "default") {
        var filled = parseAnswer(target, $("grcs-action-value").value);
        if (filled === null) { throw problem("Enter the value to fill in."); }
        action = { action_id: uniqueAction(existing, "fill-" + target.field_id), action_type: "set_default", target_field_id: target.field_id, value: filled };
      } else if (types[kind]) {
        action = { action_id: uniqueAction(existing, kind + "-" + target.field_id), action_type: types[kind][0], target_field_id: target.field_id, value: types[kind][1] };
      } else {
        throw problem("Choose what the rule should do.");
      }
    }
    if (existing) {
      if (existing.object_id !== object.object_id) { throw problem("The rule “" + human(ruleId) + "” is for another record type. Use a different rule name."); }
      existing.when.mode = mode;
      existing.when.conditions.push(condition); existing.then.push(action);
    } else {
      composerState.rules.push({ rule_id: ruleId, object_id: object.object_id, when: { mode: mode, conditions: [condition] }, then: [action] });
    }
    $("grcs-condition-value").value = ""; $("grcs-action-value").value = "";
    renderComposer();
    added("Added to the rule “" + human(ruleId) + "”.");
  }

  function addView() {
    var object = needObject("grcs-view-object");
    var viewId = slug($("grcs-view-name").value, "the report");
    if (composerState.report_views.some(function (item) { return item.view_id === viewId; })) { throw problem("There is already a report called “" + human(viewId) + "”."); }
    var columns = checkedValues($("grcs-view-columns"));
    if (!columns.length) { throw problem("Tick at least one column."); }
    var view = { view_id: viewId, object_id: object.object_id, title_ref: viewId, columns: columns, filters: [], group_by: [], sort: [] };
    if ($("grcs-view-group").value) { view.group_by.push(needField(object, "grcs-view-group").field_id); }
    if ($("grcs-filter-field").value) {
      var filterField = needField(object, "grcs-filter-field");
      var operator = $("grcs-filter-operator").value;
      view.filters.push({ field_id: filterField.field_id, operator: operator, value: conditionValue(filterField, operator, $("grcs-filter-value").value) });
    }
    if ($("grcs-sort-field").value) {
      view.sort.push({ field_id: needField(object, "grcs-sort-field").field_id, direction: $("grcs-sort-direction").value === "descending" ? "descending" : "ascending" });
    }
    composerState.report_views.push(view);
    $("grcs-view-name").value = ""; $("grcs-filter-value").value = "";
    renderComposer();
    added("Added the report “" + human(viewId) + "”.");
  }

  function addBinding() {
    var object = needObject("grcs-binding-object");
    var bindingId = slug($("grcs-binding-name").value, "the evidence link");
    var collector = String($("grcs-collector-id").value || "").trim();
    var source = selectedCollector();
    if (!source || !ID.test(collector)) { throw problem("Choose a current approved source from the list."); }
    var version = Number($("grcs-collector-version").value);
    if (!Number.isSafeInteger(version) || version < 1) { throw problem("Choose a current approved source from the list."); }
    var fingerprint = String($("grcs-collector-digest").value || "").trim().toLowerCase();
    if (!FINGERPRINT.test(fingerprint)) { throw problem("The current approved source could not be verified. Refresh its choices before adding this link."); }
    var target = needField(object, "grcs-mapping-target", "the field to fill");
    var path = String($("grcs-source-path").value || "").split(",").map(function (item) { return item.trim(); }).filter(Boolean);
    if (!path.length || path.length > 16 || path.some(function (item) { return !ID.test(item); })) {
      throw problem("Choose a result field from this source.");
    }
    if (!source.outputs.some(function (output) { return output.path.join(",") === path.join(","); })) { throw problem("Choose a current named result field from this source."); }
    var mapping = { source_path: path, target_field_id: target.field_id, mode: $("grcs-mapping-mode").value === "append" ? "append" : "replace" };
    var controls = Array.from($("grcs-control-refs").querySelectorAll("input:checked")).map(function (input) { return input.value; });
    if (!controls.length || controls.some(function (control) { return !source.controls.some(function (row) { return row.value === control; }); })) { throw problem("Choose at least one supported named control."); }
    var existing = composerState.collector_bindings.find(function (item) { return item.binding_id === bindingId; });
    if (existing) {
      if (existing.object_id !== object.object_id || existing.collector_id !== collector || existing.collector_version !== version || existing.collector_integrity_sha256 !== fingerprint) {
        throw problem("The evidence link “" + human(bindingId) + "” uses a different source. Use a different link name.");
      }
      if (existing.field_mappings.some(function (item) { return item.target_field_id === target.field_id; })) { throw problem("This evidence link already fills “" + human(target.label_ref) + "”."); }
      existing.field_mappings.push(mapping);
      controls.forEach(function (control) { if (existing.control_refs.indexOf(control) < 0) { existing.control_refs.push(control); } });
    } else {
      composerState.collector_bindings.push({ binding_id: bindingId, collector_id: collector, collector_version: version, collector_integrity_sha256: fingerprint, object_id: object.object_id, field_mappings: [mapping], control_refs: controls });
    }
    renderComposer();
    added("Added the evidence link “" + human(bindingId) + "”.");
  }

  function currentBlueprint() {
    var name = $("grcs-name").value;
    var studioId = editing.studioId || slug(name, "the blueprint");
    if (!editing.studioId && allRows.some(function (row) { return row.studio_id === studioId; })) {
      throw problem("A blueprint called “" + human(studioId) + "” already exists. Use “New version from this” on it, or pick another name.");
    }
    return buildBlueprintFromComposer({ studio_id: studioId, name: name, description: $("grcs-description").value }, composerState);
  }

  // One retained original identity per browser; a lost reply never starts another save.
  var draftContext = "", draftGeneration = 0, draftEditRevision = 0, draftBusy = false, draftReview = null, draftOriginal = null;
  var draftCalls = new Set(), draftStorage = "lightwork-grc-original-save", originalRead = false;
  var saveReview = $("grcs-save-review"), saveOriginal = $("grcs-save-original");
  function clearReview() { draftReview = null; saveReview.hidden = true; $("grcs-save-review-body").replaceChildren(); $("grcs-save-confirm").checked = false; $("grcs-save-apply").disabled = true; }
  function privateBoundary() {
    ++draftGeneration; draftCalls.forEach(function (call) { call.abort(); }); draftContext = ""; draftOriginal = null; originalRead = false;
    clearReview(); saveOriginal.hidden = true; $("grcs-save-original-status").textContent = ""; $("grcs-save-original-current").textContent = "";
    composerState = emptyComposerState(); editing = { mode: "create", studioId: null, row: null }; builderForm.reset(); renderComposer(); builderPanel.hidden = true;
    allRows = []; versionList.replaceChildren(); $("grcs-list-count").textContent = "0 versions"; fillStudioFilter(); sources = { collectors: [], destinations: [], listed: false, loaded: false }; fillCollectorChoices(); fillProjection(); fillTargetChoices(); $("grcs-view-body").replaceChildren(); $("grcs-view-panel").hidden = true;
    $("grcs-history-list").replaceChildren(); $("grcs-history-panel").hidden = true; $("grcs-backup-list").replaceChildren(); $("grcs-retention-list").replaceChildren(); $("grcs-projection-form").reset(); operationOutput.textContent = "";
    operations.disabled = true; draftBusy = false; report("Private studio details were cleared because your account, workspace or access changed. Refresh in the current account to continue.");
  }
  async function draftRequest(path, body, expected) {
    var controller = new AbortController(), timeout = setTimeout(function () { controller.abort(); }, 20000), current = draftGeneration;
    draftCalls.add(controller);
    try {
      var response = await fetch("/api/v1/compliance/grc-draft-changes" + path, { method: body ? "POST" : "GET", credentials: "same-origin", cache: "no-store", signal: controller.signal,
        headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
      if (response.redirected || response.status === 401 || response.status === 403) { privateBoundary(); throw problem("Private details were cleared. Sign in with current studio permission before continuing."); }
      var value = await readBoundedJson(response);
      if (current !== draftGeneration) { throw problem("The account or workspace changed before the reply. Private details were cleared."); }
      if (expected && value.context !== expected) { privateBoundary(); throw problem("Your account, workspace or access changed. Private details were cleared."); }
      return value;
    } catch (error) {
      if (error && error.technical) { error.message = error.technical; error.plain = true; }
      if (error && error.status === 409 && String(error.message).indexOf("account, workspace or access changed") >= 0) { privateBoundary(); }
      if (error.name === "AbortError" || error instanceof TypeError || error instanceof SyntaxError) { throw problem("The reply is unconfirmed. Check the original save; nothing will be repeated automatically."); }
      throw error;
    } finally { clearTimeout(timeout); draftCalls.delete(controller); }
  }
  function draftLock(value) { draftBusy = value; $("grcs-save").disabled = value; $("grcs-save-read").disabled = value; $("grcs-save-restore").disabled = value; $("grcs-save-new").disabled = value; $("grcs-save-cancel").disabled = value; $("grcs-save-apply").disabled = value || !draftReview || !$("grcs-save-confirm").checked; }
  async function currentDraftContext(expected, mayPublish) {
    var value = await draftRequest("", undefined, expected || draftContext || undefined);
    if (mayPublish && !mayPublish()) { return value; }
    if (draftContext && draftContext !== value.context) { privateBoundary(); throw problem("Your account or workspace changed. Private details were cleared."); }
    if (!draftContext) { draftContext = value.context; }
    if (!draftOriginal) { try { var retained = JSON.parse(sessionStorage.getItem(draftStorage) || "null"); if (retained && retained.context === draftContext && typeof retained.token === "string" && retained.token.length <= 240000) { draftOriginal = retained; originalStatus("A previous reviewed save is retained. Check its original outcome before another save."); } } catch (_) {} }
    return value;
  }
  function originalStatus(message, value) {
    saveOriginal.hidden = !draftOriginal; $("grcs-save-original-status").textContent = message;
    $("grcs-save-original-current").textContent = value && value.confirmed ? value.name + " · version " + value.version + " · recorded change " + value.revision + ". " + (value.current || "") : "Current matching content is not an original receipt.";
    $("grcs-save-new").hidden = !originalRead;
  }
  function renderDraftReview(value) {
    if (!Array.isArray(value.changes) || !value.changes.length || value.changes.length > 512 || JSON.stringify(value.changes).length > 131072) { throw problem("The complete draft could not be displayed. No partial review can be confirmed."); }
    var body = $("grcs-save-review-body"); body.replaceChildren();
    value.changes.forEach(function (row) {
      if (!row || typeof row.label !== "string" || typeof row.before !== "string" || typeof row.after !== "string") { throw problem("The full review is unavailable. Keep editing; nothing was saved."); }
      var holder = body;
      if (row.technical) { holder = el("details"); holder.appendChild(el("summary", null, row.label)); body.appendChild(holder); }
      holder.appendChild(el("dt", null, row.label)); holder.appendChild(el("dd", null, "Current: " + row.before + "\nAfter save: " + row.after));
    });
    draftReview = value; saveReview.hidden = false; $("grcs-save-review-title").focus();
  }
  async function saveDraft(event) {
    event.preventDefault(); if (draftBusy) { return; } var current = draftGeneration; draftLock(true); clearReview();
    try {
      await currentDraftContext(); if (current !== draftGeneration) { return; }
      if (draftOriginal) { originalStatus("Check the retained original save first. A new review must be chosen explicitly after that lookup."); $("grcs-save-read").focus(); return; }
      var blueprint = currentBlueprint(), built = buildSavePayload(editing.mode === "replace" ? { mode: "replace", row: editing.row } : { mode: "create", latestVersion: latestVersion(blueprint.studio_id) }, blueprint, "review-only");
      var edited = draftEditRevision; delete built.body.operation_id; if (editing.mode === "replace") { built.body.version = editing.row.version; }
      var value = await draftRequest("/review", { context: draftContext, kind: editing.mode === "replace" ? "replace" : "create", studio: blueprint.studio_id, body: built.body }, draftContext);
      if (current !== draftGeneration) { return; } if (edited !== draftEditRevision) { report("Your entered work changed while this review was loading. Review your current choices again; nothing was saved."); return; } renderDraftReview(value); report("Review the complete current and proposed choices before saving.");
    } catch (error) { if (current === draftGeneration) { clearReview(); fail(error, "review the draft"); } }
    finally { if (current === draftGeneration) { draftLock(false); } }
  }
  $("grcs-save-baseline").addEventListener("click", async function () {
    if (draftBusy || editing.mode !== "replace") { return; } var current = draftGeneration, selected = editing.row; draftLock(true); clearReview();
    try { await currentDraftContext(); var row = await request("/studios/" + encodeURIComponent(selected.studio_id) + "/versions/" + selected.version); await currentDraftContext();
      if (current !== draftGeneration || editing.row !== selected) { return; } if (row.state !== "draft") { throw problem("This version is no longer editable. Choose “New version from this” in the register; your entered work is kept here."); }
      editing.row = row; report("Your entered choices are kept. The next complete review will compare them against the current saved draft, including other changes.");
    } catch (error) { if (current === draftGeneration) { fail(error, "update the saved comparison"); } } finally { if (current === draftGeneration) { draftLock(false); } }
  });
  $("grcs-save-confirm").addEventListener("change", function () { draftLock(draftBusy); });
  $("grcs-save-cancel").addEventListener("click", function () { clearReview(); $("grcs-save").focus(); });
  function editedDraft() { ++draftEditRevision; clearReview(); }
  builderForm.addEventListener("input", editedDraft); builderForm.addEventListener("change", editedDraft); builderForm.addEventListener("click", function (event) { if (event.target.closest("button") && event.target.id !== "grcs-save") { editedDraft(); } });
  $("grcs-save-apply").addEventListener("click", async function () {
    if (draftBusy || !draftReview || !$("grcs-save-confirm").checked) { return; } var current = draftGeneration, selected = draftReview;
    draftLock(true);
    try {
      await currentDraftContext(selected.context); if (current !== draftGeneration || draftReview !== selected) { return; }
      draftOriginal = { context: selected.context, token: selected.token }; originalRead = false;
      try { sessionStorage.setItem(draftStorage, JSON.stringify(draftOriginal)); } catch (_) { draftOriginal = null; throw problem("This browser cannot retain your original review. Free browser storage before saving; nothing was submitted."); }
      clearReview(); originalStatus("Saving the reviewed draft. If the reply is interrupted, check this original request without saving again.");
      var value = await draftRequest("/save", { token: selected.token, confirmed: true }, selected.context);
      if (current !== draftGeneration) { return; } originalRead = true; originalStatus(value.message, value); report(value.message);
      // Never replace the person's composer with an earlier result.
      await loadVersions();
    } catch (error) { if (current === draftGeneration) { originalStatus(draftOriginal ? "The original save is unconfirmed. Check its result without repeating it." : "Nothing was submitted."); fail(error, "confirm the original save"); } }
    finally { if (current === draftGeneration) { draftLock(false); } }
  });
  $("grcs-save-read").addEventListener("click", async function () {
    if (draftBusy || !draftOriginal) { return; } var current = draftGeneration, selected = draftOriginal; draftLock(true);
    try { var value = await draftRequest("/original", { token: selected.token }, selected.context); if (current !== draftGeneration) { return; } originalRead = true; originalStatus(value.message, value); report(value.message); }
    catch (error) { if (current === draftGeneration) { fail(error, "read the original save"); } }
    finally { if (current === draftGeneration) { draftLock(false); } }
  });
  $("grcs-save-new").addEventListener("click", function () { if (!draftBusy && originalRead) { draftOriginal = null; originalRead = false; sessionStorage.removeItem(draftStorage); saveOriginal.hidden = true; clearReview(); report("Your entered work is kept. Choose the current saved version before reviewing another save; the earlier original request remains historical."); $("grcs-save").focus(); } });
  $("grcs-save-restore").addEventListener("click", async function () {
    if (draftBusy || !draftOriginal || !await confirmed("Replace the entered editor choices with the retained original reviewed choices? This does not save anything.", "Restore choices")) { return; }
    if (!draftOriginal) { return; } var current = draftGeneration, selected = draftOriginal; draftLock(true);
    try { var value = await draftRequest("/choices", { token: selected.token }, selected.context); if (current !== draftGeneration) { return; }
      var input = value.inputs; openBuilder({ mode: value.kind === "replace" ? "replace" : "create", row: { studio_id: value.studio, blueprint: input.blueprint, version: input.version, revision: input.expected_revision, integrity_sha256: input.expected_integrity_sha256 } }); report("Original choices restored to the editor. Current-source review is required before any new save.");
    } catch (error) { if (current === draftGeneration) { fail(error, "restore reviewed choices"); } } finally { if (current === draftGeneration) { draftLock(false); } }
  });
  document.addEventListener("lightwork:copilot-context-changed", async function (event) {
    if (event.detail && event.detail.reason === "selection") { var selected = draftReview, current = draftGeneration; try { if (selected) { await draftRequest("/review-status", { token: selected.token }, selected.context); } else { await currentDraftContext(); } } catch (error) { if (current === draftGeneration) { if (draftReview === selected) { clearReview(); } fail(error, "verify current access"); } } }
    else { privateBoundary(); }
  });
  global.addEventListener("lightwork:copilot-context-changed", privateBoundary);
  document.addEventListener("lightwork:account-context-changed", privateBoundary);
  global.LightworkGRCDraft = { open: async function (expected, original, isActive) {
    var active = typeof isActive === "function" ? isActive : function () { return true; }; if (draftBusy || !active()) { return false; } var current = draftGeneration;
    await currentDraftContext(expected, function () { return current === draftGeneration && active(); }); if (current !== draftGeneration || !active() || draftContext !== expected) { return false; }
    if (draftReview) { await draftRequest("/review-status", { token: draftReview.token }, expected); if (current !== draftGeneration || !active()) { return false; } }
    if (original) { if (!draftOriginal) { report("No original save is retained in this browser for the current account. Open its saved draft from the register; matching content cannot establish an earlier request."); return false; } saveOriginal.hidden = false; saveOriginal.scrollIntoView({ block: "start" }); $("grcs-save-read").focus(); }
    else { if (builderPanel.hidden) { openBuilder(null); } builderPanel.scrollIntoView({ block: "start" }); $("grcs-name").focus(); }
    return true;
  } };

  // ---------- projection ----------
  function fillProjection() {
    var studioSelect = $("grcs-projection-studio");
    var live = allRows.filter(function (row) { return row.state === "published"; });
    fillSelect(studioSelect, live.map(function (row) { return { value: row.studio_id, label: nameOf(row) + " (version " + row.version + ")" }; }));
    fillDefinitions();
  }
  function fillDefinitions() {
    var row = liveRow($("grcs-projection-studio").value);
    fillSelect($("grcs-projection-definition"), row ? projectionChoices(row.blueprint) : []);
  }

  async function projection(event) {
    event.preventDefault();
    var apply = event.submitter && event.submitter.value === "apply";
    var what = apply ? "put it into use" : "preview it";
    try {
      var row = liveRow($("grcs-projection-studio").value);
      if (!row) { throw problem("Publish a blueprint first."); }
      var form = event.currentTarget;
      var payload = buildProjectionPayload(row, $("grcs-projection-definition").value, { target_id: form.elements.target_id.value, target_revision: form.elements.target_revision.value }, apply ? operationId() : null);
      if (apply) {
        var ok = await confirmed("Send this to “" + payload.target_id + "” now? The destination changes straight away.", "Put into use");
        if (!ok) { return; }
      }
      var result = await request("/operations/projections/" + (apply ? "apply" : "preview"), { method: "POST", body: payload });
      var choice = $("grcs-projection-definition").selectedOptions[0];
      report((apply ? "Sent " : "Preview ready for ") + (choice ? choice.textContent : "the selection") + " to “" + payload.target_id + "”." + (apply ? "" : " Open Technical details to see exactly what would change."), result);
    } catch (error) { fail(error, what); }
  }

  // ---------- import ----------
  async function importCopy() {
    try {
      var envelope = await readFile($("grcs-import-file"));
      if (!envelope) { return; }
      if (!envelope || typeof envelope !== "object" || !ID.test(String(envelope.studio_id || "")) || !envelope.blueprint) {
        throw problem("That file is not a copy downloaded from this studio.");
      }
      var ok = await confirmed("Bring in “" + human(envelope.blueprint.name_ref || envelope.studio_id) + "” as a new draft?", "Bring in");
      if (!ok) { return; }
      var result = await request("/operations/import", { method: "POST", body: { envelope: envelope, expected_latest_version: latestVersion(envelope.studio_id), operation_id: operationId() } });
      report("Brought in as draft version " + (result.version || "") + ".", result);
      await loadVersions();
    } catch (error) { fail(error, "bring in the copy"); }
  }

  // ---------- maintenance ----------
  async function checkIntegrity() {
    try {
      var result = await request("/operations/integrity");
      var counts = result.counts || {};
      report(result.verified === true ? "Everything checks out: " + (counts.versions || 0) + " versions and their history are unchanged." :
        "Some records could not be confirmed as unchanged. Contact your administrator.", result);
    } catch (error) {
      fail(error && error.status === 503 ? problem("Some records could not be confirmed as unchanged. Contact your administrator.") : error, "check the records");
    }
  }
  async function showRetention() {
    try {
      var result = await request("/operations/retention?limit=1000");
      var items = result.items || [];
      renderList("grcs-retention-list", items.map(function (item) {
        return el("li", null, nameOf(item) + " version " + item.version + " — " + (STATE_LABEL[item.state] || human(item.state)) + ", due " + when(item.retention_due_at));
      }), "No versions are due for deletion.");
      report(items.length ? items.length + " sent-back versions are due for deletion." : "No versions are due for deletion.");
      return items.length;
    } catch (error) { fail(error, "load the versions due for deletion"); return 0; }
  }
  async function purgeDue() {
    var count = await showRetention();
    if (!count) { return; }
    var ok = await confirmed("Permanently delete the content of " + count + " sent-back version" + (count === 1 ? "" : "s") + " that are past their keep-until date? A record that they existed is kept.", "Delete");
    if (!ok) { return; }
    try {
      var result = await request("/operations/retention/purge", { method: "POST", body: { limit: 1000 } });
      report("Deleted " + (result.purged_count || 0) + " versions.", result);
      await showRetention();
      await loadVersions();
    } catch (error) { fail(error, "delete the versions"); }
  }
  async function loadBackups() {
    var statusLine = $("grcs-backup-status");
    var list = $("grcs-backup-list");
    try {
      var result = await request("/operations/recovery/backups");
      var items = result.items || [];
      list.replaceChildren();
      statusLine.textContent = items.length ? "" : "No backups yet. Save a backup above before you change a blueprint.";
      items.forEach(function (item) {
        var tr = el("tr");
        tr.appendChild(el("td", null, when(item.created_at)));
        var cell = el("td");
        var outcome = el("span", "muted", "");
        cell.appendChild(button("Check it", async function () {
          try {
            var verified = await request("/operations/recovery/backups/" + encodeURIComponent(item.backup_id));
            outcome.className = "badge " + (verified.verified === true ? "ok" : "failed");
            outcome.textContent = verified.verified === true ? "Intact" : "Could not confirm";
            report(verified.verified === true ? "The backup from " + when(item.created_at) + " is intact." : "Could not confirm the backup is intact. Refresh the page and try again.", verified);
          } catch (error) {
            outcome.className = "badge failed"; outcome.textContent = "Could not confirm";
            fail(error, "check the backup");
          }
        }, "btn btn--ghost", "Check the backup from " + when(item.created_at)));
        cell.appendChild(document.createTextNode(" "));
        cell.appendChild(outcome);
        tr.appendChild(cell);
        list.appendChild(tr);
      });
    } catch (error) { statusLine.textContent = plainError(error, "load backups"); }
  }
  async function makeBackup() {
    try {
      var result = await request("/operations/recovery/backups", { method: "POST" });
      report("Backup made.", result);
      await loadBackups();
    } catch (error) { fail(error, "make a backup"); }
  }

  // ---------- wiring ----------
  function guarded(handler) {
    return function () { try { handler(); } catch (error) { fail(error, "add that"); } };
  }
  $("grcs-refresh-status").addEventListener("click", loadStatus);
  $("grcs-filter-studio").addEventListener("change", renderVersions);
  $("grcs-filter-state").addEventListener("change", renderVersions);
  $("grcs-new").addEventListener("click", function () { openBuilder(null); });
  $("grcs-builder-close").addEventListener("click", function () { builderPanel.hidden = true; });
  $("grcs-view-close").addEventListener("click", function () { $("grcs-view-panel").hidden = true; });
  $("grcs-history-close").addEventListener("click", function () { $("grcs-history-panel").hidden = true; });
  $("grcs-add-object").addEventListener("click", guarded(addObject));
  $("grcs-add-field").addEventListener("click", guarded(addField));
  $("grcs-add-form").addEventListener("click", guarded(addForm));
  $("grcs-add-rule").addEventListener("click", guarded(addRule));
  $("grcs-add-view").addEventListener("click", guarded(addView));
  $("grcs-add-binding").addEventListener("click", guarded(addBinding));
  $("grcs-field-type").addEventListener("change", toggleFieldType);
  $("grcs-action-type").addEventListener("change", toggleActionType);
  ["grcs-form-object", "grcs-rule-object", "grcs-view-object", "grcs-binding-object", "grcs-field-object"].forEach(function (id) {
    $(id).addEventListener("change", refreshSelectors);
  });
  builderForm.addEventListener("submit", saveDraft);
  $("grcs-import-blueprint").addEventListener("click", function () { $("grcs-import-blueprint-file").click(); });
  $("grcs-import-blueprint-file").addEventListener("change", async function () {
    try {
      var value = await readFile($("grcs-import-blueprint-file"));
      if (!value) { return; }
      var loaded = loadComposerState(value);
      composerState = loaded.state;
      if (!editing.studioId) { $("grcs-name").value = loaded.metadata.name; }
      $("grcs-description").value = loaded.metadata.description;
      renderComposer();
      report("Loaded the blueprint from the file. Check it, then save it as a draft.");
    } catch (error) { fail(error, "load the file"); }
  });
  $("grcs-download-blueprint").addEventListener("click", function () {
    try {
      var blueprint = currentBlueprint();
      download(blueprint.studio_id + "-blueprint.json", blueprint);
      report("Saved the blueprint to a file.");
    } catch (error) { fail(error, "save the file"); }
  });
  $("grcs-reset-composer").addEventListener("click", function () {
    confirmed("Clear everything you've added to this blueprint?", "Clear").then(function (ok) {
      if (!ok) { return; }
      composerState = emptyComposerState(); renderComposer(); report("Cleared.");
    });
  });
  $("grcs-projection-studio").addEventListener("change", function () { fillDefinitions(); fillTargetChoices(); });
  $("grcs-projection-definition").addEventListener("change", fillTargetChoices);
  $("grcs-projection-target").addEventListener("change", useTarget);
  $("grcs-collector-choice").addEventListener("change", useCollector);
  $("grcs-projection-form").addEventListener("submit", projection);
  $("grcs-import").addEventListener("click", function () { $("grcs-import-file").click(); });
  $("grcs-import-file").addEventListener("change", importCopy);
  $("grcs-integrity").addEventListener("click", checkIntegrity);
  $("grcs-retention").addEventListener("click", showRetention);
  $("grcs-retention-purge").addEventListener("click", purgeDue);
  $("grcs-backup").addEventListener("click", makeBackup);

  renderComposer();
  // A turned-off studio shows its gate instead: nothing is checked or loaded,
  // and the page already says when blueprints will appear.
  if (shell.dataset.moduleEnabled !== "false") { loadStatus(); }
}(typeof window !== "undefined" ? window : globalThis));
