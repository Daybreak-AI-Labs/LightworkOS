/* Governed knowledge access. Every response is context- and schema-bound, and
   every value is rendered through textContent. */
(function () {
  "use strict";

  var root = document.getElementById("knowledge-access");
  if (!root) { return; }
  var context = String(root.dataset.context || "");
  var tenant = String(root.dataset.tenant || "");
  var actor = String(root.dataset.actor || "");
  var apiBase = String(root.dataset.apiBase || "/api/v1/knowledge-access");
  var canReview = root.dataset.canReview === "true";
  var maxResponseBytes = 4 * 1024 * 1024;
  var searchForm = document.getElementById("ka-search-form");
  var searchButton = document.getElementById("ka-search");
  var exportButton = document.getElementById("ka-export");
  var status = document.getElementById("ka-status");
  var searchNote = document.getElementById("ka-search-note");
  var results = document.getElementById("ka-results");
  var detailPanel = document.getElementById("ka-detail-panel");
  var detailHeading = document.getElementById("ka-detail-heading");
  var detail = document.getElementById("ka-detail");
  var requestForm = document.getElementById("ka-request-form");
  var requestSource = document.getElementById("ka-request-source");
  var requestType = document.getElementById("ka-request-type");
  var correctionField = document.getElementById("ka-correction-field");
  var correction = document.getElementById("ka-proposed-correction");
  var submitRequest = document.getElementById("ka-submit-request");
  var requests = document.getElementById("ka-requests");
  var refreshRequests = document.getElementById("ka-refresh-requests");
  var showArchived = document.getElementById("ka-show-archived");
  var showReady = document.getElementById("ka-show-ready");
  var findArchived = document.getElementById("ka-find-archived");
  var capacityNote = document.getElementById("ka-capacity");
  var archivedView = false;
  var readyView = false;
  var archiveAvailable = true;
  var recoveryCursor = null;
  var requestPageCursor = "";
  var batchNote = document.getElementById("ka-batch-note");
  var batchCopilot = document.getElementById("ka-batch-copilot");
  var currentItems = [];
  var selectedReference = null;
  var pending = false;
  var searchGeneration = 0;
  var activeSearch = null;
  var nextCursor = null;
  var deniedPaths = new Set();
  var unconfirmedPaths = new Set();
  var access = window.LightworkAccessState.create(function () {
    return [root.dataset.context, root.dataset.tenant, root.dataset.actor].join(":");
  }, clearPrivate);
  var SHA = /^[a-f0-9]{64}$/;
  var ID = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
  var PURPOSE = /^[a-z][a-z0-9_.-]{0,63}$/;

  if (!SHA.test(context) || !tenant || !actor.startsWith("user:") ||
      !searchForm || !searchButton || !exportButton || !status ||
      !searchNote || !results || !detailPanel || !detailHeading || !detail || !requests ||
      !refreshRequests) { return; }

  var nextButton = node("button", "btn", "Next results");
  nextButton.id = "ka-next-results";
  nextButton.type = "button";
  nextButton.hidden = true;
  searchNote.after(nextButton);
  var recoveryMore = node("button", "btn", "Next batch");
  if (recoveryMore) {
    recoveryMore.id = "ka-recovery-more";
    recoveryMore.type = "button";
    recoveryMore.hidden = true;
    requests.after(recoveryMore);
  }
  refreshRequests.textContent = "Start over";

  // A reply this page could not verify is shown as one plain sentence; the
  // precise reason stays on the error for the technical record. Messages
  // meant for people pass an explicit code.
  var UNVERIFIED = "Something changed while loading. Refresh the page and try again.";
  function failure(message, code) {
    var error = new Error(code ? message : UNVERIFIED);
    error.code = code || "invalid_response";
    error.technical = message;
    return error;
  }

  function text(value, label, maximum, allowEmpty) {
    if (typeof value !== "string" || (!allowEmpty && !value.trim()) ||
        new TextEncoder().encode(value).length > maximum ||
        /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value)) {
      throw failure("The knowledge response contained an invalid " + label + ".");
    }
    return value;
  }

  function finiteTime(value, label, optional) {
    if (optional && value === null) { return null; }
    if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
      throw failure("The knowledge response contained an invalid " + label + ".");
    }
    return value;
  }

  function bool(value, label) {
    if (typeof value !== "boolean") {
      throw failure("The knowledge response contained an invalid " + label + ".");
    }
    return value;
  }

  function boundedArray(value, label, maximum) {
    if (!Array.isArray(value) || value.length > maximum) {
      throw failure("The knowledge response contained an invalid " + label + ".");
    }
    return value;
  }

  function reference(value, allowModel) {
    if (!value || typeof value !== "object" ||
        (value.kind !== "dataset" && !(allowModel && value.kind === "model")) ||
        !ID.test(value.asset_id) || !ID.test(value.version) ||
        !SHA.test(value.manifest_sha256) ||
        value.schema !== "lightwork.research-registry-ref.v1") {
      throw failure("A source in the answer could not be matched to its exact place. Refresh the page and try again.");
    }
    return {
      kind: value.kind,
      asset_id: value.asset_id,
      version: value.version,
      manifest_sha256: value.manifest_sha256,
      schema: value.schema
    };
  }

  function sameReference(left, right) {
    return left && right && left.kind === right.kind && left.asset_id === right.asset_id &&
      left.version === right.version && left.manifest_sha256 === right.manifest_sha256 &&
      left.schema === right.schema;
  }

  function derivative(value) {
    if (!value || typeof value !== "object") {
      throw failure("The rights response contained malformed derivative lineage.");
    }
    var exact = reference(value.reference, true);
    var action = text(value.required_action, "derivative action", 64, false);
    if (["invalidate_dataset", "retire_or_retrain_model"].indexOf(action) < 0) {
      throw failure("The rights response contained an unsupported derivative action.");
    }
    return {
      reference: exact,
      current_state: text(value.current_state, "derivative state", 64, false),
      required_action: action,
      authority_owner: text(value.authority_owner, "derivative authority owner", 64, false),
      workflow_state: text(value.workflow_state, "derivative workflow state", 96, false)
    };
  }

  function retentionHold(value) {
    if (value === null) { return null; }
    if (!value || typeof value !== "object" ||
        value.schema !== "lightwork.knowledge-retention-hold.v1" ||
        !ID.test(value.hold_id) ||
        ["active", "released"].indexOf(value.status) < 0 ||
        ["active", "released", "expired"].indexOf(value.effective_status) < 0 ||
        !SHA.test(value.evidence_sha256) ||
        typeof value.placed_by !== "string" || !value.placed_by.startsWith("user:")) {
      throw failure("The rights response contained a malformed retention hold.");
    }
    var released = value.status === "released";
    var placedAt = finiteTime(value.placed_at, "retention hold time", false);
    var expiresAt = finiteTime(value.expires_at, "retention hold expiry", false);
    if (expiresAt <= placedAt ||
        (released && value.effective_status !== "released") ||
        (!released && value.effective_status === "released")) {
      throw failure("The rights response contained a malformed retention hold timeline.");
    }
    if (!released &&
        (value.released_by !== null || value.released_at !== null ||
         value.release_reason !== null || value.release_evidence_sha256 !== null)) {
      throw failure("The rights response contained unexpected hold release material.");
    }
    if (released &&
        (typeof value.released_by !== "string" || !value.released_by.startsWith("user:") ||
         !SHA.test(value.release_evidence_sha256) ||
         finiteTime(value.released_at, "retention release time", false) < placedAt)) {
      throw failure("The rights response could not be verified. Refresh the page and try again.");
    }
    return {
      schema: value.schema,
      hold_id: value.hold_id,
      basis: text(value.basis, "retention hold basis", 2000, false),
      evidence_sha256: value.evidence_sha256,
      placed_by: text(value.placed_by, "retention hold actor", 512, false),
      placed_at: placedAt,
      expires_at: expiresAt,
      status: value.status,
      effective_status: value.effective_status,
      released_by: released ? value.released_by : null,
      released_at: released ? finiteTime(value.released_at, "retention release time", false) : null,
      release_reason: released ? text(value.release_reason, "retention release reason", 2000, false) : null,
      release_evidence_sha256: released ? value.release_evidence_sha256 : null
    };
  }

  function feedback(value) {
    if (!value || value.schema !== "lightwork.knowledge-feedback.v1" || !/^knowledge-req-[a-f0-9]{40}$/.test(value.id) ||
        ["submitted", "applying", "approved", "denied"].indexOf(value.status) < 0) throw failure("Invalid feedback receipt");
    return {schema:value.schema, id:value.id, status:value.status,
      request_type:text(value.request_type, "request type", 20, false),
      reason:text(value.reason, "request reason", 2000, false),
      proposed_correction:value.proposed_correction === null ? null : text(value.proposed_correction, "correction", 8192, true),
      created_at:finiteTime(value.created_at, "request time", false),
      updated_at:finiteTime(value.updated_at, "request update time", false),
      notice:text(value.notice, "request notice", 1000, false),
      source_use_status:text(value.source_use_status, "source use status", 96, false),
      raw_record_status:text(value.raw_record_status, "record status", 96, false),
      retention_review_status:text(value.retention_review_status, "retention review", 96, false),
      archived_at:value.archived_at === undefined || value.archived_at === null ?
        null : finiteTime(value.archived_at, "archive time", false)};
  }

  function rightsRequest(value) {
    if (!value || typeof value !== "object" ||
        value.schema !== "lightwork.knowledge-rights-request.v1" ||
        typeof value.revision !== "number" || !Number.isInteger(value.revision) ||
        value.revision < 1 || !/^knowledge-req-[a-f0-9]{40}$/.test(value.id) ||
        ["correction", "deletion", "exclusion"].indexOf(value.request_type) < 0 ||
        ["submitted", "applying", "approved", "denied"].indexOf(value.status) < 0 ||
        value.lineage_revalidated_before_return !== true) {
      throw failure("The rights response contained a malformed request.");
    }
    var proposed = value.proposed_correction === null ? null :
      text(value.proposed_correction, "proposed correction", 8192, true);
    var evidence = value.decision_evidence_sha256;
    if (evidence !== null && !SHA.test(evidence)) {
      throw failure("The access decision could not be read. Refresh the page and try again.");
    }
    if (value.status === "applying" &&
        (value.decision !== "approve" || typeof value.decided_by !== "string" ||
         !value.decided_by.startsWith("user:") || !SHA.test(evidence))) {
      throw failure("The rights response contained malformed recovery authority.");
    }
    return {
      schema: value.schema,
      id: value.id,
      revision: value.revision,
      request_type: value.request_type,
      status: value.status,
      source_reference: reference(value.source_reference),
      requested_by: text(value.requested_by, "requester", 512, false),
      reason: text(value.reason, "request reason", 2000, false),
      proposed_correction: proposed,
      source_use_status: text(value.source_use_status, "source use status", 96, false),
      raw_record_status: text(value.raw_record_status, "raw record status", 96, false),
      retention_review_status: text(value.retention_review_status, "retention review status", 96, false),
      retention_hold: retentionHold(value.retention_hold === undefined ? null : value.retention_hold),
      replacement_reference: value.replacement_reference === null || value.replacement_reference === undefined ?
        null : reference(value.replacement_reference),
      replacement_status: value.replacement_status === null || value.replacement_status === undefined ?
        null : text(value.replacement_status, "replacement status", 96, false),
      decision: value.decision === null ? null : text(value.decision, "decision", 16, false),
      decided_by: value.decided_by === null ? null : text(value.decided_by, "reviewer", 512, false),
      decision_evidence_sha256: evidence,
      derivatives: boundedArray(value.derivatives, "derivative list", 128).map(derivative),
      derivatives_at_request: boundedArray(
        value.derivatives_at_request || value.derivatives,
        "recorded derivative list",
        128
      ).map(derivative),
      lineage_revalidated_before_return: value.lineage_revalidated_before_return === true,
      archive_ready: value.archive_ready === true,
      archived_at: value.archived_at === undefined || value.archived_at === null ?
        null : finiteTime(value.archived_at, "archive time", false),
      weight_influence_notice: text(value.weight_influence_notice, "weight notice", 1000, false),
      training_permission_notice: text(value.training_permission_notice, "training notice", 1000, false),
      created_at: finiteTime(value.created_at, "request time", false),
      updated_at: finiteTime(value.updated_at, "request update time", false)
    };
  }

  function item(value, boundary) {
    if (!value || typeof value !== "object" || value.schema !== "lightwork.knowledge-detail.v1") {
      throw failure("The knowledge response contained an unsupported detail record.");
    }
    var exact = reference(value.reference);
    var source = value.source;
    var eligibility = value.eligibility;
    var cache = value.cache;
    if (!source || typeof source !== "object" || !eligibility || typeof eligibility !== "object" ||
        !cache || typeof cache !== "object" || eligibility.state !== "eligible" ||
        !PURPOSE.test(eligibility.purpose) ||
        ["analyze", "export", "read", "train"].indexOf(eligibility.permitted_action) < 0 ||
        ["analyze", "export", "read", "train"].indexOf(eligibility.requested_action) < 0 ||
        typeof eligibility.actor !== "string" || !eligibility.actor.startsWith("user:") ||
        !SHA.test(eligibility.actor_authorization_sha256) ||
        !SHA.test(source.content_sha256) || source.version !== exact.version ||
        source.authority_owner !== "research_registry" ||
        ["source", "derived", "synthetic"].indexOf(source.provenance_kind) < 0 ||
        ["verified", "inferred"].indexOf(value.claim_state) < 0 ||
        cache.owner !== "knowledge_access_process_projection" ||
        cache.content_revalidated_before_return !== true ||
        (boundary && eligibility.purpose !== boundary.purpose) ||
        (boundary && eligibility.requested_action !== boundary.action) ||
        (boundary && eligibility.actor !== boundary.actor) ||
        (boundary && boundary.authorizationSha256 &&
          eligibility.actor_authorization_sha256 !== boundary.authorizationSha256)) {
      throw failure("The knowledge answer included a source it may not use, so it is not shown. Refresh the page and try again.");
    }
    var history = boundedArray(value.correction_history, "correction history", 50).map(rightsRequest);
    var constraints = boundedArray(source.usage_constraints, "usage constraints", 32).map(function (entry) {
      return text(entry, "usage constraint", 256, false);
    });
    return {
      schema: value.schema,
      reference: exact,
      title: text(value.title, "title", 240, false),
      summary: text(value.summary, "summary", 8192, true),
      content_available: bool(value.content_available, "content availability"),
      claim_state: value.claim_state,
      observed_at: finiteTime(value.observed_at, "observation time", true),
      verified_at: finiteTime(value.verified_at, "verification time", true),
      source: {
        authority_owner: source.authority_owner,
        source_ref: text(source.source_ref, "source reference", 2048, false),
        version: source.version,
        content_sha256: source.content_sha256,
        provenance_kind: source.provenance_kind,
        license_id: text(source.license_id, "license", 128, false),
        usage_constraints: constraints
      },
      eligibility: {
        state: "eligible",
        checked_at: finiteTime(eligibility.checked_at, "eligibility check time", false),
        purpose: eligibility.purpose,
        permitted_action: eligibility.permitted_action,
        fresh_until: finiteTime(eligibility.fresh_until, "freshness time", false),
        consent_until: finiteTime(eligibility.consent_until, "consent time", true),
        approval_sha256: SHA.test(eligibility.approval_sha256) ? eligibility.approval_sha256 :
          (function () { throw failure("The approval record in the answer could not be read. Refresh the page and try again."); }()),
        requested_action: eligibility.requested_action,
        actor: text(eligibility.actor, "authorized actor", 512, false),
        actor_authorization_sha256: eligibility.actor_authorization_sha256
      },
      cache: {
        owner: cache.owner,
        hit: bool(cache.hit, "cache hit state"),
        content_revalidated_before_return: true
      },
      correction_history: history,
      training_permission_notice: text(value.training_permission_notice, "training notice", 1000, false)
    };
  }

  function ensureContext(payload) {
    if (!payload || typeof payload !== "object" || payload.context !== context) {
      access.invalidate("context");
      throw failure("Your account or workspace changed, so private results were cleared. Reload the page.", "context_changed");
    }
    return payload;
  }

  function errorDetail(response) {
    if (response.status === 507) {
      return "The active request list is full. Ask an administrator to review capacity. Your request was not lost.";
    }
    if (response.status === 409) {
      return "This changed since you loaded it, or current access couldn't be confirmed. Refresh and try again.";
    }
    if (typeof window.mvErrorText === "function") return window.mvErrorText({status: response.status, headers: response.headers}, "finish this");
    return "Something went wrong. Try again.";
  }

  async function readJson(response, token, path, readScope) {
    access.assertCurrent(token);
    var policy = {forbiddenScope: readScope, contextMessage: /account or workspace changed|active workspace changed/i};
    var meaning = access.observe(response, null, policy);
    if (meaning.kind === "transient" && !readScope && path.startsWith("/requests/")) unconfirmedPaths.add(path);
    if (["session", "scope", "capability"].includes(meaning.kind)) {
      if (meaning.kind === "capability") deniedPaths.add(path);
      var denial = failure(meaning.kind === "capability" ?
        "You can't do this with your current access. Ask an administrator." :
        "Your sign-in or access changed. Sign in again and reload this page.", "access_changed");
      denial.accessKind = meaning.kind;
      throw denial;
    }
    var declared = Number(response.headers.get("content-length") || 0);
    if (declared > maxResponseBytes) {
      if (response.body && typeof response.body.cancel === "function") { await response.body.cancel(); }
      throw failure("The knowledge response exceeded its size boundary.");
    }
    var body = await response.text();
    access.assertCurrent(token);
    if (new TextEncoder().encode(body).length > maxResponseBytes) {
      throw failure("The knowledge response exceeded its size boundary.");
    }
    var payload;
    try { payload = body ? JSON.parse(body) : {}; }
    catch (_error) {
      var unreadable = failure("The knowledge response could not be verified. Refresh the page and try again.");
      unreadable.accessKind = meaning.kind;
      throw unreadable;
    }
    if (!response.ok) {
      var message = errorDetail(response);
      meaning = access.observe(response, payload, policy);
      var rejected = failure(message, response.status === 409 ? "conflict" : "request_failed");
      rejected.technical = payload && typeof payload.detail === "string" ? payload.detail : "";
      rejected.accessKind = meaning.kind;
      throw rejected;
    }
    return ensureContext(payload);
  }

  async function api(path, body, method) {
    var token = access.capture();
    if (deniedPaths.has(path)) throw failure("You can't do this with your current access. Ask an administrator.", "access_changed");
    if (unconfirmedPaths.has(path)) throw failure("The last attempt wasn't confirmed. Press Refresh under Request status before trying again.", "unconfirmed");
    var response = await fetch(apiBase + path, {
      method: method || "POST",
      credentials: "same-origin",
      headers: {Accept: "application/json", "Content-Type": "application/json"},
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    return readJson(response, token, path, path === "/search" || method === "GET");
  }

  function node(tag, className, value) {
    var result = document.createElement(tag);
    if (className) { result.className = className; }
    if (value !== undefined && value !== null) { result.textContent = String(value); }
    return result;
  }

  function date(value) {
    if (value === null) { return "Not required"; }
    try { return (window.mvTimeAbsolute ? window.mvTimeAbsolute(value) : new Date(value * 1000).toLocaleString()); }
    catch (_error) { return "Unavailable"; }
  }

  var LABELS = {
    unchanged_pending_review: "Unchanged until reviewed", pending_source_review: "Waiting for review",
    retire_or_retrain_model: "Retire or retrain the model", invalidate_dataset: "Rebuild the dataset",
    retention_hold_active: "Legal hold active", retention_hold_released: "Legal hold released",
    external_source_deletion_unverified: "Not yet confirmed deleted at the original source",
    external_retention_and_deletion_unverified: "Not yet confirmed at the original source",
    revoked_for_new_use: "Stopped for new use",
    submitted: "Waiting for a decision", applying: "Being applied", approved: "Approved", denied: "Denied",
    correction: "Correction", exclusion: "Stop future use", deletion: "Deletion"
  };
  function friendly(value) {
    var key = String(value || "unknown");
    if (Object.prototype.hasOwnProperty.call(LABELS, key)) { return LABELS[key]; }
    var textValue = key.replace(/_/g, " ");
    return textValue.charAt(0).toUpperCase() + textValue.slice(1);
  }

  function shortReference(value) {
    var source = String(value || "");
    if (source.length <= 72) { return source; }
    return source.slice(0, 38) + "…" + source.slice(-24);
  }

  function setBusy(value) {
    pending = value;
    root.setAttribute("aria-busy", value ? "true" : "false");
    value = value || access.blocked;
    searchButton.disabled = value || !searchForm.elements.purpose.value;
    nextButton.disabled = value || !nextCursor;
    refreshRequests.disabled = value;
    if (recoveryMore) recoveryMore.disabled = value || !recoveryCursor;
    if (batchCopilot) batchCopilot.disabled = value;
    if (showArchived) showArchived.disabled = value;
    if (showReady) showReady.disabled = value || !archiveAvailable;
    if (findArchived) findArchived.querySelector("button").disabled = value;
    exportButton.disabled = value || !currentItems.length || deniedPaths.has("/export");
    if (submitRequest) { submitRequest.disabled = value || !selectedReference || deniedPaths.has("/requests"); }
    root.querySelectorAll("[data-access-path]").forEach(function (button) {
      button.disabled = value || deniedPaths.has(button.dataset.accessPath) || unconfirmedPaths.has(button.dataset.accessPath);
    });
    if (access.blocked) root.querySelectorAll("button,input,textarea,select").forEach(function (control) { control.disabled = true; });
  }

  function announce(message, focus, error) {
    status.textContent = message;
    // Keep the precise reason for support staff without showing it.
    if (error && typeof error.technical === "string" && error.technical) {
      status.dataset.technical = error.technical;
    } else {
      delete status.dataset.technical;
    }
    if (focus) { status.focus(); }
  }

  function clearRequestInputs() {
    selectedReference = null;
    document.dispatchEvent(new CustomEvent('lightwork:copilot-selection', {detail:{selection:{}}}));
    if (requestSource) { requestSource.textContent = "Open a source detail to select its exact version."; }
    if (requestForm) {
      requestForm.reset();
      delete requestForm.dataset.requestKey;
    }
    if (submitRequest) { submitRequest.disabled = true; }
    updateCorrectionField();
  }

  function resetSearch() {
    searchGeneration += 1;
    activeSearch = null;
    nextCursor = null;
    nextButton.hidden = true;
    nextButton.disabled = true;
  }

  function clearPrivate() {
    window.dispatchEvent(new CustomEvent("lightwork:knowledge-cleared"));
    resetSearch();
    announce("Private knowledge was cleared. Reload to recheck the current account and workspace.", true);
    currentItems = [];
    results.textContent = "";
    detail.textContent = "";
    detailPanel.hidden = true;
    requests.textContent = "";
    recoveryCursor = null;
    requestPageCursor = "";
    if (batchNote) batchNote.textContent = "";
    if (recoveryMore) recoveryMore.hidden = true;
    exportButton.disabled = true;
    clearRequestInputs();
    var query = document.getElementById("ka-query");
    if (query) { query.value = ""; }
    setBusy(false);
  }

  function clearEligibleResults() {
    resetSearch();
    currentItems = [];
    results.textContent = "";
    detail.textContent = "";
    detailPanel.hidden = true;
    exportButton.disabled = true;
    searchNote.textContent = "Displayed eligibility is no longer current. Search again.";
    clearRequestInputs();
  }

  function badge(label, state) {
    return node("span", "badge " + state, label);
  }

  function renderResult(value) {
    var card = node("article", "ka-result");
    var head = node("div", "ka-result__head");
    head.appendChild(node("h3", "", value.title));
    head.appendChild(badge(value.claim_state === "verified" ? "Verified" : "Inferred", value.claim_state === "verified" ? "approved" : "info"));
    head.appendChild(badge("Eligible now", "approved"));
    card.appendChild(head);
    card.appendChild(node("p", "", value.content_available ? value.summary : "No governed content preview is available for this registered source."));
    card.appendChild(node("p", "muted", "Version " + value.source.version));
    var meta = node("div", "ka-meta");
    meta.appendChild(node("span", "", "Up to date until " + date(value.eligibility.fresh_until)));
    meta.appendChild(node("span", "", "Allowed use: " + friendly(value.eligibility.permitted_action)));
    if (value.correction_history.length) {
      meta.appendChild(node("span", "", value.correction_history.length + " rights request" + (value.correction_history.length === 1 ? "" : "s")));
    }
    card.appendChild(meta);
    var button = node("button", "btn", "View details");
    button.type = "button";
    button.setAttribute("aria-label", "View details for " + value.title);
    button.addEventListener("click", function () { openDetail(value.reference); });
    card.appendChild(button);
    return card;
  }

  function renderResults(payload, requestedPurpose) {
    if (payload.schema !== "lightwork.knowledge-search.v1" ||
        !Array.isArray(payload.items) || payload.items.length > 50 ||
        payload.tenant !== tenant || payload.actor !== actor ||
        !SHA.test(payload.actor_authorization_sha256) ||
        payload.purpose !== requestedPurpose || !PURPOSE.test(payload.purpose) ||
        typeof payload.omitted_ineligible !== "number" ||
        !Number.isInteger(payload.omitted_ineligible) || payload.omitted_ineligible < 0 ||
        typeof payload.truncated !== "boolean" ||
        typeof payload.complete !== "boolean" || payload.truncated === payload.complete ||
        !["matched", "no_match", "incomplete", "unavailable"].includes(payload.status) ||
        !Array.isArray(payload.incomplete_reasons) ||
        payload.incomplete_reasons.some(function (value) {
          return !["more_matches", "more_candidates", "content_unavailable", "partial_source_coverage"].includes(value);
        }) ||
        (payload.next_cursor !== null &&
          (typeof payload.next_cursor !== "string" || !payload.next_cursor.length || payload.next_cursor.length > 2048)) ||
        (payload.complete && (payload.next_cursor !== null || payload.incomplete_reasons.length)) ||
        (!payload.complete && !payload.incomplete_reasons.length)) {
      throw failure("The knowledge search results could not be checked. Refresh the page and try again.");
    }
    var boundary = {purpose: requestedPurpose, action: "read", actor: actor,
      authorizationSha256: payload.actor_authorization_sha256};
    var clean = payload.items.map(function (entry) { return item(entry, boundary); });
    if (typeof payload.count !== "number" || payload.count !== clean.length) {
      throw failure("The knowledge search results were incomplete. Refresh the page and try again.");
    }
    results.textContent = "";
    currentItems = clean;
    nextCursor = payload.next_cursor;
    nextButton.hidden = !nextCursor;
    if (!clean.length) {
      results.appendChild(node("p", "muted", payload.complete ?
        "No currently eligible sources matched this search page." :
        "No matches are available on this partial search page. This does not establish that evidence is absent."));
    } else {
      clean.forEach(function (value) { results.appendChild(renderResult(value)); });
    }
    searchNote.textContent = payload.omitted_ineligible ?
      payload.omitted_ineligible + " source" + (payload.omitted_ineligible === 1 ? " was" : "s were") +
        " withheld because current access could not be revalidated." :
      "Every displayed source passed current eligibility checks.";
    if (payload.truncated) {
      searchNote.textContent += " This search is incomplete.";
      if (nextCursor) { searchNote.textContent += " Continue to the next results; each page rechecks current access."; }
      if (payload.incomplete_reasons.includes("content_unavailable")) {
        searchNote.textContent += " Some source content could not be checked; retry after it becomes available.";
      }
    }
    exportButton.disabled = !clean.length;
    announce(clean.length + (clean.length === 1 ? " eligible source" : " eligible sources") + " found.", false);
  }

  function listItem(label, value) {
    var entry = node("li");
    entry.appendChild(node("strong", "", label + ": "));
    entry.appendChild(document.createTextNode(value));
    return entry;
  }

  function renderDetail(value) {
    detail.textContent = "";
    var grid = node("div", "ka-detail-grid");
    var provenance = node("div");
    provenance.appendChild(node("h3", "", "Source and provenance"));
    var sourceList = node("ul", "ka-detail-list");
    sourceList.appendChild(listItem("Version", value.source.version));
    sourceList.appendChild(listItem("Where it came from", friendly(value.source.provenance_kind)));
    sourceList.appendChild(listItem("Status", value.claim_state === "verified" ? "Verified" : "Inferred"));
    sourceList.appendChild(listItem("Observed", date(value.observed_at)));
    sourceList.appendChild(listItem("Verified", date(value.verified_at)));
    sourceList.appendChild(listItem("License", friendly(value.source.license_id)));
    provenance.appendChild(sourceList);
    grid.appendChild(provenance);
    var eligibility = node("div");
    eligibility.appendChild(node("h3", "", "Can you use it?"));
    var useList = node("ul", "ka-detail-list");
    useList.appendChild(listItem("Last checked", date(value.eligibility.checked_at)));
    useList.appendChild(listItem("Up to date until", date(value.eligibility.fresh_until)));
    useList.appendChild(listItem("Consent lasts until", date(value.eligibility.consent_until)));
    useList.appendChild(listItem("For", friendly(value.eligibility.purpose)));
    useList.appendChild(listItem("Allowed use", friendly(value.eligibility.permitted_action)));
    eligibility.appendChild(useList);
    var technical = document.createElement("details");
    technical.appendChild(node("summary", "", "Technical details"));
    var techList = node("ul", "ka-detail-list");
    techList.appendChild(listItem("Source", value.source.source_ref));
    techList.appendChild(listItem("Checked for", friendly(value.eligibility.requested_action)));
    techList.appendChild(listItem("Checked for person", value.eligibility.actor.replace(/^user:/, "")));
    techList.appendChild(listItem("Saved copy", value.cache.hit ?
      "A recent copy was used after its source was checked again (revalidated cache hit)" :
      "Read straight from the source"));
    techList.appendChild(listItem("Where the copy lives",
      "Temporary in-app view; the source remains in its governed store"));
    technical.appendChild(techList);
    eligibility.appendChild(technical);
    grid.appendChild(eligibility);
    detail.appendChild(node("h3", "", value.title));
    detail.appendChild(node("p", "", value.content_available ? value.summary : "This source has no governed content preview."));
    detail.appendChild(grid);
    var constraints = node("div");
    constraints.appendChild(node("h3", "", "Use constraints"));
    var constraintList = node("ul", "ka-detail-list");
    value.source.usage_constraints.forEach(function (entry) { constraintList.appendChild(node("li", "", entry)); });
    constraints.appendChild(constraintList);
    detail.appendChild(constraints);
    var history = node("div");
    history.appendChild(node("h3", "", "Active correction and removal requests"));
    if (!value.correction_history.length) {
      history.appendChild(node("p", "muted", "No active requests are shown for this version. Review the finished archive for older requests."));
    } else {
      var historyList = node("ul", "ka-detail-list");
      value.correction_history.forEach(function (record) {
        historyList.appendChild(node("li", "", friendly(record.request_type) + " — " + friendly(record.status) + ": " + record.reason));
      });
      history.appendChild(historyList);
    }
    detail.appendChild(history);
    detail.appendChild(node("p", "ka-honesty", value.training_permission_notice));
    detailPanel.hidden = false;
    var use = node("button", "btn", "Use in source analysis");
    use.type = "button";
    use.addEventListener("click", function () {
      window.dispatchEvent(new CustomEvent("lightwork:source-selected", {detail: {
        reference: value.reference, title: value.title, purpose: value.eligibility.purpose,
        fresh_until: value.eligibility.fresh_until, context: context
      }}));
      var composer = document.getElementById("source-analysis");
      if (composer) composer.scrollIntoView({block: "center"});
    });
    detail.appendChild(use);
    selectedReference = value.reference;
    document.dispatchEvent(new CustomEvent('lightwork:copilot-selection', {detail:{selection:{kind:'knowledge_source',reference:value.reference,purpose:value.eligibility.purpose}}}));
    if (requestSource) {
      requestSource.textContent = value.title + " · version " + value.reference.version;
    }
    if (submitRequest) { submitRequest.disabled = false; }
    detailHeading.focus();
  }

  async function openDetail(exact) {
    if (pending) { return; }
    setBusy(true);
    announce("Rechecking this exact source version…", false);
    var requestedPurpose = document.getElementById("ka-purpose").value.trim();
    try {
      var payload = await api("/detail", {
        context: context,
        reference: exact,
        purpose: requestedPurpose
      });
      var clean = item(payload, {
        purpose: requestedPurpose,
        action: "read",
        actor: actor
      });
      if (!sameReference(clean.reference, exact)) {
        throw failure("The detail response did not match the selected source version. Refresh the page and try again.");
      }
      renderDetail(clean);
      announce("Source detail is current and ready for review.", false);
    } catch (error) {
      clearEligibleResults();
      announce(error.message || "Could not open this source. Try again.", true, error);
    } finally {
      setBusy(false);
    }
  }

  function validateRequests(payload) {
    if (payload.schema !== "lightwork.knowledge-rights-requests.v1" ||
        !Array.isArray(payload.items) || payload.items.length > 250 ||
        payload.can_review !== canReview) {
      throw failure("The rights-request list could not be checked. Refresh the page and try again.");
    }
    var clean = payload.items.map(canReview ? rightsRequest : feedback);
    if (payload.count !== clean.length) {
      throw failure("The rights-request list was incomplete. Refresh the page and try again.");
    }
    if (payload.archived !== undefined && payload.archived !== archivedView) {
      throw failure("The request view changed. Refresh to see its current status.");
    }
    if (payload.ready_to_archive !== undefined && payload.ready_to_archive !== readyView) {
      throw failure("The request view changed. Refresh to see its current status.");
    }
    if (capacityNote && payload.capacity) {
      var used = payload.capacity.active_count;
      var maximum = payload.capacity.active_limit;
      if (!Number.isInteger(used) || !Number.isInteger(maximum) ||
          used < 0 || maximum < 1 || used > maximum + 1) {
        throw failure("The request capacity could not be verified. Refresh the page and try again.");
      }
      var canArchive = payload.capacity.archive_available !== false;
      archiveAvailable = canArchive;
      var overfilled = used > maximum;
      if (showReady) {
        showReady.disabled = !canArchive;
        showReady.title = canArchive ? "" : "Finished-request archiving is unavailable on shared storage. Ask your administrator if you need it.";
      }
      capacityNote.textContent = !canArchive && used >= maximum ?
        "The active request list is full. Archiving is unavailable on this installation. Ask an administrator to review capacity; requests and evidence remain in place." :
        !canArchive && used >= Math.floor(maximum * 0.9) ?
          "The active request list is nearly full (" + used + " of " + maximum + "). Ask an administrator to review capacity." :
        overfilled ?
        "The active request list is over capacity. Open Ready to archive and scan batches to find finished requests. Records and evidence remain available in the archive." :
        used >= maximum ?
        "The active request list is full. Archive finished requests below to make room. Records and evidence remain available in the archive." :
        used >= Math.floor(maximum * 0.9) ?
          "The active request list is nearly full (" + used + " of " + maximum + "). Archive finished requests to make room." :
          used + " active requests; room for " + (maximum - used) + " more.";
    }
    return clean;
  }

  function renderDerivativeList(records) {
    if (!records.length) { return node("p", "muted", "Nothing else is built from this source."); }
    var list = node("ul", "ka-lineage");
    records.forEach(function (entry) {
      var row = node("li", "", "Used in " + (entry.reference.kind === "model" ? "the model " : "the dataset ") +
        friendly(entry.reference.asset_id) + " (version " + entry.reference.version + ") — " +
        friendly(entry.required_action).toLowerCase() + " (" + friendly(entry.required_action) + " required) · " +
        friendly(entry.workflow_state) + " · currently " + friendly(entry.current_state).toLowerCase());
      list.appendChild(row);
    });
    return list;
  }

  async function sha256(value) {
    if (!window.crypto || !window.crypto.subtle || typeof window.crypto.subtle.digest !== "function") {
      throw failure("This browser can't record the decision securely. Try a current version of Chrome, Edge, Firefox or Safari.", "browser");
    }
    var buffer = await window.crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
    return Array.from(new Uint8Array(buffer)).map(function (byte) {
      return byte.toString(16).padStart(2, "0");
    }).join("");
  }

  function canonicalJson(value) {
    if (value === null || typeof value === "string" || typeof value === "boolean") {
      return JSON.stringify(value);
    }
    if (typeof value === "number") {
      if (!Number.isFinite(value)) {
        throw failure("Authority evidence was not finite JSON.");
      }
      return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
      return "[" + value.map(canonicalJson).join(",") + "]";
    }
    if (value && typeof value === "object") {
      return "{" + Object.keys(value).sort().map(function (key) {
        return JSON.stringify(key) + ":" + canonicalJson(value[key]);
      }).join(",") + "}";
    }
    throw failure("Authority evidence was not canonical JSON.");
  }

  function reviewControls(record) {
    var box = node("div", "ka-review");
    var recovering = record.status === "applying";
    if (recovering) {
      box.appendChild(node(
        "p",
        "ka-honesty",
        "Recovery is waiting: an approval was interrupted part-way. To finish it, enter exactly the same reason " +
          String(record.decided_by || "").replace(/^user:/, "") + " gave when approving."
      ));
    }
    var label = node("label", "ka-field", recovering ?
      "The reason given when it was approved" : "Reason for your decision");
    var input = node("textarea", "textarea");
    input.rows = 3;
    input.maxLength = 2000;
    input.required = true;
    label.appendChild(input);
    box.appendChild(label);
    var confirmLabel = node("label", "ka-check");
    var confirm = document.createElement("input");
    confirm.type = "checkbox";
    confirmLabel.appendChild(confirm);
    confirmLabel.appendChild(node("span", "", recovering ?
      "I'm finishing the approval that was already given." :
      "I reviewed the source and everything built from it listed above."));
    box.appendChild(confirmLabel);
    var actions = node("div", "ka-actions");
    (recovering ? [
      ["Finish the approved removal", "approve", "btn btn--danger"]
    ] : [
      ["Approve and stop using this source", "approve", "btn btn--danger"],
      ["Deny request", "deny", "btn"]
    ]).forEach(function (choice) {
      var button = node("button", choice[2], choice[0]);
      button.type = "button";
      button.dataset.accessPath = "/requests/" + encodeURIComponent(record.id) + "/decision";
      button.addEventListener("click", async function () {
        var note = input.value.trim();
        if (!note || !confirm.checked) {
          announce("Add a reason and tick the confirmation first.", true);
          return;
        }
        if (pending) { return; }
        setBusy(true);
        announce("Applying the reviewed source-rights decision…", false);
        try {
          var digest = await sha256(note);
          var payload = await api("/requests/" + encodeURIComponent(record.id) + "/decision", {
            context: context,
            confirm: true,
            expected_revision: record.revision,
            decision: choice[1],
            evidence_sha256: digest
          });
          rightsRequest(payload);
          await loadRequests();
          if (choice[1] === "approve") {
            currentItems = [];
            results.textContent = "";
            exportButton.disabled = true;
            detail.textContent = "";
            detailPanel.hidden = true;
            clearRequestInputs();
          }
          announce(choice[1] === "approve" ?
            "The source is no longer used. The follow-up for material built from it is recorded." :
            "The request was denied; the source can still be used.", true);
        } catch (error) {
          if (!["capability", "transient"].includes(error.accessKind)) {
            try { await loadRequests(); } catch (_refreshError) { /* retain the decision error */ }
          }
          announce(error.message || "Could not save your decision. Try again.", true, error);
        } finally {
          setBusy(false);
        }
      });
      actions.appendChild(button);
    });
    box.appendChild(actions);
    return box;
  }

  function retentionHoldControls(record) {
    var box = node("div", "ka-review");
    box.appendChild(node("h4", "", "Preservation hold (legal hold)"));
    var hold = record.retention_hold;
    if (!hold) {
      var identityLabel = node("label", "ka-field", "Name of the legal matter");
      var identity = document.createElement("input");
      identity.className = "input";
      identity.maxLength = 80;
      identity.required = true;
      identity.placeholder = "For example: Smith v Acme 2026";
      identityLabel.appendChild(identity);
      box.appendChild(identityLabel);
      var basisLabel = node("label", "ka-field", "Legal or preservation basis");
      var basis = document.createElement("textarea");
      basis.className = "textarea";
      basis.rows = 3;
      basis.maxLength = 2000;
      basis.required = true;
      basisLabel.appendChild(basis);
      box.appendChild(basisLabel);
      var expiryLabel = node("label", "ka-field", "Hold expires");
      var expiry = document.createElement("input");
      expiry.className = "input";
      expiry.type = "datetime-local";
      expiry.required = true;
      expiryLabel.appendChild(expiry);
      box.appendChild(expiryLabel);
      var confirmLabel = node("label", "ka-check");
      var confirm = document.createElement("input");
      confirm.type = "checkbox";
      confirmLabel.appendChild(confirm);
      confirmLabel.appendChild(node("span", "", "I checked the matter, the reason and the end date."));
      box.appendChild(confirmLabel);
      var place = node("button", "btn", "Place retention hold");
      place.setAttribute("aria-label", "Place a legal hold on this deletion request");
      place.type = "button";
      place.dataset.accessPath = "/requests/" + encodeURIComponent(record.id) + "/retention-hold";
      place.addEventListener("click", async function () {
        var holdId = identity.value.trim();
        if (holdId && !ID.test(holdId)) {
          // A matter name becomes the hold's reference: letters and numbers joined by dashes.
          holdId = holdId.normalize("NFKD").replace(/[^A-Za-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 100);
        }
        var holdBasis = basis.value.trim();
        var expiresAt = new Date(expiry.value).getTime() / 1000;
        if (!ID.test(holdId) || !holdBasis || !Number.isFinite(expiresAt) ||
            expiresAt <= Date.now() / 1000 || !confirm.checked) {
          announce("Add the matter name, the reason, an end date in the future, and tick the confirmation.", true);
          return;
        }
        if (pending) { return; }
        setBusy(true);
        try {
          var evidence = await sha256(canonicalJson({
            request_id: record.id,
            hold_id: holdId,
            basis: holdBasis,
            expires_at: expiresAt
          }));
          await api("/requests/" + encodeURIComponent(record.id) + "/retention-hold", {
            context: context,
            confirm: true,
            expected_revision: record.revision,
            hold_id: holdId,
            basis: holdBasis,
            expires_at: expiresAt,
            evidence_sha256: evidence
          });
          await loadRequests();
          announce("The legal hold is in place for this deletion request.", true);
        } catch (error) {
          if (!["capability", "transient"].includes(error.accessKind)) {
            try { await loadRequests(); } catch (_refreshError) { /* retain original error */ }
          }
          announce(error.message || "Could not place the hold. Try again.", true, error);
        } finally {
          setBusy(false);
        }
      });
      box.appendChild(place);
      return box;
    }
    if (hold.effective_status === "released") { return box; }
    var reasonLabel = node("label", "ka-field", "Why the hold can be released");
    var reason = document.createElement("textarea");
    reason.className = "textarea";
    reason.rows = 3;
    reason.maxLength = 2000;
    reason.required = true;
    reasonLabel.appendChild(reason);
    box.appendChild(reasonLabel);
    var releaseConfirmLabel = node("label", "ka-check");
    var releaseConfirm = document.createElement("input");
    releaseConfirm.type = "checkbox";
    releaseConfirmLabel.appendChild(releaseConfirm);
    releaseConfirmLabel.appendChild(node("span", "", "I verified the preservation duty has ended."));
    box.appendChild(releaseConfirmLabel);
    var release = node("button", "btn btn--danger", "Release retention hold");
    release.setAttribute("aria-label", "Release the legal hold");
    release.type = "button";
    release.dataset.accessPath = "/requests/" + encodeURIComponent(record.id) + "/retention-hold/release";
    release.addEventListener("click", async function () {
      var releaseReason = reason.value.trim();
      if (!releaseReason || !releaseConfirm.checked) {
        announce("Add the reason for releasing the hold and tick the confirmation.", true);
        return;
      }
      if (pending) { return; }
      setBusy(true);
      try {
        var evidence = await sha256(canonicalJson({
          request_id: record.id,
          hold_id: hold.hold_id,
          reason: releaseReason
        }));
        await api("/requests/" + encodeURIComponent(record.id) + "/retention-hold/release", {
          context: context,
          confirm: true,
          expected_revision: record.revision,
          reason: releaseReason,
          evidence_sha256: evidence
        });
        await loadRequests();
        announce("The legal hold was released.", true);
      } catch (error) {
        if (!["capability", "transient"].includes(error.accessKind)) {
          try { await loadRequests(); } catch (_refreshError) { /* retain original error */ }
        }
        announce(error.message || "Could not release the hold. Try again.", true, error);
      } finally {
        setBusy(false);
      }
    });
    box.appendChild(release);
    return box;
  }

  function renderRequests(items, append, recoveryScan) {
    if (!append || !requests.querySelector(".ka-request")) requests.textContent = "";
    if (!items.length) {
      if (requests.querySelector(".ka-request")) return;
      var empty = recoveryScan ?
        ["No matching requests in this batch", "Continue to the next batch if one is available."] : archivedView ?
        ["No finished requests are in the archive yet", "Finished requests appear here once they are archived."] : readyView ?
        ["No finished requests are ready to archive", "Requests appear here when they can be archived. Complete a review or release a legal hold first."] :
        ["No correction, exclusion, or deletion requests in this view", "Requests to correct, exclude or delete a source appear here with their status. Open a source with View details, then use the Request a correction or removal section to make one."];
      requests.appendChild(window.mvEmpty ? window.mvEmpty(empty[0], empty[1], null, { compact: true })
        : node("p", "muted", empty[0] + ". " + empty[1]));
      return;
    }
    items.forEach(function (record) {
      var card = node(canReview ? "details" : "article", "ka-request");
      if (canReview) {
        card.appendChild(node("summary", "", friendly(record.request_type) + " request · " +
          friendly(record.status) + " · " + record.reason.slice(0, 120)));
      }
      if (record.schema === "lightwork.knowledge-feedback.v1") {
        card.appendChild(node("h3", "", friendly(record.request_type) + " request · " + friendly(record.status)));
        card.appendChild(node("p", "muted", "Request reference: " + record.id));
        if (record.archived_at !== null) {
          card.appendChild(node("p", "muted", "Retained in the finished archive " + date(record.archived_at) + "."));
        }
        card.appendChild(node("p", "", record.reason));
        if (record.proposed_correction) card.appendChild(node("p", "", "Your suggested correction: " + record.proposed_correction));
        card.appendChild(node("p", "muted", "Updated " + date(record.updated_at) + ". Source use: " + friendly(record.source_use_status) + ". Record: " + friendly(record.raw_record_status) + ". Retention review: " + friendly(record.retention_review_status) + "."));
        card.appendChild(node("p", "muted", record.notice));
        requests.appendChild(card); return;
      }
      var head = node("div", "ka-request__head");
      head.appendChild(node("h3", "", friendly(record.request_type) + " request"));
      head.appendChild(node("span", "muted", friendly(record.status).toLowerCase()));
      head.appendChild(badge(friendly(record.status), record.status === "approved" ? "approved" :
        record.status === "denied" ? "denied" : record.status === "applying" ? "warning" : "pending"));
      card.appendChild(head);
      card.appendChild(node("p", "muted", "Request reference: " + record.id));
      if (record.archived_at !== null) {
        card.appendChild(node("p", "muted", "Retained in the finished archive " + date(record.archived_at) + "."));
      }
      card.appendChild(node("p", "muted", "Source: " + friendly(record.source_reference.asset_id) +
        " (version " + record.source_reference.version + ")"));
      card.appendChild(node("p", "", record.reason));
      if (record.proposed_correction) {
        card.appendChild(node("p", "", "Proposed correction: " + record.proposed_correction));
      }
      if (record.replacement_reference) {
        card.appendChild(node(
          "p",
          "",
          "Corrected replacement: " + record.replacement_reference.asset_id +
            " (version " + record.replacement_reference.version + ") · " + friendly(record.replacement_status).toLowerCase()
        ));
      } else if (record.request_type === "correction" && record.status === "submitted") {
        card.appendChild(node(
          "p",
          "muted",
          "A different named administrator must review and approve the corrected replacement."
        ));
      }
      card.appendChild(node("p", "", "Source use: " + friendly(record.source_use_status) +
        ". Original record: " + friendly(record.raw_record_status) +
        ". Keep-or-delete review: " + friendly(record.retention_review_status) + "."));
      if (record.retention_hold) {
        var hold = record.retention_hold;
        card.appendChild(node(
          "p",
          "ka-honesty",
          "Legal hold " + hold.hold_id + " is " + friendly(hold.effective_status).toLowerCase() +
            " until " + date(hold.expires_at) + ". Reason: " + hold.basis +
            (hold.release_reason ? " Release: " + hold.release_reason : "")
        ));
      }
      card.appendChild(node("p", "ka-lineage-label", "Also affects"));
      card.appendChild(renderDerivativeList(record.derivatives));
      if (JSON.stringify(record.derivatives_at_request) !== JSON.stringify(record.derivatives)) {
        var recorded = document.createElement("details");
        recorded.appendChild(node("summary", "", "What it affected when the request was made"));
        recorded.appendChild(renderDerivativeList(record.derivatives_at_request));
        card.appendChild(recorded);
      }
      card.appendChild(node("p", "ka-honesty", record.weight_influence_notice));
      if (canReview && !archivedView && (record.status === "submitted" || record.status === "applying")) {
        card.appendChild(reviewControls(record));
      }
      if (canReview && !archivedView && record.request_type === "deletion" &&
          record.status !== "applying" &&
          (!record.retention_hold || record.retention_hold.effective_status !== "released")) {
        card.appendChild(retentionHoldControls(record));
      }
      if (canReview) {
        var copilot = node("button", "btn", "Work on this with Copilot");
        copilot.type = "button";
        copilot.addEventListener("click", function () {
          document.dispatchEvent(new CustomEvent("lightwork:copilot-selection", {
            detail: {selection: {kind: "knowledge_request", id: record.id}}
          }));
          var panel = document.getElementById("mv-copilot");
          var open = document.getElementById("mv-copilot-fab");
          if (panel && panel.hidden && open) open.click();
          announce("Copilot is focused on this request.", false);
        });
        card.appendChild(copilot);
      }
      if (canReview && !archivedView && record.archive_ready) {
        var archive = node("button", "btn", "Move to finished archive");
        archive.type = "button";
        archive.dataset.accessPath = "/requests/" + encodeURIComponent(record.id) + "/archive";
        archive.addEventListener("click", async function () {
          // Archiving keeps the request, its restrictions and evidence: no question.
          if (pending) return;
          setBusy(true);
          try {
            var saved = await api(archive.dataset.accessPath, {
              context: context, confirm: true, expected_revision: record.revision
            });
            if (rightsRequest(saved).archived_at === null) throw failure("The archive could not be verified. Refresh the page and try again.");
            await loadRequests();
            announce("The finished request is retained in the archive. Its source restrictions remain in force.", true);
          } catch (error) {
            announce(error.message || "Could not archive this request. It remains in the active list. Try again.", true, error);
          } finally { setBusy(false); }
        });
        card.appendChild(archive);
      }
      requests.appendChild(card);
    });
  }

  function requestView() { return archivedView ? "archive" : readyView ? "ready" : "active"; }

  async function loadRequests(advance, explicitCursor) {
    var token = access.capture();
    var chosenCursor = explicitCursor === undefined ? (advance ? recoveryCursor || "" : "") : explicitCursor;
    var path = "/request-batches?limit=25&view=" + requestView() + "&cursor=" + encodeURIComponent(chosenCursor);
    var response = await fetch(apiBase + path, {
      method: "GET",
      credentials: "same-origin",
      headers: {Accept: "application/json"}
    });
    var payload = await readJson(response, token, "/request-batches", true);
    var items = validateRequests(payload);
    {
      if (payload.next_cursor !== null &&
          (typeof payload.next_cursor !== "string" || payload.next_cursor.length > 2048 ||
           !/^[A-Za-z0-9_-]+$/.test(payload.next_cursor))) {
        throw failure("The next page of requests could not be checked. Refresh the page and try again.");
      }
      if (payload.view !== requestView() || typeof payload.complete !== "boolean" ||
          payload.complete !== (payload.next_cursor === null) ||
          !Number.isInteger(payload.scanned) || payload.scanned < items.length || payload.scanned > 25 ||
          typeof payload.notice !== "string" || payload.notice.length > 1000) {
        throw failure("The current request batch could not be verified.");
      }
      requestPageCursor = chosenCursor;
      recoveryCursor = payload.next_cursor;
      if (batchNote) batchNote.textContent = "Showing " + items.length + " matching request" +
        (items.length === 1 ? "" : "s") + " in this batch. " +
        (payload.complete ? "End of this view. " : "More records can be checked with Next batch. ") + payload.notice;
    }
    renderRequests(items, false, chosenCursor !== "" || !payload.complete);
    if (recoveryMore) recoveryMore.hidden = !recoveryCursor;
    unconfirmedPaths.clear();
  }

  async function openRequestBatch(view, cursor) {
    if (pending || access.blocked || !["active", "archive", "ready"].includes(view) || (!canReview && view === "ready") ||
        typeof cursor !== "string" || cursor.length > 2048 || (cursor && !/^[A-Za-z0-9_-]+$/.test(cursor))) return false;
    var previousArchived = archivedView, previousReady = readyView;
    archivedView = view === "archive";
    readyView = view === "ready";
    setBusy(true);
    try {
      await loadRequests(false, cursor);
      if (showArchived) {
        showArchived.setAttribute("aria-pressed", archivedView ? "true" : "false");
        showArchived.textContent = archivedView ? "View active requests" : "View finished archive";
      }
      if (showReady) showReady.setAttribute("aria-pressed", readyView ? "true" : "false");
      announce("This request batch was checked against current access and source restrictions.", false);
      var heading = document.getElementById("ka-requests-heading");
      heading.tabIndex = -1;
      heading.focus({preventScroll: true});
      heading.scrollIntoView({block: "start"});
      return true;
    } catch (error) {
      archivedView = previousArchived; readyView = previousReady;
      announce(error.message || "Could not open this batch. Start this view again.", true, error);
      return false;
    } finally { setBusy(false); }
  }
  window.LightworkKnowledgeRequests = {openBatch: openRequestBatch};
  if (batchCopilot) batchCopilot.addEventListener("click", function () {
    if (pending || access.blocked) return;
    document.dispatchEvent(new CustomEvent("lightwork:copilot-selection", {
      detail: {selection: {kind: "knowledge_request_batch", view: requestView(), cursor: requestPageCursor}}
    }));
    var panel = document.getElementById("mv-copilot"), open = document.getElementById("mv-copilot-fab");
    if (panel && panel.hidden && open) open.click();
    announce("Copilot is focused on this request batch.", false);
  });

  function updateCorrectionField() {
    if (!requestType || !correctionField || !correction) { return; }
    var shown = requestType.value === "correction";
    correctionField.hidden = !shown;
    correction.required = shown;
    if (!shown) { correction.value = ""; }
  }

  async function runSearch(requested) {
    if (pending) { return; }
    var generation = ++searchGeneration;
    activeSearch = {query: requested.query, purpose: requested.purpose, limit: requested.limit};
    nextCursor = null;
    nextButton.hidden = true;
    currentItems = [];
    setBusy(true);
    detail.textContent = "";
    detailPanel.hidden = true;
    clearRequestInputs();
    results.textContent = "";
    results.appendChild(node("p", "muted", "Rechecking current source access…"));
    announce("Searching currently eligible sources…", false);
    try {
      var payload = await api("/search", {
        context: context,
        query: requested.query,
        purpose: requested.purpose,
        limit: requested.limit,
        cursor: requested.cursor || null
      });
      if (generation !== searchGeneration) { return; }
      renderResults(payload, requested.purpose);
    } catch (error) {
      if (generation !== searchGeneration) { return; }
      currentItems = [];
      results.textContent = "";
      exportButton.disabled = true;
      nextCursor = null;
      nextButton.hidden = true;
      announce(error.message || "Could not search. Try again.", true, error);
    } finally {
      if (generation === searchGeneration || activeSearch === null) { setBusy(false); }
    }
  }

  searchForm.addEventListener("submit", async function (event) {
    event.preventDefault();
    if (pending) { return; }
    var purpose = document.getElementById("ka-purpose").value.trim();
    var limit = Number(document.getElementById("ka-limit").value);
    if (!PURPOSE.test(purpose) || !Number.isInteger(limit) || limit < 1 || limit > 50) {
      announce("Choose what you'll use the information for. If the list is empty, add sources first.", true);
      return;
    }
    await runSearch({query: document.getElementById("ka-query").value.trim(), purpose: purpose, limit: limit});
  });

  nextButton.addEventListener("click", async function () {
    if (pending || !activeSearch || !nextCursor) { return; }
    await runSearch({query: activeSearch.query, purpose: activeSearch.purpose,
      limit: activeSearch.limit, cursor: nextCursor});
  });

  ["ka-query", "ka-purpose", "ka-limit"].forEach(function (id) {
    document.getElementById(id).addEventListener("input", clearEligibleResults);
  });

  exportButton.addEventListener("click", async function () {
    if (pending || !currentItems.length) { return; }
    var expected = currentItems.map(function (entry) { return entry.reference; });
    var requestedPurpose = document.getElementById("ka-purpose").value.trim();
    setBusy(true);
    announce("Rechecking every source before export…", false);
    try {
      var payload = await api("/export", {
        context: context,
        purpose: requestedPurpose,
        references: expected
      });
      if (payload.schema !== "lightwork.knowledge-export.v1" || payload.complete !== true ||
          payload.count !== expected.length || !Array.isArray(payload.items) ||
          payload.items.length !== expected.length) {
        throw failure("The knowledge export was incomplete or malformed.");
      }
      if (payload.tenant !== tenant || payload.actor !== actor ||
          payload.purpose !== requestedPurpose ||
          !SHA.test(payload.actor_authorization_sha256)) {
        throw failure("The knowledge export crossed its requested authority boundary.");
      }
      var clean = payload.items.map(function (entry) {
        return item(entry, {
          purpose: requestedPurpose,
          action: "export",
          actor: actor,
          authorizationSha256: payload.actor_authorization_sha256
        });
      });
      clean.forEach(function (entry, index) {
        if (!sameReference(entry.reference, expected[index]) ||
            entry.eligibility.requested_action !== "export") {
          throw failure("The knowledge export did not match the selected source versions. Choose the sources again, then export.");
        }
      });
      var evidence = payload.authority_evidence;
      var qualification = payload.qualification;
      if (!evidence || typeof evidence !== "object" ||
          evidence.schema !== "lightwork.knowledge-export-authority-evidence.v1" ||
          evidence.action !== "export" || evidence.tenant !== payload.tenant ||
          evidence.actor !== payload.actor || evidence.purpose !== payload.purpose ||
          evidence.actor_authorization_sha256 !== payload.actor_authorization_sha256 ||
          !String(payload.actor || "").startsWith("user:") ||
          !SHA.test(payload.actor_authorization_sha256) || !SHA.test(evidence.binding_sha256) ||
          !Array.isArray(evidence.sources) || evidence.sources.length !== clean.length ||
          !qualification || typeof qualification !== "object" ||
          qualification.local_control_validation !== "passed_at_request_time" ||
          qualification.external_store_and_customer_qualification !== "qualification_pending") {
        throw failure("The knowledge export authority evidence was malformed.");
      }
      evidence.sources.forEach(function (source, index) {
        if (!source || typeof source !== "object" ||
            !sameReference(reference(source.reference), clean[index].reference) ||
            source.content_sha256 !== clean[index].source.content_sha256 ||
            source.approval_sha256 !== clean[index].eligibility.approval_sha256 ||
            !SHA.test(source.content_sha256) || !SHA.test(source.approval_sha256)) {
          throw failure("The knowledge export did not match its source versions. Refresh the page and try again.");
        }
      });
      var boundEvidence = {
        schema: evidence.schema,
        tenant: evidence.tenant,
        actor: evidence.actor,
        actor_authorization_sha256: evidence.actor_authorization_sha256,
        purpose: evidence.purpose,
        action: evidence.action,
        sources: evidence.sources.map(function (source) {
          return {
            reference: reference(source.reference),
            content_sha256: source.content_sha256,
            approval_sha256: source.approval_sha256
          };
        })
      };
      if ((await sha256(canonicalJson(boundEvidence))) !== evidence.binding_sha256) {
        throw failure("The knowledge export did not match its evidence. Refresh the page and try again.");
      }
      var blob = new Blob([JSON.stringify(payload, null, 2)], {type: "application/json"});
      var url = URL.createObjectURL(blob);
      var link = document.createElement("a");
      link.href = url;
      link.download = "knowledge-access-export.json";
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 0);
      announce("Exported " + clean.length + " currently eligible source" + (clean.length === 1 ? "." : "s."), false);
    } catch (error) {
      if (!["capability", "transient"].includes(error.accessKind)) clearEligibleResults();
      announce(error.message || "Could not download the results. Try again.", true, error);
    } finally {
      setBusy(false);
    }
  });

  if (requestType) {
    requestType.addEventListener("change", updateCorrectionField);
    updateCorrectionField();
  }

  if (requestForm) {
    requestForm.addEventListener("submit", async function (event) {
      event.preventDefault();
      if (pending || !selectedReference) { return; }
      var reason = requestForm.elements.reason.value.trim();
      var type = requestForm.elements.request_type.value;
      var proposed = requestForm.elements.proposed_correction.value.trim();
      if (!reason || !requestForm.elements.confirm.checked || (type === "correction" && !proposed)) {
        announce("Complete and confirm the exact source-rights request.", true);
        return;
      }
      if (!requestForm.dataset.requestKey) {
        requestForm.dataset.requestKey = "request-" + (window.crypto && typeof window.crypto.randomUUID === "function" ?
          window.crypto.randomUUID() : Date.now().toString(36) + "-" + Math.random().toString(36).slice(2));
      }
      var body = {
        context: context,
        confirm: true,
        reference: selectedReference,
        purpose: activeSearch ? activeSearch.purpose : searchForm.elements.purpose.value,
        request_type: type,
        reason: reason,
        request_key: requestForm.dataset.requestKey,
        proposed_correction: type === "correction" ? proposed : null
      };
      setBusy(true);
      announce("Recording the exact source and its derivative impact…", false);
      try {
        var payload = await api("/requests", body);
        (canReview ? rightsRequest : feedback)(payload);
        requestForm.reset();
        delete requestForm.dataset.requestKey;
        updateCorrectionField();
        await loadRequests();
        announce("Your request is recorded for independent administrator review. Source access and training policy are unchanged.", true);
      } catch (error) {
        announce((error.message || "Could not send the request. Try again.") + " Your answers are still here, so you can try again.", true, error);
      } finally {
        setBusy(false);
      }
    });
  }

  refreshRequests.addEventListener("click", async function () {
    if (pending) { return; }
    setBusy(true);
    try {
      await loadRequests();
      announce("Requests are up to date.", false);
    } catch (error) {
      announce(error.message || "Could not load requests. Try again.", true, error);
    } finally {
      setBusy(false);
    }
  });

  if (recoveryMore) recoveryMore.addEventListener("click", async function () {
    if (pending || !recoveryCursor) return;
    setBusy(true);
    try {
      await loadRequests(true);
      announce(recoveryCursor ? "Showing the next batch. More records remain to check." : "This view reached its last batch.", false);
    } catch (error) {
      announce(error.message || "Could not scan the next batch. Try again.", true, error);
    } finally { setBusy(false); }
  });

  if (showArchived) showArchived.addEventListener("click", async function () {
    if (pending) return;
    var priorArchived = archivedView, priorReady = readyView;
    archivedView = !archivedView;
    readyView = false;
    if (showReady) showReady.setAttribute("aria-pressed", "false");
    showArchived.setAttribute("aria-pressed", archivedView ? "true" : "false");
    showArchived.textContent = archivedView ? "View active requests" : "View finished archive";
    setBusy(true);
    try {
      await loadRequests();
      announce(archivedView ? "Showing retained finished requests." : "Showing active requests.", false);
    } catch (error) {
      archivedView = priorArchived;
      readyView = priorReady;
      if (showReady) showReady.setAttribute("aria-pressed", readyView ? "true" : "false");
      showArchived.setAttribute("aria-pressed", archivedView ? "true" : "false");
      showArchived.textContent = archivedView ? "View active requests" : "View finished archive";
      announce(error.message || "Could not load this request view. Try again.", true, error);
    } finally { setBusy(false); }
  });

  if (showReady) showReady.addEventListener("click", async function () {
    if (pending) return;
    var priorArchived = archivedView, priorReady = readyView;
    readyView = !readyView;
    archivedView = false;
    if (showArchived) {
      showArchived.setAttribute("aria-pressed", "false");
      showArchived.textContent = "View finished archive";
    }
    showReady.setAttribute("aria-pressed", readyView ? "true" : "false");
    setBusy(true);
    try {
      await loadRequests();
      announce(readyView ? "Showing finished requests ready to archive." : "Showing active requests.", false);
    } catch (error) {
      archivedView = priorArchived;
      readyView = priorReady;
      if (showArchived) {
        showArchived.setAttribute("aria-pressed", archivedView ? "true" : "false");
        showArchived.textContent = archivedView ? "View active requests" : "View finished archive";
      }
      showReady.setAttribute("aria-pressed", readyView ? "true" : "false");
      announce(error.message || "Could not load this request view. Try again.", true, error);
    } finally { setBusy(false); }
  });

  if (findArchived) findArchived.addEventListener("submit", async function (event) {
    event.preventDefault();
    if (pending) return;
    var requestId = findArchived.elements.request_reference.value.trim();
    if (!/^knowledge-req-[a-f0-9]{40}$/.test(requestId)) {
      announce("Paste a full request reference from its receipt or card.", true);
      return;
    }
    setBusy(true);
    try {
      var result = await api("/requests/" + encodeURIComponent(requestId), undefined, "GET");
      if (result.schema !== "lightwork.knowledge-rights-request-detail.v1") {
        throw failure("The retained request could not be verified. Refresh the page and try again.");
      }
      var record = (canReview ? rightsRequest : feedback)(result.item);
      if (record.id !== requestId || record.archived_at === null) {
        throw failure("This request is not in the finished archive. Review active requests.");
      }
      archivedView = true;
      readyView = false;
      if (showArchived) {
        showArchived.setAttribute("aria-pressed", "true");
        showArchived.textContent = "View active requests";
      }
      if (showReady) showReady.setAttribute("aria-pressed", "false");
      renderRequests([record]);
      announce("Showing the retained request you looked up.", true);
    } catch (error) {
      announce(error.message || "Could not find that archived request. Check the reference and try again.", true, error);
    } finally { setBusy(false); }
  });

  var initialPage = new URLSearchParams(window.location.search);
  if (initialPage.has("requests_view")) {
    openRequestBatch(initialPage.get("requests_view"), initialPage.get("requests_page") || "").then(function (opened) {
      if (!opened) requests.textContent = "This request page could not be opened. Choose a view or use Start over to check current requests.";
    });
  } else {
    setBusy(true);
    loadRequests().catch(function (error) {
      requests.textContent = "";
      var note = node("p", "muted", error.message || "Requests are not available right now. Try again in a minute.");
      if (error && error.technical) { note.dataset.technical = error.technical; }
      requests.appendChild(note);
    }).finally(function () { setBusy(false); });
  }
  var purposePicker = document.getElementById("ka-purpose");
  var retryPurposes = document.getElementById("ka-retry-purposes");
  if (root.dataset.purposeState === "unavailable") {
    announce("Approved uses could not be loaded. Your query is still here. Refresh available uses to retry.");
  }
  if (retryPurposes) retryPurposes.addEventListener("click", async function () {
    if (pending) return;
    var prior = purposePicker.value;
    setBusy(true);
    retryPurposes.disabled = true;
    announce("Loading the uses currently available to your account.");
    try {
      var payload = await api("/purposes", undefined, "GET");
      if (payload.context !== context || !Array.isArray(payload.items)) throw new Error(UNVERIFIED);
      var options = payload.items.map(function (item) {
        if (!item || !PURPOSE.test(item.code)) throw new Error(UNVERIFIED);
        var option = document.createElement("option");
        option.value = item.code;
        option.textContent = window.mvHuman ? window.mvHuman(item.code) : item.code;
        return option;
      });
      purposePicker.replaceChildren.apply(purposePicker, options);
      if (options.some(function (option) { return option.value === prior; })) purposePicker.value = prior;
      clearEligibleResults();
      announce(options.length ? "Available uses refreshed. Your query is unchanged." : "No approved uses are currently available to your account. Ask your administrator to review source access.");
    } catch (error) {
      announce(error.message || "Approved uses are temporarily unavailable. Retry when ready.");
    } finally {
      retryPurposes.disabled = access.blocked;
      setBusy(false);
    }
  });
  // Finder links carry references only. Opening always calls the native current
  // authorization/detail service; neither URL state nor a search snippet grants use.
  if (window.location.hash.startsWith('#source=')) {
    try {
      var rawSelection = window.location.hash.slice(8);
      if (rawSelection.length > 6000) throw new Error('The selected source reference is too long.');
      var selectedSource = JSON.parse(decodeURIComponent(rawSelection));
      var exactSource = reference(selectedSource.reference);
      if (!PURPOSE.test(selectedSource.purpose)) throw new Error('Choose a permitted use again.');
      if (!Array.from(purposePicker.options).some(function(option){return option.value===selectedSource.purpose;})) throw new Error('This source use is no longer permitted. Choose current evidence.');
      purposePicker.value=selectedSource.purpose;
      openDetail(exactSource);
    } catch(error) { announce(error.message || 'This source cannot be opened. Search current approved evidence.', true); }
  }
})();
