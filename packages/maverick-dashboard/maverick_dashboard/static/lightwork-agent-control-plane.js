(function () {
  "use strict";

  var root = document.getElementById("acp-root");
  if (!root) { return; }

  var apiBase = root.dataset.apiBase || "/api/v1/agent-control-plane";
  var canOperate = root.dataset.canOperate === "true";
  var canAudit = root.dataset.canAudit === "true";
  var canAdmin = root.dataset.canAdmin === "true";
  var canHalt = root.dataset.canHalt === "true";
  var haltScope = root.dataset.haltScope || "unknown";
  var maxResponseBytes = 2 * 1024 * 1024;
  var maxAnnouncedErrorChars = 1000;
  var configuredTimeout = Number(root.dataset.requestTimeoutMs || 15000);
  var requestTimeoutMs = Number.isFinite(configuredTimeout) && configuredTimeout >= 10
    ? Math.min(configuredTimeout, 120000)
    : 15000;
  var rosterLimit = 100;
  var rosterOffset = 0;
  var rosterNextOffset = null;
  var desiredRosterOffset = 0;
  var mutationInFlight = false;
  var controlPlaneReady = false;
  var haltAuthorityReady = false;
  var operationRequested = 0;
  var toolPattern = /^[A-Za-z0-9_.-]{1,64}$/;

  var state = document.getElementById("acp-state");
  var output = document.getElementById("acp-output");
  var operationState = document.getElementById("acp-operation-state");
  var rows = document.getElementById("acp-rows");
  var rosterHeading = document.getElementById("acp-roster-title");
  var rosterPage = document.getElementById("acp-roster-page");
  var rosterPrevious = document.getElementById("acp-roster-prev");
  var rosterNext = document.getElementById("acp-roster-next");
  var verbControls = document.getElementById("acp-verb-controls");
  var verbSelect = document.getElementById("acp-verb-select");
  var verbSubmit = document.getElementById("acp-verb-submit");
  var attenuateControls = document.getElementById("acp-attenuate-controls");
  var fleetControls = document.getElementById("acp-fleet-controls");
  var fleetForm = document.getElementById("acp-fleet-form");
  var fleetVerb = document.getElementById("acp-fleet-verb");
  var fleetReview = document.getElementById("acp-fleet-review");
  var fleetApply = document.getElementById("acp-fleet-apply");
  var fleetSelectionState = document.getElementById("acp-fleet-selection-state");
  var haltControls = document.getElementById("acp-halt-controls");
  var clearHalt = document.getElementById("acp-clear-halt");
  var outputSummary = document.getElementById("acp-output-summary");
  var verbPrincipal = document.getElementById("acp-verb-principal");
  var attenuatePrincipal = document.getElementById("acp-attenuate-principal");
  var denyTools = document.getElementById("acp-deny-tools");
  var fleetScope = document.getElementById("acp-fleet-scope");
  var workspaceScopeKnown = root.dataset.workspaceScope === "true";
  var workspaceScopeValue = root.dataset.workspaceValue || "";
  var rosterRows = [];
  var fleetSelection = null;

  var planeRequested = 0;
  var planeApplied = 0;
  var planeRefreshPromise = null;
  var planeLastResult = {
    planeOk: false, halt: null, haltComplete: false, planeError: null, haltError: null
  };

  function fail(message) {
    var error = new Error(message);
    error.code = "invalid_input";
    return error;
  }

  // A reply that does not match what this page expects. The person sees one
  // plain sentence; the precise reason stays in Technical details.
  function failServer(technical) {
    var error = new Error("Lightwork returned something unexpected. Refresh the page and try again.");
    error.code = "invalid_response";
    error.technical = technical;
    return error;
  }

  var VERB_LABELS = {
    suspend: "Pause", resume: "Resume", contain: "Isolate",
    release: "End isolation", ledger: "View history", attenuate: "Limit"
  };
  var STATE_LABELS = {
    running: ["Working", "running"], active: ["Active", "ok"], idle: ["Idle", "idle"],
    suspended: ["Paused", "paused"], contained: ["Isolated", "failed"],
    expired: ["Access expired", "warn"], missing_trust: ["Not yet trusted", "warn"],
    not_yet_valid: ["Not active yet", "warn"], revoked: ["Paused", "paused"]
  };
  var RESULT_CODES = {
    protected_containment: "This agent is isolated. An administrator must end the isolation first.",
    dependency_unavailable: "Part of Lightwork needed for this is not available right now. Try again in a minute.",
    not_applied: "The change did not take effect.",
    containment_failed: "The agent could not be fully isolated. Try again.",
    schedule_unavailable: "The automatic end of isolation could not be scheduled. End the isolation yourself when it is no longer needed.",
    concurrent_containment: "Someone else changed this agent at the same time. Check the list and try again.",
    already_released: "This agent was already released from isolation.",
    superseded: "A newer isolation replaced this one, so it was left in place.",
    release_failed: "The isolation could not be ended. Try again.",
    action_error: "The change could not be completed. Try again.",
    concurrent_halt: "Someone else changed the emergency stop at the same time. Check its state and try again.",
    idempotent_replay: "This exact change had already been applied.",
    recovered: "An earlier unfinished change was completed."
  };

  function human(value) {
    if (typeof window.mvHuman === "function") { return window.mvHuman(value); }
    var text = String(value || "").replace(/[_-]+/g, " ").trim();
    return text ? text.charAt(0).toUpperCase() + text.slice(1) : "";
  }

  function nameOf(principal) {
    for (var index = 0; index < rosterRows.length; index += 1) {
      if (rosterRows[index].principal === principal) { return displayName(rosterRows[index]); }
    }
    return String(principal || "").replace(/^(user|agent|agents|external|service):/, "");
  }

  function displayName(row) {
    var label = typeof row.label === "string" ? row.label.trim() : "";
    return label || String(row.principal).replace(/^(user|agent|agents|external|service):/, "");
  }

  function duration(seconds) {
    var value = Number(seconds);
    if (!Number.isFinite(value) || value <= 0) { return ""; }
    if (value < 90) { return Math.round(value) + " seconds"; }
    if (value < 5400) { return Math.round(value / 60) + " minutes"; }
    if (value < 129600) { return Math.round(value / 3600) + " hours"; }
    return Math.round(value / 86400) + " days";
  }

  function plainFailure(status, detail, headers) {
    if (detail === "control_plane_disabled") {
      return "Agent controls are turned off. Ask an administrator to turn them on.";
    }
    if (status === 409) {
      return "This changed since you last looked. The list has been refreshed; check it and try again.";
    }
    if (typeof window.mvErrorText === "function") {
      // Headers carry the turned-off reason, so "off" is never read as "no permission".
      return window.mvErrorText({ status: status, headers: headers }, "finish this");
    }
    if (status === 403) { return "You do not have permission to do this. Ask an administrator."; }
    if (status === 400 || status === 422) { return "Some of the details need fixing. Check them and try again."; }
    return "Something went wrong. Try again.";
  }

  function boundedError(error) {
    var message = error && error.message ? error.message : String(error);
    if (message.length <= maxAnnouncedErrorChars) { return message; }
    return message.slice(0, maxAnnouncedErrorChars - 1) + "…";
  }

  function responseDetail(payload) {
    var detail = payload && payload.detail;
    if (typeof detail === "string" && detail) { return detail; }
    if (Array.isArray(detail)) {
      var entries = detail.slice(0, 8).map(function (entry) {
        if (typeof entry === "string") { return entry.slice(0, 250); }
        if (!entry || typeof entry !== "object") { return "One of the values sent was not accepted."; }
        var location = Array.isArray(entry.loc)
          ? entry.loc.filter(function (part) {
            return part !== "body" && part !== "query" && part !== "path";
          }).map(String).join(".")
          : "";
        var message = typeof entry.msg === "string" && entry.msg
          ? entry.msg
          : "One of the values sent was not accepted.";
        return (location ? location + ": " : "") + message.slice(0, 250);
      });
      if (detail.length > entries.length) {
        entries.push(String(detail.length - entries.length) + " more validation error(s)");
      }
      if (entries.length) { return boundedError(entries.join("; ")); }
    }
    if (detail && typeof detail === "object" &&
        typeof detail.message === "string" && detail.message) {
      return detail.message;
    }
    return "That didn't work. Refresh the page and try again.";
  }

  function utf8ByteLength(value) {
    var bytes = 0;
    for (var index = 0; index < value.length; index += 1) {
      var code = value.charCodeAt(index);
      if (code <= 0x7f) { bytes += 1; }
      else if (code <= 0x7ff) { bytes += 2; }
      else if (code >= 0xd800 && code <= 0xdbff &&
          index + 1 < value.length &&
          value.charCodeAt(index + 1) >= 0xdc00 &&
          value.charCodeAt(index + 1) <= 0xdfff) {
        bytes += 4;
        index += 1;
      } else { bytes += 3; }
    }
    return bytes;
  }

  async function boundedResponseText(response) {
    var declared = Number(response.headers.get("content-length") || 0);
    if (declared > maxResponseBytes) {
      if (response.body && typeof response.body.cancel === "function") {
        await response.body.cancel();
      }
      throw failServer("The reply was too large.");
    }
    if (response.body && typeof response.body.getReader === "function" &&
        typeof TextDecoder === "function") {
      var reader = response.body.getReader();
      var decoder = new TextDecoder("utf-8", { fatal: false });
      var received = 0;
      var text = "";
      while (true) {
        var chunk = await reader.read();
        if (chunk.done) { break; }
        received += chunk.value.byteLength;
        if (received > maxResponseBytes) {
          await reader.cancel();
          throw failServer("The reply was too large.");
        }
        text += decoder.decode(chunk.value, { stream: true });
      }
      return text + decoder.decode();
    }
    // Test doubles and older non-browser fetch implementations may not expose a
    // ReadableStream. Keep the validation byte-accurate there, while real
    // browsers take the bounded streaming path above before allocating the body.
    var fallback = await response.text();
    if (utf8ByteLength(fallback) > maxResponseBytes) {
      throw failServer("The reply was too large.");
    }
    return fallback;
  }

  async function readJson(response) {
    var text = await boundedResponseText(response);
    var payload;
    try { payload = text ? JSON.parse(text) : {}; }
    catch (_error) { throw failServer("The reply could not be read. Refresh the page and try again."); }
    if (!response.ok) {
      var detail = responseDetail(payload);
      var responseError = fail(plainFailure(response.status, detail, response.headers));
      responseError.technical = detail;
      responseError.status = response.status;
      responseError.payload = payload;
      throw responseError;
    }
    return payload;
  }

  async function requestAt(url, options) {
    var supplied = options || {};
    var settings = Object.assign({ credentials: "same-origin" }, supplied);
    settings.headers = Object.assign(
      { Accept: "application/json" }, supplied.headers || {}
    );
    if (settings.body) { settings.headers["Content-Type"] = "application/json"; }
    var controller = typeof AbortController === "function" ? new AbortController() : null;
    var timeout = null;
    if (controller) {
      settings.signal = controller.signal;
      timeout = setTimeout(function () { controller.abort(); }, requestTimeoutMs);
    }
    try {
      return await readJson(await fetch(url, settings));
    } catch (error) {
      if (controller && controller.signal.aborted) {
        throw fail("Lightwork took too long to answer. Nothing is assumed to have changed; refresh to check.");
      }
      throw error;
    } finally {
      if (timeout !== null) { clearTimeout(timeout); }
    }
  }

  function request(path, options) {
    return requestAt(apiBase + path, options);
  }

  function summaryLines(payload) {
    var lines = [];
    if (!payload || typeof payload !== "object") { return lines; }
    if (Array.isArray(payload)) {
      payload.slice(0, 100).forEach(function (item) {
        if (!item || typeof item !== "object") { return; }
        var when = typeof window.mvWhen === "function" ? window.mvWhen(item.ts) : "";
        var text = human(item.kind || "event");
        if (typeof item.detail === "string" && item.detail) { text += ": " + boundedError(item.detail); }
        lines.push((when ? when + " — " : "") + text);
      });
      if (!lines.length) { lines.push("No history has been recorded yet. Actions on this agent appear here."); }
      return lines;
    }
    if (Array.isArray(payload.results)) {
      payload.results.forEach(function (item) {
        if (!item || typeof item !== "object") { return; }
        lines.push(nameOf(item.principal) + ": " + (item.ok ? "done" :
          "not done" + (RESULT_CODES[item.code] ? " — " + RESULT_CODES[item.code] : "")));
      });
    }
    if (Array.isArray(payload.principals) && !Array.isArray(payload.results)) {
      payload.principals.forEach(function (principal) { lines.push(nameOf(principal)); });
    }
    return lines;
  }

  function show(label, payload, ticket) {
    if (ticket !== undefined && ticket !== null && ticket !== operationRequested) {
      return false;
    }
    var parts = [label];
    if (payload && typeof payload === "object" && !Array.isArray(payload)) {
      if (payload.ok === false && RESULT_CODES[payload.code]) {
        parts.push(RESULT_CODES[payload.code]);
      }
      if (Object.prototype.hasOwnProperty.call(payload, "audit_written")) {
        parts.push(payload.audit_written === true
          ? "It was recorded in the history."
          : payload.audit_written === false
            ? "Warning: it was not recorded in the history."
            : "Lightwork could not confirm it was recorded in the history. Refresh the page to see the latest.");
      }
    }
    var announced = parts.map(function (part) {
      return /[.!?]$/.test(part) ? part : part + ".";
    }).join(" ");
    operationState.textContent = announced;
    if (outputSummary) {
      outputSummary.textContent = "";
      var lines = summaryLines(payload);
      if (lines.length) {
        var list = document.createElement("ul");
        lines.forEach(function (line) {
          var item = document.createElement("li");
          item.textContent = line;
          list.appendChild(item);
        });
        outputSummary.appendChild(list);
      }
    }
    output.textContent = typeof payload === "string"
      ? payload
      : JSON.stringify(payload, null, 2);
    return true;
  }

  function showError(error, prefix, ticket) {
    if (ticket !== undefined && ticket !== null && ticket !== operationRequested) {
      return false;
    }
    var message = boundedError(error);
    operationState.textContent = (prefix || "That did not work") + ". " + message;
    if (outputSummary) { outputSummary.textContent = ""; }
    output.textContent = error && error.technical ? boundedError({ message: String(error.technical) }) : message;
    return true;
  }

  function checkPrincipal(value) {
    var principal = String(value || "");
    if (!principal || principal !== principal.trim() || principal.length > 512 ||
        /[\u0000-\u001f\u007f-\u009f]/.test(principal)) {
      throw fail("Choose an agent or person from the list.");
    }
    return principal;
  }

  function setMark(marker, text) {
    state.dataset.state = marker;
    state.className = "badge " + (marker === "ready" ? "ok" : marker === "failed" ? "failed" : "warn");
    state.textContent = text;
  }

  function setBusy(control, busy) {
    if (!control) { return; }
    if (busy) {
      control.dataset.acpBusy = "true";
      control.setAttribute("aria-busy", "true");
      control.disabled = true;
      return;
    }
    delete control.dataset.acpBusy;
    control.removeAttribute("aria-busy");
    if (control === rosterPrevious) {
      control.disabled = rosterOffset <= 0;
    } else if (control === rosterNext) {
      control.disabled = rosterNextOffset === null;
    } else if (control === clearHalt) {
      control.disabled = !canHalt || !haltAuthorityReady;
    } else if (control === verbSubmit) {
      updateVerbSubmit();
    } else if (control === fleetReview || control === fleetApply) {
      updateFleetControls();
    } else if (control.dataset.requiresControlPlane === "true") {
      control.disabled = !controlPlaneReady;
    } else {
      control.disabled = control.dataset.roleDisabled === "true";
    }
  }

  async function withBusy(control, task) {
    setBusy(control, true);
    try { return await task(); }
    finally { setBusy(control, false); }
  }

  function runGuarded(target, isMutation, task, ownsOutput) {
    if (!target || target.dataset.inFlight === "true") {
      return Promise.resolve(null);
    }
    if (isMutation && mutationInFlight) { return Promise.resolve(null); }
    target.dataset.inFlight = "true";
    if (isMutation) {
      mutationInFlight = true;
      root.dataset.mutationPending = "true";
    }
    var ticket = ownsOutput ? ++operationRequested : null;
    return Promise.resolve()
      .then(function () { return task(ticket); })
      .catch(function (error) {
        if (ownsOutput) { showError(error, undefined, ticket); }
        return null;
      })
      .finally(function () {
        delete target.dataset.inFlight;
        if (isMutation) {
          mutationInFlight = false;
          delete root.dataset.mutationPending;
        }
      });
  }

  async function collectReason(verb, principal) {
    if (typeof window.mvForm !== "function") {
      throw fail("The reason form could not open. Nothing was changed; refresh the page and try again.");
    }
    var values = await window.mvForm(
      VERB_LABELS[verb] + " " + nameOf(principal),
      [{
        key: "reason",
        label: "Reason",
        type: "text",
        required: true,
        placeholder: "Why is this needed?",
        help: "The reason is saved in this agent's history."
      }],
      { okText: VERB_LABELS[verb] }
    );
    if (values === null) { return null; }
    var reason = String(values.reason || "").trim();
    if (!reason) { throw fail("A reason is required."); }
    if (reason.length > 500) { throw fail("Reason must be at most 500 characters."); }
    return reason;
  }

  async function confirmAction(message, okText) {
    if (typeof window.mvConfirm !== "function") {
      throw fail("The confirmation could not open. Nothing was changed; refresh the page and try again.");
    }
    return window.mvConfirm(message, { okText: okText });
  }

  function updateVerbSubmit() {
    var verb = verbSelect ? verbSelect.value : "";
    var mutation = verb !== "ledger";
    if (verbSubmit) {
      verbSubmit.disabled = verbControls.dataset.roleDisabled === "true" ||
        (mutation && !controlPlaneReady);
    }
  }

  function updateFleetControls() {
    if (!fleetControls || !fleetReview || !fleetApply) { return; }
    var fleetAllowed = canOperate || canAdmin;
    if (fleetControls.dataset.roleDisabled !== "true") {
      fleetControls.disabled = !fleetAllowed || !controlPlaneReady;
      fleetControls.setAttribute("aria-disabled", String(fleetControls.disabled));
    }
    fleetReview.disabled = !fleetAllowed || !controlPlaneReady;
    fleetApply.disabled = !fleetAllowed || !controlPlaneReady || !fleetSelection;
  }

  function updateRuntimeControls() {
    var options = verbSelect.querySelectorAll("option[data-requires-control-plane]");
    options.forEach(function (option) { option.disabled = !controlPlaneReady; });
    if (verbControls.dataset.roleDisabled !== "true") {
      verbControls.disabled = false;
      verbControls.removeAttribute("aria-disabled");
    }
    if (attenuateControls) {
      attenuateControls.disabled = !canOperate || !controlPlaneReady;
      attenuateControls.setAttribute("aria-disabled", String(attenuateControls.disabled));
    }
    updateFleetControls();
    haltControls.disabled = !canHalt || !haltAuthorityReady;
    haltControls.setAttribute("aria-disabled", String(haltControls.disabled));
    clearHalt.disabled = !canHalt || !haltAuthorityReady;
    var rowMutations = rows.querySelectorAll("button[data-requires-control-plane]");
    rowMutations.forEach(function (button) { button.disabled = !controlPlaneReady; });
    updateVerbSubmit();
  }

  function checkSelectionText(value, label, required) {
    var text = String(value || "");
    if (!text && !required) { return ""; }
    if (!text || text !== text.trim() || text.length > 160 ||
        /[\u0000-\u001f\u007f-\u009f]/.test(text)) {
      throw fail("Choose a group from the list.");
    }
    return text;
  }

  function fleetScopeFromForm() {
    if (!fleetForm) { throw fail("Group actions are unavailable. Refresh the page and try again."); }
    var form = new FormData(fleetForm);
    var scope = String(form.get("scope") || "");
    if (scope === "workspace" && workspaceScopeKnown) {
      return { tenant: workspaceScopeValue, platform: null };
    }
    if (scope.indexOf("platform:") === 0) {
      var platform = checkSelectionText(scope.slice(9), "Platform", true);
      return { tenant: null, platform: platform };
    }
    throw fail("Choose a group first.");
  }

  function sameFleetScope(first, second) {
    return Boolean(first && second && first.tenant === second.tenant &&
      first.platform === second.platform);
  }

  function validateFleetSelection(payload, requestedScope) {
    if (!payload || typeof payload !== "object" ||
        payload.schema !== "lightwork.agent-control-plane-selection.v1" ||
        typeof payload.tenant !== "string" || payload.tenant !== payload.tenant.trim() ||
        !/^[0-9a-f]{64}$/.test(String(payload.snapshot_sha256 || "")) ||
        typeof payload.captured_at !== "number" || !Number.isFinite(payload.captured_at) ||
        payload.captured_at <= 0 || !Array.isArray(payload.principals) ||
        !payload.principals.length || payload.principals.length > 500) {
      throw failServer("The group review reply was incomplete.");
    }
    if (payload.platform !== null && payload.platform !== undefined &&
        (typeof payload.platform !== "string" || !payload.platform ||
         payload.platform !== payload.platform.trim() || payload.platform.length > 160)) {
      throw failServer("The group review reply named an unexpected platform.");
    }
    var principals = payload.principals.map(checkPrincipal);
    var canonical = principals.slice().sort();
    if (principals.some(function (principal, index) { return principal !== canonical[index]; }) ||
        new Set(principals).size !== principals.length) {
      throw failServer("The group review reply was not in the expected order.");
    }
    if (requestedScope.tenant !== null && payload.tenant !== requestedScope.tenant) {
      throw failServer("The group review reply was for a different workspace.");
    }
    if ((requestedScope.platform || null) !== (payload.platform || null)) {
      throw failServer("The group review reply was for a different platform.");
    }
    return {
      schema: payload.schema,
      tenant: payload.tenant,
      platform: payload.platform || null,
      principals: principals,
      snapshot_sha256: payload.snapshot_sha256,
      captured_at: payload.captured_at,
      requested_scope: requestedScope
    };
  }

  function invalidateFleetSelection(message) {
    fleetSelection = null;
    if (fleetSelectionState && message) { fleetSelectionState.textContent = message; }
    updateFleetControls();
  }

  function fleetActionFromForm() {
    if (!fleetForm || !fleetVerb) { throw fail("Group actions are unavailable. Refresh the page and try again."); }
    var form = new FormData(fleetForm);
    var verb = String(fleetVerb.value || "");
    var allowed = (verb === "suspend" || verb === "resume") ? canOperate : canAdmin;
    if (!allowed || !["suspend", "resume", "contain", "release"].includes(verb)) {
      throw fail("Your role cannot use this group action.");
    }
    var reason = String(form.get("reason") || "").trim();
    if ((verb === "suspend" || verb === "contain") && !reason) {
      throw fail("Give a reason to " + VERB_LABELS[verb].toLowerCase() + " this group.");
    }
    if (reason.length > 500) { throw fail("Reason must be at most 500 characters."); }
    if ((verb === "resume" || verb === "release") && reason) {
      throw fail("Leave the reason empty to " + VERB_LABELS[verb].toLowerCase() + " a group.");
    }
    var secondsRaw = String(form.get("release_after_seconds") || "").trim();
    var seconds = null;
    if (secondsRaw) {
      seconds = Number(secondsRaw);
      if (!Number.isFinite(seconds) || seconds <= 0 || seconds > 2678400) {
        throw fail("Choose how long the isolation should last from the list.");
      }
    }
    var idempotencyKey = String(form.get("idempotency_key") || "").trim();
    if (seconds !== null) {
      if (verb !== "contain") {
        throw fail("Automatic ending only applies when you isolate a group. Choose Never, or choose Isolate.");
      }
      if (!/^[A-Za-z0-9._:-]{1,160}$/.test(idempotencyKey)) {
        throw fail("The page is not ready yet. Refresh it and try again.");
      }
    }
    return {
      verb: verb,
      reason: reason || null,
      release_after_seconds: seconds,
      idempotency_key: seconds !== null ? idempotencyKey : null
    };
  }

  async function reviewFleetSelection(ticket) {
    if (!controlPlaneReady) {
      throw fail("Lightwork has not confirmed the current state of your agents yet, so nothing was sent. Refresh and try again.");
    }
    var requestedScope = fleetScopeFromForm();
    var payload = {};
    if (requestedScope.tenant !== null) { payload.tenant = requestedScope.tenant; }
    if (requestedScope.platform) { payload.platform = requestedScope.platform; }
    var returned = await request("/bulk/select", {
      method: "POST", body: JSON.stringify(payload)
    });
    fleetSelection = validateFleetSelection(returned, requestedScope);
    fleetSelectionState.textContent = "Reviewed " + fleetSelection.principals.length +
      (fleetSelection.principals.length === 1 ? " agent or person." : " agents and people.") +
      " You can now apply the action.";
    updateFleetControls();
    show("Group reviewed. These are the agents and people it includes", returned, ticket);
    return returned;
  }

  async function applyFleetAction(ticket) {
    if (!controlPlaneReady || !fleetSelection) {
      throw fail("Press Review group before applying an action.");
    }
    var requestedScope = fleetScopeFromForm();
    if (!sameFleetScope(requestedScope, fleetSelection.requested_scope)) {
      invalidateFleetSelection("The group changed. Press Review group again.");
      throw fail("The group changed. Press Review group again.");
    }
    var action = fleetActionFromForm();
    var count = fleetSelection.principals.length;
    if (!(await confirmAction(
      VERB_LABELS[action.verb] + " " + count + (count === 1 ? " agent or person" : " agents and people") +
        "? If anyone's status changed since you reviewed the group, nothing will be changed.",
      VERB_LABELS[action.verb] + " group"
    ))) { return null; }
    var body = {
      selection: {
        schema: fleetSelection.schema,
        tenant: fleetSelection.tenant,
        platform: fleetSelection.platform,
        principals: fleetSelection.principals,
        snapshot_sha256: fleetSelection.snapshot_sha256,
        captured_at: fleetSelection.captured_at
      },
      verb: action.verb
    };
    if (action.reason !== null) { body.reason = action.reason; }
    if (action.release_after_seconds !== null) {
      body.release_after_seconds = action.release_after_seconds;
      body.idempotency_key = action.idempotency_key;
    }
    var result = null;
    var requestError = null;
    try {
      result = await request("/bulk/actions", {
        method: "POST", body: JSON.stringify(body)
      });
    } catch (error) {
      requestError = error;
    }
    invalidateFleetSelection("Review the group again before another group action.");
    var refreshed = await refresh();
    if (requestError) {
      if (requestError.payload && typeof requestError.payload === "object") {
        show("The group action was not fully confirmed. The list below shows the current state", requestError.payload, ticket);
        return requestError.payload;
      }
      showError(requestError, refreshed.planeOk
        ? "The group action did not go through. The list has been refreshed"
        : "The group action did not go through, and the list could not be refreshed", ticket);
      return null;
    }
    show("Group action finished: " + VERB_LABELS[action.verb] +
      (refreshed.planeOk ? "" : ". The list could not be refreshed, so check it before relying on this"), result, ticket);
    return result;
  }

  function isNonNegativeInteger(value) {
    return typeof value === "number" && Number.isFinite(value) &&
      Number.isInteger(value) && value >= 0;
  }

  function hasMetricContract(value, names) {
    if (!value || typeof value !== "object" || Array.isArray(value)) { return false; }
    return names.every(function (name) { return isNonNegativeInteger(value[name]); });
  }

  function validatePlaneSnapshot(payload) {
    if (!payload || typeof payload !== "object" ||
        !payload.status || !payload.agents) {
      throw failServer("The agent status reply was incomplete.");
    }
    var st = payload.status;
    var agents = payload.agents;
    var capturedAt = st.captured_at;
    var rosterCapturedAt = agents.captured_at;
    var complete = st.schema === "lightwork.agent-control-plane-status.v1" &&
      typeof capturedAt === "number" && Number.isFinite(capturedAt) && capturedAt >= 0 &&
      typeof rosterCapturedAt === "number" && Number.isFinite(rosterCapturedAt) &&
      rosterCapturedAt === capturedAt &&
      typeof st.enabled === "boolean" && typeof st.halted === "boolean" &&
      typeof st.halt_scope === "string" && st.halt_scope.length > 0 &&
      typeof st.trust_enforced === "boolean" &&
      typeof st.external_agents_enabled === "boolean" &&
      hasMetricContract(
        st.native, ["principals", "running_goals", "suspended", "contained"]
      ) &&
      hasMetricContract(
        st.external, ["agents", "active", "suspended", "contained"]
      );
    if (!complete) {
      throw failServer("The agent status reply was incomplete or out of date.");
    }
    return { status: st, agents: agents };
  }

  function applyStatus(st, halt, haltError) {
    var haltStatusComplete = !haltError && halt && typeof halt.active === "boolean" &&
      halt.scope === haltScope &&
      (haltScope === "local" ||
        (haltScope === "cluster" && typeof halt.cluster_halt === "boolean")) &&
      st.halted === halt.active;
    haltAuthorityReady = Boolean(haltStatusComplete);
    controlPlaneReady = Boolean(st.enabled === true && haltStatusComplete);
    updateRuntimeControls();
    var native = st && st.native ? st.native : {};
    var external = st && st.external ? st.external : {};
    document.getElementById("acp-native").textContent = String(native.principals ?? "—");
    document.getElementById("acp-external").textContent = String(external.agents ?? "—");
    var suspended = Number(native.suspended);
    var externalSuspended = Number(external.suspended);
    var nativeContained = Number(native.contained);
    var externalContained = Number(external.contained);
    document.getElementById("acp-suspended").textContent =
      Number.isFinite(suspended) && Number.isFinite(externalSuspended) &&
        Number.isFinite(nativeContained) && Number.isFinite(externalContained)
        ? String(suspended + externalSuspended) + " / " +
          String(nativeContained + externalContained)
        : "—";

    var title = document.getElementById("acp-health-title");
    var detail = document.getElementById("acp-health-detail");
    if (!haltStatusComplete) {
      setMark("partial", "Unknown");
      title.textContent = "Emergency stop state is unknown";
      detail.textContent = "Lightwork could not check the emergency stop. Don't assume agents are running or stopped; refresh to try again.";
    } else if (halt.active) {
      if (haltScope === "cluster" && halt.cluster_halt !== true) {
        setMark("failed", "Partly stopped");
        title.textContent = "The stop is not confirmed everywhere";
        detail.textContent = "This Lightwork server is stopped, but others may still be running.";
      } else {
        setMark("failed", "Stopped");
        title.textContent = haltScope === "cluster"
          ? "All agents on every server are stopped"
          : "All agents on this server are stopped";
        detail.textContent = "The emergency stop is on and confirmed. Use Resume all work when it is safe.";
      }
    } else if (!st.enabled) {
      setMark("partial", "View only");
      title.textContent = "Agent controls are turned off";
      detail.textContent = "You can see your agents, but pausing, isolating and limiting are turned off. Ask an administrator to turn agent controls on.";
    } else {
      setMark("ready", "Ready");
      title.textContent = "Agent controls are ready";
      detail.textContent = (st.trust_enforced
        ? "Only trusted agents may act. "
        : "Agents do not need to be approved as trusted before they act. ") +
        (st.external_agents_enabled ? "Outside agents can connect." : "Outside agents cannot connect.");
    }
  }

  function cell(text) {
    var td = document.createElement("td");
    td.textContent = text;
    return td;
  }

  function currentRosterFocus() {
    var active = document.activeElement;
    if (!active || !rows.contains(active)) { return null; }
    var principal = active.dataset.acpPrincipal;
    var verb = active.dataset.acpVerb;
    return principal ? { principal: principal, verb: verb || "" } : { principal: "", verb: "" };
  }

  function restoreRosterFocus(previous) {
    if (!previous) { return; }
    var buttons = rows.querySelectorAll("button[data-acp-principal]");
    var principalMatch = null;
    for (var index = 0; index < buttons.length; index += 1) {
      var button = buttons[index];
      if (button.dataset.acpPrincipal !== previous.principal) { continue; }
      if (!principalMatch) { principalMatch = button; }
      if (button.dataset.acpVerb === previous.verb) {
        button.focus();
        return;
      }
    }
    if (principalMatch) { principalMatch.focus(); return; }
    rosterHeading.focus();
  }

  function ceilingOf(row) {
    if (row.kind !== "external") { return "—"; }
    var parts = [];
    parts.push(row.max_risk ? "Highest risk: " + human(row.max_risk) : "No risk limit");
    parts.push(row.max_dollars === null || row.max_dollars === undefined
      ? "No spending limit"
      : "Spending limit: " + (window.mvMoney ? window.mvMoney(row.max_dollars) : "$" + row.max_dollars));
    if (row.deny_tools && row.deny_tools.length) {
      parts.push("Blocked tools: " + row.deny_tools.map(human).join(", "));
    }
    if (row.allow_tools && row.allow_tools.length) {
      parts.push("Only these tools: " + row.allow_tools.map(human).join(", "));
    }
    if (row.max_wall_seconds !== null && row.max_wall_seconds !== undefined) {
      parts.push("Time limit: " + duration(row.max_wall_seconds));
    }
    return parts.join(" · ");
  }

  function validateToolList(value, field) {
    if (!Array.isArray(value) || value.length > 256 ||
        value.some(function (name) { return !toolPattern.test(name); })) {
      throw failServer("The list had a " + field + " tool list that could not be read.");
    }
    return value.slice();
  }

  function validateRosterRow(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw failServer("The list had a row that could not be read.");
    }
    var row = Object.assign({}, value);
    row.principal = checkPrincipal(row.principal);
    if (row.kind !== "native" && row.kind !== "external") {
      throw failServer("The list had a row whose kind of agent or person is not recognized.");
    }
    if (typeof row.state !== "string" || !row.state || row.state.length > 64 ||
        /[\u0000-\u001f\u007f-\u009f]/.test(row.state)) {
      throw failServer("The list had a row with a state that is not recognized.");
    }
    if (!isNonNegativeInteger(row.running_goals) ||
        typeof row.revoked !== "boolean" || typeof row.contained !== "boolean") {
      throw failServer("The list had a row whose controls could not be read.");
    }
    if (row.label !== undefined && (typeof row.label !== "string" || row.label.length > 512)) {
      row.label = "";
    }
    if (row.platform !== undefined &&
        (typeof row.platform !== "string" || row.platform.length > 128 ||
         /[\u0000-\u001f\u007f-\u009f]/.test(row.platform))) {
      throw failServer("The list had a row whose platform name could not be read.");
    }
    if (row.revoked_reason !== undefined &&
        (typeof row.revoked_reason !== "string" || row.revoked_reason.length > 500 ||
         /[\u0000-\u001f\u007f-\u009f]/.test(row.revoked_reason))) {
      throw failServer("The list had a row whose incident summary could not be read.");
    }
    if (row.max_risk !== null && row.max_risk !== undefined &&
        !["low", "medium", "high"].includes(row.max_risk)) {
      throw failServer("The list had a row whose risk limit could not be read.");
    }
    ["max_dollars", "max_wall_seconds"].forEach(function (field) {
      if (row[field] !== null && row[field] !== undefined &&
          (typeof row[field] !== "number" || !Number.isFinite(row[field]) || row[field] <= 0)) {
        throw failServer("The list had a row whose number limit could not be read.");
      }
    });
    row.allow_tools = validateToolList(row.allow_tools || [], "allowed");
    row.deny_tools = validateToolList(row.deny_tools || [], "denied");
    return row;
  }

  async function mutatePrincipal(verb, principal, reason, ticket) {
    if (!controlPlaneReady) {
      throw fail("Lightwork has not confirmed the current state of your agents yet, so nothing was sent. Refresh and try again.");
    }
    var body = { principal: principal };
    if (reason !== undefined) { body.reason = reason; }
    var options = { method: "POST", body: JSON.stringify(body) };
    var result = null;
    var requestError = null;
    try {
      result = await request("/principals/" + verb, options);
    } catch (error) {
      requestError = error;
    }
    var refreshed = await refresh();
    if (requestError) {
      if (requestError.payload && requestError.payload.ok === false) {
        show("Not done: " + VERB_LABELS[verb] + " " + nameOf(principal) +
          (refreshed.planeOk ? "" : ". The list could not be refreshed"),
        requestError.payload, ticket);
        return requestError.payload;
      }
      showError(requestError, refreshed.planeOk
        ? VERB_LABELS[verb] + " did not go through. The list has been refreshed"
        : VERB_LABELS[verb] + " did not go through, and the list could not be refreshed", ticket);
      return null;
    }
    show((result.ok ? "Done: " : "Not done: ") + VERB_LABELS[verb] + " " + nameOf(principal) +
      (refreshed.planeOk ? "" : ". The list could not be refreshed, so check it before relying on this"), result, ticket);
    return result;
  }

  async function ledger(principal, ticket) {
    var query = new URLSearchParams({ principal: principal, limit: "100" });
    var payload = await request("/principals/ledger?" + query.toString());
    if (ticket === operationRequested) {
      show(
        "History for " + nameOf(principal) + " (" + payload.count +
          (payload.count === 1 ? " event)" : " events)"),
        payload.items,
        ticket
      );
    }
    return payload;
  }

  function verbButton(verb, row, handler, isMutation) {
    var label = VERB_LABELS[verb];
    var principal = row.principal;
    var button = document.createElement("button");
    button.type = "button";
    button.className = verb === "contain" ? "btn btn--danger" : isMutation ? "btn" : "btn btn--ghost";
    button.textContent = label;
    button.dataset.acpPrincipal = principal;
    button.dataset.acpVerb = verb;
    if (isMutation) {
      button.dataset.requiresControlPlane = "true";
      button.disabled = !controlPlaneReady;
    }
    button.setAttribute("aria-label", label + " " + displayName(row));
    button.addEventListener("click", function () {
      runGuarded(button, isMutation, function (ticket) {
        return handler(button, ticket);
      }, true);
    });
    return button;
  }

  function renderRow(row) {
    var tr = document.createElement("tr");
    if (canOperate && !row.contained) {
      tr.dataset.bulkId = row.principal;
      tr.dataset.bulkLabel = displayName(row);
      tr.dataset.bulkPaused = row.revoked ? "true" : "false";
    }
    var principal = document.createElement("th");
    principal.scope = "row";
    principal.textContent = displayName(row);
    tr.appendChild(principal);
    tr.appendChild(cell((row.kind === "external" ? "Outside agent" : "Lightwork agent or person") +
      (row.platform ? " · " + row.platform : "")));
    var stateCell = document.createElement("td");
    var mark = document.createElement("span");
    var stateLabel = STATE_LABELS[row.state] || [human(row.state), "idle"];
    mark.className = "badge " + stateLabel[1];
    mark.dataset.state = row.state;
    mark.textContent = stateLabel[0];
    stateCell.appendChild(mark);
    if (row.revoked_reason) {
      var why = document.createElement("div");
      why.className = "muted";
      why.textContent = "Reason: " + row.revoked_reason;
      stateCell.appendChild(why);
    }
    tr.appendChild(stateCell);
    tr.appendChild(cell(String(row.running_goals ?? "—")));
    tr.appendChild(cell(ceilingOf(row)));
    var actions = document.createElement("td");
    var verbs = document.createElement("div");
    verbs.className = "acp-verbs";
    if (row.contained) {
      if (canAdmin) {
        verbs.appendChild(verbButton("release", row, async function (button, ticket) {
          if (!(await confirmAction(
            "End isolation for " + displayName(row) + "? It can then be resumed and work again.",
            "End isolation"
          ))) { return null; }
          return withBusy(button, function () {
            return mutatePrincipal("release", row.principal, undefined, ticket);
          });
        }, true));
      }
    } else if (row.revoked) {
      if (canOperate) {
        verbs.appendChild(verbButton("resume", row, async function (button, ticket) {
          if (!(await confirmAction(
            "Resume " + displayName(row) + "? It will be able to work again straight away.",
            "Resume"
          ))) { return null; }
          return withBusy(button, function () {
            return mutatePrincipal("resume", row.principal, undefined, ticket);
          });
        }, true));
      }
    } else {
      if (canOperate) {
        verbs.appendChild(verbButton("suspend", row, async function (button, ticket) {
          var reason = await collectReason("suspend", row.principal);
          if (reason === null) { return null; }
          return withBusy(button, function () {
            return mutatePrincipal("suspend", row.principal, reason, ticket);
          });
        }, true));
      }
      if (canAdmin) {
        verbs.appendChild(verbButton("contain", row, async function (button, ticket) {
          var reason = await collectReason("contain", row.principal);
          if (reason === null) { return null; }
          return withBusy(button, function () {
            return mutatePrincipal("contain", row.principal, reason, ticket);
          });
        }, true));
      }
    }
    if (canOperate && row.kind === "external" && !row.contained) {
      var limit = document.createElement("button");
      limit.type = "button";
      limit.className = "btn";
      limit.textContent = VERB_LABELS.attenuate;
      limit.dataset.acpPrincipal = row.principal;
      limit.dataset.acpVerb = "attenuate";
      limit.dataset.requiresControlPlane = "true";
      limit.disabled = !controlPlaneReady;
      limit.setAttribute("aria-label", "Limit " + displayName(row));
      limit.addEventListener("click", function () { openLimits(row.principal); });
      verbs.appendChild(limit);
    }
    if (canAudit) {
      verbs.appendChild(verbButton("ledger", row, function (button, ticket) {
        return withBusy(button, function () { return ledger(row.principal, ticket); });
      }, false));
    }
    actions.appendChild(verbs);
    tr.appendChild(actions);
    return tr;
  }

  function refillSelect(select, options, emptyLabel) {
    if (!select) { return; }
    var previous = select.value;
    select.textContent = "";
    var placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = options.length ? "Choose…" : emptyLabel;
    select.appendChild(placeholder);
    options.forEach(function (entry) {
      var option = document.createElement("option");
      option.value = entry[0];
      option.textContent = entry[1];
      select.appendChild(option);
    });
    var stillThere = options.some(function (entry) { return entry[0] === previous; });
    select.value = stillThere ? previous : "";
  }

  function fillSelectors() {
    refillSelect(verbPrincipal, rosterRows.map(function (row) {
      return [row.principal, displayName(row)];
    }), "No agents or people yet");
    refillSelect(attenuatePrincipal, rosterRows.filter(function (row) {
      return row.kind === "external" && !row.contained;
    }).map(function (row) { return [row.principal, displayName(row)]; }),
    "No outside agents connected");
    if (fleetScope) {
      var groups = [];
      if (workspaceScopeKnown) { groups.push(["workspace", "Everyone in this workspace"]); }
      var seen = {};
      rosterRows.forEach(function (row) {
        if (row.kind !== "external" || !row.platform || seen[row.platform]) { return; }
        seen[row.platform] = true;
        groups.push(["platform:" + row.platform, "Outside agents from " + row.platform]);
      });
      refillSelect(fleetScope, groups, "No groups available");
    }
    renderTools();
  }

  function renderTools() {
    if (!denyTools) { return; }
    var chosen = attenuatePrincipal ? attenuatePrincipal.value : "";
    var row = null;
    rosterRows.forEach(function (candidate) { if (candidate.principal === chosen) { row = candidate; } });
    Array.prototype.slice.call(denyTools.querySelectorAll("label, .muted")).forEach(function (node) {
      node.remove();
    });
    var names = [];
    if (row) {
      (row.allow_tools || []).forEach(function (name) {
        if (names.indexOf(name) < 0 && (row.deny_tools || []).indexOf(name) < 0) { names.push(name); }
      });
    }
    if (!names.length) {
      var note = document.createElement("span");
      note.className = "muted";
      note.id = "acp-deny-tools-help";
      note.textContent = !row
        ? "Choose an outside agent to see its tools."
        : "This agent has no listed tools to block. You can still limit its risk, spending and time.";
      denyTools.appendChild(note);
      return;
    }
    names.forEach(function (name) {
      var label = document.createElement("label");
      var box = document.createElement("input");
      box.type = "checkbox";
      box.name = "deny_tool";
      box.value = name;
      label.appendChild(box);
      label.appendChild(document.createTextNode(" " + human(name)));
      denyTools.appendChild(label);
    });
  }

  function openLimits(principal) {
    if (!attenuatePrincipal) { return; }
    attenuatePrincipal.value = principal;
    renderTools();
    var heading = document.getElementById("acp-attenuate-title");
    if (heading && typeof heading.scrollIntoView === "function") { heading.scrollIntoView({ block: "start" }); }
    if (typeof attenuatePrincipal.focus === "function") { attenuatePrincipal.focus(); }
  }

  if (attenuatePrincipal) { attenuatePrincipal.addEventListener("change", renderTools); }

  function applyRoster(payload) {
    if (!payload || !Array.isArray(payload.items)) {
      throw failServer("The list page was larger than allowed or could not be read.");
    }
    var validatedItems = payload.items.map(validateRosterRow);
    var focus = currentRosterFocus();
    var total = Number(payload.total);
    var offset = Number(payload.offset);
    var limit = Number(payload.limit);
    var count = Number(payload.count);
    var end = offset + validatedItems.length;
    var expectedHasMore = end < total;
    var suppliedNext = payload.next_offset === null ? null : Number(payload.next_offset);
    if (!Number.isInteger(total) || total < 0 || !Number.isInteger(offset) || offset < 0 ||
        offset > total || !Number.isInteger(limit) || limit < 1 || limit > rosterLimit ||
        !Number.isInteger(count) || count !== validatedItems.length || count > limit ||
        end > total || payload.has_more !== expectedHasMore ||
        (expectedHasMore && suppliedNext !== end) ||
        (!expectedHasMore && suppliedNext !== null)) {
      throw failServer("The details for moving between list pages could not be read.");
    }
    rosterOffset = offset;
    rosterNextOffset = expectedHasMore ? suppliedNext : null;
    rosterRows = validatedItems;
    rows.textContent = "";
    fillSelectors();
    if (!validatedItems.length) {
      var empty = document.createElement("tr");
      empty.appendChild(cell(total === 0
        ? "No agents or people are working in Lightwork yet. Agents you create, and outside agents you connect, appear here."
        : "This page of the list is empty. Use Previous to go back."));
      empty.firstChild.colSpan = 6;
      rows.appendChild(empty);
    } else {
      validatedItems.forEach(function (row) { rows.appendChild(renderRow(row)); });
    }
    var first = validatedItems.length ? offset + 1 : 0;
    var last = validatedItems.length ? end : 0;
    rosterPage.textContent = "Showing " + first + "–" + last + " of " + total + ".";
    rosterPrevious.disabled = offset <= 0;
    rosterNext.disabled = payload.has_more !== true || rosterNextOffset === null;
    restoreRosterFocus(focus);
    updateRuntimeControls();
    refreshBulk();
  }

  // Pause or resume many agents and people at once: filter the list,
  // select all matching, one confirmation states the count, and the report
  // undoes each change (resume undoes a pause and pause undoes a resume).
  var bulk = null;
  function bulkChange(verb) {
    return async function (item, extra) {
      if (!controlPlaneReady) {
        throw { bulkReason: "Lightwork has not confirmed the current state of your agents yet. Refresh and try again." };
      }
      var paused = item.row.dataset.bulkPaused === "true";
      if (verb === "suspend" && paused) { throw { bulkReason: "It is already paused." }; }
      if (verb === "resume" && !paused) { throw { bulkReason: "It is not paused." }; }
      async function send(how, reason) {
        var body = { principal: item.id };
        if (reason) { body.reason = reason; }
        var result;
        try {
          result = await request("/principals/" + how, { method: "POST", body: JSON.stringify(body) });
        } catch (error) {
          throw { bulkReason: (error && error.message) || "It could not be changed." };
        }
        if (!result || result.ok !== true) {
          throw { bulkReason: (result && typeof result.detail === "string" && result.detail) || "Lightwork could not confirm the change." };
        }
        item.row.dataset.bulkPaused = how === "suspend" ? "true" : "false";
      }
      await send(verb, extra.reason);
      return {
        note: verb === "suspend" ? "paused" : "resumed",
        undo: function () {
          return verb === "suspend" ? send("resume") : send("suspend", "Undo of a resume made from the agent list");
        }
      };
    };
  }
  function refreshBulk() {
    if (!canOperate || typeof window.mvBulk !== "function") { return; }
    if (bulk) { bulk.refresh(); return; }
    if (!rows.querySelector("tr[data-bulk-id]")) { return; }
    bulk = window.mvBulk({
      list: rows, rows: "tr[data-bulk-id]", noun: "agent or person", nouns: "agents and people", filter: true,
      actions: [
        { label: "Pause", verb: "Pause", danger: true,
          ask: async function () {
            if (typeof window.mvForm !== "function") { return null; }
            var values = await window.mvForm("Pause the selected agents and people", [{
              key: "reason", label: "Reason", type: "text", required: true,
              placeholder: "Why is this needed?", help: "The reason is saved in each one's history."
            }], { okText: "Pause them" });
            var reason = values ? String(values.reason || "").trim().slice(0, 500) : "";
            return reason ? { reason: reason } : null;
          },
          run: bulkChange("suspend"), after: function () { refresh(); } },
        { label: "Resume", verb: "Resume", run: bulkChange("resume"), after: function () { refresh(); } }
      ]
    });
  }

  function renderRosterError(error) {
    var focus = currentRosterFocus();
    var message = boundedError(error);
    rows.textContent = "";
    var failed = document.createElement("tr");
    failed.appendChild(cell("Couldn't load the list. " + message));
    failed.firstChild.colSpan = 6;
    rows.appendChild(failed);
    rosterPage.textContent = "Couldn't load the list. Use Reload list to try again.";
    rosterPrevious.disabled = true;
    rosterNext.disabled = true;
    restoreRosterFocus(focus);
  }

  function haltPayloadComplete(payload) {
    return Boolean(payload && typeof payload.active === "boolean" &&
      payload.scope === haltScope &&
      (haltScope === "local" ||
        (haltScope === "cluster" && typeof payload.cluster_halt === "boolean")));
  }

  async function drainPlaneRefreshes() {
    while (planeApplied < planeRequested) {
      var ticket = planeRequested;
      var offset = desiredRosterOffset;
      var results = await Promise.allSettled([
        request("/snapshot?limit=" + rosterLimit + "&offset=" + offset),
        requestAt("/api/v1/halt")
      ]);
      if (ticket !== planeRequested) { continue; }
      var halt = results[1].status === "fulfilled" ? results[1].value : null;
      var haltError = results[1].status === "rejected" ? results[1].reason : null;
      var refreshResult = {
        planeOk: false,
        halt: halt,
        haltComplete: haltPayloadComplete(halt),
        planeError: null,
        haltError: haltError
      };
      var planeError = null;
      if (results[0].status === "fulfilled") {
        try {
          var validated = validatePlaneSnapshot(results[0].value);
          applyStatus(validated.status, halt, haltError);
          applyRoster(validated.agents);
          refreshResult.planeOk = true;
        } catch (invalidSnapshotError) {
          planeError = invalidSnapshotError;
        }
      } else {
        planeError = results[0].reason;
      }
      if (planeError) {
        refreshResult.planeError = planeError;
        controlPlaneReady = false;
        haltAuthorityReady = haltPayloadComplete(halt);
        updateRuntimeControls();
        setMark("failed", "Unavailable");
        document.getElementById("acp-health-title").textContent =
          "Couldn't check your agents";
        document.getElementById("acp-health-detail").textContent = boundedError(planeError);
        renderRosterError(planeError);
      }
      planeLastResult = refreshResult;
      planeApplied = ticket;
    }
    return planeLastResult;
  }

  function refreshPlane(offset) {
    if (Number.isInteger(offset) && offset >= 0) { desiredRosterOffset = offset; }
    controlPlaneReady = false;
    haltAuthorityReady = false;
    updateRuntimeControls();
    setMark("partial", "Checking");
    document.getElementById("acp-health-title").textContent =
      "Checking your agents…";
    document.getElementById("acp-health-detail").textContent =
      "Actions are unavailable until Lightwork has confirmed the current state. Refresh the page to see the latest.";
    planeRequested += 1;
    if (!planeRefreshPromise) {
      planeRefreshPromise = drainPlaneRefreshes().finally(function () {
        planeRefreshPromise = null;
      });
    }
    return planeRefreshPromise;
  }

  function refreshStatus() {
    return refreshPlane(rosterOffset);
  }

  function refreshRoster(offset) {
    return refreshPlane(offset);
  }

  function refresh() {
    return refreshPlane(rosterOffset);
  }

  function haltMatches(payload, expectedActive) {
    if (!haltPayloadComplete(payload)) { return false; }
    if (!expectedActive) {
      return haltScope === "cluster"
        ? payload.active === false && payload.cluster_halt === false
        : payload.active === false;
    }
    if (haltScope === "cluster") {
      return payload.active === true && payload.cluster_halt === true;
    }
    return payload.active === true;
  }

  async function changeHalt(expectedActive, reason, ticket) {
    if (!haltAuthorityReady) {
      throw fail("Lightwork could not confirm the emergency stop's current state, so nothing was sent. Refresh and try again.");
    }
    var mutationError = null;
    try {
      await requestAt("/api/v1/halt", expectedActive
        ? { method: "POST", body: JSON.stringify({ reason: reason }) }
        : { method: "DELETE" });
    } catch (error) {
      mutationError = error;
    }

    var refreshed = await refreshStatus();
    var verified = refreshed.halt;
    if (!refreshed.haltComplete) {
      var combined = mutationError
        ? boundedError(mutationError) + " Lightwork also could not check whether the emergency stop is on. Refresh to check."
        : "Lightwork could not check whether the emergency stop is on. Refresh to check.";
      throw fail(combined);
    }
    if (mutationError) {
      show("The emergency stop change did not go through. " + boundedError(mutationError), {
        request_error: boundedError(mutationError),
        verified_state: verified
      }, ticket);
      return false;
    }
    if (!haltMatches(verified, expectedActive)) {
      show("The emergency stop change could not be confirmed everywhere. Refresh and check the state", verified, ticket);
      return false;
    }
    show(
      expectedActive ? "All agents are stopped. The emergency stop is confirmed" : "The emergency stop is off. Agents can work again",
      verified,
      ticket
    );
    return true;
  }

  document.getElementById("acp-refresh").addEventListener("click", function (event) {
    runGuarded(event.currentTarget, false, function () {
      return withBusy(event.currentTarget, refresh);
    }, false);
  });

  document.getElementById("acp-load-roster").addEventListener("click", function (event) {
    runGuarded(event.currentTarget, false, function () {
      return withBusy(event.currentTarget, function () { return refreshRoster(rosterOffset); });
    }, false);
  });

  rosterPrevious.addEventListener("click", function (event) {
    runGuarded(event.currentTarget, false, function () {
      var previousOffset = Math.max(0, rosterOffset - rosterLimit);
      return withBusy(event.currentTarget, function () { return refreshRoster(previousOffset); });
    }, false);
  });

  rosterNext.addEventListener("click", function (event) {
    runGuarded(event.currentTarget, false, function () {
      if (rosterNextOffset === null) { return null; }
      return withBusy(event.currentTarget, function () { return refreshRoster(rosterNextOffset); });
    }, false);
  });

  if (fleetForm && fleetReview && fleetApply) {
    ["input", "change"].forEach(function (eventName) {
      fleetForm.addEventListener(eventName, function () {
        if (fleetSelection) {
          invalidateFleetSelection("Fleet inputs changed; review a new exact selection.");
        }
      });
    });
    fleetReview.addEventListener("click", function (event) {
      var button = event.currentTarget;
      runGuarded(button, false, function (ticket) {
        return withBusy(button, function () { return reviewFleetSelection(ticket); });
      }, true);
    });
    fleetApply.addEventListener("click", function (event) {
      var button = event.currentTarget;
      runGuarded(button, true, function (ticket) {
        return withBusy(button, function () { return applyFleetAction(ticket); });
      }, true);
    });
  }

  document.getElementById("acp-verb-form").addEventListener("submit", function (event) {
    event.preventDefault();
    var formElement = event.currentTarget;
    var submitter = event.submitter;
    var form = new FormData(formElement);
    var verb = String(form.get("verb") || "");
    runGuarded(formElement, verb !== "ledger", async function (ticket) {
      var principal = checkPrincipal(form.get("principal"));
      var reason = String(form.get("reason") || "").trim();
      if (verb === "ledger") {
        if (!canAudit) { throw fail("You need auditor access to see history."); }
        return withBusy(submitter, function () { return ledger(principal, ticket); });
      }
      var canApplyVerb =
        ((verb === "suspend" || verb === "resume") && canOperate) ||
        ((verb === "contain" || verb === "release") && canAdmin);
      if (!canApplyVerb) {
        throw fail("Your role cannot use this action.");
      }
      if (verb === "suspend" || verb === "contain") {
        if (!reason) { throw fail("Give a reason to " + VERB_LABELS[verb].toLowerCase() + "."); }
        if (reason.length > 500) { throw fail("Keep the reason under 500 characters."); }
      }
      if (!(await confirmAction(
        VERB_LABELS[verb] + " " + nameOf(principal) + "?",
        VERB_LABELS[verb]
      ))) { return null; }
      return withBusy(submitter, function () {
        return mutatePrincipal(verb, principal,
          verb === "suspend" || verb === "contain" ? reason : undefined,
          ticket);
      });
    }, true);
  });

  verbSelect.addEventListener("change", updateVerbSubmit);

  document.getElementById("acp-attenuate-form").addEventListener("submit", function (event) {
    event.preventDefault();
    var formElement = event.currentTarget;
    var submitter = event.submitter;
    var form = new FormData(formElement);
    runGuarded(formElement, true, async function (ticket) {
      if (!canOperate) { throw fail("Your role cannot limit agents. Ask an operator or administrator."); }
      var principal = checkPrincipal(form.get("principal"));
      var body = { deny_tools: [] };
      if (denyTools) {
        Array.prototype.forEach.call(
          denyTools.querySelectorAll("input[type=checkbox]:checked"),
          function (box) { body.deny_tools.push(box.value); }
        );
      } else {
        String(form.get("deny_tools") || "").split(",").forEach(function (tool) {
          var name = tool.trim();
          if (name) { body.deny_tools.push(name); }
        });
      }
      if (body.deny_tools.length > 64) {
        throw fail("Block at most 64 tools at a time.");
      }
      if (body.deny_tools.some(function (name) { return !toolPattern.test(name); })) {
        throw fail("One of the chosen tools could not be used. Reload the list and choose again.");
      }
      var risk = String(form.get("max_risk") || "");
      if (risk) {
        if (!["low", "medium", "high"].includes(risk)) {
          throw fail("Choose Low, Medium or High for the risk limit.");
        }
        body.max_risk = risk;
      }
      var dollars = String(form.get("max_dollars") || "").trim();
      if (dollars) {
        body.max_dollars = Number(dollars);
        if (!Number.isFinite(body.max_dollars) || body.max_dollars <= 0 ||
            body.max_dollars > 1000000) {
          throw fail("Enter a spending limit between $0.01 and $1,000,000.");
        }
      }
      var wall = String(form.get("max_wall_seconds") || "").trim();
      if (wall) {
        body.max_wall_seconds = Number(wall);
        if (!Number.isFinite(body.max_wall_seconds) || body.max_wall_seconds <= 0 ||
            body.max_wall_seconds > 31536000) {
          throw fail("Choose a time limit from the list.");
        }
      }
      if (!body.deny_tools.length && body.max_risk === undefined &&
          body.max_dollars === undefined && body.max_wall_seconds === undefined) {
        throw fail("Choose at least one limit to apply.");
      }
      if (!(await confirmAction(
        "Apply these limits to " + nameOf(principal) + "? Limits can only be tightened here, never loosened.",
        "Apply limits"
      ))) { return null; }
      return withBusy(submitter, async function () {
        if (!controlPlaneReady) {
          throw fail("Lightwork has not confirmed the current state of your agents yet, so nothing was sent. Refresh and try again.");
        }
        var result = null;
        var requestError = null;
        try {
          body.principal = principal;
          result = await request("/principals/attenuate", {
            method: "POST", body: JSON.stringify(body)
          });
        } catch (error) {
          requestError = error;
        }
        var refreshed = await refresh();
        if (requestError) {
          showError(requestError, refreshed.planeOk
            ? "The limits did not go through. The list has been refreshed"
            : "The limits did not go through, and the list could not be refreshed", ticket);
          return null;
        }
        show((result.ok ? "Done: limits applied to " : "Not done: limits for ") + nameOf(principal) +
          (refreshed.planeOk ? "" : ". The list could not be refreshed, so check it before relying on this"), result, ticket);
        return result;
      });
    }, true);
  });

  document.getElementById("acp-halt-form").addEventListener("submit", function (event) {
    event.preventDefault();
    var formElement = event.currentTarget;
    var submitter = event.submitter;
    var form = new FormData(formElement);
    runGuarded(formElement, true, async function (ticket) {
      if (!canHalt) { throw fail("Your role cannot use the emergency stop."); }
      var reason = String(form.get("reason") || "").trim();
      if (!reason) { throw fail("Give a reason for stopping all agents."); }
      if (reason.length > 200) { throw fail("Keep the reason under 200 characters."); }
      if (!(await confirmAction(
        (haltScope === "cluster" ? "Stop every agent on every Lightwork server now?"
          : "Stop every agent on this Lightwork server now?") +
          " Work in progress stops before its next step.",
        "Stop all agents"
      ))) { return null; }
      return withBusy(submitter, function () { return changeHalt(true, reason, ticket); });
    }, true);
  });

  document.getElementById("acp-clear-halt").addEventListener("click", function (event) {
    var button = event.currentTarget;
    runGuarded(button, true, async function (ticket) {
      if (!canHalt) { throw fail("Your role cannot use the emergency stop."); }
      if (!(await confirmAction(
        "Turn off the emergency stop? Agents can start working again straight away.",
        "Resume all work"
      ))) { return null; }
      return withBusy(button, function () { return changeHalt(false, undefined, ticket); });
    }, true);
  });

  refresh().catch(function (error) {
    controlPlaneReady = false;
    haltAuthorityReady = false;
    updateRuntimeControls();
    setMark("failed", "Unavailable");
    document.getElementById("acp-health-title").textContent =
      "Couldn't check your agents";
    document.getElementById("acp-health-detail").textContent = boundedError(error);
  });
})();
