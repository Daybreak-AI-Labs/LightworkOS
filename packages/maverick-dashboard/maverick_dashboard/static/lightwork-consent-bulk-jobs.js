"use strict";

(function (global) {
  var MAX_RESPONSE_BYTES = 64 * 1024;
  var MAX_JSON_INPUT_BYTES = 240 * 1024;
  var MAX_UI_ITEMS = 500;
  var ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
  var IDEMPOTENCY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{7,191}$/;
  var DIGEST_PATTERN = /^[0-9a-f]{64}$/;
  var STATES = new Set(["queued", "running", "succeeded", "failed", "cancelled"]);
  var ACTIONS = new Set(["grant", "deny", "revoke", "withdraw"]);
  var SOURCES = new Set(["client", "edge", "operator", "sdk", "header"]);
  var OPERATIONS = new Set([
    "edit_preferences", "delete_subject", "change_identifier_type",
    "reactivate", "clear_expiration"
  ]);

  function failure(message, code, status) {
    var error = new Error(message);
    error.code = code;
    error.status = status || 0;
    return error;
  }

  async function readBoundedJson(response) {
    var declared = response.headers.get("Content-Length");
    if (declared !== null && Number(declared) > MAX_RESPONSE_BYTES) {
      if (response.body && typeof response.body.cancel === "function") {
        await response.body.cancel();
      }
      throw failure("Server response exceeded the 64 KiB safety limit.", "response_too_large", response.status);
    }
    if (!response.body || typeof response.body.getReader !== "function") {
      throw failure("The reply could not be read. Refresh the page and try again.", "response_stream_unavailable", response.status);
    }
    var reader = response.body.getReader();
    var chunks = [];
    var total = 0;
    while (true) {
      var part = await reader.read();
      if (part.done) { break; }
      total += part.value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw failure("Server response exceeded the 64 KiB safety limit.", "response_too_large", response.status);
      }
      chunks.push(part.value);
    }
    var bytes = new Uint8Array(total);
    var offset = 0;
    chunks.forEach(function (chunk) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    });
    var responseText = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    try {
      return JSON.parse(responseText);
    } catch (_error) {
      throw failure("The reply from the server could not be read. Try again.", "response_invalid_json", response.status);
    }
  }

  async function parseResponse(response) {
    var payload = await readBoundedJson(response);
    if (!response.ok) {
      var detail = payload && typeof payload.detail === "string"
        ? payload.detail.slice(0, 500)
        : "The bulk request didn't work. Refresh the page and try again.";
      if (response.status === 422 && payload && Array.isArray(payload.detail)) {
        var invalidField = payload.detail.find(function (issue) {
          return issue && Array.isArray(issue.loc) && issue.loc[0] === "body" &&
            issue.loc[1] === "items" && Number.isInteger(issue.loc[2]) &&
            (issue.loc[3] === "receipt_limit" || issue.loc[3] === "after_sequence");
        });
        if (invalidField) {
          detail = invalidField.loc[3] === "receipt_limit"
            ? "Choose between 1 and 500 records per person."
            : "Starting from a saved position is not available. Choose up to the latest 500 records per person.";
        }
      }
      throw failure(detail, "request_failed", response.status);
    }
    return payload;
  }

  function identifier(value, label) {
    var selected = String(value || "").trim();
    if (!ID_PATTERN.test(selected)) {
      throw failure(label + " must be a valid opaque reference.", "invalid_input");
    }
    return selected;
  }

  function idempotencyKey(value) {
    var selected = String(value || "").trim();
    if (!IDEMPOTENCY_PATTERN.test(selected)) {
      throw failure("The request reference must contain 8 to 192 letters, numbers, or supported separators.", "invalid_input");
    }
    return selected;
  }

  function integer(value, label, minimum, maximum) {
    var selected = Number(value);
    if (!Number.isInteger(selected) || selected < minimum || selected > maximum) {
      throw failure(label + " must be an integer from " + minimum + " to " + maximum + ".", "invalid_input");
    }
    return selected;
  }

  function positiveNumber(value, label, allowNull) {
    if (allowNull && (value === null || value === undefined || value === "")) { return null; }
    var selected = Number(value);
    if (!Number.isFinite(selected) || selected <= 0) {
      throw failure(label + " must be a positive timestamp.", "invalid_input");
    }
    return selected;
  }

  function optionalTimestamp(value, label) {
    if (value === null || value === undefined || String(value).trim() === "") { return null; }
    if (typeof value === "number") { return positiveNumber(value, label, false); }
    var parsed = Date.parse(String(value));
    if (!Number.isFinite(parsed) || parsed <= 0) {
      throw failure(label + " is invalid.", "invalid_input");
    }
    return parsed / 1000;
  }

  function objectValue(value, label) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw failure(label + " must be an object.", "invalid_input");
    }
    return value;
  }

  function exactShape(value, required, optional, label) {
    var selected = objectValue(value, label);
    var allowed = new Set(required.concat(optional));
    Object.keys(selected).forEach(function (key) {
      if (!allowed.has(key)) {
        throw failure(label + " contains unsupported field " + key + ".", "invalid_input");
      }
    });
    required.forEach(function (key) {
      if (!Object.prototype.hasOwnProperty.call(selected, key) || selected[key] === null) {
        throw failure(label + " is missing " + key + ".", "invalid_input");
      }
    });
    return selected;
  }

  function contextValue(value) {
    var selected = exactShape(
      value,
      ["jurisdiction", "country_code"],
      ["region_code", "collection_point", "asserted_source"],
      "Context"
    );
    var country = String(selected.country_code || "");
    var region = String(selected.region_code || "");
    var source = String(selected.asserted_source || "operator");
    if (!/^[A-Z]{2}$/.test(country) || !/^(?:[A-Z0-9]{1,8}(?:-[A-Z0-9]{1,8}){0,2})?$/.test(region)) {
      throw failure("That country or region code is not recognized. Use a two-letter code such as US or FR.", "invalid_input");
    }
    if (!SOURCES.has(source)) { throw failure("That source is not one of the choices. Choose a source from the list.", "invalid_input"); }
    return {
      jurisdiction: identifier(selected.jurisdiction, "Jurisdiction"),
      country_code: country,
      region_code: region,
      collection_point: identifier(selected.collection_point || "web", "Collection point"),
      asserted_source: source
    };
  }

  function choicesValue(value) {
    if (!Array.isArray(value) || value.length < 1 || value.length > 128) {
      throw failure("Choices must contain 1-128 entries.", "invalid_input");
    }
    return value.map(function (raw, index) {
      var item = exactShape(
        raw,
        ["purpose_id", "action"],
        ["channel", "vendor_id", "expires_at"],
        "Choice " + (index + 1)
      );
      if (!ACTIONS.has(item.action)) { throw failure("That choice was not recognized. Refresh the page and try again.", "invalid_input"); }
      return {
        purpose_id: identifier(item.purpose_id, "Purpose ID"),
        action: item.action,
        channel: identifier(item.channel || "all", "Channel"),
        vendor_id: identifier(item.vendor_id || "all", "Vendor ID"),
        expires_at: positiveNumber(item.expires_at, "Choice expiration", true)
      };
    });
  }

  function parseItems(source, operation) {
    var raw = String(source || "");
    if (new TextEncoder().encode(raw).byteLength > MAX_JSON_INPUT_BYTES) {
      throw failure("This job contains too much detail for one submission. Choose fewer records or choices.", "invalid_input");
    }
    var parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (_error) {
      throw failure("The selected changes could not be prepared. Reload them and review again.", "invalid_input");
    }
    if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > MAX_UI_ITEMS) {
      throw failure("Choose between 1 and 500 records for this job.", "invalid_input");
    }
    var seen = new Set();
    return parsed.map(function (rawItem, index) {
      var label = "Item " + (index + 1);
      var item;
      var normalized;
      if (operation === "export_receipts") {
        if (rawItem && Object.prototype.hasOwnProperty.call(rawItem, "after_sequence")) {
          throw failure("Starting from a saved position is not available. Choose up to the latest 500 records per person.", "invalid_input");
        }
        item = exactShape(rawItem, ["item_id", "profile_id"], ["receipt_limit"], label);
        normalized = {
          item_id: identifier(item.item_id, "Item ID"),
          profile_id: identifier(item.profile_id, "Profile ID")
        };
        if (Object.prototype.hasOwnProperty.call(item, "receipt_limit")) {
          normalized.receipt_limit = integer(item.receipt_limit, "Receipt limit", 1, 500);
        }
      } else if (operation === "edit_preferences") {
        item = exactShape(
          rawItem,
          ["item_id", "profile_id", "expected_revision", "policy_id", "policy_version", "context", "choices"],
          ["retention_until"],
          label
        );
        normalized = {
          item_id: identifier(item.item_id, "Item ID"),
          profile_id: identifier(item.profile_id, "Profile ID"),
          expected_revision: integer(item.expected_revision, "Expected revision", 0, 2147483647),
          policy_id: identifier(item.policy_id, "Policy ID"),
          policy_version: integer(item.policy_version, "Policy version", 1, 2147483647),
          context: contextValue(item.context),
          choices: choicesValue(item.choices)
        };
        if (Object.prototype.hasOwnProperty.call(item, "retention_until")) {
          normalized.retention_until = positiveNumber(item.retention_until, "Retention timestamp", true);
        }
      } else if (operation === "reactivate") {
        item = exactShape(
          rawItem,
          ["item_id", "profile_id", "expected_revision", "receipt_id", "reactivation_at"],
          [],
          label
        );
        normalized = {
          item_id: identifier(item.item_id, "Item ID"),
          profile_id: identifier(item.profile_id, "Profile ID"),
          expected_revision: integer(item.expected_revision, "Expected revision", 0, 2147483647),
          receipt_id: identifier(item.receipt_id, "Receipt ID"),
          reactivation_at: positiveNumber(item.reactivation_at, "Reactivation timestamp", false)
        };
      } else if (operation === "delete_subject") {
        item = exactShape(rawItem, ["item_id", "profile_id", "expected_revision", "reason_code"], [], label);
        normalized = {
          item_id: identifier(item.item_id, "Item ID"),
          profile_id: identifier(item.profile_id, "Profile ID"),
          expected_revision: integer(item.expected_revision, "Expected revision", 0, 2147483647),
          reason_code: identifier(item.reason_code, "Reason code")
        };
      } else if (operation === "change_identifier_type") {
        item = exactShape(rawItem, ["item_id", "profile_id", "expected_revision", "identity_kind", "subject_sha256"], [], label);
        if (item.identity_kind !== "known" && item.identity_kind !== "anonymous") {
          throw failure("That identity type is not one of the choices. Choose an identity type from the list.", "invalid_input");
        }
        if (!DIGEST_PATTERN.test(String(item.subject_sha256 || ""))) {
          throw failure("Subject digest must be lowercase SHA-256.", "invalid_input");
        }
        normalized = {
          item_id: identifier(item.item_id, "Item ID"),
          profile_id: identifier(item.profile_id, "Profile ID"),
          expected_revision: integer(item.expected_revision, "Expected revision", 0, 2147483647),
          identity_kind: item.identity_kind,
          subject_sha256: item.subject_sha256
        };
      } else if (operation === "clear_expiration") {
        item = exactShape(rawItem, ["item_id", "profile_id", "expected_revision", "receipt_id"], [], label);
        normalized = {
          item_id: identifier(item.item_id, "Item ID"),
          profile_id: identifier(item.profile_id, "Profile ID"),
          expected_revision: integer(item.expected_revision, "Expected revision", 0, 2147483647),
          receipt_id: identifier(item.receipt_id, "Receipt ID")
        };
      } else {
        throw failure("Operation is unsupported.", "invalid_input");
      }
      if (seen.has(normalized.item_id)) { throw failure("Item IDs must be unique.", "invalid_input"); }
      seen.add(normalized.item_id);
      return normalized;
    });
  }

  function buildExportPayload(values) {
    var payload = {
      items: parseItems(values.items_json, "export_receipts"),
      idempotency_key: idempotencyKey(values.idempotency_key)
    };
    var scheduled = optionalTimestamp(values.scheduled_for, "Schedule");
    if (scheduled !== null) { payload.scheduled_for = scheduled; }
    return payload;
  }

  function buildActionPayload(values) {
    var operation = String(values.operation || "");
    if (!OPERATIONS.has(operation)) { throw failure("Operation is unsupported.", "invalid_input"); }
    var payload = {
      operation: operation,
      items: parseItems(values.items_json, operation),
      idempotency_key: idempotencyKey(values.idempotency_key)
    };
    var scheduled = optionalTimestamp(values.scheduled_for, "Schedule");
    if (scheduled !== null) { payload.scheduled_for = scheduled; }
    return payload;
  }

  global.LightworkConsentBulkJobsClient = {
    MAX_RESPONSE_BYTES: MAX_RESPONSE_BYTES,
    MAX_JSON_INPUT_BYTES: MAX_JSON_INPUT_BYTES,
    readBoundedJson: readBoundedJson,
    parseResponse: parseResponse,
    parseItems: parseItems,
    buildExportPayload: buildExportPayload,
    buildActionPayload: buildActionPayload,
    identifier: identifier,
    idempotencyKey: idempotencyKey
  };

  if (typeof document === "undefined") { return; }

  document.addEventListener("DOMContentLoaded", function () {
    var shell = document.getElementById("consent-bulk-jobs-shell");
    var CW = global.LightworkConsentWorkbench;
    if (!shell || !CW) { return; }
    if (shell.dataset.initialized === "true") return;
    shell.dataset.initialized = "true";
    var $ = function (id) { return document.getElementById(id); };
    var apiBase = shell.dataset.apiBase;
    var consentBase = "/api/v1/consent";
    var canAudit = shell.dataset.canAudit === "true";
    var canAdmin = shell.dataset.canAdmin === "true";
    var operations = $("cbj-operations");
    var readinessDetail = $("cbj-readiness-detail");
    var status = $("cbj-operation-status");
    var form = $("cbj-create");
    var state = { status: null, jobs: [], credit: null, profiles: [], profileCache: new Map(), chosen: new Set(), policies: [], identifiers: [], receipts: [],
      peoplePages: [null], peoplePage: 0, nextPeople: null, chosenReceipts: new Set(), receiptPeopleKey: "", nextReceipt: null };
    var peopleGeneration = 0, selectionGeneration = 0, receiptsGeneration = 0, peopleSearchTimer = null, privatePeopleCleared = false;
    var selectedJobId = null, detailGeneration = 0, hostedCreate = null;
    function selectJob(job) {
      var id = job ? job.job_id : null;
      if (id === selectedJobId) return;
      selectedJobId = id;
      document.dispatchEvent(new CustomEvent('lightwork:copilot-selection', {detail:{selection:
        id ? {kind:'consent_bulk_job', id:id} : null}}));
    }
    var WHAT = {
      export_receipts: "Export consent records", edit_preferences: "Change choices", delete_subject: "Erase stored identifiers",
      change_identifier_type: "Change how people are identified", reactivate: "Bring back earlier choices", clear_expiration: "Remove end dates"
    };
    var STATE_LABELS = { queued: ["Waiting", "warn"], running: ["Running", "info"], succeeded: ["Finished", "ok"], failed: ["Failed", "danger"], cancelled: ["Cancelled", "idle"] };

    // Requests go through the bounded client above; a refusal keeps only its
    // status so the person sees a plain sentence from mvErrorText.
    async function request(base, path, options) {
      var selected = options || {};
      var headers = { Accept: "application/json" };
      if ((base === consentBase || base === apiBase) && shell.dataset.requestContext) headers['X-Lightwork-Profile-Context'] = shell.dataset.requestContext;
      var body;
      if (Object.prototype.hasOwnProperty.call(selected, "body")) {
        headers["Content-Type"] = "application/json";
        body = JSON.stringify(selected.body);
      }
      var controller = new AbortController(), timeout = setTimeout(function () { controller.abort(); }, 30000);
      try {
        var response = await fetch(base + path, {
          method: selected.method || "GET", headers: headers, body: body, signal: controller.signal,
          credentials: "same-origin", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer"
        });
        var returnedContext = response.headers.get('X-Lightwork-Profile-Context');
        if (returnedContext && shell.dataset.requestContext && returnedContext !== shell.dataset.requestContext)
          throw failure('Your account or workspace changed. Reload this page before choosing people.', 'context_changed', 409);
        var result = await parseResponse(response);
        if (selected.profileContext && shell.dataset.requestContext &&
            (response.headers.get("X-Lightwork-Profile-Context") || result.context) !== shell.dataset.requestContext)
          throw failure("Your account or workspace changed. Reload the page before choosing people.", "context_changed", 409);
        return result;
      } finally { clearTimeout(timeout); }
    }
    async function api(path, options) {
      try { return await request(apiBase, path, options); }
      catch (error) {
        if (error.code === 'context_changed' || error.status === 401 || error.status === 403) {
          clearPrivatePeople(); error.plain = 'Your account, workspace or access changed. Reload the page before continuing.';
        } else if (['A selected person\'s record changed. Review the selection again before submitting.',
            'The selected policy is no longer current. Review the policy and choices again.',
            'A selected choice is no longer available for this person. Choose it again before reviewing.'].indexOf(error.message) >= 0) error.plain = error.message;
        throw error;
      }
    }
    function say(text, isError) { CW.say(status, privatePeopleCleared ? "Your account, workspace or access changed. Reload the page before continuing." : text, privatePeopleCleared || isError); }
    function fail(error, action) {
      if (privatePeopleCleared) { var changed="Your account, workspace or access changed. Reload the page before continuing.";say(changed,true);return changed; }
      if (error && typeof error.plain === "string") { say(error.plain, true); return error.plain; }
      return CW.fail(status, error, action);
    }
    var pendingSubmission = null;
    var recoveryKey = shell.dataset.requestContext ? 'lightwork:consent-submission:' + shell.dataset.requestContext : '';
    try {
      var savedReference = recoveryKey && global.sessionStorage.getItem(recoveryKey);
      if (savedReference && IDEMPOTENCY_PATTERN.test(savedReference)) pendingSubmission = savedReference;
    } catch (_) { /* Keep this tab's reference when browser storage is unavailable. */ }
    function rememberSubmission(reference) {
      pendingSubmission = reference;
      try { if (recoveryKey) { if (reference) global.sessionStorage.setItem(recoveryKey, reference); else global.sessionStorage.removeItem(recoveryKey); } }
      catch (_) { say('Keep this tab open until the submitted job is confirmed.', true); }
      $('cbj-submission-recovery').hidden = !reference;
    }
    rememberSubmission(pendingSubmission);
    async function checkSubmission() {
      if (!pendingSubmission) return;
      var result = await api('/requests/check', {method: 'POST', body: {idempotency_key: pendingSubmission}});
      if (!result.found || !result.job) {
        $('cbj-submission-note').textContent = 'No saved submission has been found yet. The original request may still be finishing. Check again; this check starts no work.';
        return false;
      }
      var job = result.job, inCopilot = !!hostedCreate;
      rememberSubmission(null); clearReview(); form.hidden = true;
      say(job.retained === false ? 'The original job was accepted, but its keeping period has ended. No job was repeated.'
        : 'Your original job is ' + (STATE_LABELS[job.state] || ['recorded'])[0].toLowerCase() + '. No job was repeated.');
      await Promise.all([refreshJobs(), refreshCredit()]);
      if (inCopilot) finishCreate("submitted", job);
      else if (job.retained !== false) await showDetail(job);
      return true;
    }
    $('cbj-check-submission').addEventListener('click', function (event) {
      handle(event.currentTarget, function (disableControls) { disableControls(); return checkSubmission(); });
    });
    // One change at a time. The clicked control stays enabled (and focused)
    // until the shared confirmation captures it; a handler disables it only
    // after the person confirms, by calling disableControls().
    var operationInFlight = false;
    function handle(button, work) {
      if (operationInFlight) {
        say("Another operation is already running. Wait for it to finish.", true);
        return Promise.resolve();
      }
      operationInFlight = true;
      shell.dataset.operationInFlight = "true";
      var wasDisabled = button ? button.disabled : false, controlsDisabled = false;
      function disableControls() { if (button && !controlsDisabled) { button.disabled = true; controlsDisabled = true; } }
      return Promise.resolve().then(function () {
        return work(disableControls);
      }).catch(function (error) { fail(error, "finish the change"); }).finally(function () {
        if (controlsDisabled) button.disabled = wasDisabled;
        operationInFlight = false;
        delete shell.dataset.operationInFlight;
      });
    }
    document.querySelectorAll("[data-cbj-close]").forEach(function (b) { b.addEventListener("click", function () {
      $(b.dataset.cbjClose).hidden = true;
      if (b.dataset.cbjClose === 'cbj-detail') { detailGeneration += 1; selectJob(null); }
      if (b.dataset.cbjClose === 'cbj-create') finishCreate(pendingSubmission ? 'unconfirmed' : 'cancelled');
    }); });

    async function refreshStatus() {
      operations.disabled = true;
      if (!canAudit) {
        CW.say(readinessDetail, "You need audit access to use bulk changes.", true);
        return false;
      }
      try {
        var result = await api("/status");
        state.status = result;
        var ready = result && result.ready === true;
        operations.disabled = !ready;
        if (!ready) {
          CW.say(readinessDetail, result && result.enabled === false ? "Bulk changes are turned off for this workspace." : "Bulk changes are not ready yet. An administrator needs to finish setting them up.", true);
          return false;
        }
        var ops = result.operations || {};
        var missing = Object.keys(WHAT).filter(function (k) { return ops[k] !== true; });
        CW.say(readinessDetail, missing.length ? "Some kinds of change are not set up yet: " + missing.map(function (k) { return WHAT[k].toLowerCase(); }).join(", ") + "." : "");
        form.querySelectorAll("input[name=operation]").forEach(function (radio) {
          radio.disabled = !canAdmin || ops[radio.value] !== true;
        });
        return true;
      } catch (error) {
        CW.fail(readinessDetail, error, "check whether bulk changes are available");
        return false;
      }
    }

    function progressText(job) {
      var text = job.processed_items + " of " + job.total_items + " done";
      if (job.failed_items) text += ", " + job.failed_items + " could not be changed";
      return text;
    }
    var jobsNext = null, jobsLoading = 0;
    async function refreshJobs(before) {
      before = typeof before === 'string' ? before : null;
      var generation = ++jobsLoading, older = $('cbj-jobs-older'), latest = $('cbj-jobs-latest');
      var filter = $("cbj-state-filter").value;
      if (older) older.disabled = true;
      if (latest) latest.disabled = true;
      try {
        var result = await api("?limit=50" + (filter ? "&state=" + encodeURIComponent(filter) : "") +
          (before ? '&before_job_id=' + encodeURIComponent(before) : ''));
        if (generation !== jobsLoading) return;
        state.jobs = result.jobs || [];
        jobsNext = result.next_before_job_id || null;
        if (older) older.hidden = !jobsNext;
        if ($('cbj-jobs-page')) $('cbj-jobs-page').textContent = before ? 'Older jobs. Select Latest jobs to return to new work.' : 'Latest jobs.';
        CW.table($("cbj-job-list"), state.jobs, {
          label: "Bulk change", name: function (j) { return WHAT[j.operation] || CW.human(j.operation); },
          columns: [
            { label: "What", value: function (j) { return WHAT[j.operation] || CW.human(j.operation); } },
            { label: "People", value: function (j) { return String(j.total_items); } },
            { label: "Progress", value: progressText },
            { label: "Starts", value: function (j) { return j.scheduled_for ? CW.when(j.scheduled_for) : "As soon as possible"; } },
            { label: "Status", value: function (j) { var m = STATE_LABELS[j.state] || [CW.human(j.state), "idle"]; return CW.badge(j.cancel_requested && j.state !== "cancelled" ? "Cancelling" : m[0], m[1]); } }
          ],
          actions: [
            { label: "Details", run: function (j, b) { CW.busy(b, function () { return showDetail(j); }); } },
            { label: "Ask Copilot", run: function (j, b) { CW.busy(b, async function () {
              await showDetail(j);
              var panel = $('mv-copilot'), launch = $('mv-copilot-fab');
              if (selectedJobId === j.job_id && panel && panel.hidden && launch) launch.click();
            }); } },
            { label: "Download", when: function (j) { return j.operation === "export_receipts" && j.state === "succeeded"; }, run: function (j) { global.location.assign(apiBase + "/" + encodeURIComponent(j.job_id) + "/download"); } },
            { label: "Run now", kind: "primary", when: function (j) { return canAdmin && (j.state === "queued" || j.state === "running"); }, run: function (j, b) { handle(b, function (disableControls) { return runJob(j, disableControls); }); } },
            { label: "Run one part", when: function (j) { return canAdmin && (j.state === 'queued' || j.state === 'running') && !j.cancel_requested; }, run: function (j, b) { handle(b, function (disableControls) { return runPart(j, disableControls); }); } },
            { label: "Cancel", kind: "danger", when: function (j) { return canAdmin && (j.state === "queued" || j.state === "running") && !j.cancel_requested; }, run: function (j, b) { handle(b, function (disableControls) { return cancelJob(j, disableControls); }); } }
          ],
          empty: { title: "No bulk changes yet.", body: "Start a bulk change to export or change many people’s consent records at once.", action: canAdmin ? { label: "Start a bulk change", run: openCreate } : null }
        });
      } catch (error) {
        if (generation !== jobsLoading) return;
        fail(error, 'load the bulk changes');
      } finally {
        if (generation === jobsLoading) {
          if (older) older.disabled = false;
          if (latest) latest.disabled = false;
        }
      }
    }

    async function showDetail(job, focus) {
      var generation = ++detailGeneration;
      var body = $("cbj-detail-body");
      $("cbj-detail-title").textContent = WHAT[job.operation] || "Bulk change details";
      body.replaceChildren(CW.el("p", "muted", "Loading…"));
      $("cbj-detail").hidden = false;
      try {
        var current = await api('/' + encodeURIComponent(job.job_id));
        var history = await api("/" + encodeURIComponent(job.job_id) + "/history?limit=50");
        if (generation !== detailGeneration) return;
        job = current; selectJob(job);
        body.replaceChildren();
        CW.facts(body, [
          ["Status", (STATE_LABELS[job.state] || [CW.human(job.state)])[0]],
          ["Progress", progressText(job)],
          ["Created", CW.when(job.created_at)],
          ["Starts", job.scheduled_for ? CW.when(job.scheduled_for) : "As soon as possible"]
        ]);
        var list = CW.el("ul");
        var eventLabels = {'job.created': 'Job queued', 'job.leased': 'Processing started',
          'job.cancel_requested': 'Cancellation requested', 'job.cancelled': 'Job cancelled',
          'job.recovered': 'Job is ready to resume', 'job.succeeded': 'Job finished',
          'job.failed': 'Job finished with records needing review', 'item.succeeded': 'Record processed'};
        var reasons = {conflict: 'The record changed or an earlier selected change was not confirmed. Review the current record before starting a new job.',
          not_found: 'The selected record is no longer available.', invalid_item: 'The selected change is no longer valid.',
          authority_unavailable: 'The change could not be safely confirmed.', quota_exceeded: 'The available allowance was exceeded.',
          worker_failure: 'Processing could not confirm this change. Review its history before trying again.'};
        function renderHistory(value) {
          list.replaceChildren();
          (value.events || []).forEach(function (event) {
          var text = eventLabels[event.event_type] || 'Job activity recorded';
          if (event.event_type === 'item.failed') {
            var detail = event.payload || {};
            text = 'Record ' + (Number(detail.ordinal) + 1) + ' needs review. ' + (reasons[detail.error_code] || reasons.authority_unavailable);
          }
          list.appendChild(CW.el('li', '', CW.when(event.created_at) + ' – ' + text));
          });
        }
        renderHistory(history);
        body.appendChild(CW.el("h4", "", "History"));
        body.appendChild(list);
        var actions = CW.el('div', 'cw-actions'), older = CW.el('button', 'btn', 'Older activity'), latest = CW.el('button', 'btn btn--ghost', 'Latest activity');
        older.type = latest.type = 'button'; older.hidden = !history.next_before_sequence;
        actions.appendChild(older); actions.appendChild(latest); body.appendChild(actions);
        async function loadHistory(before) {
          older.disabled = latest.disabled = true;
          try {
            var value = await api('/' + encodeURIComponent(job.job_id) + '/history?limit=50' +
              (before ? '&before_sequence=' + before : ''));
            if (!body.contains(list)) return;
            renderHistory(value); history = value; older.hidden = !history.next_before_sequence;
          } catch (error) { fail(error, 'load the older job history'); }
          finally { older.disabled = latest.disabled = false; }
        }
        older.addEventListener('click', function () { loadHistory(history.next_before_sequence); });
        latest.addEventListener('click', function () { loadHistory(null); });
        if (focus !== false) CW.open($("cbj-detail"), null);
      } catch (error) {
        if (generation !== detailGeneration) return;
        selectJob(null); body.replaceChildren(CW.el("p", "danger-text", CW.errorText(error, "load the bulk change details")));
      }
    }
    async function runPart(job, disableControls) {
      if (!(await CW.confirm('Run one part of this reviewed bulk change? It may change or erase consent information. Remaining parts do not start automatically, and completed changes stay applied.', 'Run one part'))) return;
      disableControls();
      try {
        var result = await api('/' + encodeURIComponent(job.job_id) + '/run', {method:'POST', body:{expected_revision:job.revision}});
        say(result.state === 'succeeded' || result.state === 'failed' ? 'The job finished. ' + progressText(result) + '.'
          : 'One part finished. ' + progressText(result) + '. Review the job before continuing.');
      } catch (error) {
        try {
          var current = await api('/' + encodeURIComponent(job.job_id));
          say('No additional part was started. Saved progress: ' + progressText(current) + '. Review the job before continuing.', true);
        } catch (_) { fail(error, 'check the saved job progress'); }
      } finally { await Promise.all([refreshJobs(), refreshCredit()]); }
    }
    async function runJob(job, disableControls) {
      if (!(await CW.confirm("Run this reviewed bulk change to completion? It may change or delete people’s consent records. Keep this page open. You can pause before the next part; completed changes stay applied.", "Run now"))) return;
      disableControls();
      var paused = false, current = job, panel = CW.el('section', 'panel');
      panel.appendChild(CW.el('h3', '', 'Processing your reviewed job'));
      var progress = CW.el('p', '', progressText(job)), pause = CW.el('button', 'btn', 'Pause after this part');
      progress.setAttribute('role', 'status'); progress.setAttribute('aria-live', 'polite');
      pause.type = 'button'; pause.addEventListener('click', function () {
        paused = true; pause.disabled = true; pause.textContent = 'Pausing after this part…';
      });
      panel.appendChild(progress); panel.appendChild(pause); $('cbj-job-list').before(panel);
      try {
        for (var part = 0; part < MAX_UI_ITEMS && !paused; part++) {
          var before = current.processed_items;
          var next = await api('/' + encodeURIComponent(job.job_id) + '/run', {method: 'POST', body: {}});
          if (!next || next.job_id !== job.job_id || next.total_items !== job.total_items ||
              !Number.isInteger(next.processed_items) || next.processed_items < current.processed_items ||
              next.processed_items > next.total_items || !STATES.has(next.state))
            throw failure('The saved job progress could not be confirmed. Check its details before continuing.', 'invalid_progress');
          progress.textContent = progressText(next); current = next;
          if (next.state === 'succeeded' || next.state === 'failed' || next.state === 'cancelled') break;
          if (next.processed_items === before)
            throw failure('This part made no confirmed progress. Check the job details before continuing.', 'no_progress');
        }
        say(current.state === 'succeeded' ? 'The job finished.' : current.state === 'failed'
          ? 'The job finished with ' + current.failed_items + ' records needing review. Check its details.'
          : current.state === 'cancelled' ? 'The job was cancelled. Completed changes stay applied.'
          : 'Processing paused. ' + progressText(current) + ' Use Run now to continue. Completed changes stay applied.');
      } catch (error) {
        // A lost response stops continuation. Read saved status; never resend
        // an uncertain part automatically, even though native effects replay.
        try {
          current = await api('/' + encodeURIComponent(job.job_id));
          say('Processing stopped before the next part. Saved progress: ' + progressText(current) + ' Check the job details before continuing.', true);
        } catch (_) { fail(error, 'confirm the job progress'); }
      } finally {
        panel.remove(); await Promise.all([refreshJobs(), refreshCredit()]);
      }
    }
    async function cancelJob(job, disableControls) {
      if (!(await CW.confirm("Cancel this bulk change? Changes already made are not undone.", "Cancel bulk change"))) return;
      disableControls();
      try {
        await api("/" + encodeURIComponent(job.job_id) + "/cancel", { method: "POST", body: { expected_revision: job.revision, idempotency_key: CW.reference() } });
        say("Cancellation recorded. Completed changes stay applied.");
      } catch (error) {
        try {
          var current = await api('/' + encodeURIComponent(job.job_id));
          say(current.cancel_requested ? 'Cancellation is already recorded. Completed changes stay applied.'
            : 'The cancellation could not be confirmed. Saved progress: ' + progressText(current) + '. Review the job before deciding what to do next.', !current.cancel_requested);
        } catch (_) { fail(error, 'check whether cancellation was recorded'); }
      } finally {
        await refreshJobs();
        if (selectedJobId === job.job_id && !$('cbj-detail').hidden) showDetail({job_id:job.job_id}, false);
      }
    }

    // ----- Start a bulk change -----
    function operation() { var r = form.querySelector("input[name=operation]:checked"); return r ? r.value : "export_receipts"; }
    function syncForm() {
      var op = operation();
      form.querySelectorAll("[data-for]").forEach(function (node) {
        var key = node.dataset.for;
        var show = key === op || (key === "people" && op !== "change_identifier_type") || (key === "identifiers" && op === "change_identifier_type") || (key === "receipts" && (op === "reactivate" || op === "clear_expiration"));
        node.hidden = !show;
      });
      var later = form.elements.when.value === "later";
      form.querySelector("[data-when=later]").hidden = !later;
    }
    function renderPeople() {
      var host = $("cbj-people");
      host.replaceChildren();
      if (!state.profiles.length) host.appendChild(CW.el("p", "muted", "No people match this search. Try another reference."));
      state.profiles.forEach(function (p) {
        var label = CW.el("label"), input = document.createElement("input");
        input.type = "checkbox"; input.name = "person"; input.value = p.profile_id; input.checked = state.chosen.has(p.profile_id);
        input.addEventListener("change", function () {
          if (input.checked && state.chosen.size >= MAX_UI_ITEMS) { input.checked = false; say("Choose up to 500 people for one job.", true); return; }
          if (input.checked) state.chosen.add(p.profile_id); else state.chosen.delete(p.profile_id); countPeople();
        });
        label.append(input, " " + p.profile_id + (p.identity_kind === "anonymous" ? " (anonymous)" : ""));
        host.appendChild(label);
      });
      countPeople();
    }
    function pruneProfiles() {
      var keep = new Set(state.profiles.map(function (p) { return p.profile_id; }).concat(Array.from(state.chosen),
        state.identifiers.map(function (entry) { return entry.profile.profile_id; })));
      state.profileCache.forEach(function (_profile, id) { if (!keep.has(id)) state.profileCache.delete(id); });
    }
    function clearPrivatePeople() {
      if (privatePeopleCleared) return;
      privatePeopleCleared = true;
      if (hostedCreate) finishCreate(pendingSubmission ? "unconfirmed" : "cancelled");
      if (peopleSearchTimer) clearTimeout(peopleSearchTimer);
      detailGeneration += 1; selectJob(null);
      jobsLoading += 1; operations.disabled = true;
      $("cbj-detail").hidden = true; $("cbj-detail-body").replaceChildren();
      $("cbj-job-list").replaceChildren(CW.el("p","muted","Reload this page to use the current account and workspace."));
      state.credit = null; $("cbj-credit-detail").textContent = "";
      selectionGeneration += 1;
      peopleGeneration += 1; state.profiles = []; state.profileCache.clear(); state.chosen.clear();
      state.identifiers = []; state.receipts = []; state.policies = []; clearReview(); form.reset(); form.hidden = true;
      clearReceipts();
      $("cbj-people").replaceChildren(); $("cbj-selected-people").replaceChildren(); $("cbj-receipts").replaceChildren();
      $("cbj-people-count").textContent = "No one selected."; $("cbj-selected-title").textContent = "Selected people";
      $("cbj-people-page").textContent = "";
    }
    async function profileRequest(path, options) {
      try {
        return await request(consentBase, path, Object.assign({}, options || {}, {profileContext:true}));
      } catch (error) {
        if ([401, 403, 409].indexOf(error.status) >= 0) {
          clearPrivatePeople(); error.plain = "Your account, workspace or access changed. Reload the page before choosing people.";
        }
        throw error;
      }
    }
    async function loadPeople(after, pageIndex) {
      if (privatePeopleCleared) { fail(null,"find people");return; }
      var started = ++peopleGeneration, search = $("cbj-people-search").value.trim();
      $("cbj-people-prev").disabled = true; $("cbj-people-next").disabled = true; $("cbj-select-shown").disabled = true;
      $("cbj-people").replaceChildren(CW.el("p", "muted", "Finding people…"));
      try {
        var result = await profileRequest("/profiles?limit=50&search=" + encodeURIComponent(search) + (after ? "&after=" + encodeURIComponent(after) : ""));
        if (started !== peopleGeneration) return;
        state.profiles = result.profiles || []; state.nextPeople = result.next_after || null;
        state.peoplePage = pageIndex; state.peoplePages[pageIndex] = after; state.peoplePages.length = pageIndex + 1;
        state.profiles.forEach(function (p) { state.profileCache.set(p.profile_id, p); }); pruneProfiles(); renderPeople();
        $("cbj-people-page").textContent = "Page " + (pageIndex + 1) + ". " + state.profiles.length + " people shown." + (state.nextPeople ? " More people are available." : "");
      } catch (error) {
        if (started !== peopleGeneration) { fail(error, "find people"); return; }
        state.profiles = []; state.nextPeople = null; state.peoplePage = 0; state.peoplePages = [null];
        $("cbj-people-page").textContent = "People could not be loaded. Try again.";
        $("cbj-people").replaceChildren(CW.el("p", "danger-text", CW.errorText(error, "find people")));
        var retry = CW.el("button", "btn btn--ghost", "Try finding people again"); retry.type = "button";
        retry.addEventListener("click", function () { loadPeople($("cbj-people-search").value.trim() === search ? after : null, $("cbj-people-search").value.trim() === search ? pageIndex : 0); }); $("cbj-people").appendChild(retry);
      } finally {
        if (started === peopleGeneration) {
          $("cbj-people-prev").disabled = state.peoplePage === 0; $("cbj-people-next").disabled = !state.nextPeople;
          $("cbj-select-shown").disabled = !state.profiles.length;
        }
      }
    }
    async function lookupPeople(ids, requireAll) {
      var unique = Array.from(new Set(ids));
      if (!unique.length || unique.length > MAX_UI_ITEMS) throw Object.assign(new Error("people"), {plain:"Choose between 1 and 500 people for one job."});
      var found = [], missing = [], started = selectionGeneration;
      for (var start = 0; start < unique.length; start += 100) {
        var batch = unique.slice(start, start + 100);
        var result = await profileRequest("/profiles/lookup", {method:"POST", body:{profile_ids:batch}});
        if (started !== selectionGeneration) throw Object.assign(new Error("selection changed"), {plain:"The selection changed. Choose the list again before reviewing."});
        var rows = result.profiles, absent = result.missing;
        if (!Array.isArray(rows) || !Array.isArray(absent) || rows.some(function (p) { return !p || batch.indexOf(p.profile_id) < 0 || !Number.isSafeInteger(p.revision) || p.revision < 0; }) || absent.some(function (id) { return batch.indexOf(id) < 0; }) || new Set(rows.map(function (p) { return p.profile_id; }).concat(absent)).size !== batch.length || rows.length + absent.length !== batch.length)
          throw Object.assign(new Error("invalid lookup"), {plain:"People could not be verified. Try the list again before reviewing."});
        found = found.concat(result.profiles || []); missing = missing.concat(result.missing || []);
      }
      if (requireAll && (missing.length || found.length !== unique.length))
        throw Object.assign(new Error("people"), {plain:"Some selected people are no longer available. Refresh or remove them before reviewing."});
      found.forEach(function (p) { state.profileCache.set(p.profile_id, p); });
      missing.forEach(function (id) { state.profileCache.delete(id); });
      return {profiles:found, missing:missing};
    }
    function countPeople() {
      clearReview();
      var key = Array.from(state.chosen).sort().join("\n");
      if (key !== state.receiptPeopleKey) { clearReceipts(); state.receiptPeopleKey = key; }
      var n = state.chosen.size;
      $("cbj-people-count").textContent = n ? n + (n === 1 ? " person selected." : " people selected.") : "No one selected.";
      $("cbj-selected-title").textContent = n ? n + " selected people" : "Selected people";
      var selected = $("cbj-selected-people"); selected.replaceChildren();
      state.chosen.forEach(function (id) {
        var label = CW.el("label"), input = document.createElement("input"); input.type = "checkbox"; input.checked = true;
        input.addEventListener("change", function () { state.chosen.delete(id); pruneProfiles(); renderPeople(); });
        label.append(input, " " + id); selected.appendChild(label);
      });
    }
    async function readLines(file) {
      if (file.size > 256 * 1024) throw Object.assign(new Error("file"), {plain:"Use a list file smaller than 256 KB."});
      var text = await file.text();
      var lines = text.split(/\r?\n/).map(function (line) { return line.trim(); }).filter(Boolean);
      if (lines.length > MAX_UI_ITEMS) throw Object.assign(new Error("file"), {plain:"Use up to 500 people in one list. Start another job for the rest."});
      return lines;
    }
    function profileById(id) { return state.profileCache.get(id) || null; }
    async function openCreate() {
      if (privatePeopleCleared) { say("Reload the page to use the current account and workspace.", true); return; }
      if (pendingSubmission) { CW.open($('cbj-submission-recovery'), '#cbj-check-submission'); return; }
      selectionGeneration += 1;
      if (peopleSearchTimer) clearTimeout(peopleSearchTimer);
      clearReview();
      form.reset();
      form.elements.idempotency_key.value = CW.reference();
      state.chosen = new Set(); state.identifiers = []; state.receipts = []; state.policies = [];
      state.profileCache.clear(); state.profiles = []; state.peoplePages = [null]; state.peoplePage = 0; state.nextPeople = null;
      $("cbj-receipts").replaceChildren();
      $("cbj-identifier-count").textContent = "No file chosen.";
      try {
        var results = await Promise.all([loadPeople(null, 0), request(consentBase, "/policies?limit=500")]);
        if (privatePeopleCleared) return;
        state.policies = results[1].policies || [];
      } catch (error) { fail(error, "load people and policies"); }
      if (privatePeopleCleared) return;
      var latest = {};
      state.policies.forEach(function (p) { if (!latest[p.policy_id] || latest[p.policy_id].version < p.version) latest[p.policy_id] = p; });
      CW.fill(form.elements.policy_key, Object.keys(latest).sort().map(function (k) { return { value: k + "|" + latest[k].version, label: CW.human(k) + " (version " + latest[k].version + ")" }; }));
      fillPurposes();
      CW.fill(form.elements.channel, CW.CHANNELS);
      CW.fill(form.elements.jurisdiction, CW.JURISDICTIONS);
      CW.fill(form.elements.country_code, CW.COUNTRIES);
      var first = form.querySelector("input[name=operation]:not(:disabled)");
      if (first) first.checked = true;
      renderPeople(); syncForm();
      CW.open(form, "input[name=operation]:checked");
    }
    function finishCreate(outcome, job) {
      var session = hostedCreate;
      if (!session) return;
      hostedCreate = null; session.observer.disconnect();
      session.nodes.forEach(function (pair) { pair.marker.replaceWith(pair.node); });
      var publicJob = job ? {Status:job.retained === false ? 'Original acceptance retained; job no longer kept' : (STATE_LABELS[job.state] || ['Recorded'])[0],
        'Selected records':job.total_items, Progress:job.retained === false ? 'The processing result is no longer retained.' : progressText(job)} : null;
      if (job && job.retained !== false) publicJob.open={label:'Open submitted job',href:'/consent/bulk-jobs?job='+encodeURIComponent(job.job_id)};
      session.resolve({status:outcome, job:publicJob});
    }
    global.LightworkConsentBulkJobs = {
      openCreate:async function (options) {
        if (!options || !options.host || !options.host.isConnected || typeof options.active !== 'function' ||
            options.context !== shell.dataset.requestContext || !canAdmin || hostedCreate || privatePeopleCleared)
          throw new Error('Reopen the current consent page before preparing a request.');
        if (!(await refreshStatus()) || !options.active()) throw new Error('Consent requests are not available here.');
        var result = new Promise(function (resolve) {
          var nodes = [form,$('cbj-submission-recovery'),status].map(function (node) {
            var marker = document.createComment('native consent form position'); node.before(marker); options.host.appendChild(node);
            return {node:node,marker:marker};
          });
          var observer = new MutationObserver(function () {
            if (!options.host.isConnected || !options.active()) finishCreate(pendingSubmission ? 'unconfirmed' : 'cancelled');
          });
          hostedCreate = {nodes:nodes,observer:observer,resolve:resolve};
          observer.observe(document.body,{subtree:true,childList:true,attributes:true,attributeFilter:['hidden']});
        });
        try { await openCreate(); }
        catch (error) { finishCreate(pendingSubmission ? 'unconfirmed' : 'cancelled'); throw error; }
        return result;
      }
    };
    function fillPurposes() {
      var key = form.elements.policy_key.value.split("|"), policy = state.policies.filter(function (p) { return p.policy_id === key[0] && String(p.version) === key[1]; })[0];
      CW.fill(form.elements.purpose_id, Object.keys((policy && policy.purposes) || {}).map(function (k) { return { value: k, label: CW.human(k) }; }));
    }
    function clearReceipts() {
      receiptsGeneration += 1; state.receipts = []; state.chosenReceipts.clear(); state.nextReceipt = null;
      $("cbj-receipts").replaceChildren(); $("cbj-selected-receipts").replaceChildren();
      $("cbj-selected-receipts-title").textContent = "Selected choices"; $("cbj-receipt-pages").hidden = true;
      $("cbj-receipt-person").replaceChildren(); $("cbj-receipt-older").disabled = true;
      $("cbj-receipt-page").textContent = "";
    }
    function receiptLabel(r) {
      var choices = (r.choices || []).map(function (c) { return CW.human(c.purpose_id) + ": " + CW.human(c.action) + (c.expires_at ? " (ends " + CW.when(c.expires_at) + ")" : ""); }).join("; ");
      return r.profile_id + " – " + choices + " – recorded " + CW.when(r.created_at);
    }
    function renderSelectedReceipts() {
      var host = $("cbj-selected-receipts"); host.replaceChildren();
      $("cbj-selected-receipts-title").textContent = state.chosenReceipts.size ? state.chosenReceipts.size + " selected choices" : "Selected choices";
      state.receipts.filter(function (r) { return state.chosenReceipts.has(r.receipt_id); }).forEach(function (r) {
        var label = CW.el("label"), input = document.createElement("input"); input.type = "checkbox"; input.checked = true;
        input.addEventListener("change", function () {
          state.chosenReceipts.delete(r.receipt_id); clearReview(); renderSelectedReceipts();
          Array.prototype.forEach.call($("cbj-receipts").querySelectorAll("input"), function (shown) { if (shown.value === r.receipt_id) shown.checked = false; });
        });
        label.append(input, " " + receiptLabel(r)); host.appendChild(label);
      });
    }
    async function loadReceiptPage(before) {
      var person = $("cbj-receipt-person").value, started = ++receiptsGeneration, host = $("cbj-receipts");
      if (!state.chosen.has(person)) { clearReceipts(); return; }
      clearReview(); host.replaceChildren(CW.el("p", "muted", "Loading choices…"));
      $("cbj-receipt-older").disabled = true;
      try {
        var exported = await profileRequest("/profiles/" + encodeURIComponent(person) + "/export?access_purpose=bulk-change-selection&receipt_limit=10" + (before ? "&before_sequence=" + before : ""));
        if (started !== receiptsGeneration) return;
        var rows = (exported.receipts || []).filter(function (r) { return state.chosen.has(r.profile_id); });
        state.receipts = state.receipts.filter(function (r) { return state.chosenReceipts.has(r.receipt_id) && !rows.some(function (shown) { return shown.receipt_id === r.receipt_id; }); }).concat(rows);
        state.nextReceipt = exported.next_before_sequence || null; host.replaceChildren();
        if (!rows.length) host.appendChild(CW.el("p", "muted", "No choices for the selected people appear on this page."));
        rows.forEach(function (r) {
          var label = CW.el("label"), input = document.createElement("input");
          input.type = "checkbox"; input.name = "receipt"; input.value = r.receipt_id; input.checked = state.chosenReceipts.has(r.receipt_id);
          input.addEventListener("change", function () {
            if (input.checked && state.chosenReceipts.size >= MAX_UI_ITEMS) { input.checked = false; say("Choose up to 500 choices for one job.", true); return; }
            if (input.checked) state.chosenReceipts.add(r.receipt_id); else state.chosenReceipts.delete(r.receipt_id);
            clearReview(); renderSelectedReceipts();
          });
          label.append(input, " " + receiptLabel(r)); host.appendChild(label);
        });
        $("cbj-receipt-page").textContent = rows.length + " recorded choices shown." + (state.nextReceipt ? " Earlier choices are available." : "");
        $("cbj-receipt-older").disabled = !state.nextReceipt; renderSelectedReceipts();
      } catch (error) {
        if (started !== receiptsGeneration) return;
        state.nextReceipt = null; host.replaceChildren(CW.el("p", "danger-text", CW.errorText(error, "load their choices")));
        $("cbj-receipt-page").textContent = "Choices could not be loaded. Choose Latest choices to try again.";
      }
    }
    async function loadReceipts() {
      var ids = Array.from(state.chosen);
      if (!ids.length) { say("Choose the people first.", true); return; }
      clearReceipts();
      CW.fill($("cbj-receipt-person"), ids.map(function (id) { return {value:id, label:id}; }));
      $("cbj-receipt-pages").hidden = false;
      await loadReceiptPage(null);
    }
    function whenValue() {
      if (form.elements.when.value !== "later") return "";
      var seconds = CW.toSeconds(form.elements.scheduled_for.value);
      if (!(seconds > Date.now() / 1000)) throw Object.assign(new Error("when"), { plain: "Choose a start time in the future." });
      return new Date(seconds * 1000).toISOString();
    }
    async function buildItems(op) {
      var freshIds = op === "change_identifier_type" ? state.identifiers.map(function (entry) { return entry.profile.profile_id; }) : Array.from(state.chosen);
      if (freshIds.length) await lookupPeople(freshIds, true);
      var items = [], n = 0;
      function next() { n += 1; return "item-" + n; }
      if (op === "change_identifier_type") {
        if (!state.identifiers.length) throw Object.assign(new Error("ids"), { plain: "Upload the list of people and their new identifiers." });
        for (var k = 0; k < state.identifiers.length; k++) {
          var entry = state.identifiers[k];
          items.push({ item_id: next(), profile_id: entry.profile.profile_id, expected_revision: profileById(entry.profile.profile_id).revision, identity_kind: form.elements.identity_kind.value, subject_sha256: await CW.sha256(entry.identifier) });
        }
        return items;
      }
      var people = Array.from(state.chosen).map(profileById).filter(Boolean);
      if (!people.length) throw Object.assign(new Error("people"), { plain: "Choose at least one person." });
      if (op === "export_receipts") return people.map(function (p) { return { item_id: next(), profile_id: p.profile_id, receipt_limit: Number(form.elements.receipt_limit.value) }; });
      if (op === "delete_subject") return people.map(function (p) { return { item_id: next(), profile_id: p.profile_id, expected_revision: p.revision, reason_code: form.elements.reason_code.value }; });
      if (op === "edit_preferences") {
        var key = form.elements.policy_key.value.split("|");
        if (!key[0] || !form.elements.purpose_id.value) throw Object.assign(new Error("policy"), { plain: "Choose a consent policy and a use of data." });
        return people.map(function (p) {
          return { item_id: next(), profile_id: p.profile_id, expected_revision: p.revision, policy_id: key[0], policy_version: Number(key[1]),
            context: { jurisdiction: form.elements.jurisdiction.value, country_code: form.elements.country_code.value, region_code: "", collection_point: "admin", asserted_source: "operator" },
            choices: [{ purpose_id: form.elements.purpose_id.value, action: form.elements.action.value, channel: form.elements.channel.value, vendor_id: "all" }] };
        });
      }
      var picked = Array.from(state.chosenReceipts);
      if (!picked.length) throw Object.assign(new Error("receipts"), { plain: "Show the people’s choices and tick the ones to change." });
      var at = op === "reactivate" ? CW.toSeconds(form.elements.reactivation_at.value) : 0;
      if (op === "reactivate" && !(at > Date.now() / 1000)) throw Object.assign(new Error("at"), { plain: "Choose when to bring the choices back, in the future." });
      return picked.map(function (receiptId) {
        var receipt = state.receipts.filter(function (r) { return r.receipt_id === receiptId; })[0];
        if (!receipt || !state.chosen.has(receipt.profile_id) || !profileById(receipt.profile_id))
          throw Object.assign(new Error("selection changed"), {plain:"Your people selection changed. Show their choices and choose them again before reviewing."});
        var item = { item_id: next(), profile_id: receipt.profile_id, expected_revision: profileById(receipt.profile_id).revision, receipt_id: receiptId };
        if (op === "reactivate") item.reactivation_at = at;
        return item;
      });
    }
    var reviewedJob = null, reviewRevision = 0;
    function clearReview() {
      reviewRevision += 1;
      reviewedJob = null;
      $("cbj-review").hidden = true;
      $("cbj-review-rows").replaceChildren();
    }
    function reviewChange(op, item) {
      if (op === "export_receipts") return "Export up to " + item.receipt_limit + " consent records.";
      if (op === "delete_subject") return "Stop using this person's choices and replace their stored identifier. Past records remain for audit. Reason: " + CW.human(item.reason_code) + ".";
      if (op === "edit_preferences") return item.choices.map(function (choice) {
        return CW.human(choice.action) + " " + CW.human(choice.purpose_id) + " for " + CW.human(choice.channel) + " channels.";
      }).join(" ");
      if (op === "change_identifier_type") {
        var entry = state.identifiers.find(function (value) { return value.profile.profile_id === item.profile_id; });
        return "Use " + CW.human(item.identity_kind) + " identification: " + (entry ? entry.identifier : "the uploaded value") + ".";
      }
      var receipt = state.receipts.find(function (value) { return value.receipt_id === item.receipt_id; });
      var purpose = receipt && receipt.choices ? receipt.choices.map(function (choice) { return CW.human(choice.purpose_id) + ": " + CW.human(choice.action); }).join("; ") : "the selected consent choice";
      return op === "reactivate" ? "Bring back " + purpose + " on " + CW.when(item.reactivation_at) + "."
        : "Remove the end date from " + purpose + ".";
    }
    async function submitCreate() {
      if (pendingSubmission) { CW.open($('cbj-submission-recovery'), '#cbj-check-submission'); return; }
      var op = operation();
      var revision = reviewRevision;
      try {
        var items = await buildItems(op);
        var itemsJson = JSON.stringify(items);
        if (items.length > MAX_UI_ITEMS || new TextEncoder().encode(itemsJson).byteLength > MAX_JSON_INPUT_BYTES) {
          say("That is too many records for one bulk change. Choose fewer people and start another bulk change for the rest.", true);
          return;
        }
        var values = { items_json: itemsJson, idempotency_key: form.elements.idempotency_key.value, scheduled_for: whenValue() };
        var payload;
        if (op === "export_receipts") payload = buildExportPayload(values);
        else { values.operation = op; payload = buildActionPayload(values); }
        if (revision !== reviewRevision) { say("Your selection changed while preparing the review. Review it again.", true); return; }
        reviewedJob = { operation: op, payload: payload };
        var rows = $("cbj-review-rows");
        rows.replaceChildren();
        payload.items.forEach(function (item) {
          var row = CW.el("tr");
          row.append(CW.el("td", "", item.profile_id), CW.el("td", "", reviewChange(op, item)));
          rows.appendChild(row);
        });
        $("cbj-review-summary").textContent = WHAT[op] + " for " + payload.items.length + " records. " +
          (payload.scheduled_for ? "Scheduled for " + CW.when(payload.scheduled_for) + ". " : "Starts as soon as possible. ") +
          (op === "export_receipts" ? "The export will contain personal consent records." : "Cancelling later will not undo changes already made.");
        CW.open($("cbj-review"), "#cbj-start-reviewed");
      } catch (error) {
        if (error && error.plain) { say(error.plain, true); return; }
        if (error && error.code === "invalid_input") { say("Some of the details could not be used. Check your choices and try again.", true); return; }
        fail(error, "start the bulk change");
      }
    }
    $("cbj-start-reviewed").addEventListener("click", function (event) {
      handle(event.currentTarget, async function (disableControls) {
        var selected = reviewedJob;
        if (!selected) { say("Review your selection before starting the job.", true); return; }
        var count = selected.payload.items.length;
        if (!(await CW.confirm(WHAT[selected.operation] + " for " + count + (count === 1 ? " record" : " records") + "? " +
          (selected.operation === "export_receipts" ? "This creates a file containing the selected consent records." : "This changes people’s consent records and cannot be undone by cancelling."), "Start job"))) return;
        if (reviewedJob !== selected) { say("Your selection changed. Review it again before starting.", true); return; }
        disableControls();
        rememberSubmission(selected.payload.idempotency_key);
        try {
          var acceptedJob = await api(selected.operation === "export_receipts" ? "/exports" : "/actions", { method: "POST", body: selected.payload });
        } catch (error) {
          // A failed wait is not evidence that admission failed. Read this
          // exact actor-bound submission rather than creating a new reference.
          if ([400, 422].indexOf(error.status) >= 0) { rememberSubmission(null); throw error; }
          say('The submission result could not be confirmed. Check submitted job before starting another job.', true);
          try {
            var found = await checkSubmission();
            if (found === false && error.status === 409) { rememberSubmission(null); throw error; }
          } catch (checkError) { if (checkError === error) throw error; /* The dedicated check remains available. */ }
          return;
        }
        rememberSubmission(null);
        clearReview(); form.hidden = true;
        say("Job queued. Use Run now on its row when it is due." + (selected.operation === "export_receipts" ? " Download the file when it has finished." : ""));
        await Promise.all([refreshJobs(), refreshCredit()]);
        finishCreate("submitted", acceptedJob);
      });
    });
    $("cbj-edit-reviewed").addEventListener("click", function () {
      clearReview(); CW.open(form, "input[name=operation]:checked");
    });
    form.addEventListener("input", clearReview);
    form.addEventListener("change", clearReview);

    // ----- Allowance and upkeep -----
    async function refreshCredit() {
      state.credit = null;
      try {
        var credit = await api("/credits/detail");
        if (privatePeopleCleared) return;
        state.credit = credit;
        $("cbj-credit-detail").textContent = credit.available + " records can still be processed (" + credit.reserved + " set aside for waiting bulk changes, " + credit.consumed + " used).";
      } catch (error) { CW.fail($("cbj-credit-detail"), error, "load the allowance"); }
    }
    var pendingAllowance = null, allowanceKey = recoveryKey ? recoveryKey + ':allowance' : '';
    try { var storedAllowance = allowanceKey && global.sessionStorage.getItem(allowanceKey); if (storedAllowance && IDEMPOTENCY_PATTERN.test(storedAllowance)) pendingAllowance = storedAllowance; } catch (_) {}
    function rememberAllowance(reference) {
      pendingAllowance = reference;
      try { if (allowanceKey) { if (reference) global.sessionStorage.setItem(allowanceKey,reference); else global.sessionStorage.removeItem(allowanceKey); } } catch (_) {}
      $('cbj-allowance-recovery').hidden = !reference;
    }
    rememberAllowance(pendingAllowance);
    async function checkAllowance() {
      if (!pendingAllowance) return;
      var result = await api('/credits/check',{method:'POST',body:{idempotency_key:pendingAllowance}});
      if (!result.found) { $('cbj-allowance-note').textContent='No original acceptance is recorded yet. Check again before deciding on another change. This check does not add records.'; return; }
      rememberAllowance(null);say('Your original change allowed '+result.allowance.added+' more records. No allowance was added again.');await refreshCredit();
    }
    $('cbj-check-allowance').addEventListener('click',function(event){handle(event.currentTarget,function(disableControls){disableControls();return checkAllowance();});});
    async function addCredits(disableControls) {
      if (pendingAllowance) { CW.open($('cbj-allowance-recovery'),'#cbj-check-allowance');return; }
      await refreshCredit();
      if (!state.credit) return;
      var answers = await global.mvForm("Add to the allowance", [{ key: "amount", label: "How many more records", type: "select", required: true, default: "10", options: [{ value: "10", label: "10" }, { value: "50", label: "50" }, { value: "100", label: "100" }, { value: "500", label: "500" }] }], { okText: "Review the larger allowance" });
      if (!answers) return;
      if (!(await CW.confirm("Allow " + answers.amount + " more consent records to be processed in this workspace? No job runs and no payment is made.", "Add"))) return;
      disableControls();
      var original = CW.reference();rememberAllowance(original);
      try { await api("/credits/grant", { method: "POST", body: { amount: Number(answers.amount), expected_revision: state.credit.revision, idempotency_key: original } });rememberAllowance(null);say("Allowance updated.");await refreshCredit(); }
      catch (error) {
        if ([400,409,422].indexOf(error.status)>=0) { rememberAllowance(null);fail(error,'update the allowance');await refreshCredit();return; }
        say('The allowance reply was interrupted. Check your original allowance change before adding more. No automatic repeat will occur.',true);
      }
    }

    $("cbj-new").addEventListener("click", function (event) { CW.busy(event.currentTarget, openCreate); });
    $("cbj-state-filter").addEventListener("change", refreshJobs);
    if ($('cbj-jobs-older')) $('cbj-jobs-older').addEventListener('click', function () { if (jobsNext) refreshJobs(jobsNext); });
    if ($('cbj-jobs-latest')) $('cbj-jobs-latest').addEventListener('click', function () { refreshJobs(); });
    form.querySelectorAll("input[name=operation]").forEach(function (radio) { radio.addEventListener("change", syncForm); });
    form.elements.when.addEventListener("change", syncForm);
    form.elements.policy_key.addEventListener("change", fillPurposes);
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      handle(form.querySelector("button[type=submit]"), function (disableControls) { return submitCreate(disableControls); });
    });
    function findPeople() { if (peopleSearchTimer) clearTimeout(peopleSearchTimer); return loadPeople(null, 0); }
    $("cbj-people-search").addEventListener("input", function () { if (peopleSearchTimer) clearTimeout(peopleSearchTimer); peopleGeneration += 1; peopleSearchTimer = setTimeout(findPeople, 250); });
    $("cbj-people-search").addEventListener("keydown", function (event) { if (event.key === "Enter") { event.preventDefault(); findPeople(); } });
    $("cbj-find-people").addEventListener("click", findPeople);
    $("cbj-people-prev").addEventListener("click", function () { if (state.peoplePage > 0) loadPeople(state.peoplePages[state.peoplePage - 1], state.peoplePage - 1); });
    $("cbj-people-next").addEventListener("click", function () { if (state.nextPeople) loadPeople(state.nextPeople, state.peoplePage + 1); });
    $("cbj-select-shown").addEventListener("click", function () {
      var ids = state.profiles.map(function (p) { return p.profile_id; });
      if (new Set(Array.from(state.chosen).concat(ids)).size > MAX_UI_ITEMS) { say("Choose up to 500 people for one job.", true); return; }
      ids.forEach(function (id) { state.chosen.add(id); }); renderPeople();
    });
    $("cbj-clear-people").addEventListener("click", function () { state.chosen = new Set(); renderPeople(); });
    $("cbj-people-file").addEventListener("change", async function (event) {
      var file = event.target.files && event.target.files[0], started = selectionGeneration;
      if (!file) return;
      try {
        var ids = (await readLines(file)).map(function (line) { return line.split(",")[0].trim(); });
        if (started !== selectionGeneration) return;
        if (ids.some(function (id) { return !ID_PATTERN.test(id); })) throw Object.assign(new Error("file"), {plain:"Use one valid person reference per line."});
        if (new Set(Array.from(state.chosen).concat(ids)).size > MAX_UI_ITEMS) throw Object.assign(new Error("people"), {plain:"Choose up to 500 people for one job."});
        var found = await lookupPeople(ids, false);
        if (new Set(Array.from(state.chosen).concat(found.profiles.map(function (p) { return p.profile_id; }))).size > MAX_UI_ITEMS) {
          pruneProfiles(); throw Object.assign(new Error("people"), {plain:"Choose up to 500 people for one job."});
        }
        found.profiles.forEach(function (p) { state.chosen.add(p.profile_id); }); renderPeople(); pruneProfiles();
        say(found.profiles.length + " people added from the list." + (found.missing.length ? " " + found.missing.length + " references did not match anyone." : ""), found.missing.length > 0);
      } catch (error) { fail(error, "read the people list"); }
    });
    $("cbj-identifier-file").addEventListener("change", async function (event) {
      var file = event.target.files && event.target.files[0], started = selectionGeneration;
      if (!file) return;
      try {
        var lines = await readLines(file), entries = lines.map(function (line) { var parts = line.split(","); return {id:(parts[0] || "").trim(), identifier:parts.slice(1).join(",").trim()}; });
        if (started !== selectionGeneration) return;
        if (entries.some(function (entry) { return !ID_PATTERN.test(entry.id) || !entry.identifier; }) || new Set(entries.map(function (entry) { return entry.id; })).size !== entries.length)
          throw Object.assign(new Error("file"), {plain:"Use each person once, with their reference and new identifier separated by a comma."});
        var found = await lookupPeople(entries.map(function (entry) { return entry.id; }), false);
        var matched = new Set(found.profiles.map(function (p) { return p.profile_id; }));
        state.identifiers = entries.filter(function (entry) { return matched.has(entry.id); }).map(function (entry) { return {profile:profileById(entry.id), identifier:entry.identifier}; });
        pruneProfiles(); clearReview();
        $("cbj-identifier-count").textContent = state.identifiers.length + " people ready." + (found.missing.length ? " " + found.missing.length + " references could not be matched." : "");
      } catch (error) { fail(error, "read the identifier list"); }
    });
    $("cbj-load-receipts").addEventListener("click", function (event) { CW.busy(event.currentTarget, loadReceipts); });
    $("cbj-receipt-person").addEventListener("change", function () { loadReceiptPage(null); });
    $("cbj-receipt-latest").addEventListener("click", function () { loadReceiptPage(null); });
    $("cbj-receipt-older").addEventListener("click", function () { if (state.nextReceipt) loadReceiptPage(state.nextReceipt); });
    $("cbj-add-credits").addEventListener("click", function (event) { handle(event.currentTarget, addCredits); });
    $("cbj-run-next").addEventListener("click", function (event) {
      handle(event.currentTarget, async function (disableControls) {
        if (!(await CW.confirm("Run the next bulk change that is due now? It may change or delete people’s consent records.", "Run next change"))) return;
        disableControls();
        try { await api("/worker/run-next", { method: "POST", body: {} }); say("The next due bulk change ran."); await refreshJobs(); }
        catch (error) { fail(error, "run the next bulk change"); }
      });
    });
    $("cbj-recover").addEventListener("click", function (event) {
      handle(event.currentTarget, async function (disableControls) {
        if (!(await CW.confirm("Restart bulk changes that stopped part-way? They will carry on from where they stopped.", "Restart"))) return;
        disableControls();
        try { await api("/operations/recover", { method: "POST", body: { limit: 100 } }); say("Stuck bulk changes restarted."); await refreshJobs(); }
        catch (error) { fail(error, "restart stuck bulk changes"); }
      });
    });
    $("cbj-verify-integrity").addEventListener("click", function (event) {
      CW.busy(event.currentTarget, async function () {
        try { var result = await api("/operations/integrity"); var ok = !(result && result.valid === false); say(ok ? "The history is intact." : "The check found a problem. Contact support before changing anything.", !ok); }
        catch (error) { fail(error, "check the history"); }
      });
    });
    $("cbj-retention-before").value = CW.toInput(Date.now() / 1000, true);
    $("cbj-retention").addEventListener("submit", function (event) {
      event.preventDefault();
      handle($("cbj-purge"), purgeOld);
    });
    async function purgeOld(disableControls) {
      var before = CW.toSeconds($("cbj-retention-before").value);
      if (!(before > 0)) { say("Choose a date.", true); return; }
      try {
        var due = await api("/operations/retention?limit=500&before=" + encodeURIComponent(String(before)));
        var count = (due.jobs || due.items || []).length;
        if (!count) { say("No finished bulk changes reached the end of their keeping period before " + CW.when(before) + "."); return; }
        if (!(await CW.confirm("Permanently delete " + count + " finished bulk changes from before " + CW.when(before) + "? They cannot be recovered.", "Delete"))) return;
        disableControls();
        await api("/operations/retention/purge", { method: "POST", body: { before: before, limit: 500 } });
        say("Old bulk changes deleted."); await refreshJobs();
      } catch (error) { fail(error, "delete old bulk changes"); }
    }

    refreshStatus().then(function (ready) {
      if (!ready) {
        $("cbj-job-list").replaceChildren(CW.el("p", "muted", "Bulk changes appear here once they are set up."));
        $("cbj-credit-detail").textContent = "";
        return null;
      }
      return Promise.all([refreshJobs(), refreshCredit()]).then(function () {
        var selected = new URLSearchParams(global.location.search).get('job');
        if (selected && ID_PATTERN.test(selected)) showDetail({job_id:selected});
      });
    });
    document.addEventListener('lightwork:copilot-context-changed',function(){
      if (!privatePeopleCleared) api('/status').catch(function(error){if(privatePeopleCleared)fail(error,'continue');});
    });
    document.addEventListener('lightwork:product-operation-complete', function (event) {
      if (event.detail && /^consent\.jobs\./.test(event.detail.operation || '')) {
        refreshJobs(); refreshCredit();
        if (selectedJobId && !$('cbj-detail').hidden) showDetail({job_id:selectedJobId}, false);
      }
    });
  });
})(typeof window !== "undefined" ? window : this);
