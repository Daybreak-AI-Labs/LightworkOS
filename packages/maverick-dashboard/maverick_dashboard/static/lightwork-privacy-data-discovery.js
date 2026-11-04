(function (global) {
  "use strict";

  // ---- Bounded client helpers (also used by the unit tests) -----------------
  var MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
  var MAX_INPUT_BYTES = 32 * 1024;
  var ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
  var OPERATION_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$/;
  var ENVIRONMENT_REF = /^[A-Z][A-Z0-9_]{1,127}$/;
  var DIGEST = /^[0-9a-f]{64}$/;

  function problem(message, code, status) {
    var error = new Error(message);
    error.code = code || "invalid_input";
    error.status = status || 0;
    return error;
  }
  function identifier(value, label, operation) {
    var selected = String(value || "").trim();
    if (!(operation ? OPERATION_ID : ID).test(selected)) { throw problem(label + " is invalid."); }
    return selected;
  }
  function environmentReference(value, label) {
    var selected = String(value || "").trim();
    if (!ENVIRONMENT_REF.test(selected)) {
      throw problem(label + " must be an environment-variable name, not a credential value.");
    }
    return selected;
  }
  function savedReference(value, label, evidence) {
    var selected = String(value || "").trim();
    var pattern = evidence ? /^evidence-key:[a-z0-9][a-z0-9_-]{0,63}:[1-9][0-9]{0,9}$/ : /^connection:[a-z0-9][a-z0-9_-]{0,63}:[0-9a-f]{32}$/;
    if (!pattern.test(selected)) { return environmentReference(selected, label); }
    return selected;
  }
  function digest(value, label) {
    var selected = String(value || "").trim();
    if (!DIGEST.test(selected)) { throw problem(label + " must be a lowercase SHA-256 digest."); }
    return selected;
  }
  function finiteNumber(value, label, minimum, maximum, integerOnly) {
    var selected = Number(value);
    if (!Number.isFinite(selected) || (integerOnly && !Number.isSafeInteger(selected)) || selected < minimum || selected > maximum) {
      throw problem(label + " is outside its bound.");
    }
    return selected;
  }
  function parseBoundedObject(value, label) {
    var text = String(value || "");
    if (!text || new TextEncoder().encode(text).length > MAX_INPUT_BYTES) { throw problem(label + " is empty or exceeds its byte bound."); }
    var parsed;
    try { parsed = JSON.parse(text); } catch (_error) { throw problem(label + " is not valid JSON."); }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) { throw problem(label + " must be a JSON object."); }
    return parsed;
  }
  // Reads at most 2 MiB; a non-OK answer rejects with an error carrying the
  // status so the page can explain it in plain words.
  async function readBoundedJson(response) {
    var declared = response.headers.get("content-length");
    if (declared !== null && Number(declared) > MAX_RESPONSE_BYTES) {
      if (response.body && typeof response.body.cancel === "function") { await response.body.cancel(); }
      throw problem("Server response exceeded the 2 MiB safety limit.", "response_too_large", response.status);
    }
    if (!response.body || typeof response.body.getReader !== "function") {
      throw problem("The reply could not be read. Refresh the page and try again.", "response_stream_unavailable", response.status);
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
        throw problem("Server response exceeded the 2 MiB safety limit.", "response_too_large", response.status);
      }
      chunks.push(part.value);
    }
    var bytes = new Uint8Array(total);
    var offset = 0;
    chunks.forEach(function (chunk) { bytes.set(chunk, offset); offset += chunk.byteLength; });
    var text;
    try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
    catch (_error) { throw problem("Server response was not valid UTF-8.", "invalid_response", response.status); }
    var payload;
    try { payload = text ? JSON.parse(text) : {}; }
    catch (_error) { throw problem("The reply from the server could not be read. Try again.", "invalid_response", response.status); }
    if (!response.ok) { throw problem("request failed", "request_failed", response.status); }
    return payload;
  }

  global.LightworkPrivacyDataDiscoveryClient = {
    MAX_INPUT_BYTES: MAX_INPUT_BYTES,
    MAX_RESPONSE_BYTES: MAX_RESPONSE_BYTES,
    digest: digest,
    environmentReference: environmentReference,
    savedReference: savedReference,
    finiteNumber: finiteNumber,
    identifier: identifier,
    parseBoundedObject: parseBoundedObject,
    readBoundedJson: readBoundedJson
  };

  // ---- Page -------------------------------------------------------------------
  if (typeof document === "undefined") { return; }
  var root = document.getElementById("pdd-root");
  var R = global.LwRecords;
  if (!root || !R || root.dataset.featureEnabled !== "true") { return; }
  if (root.dataset.clientBound === "true") { return; }
  root.dataset.clientBound = "true";
  var apiBase = root.dataset.apiBase || "/api/v1/privacy/data-discovery";
  var can = { operate: root.dataset.canOperate === "true", audit: root.dataset.canAudit === "true", admin: root.dataset.canAdmin === "true" };
  var statusEl = document.getElementById("pdd-status");
  var DEFAULT_KEY = "privacy-inventory";
  var DEFAULT_LIMITS = { max_records: 10000, max_files: 1000, max_bytes: 67108864, max_seconds: 300.0, max_findings: 10000, max_fields_per_record: 256, max_record_bytes: 262144, max_document_bytes: 4194304 };
  var setup = { providers: [], connections: [], evidence_keys: [] };
  var state = { sources: [], jobs: [], reports: [] };
  var workingJobs = Object.create(null);
  var openReport = null;

  var PROVIDERS = {
    aws_s3: "Amazon S3", azure_blob: "Azure Blob Storage", gcs: "Google Cloud Storage", google_cloud_storage: "Google Cloud Storage",
    snowflake_metadata: "Snowflake", snowflake: "Snowflake", servicenow_cmdb: "ServiceNow CMDB", microsoft_entra: "Microsoft Entra",
  };
  var CATEGORY = {
    authentication_secret: "Password or secret key", biometric_identifier: "Biometric data", date_of_birth: "Date of birth",  // pragma: allowlist secret
    email_address: "Email address", financial_account: "Bank or financial account", government_identifier: "Government ID number",
    health_information: "Health information", ip_address: "IP address", payment_card: "Payment card number",
    person_name: "Person's name", phone_number: "Phone number", physical_address: "Home or postal address",
    precise_location: "Precise location", unknown_personal_data: "Other personal data",
  };
  var SOURCE_STATE = { active: ["Active", "active"], suspended: ["Paused", "warn"], revoked: ["Removed", "idle"] };
  var JOB_STATE = { queued: ["Waiting to run", "info"], leased: ["Running or awaiting its saved result", "info"], complete: ["Done", "active"], dead_letter: ["Needs attention", "blocked"], cancelled: ["Cancelled", "idle"] };
  var JOB_ERROR = { source_changed: "Source changed; waiting to retry its current selection.", source_inactive: "The source was paused or removed.",
    stale_lease_recovered: "An interrupted scan was queued again.", stale_lease_exhausted: "An interrupted scan used its allowed attempts.",
    credential_unavailable: "The saved connection or protection key needs attention.", adapter_error: "The storage service could not finish the scan.",
    provider_contract_invalid: "The storage service returned an unreadable reply.", operator_cancelled: "Cancelled by your team." };
  var WORK_STATE = {
    queued: ["Waiting", "info"], leased: ["In progress", "info"], applied: ["Done", "active"], no_change: ["Already up to date", "active"],
    ambiguous: ["Needs checking", "warn"], dead_letter: ["Failed", "blocked"], cancelled: ["Cancelled", "idle"],
  };
  var COMPLETENESS = { complete: "Finished within the selected limits", complete_within_declared_bounds: "Finished within the selected limits",
    bounded_partial: "Partly checked", partial: "Partly checked", truncated: "Stopped at a limit", failed: "Could not finish" };
  var DECISION = { confirmed: "Correct", reclassified: "Different kind of data", false_positive: "Not personal data" };

  function say(text) { window.mvStatus(statusEl, text); }
  function fail(f, action) { say(R.errorText(f, action)); }
  function badge(map, v) { var s = map[v] || [R.human(v), "info"]; return R.badge(s[0], s[1]); }
  function provider(name) { return PROVIDERS[name] || R.human(name); }
  function category(name) { return CATEGORY[name] || R.human(name); }
  async function call(path, method, body) {
    var settings = { method: method || "GET", credentials: "same-origin", headers: { Accept: "application/json" } };
    if (body !== undefined) { settings.headers["Content-Type"] = "application/json"; settings.body = JSON.stringify(body); }
    return readBoundedJson(await global.fetch(apiBase + path, settings));
  }
  function sourceName(id) { return R.human(id); }
  function latestReport(sourceId) {
    return state.reports.filter(function (r) { return r.source_id === sourceId; })
      .sort(function (a, b) { return b.finished_at - a.finished_at; })[0];
  }

  // ---- loading ------------------------------------------------------------------
  async function loadReadiness() {
    var el = document.getElementById("pdd-ready");
    try {
      var st = await call("/status");
      el.textContent = st.ready ? "Ready: scanning is set up for this workspace." :
        "Scanning is not fully set up yet. Ask an administrator to turn on the storage services you use in Settings.";
    } catch (f) { el.textContent = R.errorText(f, "check whether scanning is set up"); }
  }

  async function load() {
    try {
      var both = await Promise.all([call("/sources?limit=500"), call("/jobs?limit=200"), call("/reports?limit=200")]);
      if (both[0].permissions) {
        can.operate = both[0].permissions.operate === true;
        can.admin = both[0].permissions.admin === true;
        can.audit = both[0].permissions.audit === true;
        ["pdd-new-source", "pdd-process", "pdd-maintenance", "pdd-rotate-key", "pdd-purge"].forEach(function (id) {
          var control = document.getElementById(id); if (control) control.disabled = !can.admin;
        });
        var saveSource = document.querySelector("#pdd-source-form button[type=submit]");
        if (saveSource) saveSource.disabled = !can.admin;
        var queueDue = document.getElementById("pdd-enqueue-due"); if (queueDue) queueDue.disabled = !can.operate;
        ["pdd-verify", "pdd-audit"].forEach(function (id) { var control = document.getElementById(id); if (control) control.disabled = !can.audit; });
      }
      state.sources = both[0].items || [];
      state.jobs = both[1].items || [];
      state.reports = both[2].items || [];
      render();
      loadReviews();
      loadInventory();
      if (can.admin) loadWork();
      return true;
    } catch (f) {
      if (f && (f.status === 401 || f.status === 403 || f.status === 409)) {
        state = { sources: [], jobs: [], reports: [] };
        can.admin = false; can.operate = false; render();
      }
      fail(f, "load your data sources"); return false;
    }
  }

  function discoveryTable(container, columns, rows, actions, empty) {
    R.table(container, columns, rows, actions, empty);
    container.querySelectorAll("tbody tr").forEach(function (row) {
      Array.from(row.cells).forEach(function (cell, index) {
        cell.dataset.label = index < columns.length ? columns[index].label : "Actions";
      });
    });
  }

  function render() {
    discoveryTable(document.getElementById("pdd-sources"), [
      { label: "Source", value: function (s) { return sourceName(s.source_id); } },
      { label: "Where", value: function (s) { return provider(s.provider) + " – " + s.resource_ref; } },
      { label: "Status", value: function (s) { return badge(SOURCE_STATE, s.state); } },
      { label: "Last scan", value: function (s) { var r = latestReport(s.source_id); return r ? R.when(r.finished_at) : "Never"; } },
    ], state.sources, [
      { label: "Scan now", kind: "primary", when: function (s) { return can.operate && s.state === "active"; }, run: scanNow },
      { label: "Scan regularly", when: function (s) { return can.admin && s.state === "active"; }, run: scheduleSource },
      { label: "Test access", when: function (s) { return can.admin && s.state === "active"; }, run: testAccess },
      { label: "Pause", when: function (s) { return can.admin && s.state === "active"; }, run: function (s) { setState(s, "suspended"); } },
      { label: "Resume", when: function (s) { return can.admin && s.state === "suspended"; }, run: function (s) { setState(s, "active"); } },
      { label: "Remove", kind: "danger", when: function (s) { return can.admin && s.state !== "revoked"; }, run: function (s) { setState(s, "revoked"); } },
    ], { text: can.admin ? "No data sources yet. Use “Add a data source”." : "No data sources yet. Ask an administrator to add one." });

    discoveryTable(document.getElementById("pdd-jobs"), [
      { label: "Source", value: function (j) { return sourceName(j.source_id); } },
      { label: "Status", value: function (j) { return badge(JOB_STATE, j.state); } },
      { label: "Next step", value: function (j) { return JOB_ERROR[j.last_error_code] || ""; } },
      { label: "Tries", value: function (j) { return j.attempts + " of " + j.max_attempts; } },
      { label: "Started by", value: function (j) { return j.schedule_id ? "Schedule" : "Someone on your team"; } },
    ], state.jobs, [
      { label: "Run now", kind: "primary", when: function (j) { return canRunSource(j.source_id) && j.state === "queued" && j.next_attempt_at <= Date.now() / 1000; }, run: runJob },
      { label: "Try again", when: function (j) { return can.admin && j.state === "dead_letter"; }, run: retryJob },
      { label: "Cancel", kind: "danger", when: function (j) { return can.operate && j.state === "queued"; }, run: cancelJob },
      { label: "Read saved result", when: function (j) { return j.state === "complete" || j.state === "leased"; }, run: function (j) {
        readOriginal(j).catch(function (f) { fail(f, "read the saved scan"); });
      } },
    ], { text: "No scans yet. Use “Scan now” on a data source." });

    discoveryTable(document.getElementById("pdd-reports"), [
      { label: "Source", value: function (r) { return sourceName(r.source_id); } },
      { label: "Finished", value: function (r) { return R.when(r.finished_at); } },
      { label: "Checked", value: function (r) { return (r.records_seen || 0) + " records, " + (r.files_seen || 0) + " files"; } },
      { label: "Found", value: function (r) { return r.findings_count + (r.ambiguous_count ? " (" + r.ambiguous_count + " to check)" : ""); } },
      { label: "Coverage", value: function (r) { return COMPLETENESS[r.completeness] || R.human(r.completeness); } },
    ], state.reports, [
      { label: "See findings", kind: "primary", run: showFindings },
      { label: "Compare with earlier", when: function (r) { return earlierReports(r).length > 0; }, run: compare },
    ], { text: "No reports yet. Reports appear here after a scan finishes." });
  }

  function earlierReports(r) {
    return state.reports.filter(function (x) { return x.source_id === r.source_id && x.finished_at < r.finished_at; });
  }

  // ---- data sources -----------------------------------------------------------------
  function canRunSource(sourceId) {
    var source = state.sources.find(function (s) { return s.source_id === sourceId; });
    return can.operate && source && (can.admin || source.credential_env.indexOf("connection:") === 0);
  }

  async function scanNow(s) {
    try {
      await call("/sources/" + encodeURIComponent(s.source_id) + "/jobs", "POST",
        { limits: DEFAULT_LIMITS, max_attempts: 3, retention_seconds: 90 * 86400, idempotency_key: R.newKey() });
      say(canRunSource(s.source_id) ? "Scan queued. Use “Run now” in the Scans list to start it." : "Scan queued. It runs when an administrator starts it or the scheduler picks it up.");
      await load();
    } catch (f) { fail(f, "queue the scan"); }
  }

  async function scheduleSource(s) {
    var values = await R.form("Scan " + sourceName(s.source_id) + " regularly", [
      { key: "every", label: "How often", type: "select", default: "86400", options: [
        { value: "3600", label: "Every hour" }, { value: "86400", label: "Every day" }, { value: "604800", label: "Every week" }, { value: "2592000", label: "Every month" },
      ] },
      { key: "first", label: "First scan on", type: "date", default: R.isoDateIn(0) },
      { key: "keep", label: "Keep scan reports for", type: "select", default: "7776000", options: [
        { value: "2592000", label: "30 days" }, { value: "7776000", label: "90 days" }, { value: "31536000", label: "1 year" },
      ] },
      { key: "active", label: "Schedule is on", type: "bool", default: true },
    ], "Save schedule");
    if (!values) return;
    var id = ("schedule-" + s.source_id).slice(0, 128);
    try {
      var existing = null;
      try { existing = await call("/schedules/" + encodeURIComponent(id)); } catch (f) { if (!f || f.status !== 404) throw f; }
      var first = R.toEpoch(values.first);
      var body = {
        source_id: s.source_id, interval_seconds: parseInt(values.every, 10), limits: DEFAULT_LIMITS, max_attempts: 3,
        retention_seconds: parseInt(values.keep, 10), active: !!values.active,
        expected_revision: existing ? existing.revision : 0, idempotency_key: R.newKey(),
        next_run_at: first ? Math.max(first - 86399, Math.floor(Date.now() / 1000) + 60) : null,
      };
      await call("/schedules/" + encodeURIComponent(id), "PUT", body);
      say("Schedule saved.");
    } catch (f) { fail(f, "save the schedule"); }
  }

  async function testAccess(s) {
    var ok = await R.confirm("Check that Lightwork can read " + sourceName(s.source_id) + "? It reads a small sample and stores nothing.", "Test access");
    if (!ok) return;
    try {
      await call("/sources/" + encodeURIComponent(s.source_id) + "/test-access", "POST", { confirm: true, expected_revision: s.revision });
      say("Lightwork can read this source.");
    } catch (f) {
      if (f && (f.status === 409 || f.status === 422)) { say("Lightwork could not read this source. Check the saved connection and that this storage service is turned on in Settings."); return; }
      fail(f, "test access");
    }
  }

  async function setState(s, next) {
    var messages = {
      suspended: ["Pause scanning " + sourceName(s.source_id) + "?", "Pause", "Paused."],
      active: ["Resume scanning " + sourceName(s.source_id) + "?", "Resume", "Resumed."],
      revoked: ["Remove " + sourceName(s.source_id) + "? It can no longer be scanned. Past reports are kept until they expire.", "Remove", "Removed."],
    }[next];
    if (!(await R.confirm(messages[0], messages[1]))) return;
    try {
      await call("/sources/" + encodeURIComponent(s.source_id) + "/state", "POST", { state: next, expected_revision: s.revision, idempotency_key: R.newKey() });
      say(messages[2]);
      await load();
    } catch (f) { fail(f, "change the source"); }
  }

  // ---- add a source (administrators) --------------------------------------------------
  function fillSelect(select, rows, placeholder) {
    select.textContent = "";
    var empty = R.el("option", "", placeholder); empty.value = ""; select.appendChild(empty);
    rows.forEach(function (row) { var o = R.el("option", "", row.label); o.value = row.value; select.appendChild(o); });
  }
  function renderConnections() {
    var chosen = document.getElementById("pdd-provider").value;
    var rows = setup.connections.filter(function (c) { return c.provider === chosen; })
      .map(function (c) { return { value: c.reference, label: c.name }; });
    fillSelect(document.getElementById("pdd-connection"), rows, rows.length ? "Choose a saved connection" : "No saved connection for this service yet");
    var descriptor = setup.providers.filter(function (p) { return p.provider === chosen; })[0];
    document.getElementById("pdd-resource-help").textContent = descriptor
      ? "Enter the " + R.human(descriptor.resource_ref_contract).toLowerCase() + " to scan." : "";
  }
  async function loadSetup() {
    setup = await call("/setup");
    if (!Array.isArray(setup.providers) || !Array.isArray(setup.connections) || !Array.isArray(setup.evidence_keys)) throw problem("setup incomplete");
    fillSelect(document.getElementById("pdd-provider"),
      setup.providers.map(function (p) { return { value: p.provider, label: provider(p.provider) }; }),
      setup.providers.length ? "Choose a storage service" : "No storage services are turned on yet");
    renderConnections();
  }
  async function protectionKey() {
    var keys = setup.evidence_keys.slice().sort(function (a, b) { return b.revision - a.revision; });
    var existing = keys.filter(function (k) { return k.name === DEFAULT_KEY; })[0] || keys[0];
    if (existing) return existing.reference;
    var created = await call("/evidence-keys/" + DEFAULT_KEY, "PUT", { expected_revision: 0, idempotency_key: R.newKey() });
    await loadSetup();
    return created.reference || (setup.evidence_keys.filter(function (k) { return k.name === DEFAULT_KEY; })[0] || {}).reference;
  }

  var newSource = document.getElementById("pdd-new-source");
  if (newSource) newSource.addEventListener("click", async function () {
    try {
      await loadSetup();
      var panel = document.getElementById("pdd-source-panel");
      panel.hidden = false;
      panel.scrollIntoView({ block: "start" });
    } catch (f) { fail(f, "load the storage services"); }
  });
  var cancelSource = document.getElementById("pdd-source-cancel");
  if (cancelSource) cancelSource.addEventListener("click", function () { document.getElementById("pdd-source-panel").hidden = true; });
  var providerSelect = document.getElementById("pdd-provider");
  if (providerSelect) providerSelect.addEventListener("change", renderConnections);

  var sourceForm = document.getElementById("pdd-source-form");
  if (sourceForm) sourceForm.addEventListener("submit", async function (ev) {
    ev.preventDefault();
    var chosenProvider = document.getElementById("pdd-provider").value;
    var connectionRef = document.getElementById("pdd-connection").value;
    var connection = setup.connections.filter(function (c) { return c.reference === connectionRef; })[0];
    var descriptor = setup.providers.filter(function (p) { return p.provider === chosenProvider; })[0];
    var resource = document.getElementById("pdd-resource").value.trim();
    if (!descriptor) { say("Choose where the data lives."); return; }
    if (!connection) { say("Choose a saved connection. You can add one on the Connections page."); return; }
    if (!ID.test(resource)) { say("Enter the name exactly as it appears in " + provider(chosenProvider) + " (letters, numbers, dots, dashes and underscores)."); return; }
    var id = R.slug(document.getElementById("pdd-name").value, "data-source");
    var existing = state.sources.filter(function (s) { return s.source_id === id; })[0];
    try {
      var keyRef = await protectionKey();
      await call("/sources/" + encodeURIComponent(id), "PUT", {
        kind: descriptor.kind, provider: chosenProvider, origin: connection.origin, resource_ref: resource,
        credential_env: savedReference(connection.reference, "Connection", false),
        evidence_key_env: savedReference(keyRef, "Protection key", true),
        expected_revision: existing ? existing.revision : 0, idempotency_key: R.newKey(),
      });
      sourceForm.reset();
      document.getElementById("pdd-source-panel").hidden = true;
      say("Data source saved. Use “Test access” to check Lightwork can read it.");
      await load();
    } catch (f) { fail(f, "save the data source"); }
  });

  var rotate = document.getElementById("pdd-rotate-key");
  if (rotate) rotate.addEventListener("click", async function () {
    var ok = await R.confirm("Replace the protection key? Sources using the old key stop scanning until you save each of them again, and new reports cannot be compared with older ones.", "Replace key");
    if (!ok) return;
    try {
      await loadSetup();
      var current = setup.evidence_keys.filter(function (k) { return k.name === DEFAULT_KEY; })[0];
      await call("/evidence-keys/" + DEFAULT_KEY, "PUT", { expected_revision: current ? current.revision : 0, idempotency_key: R.newKey() });
      say("Protection key replaced. Existing sources were not changed; save each one again to use the new key.");
    } catch (f) { fail(f, "replace the protection key"); }
  });

  // ---- scans --------------------------------------------------------------------------
  async function readOriginal(j) {
    var original = await call("/jobs/" + encodeURIComponent(j.job_id) + "/result");
    if (original.report) {
      say("Saved scan: " + original.report.findings_count + " possible item(s) of personal data found. " +
        (COMPLETENESS[original.report.completeness] || "Review its saved coverage and limits."));
    } else if (original.job.state === "cancelled") {
      say("Cancellation is saved. This scan will not run.");
    } else if (original.job.state === "leased") {
      say("The earlier scan may still be running. No scan was repeated. Read its saved result again before another decision.");
    } else {
      say(JOB_ERROR[original.job.last_error_code] || "The earlier scan has no saved report. Refresh its current state before another decision.");
    }
    if (!(await load())) return false;
    return original;
  }
  async function runJob(j) {
    if (workingJobs[j.job_id]) return;
    workingJobs[j.job_id] = true;
    var submitted = false;
    try {
      var original = await call("/jobs/" + encodeURIComponent(j.job_id) + "/result");
      var current = original.job;
      if (current.state !== "queued" || current.revision !== j.revision) {
        say("This scan changed or already started. Read its saved result before another decision."); await load(); return;
      }
      var source = await call("/sources/" + encodeURIComponent(current.source_id));
      var bounds = current.limits;
      var ok = await R.confirm("Scan " + sourceName(current.source_id) + " at " + source.resource_ref + " now? Lightwork will read up to " +
        bounds.max_records + " records, " + bounds.max_files + " files and " + Math.round(bounds.max_bytes / 1048576) +
        " MB, for up to " + bounds.max_seconds + " seconds. Only fingerprints and counts are saved. This does not prove the whole system was checked.", "Scan now");
      if (!ok) return;
      submitted = true;
      say("Scanning the reviewed source. You can read its saved result if this reply is interrupted.");
      var res = await call("/jobs/" + encodeURIComponent(j.job_id) + "/run", "POST", {
        expected_revision: current.revision, expected_source_revision: source.revision,
        expected_source_integrity_sha256: source.integrity_sha256, idempotency_key: R.newKey(), confirmed: true
      });
      var rep = res && res.report;
      say(rep ? "Scan finished: " + rep.findings_count + " possible item(s) of personal data found. " + (COMPLETENESS[rep.completeness] || "") :
        "The earlier scan has no saved report yet. No scan was repeated. Read its saved result before another decision.");
      await load();
    } catch (f) {
      if (submitted) {
        try { await readOriginal(j); return; }
        catch (_unavailable) { say("The scan reply and its saved result could not be read. No scan was repeated. Refresh and read the original before another decision."); return; }
      }
      fail(f, "run the scan");
    } finally { delete workingJobs[j.job_id]; }
  }
  async function retryJob(j) {
    try {
      await call("/jobs/" + encodeURIComponent(j.job_id) + "/replay", "POST", { expected_revision: j.revision, idempotency_key: R.newKey() });
      say("Scan queued again.");
      await load();
    } catch (f) { fail(f, "retry the scan"); }
  }
  async function cancelJob(j) {
    if (workingJobs[j.job_id]) return;
    workingJobs[j.job_id] = true;
    var submitted = false;
    try {
      if (!(await R.confirm("Cancel this waiting scan for " + sourceName(j.source_id) + "? Its saved schedule is kept. Work that already started cannot be cancelled here.", "Cancel scan"))) return;
      submitted = true;
      await call("/jobs/" + encodeURIComponent(j.job_id) + "/cancel", "POST", { expected_revision: j.revision, idempotency_key: R.newKey(), confirmed: true });
      say("Scan cancelled. It will not run.");
      await load();
    } catch (f) {
      if (submitted) {
        try { await readOriginal(j); return; }
        catch (_unavailable) { say("The cancellation reply could not be read. No cancellation was repeated. Refresh and read this scan's saved state."); return; }
      }
      fail(f, "cancel the scan");
    } finally { delete workingJobs[j.job_id]; }
  }

  global.LightworkPrivacyDiscovery = { openReview: async function (selection, options) {
    if (selection && Object.keys(selection).length) return false;
    var current = options && options.isCurrent;
    if (current && !current()) return false;
    if (!(await load())) return false;
    if (current && !current()) return false;
    var box = document.getElementById("pdd-jobs");
    box.setAttribute("tabindex", "-1"); box.focus(); box.scrollIntoView({ block: "center" });
    say("Review the current scans before starting or cancelling one. Each change needs a separate review.");
    return true;
  } };
  var due = document.getElementById("pdd-enqueue-due");
  if (due) due.addEventListener("click", async function () {
    try {
      var res = await call("/schedules/enqueue-due", "POST", { limit: 100 });
      say((res.enqueued || 0) + " scheduled scan(s) queued.");
      await load();
    } catch (f) { fail(f, "queue the scheduled scans"); }
  });

  // ---- findings and reviews -------------------------------------------------------------
  async function showFindings(r) {
    openReport = r;
    var panel = document.getElementById("pdd-findings-panel");
    document.getElementById("pdd-diff").textContent = "";
    try {
      var res = await call("/reports/" + encodeURIComponent(r.report_id) + "/findings?limit=500");
      var findings = res.items || [];
      document.getElementById("pdd-findings-summary").textContent =
        sourceName(r.source_id) + ", scanned " + R.when(r.finished_at) + ". " + (COMPLETENESS[r.completeness] || "") +
        ((r.limitations || []).length ? ". Some items could not be read." : ".");
      discoveryTable(document.getElementById("pdd-findings"), [
        { label: "Kind of data", value: function (x) { return category(x.category); } },
        { label: "How sure", value: function (x) { return Math.round((x.confidence || 0) * 100) + "%"; } },
        { label: "Needs a closer look", value: function (x) { return x.ambiguous ? "Yes" : "No"; } },
      ], findings, [
        { label: "Check", kind: "primary", when: function () { return can.admin; }, run: proposeReview },
      ], { text: "Nothing was found in this scan. That does not prove there is no personal data." });
      panel.hidden = false;
      panel.scrollIntoView({ block: "start" });
    } catch (f) { fail(f, "load the findings"); }
  }

  async function compare(r) {
    var earlier = earlierReports(r);
    var values = await R.form("Compare with an earlier scan", [
      { key: "base", label: "Earlier scan", type: "select", default: earlier[0].report_id,
        options: earlier.map(function (x) { return { value: x.report_id, label: R.when(x.finished_at) }; }) },
    ], "Compare");
    if (!values) return;
    try {
      var d = await call("/reports/diff?base_report_id=" + encodeURIComponent(values.base) + "&target_report_id=" + encodeURIComponent(r.report_id) + "&limit=1000");
      if (openReport !== r) await showFindings(r);
      var box = document.getElementById("pdd-diff");
      box.textContent = "";
      box.appendChild(R.el("h3", "", "Changes since the earlier scan"));
      box.appendChild(R.el("p", "", (d.added_finding_sha256 || []).length + " new item(s), " + (d.removed_finding_sha256 || []).length +
        " no longer found, " + (d.unchanged_count || 0) + " unchanged."));
    } catch (f) {
      if (f && f.status === 409) { say("These two scans used different protection keys, so they cannot be compared. Choose two scans made with the same key."); return; }
      fail(f, "compare the scans");
    }
  }

  async function proposeReview(x) {
    var options = Object.keys(CATEGORY).map(function (k) { return { value: k, label: CATEGORY[k] }; });
    var values = await R.form("Check this finding: " + category(x.category), [
      { key: "decision", label: "Is it right?", type: "select", default: "confirmed", options: [
        { value: "confirmed", label: "Yes, it is " + category(x.category).toLowerCase() },
        { value: "reclassified", label: "It is personal data, but a different kind" },
        { value: "false_positive", label: "It is not personal data" },
      ] },
      { key: "category", label: "If a different kind, which?", type: "select", default: x.category, options: options },
    ], "Send for approval");
    if (!values) return;
    var effective = values.decision === "false_positive" ? null : values.decision === "confirmed" ? x.category : values.category;
    try {
      await call("/findings/" + encodeURIComponent(x.finding_id) + "/reviews", "POST", {
        decision: values.decision, effective_category: effective, freshness_seconds: 7 * 86400,
        expected_finding_revision: x.revision, idempotency_key: R.newKey(),
      });
      say("Sent for approval. A different person must approve it.");
      await loadReviews();
    } catch (f) { fail(f, "send the check for approval"); }
  }

  async function loadReviews() {
    var box = document.getElementById("pdd-reviews");
    try {
      var res = await call("/reviews?status=pending&limit=200");
      discoveryTable(box, [
        { label: "Decision", value: function (v) { return DECISION[v.decision] || R.human(v.decision); } },
        { label: "Kind of data", value: function (v) { return v.effective_category ? category(v.effective_category) : "Not personal data"; } },
        { label: "Checked", value: function (v) { return R.when(v.prepared_at); } },
      ], res.items || [], [
        { label: "Approve", kind: "primary", when: function () { return can.admin; }, run: approveReview },
      ], { text: "Nothing is waiting for approval. Findings from a scan appear here for review." });
    } catch (f) { box.textContent = R.errorText(f, "load the approvals"); }
  }

  async function approveReview(v) {
    if (!(await R.confirm("Approve this check and add it to your data map? You must not be the person who made the check.", "Approve"))) return;
    try {
      await call("/reviews/" + encodeURIComponent(v.review_id) + "/approve", "POST", {
        expected_version: v.version, expected_integrity_sha256: digest(v.integrity_sha256, "Review"), idempotency_key: R.newKey(),
      });
      say("Approved and sent to your data map.");
      await loadReviews();
      await loadInventory();
    } catch (f) {
      if (f && f.status === 409) { say("This check cannot be approved: you made it yourself, it has expired, or it changed. Ask someone else, or check the finding again."); await loadReviews(); return; }
      fail(f, "approve the check");
    }
  }

  async function loadInventory() {
    var box = document.getElementById("pdd-inventory");
    try {
      var inv = await call("/inventory");
      var counts = inv.counts_by_category || {};
      var rows = Object.keys(counts).map(function (k) { return { k: k, n: counts[k] }; }).sort(function (a, b) { return b.n - a.n; });
      discoveryTable(box, [
        { label: "Kind of data", value: function (r) { return category(r.k); } },
        { label: "Places found", value: function (r) { return r.n; } },
      ], rows, null, { text: "Nothing recorded yet. Scan a data source to start building your data map." });
      if (rows.length) {
        box.appendChild(R.el("p", "muted", (inv.unreviewed_count || 0) + " finding(s) not checked yet; " + (inv.false_positive_count || 0) +
          " marked as not personal data. " + (inv.truncated ? "Some scans stopped at a limit, so this may be incomplete." : "")));
      }
    } catch (f) { box.textContent = R.errorText(f, "load the summary"); }
  }

  // ---- data map updates (administrators) ------------------------------------------------
  async function loadWork() {
    var box = document.getElementById("pdd-work");
    if (!box) return;
    try {
      var res = await call("/remediation/work?limit=100");
      discoveryTable(box, [
        { label: "Update", value: function (w) { return "Data map update"; } },
        { label: "Status", value: function (w) { return badge(WORK_STATE, w.state); } },
        { label: "Tries", value: function (w) { return w.attempts != null ? w.attempts + (w.max_attempts ? " of " + w.max_attempts : "") : ""; } },
      ], res.items || [], [
        { label: "Check again", when: function (w) { return w.state === "ambiguous"; }, run: reconcile },
      ], { text: "No data map updates yet. They appear after a check is approved." });
    } catch (f) {
      if (f && f.status === 503) { box.textContent = "Data map updates are not set up for this workspace yet."; return; }
      box.textContent = R.errorText(f, "load the data map updates");
    }
  }
  async function reconcile(w) {
    try {
      var res = await call("/remediation/work/" + encodeURIComponent(w.work_id) + "/reconcile", "POST",
        { expected_revision: w.revision, absent_backoff_seconds: 0, idempotency_key: R.newKey() });
      say("Checked again: " + (WORK_STATE[res.state] || [R.human(res.state)])[0] + ".");
      await loadWork();
    } catch (f) { fail(f, "check the update again"); }
  }
  var processBtn = document.getElementById("pdd-process");
  if (processBtn) processBtn.addEventListener("click", async function () {
    processBtn.disabled = true;
    try {
      await call("/remediation/worker/run-once", "POST", { limit: 10, lease_seconds: 60 });
      say("Waiting data map updates processed.");
      await loadWork();
      await loadInventory();
    } catch (f) {
      if (f && f.status === 503) { say("Data map updates are not set up for this workspace yet."); }
      else fail(f, "process the updates");
    } finally { processBtn.disabled = false; }
  });
  var maintenance = document.getElementById("pdd-maintenance");
  if (maintenance) maintenance.addEventListener("click", async function () {
    if (!(await R.confirm("Delete expired data map update records and check the rest are intact?", "Tidy up"))) return;
    try {
      await call("/remediation/maintenance", "POST", { idempotency_key: R.newKey(), target_limit: 500 });
      say("Old data map updates tidied up; the rest are intact.");
      await loadWork();
    } catch (f) { fail(f, "tidy up the updates"); }
  });

  // ---- history and retention ------------------------------------------------------------------
  var verify = document.getElementById("pdd-verify");
  if (verify) verify.addEventListener("click", async function () {
    try {
      var res = await call("/audit/verify");
      say(res && res.valid === false ? "The activity history has a problem. Tell whoever installed Lightwork." : "The activity history is intact.");
    } catch (f) { fail(f, "check the activity history"); }
  });
  var audit = document.getElementById("pdd-audit");
  if (audit) audit.addEventListener("click", async function () {
    try { R.download("data-discovery-activity.json", await call("/audit?limit=500")); say("Activity history downloaded."); }
    catch (f) { fail(f, "download the activity history"); }
  });
  var purge = document.getElementById("pdd-purge");
  if (purge) purge.addEventListener("click", async function () {
    if (!(await R.confirm("Permanently delete scan reports whose keep-until date has passed? A record of the deletion is kept.", "Delete"))) return;
    try {
      await call("/retention/purge", "POST", { idempotency_key: R.newKey() });
      say("Expired reports deleted.");
      await load();
    } catch (f) { fail(f, "delete expired reports"); }
  });

  loadReadiness();
  load();
}(typeof window !== "undefined" ? window : this));
