/* California DROP requests page. Requests, brokers and waiting changes are
   listed on arrival; files are fingerprinted by the server and only their
   fingerprints are sent. Tenant, identity and DSAR composition stay server-owned. */
(function () {
  "use strict";

  var MAX_RESPONSE_BYTES = 512 * 1024;

  function responseTooLarge() {
    var error = new Error("The answer from Lightwork was too large to show.");
    error.code = "response_too_large";
    return error;
  }

  function invalidResponse() {
    var error = new Error("Lightwork sent an answer this page could not read. Refresh the page and try again.");
    error.code = "response_invalid_json";
    return error;
  }

  async function cancelBody(body) {
    if (!body || typeof body.cancel !== "function") return;
    try { await body.cancel(); }
    catch (_error) { /* The bounded request has already failed closed. */ }
  }

  async function boundedResponseText(response) {
    var declared = response.headers && response.headers.get("Content-Length");
    if (declared && /^\d+$/.test(declared) && Number(declared) > MAX_RESPONSE_BYTES) {
      await cancelBody(response.body);
      throw responseTooLarge();
    }
    if (!response.body || typeof response.body.getReader !== "function") {
      // A whole-body fallback (response.text/json/arrayBuffer) cannot enforce
      // the raw-byte ceiling before allocation. Modern supported browsers
      // expose a ReadableStream; fail closed when that contract is absent.
      throw invalidResponse();
    }
    var reader = response.body.getReader();
    var decoder = new TextDecoder("utf-8", {fatal: false});
    var received = 0;
    var text = "";
    while (true) {
      var chunk = await reader.read();
      if (chunk.done) break;
      received += chunk.value.byteLength;
      if (received > MAX_RESPONSE_BYTES) {
        try { await reader.cancel(); }
        catch (_error) { /* The size violation remains authoritative. */ }
        throw responseTooLarge();
      }
      text += decoder.decode(chunk.value, {stream: true});
    }
    return text + decoder.decode();
  }

  async function readBoundedJson(response) {
    var responseText = await boundedResponseText(response);
    if (!responseText) throw invalidResponse();
    try { return JSON.parse(responseText); }
    catch (_error) { throw invalidResponse(); }
  }

  async function parseResponse(response) {
    var payload;
    try {
      payload = await readBoundedJson(response);
    } catch (error) {
      error.status = response.status;
      throw error;
    }
    if (!response.ok) {
      var failure = new Error(
        payload && typeof payload.detail === "string" ?
          payload.detail : "That didn't work. Refresh the page and try again."
      );
      failure.status = response.status;
      throw failure;
    }
    return payload;
  }

  if (typeof window !== "undefined") {
    Object.defineProperty(window, "LightworkPrivacyDROPClient", {
      configurable: false,
      enumerable: false,
      writable: false,
      value: Object.freeze({
        MAX_RESPONSE_BYTES: MAX_RESPONSE_BYTES,
        readBoundedJson: readBoundedJson,
        parseResponse: parseResponse
      })
    });
  }
  if (typeof document === "undefined") return;
  var shell = document.getElementById("drop-workbench");
  var R = window.LwRecords;
  if (!shell || !R || shell.dataset.clientBound === "true") return;
  shell.dataset.clientBound = "true";
  var apiBase = shell.dataset.apiBase || "/api/v1/privacy/drop";
  var can = {
    operate: shell.dataset.canOperate === "true",
    audit: shell.dataset.canAudit === "true",
    admin: shell.dataset.canAdmin === "true"
  };
  var canList = can.operate || can.audit;
  var statusEl = byId("drop-status");
  var state = { requests: [], brokers: [], waiting: [], keys: [], dependencies: {} };
  var outcomeRow = null;
  var settled = null;

  var TYPE = { DataDeletion: "Delete their data", OptOut: "Stop selling or sharing" };
  var LANGUAGE = { en: "English", es: "Spanish", zh: "Chinese", vi: "Vietnamese", tl: "Tagalog", ko: "Korean" };
  var RESULT = {
    PENDING: ["In progress", "info"], DELETED: ["Data deleted", "active"], OPTED_OUT: ["Opted out", "active"],
    EXEMPTED: ["Exempt", "warn"], NOT_FOUND: ["No data found", "active"]
  };
  var CHANGE = {
    enroll_broker: "Add a data broker", revoke_broker: "Remove a data broker", import_record: "Add a DROP request",
    revoke_record: "Withdraw a DROP request", approve_outcome: "Approve a result", rotate_key: "Replace the signing key",
    retire_key: "Retire an old signing key", revoke_key: "Block an old signing key", record_key_migration: "Record a signing key move"
  };
  var KEY_STATE = { current: ["In use", "active"], previous: ["Replaced", "warn"], retired: ["Retired", "idle"], revoked: ["Blocked", "blocked"] };
  var TEMPLATE_RE = /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-5][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$/;

  function byId(id) { return document.getElementById(id); }
  function say(text) { window.mvStatus(statusEl, text); }
  function fail(failure, action) { say(R.errorText(failure, action)); }
  function language(code) { return LANGUAGE[String(code || "").toLowerCase()] || String(code || "").toUpperCase(); }
  function brokerName(ref) { return R.human(ref); }
  function badge(map, value) { var s = map[value] || [R.human(value), "info"]; return R.badge(s[0], s[1]); }
  function nowSeconds() { return Math.floor(Date.now() / 1000); }

  async function request(path, method, body) {
    var settings = {
      method: method || "GET",
      cache: "no-store",
      credentials: "same-origin",
      headers: { Accept: "application/json" }
    };
    if (body !== undefined) {
      settings.headers["Content-Type"] = "application/json";
      settings.body = JSON.stringify(body);
    }
    return parseResponse(await fetch(apiBase + path, settings));
  }

  async function fileFingerprint(input, label) {
    var file = input && input.files && input.files[0];
    if (!file) { var missing = new Error(label); missing.code = "missing_file"; throw missing; }
    var result = await R.fingerprint(file);
    return result.sha256;
  }

  async function propose(path, body, doneText) {
    await request("/authority/" + path, "POST", Object.assign({}, body, { idempotency_key: R.newKey() }));
    say(doneText || "Sent for approval. A different administrator must approve it under “Waiting for a second administrator”.");
    await load();
  }

  // ---- readiness ---------------------------------------------------------------
  async function refreshStatus() {
    var el = byId("drop-readiness");
    try {
      var st = await request("/status");
      settled = st;
      if (st.ready === true) {
        el.textContent = "Ready: California DROP requests are set up for this workspace.";
      } else if (st.enabled !== true) {
        el.textContent = "California DROP requests are turned off. Ask whoever runs Lightwork to turn them on, together with privacy request handling.";
      } else {
        var missing = [];
        var config = st.configuration || {};
        var counts = st.authority_counts || {};
        if (config.store_factory_configured === false || config.authority_resolver_configured === false) missing.push("request storage has not been set up");
        if (!counts.active_brokers) missing.push("no data broker has been added");
        if (!counts.active_records) missing.push("no DROP request has been added");
        if (!missing.length) missing.push("the setup has not been checked yet");
        el.textContent = "Not ready yet: " + missing.join("; ") + ".";
      }
    } catch (failure) {
      el.textContent = R.errorText(failure, "check whether DROP requests are set up");
    }
    return settled;
  }

  // Replace every list's "Loading…" placeholder with a plain sentence, so a
  // turned-off or unreachable feature never looks like it is still loading.
  function showNothing(text) {
    ["drop-requests", "drop-waiting", "drop-brokers"].forEach(function (id) {
      var box = byId(id);
      if (!box) return;
      var note = document.createElement("p");
      note.className = "muted";
      note.textContent = text;
      box.replaceChildren(note);
    });
    var broker = byId("drop-import-broker");
    if (broker) {
      var option = document.createElement("option");
      option.value = "";
      option.textContent = "No data brokers available";
      broker.replaceChildren(option);
    }
  }

  // ---- loading -------------------------------------------------------------------
  async function load() {
    if (!canList) { renderLookup(); return; }
    try {
      var overview = await request("/authority/overview");
      state.requests = overview.requests || [];
      state.brokers = overview.brokers || [];
      state.waiting = overview.waiting || [];
      render();
    } catch (failure) {
      fail(failure, "load the DROP requests");
      showNothing("Nothing to show right now. Reload the page to try again.");
    }
  }

  function activeOutcome(row) {
    return (row.outcomes || []).filter(function (o) { return o.state === "active"; })[0] || null;
  }
  function outcomeFor(row, status) {
    return (row.outcomes || []).filter(function (o) { return o.status === status; })[0] || null;
  }
  function requestStatus(row) {
    if (!row.usable) return R.badge(row.state === "revoked" ? "Withdrawn" : "Past its handle-by date", "idle");
    if (!row.request) return R.badge("Not started", "warn");
    if (row.request.status === "PENDING" && activeOutcome(row)) return R.badge("Result approved, ready to close", "info");
    return badge(RESULT, row.request.status);
  }

  function render() {
    R.table(byId("drop-requests"), [
      { label: "DROP request", value: function (r) { return String(r.drop_id); } },
      { label: "Asked for", value: function (r) { return TYPE[r.request_type] || R.human(r.request_type); } },
      { label: "Reply language", value: function (r) { return language(r.language); } },
      { label: "Handle by", value: function (r) { return R.day(r.valid_until); } },
      { label: "Status", value: requestStatus }
    ], state.requests, [
      { label: "Start", kind: "primary", when: function (r) { return can.operate && r.usable && !r.request; }, run: startRequest },
      { label: "Record the result", when: function (r) { return can.admin && r.usable && r.request && r.request.status === "PENDING" && !activeOutcome(r); }, run: openOutcome },
      { label: "Close request", kind: "primary", when: function (r) { return can.admin && r.usable && r.request && r.request.status === "PENDING" && activeOutcome(r); }, run: closeRequest },
      { label: "Withdraw", kind: "danger", when: function (r) { return can.admin && r.state === "active"; }, run: withdrawRecord }
    ], { text: can.admin ? "No DROP requests yet. Use “Add a DROP request” when DROP sends you one." : "No DROP requests yet. They appear here when an administrator adds one." });

    var waiting = byId("drop-waiting");
    if (waiting) {
      R.table(waiting, [
        { label: "Change", value: function (w) { return CHANGE[w.kind] || R.human(w.kind); } },
        { label: "Details", value: describe },
        { label: "Proposed", value: function (w) { return R.when(w.created_at); } },
        { label: "By", value: function (w) { return w.proposed_by_you ? "You" : "Another administrator"; } }
      ], state.waiting, [
        { label: "Approve", kind: "primary", when: function (w) { return can.admin && !w.proposed_by_you; }, run: approve }
      ], { text: "Nothing is waiting for approval." });
    }

    var brokers = byId("drop-brokers");
    if (brokers) {
      R.table(brokers, [
        { label: "Data broker", value: function (b) { return brokerName(b.broker_ref); } },
        { label: "Status", value: function (b) { return b.state === "active" ? R.badge("Active", "active") : R.badge("Removed", "idle"); } },
        { label: "Registration valid until", value: function (b) { return b.valid_until ? R.day(b.valid_until) : ""; } }
      ], state.brokers, [
        { label: "Remove", kind: "danger", when: function (b) { return can.admin && b.state === "active"; }, run: removeBroker }
      ], { text: can.admin ? "No data brokers yet. Add the broker registration your DROP requests arrive under." : "No data brokers yet. They appear here when an administrator adds one." });
    }
    fillBrokers();
  }

  function describe(w) {
    var s = w.summary || {};
    var parts = [];
    if (s.drop_id) parts.push("DROP request " + s.drop_id);
    if (s.broker_ref) parts.push(brokerName(s.broker_ref));
    if (s.request_type) parts.push(TYPE[s.request_type] || R.human(s.request_type));
    if (s.status) parts.push((RESULT[s.status] || [R.human(s.status)])[0]);
    if (s.key_revision) parts.push("Key " + s.key_revision);
    if (s.valid_until) parts.push("until " + R.day(s.valid_until));
    return parts.join(" · ");
  }

  // Everyone else can still look a request up by the number they were given.
  function renderLookup() {
    var box = byId("drop-requests");
    box.textContent = "";
    box.appendChild(R.button("Look up a request", "primary", async function () {
      var values = await R.form("Look up a DROP request", [
        { key: "number", label: "DROP request number", type: "number", required: true }
      ], "Look up");
      if (!values) return;
      var number = Number(values.number);
      if (!Number.isSafeInteger(number) || number < 1 || number > 2147483647) { say("Enter the request number as a whole number."); return; }
      try {
        var found = await request("/" + encodeURIComponent(number));
        say("DROP request " + number + ": " + (RESULT[found.status] || [R.human(found.status)])[0] + ". Last updated " + R.when(found.updated_at) + ".");
      } catch (failure) {
        if (failure && failure.status === 404) { say("There is no DROP request " + number + " in progress here."); return; }
        fail(failure, "look up the request");
      }
    }));
  }

  // ---- request actions -------------------------------------------------------------
  async function startRequest(row) {
    if (!(await R.confirm("Start work on DROP request " + row.drop_id + "? Lightwork opens a privacy request for your team to handle.", "Start"))) return;
    try {
      var dropId = row.drop_id;
      await request("/" + encodeURIComponent(dropId) + "/request", "POST", {
        request_type: row.request_type, template_id: row.template_id, language: row.language,
        expected_revision: 0, idempotency_key: R.newKey()
      });
      say("DROP request " + row.drop_id + " started.");
      await load();
    } catch (failure) { fail(failure, "start the request"); }
  }

  async function closeRequest(row) {
    var outcome = activeOutcome(row);
    var label = (RESULT[outcome.status] || [R.human(outcome.status)])[0];
    if (!(await R.confirm("Close DROP request " + row.drop_id + " as “" + label + "”? This cannot be undone.", "Close request"))) return;
    try {
      var dropId = row.drop_id;
      await request("/" + encodeURIComponent(dropId), "PUT", {
        status: outcome.status, expected_revision: row.request.revision, idempotency_key: R.newKey()
      });
      say("DROP request " + row.drop_id + " closed as “" + label + "”.");
      await load();
    } catch (failure) { fail(failure, "close the request"); }
  }

  async function withdrawRecord(row) {
    if (!(await R.confirm("Withdraw DROP request " + row.drop_id + "? Next, choose the file that shows why. A second administrator must approve.", "Choose file"))) return;
    var file = await R.pickFile();
    if (!file) { say("Nothing was sent. Choose a file to withdraw the request."); return; }
    try {
      var digest = (await R.fingerprint(file)).sha256;
      await propose("records/proposals", { action: "revoke_record", drop_id: row.drop_id, evidence_sha256: digest, expected_version: row.version });
    } catch (failure) { fail(failure, "send the withdrawal for approval"); }
  }

  function openPanel(id) {
    var panel = byId(id);
    panel.hidden = false;
    if (typeof panel.scrollIntoView === "function") panel.scrollIntoView({ block: "start" });
  }
  Array.prototype.forEach.call(document.querySelectorAll("[data-close]"), function (btn) {
    btn.addEventListener("click", function () { byId(btn.getAttribute("data-close")).hidden = true; });
  });

  function openOutcome(row) {
    outcomeRow = row;
    byId("drop-outcome-for").textContent = "DROP request " + row.drop_id + " · " + (TYPE[row.request_type] || "");
    byId("drop-outcome-status").value = row.request_type === "OptOut" ? "OPTED_OUT" : "DELETED";
    byId("drop-outcome-observed").value = R.isoDateIn(0);
    byId("drop-outcome-until").value = R.isoDateIn(30);
    openPanel("drop-outcome-panel");
  }

  var outcomeForm = byId("drop-outcome-form");
  if (outcomeForm) outcomeForm.addEventListener("submit", async function (event) {
    event.preventDefault();
    var row = outcomeRow;
    if (!row) return;
    var status = byId("drop-outcome-status").value;
    var observed = R.toEpoch(byId("drop-outcome-observed").value);
    var until = R.toEpoch(byId("drop-outcome-until").value);
    if (!observed || !until) { say("Choose both dates."); return; }
    if (until <= nowSeconds()) { say("The evidence must still be valid after today."); return; }
    var previous = outcomeFor(row, status);
    try {
      var digest = await fileFingerprint(byId("drop-outcome-evidence"), "Choose the evidence file.");
      await propose("outcomes/proposals", {
        drop_id: row.drop_id, status: status, evidence_sha256: digest,
        evidence_revision: previous ? previous.version + 1 : 1,
        observed_at: Math.min(observed, nowSeconds()), valid_until: until,
        deletion_verified: byId("drop-check-deletion").checked, opt_out_verified: byId("drop-check-optout").checked,
        search_complete: byId("drop-check-search").checked, exemption_approved: byId("drop-check-exemption").checked,
        provider_operations_complete: byId("drop-check-providers").checked,
        expected_version: previous ? previous.version : 0
      });
      outcomeForm.reset();
      byId("drop-outcome-panel").hidden = true;
    } catch (failure) {
      if (failure && failure.code === "missing_file") { say(failure.message); return; }
      fail(failure, "send the result for approval");
    }
  });

  // ---- adding requests and brokers -----------------------------------------------------
  function fillBrokers() {
    var select = byId("drop-import-broker");
    if (!select) return;
    var active = state.brokers.filter(function (b) { return b.state === "active" && b.registration_sha256; });
    select.textContent = "";
    var first = R.el("option", "", active.length ? "Choose a data broker" : "Add a data broker first");
    first.value = "";
    select.appendChild(first);
    active.forEach(function (b) {
      var option = R.el("option", "", brokerName(b.broker_ref));
      option.value = b.broker_ref;
      select.appendChild(option);
    });
  }

  var importButton = byId("drop-import");
  if (importButton) importButton.addEventListener("click", function () {
    byId("drop-import-until").value = R.isoDateIn(45);
    openPanel("drop-import-panel");
  });
  var importForm = byId("drop-import-form");
  if (importForm) importForm.addEventListener("submit", async function (event) {
    event.preventDefault();
    var number = Number(byId("drop-import-number").value);
    if (!Number.isSafeInteger(number) || number < 1 || number > 2147483647) { say("Enter the DROP request number as a whole number."); return; }
    var brokerRef = byId("drop-import-broker").value;
    var broker = state.brokers.filter(function (b) { return b.broker_ref === brokerRef; })[0];
    if (!broker) { say("Choose the data broker this request arrived under."); return; }
    var template = byId("drop-import-template").value.trim();
    if (!TEMPLATE_RE.test(template)) { say("Enter the reply template number exactly as DROP shows it."); return; }
    var until = R.toEpoch(byId("drop-import-until").value);
    if (!until || until <= nowSeconds()) { say("Choose a handle-by date after today."); return; }
    var existing = state.requests.filter(function (r) { return r.drop_id === number; })[0];
    try {
      var match = await fileFingerprint(byId("drop-import-match"), "Choose the identity match file from DROP.");
      var evidence = await fileFingerprint(byId("drop-import-evidence"), "Choose the copy of the DROP record.");
      await propose("records/proposals", {
        action: "import_record", drop_id: number, broker_ref: broker.broker_ref,
        broker_registration_sha256: broker.registration_sha256, subject_binding_sha256: match,
        request_type: byId("drop-import-type").value, template_id: template.toLowerCase(),
        language: byId("drop-import-language").value, record_revision: 1, valid_until: until,
        evidence_sha256: evidence, expected_version: existing ? existing.version : 0
      });
      importForm.reset();
      byId("drop-import-panel").hidden = true;
    } catch (failure) {
      if (failure && failure.code === "missing_file") { say(failure.message); return; }
      fail(failure, "send the request for approval");
    }
  });

  var brokerButton = byId("drop-add-broker");
  if (brokerButton) brokerButton.addEventListener("click", function () {
    byId("drop-broker-until").value = R.isoDateIn(365);
    openPanel("drop-broker-panel");
  });
  var brokerForm = byId("drop-broker-form");
  if (brokerForm) brokerForm.addEventListener("submit", async function (event) {
    event.preventDefault();
    var ref = R.slug(byId("drop-broker-name").value, "");
    if (!ref) { say("Enter the broker name."); return; }
    var until = R.toEpoch(byId("drop-broker-until").value);
    if (!until || until <= nowSeconds()) { say("Choose a date after today."); return; }
    var existing = state.brokers.filter(function (b) { return b.broker_ref === ref; })[0];
    try {
      var registration = await fileFingerprint(byId("drop-broker-registration"), "Choose the registration document.");
      var evidence = await fileFingerprint(byId("drop-broker-evidence"), "Choose the proof of registration.");
      await propose("brokers/proposals", {
        action: "enroll_broker", broker_ref: ref, registration_sha256: registration,
        evidence_sha256: evidence, valid_until: until, expected_version: existing ? existing.version : 0
      });
      brokerForm.reset();
      byId("drop-broker-panel").hidden = true;
    } catch (failure) {
      if (failure && failure.code === "missing_file") { say(failure.message); return; }
      fail(failure, "send the broker for approval");
    }
  });

  async function removeBroker(broker) {
    if (!(await R.confirm("Remove " + brokerName(broker.broker_ref) + "? New DROP requests cannot be added under it. Next, choose the file that shows why.", "Choose file"))) return;
    var file = await R.pickFile();
    if (!file) { say("Nothing was sent. Choose a file to remove the broker."); return; }
    try {
      var digest = (await R.fingerprint(file)).sha256;
      await propose("brokers/proposals", { action: "revoke_broker", broker_ref: broker.broker_ref, evidence_sha256: digest, expected_version: broker.version });
    } catch (failure) { fail(failure, "send the removal for approval"); }
  }

  var reviewGeneration = 0, reviewing = false;
  function clearReview() {
    reviewGeneration += 1;
    if (reviewing) { var cancel = byId("mv-confirm-cancel"); if (cancel) cancel.click(); }
  }
  [window, document].forEach(function (target) { ["lightwork:workspace-changed", "lightwork:account-context-changed"].forEach(function (name) { target.addEventListener(name, clearReview); }); });
  async function confirmReview(text) {
    var dialog = byId("mv-confirm"), message = byId("mv-confirm-msg");
    if (dialog && dialog.open) return false;
    var previous = message ? message.style.cssText : "";
    var answer = R.confirm(text, "Approve this exact change"); reviewing = true;
    if (message) { message.style.whiteSpace = "pre-wrap"; message.style.overflowWrap = "anywhere"; message.style.maxHeight = "60vh"; message.style.overflowY = "auto"; }
    try { return await answer; }
    finally { reviewing = false; if (message) { message.textContent = ""; message.style.cssText = previous; } }
  }
  async function approve(change) {
    var generation = reviewGeneration;
    try {
      var review = await request("/authority/proposals/" + encodeURIComponent(change.proposal_id) + "/review");
      if (generation !== reviewGeneration) return;
      if (review.proposal.revision !== change.revision || review.proposal.kind !== change.kind || review.proposed_by_you) {
        say("The change is no longer available for your independent approval. Refresh the list."); return;
      }
      var labels = {action: "Change", broker_ref: "Data broker", drop_id: "DROP request", status: "Result", request_type: "Requested action", language: "Reply language", valid_until: "Valid until", observed_at: "Evidence recorded on", expected_version: "Current source version", record_revision: "Request version", evidence_revision: "Evidence version", deletion_verified: "Deletion checked", opt_out_verified: "Opt-out checked", search_complete: "Search completed", exemption_approved: "Exemption approved", provider_operations_complete: "Work in connected services completed", expected_current_revision: "Current signing key version", key_revision: "Signing key version", from_revision: "Previous key version", to_revision: "New key version", objects_migrated: "Records moved", remaining_dependencies: "Records still depending on the old key", template_id: "Privacy request form", migration_id: "Key change record", registration_sha256: "Registration file identity", evidence_sha256: "Evidence file identity", broker_registration_sha256: "Broker registration file identity", subject_binding_sha256: "Protected person identity", new_key_ref: "Protected signing key reference"};
      var text = "Review “" + (CHANGE[change.kind] || R.human(change.kind)) + "”\n\n" + Object.keys(review.contents).map(function (key) {
        if (!labels[key]) throw new Error("This change contains information this view cannot explain. Nothing was approved.");
        var value = review.contents[key];
        if (value && typeof value === "object") throw new Error("The complete change could not be shown. Nothing was approved.");
        return labels[key] + ": " + (value === true ? "Yes" : value === false ? "No" : value === null ? "Not provided" : key === "valid_until" || key === "observed_at" ? R.when(value) : key === "action" && CHANGE[value] ? CHANGE[value] : typeof value === "number" || /sha256$/.test(key) || key === "new_key_ref" || key === "template_id" ? String(value) : R.human(value));
      }).join("\n") + "\nKeep this review until: " + R.when(review.proposal.retained_until) +
        "\n\nRecorded file identities do not show the original files. Check those files through your organization's approved channel. Approval records a local decision and can take effect immediately; it does not prove an outside result.";
      if (!(await confirmReview(text)) || generation !== reviewGeneration) return;
      await request("/authority/proposals/" + encodeURIComponent(change.proposal_id) + "/approve", "POST",
        { expected_revision: review.proposal.revision, idempotency_key: R.newKey() });
      say("Approved. The change is now in effect.");
      await load();
    } catch (failure) {
      if (failure && failure.status === 409) { say("This change could not be approved. Changes cannot be approved by the person who proposed them, and the records may have changed since. Refresh and check."); return; }
      fail(failure, "approve the change");
    }
  }

  // ---- integrity ----------------------------------------------------------------------
  var integrity = byId("drop-integrity");
  if (integrity) integrity.addEventListener("click", async function () {
    try {
      await request("/integrity");
      await request("/authority/integrity");
      say("All DROP records are intact.");
    } catch (failure) {
      if (failure && failure.status === 503) { say("A problem was found in the DROP records. Tell whoever runs Lightwork before closing more requests."); return; }
      fail(failure, "check the records");
    }
  });

  // ---- signing key (advanced) --------------------------------------------------------------
  function currentKey() { return state.keys.filter(function (k) { return k.state === "current"; })[0] || null; }

  async function loadKeys() {
    var box = byId("drop-keys");
    try {
      var data = await request("/authority/revisions");
      state.keys = data.keys || [];
      state.dependencies = data.dependency_counts || {};
      R.table(box, [
        { label: "Key", value: function (k) { return "Key " + k.revision; } },
        { label: "Status", value: function (k) { return badge(KEY_STATE, k.state); } },
        { label: "Since", value: function (k) { return R.day(k.created_at); } },
        { label: "Records still using it", value: function (k) { var n = state.dependencies[k.revision]; return n === undefined ? "" : String(n); } }
      ], state.keys, [
        { label: "Record data moved", when: function (k) { return can.admin && k.state === "previous"; }, run: recordMove },
        { label: "Retire", when: function (k) { return can.admin && k.state === "previous"; }, run: function (k) { retireKey(k, false); } },
        { label: "Block", kind: "danger", when: function (k) { return can.admin && k.state === "previous"; }, run: function (k) { retireKey(k, true); } }
      ], { text: "No signing key has been set up yet." });
    } catch (failure) {
      box.textContent = R.errorText(failure, "load the signing key history");
    }
  }
  var keysPanel = byId("drop-keys-panel");
  if (keysPanel) keysPanel.addEventListener("toggle", function () { if (keysPanel.open) loadKeys(); });

  async function retireKey(key, block) {
    var text = block
      ? "Block key " + key.revision + "? Anything still signed with it can no longer be checked. Use this only if the key may have leaked."
      : "Retire key " + key.revision + "? Do this once nothing uses it any more.";
    if (!(await R.confirm(text, block ? "Block key" : "Retire key"))) return;
    try {
      await propose("keys/proposals", { action: block ? "revoke_key" : "retire_key", key_revision: key.revision });
      await loadKeys();
    } catch (failure) { fail(failure, block ? "block the key" : "retire the key"); }
  }

  async function recordMove(key) {
    var current = currentKey();
    if (!current) { say("There is no key in use to move to."); return; }
    var remaining = state.dependencies[key.revision];
    var values = await R.form("Record data moved from key " + key.revision + " to key " + current.revision, [
      { key: "moved", label: "Records moved", type: "number", required: true, default: 0 },
      { key: "remaining", label: "Records still to move", type: "number", required: true, default: remaining === undefined ? 0 : remaining }
    ], "Send for approval");
    if (!values) return;
    var moved = Number(values.moved), left = Number(values.remaining);
    if (!Number.isSafeInteger(moved) || moved < 0 || !Number.isSafeInteger(left) || left < 0) { say("Enter whole numbers of 0 or more."); return; }
    try {
      await propose("keys/proposals", {
        action: "record_key_migration", migration_id: R.newId("key-move"), from_revision: key.revision,
        to_revision: current.revision, objects_migrated: moved, remaining_dependencies: left
      });
    } catch (failure) { fail(failure, "record the move"); }
  }

  var rotate = byId("drop-rotate");
  if (rotate) rotate.addEventListener("click", async function () {
    if (!state.keys.length) await loadKeys();
    var current = currentKey();
    var values = await R.form("Replace the signing key", [
      { key: "location", label: "Where the new key is kept (from your key vault)", type: "text", required: true }
    ], "Continue");
    if (!values) return;
    var location = String(values.location || "").trim();
    if (!/^(?:env:[A-Z][A-Z0-9_]{0,127}|(?:kms|secret|vault|aws-kms|azure-keyvault|gcp-kms):\/\/[A-Za-z0-9][A-Za-z0-9_./:@+\-]{0,239})$/.test(location)) {
      say("Enter the key location exactly as your key vault shows it. Ask whoever manages your keys.");
      return;
    }
    if (!(await R.confirm("Replace the signing key? Existing records keep working and a second administrator must approve.", "Send for approval"))) return;
    try {
      await propose("keys/proposals", { action: "rotate_key", new_key_ref: location, expected_current_revision: current ? current.revision : 1 });
    } catch (failure) { fail(failure, "send the key change for approval"); }
  });

  // Only ask for the lists when the feature is on: a turned-off feature has no
  // requests, and asking would only fail. If the check itself fails, try anyway.
  refreshStatus().then(function (st) {
    if (st && st.enabled === false) {
      showNothing("Nothing to show: California DROP requests are turned off. An administrator can turn them on in Settings.");
      return;
    }
    return load();
  });
})();
