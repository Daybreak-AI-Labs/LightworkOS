(function () {
  "use strict";

  var root = document.getElementById("elv-root");
  if (!root) { return; }

  var apiBase = root.dataset.apiBase || "/api/v1/audit/evolution-ledger";
  var maxResponseBytes = 1024 * 1024;
  var maxReceiptBytes = 64 * 1024;
  var maxEntries = 500;
  var healthDetail = document.getElementById("elv-health-detail");
  var errorEl = document.getElementById("elv-error");
  var entriesBody = document.getElementById("elv-entries");
  var limitations = document.getElementById("elv-limitations");
  var LOAD_FAILED = "We could not load the learning history. Select Refresh; if it keeps failing, contact your administrator.";

  var KIND = { promotion: "Adopted a learning change", rollback: "Restored an earlier learning state" };
  var INTEGRITY = {
    hash_chained_local_promotion_ledger: "Stored chain checks match",
    legacy_projection_promotion_ledger: "Older format; no sealed history",
    in_memory_promotion_ledger: "Not sealed (temporary record)",
    runtime_supplied: "Not sealed"
  };
  var APPROVAL = {
    verified: "Yes, confirmed",
    not_recorded: "No approval recorded",
    not_applicable: "Not needed",
    not_verifiable_without_private_binding: "Recorded, cannot be confirmed here",
    receipt_invalid: "Receipt not valid",
    private_binding_invalid: "Could not be confirmed",
    private_binding_mismatch: "Does not match",
    signature_untrusted_or_invalid: "Signature not trusted",
    approval_signer_key_id_mismatch: "Signed by an unexpected key"
  };
  var LIMITS = {
    promotion_ledger_not_present: "No adopted changes are recorded in this history yet. Changes appear here once a suggested change is adopted.",
    promotion_ledger_is_local_not_externally_anchored: "This history is kept in this installation. A separately trusted copy is needed to detect replacement of the whole history.",
    promotion_ledger_has_no_hash_chained_journal: "These older records have no sealed history. Their current fingerprints do not establish that earlier records were unchanged.",
    promotion_ledger_is_not_durable: "This history exists only temporarily and will not survive a restart.",
    dashboard_projects_only_digest_only_promotion_history: "This page shows fingerprints and outcomes only, never the learned content itself.",
    dreaming_hindsight_and_runtime_proof_sources_are_not_exposed_here: "Overnight learning runs and learning checks are shown on the Learning page, not here.",
    receipt_integrity_is_not_a_human_approval_verification: "Matching receipt fingerprints do not establish who created or approved a receipt, or whether the whole history was replaced.",
    human_approval_signature_not_verifiable_from_receipt: "A person’s approval signature cannot be checked from the receipt alone. Open the approval in Lightwork to check it.",
    approval_signature_requires_private_binding_verification: "Confirming the approval needs private records that stay on the server.",
    workspace_snapshot_digest_not_recorded: "Some older records do not include a fingerprint of the workspace.",
    runtime_artifact_binding_not_recorded: "Some older records do not name the exact files that changed."
  };

  function human(v) { return window.mvHuman ? window.mvHuman(v) : String(v || ""); }
  function plain(map, v) { return typeof v === "string" ? (map[v] || human(v)) : "—"; }
  function fail(message) { var error = new Error(message); error.plain = true; return error; }
  function showError(error, action) {
    errorEl.textContent = error && error.plain ? error.message : (error && (error.status || error.name) ? window.mvErrorText(error, action) : LOAD_FAILED);
  }
  function byteLength(text) { return new TextEncoder().encode(String(text || "")).length; }

  async function readBody(response) {
    var declared = Number(response.headers.get("content-length") || 0);
    if (declared > maxResponseBytes) {
      if (response.body && typeof response.body.cancel === "function") { await response.body.cancel(); }
      throw fail(LOAD_FAILED);
    }
    if (!response.body || typeof response.body.getReader !== "function") {
      var fallback = await response.text();
      if (byteLength(fallback) > maxResponseBytes) { throw fail(LOAD_FAILED); }
      return fallback;
    }
    var reader = response.body.getReader();
    var chunks = [];
    var total = 0;
    try {
      while (true) {
        var next = await reader.read();
        if (next.done) { break; }
        total += next.value.byteLength;
        if (total > maxResponseBytes) { await reader.cancel(); throw fail(LOAD_FAILED); }
        chunks.push(next.value);
      }
    } finally {
      reader.releaseLock();
    }
    var result = new Uint8Array(total);
    var position = 0;
    chunks.forEach(function (chunk) { result.set(chunk, position); position += chunk.byteLength; });
    try { return new TextDecoder("utf-8", { fatal: true }).decode(result); }
    catch (_error) { throw fail(LOAD_FAILED); }
  }

  async function readJson(response, action) {
    if (!response.ok) { throw fail(window.mvErrorText(response, action)); }
    var text = await readBody(response);
    try { return text ? JSON.parse(text) : {}; }
    catch (_error) { throw fail(LOAD_FAILED); }
  }

  async function request(path, options) {
    var controller = new AbortController();
    var timeout = setTimeout(function () { controller.abort(); }, 15000);
    var settings = Object.assign(
      { credentials: "same-origin", headers: { Accept: "application/json" }, signal: controller.signal },
      options || {}
    );
    if (settings.body) { settings.headers["Content-Type"] = "application/json"; }
    try {
      return await fetch(apiBase + path, settings);
    } finally {
      clearTimeout(timeout);
    }
  }

  function cell(text, label) { var td = document.createElement("td"); td.textContent = text; td.dataset.label = label; return td; }

  function auditCell(entry) {
    var td = document.createElement("td");
    td.dataset.label = 'Receipt';
    if (typeof entry.entry_sha256 === 'string' && /^[0-9a-f]{64}$/.test(entry.entry_sha256)) {
      var download = document.createElement('a'); download.className = 'btn btn--ghost';
      download.textContent = 'Download receipt';
      download.href = apiBase + '/entries/' + entry.entry_sha256 + '/receipt';
      var downloading = false;
      download.addEventListener('click', async function (event) {
        event.preventDefault(); if (downloading) return;
        downloading = true; download.setAttribute('aria-disabled', 'true');
        try {
          var response = await request('/entries/' + entry.entry_sha256 + '/receipt');
          if (!response.ok) throw fail('That recorded receipt is unavailable. Refresh Learning history before trying again.');
          var content = await readBody(response);
          if (byteLength(content) > maxReceiptBytes) throw fail('That receipt could not be safely downloaded.');
          var url = URL.createObjectURL(new Blob([content], {type: 'application/json'}));
          var save = document.createElement('a'); save.href = url;
          save.download = 'learning-receipt-' + entry.entry_sha256.slice(0, 16) + '.json';
          document.body.appendChild(save); save.click(); save.remove();
          setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
          errorEl.textContent = '';
        } catch (error) { showError(error, 'download the recorded receipt'); }
        finally { downloading = false; download.removeAttribute('aria-disabled'); }
      });
      td.appendChild(download);
    }
    var details = document.createElement("details");
    var summary = document.createElement("summary");
    summary.textContent = "Fingerprints";
    details.appendChild(summary);
    [["Record", entry.entry_sha256], ["Receipt", entry.promotion_receipt_sha256]].forEach(function (pair) {
      if (typeof pair[1] !== "string" || !/^[0-9a-f]{64}$/.test(pair[1])) { return; }
      var p = document.createElement("p");
      p.className = "elv-key";
      p.textContent = pair[0] + ": " + pair[1];
      details.appendChild(p);
    });
    td.appendChild(details);
    return td;
  }

  function when(value) {
    var timestamp = Number(value);
    if (!Number.isFinite(timestamp) || timestamp <= 0) { return "—"; }
    return window.mvWhen ? window.mvWhen(timestamp) : new Date(timestamp * 1000).toLocaleString();
  }

  function renderEntries(entries) {
    entriesBody.textContent = "";
    if (!entries.length) {
      var empty = document.createElement("tr");
      var td = document.createElement("td");
      td.colSpan = 5;
      td.appendChild(document.createTextNode("No adopted learning changes are recorded in this history yet. "));
      var link = document.createElement("a");
      link.className = "btn btn--ghost";
      link.href = "/learning";
      link.textContent = "See what Lightwork is learning";
      td.appendChild(link);
      empty.appendChild(td);
      entriesBody.appendChild(empty);
      return;
    }
    entries.slice().reverse().forEach(function (entry) {
      var row = document.createElement("tr");
      row.appendChild(cell(when(entry.occurred_at), 'When'));
      row.appendChild(cell(plain(KIND, entry.kind), 'What happened'));
      row.appendChild(cell(plain(INTEGRITY, entry.integrity), 'Stored record check'));
      row.appendChild(cell(plain(APPROVAL, entry.approval_status), 'Approved by a person'));
      row.appendChild(auditCell(entry));
      entriesBody.appendChild(row);
    });
  }

  function renderLimitations(items) {
    limitations.textContent = "";
    var list = items.slice(0, 32).map(function (item) { return LIMITS[item] || human(item) + "."; });
    if (!list.length) { list = ["Nothing further to note."]; }
    list.forEach(function (text) {
      var li = document.createElement("li");
      li.textContent = text;
      limitations.appendChild(li);
    });
  }

  function renderSnapshot(payload) {
    if (!payload || payload.schema !== "lightwork.evolution-ledger-dashboard-snapshot.v1") { throw fail(LOAD_FAILED); }
    var projection = payload.projection;
    var sources = payload.sources;
    if (!projection || typeof projection !== "object" || !Array.isArray(projection.entries) || !sources || typeof sources !== "object") {
      throw fail(LOAD_FAILED);
    }
    if (projection.entries.length > maxEntries) { throw fail(LOAD_FAILED); }
    var entries = projection.entries;
    document.getElementById("elv-entry-count").textContent = String(projection.entry_count || 0);
    document.getElementById("elv-promotions").textContent = String(entries.filter(function (e) { return e && e.kind === "promotion"; }).length);
    document.getElementById("elv-rollbacks").textContent = String(entries.filter(function (e) { return e && e.kind === "rollback"; }).length);
    var total = Number(projection.total_entries || 0);
    document.getElementById("elv-table-note").textContent = projection.truncated
      ? "Showing the newest " + (projection.entry_count || 0) + " of " + total + " records."
      : (total === 1 ? "1 record." : total + " records.");
    renderEntries(entries);
    renderLimitations(Array.isArray(projection.limitations) ? projection.limitations : []);
    healthDetail.textContent = sources.promotion_ledger === "available" ? "Stored history checked." : "No adopted changes are recorded in this history yet. Changes appear here once a suggested change is adopted.";
    errorEl.textContent = "";
  }

  async function loadSnapshot() {
    healthDetail.textContent = "Loading.";
    try {
      renderSnapshot(await readJson(await request("/snapshot"), "load the learning history"));
    } catch (error) {
      healthDetail.textContent = "";
      showError(error, "load the learning history");
    }
  }

  function renderReceiptVerdict(result) {
    var box = document.getElementById("elv-verdict-box");
    var verdict = document.getElementById("elv-verdict");
    var detail = document.getElementById("elv-verdict-detail");
    var valid = result && result.receipt_valid === true;
    box.hidden = false;
    verdict.dataset.valid = valid && result.recorded_in_current_history === true ? "true" : "false";
    verdict.textContent = valid ? (result.recorded_in_current_history === true
      ? "This receipt matches a change in the current workspace history."
      : "The receipt contents match their fingerprint, but no matching change was found in the current workspace history.") :
      "This receipt could not be confirmed. It may have been changed, or it is not a Lightwork receipt. Ask for the original file.";
    detail.textContent = (result && result.checked_at && window.mvWhen ? "Checked " + window.mvWhen(result.checked_at) + ". " : "") +
      "Approval by a person: " + plain(APPROVAL, result && result.approval_status) +
      ". A matching fingerprint alone does not prove who created this receipt or that the complete history is unchanged.";
  }

  document.getElementById("elv-refresh").addEventListener("click", loadSnapshot);

  document.getElementById("elv-verify-form").addEventListener("submit", function (event) {
    event.preventDefault();
    (async function () {
      var input = document.getElementById("elv-receipt");
      var file = input.files && input.files[0];
      if (!file) { throw fail("Choose a receipt file first."); }
      if (file.size > maxReceiptBytes) { throw fail("That file is too large to be a receipt."); }
      var raw = (await file.text()).trim();
      if (byteLength(raw) > maxReceiptBytes) { throw fail("That file is too large to be a receipt."); }
      var parsed;
      try { parsed = JSON.parse(raw); } catch (_error) { parsed = null; }
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw fail("That file is not a Lightwork receipt.");
      }
      var response = await request("/verify-receipt", { method: "POST", body: JSON.stringify({ receipt: raw }) });
      if (response.status === 422) { throw fail("That file is not a Lightwork receipt."); }
      renderReceiptVerdict(await readJson(response, "check the receipt"));
      errorEl.textContent = "";
    })().catch(function (error) {
      document.getElementById("elv-verdict-box").hidden = true;
      showError(error, "check the receipt");
    });
  });

  loadSnapshot();
})();

/* Complete native history references: retained files never enter Copilot text. */
(function () {
  "use strict";
  var root = document.getElementById("elv-root");
  var form = document.getElementById("elv-checkpoint-form");
  if (!root || !form) { return; }
  var base = (root.dataset.apiBase || "/api/v1/audit/evolution-ledger") + "/checkpoint";
  var input = document.getElementById("elv-checkpoint-file");
  var download = document.getElementById("elv-checkpoint-download");
  var status = document.getElementById("elv-checkpoint-status");
  var result = document.getElementById("elv-checkpoint-result");
  var error = document.getElementById("elv-checkpoint-error");
  var generation = 0, busy = false, available = false, refreshPending = false;
  var controllers = new Set();
  function clearResult() { result.hidden = true; result.textContent = ""; error.textContent = ""; }
  function lock() { form.querySelector("button").disabled = busy; input.disabled = busy; download.disabled = busy || !available; }
  function when(value) { var date = new Date(Number(value) * 1000); return Number.isFinite(date.getTime()) ? date.toLocaleString() : "an unrecorded time"; }
  async function request(path, body) {
    var controller = new AbortController(); controllers.add(controller);
    var timeout = setTimeout(function () { controller.abort(); }, 15000);
    try {
      var response = await fetch(base + path, {method: body ? "POST" : "GET", credentials: "same-origin", cache: "no-store",
        headers: {"Content-Type": "application/json"}, body: body ? JSON.stringify(body) : undefined, signal: controller.signal});
      var chunks = [], total = 0, raw;
      if (Number(response.headers.get("content-length") || 0) > 16384) { throw new Error("The checkpoint response was too large. Refresh before relying on it."); }
      if (response.body && response.body.getReader) {
        var reader = response.body.getReader();
        try {
          while (true) {
            var chunk = await reader.read(); if (chunk.done) { break; }
            total += chunk.value.byteLength;
            if (total > 16384) { await reader.cancel(); throw new Error("The checkpoint response was too large. Refresh before relying on it."); }
            chunks.push(chunk.value);
          }
        } finally { reader.releaseLock(); }
        var bytes = new Uint8Array(total), offset = 0;
        chunks.forEach(function (chunk) { bytes.set(chunk, offset); offset += chunk.byteLength; });
        raw = new TextDecoder("utf-8", {fatal: true}).decode(bytes);
      } else {
        raw = await response.text();
        if (new TextEncoder().encode(raw).length > 16384) { throw new Error("The checkpoint response was too large. Refresh before relying on it."); }
      }
      var value;
      try { value = JSON.parse(raw); } catch (_) { throw new Error("The checkpoint response could not be read. Refresh before relying on it."); }
      if (!response.ok) { throw new Error(typeof value.detail === "string" ? value.detail : "The checkpoint could not be checked. Refresh and choose the original file."); }
      return {value: value, raw: raw};
    } catch (failure) {
      if (failure.name === "AbortError") { throw new Error("The wait ended before the checkpoint result was confirmed. Refresh and try again; no history was changed."); }
      if (failure instanceof TypeError) { throw new Error("The checkpoint could not be reached. Check your connection and refresh; no history was changed."); }
      throw failure;
    } finally { clearTimeout(timeout); controller.abort(); controllers.delete(controller); }
  }
  async function perform(action) {
    if (busy) { return; }
    var current = generation; busy = true; lock(); clearResult();
    try { await action(current); }
    catch (failure) { if (current === generation) { error.textContent = failure.message || "The checkpoint result could not be confirmed. Refresh before relying on it."; } }
    finally {
      if (current === generation) {
        busy = false; lock();
        if (refreshPending) { refreshPending = false; void refresh(); }
      }
    }
  }
  function refresh() {
    if (busy) { refreshPending = true; return; }
    var currentGeneration = generation;
    available = false; status.textContent = "Checking whether a complete checkpoint is available.";
    return perform(async function (current) {
      var checked = (await request("/status")).value;
      if (current !== generation) { return; }
      available = true;
      status.textContent = "The complete supported history contains " + checked.record_count + " stored records, including " + checked.adopted_changes + " adopted changes and " + checked.restorations + " restorations. Checked " + when(checked.checked_at) + ".";
    }).then(function () { if (currentGeneration === generation && !available) { status.textContent = "A complete checkpoint is unavailable. See the explanation below; no partial file was created."; } });
  }
  download.addEventListener("click", function () {
    void perform(async function (current) {
      var response = await request("/download");
      if (current !== generation) { return; }
      var url = URL.createObjectURL(new Blob([response.raw], {type: "application/json"}));
      var link = document.createElement("a"); link.href = url; link.download = "lightwork-learning-history-checkpoint.json";
      document.body.appendChild(link); link.click(); link.remove(); setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
      status.textContent = "A download was offered for all " + response.value.record_count + " stored records, checked " + when(response.value.saved_at) + ". Keep the original file somewhere you trust outside this installation; the browser controls whether it is saved.";
    });
  });
  input.addEventListener("change", clearResult);
  form.addEventListener("submit", function (event) {
    event.preventDefault();
    void perform(async function (current) {
      var file = input.files && input.files[0];
      if (!file) { throw new Error("Choose the original history checkpoint you kept first."); }
      if (file.size > 4096) { throw new Error("Choose the original downloaded checkpoint, 4 KB or smaller."); }
      var raw = await file.text();
      if (new TextEncoder().encode(raw).length > 4096) { throw new Error("Choose the original downloaded checkpoint, 4 KB or smaller."); }
      if (current !== generation) { return; }
      var checked = (await request("/check", {checkpoint: raw})).value;
      if (current !== generation) { return; }
      result.hidden = false; result.dataset.matches = String(checked.matches === true);
      result.textContent = (checked.matches ? "Saved history matches. " : "Saved history does not match. ") + checked.detail +
        " Saved " + when(checked.saved_at) + "; checked " + when(checked.checked_at) + ". The checkpoint covers " + checked.saved_records + " earlier stored records" +
        (checked.matches ? "; " + checked.later_records + " later records are present. " : ". ") + checked.trust;
    });
  });
  document.getElementById("elv-refresh").addEventListener("click", function () { void refresh(); });
  window.addEventListener("lightwork:product-state-changed", function () { void refresh(); });
  document.addEventListener("lightwork:product-operation-complete", function () { void refresh(); });
  document.addEventListener("lightwork:account-context-changed", function () {
    ++generation; controllers.forEach(function (controller) { controller.abort(); }); controllers.clear();
    busy = false; available = false; refreshPending = false; input.value = ""; clearResult(); lock(); void refresh();
  });
  void refresh();
})();
