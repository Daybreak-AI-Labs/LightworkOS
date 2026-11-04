(function () {
  "use strict";

  var MAX_REQUEST_BYTES = 6 * 1024 * 1024;
  var MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
  var MAX_FILE_BYTES = 1024 * 1024;
  var MAX_TOTAL_FILE_BYTES = 4 * 1024 * 1024;
  var shell = document.getElementById("consent-application-scanner-shell");
  if (!shell) return;

  var apiBase = shell.getAttribute("data-api-base") || "";
  var operations = document.getElementById("cas-operations");
  var runtimeStatus = document.getElementById("cas-runtime-status");
  var operationStatus = document.getElementById("cas-operation-status");
  var CW = window.LightworkConsentWorkbench;
  var canAdmin = shell.getAttribute("data-can-admin") === "true";
  var canAudit = shell.getAttribute("data-can-audit") === "true";
  var apps = [];

  function element(id) {
    return document.getElementById(id);
  }

  function byteLength(value) {
    return new TextEncoder().encode(value).length;
  }

  // A failure carries only a status for mvErrorText; a person never sees raw text.
  function failure(status, plain) {
    var error = new Error("request failed");
    error.status = status || 0;
    if (plain) error.plain = plain;
    return error;
  }

  function say(message, isError) { CW.say(operationStatus, message, isError); }
  function sayError(error, action) {
    if (error && error.plain) { say(error.plain, true); return; }
    CW.fail(operationStatus, error, action);
  }

  function inputValue(form, name) {
    var control = form.elements[name];
    return control ? String(control.value || "").trim() : "";
  }

  async function call(path, options, acceptedStatuses) {
    var settings = Object.assign(
      {
        cache: "no-store",
        credentials: "same-origin",
        headers: {},
        referrerPolicy: "no-referrer"
      },
      options || {}
    );
    if (typeof settings.body === "string") {
      if (byteLength(settings.body) > MAX_REQUEST_BYTES) {
        throw failure(413);
      }
      settings.headers = Object.assign({ "Content-Type": "application/json" }, settings.headers);
    }
    var response = await fetch(apiBase + path, settings);
    var declared = Number(response.headers.get("content-length") || "0");
    if (declared > MAX_RESPONSE_BYTES) {
      throw failure(413);
    }
    var reader = response.body && response.body.getReader ? response.body.getReader() : null;
    if (!reader) throw failure(response.ok ? 0 : response.status);
    var decoder = new TextDecoder("utf-8", { fatal: true });
    var chunks = "";
    var received = 0;
    while (true) {
      var part = await reader.read();
      if (part.done) break;
      received += part.value.byteLength;
      if (received > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw failure(413);
      }
      chunks += decoder.decode(part.value, { stream: true });
    }
    chunks += decoder.decode();
    var body;
    try {
      body = chunks ? JSON.parse(chunks) : {};
    } catch (_error) {
      throw failure(response.ok ? 0 : response.status);
    }
    var accepted = Array.isArray(acceptedStatuses) && acceptedStatuses.indexOf(response.status) !== -1;
    if (!response.ok && !accepted) throw failure(response.status);
    return body;
  }

  function bytesToBase64(bytes) {
    var output = "";
    var chunkSize = 0x8000;
    for (var offset = 0; offset < bytes.length; offset += chunkSize) {
      var chunk = bytes.subarray(offset, Math.min(offset + chunkSize, bytes.length));
      output += String.fromCharCode.apply(null, chunk);
    }
    return btoa(output);
  }

  function mediaType(file) {
    if (file.type && /^[a-z0-9][a-z0-9.+-]{0,63}\/[a-z0-9][a-z0-9.+-]{0,63}$/i.test(file.type)) {
      return file.type.toLowerCase();
    }
    var lower = file.name.toLowerCase();
    if (lower.endsWith(".xml")) return "application/xml";
    if (lower.endsWith(".json")) return "application/json";
    if (lower.endsWith(".plist") || lower.endsWith(".xcprivacy")) return "application/x-plist";
    return "text/plain";
  }

  async function manifestPayload(fileList) {
    var files = Array.prototype.slice.call(fileList || []);
    if (!files.length || files.length > 64) {
      throw failure(422, "Choose between 1 and 64 settings files.");
    }
    var total = files.reduce(function (sum, file) {
      if (!file.size || file.size > MAX_FILE_BYTES) {
        throw failure(422, "Each file must be under 1 MB and not empty.");
      }
      return sum + file.size;
    }, 0);
    if (total > MAX_TOTAL_FILE_BYTES) {
      throw failure(413, "Together the files must be under 4 MB. Choose fewer files.");
    }
    var output = [];
    for (var index = 0; index < files.length; index += 1) {
      var file = files[index];
      var bytes = new Uint8Array(await file.arrayBuffer());
      output.push({
        path: file.webkitRelativePath || file.name,
        media_type: mediaType(file),
        content_base64: bytesToBase64(bytes)
      });
    }
    return output;
  }

  var PLATFORMS = {
    android: "Android", ios: "iPhone and iPad", fireos: "Amazon Fire", tvos: "Apple TV",
    roku: "Roku", tizen: "Samsung TV", webos: "LG TV"
  };
  var STATUS = {
    pending_review: ["Waiting for review", "warn"], accepted: ["Accepted", "ok"],
    needs_changes: ["Needs changes", "warn"], rejected: ["Rejected", "danger"],
    purged: ["Deleted after retention", "idle"]
  };

  function appName(id) {
    for (var i = 0; i < apps.length; i += 1) if (apps[i].id === id) return apps[i].display_name;
    return "Removed app";
  }

  function open(id, focus) { CW.open(element(id), focus); }

  async function refreshStatus() {
    if (!/^\/api\/v1\/consent\/application-scans$/.test(apiBase)) {
      CW.say(runtimeStatus, "App checks are not available on this page right now. Try again in a minute.", true);
      operations.disabled = true;
      return;
    }
    CW.say(runtimeStatus, "Checking whether app checks are available…");
    operations.disabled = true;
    try {
      var value = await call("/readiness", undefined, [503]);
      var ready = value && value.enabled === true && value.ready === true;
      CW.say(runtimeStatus, ready
        ? ""
        : (value && value.enabled === true
          ? "App checks are turned on but not ready yet. An administrator needs to finish setting them up."
          : "App checks are turned off for this workspace."), !ready);
      operations.disabled = !ready;
      if (ready) await Promise.all([loadApps(), loadScans()]);
      else {
        ["cas-apps", "cas-scans"].forEach(function (id) {
          element(id).replaceChildren(CW.el("p", "muted", "Your apps and results appear here once app checks are set up."));
        });
      }
    } catch (error) {
      CW.fail(runtimeStatus, error, "check whether app checks are available");
      operations.disabled = true;
    }
  }

  async function loadApps() {
    var host = element("cas-apps");
    try {
      var value = await call("/applications?limit=500");
      apps = Array.isArray(value.applications) ? value.applications : [];
      CW.table(host, apps, {
        label: "Your apps",
        name: function (a) { return a.display_name; },
        columns: [
          { label: "App", value: function (a) { return a.display_name; } },
          { label: "Runs On", value: function (a) { return PLATFORMS[a.platform] || CW.human(a.platform); } },
          { label: "App Store Name", value: function (a) { return a.bundle_id; } },
          { label: "Status", value: function (a) { return a.status === "active" ? CW.badge("Active", "ok") : CW.badge("Removed", "idle"); } }
        ],
        actions: [
          { label: "Check files", kind: "primary", when: function (a) { return canAdmin && a.status === "active"; }, run: openScan },
          { label: "Remove", kind: "danger", when: function (a) { return canAdmin && a.status === "active"; }, run: function (a, b) { CW.busy(b, function () { return removeApp(a); }); } }
        ],
        empty: {
          title: "No apps yet.",
          body: "Add your mobile or TV app, then upload its settings files to see what it declares.",
          action: canAdmin ? { label: "Add an app", run: openRegister } : null
        }
      });
    } catch (error) {
      host.replaceChildren(CW.el("p", "danger-text", CW.errorText(error, "load your apps")));
    }
  }

  function findingsText(s) {
    if (s.status === "purged") return "—";
    return s.permission_count + " permissions, " + s.privacy_data_type_count + " kinds of personal data, " +
      s.sdk_candidate_count + " possible tracking tools";
  }

  async function loadScans() {
    var host = element("cas-scans");
    try {
      var value = await call("/scans?limit=500");
      var scans = Array.isArray(value.scans) ? value.scans : [];
      CW.table(host, scans, {
        label: "Check results",
        name: function (s) { return appName(s.application_id) + " " + CW.when(s.scanned_at || s.purged_at); },
        columns: [
          { label: "App", value: function (s) { return appName(s.application_id); } },
          { label: "Checked", value: function (s) { return CW.when(s.scanned_at || s.purged_at); } },
          { label: "Found", value: findingsText },
          { label: "All Files Present", value: function (s) { return s.status === "purged" ? "—" : (s.complete ? "Yes" : "No, some files are missing"); } },
          { label: "Status", value: function (s) { var st = STATUS[s.status] || [CW.human(s.status), "idle"]; return CW.badge(st[0], st[1]); } }
        ],
        actions: [
          { label: "View", when: function (s) { return s.status !== "purged"; }, run: function (s, b) { CW.busy(b, function () { return viewScan(s); }); } },
          { label: "Review", kind: "primary", when: function (s) { return canAdmin && s.status === "pending_review"; }, run: openReview }
        ],
        empty: {
          title: "No results yet.",
          body: "Use “Check files” on one of your apps to create the first result."
        }
      });
    } catch (error) {
      host.replaceChildren(CW.el("p", "danger-text", CW.errorText(error, "load the results")));
    }
  }

  function openRegister() {
    var form = element("cas-register-form");
    form.reset();
    form.elements.idempotency_key.value = CW.reference();
    open("cas-register-form", "input[name=display_name]");
  }

  function openScan(app) {
    var form = element("cas-scan-form");
    form.reset();
    form.elements.application_id.value = app.id;
    form.elements.expected_application_revision.value = String(app.revision);
    form.elements.idempotency_key.value = CW.reference();
    element("cas-scan-title").textContent = "Check the files of " + app.display_name;
    open("cas-scan-form", "input[type=file]");
  }

  function openReview(scan) {
    var form = element("cas-review-form");
    form.reset();
    form.elements.scan_id.value = scan.id;
    form.elements.expected_revision.value = String(scan.revision);
    element("cas-review-title").textContent = "Review the result for " + appName(scan.application_id);
    open("cas-review-form", "select");
  }

  async function registerApplication(event) {
    event.preventDefault();
    var form = event.currentTarget;
    if (!inputValue(form, "display_name") || !inputValue(form, "bundle_id")) {
      say("Enter the app’s name and its app store name.", true);
      return;
    }
    try {
      await call("/applications", {
        method: "POST",
        body: JSON.stringify({
          platform: inputValue(form, "platform"),
          bundle_id: inputValue(form, "bundle_id"),
          display_name: inputValue(form, "display_name"),
          idempotency_key: inputValue(form, "idempotency_key")
        })
      });
      form.hidden = true;
      say("App added. Use “Check files” to upload its settings files.");
      await loadApps();
    } catch (error) {
      sayError(error, "add the app");
    }
  }

  async function scanApplication(event) {
    event.preventDefault();
    var form = event.currentTarget;
    try {
      say("Reading the files…");
      var files = await manifestPayload(form.elements.files.files);
      var applicationId = inputValue(form, "application_id");
      var revision = Number(inputValue(form, "expected_application_revision"));
      if (!applicationId || !Number.isInteger(revision) || revision < 1) {
        throw failure(422, "Choose an app from the list first.");
      }
      await call("/applications/" + encodeURIComponent(applicationId) + "/scans", {
        method: "POST",
        body: JSON.stringify({
          expected_application_revision: revision,
          idempotency_key: inputValue(form, "idempotency_key"),
          files: files
        })
      });
      form.elements.files.value = "";
      form.hidden = true;
      say("Files checked. Ask a colleague to review the new result below.");
      await loadScans();
    } catch (error) {
      if (error && error.status === 422 && !error.plain) {
        error.plain = "These files could not be read. Make sure they are the app’s settings files listed above.";
      }
      sayError(error, "check the files");
    }
  }

  async function reviewScan(event) {
    event.preventDefault();
    var form = event.currentTarget;
    try {
      await call("/scans/" + encodeURIComponent(inputValue(form, "scan_id")) + "/review", {
        method: "POST",
        body: JSON.stringify({
          decision: inputValue(form, "decision"),
          expected_revision: Number(inputValue(form, "expected_revision")),
          review_note_code: inputValue(form, "review_note_code")
        })
      });
      form.hidden = true;
      say("Review saved.");
      await loadScans();
    } catch (error) {
      if (error && error.status === 409) {
        error.plain = "Could not save the review. Someone other than the person who uploaded the files must review it, or it was already reviewed. Refresh the list and try again.";
      }
      sayError(error, "save the review");
    }
  }

  async function removeApp(app) {
    var answers = await window.mvForm("Remove " + app.display_name, [{
      key: "reason", label: "Why remove this app?", type: "select", required: true, default: "app-retired",
      options: [
        { value: "app-retired", label: "The app is no longer offered" },
        { value: "added-by-mistake", label: "Added by mistake" },
        { value: "replaced-by-new-app", label: "Replaced by a new app" },
        { value: "other", label: "Other" }
      ]
    }], { okText: "Review removal" });
    if (!answers) return;
    var ok = await CW.confirm("Remove " + app.display_name + "? You will no longer be able to check its files. Earlier results stay on record.", "Remove app");
    if (!ok) return;
    try {
      await call("/applications/" + encodeURIComponent(app.id) + "/revoke", {
        method: "POST",
        body: JSON.stringify({ expected_revision: app.revision, reason_code: answers.reason })
      });
      say(app.display_name + " was removed.");
      await loadApps();
    } catch (error) {
      sayError(error, "remove the app");
    }
  }

  function listSection(title, items, describe) {
    var box = CW.el("div");
    box.appendChild(CW.el("h4", "", title + " (" + items.length + ")"));
    if (!items.length) { box.appendChild(CW.el("p", "muted", "None declared.")); return box; }
    var list = CW.el("ul");
    items.slice(0, 200).forEach(function (item) { list.appendChild(CW.el("li", "", describe(item))); });
    box.appendChild(list);
    return box;
  }

  async function viewScan(summary) {
    var host = element("cas-detail-body");
    element("cas-detail-title").textContent = "Result for " + appName(summary.application_id);
    host.replaceChildren(CW.el("p", "muted", "Loading…"));
    element("cas-detail").hidden = false;
    try {
      var scan = await call("/scans/" + encodeURIComponent(summary.id));
      var result = scan.result || {};
      var complete = result.completeness || {};
      host.replaceChildren();
      CW.facts(host, [
        ["Checked", CW.when(scan.scanned_at)],
        ["Result kept until", CW.when(scan.retained_until)],
        ["All files present", complete.complete ? "Yes" : "No. Missing: " + (complete.missing_basenames || []).join(", ")]
      ]);
      host.appendChild(listSection("Permissions the app asks for", result.permissions || [], function (p) {
        return p.permission;
      }));
      host.appendChild(listSection("Personal data the app says it collects", result.privacy_data_types || [], function (d) {
        var parts = [d.data_type.replace(/^NSPrivacyCollectedDataType/, "")];
        if (d.used_for_tracking) parts.push("used for tracking");
        if (d.linked_to_identity) parts.push("linked to the person");
        return parts.join(" – ");
      }));
      host.appendChild(listSection("Possible tracking tools (to be confirmed by a person)", result.sdk_candidates || [], function (c) {
        return c.vendor_hint ? c.name + " (" + CW.human(c.vendor_hint) + ")" : c.name;
      }));
      open("cas-detail", null);
    } catch (error) {
      host.replaceChildren(CW.el("p", "danger-text", CW.errorText(error, "load the result")));
    }
  }

  async function checkIntegrity() {
    try {
      var value = await call("/integrity?limit=500");
      say(value && value.ok === true ? "All records are intact." : "The check found a problem. Contact support before changing anything.", !(value && value.ok === true));
    } catch (error) {
      sayError(error, "check the records");
    }
  }

  async function purgeExpired() {
    var ok = await CW.confirm("Delete check results that are past their keeping period? This cannot be undone. A short record that each result existed is kept.", "Delete expired results");
    if (!ok) return;
    try {
      var value = await call("/maintenance/purge", { method: "POST", body: JSON.stringify({ limit: 100 }) });
      var count = value && Number.isInteger(value.purged) ? value.purged : 0;
      say(count ? count + " expired results deleted." : "Nothing was past its keeping period.");
      await loadScans();
    } catch (error) {
      sayError(error, "delete expired results");
    }
  }

  document.querySelectorAll("[data-cas-close]").forEach(function (button) {
    button.addEventListener("click", function () { element(button.getAttribute("data-cas-close")).hidden = true; });
  });
  element("cas-new").addEventListener("click", openRegister);
  element("cas-register-form").addEventListener("submit", registerApplication);
  element("cas-scan-form").addEventListener("submit", scanApplication);
  element("cas-review-form").addEventListener("submit", reviewScan);
  element("cas-refresh-status").addEventListener("click", refreshStatus);
  element("cas-verify-integrity").addEventListener("click", function (event) {
    CW.busy(event.currentTarget, checkIntegrity);
  });
  element("cas-purge").addEventListener("click", function (event) {
    CW.busy(event.currentTarget, purgeExpired);
  });
  if (!canAudit) element("cas-verify-integrity").disabled = true;
  refreshStatus();
})();
