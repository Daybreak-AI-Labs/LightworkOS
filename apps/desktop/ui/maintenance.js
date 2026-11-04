(function () {
  "use strict";
  var get = function (id) { return document.getElementById(id); };
  var busy = false;
  var configured = false;
  var recoveryAvailable = true;
  var review = null;
  var repairReview = false;
  var identityTransition = null;
  var handoff = null;
  var offlineReview = null, recoveryPlan = null;
  function protectedApproval(operation) { return handoff && handoff.operation === operation && handoff.expires_at * 1000 > Date.now(); }
  var AUTHORIZATION = /^[0-9a-f]{32}:[0-9a-f]{64}$/;
  var FAILED = "Lightwork could not complete that step.";
  var STATUS_LABELS = {
    prepared: "getting ready", applying: "in progress", incomplete: "interrupted",
    upgraded: "updated", upgrade_recovered: "returned to the previous version",
    repaired: "repaired", repair_recovered: "repaired", rolled_back: "returned to the previous version"
  };
  var COMPLETED = ["upgraded", "upgrade_recovered", "repaired", "repair_recovered", "rolled_back"];
  function invoke(command, args) {
    if (!window.__TAURI__ || !window.__TAURI__.core) return Promise.reject(new Error("Open this page in Lightwork Desktop."));
    return window.__TAURI__.core.invoke(command, args);
  }
  // The approval code is copied between two screens, so forgive stray spaces
  // and line breaks from the copy. The format check itself is unchanged.
  function code() { return String(get("maintenance-authorization").value || "").replace(/\s+/g, ""); }
  function hint(text, tone) {
    var node = get("maintenance-authorization-hint");
    if (!node) return;
    node.textContent = text;
    node.className = "hint" + (tone ? " " + tone : "");
  }
  function describeCode() {
    var value = code();
    if (!value && handoff) hint("Protected " + handoff.operation + " approval from " + handoff.actor_label + ". Expires " + new Date(handoff.expires_at * 1000).toLocaleString() + ". " + handoff.scope, protectedApproval(handoff.operation) ? "ok" : "bad");
    else if (!value) hint("No code yet. Copy it in Workspace recovery mode, then select Paste code.");
    else if (AUTHORIZATION.test(value)) hint("Code ready. It works for 15 minutes after it was made.", "ok");
    else hint("This isn't a complete approval code. Copy the whole code again in Workspace recovery mode and paste it here.", "bad");
  }
  function controls() {
    get("check-update").disabled = busy || !configured || !recoveryAvailable;
    get("repair-install").disabled = busy || !configured;
    var authorized = AUTHORIZATION.test(code());
    get("install-update").disabled = busy || !review || (!repairReview && !authorized && !protectedApproval("upgrade"));
    get("rollback-install").disabled = busy || (!authorized && !protectedApproval("rollback"));
    get("resume-maintenance").disabled = busy || !get("maintenance-incomplete").value;
    get("maintenance-logs").disabled = busy || !get("maintenance-log-point").value;
    get("back").disabled = busy;
    get("offline-review").disabled = busy || !get("offline-folder").value.trim();
    get("offline-install").disabled = busy || !offlineReview || offlineReview.expires_at * 1000 <= Date.now();
    get("planner-load").disabled = busy || !get("planner-point").value;
    get("planner-next").disabled = busy || !recoveryPlan || !recoveryPlan.has_more;
    get("planner-save").disabled = busy || !recoveryPlan;
    get("planner-repair").disabled = busy || !configured;
    get("planner-workspace").disabled = busy;
    get("save-identity-transition").disabled = busy || !identityTransition;
    if (get("load-handoff")) get("load-handoff").disabled = busy;
    if (get("paste-authorization")) get("paste-authorization").disabled = busy;
    if (get("clear-authorization")) get("clear-authorization").disabled = busy;
  }
  function status(text) { get("maintenance-status").textContent = text; }
  function failure(error) {
    var detail = String(error);
    var reason = "Open Details for support to see why, then try again or contact your administrator.";
    if (/expired or was (already used|retired)/i.test(detail)) {
      reason = "The approval code has expired or was already used. Get a new code in Workspace recovery mode and paste it again.";
      hint("That code can't be used any more. Get a new one in Workspace recovery mode.", "bad");
    } else if (/authorization does not match|Use the rollback authorization/i.test(detail)) {
      reason = "This approval code was made for a different action. Get a new code for this exact action in Workspace recovery mode.";
      hint("That code was made for a different action. Get a new one in Workspace recovery mode.", "bad");
    } else if (/Copy the current maintenance authorization|Authorize this installation in Workspace recovery first/i.test(detail)) {
      reason = "Paste a current approval code from Workspace recovery mode, then try again.";
    }
    status(FAILED + " " + reason);
    get("maintenance-details").textContent = detail;
  }
  function pointLabel(point, waiting) {
    var label = waiting ? "needs finishing" : STATUS_LABELS[point.status] || "unknown state";
    return point.old_version + " → " + point.new_version + " · " + label;
  }
  function showReview(result) {
        if (typeof result.review !== "string" || typeof result.version !== "string") throw new Error("The update response was incomplete. Check again.");
        review = result.review;
        repairReview = result.repair === true;
        if (result.identity_transition != null) {
          if (repairReview || typeof result.identity_transition !== "object" || JSON.stringify(result.identity_transition).length > 65536) throw new Error("The proposed signing transition is incomplete or too large. Contact your administrator.");
          identityTransition = result.identity_transition;
          get("identity-transition-notice").hidden = false; get("save-identity-transition").hidden = false;
        }
        get("update-version").textContent = (result.repair ? "Repair version " : "Install version ") + result.version;
        get("update-notes").textContent = result.notes || "No details were provided for this version.";
        get("install-update").textContent = result.repair ? "Repair and restart" : "Install and restart";
        if (get("update-steps")) get("update-steps").hidden = repairReview;
        if (get("repair-steps")) get("repair-steps").hidden = !repairReview;
        get("update-review").hidden = false;
        status(repairReview
          ? "Review the repair below. Nothing changes until you select Repair and restart."
          : "Review the update below and follow its steps. Nothing is installed until you select Install and restart.");
  }
  async function check(repair) {
    if (busy || !configured || (!repair && !recoveryAvailable)) return;
    busy = true;
    review = null;
    identityTransition = null;
    get("identity-transition-notice").hidden = true; get("save-identity-transition").hidden = true;
    get("update-review").hidden = true;
    controls();
    status(repair ? "Looking for a safe copy of your installed version…" : "Checking for updates…");
    try {
      var result = await invoke("check_desktop_update", { repair: repair });
      if (result) {
        showReview(result);
      } else {
        status(repair ? "A repair copy of this version isn't available right now. Contact your administrator." : "You have the latest version. No update is available.");
      }
    } catch (error) { review = null; identityTransition = null; get("update-review").hidden = true; failure(error); }
    finally { busy = false; controls(); }
  }
  function download(text, name, type) {
    var url = URL.createObjectURL(new Blob([text], { type: type }));
    var link = document.createElement("a"); link.href = url; link.download = name; link.click();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }
  if (get("load-handoff")) get("load-handoff").addEventListener("click", async function () {
    if (busy) return;
    busy = true; controls();
    try {
      var result = await invoke("review_maintenance_handoff");
      if (!result || typeof result.actor_label !== "string" || ["upgrade", "rollback"].indexOf(result.operation) < 0 || !Number.isFinite(result.expires_at) || result.expires_at * 1000 <= Date.now() || "authorization" in result) throw new Error("The protected approval is unavailable or expired. Review it again in Workspace recovery.");
      handoff = result; get("maintenance-authorization").value = "";
      status("Protected " + result.operation + " reviewed for " + (result.new_version || result.old_version) + ". Nothing changes until your final action below.");
      describeCode();
    } catch (error) { handoff = null; failure(error); }
    finally { busy = false; controls(); }
  });
  setInterval(function () { if (!busy) { describeCode(); controls(); } }, 1000);
  get("check-update").addEventListener("click", function () { return check(false); });
  get("repair-install").addEventListener("click", function () { return check(true); });
  get("save-identity-transition").addEventListener("click", function () {
    if (busy || !identityTransition) return;
    download(JSON.stringify(identityTransition, null, 2), "lightwork-signing-transition.json", "application/json");
  });
  get("install-update").addEventListener("click", async function () {
    if (busy || !review || get("install-update").disabled) return;
    var selected = review;
    review = null;
    busy = true;
    controls();
    status("Downloading and checking the installer. Lightwork will close when installation begins…");
    try {
      var args = { review: selected, confirm: true };
      if (!repairReview && code()) args.authorization = code();
      get("maintenance-authorization").value = "";
      // The native side spends a loaded protected approval on the first attempt, so stop showing it as loaded.
      if (!repairReview) handoff = null;
      describeCode();
      await invoke("install_desktop_update", args);
      status("The installer has started. Lightwork will reopen when it finishes.");
    } catch (error) {
      failure(error);
      try { var current = await invoke("maintenance_status"); if (current.reviewed_update) showReview(current.reviewed_update); } catch (_) {}
    }
    finally { busy = false; get("update-review").hidden = !review; controls(); }
  });
  get("back").addEventListener("click", function () {
    if (!busy) window.location.replace("index.html");
  });
  get("maintenance-authorization").addEventListener("input", function () { describeCode(); controls(); });
  if (get("paste-authorization")) get("paste-authorization").addEventListener("click", async function () {
    if (busy) return;
    var clip = typeof navigator !== "undefined" && navigator.clipboard;
    try {
      if (!clip || !clip.readText) throw new Error("Clipboard reading is unavailable.");
      get("maintenance-authorization").value = String(await clip.readText()).replace(/\s+/g, "");
      describeCode();
    } catch (_) {
      hint("Lightwork couldn't read the clipboard. Click in the Approval code box and press Ctrl+V instead.", "bad");
    }
    controls();
  });
  if (get("clear-authorization")) get("clear-authorization").addEventListener("click", function () {
    if (busy) return;
    get("maintenance-authorization").value = ""; handoff = null;
    describeCode(); controls();
  });
  get("maintenance-incomplete").addEventListener("change", controls);
  get("maintenance-log-point").addEventListener("change", controls);
  get("maintenance-logs").addEventListener("click", async function () {
    if (busy || !get("maintenance-log-point").value) return;
    busy = true; controls();
    try { var result = await invoke("desktop_maintenance_logs", { id: get("maintenance-log-point").value }); get("maintenance-details").textContent = result.details || "Nothing was recorded for this one."; }
    catch (error) { failure(error); }
    finally { busy = false; controls(); }
  });
  if (get("maintenance-details-copy")) get("maintenance-details-copy").addEventListener("click", function () {
    var text = get("maintenance-details").textContent || "";
    var say = function (message) { if (get("maintenance-details-copied")) get("maintenance-details-copied").textContent = message; };
    var clip = typeof navigator !== "undefined" && navigator.clipboard;
    if (clip && clip.writeText) return clip.writeText(text).then(function () { say("Copied."); }, function () { say("Couldn't copy. Use Save instead."); });
    say("Couldn't copy. Use Save instead.");
  });
  if (get("maintenance-details-save")) get("maintenance-details-save").addEventListener("click", function () {
    download(get("maintenance-details").textContent || "", "Lightwork-installation-details.txt", "text/plain");
  });
  async function recover(resume) {
    if (busy || (resume ? get("resume-maintenance").disabled : get("rollback-install").disabled)) return;
    busy = true; controls();
    var args = resume ? { id: get("maintenance-incomplete").value, confirm: true } : { confirm: true };
    if (!resume && code()) args.authorization = code();
    get("maintenance-authorization").value = "";
    if (!resume) handoff = null; // Spent by the first attempt, like a pasted code.
    describeCode();
    status(resume ? "Finishing the interrupted update. Lightwork will reopen with the result…" : "Getting ready to go back to the previous version. Lightwork will reopen with the result…");
    try { await invoke(resume ? "resume_desktop_maintenance" : "rollback_desktop_update", args); }
    catch (error) { failure(error); }
    finally { busy = false; controls(); }
  }
  get("rollback-install").addEventListener("click", function () { return recover(false); });
  get("resume-maintenance").addEventListener("click", function () { return recover(true); });
  get("offline-folder").addEventListener("input", function () { offlineReview = null; get("offline-details").textContent = "Package selection changed. Verify it again."; controls(); });
  get("offline-review").addEventListener("click", async function () {
    if (busy) return;
    var selected = get("offline-folder").value.trim();
    offlineReview = null; busy = true; controls();
    try {
      var result = await invoke("review_offline_repair", { folder: selected });
      if (selected !== get("offline-folder").value.trim() || !result || result.verified !== true || !/^[a-f0-9]{32}$/.test(result.review || "")) throw new Error("The offline selection changed or could not be verified.");
      offlineReview = result;
      get("offline-details").textContent = "Verified exact version " + result.version + ", " + result.size_bytes + " bytes. Publisher: " + result.publisher_thumbprint + ". Installer SHA-256: " + result.installer_sha256 + ". Review expires " + new Date(result.expires_at * 1000).toLocaleString() + ". Nothing has been installed.";
    } catch (error) { failure(error); }
    finally { busy = false; controls(); }
  });
  get("offline-install").addEventListener("click", async function () {
    if (busy || get("offline-install").disabled) return;
    var selected = offlineReview; offlineReview = null; busy = true; controls();
    try { await invoke("install_offline_repair", { review: selected.review, confirm: true }); }
    catch (error) { failure(error); }
    finally { busy = false; controls(); }
  });
  async function loadPlan(offset) {
    if (busy || !get("planner-point").value) return;
    busy = true; controls();
    try {
      var selected = get("planner-point").value;
      var result = await invoke("desktop_recovery_plan", { id: selected, offset: offset });
      if (selected !== get("planner-point").value || result.id !== selected) throw new Error("The selected recovery point changed. Review it again.");
      recoveryPlan = result;
      get("planner-details").textContent = (result.blockers.length ? result.blockers.map(function (row) { return row.code + ": " + row.message; }).join("\n") : "No current blocker found. Administrator approval and a fresh check are still required before rollback.") +
        "\nAffected protected files " + Math.min(offset + 1, result.total_affected) + "-" + Math.min(offset + 50, result.total_affected) + " of " + result.total_affected + ":\n" + result.affected.map(function (row) { return row.change + ": " + row.path; }).join("\n") + "\n" + result.notice;
    } catch (error) { recoveryPlan = null; failure(error); }
    finally { busy = false; controls(); }
  }
  get("planner-point").addEventListener("change", function () { recoveryPlan = null; get("planner-details").textContent = ""; controls(); });
  get("planner-load").addEventListener("click", function () { return loadPlan(0); });
  get("planner-next").addEventListener("click", function () { if (recoveryPlan) return loadPlan(recoveryPlan.offset + 50); });
  get("planner-save").addEventListener("click", function () { if (recoveryPlan) download(JSON.stringify(recoveryPlan, null, 2), "Lightwork-recovery-coordination.json", "application/json"); });
  get("planner-repair").addEventListener("click", function () { return check(true); });
  get("planner-workspace").addEventListener("click", function () { if (!busy) window.location.replace("recovery.html"); });
  describeCode();
  controls();
  invoke("maintenance_status").then(function (result) {
    get("installed-version").textContent = result.version;
    if (result.reviewed_update) showReview(result.reviewed_update);
    configured = result.updates_configured === true;
    var recovery = result.recovery || {};
    recoveryAvailable = recovery.unavailable !== true;
    (recovery.recovery_points || []).forEach(function (point) {
      var planOption = document.createElement("option"); planOption.value = point.id; planOption.textContent = pointLabel(point, false); get("planner-point").appendChild(planOption);
      var logOption = document.createElement("option"); logOption.value = point.id; logOption.textContent = pointLabel(point, false); get("maintenance-log-point").appendChild(logOption);
      if (point.pending_finalization || ["prepared", "applying", "incomplete"].indexOf(point.status) >= 0) {
        var option = document.createElement("option"); option.value = point.id; option.textContent = pointLabel(point, point.pending_finalization && COMPLETED.indexOf(point.status) >= 0); get("maintenance-incomplete").appendChild(option);
      }
    });
    if (recovery.incomplete) configured = false;
    var completed = (recovery.recovery_points || []).filter(function (point) { return COMPLETED.indexOf(point.status) >= 0; }).map(function (point) { if (point.status === "rolled_back" || point.status === "upgrade_recovered") return "returned to " + point.old_version; if (point.status === "repaired" || point.status === "repair_recovered") return "repaired " + point.old_version; return "updated to " + point.new_version; }).join(", ");
    if (recovery.incomplete) get("resume-maintenance").textContent = "Recover and restart";
    get("maintenance-recovery-result").textContent = recovery.incomplete ? "An unfinished installation is blocking normal workspace startup. Choose it above and select Recover and restart to put back the last working version. Its saved copies and installation records are kept." : completed ? "Completed: " + completed + "." : "Nothing has been updated or repaired here yet.";
    status(recovery.incomplete ? "An unfinished update is stopping your workspace from opening. Finish it under Go back to the previous version below." : !recoveryAvailable ? "Lightwork couldn't read its saved restore points. You can still repair this version, but updates are paused. Contact your administrator if this continues." : configured ? "Check for an update, or repair the installed version." : "This copy of Lightwork can't check for updates by itself. Contact your administrator for the latest installer.");
    if (recovery.detail) get("maintenance-details").textContent = recovery.detail;
    controls();
  }, failure);
})();
