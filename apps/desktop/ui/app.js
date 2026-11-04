// Native bounded identity/readiness handshake; opaque HTTP responses are never identity.

(function () {
  "use strict";

  var PORT = 8765; // canonical dashboard port (maverick dashboard default)
  var DASH = "http://127.0.0.1:" + PORT;
  var FAST_MS = 600; // poll interval while we expect a quick startup
  var SLOW_MS = 2000; // poll interval after we've shown the trouble card
  var TROUBLE_MS = 6000; // elapsed time, independent of network completion
  // Covers the native readiness check: up to 3 s to connect (Windows refuses a
  // free port after about 2 s), then up to 2 s for the identity headers.
  var PROBE_MS = 5500;

  var statusText = document.getElementById("status-text");
  var trouble = document.getElementById("trouble");
  var phase = "connecting";
  var connected = false;
  var probeTimer;
  var probeDeadline;
  var watchdogTimer;
  var activeProbe;
  var began = performance.now();
  var generation = 0;
  var retryPending = false;
  var diagnostics = document.getElementById("diagnostics");
  var prepareReport = document.getElementById("prepare-startup-report");
  var downloadReport = document.getElementById("download-startup-report");
  var reportStatus = document.getElementById("startup-report-status");
  var reportPreview = document.getElementById("startup-report");
  var supportDetails = document.getElementById("support-details");
  var startupReport = null;

  function invoke(command) {
    if (window.__TAURI__ && window.__TAURI__.core) return window.__TAURI__.core.invoke(command);
    return Promise.reject(new Error("Startup controls are available in the Lightwork desktop app."));
  }

  function refreshDetails() {
    return invoke("dashboard_diagnostics").then(function (text) {
      if (diagnostics) diagnostics.textContent = text || "No startup messages were recorded.";
    }, function (error) {
      if (diagnostics) diagnostics.textContent = String(error);
    });
  }

  if (prepareReport && downloadReport && reportStatus && reportPreview) {
    prepareReport.addEventListener("click", function () {
      startupReport = null; prepareReport.disabled = true; downloadReport.disabled = true;
      reportPreview.textContent = ""; reportPreview.hidden = true; reportStatus.textContent = "Creating your support report…";
      if (supportDetails) supportDetails.open = true;
      invoke("startup_support_report").then(function (report) {
        if (!report || report.schema !== "lightwork.startup-support.v1") throw new Error("The startup report could not be verified.");
        startupReport = JSON.stringify(report, null, 2); reportPreview.textContent = startupReport; reportPreview.hidden = false;
        downloadReport.disabled = false; reportStatus.textContent = "Your support report is ready. Select Download report under Details for support, then send the file to your support contact.";
      }).catch(function () {
        startupReport = null; reportStatus.textContent = "The support report couldn't be created. Try again, or copy the startup messages under Details for support instead.";
      }).finally(function () { prepareReport.disabled = false; });
    });
    downloadReport.addEventListener("click", function () {
      if (!startupReport) return;
      var url = URL.createObjectURL(new Blob([startupReport], {type: "application/json"}));
      var link = document.createElement("a"); link.href = url; link.download = "Lightwork-startup-support.json"; link.click();
      setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
      reportStatus.textContent = "Support report downloaded. Send the file to your support contact. Nothing was sent automatically.";
    });
  }

  function setStatus(msg) {
    if (statusText) statusText.textContent = msg;
  }

  function connect() {
    if (connected) return;
    connected = true;
    phase = "connected";
    cancelProbes();
    setStatus("Opening your workspace…");
    window.location.replace(DASH + "/");
  }

  function cancelProbes() {
    clearTimeout(probeTimer);
    clearTimeout(probeDeadline);
    clearTimeout(watchdogTimer);
    if (activeProbe) activeProbe.abort();
    activeProbe = null;
  }

  function watch(current) {
    if (connected || current !== generation || phase === "stopped") return;
    var remaining = TROUBLE_MS - (performance.now() - began);
    if (remaining <= 0) showTrouble();
    else watchdogTimer = setTimeout(function () { watch(current); }, remaining);
  }

  function probe() {
    if (connected || phase === "stopped") return;
    var current = generation;
    var controller = new AbortController();
    var finished = false;
    activeProbe = controller;
    if (phase !== "trouble") setStatus("Opening your workspace…");
    function finish(success) {
      if (finished) return;
      finished = true;
      clearTimeout(deadline);
      if (current !== generation || connected || phase === "stopped") return;
      if (activeProbe === controller) activeProbe = null;
      if (success) connect();
      else probeTimer = setTimeout(probe, phase === "trouble" ? SLOW_MS : FAST_MS);
    }
    // Native transport owns its socket deadline. This UI deadline independently
    // prevents a late IPC response from navigating an obsolete page.
    var deadline = setTimeout(function () { controller.abort(); finish(false); }, PROBE_MS);
    probeDeadline = deadline;
    invoke("dashboard_readiness")
      .then(function (result) {
        if (finished || current !== generation || phase === "stopped") return;
        if (result && result.service === "lightwork-dashboard" && ["ready", "setup_required"].indexOf(result.state) >= 0) {
          finish(true);
        } else {
          if (result && result.state === "conflict") {
            showTrouble(); clearTimeout(watchdogTimer);
            setStatus("Port 8765 is occupied by an unrecognized service. No process was stopped. Close or reconfigure that service, then Retry or create a support report.");
          }
          finish(false);
        }
      })
      .catch(function () {
        finish(false);
      });
  }

  function showTrouble() {
    phase = "trouble";
    if (trouble) trouble.style.display = "block";
    setStatus("Still starting…");
  }

  // --- trouble-card controls ---
  var retry = document.getElementById("retry");
  if (retry) {
    retry.addEventListener("click", async function () {
      if (retryPending || connected) return;
      retryPending = true;
      retry.disabled = true;
      generation += 1;
      cancelProbes();
      phase = "retrying";
      began = performance.now();
      var current = generation;
      watch(current);
      if (trouble) trouble.style.display = "none";
      setStatus("Trying again…");
      try {
        await invoke("retry_dashboard");
        if (current !== generation || phase === "stopped") return;
        if (phase !== "trouble") phase = "connecting";
        probe();
      } catch (error) {
        if (current !== generation || phase === "stopped") return;
        if (diagnostics) diagnostics.textContent = String(error);
        showTrouble();
        setStatus("Lightwork could not start. Select Try again, or create a support report.");
        probeTimer = setTimeout(probe, SLOW_MS);
      } finally {
        retryPending = false;
        retry.disabled = false;
      }
    });
  }

  var refresh = document.getElementById("refresh-details");
  if (refresh) refresh.addEventListener("click", refreshDetails);

  var copy = document.getElementById("copy");
  var copied = document.getElementById("copied");
  if (copy) {
    copy.addEventListener("click", function () {
      var cmd = diagnostics ? diagnostics.textContent : "No startup messages available.";
      var flash = function (message) {
        if (!copied) return;
        copied.textContent = message || "Copied";
        copied.style.opacity = "1";
        setTimeout(function () { copied.style.opacity = "0"; }, message ? 5000 : 1400);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(cmd).then(flash, fallbackCopy);
      } else {
        fallbackCopy();
      }
      function fallbackCopy() {
        var ta = document.createElement("textarea");
        ta.value = cmd;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        try {
          if (document.execCommand("copy")) flash();
          else flash("Could not copy. Use Save instead.");
        } catch (e) {
          flash("Could not copy. Use Save instead.");
        } finally {
          document.body.removeChild(ta);
        }
      }
    });
  }

  var save = document.getElementById("save-details");
  if (save) {
    save.addEventListener("click", function () {
      var text = diagnostics ? diagnostics.textContent : "";
      var url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
      var link = document.createElement("a"); link.href = url; link.download = "Lightwork-startup-messages.txt"; link.click();
      setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    });
  }

  window.addEventListener("pagehide", function () {
    generation += 1;
    phase = "stopped";
    cancelProbes();
  });
  setStatus("Starting Lightwork…");
  watch(generation);
  probe();
})();
