(function () {
  "use strict";
  var busy = false;
  var get = function (id) { return document.getElementById(id); };
  async function waitForWorkspace() {
    var deadline = Date.now() + 60000;
    while (Date.now() < deadline) {
      var controller = new AbortController(), timer;
      try {
        var result = await Promise.race([
          window.__TAURI__.core.invoke("dashboard_readiness"),
          new Promise(function (_, reject) {
            timer = setTimeout(function () { controller.abort(); reject(new Error("Readiness request timed out.")); }, Math.min(5500, deadline - Date.now()));
          })
        ]);
        if (!result || result.service !== "lightwork-dashboard" || ["ready", "setup_required"].indexOf(result.state) < 0) {
          throw new Error(result && result.state === "conflict" ? "Port 8765 belongs to an unrecognized service; no process was stopped." : "Lightwork has not completed its identity check.");
        }
        return;
      } catch (_) {
        if (Date.now() < deadline) await new Promise(function (resolve) { setTimeout(resolve, Math.min(1000, deadline - Date.now())); });
      } finally { clearTimeout(timer); }
    }
    throw new Error("The selected workspace mode did not respond within 60 seconds. Retry or inspect startup details from Reconnect Lightwork.");
  }
  async function switchMode(recovery) {
    if (busy) return;
    busy = true;
    get("enter-recovery").disabled = get("leave-recovery").disabled = true;
    get("status").textContent = recovery ? "Closing your workspace and opening recovery mode… This can take up to a minute." : "Closing recovery mode and reopening your workspace… This can take up to a minute.";
    var modeChanged = false;
    try {
      if (!window.__TAURI__ || !window.__TAURI__.core) throw new Error("Open these controls from Lightwork Desktop.");
      await window.__TAURI__.core.invoke("switch_recovery_mode", { recovery: recovery, confirm: true });
      modeChanged = true;
      await waitForWorkspace();
      window.location.replace(recovery ? "http://127.0.0.1:8765/workspace/recovery" : "http://127.0.0.1:8765/");
    } catch (error) {
      get("status").textContent = modeChanged
        ? "Lightwork switched modes, but your workspace isn't answering yet. Select the button again, or choose Reconnect Lightwork from the Lightwork menu."
        : "Lightwork couldn't switch modes. Nothing was changed. Try again, and if it keeps happening, copy the Details for support and send them to your support contact.";
      get("details").textContent = String(error);
    } finally {
      busy = false;
      get("enter-recovery").disabled = get("leave-recovery").disabled = false;
    }
  }
  get("details-copy").addEventListener("click", function () {
    var text = get("details").textContent || "";
    var done = function () { get("details-copied").textContent = "Copied."; };
    var failed = function () { get("details-copied").textContent = "Couldn't copy. Select the text above and copy it yourself."; };
    var clip = typeof navigator !== "undefined" && navigator.clipboard;
    if (clip && clip.writeText) return clip.writeText(text).then(done, failed);
    failed();
  });
  get("enter-recovery").addEventListener("click", function () { return switchMode(true); });
  get("leave-recovery").addEventListener("click", function () { return switchMode(false); });
})();
