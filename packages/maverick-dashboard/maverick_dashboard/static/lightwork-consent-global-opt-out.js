/* Opt out everywhere: set-ups load as rows with buttons; the key, language,
   devices and dates are chosen, and versions ride along from the chosen row. */
(function () {
  "use strict";

  var MAX_REQUEST_BYTES = 64 * 1024;
  var MAX_RESPONSE_BYTES = 256 * 1024;
  var shell = document.getElementById("global-opt-out-shell");
  if (!shell) return;
  var CW = window.LightworkConsentWorkbench;

  var apiBase = shell.getAttribute("data-api-base") || "";
  var canAdmin = shell.getAttribute("data-can-admin") === "true";
  var canAudit = shell.getAttribute("data-can-audit") === "true";
  var operations = document.getElementById("goo-operations");
  var runtimeStatus = document.getElementById("goo-runtime-status");
  var operationStatus = document.getElementById("goo-operation-status");
  var state = { items: [], keys: [], editing: null };
  var STATES = { draft: ["Draft", "warn"], active: ["On", "ok"], revoked: ["Switched off", "idle"], purged: ["Deleted", "idle"] };
  var ACTIONS = { created: "Set up", updated: "Changed", activated: "Switched on", revoked: "Switched off", purged: "Deleted" };

  function element(id) { return document.getElementById(id); }
  function byteLength(value) { return new TextEncoder().encode(value).length; }
  function localError(message) { var error = new Error(message); error.local = true; return error; }
  function say(target, message, failed) { CW.say(target, message, failed); }
  function explain(target, error, action) {
    if (error && error.local) return say(target, error.message, true);
    if (error && error.status === 409) return say(target, "This key no longer matches your published banner or consent policy, or the set-up changed since you opened it. Refresh and try again.", true);
    return say(target, CW.errorText(error, action), true);
  }

  async function call(path, options) {
    var settings = Object.assign(
      { cache: "no-store", credentials: "same-origin", headers: {}, referrerPolicy: "no-referrer" },
      options || {}
    );
    if (typeof settings.body === "string") {
      if (byteLength(settings.body) > MAX_REQUEST_BYTES) throw localError("That is too much text. Shorten the messages and try again.");
      settings.headers = Object.assign({ "Content-Type": "application/json" }, settings.headers);
    }
    var response = await fetch(apiBase + path, settings);
    var declared = Number(response.headers.get("content-length") || "0");
    var text = declared > MAX_RESPONSE_BYTES ? null : await response.text();
    var body;
    try {
      if (text === null || byteLength(text) > MAX_RESPONSE_BYTES) throw new Error("oversized");
      body = text ? JSON.parse(text) : {};
    } catch (_error) {
      var invalid = new Error("invalid response"); invalid.status = response.ok ? 0 : response.status; throw invalid;
    }
    if (!response.ok) { var failed = new Error("request failed"); failed.status = response.status; throw failed; }
    return body;
  }
  function post(path, payload, method) {
    return call(path, { method: method || "POST", body: JSON.stringify(payload) });
  }

  function keyLabel(ref) {
    var key = state.keys.filter(function (k) { return k.credential_id === ref; })[0];
    return key ? CW.human(key.property_id) + " · " + (key.browser_origin || key.target_origin || key.target_bundle_id || "") : "A website or app key";
  }
  function channels(item) {
    var on = [];
    if (item.mobile_ui && item.mobile_ui.enabled) on.push("Mobile app");
    if (item.email_ui && item.email_ui.enabled) on.push("Email");
    return on.join(" and ");
  }

  async function loadKeys() {
    try {
      state.keys = await CW.publicClients();
    } catch (_error) { state.keys = []; }
  }
  async function load() {
    try { state.items = (await call("/configurations?limit=500")).items || []; }
    catch (error) { element("goo-table").replaceChildren(); explain(runtimeStatus, error, "load opt-out set-ups"); return; }
    CW.table(element("goo-table"), state.items, {
      label: "Opt-out set-ups", name: function (x) { return keyLabel(x.application_ref); },
      columns: [
        { label: "Website or app", value: function (x) { return keyLabel(x.application_ref); } },
        { label: "Offered in", value: channels },
        { label: "Language", value: function (x) { return CW.labelFor(CW.LOCALES, x.locale); } },
        { label: "Status", value: function (x) { var s = STATES[x.state] || [CW.human(x.state), "idle"]; return CW.badge(s[0], s[1]); } },
        { label: "Last changed", value: function (x) { return CW.when(x.updated_at); } },
      ],
      actions: [
        { label: "Edit", when: function (x) { return canAdmin && (x.state === "draft" || x.state === "active"); }, run: function (x) { openForm(x); } },
        { label: "Switch on", when: function (x) { return canAdmin && x.state === "draft"; }, run: function (x, b) { lifecycle(x, "activate", b); } },
        { label: "History", when: function () { return canAudit; }, run: function (x, b) { history(x, b); } },
        { label: "Switch off", kind: "danger", when: function (x) { return canAdmin && (x.state === "draft" || x.state === "active"); }, run: function (x, b) { lifecycle(x, "revoke", b); } },
      ],
      empty: { title: "Opt-out is not set up yet.", body: "Choose a website or app key and write the messages people see.", action: canAdmin ? { label: "Set up opt-out", run: function () { openForm(null); } } : null },
    });
  }

  function lifecycle(item, action, button) {
    return CW.busy(button, async function () {
      var name = keyLabel(item.application_ref);
      var message = action === "activate"
        ? "Switch on opt-out for " + name + "? People will be able to send opt-out requests from the places you chose."
        : "Switch off opt-out for " + name + "? People will no longer be able to send requests this way. This cannot be undone; you would set it up again.";
      if (!(await CW.confirm(message, action === "activate" ? "Switch on" : "Switch off"))) return;
      try {
        await post("/configurations/" + encodeURIComponent(item.configuration_id) + "/" + action, { expected_revision: item.revision, idempotency_key: CW.reference() });
        await load(); say(operationStatus, action === "activate" ? "Opt-out is on." : "Opt-out is switched off.", false);
      } catch (error) { explain(operationStatus, error, action === "activate" ? "switch it on" : "switch it off"); }
    });
  }
  function history(item, button) {
    return CW.busy(button, async function () {
      try {
        var data = await call("/configurations/" + encodeURIComponent(item.configuration_id) + "/history");
        element("goo-history-title").textContent = "History for " + keyLabel(item.application_ref);
        CW.table(element("goo-history-table"), (data.history || []).slice().reverse(), {
          label: "History",
          columns: [
            { label: "When", value: function (e) { return CW.when(e.occurred_at); } },
            { label: "What happened", value: function (e) { return ACTIONS[e.action] || CW.human(e.action); } },
          ],
          empty: { title: "No changes recorded." },
        });
        CW.open(element("goo-history"));
      } catch (error) { explain(operationStatus, error, "load the history"); }
    });
  }

  // Set up or edit
  var panel = element("goo-config-panel");
  var form = element("goo-config-form");
  function setChannel(prefix, ui) {
    if (!ui) return;
    form.elements[prefix + "_enabled"].checked = !!ui.enabled;
    ["title", "body", "submit_label", "success_message"].forEach(function (k) { form.elements[prefix + "_" + k].value = ui[k] || ""; });
  }
  function openForm(item) {
    state.editing = item; form.reset();
    var taken = state.items.filter(function (x) { return x.state !== "revoked" && x.state !== "purged"; }).map(function (x) { return x.application_ref; });
    var keys = state.keys.filter(function (k) { return k.status === "active" && (item ? k.credential_id === item.application_ref : taken.indexOf(k.credential_id) < 0); });
    CW.fill(element("goo-application-ref"), item && !keys.length ? [{ value: item.application_ref, label: keyLabel(item.application_ref) }] :
      keys.map(function (k) { return { value: k.credential_id, label: keyLabel(k.credential_id) }; }), keys.length || item ? "" : "Create a website or app key first");
    element("goo-application-ref").disabled = !!item;
    CW.fill(element("goo-locale"), CW.LOCALES);
    element("goo-configuration-id").value = item ? item.configuration_id : "";
    element("goo-expected-revision").value = String(item ? item.revision : 0);
    if (item) {
      element("goo-locale").value = item.locale;
      setChannel("mobile", item.mobile_ui); setChannel("email", item.email_ui);
      form.querySelectorAll('[name="supported_devices"]').forEach(function (c) { c.checked = item.supported_devices.indexOf(c.value) >= 0; });
      form.querySelectorAll('[name="supported_services"]').forEach(function (c) { c.checked = item.supported_services.indexOf(c.value) >= 0; });
      element("goo-expires-at").value = item.expires_at ? CW.toInput(item.expires_at, true) : "";
    }
    element("goo-config-title").textContent = item ? "Edit opt-out for " + keyLabel(item.application_ref) : "Set up opt-out";
    CW.open(panel, item ? "#goo-locale" : "#goo-application-ref");
  }
  element("goo-new").addEventListener("click", function () { openForm(null); });
  element("goo-cancel").addEventListener("click", function () { panel.hidden = true; });

  function inputValue(name) { var control = form.elements[name]; return control ? String(control.value || "").trim() : ""; }
  function checkedValues(name) {
    return Array.prototype.map.call(form.querySelectorAll('input[name="' + name + '"]:checked'), function (control) { return control.value; });
  }
  function channelUI(prefix) {
    return { enabled: Boolean(form.elements[prefix + "_enabled"].checked), title: inputValue(prefix + "_title"), body: inputValue(prefix + "_body"),
      submit_label: inputValue(prefix + "_submit_label"), success_message: inputValue(prefix + "_success_message") };
  }
  function configurationPayload(creating) {
    var date = inputValue("expires_on"), expiry = date ? CW.toSeconds(date) + 86399 : null;
    if (date && !(expiry > Date.now() / 1000)) throw localError("Choose a date in the future, or leave it empty.");
    var payload = { locale: inputValue("locale"), mobile_ui: channelUI("mobile"), email_ui: channelUI("email"),
      supported_devices: checkedValues("supported_devices"), supported_services: checkedValues("supported_services"), expires_at: expiry,
      expected_revision: Number(inputValue("expected_revision")), idempotency_key: inputValue("idempotency_key") || CW.reference() };
    if (creating) payload.application_ref = inputValue("application_ref");
    if (creating && !payload.application_ref) throw localError("Choose a website or app key.");
    if (!payload.mobile_ui.enabled && !payload.email_ui.enabled) throw localError("Offer opt-out in the app, by email, or both.");
    if (!payload.supported_devices.length || !payload.supported_services.length) throw localError("Tick at least one device and one service.");
    ["mobile_ui", "email_ui"].forEach(function (k) {
      var ui = payload[k];
      if (!ui.title || !ui.body || !ui.submit_label || !ui.success_message) throw localError("Fill in every message, including the ones for places you switched off.");
    });
    return payload;
  }
  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    try {
      var creating = !state.editing, payload = configurationPayload(creating);
      if (!creating && state.editing.state === "active" &&
          !(await CW.confirm("Update opt-out for " + keyLabel(state.editing.application_ref) + "? It is switched on, so people will see the new messages and choices right away.", "Update"))) return;
      if (creating) await post("/configurations", payload);
      else await post("/configurations/" + encodeURIComponent(state.editing.configuration_id), payload, "PUT");
      panel.hidden = true; await load();
      say(operationStatus, creating ? "Opt-out set up as a draft. Use “Switch on” on its row when you are ready." : "Changes saved.", false);
    } catch (error) { explain(operationStatus, error, "save the opt-out set-up"); }
  });

  // Record care
  element("goo-integrity").addEventListener("click", function (event) {
    CW.busy(event.currentTarget, async function () {
      try { var r = await call("/integrity?limit=10000"); say(operationStatus, r.ok ? "Checked " + (r.checked || 0) + " records. Everything is intact." : "Some records failed their check. Contact support.", !r.ok); }
      catch (error) { explain(operationStatus, error, "check the records"); }
    });
  });
  element("goo-retry-audit").addEventListener("click", function (event) {
    CW.busy(event.currentTarget, async function () {
      try { var r = await post("/maintenance/retry-audit", { limit: 100 }); say(operationStatus, "Resent " + (r.cleared || 0) + " waiting audit entr" + (r.cleared === 1 ? "y" : "ies") + ".", false); }
      catch (error) { explain(operationStatus, error, "resend audit entries"); }
    });
  });
  element("goo-purge").addEventListener("click", function (event) {
    CW.busy(event.currentTarget, async function () {
      if (!(await CW.confirm("Delete opt-out records that are past their keep-until date? This cannot be undone.", "Delete"))) return;
      try { await post("/maintenance/purge", { limit: 100 }); await load(); say(operationStatus, "Expired records deleted.", false); }
      catch (error) { explain(operationStatus, error, "delete expired records"); }
    });
  });

  async function refreshStatus() {
    operations.disabled = true;
    if (!/^\/api\/v1\/consent\/global-opt-out$/.test(apiBase)) { say(runtimeStatus, "This page could not finish loading. Reload the page.", true); return; }
    try {
      var value = await call("/status");
      var ready = value && value.enabled === true && value.readiness && value.readiness.ready === true;
      if (ready) {
        operations.disabled = false; say(runtimeStatus, "", false);
        await loadKeys(); await load();
      } else if (value && value.enabled === true) {
        say(runtimeStatus, "Opt-out requests are turned on but not ready yet. Publish your banner and create a website or app key first.", true);
        settleTable("Opt-out set-ups appear here once your banner is published and a website or app key exists.");
      } else {
        say(runtimeStatus, "Opt-out requests are not turned on for this workspace. Ask an administrator to turn them on.", true);
        settleTable("Opt-out set-ups appear here once this is turned on.");
      }
    } catch (error) {
      explain(runtimeStatus, error, "check availability");
      settleTable(CW.errorText(error, "load opt-out set-ups"));
    }
  }
  // The list never loads while opt-out is unavailable; say why instead of "Loading…".
  function settleTable(message) { element("goo-table").replaceChildren(CW.el("p", "muted", message)); }
  if (!CW) { runtimeStatus.textContent = "This page could not finish loading. Reload the page."; return; }
  // A turned-off module shows its gate instead: nothing is checked or loaded,
  // and no second "not turned on" sentence appears under the banner.
  if (shell.getAttribute("data-module-enabled") !== "false") refreshStatus();
})();
