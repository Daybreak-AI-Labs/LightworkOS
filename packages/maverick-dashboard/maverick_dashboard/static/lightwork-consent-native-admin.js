/* Mobile app consent: apps and devices as record lists with row buttons.
   Identifiers, versions and fingerprints travel only from the chosen row; a
   person never types one. Errors a person sees go through mvErrorText. */
(function () {
  "use strict";

  var root = document.getElementById("nca-root");
  if (!root) { return; }
  var CW = window.LightworkConsentWorkbench;
  var maxResponseBytes = 512 * 1024;
  var maxRequestBytes = 128 * 1024;
  var identifierPattern = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
  var canAdmin = root.dataset.canAdmin === "true";
  var canAudit = root.dataset.canAudit === "true";
  var status = document.getElementById("nca-status");
  var adminBase = endpointBase(root.dataset.adminApiBase, "/api/v1/consent/native");
  var publicKeysBase = endpointBase(
    root.dataset.publicKeysBase,
    "/api/v1/public/consent/native/receipt-keys",
  );
  var clientsBase = "/api/v1/consent/public-clients";
  var apps = [];

  // A refusal carries the HTTP status only for mvErrorText; nothing raw is shown.
  function failure(statusCode) {
    var error = new Error("request failed");
    error.status = statusCode || 0;
    return error;
  }

  function endpointBase(value, fallback) {
    var selected = String(value || fallback);
    var parsed = new URL(selected, window.location.origin);
    if (parsed.origin !== window.location.origin || parsed.search || parsed.hash) {
      throw failure(0);
    }
    return parsed.pathname.replace(/\/$/, "");
  }

  function endpoint(base, path) {
    var parsed = new URL(base + path, window.location.origin);
    if (parsed.origin !== window.location.origin) { throw failure(0); }
    return parsed.pathname + parsed.search;
  }

  async function readJson(response) {
    var declared = Number(response.headers.get("content-length") || 0);
    if (!Number.isFinite(declared) || declared < 0 || declared > maxResponseBytes) {
      if (response.body && typeof response.body.cancel === "function") {
        await response.body.cancel();
      }
      throw failure(413);
    }
    if (!response.body || typeof response.body.getReader !== "function") {
      throw failure(response.ok ? 0 : response.status);
    }
    var reader = response.body.getReader();
    var chunks = [];
    var total = 0;
    while (true) {
      var part = await reader.read();
      if (part.done) { break; }
      total += part.value.byteLength;
      if (total > maxResponseBytes) {
        await reader.cancel();
        throw failure(413);
      }
      chunks.push(part.value);
    }
    var bytes = new Uint8Array(total);
    var offset = 0;
    chunks.forEach(function (chunk) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    });
    var payload;
    try { payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes) || "{}"); }
    catch (_error) { throw failure(response.ok ? 0 : response.status); }
    if (!response.ok) { throw failure(response.status); }
    return payload;
  }

  async function request(base, path, options, publicMetadata) {
    var settings = Object.assign(
      {
        credentials: publicMetadata ? "omit" : "same-origin",
        headers: { Accept: "application/json" },
        redirect: "error",
      },
      options || {},
    );
    if (settings.body) {
      if (new TextEncoder().encode(settings.body).byteLength > maxRequestBytes) {
        throw failure(413);
      }
      settings.headers["Content-Type"] = "application/json";
    }
    return readJson(await fetch(endpoint(base, path), settings));
  }

  function mutation(path, body) {
    return request(adminBase, path, { method: "POST", body: JSON.stringify(body) }, false);
  }

  function identifier(value) {
    var selected = String(value || "").trim();
    if (!identifierPattern.test(selected)) { throw failure(422); }
    return selected;
  }

  function say(text, isError) { CW.say(status, text, isError); }
  function fail(error, action) { return CW.fail(status, error, action); }

  // Readiness reasons become plain sentences, each with the step that fixes it.
  var REASONS = {
    configuration_unavailable: ["Mobile app consent has not been set up for this workspace yet. An administrator needs to finish its setup.", null],
    attestation_verifier_unavailable: ["The service that confirms each device is a genuine copy of your app is not connected yet. An administrator needs to connect it.", null],
    receipt_signer_unavailable: ["The key that signs consent receipts is not set up yet. An administrator needs to add it.", null],
    profile_linker_unavailable: ["Linking app users to their consent records is switched on, but the link service is not connected yet.", null],
    rights_requester_unavailable: ["Privacy requests from inside the app are switched on, but the request service is not connected yet.", null],
    standards_wire_verifier_unavailable: ["Checking of industry consent signals is switched on, but the checker is not connected yet.", null],
    public_consent_authority_unavailable: ["Your consent banner is not published yet. Publish it first.", ["Publish your banner", "/consent/publishing"]],
    application_directory_integrity_failed: ["The records check found a problem with the app list. Run the records check below and contact support.", null],
    application_directory_unavailable: ["The list of apps could not be read. Try again in a minute.", null],
    application_registration_required: ["Add your first app so its banner can be shown.", ["Add an app", "#new"]],
    device_registry_integrity_failed: ["The records check found a problem with the device list. Run the records check below and contact support.", null],
    receipt_key_rotation_incomplete: ["An app is still signing receipts with an older key. Use “Update signing key” on that app.", null],
    registered_application_authority_unavailable: ["An app’s settings no longer match its app key. Add the app again with a current key.", ["Manage app keys", "/consent/public-clients"]],
  };

  function heroState(title, badgeText, tone) {
    var box = document.querySelector(".hero-statebox");
    if (!box) { return; }
    var strong = box.querySelector(".hero-statebox__row strong");
    var badge = box.querySelector(".badge");
    if (strong) { strong.textContent = title; }
    if (badge) { badge.textContent = badgeText; badge.className = "badge " + tone; }
  }

  function renderReasons(reasons) {
    var list = document.getElementById("nca-reasons");
    list.replaceChildren();
    if (!reasons.length) {
      list.appendChild(CW.el("li", "", "Everything is set up. Your apps can show the consent banner."));
      return;
    }
    reasons.slice(0, 32).forEach(function (code) {
      var entry = REASONS[code] || ["Something still needs setting up. Ask an administrator to check mobile app consent.", null];
      var item = CW.el("li", "", entry[0] + " ");
      if (entry[1]) {
        if (entry[1][1] === "#new") {
          var button = CW.el("button", "btn btn--ghost", entry[1][0]);
          button.type = "button";
          button.disabled = !canAdmin;
          button.addEventListener("click", openRegister);
          item.appendChild(button);
        } else {
          var link = CW.el("a", "btn btn--ghost", entry[1][0]);
          link.href = entry[1][1];
          item.appendChild(link);
        }
      }
      list.appendChild(item);
    });
  }

  async function loadReadiness() {
    heroState("Checking…", "Checking", "idle");
    try {
      var result = await request(adminBase, "/readiness", null, false);
      var ready = result && result.ready === true;
      var reasons = Array.isArray(result && result.reasons) ? result.reasons : [];
      heroState(
        ready ? "Ready" : (result && result.enabled === true ? "Needs setting up" : "Turned off"),
        ready ? "Ready" : "Action needed",
        ready ? "ok" : "warn",
      );
      renderReasons(result && result.enabled === false ? ["configuration_unavailable"] : reasons);
    } catch (error) {
      heroState("Not available", "Unavailable", "danger");
      var list = document.getElementById("nca-reasons");
      list.replaceChildren(CW.el("li", "", CW.errorText(error, "check readiness")));
    }
  }

  function platformName(value) {
    var names = { ios: "iPhone and iPad", ipados: "iPad", android: "Android", fireos: "Fire TV", tvos: "Apple TV", roku: "Roku", tizen: "Samsung TV", webos: "LG TV" };
    return names[String(value || "").toLowerCase()] || CW.human(value);
  }

  function shortName(id) {
    var text = String(id || "");
    return text.length > 6 ? "Device …" + text.slice(-6) : "Device " + text;
  }

  async function loadApps() {
    var host = document.getElementById("nca-apps");
    if (!canAudit) {
      host.replaceChildren(CW.el("p", "muted", "You need audit access to see the list of apps."));
      return;
    }
    try {
      var result = await request(adminBase, "/applications", null, false);
      apps = Array.isArray(result.items) ? result.items : [];
      CW.table(host, apps, {
        label: "Your apps",
        name: function (a) { return a.application_id; },
        columns: [
          { label: "App", value: function (a) { return a.application_id; } },
          { label: "Runs On", value: function (a) { return platformName(a.platform); } },
          { label: "Website or App", value: function (a) { return CW.human(a.property_id); } },
          { label: "Language", value: function (a) { return CW.labelFor(CW.LOCALES, a.default_locale); } },
        ],
        actions: [
          { label: "Devices", run: function (a, b) { CW.busy(b, function () { return showDevices(a); }); } },
          { label: "Receipt keys", run: function (a, b) { CW.busy(b, function () { return showKeys(a); }); } },
          { label: "Update signing key", when: function () { return canAdmin; }, run: function (a, b) { CW.busy(b, function () { return rotateReceiptKey(a); }); } },
        ],
        empty: {
          title: "No apps yet.",
          body: "Add your mobile or TV app so it can show your consent banner.",
          action: canAdmin ? { label: "Add an app", run: openRegister } : null,
        },
      });
    } catch (error) {
      host.replaceChildren(CW.el("p", "danger-text", CW.errorText(error, "load your apps")));
    }
  }

  async function openRegister() {
    var form = document.getElementById("nca-register-form");
    var select = form.elements.public_client_ref;
    select.replaceChildren();
    try {
      var clients = await CW.publicClients(function (path) {
        return request(clientsBase, path, null, false);
      });
      var items = clients.filter(function (c) {
        return c.status === "active" && c.client_kind === "service" && c.target_bundle_id;
      });
      CW.fill(select, items.map(function (c) {
        return { value: c.credential_id, label: c.target_bundle_id + " (" + platformName(c.target_platform) + ")" };
      }), items.length ? "Choose an app key" : "No app keys yet");
      if (!items.length) {
        say("Create an app key first on the Website and App Keys page, choosing “An app or server”.", true);
      }
    } catch (error) {
      fail(error, "load your app keys");
      return;
    }
    CW.open(form, "select");
  }

  async function register(event) {
    event.preventDefault();
    var form = event.currentTarget;
    var chosen = form.elements.public_client_ref.value;
    if (!chosen) { say("Choose the app key for this app.", true); return; }
    var body = {
      public_client_ref: identifier(chosen),
      minimum_sdk_version: Number(form.elements.minimum_sdk_version.value) || 1,
      expected_revision: 0,
    };
    try {
      await mutation("/applications", body);
      form.hidden = true;
      say("App added. It can now show your consent banner once everything above is set up.");
      await Promise.all([loadApps(), loadReadiness()]);
    } catch (error) {
      fail(error, "add the app");
    }
  }

  async function rotateReceiptKey(app) {
    var ok = await CW.confirm(
      "Start signing new consent receipts for " + app.application_id + " with the workspace’s current signing key? Older receipts can still be checked.",
      "Update key",
    );
    if (!ok) { return; }
    try {
      await mutation(
        "/applications/" + encodeURIComponent(identifier(app.application_ref)) + "/receipt-key/rotate",
        { expected_directory_revision: app.directory_revision },
      );
      say("Signing key updated for " + app.application_id + ".");
      await Promise.all([loadApps(), loadReadiness()]);
    } catch (error) {
      fail(error, "update the signing key");
    }
  }

  async function showDevices(app) {
    var panel = document.getElementById("nca-devices-panel");
    var host = document.getElementById("nca-devices");
    document.getElementById("nca-devices-heading").textContent = "Devices using " + app.application_id;
    panel.hidden = false;
    host.replaceChildren(CW.el("p", "muted", "Loading devices…"));
    try {
      var result = await request(
        adminBase,
        "/applications/" + encodeURIComponent(identifier(app.application_ref)) + "/devices",
        null,
        false,
      );
      CW.table(host, result.items || [], {
        label: "Devices",
        name: function (d) { return shortName(d.device_id); },
        columns: [
          { label: "Device", value: function (d) { return shortName(d.device_id); } },
          { label: "Runs On", value: function (d) { return platformName(d.platform); } },
          { label: "Connected", value: function (d) { return CW.when(d.created_at); } },
          { label: "Status", value: function (d) { return d.status === "active" ? CW.badge("Connected", "ok") : CW.badge("Access removed", "idle"); } },
        ],
        actions: [
          { label: "Remove access", kind: "danger", when: function (d) { return canAdmin && d.status === "active"; }, run: function (d, b) { CW.busy(b, function () { return revokeDevice(app, d); }); } },
        ],
        empty: { title: "No devices yet.", body: "Devices appear here after someone installs your app and it connects for the first time." },
      });
      CW.open(panel, "button");
    } catch (error) {
      host.replaceChildren(CW.el("p", "danger-text", CW.errorText(error, "load the devices")));
    }
  }

  async function revokeDevice(app, device) {
    var fields = [{
      key: "reason", label: "Why remove this device?", type: "select", required: true, default: "lost_or_stolen",
      options: [
        { value: "lost_or_stolen", label: "Lost or stolen" },
        { value: "suspicious_activity", label: "Suspicious activity" },
        { value: "user_request", label: "The person asked us to" },
        { value: "retired_device", label: "Device no longer used" },
        { value: "other", label: "Other" },
      ],
    }];
    var answers = await window.mvForm("Remove device access", fields, { okText: "Review removal" });
    if (!answers) { return; }
    var ok = await CW.confirm(
      "Remove " + shortName(device.device_id) + " from " + app.application_id + "? This cannot be undone. The device will stop saving consent choices until the app is set up on it again.",
      "Remove access",
    );
    if (!ok) { return; }
    try {
      // The reason is recorded as a fingerprint, computed here from the choice.
      var evidence = await CW.sha256(JSON.stringify({
        kind: "lightwork.native-device-revocation-reason.v1",
        reason: answers.reason,
        application: app.application_ref,
        device: device.device_id,
      }));
      await mutation(
        "/applications/" + encodeURIComponent(identifier(app.application_ref)) + "/devices/" +
          encodeURIComponent(identifier(device.device_id)) + "/revoke",
        { expected_revision: device.revision, evidence_sha256: evidence },
      );
      say(shortName(device.device_id) + " can no longer save consent choices.");
      await showDevices(app);
    } catch (error) {
      fail(error, "remove the device");
    }
  }

  async function showKeys(app) {
    var panel = document.getElementById("nca-keys-panel");
    var host = document.getElementById("nca-keys");
    panel.hidden = false;
    host.replaceChildren(CW.el("p", "muted", "Loading keys…"));
    try {
      var path = "/" + encodeURIComponent(identifier(app.application_ref));
      document.getElementById("nca-public-key-link").href = endpoint(publicKeysBase, path);
      var payload = await request(publicKeysBase, path, null, true);
      var keys = Array.isArray(payload.keys) ? payload.keys.slice(0, 64) : [];
      CW.table(host, keys, {
        label: "Receipt checking keys",
        name: function (k) { return "Key " + k.key_revision; },
        columns: [
          { label: "Key", value: function (k) { return "Key " + k.key_revision; } },
          { label: "In Use", value: function (k) { return k.current === true ? CW.badge("Current", "ok") : CW.badge("Older", "idle"); } },
        ],
        actions: [
          { label: "Copy key", run: function (k) { window.mvCopy(String(k.public_key_hex || "")); } },
        ],
        empty: { title: "No keys yet.", body: "Keys appear after the app is added." },
      });
      CW.open(panel, "button");
    } catch (error) {
      host.replaceChildren(CW.el("p", "danger-text", CW.errorText(error, "load the keys")));
    }
  }

  async function checkIntegrity(button) {
    var host = document.getElementById("nca-integrity-result");
    try {
      var result = await request(adminBase, "/integrity", null, false);
      CW.say(host, result && result.valid === true
        ? "All records are intact."
        : "The check found a problem. Contact support before changing anything.", !(result && result.valid === true));
    } catch (error) {
      CW.fail(host, error, "check the records");
    }
    return button;
  }

  document.querySelectorAll("[data-nca-close]").forEach(function (button) {
    button.addEventListener("click", function () {
      document.getElementById(button.dataset.ncaClose).hidden = true;
    });
  });
  document.getElementById("nca-new").addEventListener("click", openRegister);
  document.getElementById("nca-register-form").addEventListener("submit", function (event) {
    register(event).catch(function (error) { fail(error, "add the app"); });
  });
  document.getElementById("nca-refresh").addEventListener("click", function () {
    loadReadiness();
    loadApps();
  });
  document.getElementById("nca-integrity").addEventListener("click", function (event) {
    var button = event.currentTarget;
    CW.busy(button, function () { return checkIntegrity(button); });
  });

  loadReadiness();
  loadApps();
}());
