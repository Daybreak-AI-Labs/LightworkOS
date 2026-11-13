"use strict";

(function consentPublishSettingsClient(global) {
  const MAX_REQUEST_BYTES = 64 * 1024;
  const MAX_RESPONSE_BYTES = 512 * 1024;
  const opaquePattern = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
  const operationPattern = /^[A-Za-z0-9][A-Za-z0-9_.:-]{7,191}$/;
  const semverPattern = /^(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
  const jurisdictionPattern = /^[A-Z]{2}(?:-[A-Z0-9]{1,16})?$/;
  const commonTrackers = new Set([
    "google_analytics", "google_tag_manager", "linkedin_insight",
    "meta_pixel", "microsoft_clarity", "tiktok_pixel",
  ]);
  const analyticsCategories = new Set(["advertising", "analytics", "essential", "functional"]);

  function failure(code, message, status) {
    const error = new Error(message);
    error.code = code;
    if (Number.isInteger(status)) error.status = status;
    return error;
  }

  function integer(value, label, minimum, maximum) {
    if (typeof value === "string" && !/^(0|[1-9][0-9]*)$/.test(value.trim())) {
      throw failure("field_invalid", `${label} must be an integer.`);
    }
    const selected = typeof value === "string" ? Number(value.trim()) : value;
    if (!Number.isSafeInteger(selected) || selected < minimum || selected > maximum) {
      throw failure("field_invalid", `${label} is outside its allowed range.`);
    }
    return selected;
  }

  function opaque(value, label) {
    if (typeof value !== "string" || !opaquePattern.test(value.trim())) {
      throw failure("field_invalid", `${label} must be a bounded opaque identifier.`);
    }
    return value.trim();
  }

  function operation(value) {
    if (typeof value !== "string" || !operationPattern.test(value.trim())) {
      throw failure("field_invalid", "Enter a valid request reference; reuse it only when retrying the same action.");
    }
    return value.trim();
  }

  function strictBoolean(value, label) {
    if (typeof value !== "boolean") {
      throw failure("field_invalid", `${label} must be true or false.`);
    }
    return value;
  }

  function parsePairs(value, kind) {
    const lines = Array.isArray(value) ? value : String(value || "").split(/\r?\n/);
    const result = [];
    const seen = new Set();
    for (const raw of lines) {
      if (raw === null || raw === undefined || String(raw).trim() === "") continue;
      let left;
      let right;
      if (typeof raw === "object" && !Array.isArray(raw)) {
        left = kind === "geo" ? raw.jurisdiction : raw.tracker;
        right = kind === "geo" ? raw.reconsent_after_days : raw.category;
      } else {
        const parts = String(raw).split("=");
        if (parts.length !== 2) throw failure("field_invalid", "Each mapping must contain one equals sign.");
        [left, right] = parts.map((item) => item.trim());
      }
      if (kind === "geo") {
        if (typeof left !== "string" || !jurisdictionPattern.test(left) || seen.has(left)) {
          throw failure("field_invalid", "Geolocation reconsent entries must use unique bounded jurisdictions.");
        }
        seen.add(left);
        result.push({ jurisdiction: left, reconsent_after_days: integer(right, "Reconsent days", 1, 3650) });
      } else {
        if (!commonTrackers.has(left) || !analyticsCategories.has(right) || seen.has(left)) {
          throw failure("field_invalid", "Some trackers have no category or more than one. Give each tracker one category, then save again.");
        }
        seen.add(left);
        result.push({ tracker: left, category: right });
      }
    }
    const key = kind === "geo" ? "jurisdiction" : "tracker";
    return result.sort((left, right) => left[key].localeCompare(right[key]));
  }

  function normalizeTrackers(value) {
    if (!Array.isArray(value)) throw failure("field_invalid", "Common trackers must be a list.");
    const result = [...new Set(value)];
    if (result.length !== value.length || result.length > commonTrackers.size || result.some((item) => !commonTrackers.has(item))) {
      throw failure("field_invalid", "Some common trackers are listed twice or not recognized. Remove the repeated trackers, then save again.");
    }
    return result.sort();
  }

  function buildSettings(value) {
    const sdkVersion = typeof value.sdk_version === "string" ? value.sdk_version.trim() : "";
    if (!semverPattern.test(sdkVersion)) throw failure("field_invalid", "SDK version must be bounded semantic versioning.");
    const trackers = normalizeTrackers(value.common_trackers);
    const assignments = parsePairs(value.analytics_category_assignments, "analytics");
    if (assignments.some((item) => !trackers.includes(item.tracker))) {
      throw failure("field_invalid", "Every category assignment must name an enabled common tracker.");
    }
    if (!new Set(["strict", "lax", "none"]).has(value.cookie_same_site)) {
      throw failure("field_invalid", "That cookie SameSite setting is not one of the choices. Choose Lax, Strict or None.");
    }
    if (!new Set(["host_only", "property_domain"]).has(value.cookie_domain_separation)) {
      throw failure("field_invalid", "That cookie domain choice is not one of the options. Choose an option from the list.");
    }
    const refresh = value.automatic_refresh_seconds === "" || value.automatic_refresh_seconds === null || value.automatic_refresh_seconds === undefined
      ? null : integer(value.automatic_refresh_seconds, "Automatic refresh seconds", 30, 86400);
    return {
      sdk_version: sdkVersion,
      geolocation_reconsent: parsePairs(value.geolocation_reconsent, "geo"),
      analytics_tracking_enabled: strictBoolean(value.analytics_tracking_enabled, "Analytics tracking"),
      analytics_category_assignments: assignments,
      common_trackers: trackers,
      cookie_same_site: value.cookie_same_site,
      cookie_domain_separation: value.cookie_domain_separation,
      spa_reload_on_route_change: strictBoolean(value.spa_reload_on_route_change, "SPA reload"),
      csp_nonce_required: strictBoolean(value.csp_nonce_required, "CSP requirement"),
      automatic_refresh_seconds: refresh,
    };
  }

  function buildCreatePayload(value) {
    return {
      expected_head_revision: integer(value.expected_head_revision, "Expected head revision", 0, 2147483647),
      idempotency_key: operation(value.idempotency_key),
      settings: buildSettings(value),
    };
  }

  function buildRevisionPayload(value) {
    return {
      expected_head_revision: integer(value.expected_head_revision, "Expected head revision", 1, 2147483647),
      idempotency_key: operation(value.idempotency_key),
    };
  }

  function boundedBody(payload) {
    const body = JSON.stringify(payload);
    if (new TextEncoder().encode(body).byteLength > MAX_REQUEST_BYTES) {
      throw failure("request_too_large", "The JSON request exceeds 64 KiB.");
    }
    return body;
  }

  async function readBoundedJson(response) {
    const declaredRaw = response.headers && response.headers.get("content-length");
    const declared = declaredRaw === null ? null : Number(declaredRaw);
    if (declared !== null && Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
      if (response.body && typeof response.body.cancel === "function") await response.body.cancel();
      throw failure("response_too_large", "The server response exceeds 512 KiB.", response.status);
    }
    let text;
    if (response.body && typeof response.body.getReader === "function") {
      const reader = response.body.getReader();
      const chunks = [];
      let total = 0;
      while (true) {
        const item = await reader.read();
        if (item.done) break;
        total += item.value.byteLength;
        if (total > MAX_RESPONSE_BYTES) {
          if (typeof reader.cancel === "function") await reader.cancel();
          throw failure("response_too_large", "The server response exceeds 512 KiB.", response.status);
        }
        chunks.push(item.value);
      }
      const merged = new Uint8Array(total);
      let offset = 0;
      for (const chunk of chunks) { merged.set(chunk, offset); offset += chunk.byteLength; }
      text = new TextDecoder("utf-8", { fatal: true }).decode(merged);
    } else {
      text = await response.text();
      if (new TextEncoder().encode(text).byteLength > MAX_RESPONSE_BYTES) {
        throw failure("response_too_large", "The server response exceeds 512 KiB.", response.status);
      }
    }
    try {
      return JSON.parse(text);
    } catch (_error) {
      throw failure("response_invalid_json", "The reply from the server could not be read. Try again.", response.status);
    }
  }

  async function parseResponse(response) {
    const payload = await readBoundedJson(response);
    if (!response.ok) {
      const message = payload && typeof payload.detail === "string" ? payload.detail : "That didn't work. Refresh the page and try again.";
      throw failure("request_failed", message, response.status);
    }
    return payload;
  }

  const api = {
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    boundedBody,
    buildCreatePayload,
    buildRevisionPayload,
    buildSettings,
    normalizeTrackers,
    parsePairs,
    parseResponse,
    readBoundedJson,
  };
  global.LightworkConsentPublishSettingsClient = Object.freeze(api);

  if (typeof document === "undefined") return;
  const shell = document.getElementById("publish-settings-shell");
  if (!shell) return;
  const CW = global.LightworkConsentWorkbench;
  const apiBase = shell.dataset.apiBase || "";
  const canAdmin = shell.dataset.canAdmin === "true";
  const canAudit = shell.dataset.canAudit === "true";
  const operations = document.getElementById("publish-settings-operations");
  const runtimeStatus = document.getElementById("publish-settings-runtime-status");
  const operationStatus = document.getElementById("publish-settings-operation-status");
  const state = { head: null, versions: [], properties: [] };
  const EVENTS = { created: "New settings saved", activated: "Settings switched on", rolled_back: "Went back to earlier settings",
    withdrawn: "Settings turned off", retention_purged: "Old settings deleted" };
  const REGIONS = [["US", "United States"], ["US-CA", "California"], ["CA", "Canada"], ["CA-QC", "Quebec"], ["GB", "United Kingdom"],
    ["FR", "France"], ["DE", "Germany"], ["ES", "Spain"], ["IT", "Italy"], ["NL", "Netherlands"], ["BR", "Brazil"], ["AU", "Australia"], ["JP", "Japan"]]
    .map(([value, label]) => ({ value, label }));
  const DAYS = [["90", "3 months"], ["180", "6 months"], ["365", "1 year"], ["730", "2 years"]].map(([value, label]) => ({ value, label }));

  function element(id) { return document.getElementById(id); }
  function say(target, message, failed) {
    if (CW) CW.say(target, message, failed);
    else { target.textContent = message; target.dataset.state = failed ? "failed" : "ready"; }
  }
  // Plain sentences only; a local validation failure has no status code.
  function explain(target, error, action) {
    if (error && error.code === "field_invalid") return say(target, "Some settings need fixing. Check the choices and try again.", true);
    if (error && error.status === 409) return say(target, "These settings changed since you opened the page, or the published banner changed. Refresh and try again.", true);
    return say(target, CW ? CW.errorText(error, action) : "Could not " + action + ".", true);
  }
  function human(value) { return CW ? CW.human(value) : String(value); }
  function when(value) { return CW ? CW.when(value) : ""; }
  function propertyId() { return element("publish-settings-property-id").value; }
  function propertyPath() { return encodeURIComponent(opaque(propertyId(), "Website")); }

  async function request(path, options) {
    const response = await fetch(`${apiBase}${path}`, {
      cache: "no-store",
      credentials: "same-origin",
      redirect: "error",
      referrerPolicy: "no-referrer",
      ...(options || {}),
      headers: { Accept: "application/json", ...((options && options.headers) || {}) },
    });
    return parseResponse(response);
  }
  function post(path, payload) {
    return request(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: boundedBody(payload) });
  }
  function reference() { return CW ? CW.reference() : String(Date.now()) + "-settings"; }

  async function refreshStatus() {
    operations.disabled = true;
    say(runtimeStatus, "Checking that website banner settings are available…", false);
    try {
      const payload = await request("/status");
      if (payload.ready === true) {
        operations.disabled = false;
        say(runtimeStatus, "", false);
        await loadProperties();
      } else if (payload.enabled === true) {
        say(runtimeStatus, "Website banner settings are turned on but not ready yet. Publish your banner first, then refresh this page.", true);
      } else {
        say(runtimeStatus, "Website banner settings are not turned on for this workspace. Ask an administrator to turn them on.", true);
      }
    } catch (error) { explain(runtimeStatus, error, "check availability"); }
  }

  async function loadProperties() {
    const select = element("publish-settings-property-id");
    try {
      const catalog = CW.client("/api/v1/consent/publishing");
      // The catalog pages 50 at a time; read every page, as the publishing
      // page does, so a website past the first page is still offered.
      const all = [];
      for (let i = 0, offset = 0; i < 20 && offset !== null; i++) {
        const data = await catalog("/catalog/properties?limit=50&offset=" + offset);
        all.push(...(data.items || []));
        offset = Number.isInteger(data.next_offset) ? data.next_offset : null;
      }
      state.properties = all.filter((item) => item.kind === "web");
      CW.fill(select, state.properties.map((item) => ({ value: item.property_id, label: human(item.property_id) })),
        state.properties.length ? "" : "Add a website on the Banner and preference center page first");
      if (state.properties.length) await loadVersions();
    } catch (error) { explain(runtimeStatus, error, "load your websites"); }
  }

  function statusOf(version) {
    const head = state.head;
    if (head && head.active_version_id === version.version_id && head.state === "active") return ["Live", "ok"];
    if (head && head.latest_version_id === version.version_id) return ["Newest, not live", "warn"];
    return ["Earlier version", "idle"];
  }
  function summary(settings) {
    const trackers = (settings.common_trackers || []).map(human).join(", ") || "No trackers";
    const again = (settings.geolocation_reconsent || []).map((item) => item.jurisdiction + " every " + item.reconsent_after_days + " days").join(", ");
    return trackers + (again ? "; asks again: " + again : "");
  }
  async function loadVersions() {
    const host = element("publish-settings-versions-table");
    state.head = null; state.versions = [];
    try {
      try { state.head = await request(`/properties/${propertyPath()}`); }
      catch (error) { if (error.status !== 404) throw error; }
      if (state.head) state.versions = (await request(`/properties/${propertyPath()}/versions?limit=100`)).items || [];
    } catch (error) { host.replaceChildren(); explain(element("publish-settings-head"), error, "load the settings"); return; }
    const head = state.head;
    say(element("publish-settings-head"), !head ? "This website has no settings yet." : head.state === "active" ? "Settings are live on this website." :
      head.state === "withdrawn" ? "Settings are turned off for this website." : "Settings are saved but none is live yet.", false);
    element("publish-settings-withdraw").hidden = !(head && head.state === "active" && canAdmin);
    CW.table(host, state.versions, {
      label: "Settings versions", name: (v) => "version " + v.version_number,
      columns: [
        { label: "Version", value: (v) => v.version_number },
        { label: "Status", value: (v) => { const s = statusOf(v); return CW.badge(s[0], s[1]); } },
        { label: "What it does", value: (v) => summary(v.settings || {}) },
        { label: "Saved", value: (v) => when(v.created_at) },
      ],
      actions: [
        { label: "Make live", when: (v) => canAdmin && head && head.state !== "active" && head.latest_version_id === v.version_id, run: (v, b) => activate(v, b) },
        { label: "Go back to this", when: (v) => canAdmin && head && head.state === "active" && head.active_version_id !== v.version_id, run: (v, b) => rollback(v, b) },
      ],
      empty: { title: "No settings yet.", body: "Create the first settings for this website.", action: canAdmin ? { label: "New settings", run: openCreate } : null },
    });
    if (canAudit) loadHistory();
  }
  async function lifecycle(button, message, okText, label, path, payload) {
    return CW.busy(button, async () => {
      if (!(await CW.confirm(message, okText))) return;
      try { await post(path, payload); await loadVersions(); say(operationStatus, label, false); }
      catch (error) { explain(operationStatus, error, "change the settings"); }
    });
  }
  function revision() { return buildRevisionPayload({ expected_head_revision: state.head.revision, idempotency_key: reference() }); }
  function activate(version, button) {
    return lifecycle(button, "Make version " + version.version_number + " live on " + human(propertyId()) + "? The banner will use these settings right away.", "Make live",
      "Version " + version.version_number + " is now live.", `/properties/${propertyPath()}/versions/${encodeURIComponent(opaque(version.version_id, "Version"))}/activate`, revision());
  }
  function rollback(version, button) {
    return lifecycle(button, "Go back to version " + version.version_number + " on " + human(propertyId()) + "? It replaces the live settings right away.", "Go back",
      "Version " + version.version_number + " is live again.", `/properties/${propertyPath()}/rollback`, { ...revision(), target_version_id: opaque(version.version_id, "Version") });
  }
  element("publish-settings-withdraw").addEventListener("click", (event) => lifecycle(event.currentTarget,
    "Turn off the banner settings on " + human(propertyId()) + "? The banner falls back to its default behaviour. The history is kept.", "Turn off",
    "Settings turned off.", `/properties/${propertyPath()}/withdraw`, revision()));
  element("publish-settings-property-id").addEventListener("change", loadVersions);

  // New settings
  const createPanel = element("publish-settings-create-panel");
  function geoRow(region, days) {
    const row = CW.el("div", "cw-row");
    const where = CW.el("label", "", "Region"), whereSelect = CW.fill(CW.el("select", "select"), REGIONS);
    whereSelect.name = "geolocation_reconsent"; whereSelect.value = region || "US"; where.appendChild(whereSelect);
    const after = CW.el("label", "", "Ask again after"), afterSelect = CW.fill(CW.el("select", "select"), DAYS);
    afterSelect.name = "geolocation_reconsent_days"; afterSelect.value = days || "365"; after.appendChild(afterSelect);
    const remove = CW.el("button", "btn btn--ghost", "Remove"); remove.type = "button"; remove.addEventListener("click", () => row.remove());
    row.append(where, after, remove);
    return row;
  }
  function openCreate() {
    element("publish-settings-create-form").reset();
    const versions = new Set([shell.dataset.sdkVersion || "1.0.0"]);
    state.versions.forEach((v) => v.settings && versions.add(v.settings.sdk_version));
    CW.fill(element("publish-settings-sdk-version"), [...versions].map((v, index) => ({ value: v, label: index === 0 ? "Current (" + v + ")" : "Earlier (" + v + ")" })));
    element("publish-settings-geolocation").replaceChildren();
    const live = state.versions.find((v) => state.head && v.version_id === (state.head.active_version_id || state.head.latest_version_id));
    if (live && live.settings) {
      const s = live.settings;
      (s.common_trackers || []).forEach((t) => { const box = document.querySelector(`input[name="common_trackers"][value="${t}"]`); if (box) box.checked = true; });
      (s.analytics_category_assignments || []).forEach((a) => { const sel = document.querySelector(`select[data-tracker="${a.tracker}"]`); if (sel) sel.value = a.category; });
      (s.geolocation_reconsent || []).forEach((g) => element("publish-settings-geolocation").appendChild(geoRow(g.jurisdiction, String(g.reconsent_after_days))));
      element("publish-settings-analytics-enabled").checked = !!s.analytics_tracking_enabled;
      element("publish-settings-spa-reload").checked = !!s.spa_reload_on_route_change;
      element("publish-settings-csp-required").checked = !!s.csp_nonce_required;
      element("publish-settings-same-site").value = s.cookie_same_site;
      element("publish-settings-domain-separation").value = s.cookie_domain_separation;
      element("publish-settings-refresh-seconds").value = s.automatic_refresh_seconds ? String(s.automatic_refresh_seconds) : "";
    }
    element("publish-settings-expected-revision").value = String(state.head ? state.head.revision : 0);
    CW.open(createPanel, "#publish-settings-sdk-version");
  }
  element("publish-settings-new").addEventListener("click", openCreate);
  element("publish-settings-cancel").addEventListener("click", () => { createPanel.hidden = true; });
  element("publish-settings-geo-add").addEventListener("click", () => element("publish-settings-geolocation").appendChild(geoRow()));
  element("publish-settings-create-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const status = element("publish-settings-operation-status");
    try {
      const trackers = [...document.querySelectorAll('input[name="common_trackers"]:checked')].map((item) => item.value);
      const assignments = trackers.map((tracker) => ({ tracker, category: document.querySelector(`select[data-tracker="${tracker}"]`).value }))
        .filter((item) => item.category);
      const geo = [...document.querySelectorAll("#publish-settings-geolocation .cw-row")].map((row) => ({
        jurisdiction: row.querySelector('[name="geolocation_reconsent"]').value,
        reconsent_after_days: row.querySelector('[name="geolocation_reconsent_days"]').value,
      }));
      if (new Set(geo.map((g) => g.jurisdiction)).size !== geo.length) { say(status, "Each region can appear only once.", true); return; }
      const payload = buildCreatePayload({
        expected_head_revision: element("publish-settings-expected-revision").value,
        idempotency_key: element("publish-settings-idempotency").value || reference(),
        sdk_version: element("publish-settings-sdk-version").value,
        geolocation_reconsent: geo,
        analytics_tracking_enabled: element("publish-settings-analytics-enabled").checked,
        analytics_category_assignments: assignments,
        common_trackers: trackers,
        cookie_same_site: element("publish-settings-same-site").value,
        cookie_domain_separation: element("publish-settings-domain-separation").value,
        spa_reload_on_route_change: element("publish-settings-spa-reload").checked,
        csp_nonce_required: element("publish-settings-csp-required").checked,
        automatic_refresh_seconds: element("publish-settings-refresh-seconds").value,
      });
      await post(`/properties/${propertyPath()}/versions`, payload);
      createPanel.hidden = true; await loadVersions();
      say(status, "New settings saved. Use “Make live” to switch them on.", false);
    } catch (error) { explain(status, error, "save the settings"); }
  });

  // History and checks
  async function loadHistory() {
    try {
      const events = await request(`/operations/history?property_id=${propertyPath()}&limit=100`);
      CW.table(element("publish-settings-history-table"), Array.isArray(events) ? events : (events.items || []), {
        label: "Settings history",
        columns: [
          { label: "When", value: (e) => when(e.occurred_at) },
          { label: "What happened", value: (e) => EVENTS[e.event_type] || human(e.event_type) },
        ],
        empty: { title: "No changes recorded yet.", body: "Each saved change to these settings appears here." },
      });
    } catch (error) { explain(operationStatus, error, "load the history"); }
  }
  element("publish-settings-integrity").addEventListener("click", (event) => CW.busy(event.currentTarget, async () => {
    try { const r = await request("/operations/integrity"); say(operationStatus, r.valid === false ? "The settings history failed its check. Contact support." : "The settings history is intact.", r.valid === false); }
    catch (error) { explain(operationStatus, error, "check the history"); }
  }));
  element("publish-settings-recovery").addEventListener("click", (event) => CW.busy(event.currentTarget, async () => {
    try { const r = await request("/operations/recovery"); say(operationStatus, r.ready ? "Settings records are healthy and ready to back up." : "Settings records need attention before a backup. Contact support.", !r.ready); }
    catch (error) { explain(operationStatus, error, "check backups"); }
  }));

  if (!CW) { say(runtimeStatus, "This page could not finish loading. Reload the page.", true); return; }
  operations.disabled = true;
  refreshStatus();
})(typeof window === "undefined" ? globalThis : window);
