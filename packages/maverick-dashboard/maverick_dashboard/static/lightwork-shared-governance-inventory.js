// Governance inventory page: records and links load on open as tables,
// filters are dropdowns filled from the current inventory, and maintenance
// actions are buttons. The version check values and request key for an
// update come from the loaded status or are generated here, never typed.
(function () {
  "use strict";

  var root = document.getElementById("sgi-root");
  if (!root) { return; }
  var apiBase = root.dataset.apiBase || "/api/v1/governance/inventory";
  var maxResponseBytes = 2 * 1024 * 1024;
  var state = document.getElementById("sgi-state");
  var output = document.getElementById("sgi-output");
  var operationState = document.getElementById("sgi-operation-state");
  var operations = document.getElementById("sgi-operations");
  var PAGE = 100;

  var SOURCES = {
    ai_governance: "AI governance",
    consent_preferences: "Consent",
    data_use_governance: "Data use",
    privacy_automation: "Privacy",
    tech_risk_compliance: "Technology risk",
    third_party_management: "Third parties"
  };
  var STATES = { available: "Complete", partial: "Partly complete", unavailable: "Not available", drifted: "Changed at the source" };
  var KIND_LABELS = { governance_resource: "Governance record", dpa_review: "Data processing agreement review", paper_review: "Contract review", ai_system: "AI system", dsar: "Personal data request" };

  var current = { active: null, kinds: {}, entityById: {}, entityCursor: 0, linkCursor: 0, focus: null };

  function fail(message) {
    var error = new Error(message);
    error.plain = true;
    return error;
  }

  async function readJson(response) {
    if (!response.ok) { throw response; }
    var declared = Number(response.headers.get("content-length") || 0);
    if (declared > maxResponseBytes) {
      if (response.body && typeof response.body.cancel === "function") { await response.body.cancel(); }
      throw fail("The answer was too large to show. Try a narrower filter.");
    }
    if (!response.body || typeof response.body.getReader !== "function") {
      return response.json();
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
        throw fail("The answer was too large to show. Try a narrower filter.");
      }
      chunks.push(part.value);
    }
    var bytes = new Uint8Array(total);
    var offset = 0;
    chunks.forEach(function (chunk) { bytes.set(chunk, offset); offset += chunk.byteLength; });
    var text;
    try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
    catch (_error) { throw fail("Lightwork sent an answer this page could not read. Try again."); }
    try { return text ? JSON.parse(text) : {}; }
    catch (_error) { throw fail("Lightwork sent an answer this page could not read. Try again."); }
  }

  async function request(path, options) {
    var settings = Object.assign({ credentials: "same-origin", headers: { Accept: "application/json" } }, options || {});
    if (settings.body) { settings.headers["Content-Type"] = "application/json"; }
    return readJson(await fetch(apiBase + path, settings));
  }

  function human(value) {
    if (value === null || value === undefined || value === "") { return ""; }
    if (KIND_LABELS[value]) { return KIND_LABELS[value]; }
    if (window.mvHuman) { return window.mvHuman(value); }
    var s = String(value).replace(/[_-]+/g, " ").trim();
    return s.charAt(0).toUpperCase() + s.slice(1);
  }
  function when(ts) {
    var n = Number(ts);
    if (!isFinite(n) || n <= 0) { return "—"; }
    return (window.mvTimeAbsolute ? window.mvTimeAbsolute(n) : new Date(n * 1000).toLocaleString());
  }
  function errorText(failure, action) {
    if (failure && failure.plain) { return failure.message; }
    return window.mvErrorText ? window.mvErrorText(failure, action) : "Could not " + action + ". Try again.";
  }

  // The raw answer is kept only inside the collapsed "Technical details".
  function show(message, payload) {
    window.mvStatus(operationState, message);
    output.textContent = JSON.stringify(payload === undefined ? {} : payload, null, 2);
  }
  function showError(action) {
    return function (failure) { window.mvStatus(operationState, errorText(failure, action), {error: true}); };
  }

  function newOperationId() {
    if (window.crypto && typeof window.crypto.randomUUID === "function") { return "update-" + window.crypto.randomUUID(); }
    return "update-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 12);
  }

  function setReady(ready) {
    operations.setAttribute("aria-disabled", ready ? "false" : "true");
    operations.classList.toggle("sgi-disabled", !ready);
    operations.querySelectorAll("button,input,select").forEach(function (control) {
      if (!ready) { control.disabled = true; }
      else if (!control.hasAttribute("data-role-disabled")) { control.disabled = false; }
    });
  }

  function cell(value) {
    var td = document.createElement("td");
    if (value && value.nodeType) { td.appendChild(value); }
    else { td.textContent = value === undefined || value === null || value === "" ? "—" : String(value); }
    return td;
  }
  function emptyRow(body, span, text) {
    var tr = document.createElement("tr");
    var td = cell(text);
    td.colSpan = span;
    tr.appendChild(td);
    body.appendChild(tr);
  }
  function badge(text, kind) {
    var span = document.createElement("span");
    span.className = "badge " + (kind || "idle");
    span.textContent = text;
    return span;
  }
  function fillSelect(select, firstLabel, values, labeller) {
    var chosen = select.value;
    select.replaceChildren();
    var all = document.createElement("option");
    all.value = ""; all.textContent = firstLabel;
    select.appendChild(all);
    values.forEach(function (value) {
      var option = document.createElement("option");
      option.value = value; option.textContent = labeller(value);
      select.appendChild(option);
    });
    if (values.indexOf(chosen) >= 0) { select.value = chosen; }
  }

  function updateSourceCards(sources) {
    var list = document.getElementById("sgi-suites");
    if (!Array.isArray(sources) || !sources.length) { return; }
    list.replaceChildren();
    sources.slice(0, 6).forEach(function (source) {
      var item = document.createElement("li");
      var name = document.createElement("strong");
      name.textContent = SOURCES[source.source_id] || human(source.source_id);
      item.appendChild(name);
      item.appendChild(document.createElement("br"));
      item.appendChild(source.complete === true ? badge("Complete", "ok") : badge("Incomplete", "warn"));
      list.appendChild(item);
    });
  }

  async function loadStatus() {
    state.className = "badge idle";
    state.textContent = "Checking";
    setReady(false);
    try {
      var status = await request("/status");
      var ready = status.enabled === true && status.ready === true;
      var title = document.getElementById("sgi-health-title");
      var detail = document.getElementById("sgi-health-detail");
      if (status.enabled !== true) {
        state.className = "badge warn"; state.textContent = "Off";
        title.textContent = "The governance inventory is turned off";
        detail.textContent = "Ask your IT team to turn on the governance inventory for this installation.";
      } else if (!ready) {
        state.className = "badge warn"; state.textContent = "Not ready";
        title.textContent = "Some sources aren't ready yet";
        detail.textContent = "The inventory appears when every source is ready. Try Refresh in a few minutes.";
      } else {
        state.className = "badge " + (status.complete === true ? "ok" : "warn");
        state.textContent = status.complete === true ? "Complete" : "Partly complete";
        title.textContent = status.complete === true ? "Your inventory is up to date" : "Your inventory is missing some sources";
        detail.textContent = status.complete === true
          ? "Every record shown comes from the current saved version."
          : "Records from the incomplete sources may be missing. Update the inventory once they are ready.";
      }
      current.active = status.active && typeof status.active === "object" ? status.active : null;
      document.getElementById("sgi-revision").textContent = String((current.active && current.active.revision) || 0);
      updateSourceCards(status.sources);
      setReady(ready);
      show(ready ? "Inventory loaded." : "The inventory is not ready yet.", status);
      if (ready) {
        await loadCurrent();
        await Promise.all([loadSnapshots(), loadEntities(false), loadLinks(false)]);
      }
    } catch (failure) {
      state.className = "badge danger";
      state.textContent = "Unavailable";
      document.getElementById("sgi-health-title").textContent = "The inventory could not be loaded";
      document.getElementById("sgi-health-detail").textContent = errorText(failure, "load the inventory");
    }
  }

  async function loadCurrent() {
    if (!current.active || !current.active.snapshot_id) {
      document.getElementById("sgi-entities").textContent = "0";
      document.getElementById("sgi-relationships").textContent = "0";
      return;
    }
    var snapshot = await request("/snapshots/current");
    var projection = snapshot.projection && typeof snapshot.projection === "object" ? snapshot.projection : {};
    var entities = Array.isArray(projection.entities) ? projection.entities : [];
    var links = Array.isArray(projection.relationships) ? projection.relationships : [];
    document.getElementById("sgi-entities").textContent = String(entities.length);
    document.getElementById("sgi-relationships").textContent = String(links.length);
    var kinds = {};
    var relations = {};
    current.entityById = {};
    entities.forEach(function (item) {
      kinds[item.entity_kind] = true;
      current.entityById[item.entity_ref_sha256] = item;
    });
    links.forEach(function (item) { relations[item.relation_type] = true; });
    fillSelect(document.getElementById("sgi-kind"), "All types", Object.keys(kinds).sort(), human);
    fillSelect(document.getElementById("sgi-relation"), "All link types", Object.keys(relations).sort(), human);
  }

  function describe(ref) {
    var item = current.entityById[ref];
    if (!item) { return "A record in another version"; }
    return human(item.entity_kind) + (item.source_id ? " (" + (SOURCES[item.source_id] || human(item.source_id)) + ")" : "");
  }

  async function loadEntities(more) {
    var form = document.getElementById("sgi-query-form");
    if (!more) { current.entityCursor = 0; }
    var params = new URLSearchParams({ limit: String(PAGE), cursor: String(current.entityCursor) });
    if (form.elements.snapshot_id.value) { params.set("snapshot_id", form.elements.snapshot_id.value); }
    if (form.elements.source_id.value) { params.set("source_id", form.elements.source_id.value); }
    if (form.elements.entity_kind.value) { params.set("entity_kind", form.elements.entity_kind.value); }
    var payload = await request("/entities?" + params.toString());
    var body = document.getElementById("sgi-entity-rows");
    if (!more) { body.replaceChildren(); }
    var items = Array.isArray(payload.items) ? payload.items : [];
    items.forEach(function (item) {
      var tr = document.createElement("tr");
      tr.appendChild(cell(human(item.entity_kind)));
      tr.appendChild(cell(SOURCES[item.source_id] || (item.origin === "entity_graph" ? "Linked records" : human(item.source_id))));
      tr.appendChild(cell(item.record_count));
      tr.appendChild(cell(when(item.first_observed_at)));
      tr.appendChild(cell(when(item.last_observed_at)));
      tr.appendChild(cell(human(item.latest_action)));
      var button = document.createElement("button");
      button.type = "button"; button.className = "btn btn--ghost";
      button.textContent = "Show links";
      button.setAttribute("aria-label", "Show links for this " + human(item.entity_kind).toLowerCase());
      button.addEventListener("click", function () {
        current.focus = item.entity_ref_sha256;
        loadLinks(false).then(function () {
          window.mvReveal(document.getElementById("sgi-links-title"));
        }).catch(showError("load the links"));
      });
      tr.appendChild(cell(button));
      body.appendChild(tr);
    });
    if (!body.children.length) { emptyRow(body, 7, "No records match. Choose another source or record type, or update the inventory from its sources."); }
    current.entityCursor = payload.next_cursor || 0;
    document.getElementById("sgi-more-entities").hidden = !payload.next_cursor;
    document.getElementById("sgi-records-note").textContent = "Showing " + body.querySelectorAll("button").length + " of " + (payload.total_matching || 0) + " records.";
    return payload;
  }

  async function loadLinks(more) {
    var form = document.getElementById("sgi-query-form");
    if (!more) { current.linkCursor = 0; }
    var params = new URLSearchParams({ limit: String(PAGE), cursor: String(current.linkCursor) });
    if (form.elements.snapshot_id.value) { params.set("snapshot_id", form.elements.snapshot_id.value); }
    var relation = document.getElementById("sgi-relation").value;
    if (relation) { params.set("relation_type", relation); }
    if (current.focus) { params.set("entity_ref_sha256", current.focus); }
    var payload = await request("/relationships?" + params.toString());
    var body = document.getElementById("sgi-link-rows");
    if (!more) { body.replaceChildren(); }
    (Array.isArray(payload.items) ? payload.items : []).forEach(function (item) {
      var tr = document.createElement("tr");
      tr.appendChild(cell(describe(item.source_entity_ref_sha256)));
      tr.appendChild(cell(human(item.relation_type)));
      tr.appendChild(cell(describe(item.target_entity_ref_sha256)));
      tr.appendChild(cell(when(item.valid_from)));
      body.appendChild(tr);
    });
    if (!body.children.length) { emptyRow(body, 4, current.focus ? "This record has no links." : "No links match."); }
    current.linkCursor = payload.next_cursor || 0;
    document.getElementById("sgi-more-links").hidden = !payload.next_cursor;
    document.getElementById("sgi-all-links").hidden = !current.focus;
    document.getElementById("sgi-links-note").textContent = current.focus
      ? "Showing links for one " + describe(current.focus).toLowerCase() + "."
      : "Showing " + (payload.total_matching || 0) + " links.";
    return payload;
  }

  async function loadSnapshots() {
    var payload = await request("/snapshots?limit=100");
    var rows = document.getElementById("sgi-snapshot-rows");
    var versions = document.getElementById("sgi-version");
    rows.replaceChildren();
    var chosen = versions.value;
    versions.replaceChildren();
    var latest = document.createElement("option");
    latest.value = ""; latest.textContent = "Latest";
    versions.appendChild(latest);
    (Array.isArray(payload.items) ? payload.items : []).forEach(function (item) {
      var row = document.createElement("tr");
      row.appendChild(cell(when(item.created_at)));
      row.appendChild(cell(item.version));
      row.appendChild(cell(STATES[item.state] || human(item.state)));
      row.appendChild(cell(item.entity_count));
      row.appendChild(cell(item.payload_available === false ? badge("Removed after its keep period", "idle") : badge("Kept", "ok")));
      rows.appendChild(row);
      if (item.payload_available !== false && item.snapshot_id) {
        var option = document.createElement("option");
        option.value = item.snapshot_id;
        option.textContent = "Version " + item.version + " · " + when(item.created_at);
        versions.appendChild(option);
      }
    });
    if (chosen) { versions.value = chosen; }
    if (!rows.children.length) { emptyRow(rows, 5, "No saved versions yet. Use Update inventory from sources to create the first one."); }
  }

  async function confirmed(message, okText) {
    return window.mvConfirm ? window.mvConfirm(message, { okText: okText }) : false;
  }

  async function reconcile() {
    if (!(await confirmed("Update the inventory from its six sources now? A new saved version is created; earlier versions are kept.", "Update"))) { return; }
    var active = current.active || {};
    var body = {
      expected_active_revision: Number(active.revision || 0),
      expected_active_integrity_sha256: String(active.integrity_sha256 || "0".repeat(64)),
      operation_id: newOperationId()
    };
    operationState.textContent = "Updating the inventory…";
    var payload = await request("/reconcile", { method: "POST", body: JSON.stringify(body) });
    show("The inventory was updated.", payload);
    await loadStatus();
  }

  async function integrity() {
    var payload = await request("/integrity");
    show(payload.verified === true
      ? "No tampering found. " + (payload.snapshot_count || 0) + " saved versions were checked."
      : "The check found a problem. Ask your IT team to look at the inventory.", payload);
  }

  async function exportInventory() {
    var payload = await request("/export");
    var blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    var url = URL.createObjectURL(blob);
    var link = document.createElement("a");
    link.href = url; link.download = "governance-inventory.json";
    document.body.appendChild(link); link.click(); link.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
    show("Inventory downloaded as governance-inventory.json.", { downloaded: true });
  }

  async function checkpoint() {
    var payload = await request("/recovery/checkpoint", { method: "POST" });
    show("Restore point saved.", payload);
  }

  async function restore() {
    if (!(await confirmed("Restore the inventory from the last restore point? This only works when the inventory is empty, for example after moving to a new server.", "Restore"))) { return; }
    var payload = await request("/recovery/restore", { method: "POST" });
    show("The inventory was restored from the last restore point.", payload);
    await loadStatus();
  }

  async function purge() {
    // The server refuses a purge that names no current version, so say why here.
    if (!current.active || !current.active.revision || !current.active.integrity_sha256) {
      throw fail("There is no current saved version yet, so there is nothing to delete. Use Update inventory from sources first.");
    }
    if (!(await confirmed("Delete saved versions whose keep period has ended? The two newest versions are always kept. A short note that each one existed is kept.", "Delete"))) { return; }
    var active = current.active || {};
    var body = {
      expected_active_revision: Number(active.revision || 0),
      expected_active_integrity_sha256: String(active.integrity_sha256 || ""),
      operation_id: newOperationId(),
      retain_latest: 2
    };
    var payload = await request("/retention/purge", { method: "POST", body: JSON.stringify(body) });
    show("Expired versions were deleted.", payload);
    await loadSnapshots();
  }

  function on(id, event, handler) {
    var el = document.getElementById(id);
    if (el) { el.addEventListener(event, handler); }
  }
  function filtersChanged() {
    current.focus = null;
    loadEntities(false).then(function () { return loadLinks(false); }).catch(showError("load the records"));
  }

  on("sgi-refresh", "click", function () { loadStatus(); });
  on("sgi-load-snapshots", "click", function () { loadSnapshots().catch(showError("load the saved versions")); });
  on("sgi-query-form", "submit", function (event) { event.preventDefault(); filtersChanged(); });
  on("sgi-version", "change", filtersChanged);
  on("sgi-source", "change", filtersChanged);
  on("sgi-kind", "change", filtersChanged);
  on("sgi-relation", "change", function () { loadLinks(false).catch(showError("load the links")); });
  on("sgi-all-links", "click", function () { current.focus = null; loadLinks(false).catch(showError("load the links")); });
  on("sgi-more-entities", "click", function () { loadEntities(true).catch(showError("load more records")); });
  on("sgi-more-links", "click", function () { loadLinks(true).catch(showError("load more links")); });
  on("sgi-reconcile", "click", function () { reconcile().catch(showError("update the inventory")); });
  on("sgi-integrity", "click", function () { integrity().catch(showError("check the inventory")); });
  on("sgi-export", "click", function () { exportInventory().catch(showError("download the inventory")); });
  on("sgi-checkpoint", "click", function () { checkpoint().catch(showError("save a restore point")); });
  on("sgi-restore", "click", function () { restore().catch(showError("restore the inventory")); });
  on("sgi-purge", "click", function () { purge().catch(showError("delete expired versions")); });

  loadStatus();
}());
