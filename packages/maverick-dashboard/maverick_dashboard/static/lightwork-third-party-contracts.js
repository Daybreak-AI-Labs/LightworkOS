"use strict";

// Contracts and engagements page: records load as a list on arrival, with a
// button per next step (view, edit, change status, archive, delete). The add
// and edit form uses dropdowns filled from real vendors, people and existing
// contracts; custom fields and calculations are built with buttons. Record
// references, versions and request keys come from the chosen row or are made
// here, never typed.
(function (global) {
  var document = global.document;
  var shell = document.getElementById("third-party-contracts-shell");
  if (!shell || !global.LwRecords) { return; }
  var R = global.LwRecords;
  var API = shell.dataset.apiBase || "/api/v1/third-party/contracts";
  var canOperate = shell.dataset.canOperate === "true";
  var canAudit = shell.dataset.canAudit === "true";
  var canAdmin = shell.dataset.canAdmin === "true";
  var operations = document.getElementById("tpc-operations");
  var listStatus = document.getElementById("tpc-list-status");
  var formStatus = document.getElementById("tpc-form-status");
  var opStatus = document.getElementById("tpc-operation-status");
  var editor = document.getElementById("tpc-editor");
  var form = document.getElementById("tpc-create-form");
  var filters = document.getElementById("tpc-filter-form");
  var S = { records: [], vendors: [], people: [] };
  var profileVendor = '', profileSelectionApplied = false;

  var STATUS = {
    draft: "Draft", negotiation: "In negotiation", active: "Active", suspended: "Suspended", expired: "Expired",
    terminated: "Ended", archived: "Archived", planned: "Planned", paused: "Paused", completed: "Completed", cancelled: "Cancelled",
  };
  var TRANSITIONS = {
    contract: { draft: ["negotiation", "active", "terminated"], negotiation: ["draft", "active", "terminated"], active: ["suspended", "expired", "terminated"],
      suspended: ["active", "terminated"], expired: ["terminated"], terminated: [], archived: [] },
    engagement: { planned: ["active", "cancelled"], active: ["paused", "completed", "terminated"], paused: ["active", "terminated"],
      completed: [], cancelled: [], terminated: [], archived: [] },
  };
  var FIELD_TYPES = [["boolean", "Yes or no"], ["integer", "Whole number"], ["decimal", "Number"], ["timestamp", "Date"],
    ["single_choice", "Pick one"], ["multi_choice", "Pick several"], ["text_ref", "Document name"]];
  var SENSITIVITY = [["internal", "Internal"], ["public", "Public"], ["confidential", "Confidential"], ["restricted", "Restricted"]];
  var OPERATORS = [["add", "Add up"], ["subtract", "Subtract"], ["multiply", "Multiply"], ["divide", "Divide"], ["minimum", "Smallest of"], ["maximum", "Largest of"], ["count", "Count filled in"]];

  function F(name) { return form.elements.namedItem(name); }
  function say(el, text) { window.mvStatus(el, text); }
  function fail(el, action) { return function (f) { say(el, f && f.plain ? f.plain : R.errorText(f, action)); }; }
  function plain(text) { var e = new Error("plain"); e.plain = text; return e; }
  // Same-origin, uncached, redirect-refusing requests whose answers are read
  // with a size bound; a failure is thrown as { status } so it can be worded
  // plainly with R.errorText.
  var MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
  async function readBoundedJson(response) {
    var declared = response.headers.get("Content-Length");
    if (declared !== null && Number(declared) > MAX_RESPONSE_BYTES) {
      if (response.body && typeof response.body.cancel === "function") { await response.body.cancel(); }
      throw plain("There were too many records to show. Narrow the filters.");
    }
    var responseText;
    if (response.body && typeof response.body.getReader === "function") {
      var reader = response.body.getReader();
      var chunks = [];
      var total = 0;
      while (true) {
        var part = await reader.read();
        if (part.done) { break; }
        total += part.value.byteLength;
        if (total > MAX_RESPONSE_BYTES) { await reader.cancel(); throw plain("There were too many records to show. Narrow the filters."); }
        chunks.push(part.value);
      }
      var bytes = new Uint8Array(total);
      var offset = 0;
      chunks.forEach(function (chunk) { bytes.set(chunk, offset); offset += chunk.byteLength; });
      responseText = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } else {
      responseText = await response.text();
    }
    if (!responseText) { return {}; }
    try { return JSON.parse(responseText); }
    catch (_error) { throw plain("Lightwork sent an answer this page could not read. Try again."); }
  }
  async function request(path, method, body) {
    var options = { method: method || "GET", credentials: "same-origin", cache: "no-store", redirect: "error",
      referrerPolicy: "no-referrer", headers: { Accept: "application/json" } };
    if (body !== undefined) { options.headers["Content-Type"] = "application/json"; options.body = JSON.stringify(body); }
    var response = await global.fetch(API + path, options);
    if (!response.ok) { throw { status: response.status }; }
    return readBoundedJson(response);
  }

  // Words become a stored reference and read back as words.
  function ref(text, prefix) {
    var s = String(text || "");
    if (s.normalize) { s = s.normalize("NFKD"); }
    s = s.replace(/[^A-Za-z0-9 _.-]+/g, "").trim().replace(/\s+/g, "-").replace(/^[^A-Za-z0-9]+/, "").slice(0, 110);
    return (prefix || "") + (s || R.newId("item"));
  }
  function words(value) {
    if (value === null || value === undefined || value === "") { return "—"; }
    var s = String(value).replace(/^(doc|field|calc)\./, "").replace(/[-_.:]+/g, " ").trim();
    return s.charAt(0).toUpperCase() + s.slice(1);
  }
  function personRef(principal) { return String(principal || "").replace(/@/g, ".at.").slice(0, 128); }
  function personName(refValue) {
    var p = S.people.filter(function (x) { return personRef(x.value) === refValue; })[0];
    if (!p && /^(?:contract|tpc|tpl|tpi)-principal-[a-f0-9]+$/.test(String(refValue || ""))) { return "Recorded owner"; }
    return p ? p.label : words(String(refValue || "").replace(/^user:/, "").replace(/\.at\./, "@"));
  }
  function vendorName(id) { var v = S.vendors.filter(function (x) { return x.vendor_id === id; })[0]; return v ? v.display_label : "A vendor"; }
  function dayOf(ts) { return ts ? R.day(ts) : "—"; }
  function dateValue(ts) { return ts ? new Date(ts * 1000).toISOString().slice(0, 10) : ""; }
  function epoch(value) { if (!value) { return null; } var t = new Date(value + "T00:00:00Z").getTime(); return isFinite(t) ? t / 1000 : null; }
  function fill(select, options, keepFirst) {
    var first = keepFirst ? select.options[0] : null;
    select.textContent = "";
    if (first) { select.appendChild(first); }
    options.forEach(function (o) { var opt = R.el("option", "", o.label); opt.value = o.value; select.appendChild(opt); });
  }

  // ---- loading -----------------------------------------------------------------
  function setReady(ready, headline, detail, badgeKind) {
    operations.disabled = !ready;
    say(document.getElementById("tpc-readiness"), headline);
    var mark = document.getElementById("tpc-status-mark");
    mark.textContent = ready ? "Ready" : "Unavailable";
    mark.className = "badge " + (badgeKind || (ready ? "ok" : "warn"));
    say(document.getElementById("tpc-readiness-detail"), detail);
  }
  function loadChoices() {
    return Promise.all([
      R.call("GET", "/api/v1/third-party/intelligence/vendors").then(function (d) {
        S.vendors = (d.items || []).filter(function (v) { return v.state === "active"; });
      }).catch(function () { S.vendors = []; }),
      R.call("GET", "/api/v1/choices/people").then(function (d) { S.people = d.people || []; }).catch(function () { S.people = []; }),
    ]).then(function () {
      var vendorOptions = S.vendors.map(function (v) { return { value: v.vendor_id, label: v.display_label }; });
      var peopleOptions = S.people.map(function (p) { return { value: personRef(p.value), label: p.label }; });
      fill(filters.elements.namedItem("vendor_id"), vendorOptions, true);
      fill(filters.elements.namedItem("owner_ref"), peopleOptions, true);
      fill(filters.elements.namedItem("status"), Object.keys(STATUS).map(function (k) { return { value: k, label: STATUS[k] }; }), true);
      fill(F("vendor_id"), vendorOptions, false);
      fill(F("owner_ref"), peopleOptions, false);
      fill(F("business_owner_ref"), peopleOptions, false);
      if (!profileSelectionApplied) {
        var query = new URLSearchParams(global.location.search);
        var actual = S.vendors.find(function (v) { return query.get('registered_vendor') === v.register_vendor_id || query.get('vendor_id') === v.vendor_id; });
        if (actual) { profileVendor = actual.vendor_id; filters.elements.namedItem('vendor_id').value = profileVendor; F('vendor_id').value = profileVendor; }
        else if (query.get('registered_vendor') || query.get('vendor_id')) { say(listStatus, 'This vendor has no currently usable linked Intelligence identity. Open its registered vendor profile before choosing a contract identity.'); }
        profileSelectionApplied = true;
      }
    });
  }
  function refreshStatus() {
    operations.disabled = true;
    setReady(false, "Checking…", "Checking that contracts are available…", "idle");
    return request("/status").then(function (status) {
      var ready = status && status.enabled === true && status.configured === true && status.ready === true;
      if (!ready) {
        operations.disabled = true;
        var off = status && status.enabled === false;
        setReady(false, "Not available", off
          ? "Contracts are turned off for this workspace. Ask an administrator to turn them on."
          : "Contracts aren't set up for this workspace yet. Ask your IT team to finish the setup.");
        // The list never loads until contracts are ready; say why instead of "Loading…".
        say(listStatus, off ? "Contracts and engagements appear here once this is turned on."
          : "Contracts and engagements appear here once the setup is finished.");
        return;
      }
      setReady(true, "Ready", "Available actions depend on your permissions.");
      operations.disabled = false;
      return loadChoices().then(loadRecords);
    }).catch(function (f) {
      operations.disabled = true;
      setReady(false, "Not available", R.errorText(f, "check contracts"), "danger");
      say(listStatus, R.errorText(f, "load the contracts"));
    });
  }
  function filterQuery() {
    var params = new URLSearchParams({ limit: "200" });
    ["record_kind", "vendor_id", "status", "owner_ref"].forEach(function (k) {
      var v = filters.elements.namedItem(k).value;
      if (v) { params.set(k, v); }
    });
    var sensitive = filters.elements.namedItem("include_sensitive_fields");
    if (sensitive && sensitive.checked) { params.set("include_sensitive_fields", "true"); }
    return params.toString();
  }
  function loadRecords() {
    say(listStatus, "Loading…");
    return request("?" + filterQuery()).then(function (page) {
      S.records = page.items || [];
      render();
      say(listStatus, "Showing " + S.records.length + " contract" + (S.records.length === 1 ? "" : "s") + " and engagements.");
    }).catch(fail(listStatus, "load the contracts"));
  }

  function render() {
    R.table(document.getElementById("tpc-record-list"), [
      { label: "Name", value: function (r) { return words(r.title_ref); } },
      { label: "Kind", value: function (r) { return r.record_kind === "engagement" ? "Engagement" : "Contract"; } },
      { label: "Vendor", value: function (r) { return vendorName(r.vendor_id); } },
      { label: "Owner", value: function (r) { return personName(r.owner_ref); } },
      { label: "Status", value: function (r) { return R.badge(STATUS[r.status] || words(r.status), r.status === "active" ? "ok" : r.status === "archived" ? "idle" : "info"); } },
      { label: "Ends", value: function (r) { var l = r.lifecycle || {}; return dayOf(l.expires_at || l.end_at); } },
    ], S.records, [
      { label: "View details", kind: "primary", run: showDetail },
      { label: "Edit", when: function (r) { return canOperate && r.status !== "archived"; }, run: openEditor },
      { label: "Change status", when: function (r) { return canOperate && ((TRANSITIONS[r.record_kind] || {})[r.status] || []).length; }, run: changeStatus },
      { label: "Archive", when: function (r) { return canOperate && r.status !== "archived"; }, run: archive },
      { label: "Delete permanently", kind: "danger", when: function (r) { return canAdmin && r.status === "archived"; }, run: remove },
    ], { text: "No contracts or engagements match. Add one, or change the filters.", action: canOperate ? { label: "Add a contract or engagement", run: function () { openEditor(null); } } : null });
  }

  function showDetail(r) {
    var host = document.getElementById("tpc-detail");
    host.hidden = false; host.textContent = "";
    host.appendChild(R.el("h3", "", words(r.title_ref)));
    var l = r.lifecycle || {};
    var dl = R.el("dl");
    function row(k, v) { dl.appendChild(R.el("dt", "", k)); dl.appendChild(R.el("dd", "", v === undefined || v === null || v === "" ? "—" : String(v))); }
    row("Vendor", vendorName(r.vendor_id));
    row("Owner", personName(r.owner_ref));
    row("Status", STATUS[r.status] || words(r.status));
    if (r.record_kind === "contract") {
      row("Type", words(l.agreement_type)); row("Signed document", words(l.agreement_ref)); row("Starts", dayOf(l.effective_at));
      row("Ends", dayOf(l.expires_at)); row("Renewal", { none: "Doesn't renew", manual: "We renew it", automatic: "Renews automatically" }[l.renewal_mode]);
      row("Notice period", (l.notice_period_days || 0) + " days"); row("Governing law", words(l.governing_law_ref));
    } else {
      row("Type", words(l.engagement_type)); row("Business owner", personName(l.business_owner_ref)); row("Starts", dayOf(l.start_at));
      row("Ends", dayOf(l.end_at)); row("How critical", words(l.operational_criticality)); row("Access to our data", words(l.data_access));
    }
    (r.field_schema || []).forEach(function (f) {
      var v = (r.field_values || {})[f.field_id];
      row(words(f.label_ref), Array.isArray(v) ? v.map(words).join(", ") : typeof v === "boolean" ? (v ? "Yes" : "No") : f.field_type === "timestamp" ? dayOf(v) : v === undefined ? "Hidden or not set" : words(v));
    });
    Object.keys(r.computed_values || {}).forEach(function (k) { row(words(k), r.computed_values[k]); });
    host.appendChild(dl);
    var actions = R.el("div", "tpc-actions");
    actions.appendChild(R.button("Show history", "", function () { history(r, host); }));
    if (canAudit && r.status === "archived") { actions.appendChild(R.button("Show the deletion note", "", function () { tombstone(r, host); })); }
    host.appendChild(actions);
    window.mvReveal(host);
  }
  function history(r, host) {
    request("/" + encodeURIComponent(r.record_id) + "/history").then(function (d) {
      var box = R.el("div");
      host.appendChild(box);
      R.table(box, [
        { label: "When", value: function (h) { return R.when(h.created_at); } },
        { label: "What happened", value: function (h) { return words(h.event_type); } },
        { label: "By", value: function (h) { return personName(h.actor_ref); } },
        { label: "Changed", value: function (h) { return (h.changed_fields || []).map(words).join(", ") || "—"; } },
      ], d.items || [], [], { text: "No history yet. Changes to this record appear here." });
    }, fail(listStatus, "load the history"));
  }
  function tombstone(r, host) {
    request("/" + encodeURIComponent(r.record_id) + "/tombstone").then(function (t) {
      host.appendChild(R.el("p", "muted", "Deleted on " + R.when(t.deleted_at) + " by " + personName(t.deleted_by_ref) + "."));
    }, function (f) { host.appendChild(R.el("p", "muted", f && f.status === 404 ? "This record hasn't been deleted." : R.errorText(f, "load the deletion note"))); });
  }

  // ---- add and edit --------------------------------------------------------------
  var editing = null;
  function switchKind() {
    var engagement = F("record_kind").value === "engagement";
    var c = document.getElementById("tpc-contract-fields");
    var e = document.getElementById("tpc-engagement-fields");
    c.hidden = engagement; c.disabled = engagement;
    e.hidden = !engagement; e.disabled = !engagement;
    F("agreement").required = !engagement;
  }
  function contractOptions(exclude) {
    return S.records.filter(function (r) { return r.record_kind === "contract" && r.record_id !== exclude; })
      .map(function (r) { return { value: r.record_id, label: words(r.title_ref) + " (" + vendorName(r.vendor_id) + ")" }; });
  }
  function customFieldRow(f, value) {
    var host = document.getElementById("tpc-custom-fields");
    var row = R.el("div", "tpc-row tpc-custom-field");
    var grid = R.el("div", "tpc-grid");
    function control(tag, name, labelText, cls) {
      var label = R.el("label", "", labelText);
      var el = R.el(tag, cls || "input");
      el.name = name;
      label.appendChild(el);
      grid.appendChild(label);
      return el;
    }
    var name = control("input", "cf_name", "Field name"); name.maxLength = 100; name.value = f ? words(f.label_ref) : "";
    var type = control("select", "cf_type", "Type", "select");
    FIELD_TYPES.forEach(function (p) { var o = R.el("option", "", p[1]); o.value = p[0]; type.appendChild(o); });
    type.value = f ? f.field_type : "text_ref";
    var sens = control("select", "cf_sensitivity", "Who may see it", "select");
    SENSITIVITY.forEach(function (p) { var o = R.el("option", "", p[1]); o.value = p[0]; sens.appendChild(o); });
    sens.value = f ? f.sensitivity : "internal";
    var choices = control("input", "cf_choices", "Choices (separate with commas)");
    choices.value = f ? (f.options || []).map(words).join(", ") : "";
    var valueInput = control("input", "cf_value", "Value");
    var req = R.el("label", "tpc-actions"); var cb = R.el("input"); cb.type = "checkbox"; cb.name = "cf_required"; cb.checked = f ? !!f.required : false;
    req.appendChild(cb); req.appendChild(document.createTextNode(" Must be filled in")); grid.appendChild(req);
    row.appendChild(grid);
    row.appendChild(R.button("Remove field", "ghost", function () { row.remove(); }));
    row.dataset.fieldId = f ? f.field_id : "";
    function sync() {
      var t = type.value;
      choices.parentElement.hidden = !(t === "single_choice" || t === "multi_choice");
      valueInput.type = t === "timestamp" ? "date" : (t === "integer" || t === "decimal") ? "number" : "text";
      valueInput.step = t === "decimal" ? "any" : "1";
      valueInput.placeholder = t === "boolean" ? "Yes or no" : (t === "single_choice" || t === "multi_choice") ? "One of the choices" : "";
    }
    type.addEventListener("change", sync);
    sync();
    if (value !== undefined && value !== null) {
      valueInput.value = Array.isArray(value) ? value.map(words).join(", ") : typeof value === "boolean" ? (value ? "Yes" : "No") : f && f.field_type === "timestamp" ? dateValue(value) : f && (f.field_type === "text_ref" || f.field_type === "single_choice") ? words(value) : String(value);
    }
    host.appendChild(row);
  }
  function formulaRow(fm) {
    var host = document.getElementById("tpc-formulas");
    var row = R.el("div", "tpc-row tpc-formula");
    var grid = R.el("div", "tpc-grid");
    var nameLabel = R.el("label", "", "Calculation name"); var name = R.el("input", "input"); name.name = "fm_name"; name.value = fm ? words(fm.formula_id) : "";
    nameLabel.appendChild(name); grid.appendChild(nameLabel);
    var opLabel = R.el("label", "", "What it does"); var op = R.el("select", "select"); op.name = "fm_op";
    OPERATORS.forEach(function (p) { var o = R.el("option", "", p[1]); o.value = p[0]; op.appendChild(o); });
    op.value = fm ? fm.operator : "add"; opLabel.appendChild(op); grid.appendChild(opLabel);
    var fieldsLabel = R.el("label", "", "Using the number fields named (separate with commas)"); var fieldsInput = R.el("input", "input"); fieldsInput.name = "fm_fields";
    fieldsInput.value = fm ? fm.operands.filter(function (o) { return o.source === "field"; }).map(function (o) { return words(o.field_id); }).join(", ") : "";
    fieldsLabel.appendChild(fieldsInput); grid.appendChild(fieldsLabel);
    var constLabel = R.el("label", "", "And this number (optional)"); var constant = R.el("input", "input"); constant.type = "number"; constant.step = "any"; constant.name = "fm_const";
    var lit = fm ? fm.operands.filter(function (o) { return o.source === "literal"; })[0] : null; constant.value = lit ? lit.value : "";
    constLabel.appendChild(constant); grid.appendChild(constLabel);
    row.appendChild(grid);
    row.appendChild(R.button("Remove calculation", "ghost", function () { row.remove(); }));
    host.appendChild(row);
  }
  function openEditor(r) {
    editing = r;
    form.reset();
    document.getElementById("tpc-custom-fields").textContent = "";
    document.getElementById("tpc-formulas").textContent = "";
    fill(F("parent_contract_id"), [{ value: "", label: "No" }].concat(contractOptions(r && r.record_id)), false);
    var linkedHost = document.getElementById("tpc-linked");
    linkedHost.textContent = "";
    contractOptions(r && r.record_id).forEach(function (c) {
      var label = R.el("label"); var cb = R.el("input"); cb.type = "checkbox"; cb.name = "linked"; cb.value = c.value;
      cb.checked = !!(r && r.lifecycle && (r.lifecycle.linked_contract_ids || []).indexOf(c.value) >= 0);
      label.appendChild(cb); label.appendChild(document.createTextNode(" " + c.label)); linkedHost.appendChild(label);
    });
    if (!linkedHost.childNodes.length) { linkedHost.appendChild(R.el("p", "muted", "No contracts to link yet.")); }
    if (!S.vendors.length) { say(formStatus, "Add the vendor on the Third-party Intelligence page first; contracts are linked to those vendors."); }
    F("record_kind").disabled = !!r;
    F("vendor_id").disabled = !!r;
    if (!r && profileVendor && S.vendors.some(function (v) { return v.vendor_id === profileVendor; })) { F('vendor_id').value = profileVendor; }
    document.getElementById("tpc-editor-title").textContent = r ? "Edit " + words(r.title_ref) : "Add a contract or engagement";
    if (r) {
      var l = r.lifecycle || {};
      F("record_kind").value = r.record_kind;
      F("vendor_id").value = r.vendor_id;
      F("title").value = words(r.title_ref);
      F("owner_ref").value = r.owner_ref;
      if (r.record_kind === "contract") {
        F("agreement_type").value = l.agreement_type; F("agreement").value = words(l.agreement_ref); F("renewal_mode").value = l.renewal_mode;
        F("effective_at").value = dateValue(l.effective_at); F("expires_at").value = dateValue(l.expires_at);
        F("notice_period_days").value = l.notice_period_days || 0; F("governing_law").value = l.governing_law_ref || "";
        F("parent_contract_id").value = l.parent_contract_id || "";
      } else {
        F("engagement_type").value = l.engagement_type; F("service_category").value = l.service_category_ref; F("business_owner_ref").value = l.business_owner_ref;
        F("start_at").value = dateValue(l.start_at); F("end_at").value = dateValue(l.end_at); F("operational_criticality").value = l.operational_criticality;
        F("data_access").value = l.data_access; F("hosting_model").value = l.hosting_model;
      }
      (r.field_schema || []).forEach(function (f) { customFieldRow(f, (r.field_values || {})[f.field_id]); });
      (r.formulas || []).forEach(formulaRow);
    }
    switchKind();
    editor.hidden = false;
    window.mvReveal(editor);
    F("title").focus();
  }
  F("record_kind").addEventListener("change", switchKind);
  document.getElementById("tpc-new").addEventListener("click", function () { openEditor(null); });
  document.getElementById("tpc-cancel").addEventListener("click", function () { editor.hidden = true; editing = null; });
  document.getElementById("tpc-add-field").addEventListener("click", function () { customFieldRow(null); });
  document.getElementById("tpc-add-formula").addEventListener("click", function () { formulaRow(null); });

  function customFields() {
    var schema = [];
    var values = {};
    var byName = {};
    document.querySelectorAll("#tpc-custom-fields .tpc-custom-field").forEach(function (row) {
      var q = function (n) { return row.querySelector('[name="' + n + '"]'); };
      var label = q("cf_name").value.trim();
      if (!label) { return; }
      var type = q("cf_type").value;
      var id = row.dataset.fieldId || ref(label, "field.").toLowerCase().slice(0, 100);
      var options = (type === "single_choice" || type === "multi_choice")
        ? q("cf_choices").value.split(",").map(function (s) { return s.trim(); }).filter(Boolean).map(function (s) { return ref(s, ""); }) : [];
      if ((type === "single_choice" || type === "multi_choice") && !options.length) { throw plain("Add the choices for \"" + label + "\"."); }
      schema.push({ field_id: id, label_ref: ref(label, ""), field_type: type, required: q("cf_required").checked, sensitivity: q("cf_sensitivity").value, options: options });
      byName[label.toLowerCase()] = id;
      var raw = q("cf_value").value.trim();
      if (!raw) { if (q("cf_required").checked) { throw plain("Fill in \"" + label + "\"."); } return; }
      var v;
      if (type === "boolean") { v = /^(y|yes|true)$/i.test(raw); }
      else if (type === "integer") { v = parseInt(raw, 10); }
      else if (type === "decimal") { v = parseFloat(raw); }
      else if (type === "timestamp") { v = epoch(raw); }
      else if (type === "multi_choice") { v = raw.split(",").map(function (s) { return ref(s.trim(), ""); }).filter(function (s) { return options.indexOf(s) >= 0; }); }
      else if (type === "single_choice") { v = ref(raw, ""); if (options.indexOf(v) < 0) { throw plain("Pick one of the choices for \"" + label + "\"."); } }
      else { v = ref(raw, "doc."); }
      if (v === null || (typeof v === "number" && !isFinite(v))) { throw plain("Check the value of \"" + label + "\"."); }
      values[id] = v;
    });
    var formulas = [];
    document.querySelectorAll("#tpc-formulas .tpc-formula").forEach(function (row) {
      var q = function (n) { return row.querySelector('[name="' + n + '"]'); };
      var name = q("fm_name").value.trim();
      if (!name) { return; }
      var operands = q("fm_fields").value.split(",").map(function (s) { return s.trim().toLowerCase(); }).filter(Boolean).map(function (n) {
        if (!byName[n]) { throw plain("\"" + n + "\" isn't one of your custom fields."); }
        return { source: "field", field_id: byName[n] };
      });
      var c = q("fm_const").value;
      if (c !== "") { operands.push({ source: "literal", value: Number(c) }); }
      if (!operands.length) { throw plain("Choose what \"" + name + "\" calculates from."); }
      formulas.push({ formula_id: ref(name, "calc.").toLowerCase().slice(0, 100), operator: q("fm_op").value, operands: operands, round_digits: 2 });
    });
    return { schema: schema, values: values, formulas: formulas };
  }
  function lifecycle(kind) {
    if (kind === "contract") {
      var body = { agreement_type: F("agreement_type").value, agreement_ref: ref(F("agreement").value, "doc."),
        effective_at: epoch(F("effective_at").value), expires_at: epoch(F("expires_at").value), renewal_mode: F("renewal_mode").value,
        notice_period_days: Math.max(0, parseInt(F("notice_period_days").value, 10) || 0) };
      if (F("governing_law").value) { body.governing_law_ref = F("governing_law").value; }
      if (F("parent_contract_id").value) { body.parent_contract_id = F("parent_contract_id").value; }
      if (!F("agreement").value.trim()) { throw plain("Say where the signed document is."); }
      return body;
    }
    return { engagement_type: F("engagement_type").value, service_category_ref: F("service_category").value,
      start_at: epoch(F("start_at").value), end_at: epoch(F("end_at").value), operational_criticality: F("operational_criticality").value,
      data_access: F("data_access").value, hosting_model: F("hosting_model").value, business_owner_ref: F("business_owner_ref").value,
      linked_contract_ids: Array.prototype.map.call(form.querySelectorAll('input[name="linked"]:checked'), function (c) { return c.value; }) };
  }
  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var kind = editing ? editing.record_kind : F("record_kind").value;
    Promise.resolve().then(function () {
      if (!F("title").value.trim()) { throw plain("Give it a name."); }
      if (!editing && !F("vendor_id").value) { throw plain("Choose the vendor."); }
      if (!F("owner_ref").value) { throw plain("Choose the owner."); }
      var custom = customFields();
      var life = lifecycle(kind);
      if (editing) {
        return request("/" + (kind === "contract" ? "contracts/" : "engagements/") + encodeURIComponent(editing.record_id), "PATCH", {
          expected_revision: editing.revision, title_ref: ref(F("title").value, ""), owner_ref: F("owner_ref").value, lifecycle: life,
          field_schema: custom.schema, field_values: custom.values, formulas: custom.formulas, idempotency_key: R.newKey(),
        });
      }
      var vendor = S.vendors.filter(function (v) { return v.vendor_id === F("vendor_id").value; })[0];
      var body = { vendor_id: vendor.vendor_id, vendor_revision: vendor.revision, title_ref: ref(F("title").value, ""), owner_ref: F("owner_ref").value,
        status: kind === "contract" ? F("contract_status").value : F("engagement_status").value, lifecycle: life,
        field_schema: custom.schema, field_values: custom.values, formulas: custom.formulas, idempotency_key: R.newKey() };
      return request("/" + (kind === "contract" ? "contracts" : "engagements"), "POST", body);
    }).then(function () {
      say(formStatus, "Saved.");
      editor.hidden = true; editing = null;
      return loadRecords();
    }).catch(fail(formStatus, "save it"));
  });

  // ---- row actions ---------------------------------------------------------------
  function changeStatus(r) {
    var next = (TRANSITIONS[r.record_kind] || {})[r.status] || [];
    R.form("Change the status of " + words(r.title_ref), [
      { key: "status", label: "New status", type: "select", default: next[0], options: next.map(function (s) { return { value: s, label: STATUS[s] }; }) },
    ], "Change").then(function (v) {
      if (!v) { return; }
      var ask = v.status === "terminated" ? R.confirm("End " + words(r.title_ref) + "? It can only be archived afterwards.", "End it") : Promise.resolve(true);
      return ask.then(function (ok) {
        if (!ok) { return; }
        return request("/" + (r.record_kind === "contract" ? "contracts/" : "engagements/") + encodeURIComponent(r.record_id), "PATCH",
          { expected_revision: r.revision, status: v.status, idempotency_key: R.newKey() }).then(function () { say(listStatus, "Status changed."); return loadRecords(); });
      });
    }).catch(fail(listStatus, "change the status"));
  }
  function archive(r) {
    R.confirm("Archive " + words(r.title_ref) + "? It can no longer be edited and will be deleted when its keep period ends.", "Archive").then(function (ok) {
      if (!ok) { return; }
      return request("/" + encodeURIComponent(r.record_id) + "/archive", "POST", { expected_revision: r.revision, idempotency_key: R.newKey() })
        .then(function () { say(listStatus, "Archived."); return loadRecords(); });
    }).catch(fail(listStatus, "archive it"));
  }
  function remove(r) {
    R.confirm("Delete " + words(r.title_ref) + " permanently? The contract and its history are deleted. A short note that it existed is kept.", "Delete").then(function (ok) {
      if (!ok) { return; }
      return request("/" + encodeURIComponent(r.record_id), "DELETE", { expected_revision: r.revision, idempotency_key: R.newKey() })
        .then(function () { say(listStatus, "Deleted."); return loadRecords(); });
    }).catch(fail(listStatus, "delete it"));
  }

  // ---- administrator tools -------------------------------------------------------
  document.getElementById("tpc-verify-integrity").addEventListener("click", function () {
    request("/operations/integrity").then(function () { say(opStatus, "No changes found in the contract records."); }, fail(opStatus, "check the records"));
  });
  document.getElementById("tpc-retention-due").addEventListener("click", function () {
    request("/operations/retention-due?limit=200").then(function (d) {
      say(opStatus, (d.items || []).length + " archived record(s) are due for deletion.");
      R.table(document.getElementById("tpc-admin-list"), [
        { label: "Name", value: function (r) { return words(r.title_ref); } },
        { label: "Vendor", value: function (r) { return vendorName(r.vendor_id); } },
        { label: "Keep until", value: function (r) { return dayOf(r.retained_until); } },
      ], d.items || [], [], { text: "Nothing is due for deletion." });
    }, fail(opStatus, "load the records due for deletion"));
  });
  document.getElementById("tpc-recovery-preflight").addEventListener("click", function () {
    Promise.all([request("/status"), request("/operations/integrity")]).then(function (res) {
      var ok = res[0] && res[0].ready === true;
      say(opStatus, ok ? "Records are consistent and ready to be backed up. Backups run on the schedule your IT team set." : "Contracts aren't ready, so a backup would be incomplete. Ask your IT team.");
    }, fail(opStatus, "check backup readiness"));
  });
  document.getElementById("tpc-purge").addEventListener("click", function () {
    R.confirm("Delete archived contracts whose keep period has ended? A short note that each existed is kept. This can't be undone.", "Delete").then(function (ok) {
      if (!ok) { return; }
      return request("/operations/purge-expired", "POST", { limit: 1000 }).then(function (d) {
        say(opStatus, (d.removed && d.removed.length !== undefined ? d.removed.length : d.removed || 0) + " expired record(s) deleted.");
        return loadRecords();
      });
    }).catch(fail(opStatus, "delete expired contracts"));
  });

  Array.prototype.forEach.call(filters.elements, function (el) { el.addEventListener("change", function () { loadRecords(); }); });
  filters.addEventListener("submit", function (ev) { ev.preventDefault(); loadRecords(); });
  document.getElementById("tpc-refresh-status").addEventListener("click", refreshStatus);
  // A turned-off module shows its gate instead: nothing is checked or loaded,
  // and the page already says when records will appear.
  if (shell.dataset.moduleEnabled !== "false") { refreshStatus(); }
}(typeof window !== "undefined" ? window : this));
