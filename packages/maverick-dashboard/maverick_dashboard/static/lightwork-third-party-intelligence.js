// Third-party intelligence page: data sources, vendors, screening, risk
// decisions, due diligence, monitoring and partner sharing load as lists on
// arrival; each change is a row button or a guided form. Record references,
// versions, request keys and fingerprints are carried from the chosen row or
// computed on the server, never typed by a person.
(function () {
  "use strict";
  var root = document.getElementById("tpi-root");
  if (!root || !window.LwRecords) { return; }
  var R = window.LwRecords;
  var API = root.getAttribute("data-api") || "/api/v1/third-party/intelligence";
  var canAdmin = root.getAttribute("data-can-admin") === "true";
  var canAudit = root.getAttribute("data-can-audit") === "true";
  var statusLine = document.getElementById("tpi-status");
  var S = { me: "", status: null, sources: [], snapshots: [], vendors: [], runs: [], policies: [], decisions: [], cases: [], monitors: [], alerts: [], consents: [], register: [], recipients: [], deliveries: [], mailContext: "" };
  var mailBusy = false, recipientPending = null, lastSavedRecipient = null;

  var KINDS = [["sanctions", "Sanctions lists"], ["pep", "Politically exposed people"], ["watchlist", "Watchlists"], ["adverse_media", "Negative news"],
    ["cyber_posture", "Cyber security rating"], ["breach_intelligence", "Data breaches"], ["compliance", "Compliance records"], ["performance", "Performance"]];
  var PURPOSES = [["screening", "Screening"], ["monitoring", "Watching for changes"], ["risk_scoring", "Risk scoring"], ["edd", "Enhanced due diligence"], ["exchange", "Sharing with partners"]];
  var REGIONS = [["GLOBAL", "Worldwide"], ["US", "United States"], ["EU", "European Union"], ["GB", "United Kingdom"], ["CA", "Canada"], ["AU", "Australia"], ["APAC", "Asia Pacific"], ["LATAM", "Latin America"]];
  var PROVIDERS = [["riskrecon", "RiskRecon"], ["securityscorecard", "SecurityScorecard"], ["hacknotice", "HackNotice"], ["supplywisdom", "SupplyWisdom"], ["iss", "ISS Corporate Solutions"], ["generic", "Another approved provider"]];
  var LEVELS = [["1", "1 – Very low"], ["2", "2 – Low"], ["3", "3 – Medium"], ["4", "4 – High"], ["5", "5 – Very high"]];
  var ACCESS = [["none", "No access to our data"], ["limited", "Limited access"], ["standard", "Standard access"], ["sensitive", "Access to sensitive data"]];
  var CATEGORIES = [["cloud-hosting", "Cloud hosting"], ["software", "Software"], ["payments", "Payments"], ["professional-services", "Professional services"], ["data-processing", "Data processing"], ["logistics", "Logistics"], ["other", "Other"]];
  var SEVERITY = [["informational", "For information"], ["low", "Low"], ["medium", "Medium"], ["high", "High"], ["critical", "Critical"]];
  var DISPOSITION = [["not_a_match", "Not the same company"], ["false_positive", "Wrongly flagged"], ["confirmed", "Confirmed match"], ["escalated", "Needs a closer look"]];
  var DECISION = { approved: ["Approved", "ok"], rejected: ["Rejected", "danger"], human_review: ["Needs a person's review", "warn"] };
  var STATE = { pending: ["Waiting for approval", "warn"], approved: ["Approved", "ok"], complete: ["Completed", "ok"], blocked: ["Blocked by a match", "danger"], escalated: ["Escalated", "warn"], rejected: ["Rejected", "danger"], revoked: ["Revoked", "idle"],
    active: ["Active", "ok"], open: ["Open", "info"], in_review: ["In review", "warn"], completed: ["Completed", "ok"], decided: ["Decided", "ok"], withdrawn: ["Withdrawn", "idle"],
    pending_review: ["Waiting for review", "warn"], review_required: ["Review needed", "warn"] };
  var FACTORS = [["inherent_risk", "Inherent risk"], ["criticality", "How critical they are"], ["sanctions", "Sanctions"], ["pep", "Politically exposed people"], ["watchlist", "Watchlists"],
    ["adverse_media", "Negative news"], ["cyber_posture", "Cyber security rating"], ["breach_intelligence", "Data breaches"], ["compliance", "Compliance"], ["performance", "Performance"]];
  var KEEP = [["365", "1 year"], ["1095", "3 years"], ["2555", "7 years"]];

  function label(list, value) { var m = list.filter(function (p) { return p[0] === value; })[0]; return m ? m[1] : R.human(value); }
  function opts(list) { return list.map(function (p) { return { value: p[0], label: p[1] }; }); }
  function badge(value) { var s = STATE[value] || [R.human(value), "idle"]; return R.badge(s[0], s[1]); }
  function say(text) { window.mvStatus(statusLine, text); }
  function fail(action) { return function (f) { var t = f && f.plain ? f.plain : R.errorText(f, action); say(t); if (window.mvToast) { window.mvToast(t, { error: true }); } }; }
  function plain(text) { var e = new Error("plain"); e.plain = text; return e; }
  function api(method, path, body) { return R.call(method, API + path, body); }
  function ref(text, prefix) {
    var s = String(text || "");
    if (s.normalize) { s = s.normalize("NFKD"); }
    s = s.replace(/[^A-Za-z0-9 _.-]+/g, "").trim().replace(/\s+/g, "-").replace(/^[^A-Za-z0-9]+/, "").slice(0, 100);
    return (prefix || "") + (s || R.newId("item"));
  }
  function textFingerprint(text) { return R.fingerprint(new Blob([String(text)], { type: "text/plain" })).then(function (d) { return d.sha256; }); }
  function fileFingerprint(what) {
    return R.pickFile().then(function (file) {
      if (!file) { throw plain("Choose the " + what + " file."); }
      return R.fingerprint(file).then(function (d) { return { sha: d.sha256, name: file.name }; });
    });
  }
  function days(n) { return Number(n) * 86400; }
  function vendorOf(id) { return S.vendors.filter(function (v) { return v.vendor_id === id; })[0]; }
  function vendorName(id) { var v = vendorOf(id); return v ? v.display_label : "A vendor"; }
  function sourceOf(id) { return S.sources.filter(function (s) { return s.source_id === id; })[0]; }
  function mine(actor) { return actor && actor === S.me; }
  function regionFields(prefix) { return REGIONS.map(function (r, i) { return { key: prefix + i, label: r[1], type: "bool", default: i === 0 }; }); }
  function chosenRegions(values, prefix) { return REGIONS.filter(function (_r, i) { return values[prefix + i]; }).map(function (r) { return r[0]; }); }
  function citation(title, uri, where) { return [{ citation_id: R.newId("citation"), title: title, uri: uri, pinpoint: where || "Whole document" }]; }
  function citationFields() {
    return [
      { key: "cite_title", label: "Name of the source document", required: true, placeholder: "For example: Monthly sanctions list" },
      { key: "cite_uri", label: "Its web address (starts with https://)", required: true, placeholder: "https://" },
      { key: "cite_where", label: "Where in it (page or section, optional)" },
    ];
  }
  function checkUri(uri) { if (!/^https:\/\/\S+$/.test(uri || "")) { throw plain("The web address must start with https://."); } }

  // ---- loading ---------------------------------------------------------------
  function load(path, key) { return api("GET", path).then(function (d) { S[key] = d.items || []; }); }
  function loadAll() {
    say("Loading…");
    return Promise.all([
      api("GET", "/me").then(function (d) { S.me = d.principal_ref; }),
      api("GET", "/status").then(function (d) { S.status = d; }),
      load("/sources", "sources"), load("/snapshots", "snapshots"), load("/vendors", "vendors"), load("/screening/runs", "runs"),
      load("/risk/policies", "policies"), load("/risk/decisions", "decisions"), load("/edd/cases", "cases"),
      load("/monitors", "monitors"), load("/monitoring/alerts", "alerts"), load("/exchange/consents", "consents"),
      api("GET", "/alert-recipients").then(function (d) { S.recipients = d.items || []; S.mailContext = d.context; }).catch(function (e) { if (e.status !== 403) { throw e; } }),
      load("/outbox", "deliveries"),
      R.call("GET", "/api/v1/vendors").then(function (d) { S.register = d.vendors || []; }).catch(function () { S.register = []; }),
    ]).then(function () {
      renderStatus(); renderSources(); renderVendors(); renderRuns(); renderPolicies(); renderDecisions(); renderCases(); renderRecipients(); renderMonitors(); renderConsents();
      say("Up to date.");
    }).catch(fail("load the intelligence records"));
  }

  function renderStatus() {
    var host = document.getElementById("tpi-status-card");
    host.textContent = "";
    var st = S.status || {};
    var runtime = st.provider_runtime || {};
    var providers = (runtime.enabled_providers || []).map(function (p) { return label(PROVIDERS, p); });
    var grid = R.el("div", "grid");
    function stat(num, text) { var d = R.el("div", "stat"); d.appendChild(R.el("div", "num", num)); d.appendChild(R.el("div", "label", text)); grid.appendChild(d); }
    stat(String(S.sources.filter(function (s) { return s.state === "active"; }).length), "Approved data sources");
    stat(String(S.vendors.length), "Vendors");
    stat(String(S.runs.filter(function (r) { return r.state === "open"; }).length), "Screenings in progress");
    stat(String(S.alerts.length), "Change alerts");
    host.appendChild(grid);
    host.appendChild(R.el("p", "muted", providers.length ? "Providers set up by your IT team: " + providers.join(", ") + "." :
      "No provider connections are set up yet. Your IT team adds them; until then you can record data updates by hand."));
    host.appendChild(R.el("p", "muted", (st.provider_scheduler && st.provider_scheduler.running) ? "Automatic data collection is running." : "Automatic data collection is off."));
  }

  // ---- data sources ------------------------------------------------------------
  function renderSources() {
    R.table(document.getElementById("tpi-sources"), [
      { label: "Provider", value: function (s) { return label(PROVIDERS, s.provider); } },
      { label: "Data", value: function (s) { return label(KINDS, s.kind); } },
      { label: "Used for", value: function (s) { return (s.purposes || []).map(function (p) { return label(PURPOSES, p); }).join(", "); } },
      { label: "Regions", value: function (s) { return (s.territories || []).map(function (t) { return label(REGIONS, t); }).join(", "); } },
      { label: "Status", value: function (s) { return badge(s.state === "active" ? "approved" : s.state); } },
      { label: "Latest data", value: function (s) { var snaps = S.snapshots.filter(function (x) { return x.source_id === s.source_id; }); var last = snaps.sort(function (a, b) { return b.observed_at - a.observed_at; })[0]; return last ? R.day(last.observed_at) : "None yet"; } },
    ], S.sources, [
      { label: "Approve", kind: "primary", when: function (s) { return canAdmin && s.state === "pending" && !mine(s.enrolled_by); }, run: function (s) { decideSource(s, true); } },
      { label: "Reject", when: function (s) { return canAdmin && s.state === "pending" && !mine(s.enrolled_by); }, run: function (s) { decideSource(s, false); } },
      { label: "Test connection", when: function (s) { return canAdmin && s.state === "active"; }, run: testSource },
      { label: "Record a data update", when: function (s) { return s.state === "active"; }, run: recordSnapshot },
      { label: "Revoke", kind: "danger", when: function (s) { return canAdmin && s.state === "active"; }, run: revokeSource },
    ], { text: "No data sources yet. Add the risk data you subscribe to.", action: canAdmin ? { label: "Add a data source", run: addSource } : null });
  }
  function addSource() {
    if (!canAdmin) { say("Only administrators can add data sources."); return; }
    var enabled = ((S.status || {}).provider_runtime || {}).enabled_providers || [];
    var providerOptions = opts(PROVIDERS.filter(function (p) { return !enabled.length || enabled.indexOf(p[0]) >= 0 || p[0] === "generic"; }));
    R.form("Add a data source", [
      { key: "provider", label: "Provider", type: "select", default: providerOptions[0].value, options: providerOptions },
      { key: "kind", label: "Kind of data", type: "select", default: "sanctions", options: opts(KINDS) },
      { key: "uri", label: "Where the data comes from (web address)", required: true, placeholder: "https://" },
      { key: "credential", label: "Connection key name (your IT team gives you this)", required: true, placeholder: "For example: SANCTIONS PROVIDER TOKEN" },
      { key: "license", label: "License or contract name", required: true },
      { key: "rights", label: "What the license allows", required: true, placeholder: "For example: Screening our own suppliers" },
    ].concat(PURPOSES.map(function (p, i) { return { key: "p" + i, label: "Use for: " + p[1], type: "bool", default: i < 2 }; }))
     .concat(regionFields("r"))
     .concat([{ key: "keep", label: "Keep the data for", type: "select", default: "365", options: opts(KEEP) }]), "Add source").then(function (v) {
      if (!v) { return; }
      checkUri(v.uri);
      var purposes = PURPOSES.filter(function (_p, i) { return v["p" + i]; }).map(function (p) { return p[0]; });
      var regions = chosenRegions(v, "r");
      if (!purposes.length) { throw plain("Choose at least one use."); }
      if (!regions.length) { throw plain("Choose at least one region."); }
      var envName = String(v.credential).trim().toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_+|_+$/g, "");
      if (!/^[A-Z][A-Z0-9_]{1,127}$/.test(envName)) { throw plain("Check the connection key name with your IT team."); }
      return api("PUT", "/sources/" + encodeURIComponent(R.newId("source")), {
        provider: v.provider, kind: v.kind, provenance_uri: v.uri, credential_env: envName, license_ref: v.license, rights_basis: v.rights,
        purposes: purposes, territories: regions, retention_seconds: days(v.keep), expected_revision: 0, idempotency_key: R.newKey(),
      }).then(function () { say("Data source added. A different administrator now needs to approve it."); loadAll(); });
    }).catch(fail("add the data source"));
  }
  function decideSource(s, approved) {
    R.form((approved ? "Approve " : "Reject ") + label(PROVIDERS, s.provider) + " (" + label(KINDS, s.kind) + ")", [{ key: "why", label: "Reason", required: true }], approved ? "Approve" : "Reject").then(function (v) {
      if (!v) { return; }
      return api("POST", "/sources/" + encodeURIComponent(s.source_id) + "/approval", { expected_revision: s.revision, approved: approved, rationale: v.why, idempotency_key: R.newKey() })
        .then(function () { say(approved ? "Data source approved." : "Data source rejected."); loadAll(); });
    }).catch(fail("record the decision"));
  }
  function revokeSource(s) {
    R.form("Revoke " + label(PROVIDERS, s.provider), [{ key: "why", label: "Reason", required: true }], "Revoke").then(function (v) {
      if (!v) { return; }
      return R.confirm("Revoke this data source? It can no longer be used for screening or monitoring, and alerts waiting to be sent from it are cancelled.", "Revoke").then(function (ok) {
        if (!ok) { return; }
        return api("POST", "/sources/" + encodeURIComponent(s.source_id) + "/revoke", { expected_revision: s.revision, rationale: v.why, idempotency_key: R.newKey() })
          .then(function () { say("Data source revoked."); loadAll(); });
      });
    }).catch(fail("revoke the data source"));
  }
  function testSource(s) {
    say("Testing the connection…");
    api("POST", "/provider-runtime/sources/" + encodeURIComponent(s.source_id) + "/readiness").then(function (d) {
      say(d.ready ? "The connection is ready. Lightwork will try it on the next collection." : "The connection isn't ready yet. Ask your IT team to check the connection key.");
    }, function (f) {
      say(f && f.status === 403 ? "This source isn't approved for watching for changes, so it can't be collected automatically. Collect it by hand, or ask an administrator to approve it." : R.errorText(f, "test the connection"));
    });
  }
  function recordSnapshot(s) {
    R.form("Record a data update from " + label(PROVIDERS, s.provider), [
      { key: "name", label: "Name of this update", required: true, placeholder: "For example: September list" },
      { key: "observed", label: "Date of the data", type: "date", required: true, default: R.isoDateIn(0) },
      { key: "valid", label: "Valid until", type: "date", required: true, default: R.isoDateIn(30) },
      { key: "complete", label: "How complete is it (%)", type: "number", required: true, default: "100" },
      { key: "count", label: "Number of records", type: "number", required: true, default: "0" },
    ].concat(citationFields()), "Choose the data file").then(function (v) {
      if (!v) { return; }
      checkUri(v.cite_uri);
      return fileFingerprint("data").then(function (file) {
        return api("PUT", "/sources/" + encodeURIComponent(s.source_id) + "/snapshots/" + encodeURIComponent(R.newId("snapshot")), {
          dataset_revision: ref(v.name, ""), observed_at: R.toEpoch(v.observed), valid_until: R.toEpoch(v.valid),
          completeness: Math.max(0, Math.min(1, Number(v.complete) / 100)), record_count: Math.max(0, parseInt(v.count, 10) || 0),
          evidence_sha256: file.sha, citations: citation(v.cite_title, v.cite_uri, v.cite_where), provenance_uri: s.provenance_uri, idempotency_key: R.newKey(),
        });
      }).then(function () { say("Data update recorded."); loadAll(); });
    }).catch(fail("record the data update"));
  }
  document.getElementById("tpi-add-source").addEventListener("click", addSource);

  // ---- vendors ---------------------------------------------------------------
  function renderVendors() {
    R.table(document.getElementById("tpi-vendors"), [
      { label: "Vendor", value: function (v) { return v.display_label; } },
      { label: "Regions", value: function (v) { return (v.territories || []).map(function (t) { return label(REGIONS, t); }).join(", "); } },
      { label: "Inherent risk", value: function (v) { return label(LEVELS, String(v.inherent_risk_level)); } },
      { label: "How critical", value: function (v) { return label(LEVELS, String(v.criticality)); } },
      { label: "Access to our data", value: function (v) { return label(ACCESS, v.data_access_level); } },
      { label: "Latest decision", value: function (v) { var d = latestDecision(v.vendor_id); return d ? badge2(DECISION, d.status) : "None yet"; } },
    ], S.vendors, [
      { label: "Open registered vendor", when: function (v) { return !!v.register_vendor_id; }, run: function (v) { window.location.href = '/privacy/vendors/' + encodeURIComponent(v.register_vendor_id) + '#vendor-profile'; } },
      { label: "Screen", kind: "primary", run: screen },
      { label: "Decide risk", run: evaluate },
      { label: "Watch for changes", run: watch },
      { label: "Start due diligence", run: openCase },
      { label: "Add a relationship", run: relate },
      { label: "Share with partners", run: share },
    ], { text: "No vendors yet. Add a vendor from your vendor list to screen it.", action: { label: "Add a vendor", run: addVendor } });
  }
  function badge2(map, value) { var s = map[value] || [R.human(value), "idle"]; return R.badge(s[0], s[1]); }
  function latestDecision(vendorId) {
    return S.decisions.filter(function (d) { return d.vendor_id === vendorId; }).sort(function (a, b) { return b.decided_at - a.decided_at; })[0];
  }
  function addVendor() {
    var register = S.register.filter(function (v) { return !S.vendors.some(function (profile) { return profile.register_vendor_id === v.id; }); }).map(function (v) { return { value: v.id, label: v.name }; });
    if (!register.length) { say('Register the vendor in Privacy first, or open its already linked Intelligence identity. Existing separate identities can be linked from the vendor profile.'); return; }
    var selectedVendor = new URLSearchParams(window.location.search).get('registered_vendor');
    R.form("Add a vendor", [
      { key: "pick", label: "Registered vendor", type: "select", default: register.some(function (row) { return row.value === selectedVendor; }) ? selectedVendor : register[0].value, options: register },
      { key: "category", label: "What they do for us", type: "select", default: "software", options: opts(CATEGORIES) },
      { key: "inherent", label: "Inherent risk", type: "select", default: "3", options: opts(LEVELS) },
      { key: "critical", label: "How critical they are to us", type: "select", default: "3", options: opts(LEVELS) },
      { key: "access", label: "Access to our data", type: "select", default: "limited", options: opts(ACCESS) },
    ].concat(regionFields("r")), "Add vendor").then(function (v) {
      if (!v) { return; }
      var registered = S.register.find(function (row) { return row.id === v.pick; });
      if (!registered) { throw plain("Choose a current registered vendor."); }
      var name = registered.name;
      var regions = chosenRegions(v, "r");
      if (!regions.length) { throw plain("Choose at least one region."); }
      var slugName = ref(name, "").toLowerCase();
      // The vendor's identity is stored as a fingerprint the server computes.
      return textFingerprint("vendor:" + name.trim().toLowerCase()).then(function (identity) {
        return api("PUT", "/vendors/" + encodeURIComponent(R.newId("vendor")), {
          display_label: name, entity_identity_sha256: identity, encrypted_profile_ref: ("profile." + slugName).slice(0, 128), profile_key_ref: "profile-key.default",
          territories: regions, service_categories: [v.category], inherent_risk_level: Number(v.inherent), criticality: Number(v.critical),
          data_access_level: v.access, expected_revision: 0, idempotency_key: R.newKey(),
          register_vendor_id: registered.id,
        });
      }).then(function () { say("Vendor added."); loadAll(); });
    }).catch(fail("add the vendor"));
  }
  document.getElementById("tpi-add-vendor").addEventListener("click", addVendor);

  function usableSnapshot(kind, purpose) {
    var now = Date.now() / 1000;
    return S.snapshots.filter(function (x) {
      var src = sourceOf(x.source_id);
      return src && src.kind === kind && src.state === "active" && (src.purposes || []).indexOf(purpose) >= 0 && x.valid_until > now;
    }).sort(function (a, b) { return b.observed_at - a.observed_at; })[0];
  }
  function availableKinds(purpose) { return KINDS.filter(function (k) { return usableSnapshot(k[0], purpose); }); }
  function screen(v) {
    var kinds = availableKinds("screening");
    if (!kinds.length) { say("There's no current, approved data to screen against. Add a data source and record a data update first."); return; }
    R.form("Screen " + v.display_label, kinds.map(function (k, i) { return { key: "k" + i, label: "Check " + k[1], type: "bool", default: true }; }), "Start screening").then(function (vals) {
      if (!vals) { return; }
      var chosen = kinds.filter(function (_k, i) { return vals["k" + i]; }).map(function (k) { return k[0]; });
      if (!chosen.length) { throw plain("Choose at least one check."); }
      var bindings = {};
      chosen.forEach(function (k) { bindings[k] = usableSnapshot(k, "screening").snapshot_id; });
      return api("PUT", "/screening/runs/" + encodeURIComponent(R.newId("screening")), {
        vendor_id: v.vendor_id, subject_identity_sha256: v.entity_identity_sha256, snapshot_bindings: bindings, requested_kinds: chosen, idempotency_key: R.newKey(),
      }).then(function () { say("Screening started. Record any possible matches, have them reviewed, then complete it."); loadAll(); });
    }).catch(fail("start the screening"));
  }
  function relate(v) {
    var others = S.vendors.filter(function (o) { return o.vendor_id !== v.vendor_id; }).map(function (o) { return { value: o.vendor_id, label: o.display_label }; });
    R.form("Add a relationship for " + v.display_label, [
      { key: "type", label: "Relationship", type: "select", default: "subprocessor", options: [
        { value: "subprocessor", label: "They use a subcontractor" }, { value: "parent-company", label: "Parent company" },
        { value: "reseller", label: "Reseller" }, { value: "supplier", label: "Supplier to us" }] },
      { key: "other", label: "Related vendor (optional)", type: "select", default: "", options: [{ value: "", label: "Not in the list" }].concat(others) },
      { key: "scope", label: "What it covers", required: true, placeholder: "For example: Payroll processing" },
      { key: "critical", label: "How critical", type: "select", default: String(v.criticality), options: opts(LEVELS) },
      { key: "access", label: "Access to our data", type: "select", default: v.data_access_level, options: opts(ACCESS) },
    ], "Save").then(function (vals) {
      if (!vals) { return; }
      var body = { vendor_id: v.vendor_id, relationship_type: vals.type, scope_ref: ref(vals.scope, ""), criticality: Number(vals.critical),
        data_access_level: vals.access, expected_revision: 0, idempotency_key: R.newKey() };
      if (vals.other) { body.related_vendor_id = vals.other; }
      return api("PUT", "/relationships/" + encodeURIComponent(R.newId("relationship")), body).then(function () { say("Relationship saved."); });
    }).catch(fail("save the relationship"));
  }

  // ---- screening ---------------------------------------------------------------
  function renderRuns() {
    R.table(document.getElementById("tpi-runs"), [
      { label: "Vendor", value: function (r) { return vendorName(r.vendor_id); } },
      { label: "Checks", value: function (r) { return (r.requested_kinds || []).map(function (k) { return label(KINDS, k); }).join(", "); } },
      { label: "Status", value: function (r) { return badge(r.state); } },
      { label: "Started", value: function (r) { return R.when(r.initiated_at); } },
    ], S.runs.slice().sort(function (a, b) { return b.initiated_at - a.initiated_at; }), [
      { label: "Possible matches", kind: "primary", run: openFindings },
      { label: "Record a possible match", when: function (r) { return r.state === "open"; }, run: recordFinding },
      { label: "Complete", when: function (r) { return r.state === "open"; }, run: completeRun },
    ], { text: "No screenings yet. Use Screen on a vendor to start one." });
  }
  function openFindings(r) {
    api("GET", "/screening/runs/" + encodeURIComponent(r.run_id) + "/findings").then(function (d) {
      var host = document.getElementById("tpi-findings");
      host.hidden = false; host.textContent = "";
      host.appendChild(R.el("h3", "", "Possible matches for " + vendorName(r.vendor_id)));
      R.table(host.appendChild(R.el("div")), [
        { label: "Data", value: function (f) { return label(KINDS, f.kind); } },
        { label: "Matched name", value: function (f) { return R.human(f.candidate_ref); } },
        { label: "Confidence", value: function (f) { return Math.round((f.match_confidence || 0) * 100) + "%"; } },
        { label: "Severity", value: function (f) { return label(SEVERITY, f.severity); } },
        { label: "Review", value: function (f) { return f.disposition && f.disposition !== "pending_review" ? label(DISPOSITION, f.disposition) : R.badge("Waiting for review", "warn"); } },
      ], d.items || [], [
        { label: "Review", kind: "primary", when: function (f) { return (!f.disposition || f.disposition === "pending_review") && !mine(f.detected_by); }, run: function (f) { reviewFinding(r, f); } },
      ], { text: "No possible matches recorded." });
      window.mvReveal(host);
    }, fail("load the possible matches"));
  }
  function recordFinding(r) {
    var sources = S.sources.filter(function (s) { return (r.requested_kinds || []).indexOf(s.kind) >= 0 && s.state === "active"; });
    if (!sources.length) { say("None of this screening's data sources are approved any more."); return; }
    R.form("Record a possible match", [
      { key: "source", label: "Found in", type: "select", default: sources[0].source_id, options: sources.map(function (s) { return { value: s.source_id, label: label(PROVIDERS, s.provider) + " – " + label(KINDS, s.kind) }; }) },
      { key: "name", label: "Name that matched", required: true },
      { key: "confidence", label: "How sure (%)", type: "number", required: true, default: "80" },
      { key: "severity", label: "Severity", type: "select", default: "high", options: opts(SEVERITY) },
      { key: "observed", label: "Date seen", type: "date", required: true, default: R.isoDateIn(0) },
      { key: "valid", label: "Valid until", type: "date", required: true, default: R.isoDateIn(90) },
    ].concat(citationFields()), "Choose the evidence file").then(function (v) {
      if (!v) { return; }
      checkUri(v.cite_uri);
      var src = sourceOf(v.source);
      return fileFingerprint("evidence").then(function (file) {
        return api("PUT", "/screening/runs/" + encodeURIComponent(r.run_id) + "/findings/" + encodeURIComponent(R.newId("finding")), {
          source_id: src.source_id, kind: src.kind, candidate_ref: ref(v.name, ""), match_confidence: Math.max(0, Math.min(1, Number(v.confidence) / 100)),
          severity: v.severity, observed_at: R.toEpoch(v.observed), valid_until: R.toEpoch(v.valid), evidence_sha256: file.sha,
          citations: citation(v.cite_title, v.cite_uri, v.cite_where), idempotency_key: R.newKey(),
        });
      }).then(function () { say("Possible match recorded. A different person must review it."); openFindings(r); });
    }).catch(fail("record the possible match"));
  }
  function reviewFinding(r, f) {
    R.form("Review the possible match", [
      { key: "disposition", label: "Your decision", type: "select", default: "not_a_match", options: opts(DISPOSITION) },
      { key: "why", label: "Reason", required: true },
    ], "Save review").then(function (v) {
      if (!v) { return; }
      var confirmText = v.disposition === "confirmed" ? "Confirm this match? The vendor stays blocked." : null;
      var go = confirmText ? R.confirm(confirmText, "Confirm match") : Promise.resolve(true);
      return go.then(function (ok) {
        if (!ok) { return; }
        return api("POST", "/screening/findings/" + encodeURIComponent(f.finding_id) + "/review", { disposition: v.disposition, expected_revision: f.revision, rationale: v.why, idempotency_key: R.newKey() })
          .then(function () { say("Review saved."); openFindings(r); });
      });
    }).catch(fail("save the review"));
  }
  function completeRun(r) {
    R.confirm("Complete the screening of " + vendorName(r.vendor_id) + "? Every possible match must have been reviewed.", "Complete").then(function (ok) {
      if (!ok) { return; }
      return api("POST", "/screening/runs/" + encodeURIComponent(r.run_id) + "/complete", { expected_revision: r.revision, idempotency_key: R.newKey() })
        .then(function () { say("Screening complete."); loadAll(); });
    }).catch(fail("complete the screening"));
  }

  // ---- risk ----------------------------------------------------------------------
  function policyLatest(id) { return S.policies.filter(function (p) { return p.policy_id === id; }).reduce(function (m, p) { return Math.max(m, p.version); }, 0); }
  function policyName(p) { return R.human(p.policy_id) + " (version " + p.version + ")"; }
  function renderPolicies() {
    R.table(document.getElementById("tpi-policies"), [
      { label: "Policy", value: policyName },
      { label: "Required checks", value: function (p) { return (p.required_source_kinds || []).map(function (k) { return label(KINDS, k); }).join(", "); } },
      { label: "Low-risk vendors approved automatically", value: function (p) { return p.allow_low_risk_autoapproval ? "Yes, up to score " + p.maximum_autoapproval_score : "No"; } },
      { label: "Status", value: function (p) { return badge(p.state); } },
    ], S.policies, [
      { label: "Approve", kind: "primary", when: function (p) { return canAdmin && p.state === "pending" && !mine(p.authored_by); }, run: function (p) { decidePolicy(p, true); } },
      { label: "Reject", when: function (p) { return canAdmin && p.state === "pending" && !mine(p.authored_by); }, run: function (p) { decidePolicy(p, false); } },
      { label: "New version", when: function (p) { return canAdmin && p.version === policyLatest(p.policy_id); }, run: function (p) { newPolicy(p); } },
    ], { text: "No risk policies yet. A policy sets which checks are required and how scores are weighted.", action: canAdmin ? { label: "New risk policy", run: function () { newPolicy(null); } } : null });
  }
  function newPolicy(from) {
    if (!canAdmin) { say("Only administrators can write risk policies."); return; }
    var fields = from ? [] : [{ key: "name", label: "Policy name", required: true, placeholder: "For example: Standard vendor policy" }];
    fields = fields.concat(KINDS.map(function (k, i) { return { key: "k" + i, label: "Require " + k[1], type: "bool", default: from ? from.required_source_kinds.indexOf(k[0]) >= 0 : i < 2 }; }));
    fields.push({ key: "age", label: "Data must be newer than", type: "select", default: from ? String(Math.round(from.maximum_source_age_seconds / 86400)) : "30", options: [{ value: "7", label: "1 week" }, { value: "30", label: "30 days" }, { value: "90", label: "90 days" }, { value: "365", label: "1 year" }] });
    fields.push({ key: "complete", label: "Data must be at least this complete (%)", type: "number", default: from ? String(Math.round(from.minimum_completeness * 100)) : "90" });
    FACTORS.forEach(function (f, i) { fields.push({ key: "w" + i, label: "Weight for " + f[1] + " (0–100)", type: "number", default: from ? String(from.factor_weights[f[0]]) : "10" }); });
    fields.push({ key: "auto", label: "Approve low-risk vendors automatically", type: "bool", default: from ? from.allow_low_risk_autoapproval : false });
    fields.push({ key: "max_score", label: "Highest score approved automatically", type: "number", default: from ? String(from.maximum_autoapproval_score) : "20" });
    fields.push({ key: "max_critical", label: "Only for vendors no more critical than", type: "select", default: from ? String(from.maximum_vendor_criticality) : "2", options: opts(LEVELS) });
    fields.push({ key: "max_access", label: "Only for vendors with at most", type: "select", default: from ? from.maximum_data_access_level : "limited", options: opts(ACCESS) });
    fields = fields.concat(regionFields("r"));
    R.form(from ? "New version of " + R.human(from.policy_id) : "New risk policy", fields, "Save policy").then(function (v) {
      if (!v) { return; }
      var required = KINDS.filter(function (_k, i) { return v["k" + i]; }).map(function (k) { return k[0]; });
      var regions = chosenRegions(v, "r");
      if (!required.length) { throw plain("Require at least one check."); }
      if (!regions.length) { throw plain("Choose at least one region."); }
      var weights = {};
      FACTORS.forEach(function (f, i) { weights[f[0]] = Math.max(0, Math.min(100, parseInt(v["w" + i], 10) || 0)); });
      var id = from ? from.policy_id : ref(v.name, "").toLowerCase().slice(0, 80);
      return api("PUT", "/risk/policies/" + encodeURIComponent(id), {
        required_source_kinds: required, maximum_source_age_seconds: days(v.age), minimum_completeness: Math.max(0, Math.min(1, Number(v.complete) / 100)),
        factor_weights: weights, maximum_autoapproval_score: Math.max(0, parseInt(v.max_score, 10) || 0), allow_low_risk_autoapproval: !!v.auto,
        allowed_territories: regions, maximum_vendor_criticality: Number(v.max_critical), maximum_data_access_level: v.max_access,
        expected_latest_version: policyLatest(id), idempotency_key: R.newKey(),
      }).then(function () { say("Policy saved. A different administrator now needs to approve it."); loadAll(); });
    }).catch(fail("save the policy"));
  }
  document.getElementById("tpi-add-policy").addEventListener("click", function () { newPolicy(null); });
  function decidePolicy(p, approved) {
    R.form((approved ? "Approve " : "Reject ") + policyName(p), [{ key: "why", label: "Reason", required: true }], approved ? "Approve" : "Reject").then(function (v) {
      if (!v) { return; }
      return api("POST", "/risk/policies/" + encodeURIComponent(p.policy_id) + "/versions/" + p.version + "/approval", { approved: approved, rationale: v.why, idempotency_key: R.newKey() })
        .then(function () { say(approved ? "Policy approved." : "Policy rejected."); loadAll(); });
    }).catch(fail("record the decision"));
  }
  function evaluate(v) {
    var policies = S.policies.filter(function (p) { return p.state === "approved"; });
    var runs = S.runs.filter(function (r) { return r.vendor_id === v.vendor_id && r.state === "complete"; }).sort(function (a, b) { return b.initiated_at - a.initiated_at; });
    if (!policies.length) { say("Approve a risk policy first."); return; }
    if (!runs.length) { say("Complete a screening of " + v.display_label + " first."); return; }
    R.form("Decide the risk of " + v.display_label, [
      { key: "policy", label: "Policy", type: "select", default: policies[0].policy_id + "@" + policies[0].version, options: policies.map(function (p) { return { value: p.policy_id + "@" + p.version, label: policyName(p) }; }) },
      { key: "run", label: "Screening", type: "select", default: runs[0].run_id, options: runs.map(function (r) { return { value: r.run_id, label: "Screening of " + R.day(r.initiated_at) }; }) },
    ], "Decide").then(function (vals) {
      if (!vals) { return; }
      var parts = vals.policy.split("@");
      return api("PUT", "/risk/decisions/" + encodeURIComponent(R.newId("decision")) + "/evaluate", { vendor_id: v.vendor_id, run_id: vals.run, policy_id: parts[0], policy_version: Number(parts[1]), idempotency_key: R.newKey() })
        .then(function (d) { say("Result: " + ((DECISION[d.status] || [R.human(d.status)])[0]) + " (score " + d.score + ")."); loadAll(); });
    }).catch(fail("decide the risk"));
  }
  function renderDecisions() {
    R.table(document.getElementById("tpi-decisions"), [
      { label: "Vendor", value: function (d) { return vendorName(d.vendor_id); } },
      { label: "Result", value: function (d) { return badge2(DECISION, d.status); } },
      { label: "Score", value: function (d) { return d.score; } },
      { label: "How", value: function (d) { return d.autoapproved ? "Automatically" : d.rolled_back_from ? "Restored earlier decision" : d.supersedes_decision_id ? "Changed by a person" : "By the policy"; } },
      { label: "When", value: function (d) { return R.when(d.decided_at); } },
    ], S.decisions.slice().sort(function (a, b) { return b.decided_at - a.decided_at; }), [
      { label: "Change the result", when: function () { return canAdmin; }, run: override },
      { label: "Go back to an earlier result", when: function (d) { return canAdmin && S.decisions.some(function (o) { return o.vendor_id === d.vendor_id && o.decision_id !== d.decision_id; }); }, run: rollback },
    ], { text: "No risk decisions yet. Use Decide risk on a screened vendor." });
  }
  function override(d) {
    R.form("Change the result for " + vendorName(d.vendor_id), [
      { key: "status", label: "New result", type: "select", default: "human_review", options: [{ value: "approved", label: "Approved" }, { value: "rejected", label: "Rejected" }, { value: "human_review", label: "Needs a person's review" }] },
      { key: "why", label: "Reason", required: true },
    ], "Change").then(function (v) {
      if (!v) { return; }
      return api("POST", "/risk/decisions/" + encodeURIComponent(d.decision_id) + "/overrides/" + encodeURIComponent(R.newId("decision")), { status: v.status, expected_revision: d.revision, rationale: v.why, idempotency_key: R.newKey() })
        .then(function () { say("Result changed. The earlier decision is kept in the history."); loadAll(); });
    }).catch(fail("change the result"));
  }
  function rollback(d) {
    var earlier = S.decisions.filter(function (o) { return o.vendor_id === d.vendor_id && o.decision_id !== d.decision_id; });
    R.form("Go back to an earlier result", [
      { key: "restore", label: "Earlier result", type: "select", default: earlier[0].decision_id, options: earlier.map(function (o) { return { value: o.decision_id, label: (DECISION[o.status] || [R.human(o.status)])[0] + " on " + R.day(o.decided_at) }; }) },
      { key: "why", label: "Reason", required: true },
    ], "Go back").then(function (v) {
      if (!v) { return; }
      return api("POST", "/risk/decisions/" + encodeURIComponent(d.decision_id) + "/rollbacks/" + encodeURIComponent(R.newId("decision")), { restore_decision_id: v.restore, rationale: v.why, idempotency_key: R.newKey() })
        .then(function () { say("Earlier result restored."); loadAll(); });
    }).catch(fail("restore the earlier result"));
  }

  // ---- due diligence -------------------------------------------------------------
  function renderCases() {
    R.table(document.getElementById("tpi-cases"), [
      { label: "Vendor", value: function (c) { return vendorName(c.vendor_id); } },
      { label: "Reason", value: function (c) { return c.reason; } },
      { label: "Severity", value: function (c) { return label(SEVERITY, c.severity); } },
      { label: "Status", value: function (c) { return c.decision ? R.human(c.decision) : badge(c.state); } },
      { label: "Tasks done", value: function (c) { var t = c.tasks || []; return t.filter(function (x) { return x.status !== "open"; }).length + " of " + t.length; } },
    ], S.cases, [
      { label: "Open", kind: "primary", run: showCase },
      { label: "Decide", when: function (c) { return canAdmin && !c.decision && !mine(c.opened_by); }, run: decideCase },
    ], { text: "No due diligence reviews yet. Start one from a vendor's row." });
  }
  function openCase(v) {
    R.form("Start due diligence for " + v.display_label, [
      { key: "reason", label: "Why", required: true, placeholder: "For example: Possible sanctions match needs a closer look" },
      { key: "severity", label: "Severity", type: "select", default: "medium", options: opts(SEVERITY.slice(1)) },
    ], "Start").then(function (vals) {
      if (!vals) { return; }
      return api("PUT", "/edd/cases/" + encodeURIComponent(R.newId("review")), { vendor_id: v.vendor_id, reason: vals.reason, severity: vals.severity, idempotency_key: R.newKey() })
        .then(function () { say("Due diligence started."); loadAll(); });
    }).catch(fail("start due diligence"));
  }
  function showCase(c) {
    var host = document.getElementById("tpi-case-detail");
    host.hidden = false; host.textContent = "";
    host.appendChild(R.el("h3", "", "Due diligence: " + vendorName(c.vendor_id)));
    var actions = R.el("div", "tpi-actions");
    if (!c.decision) {
      actions.appendChild(R.button("Add a task", "primary", function () { caseTask(c, null); }));
      actions.appendChild(R.button("Add evidence", "", function () { caseEvidence(c); }));
    }
    host.appendChild(actions);
    R.table(host.appendChild(R.el("div")), [
      { label: "Task", value: function (t) { return t.title; } },
      { label: "Assigned to", value: function (t) { return t.assignee_ref === S.me ? "Me" : "A team member"; } },
      { label: "Due", value: function (t) { return R.day(t.due_at); } },
      { label: "Status", value: function (t) { return R.human(t.status); } },
    ], c.tasks || [], [
      { label: "Mark complete", when: function (t) { return !c.decision && t.status === "open"; }, run: function (t) { caseTask(c, t, "complete"); } },
      { label: "Not needed", when: function (t) { return !c.decision && t.status === "open"; }, run: function (t) { caseTask(c, t, "waived"); } },
    ], { text: "No tasks yet. Tasks appear here when a review asks for follow-up." });
    host.appendChild(R.el("p", "muted", (c.evidence || []).length + " piece(s) of evidence recorded."));
    window.mvReveal(host);
  }
  function caseTask(c, t, status) {
    var fields = t ? [] : [
      { key: "title", label: "Task", required: true },
      { key: "due", label: "Due date", type: "date", required: true, default: R.isoDateIn(14) },
    ];
    var ask = fields.length ? R.form("Add a task", fields, "Add task") : Promise.resolve({});
    ask.then(function (v) {
      if (!v) { return; }
      var evidence = status === "complete" ? fileFingerprint("evidence") : Promise.resolve(null);
      return evidence.then(function (file) {
        var id = t ? t.task_id : R.newId("task");
        var body = { title: t ? t.title : v.title, assignee_ref: t ? t.assignee_ref : S.me, due_at: t ? t.due_at : R.toEpoch(v.due),
          status: status || "open", expected_revision: c.revision, idempotency_key: R.newKey() };
        if (file) { body.evidence_sha256 = file.sha; }
        return api("PUT", "/edd/cases/" + encodeURIComponent(c.case_id) + "/tasks/" + encodeURIComponent(id), body);
      }).then(function (updated) { say("Task saved."); return loadAll().then(function () { showCase(updated.case_id ? updated : c); }); });
    }).catch(fail("save the task"));
  }
  function caseEvidence(c) {
    var snaps = S.snapshots.filter(function (x) { var s = sourceOf(x.source_id); return s && s.state === "active" && (s.purposes || []).indexOf("edd") >= 0; });
    if (!snaps.length) { say("Record a data update from a source approved for due diligence first."); return; }
    R.form("Add evidence", [
      { key: "snapshot", label: "From which data update", type: "select", default: snaps[0].snapshot_id, options: snaps.map(function (x) { var s = sourceOf(x.source_id); return { value: x.snapshot_id, label: label(PROVIDERS, s.provider) + " – " + R.human(x.dataset_revision) + " (" + R.day(x.observed_at) + ")" }; }) },
      { key: "summary", label: "What it shows", required: true },
    ].concat(citationFields()), "Choose the evidence file").then(function (v) {
      if (!v) { return; }
      checkUri(v.cite_uri);
      return fileFingerprint("evidence").then(function (file) {
        return api("PUT", "/edd/cases/" + encodeURIComponent(c.case_id) + "/evidence/" + encodeURIComponent(R.newId("evidence")), {
          snapshot_id: v.snapshot, evidence_sha256: file.sha, citations: citation(v.cite_title, v.cite_uri, v.cite_where), summary: v.summary, expected_revision: c.revision, idempotency_key: R.newKey(),
        });
      }).then(function (updated) { say("Evidence added."); return loadAll().then(function () { showCase(updated.case_id ? updated : c); }); });
    }).catch(fail("add the evidence"));
  }
  function decideCase(c) {
    R.form("Decide the due diligence for " + vendorName(c.vendor_id), [
      { key: "decision", label: "Decision", type: "select", default: "escalated", options: [{ value: "approved", label: "Approve the vendor" }, { value: "rejected", label: "Reject the vendor" }, { value: "escalated", label: "Escalate" }] },
      { key: "why", label: "Reason", required: true },
    ], "Save decision").then(function (v) {
      if (!v) { return; }
      return R.confirm("Save this decision? It can't be changed afterwards.", "Save decision").then(function (ok) {
        if (!ok) { return; }
        return api("POST", "/edd/cases/" + encodeURIComponent(c.case_id) + "/decision", { decision: v.decision, rationale: v.why, expected_revision: c.revision, idempotency_key: R.newKey() })
          .then(function () { say("Decision saved."); loadAll(); });
      });
    }).catch(fail("save the decision"));
  }

  // ---- monitoring ------------------------------------------------------------------
  function recipientStatus(text) { window.mvStatus(document.getElementById("tpi-recipient-result"), text); }
  function recipientControls() {
    ["tpi-recipient-name", "tpi-recipient-address"].forEach(function (id) {
      var input = document.getElementById(id); if (input) { input.readOnly = Boolean(recipientPending); }
    });
    var save = document.getElementById("tpi-save-recipient");
    if (save) { save.disabled = mailBusy; save.textContent = recipientPending ? "Retry this same recipient" : "Review recipient"; }
    var original = document.getElementById("tpi-recipient-original");
    if (original) { original.hidden = !recipientPending; original.disabled = mailBusy; }
  }
  function recipientSaved(record) {
    if (!recipientPending || record.recipient_id !== recipientPending.id || record.name !== recipientPending.name || record.address !== recipientPending.address) {
      throw plain("The saved recipient differs from this form. Keep this request and ask an administrator to review it.");
    }
    recipientPending = null; lastSavedRecipient = record.recipient_id;
    document.getElementById("tpi-recipient-name").value = "";
    document.getElementById("tpi-recipient-address").value = "";
    recipientStatus(record.state === "active" ? "Recipient saved. Choose it when you start watching a vendor." : "This recipient was saved, then withdrawn. Add a new recipient before starting a watch.");
    return loadAll();
  }
  function renderRecipients() {
    if (lastSavedRecipient && S.recipients.some(function (r) { return r.recipient_id === lastSavedRecipient && r.state === "withdrawn"; })) {
      recipientStatus("That saved recipient was withdrawn. Add a new recipient before starting another watch.");
    }
    R.table(document.getElementById("tpi-recipients"), [
      { label: "Name", value: function (r) { return r.name; } },
      { label: "Email address", value: function (r) { return r.address; } },
      { label: "Status", value: function (r) { return r.state === "active" ? R.badge("Available", "ok") : R.badge("Withdrawn", "idle"); } },
    ], S.recipients, [{ label: "Withdraw", kind: "danger", when: function (r) { return canAdmin && r.state === "active"; }, run: function (r) {
      if (mailBusy) { return; }
      mailBusy = true; recipientControls();
      R.confirm("Withdraw " + r.name + " (" + r.address + ")? Watches using this saved address will stop sending to it. Messages already accepted cannot be recalled. To change an address, withdraw this recipient and add the new one.", "Withdraw recipient").then(function (ok) {
        if (!ok) { return; }
        return api("POST", "/alert-recipients/" + encodeURIComponent(r.recipient_id) + "/withdraw", { expected_revision: r.revision, context: S.mailContext, idempotency_key: R.newKey() })
          .then(function () { say("Recipient withdrawn."); return loadAll(); });
      }).catch(fail("withdraw the recipient")).finally(function () { mailBusy = false; recipientControls(); });
    } }], { text: "No saved recipients. An administrator can add the team or person who should receive change alerts." });
  }
  var recipientForm = document.getElementById("tpi-recipient-form");
  if (recipientForm) {
    recipientForm.addEventListener("submit", function (event) {
      event.preventDefault();
      if (mailBusy || !S.mailContext) { return; }
      var draft = recipientPending || { id: R.newId("recipient"), name: document.getElementById("tpi-recipient-name").value.trim(),
        address: document.getElementById("tpi-recipient-address").value.trim(), context: S.mailContext, key: R.newKey() };
      mailBusy = true; recipientControls();
      R.confirm("Save " + draft.name + " at " + draft.address + "? When you explicitly send waiting alerts, this address receives vendor names, change notices and review references by email outside Lightwork. Source contents are not attached. Only watches that select this saved recipient will use it.", "Save recipient").then(function (ok) {
        if (!ok) { return; }
        recipientPending = draft; recipientControls();
        return api("PUT", "/alert-recipients/" + encodeURIComponent(draft.id), { name: draft.name, address: draft.address, external_use_reviewed: true, context: draft.context, idempotency_key: draft.key }).then(recipientSaved);
      }).catch(function (e) {
        if (recipientPending && !recipientPending.uncertain && e.status >= 400 && e.status < 500) {
          recipientPending = null;
          recipientStatus(R.errorText(e, "save the recipient") + " Your entries were kept; correct them and review again.");
        } else {
          if (recipientPending) { recipientPending.uncertain = true; }
          recipientStatus(R.errorText(e, "save the recipient") + " Your form and the same request were kept. Read the saved recipient or retry this exact request; do not create a second recipient for an uncertain reply.");
        }
      }).finally(function () { mailBusy = false; recipientControls(); });
    });
    document.getElementById("tpi-recipient-original").addEventListener("click", function () {
      if (!recipientPending || mailBusy) { return; }
      mailBusy = true; recipientControls();
      api("GET", "/alert-recipients/" + encodeURIComponent(recipientPending.id)).then(recipientSaved).catch(function (e) {
        recipientStatus(e.status === 404 ? "A saved recipient is not confirmed yet. Your form is kept. Retry this same request when the service is available." : R.errorText(e, "read the saved recipient"));
      }).finally(function () { mailBusy = false; recipientControls(); });
    });
  }
  window.LightworkThirdPartyAlerts = { openReview: function (context, isCurrent) {
    if (!canAdmin || mailBusy || !recipientForm || !/^[0-9a-f]{64}$/.test(context || "") || typeof isCurrent !== "function" || !isCurrent()) { return Promise.resolve(false); }
    mailBusy = true; recipientControls();
    return api("GET", "/alert-recipients").then(function (d) {
      if (!isCurrent() || d.context !== context || (S.mailContext && S.mailContext !== context)) { say("Your account or workspace changed. Your current form was kept; reload the current controls before continuing."); return false; }
      S.mailContext = d.context; S.recipients = d.items || []; renderRecipients();
      document.getElementById("tpi-recipient-setup").scrollIntoView({ block: "center" });
      document.getElementById("tpi-recipient-name").focus(); return true;
    }).catch(function (e) { fail("open alert recipients")(e); return false; }).finally(function () { mailBusy = false; recipientControls(); });
  } };
  function renderMonitors() {
    R.table(document.getElementById("tpi-monitors"), [
      { label: "Vendor", value: function (m) { return vendorName(m.vendor_id); } },
      { label: "Checks", value: function (m) { return Object.keys(m.source_bindings || {}).map(function (k) { return label(KINDS, k); }).join(", "); } },
      { label: "How often", value: function (m) { var d = Math.round(m.cadence_seconds / 86400); return d >= 1 ? "Every " + d + " day" + (d === 1 ? "" : "s") : "Every " + Math.round(m.cadence_seconds / 3600) + " hours"; } },
      { label: "Next check", value: function (m) { return R.when(m.next_run_at); } },
      { label: "Status", value: function (m) { return badge(m.state); } },
      { label: "Alerts to", value: function (m) { var r = S.recipients.filter(function (r) { return r.destination_ref === m.destination_ref; })[0]; return r ? r.name + (r.state !== "active" ? " · withdrawn" : "") : "Choose a saved recipient by starting a new watch"; } },
    ], S.monitors, [
      { label: "Stop watching", kind: "danger", when: function (m) { return m.state === "active"; }, run: stopWatching },
    ], { text: "No vendors are being watched. Use Watch for changes on a vendor." });
    R.table(document.getElementById("tpi-alerts"), [
      { label: "Vendor", value: function (a) { return vendorName(a.vendor_id); } },
      { label: "Found", value: function (a) { return R.when(a.created_at); } },
      { label: "Source", value: function (a) { return (a.citations || []).map(function (c) { return c.title; }).join(", ") || "—"; } },
    ], S.alerts.slice().sort(function (a, b) { return b.created_at - a.created_at; }), [], { text: "No changes found yet. Changes appear here when a watched source reports one." });
    var outcomes = { pending: "Waiting to send", leased: "Reserved to send", dispatching: "Send not yet confirmed · will not resend automatically", ambiguous: "Unconfirmed · will not resend automatically", delivered: "Accepted by mail service", cancelled: "Cancelled", dead_letter: "Stopped after unsuccessful attempts" };
    R.table(document.getElementById("tpi-deliveries"), [
      { label: "Vendor", value: function (d) { var a = S.alerts.filter(function (a) { return a.alert_id === d.alert_id; })[0]; return a ? vendorName(a.vendor_id) : "Retained alert"; } },
      { label: "Outcome", value: function (d) { return outcomes[d.state] || "Needs review"; } },
      { label: "Next try", value: function (d) { return d.state === "pending" ? R.when(d.next_attempt_at) : "—"; } },
    ], S.deliveries, [], { text: "No emails have been queued yet. An email is queued when a watched vendor has a change and a saved alert recipient." });
  }
  function watch(v) {
    var kinds = availableKinds("monitoring");
    if (!kinds.length) { say("There's no current data approved for watching for changes. Approve a source for that use and record a data update first."); return; }
    var recipients = S.recipients.filter(function (r) { return r.state === "active"; });
    if (!recipients.length) { say("Add a saved alert recipient first. An administrator can do this in Alert recipients on this page."); document.getElementById("tpi-recipient-setup").scrollIntoView({ block: "center" }); return; }
    R.form("Watch " + v.display_label + " for changes", kinds.map(function (k, i) { return { key: "k" + i, label: "Watch " + k[1], type: "bool", default: true }; }).concat([
      { key: "every", label: "Check", type: "select", default: "7", options: [{ value: "1", label: "Every day" }, { value: "7", label: "Every week" }, { value: "30", label: "Every month" }] },
      { key: "to", label: "Send alerts to", type: "select", required: true, options: recipients.map(function (r) { return { value: r.destination_ref, label: r.name + " · " + r.address }; }) },
    ]), "Start watching").then(function (vals) {
      if (!vals) { return; }
      var bindings = {};
      kinds.forEach(function (k, i) { if (vals["k" + i]) { var snapshot = usableSnapshot(k[0], "monitoring"); if (!snapshot) { throw plain("This source changed. Reload its current data before starting a watch."); } bindings[k[0]] = snapshot.source_id; } });
      if (!Object.keys(bindings).length) { throw plain("Choose at least one check."); }
      return api("PUT", "/monitors/" + encodeURIComponent(R.newId("watch")), { vendor_id: v.vendor_id, source_bindings: bindings, destination_ref: vals.to, cadence_seconds: days(vals.every), idempotency_key: R.newKey() })
        .then(function () { say("Now watching " + v.display_label + "."); loadAll(); });
    }).catch(fail("start watching"));
  }
  function stopWatching(m) {
    R.confirm("Stop watching " + vendorName(m.vendor_id) + " for changes? Alerts not yet sent are cancelled.", "Stop watching").then(function (ok) {
      if (!ok) { return; }
      return api("POST", "/monitors/" + encodeURIComponent(m.monitor_id) + "/revoke", { expected_revision: m.revision, idempotency_key: R.newKey() })
        .then(function () { say("Stopped watching."); loadAll(); });
    }).catch(fail("stop watching"));
  }
  document.getElementById("tpi-send-alerts").addEventListener("click", function () {
    if (mailBusy) { return; }
    mailBusy = true;
    document.getElementById("tpi-send-alerts").disabled = true; recipientControls();
    api("GET", "/outbox/review").then(function (review) {
      if (!review.items.length) { say("No current alerts are ready to send. Unconfirmed messages remain in Email outcomes and are not repeated."); return; }
      var content = "Send " + review.items.length + " alert(s) from " + review.sender + "?\n\n" + review.items.map(function (item) {
        return "To: " + item.recipient + " · " + item.address + "\nSubject: " + item.subject + "\n" + item.body;
      }).join("\n\n") + "\n\n" + review.external_use;
      return R.confirm(content, "Send reviewed alerts").then(function (ok) {
        if (!ok) { return; }
        return api("POST", "/outbox/run", { context: review.context, review_sha256: review.review_sha256, items: review.items.map(function (item) { return { delivery_id: item.delivery_id, pin: item.pin }; }) }).then(function (d) {
          return loadAll().then(function () { say(d.acknowledged + " accepted by the mail service; " + d.retry_pending + " waiting for another try; " + d.dead_lettered + " stopped; " + (d.cancelled || 0) + " cancelled; " + d.acknowledgement_ambiguous + " unconfirmed. Accepted does not prove inbox receipt."); });
        });
      });
    }).catch(function (f) {
      return loadAll().then(function () { say(R.errorText(f, "send the alerts") + " Read Email outcomes before trying again. Unconfirmed sends are kept and are not automatically repeated."); });
    }).finally(function () { mailBusy = false; document.getElementById("tpi-send-alerts").disabled = false; recipientControls(); });
  });

  // ---- sharing with partners ------------------------------------------------------
  var METRICS = [["risk-rating", "Overall risk rating"], ["screening-result", "Screening result"], ["cyber-rating", "Cyber security rating"]];
  function renderConsents() {
    R.table(document.getElementById("tpi-consents"), [
      { label: "Vendor", value: function (c) { return vendorName(c.vendor_id); } },
      { label: "Shared with", value: function (c) { return c.audience === S.me ? "Me" : R.human(c.audience); } },
      { label: "What", value: function (c) { return (c.allowed_metrics || []).map(function (m) { return label(METRICS, m); }).join(", "); } },
      { label: "Reviewed", value: function (c) { return c.inclusion_reviewed ? "Yes" : R.badge("Waiting for review", "warn"); } },
      { label: "Status", value: function (c) { return badge(c.state); } },
      { label: "Until", value: function (c) { return R.day(c.expires_at); } },
    ], S.consents, [
      { label: "Review", kind: "primary", when: function (c) { return !c.inclusion_reviewed && c.state !== "withdrawn" && !mine(c.granted_by); }, run: reviewConsent },
      { label: "Share a value", when: function (c) { return c.state === "active"; }, run: contribute },
      { label: "Withdraw", kind: "danger", when: function (c) { return c.state !== "withdrawn"; }, run: withdraw },
    ], { text: "Nothing is shared with partners. Use Share with partners on a vendor to start." });
  }
  function share(v) {
    R.form("Share " + v.display_label + "'s risk with a partner", [
      { key: "partner", label: "Partner organisation", required: true },
      { key: "purpose", label: "Why they need it", type: "select", default: "vendor-risk-benchmarking", options: [{ value: "vendor-risk-benchmarking", label: "Comparing vendor risk" }, { value: "joint-due-diligence", label: "Joint due diligence" }] },
    ].concat(METRICS.map(function (m, i) { return { key: "m" + i, label: "Share " + m[1], type: "bool", default: i === 0 }; })).concat([
      { key: "until", label: "Share until", type: "date", required: true, default: R.isoDateIn(365) },
      { key: "consent", label: "I have permission to share this", type: "bool" },
    ]), "Share").then(function (vals) {
      if (!vals) { return; }
      if (!vals.consent) { throw plain("Tick that you have permission to share this."); }
      var metrics = METRICS.filter(function (_m, i) { return vals["m" + i]; }).map(function (m) { return m[0]; });
      if (!metrics.length) { throw plain("Choose what to share."); }
      return api("PUT", "/exchange/consents/" + encodeURIComponent(R.newId("sharing")), { vendor_id: v.vendor_id, audience: ref(vals.partner, "").toLowerCase(), purpose: vals.purpose, allowed_metrics: metrics, explicit_consent: true, expires_at: R.toEpoch(vals.until), idempotency_key: R.newKey() })
        .then(function () { say("Sharing set up. A different person must review it before anything is shared."); loadAll(); });
    }).catch(fail("set up sharing"));
  }
  function reviewConsent(c) {
    R.form("Review sharing of " + vendorName(c.vendor_id), [
      { key: "ok", label: "Allow this to be shared", type: "bool", default: true },
      { key: "privacy", label: "Name of the privacy review (if one was done)" },
      { key: "anon", label: "Name of the proof it can't identify anyone (if you have one)" },
      { key: "why", label: "Reason", required: true },
    ], "Save review").then(function (v) {
      if (!v) { return; }
      var body = { inclusion_approved: !!v.ok, expected_revision: c.revision, rationale: v.why, idempotency_key: R.newKey() };
      if (v.privacy) { body.privacy_review_ref = ref(v.privacy, "review."); }
      if (v.anon) { body.anonymity_proof_ref = ref(v.anon, "proof."); }
      return api("POST", "/exchange/consents/" + encodeURIComponent(c.consent_id) + "/review", body).then(function () { say("Review saved."); loadAll(); });
    }).catch(fail("save the review"));
  }
  function contribute(c) {
    R.form("Share a value for " + vendorName(c.vendor_id), [
      { key: "metric", label: "What", type: "select", default: c.allowed_metrics[0], options: c.allowed_metrics.map(function (m) { return { value: m, label: label(METRICS, m) }; }) },
      { key: "band", label: "Value", type: "select", default: "medium", options: [{ value: "low", label: "Low" }, { value: "medium", label: "Medium" }, { value: "high", label: "High" }] },
      { key: "keep", label: "Keep it for", type: "select", default: "365", options: opts(KEEP) },
    ], "Choose the supporting file").then(function (v) {
      if (!v) { return; }
      var decision = latestDecision(c.vendor_id);
      return fileFingerprint("supporting").then(function (file) {
        return api("PUT", "/exchange/consents/" + encodeURIComponent(c.consent_id) + "/contributions/" + encodeURIComponent(R.newId("shared")), {
          metric_id: v.metric, value_band: v.band, audience: c.audience, purpose: c.purpose, evidence_sha256: file.sha,
          lineage_refs: [decision ? "decision:" + decision.decision_id : "vendor:" + c.vendor_id], retention_seconds: days(v.keep), idempotency_key: R.newKey(),
        });
      }).then(function () { say("Value shared."); });
    }).catch(fail("share the value"));
  }
  function withdraw(c) {
    R.form("Withdraw sharing", [{ key: "why", label: "Reason", required: true }], "Withdraw").then(function (v) {
      if (!v) { return; }
      return R.confirm("Withdraw this sharing? Partners can no longer see what was shared.", "Withdraw").then(function (ok) {
        if (!ok) { return; }
        return api("POST", "/exchange/consents/" + encodeURIComponent(c.consent_id) + "/withdraw", { expected_revision: c.revision, rationale: v.why, idempotency_key: R.newKey() })
          .then(function () { say("Sharing withdrawn."); loadAll(); });
      });
    }).catch(fail("withdraw the sharing"));
  }
  document.getElementById("tpi-see-shared").addEventListener("click", function () {
    R.form("See what partners shared with you", [
      { key: "purpose", label: "Why", type: "select", default: "vendor-risk-benchmarking", options: [{ value: "vendor-risk-benchmarking", label: "Comparing vendor risk" }, { value: "joint-due-diligence", label: "Joint due diligence" }] },
      { key: "metric", label: "What", type: "select", default: "risk-rating", options: opts(METRICS) },
    ], "Show").then(function (v) {
      if (!v) { return; }
      return api("POST", "/exchange/query", { audience: S.me, purpose: v.purpose, metric_id: v.metric, limit: 100 }).then(function (d) {
        var host = document.getElementById("tpi-shared");
        host.hidden = false; host.textContent = "";
        host.appendChild(R.el("h3", "", "Shared with you"));
        R.table(host.appendChild(R.el("div")), [
          { label: "What", value: function (x) { return label(METRICS, x.metric_id); } },
          { label: "Value", value: function (x) { return R.human(x.value_band); } },
          { label: "Shared", value: function (x) { return R.day(x.created_at); } },
        ], d.items || [], [], { text: "Nothing has been shared with you for this." });
      });
    }).catch(fail("load what was shared"));
  });

  // ---- administrator tools -----------------------------------------------------------
  var adminResult = document.getElementById("tpi-admin-result");
  document.getElementById("tpi-integrity").addEventListener("click", function () {
    if (!canAudit) { adminResult.textContent = "Only auditors and administrators can run this check."; return; }
    api("GET", "/integrity").then(function (d) { adminResult.textContent = "No changes found. " + (d.verified_records || 0) + " records were checked."; },
      function (f) { adminResult.textContent = R.errorText(f, "check the records"); });
  });
  document.getElementById("tpi-purge").addEventListener("click", function () {
    if (!canAdmin) { adminResult.textContent = "Only administrators can delete expired records."; return; }
    R.confirm("Delete intelligence records whose keep period has ended? The audit history is kept. This can't be undone.", "Delete").then(function (ok) {
      if (!ok) { return; }
      api("POST", "/retention/purge").then(function () { adminResult.textContent = "Expired records were deleted."; loadAll(); },
        function (f) { adminResult.textContent = R.errorText(f, "delete expired records"); });
    });
  });

  loadAll();
})();
