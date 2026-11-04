// Continuous evidence page: sources, collection setups, recent collections
// and evidence changes load as lists on arrival. Setting up a source,
// approving it, pausing, resuming and retrying are row buttons; versions,
// fingerprints and request keys come from the chosen row or the server.
(function () {
  "use strict";
  var root = document.getElementById("trc-root");
  if (!root || !window.LwRecords) { return; }
  var R = window.LwRecords;
  var API = root.getAttribute("data-api") || "/api/v1/compliance/continuous-evidence";
  var canAdmin = root.getAttribute("data-can-admin") === "true";
  var canAudit = root.getAttribute("data-can-audit") === "true";
  var live = document.getElementById("trc-live-status");
  var runCycle = document.getElementById("trc-run-cycle");
  var S = { status: null, setup: [], definitions: [], enrollments: [], runs: [], jobs: [], alerts: [] };
  var STATUS = { observed: ["Passing", "ok"], failed: ["Failing", "danger"], unknown: ["Couldn't tell", "warn"] };

  function say(text) { window.mvStatus(live, text); }
  function fail(action) { return function (f) { var t = R.errorText(f, action); say(t); if (window.mvToast) { window.mvToast(t, { error: true }); } }; }
  function api(method, path, body) { return window.mvFetchJSON(API + path, {method:method || "GET",body:body,onAccess:clearSourceAccess}).then(function (value) { return value || {}; }); }
  var contextChanged = false;
  window.LightworkContinuousEvidence = { openReview: async function (selection, options) {
    var current = options && options.isCurrent, context = options && options.context;
    if (contextChanged || location.pathname !== "/compliance/continuous-evidence" ||
        (selection && Object.keys(selection).length) || !/^[a-f0-9]{64}$/.test(context || "") ||
        (current && !current())) { return false; }
    var checked = await R.call("POST", "/api/v1/copilot/product-operations/catalog", {
      page: "/compliance/continuous-evidence", selection: {}
    });
    if (contextChanged || checked.context !== context || (current && !current()) ||
        !(checked.operations || []).some(function (row) {
          return row.id === "connections.continuous_evidence_status" && row.available;
        })) { return false; }
    // Focus only: refreshing lists would discard a currently open collection
    // form. Native approval and collection stay separate, reviewed actions.
    var target = sourceEl("editor") && !sourceEl("editor").hidden ? sourceEl("editor-title") : sourceEl("new") || document.getElementById("trc-refresh");
    if (!target || target.disabled) { return false; }
    target.focus(); target.scrollIntoView({ block: "center" });
    say("Review the source setup controls here. Your entered choices were kept; no setup was saved and no collection was started.");
    return true;
  } };
  var sourceGeneration = 0, sourceOptions = null, sourceReview = null;
  var sourceAttempt = null, sourceOriginalRequest = null, sourceBusy = false, sourceChecks = [], editingSource = null, sourceFormLoaded = false, sourceChosenProvider = "";
  var sourceLegacyStorage = "lightwork:continuous-evidence:source-original";
  var sourceAccountContext = (document.querySelector('meta[name="lightwork-preference-context"]') || {}).content || "";
  var sourceStorage = /^[a-f0-9]{64}$/.test(sourceAccountContext) ? sourceLegacyStorage + ":" + sourceAccountContext : null;
  var sourceDraftStorage = "lightwork:continuous-evidence:source-draft", sourceExpiryTimer = null, activeSourceApproval = null;
  function sourceEl(id) { return document.getElementById("trc-source-" + id); }
  function sourceSay(text) { var target = sourceEl("form-status") || sourceEl("original-status"); if (target) target.textContent = text; }
  function sourceCurrent(generation) { return !contextChanged && generation === sourceGeneration; }
  function sourceError(failure, action) {
    if (failure && (failure.status === 401 || failure.status === 403) && !contextChanged) { clearSourceAccess(failure); }
    var text = R.errorText(failure, action); sourceSay(text); return text;
  }
  function sourceCall(method, path, body) { return api(method, "/setup" + path, body); }
  function sourceProvider() {
    var name = sourceEl("provider") ? sourceEl("provider").value : "";
    return ((sourceOptions || {}).providers || []).filter(function (item) { return item.id === name; })[0];
  }
  function sourceSync() {
    var provider = sourceProvider(), available = provider && provider.accounts && provider.accounts.length;
    var held = !!sourceAttempt;
    if (sourceEl("discover")) sourceEl("discover").disabled = sourceBusy || held || !available || !sourceEl("account").value || !sourceScope().scope_ref;
    if (sourceEl("add-binding")) sourceEl("add-binding").disabled = sourceBusy || held || !sourceChecks.length;
    if (sourceEl("prepare")) sourceEl("prepare").disabled = sourceBusy || held || !provider || !available || !sourceChecks.length;
    if (sourceEl("save")) sourceEl("save").disabled = sourceBusy || held || !sourceReview || !sourceEl("confirm").checked || Date.now() >= sourceReview.expires_at * 1000;
    if (sourceEl("read-original")) sourceEl("read-original").disabled = sourceBusy || !(sourceAttempt || sourceOriginalRequest);
  }
  function invalidateSourceReview() {
    sourceReview = null;
    if (sourceExpiryTimer) { clearTimeout(sourceExpiryTimer); sourceExpiryTimer = null; }
    if (sourceEl("review")) sourceEl("review").hidden = true;
    if (sourceEl("review-rows")) sourceEl("review-rows").textContent = "";
    if (sourceEl("confirm")) sourceEl("confirm").checked = false;
    sourceSync();
  }
  function clearSourceAccess(event) {
    if (event && event.detail && (event.detail.reason === "selection" || event.detail.selectionOnly === true)) return;
    contextChanged = true; sourceGeneration += 1; sourceBusy = false;
    if (activeSourceApproval) activeSourceApproval(false);
    sourceOptions = null; sourceChecks = []; sourceReview = null; sourceAttempt = null; sourceOriginalRequest = null; editingSource = null; sourceFormLoaded = false; sourceChosenProvider = "";
    S = {status:null,setup:[],definitions:[],enrollments:[],runs:[],jobs:[],alerts:[]};
    ["trc-sources","trc-definitions","trc-runs","trc-alerts","trc-source-bindings","trc-source-review-rows","trc-source-original-rows"].forEach(function (id) {
      var target = document.getElementById(id); if (target) target.textContent = "";
    });
    if (sourceEl("form")) sourceEl("form").reset();
    if (sourceEl("scope")) sourceEl("scope").textContent = "";
    if (sourceEl("editor")) sourceEl("editor").hidden = true;
    if (sourceEl("original")) sourceEl("original").hidden = true;
    if (sourceEl("new")) sourceEl("new").disabled = true;
    setCycleReady(false);
    say(event && typeof event.status === "number" ? "This action was refused. Reload to check current access. Private details were cleared; entered choices are kept for the same account and workspace." : "Your account or workspace access changed. Reload to check current access. Private source details were cleared.");
  }
  document.addEventListener("lightwork:account-context-changed", clearSourceAccess);
  document.addEventListener("lightwork:workspace-changed", clearSourceAccess);
  document.addEventListener("lightwork:copilot-context-changed", clearSourceAccess);
  document.addEventListener("lightwork:authority-changed", clearSourceAccess);
  window.addEventListener("lightwork:context-changed", clearSourceAccess);
  function sourceSelect(target, choices, empty, chosen) {
    target.textContent = "";
    var blank = document.createElement("option"); blank.value = ""; blank.textContent = empty; target.appendChild(blank);
    choices.forEach(function (choice) {
      var option = document.createElement("option"); option.value = choice.id || choice.name; option.textContent = choice.label;
      target.appendChild(option);
    });
    target.value = chosen || "";
  }
  function retainUnavailableChoice(target, chosen, choices, message) {
    if (!chosen || choices.some(function (item) { return (item.id || item.name) === chosen; })) return;
    var option = document.createElement("option"); option.value = chosen; option.textContent = message; target.appendChild(option); target.value = chosen;
  }
  function sourceScope() {
    return {scope_ref:(sourceEl("scope-ref") || {}).value || "",region:(sourceEl("region") || {}).value || null,stream:(sourceEl("stream") || {}).value || null};
  }
  function sourceScopeField(id, label, required, choices, value) {
    var holder = document.createElement("label"); holder.htmlFor = "trc-source-" + id;
    var title = document.createElement("span"); title.textContent = label; holder.appendChild(title);
    var field = document.createElement(choices ? "select" : "input"); field.className = "input"; field.id = "trc-source-" + id;
    field.required = required; if (!choices) { field.type = "text"; field.maxLength = id === "region" ? 64 : 512; field.autocomplete = "off"; }
    if (choices) sourceSelect(field, choices, "Choose " + label.toLowerCase(), value); else field.value = value || "";
    field.addEventListener("input", function () { sourceChecks = []; sourceEl("bindings").textContent = ""; sourceEl("check-status").textContent = "Scope changed. Find the checks again before reviewing."; invalidateSourceReview(); });
    holder.appendChild(field); sourceEl("scope").appendChild(holder);
  }
  function renderSourceProvider(saved) {
    var provider = sourceProvider(); sourceEl("scope").textContent = ""; sourceChecks = [];
    sourceEl("connect").href = provider ? "/connections?evidence=" + encodeURIComponent(provider.id) : "/connections";
    sourceEl("bindings").textContent = ""; sourceEl("check-status").textContent = "";
    sourceEl("coverage").textContent = "";
    sourceSelect(sourceEl("account"), (provider || {}).accounts || [], "Choose a saved account", saved && saved.connection_name);
    sourceEl("account-help").textContent = provider && provider.accounts.length ? "Only current saved accounts compatible with this provider are shown." : "No compatible saved account is available. Connect an account, then close and reopen this form to check it.";
    if (provider) {
      sourceScopeField("scope-ref", provider.scope_label, true, null, saved && saved.scope_ref);
      if (provider.region_required) sourceScopeField("region", "Cloud region", true, null, saved && saved.region);
      if (provider.streams && provider.streams.length) sourceScopeField("stream", "Checks to read", true, provider.streams, saved && saved.stream);
      sourceEl("coverage").textContent = "Choose up to " + provider.max_bindings + " exact check and control pairs. Unselected checks are outside this setup.";
    }
    invalidateSourceReview();
  }
  async function openSource(saved, options) {
    var isCurrent = options && options.isCurrent;
    if (isCurrent && !isCurrent()) return false;
    if (contextChanged || !canAdmin || sourceBusy || sourceAttempt) { sourceSay(sourceAttempt ? "Read the earlier setup result before preparing another save." : "Reload to check current setup access."); return false; }
    var generation = sourceGeneration;
    if (sourceFormLoaded && !saved) { sourceEl("editor").hidden = false; sourceEl("editor-title").focus(); return true; }
    if (sourceFormLoaded && saved && !(await R.confirm("Load this saved source instead of the choices already entered? The current form is replaced only if you choose Load source.", "Load source"))) return false;
    if (!sourceCurrent(generation) || (isCurrent && !isCurrent())) return false;
    sourceBusy = true; sourceSync();
    try {
      var options = await sourceCall("GET", "/source-options");
      if (!sourceCurrent(generation) || (isCurrent && !isCurrent())) return false;
      if (saved && !(options.sources || []).some(function (item) { return item.definition_id === saved.definition_id && item.version === saved.version && item.expected_integrity_sha256 === saved.expected_integrity_sha256 && item.editable === true; })) { sourceSay("This saved source changed. Refresh the list and choose its current setup; your entered choices were kept."); return false; }
      if (options.setup_available === false) { say(options.notice || "Source setup is not available for the current account. Check sign-in and Settings."); return false; }
      sourceOptions = options; editingSource = saved || null; sourceFormLoaded = true; sourceChosenProvider = saved ? saved.provider : "";
      sourceSelect(sourceEl("provider"), options.providers || [], "Choose a provider", saved && saved.provider);
      sourceEl("label").value = saved ? saved.label : "";
      sourceEl("background").checked = saved ? saved.background_authorized === true : false;
      renderSourceProvider(saved);
      if (!saved) restoreSourceDraft(options);
      sourceEl("editor").hidden = false; sourceEl("editor-title").textContent = editingSource ? "Change this evidence source" : "Connect evidence to your controls";
      sourceSay(saved ? "The saved choices are loaded. Find the current checks, then review every change. The earlier collection will pause when this new setup is saved." : "Choose a provider and account. Finding checks is a separate read; saving does not start collection.");
      if (!sourceCurrent(generation) || (isCurrent && !isCurrent())) return false;
      sourceEl("editor-title").focus();
      return true;
    } catch (failure) { if (sourceCurrent(generation)) sourceError(failure, "read the source setup choices"); return false; }
    finally { if (sourceCurrent(generation)) { sourceBusy = false; sourceSync(); } }
  }
  function addSourceBinding(saved) {
    var provider = sourceProvider();
    if (!provider || sourceEl("bindings").children.length >= provider.max_bindings) { sourceSay("The complete setup has reached its permitted number of check and control pairs."); return; }
    var row = document.createElement("div"); row.className = "trc-check-row";
    var checkLabel = document.createElement("label"), controlLabel = document.createElement("label");
    checkLabel.appendChild(document.createTextNode("Provider check")); controlLabel.appendChild(document.createTextNode("Your control"));
    var check = document.createElement("select"), ownControl = document.createElement("select"); check.className = "input"; ownControl.className = "input";
    check.required = true; ownControl.required = true; check.setAttribute("data-source-check", ""); ownControl.setAttribute("data-source-control", "");
    sourceSelect(check, sourceChecks, "Choose a check", saved && saved.source_ref);
    sourceSelect(ownControl, sourceOptions.controls || [], "Choose a control", saved && saved.control_ref);
    retainUnavailableChoice(check, saved && saved.source_ref, sourceChecks, "Earlier check unavailable — choose a current check");
    retainUnavailableChoice(ownControl, saved && saved.control_ref, sourceOptions.controls || [], "Earlier control unavailable — choose a current control");
    check.addEventListener("change", invalidateSourceReview); ownControl.addEventListener("change", invalidateSourceReview);
    checkLabel.appendChild(check); controlLabel.appendChild(ownControl); row.appendChild(checkLabel); row.appendChild(controlLabel);
    var remove = document.createElement("button"); remove.type = "button"; remove.className = "btn"; remove.textContent = "Remove this pair";
    remove.addEventListener("click", function () { row.remove(); invalidateSourceReview(); rememberSourceDraft(); }); row.appendChild(remove);
    sourceEl("bindings").appendChild(row); invalidateSourceReview(); rememberSourceDraft();
  }
  async function discoverSourceChecks() {
    if (sourceBusy || sourceAttempt || contextChanged) return;
    var provider = sourceProvider(), account = provider && provider.accounts.filter(function (item) { return item.name === sourceEl("account").value; })[0];
    if (!account || !sourceEl("form").reportValidity()) return;
    var retainedPairs = Array.from(sourceEl("bindings").children).map(function (row) { return {control_ref:row.querySelector("[data-source-control]").value,source_ref:row.querySelector("[data-source-check]").value}; });
    var generation = sourceGeneration, scope = sourceScope(), query = {provider:provider.id,connection_name:account.name,connection_revision:account.revision,scope_ref:scope.scope_ref,region:scope.region,stream:scope.stream};
    sourceBusy = true; invalidateSourceReview(); sourceEl("check-status").textContent = "Reading checks from the selected account…";
    try {
      var found = await sourceCall("POST", "/source-checks", query);
      if (!sourceCurrent(generation) || JSON.stringify(scope) !== JSON.stringify(sourceScope()) || account.name !== sourceEl("account").value || provider.id !== sourceEl("provider").value) return;
      sourceChecks = found.items || []; sourceEl("bindings").textContent = "";
      sourceEl("check-status").textContent = (found.complete ? "All checks returned for this scope: " : "This source returned a limited list: ") + sourceChecks.length + ". " + (found.notice || "");
      if (!found.complete) { sourceEl("coverage").textContent = "The returned list is incomplete. Only the exact checks you select are covered; missing checks have not been verified."; }
      if (retainedPairs.length) retainedPairs.forEach(addSourceBinding); else if (editingSource) (editingSource.bindings || []).forEach(addSourceBinding); else if (sourceChecks.length) addSourceBinding();
      if (!sourceChecks.length) sourceEl("coverage").textContent = "No usable checks were returned. Confirm this account and scope in Connections; no source setup was saved.";
    } catch (failure) { if (sourceCurrent(generation)) { sourceChecks = []; sourceEl("check-status").textContent = sourceError(failure, "read checks from this account"); } }
    finally { if (sourceCurrent(generation)) { sourceBusy = false; sourceSync(); } }
  }
  function sourceDraft() {
    var provider = sourceProvider(), account = provider && provider.accounts.filter(function (item) { return item.name === sourceEl("account").value; })[0];
    if (!account) throw new Error("Choose a current saved account first.");
    var scope = sourceScope(), bindings = Array.from(sourceEl("bindings").children).map(function (row) {
      return {control_ref:row.querySelector("[data-source-control]").value,source_ref:row.querySelector("[data-source-check]").value};
    });
    if (!bindings.length || bindings.some(function (pair) { return !pair.control_ref || !pair.source_ref; })) throw new Error("Choose the provider check and your control for every pair.");
    if (bindings.some(function (pair) { return !sourceChecks.some(function (item) { return item.id === pair.source_ref; }) || !(sourceOptions.controls || []).some(function (item) { return item.id === pair.control_ref; }); })) throw new Error("An earlier selected check or control is unavailable. Choose a current check and control for that pair before reviewing.");
    if (!sourceEl("background").checked) throw new Error("Review and explicitly allow future scheduled use of this saved account first.");
    return {label:sourceEl("label").value.trim(),provider:provider.id,connection_name:account.name,connection_revision:account.revision,scope_ref:scope.scope_ref,region:scope.region,stream:scope.stream,bindings:bindings,background_authorized:true,definition_id:editingSource ? editingSource.definition_id : null,expected_version:editingSource ? editingSource.version : null,expected_integrity_sha256:editingSource ? editingSource.expected_integrity_sha256 : null};
  }
  function sourceInputIdentity(draft) {
    return JSON.stringify({label:draft.label,provider:draft.provider,connection_name:draft.connection_name,connection_revision:draft.connection_revision,scope_ref:draft.scope_ref,region:draft.region,stream:draft.stream,bindings:draft.bindings.map(function (pair) { return {control_ref:pair.control_ref,source_ref:pair.source_ref}; }),background_authorized:draft.background_authorized,definition_id:draft.definition_id,expected_version:draft.expected_version,expected_integrity_sha256:draft.expected_integrity_sha256});
  }
  function sourceApprovalReview(rows) {
    return new Promise(function (resolve) {
      var generation = sourceGeneration, focusBefore = document.activeElement;
      var dialog = document.createElement("dialog"); dialog.className = "mv-confirm trc-source-approval";
      dialog.setAttribute("aria-labelledby","trc-source-approval-title");
      var body = document.createElement("div"); body.className = "mv-confirm__body";
      var heading = document.createElement("h2"); heading.id = "trc-source-approval-title"; heading.textContent = "Approve this complete setup"; body.appendChild(heading);
      var content = document.createElement("div"); renderSourceRows(content,rows); body.appendChild(content);
      var consequence = document.createElement("p"); consequence.textContent = "This is your separate approval of this exact setup. You cannot approve a setup you created. Collection starts only after an administrator separately chooses Start collecting."; body.appendChild(consequence);
      var checkLabel = document.createElement("label"); checkLabel.className = "check";
      var check = document.createElement("input"); check.type = "checkbox"; checkLabel.appendChild(check); checkLabel.appendChild(document.createTextNode(" I reviewed the named account, every check and control, and future collection permission.")); body.appendChild(checkLabel);
      var actions = document.createElement("div"); actions.className = "mv-confirm__row";
      var cancel = document.createElement("button"), approveButton = document.createElement("button");
      cancel.className = "btn"; cancel.textContent = "Cancel"; cancel.type = "button";
      approveButton.className = "btn btn--primary"; approveButton.textContent = "Approve setup"; approveButton.type = "button"; approveButton.disabled = true;
      function finish(accepted) { activeSourceApproval = null; dialog.close(); dialog.remove(); if (sourceCurrent(generation) && focusBefore && focusBefore.isConnected) focusBefore.focus(); resolve(accepted && sourceCurrent(generation)); }
      check.addEventListener("change",function () { approveButton.disabled = !check.checked; });
      cancel.addEventListener("click",function () { finish(false); });
      approveButton.addEventListener("click",function () { if (check.checked && sourceCurrent(generation)) finish(true); });
      dialog.addEventListener("cancel",function (event) { event.preventDefault(); finish(false); });
      actions.appendChild(cancel); actions.appendChild(approveButton); body.appendChild(actions); dialog.appendChild(body); document.body.appendChild(dialog);
      activeSourceApproval = finish; dialog.showModal(); cancel.focus();
    });
  }
  function sourceReviewRows(review) {
    var summary = review.summary, draft = review.draft;
    if (!summary || !Array.isArray(summary.controls) || summary.controls.length !== draft.bindings.length) throw new Error("The complete account, check and control review is unavailable. Nothing was saved.");
    var rows = [{label:"Source name",value:summary.label || draft.label},{label:"Evidence provider",value:summary.provider},{label:"Saved account",value:summary.account},{label:"Systems to check",value:summary.scope}];
    if (draft.region) rows.push({label:"Cloud region",value:summary.region || draft.region});
    if (draft.stream) {
      var provider = ((sourceOptions || {}).providers || S.authorProviders || []).filter(function (item) { return item.id === draft.provider; })[0];
      var stream = provider && provider.streams.filter(function (item) { return item.id === draft.stream; })[0];
      var streamLabels = {dependabot:"Dependency security",code_scanning:"Code security",secret_scanning:"Exposed secrets"};  // pragma: allowlist secret -- display labels, not a value
      rows.push({label:"Checks to read",value:stream ? stream.label : streamLabels[draft.stream] || R.human(summary.stream || draft.stream)});
    }
    summary.controls.forEach(function (pair, index) { rows.push({label:"Check " + (index + 1),value:pair.check}); rows.push({label:"Evidence for control " + (index + 1),value:pair.control}); });
    rows.push({label:"Future scheduled account use",value:summary.background_authorization},{label:"What saving changes",value:summary.change_effect});
    return rows;
  }
  function renderSourceRows(target, rows) {
    target.textContent = "";
    rows.forEach(function (row) {
      if (typeof row.value !== "string" || !row.value) throw new Error("A complete readable setup review is missing. Nothing was saved.");
      var list = document.createElement("dl"); list.className = "trc-review-row";
      var label = document.createElement("dt"), value = document.createElement("dd"); label.textContent = row.label; value.textContent = row.value;
      list.appendChild(label); list.appendChild(value); target.appendChild(list);
    });
  }
  async function prepareSource(event) {
    event.preventDefault(); if (sourceBusy || sourceAttempt || contextChanged || !sourceEl("form").reportValidity()) return;
    var draft; try { draft = sourceDraft(); } catch (failure) { sourceSay(failure.message); return; }
    var generation = sourceGeneration; sourceBusy = true; invalidateSourceReview(); sourceSay("Checking the complete source setup…");
    try {
      var reviewed = await sourceCall("POST", "/sources/review", draft);
      if (!sourceCurrent(generation) || sourceInputIdentity(draft) !== sourceInputIdentity(sourceDraft())) return;
      if (!reviewed.draft || !/^[a-f0-9]{64}$/.test(reviewed.review_sha256 || "") || !/^source-[a-f0-9-]+$/.test(reviewed.operation_id || "") || !reviewed.context || !Number.isFinite(reviewed.expires_at) || reviewed.expires_at * 1000 <= Date.now()) throw new Error("A complete current review is unavailable. Nothing was saved.");
      renderSourceRows(sourceEl("review-rows"), sourceReviewRows(reviewed)); sourceReview = reviewed;
      sourceEl("review").hidden = false; sourceEl("confirm").checked = false;
      sourceEl("review-expiry").textContent = "Review valid until " + R.when(reviewed.expires_at) + ". Any entered change needs a fresh review.";
      sourceEl("review-title").focus(); sourceSay("Read the complete setup below. Saving waits for separate approval; no collection starts.");
      sourceExpiryTimer = setTimeout(function () { if (sourceCurrent(generation) && sourceReview === reviewed) { sourceSync(); sourceSay("This review expired. Your entered choices were kept; review the complete setup again."); } }, Math.max(0, reviewed.expires_at * 1000 - Date.now()));
    } catch (failure) { if (sourceCurrent(generation)) sourceSay(failure.message && !failure.status ? failure.message : sourceError(failure, "review this source setup")); }
    finally { if (sourceCurrent(generation)) { sourceBusy = false; sourceSync(); } }
  }
  function rememberSourceDraft() {
    if (!sourceOptions || !sourceOptions.context || !sourceFormLoaded || contextChanged) return;
    var scope = sourceScope(), pairs = Array.from(sourceEl("bindings").children).map(function (row) { return {source_ref:row.querySelector("[data-source-check]").value,control_ref:row.querySelector("[data-source-control]").value}; });
    var draft = {context:sourceOptions.context,label:sourceEl("label").value,provider:sourceEl("provider").value,connection_name:sourceEl("account").value,scope_ref:scope.scope_ref,region:scope.region,stream:scope.stream,bindings:pairs,background_authorized:sourceEl("background").checked,editing:editingSource,checks:sourceChecks};
    try { sessionStorage.setItem(sourceDraftStorage, JSON.stringify(draft)); } catch (_failure) { sourceSay("This browser cannot retain these choices after leaving the page. Keep this page open until the setup is saved."); }
  }
  function restoreSourceDraft(options) {
    var saved; try { saved = JSON.parse(sessionStorage.getItem(sourceDraftStorage) || "null"); } catch (_failure) { return; }
    if (!saved || !options.context || JSON.stringify(saved.context) !== JSON.stringify(options.context)) return;
    if (!(options.providers || []).some(function (item) { return item.id === saved.provider; })) return;
    if (saved.editing && !(options.sources || []).some(function (item) { return item.definition_id === saved.editing.definition_id && item.version === saved.editing.version && item.expected_integrity_sha256 === saved.editing.expected_integrity_sha256; })) { sourceSay("An earlier entered source has changed. Refresh its current setup before using those earlier choices."); return; }
    editingSource = saved.editing || null; sourceChosenProvider = saved.provider; sourceEl("provider").value = saved.provider;
    sourceEl("label").value = saved.label || ""; sourceEl("background").checked = saved.background_authorized === true;
    renderSourceProvider(saved); sourceChecks = Array.isArray(saved.checks) ? saved.checks : [];
    (saved.bindings || []).forEach(addSourceBinding);
    sourceEl("check-status").textContent = "Your earlier entered choices were restored. Find the checks again if the account or scope changed. A fresh complete review is required.";
  }
  function rememberSourceAttempt(envelope) { sourceOriginalRequest = envelope; try { if (!sourceStorage) throw new Error("Account context unavailable"); sessionStorage.setItem(sourceStorage, JSON.stringify(envelope)); } catch (_failure) { sourceSay("This browser cannot keep the recovery reference after a reload. Keep this page open until the original result is read."); } }
  function restoreLegacyOriginal(context) {
    if (sourceOriginalRequest || !sourceStorage || !context) return;
    var retained; try { retained = JSON.parse(sessionStorage.getItem(sourceLegacyStorage) || "null"); } catch (_failure) { return; }
    if (!retained || !retained.draft || !retained.context || !retained.operation_id || retained.context.tenant_id !== context.tenant_id || retained.context.principal_ref !== context.principal_ref) return;
    sourceAttempt = retained; rememberSourceAttempt(retained); readSourceOriginal();
  }
  function originalMessage(result) {
    return "The original save created a setup for a different administrator to approve. " + (result.paused_enrollments ? result.paused_enrollments + " earlier collection(s) were paused. " : "") + "That save did not start collection. Read the current setup status before any separate approval or Start collecting.";
  }
  function showSourceOriginal(found) {
    sourceEl("original").hidden = false; sourceEl("original-rows").textContent = "";
    if (!found || !found.found || !found.result) { sourceEl("original-status").textContent = "The original save has not been found yet. Check again before starting another source. Do not save this request again."; return false; }
    var receipt = found.result;
    if (receipt.saved !== true || receipt.state !== "pending" || !Number.isInteger(receipt.version)) throw new Error("The earlier setup result could not be confirmed. No request was repeated.");
    sourceEl("original-status").textContent = originalMessage(receipt);
    var rows = receipt.summary && sourceOriginalRequest ? sourceReviewRows({summary:receipt.summary,draft:sourceOriginalRequest.draft}) : [];
    rows.push({label:"Saved setup edition",value:String(receipt.version)},{label:"Next step",value:"Read the current setup status. Approval by a different administrator and Start collecting are separate actions; this card records only the earlier save."});
    renderSourceRows(sourceEl("original-rows"), rows);
    return true;
  }
  async function readSourceOriginal() {
    if (!(sourceAttempt || sourceOriginalRequest) || sourceBusy || contextChanged) return;
    var generation = sourceGeneration, wasHeld = !!sourceAttempt, envelope = sourceAttempt || sourceOriginalRequest; sourceBusy = true; sourceSync(); sourceEl("original").hidden = false;
    sourceEl("original-status").textContent = "Reading the original request only…";
    try {
      var found = await sourceCall("POST", "/sources/original", envelope);
      if (!sourceCurrent(generation)) return;
      if (showSourceOriginal(found)) {
        sourceAttempt = null; sourceOriginalRequest = envelope;
        if (wasHeld && sourceEl("editor")) { sourceEl("editor").hidden = true; sourceFormLoaded = false; try { sessionStorage.removeItem(sourceDraftStorage); } catch (_failure) { /* confirmed original remains available */ } }
        if (root.getAttribute("data-enabled") !== "false") await loadAll();
      } else { sourceAttempt = envelope; }
    } catch (failure) { if (sourceCurrent(generation)) { var text = sourceError(failure, "read the original setup result"); if (sourceEl("original-status")) sourceEl("original-status").textContent = text; } }
    finally { if (sourceCurrent(generation)) { sourceBusy = false; sourceSync(); } }
  }
  async function saveSource() {
    if (sourceBusy || sourceAttempt || contextChanged || !sourceReview || !sourceEl("confirm").checked) return;
    if (Date.now() >= sourceReview.expires_at * 1000) { invalidateSourceReview(); sourceSay("This review expired. Review the complete setup again; nothing was saved."); return; }
    if (sourceInputIdentity(sourceReview.draft) !== sourceInputIdentity(sourceDraft())) { invalidateSourceReview(); sourceSay("Your choices changed. Review the complete setup again; nothing was saved."); return; }
    var generation = sourceGeneration;
    sourceAttempt = {draft:sourceReview.draft,review_sha256:sourceReview.review_sha256,context:sourceReview.context,operation_id:sourceReview.operation_id,expires_at:sourceReview.expires_at};
    rememberSourceAttempt(sourceAttempt); sourceBusy = true; sourceSync(); sourceEl("confirm").checked = false;
    try {
      var result = await sourceCall("POST", "/sources/save", sourceAttempt);
      if (!sourceCurrent(generation)) return;
      showSourceOriginal({found:true,result:result}); sourceAttempt = null;
      sourceEl("editor").hidden = true; sourceFormLoaded = false; try { sessionStorage.removeItem(sourceDraftStorage); } catch (_failure) { /* confirmed original remains available */ } invalidateSourceReview(); say(originalMessage(result)); await loadAll();
    } catch (failure) {
      if (!sourceCurrent(generation)) return;
      sourceEl("review").hidden = true;
      sourceEl("original").hidden = false;
      sourceEl("original-status").textContent = "The setup save result could not be confirmed. Your entered choices were kept. Read the original result below; do not save this request again.";
      sourceSay("The setup save result is uncertain. Use Read the original result; no second save is allowed here.");
      if (failure && (failure.status === 401 || failure.status === 403)) sourceError(failure, "save this source setup");
    } finally { if (sourceCurrent(generation)) { sourceBusy = false; sourceSync(); } }
  }
  function initializeSourceForm() {
    if (sourceEl("new")) sourceEl("new").addEventListener("click", function () { openSource(null); });
    if (sourceEl("form")) {
      sourceEl("form").addEventListener("submit", prepareSource);
      sourceEl("form").addEventListener("input", rememberSourceDraft);
      sourceEl("form").addEventListener("change", rememberSourceDraft);
      sourceEl("connect").addEventListener("click", rememberSourceDraft);
      sourceEl("label").addEventListener("input", invalidateSourceReview);
      sourceEl("provider").addEventListener("change", async function () {
        var next = sourceEl("provider").value, generation = sourceGeneration;
        if (sourceChosenProvider && sourceEl("bindings").children.length && !(await R.confirm("Change the provider? The current account, scope and check pairs will be cleared. The entered source name is kept.", "Change provider"))) { sourceEl("provider").value = sourceChosenProvider; rememberSourceDraft(); return; }
        if (!sourceCurrent(generation)) return;
        sourceChosenProvider = next; renderSourceProvider(null); rememberSourceDraft();
      });
      sourceEl("account").addEventListener("change", function () { sourceChecks = []; sourceEl("bindings").textContent = ""; invalidateSourceReview(); });
      sourceEl("background").addEventListener("change", invalidateSourceReview);
      sourceEl("discover").addEventListener("click", discoverSourceChecks);
      sourceEl("add-binding").addEventListener("click", function () { addSourceBinding(); });
      sourceEl("close").addEventListener("click", function () { rememberSourceDraft(); sourceEl("editor").hidden = true; invalidateSourceReview(); if (sourceEl("new")) sourceEl("new").focus(); });
      sourceEl("edit").addEventListener("click", function () { invalidateSourceReview(); sourceEl("label").focus(); });
      sourceEl("confirm").addEventListener("change", sourceSync);
      sourceEl("save").addEventListener("click", saveSource);
    }
    if (sourceEl("read-original")) sourceEl("read-original").addEventListener("click", readSourceOriginal);
    try { var retained = sourceStorage && JSON.parse(sessionStorage.getItem(sourceStorage) || "null"); if (retained && retained.draft && retained.context && retained.operation_id) { sourceAttempt = retained; sourceOriginalRequest = retained; readSourceOriginal(); } } catch (_failure) { /* invalid browser recovery data is not submitted */ }
    sourceSync();
  }

  window.LightworkContinuousEvidence.openSourceReview = async function (selection, options) {
    var current = options && options.isCurrent, context = options && options.context, generation = sourceGeneration;
    if (contextChanged || location.pathname !== "/compliance/continuous-evidence" || (selection && Object.keys(selection).length) || !/^[a-f0-9]{64}$/.test(context || "") || (current && !current()) || sourceBusy) return false;
    var checked;
    try { checked = await R.call("POST", "/api/v1/copilot/product-operations/catalog", {page:"/compliance/continuous-evidence",selection:{}}); }
    catch (failure) { if (sourceCurrent(generation)) sourceError(failure,"check current evidence setup access"); return false; }
    if (!sourceCurrent(generation) || checked.context !== context || (current && !current()) || !(checked.operations || []).some(function (row) { return row.id === "connections.evidence_source_setup" && row.available; })) return false;
    if (sourceAttempt) {
      if (current && !current()) return false;
      sourceEl("original").hidden = false; sourceEl("read-original").focus(); sourceEl("original").scrollIntoView({block:"center"});
      sourceEl("original-status").textContent = "Your earlier setup result is still uncertain. Read its original result before another save. Your entered choices were kept.";
      return true;
    }
    var opened = await openSource(null, {isCurrent:current});
    if (!opened || !sourceCurrent(generation) || (current && !current())) return false;
    sourceEl("editor").scrollIntoView({block:"start"});
    sourceSay("Your entered source choices were kept. Opening this form did not save, approve or start collection.");
    return true;
  };
  function setCycleReady(ready) {
    runCycle.disabled = !ready || !canAdmin;
    if (runCycle.disabled) { runCycle.setAttribute("aria-disabled", "true"); } else { runCycle.removeAttribute("aria-disabled"); }
  }
  function control(ref) { return R.human(ref); }
  function setupFor(item) { return S.setup.filter(function (s) { return s.definition_id === item.definition_id; })[0]; }
  function labelFor(item) { var s = setupFor(item); return s ? s.label : "A collection"; }

  function loadAll() {
    setCycleReady(false);
    say("Loading…");
    var generation = sourceGeneration;
    return Promise.all([
      api("GET", "/status"), api("GET", "/setup"), api("GET", "/definitions"),
      api("GET", "/enrollments"), api("GET", "/runs?limit=50"),
      api("GET", "/jobs?state=dead_letter"), api("GET", "/alerts?limit=100"),
      canAdmin ? sourceCall("GET", "/source-options").catch(function (failure) { if (failure && (failure.status === 401 || failure.status === 403)) clearSourceAccess(); return {sources:[],unavailable:true,notice:R.errorText(failure,"read source setup choices")}; }) : Promise.resolve({sources:[]})
    ]).then(function (results) {
      if (!sourceCurrent(generation)) { return; }
      S.status = results[0]; S.setup = results[1].items || []; S.definitions = results[2].items || [];
      S.enrollments = results[3].items || []; S.runs = results[4].items || []; S.jobs = results[5].items || []; S.alerts = results[6].items || [];
      S.authorSources = results[7].sources || []; S.authorProviders = results[7].providers || [];
      renderStatus(); renderSources(); renderDefinitions(); renderRuns(); renderAlerts();
      say(results[7].unavailable || results[7].setup_available === false ? "Evidence lists loaded. " + results[7].notice : "Up to date.");
      restoreLegacyOriginal(results[7].context);
    }).catch(function (failure) { if (sourceCurrent(generation)) { fail("load continuous evidence")(failure); } });
  }

  function renderStatus() {
    var result = S.status || {};
    var stock = result.stock_collectors || {};
    var ready = stock.ready === true || stock.composition_ready === true;
    var missing = (stock.missing_stock_collector_ids || []).length;
    document.getElementById("trc-composition").textContent = ready ? "Complete" : missing ? missing + " step" + (missing === 1 ? "" : "s") + " left" : "Not finished";
    var running = Boolean(result.scheduler && result.scheduler.running === true);
    document.getElementById("trc-scheduler").textContent = running ? "On" : "Off";
    var active = S.enrollments.filter(function (e) { return e.state === "active"; }).length;
    document.getElementById("trc-feeds").textContent = active + " of " + Math.max(S.setup.length, active);
    var last = S.runs.slice().sort(function (a, b) { return b.completed_at - a.completed_at; })[0];
    var lastBatch = last ? S.runs.filter(function (r) { return Math.abs(r.completed_at - last.completed_at) < 3600; }) : [];
    document.getElementById("trc-cycle").textContent = last ? R.when(last.completed_at) : "Not yet";
    document.getElementById("trc-cycle-detail").textContent = last
      ? "Last collection: " + lastBatch.filter(function (r) { return r.complete; }).length + " finished, " + lastBatch.filter(function (r) { return !r.complete; }).length + " incomplete"
      : "Last collection";
    // Manual collection unlocks only on positive proof the scheduler runs.
    setCycleReady(Boolean(result.scheduler && result.scheduler.running === true));
  }

  function enrollmentFor(item) { return S.enrollments.filter(function (e) { return e.enrollment_id === item.enrollment_id && e.definition_id === item.definition_id && e.definition_version === item.definition_version; })[0]; }
  function definitionFor(item) { return S.definitions.filter(function (d) { return d.definition_id === item.definition_id && d.version === item.definition_version; })[0]; }
  function sourceState(item) {
    var def = definitionFor(item);
    var enr = enrollmentFor(item);
    if (def && def.state === "pending") { return ["Waiting for approval", "warn"]; }
    if (enr) { return enr.state === "active" ? ["Schedule active", "ok"] : enr.state === "paused" ? ["Paused", "warn"] : ["Removed", "idle"]; }
    if (!def) { return ["Not set up", "idle"]; }
    if (def.state === "pending") { return ["Waiting for approval", "warn"]; }
    if (def.state === "approved") { return ["Ready to start", "info"]; }
    return ["Retired", "idle"];
  }
  function renderSources() {
    R.table(document.getElementById("trc-sources"), [
      { label: "Source", value: function (s) { return s.label; } },
      { label: "Controls", value: function (s) { return s.control_count; } },
      { label: "Setup managed here", value: function (s) { return s.managed === true ? "Yes — choose Change setup to review edits" : "Installation-managed; its saved settings are preserved"; } },
      { label: "Saved account", value: function (s) { var source = (S.authorSources || []).filter(function (item) { return item.definition_id === s.definition_id && item.version === s.definition_version; })[0]; return source ? source.connection_name : s.credential_ready === false ? R.badge("Missing", "danger") : s.credential_ready ? R.badge("Found", "ok") : "—"; } },
      { label: "Status", value: function (s) { var st = sourceState(s); return R.badge(st[0], st[1]); } },
    ], S.setup, [
      { label: "Change setup", when: function (item) { return canAdmin && (S.authorSources || []).some(function (source) { return source.definition_id === item.definition_id && source.editable === true; }); }, run: function (item) { var source = (S.authorSources || []).filter(function (candidate) { return candidate.definition_id === item.definition_id && candidate.editable === true; }).sort(function (a,b) { return b.version-a.version; })[0]; if (source) openSource(source); } },
      { label: "Set up", kind: "primary", when: function (s) { return canAdmin && !definitionFor(s); }, run: setUp },
      { label: "Start collecting", kind: "primary", when: function (s) { var d = definitionFor(s); return canAdmin && d && d.state === "approved" && !enrollmentFor(s); }, run: startCollecting },
      { label: "Pause", when: function (s) { var e = enrollmentFor(s); return canAdmin && e && e.state === "active"; }, run: function (s) { changeState(enrollmentFor(s), "paused", s.label); } },
      { label: "Resume", kind: "primary", when: function (s) { var e = enrollmentFor(s); return canAdmin && e && e.state === "paused"; }, run: function (s) { changeState(enrollmentFor(s), "active", s.label); } },
      { label: "Remove", kind: "danger", when: function (s) { var e = enrollmentFor(s); return canAdmin && e && e.state !== "revoked"; }, run: function (s) { changeState(enrollmentFor(s), "revoked", s.label); } },
    ], { text: "No sources are configured for this workspace yet. Choose Add a source to use a saved account and select the checks and controls." });
  }
  function setUp(s) {
    R.confirm("Set up evidence collection from " + s.label + "? A different administrator then approves it before any collection starts.", "Set up").then(function (ok) {
      if (!ok) { return; }
      return api("POST", "/setup/" + encodeURIComponent(s.key) + "/definition").then(function () { say(s.label + " is set up and waiting for approval."); loadAll(); });
    }).catch(fail("set up the source"));
  }
  function startCollecting(s) {
    R.form("Start collecting from " + s.label, [
      { key: "every", label: "Collect", type: "select", default: "86400", options: [{ value: "3600", label: "Every hour" }, { value: "21600", label: "Every 6 hours" }, { value: "86400", label: "Every day" }, { value: "604800", label: "Every week" }] },
      { key: "keep", label: "Keep evidence for", type: "select", default: "31536000", options: [{ value: "7776000", label: "90 days" }, { value: "31536000", label: "1 year" }, { value: "94608000", label: "3 years" }, { value: "220752000", label: "7 years" }] },
    ], "Start").then(function (v) {
      if (!v) { return; }
      return api("POST", "/setup/" + encodeURIComponent(s.key) + "/enrollment", { interval_seconds: Number(v.every), retention_seconds: Number(v.keep) })
        .then(function () { say("Collection from " + s.label + " has started."); loadAll(); });
    }).catch(fail("start collecting"));
  }
  function changeState(e, state, name) {
    var words = { paused: ["Pause collecting from " + name + "?", "Pause"], active: ["Resume collecting from " + name + "?", "Resume"],
      revoked: ["Stop and remove collection from " + name + "? It can't be resumed; you would set it up again.", "Remove"] }[state];
    R.confirm(words[0], words[1]).then(function (ok) {
      if (!ok) { return; }
      return api("POST", "/enrollments/" + encodeURIComponent(e.enrollment_id) + "/state", { state: state, expected_revision: e.revision, expected_integrity_sha256: e.integrity_sha256 })
        .then(function () { say("Updated."); loadAll(); });
    }).catch(fail("update the collection"));
  }

  function renderDefinitions() {
    R.table(document.getElementById("trc-definitions"), [
      { label: "Source", value: labelFor },
      { label: "Setup edition", value: function (d) { var setup = setupFor(d); return String(d.version) + (setup && setup.definition_version !== d.version ? " — earlier setup" : " — current setup"); } },
      { label: "Controls", value: function (d) { return (d.allowed_control_refs || []).length; } },
      { label: "Status", value: function (d) { return R.badge(d.state === "pending" ? "Waiting for approval" : R.human(d.state), d.state === "approved" ? "ok" : d.state === "pending" ? "warn" : "idle"); } },
      { label: "Created", value: function (d) { return R.when(d.created_at); } },
    ], S.definitions, [
      { label: "Approve", kind: "primary", when: function (d) { return canAdmin && d.state === "pending"; }, run: approve },
      { label: "Retire", kind: "danger", when: function (d) { return canAdmin && d.state === "approved"; }, run: retire },
    ], { text: "No collection setups yet. Use Set up on a source above." });
  }
  function approve(d) {
    var source = (S.authorSources || []).filter(function (item) { return item.definition_id === d.definition_id && item.version === d.version; })[0];
    var generation = sourceGeneration, review;
    if (source && source.summary) {
      try { review = sourceApprovalReview(sourceReviewRows({summary:source.summary,draft:source})); }
      catch (failure) { say(failure.message); return; }
    } else review = R.confirm("Approve collecting evidence from " + labelFor(d) + " for " + (d.allowed_control_refs || []).length + " controls? You can't approve a setup you created.", "Approve");
    review.then(function (ok) {
      if (!ok || !sourceCurrent(generation)) { return; }
      return api("POST", "/definitions/" + encodeURIComponent(d.definition_id) + "/versions/" + d.version + "/approve", { expected_integrity_sha256: d.integrity_sha256 })
        .then(function () { if (sourceCurrent(generation)) { say("Approved. Collection has not started; choose Start collecting separately."); loadAll(); } });
    }).catch(fail("approve the setup"));
  }
  function retire(d) {
    R.confirm("Retire this setup for " + labelFor(d) + "? Collections using it stop.", "Retire").then(function (ok) {
      if (!ok) { return; }
      return api("POST", "/definitions/" + encodeURIComponent(d.definition_id) + "/versions/" + d.version + "/retire", { expected_integrity_sha256: d.integrity_sha256 })
        .then(function () { say("Retired."); loadAll(); });
    }).catch(fail("retire the setup"));
  }

  function enrollmentLabel(id) { var s = S.setup.filter(function (x) { return x.enrollment_id === id; })[0]; return s ? s.label : "A source"; }
  function renderRuns() {
    R.table(document.getElementById("trc-runs"), [
      { label: "Source", value: function (r) { return enrollmentLabel(r.enrollment_id); } },
      { label: "Finished", value: function (r) { return R.when(r.completed_at); } },
      { label: "Result", value: function (r) { return r.complete ? R.badge("Complete", "ok") : R.badge("Incomplete", "warn"); } },
      { label: "Items checked", value: function (r) { return r.item_count; } },
    ], S.runs.slice().sort(function (a, b) { return b.completed_at - a.completed_at; }).slice(0, 50), [], { text: "No collections yet. They start once a source is set up, approved and started." });
    var retry = document.getElementById("trc-retry");
    retry.hidden = !(canAdmin && S.jobs.length);
    retry.textContent = "Retry failed collections (" + S.jobs.length + ")";
  }
  initializeSourceForm();
  if (root.getAttribute("data-enabled") === "false") { return; }

  document.getElementById("trc-retry").addEventListener("click", function () {
    R.confirm("Retry the " + S.jobs.length + " collection(s) that failed?", "Retry").then(function (ok) {
      if (!ok) { return; }
      return Promise.all(S.jobs.map(function (j) {
        return api("POST", "/jobs/" + encodeURIComponent(j.job_id) + "/requeue", { expected_revision: j.revision, operation_id: "retry-" + R.newKey().toLowerCase().replace(/[^a-z0-9-]/g, "") });
      })).then(function () { say("Failed collections will be tried again."); loadAll(); });
    }).catch(fail("retry the failed collections"));
  });

  function renderAlerts() {
    R.table(document.getElementById("trc-alerts"), [
      { label: "Source", value: function (a) { return enrollmentLabel(a.enrollment_id); } },
      { label: "Control", value: function (a) { return control(a.control_ref); } },
      { label: "Was", value: function (a) { var s = STATUS[a.previous_status] || [R.human(a.previous_status), "idle"]; return R.badge(s[0], s[1]); } },
      { label: "Now", value: function (a) { var s = STATUS[a.current_status] || [R.human(a.current_status), "idle"]; return R.badge(s[0], s[1]); } },
      { label: "When", value: function (a) { return R.when(a.created_at); } },
    ], S.alerts.slice().sort(function (a, b) { return b.created_at - a.created_at; }), [], { text: "No evidence has changed." });
  }

  document.getElementById("trc-refresh").addEventListener("click", loadAll);
  runCycle.addEventListener("click", function () {
    runCycle.disabled = true;
    say("Collecting evidence…");
    api("POST", "/scheduler/run-once").then(function (d) {
      say(d.executed ? "Collection finished. Check the list below for any incomplete sources." : "Nothing was due to be collected.");
      return loadAll();
    }).catch(function (f) {
      say(f && f.status === 409 ? "A collection is already running. Try again in a minute." : R.errorText(f, "collect evidence"));
      setCycleReady(Boolean(S.status && S.status.scheduler && S.status.scheduler.running === true));
    });
  });

  var adminResult = document.getElementById("trc-admin-result");
  document.getElementById("trc-purge-before").value = R.isoDateIn(0);
  document.getElementById("trc-integrity").addEventListener("click", function () {
    if (!canAudit) { adminResult.textContent = "Only auditors and administrators can run this check."; return; }
    api("GET", "/integrity").then(function () { adminResult.textContent = "No changes found in the evidence records."; },
      function (f) { adminResult.textContent = R.errorText(f, "check the records"); });
  });
  document.getElementById("trc-purge").addEventListener("click", function () {
    if (!canAdmin) { adminResult.textContent = "Only administrators can delete expired records."; return; }
    var cutoff = R.toEpoch(document.getElementById("trc-purge-before").value);
    if (!cutoff) { adminResult.textContent = "Choose a date first."; return; }
    R.confirm("Delete evidence records whose keep period ended before this date? This can't be undone.", "Delete").then(function (ok) {
      if (!ok) { return; }
      api("POST", "/retention/purge", { cutoff: cutoff, limit: 500 }).then(function () { adminResult.textContent = "Expired records were deleted."; loadAll(); },
        function (f) { adminResult.textContent = R.errorText(f, "delete expired records"); });
    });
  });

  loadAll();
})();
