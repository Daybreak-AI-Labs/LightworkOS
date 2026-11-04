/* Governance assistants page: reviews, policies and maintenance as lists and
   buttons. Every button is enabled only when the server reports that its
   operation is set up; record references and versions come from the chosen
   row, and evidence is chosen from the server's own current record list. */
(function () {
  "use strict";
  var root = document.getElementById("ga-root");
  if (!root) return;
  var API = root.dataset.api || "/api/v1/governance-agents";
  var MAX_RESPONSE_BYTES = 1024 * 1024;
  var can = {
    operate: root.dataset.canOperate === "true",
    admin: root.dataset.canAdmin === "true",
    audit: root.dataset.canAudit === "true"
  };
  var OP_STATUS = {
    "analysis": "analysis", "run-list": "run_read", "review": "review", "execute": "execution",
    "recover": "recovery", "run-revoke": "run_revoke", "policy-revoke": "policy_revoke",
    "retention-purge": "retention_purge", "integrity": "integrity",
    "maintenance-readiness": "maintenance_readiness", "adapter-rotate": "maintenance_bindings",
    "adapter-revoke": "maintenance_bindings", "dispatcher-rotate": "maintenance_bindings",
    "dispatcher-revoke": "maintenance_bindings", "custody-rotate": "maintenance_custody",
    "token-reconcile": "maintenance_custody", "intent-list": "maintenance_intents"
  };
  var SETUP_LABELS = {
    policy_publish: "publishing policies", policy_revoke: "stopping policies", analysis: "preparing reviews",
    run_read: "showing reviews", review: "approving reviews", execution: "carrying out approved actions",
    recovery: "finishing interrupted actions", run_revoke: "withdrawing reviews",
    retention_purge: "deleting old reviews", integrity: "checking records",
    maintenance_readiness: "readiness checks", maintenance_bindings: "managing assistant engines",
    maintenance_custody: "managing recovery keys", maintenance_intents: "listing internal actions"
  };
  var AGENTS = {
    breach_response: "Breach response", privacy_risk_assessment: "Privacy risk",
    program_copilot: "Program copilot", knowledgebase_governance: "Knowledgebase governance",
    third_party_risk: "Third-party risk"
  };
  var STATES = {
    pending_review: ["Waiting for review", "warn"], approved: ["Approved", "ok"], rejected: ["Rejected", "failed"],
    executing: ["Being carried out", "running"], executed: ["Carried out", "ok"],
    execution_failed: ["Couldn't be carried out", "failed"], revoked: ["Withdrawn", "idle"]
  };
  var REASONS = [
    ["evidence_sufficient", "The evidence is enough"], ["evidence_partial", "The evidence is incomplete"],
    ["evidence_conflicting", "The evidence conflicts"], ["evidence_stale", "The evidence is out of date"],
    ["authority_required", "Someone with more authority must decide"], ["policy_threshold", "Our policy requires it"],
    ["human_override", "My own judgement"], ["false_positive", "This is a false alarm"],
    ["risk_accepted", "We accept the risk"], ["not_applicable", "It doesn't apply"]
  ];
  var configured = {};
  var policies = [];
  var runs = [];
  var starting = null;
  var preview = null;
  var result = document.getElementById("ga-result");
  var output = document.getElementById("ga-output");

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }
  function human(value) {
    if (typeof window.mvHuman === "function") return window.mvHuman(value);
    var text = String(value || "").replace(/[_.:-]+/g, " ").trim();
    return text ? text.charAt(0).toUpperCase() + text.slice(1) : "";
  }
  function when(ts) {
    if (typeof window.mvWhen === "function") return window.mvWhen(ts);
    return ts ? (window.mvTimeAbsolute ? window.mvTimeAbsolute(ts) : new Date(ts * 1000).toLocaleString()) : "";
  }
  function reference(prefix) {
    if (window.crypto && typeof window.crypto.randomUUID === "function") return prefix + "-" + window.crypto.randomUUID();
    return prefix + "-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 12);
  }
  function plain(status, action, headers) {
    // Headers carry the turned-off reason, so "off" is never read as "no permission".
    if (typeof window.mvErrorText === "function") return window.mvErrorText({ status: status, headers: headers }, action);
    if (status === 403) return "Could not " + action + ". You do not have permission to do this.";
    if (status === 409) return "Could not " + action + ". This changed since you opened it. Refresh and try again.";
    return "Could not " + action + ". Something went wrong. Try again.";
  }
  function unexpected() { return new Error("Lightwork returned something unexpected. Refresh the page and try again."); }

  async function boundedResponseText(response) {
    var declared = response.headers && response.headers.get("Content-Length");
    if (declared && /^\d+$/.test(declared) && Number(declared) > MAX_RESPONSE_BYTES) {
      if (response.body && typeof response.body.cancel === "function") {
        try { await response.body.cancel(); } catch (_error) { /* already failing closed */ }
      }
      throw unexpected();
    }
    if (!response.body || typeof response.body.getReader !== "function") throw unexpected();
    var reader = response.body.getReader();
    var decoder = new TextDecoder("utf-8", { fatal: false });
    var received = 0;
    var text = "";
    while (true) {
      var chunk = await reader.read();
      if (chunk.done) break;
      received += chunk.value.byteLength;
      if (received > MAX_RESPONSE_BYTES) {
        try { await reader.cancel(); } catch (_error) { /* size failure wins */ }
        throw unexpected();
      }
      text += decoder.decode(chunk.value, { stream: true });
    }
    return text + decoder.decode();
  }
  async function request(method, path, payload, action, base) {
    var options = { method: method, headers: { Accept: "application/json" }, credentials: "same-origin", cache: "no-store" };
    if (method !== "GET") {
      options.headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(payload || {});
    }
    var response = await fetch((base || API) + path, options);
    var text = await boundedResponseText(response);
    var body;
    try { body = text ? JSON.parse(text) : {}; } catch (_error) { throw unexpected(); }
    if (!response.ok) {
      var error = new Error(plain(response.status, action || "finish this", response.headers));
      error.status = response.status;
      error.technical = body && typeof body.detail === "string" ? body.detail : "";
      throw error;
    }
    return body;
  }
  function say(message, details) {
    window.mvStatus(result, message);
    output.textContent = details === undefined ? "" : typeof details === "string" ? details : JSON.stringify(details, null, 2);
  }
  function failed(error) {
    say(error && error.message ? error.message : "Something went wrong. Try again.", error && error.technical ? error.technical : undefined);
  }
  function ask(message, okText) {
    if (typeof window.mvConfirm === "function") return window.mvConfirm(message, { okText: okText });
    return Promise.resolve(false);
  }
  function askReason(title, okText) {
    if (typeof window.mvForm !== "function") return Promise.resolve(null);
    return window.mvForm(title, [{
      key: "reason", label: "Why?", type: "select", required: true, default: "evidence_sufficient",
      options: REASONS.map(function (item) { return { value: item[0], label: item[1] }; })
    }], { okText: okText });
  }
  function ready(op) { return configured[OP_STATUS[op]] === true; }
  function button(label, op, handler, cls) {
    var b = el("button", cls || "btn", label);
    b.type = "button";
    b.dataset.op = op;
    b.disabled = !ready(op);
    b.addEventListener("click", function () {
      if (b.disabled) return;
      b.disabled = true;
      Promise.resolve().then(handler).catch(failed).then(function () { b.disabled = !ready(op); });
    });
    return b;
  }
  function emptyRow(tbody, columns, text) {
    tbody.textContent = "";
    var tr = el("tr");
    var td = el("td", null, text);
    td.colSpan = columns;
    tr.appendChild(td);
    tbody.appendChild(tr);
  }

  // ---- status ------------------------------------------------------------
  function applyStatus(body) {
    var composition = body && body.composition;
    var operations = composition && composition.operations_configured_for_attempt;
    if (!body || body.schema !== "lightwork.governance-agent-status.v1" || !composition ||
        composition.assessment !== "configured_for_attempt_only" ||
        composition.status_opened_store !== false ||
        composition.operational_verification_performed !== false ||
        !operations || typeof operations !== "object") {
      throw unexpected();
    }
    configured = {};
    Object.keys(operations).forEach(function (key) { configured[key] = operations[key] === true; });
    Array.prototype.forEach.call(document.querySelectorAll("[data-op]"), function (node) {
      node.disabled = !ready(node.dataset.op);
    });
    var missing = Object.keys(SETUP_LABELS).filter(function (key) { return operations[key] !== true; });
    var list = document.getElementById("ga-missing");
    list.textContent = "";
    missing.forEach(function (key) { list.appendChild(el("li", null, "Not set up yet: " + SETUP_LABELS[key])); });
    document.getElementById("ga-readiness-note").textContent = missing.length
      ? "Some parts aren't set up yet, so their buttons are turned off. Ask an administrator to finish setting them up."
      : "Everything is set up. Each action is still checked when you use it.";
  }
  async function loadStatus() {
    configured = {};
    Array.prototype.forEach.call(document.querySelectorAll("[data-op]"), function (node) { node.disabled = true; });
    document.getElementById("ga-readiness-note").textContent = "Checking what is set up…";
    try {
      applyStatus(await request("GET", "/status", undefined, "check what is set up"));
    } catch (error) {
      configured = {};
      document.getElementById("ga-readiness-note").textContent = (error && error.message) || "Couldn't check what is set up. Refresh the page and try again.";
    }
  }

  // ---- policies ------------------------------------------------------------
  async function loadPolicies() {
    var tbody = document.getElementById("ga-policies");
    try {
      var body = await request("GET", "/policies", undefined, "load policies");
      policies = Array.isArray(body.items) ? body.items : [];
    } catch (error) {
      policies = [];
      emptyRow(tbody, 6, error.message);
      return;
    }
    if (!policies.length) {
      emptyRow(tbody, 6, "No policies yet. An administrator publishes a policy before assistants can prepare reviews.");
      return;
    }
    tbody.textContent = "";
    policies.forEach(function (policy) {
      var tr = el("tr");
      var th = el("th", null, human(policy.policy_id)); th.scope = "row"; tr.appendChild(th);
      tr.appendChild(el("td", null, AGENTS[policy.agent_kind] || human(policy.agent_kind)));
      tr.appendChild(el("td", null, String(policy.required_approvals)));
      tr.appendChild(el("td", null, policy.execution_enabled ? "Yes" : "No"));
      var active = !policy.revoked && Number(policy.valid_until) * 1000 > Date.now();
      var status = el("td");
      status.appendChild(el("span", "badge " + (active ? "ok" : "idle"), policy.revoked ? "Stopped" : active ? "In use" : "Expired"));
      tr.appendChild(status);
      var actions = el("td");
      if (can.admin && active) {
        actions.appendChild(button("Stop using", "policy-revoke", function () { return revokePolicy(policy); }, "btn btn--danger"));
      }
      tr.appendChild(actions);
      tbody.appendChild(tr);
    });
  }
  async function revokePolicy(policy) {
    var choice = await askReason("Stop using the policy " + human(policy.policy_id), "Stop using");
    if (!choice || !choice.reason) return;
    var body = await request("POST", "/policies/" + encodeURIComponent(policy.policy_id) + "/revoke",
      { revision: policy.revision, reason_code: choice.reason }, "stop the policy");
    say("The policy " + human(policy.policy_id) + " is no longer in use.", body);
    await loadPolicies();
  }

  // ---- runs --------------------------------------------------------------
  async function loadRuns() {
    var tbody = document.getElementById("ga-runs");
    try {
      var body = await request("GET", "/runs?limit=200", undefined, "load reviews");
      runs = Array.isArray(body.items) ? body.items : [];
    } catch (error) {
      runs = [];
      emptyRow(tbody, 6, error.message);
      return;
    }
    renderRuns();
  }
  function policyFor(run) {
    for (var i = 0; i < policies.length; i += 1) if (policies[i].policy_id === run.policy_id) return policies[i];
    return null;
  }
  function renderRuns() {
    var tbody = document.getElementById("ga-runs");
    var filter = document.getElementById("ga-runs-filter").value;
    var shown = runs.filter(function (run) { return !filter || run.agent_kind === filter; });
    if (!shown.length) {
      emptyRow(tbody, 6, can.operate ? "No reviews yet. Use Start a review on one of the assistants above." : "No reviews yet. They appear here when an operator starts one.");
      return;
    }
    tbody.textContent = "";
    shown.forEach(function (run) {
      var tr = el("tr");
      var th = el("th", null, AGENTS[run.agent_kind] || human(run.agent_kind)); th.scope = "row"; tr.appendChild(th);
      tr.appendChild(el("td", null, human(run.capability)));
      var state = el("td");
      var pair = STATES[run.state] || [human(run.state), "idle"];
      state.appendChild(el("span", "badge " + pair[1], pair[0]));
      var approvals = Array.isArray(run.approvals) ? run.approvals.filter(function (a) { return a.decision === "approve"; }).length : 0;
      var policy = policyFor(run);
      if (run.state === "pending_review" && policy) {
        state.appendChild(el("div", "muted", approvals + " of " + policy.required_approvals + " approvals"));
      }
      tr.appendChild(state);
      tr.appendChild(el("td", null, String(Array.isArray(run.findings) ? run.findings.length : 0)));
      tr.appendChild(el("td", null, when(run.updated_at)));
      var actions = el("td");
      var wrap = el("div", "ga-actions", null);
      wrap.appendChild(button("View", "run-list", function () { showRun(run); }, "btn btn--ghost"));
      if (can.operate && run.state === "pending_review") {
        wrap.appendChild(button("Approve", "review", function () { return review(run, "approve"); }, "btn btn--primary"));
        wrap.appendChild(button("Reject", "review", function () { return review(run, "reject"); }));
      }
      if (can.admin && run.state === "approved" && policy && policy.execution_enabled) {
        wrap.appendChild(button("Carry out", "execute", function () { return execute(run); }, "btn btn--primary"));
      }
      if (can.admin && run.state === "executing") {
        wrap.appendChild(button("Finish the interrupted action", "recover", function () { return recover(run); }));
      }
      if (can.admin && ["pending_review", "approved"].indexOf(run.state) >= 0) {
        wrap.appendChild(button("Withdraw", "run-revoke", function () { return withdraw(run); }, "btn btn--danger"));
      }
      actions.appendChild(wrap);
      tr.appendChild(actions);
      tbody.appendChild(tr);
    });
  }
  function showRun(run) {
    var box = document.getElementById("ga-detail");
    box.textContent = "";
    box.appendChild(el("p", null, (AGENTS[run.agent_kind] || human(run.agent_kind)) + " · " + human(run.capability) +
      " · " + (STATES[run.state] || [human(run.state)])[0]));
    var findings = Array.isArray(run.findings) ? run.findings : [];
    if (!findings.length) box.appendChild(el("p", "muted", "No findings."));
    var list = el("ul");
    findings.forEach(function (finding) {
      var text = human(finding.finding_code) + " (" + human(finding.severity) + ")";
      if (finding.recommended_action_code) text += " — suggested next step: " + human(finding.recommended_action_code);
      if (Number.isFinite(finding.confidence_bps)) text += " · confidence " + Math.round(finding.confidence_bps / 100) + "%";
      list.appendChild(el("li", null, text));
    });
    box.appendChild(list);
    var limits = Array.isArray(run.limitations) ? run.limitations : [];
    if (limits.length) box.appendChild(el("p", "muted", "Limits: " + limits.map(human).join(", ")));
    if (run.analysis_complete === false) box.appendChild(el("p", "muted", "The assistant could not read everything it needed. Refresh the page and try again."));
    document.getElementById("ga-detail-panel").hidden = false;
    var heading = document.getElementById("ga-detail-title");
    if (heading && heading.focus) heading.focus();
    say("Showing the findings of this review.", run);
  }
  async function review(run, decision) {
    var choice = await askReason(decision === "approve" ? "Approve this review" : "Reject this review",
      decision === "approve" ? "Approve" : "Reject");
    if (!choice || !choice.reason) return;
    var body = await request("POST", "/runs/" + encodeURIComponent(run.run_id) + "/review",
      { expected_revision: run.revision, decision: decision, rationale_code: choice.reason },
      decision === "approve" ? "approve the review" : "reject the review");
    say(decision === "approve" ? "Your approval was recorded." : "The review was rejected.", body);
    await loadRuns();
  }
  async function execute(run) {
    var ok = await ask("Carry out the approved action for this " + (AGENTS[run.agent_kind] || "assistant") +
      " review? It is recorded and can't be undone from here.", "Carry out");
    if (!ok) return;
    var body = await request("POST", "/runs/" + encodeURIComponent(run.run_id) + "/execute",
      { expected_revision: run.revision }, "carry out the action");
    say("The action was carried out.", body);
    await loadRuns();
  }
  async function recover(run) {
    var ok = await ask("Finish the interrupted action for this review? It is completed exactly once.", "Finish it");
    if (!ok) return;
    var body = await request("POST", "/runs/" + encodeURIComponent(run.run_id) + "/recover",
      { expected_revision: run.revision }, "finish the interrupted action");
    say("The interrupted action was finished.", body);
    await loadRuns();
  }
  async function withdraw(run) {
    var choice = await askReason("Withdraw this review", "Withdraw");
    if (!choice || !choice.reason) return;
    var body = await request("POST", "/runs/" + encodeURIComponent(run.run_id) + "/revoke",
      { expected_revision: run.revision, reason_code: choice.reason }, "withdraw the review");
    say("The review was withdrawn.", body);
    await loadRuns();
  }

  // ---- start a review ------------------------------------------------------
  function option(select, value, label) {
    var o = el("option", null, label);
    o.value = value;
    select.appendChild(o);
  }
  function fillCapabilities() {
    var policy = policies[Number(document.getElementById("ga-start-policy").value)];
    var select = document.getElementById("ga-start-capability");
    select.textContent = "";
    (policy && Array.isArray(policy.allowed_capabilities) ? policy.allowed_capabilities : []).forEach(function (cap) {
      option(select, cap, human(cap));
    });
  }
  async function openStart(kind) {
    starting = kind;
    if (!policies.length) await loadPolicies();
    document.getElementById("ga-start-agent").textContent = AGENTS[kind] || human(kind);
    var select = document.getElementById("ga-start-policy");
    select.textContent = "";
    var usable = 0;
    policies.forEach(function (policy, index) {
      if (policy.agent_kind === kind && !policy.revoked && Number(policy.valid_until) * 1000 > Date.now()) {
        option(select, String(index), human(policy.policy_id));
        usable += 1;
      }
    });
    if (!usable) option(select, "", "No policy for this assistant yet — ask an administrator");
    fillCapabilities();
    var sources = document.getElementById("ga-start-sources");
    Array.prototype.slice.call(sources.querySelectorAll("label, p")).forEach(function (node) { node.remove(); });
    preview = null;
    try {
      preview = await request("GET", "/preview/" + encodeURIComponent(kind), undefined, "list the records the assistant can read",
        API + "/context");
    } catch (error) {
      sources.appendChild(el("p", "muted", error.message));
    }
    var refs = preview && Array.isArray(preview.references) ? preview.references : [];
    var kinds = {};
    refs.forEach(function (ref) { kinds[ref.source_kind] = (kinds[ref.source_kind] || 0) + 1; });
    Object.keys(kinds).sort().forEach(function (sourceKind) {
      var label = el("label");
      var box = el("input");
      box.type = "checkbox"; box.name = "source_kind"; box.value = sourceKind; box.checked = true;
      label.appendChild(box);
      label.appendChild(document.createTextNode(" " + human(sourceKind) + " (" + kinds[sourceKind] + ")"));
      sources.appendChild(label);
    });
    if (preview && !refs.length) sources.appendChild(el("p", "muted", "There are no records for this assistant to read yet."));
    if (preview && preview.complete === false) sources.appendChild(el("p", "muted", "Some sources couldn't be read right now, so this list may be incomplete. Refresh the page and try again."));
    document.getElementById("ga-start-panel").hidden = false;
    var heading = document.getElementById("ga-start-title");
    if (heading && heading.focus) heading.focus();
  }
  async function submitStart(form) {
    var policy = policies[Number(document.getElementById("ga-start-policy").value)];
    if (!policy || document.getElementById("ga-start-policy").value === "") throw new Error("Choose a policy first.");
    var capability = document.getElementById("ga-start-capability").value;
    if (!capability) throw new Error("Choose what the assistant should prepare.");
    var chosen = Array.prototype.slice.call(form.querySelectorAll('input[name="source_kind"]:checked')).map(function (box) { return box.value; });
    var refs = (preview && Array.isArray(preview.references) ? preview.references : []).filter(function (ref) {
      return chosen.indexOf(ref.source_kind) >= 0;
    }).map(function (ref) {
      return { item_id: ref.item_id, source_kind: ref.source_kind, source_ref: ref.source_ref, source_revision: ref.source_revision };
    });
    if (!refs.length) throw new Error("Choose at least one kind of record for the assistant to read.");
    var runId = reference("run");
    var body = await request("PUT", "/runs/" + encodeURIComponent(runId) + "/analysis", {
      policy_id: policy.policy_id,
      policy_revision: policy.revision,
      capability: capability,
      context: refs.slice(0, 1000),
      idempotency_key: form.elements.namedItem("idempotency_key").value || reference("analysis")
    }, "start the review");
    form.elements.namedItem("idempotency_key").value = reference("analysis");
    document.getElementById("ga-start-panel").hidden = true;
    say("The review is ready and waiting for approval.", body);
    await loadRuns();
  }

  // ---- maintenance ---------------------------------------------------------
  var MAINT = {
    "maintenance-readiness": ["GET", function () { return "/maintenance/readiness"; }, null, "Readiness check finished."],
    "custody-rotate": ["POST", function () { return "/maintenance/custody/rotate"; }, "Replace the recovery key used to finish interrupted actions?", "The recovery key was replaced."],
    "token-reconcile": ["POST", function () { return "/maintenance/tokens/reconcile"; }, null, "Unused action permissions were tidied up."],
    "retention-purge": ["POST", function () { return "/retention/purge"; }, "Permanently delete finished reviews whose keep date has passed? This can't be undone.", "Old reviews were deleted."],
    "adapter-rotate": ["POST", function (kind) { return "/maintenance/adapters/" + kind + "/rotate"; }, "Refresh the analysis engine for this assistant?", "The analysis engine was refreshed."],
    "adapter-revoke": ["POST", function (kind) { return "/maintenance/adapters/" + kind + "/revoke"; }, "Switch off the analysis engine for this assistant? It can't prepare reviews until it is refreshed.", "The analysis engine was switched off."],
    "dispatcher-rotate": ["POST", function (kind) { return "/maintenance/dispatchers/" + kind + "/rotate"; }, "Refresh how this assistant carries out approved actions?", "It was refreshed."],
    "dispatcher-revoke": ["POST", function (kind) { return "/maintenance/dispatchers/" + kind + "/revoke"; }, "Stop this assistant carrying out approved actions?", "Carrying out actions was switched off for this assistant."],
    "integrity": ["GET", function () { return "/integrity"; }, null, "All review records are intact and unaltered."],
    "intent-list": ["GET", function () { return "/maintenance/intents?limit=1000"; }, null, null]
  };
  async function maintenance(op) {
    var spec = MAINT[op];
    var kind = (document.getElementById("ga-maint-kind") || {}).value || "";
    if (spec[2] && !(await ask(spec[2] + (kind && /\/(adapters|dispatchers)\//.test(spec[1](kind)) ? " (" + (AGENTS[kind] || kind) + ")" : ""), "Continue"))) return;
    var body = await request(spec[0], spec[1](encodeURIComponent(kind)), spec[0] === "GET" ? undefined : {}, "finish the maintenance task");
    if (op === "intent-list") {
      var count = Array.isArray(body.items) ? body.items.length : 0;
      say(count ? count + " internal " + (count === 1 ? "action is" : "actions are") + " pending." : "No internal actions are pending.", body);
      return;
    }
    say(spec[3], body);
    if (op === "retention-purge") await loadRuns();
  }

  // ---- wiring --------------------------------------------------------------
  Array.prototype.forEach.call(document.querySelectorAll("[data-start]"), function (node) {
    node.addEventListener("click", function () { openStart(node.dataset.start).catch(failed); });
  });
  Array.prototype.forEach.call(document.querySelectorAll("[data-show]"), function (node) {
    node.addEventListener("click", function () {
      document.getElementById("ga-runs-filter").value = node.dataset.show;
      renderRuns();
      var heading = document.getElementById("ga-runs-title");
      if (heading && heading.scrollIntoView) heading.scrollIntoView({ block: "start" });
    });
  });
  Object.keys(MAINT).forEach(function (op) {
    var node = document.querySelector('button[data-op="' + op + '"]');
    if (!node) return;
    node.addEventListener("click", function () {
      if (node.disabled) return;
      node.disabled = true;
      maintenance(op).catch(failed).then(function () { node.disabled = !ready(op); });
    });
  });
  document.getElementById("ga-runs-filter").addEventListener("change", renderRuns);
  document.getElementById("ga-start-policy").addEventListener("change", fillCapabilities);
  document.getElementById("ga-start-cancel").addEventListener("click", function () {
    document.getElementById("ga-start-panel").hidden = true;
  });
  document.getElementById("ga-start-form").addEventListener("submit", function (event) {
    event.preventDefault();
    var submit = event.currentTarget.querySelector("button[type=submit]");
    submit.disabled = true;
    submitStart(event.currentTarget).catch(failed).then(function () { submit.disabled = false; });
  });
  document.getElementById("ga-load-status").addEventListener("click", function () {
    loadStatus().then(loadPolicies).then(loadRuns);
  });

  loadStatus().then(function () {
    if (!ready("run-list")) {
      emptyRow(document.getElementById("ga-runs"), 6, "Reviews can't be shown until setup is finished. Ask your administrator to set it up.");
      emptyRow(document.getElementById("ga-policies"), 6, "Policies can't be shown until setup is finished. Ask your administrator to set it up.");
      return undefined;
    }
    return loadPolicies().then(loadRuns);
  });
})();
