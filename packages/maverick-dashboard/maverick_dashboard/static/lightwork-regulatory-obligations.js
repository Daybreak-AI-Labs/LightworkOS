(function () {
  "use strict";

  var root = document.getElementById("rob-root");
  if (!root) { return; }
  var apiBase = root.dataset.apiBase || "/api/v1/regulatory";
  var canAdmin = root.dataset.canAdmin === "true";
  var feedBase = "/api/v1/security/assurance/ai-regulatory-feed";
  var maxResponseBytes = 2 * 1024 * 1024;
  var state = document.getElementById("rob-state");
  var operationState = document.getElementById("rob-operation-state");
  var rows = document.getElementById("rob-rows");
  var library = document.getElementById("rob-library");
  var problemList = document.getElementById("rob-problem-list");
  var gatewayPreviewState = document.getElementById("rob-gateway-preview-state");
  var actionSelect = document.getElementById("rob-action");
  var actionFilter = document.getElementById("rob-action-filter");
  var current = null;
  var allTools = [];

  // Plain names for the regulations and the effects a rule can have.
  var REGULATION_NAMES = {
    gdpr: "GDPR (EU data protection)",
    eu_ai_act: "EU AI Act",
    hipaa: "HIPAA (US health information)",
    nist_ai_rmf: "NIST AI Risk Management Framework",
    iso_42001: "ISO/IEC 42001 (AI management)",
    soc2: "SOC 2",
    sr_11_7: "US banking model-risk guidance (SR 26-2)"
  };
  var EFFECTS = { deny: "Blocks it", require_human: "Needs approval", attenuate: "Turns it off", allow: "Allows it" };
  var DECISIONS = { allow: "Allowed", require_human: "Needs human approval", deny: "Blocked" };
  var RISK = { 0: "Low", 1: "Low", 2: "Medium", 3: "High", 4: "Critical" };

  function human(value) {
    return window.mvHuman ? window.mvHuman(value) : String(value || "").replace(/_/g, " ");
  }
  function regulationName(key, fallback) { return REGULATION_NAMES[key] || fallback || human(key); }
  function errorText(failure, action) {
    return window.mvErrorText ? window.mvErrorText(failure, action) : "Could not " + action + ". Try again.";
  }
  function say(text) { window.mvStatus(operationState, text); }

  async function readJson(response) {
    if (!response.ok) { throw response; }
    var declared = Number(response.headers.get("content-length") || 0);
    if (declared > maxResponseBytes) {
      if (response.body && typeof response.body.cancel === "function") { await response.body.cancel(); }
      throw new Error("too large");
    }
    var text = await response.text();
    if (text.length > maxResponseBytes) { throw new Error("too large"); }
    return text ? JSON.parse(text) : {};
  }

  async function request(url, options) {
    var settings = Object.assign({ credentials: "same-origin", headers: { Accept: "application/json" } }, options || {});
    if (settings.body) { settings.headers["Content-Type"] = "application/json"; }
    return readJson(await fetch(url, settings));
  }
  function api(path, options) { return request(apiBase + path, options); }

  function cell(text) {
    var td = document.createElement("td");
    td.textContent = text;
    return td;
  }

  function scopeOf(ob) {
    var parts = [];
    if (ob.actions && ob.actions.length) { parts.push(ob.actions.map(human).join(", ")); }
    if (ob.deny_tools && ob.deny_tools.length) { parts.push("Turns off: " + ob.deny_tools.map(human).join(", ")); }
    if (ob.min_risk) { parts.push("Any action rated " + (RISK[ob.min_risk] || human(ob.min_risk)).toLowerCase() + " risk or above"); }
    return parts.join(" · ") || "All actions";
  }

  function renderObligations(items, note) {
    rows.textContent = "";
    document.getElementById("rob-obligations-note").textContent = note;
    if (!items.length) {
      var empty = document.createElement("tr");
      var td = cell("No rules are in force. Turn on a regulation above to add its rules.");
      td.colSpan = 6;
      empty.appendChild(td);
      rows.appendChild(empty);
      return;
    }
    items.forEach(function (ob) {
      var tr = document.createElement("tr");
      tr.appendChild(cell(ob.regulation));
      tr.appendChild(cell(ob.article));
      tr.appendChild(cell(ob.title || "Rule"));
      var effectCell = document.createElement("td");
      var chip = document.createElement("span");
      chip.className = "badge " + (ob.effect === "deny" ? "blocked" : ob.effect === "require_human" ? "warn" : "info");
      chip.textContent = EFFECTS[ob.effect] || human(ob.effect);
      effectCell.appendChild(chip);
      tr.appendChild(effectCell);
      tr.appendChild(cell(scopeOf(ob)));
      var source = document.createElement("td");
      if (ob.source_url && /^https:\/\//.test(ob.source_url)) {
        var link = document.createElement("a");
        link.href = ob.source_url;
        link.rel = "noopener noreferrer";
        link.target = "_blank";
        link.textContent = "Read the law";
        source.appendChild(link);
      } else {
        source.textContent = "Not linked";
      }
      tr.appendChild(source);
      rows.appendChild(tr);
    });
  }

  function renderLibrary(items) {
    library.textContent = "";
    items.forEach(function (entry) {
      var li = document.createElement("li");
      var label = document.createElement("span");
      var name = document.createElement("strong");
      name.textContent = regulationName(entry.key, entry.regulation);
      label.appendChild(name);
      label.appendChild(document.createTextNode(" · " + entry.obligations + " rule" + (entry.obligations === 1 ? "" : "s") + " "));
      var badge = document.createElement("span");
      badge.className = "badge " + (entry.active ? "active" : "idle");
      badge.textContent = entry.active ? "On" : "Off";
      label.appendChild(badge);
      li.appendChild(label);
      var buttons = document.createElement("span");
      buttons.className = "rob-row";
      var see = document.createElement("button");
      see.type = "button";
      see.className = "btn btn--ghost";
      see.textContent = "See rules";
      see.addEventListener("click", function () {
        inspect(entry).catch(function (e) { say(errorText(e, "load its rules")); });
      });
      buttons.appendChild(see);
      if (canAdmin && !entry.active) {
        var on = document.createElement("button");
        on.type = "button";
        on.className = "btn btn--primary";
        on.textContent = "Turn on";
        on.addEventListener("click", function () { activate(entry, on); });
        buttons.appendChild(on);
      }
      li.appendChild(buttons);
      library.appendChild(li);
    });
  }

  async function activate(entry, button) {
    var ok = window.mvConfirm ? await window.mvConfirm(
      "Turn on " + regulationName(entry.key, entry.regulation) + "? Its " + entry.obligations +
      " rule(s) will start blocking or pausing the actions they cover right away.", { okText: "Turn on" }) : false;
    if (!ok) { return; }
    button.disabled = true;
    try {
      var result = await api("/profiles/" + encodeURIComponent(entry.key) + "/activate", { method: "POST", body: "{}" });
      say(result.message || "Turned on.");
      await loadStatus();
    } catch (e) {
      say(e && e.status === 409
        ? "Set up sign-in for Lightwork first. Once a regulation is on, everyone must sign in."
        : errorText(e, "turn the regulation on"));
      button.disabled = false;
    }
  }

  function renderProblems(verification) {
    problemList.textContent = "";
    var problems = (verification && verification.problems) || [];
    problemList.hidden = !problems.length;
    problems.forEach(function (problem) {
      var li = document.createElement("li");
      li.textContent = problem;
      problemList.appendChild(li);
    });
  }

  function setMark(kind, text) {
    state.className = "badge " + kind;
    state.textContent = text;
  }

  async function loadStatus() {
    var st = await api("/status");
    current = st;
    var names = st.active_profiles.map(function (k) { return regulationName(k); });
    document.getElementById("rob-active").textContent = String(st.active_profiles.length);
    document.getElementById("rob-count").textContent = String(st.obligations.length);
    document.getElementById("rob-problems").textContent = String(st.verification.problems.length);
    var title = document.getElementById("rob-health-title");
    var detail = document.getElementById("rob-health-detail");
    if (!st.active_profiles.length) {
      setMark("idle", "No regulations on");
      title.textContent = "No regulation is turned on";
      detail.textContent = canAdmin ? "Turn one on in the list below." : "Ask an administrator to turn on the regulations you follow.";
    } else if (st.verification.sound) {
      setMark("ok", "All rules working");
      title.textContent = names.join(", ") + " on and checked";
      detail.textContent = st.verification.inspected + " rule(s) tested; each one really blocks or pauses what it covers.";
    } else {
      setMark("blocked", "A rule is not working");
      title.textContent = "A rule is not enforcing what it should";
      detail.textContent = st.verification.problems.length + " problem(s) found. Tell whoever installed Lightwork before relying on these rules.";
    }
    renderObligations(st.obligations, st.active_profiles.length ? "Rules from " + names.join(", ") : "Nothing is on");
    renderLibrary(st.library);
    renderProblems(st.verification);
    return st;
  }

  function fillActions() {
    var term = (actionFilter.value || "").trim().toLowerCase();
    var chosen = actionSelect.value;
    actionSelect.textContent = "";
    var first = document.createElement("option");
    first.value = "";
    var matches = allTools.filter(function (name) {
      return !term || name.toLowerCase().indexOf(term) >= 0 || human(name).toLowerCase().indexOf(term) >= 0;
    });
    first.textContent = matches.length ? "Choose an action" : "No actions match";
    actionSelect.appendChild(first);
    matches.forEach(function (name) {
      var option = document.createElement("option");
      option.value = name;
      option.textContent = human(name);
      actionSelect.appendChild(option);
    });
    if (matches.indexOf(chosen) >= 0) { actionSelect.value = chosen; }
  }

  async function loadTools() {
    var payload = await api("/tools");
    allTools = (payload.items || []).slice().sort(function (a, b) { return human(a).localeCompare(human(b)); });
    fillActions();
  }

  async function inspect(entry) {
    var payload = await api("/profiles/" + encodeURIComponent(entry.key));
    renderObligations(payload.obligations, (payload.active ? "On: " : "Preview (not on): ") + regulationName(entry.key, entry.regulation));
    renderProblems(payload.verification);
    document.getElementById("rob-rules-title").scrollIntoView({ block: "start" });
  }

  async function check(action, scope) {
    var body = { action: action };
    if (scope === "all" && current) { body.profiles = current.library.map(function (e) { return e.key; }); }
    var result = await api("/check", { method: "POST", body: JSON.stringify(body) });
    var box = document.getElementById("rob-verdict-box");
    var verdict = document.getElementById("rob-verdict");
    var detail = document.getElementById("rob-verdict-detail");
    box.hidden = false;
    verdict.dataset.decision = result.decision;
    verdict.textContent = human(result.action) + ": " + (DECISIONS[result.decision] || human(result.decision));
    var parts = [];
    if (!result.classified) { parts.push("This action has no risk rating, so only rules that name it directly apply."); }
    else { parts.push("Risk level: " + (RISK[result.risk] || human(result.risk)) + "."); }
    if (result.obligation) { parts.push("Decided by " + result.obligation.regulation + " " + result.obligation.article + "."); }
    if (result.attenuated) { parts.push("A regulation switches this action off completely."); }
    if (!result.obligation && !result.attenuated) { parts.push("No regulation rule covers it; your other safety settings decide."); }
    detail.textContent = parts.join(" ");
  }

  // Regulatory updates (notices and evidence to refresh).
  var updates = document.getElementById("rob-updates");
  function updatesMessage(text) {
    updates.textContent = "";
    var p = document.createElement("p"); p.className = "muted"; p.textContent = text;
    updates.appendChild(p);
  }
  async function loadUpdates() {
    var notices, stale;
    try {
      notices = (await request(feedBase + "/notices")).notices || [];
      stale = (await request(feedBase + "/staleness")).staleness || [];
    } catch (e) {
      if (e && (e.status === 403 || e.status === 503 || e.status === 404)) {
        updatesMessage("Regulatory updates are not turned on for this workspace.");
      } else if (e && e.status === 409) {
        updatesMessage("Choose a workspace to see its regulatory updates.");
      } else {
        updatesMessage(errorText(e, "load regulatory updates"));
      }
      return;
    }
    updates.textContent = "";
    if (!notices.length && !stale.length) { updatesMessage("Nothing needs your attention."); return; }
    function table(headers, list, render) {
      var t = document.createElement("table");
      var head = document.createElement("tr");
      headers.forEach(function (h) { var th = document.createElement("th"); th.scope = "col"; th.textContent = h; head.appendChild(th); });
      var thead = document.createElement("thead"); thead.appendChild(head); t.appendChild(thead);
      var tbody = document.createElement("tbody");
      list.forEach(function (row) { tbody.appendChild(render(row)); });
      t.appendChild(tbody);
      return t;
    }
    if (notices.length) {
      var h = document.createElement("h3"); h.textContent = "Customer notices"; updates.appendChild(h);
      updates.appendChild(table(["Notice", "Status", ""], notices, function (n) {
        var tr = document.createElement("tr");
        tr.appendChild(cell(n.title || "Notice"));
        tr.appendChild(cell(human(n.status || "")));
        var td = document.createElement("td");
        if (canAdmin && n.status !== "delivered") {
          var b = document.createElement("button"); b.type = "button"; b.className = "btn btn--ghost"; b.textContent = "Send notice";
          b.addEventListener("click", async function () {
            var ok = window.mvConfirm ? await window.mvConfirm("Send “" + (n.title || "this notice") + "” to your customers now?", { okText: "Send" }) : false;
            if (!ok) { return; }
            try {
              await request(feedBase + "/notices/" + encodeURIComponent(n.id) + "/deliver", { method: "POST", body: JSON.stringify({ expected_revision: n.revision }) });
              say("Notice sent."); loadUpdates();
            } catch (e) { say(errorText(e, "send the notice")); }
          });
          td.appendChild(b);
        }
        tr.appendChild(td);
        return tr;
      }));
    }
    if (stale.length) {
      var h2 = document.createElement("h3"); h2.textContent = "Evidence to refresh"; updates.appendChild(h2);
      updates.appendChild(table(["Evidence", "Control", "Flagged", ""], stale, function (s) {
        var tr = document.createElement("tr");
        tr.appendChild(cell(human(s.evidence_id || "Evidence")));
        tr.appendChild(cell(human(s.control_id || "")));
        tr.appendChild(cell(window.mvWhen ? window.mvWhen(s.created_at) : ""));
        var td = document.createElement("td");
        if (canAdmin) {
          var b = document.createElement("button"); b.type = "button"; b.className = "btn btn--ghost"; b.textContent = "Mark refreshed";
          b.addEventListener("click", async function () {
            var values = window.mvForm ? await window.mvForm("Mark evidence refreshed", [
              { key: "resolution", label: "What did you refresh or re-check?", type: "text", required: true }
            ], { okText: "Save" }) : null;
            if (!values) { return; }
            try {
              await request(feedBase + "/staleness/" + encodeURIComponent(s.id) + "/resolve", {
                method: "POST", body: JSON.stringify({ expected_revision: s.revision, resolution: values.resolution })
              });
              say("Marked as refreshed."); loadUpdates();
            } catch (e) { say(errorText(e, "save that")); }
          });
          td.appendChild(b);
        }
        tr.appendChild(td);
        return tr;
      }));
    }
  }

  async function previewGatewayConstraints(file) {
    if (!current || !current.active_profiles.length) {
      gatewayPreviewState.textContent = "Turn on at least one regulation first.";
      return;
    }
    if (!file) { gatewayPreviewState.textContent = "Choose the gateway's rules file first."; return; }
    if (file.size > 131072) { gatewayPreviewState.textContent = "That file is too large. Choose a smaller rules file."; return; }
    var parsed;
    try { parsed = JSON.parse(await file.text()); } catch (_e) { parsed = null; }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      gatewayPreviewState.textContent = "That file is not a gateway rules file.";
      return;
    }
    var result;
    try {
      result = await api("/gateway-constraints/preview", {
        method: "POST",
        body: JSON.stringify({ document: parsed, profiles: current.active_profiles })
      });
    } catch (e) {
      gatewayPreviewState.textContent = e && e.status === 422
        ? "Lightwork could not read that file as gateway rules. Choose the file again, or try a different file."
        : errorText(e, "preview the file");
      return;
    }
    gatewayPreviewState.textContent = result.complete
      ? "Every gateway rule matched an action. Nothing has been changed."
      : "Some gateway rules name actions Lightwork does not know. Check them with your gateway provider.";
    var out = document.getElementById("rob-gateway-result");
    out.textContent = "";
    var changed = (result.verdicts || []).filter(function (v) { return v.effective_decision !== v.compiler_decision; });
    var p = document.createElement("p");
    p.textContent = changed.length
      ? changed.length + " action(s) would become stricter: " + changed.map(function (v) {
        return human(v.action) + " (" + (DECISIONS[v.effective_decision] || human(v.effective_decision)) + ")";
      }).join(", ") + "."
      : "No action would change.";
    out.appendChild(p);
  }

  async function refresh() {
    await loadStatus();
    await loadTools();
  }

  document.getElementById("rob-refresh").addEventListener("click", function () {
    refresh().then(function () { say("Up to date."); }).catch(function (e) { say(errorText(e, "refresh")); });
  });
  actionFilter.addEventListener("input", fillActions);

  document.getElementById("rob-check-form").addEventListener("submit", function (event) {
    event.preventDefault();
    var action = actionSelect.value;
    if (!action) { say("Choose an action to test."); actionSelect.focus(); return; }
    check(action, document.getElementById("rob-scope").value).catch(function (e) { say(errorText(e, "test the action")); });
  });

  document.getElementById("rob-gateway-preview-form").addEventListener("submit", function (event) {
    event.preventDefault();
    var input = document.getElementById("rob-gateway-file");
    previewGatewayConstraints(input.files && input.files[0]).catch(function (e) {
      gatewayPreviewState.textContent = errorText(e, "preview the file");
    });
  });

  refresh().catch(function (error) {
    setMark("blocked", "Unavailable");
    document.getElementById("rob-health-title").textContent = "Regulations could not be loaded";
    say(errorText(error, "load your regulations") + " Use Refresh to try again.");
  });
  loadUpdates();
})();
