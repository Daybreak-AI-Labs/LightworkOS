(function () {
  "use strict";

  var ATTACK = {
    T1078: "Using stolen or valid accounts", T1098: "Changing accounts to keep access",
    "T1098.001": "Adding extra cloud keys", T1548: "Gaining higher permissions",
    T1041: "Sending data out over an existing connection", T1567: "Sending data to a web service",
    T1110: "Guessing passwords", T1059: "Running commands or scripts", T1190: "Attacking a public app",
    T1486: "Encrypting data for ransom", T1562: "Switching off defences", T1021: "Remote access",
    T1003: "Stealing passwords from a computer", T1136: "Creating new accounts", T1071: "Hidden network traffic",
    T1530: "Taking data from cloud storage", T1552: "Finding stored passwords or keys",
    T1204: "Tricking a user into running something", T1566: "Phishing", T1537: "Moving data to another cloud account",
    T1485: "Deleting data", T1496: "Using resources for someone else", T1068: "Exploiting a flaw to gain access",
    T1087: "Listing accounts", T1069: "Listing groups and permissions", T1580: "Looking around a cloud account",
    T1199: "Coming in through a trusted partner", T1133: "Using remote access services"
  };
  var SEVERITY = { low: "Low", medium: "Medium", high: "High", critical: "Critical", info: "Information" };
  var STATUS = { open: "New", triaged: "Reviewed", investigating: "Being looked into", resolved: "Resolved",
    false_positive: "Not a problem", closed: "Closed", contained: "Contained" };
  var INV_STATUSES = ["open", "triaged", "investigating", "contained", "resolved", "closed"];
  var CONTAINMENT = [
    "Pause the assistant", "Remove the assistant's tool access", "Block data from leaving",
    "Replace the account's passwords and keys", "Require approval for this kind of action"
  ];
  var CUSTOM_KEY = "lw-soc-custom-checks";

  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    if (text !== undefined && text !== null) { e.textContent = String(text); }
    return e;
  }
  function human(v) { return window.mvHuman ? window.mvHuman(v) : String(v || ""); }
  function attackName(id) {
    var key = String(id || "").toUpperCase();
    var name = ATTACK[key] || ATTACK[key.split(".")[0]];
    return name ? name + " (" + key + ")" : key;
  }
  function plural(n, one, many) { return n + " " + (n === 1 ? one : many); }
  function when(ts) { return window.mvWhen ? window.mvWhen(ts) : ""; }
  function say(text) { window.mvStatus($("hunt-status"), text); }
  function fail(text) {
    var e = $("hunt-error");
    if (e) { e.textContent = text; }
    if (window.mvToast) { window.mvToast(text, { error: true }); }
  }
  function clear(node) { while (node && node.firstChild) { node.removeChild(node.firstChild); } }
  function button(label, cls, fn) {
    var b = el("button", "btn " + (cls || "btn--ghost"), label);
    b.type = "button";
    b.addEventListener("click", function () { b.disabled = true; Promise.resolve(fn()).finally(function () { b.disabled = false; }); });
    return b;
  }

  async function call(method, url, body, action, plainByStatus) {
    var data;
    try { data = await window.mvFetchJSON(url, { method: method, body: body || undefined }, action); }
    catch (error) {
      fail((plainByStatus && plainByStatus[error.status]) || error.message);
      return null;
    }
    var e2 = $("hunt-error");
    if (e2) { e2.textContent = ""; }
    return data || {};
  }

  // Turning a hunter on (shown when it is off).
  var turnOn = $("hunt-turn-on");
  if (turnOn) {
    turnOn.addEventListener("click", async function () {
      var ok = await window.mvConfirm("Turn this on? Lightwork starts reading activity to look for threats. It never changes anything.", { okText: "Turn on" });
      if (!ok) { return; }
      turnOn.disabled = true;
      try {
        await window.mvFetchJSON("/api/v1/features/switches", { method: "POST", body: { section: turnOn.dataset.section, enabled: true } }, "turn this on");
        location.reload();
      } catch (error) { $("hunt-turn-on-msg").textContent = error.message; turnOn.disabled = false; }
    });
  }

  var root = $("hunt-root");
  if (!root) { return; }
  var api = root.dataset.api;
  var kind = root.dataset.hunt;
  var people = [];
  try { people = JSON.parse(($("hunt-people") || {}).textContent || "[]") || []; } catch (e) { people = []; }
  var summary = null;

  function personLabel(value) {
    var hit = people.filter(function (p) { return p.value === value; })[0];
    return hit ? hit.label : (value ? String(value).replace(/^user:/, "") : "—");
  }
  function confidenceText(f) {
    var v = f.confidence !== undefined && f.confidence !== null ? Number(f.confidence) : Number(f.score) / 100;
    if (!isFinite(v)) { return "—"; }
    return v >= 0.8 ? "Very sure" : v >= 0.5 ? "Fairly sure" : "Not very sure";
  }
  function evidenceCell(f) {
    var list = f.evidence || [];
    var d = el("details");
    d.appendChild(el("summary", null, plural(list.length, "event", "events")));
    var ul = el("ul");
    list.slice(0, 20).forEach(function (e) {
      var text = (when(e.observed_at) ? when(e.observed_at) + ": " : "") + (e.quote || human(e.source) + " event");
      ul.appendChild(el("li", null, text));
    });
    d.appendChild(ul);
    return d;
  }

  async function setFindingStatus(f, status) {
    var out = await call("PATCH", api + "/findings/" + encodeURIComponent(f.finding_id), { changes: { status: status }, expected_revision: Number(f.revision || 1) },
      "update the finding", { 409: "Someone else changed this finding. Refreshed to show the latest." });
    if (out) { say("Finding marked " + (STATUS[status] || human(status)).toLowerCase() + "."); }
    await load(true);
  }

  function renderFindings() {
    var body = $("hunt-findings");
    clear(body);
    var list = (summary && summary.findings) || [];
    var cols = kind === "platform" ? 8 : 7;
    if (!list.length) {
      var tr = el("tr");
      var td = el("td", "muted", kind === "platform" ? "Nothing suspicious found. Run a check to look again." : "Nothing suspicious found yet. Look for threats above.");
      td.colSpan = cols;
      tr.appendChild(td);
      body.appendChild(tr);
      return;
    }
    list.forEach(function (f) {
      var tr = el("tr");
      if (kind === "platform") {
        var pick = el("td");
        var box = el("input");
        box.type = "checkbox"; box.className = "hunt-pick"; box.value = f.finding_id;
        box.setAttribute("aria-label", "Choose " + (f.title || "finding"));
        pick.appendChild(box);
        tr.appendChild(pick);
      }
      tr.appendChild(el("td", null, SEVERITY[f.severity] || human(f.severity)));
      tr.appendChild(el("td", null, f.title || "Finding"));
      tr.appendChild(el("td", null, (f.mitre_techniques || []).map(attackName).join("; ") || "—"));
      tr.appendChild(el("td", null, confidenceText(f)));
      var ev = el("td"); ev.appendChild(evidenceCell(f)); tr.appendChild(ev);
      tr.appendChild(el("td", null, STATUS[f.status] || human(f.status)));
      var act = el("td");
      var wrap = el("div", "hunt-actions");
      if (f.status !== "triaged") { wrap.appendChild(button("Mark reviewed", "btn--ghost", function () { return setFindingStatus(f, "triaged"); })); }
      if (f.status !== "false_positive") { wrap.appendChild(button("Not a problem", "btn--ghost", function () { return setFindingStatus(f, "false_positive"); })); }
      if (f.status !== "resolved") { wrap.appendChild(button("Resolved", "btn--ghost", function () { return setFindingStatus(f, "resolved"); })); }
      act.appendChild(wrap);
      tr.appendChild(act);
      body.appendChild(tr);
    });
  }

  function showDetail(inv) {
    var box = $("hunt-detail");
    clear(box);
    var panel = el("div", "panel");
    panel.appendChild(el("h3", null, inv.title || "Investigation"));
    if (inv.summary) { panel.appendChild(el("p", null, inv.summary)); }
    var items = inv.timeline || inv.evidence || [];
    if (!items.length) {
      panel.appendChild(el("p", "muted", "No events recorded for this investigation yet. Events appear here as the investigation finds them."));
    } else {
      var ol = el("ol");
      items.slice(0, 100).forEach(function (t) {
        var text = (when(t.observed_at || t.at || t.ts) ? when(t.observed_at || t.at || t.ts) + ": " : "") +
          (t.quote || t.summary || t.description || (t.action ? human(t.action) : "") || human(t.source) || "Event");
        ol.appendChild(el("li", null, text));
      });
      panel.appendChild(ol);
    }
    panel.appendChild(button("Close", "btn--ghost", function () { clear(box); }));
    box.appendChild(panel);
    panel.scrollIntoView && panel.scrollIntoView({ block: "nearest" });
  }

  async function updateInvestigation(inv, changes, done) {
    var out = await call("PATCH", api + "/investigations/" + encodeURIComponent(inv.investigation_id), { changes: changes, expected_revision: Number(inv.revision || 1) },
      "update the investigation", { 409: "Someone else changed this investigation. Refreshed to show the latest." });
    if (out) { say(done); }
    await load(true);
  }

  async function changeStatus(inv) {
    var values = await window.mvForm("Change status", [
      { key: "status", label: "Status", type: "select", default: inv.status,
        options: INV_STATUSES.map(function (s) { return { value: s, label: STATUS[s] || human(s) }; }) }
    ], { okText: "Save" });
    if (!values || values.status === inv.status) { return; }
    await updateInvestigation(inv, { status: values.status }, "Status changed.");
  }

  async function assign(inv) {
    if (!people.length) { fail("There is nobody to assign yet. Invite people on the Users page."); return; }
    var values = await window.mvForm("Assign the investigation", [
      { key: "assignee", label: "Person", type: "select", default: inv.assignee || people[0].value, options: people }
    ], { okText: "Assign" });
    if (!values) { return; }
    await updateInvestigation(inv, { assignee: values.assignee }, "Assigned to " + personLabel(values.assignee) + ".");
  }

  async function proposeContainment(inv) {
    var suggestions = CONTAINMENT.slice();
    ((summary && summary.findings) || []).forEach(function (f) {
      if ((inv.finding_ids || []).indexOf(f.finding_id) >= 0 && f.suggested_containment && suggestions.indexOf(f.suggested_containment) < 0) {
        suggestions.unshift(f.suggested_containment);
      }
    });
    var values = await window.mvForm("Propose containment", [
      { key: "action", label: "What should happen", type: "select", default: suggestions[0],
        options: suggestions.map(function (s) { return { value: s, label: s }; }) },
      { key: "scope", label: "Which assistant, account or system", required: true, default: inv.title || "",
        help: "Name it the way your team would recognise it." },
      { key: "reason", label: "Why", required: true, default: inv.summary || "" }
    ], { okText: "Send for approval" });
    if (!values) { return; }
    var ok = await window.mvConfirm("Send this containment to the approvals queue? Nothing happens until a person approves it.", { okText: "Send for approval" });
    if (!ok) { return; }
    var out = await call("POST", api + "/investigations/" + encodeURIComponent(inv.investigation_id) + "/containment",
      { action: values.action, scope: values.scope, reason: values.reason, expected_revision: Number(inv.revision || 1) },
      "send the containment for approval", { 409: "Someone else changed this investigation. Refreshed to show the latest." });
    if (out) { say(out.approval_queued ? "Sent to the approvals queue." : "Saved, but the approvals queue is not available right now. Try again later."); }
    await load(true);
  }

  function approvalLink(id) {
    var a = el("a", "btn btn--primary", "Decide in the approvals queue");
    a.href = "/approvals#approval-" + encodeURIComponent(id);
    return a;
  }

  function renderInvestigations() {
    var body = $("hunt-investigations-rows");
    clear(body);
    var list = (summary && summary.investigations) || [];
    if (!list.length) {
      var tr = el("tr");
      var td = el("td", "muted", kind === "platform" ? "No investigations yet. Choose findings above and start one." : "No investigations yet. They appear when related findings are grouped together.");
      td.colSpan = 6;
      tr.appendChild(td);
      body.appendChild(tr);
      return;
    }
    list.forEach(function (inv) {
      var tr = el("tr");
      tr.appendChild(el("td", null, inv.title || "Investigation"));
      tr.appendChild(el("td", null, STATUS[inv.status] || human(inv.status)));
      tr.appendChild(el("td", null, inv.assignee ? personLabel(inv.assignee) : "Nobody yet"));
      if (kind === "platform") {
        tr.appendChild(el("td", null, plural((inv.finding_ids || []).length, "finding", "findings")));
      } else {
        tr.appendChild(el("td", null, plural((inv.timeline || []).length, "event", "events")));
      }
      var plan = kind === "platform" ? inv.containment : inv.response_proposal;
      var resp = el("td");
      if (plan) {
        resp.appendChild(el("div", null, plan.action ? human(plan.action) : "Proposed"));
        if (inv.approval_id || plan.approval_id) { resp.appendChild(approvalLink(inv.approval_id || plan.approval_id)); }
      } else {
        resp.textContent = "None proposed";
      }
      tr.appendChild(resp);
      var act = el("td");
      var wrap = el("div", "hunt-actions");
      wrap.appendChild(button("Open", "btn--ghost", function () { showDetail(inv); }));
      wrap.appendChild(button("Change status", "btn--ghost", function () { return changeStatus(inv); }));
      wrap.appendChild(button("Assign", "btn--ghost", function () { return assign(inv); }));
      if (kind === "platform" && !plan) { wrap.appendChild(button("Propose containment", "btn--primary", function () { return proposeContainment(inv); })); }
      act.appendChild(wrap);
      tr.appendChild(act);
      body.appendChild(tr);
    });
  }

  function renderHeatmap() {
    var body = $("hunt-heatmap");
    if (!body) { return; }
    clear(body);
    var list = (summary && summary.attack_heatmap) || [];
    if (!list.length) {
      var tr = el("tr");
      var td = el("td", "muted", "No kinds of attack seen yet. They appear here when a check matches activity.");
      td.colSpan = 3; tr.appendChild(td); body.appendChild(tr);
      return;
    }
    list.forEach(function (row) {
      var tr = el("tr");
      tr.appendChild(el("td", null, attackName(row.technique)));
      tr.appendChild(el("td", null, row.count));
      tr.appendChild(el("td", null, Object.keys(row.severities || {}).sort().map(function (k) {
        return (SEVERITY[k] || human(k)) + ": " + row.severities[k];
      }).join(", ")));
      body.appendChild(tr);
    });
  }

  async function load(keepStatus) {
    if (!keepStatus) { say("Loading…"); }
    try { summary = await window.mvFetchJSON(api + "/summary", {}, "load the findings"); }
    catch (error) { if (error.status) { say(""); } fail(error.message); return; }
    $("hunt-open").textContent = String(summary.open_findings || 0);
    $("hunt-investigations").textContent = String((summary.investigations || []).length);
    if ($("hunt-safety")) { $("hunt-safety").textContent = summary.reduced_autonomy ? "Not installed: automatic steps paused" : "Connected"; }
    if ($("hunt-chain")) {
      var chain = summary.chain_status;
      $("hunt-chain").textContent = chain ? (chain.intact ? "Not tampered with" : "Changed: check the activity log") : "Not checked yet";
    }
    renderFindings();
    renderInvestigations();
    renderHeatmap();
    if (!keepStatus) { say(""); }
  }

  // Built-in check names: show attack names instead of codes.
  Array.prototype.forEach.call(document.querySelectorAll("[data-attack]"), function (td) {
    var ids = (td.getAttribute("data-attack") || "").split(",").filter(Boolean);
    td.textContent = ids.map(attackName).join("; ") || "—";
  });

  // ---- Platform: run a check, start an investigation ----
  var run = $("hunt-run");
  if (run) {
    run.addEventListener("click", async function () {
      run.disabled = true;
      say("Checking the activity log and looking for threats…");
      var out = await call("POST", api + "/scan", {}, "run the check");
      run.disabled = false;
      if (out) { say("Check finished."); }
      await load(true);
    });
  }
  var investigate = $("hunt-investigate");
  if (investigate) {
    investigate.addEventListener("click", async function () {
      var ids = Array.prototype.slice.call(document.querySelectorAll(".hunt-pick:checked")).map(function (b) { return b.value; });
      if (!ids.length) { fail("Choose one or more findings first."); return; }
      var values = await window.mvForm("Start an investigation", [
        { key: "title", label: "Name", required: true, placeholder: "For example: unusual sign-ins on Monday" },
        { key: "summary", label: "What you know so far", required: true }
      ], { okText: "Start" });
      if (!values) { return; }
      var out = await call("POST", api + "/investigations", { title: values.title, summary: values.summary, finding_ids: ids }, "start the investigation");
      if (out) { say("Investigation started."); }
      await load(true);
    });
  }

  // ---- Environment: custom checks, pull and file analysis ----
  function readChecks() {
    try { return JSON.parse(window.localStorage.getItem(CUSTOM_KEY) || "[]") || []; } catch (e) { return []; }
  }
  function saveChecks(list) {
    try { window.localStorage.setItem(CUSTOM_KEY, JSON.stringify(list)); } catch (e) { /* kept for this visit only */ }
    customChecks = list;
  }
  var customChecks = readChecks();
  var FIELD = { action: "What happened", principal: "Who did it", target: "What it affected", outcome: "The result" };
  function ruleText(check) {
    if (check.raw) { return check.raw; }
    var sel = {};
    sel[check.field + (check.match === "contains" ? "|contains" : "")] = check.value;
    var rule = { title: check.title, id: check.id, logsource: {}, detection: { selection: sel, condition: "selection" },
      level: check.level, tags: check.technique ? ["attack." + String(check.technique).toLowerCase()] : [] };
    return JSON.stringify(rule);
  }
  function renderChecks() {
    var body = $("soc-custom-rows");
    if (!body) { return; }
    clear(body);
    if (!customChecks.length) {
      var tr = el("tr");
      var td = el("td", "muted", "No checks of your own yet. Add one above to look for a pattern you care about.");
      td.colSpan = 4; tr.appendChild(td); body.appendChild(tr);
      return;
    }
    customChecks.forEach(function (c, i) {
      var tr = el("tr");
      tr.appendChild(el("td", null, c.title));
      tr.appendChild(el("td", null, c.raw ? "Loaded from a file" : FIELD[c.field] + (c.match === "contains" ? " contains “" : " is “") + c.value + "”"));
      tr.appendChild(el("td", null, SEVERITY[c.level] || human(c.level)));
      var act = el("td");
      act.appendChild(button("Remove", "btn--ghost", async function () {
        var ok = await window.mvConfirm("Remove the check “" + c.title + "”?", { okText: "Remove check" });
        if (!ok) { return; }
        var next = customChecks.slice(); next.splice(i, 1); saveChecks(next); renderChecks();
      }));
      tr.appendChild(act);
      body.appendChild(tr);
    });
  }
  var addRule = $("soc-rule-add");
  if (addRule) {
    addRule.addEventListener("click", async function () {
      var techniques = Object.keys(ATTACK).map(function (k) { return { value: k, label: ATTACK[k] + " (" + k + ")" }; });
      techniques.unshift({ value: "", label: "Not sure" });
      var values = await window.mvForm("Add a check", [
        { key: "title", label: "Name of the check", required: true, placeholder: "For example: sign-in from the test account" },
        { key: "field", label: "Look at", type: "select", default: "action",
          options: Object.keys(FIELD).map(function (k) { return { value: k, label: FIELD[k] }; }) },
        { key: "match", label: "Match when it", type: "select", default: "contains",
          options: [{ value: "contains", label: "Contains" }, { value: "equals", label: "Is exactly" }] },
        { key: "value", label: "These words", required: true },
        { key: "level", label: "How serious", type: "select", default: "medium",
          options: ["low", "medium", "high", "critical"].map(function (k) { return { value: k, label: SEVERITY[k] }; }) },
        { key: "technique", label: "Kind of attack", type: "select", default: "", options: techniques }
      ], { okText: "Add check" });
      if (!values) { return; }
      values.id = "custom-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 6);
      saveChecks(customChecks.concat([values]));
      renderChecks();
      say("Check added. It is used the next time you look for threats.");
    });
  }
  var ruleFile = $("soc-rule-file");
  if (ruleFile) {
    ruleFile.addEventListener("change", async function () {
      var file = ruleFile.files && ruleFile.files[0];
      if (!file) { return; }
      if (file.size > 256 * 1024) { fail("That file is too large for a list of checks."); return; }
      var text = await file.text();
      var titles = (text.match(/^\s*title\s*:\s*(.+)$/gm) || []).length || 1;
      saveChecks(customChecks.concat([{ title: file.name, raw: text, level: "medium", count: titles }]));
      renderChecks();
      ruleFile.value = "";
      say("Loaded checks from " + file.name + ".");
    });
  }
  renderChecks();

  var INGEST_ERRORS = {
    403: "Lightwork is not allowed to read this system that way. Ask your administrator.",
    422: "Those events, or one of your checks, are not in a format Lightwork understands for that system.",
    503: "That system could not be read right now. Try again in a few minutes."
  };
  async function ingest(body, label) {
    body.sigma_rules = customChecks.map(ruleText);
    say("Looking for threats in " + label + "…");
    var out = await call("POST", api + "/ingest", body, "look for threats", INGEST_ERRORS);
    if (out) {
      var created = out.findings_created;
      var n = Array.isArray(created) ? created.length : Number(created || out.findings_detected || 0);
      say("Done. " + (out.events_accepted !== undefined ? plural(Number(out.events_accepted), "event", "events") + " looked at; " : "") +
        (n ? plural(n, "new finding", "new findings") + " below." : "nothing suspicious found."));
    } else { say(""); }
    await load(true);
  }
  var pullRun = $("soc-pull-run");
  if (pullRun) {
    pullRun.addEventListener("click", async function () {
      pullRun.disabled = true;
      var sel = $("soc-pull-connector");
      var seconds = Number($("soc-pull-window").value);
      var end = Date.now() / 1000;
      await ingest({ connector: sel.value, start: end - seconds, end: end }, sel.options[sel.selectedIndex].textContent);
      pullRun.disabled = false;
    });
  }

  var pending = null;
  function rowsFrom(text) {
    var trimmed = text.trim();
    try {
      var data = JSON.parse(trimmed);
      if (Array.isArray(data)) { return data; }
      if (data && Array.isArray(data.Records)) { return data.Records; }
      if (data && Array.isArray(data.events)) { return data.events; }
      if (data && typeof data === "object") { return [data]; }
    } catch (e) { /* maybe one event per line */ }
    var out = [];
    trimmed.split(/\r?\n/).forEach(function (line) {
      if (!line.trim()) { return; }
      try { var v = JSON.parse(line); if (v && typeof v === "object") { out.push(v); } } catch (e) { /* skip */ }
    });
    return out;
  }
  function pickField(row, keys) {
    for (var i = 0; i < keys.length; i++) {
      var parts = keys[i].split(".");
      var v = row;
      for (var j = 0; j < parts.length && v; j++) { v = v[parts[j]]; }
      if (v !== undefined && v !== null && typeof v !== "object") { return String(v); }
    }
    return "—";
  }
  var fileInput = $("soc-file");
  if (fileInput) {
    fileInput.addEventListener("change", async function () {
      pending = null;
      $("soc-preview").hidden = true;
      var file = fileInput.files && fileInput.files[0];
      if (!file) { return; }
      if (file.size > 20 * 1024 * 1024) { fail("That file is too large. Export a shorter time period."); return; }
      var rows = rowsFrom(await file.text());
      if (!rows.length) { fail("No events were found in that file. Check it is the activity export from the system you chose."); return; }
      if (rows.length > 10000) { fail("That file has more than 10,000 events. Export a shorter time period."); return; }
      pending = rows;
      $("soc-preview-summary").textContent = "Found " + plural(rows.length, "event", "events") + " in " + file.name + ". The first few:";
      var body = $("soc-preview-rows");
      clear(body);
      rows.slice(0, 5).forEach(function (row) {
        var tr = el("tr");
        tr.appendChild(el("td", null, pickField(row, ["eventTime", "timestamp", "@timestamp", "time", "published", "createdDateTime", "requestReceivedTimestamp"])));
        tr.appendChild(el("td", null, pickField(row, ["eventName", "action", "eventType", "event.action", "type", "activityDisplayName", "verb", "message"])));
        tr.appendChild(el("td", null, pickField(row, ["userIdentity.arn", "userIdentity.userName", "actor.alternateId", "user", "user.name", "userPrincipalName", "principal"])));
        body.appendChild(tr);
      });
      $("soc-preview").hidden = false;
      var e = $("hunt-error"); if (e) { e.textContent = ""; }
    });
  }
  var fileRun = $("soc-file-run");
  if (fileRun) {
    fileRun.addEventListener("click", async function () {
      if (!pending) { fail("Choose a log file first."); return; }
      fileRun.disabled = true;
      var sel = $("soc-file-connector");
      await ingest({ connector: sel.value, events: pending }, "the file");
      fileRun.disabled = false;
    });
  }

  load();
})();
