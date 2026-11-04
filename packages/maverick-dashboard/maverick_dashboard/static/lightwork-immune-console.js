(function () {
  "use strict";

  var root = document.getElementById("ic-root");
  if (!root || root.dataset.console !== "immune") { return; }
  var canAdmin = root.dataset.canAdmin === "true";
  var canGlobalAdmin = root.dataset.canGlobalAdmin === "true";
  var statusEl = document.getElementById("ic-status");
  var errorEl = document.getElementById("ic-error");
  var maxFileBytes = 5 * 1024 * 1024;
  var titles = {};
  var choices = { canaries: false, twin_record: false, decision_classes: [], recorded_goals: [], people: [] };

  var IFC_MODE = {
    off: "Protection: not checking sensitive data.",
    audit: "Protection: recording when sensitive data leaves, without blocking it.",
    approve: "Protection: a person must approve before sensitive data leaves.",
    block: "Protection: sensitive data is blocked from leaving."
  };
  var OUTCOME = { blocked: "Blocked", allowed: "Allowed", approved: "Approved by a person",
    denied: "Refused", recorded: "Recorded", held: "Held for approval" };

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    if (text !== undefined && text !== null) { e.textContent = String(text); }
    return e;
  }
  function human(v) { return window.mvHuman ? window.mvHuman(v) : String(v || ""); }
  function say(text) { window.mvStatus(statusEl, text); }
  function fail(text) { if (errorEl) { errorEl.textContent = text; } if (window.mvToast) { window.mvToast(text, { error: true }); } }
  function clear(node) { while (node.firstChild) { node.removeChild(node.firstChild); } }
  function text(id, value) {
    var node = document.getElementById(id);
    if (node) { node.textContent = value === null || value === undefined ? "—" : String(value); }
  }
  function task(id) {
    if (id === null || id === undefined) { return "—"; }
    return titles[String(id)] || ("Task " + id);
  }
  function percent(value) {
    if (value === null || value === undefined || !isFinite(value)) { return "—"; }
    return Math.round(Number(value) * 100) + "%";
  }
  function tool(pair) {
    // [assistant, tool] -> "Send email (Sales assistant)"
    if (!pair || !pair.length) { return "—"; }
    if (pair.length < 2) { return human(pair[0]); }
    return human(pair[1]) + " (" + human(pair[0]) + ")";
  }

  function failure(error, action) {
    var plain = window.mvPlainDetail && window.mvPlainDetail(error && error.detail);
    if (plain && [404, 409, 422, 503].indexOf(error.status) >= 0) {
      return plain;
    }
    return error && error.message ? error.message : window.mvErrorText(error, action);
  }

  async function call(method, url, body, action) {
    var data;
    try { data = await window.mvFetchJSON(url, { method: method, body: body }, action); }
    catch (error) { fail(failure(error, action)); return null; }
    if (errorEl) { errorEl.textContent = ""; }
    return data || {};
  }

  function button(label, cls, onClick) {
    var b = el("button", "btn " + (cls || "btn--ghost"), label);
    b.type = "button";
    b.addEventListener("click", function () {
      b.disabled = true;
      Promise.resolve(onClick()).finally(function () { b.disabled = false; });
    });
    return b;
  }

  function rows(id, items, columns, empty) {
    var body = document.getElementById(id);
    if (!body) { return; }
    clear(body);
    if (!items || !items.length) {
      var tr = el("tr");
      var td = el("td", null, empty);
      td.colSpan = columns.length;
      tr.appendChild(td);
      body.appendChild(tr);
      return;
    }
    items.forEach(function (item) {
      var tr = el("tr");
      columns.forEach(function (column) {
        var value = column(item);
        var td = el("td");
        if (value && value.nodeType) { td.appendChild(value); } else { td.textContent = value === null || value === undefined ? "—" : String(value); }
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
  }

  function renderSummary(data) {
    titles = data.goal_titles || {};
    var comp = data.composition || {};
    var ifc = data.ifc || {};
    var over = data.oversight || {};
    var twin = data.twin || {};
    text("ic-trifectas", comp.available ? (comp.by_kind || {}).trifecta || 0 : "Not available");
    text("ic-exfil", comp.available ? (comp.by_kind || {}).exfiltration || 0 : "Not available");
    text("ic-ifc-events", ifc.available ? ifc.events : "Not available");
    text("ic-replays", twin.available ? (twin.replays || []).length : "Not available");
    rows("ic-comp-rows", comp.trifectas, [
      function (f) { return (f.path || []).map(human).join(" → "); },
      function (f) { return tool((f.witness || {}).sensitive); },
      function (f) { return tool((f.witness || {}).mutate); },
      function (f) { return tool((f.witness || {}).external); },
      function (f) { return human(f.sink_risk); }
    ], comp.available ? "No risky combinations found." : "This check could not run right now. Refresh to try again.");
    text("ic-ifc-mode", IFC_MODE[ifc.mode] || ("Protection: " + human(ifc.mode || "unknown") + "."));
    rows("ic-ifc-rows", ifc.recent, [
      function (r) { return task(r.goal_id); },
      function (r) { return human(r.tool); },
      function (r) { return (r.labels || []).map(function (l) { return human(String(l).replace(/^data:/, "")); }).join(", "); },
      function (r) { return (r.explicit || []).length ? "Yes" : "No"; },
      function (r) { return OUTCOME[r.outcome] || human(r.outcome); }
    ], "No sensitive data has reached a tool that sends it outside.");
    function scoreRows(id, list, emptyText, yes, no) {
      rows(id, list, [
        function (r) { return r.person_label || r.person; },
        function (r) { return human(r["class"]); },
        function (r) { return r.caught; },
        function (r) { return r.missed; },
        function (r) { return percent(r.assured); },
        function (r) { return r.authority ? yes : no; }
      ], emptyText);
    }
    scoreRows("ic-over-rows", over.canary, over.available ? "No reviewer tests have been decided yet." :
      "Reviewer results are not available right now. Try again in a minute.", "Yes", "Not yet");
    scoreRows("ic-drill-rows", over.drill, "No drill results yet. Record one above after a drill.", "Yes", "Not yet");
    rows("ic-twin-rows", twin.replays, [
      function (r) { return task(r.production_goal); },
      function (r) { return task(r.twin_goal); },
      function (r) { return r.watched ? "Yes" : "No"; },
      function (r) { return human(r.twin_status); },
      function (r) { return r.served + " of " + r.recorded; },
      function (r) { return r.approximate; },
      function (r) { return r.unmatched; },
      function (r) { return percent(r.result_similarity); }
    ], twin.recording ? "No re-runs yet. Choose a recorded task above and select Re-run." :
      "Recording is off, so there is nothing to re-run yet.");
  }

  function fillSelect(sel, items, toOption) {
    if (!sel) { return; }
    while (sel.options.length > 1) { sel.remove(1); }
    items.forEach(function (item) {
      var o = toOption(item);
      var opt = el("option", null, o.label);
      opt.value = o.value;
      sel.appendChild(opt);
    });
  }

  async function setSetting(key, value, question, okText) {
    var ok = await window.mvConfirm(question, { okText: okText });
    if (!ok) { return; }
    var body = {};
    body[key] = value;
    var out = await call("POST", "/api/v1/immune/settings", body, "change the setting");
    if (out) { say("Saved."); await loadAll(true); }
  }

  function renderChoices() {
    text("ic-over-state", "Reviewer tests: " + (choices.canaries ? "On" : "Off"));
    text("ic-twin-state", "Recording: " + (choices.twin_record ? "On" : "Off"));
    var overControls = document.getElementById("ic-over-controls");
    var twinControls = document.getElementById("ic-twin-controls");
    var canaryForm = document.getElementById("ic-canary-form");
    clear(overControls);
    clear(twinControls);
    if (canGlobalAdmin) {
      overControls.appendChild(choices.canaries ?
        button("Turn reviewer tests off", "btn--ghost", function () {
          return setSetting("canaries", false, "Stop planting test approvals? Results so far are kept.", "Turn off");
        }) :
        button("Turn reviewer tests on", "btn--primary", function () {
          return setSetting("canaries", true, "Allow Lightwork to place test approvals with planted mistakes in the real approvals queue? Reviewers are not told which ones are tests.", "Turn on");
        }));
      twinControls.appendChild(choices.twin_record ?
        button("Stop recording tasks", "btn--ghost", function () {
          return setSetting("twin_record", false, "Stop recording what tools return during tasks? Existing recordings are kept until you delete them.", "Stop recording");
        }) :
        button("Record tasks for re-runs", "btn--primary", function () {
          return setSetting("twin_record", true, "Record what tools return during every task so tasks can be re-run later? Recordings are kept private and can be deleted here.", "Start recording");
        }));
    } else if (!choices.canaries || !choices.twin_record) {
      overControls.appendChild(el("span", "muted", "An administrator can change these settings."));
    }
    if (canaryForm) { canaryForm.hidden = !(canAdmin && choices.canaries); }
    fillSelect(document.getElementById("ic-canary-class"), choices.decision_classes, function (c) { return { value: c, label: human(c) }; });
    fillSelect(document.getElementById("ic-drill-class"), choices.decision_classes, function (c) { return { value: c, label: human(c) }; });
    fillSelect(document.getElementById("ic-drill-person"), choices.people, function (p) { return p; });
    rows("ic-recorded-rows", choices.recorded_goals, [
      function (g) {
        var box = el("input");
        box.type = "checkbox";
        box.value = String(g.id);
        box.className = "ic-pick";
        box.setAttribute("aria-label", "Choose " + g.title);
        return box;
      },
      function (g) { return g.title; },
      function (g) { return human(g.status) || "—"; },
      function (g) {
        var wrap = el("div", "ic-actions");
        if (canAdmin) {
          wrap.appendChild(button("Re-run", "btn--primary", function () { return replay(g); }));
          wrap.appendChild(button("Delete recording", "btn--danger", function () { return forget(g); }));
        } else {
          wrap.appendChild(el("span", "muted", "Administrators can re-run tasks."));
        }
        return wrap;
      }
    ], choices.twin_record ? "No recorded tasks yet. Tasks are recorded as they run." :
      "No recorded tasks. Turn on recording to re-run tasks later.");
  }

  async function replay(g) {
    var ok = await window.mvConfirm("Re-run “" + g.title + "” with the tool answers recorded last time? This uses AI and creates a new practice task.", { okText: "Re-run" });
    if (!ok) { return; }
    var out = await call("POST", "/api/v1/immune/twin/" + encodeURIComponent(g.id) + "/replay", {}, "start the re-run");
    if (out) { say("Re-run started. Its result appears under Past re-runs when it finishes."); }
  }

  function forget(g) {
    // One action with a way back: deleted when the Undo time is up.
    var pick = document.querySelector('.ic-pick[value="' + String(Number(g.id)) + '"]');
    var row = pick ? pick.closest("tr") : null;
    if (row) { row.hidden = true; }
    window.mvUndo("Recording for “{title}” deleted. Past re-run results are kept.", { values: {title: g.title},
      action: "delete the recording",
      run: function (keepalive) { return fetch("/api/v1/immune/twin/" + encodeURIComponent(g.id), { method: "DELETE", keepalive: keepalive, headers: { Accept: "application/json" } }); },
      undo: function () { if (row) { row.hidden = false; } },
      done: function () { say("Recording deleted."); return loadAll(true); }
    });
  }

  async function awareness() {
    var picked = Array.prototype.slice.call(document.querySelectorAll(".ic-pick:checked")).map(function (b) { return Number(b.value); });
    if (!picked.length) { fail("Choose at least one recorded task first."); return; }
    if (picked.length > 10) { fail("Choose up to 10 tasks."); return; }
    var ok = await window.mvConfirm("Re-run each chosen task twice, once telling the assistant it is being watched, and compare? This uses AI (" + (picked.length * 2) + " runs).", { okText: "Start check" });
    if (!ok) { return; }
    var out = await call("POST", "/api/v1/immune/awareness", { goal_ids: picked }, "start the check");
    if (out) { say("Check started. Results appear under Past re-runs when it finishes."); }
  }

  // A table whose data never arrived says so instead of "Loading." forever.
  function settleLoading(message) {
    Array.prototype.forEach.call(root.querySelectorAll("tbody"), function (body) {
      if (body.textContent.trim() !== "Loading.") { return; }
      var cell = body.querySelector("td");
      if (cell) { cell.textContent = message; }
    });
  }

  async function loadAll(keepStatus) {
    try {
      renderSummary(await window.mvFetchJSON(root.dataset.apiUrl, {}, "load the safety summary"));
      try { choices = await window.mvFetchJSON("/api/v1/immune/choices"); renderChoices(); } catch (e) { /* choices stay as they were */ }
      settleLoading((window.LightworkI18n ? window.LightworkI18n.text("Not available right now. Reload the page to try again.") : "Not available right now. Reload the page to try again."));
      if (!keepStatus) { say("Up to date."); }
    } catch (error) {
      say("");
      fail(error.message);
      settleLoading((window.LightworkI18n ? window.LightworkI18n.text("Could not be loaded. Reload the page to try again.") : "Could not be loaded. Reload the page to try again."));
    }
  }

  function readJsonFile(input, what) {
    return new Promise(function (resolve) {
      var files = input && input.files ? Array.prototype.slice.call(input.files) : [];
      if (!files.length) { fail("Choose " + what + " first."); resolve(null); return; }
      Promise.all(files.map(function (file) {
        if (file.size > maxFileBytes) { return Promise.reject(new Error("big")); }
        return file.text().then(function (t) { return JSON.parse(t); });
      })).then(function (docs) { resolve(docs); }, function () {
        fail("That file could not be read. Choose the file Lightwork or your team exported.");
        resolve(null);
      });
    });
  }

  function download(name, obj) {
    var blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
    var a = el("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }

  function showList(target, heading, items, emptyText) {
    clear(target);
    target.appendChild(el("p", null, items.length ? heading : emptyText));
    if (items.length) {
      var ul = el("ul", "ic-list");
      items.forEach(function (t) { ul.appendChild(el("li", null, t)); });
      target.appendChild(ul);
    }
  }

  function wire(id, fn) {
    var b = document.getElementById(id);
    if (b) {
      b.addEventListener("click", function () {
        b.disabled = true;
        Promise.resolve(fn()).finally(function () { b.disabled = false; });
      });
    }
  }

  wire("ic-rules-check", async function () {
    var docs = await readJsonFile(document.getElementById("ic-rules-file"), "a rule set file");
    if (!docs) { return; }
    var rules = docs[0] && Array.isArray(docs[0].rules) ? docs[0].rules : null;
    if (!rules) { fail("That file is not a rule set Lightwork can read."); return; }
    var out = await call("POST", "/api/v1/immune/rules/check", { rules: rules }, "check the rule set");
    if (!out) { return; }
    showList(document.getElementById("ic-rules-result"),
      out.contradictions.length + " conflict(s) found in " + out.rules + " rules:",
      out.contradictions.map(function (c) { return "Rule " + c.forbidding + " forbids what rule " + c.requiring + " requires" + (c.when ? " when " + c.when : "") + "."; }),
      "No conflicts found in " + out.rules + " rules.");
  });

  wire("ic-title-check", async function () {
    var docs = await readJsonFile(document.getElementById("ic-title-file"), "a discovery record file");
    if (!docs) { return; }
    var out = await call("POST", "/api/v1/immune/title/check", { dossier: docs[0] }, "check the record");
    if (out) {
      showList(document.getElementById("ic-title-result"), "These points would not stand up to scrutiny:",
        out.problems, "No problems found. This record is ready for your legal team.");
    }
  });

  wire("ic-title-seal", async function () {
    var docs = await readJsonFile(document.getElementById("ic-title-file"), "a discovery record file");
    if (!docs) { return; }
    var ok = await window.mvConfirm("Sign this discovery record with your organisation’s signing key? Anyone can later confirm it has not been changed.", { okText: "Sign" });
    if (!ok) { return; }
    var out = await call("POST", "/api/v1/immune/title/seal", { dossier: docs[0] }, "sign the record");
    if (out) { download("signed-discovery-record.json", out.sealed); say("Signed. The signed record was downloaded."); }
  });

  wire("ic-title-verify", async function () {
    var docs = await readJsonFile(document.getElementById("ic-title-file"), "a signed discovery record file");
    if (!docs) { return; }
    var out = await call("POST", "/api/v1/immune/title/verify", { sealed: docs[0] }, "confirm the record");
    if (!out) { return; }
    var target = document.getElementById("ic-title-result");
    clear(target);
    target.appendChild(el("p", null, out.verified ? "Confirmed: this record was signed by your organisation and has not been changed." :
      "Not confirmed: this record was changed after signing, or was not signed by your organisation."));
    if (!out.verified) { return; }
    if (out.sealed_by) { target.appendChild(el("p", null, "Signed by " + String(out.sealed_by).replace(/^user:/, "") + ".")); }
    if (out.open_problems === null || out.open_problems === undefined) {
      target.appendChild(el("p", null, "This record was signed before Lightwork noted open problems at signing, so check it again below."));
    } else if (!out.open_problems.length) {
      target.appendChild(el("p", null, "Nothing was left open when it was signed."));
    } else {
      target.appendChild(el("p", null, "Still open when it was signed:"));
      var list = el("ul");
      out.open_problems.forEach(function (p) { list.appendChild(el("li", null, p)); });
      target.appendChild(list);
    }
  });

  wire("ic-title-research", async function () {
    var dossier = await readJsonFile(document.getElementById("ic-title-file"), "a discovery record file");
    if (!dossier) { return; }
    var runs = await readJsonFile(document.getElementById("ic-title-runs"), "one or more research run records");
    if (!runs) { return; }
    var elements = (document.getElementById("ic-title-elements").value || "").split(/\n/).map(function (s) { return s.trim(); }).filter(Boolean);
    var out = await call("POST", "/api/v1/immune/title/research", { dossier: dossier[0], runs: runs, elements: elements }, "add the research runs");
    if (out) { download("discovery-record.json", out.dossier); say("Added " + out.added + " human decision(s). The updated record was downloaded."); }
  });

  wire("ic-awareness", awareness);

  var canaryForm = document.getElementById("ic-canary-form");
  if (canaryForm) {
    canaryForm.addEventListener("submit", async function (ev) {
      ev.preventDefault();
      var count = Number(canaryForm.elements.count.value || 1);
      var ok = await window.mvConfirm("Place " + count + " test approval(s) with a planted mistake in the real approvals queue?", { okText: "Plant tests" });
      if (!ok) { return; }
      var out = await call("POST", "/api/v1/immune/canaries", { decision_class: canaryForm.elements.decision_class.value || null, count: count }, "plant the test approvals");
      if (out) { say("Planted " + out.planted + " test approval(s). Results appear here once reviewers decide them."); }
    });
  }
  var drillForm = document.getElementById("ic-drill-form");
  if (drillForm) {
    drillForm.addEventListener("submit", async function (ev) {
      ev.preventDefault();
      var passed = drillForm.querySelector("input[name=passed]:checked");
      if (!drillForm.elements.person.value || !drillForm.elements.decision_class.value || !passed) {
        fail("Choose a person, a kind of decision and a result.");
        return;
      }
      var out = await call("POST", "/api/v1/immune/drills", {
        person: drillForm.elements.person.value, decision_class: drillForm.elements.decision_class.value,
        passed: passed.value === "true" }, "save the drill result");
      if (out) { drillForm.reset(); say("Drill result saved."); await loadAll(true); }
    });
  }

  loadAll();
})();
