(function () {
  "use strict";

  var root = document.getElementById("ic-root");
  if (!root || root.dataset.console !== "code") { return; }
  var canAdmin = root.dataset.canAdmin === "true";
  var enabled = root.dataset.enabled === "true";
  var statusEl = document.getElementById("ic-status");
  var errorEl = document.getElementById("ic-error");
  var summary = { repos: [], proposals: [] };

  var STATUS = {
    pending: "Waiting for approval",
    approved: "Approved, ready to merge",
    rejected: "Rejected",
    expired: "Approval request lapsed",
    unrequested: "Needs an approval request",
    merged: "Merged",
    empty: "No changes were made",
    conflict: "No longer fits the latest code"
  };
  var PROTECT = {
    block: "Code never leaves Lightwork",
    approve: "Code leaves only with approval",
    audit: "Code can leave, and each time is recorded"
  };

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    if (text !== undefined && text !== null) { e.textContent = String(text); }
    return e;
  }
  function human(v) { return window.mvHuman ? window.mvHuman(v) : String(v || ""); }
  function when(ts) { return window.mvWhen ? window.mvWhen(ts) : ""; }
  function say(text) { window.mvStatus(statusEl, text); }
  function fail(text) { if (errorEl) { errorEl.textContent = text; } if (window.mvToast) { window.mvToast(text, { error: true }); } }
  function clear(node) { while (node.firstChild) { node.removeChild(node.firstChild); } }

  // Our own action routes answer with a short plain sentence; anything else
  // (a validation list, a proxy page) falls back to the shared wording.
  function failure(error, action) {
    var plain = window.mvPlainDetail && window.mvPlainDetail(error && error.detail);
    if (plain && [409, 422, 502, 503].indexOf(error.status) >= 0) {
      return plain;
    }
    return error && error.message ? error.message : window.mvErrorText(error, action);
  }

  async function post(url, body, action) {
    var data;
    try { data = await window.mvFetchJSON(url, { method: "POST", body: body || {} }, action); }
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

  function emptyRow(body, cols, text, action) {
    var tr = el("tr");
    var td = el("td");
    td.colSpan = cols;
    td.appendChild(el("span", null, text));
    if (action) { td.appendChild(document.createTextNode(" ")); td.appendChild(action); }
    tr.appendChild(td);
    body.appendChild(tr);
  }

  function testsText(value) {
    if (value === null || value === undefined) { return "Not set up"; }
    return value ? "Passed" : "Failed";
  }
  function reviewText(value) {
    if (value === null || value === undefined) { return "Not run"; }
    return value ? "Recommends it" : "Has concerns";
  }

  function renderRepos() {
    var body = document.getElementById("ic-repo-rows");
    clear(body);
    var repos = summary.repos || [];
    if (!repos.length) {
      if (!enabled) { emptyRow(body, 6, "Code projects are turned off. Turn them on above to add one."); return; }
      var add = canAdmin ? button("Add a code project", "btn--primary", addRepo) : null;
      emptyRow(body, 6, canAdmin ? "No code projects yet." :
        "No code projects yet. Ask an administrator to add one.", add);
      return;
    }
    repos.forEach(function (r) {
      var tr = el("tr");
      tr.appendChild(el("td", null, r.name));
      tr.appendChild(el("td", null, r.default_branch));
      tr.appendChild(el("td", null, PROTECT[r.protect] || human(r.protect)));
      tr.appendChild(el("td", null, r.tests ? "Set up" : "Not set up"));
      tr.appendChild(el("td", null, when(r.updated_at) || "—"));
      var actions = el("td");
      var wrap = el("div", "ic-actions");
      if (canAdmin) {
        wrap.appendChild(button("Start a change", "btn--primary", function () { pickRepo(r.name); }));
        wrap.appendChild(button("Get latest changes", "btn--ghost", function () { syncRepo(r.name); }));
        wrap.appendChild(button("Download a copy", "btn--ghost", function () { exportRepo(r.name); }));
      } else {
        wrap.appendChild(el("span", "muted", "Administrators can start changes."));
      }
      actions.appendChild(wrap);
      tr.appendChild(actions);
      body.appendChild(tr);
    });
  }

  function renderProposals() {
    var body = document.getElementById("ic-prop-rows");
    clear(body);
    var props = summary.proposals || [];
    if (!props.length) {
      var start = canAdmin && (summary.repos || []).length ? button("Start a change", "btn--primary", function () { pickRepo(""); }) : null;
      emptyRow(body, 7, "No proposed changes yet. Changes appear here when an agent proposes one; ask for one in Chat.", start);
      return;
    }
    props.forEach(function (p) {
      var tr = el("tr");
      tr.appendChild(el("td", null, p.title));
      tr.appendChild(el("td", null, p.repo));
      tr.appendChild(el("td", null, p.files));
      tr.appendChild(el("td", null, testsText(p.tests)));
      tr.appendChild(el("td", null, reviewText(p.review)));
      tr.appendChild(el("td", null, STATUS[p.status] || human(p.status)));
      var td = el("td");
      var wrap = el("div", "ic-actions");
      if (canAdmin) { wrap.appendChild(button("Review", "btn--ghost", function () { review(p.id); })); }
      if (p.status === "pending" && p.approval_id) {
        var link = el("a", "btn btn--primary", "Approve in the approvals queue");
        link.href = "/approvals#approval-" + encodeURIComponent(p.approval_id);
        wrap.appendChild(link);
      }
      if (canAdmin && p.status === "approved") {
        wrap.appendChild(button("Merge", "btn--primary", function () { merge(p); }));
      }
      if (canAdmin && (p.status === "approved" || p.status === "merged")) {
        wrap.appendChild(button("Send to the original project", "btn--ghost", function () { push(p); }));
      }
      if (canAdmin && (p.status === "expired" || p.status === "unrequested")) {
        wrap.appendChild(button("Ask for approval again", "btn--primary", function () { renew(p); }));
      }
      if (!wrap.firstChild) { wrap.appendChild(el("span", "muted", "Nothing to do")); }
      td.appendChild(wrap);
      tr.appendChild(td);
      body.appendChild(tr);
    });
  }

  // Download a copy (code export): an unprotected plain copy, confirmed first.
  async function exportRepo(name) {
    var ok = await window.mvConfirm("Download a full copy of " + name + "? Once it leaves Lightwork, the copy is " +
      "not protected, so keep it somewhere safe. The download is recorded.", { okText: "Download" });
    if (!ok) { return; }
    say("Preparing a copy of " + name + ". Large projects can take a minute.");
    var response;
    try {
      response = await window.mvFetchJSON("/api/v1/code/repos/" + encodeURIComponent(name) + "/export",
        { method: "POST", body: { confirm: true }, raw: true }, "download the copy");
    } catch (error) { say(""); fail(failure(error, "download the copy")); return; }
    var link = document.createElement("a");
    link.href = URL.createObjectURL(await response.blob());
    link.download = name + "-copy.zip";
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(function () { URL.revokeObjectURL(link.href); }, 1000);
    say("Downloaded a copy of " + name + ".");
  }

  // Watch a code project for notes to Lightwork (watch).
  var WATCH = { starting: "Starting", watching: "Watching", stopped: "Stopped", failed: "Stopped after a problem" };
  var watchState = { rows: [] };
  function renderWatch() {
    var list = document.getElementById("code-watch-list");
    if (!list) { return; }
    clear(list);
    var rows = watchState.rows;
    if (!rows.length) {
      list.appendChild(el("p", "muted", "Lightwork is not watching any code project. Choose one above to start."));
      return;
    }
    rows.forEach(function (w) {
      var box = el("div", "panel ic-watch");
      var head = el("div", "ic-head");
      head.appendChild(el("h3", null, w.repo + " · " + (WATCH[w.state] || w.state)));
      if (w.state === "watching" || w.state === "starting") {
        head.appendChild(button("Stop watching", "btn--ghost", function () { stopWatch(w.repo); }));
      } else {
        head.appendChild(button("Start again", "btn--ghost", function () { startWatch(w.repo); }));
      }
      box.appendChild(head);
      if (w.reason && w.state !== "watching") { box.appendChild(el("p", "muted", w.reason)); }
      box.appendChild(el("p", "muted", w.last_scan ? "Last read " + when(w.last_scan) + ". " + (w.notes.length ?
        w.notes.length + " note" + (w.notes.length === 1 ? "" : "s") + " found." : "No notes found.") :
        "Reading the code project for the first time."));
      if (w.notes.length) {
        var wrap = el("div", "ic-table-wrap");
        // A named region a keyboard can focus and scroll, like the page's own tables.
        wrap.tabIndex = 0;
        wrap.setAttribute("role", "region");
        wrap.setAttribute("aria-label", "Notes to Lightwork found in " + w.repo);
        var t = el("table", "ic-table");
        t.appendChild(el("caption", null, "Notes to Lightwork found in " + w.repo));
        var hr = el("tr");
        ["Note", "Where", "Actions"].forEach(function (h) { var th = el("th", null, h); th.scope = "col"; hr.appendChild(th); });
        var thead = el("thead"); thead.appendChild(hr); t.appendChild(thead);
        var tb = el("tbody");
        w.notes.forEach(function (n) {
          var tr = el("tr");
          tr.appendChild(el("td", null, n.note || "(a note with no text)"));
          tr.appendChild(el("td", null, n.file + ", line " + n.line));
          var td = el("td");
          td.appendChild(button("Start a task from this note", "btn--primary", function () { startNoteTask(w.repo, n); }));
          tr.appendChild(td);
          tb.appendChild(tr);
        });
        t.appendChild(tb);
        wrap.appendChild(t);
        box.appendChild(wrap);
      }
      list.appendChild(box);
    });
  }
  async function loadWatch() {
    if (!document.getElementById("code-watch-list")) { return; }
    try {
      watchState.rows = ((await window.mvFetchJSON("/api/v1/code/watch")) || {}).watching || [];
      renderWatch();
    } catch (e) { /* the list simply stays as it was */ }
  }
  async function startWatch(name) {
    if (!name) { fail("Choose a code project to watch."); return; }
    var ok = await window.mvConfirm("Watch " + name + " for notes to Lightwork? Lightwork reads the project again " +
      "each time it changes, for up to eight hours. Nothing runs until you start a task from a note.", { okText: "Start watching" });
    if (!ok) { return; }
    var out = await post("/api/v1/code/watch/" + encodeURIComponent(name) + "/start", { confirm: true }, "start watching");
    if (out) { say("Watching " + name + "."); await loadWatch(); }
  }
  async function stopWatch(name) {
    var out = await post("/api/v1/code/watch/" + encodeURIComponent(name) + "/stop", {}, "stop watching");
    if (out) { say("Stopped watching " + name + "."); await loadWatch(); }
  }
  // A note starts work on a private copy of the code, under the project's own
  // protection (the same path as "Build a change"), never as an ordinary task:
  // the code can leave Lightwork only as the project allows, and any change
  // waits for approval.
  async function startNoteTask(repo, n) {
    var project = (summary.repos || []).filter(function (r) { return r.name === repo; })[0];
    var rule = project && PROTECT[project.protect] ? " (" + PROTECT[project.protect] + ")" : "";
    var ok = await window.mvConfirm("Start work on the note “" + (n.note || n.file) + "”? Lightwork works on a " +
      "private copy of " + repo + " under its protection" + rule + ", within your spending limits, and uses AI. " +
      "Any change waits for your approval.", { okText: "Start work" });
    if (!ok) { return; }
    var out = await post("/api/v1/code/watch/" + encodeURIComponent(repo) + "/notes/" +
      encodeURIComponent(n.id) + "/start", { confirm: true }, "start the work");
    if (out && out.started) { say("Started work on the note. The change appears under Changes when it is ready."); }
  }

  function renderPicker() {
    var sel = document.getElementById("code-feature-repo");
    if (!sel) { return; }
    var current = sel.value;
    while (sel.options.length > 1) { sel.remove(1); }
    (summary.repos || []).forEach(function (r) {
      var o = el("option", null, r.name);
      o.value = r.name;
      sel.appendChild(o);
    });
    if (current) { sel.value = current; }
  }

  function render() {
    var props = summary.proposals || [];
    function count(state) { return props.filter(function (p) { return p.status === state; }).length; }
    document.getElementById("ic-repos").textContent = String((summary.repos || []).length);
    document.getElementById("ic-pending").textContent = String(count("pending"));
    document.getElementById("ic-approved").textContent = String(count("approved"));
    document.getElementById("ic-merged").textContent = String(count("merged"));
    renderRepos();
    renderProposals();
    renderPicker();
    var watchSel = document.getElementById("code-watch-repo");
    if (watchSel) {
      var picked = watchSel.value;
      while (watchSel.options.length > 1) { watchSel.remove(1); }
      (summary.repos || []).forEach(function (r) { var o = el("option", null, r.name); o.value = r.name; watchSel.appendChild(o); });
      if (picked) { watchSel.value = picked; }
    }
  }

  async function load(keepStatus) {
    try {
      summary = await window.mvFetchJSON(root.dataset.apiUrl, {}, "load the code projects");
      render();
      if (!keepStatus) { say("Up to date."); }
    } catch (error) {
      say("");
      fail(error.message);
    }
  }

  function pickRepo(name) {
    var sel = document.getElementById("code-feature-repo");
    if (!sel) { return; }
    if (name) { sel.value = name; }
    var section = document.getElementById("code-feature");
    if (section && section.scrollIntoView) { section.scrollIntoView({ block: "start" }); }
    var title = document.getElementById("code-feature-title-input");
    if (title) { title.focus(); }
  }

  async function addRepo() {
    var values = await window.mvForm("Add a code project", [
      { key: "name", label: "Name", required: true, placeholder: "For example: website" },
      { key: "source", label: "Web address of the code", required: true,
        placeholder: "https://github.com/your-company/your-project",
        help: "Lightwork keeps a private copy. Nothing is changed in the original." },
      { key: "protect", label: "Protection", type: "select", default: "block", options: [
        { value: "block", label: PROTECT.block },
        { value: "approve", label: PROTECT.approve },
        { value: "audit", label: PROTECT.audit }] },
      { key: "branch", label: "Main branch (optional)", help: "Leave empty to use the project’s usual main branch." },
      { key: "test_command", label: "How its tests are run (optional)", placeholder: "For example: npm test",
        help: "Ask the project’s developers. Lightwork runs this after every change." }
    ], { okText: "Add project" });
    if (!values) { return; }
    say("Copying the code project. This can take a minute.");
    var out = await post("/api/v1/code/repos", values, "add the code project");
    if (out) { say("Added " + out.name + "."); await load(true); } else { say(""); }
  }

  async function syncRepo(name) {
    var ok = await window.mvConfirm("Bring the latest changes from the original project into Lightwork’s copy of " +
      name + "? Changes already merged here are kept.", { okText: "Get latest changes" });
    if (!ok) { return; }
    say("Getting the latest changes for " + name + ".");
    var out = await post("/api/v1/code/repos/" + encodeURIComponent(name) + "/sync", {}, "get the latest changes");
    if (out) {
      say(out.updated_branches || out.new_branches ? "Updated " + name + "." : name + " was already up to date.");
      await load(true);
    } else { say(""); }
  }

  async function merge(p) {
    var ok = await window.mvConfirm("Merge “" + p.title + "” into Lightwork’s copy of " + p.repo +
      "? It becomes part of the main code there.", { okText: "Merge" });
    if (!ok) { return; }
    var out = await post("/api/v1/code/proposals/" + encodeURIComponent(p.id) + "/merge", {}, "merge the change");
    if (out) { say("Merged “" + p.title + "”."); await load(true); }
  }

  async function push(p) {
    var ok = await window.mvConfirm("Send “" + p.title + "” to the original " + p.repo +
      " project so its developers can review and accept it there?", { okText: "Send" });
    if (!ok) { return; }
    var out = await post("/api/v1/code/proposals/" + encodeURIComponent(p.id) + "/push", {}, "send the change");
    if (out) { say("Sent. Ask the project’s developers to review it."); }
  }

  async function renew(p) {
    var out = await post("/api/v1/code/proposals/" + encodeURIComponent(p.id) + "/renew", {}, "ask for approval again");
    if (out) { say("Approval requested. Approve it in the approvals queue."); await load(true); }
  }

  async function mergeApproved() {
    var ok = await window.mvConfirm("Merge every change a person has already approved?", { okText: "Merge approved changes" });
    if (!ok) { return; }
    var out = await post("/api/v1/code/merge-approved", {}, "merge the approved changes");
    if (out) {
      say(out.merged ? "Merged " + out.merged + (out.merged === 1 ? " change." : " changes.") :
        "There were no approved changes to merge.");
      if (out.not_merged) { fail(out.not_merged + (out.not_merged === 1 ? " change" : " changes") + " could not be merged. Review them below."); }
      await load(true);
    }
  }

  function section(parent, title) {
    parent.appendChild(el("h3", null, title));
  }

  async function review(pid) {
    var panel = document.getElementById("code-review");
    var body = document.getElementById("code-review-body");
    var p;
    try { p = await window.mvFetchJSON("/api/v1/code/proposals/" + encodeURIComponent(pid), {}, "open the change"); }
    catch (error) { fail(failure(error, "open the change")); return; }
    clear(body);
    body.appendChild(el("p", null, p.title + " · " + p.repo + " · " + (STATUS[p.status] || human(p.status))));
    section(body, "Tests");
    body.appendChild(el("p", null, p.tests ? (p.tests.passed ? "The project’s tests passed." :
      "The project’s tests failed. Look at the test results before approving.") :
      "This project has no tests set up."));
    section(body, "Independent review");
    if (!p.review) {
      body.appendChild(el("p", null, "No independent review was run."));
    } else {
      body.appendChild(el("p", null, p.review.approves ? "The reviewer recommends this change." :
        "The reviewer has concerns (" + p.review.blockers + " must be fixed)."));
      if (p.review.comments.length) {
        var ul = el("ul", "ic-list");
        p.review.comments.forEach(function (c) {
          ul.appendChild(el("li", null, (c.file ? c.file + ": " : "") + (c.message || "")));
        });
        body.appendChild(ul);
      }
    }
    section(body, "Files changed (" + p.files.length + ")");
    var files = el("ul", "ic-list");
    p.files.slice(0, 200).forEach(function (f) { files.appendChild(el("li", null, f)); });
    body.appendChild(files);
    var actions = el("div", "ic-actions");
    if (p.status === "pending" && p.approval_id) {
      var link = el("a", "btn btn--primary", "Approve in the approvals queue");
      link.href = "/approvals#approval-" + encodeURIComponent(p.approval_id);
      actions.appendChild(link);
    }
    body.appendChild(actions);
    if (p.changes) {
      var d = el("details");
      d.appendChild(el("summary", null, "Show the changed lines (for developers)"));
      if (p.changes_cut_short) { d.appendChild(el("p", "muted", "This change is very large; only the first part is shown.")); }
      d.appendChild(el("pre", "ic-pre", p.changes));
      body.appendChild(d);
    }
    if (p.tests_output) {
      var t = el("details");
      t.appendChild(el("summary", null, "Show the test results (for developers)"));
      t.appendChild(el("pre", "ic-pre", p.tests_output));
      body.appendChild(t);
    }
    panel.hidden = false;
    var heading = document.getElementById("code-review-title");
    if (heading) { heading.tabIndex = -1; heading.focus(); }
  }

  var form = document.getElementById("code-feature-form");
  if (form) {
    form.addEventListener("submit", async function (ev) {
      ev.preventDefault();
      var repo = form.elements.repo.value;
      var title = form.elements.title.value.trim();
      if (!repo || !title) { fail("Choose a code project and say what should change."); return; }
      var ok = await window.mvConfirm("Ask Lightwork’s agents to build “" + title + "” in " + repo +
        "? This uses AI and can take a while. Nothing is merged until a person approves it.", { okText: "Start" });
      if (!ok) { return; }
      var payload = { repo: repo, title: title, description: form.elements.description.value.trim() };
      if (form.elements.max_dollars.value) { payload.max_dollars = Number(form.elements.max_dollars.value); }
      var submit = form.querySelector("button[type=submit]");
      submit.disabled = true;
      var out = await post("/api/v1/code/features", payload, "start the change");
      submit.disabled = false;
      if (out) {
        form.reset();
        say("Started. The change appears under Proposed changes when the agents finish. Refresh the page to check.");
      }
    });
  }
  var addBtn = document.getElementById("code-add");
  if (addBtn) { addBtn.addEventListener("click", addRepo); }
  var mergeBtn = document.getElementById("code-merge-approved");
  if (mergeBtn) { mergeBtn.addEventListener("click", mergeApproved); }
  var closeBtn = document.getElementById("code-review-close");
  if (closeBtn) { closeBtn.addEventListener("click", function () { document.getElementById("code-review").hidden = true; }); }
  var watchBtn = document.getElementById("code-watch-start");
  if (watchBtn) {
    watchBtn.addEventListener("click", function () { startWatch(document.getElementById("code-watch-repo").value); });
    var refresh = document.getElementById("code-watch-refresh");
    if (refresh) { refresh.addEventListener("click", loadWatch); }
  }

  load();
  loadWatch();
})();
