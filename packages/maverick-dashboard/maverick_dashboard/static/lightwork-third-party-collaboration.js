// Third-party collaboration page: invitations load as a list with a button
// per next step; inviting a vendor is a guided form built from the chosen
// assessment. The one-time access code is shown once in a copy box. Record
// references, versions, request keys and the notice fingerprint are carried
// or computed here, never typed.
(function () {
  "use strict";
  var root = document.getElementById("tpc-root");
  if (!root || !window.LwRecords) { return; }
  var R = window.LwRecords;
  var API = root.getAttribute("data-api") || "/api/v1/third-party/collaboration";
  var LIFE = root.getAttribute("data-lifecycle-api") || "/api/v1/third-party/lifecycle";
  var canAdmin = root.getAttribute("data-can-admin") === "true";
  var canAudit = root.getAttribute("data-can-audit") === "true";
  var statusLine = document.getElementById("tpc-status");
  var state = { invitations: [], after: null, assessments: [], templates: [], vendors: {}, sharing: null, notice: null };

  var STATUS = { active: ["Waiting for answers", "info"], finalizing: ["Submitting", "info"], finalized: ["Answered", "ok"],
    follow_up_required: ["More information needed", "warn"], revoked: ["Cancelled", "idle"], conflicted: ["Needs attention", "danger"] };
  var REASONS = [
    { value: "vendor-no-longer-used", label: "We no longer use this vendor" },
    { value: "sent-to-wrong-person", label: "Sent to the wrong person" },
    { value: "replaced-by-new-invitation", label: "Replaced by a new invitation" },
    { value: "other", label: "Another reason" },
  ];
  var FOLLOW_UP_REASONS = [
    { value: "answer-unclear", label: "An answer is unclear" },
    { value: "evidence-missing", label: "Evidence is missing" },
    { value: "answer-out-of-date", label: "An answer is out of date" },
    { value: "other", label: "Another reason" },
  ];

  function say(text) { window.mvStatus(statusLine, text); }
  function fail(action) { return function (f) { var t = R.errorText(f, action); say(t); if (window.mvToast) { window.mvToast(t, { error: true }); } }; }
  function words(value) {
    if (value === null || value === undefined || value === "") { return ""; }
    var s = String(value);
    if (/^(tpl|tpc)-principal-/.test(s)) { return "A person on your team"; }
    if (/^vendor-contact\./.test(s)) { return "The vendor's contact at " + vendorName(s.slice(15)); }
    s = s.replace(/^(vendor-contact|vendor|note|file|doc)[.:]/, "").replace(/[-_.:]+/g, " ").trim();
    return s.charAt(0).toUpperCase() + s.slice(1);
  }
  function vendorName(ref) { return state.vendors[ref] || words(ref); }
  function ref(text, prefix) {
    var s = String(text || "");
    if (s.normalize) { s = s.normalize("NFKD"); }
    s = s.replace(/[^A-Za-z0-9 _.-]+/g, "").trim().replace(/\s+/g, "-").replace(/^[^A-Za-z0-9]+/, "").slice(0, 100);
    return (prefix || "") + (s || R.newId("item"));
  }
  function templateOf(a) {
    return state.templates.filter(function (t) { return t.template_id === a.template_id && t.version === a.template_version; })[0];
  }
  function dayChoices(maxSeconds, list) {
    return list.filter(function (d) { return d[0] * 86400 <= maxSeconds; });
  }

  // ---- the one-time access code --------------------------------------------
  function showOnce(result, what) {
    var box = document.getElementById("tpc-once");
    box.textContent = "";
    if (!result || !result.token) {
      box.hidden = false;
      box.appendChild(R.el("p", "", "This request was already done earlier, so no new access code was created. If the vendor lost it, use Send a new link."));
      return;
    }
    box.hidden = false;
    box.appendChild(R.el("h2", "", what));
    box.appendChild(R.el("p", "", "Copy these now and send them to the vendor. The access code won't be shown again."));
    function row(label, value) {
      var wrap = R.el("div", "tpc-actions");
      var lab = R.el("label", "tpc-field", label);
      var input = R.el("input", "input");
      input.readOnly = true; input.value = value; input.style.minWidth = "min(100%, 28rem)";
      lab.appendChild(input);
      wrap.appendChild(lab);
      wrap.appendChild(R.button("Copy", "primary", function () { if (window.mvCopy) { window.mvCopy(value); } else { input.select(); } }));
      box.appendChild(wrap);
    }
    var portal = state.sharing && state.sharing.portal_path;
    if (portal) { row("Where they answer", window.location.origin + portal); }
    else { box.appendChild(R.el("p", "muted", "Your IT team hasn't set up the vendor web address yet. Send the access code once they have.")); }
    row("Access code", result.token);
    box.appendChild(R.button("I've copied it", "ghost", function () { box.hidden = true; box.textContent = ""; }));
    window.mvReveal(box);
  }

  // ---- lists ----------------------------------------------------------------
  function loadInvitations(more) {
    var query = "/invitations?limit=100" + (more && state.after ? "&after=" + encodeURIComponent(state.after) : "");
    return R.call("GET", API + query).then(function (d) {
      state.invitations = more ? state.invitations.concat(d.items || []) : (d.items || []);
      state.after = d.next_after || null;
      document.getElementById("tpc-more").hidden = !state.after;
      render();
    });
  }
  function loadAll() {
    say("Loading…");
    var jobs = [
      R.call("GET", LIFE + "/assessments").then(function (d) { state.assessments = d.items || []; }).catch(function () { state.assessments = []; }),
      R.call("GET", LIFE + "/templates").then(function (d) { state.templates = d.items || []; }).catch(function () { state.templates = []; }),
      R.call("GET", "/api/v1/vendors").then(function (d) {
        (d.vendors || []).forEach(function (v) { state.vendors[v.id] = v.name; });
      }).catch(function () { /* names fall back to the stored words */ }),
    ];
    if (canAdmin) { jobs.push(R.call("GET", API + "/sharing").then(function (d) { state.sharing = d; }).catch(function () { state.sharing = null; })); }
    return Promise.all(jobs).then(function () {
      if (!canAudit) { say("Only auditors and administrators can see invitations."); render(); return; }
      return loadInvitations(false).then(function () { say("Up to date."); });
    }).catch(function (f) {
      fail("load the invitations")(f);
      // The list never stays on "Loading…": say what happened and offer a retry.
      var box = document.getElementById("tpc-invitations");
      box.textContent = "";
      box.appendChild(window.mvEmpty((window.LightworkI18n ? window.LightworkI18n.text("Invitations could not be loaded") : "Invitations could not be loaded"), R.errorText(f, "load the invitations"),
        { label: (window.LightworkI18n ? window.LightworkI18n.text("Try again") : "Try again"), onClick: loadAll }));
    });
  }

  function assessmentOf(inv) { return state.assessments.filter(function (a) { return a.assessment_id === inv.assessment_id; })[0]; }
  function render() {
    R.table(document.getElementById("tpc-invitations"), [
      { label: "Vendor", value: function (i) { return vendorName(i.vendor_ref); } },
      { label: "Questionnaire", value: function (i) { var t = state.templates.filter(function (x) { return x.template_id === i.template_id && x.version === i.template_version; })[0]; return t ? words(t.title_ref) : words(i.template_id); } },
      { label: "Answered by", value: function (i) { return words(i.respondent_ref); } },
      { label: "Status", value: function (i) { var s = STATUS[i.status] || [words(i.status), "idle"]; return R.badge(s[0], s[1]); } },
      { label: "Link works until", value: function (i) { return R.when(i.expires_at); } },
      { label: "Legal hold", value: function (i) { return i.legal_hold ? R.badge("On hold", "danger") : "No"; } },
    ], state.invitations, [
      { label: "Send a new link", kind: "primary", when: function (i) { return canAdmin && i.status === "active"; }, run: rotate },
      { label: "Ask for more information", when: function (i) { return canAdmin && i.status === "finalized"; }, run: followUp },
      { label: "Reopen for answers", kind: "primary", when: function (i) { return canAdmin && i.status === "follow_up_required"; }, run: reopen },
      { label: "Cancel invitation", kind: "danger", when: function (i) { return canAdmin && (i.status === "active" || i.status === "follow_up_required"); }, run: revoke },
      { label: "Place legal hold", when: function (i) { return canAdmin && !i.legal_hold; }, run: function (i) { hold(i, true); } },
      { label: "Lift legal hold", when: function (i) { return canAdmin && i.legal_hold; }, run: function (i) { hold(i, false); } },
    ], { text: "No invitations yet. Invite a vendor to answer an assessment's questions.", action: canAdmin ? { label: "Invite a vendor", run: openInvite } : null });
  }

  function expiryField(label) {
    var max = state.sharing ? state.sharing.limits.invitation_seconds : 86400;
    var list = dayChoices(max, [[1, "1 day"], [3, "3 days"], [7, "7 days"], [14, "14 days"], [30, "30 days"], [90, "90 days"]]);
    if (!list.length) { list = [[max / 86400, "As long as allowed"]]; }
    return { key: "expires", label: label || "The new link works for", type: "select", default: String(list[list.length - 1][0]),
      options: list.map(function (d) { return { value: String(d[0]), label: d[1] }; }) };
  }
  function rotate(i) {
    R.form("Send a new link to " + vendorName(i.vendor_ref), [expiryField()], "Create new link").then(function (v) {
      if (!v) { return; }
      return R.confirm("Create a new access code? The old one stops working straight away.", "Create new code").then(function (ok) {
        if (!ok) { return; }
        return R.call("POST", API + "/invitations/" + encodeURIComponent(i.invitation_id) + "/rotate",
          { expires_in_seconds: Math.round(Number(v.expires) * 86400), expected_revision: i.revision, idempotency_key: R.newKey() })
          .then(function (d) { showOnce(d, "New access code for " + vendorName(i.vendor_ref)); return loadInvitations(false); });
      });
    }).catch(fail("create a new link"));
  }
  function revoke(i) {
    R.form("Cancel the invitation for " + vendorName(i.vendor_ref), [{ key: "reason", label: "Reason", type: "select", default: REASONS[0].value, options: REASONS }], "Cancel invitation").then(function (v) {
      if (!v) { return; }
      return R.confirm("Cancel this invitation? The vendor's access code stops working and they can't submit answers.", "Cancel invitation").then(function (ok) {
        if (!ok) { return; }
        return R.call("POST", API + "/invitations/" + encodeURIComponent(i.invitation_id) + "/revoke",
          { reason_code: v.reason, expected_revision: i.revision, idempotency_key: R.newKey() })
          .then(function () { say("Invitation cancelled."); return loadInvitations(false); });
      });
    }).catch(fail("cancel the invitation"));
  }
  function followUp(i) {
    var a = assessmentOf(i);
    var t = a && templateOf(a);
    var questions = (i.allowed_question_ids || []);
    var prompts = {};
    ((t && t.questions) || []).forEach(function (q) { prompts[q.question_id] = words(q.prompt_ref); });
    var fields = questions.map(function (qid, n) { return { key: "q" + n, label: prompts[qid] || words(qid), type: "bool" }; });
    fields.push({ key: "reason", label: "Reason", type: "select", default: FOLLOW_UP_REASONS[0].value, options: FOLLOW_UP_REASONS });
    R.form("Which answers need more information?", fields, "Ask for more").then(function (v) {
      if (!v) { return; }
      var chosen = questions.filter(function (_q, n) { return v["q" + n]; });
      if (!chosen.length) { say("Choose at least one question."); return; }
      return R.call("POST", API + "/invitations/" + encodeURIComponent(i.invitation_id) + "/follow-up",
        { question_ids: chosen, reason_code: v.reason, expected_revision: i.revision, idempotency_key: R.newKey() })
        .then(function () { say("Marked as needing more information. Use Reopen for answers to send the vendor a new link."); return loadInvitations(false); });
    }).catch(fail("ask for more information"));
  }
  function reopen(i) {
    R.form("Reopen for " + vendorName(i.vendor_ref), [expiryField()], "Reopen").then(function (v) {
      if (!v) { return; }
      return R.call("POST", API + "/invitations/" + encodeURIComponent(i.invitation_id) + "/follow-up/reopen",
        { expires_in_seconds: Math.round(Number(v.expires) * 86400), expected_revision: i.revision, idempotency_key: R.newKey() })
        .then(function (d) { showOnce(d, "New access code for " + vendorName(i.vendor_ref)); return loadInvitations(false); });
    }).catch(fail("reopen the invitation"));
  }
  function hold(i, active) {
    R.form(active ? "Place a legal hold" : "Lift the legal hold", [{ key: "reason", label: "Reason", required: true }], active ? "Place hold" : "Lift hold").then(function (v) {
      if (!v) { return; }
      return R.confirm(active ? "Place a legal hold? The vendor's answers can't be deleted until it is lifted." : "Lift the legal hold? The answers can then be deleted when their keep period ends.", active ? "Place hold" : "Lift hold").then(function (ok) {
        if (!ok) { return; }
        return R.call("POST", API + "/invitations/" + encodeURIComponent(i.invitation_id) + "/legal-hold",
          { active: active, evidence_ref: ref(v.reason, "hold."), expected_revision: i.revision, idempotency_key: R.newKey() })
          .then(function () { say(active ? "Legal hold placed." : "Legal hold lifted."); return loadInvitations(false); });
      });
    }).catch(fail("change the legal hold"));
  }

  // ---- invite a vendor --------------------------------------------------------
  var panel = document.getElementById("tpc-invite-panel");
  var form = document.getElementById("tpc-invite-form");
  function F(name) { return form.elements.namedItem(name); }
  function fillSelect(select, list) {
    select.textContent = "";
    list.forEach(function (o) { var opt = R.el("option", "", o.label); opt.value = o.value; select.appendChild(opt); });
  }
  function selectedAssessment() { return state.assessments.filter(function (a) { return a.assessment_id === F("assessment").value; })[0]; }
  function syncRespondents() {
    var a = selectedAssessment();
    var seen = {};
    var list = [];
    Object.keys((a && a.assignments) || {}).forEach(function (q) {
      var who = a.assignments[q];
      if (!seen[who]) { seen[who] = true; list.push({ value: who, label: words(who) }); }
    });
    fillSelect(F("respondent"), list);
    syncQuestions();
  }
  function syncQuestions() {
    var a = selectedAssessment();
    var t = a && templateOf(a);
    var who = F("respondent").value;
    var host = document.getElementById("tpc-questions");
    host.textContent = "";
    ((t && t.questions) || []).forEach(function (q) {
      if (!a || a.assignments[q.question_id] !== who) { return; }
      var label = R.el("label");
      var cb = R.el("input"); cb.type = "checkbox"; cb.name = "question"; cb.value = q.question_id; cb.checked = true;
      label.appendChild(cb); label.appendChild(document.createTextNode(" " + words(q.prompt_ref)));
      host.appendChild(label);
    });
    if (!host.childNodes.length) { host.appendChild(R.el("p", "muted", "No questions are assigned to this person.")); }
  }
  function openInvite() {
    var usable = state.assessments.filter(function (a) { var t = templateOf(a); return t && t.state === "approved"; });
    if (!usable.length) { say("Start an assessment on the Third-party lifecycle page first. Its questions are what the vendor answers."); return; }
    var limits = (state.sharing && state.sharing.limits) || { invitation_seconds: 86400, retention_seconds: 31536000, max_artifacts: 20, max_artifact_bytes: 10485760 };
    fillSelect(F("assessment"), usable.map(function (a) { var t = templateOf(a); return { value: a.assessment_id, label: vendorName(a.vendor_ref) + " · " + words(t.title_ref) }; }));
    var exp = expiryField("Link works for");
    fillSelect(F("expires"), exp.options); F("expires").value = exp.default;
    var keep = dayChoices(limits.retention_seconds, [[90, "3 months"], [365, "1 year"], [1095, "3 years"], [2555, "7 years"]]);
    if (!keep.length) { keep = [[Math.floor(limits.retention_seconds / 86400), "As long as allowed"]]; }
    fillSelect(F("keep"), keep.map(function (d) { return { value: String(d[0]), label: d[1] }; })); F("keep").value = String(keep[keep.length - 1][0]);
    var files = [0, 5, 10, 20, 50, 100].filter(function (n) { return n <= limits.max_artifacts; });
    fillSelect(F("max_files"), files.map(function (n) { return { value: String(n), label: n === 0 ? "No documents" : n + " documents" }; })); F("max_files").value = String(files[files.length - 1]);
    var mb = [1, 5, 10, 25, 50, 100].filter(function (n) { return n * 1048576 <= limits.max_artifact_bytes; });
    if (!mb.length) { mb = [Math.max(0, Math.floor(limits.max_artifact_bytes / 1048576))]; }
    fillSelect(F("max_size"), mb.map(function (n) { return { value: String(n), label: n + " MB" }; })); F("max_size").value = String(mb[mb.length - 1]);
    state.notice = null;
    document.getElementById("tpc-notice-name").textContent = "No file chosen yet. Choose the notice file to attach.";
    syncRespondents();
    panel.hidden = false;
    window.mvReveal(panel);
    F("assessment").focus();
  }
  F("assessment").addEventListener("change", syncRespondents);
  F("respondent").addEventListener("change", syncQuestions);
  document.getElementById("tpc-invite").addEventListener("click", function () {
    if (!canAdmin) { say("Only administrators can invite vendors."); return; }
    openInvite();
  });
  document.getElementById("tpc-invite-cancel").addEventListener("click", function () { panel.hidden = true; });
  document.getElementById("tpc-notice").addEventListener("click", function () {
    R.pickFile(".pdf,.txt,.html,.htm,.md,.doc,.docx").then(function (file) {
      if (!file) { return; }
      document.getElementById("tpc-notice-name").textContent = "Reading " + file.name + "…";
      return R.fingerprint(file).then(function (d) {
        state.notice = { ref: ref(file.name.replace(/\.[^.]+$/, ""), "notice."), sha: d.sha256, name: file.name };
        document.getElementById("tpc-notice-name").textContent = file.name;
      });
    }).catch(function (f) { document.getElementById("tpc-notice-name").textContent = R.errorText(f, "read the notice file"); });
  });
  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var a = selectedAssessment();
    var questions = Array.prototype.map.call(form.querySelectorAll('input[name="question"]:checked'), function (c) { return c.value; });
    var kinds = Array.prototype.map.call(form.querySelectorAll('input[name="kind"]:checked'), function (c) { return c.value; });
    if (!a) { say("Choose an assessment."); return; }
    if (!questions.length) { say("Choose at least one question for the vendor."); return; }
    if (!state.notice) { say("Choose the notice file the vendor will see."); return; }
    var body = {
      invitation_id: R.newId("invitation"),
      assessment_id: a.assessment_id,
      respondent_ref: F("respondent").value,
      allowed_question_ids: questions,
      notice_ref: state.notice.ref,
      notice_sha256: state.notice.sha,
      artifact_policy: { allowed_kinds: kinds, maximum_artifacts: Number(F("max_files").value), maximum_total_bytes: Number(F("max_size").value) * 1048576 },
      expires_in_seconds: Math.round(Number(F("expires").value) * 86400),
      retention_seconds: Math.round(Number(F("keep").value) * 86400),
      idempotency_key: R.newKey(),
    };
    R.call("POST", API + "/invitations", body).then(function (d) {
      panel.hidden = true;
      showOnce(d, "Invitation for " + vendorName(a.vendor_ref) + " created");
      return loadInvitations(false);
    }).catch(fail("create the invitation"));
  });
  document.getElementById("tpc-more").addEventListener("click", function () { loadInvitations(true).catch(fail("load more invitations")); });

  // ---- administrator tools ---------------------------------------------------
  var adminResult = document.getElementById("tpc-admin-result");
  document.getElementById("tpc-purge-before").value = R.isoDateIn(0);
  document.getElementById("tpc-integrity").addEventListener("click", function () {
    R.call("GET", API + "/integrity").then(function () {
      adminResult.textContent = "No changes found in the invitation records.";
    }, function (f) { adminResult.textContent = R.errorText(f, "check the records"); });
  });
  document.getElementById("tpc-purge").addEventListener("click", function () {
    var before = R.toEpoch(document.getElementById("tpc-purge-before").value);
    if (!before) { adminResult.textContent = "Choose a date first."; return; }
    R.confirm("Delete vendor answers whose keep period ended before this date? Answers on legal hold are kept. This can't be undone.", "Delete").then(function (ok) {
      if (!ok) { return; }
      R.call("POST", API + "/purge", { before: before, idempotency_key: R.newKey() }).then(function () {
        adminResult.textContent = "Expired data was deleted."; return loadInvitations(false);
      }, function (f) { adminResult.textContent = R.errorText(f, "clean up expired data"); });
    });
  });

  loadAll();
})();
