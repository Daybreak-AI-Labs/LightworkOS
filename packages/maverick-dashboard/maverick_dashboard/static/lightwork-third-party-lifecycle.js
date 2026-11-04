// Third-party lifecycle page: questionnaires, assessments, tracked vendors
// and offboarding plans load as lists on arrival; every change is a row
// button or a guided form. Record references, versions, request keys and
// evidence fingerprints are carried from the chosen row or made here, never
// typed by a person.
(function () {
  "use strict";
  var root = document.getElementById("tpl-root");
  if (!root || !window.LwRecords) { return; }
  var R = window.LwRecords;
  var API = root.getAttribute("data-api") || "/api/v1/third-party/lifecycle";
  var canAdmin = root.getAttribute("data-can-admin") === "true";
  var canAudit = root.getAttribute("data-can-audit") === "true";
  var statusLine = document.getElementById("tpl-status");

  var state = { me: "", namedSignin: false, localOwnerSetupAvailable: false, people: [], peopleByRef: {}, vendors: [], templates: [], assessments: [], lifecycles: [], plans: [] };

  var AREAS = [["security", "Security"], ["privacy", "Privacy"], ["compliance", "Compliance"], ["operational", "Operations"], ["ethics", "Ethics"], ["ai", "AI"]];
  var ANSWER_TYPES = [["boolean", "Yes or no"], ["single_choice", "Pick one choice"], ["multi_choice", "Pick several choices"], ["integer", "A number"], ["text_ref", "A document"]];
  var SEVERITIES = [["low", "Low"], ["medium", "Medium"], ["high", "High"], ["critical", "Critical"]];
  var ROUTES = { not_evaluated: "Not checked yet", incomplete: "Waiting for answers", owner_review: "Ready for owner review", remediation_required: "Fixes needed", escalation_required: "Escalate" };
  var STAGES = { onboarding: "Onboarding", active: "Active", suspended: "Suspended", offboarding: "Offboarding", offboarded: "Offboarded" };
  var DEP_KINDS = [["system", "A system they run for us"], ["access", "Access they have"], ["data", "Data they hold"], ["contract", "A contract"]];
  var OFF_ACTIONS = [["revoke_access", "Remove their access"], ["deprovision_account", "Close their accounts"], ["terminate_integration", "Turn off the connection"], ["archive_data", "Archive or delete the data"], ["notify_owner", "Tell the owner"]];
  var KEEP = [[365, "1 year"], [1095, "3 years"], [2555, "7 years"], [3650, "10 years"]];

  // Words become a reference Lightwork can store ("Do you encrypt data?" ->
  // "Do-you-encrypt-data"), and read back as words.
  function ref(text, prefix) {
    var s = String(text || "").normalize ? String(text || "").normalize("NFKD") : String(text || "");
    s = s.replace(/[^A-Za-z0-9 _.-]+/g, "").trim().replace(/\s+/g, "-").replace(/^[^A-Za-z0-9]+/, "");
    s = s.slice(0, 120 - (prefix ? prefix.length : 0));
    return (prefix || "") + (s || R.newId("item"));
  }
  function words(value) {
    if (value === null || value === undefined || value === "") { return ""; }
    var s = String(value);
    if (state.peopleByRef[s]) { return state.peopleByRef[s]; }
    if (/^(tpl|tpc)-principal-/.test(s)) { return "Another person"; }
    if (/^vendor-contact\./.test(s)) { return "The vendor's contact at " + vendorName(s.slice(15)); }
    s = s.replace(/^(vendor-contact|note|file|vendor|dep|task|q|t)[.:]/, "");
    s = s.replace(/[-_.:]+/g, " ").trim();
    return s.charAt(0).toUpperCase() + s.slice(1);
  }
  function vendorName(refValue) {
    var match = state.vendors.filter(function (v) { return v.value === refValue; })[0];
    return match ? match.label : words(refValue);
  }
  function days(n) { return Number(n) * 86400; }
  function say(text) { window.mvStatus(statusLine, text); }
  function fail(action) { return function (f) { say(R.errorText(f, action)); if (window.mvToast) { window.mvToast(R.errorText(f, action), { error: true }); } }; }
  function api(method, path, body) { return R.call(method, API + path, body); }
  function el(tag, cls, text) { return R.el(tag, cls, text); }

  function options(list) { return list.map(function (p) { return { value: String(p[0]), label: p[1] }; }); }
  function peopleOptions() { return state.people.map(function (p) { return { value: p.value, label: p.label }; }); }

  // Evidence for an answer or task: a chosen file's fingerprint, or the
  // fingerprint of the person's written note. Computed on the server.
  function evidenceFrom(file, note) {
    var body = file || new Blob([String(note || "")], { type: "text/plain" });
    var name = file ? ref(file.name.replace(/\.[^.]+$/, ""), "file.") : ref(String(note || "note").slice(0, 60), "note.");
    return R.fingerprint(body).then(function (d) { return { sha: d.sha256, ref: name }; });
  }
  function askEvidence(title, okText, extra) {
    var fields = (extra || []).concat([{ key: "note", label: "What shows this is done? (a short note)", required: false }]);
    return R.form(title, fields.concat([{ key: "attach", label: "Also attach a file", type: "bool" }]), okText).then(function (v) {
      if (!v) { return null; }
      var pick = v.attach ? R.pickFile() : Promise.resolve(null);
      return pick.then(function (file) {
        if (!file && !v.note) { throw Object.assign(new Error("plain"), { plain: "Write a short note or attach a file." }); }
        return evidenceFrom(file, v.note).then(function (e) { v.evidence = e; return v; });
      });
    });
  }
  function plainFail(action) {
    return function (f) { if (f && f.plain) { say(f.plain); } else { fail(action)(f); } };
  }

  // ---- loading -------------------------------------------------------------
  function loadPeople() {
    return api("GET", "/people").then(function (d) {
      state.me = d.me; state.people = d.items || [];
      state.namedSignin = d.named_signin === true;
      state.localOwnerSetupAvailable = d.local_owner_setup_available === true;
      document.getElementById("tpl-new-template").disabled = !state.namedSignin;
      state.peopleByRef = {};
      state.people.forEach(function (p) { state.peopleByRef[p.value] = p.label; });
    }).catch(function () { state.people = []; state.namedSignin = false; document.getElementById("tpl-new-template").disabled = true; });
  }
  function loadVendors() {
    return R.call("GET", "/api/v1/vendors").then(function (d) {
      state.vendors = (d.vendors || []).map(function (v) { return { value: ref(v.id || v.name, ""), label: v.name }; });
    }).catch(function () { state.vendors = []; });
  }
  function loadAll() {
    say("Loading…");
    return Promise.all([
      api("GET", "/templates").then(function (d) { state.templates = d.items || []; }),
      api("GET", "/assessments").then(function (d) { state.assessments = d.items || []; }),
      api("GET", "/lifecycles").then(function (d) { state.lifecycles = d.items || []; }),
      api("GET", "/offboarding").then(function (d) { state.plans = d.items || []; }),
    ]).then(function () {
      renderTemplates(); renderAssessments(); renderLifecycles(); renderPlans(); renderReviewerGuidance();
      say("Up to date.");
    }).catch(fail("load the lifecycle records"));
  }

  // ---- questionnaires ------------------------------------------------------
  function latestVersion(templateId) {
    return state.templates.filter(function (t) { return t.template_id === templateId; })
      .reduce(function (m, t) { return Math.max(m, t.version); }, 0);
  }
  function renderReviewerGuidance() {
    var panel = document.getElementById("tpl-reviewer-guidance");
    var message = document.getElementById("tpl-reviewer-message");
    var signin = document.getElementById("tpl-signin-link");
    var invite = document.getElementById("tpl-invite-link");
    var pending = state.templates.filter(function (t) { return t.state === "pending_approval"; });
    var oldAuthor = pending.some(function (t) { return t.needs_named_author === true; }) || state.plans.some(function (p) { return p.needs_named_initiator === true && p.state !== "completed"; });
    var mine = pending.some(function (t) { return t.authored_by === state.me; }) || state.plans.some(function (p) { return p.initiated_by === state.me && p.state !== "completed"; });
    panel.hidden = state.namedSignin && !oldAuthor && !mine;
    signin.hidden = state.namedSignin;
    invite.hidden = !state.namedSignin || oldAuthor;
    signin.href = state.localOwnerSetupAvailable ? "/auth/local-owner" : "/settings/all?id=auth.oidc.enable";
    message.textContent = !state.namedSignin
      ? "Questionnaire approvals need two people with their own sign-ins. " + (state.localOwnerSetupAvailable ? "Set up the owner account on this computer" : "Set up your company sign-in") + ", then add another administrator in Users."
      : oldAuthor
        ? "A review started before individual sign-ins cannot receive a second-person approval safely. Write a new questionnaire version or start a new offboarding plan while signed in, then ask another administrator to approve it."
        : "You cannot approve a review you started. Add another administrator in Users, give them this workspace, and ask them to approve it from this page.";
  }
  function renderTemplates() {
    R.table(document.getElementById("tpl-templates"), [
      { label: "Questionnaire", value: function (t) { return words(t.title_ref); } },
      { label: "Version", value: function (t) { return t.version; } },
      { label: "Questions", value: function (t) { return (t.questions || []).length; } },
      { label: "Status", value: function (t) { return R.badge(t.state === "approved" ? "Approved" : t.state === "retired" ? "Retired" : "Waiting for approval", t.state === "approved" ? "ok" : "warn"); } },
      { label: "Written by", value: function (t) { return words(t.authored_by); } },
      { label: "Next step", value: function (t) { return t.state === "approved" ? "Ready for assessments" : t.state === "retired" ? "No longer used" : t.needs_named_author ? "Write a new version after sign-in" : t.authored_by === state.me ? "Another administrator must approve" : "A different administrator can approve"; } },
    ], state.templates, [
      { label: "Read questionnaire", run: function (t) { reviewTemplate(t, false); } },
      { label: "Approve", kind: "primary", when: function (t) { return canAdmin && state.namedSignin && state.me && !t.needs_named_author && t.authored_by !== state.me && t.state === "pending_approval"; }, run: approveTemplate },
      { label: "New version", when: function (t) { return state.namedSignin && t.version === latestVersion(t.template_id); }, run: function (t) { openTemplateForm(t); } },
    ], { text: "No questionnaires yet. Write your first one; a different administrator approves it before use.", action: state.namedSignin ? { label: "New questionnaire", run: function () { openTemplateForm(null); } } : null });
  }
  function approveTemplate(t) {
    reviewTemplate(t, true).then(function (current) {
      if (!current) { return; }
      api("POST", "/templates/" + encodeURIComponent(t.template_id) + "/versions/" + t.version + "/approve",
        { expected_revision: current.revision, idempotency_key: R.newKey() }).then(function () { say("Questionnaire approved."); loadAll(); }, fail("approve the questionnaire"));
    });
  }

  function questionnaireText(t) {
    var labels = { question_id: "Question", domain: "Area", prompt_ref: "Question wording", response_type: "Answer type", required: "Must be answered", options: "Choices", condition: "Only ask when", operator: "Comparison", value: "Answer", risk_rules: "Risk checks", severity: "Risk level", reason_code: "Reason", recommendation_code: "Recommended next step", task_code: "Follow-up task", minimum_severity: "Minimum risk level" };
    var count = 0;
    var meanings = {boolean: "Yes or no", single_choice: "Choose one answer", multi_choice: "Choose all that apply", integer: "Whole number", text_ref: "Written answer", equals: "Is", not_equals: "Is not", contains: "Includes", in: "Is one of", greater_or_equal: "Is at least", less_or_equal: "Is at most"};
    function lines(value, indent, field) {
      if (++count > 30000 || indent.length > 30) throw new Error("The complete questionnaire could not be shown. Nothing was approved.");
      if (Array.isArray(value)) return value.length ? value.map(function (v, i) { return indent + (i + 1) + ".\n" + lines(v, indent + "  ", field); }).join("\n") : indent + "None";
      if (value && typeof value === "object") return Object.keys(value).map(function (key) {
        if (!labels[key]) throw new Error("This questionnaire has a rule this view cannot explain. Nothing was approved.");
        return indent + labels[key] + ":\n" + lines(value[key], indent + "  ", key);
      }).join("\n");
      return indent + (value === null ? "No condition" : value === true ? "Yes" : value === false ? "No" : typeof value === "number" ? String(value) : field === "value" ? String(value) : (field === "response_type" || field === "operator") && meanings[value] ? meanings[value] : words(value));
    }
    return words(t.title_ref) + " · version " + t.version + "\n\nQuestions\n" + lines(t.questions, "") + "\n\nFollow-up rules\n" + lines(t.mitigation_rules, "") + "\n\nWritten by: " + words(t.authored_by) + "\nKeep this version until: " + R.when(t.retained_until);
  }

  function reviewTemplate(t, approve) {
    var generation = reviewGeneration;
    return api("GET", "/templates/" + encodeURIComponent(t.template_id) + "/versions/" + t.version).then(function (current) {
      if (generation !== reviewGeneration) return null;
      if (current.revision !== t.revision || current.integrity_sha256 !== t.integrity_sha256) { loadAll(); throw new Error("The questionnaire changed. Read the current version before approving."); }
      var text = questionnaireText(current) + (approve ? "\n\nApprove this exact questionnaire for assessments? You cannot approve your own work." : "\n\nThis is a read-only view. No approval will be recorded.");
      return fullReview(text, approve ? "Approve this questionnaire" : "Close").then(function (ok) { return approve && ok && generation === reviewGeneration ? current : null; });
    }).catch(function (error) { say(error.status ? R.errorText(error, "read the questionnaire") : error.message); return null; });
  }

  var reviewGeneration = 0, reviewing = false;
  function clearReview() {
    reviewGeneration += 1;
    if (reviewing) { var cancel = document.getElementById("mv-confirm-cancel"); if (cancel) cancel.click(); }
  }
  [window, document].forEach(function (target) { ["lightwork:workspace-changed", "lightwork:account-context-changed"].forEach(function (name) { target.addEventListener(name, clearReview); }); });
  function fullReview(text, label) {
    var dialog = document.getElementById("mv-confirm"), message = document.getElementById("mv-confirm-msg");
    if (dialog && dialog.open) return Promise.resolve(false);
    var previous = message ? message.style.cssText : "";
    var answer = R.confirm(text, label); reviewing = true;
    if (message) { message.style.whiteSpace = "pre-wrap"; message.style.overflowWrap = "anywhere"; message.style.maxHeight = "60vh"; message.style.overflowY = "auto"; }
    return answer.finally(function () { reviewing = false; if (message) { message.textContent = ""; message.style.cssText = previous; } });
  }

  var templateForm = document.getElementById("tpl-template-form");
  var questionsBox = document.getElementById("tpl-questions");
  var editing = null;

  function select(name, list, value, label) {
    var wrap = el("label", "", label);
    var s = el("select", "select");
    s.name = name;
    list.forEach(function (p) { var o = el("option", "", p[1]); o.value = p[0]; s.appendChild(o); });
    if (value !== undefined && value !== null) { s.value = value; }
    wrap.appendChild(s);
    return wrap;
  }
  function input(name, label, value, placeholder) {
    var wrap = el("label", "", label);
    var i = el("input", "input");
    i.name = name; i.value = value || ""; if (placeholder) { i.placeholder = placeholder; }
    wrap.appendChild(i);
    return wrap;
  }
  function addQuestion(q) {
    var box = el("div", "tpl-question");
    var grid = el("div", "tpl-grid");
    grid.appendChild(input("prompt", "Question", q ? words(q.prompt_ref) : "", "For example: Do you encrypt stored data"));
    grid.appendChild(select("domain", AREAS, q ? q.domain : "security", "Area"));
    grid.appendChild(select("response_type", ANSWER_TYPES, q ? q.response_type : "boolean", "Answer type"));
    var choices = input("choices", "Choices (separate with commas)", q ? (q.options || []).map(words).join(", ") : "", "For example: Always, Sometimes, Never");
    grid.appendChild(choices);
    var req = el("label", "", ""); var cb = el("input"); cb.type = "checkbox"; cb.name = "required"; cb.checked = q ? !!q.required : true;
    req.style.display = "flex"; req.style.gap = ".4rem"; req.appendChild(cb); req.appendChild(document.createTextNode("Must be answered"));
    grid.appendChild(req);
    var rule = q && q.risk_rules && q.risk_rules[0];
    grid.appendChild(input("flag_when", "Flag a risk when the answer is (optional)", rule ? words(rule.value) : "", "For example: No"));
    grid.appendChild(select("severity", SEVERITIES, rule ? rule.severity : "medium", "How serious is that risk"));
    grid.appendChild(input("fix", "What should happen then (optional)", "", "For example: Ask for their encryption policy"));
    box.appendChild(grid);
    var remove = R.button("Remove question", "ghost", function () { box.remove(); });
    box.appendChild(remove);
    function sync() {
      var t = box.querySelector('[name="response_type"]').value;
      choices.hidden = !(t === "single_choice" || t === "multi_choice");
    }
    box.querySelector('[name="response_type"]').addEventListener("change", sync);
    sync();
    questionsBox.appendChild(box);
  }
  function openTemplateForm(from) {
    editing = from;
    questionsBox.textContent = "";
    templateForm.reset();
    templateForm.hidden = false;
    document.getElementById("tpl-template-form-title").textContent = from ? "New Version of " + words(from.title_ref) : "New questionnaire";
    templateForm.elements.namedItem("title").value = from ? words(from.title_ref) : "";
    templateForm.elements.namedItem("title").disabled = !!from;
    (from ? from.questions : [null]).forEach(addQuestion);
    window.mvReveal(templateForm);
    templateForm.elements.namedItem("title").focus();
  }
  function parseValue(type, text, choiceRefs) {
    var t = String(text || "").trim();
    if (!t) { return undefined; }
    if (type === "boolean") { return /^(y|yes|true)$/i.test(t); }
    if (type === "integer") { var n = parseInt(t, 10); return isFinite(n) ? n : undefined; }
    if (type === "single_choice" || type === "multi_choice") {
      var match = choiceRefs.filter(function (c) { return words(c).toLowerCase() === t.toLowerCase(); })[0];
      return match || ref(t, "");
    }
    return ref(t, "");
  }
  templateForm.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var title = templateForm.elements.namedItem("title").value.trim();
    if (!title) { say("Give the questionnaire a name."); return; }
    var mitigations = [];
    var questions = [];
    var used = {};
    questionsBox.querySelectorAll(".tpl-question").forEach(function (box, index) {
      var prompt = box.querySelector('[name="prompt"]').value.trim();
      if (!prompt) { return; }
      var type = box.querySelector('[name="response_type"]').value;
      var qid = ref(prompt, "").slice(0, 60);
      if (used[qid]) { qid = qid + "-" + (index + 1); }
      used[qid] = true;
      var choices = (type === "single_choice" || type === "multi_choice")
        ? box.querySelector('[name="choices"]').value.split(",").map(function (c) { return c.trim(); }).filter(Boolean).map(function (c) { return ref(c, ""); })
        : [];
      var q = { question_id: qid, domain: box.querySelector('[name="domain"]').value, prompt_ref: ref(prompt, ""),
        response_type: type, required: box.querySelector('[name="required"]').checked, options: choices, condition: null, risk_rules: [] };
      var flag = parseValue(type, box.querySelector('[name="flag_when"]').value, choices);
      if (flag !== undefined) {
        var severity = box.querySelector('[name="severity"]').value;
        var reason = ref(qid, "risk-").slice(0, 120);
        q.risk_rules.push({ operator: type === "multi_choice" ? "contains" : "equals", value: flag, severity: severity, reason_code: reason });
        var fix = box.querySelector('[name="fix"]').value.trim();
        if (fix) { mitigations.push({ reason_code: reason, recommendation_code: ref(fix, ""), task_code: ref(fix, "task."), minimum_severity: severity }); }
      }
      questions.push(q);
    });
    if (!questions.length) { say("Add at least one question."); return; }
    var bad = questions.filter(function (q) { return (q.response_type === "single_choice" || q.response_type === "multi_choice") && !q.options.length; })[0];
    if (bad) { say("Add the choices for \"" + words(bad.prompt_ref) + "\"."); return; }
    var templateId = editing ? editing.template_id : ref(title, "").toLowerCase().slice(0, 80);
    var body = { title_ref: editing ? editing.title_ref : ref(title, ""), questions: questions, mitigation_rules: mitigations,
      expected_latest_version: latestVersion(templateId), idempotency_key: R.newKey() };
    api("PUT", "/templates/" + encodeURIComponent(templateId), body).then(function () {
      templateForm.hidden = true;
      say("Questionnaire saved. A different administrator now needs to approve it.");
      loadAll();
    }, fail("save the questionnaire"));
  });
  document.getElementById("tpl-add-question").addEventListener("click", function () { addQuestion(null); });
  document.getElementById("tpl-template-cancel").addEventListener("click", function () { templateForm.hidden = true; });
  document.getElementById("tpl-new-template").addEventListener("click", function () { openTemplateForm(null); });

  // ---- assessments ---------------------------------------------------------
  function templateOf(a) {
    return state.templates.filter(function (t) { return t.template_id === a.template_id && t.version === a.template_version; })[0];
  }
  function renderAssessments() {
    R.table(document.getElementById("tpl-assessments"), [
      { label: "Vendor", value: function (a) { return vendorName(a.vendor_ref); } },
      { label: "Questionnaire", value: function (a) { var t = templateOf(a); return t ? words(t.title_ref) : words(a.template_id); } },
      { label: "Owner", value: function (a) { return words(a.owner_ref); } },
      { label: "Answered", value: function (a) { return Object.keys(a.responses || {}).length + " of " + Object.keys(a.assignments || {}).length; } },
      { label: "Result", value: function (a) { return R.badge(ROUTES[a.route] || words(a.route), a.route === "owner_review" ? "ok" : a.route === "not_evaluated" ? "idle" : "warn"); } },
      { label: "Highest risk", value: function (a) { return a.highest_severity ? words(a.highest_severity) : "None"; } },
      { label: "Updated", value: function (a) { return R.when(a.updated_at); } },
    ], state.assessments, [
      { label: "Open", kind: "primary", run: openAssessment },
      { label: "Check answers", run: evaluate },
      { label: "Save a record", run: function (a) { exportRecord("/assessments/", a.assessment_id); } },
    ], { text: "No assessments yet. Start one for a vendor using an approved questionnaire.", action: { label: "New assessment", run: newAssessment } });
  }
  function evaluate(a) {
    api("POST", "/assessments/" + encodeURIComponent(a.assessment_id) + "/evaluate", { expected_revision: a.revision, idempotency_key: R.newKey() })
      .then(function (d) {
        var route = (d.assessment && d.assessment.route) || d.route;
        say("Checked. Result: " + (ROUTES[route] || words(route)) + ".");
        loadAll();
      }, fail("check the answers"));
  }
  function exportRecord(kind, id) {
    R.form("Save a record of this", [{ key: "keep", label: "Keep the record for", type: "select", default: "2555", options: options(KEEP) }], "Save").then(function (v) {
      if (!v) { return; }
      api("PUT", kind + encodeURIComponent(id) + "/exports/" + encodeURIComponent(R.newId("record")), { retention_seconds: days(v.keep), idempotency_key: R.newKey() })
        .then(function (d) { R.download("lifecycle-record-" + id + ".json", d.body || d); say("Record saved and downloaded."); }, fail("save the record"));
    });
  }
  function newAssessment() {
    var approved = state.templates.filter(function (t) { return t.state === "approved"; });
    if (!approved.length) { say("A different administrator needs to approve a questionnaire first. Open Users to invite a reviewer."); return; }
    if (!state.vendors.length) { say('Register this vendor in Privacy first, then return to assess the same registered identity.'); return; }
    var vendorOpts = state.vendors;
    var selectedVendor = new URLSearchParams(window.location.search).get('registered_vendor');
    var answererOpts = [{ value: "vendor", label: "The vendor, through an invitation link" }].concat(peopleOptions());
    R.form("New assessment", [
      { key: "vendor", label: "Registered vendor", type: "select", default: vendorOpts.some(function (row) { return row.value === selectedVendor; }) ? selectedVendor : vendorOpts[0].value, options: vendorOpts },
      { key: "template", label: "Questionnaire", type: "select", required: true, default: approved[0].template_id + "@" + approved[0].version,
        options: approved.map(function (t) { return { value: t.template_id + "@" + t.version, label: words(t.title_ref) + " (version " + t.version + ")" }; }) },
      { key: "owner", label: "Owner", type: "select", default: state.me, options: peopleOptions() },
      { key: "answerer", label: "Who answers the questions", type: "select", default: "vendor", options: answererOpts },
      { key: "keep", label: "Keep records for", type: "select", default: "2555", options: options(KEEP) },
    ], "Start assessment").then(function (v) {
      if (!v) { return; }
      var vendorRef = v.vendor;
      if (!state.vendors.some(function (row) { return row.value === vendorRef; })) { say("Choose the actual registered vendor."); return; }
      var parts = v.template.split("@");
      var template = state.templates.filter(function (t) { return t.template_id === parts[0] && String(t.version) === parts[1]; })[0];
      var respondent = v.answerer === "vendor" ? ("vendor-contact." + vendorRef).slice(0, 128) : v.answerer;
      var assignments = {};
      template.questions.forEach(function (q) { assignments[q.question_id] = respondent; });
      var id = R.newId("assessment");
      api("PUT", "/assessments/" + encodeURIComponent(id), {
        vendor_ref: vendorRef, template_id: template.template_id, template_version: template.version,
        owner_ref: v.owner || state.me, respondent_assignments: assignments, retention_seconds: days(v.keep), idempotency_key: R.newKey(),
      }).then(function () { say("Assessment started."); loadAll(); }, fail("start the assessment"));
    });
  }
  document.getElementById("tpl-new-assessment").addEventListener("click", newAssessment);

  function answerText(q, response) {
    if (!response) { return "Not answered"; }
    var v = response.value;
    if (q.response_type === "boolean") { return v ? "Yes" : "No"; }
    if (Array.isArray(v)) { return v.map(words).join(", "); }
    return words(v);
  }
  function openAssessment(a) {
    var box = document.getElementById("tpl-assessment-detail");
    var template = templateOf(a);
    box.hidden = false; box.textContent = "";
    box.appendChild(el("h3", "", vendorName(a.vendor_ref) + " · " + (template ? words(template.title_ref) : "Assessment")));
    if (!template) { box.appendChild(el("p", "muted", "The questionnaire for this assessment could not be found. Refresh the page to see the latest.")); return; }
    var mine = Object.keys(a.assignments || {}).some(function (k) { return a.assignments[k] === state.me; });
    box.appendChild(el("p", "muted", mine ? "You can answer the questions assigned to you." :
      "The questions are answered by " + words(a.assignments[Object.keys(a.assignments)[0]]) + ". Send them an invitation from the Third-party collaboration page."));
    R.table(box.appendChild(el("div")), [
      { label: "Question", value: function (q) { return words(q.prompt_ref); } },
      { label: "Area", value: function (q) { return words(q.domain); } },
      { label: "Answer", value: function (q) { return answerText(q, (a.responses || {})[q.question_id]); } },
    ], template.questions, [
      { label: "Answer", kind: "primary", when: function (q) { return a.assignments[q.question_id] === state.me; }, run: function (q) { answer(a, q); } },
    ]);
    box.appendChild(el("h4", "", "Follow-up tasks"));
    var recs = (a.recommendations || []).filter(function (r) { return !(a.tasks || []).some(function (t) { return t.reason_code === r.reason_code; }); });
    var taskRows = (a.tasks || []).map(function (t) { return Object.assign({ existing: true }, t); })
      .concat(recs.map(function (r) { return { existing: false, task_id: r.task_code, reason_code: r.reason_code, status: "suggested", recommendation: r.recommendation_code }; }));
    R.table(box.appendChild(el("div")), [
      { label: "Task", value: function (t) { return words(t.task_id); } },
      { label: "Status", value: function (t) { return R.badge(t.status === "suggested" ? "Suggested" : words(t.status), t.status === "completed" ? "ok" : t.status === "waived" ? "idle" : "warn"); } },
      { label: "Assigned to", value: function (t) { return t.assignee_ref ? words(t.assignee_ref) : "—"; } },
      { label: "Due", value: function (t) { return t.due_at ? R.day(t.due_at) : "—"; } },
    ], taskRows, [
      { label: "Create task", kind: "primary", when: function (t) { return !t.existing && a.owner_ref === state.me; }, run: function (t) { setTask(a, t, "open"); } },
      { label: "Mark done", when: function (t) { return t.existing && t.status === "open" && a.owner_ref === state.me; }, run: function (t) { setTask(a, t, "completed"); } },
      { label: "Not needed", when: function (t) { return t.existing && t.status === "open" && a.owner_ref === state.me; }, run: function (t) { setTask(a, t, "waived"); } },
      { label: "Reopen", when: function (t) { return t.existing && t.status !== "open" && a.owner_ref === state.me; }, run: function (t) { setTask(a, t, "open"); } },
    ], { text: "No follow-up tasks. Use Check answers to see what needs fixing." });
    window.mvReveal(box);
  }
  function answer(a, q) {
    var field;
    if (q.response_type === "boolean") { field = { key: "value", label: words(q.prompt_ref), type: "select", required: true, default: "yes", options: [{ value: "yes", label: "Yes" }, { value: "no", label: "No" }] }; }
    else if (q.response_type === "single_choice") { field = { key: "value", label: words(q.prompt_ref), type: "select", required: true, default: q.options[0], options: q.options.map(function (o) { return { value: o, label: words(o) }; }) }; }
    else if (q.response_type === "integer") { field = { key: "value", label: words(q.prompt_ref), type: "number", required: true }; }
    else if (q.response_type === "multi_choice") { field = null; }
    else { field = { key: "value", label: words(q.prompt_ref) + " (name of the document)", required: true }; }
    var fields = field ? [field] : q.options.map(function (o, i) { return { key: "opt" + i, label: words(o), type: "bool" }; });
    askEvidence("Answer: " + words(q.prompt_ref), "Save answer", fields).then(function (v) {
      if (!v) { return; }
      var value;
      if (q.response_type === "boolean") { value = v.value === "yes"; }
      else if (q.response_type === "integer") { value = parseInt(v.value, 10); }
      else if (q.response_type === "multi_choice") { value = q.options.filter(function (_o, i) { return v["opt" + i]; }); }
      else if (q.response_type === "text_ref") { value = ref(v.value, "doc."); }
      else { value = v.value; }
      return api("PUT", "/assessments/" + encodeURIComponent(a.assessment_id) + "/responses/" + encodeURIComponent(q.question_id), {
        value: value, evidence_sha256: v.evidence.sha, evidence_refs: [v.evidence.ref], expected_revision: a.revision, idempotency_key: R.newKey(),
      }).then(function (updated) { say("Answer saved."); return loadAll().then(function () { openAssessment(updated.assessment_id ? updated : a); }); });
    }).catch(plainFail("save the answer"));
  }
  function setTask(a, t, status) {
    var needsEvidence = status === "completed" || status === "waived";
    var extra = [
      { key: "assignee", label: "Assigned to", type: "select", default: t.assignee_ref || state.me, options: peopleOptions() },
      { key: "due", label: "Due date", type: "date", required: true, default: t.due_at ? new Date(t.due_at * 1000).toISOString().slice(0, 10) : R.isoDateIn(30) },
    ];
    var ask = needsEvidence ? askEvidence(status === "completed" ? "Mark the task done" : "Mark the task as not needed", "Save", extra)
      : R.form(t.existing ? "Reopen the task" : "Create the task", extra, "Save");
    ask.then(function (v) {
      if (!v) { return; }
      var body = { status: status, reason_code: t.reason_code, assignee_ref: v.assignee || state.me, due_at: R.toEpoch(v.due),
        expected_revision: a.revision, idempotency_key: R.newKey() };
      if (v.evidence) { body.evidence_sha256 = v.evidence.sha; body.evidence_ref = v.evidence.ref; }
      return api("PUT", "/assessments/" + encodeURIComponent(a.assessment_id) + "/tasks/" + encodeURIComponent(ref(t.task_id, "")), body)
        .then(function (updated) { say("Task saved."); return loadAll().then(function () { openAssessment(updated); }); });
    }).catch(plainFail("save the task"));
  }

  // ---- tracked vendors -----------------------------------------------------
  function renderLifecycles() {
    R.table(document.getElementById("tpl-lifecycles"), [
      { label: "Vendor", value: function (l) { return vendorName(l.vendor_ref); } },
      { label: "Owner", value: function (l) { return words(l.owner_ref); } },
      { label: "Stage", value: function (l) { return R.badge(STAGES[l.stage] || words(l.stage), l.stage === "active" ? "ok" : l.stage === "suspended" ? "danger" : "info"); } },
      { label: "What they're connected to", value: function (l) { return (l.dependencies || []).map(function (d) { return words(d.reference); }).join(", ") || "Nothing recorded"; } },
      { label: "Updated", value: function (l) { return R.when(l.updated_at); } },
    ], state.lifecycles, [
      { label: "Open registered vendor", when: function (l) { return /^VMR-[a-f0-9]{24}$/.test(l.vendor_ref); }, run: function (l) { window.location.href = '/privacy/vendors/' + encodeURIComponent(l.vendor_ref) + '#vendor-profile'; } },
      { label: "Mark active", kind: "primary", when: function (l) { return l.stage === "onboarding" || (l.stage === "suspended" && canAdmin); }, run: function (l) { transition(l, "active"); } },
      { label: "Suspend", kind: "danger", when: function (l) { return canAdmin && (l.stage === "active" || l.stage === "onboarding"); }, run: function (l) { transition(l, "suspended"); } },
      { label: "Start offboarding", kind: "danger", when: function (l) { return canAdmin && state.namedSignin && !l.offboarding_plan_id && (l.stage === "active" || l.stage === "suspended"); }, run: beginOffboarding },
      { label: "Save a record", run: function (l) { exportRecord("/lifecycles/", l.lifecycle_id); } },
    ], { text: "No vendors are being tracked yet.", action: { label: "Start tracking a vendor", run: newLifecycle } });
  }
  function transition(l, target) {
    if (target === 'active' && /^VMR-[a-f0-9]{24}$/.test(l.vendor_ref)) { window.location.href = '/privacy/vendors/' + encodeURIComponent(l.vendor_ref) + '#vendor-profile'; return; }
    var text = target === "suspended" ? "Suspend " + vendorName(l.vendor_ref) + "? Mark them as not allowed to work with you until reactivated." : "Mark " + vendorName(l.vendor_ref) + " as active?";
    R.form(target === "suspended" ? "Suspend vendor" : "Mark vendor active", [{ key: "reason", label: "Reason", required: true, placeholder: target === "suspended" ? "For example: Security incident under review" : "For example: Review complete" }], target === "suspended" ? "Suspend" : "Mark active").then(function (v) {
      if (!v) { return; }
      return R.confirm(text, target === "suspended" ? "Suspend" : "Confirm").then(function (ok) {
        if (!ok) { return; }
        return api("POST", "/lifecycles/" + encodeURIComponent(l.lifecycle_id) + "/transition", { target_stage: target, reason_code: ref(v.reason, ""), expected_revision: l.revision, idempotency_key: R.newKey() })
          .then(function () { say("Vendor updated."); loadAll(); });
      });
    }).catch(fail("update the vendor"));
  }
  function newLifecycle() {
    if (!state.vendors.length) { say('Register this vendor in Privacy first, then track the same registered identity.'); return; }
    var vendorOpts = state.vendors;
    var selectedVendor = new URLSearchParams(window.location.search).get('registered_vendor');
    R.form("Start tracking a vendor", [
      { key: "vendor", label: "Registered vendor", type: "select", default: vendorOpts.some(function (row) { return row.value === selectedVendor; }) ? selectedVendor : vendorOpts[0].value, options: vendorOpts },
      { key: "owner", label: "Owner", type: "select", default: state.me, options: peopleOptions() },
      { key: "deps", label: "What they're connected to (separate with commas)", placeholder: "For example: Payroll system, Customer data" },
      { key: "dep_kind", label: "Those are mostly", type: "select", default: "system", options: options(DEP_KINDS) },
      { key: "keep", label: "Keep records for", type: "select", default: "2555", options: options(KEEP) },
    ], "Start tracking").then(function (v) {
      if (!v) { return; }
      var vendorRef = v.vendor;
      if (!state.vendors.some(function (row) { return row.value === vendorRef; })) { say("Choose the actual registered vendor."); return; }
      var names = String(v.deps || "").split(",").map(function (s) { return s.trim(); }).filter(Boolean);
      // Each connection is recorded with the fingerprint of what was written here.
      return Promise.all(names.map(function (name, i) {
        return R.fingerprint(new Blob([name], { type: "text/plain" })).then(function (d) {
          return { dependency_id: "dep-" + (i + 1), kind: v.dep_kind, reference: ref(name, ""), evidence_sha256: d.sha256 };
        });
      })).then(function (deps) {
        return api("PUT", "/lifecycles/" + encodeURIComponent(R.newId("vendor-lifecycle")), {
          vendor_ref: vendorRef, owner_ref: v.owner || state.me, dependencies: deps, retention_seconds: days(v.keep), idempotency_key: R.newKey(),
        });
      }).then(function () { say("Vendor is now tracked."); loadAll(); });
    }).catch(fail("start tracking the vendor"));
  }
  document.getElementById("tpl-new-lifecycle").addEventListener("click", newLifecycle);
  function beginOffboarding(l) {
    var deps = l.dependencies || [];
    var fields = [];
    deps.forEach(function (d, i) {
      fields.push({ key: "action" + i, label: "For " + words(d.reference), type: "select", default: d.kind === "access" ? "revoke_access" : d.kind === "data" ? "archive_data" : d.kind === "contract" ? "notify_owner" : "terminate_integration", options: options(OFF_ACTIONS) });
      fields.push({ key: "who" + i, label: "Who does it", type: "select", default: state.me, options: peopleOptions() });
    });
    fields.push({ key: "hold", label: "Keep everything for a legal hold", type: "bool" });
    fields.push({ key: "hold_reason", label: "Legal hold reason (if on hold)" });
    R.form("Start offboarding " + vendorName(l.vendor_ref), fields, "Start offboarding").then(function (v) {
      if (!v) { return; }
      if (v.hold && !v.hold_reason) { say("Give a reason for the legal hold."); return; }
      return R.confirm("Start offboarding " + vendorName(l.vendor_ref) + "? Lightwork creates one task per connection. Nothing is contacted from here.", "Start offboarding").then(function (ok) {
        if (!ok) { return; }
        var tasks = deps.map(function (d, i) {
          return { task_id: "task-" + (i + 1), dependency_id: d.dependency_id, action: v["action" + i], assignee_ref: v["who" + i] || state.me, callback_required: false };
        });
        var body = { tasks: tasks, legal_hold: !!v.hold, maximum_callback_attempts: 5, expected_lifecycle_revision: l.revision, idempotency_key: R.newKey() };
        if (v.hold) { body.legal_hold_evidence_ref = ref(v.hold_reason, "hold."); }
        return api("POST", "/lifecycles/" + encodeURIComponent(l.lifecycle_id) + "/offboarding/" + encodeURIComponent(R.newId("offboarding")), body)
          .then(function () { say("Offboarding started."); loadAll(); });
      });
    }).catch(fail("start offboarding"));
  }

  // ---- offboarding ---------------------------------------------------------
  function lifecycleOf(plan) { return state.lifecycles.filter(function (l) { return l.lifecycle_id === plan.lifecycle_id; })[0]; }
  function renderPlans() {
    R.table(document.getElementById("tpl-offboarding"), [
      { label: "Vendor", value: function (p) { var l = lifecycleOf(p); return l ? vendorName(l.vendor_ref) : "Vendor"; } },
      { label: "Status", value: function (p) { return R.badge(words(p.state), p.state === "completed" ? "ok" : "warn"); } },
      { label: "Tasks done", value: function (p) { return (p.tasks || []).filter(function (t) { return t.status === "completed"; }).length + " of " + (p.tasks || []).length; } },
      { label: "Legal hold", value: function (p) { return p.legal_hold ? R.badge("On hold", "danger") : "No"; } },
    ], state.plans, [
      { label: "Tasks", kind: "primary", run: openPlan },
      { label: "Place legal hold", kind: "danger", when: function (p) { return canAdmin && !p.legal_hold && p.state !== "completed"; }, run: function (p) { legalHold(p, true); } },
      { label: "Lift legal hold", when: function (p) { return canAdmin && p.legal_hold; }, run: function (p) { legalHold(p, false); } },
      { label: "Approve completion", when: function (p) { return canAdmin && state.namedSignin && state.me && !p.needs_named_initiator && p.initiated_by !== state.me && p.state !== "completed" && !p.legal_hold; }, run: completePlan },
    ], { text: "No vendors are being offboarded. Start offboarding from the vendor list above." });
  }
  function openPlan(p) {
    var box = document.getElementById("tpl-plan-detail");
    box.hidden = false; box.textContent = "";
    box.appendChild(el("h3", "", "Offboarding tasks"));
    R.table(box.appendChild(el("div")), [
      { label: "Task", value: function (t) { return words(t.action); } },
      { label: "For", value: function (t) { var l = lifecycleOf(p); var d = l && (l.dependencies || []).filter(function (x) { return x.dependency_id === t.dependency_id; })[0]; return d ? words(d.reference) : "—"; } },
      { label: "Who", value: function (t) { return words(t.assignee_ref); } },
      { label: "Status", value: function (t) { return R.badge(words(t.status), t.status === "completed" ? "ok" : t.status === "blocked" ? "danger" : "warn"); } },
    ], p.tasks || [], [
      { label: "Mark done", kind: "primary", when: function (t) { return t.status !== "completed"; }, run: function (t) { planTask(p, t, "completed"); } },
      { label: "Blocked", when: function (t) { return t.status === "open"; }, run: function (t) { planTask(p, t, "blocked"); } },
      { label: "Reopen", when: function (t) { return t.status !== "open"; }, run: function (t) { planTask(p, t, "open"); } },
    ]);
    if ((p.blockers || []).length) { box.appendChild(el("p", "muted", "Still to do: " + p.blockers.map(words).join(", ") + ".")); }
    window.mvReveal(box);
  }
  function planTask(p, t, status) {
    var ask = status === "completed" ? askEvidence("Mark the task done", "Save") : Promise.resolve({});
    ask.then(function (v) {
      if (!v) { return; }
      var body = { status: status, expected_revision: p.revision, idempotency_key: R.newKey() };
      if (v.evidence) { body.evidence_sha256 = v.evidence.sha; body.attestation_ref = v.evidence.ref; }
      return api("PUT", "/offboarding/" + encodeURIComponent(p.plan_id) + "/tasks/" + encodeURIComponent(t.task_id), body)
        .then(function (updated) { say("Task updated."); return loadAll().then(function () { openPlan(updated); }); });
    }).catch(plainFail("update the task"));
  }
  function legalHold(p, active) {
    R.form(active ? "Place a legal hold" : "Lift the legal hold", [{ key: "reason", label: "Reason", required: true }], active ? "Place hold" : "Lift hold").then(function (v) {
      if (!v) { return; }
      return R.confirm(active ? "Place a legal hold? Nothing about this vendor can be deleted until it is lifted." : "Lift the legal hold? Offboarding can then finish.", active ? "Place hold" : "Lift hold").then(function (ok) {
        if (!ok) { return; }
        return api("POST", "/offboarding/" + encodeURIComponent(p.plan_id) + "/legal-hold", { active: active, evidence_ref: ref(v.reason, "hold."), expected_revision: p.revision, idempotency_key: R.newKey() })
          .then(function () { say(active ? "Legal hold placed." : "Legal hold lifted."); loadAll(); });
      });
    }).catch(fail("change the legal hold"));
  }
  function completePlan(p) {
    var l = lifecycleOf(p);
    if (!l) { say("The vendor for this plan could not be found. Refresh the page to see the latest."); return; }
    R.form("Approve offboarding completion", [{ key: "note", label: "Your confirmation note", required: true, placeholder: "For example: All access removed and data archived" }], "Approve").then(function (v) {
      if (!v) { return; }
      return R.confirm("Approve that offboarding of " + vendorName(l.vendor_ref) + " is complete? The vendor is then marked as offboarded. Someone other than the person who started it must approve.", "Approve").then(function (ok) {
        if (!ok) { return; }
        return api("POST", "/offboarding/" + encodeURIComponent(p.plan_id) + "/complete", { completion_attestation_ref: ref(v.note, "note."), expected_plan_revision: p.revision, expected_lifecycle_revision: l.revision, idempotency_key: R.newKey() })
          .then(function () { say("Offboarding complete."); loadAll(); });
      });
    }).catch(fail("approve the offboarding"));
  }

  // ---- administrator tools ---------------------------------------------------
  var adminResult = document.getElementById("tpl-admin-result");
  document.getElementById("tpl-integrity").addEventListener("click", function () {
    if (!canAudit) { adminResult.textContent = "Only auditors and administrators can run this check."; return; }
    api("GET", "/integrity").then(function (d) {
      adminResult.textContent = "No changes found. " + (d.verified_records || 0) + " records were checked.";
    }, function (f) { adminResult.textContent = R.errorText(f, "check the records"); });
  });
  document.getElementById("tpl-purge-before").value = R.isoDateIn(0);
  document.getElementById("tpl-purge").addEventListener("click", function () {
    if (!canAdmin) { adminResult.textContent = "Only administrators can delete expired records."; return; }
    var before = R.toEpoch(document.getElementById("tpl-purge-before").value);
    if (!before) { adminResult.textContent = "Choose a date first."; return; }
    R.confirm("Delete lifecycle records whose keep period ended before this date? Records on legal hold are kept. This can't be undone.", "Delete").then(function (ok) {
      if (!ok) { return; }
      api("POST", "/retention/purge", { before: before, idempotency_key: R.newKey() }).then(function () {
        adminResult.textContent = "Expired records were deleted."; loadAll();
      }, function (f) { adminResult.textContent = R.errorText(f, "delete expired records"); });
    });
  });

  Promise.all([loadPeople(), loadVendors()]).then(loadAll);
})();
