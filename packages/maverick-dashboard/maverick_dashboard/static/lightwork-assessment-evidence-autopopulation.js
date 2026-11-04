/* Bounded client for governed assessment-evidence proposals. */
(function () {
  "use strict";

  var MAX_RESPONSE_BYTES = 1024 * 1024;
  var ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
  var QUESTION_PATTERN = /^[a-z0-9][a-z0-9_]{0,59}$/;
  var OP_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$/;

  function isRecord(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }

  function confidenceLabel(basisPoints) {
    return Number.isInteger(basisPoints) && basisPoints >= 0 && basisPoints <= 10000
      ? String(basisPoints / 100) + "%" : "Not reported";
  }

  function failure(message, code) {
    var error = new Error(message);
    error.code = code;
    return error;
  }

  async function boundedResponseText(response) {
    var declared = response.headers && response.headers.get("Content-Length");
    if (declared && /^\d+$/.test(declared) && Number(declared) > MAX_RESPONSE_BYTES) {
      throw failure("Lightwork returned more than this page can show (over 1 MiB). Refresh and try again.", "response_too_large");
    }
    if (!response.body || typeof response.body.getReader !== "function") {
      throw failure("This browser is too old for this page. Try a current version of Chrome, Edge, Firefox or Safari.", "response_stream_unavailable");
    }
    var reader = response.body.getReader();
    var decoder = new TextDecoder("utf-8", {fatal: false});
    var received = 0;
    var text = "";
    while (true) {
      var chunk = await reader.read();
      if (chunk.done) break;
      received += chunk.value.byteLength;
      if (received > MAX_RESPONSE_BYTES) {
        try { await reader.cancel(); } catch (_error) { /* size failure wins */ }
        throw failure("Lightwork returned more than this page can show (over 1 MiB). Refresh and try again.", "response_too_large");
      }
      text += decoder.decode(chunk.value, {stream: true});
    }
    return text + decoder.decode();
  }

  async function parseResponse(response) {
    var raw = await boundedResponseText(response);
    var payload;
    try { payload = JSON.parse(raw); }
    catch (_error) { throw failure("Lightwork returned something unexpected. Refresh the page and try again.", "response_invalid_json"); }
    if (!isRecord(payload)) throw failure("Lightwork returned something unexpected. Refresh the page and try again.", "response_invalid");
    if (!response.ok) {
      var error = failure(friendly(response.status, response.headers), "request_failed");
      error.status = response.status;
      error.technical = typeof payload.detail === "string" ? payload.detail : "";
      throw error;
    }
    return payload;
  }

  function friendly(status, headers) {
    if (typeof window !== "undefined" && typeof window.mvErrorText === "function") {
      // Headers carry the turned-off reason, so "off" is never read as "no permission".
      return window.mvErrorText({status: status, headers: headers}, "finish this");
    }
    if (status === 403) return "You do not have permission to do this. Ask an administrator.";
    if (status === 409) return "This changed since you opened it. Refresh the page and try again.";
    return "Something went wrong. Try again.";
  }

  function identifier(value, label) {
    var selected = String(value || "").trim();
    if (!ID_PATTERN.test(selected)) throw new Error("Choose " + label + " from the list.");
    return selected;
  }

  function operationKey(value) {
    var selected = String(value || "").trim();
    if (!OP_PATTERN.test(selected)) throw new Error("The page is not ready yet. Refresh it and try again.");
    return selected;
  }

  function positiveInteger(value, label) {
    var selected = Number(value);
    if (!Number.isSafeInteger(selected) || selected < 1) {
      throw new Error("The page is out of date. Refresh it and try again.");
    }
    return selected;
  }

  function analysisIds(value) {
    var seen = Object.create(null);
    var values = (Array.isArray(value) ? value : String(value || "").split(/\r?\n/)).map(function (item) {
      return item.trim();
    }).filter(Boolean).map(function (item) {
      return identifier(String(item || "").trim(), "the evidence");
    }).filter(function (item) {
      if (seen[item]) return false;
      seen[item] = true;
      return true;
    });
    if (values.length < 1 || values.length > 32) {
      throw new Error("Choose between 1 and 32 pieces of approved evidence.");
    }
    return values;
  }

  function buildCreatePayload(fields) {
    return {
      assessment_id: identifier(fields.assessment_id, "an open assessment"),
      analysis_ids: analysisIds(fields.analysis_ids),
      idempotency_key: operationKey(fields.idempotency_key)
    };
  }

  function buildReviewPayload(fields) {
    var decision = String(fields.decision || "");
    if (["approve", "reject"].indexOf(decision) === -1) throw new Error("Choose Approve or Reject.");
    var questions = Array.isArray(fields.selected_question_ids) ? fields.selected_question_ids : [];
    questions = questions.map(function (item) {
      var selected = String(item || "");
      if (!QUESTION_PATTERN.test(selected)) throw new Error("One of the chosen answers is not valid. Refresh and try again.");
      return selected;
    });
    if ((decision === "approve" && questions.length < 1) || (decision === "reject" && questions.length)) {
      throw new Error(decision === "approve" ? "Select at least one answer to approve." : "Untick the answers before rejecting.");
    }
    var rationale = String(fields.rationale || "").trim();
    if (!rationale || rationale.length > 4000) throw new Error("Enter a reason for your decision using no more than 4,000 characters.");
    return {
      decision: decision,
      selected_question_ids: questions,
      rationale: rationale,
      expected_revision: positiveInteger(fields.expected_revision, "Current proposal version"),
      idempotency_key: operationKey(fields.idempotency_key)
    };
  }

  function buildApplyPayload(fields) {
    if (fields.confirm !== true) throw new Error("Confirm that you want to add the approved answers.");
    return {
      expected_revision: positiveInteger(fields.expected_revision, "Current proposal version"),
      expected_assessment_revision: positiveInteger(fields.expected_assessment_revision, "Assessment version being reviewed"),
      idempotency_key: operationKey(fields.idempotency_key)
    };
  }

  if (typeof window !== "undefined") {
    Object.defineProperty(window, "LightworkAssessmentEvidenceClient", {
      configurable: false,
      enumerable: false,
      writable: false,
      value: Object.freeze({
        MAX_RESPONSE_BYTES: MAX_RESPONSE_BYTES,
        boundedResponseText: boundedResponseText,
        parseResponse: parseResponse,
        buildCreatePayload: buildCreatePayload,
        buildReviewPayload: buildReviewPayload,
        buildApplyPayload: buildApplyPayload,
        confidenceLabel: confidenceLabel
      })
    });
  }

  if (typeof document === "undefined") return;
  var shell = document.getElementById("assessment-evidence-shell");
  if (!shell) return;
  var apiBase = shell.dataset.apiBase || "";
  var output = document.getElementById("aep-output");
  var status = document.getElementById("aep-operation-status");
  var candidates = document.getElementById("aep-candidates");
  var selection = document.getElementById("aep-candidate-selection");
  var queue = document.getElementById("aep-queue");
  var reviewPanel = document.getElementById("aep-review-panel");
  var mutationControls = Array.prototype.slice.call(document.querySelectorAll("[data-aep-mutation]"));
  var mutationAuthorized = shell.dataset.moduleEnabled === "true" && shell.dataset.canOperate === "true";
  var sessions = [];
  var analyses = [];
  var templates = Object.create(null);
  var current = null;
  var STATUS = {
    pending_review: ["Waiting for review", "warn"], approved: ["Approved — ready to add", "ok"],
    rejected: ["Rejected", "failed"], applied: ["Added to the assessment", "ok"],
    expired: ["Expired", "idle"]
  };
  var ANSWERS = {yes: "Yes", no: "No", na: "Not applicable", partial: "Partly", unknown: "Unknown"};

  function setText(node, value) { if (node) node.textContent = String(value == null ? "" : value); }
  function clear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }
  function human(value) {
    if (typeof window.mvHuman === "function") return window.mvHuman(value);
    var text = String(value || "").replace(/[_.-]+/g, " ").trim();
    return text ? text.charAt(0).toUpperCase() + text.slice(1) : "";
  }
  function when(ts) {
    if (typeof window.mvWhen === "function") return window.mvWhen(ts);
    return ts ? (window.mvTimeAbsolute ? window.mvTimeAbsolute(ts) : new Date(ts * 1000).toLocaleString()) : "";
  }
  function documentName(artifactId) {
    var match = /^(.+)\.[0-9a-f]{8}$/.exec(String(artifactId || ""));
    return match ? human(match[1]) : "Document " + String(artifactId || "");
  }
  function reference(prefix) {
    if (window.crypto && typeof window.crypto.randomUUID === "function") return prefix + "-" + window.crypto.randomUUID();
    return prefix + "-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 12);
  }
  function setMutationReady(ready) {
    mutationControls.forEach(function (controls) {
      var disabled = !mutationAuthorized || ready !== true;
      controls.disabled = disabled;
      controls.toggleAttribute("disabled", disabled);
      controls.setAttribute("aria-disabled", disabled ? "true" : "false");
    });
  }
  function request(path, options, base) {
    var settings = options || {};
    settings.credentials = "same-origin";
    settings.headers = Object.assign({"Accept": "application/json"}, settings.headers || {});
    return fetch((base === undefined ? apiBase : base) + path, settings).then(parseResponse);
  }
  function show(payload, message) {
    setText(output, payload === undefined ? "" : JSON.stringify(payload, null, 2));
    setText(status, message || "Done.");
  }
  function showError(error) {
    setText(status, error && error.message ? error.message : "Something went wrong. Try again.");
    setText(output, error && error.technical ? error.technical : "");
  }
  function sessionById(id) {
    for (var i = 0; i < sessions.length; i += 1) if (sessions[i].id === id) return sessions[i];
    return null;
  }
  function sessionLabel(item) {
    var tpl = templates[item.type];
    var title = tpl && tpl.title ? tpl.title : human(item.type);
    return String(item.subject || "Untitled") + " — " + title +
      (item.total ? " (" + item.answered + " of " + item.total + " answered)" : "");
  }
  function analysisLabel(record) {
    var artifact = record && record.artifact ? record.artifact.artifact_id : "";
    var criteria = record && record.criteria ? record.criteria.criteria_set_id : "";
    return documentName(artifact) + " · " + human(criteria);
  }
  function analysisById(id) {
    for (var i = 0; i < analyses.length; i += 1) if (analyses[i].analysis_id === id) return analyses[i];
    return null;
  }
  function loadTemplate(type) {
    if (!type || templates[type]) return Promise.resolve(templates[type] || null);
    return request("/assess/templates/" + encodeURIComponent(type), {}, "/api/v1").then(function (tpl) {
      templates[type] = tpl; return tpl;
    }).catch(function () { templates[type] = {questions: []}; return templates[type]; });
  }
  function questionText(type, questionId) {
    var tpl = templates[type];
    var list = tpl && Array.isArray(tpl.questions) ? tpl.questions : [];
    for (var i = 0; i < list.length; i += 1) if (list[i].id === questionId) return list[i].text;
    return human(questionId);
  }

  // ---- pickers ---------------------------------------------------------
  function loadSessions() {
    var select = document.getElementById("aep-assessment-id");
    return request("/assess/sessions", {}, "/api/v1").then(function (payload) {
      var closed = {approved: true, rejected: true, declined: true, closed: true};
      sessions = (Array.isArray(payload.sessions) ? payload.sessions : []).filter(function (item) {
        return isRecord(item) && ID_PATTERN.test(String(item.id || "")) && !closed[item.status];
      });
      var types = {};
      sessions.forEach(function (item) { types[item.type] = true; });
      return Promise.all(Object.keys(types).map(loadTemplate));
    }).then(function () {
      clear(select);
      var first = document.createElement("option");
      first.value = "";
      first.textContent = sessions.length ? "Choose an open assessment…" : "No open assessments — start one on the Assessments page";
      select.appendChild(first);
      sessions.forEach(function (item) {
        var option = document.createElement("option");
        option.value = item.id; option.textContent = sessionLabel(item);
        select.appendChild(option);
      });
    }).catch(function (error) {
      clear(select);
      var option = document.createElement("option");
      option.value = ""; option.textContent = "Couldn't load assessments";
      select.appendChild(option);
      showError(error);
    });
  }
  function loadAnalyses() {
    var box = document.getElementById("aep-analysis-choices");
    return request("/ai-evidence-analysis/analyses?status=review_approved&limit=200", {}, "/api/v1").then(function (payload) {
      analyses = Array.isArray(payload.items) ? payload.items.filter(function (item) {
        return isRecord(item) && ID_PATTERN.test(String(item.analysis_id || ""));
      }) : [];
      Array.prototype.slice.call(box.querySelectorAll("label, p")).forEach(function (node) { node.remove(); });
      if (!analyses.length) {
        var note = document.createElement("p");
        note.className = "muted";
        note.textContent = "No approved evidence yet. Analyze a document on the AI evidence analysis page and have it approved first.";
        box.appendChild(note);
        return;
      }
      analyses.slice(0, 200).forEach(function (record) {
        var label = document.createElement("label");
        var check = document.createElement("input");
        check.type = "checkbox"; check.name = "analysis_ids"; check.value = record.analysis_id;
        var span = document.createElement("span");
        span.textContent = analysisLabel(record);
        label.appendChild(check); label.appendChild(span); box.appendChild(label);
      });
    }).catch(function () {
      Array.prototype.slice.call(box.querySelectorAll("label, p")).forEach(function (node) { node.remove(); });
      var note = document.createElement("p");
      note.className = "muted";
      note.textContent = "Approved evidence couldn't be loaded. AI evidence analysis may be turned off; ask your administrator to check it.";
      box.appendChild(note);
    });
  }

  // ---- proposals list --------------------------------------------------
  function assessmentName(assessment) {
    var session = isRecord(assessment) ? sessionById(assessment.id) : null;
    if (session) return String(session.subject || "Untitled");
    return isRecord(assessment) ? human(assessment.type) + " assessment" : "An assessment";
  }
  function renderQueue(payload) {
    clear(queue);
    var items = isRecord(payload) && Array.isArray(payload.items) ? payload.items : [];
    if (!items.length) {
      var tr0 = document.createElement("tr");
      var td0 = document.createElement("td");
      td0.colSpan = 5;
      td0.textContent = "No suggestions yet. Choose an open assessment and approved evidence above, then press Suggest answers.";
      tr0.appendChild(td0); queue.appendChild(tr0);
      return;
    }
    items.forEach(function (item) {
      if (!isRecord(item)) return;
      var tr = document.createElement("tr");
      var th = document.createElement("th"); th.scope = "row"; th.textContent = assessmentName(item.assessment);
      tr.appendChild(th);
      var stateCell = document.createElement("td");
      var badge = document.createElement("span");
      var pair = STATUS[item.status] || [human(item.status), "idle"];
      badge.className = "badge " + pair[1]; badge.textContent = pair[0];
      stateCell.appendChild(badge); tr.appendChild(stateCell);
      var counts = document.createElement("td");
      counts.textContent = String(item.candidate_count || 0) + " (" + String(item.eligible_candidate_count || 0) + " can be added)";
      tr.appendChild(counts);
      var created = document.createElement("td"); created.textContent = when(item.created_at); tr.appendChild(created);
      var actions = document.createElement("td");
      var wrap = document.createElement("div"); wrap.className = "aep-actions";
      wrap.appendChild(rowButton(item.status === "pending_review" ? "Review" : "View", function () { return openProposal(item.id); }, "btn"));
      if (item.status === "approved" && mutationAuthorized && mutationReadyState) {
        wrap.appendChild(rowButton("Add approved answers", function () { return applyProposal(item.id); }, "btn btn--primary"));
      }
      actions.appendChild(wrap); tr.appendChild(actions);
      queue.appendChild(tr);
    });
  }
  function rowButton(label, handler, cls) {
    var button = document.createElement("button");
    button.type = "button"; button.className = cls; button.textContent = label;
    button.addEventListener("click", function () {
      if (button.disabled) return;
      button.disabled = true;
      Promise.resolve().then(handler).catch(showError).then(function () { button.disabled = false; });
    });
    return button;
  }
  function refreshList() {
    return request("/proposals?limit=100").then(renderQueue).catch(function (error) {
      clear(queue);
      var tr = document.createElement("tr");
      var td = document.createElement("td"); td.colSpan = 5;
      td.textContent = error && error.status === 403
        ? "You need auditor access to see the list of suggestions. Ask an administrator."
        : (error && error.message) || "Couldn't load suggestions. Refresh the page and try again.";
      tr.appendChild(td); queue.appendChild(tr);
    });
  }

  // ---- review ----------------------------------------------------------
  function addDefinitionList(card, rows) {
    var list = document.createElement("dl");
    rows.forEach(function (row) {
      var dt = document.createElement("dt");
      var dd = document.createElement("dd");
      dt.textContent = row[0]; dd.textContent = String(row[1] == null ? "—" : row[1]);
      list.appendChild(dt); list.appendChild(dd);
    });
    card.appendChild(list);
  }
  function renderProposal(record) {
    current = record;
    clear(candidates);
    Array.prototype.slice.call(selection.querySelectorAll("label, p")).forEach(function (node) { node.remove(); });
    if (!isRecord(record) || !Array.isArray(record.candidates)) return;
    var type = isRecord(record.assessment) ? record.assessment.type : "";
    setText(document.getElementById("aep-review-subject"), assessmentName(record.assessment) + " · " +
      (STATUS[record.status] || [human(record.status)])[0]);
    var eligible = 0;
    record.candidates.forEach(function (candidate) {
      if (!isRecord(candidate)) return;
      var card = document.createElement("article");
      card.className = "aep-card";
      var title = document.createElement("h3");
      title.textContent = questionText(type, candidate.question_id);
      card.appendChild(title);
      var citationsList = Array.isArray(candidate.citations) ? candidate.citations : [];
      addDefinitionList(card, [
        ["Suggested answer", ANSWERS[candidate.answer] || human(candidate.answer)],
        ["Confidence", confidenceLabel(candidate.confidence_bps)],
        ["Can be added", candidate.eligible_for_apply === true ? "Yes" : "No"],
        ["Notes", Array.isArray(candidate.flags) && candidate.flags.length ? candidate.flags.map(human).join(", ") : "None"],
        ["Based on", citationsList.map(function (item) {
          if (!isRecord(item)) return "";
          var source = analysisById(item.analysis_id);
          return (source ? documentName(source.artifact && source.artifact.artifact_id) : "Approved evidence") +
            " (" + human(item.criterion_id) + ")";
        }).filter(Boolean).join("; ") || "—"]
      ]);
      candidates.appendChild(card);
      if (candidate.eligible_for_apply === true && QUESTION_PATTERN.test(String(candidate.question_id || ""))) {
        eligible += 1;
        var label = document.createElement("label");
        var check = document.createElement("input");
        var span = document.createElement("span");
        check.type = "checkbox"; check.name = "selected_question_ids"; check.value = candidate.question_id;
        span.textContent = questionText(type, candidate.question_id) + " — " + (ANSWERS[candidate.answer] || human(candidate.answer));
        label.appendChild(check); label.appendChild(span); selection.appendChild(label);
      }
    });
    if (!eligible) {
      var note = document.createElement("p");
      note.className = "muted";
      note.textContent = "None of these suggestions is strong enough to be added. You can still reject them.";
      selection.appendChild(note);
    }
    var reviewControls = document.getElementById("aep-review-controls");
    if (reviewControls && record.status !== "pending_review") {
      reviewControls.disabled = true;
      reviewControls.setAttribute("aria-disabled", "true");
    } else if (reviewControls) {
      setMutationReady(mutationReadyState);
    }
    reviewPanel.hidden = false;
    var heading = document.getElementById("aep-review-title");
    if (heading && typeof heading.focus === "function") heading.focus();
  }
  function openProposal(id) {
    return request("/proposals/" + encodeURIComponent(identifier(id, "a suggestion"))).then(function (record) {
      return loadTemplate(isRecord(record.assessment) ? record.assessment.type : "").then(function () {
        renderProposal(record);
        show(record, "Showing the suggested answers and the evidence behind them.");
        return record;
      });
    });
  }
  function ask(message, okText) {
    if (typeof window.mvConfirm === "function") return window.mvConfirm(message, {okText: okText});
    return Promise.resolve(false);
  }
  function applyProposal(id) {
    return request("/proposals/" + encodeURIComponent(identifier(id, "a suggestion"))).then(function (record) {
      var count = Array.isArray(record.review && record.review.selected_question_ids)
        ? record.review.selected_question_ids.length : 0;
      return ask("Add " + (count || "the") + " approved " + (count === 1 ? "answer" : "answers") + " to " +
        assessmentName(record.assessment) + "? Only unanswered questions are filled; the assessment still needs its final review.",
        "Add answers").then(function (ok) {
        if (!ok) return null;
        var payload = buildApplyPayload({
          expected_revision: record.revision,
          expected_assessment_revision: isRecord(record.assessment) ? record.assessment.revision : 0,
          idempotency_key: reference("apply"),
          confirm: true
        });
        return request("/proposals/" + encodeURIComponent(record.id) + "/apply", {
          method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)
        }).then(function (updated) {
          show(updated, "Approved answers were added. The assessment still needs its final review.");
          refreshList(); loadSessions();
          return updated;
        });
      });
    });
  }

  var mutationReadyState = false;
  function refreshStatus() {
    var pill = document.getElementById("aep-status-pill");
    setText(pill, "Checking"); if (pill) { pill.dataset.state = "checking"; pill.className = "badge idle"; }
    return request("/status").then(function (payload) {
      var ready = payload.ready === true;
      mutationReadyState = ready;
      setMutationReady(ready);
      setText(pill, ready ? "Ready" : "Not ready");
      if (pill) { pill.dataset.state = ready ? "ready" : "failed"; pill.className = "badge " + (ready ? "ok" : "warn"); }
      setText(document.getElementById("aep-status-detail"), ready
        ? "Suggestions are available. Your access is checked when you start."
        : payload.enabled === false
          ? "Suggested answers are turned off for this workspace."
          : "Setup isn't finished yet. Ask an administrator to complete it.");
    }).catch(function (error) {
      mutationReadyState = false;
      setMutationReady(false);
      if (pill) { pill.dataset.state = "failed"; pill.className = "badge warn"; }
      setText(pill, "Unavailable");
      setText(document.getElementById("aep-status-detail"), error && error.status === 403
        ? "You need auditor access to check availability. Ask an administrator."
        : (error && error.message) || "Couldn't check availability. Refresh the page and try again.");
    });
  }

  document.getElementById("aep-refresh-status").addEventListener("click", function () { refreshStatus(); });
  document.getElementById("aep-refresh-list").addEventListener("click", function () { refreshList(); });
  document.getElementById("aep-create-form").addEventListener("submit", function (event) {
    event.preventDefault();
    try {
      var form = event.currentTarget;
      var chosen = Array.prototype.slice.call(form.querySelectorAll('input[name="analysis_ids"]:checked')).map(function (item) { return item.value; });
      var payload = buildCreatePayload({
        assessment_id: form.elements.namedItem("assessment_id").value,
        analysis_ids: chosen,
        idempotency_key: form.elements.namedItem("idempotency_key").value || reference("create")
      });
      request("/proposals", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)}).then(function (record) {
        form.elements.namedItem("idempotency_key").value = reference("create");
        return loadTemplate(isRecord(record.assessment) ? record.assessment.type : "").then(function () {
          renderProposal(record);
          show(record, "Suggestions are ready for review. Nothing in the assessment has changed.");
          refreshList();
        });
      }).catch(showError);
    } catch (error) { showError(error); }
  });
  document.getElementById("aep-review-form").addEventListener("submit", function (event) {
    event.preventDefault();
    if (!current) return;
    try {
      var form = event.currentTarget;
      var decision = event.submitter && event.submitter.value === "reject" ? "reject" : "approve";
      var selected = decision === "approve"
        ? Array.prototype.slice.call(form.querySelectorAll('input[name="selected_question_ids"]:checked')).map(function (item) { return item.value; })
        : [];
      var payload = buildReviewPayload({
        decision: decision,
        selected_question_ids: selected,
        rationale: form.elements.namedItem("rationale").value,
        expected_revision: current.revision,
        idempotency_key: form.elements.namedItem("idempotency_key").value || reference("review")
      });
      request("/proposals/" + encodeURIComponent(identifier(current.id, "a suggestion")) + "/review", {
        method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)
      }).then(function (record) {
        form.elements.namedItem("idempotency_key").value = reference("review");
        form.elements.namedItem("rationale").value = "";
        renderProposal(record);
        show(record, decision === "approve"
          ? "Approved. Use Add approved answers in the list to put them into the assessment."
          : "Suggestions rejected. Nothing in the assessment changed.");
        refreshList();
      }).catch(showError);
    } catch (error) { showError(error); }
  });
  refreshStatus();
  loadSessions().then(refreshList);
  loadAnalyses();
}());
