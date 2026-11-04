(function () {
  "use strict";

  var root = document.getElementById("ec-root");
  if (!root) { return; }
  var admin = root.dataset.mode === "admin";
  var base = "/api/v1/employee-companion";
  var context = root.dataset.companionContext || "";
  var busy = false;
  var loaded = false;
  var blocked = false;
  var stale = false;
  var available = false;
  var conversationAvailable = false;
  var statusAvailable = false;
  var historyGeneration = 0;
  // Counts local clears. It ends in-flight replies without moving historyGeneration,
  // which must always equal what the server reports (a replayed clear changes nothing there).
  var clearEpoch = 0;
  var historyRevision = "";
  var conversationVersion = 0;
  var replyPending = false;
  var replyNetworkBusy = "";
  var replyRequestId = "";
  var receiptBusy = false;
  var taskQuestionBusy = false;
  var newReplyWarning = false;
  var policy = null;
  var policies = [];
  var employees = [];
  var sharedEmployee = "";
  var sharedOwnCompanion = false;
  var viewedReplyId = "";
  var openingReply = admin ? "" : new URLSearchParams(window.location.search).get("reply") || "";
  if (!/^[1-9][0-9]{0,15}\.[0-9a-f]{32}$/.test(openingReply)) { openingReply = ""; }
  var messages = [];
  var status = document.getElementById("ec-status");

  function el(id) { return document.getElementById(id); }
  function node(tag, text, className) {
    var item = document.createElement(tag);
    if (text !== undefined) { item.textContent = String(text); }
    if (className) { item.className = className; }
    return item;
  }
  function announce(text, error) {
    status.textContent = text;
    status.dataset.error = error ? "true" : "false";
  }
  function dateLabel(value) {
    if (value === null || value === undefined || value === "") { return "Time unavailable"; }
    var date = new Date(typeof value === "number" ? value * 1000 : value);
    return Number.isNaN(date.getTime()) ? "Time unavailable" : window.mvTimeAbsolute ? window.mvTimeAbsolute(date.getTime()) : date.toLocaleString();
  }
  function taskState(value) {
    var labels = {
      running: "Running", active: "Running", pending: "Waiting", queued: "Queued", planned: "Planned",
      paused: "Paused", blocked: "Needs attention", waiting_for_approval: "Needs approval",
      awaiting_approval: "Needs approval", awaiting_input: "Needs your input", needs_input: "Needs your input",
      completed: "Completed", succeeded: "Completed", done: "Completed", failed: "Failed",
      cancelled: "Cancelled", canceled: "Cancelled", stopped: "Stopped", interrupted: "Interrupted",
      error: "Needs attention", draft: "Awaiting submission"
    };
    return labels[value] || "Status unavailable";
  }
  function retentionLabel(days) {
    return days === 0 ? "Not saved" : days === 1 ? "1 day" : String(days) + " days";
  }
  function employeeName(principal) {
    var employee = employees.find(function (item) { return item.principal === principal; });
    return employee ? employee.label || "Employee" : "Workspace member";
  }
  function shareEmployeeSelection(owner) {
    if (owner === sharedEmployee) { return; }
    sharedEmployee = owner;
    document.dispatchEvent(new CustomEvent("lightwork:copilot-selection", {
      detail: {selection: owner ? {kind: "companion_employee", id: owner} : {}}
    }));
  }
  function shareOwnSelection(allowed) {
    if (sharedOwnCompanion === allowed) { return; }
    sharedOwnCompanion = allowed;
    document.dispatchEvent(new CustomEvent("lightwork:copilot-selection", {
      detail: {selection: allowed ? {kind: "own_companion"} : {}}
    }));
  }
  function taskLink(task, label) {
    var link;
    try {
      var target = new URL(task.href, window.location.origin);
      if (typeof task.href !== "string" || target.origin !== window.location.origin ||
          !/^\/chat\/goal\/[^/?#]+$/.test(target.pathname) || target.search || target.hash) {
        return node("span", label);
      }
      link = node("a", label);
      link.href = target.pathname;
      return link;
    } catch (_) { return node("span", label); }
  }
  function setBusy(value) {
    busy = value;
    root.setAttribute("aria-busy", value ? "true" : "false");
    el("ec-refresh").disabled = busy || blocked;
    if (admin) {
      el("ec-policy-controls").disabled = busy || blocked || !loaded;
      el("ec-save").disabled = busy || blocked || stale || !loaded || !el("ec-owner").value;
      el("ec-copilot").disabled = busy || blocked || !loaded || !el("ec-owner").value;
    } else {
      el("ec-own-copilot").disabled = busy || blocked || !loaded;
      var mayAsk = loaded && available && !blocked && !stale && !busy && !replyPending && !taskQuestionBusy;
      el("ec-message").disabled = !mayAsk;
      el("ec-send").disabled = !mayAsk;
      el("ec-send").textContent = conversationAvailable ? (newReplyWarning ? "Start a new reply" : "Ask companion") : "Check task status";
      root.querySelectorAll("[data-question]").forEach(function (button) {
        button.disabled = !loaded || !statusAvailable || blocked || stale || busy || taskQuestionBusy || replyPending;
      });
      el("ec-clear").disabled = busy || blocked || !loaded;
      el("ec-clear-yes").disabled = busy || blocked || !loaded;
      el("ec-clear-no").disabled = busy;
      el("ec-check-reply").disabled = busy || blocked || receiptBusy;
      el("ec-message-form").setAttribute("aria-busy", replyPending ? "true" : "false");
    }
  }
  function replyNotice(text, pending, canCheck) {
    el("ec-reply-state").hidden = false;
    el("ec-reply-state").dataset.pending = pending ? "true" : "false";
    el("ec-reply-status").textContent = text;
    el("ec-check-reply").hidden = !canCheck;
  }
  function clearSensitiveView() {
    messages = [];
    if (admin) {
      policies = [];
      employees = [];
      el("ec-policies").textContent = "";
      el("ec-events").textContent = "";
      el("ec-owner").textContent = "";
      el("ec-policy-form").reset();
      shareEmployeeSelection("");
    } else {
      el("ec-messages").textContent = "";
      el("ec-tasks").textContent = "";
      el("ec-message").value = "";
      el("ec-clear-confirm").hidden = true;
      el("ec-reply-state").hidden = true;
      replyRequestId = "";
      viewedReplyId = "";
      el("ec-retained-reply").hidden = true;
      el("ec-retained-answer").textContent = "";
      shareOwnSelection(false);
    }
    el("ec-policy-label").textContent = "Access needs checking";
    el("ec-policy-summary").textContent = "Reload this page after checking your account and workspace.";
    el("ec-badge").textContent = "Unavailable";
  }
  function failure(error) {
    if (error.status === 401 || error.status === 403 || error.contextChanged) {
      blocked = true;
      clearSensitiveView();
      announce("Your account, workspace or access changed. Reload this page to check your current access.", true);
    } else if (error.status === 409) {
      stale = true;
      announce(admin
        ? "This policy changed since you loaded it. Your unsaved choices are still here. Reload saved policies, review the current values and apply your choices again."
        : "Your companion policy changed. Your question is still here. Refresh to check the current policy before asking again.", true);
    } else {
      announce(error.message || "The companion could not be reached. Refresh to try again.", true);
    }
  }
  async function request(path, method, body, timeout) {
    var controller = new AbortController();
    var timer = window.setTimeout(function () { controller.abort(); }, timeout || 15000);
    try {
      var headers = { Accept: "application/json" };
      if (context) { headers["X-Lightwork-Companion-Context"] = context; }
      if (body !== undefined) { headers["Content-Type"] = "application/json"; }
      var response = await fetch(base + path, {
        method: method || "GET", credentials: "same-origin", cache: "no-store",
        headers: headers, signal: controller.signal,
        body: body === undefined ? undefined : JSON.stringify(body)
      });
      // Check loss of access before parsing a possible HTML sign-in response.
      if (response.status === 401 || response.status === 403) {
        var denied = new Error("Access changed.");
        denied.status = response.status;
        throw denied;
      }
      var text = await response.text();
      if (text.length > 2 * 1024 * 1024) { throw new Error("The reply was too large. Refresh to try again."); }
      var data;
      try { data = text ? JSON.parse(text) : {}; }
      catch (_) { throw new Error("Lightwork returned an unexpected reply. Refresh to try again."); }
      if (!response.ok) {
        var error = new Error(response.status === 400 || response.status === 422
          ? "Check your entries and try again. Your changes have not been confirmed."
          : "Lightwork could not confirm this request. Refresh to check the current state before retrying.");
        error.status = response.status;
        var detail = data.detail;
        var code = typeof detail === "string" ? detail : detail && detail.code;
        error.contextChanged = typeof code === "string" && /context.*(changed|mismatch)|companion_context/.test(code);
        throw error;
      }
      if (blocked || !data || typeof data.context !== "string" || !data.context ||
          (context && data.context !== context)) {
        var mismatch = new Error("The account or workspace changed.");
        mismatch.contextChanged = true;
        throw mismatch;
      }
      context = data.context;
      return data;
    } catch (error) {
      if (error.name === "AbortError") {
        throw new Error("This is taking too long. Refresh to check the current state before retrying. Your entered text is still here.");
      }
      if (error instanceof TypeError) {
        throw new Error("Could not connect to Lightwork. Check your connection and try again. Your entered text is still here.");
      }
      throw error;
    } finally { window.clearTimeout(timer); }
  }
  function renderMessages() {
    var container = el("ec-messages");
    container.textContent = "";
    if (!messages.length) {
      container.appendChild(node("p", conversationAvailable ? "Talk through an idea or ask for a draft. Your tasks keep working while you check in." : "Check what is running or what needs your attention. Your tasks keep working while you check in.", "muted"));
      return;
    }
    messages.forEach(function (message) {
      if (!message || typeof message.content !== "string") { return; }
      var user = message.role === "user";
      var article = node("article", undefined, "ec-message" + (user ? " ec-message--user" : ""));
      article.appendChild(node("h3", user ? "You" : "Companion"));
      article.appendChild(node("p", message.content));
      if (!user && message.kind === "draft") {
        var actions = node("div", undefined, "ec-message-actions");
        actions.appendChild(node("span", "AI draft · review before use", "badge idle"));
        var copy = node("button", "Copy draft", "btn btn--ghost");
        copy.type = "button";
        var copyStatus = node("span", "", "muted");
        copyStatus.setAttribute("role", "status");
        copy.addEventListener("click", async function () {
          copy.disabled = true;
          try {
            if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") { throw new Error("Clipboard unavailable"); }
            await navigator.clipboard.writeText(message.content);
            copyStatus.textContent = "Draft copied to your clipboard.";
          } catch (_) { copyStatus.textContent = "Select the draft text and copy it using your browser."; }
          finally { copy.disabled = false; }
        });
        actions.appendChild(copy);
        actions.appendChild(copyStatus);
        article.appendChild(actions);
      }
      if (!user && Array.isArray(message.sources) && message.sources.length) {
        article.appendChild(node("h4", message.kind === "draft" ? "Task context provided" : "Task sources"));
        var sources = node("ul", undefined, "ec-sources");
        sources.setAttribute("aria-label", message.kind === "draft" ? "Task context provided to the AI model" : "Task sources checked for this answer");
        message.sources.forEach(function (source, index) {
          var item = node("li");
          var taskId = Number.isSafeInteger(source.goal_id) && source.goal_id > 0 ? source.goal_id : index + 1;
          item.appendChild(taskLink(source, "Task " + taskId + " · " + taskState(source.status)));
          item.appendChild(node("span", " — checked " + dateLabel(source.checked_at), "muted"));
          sources.appendChild(item);
        });
        article.appendChild(sources);
      }
      if (!user && (message.trace || typeof message.model_route === "string")) {
        var trace = node("details");
        trace.appendChild(node("summary", "Answer record"));
        var record = message.trace || {};
        if (typeof message.model_route === "string" && message.model_route) {
          trace.appendChild(node("p", "Configured AI model: " + message.model_route));
        }
        if (record.decision === "allowed" && record.reason === "owner_and_policy") {
          trace.appendChild(node("p", "Allowed after checking your ownership and companion policy."));
        }
        var revision = record.policy_revision !== undefined ? record.policy_revision : record.revision;
        if (Number.isInteger(revision)) { trace.appendChild(node("p", "Companion policy version " + revision + ".")); }
        if (record.checked_at || record.time) {
          trace.appendChild(node("p", "Checked " + dateLabel(record.checked_at || record.time) + "."));
        }
        article.appendChild(trace);
      }
      container.appendChild(article);
    });
  }
  function renderTasks(tasks) {
    var list = el("ec-tasks");
    list.textContent = "";
    if (!available || !policy || !(policy.allowed_sources || []).includes("own_tasks")) { list.appendChild(node("li", "Task access is unavailable under your current companion settings. Ask your administrator if you need it.")); return; }
    if (!tasks.length) { list.appendChild(node("li", "No active tasks to show.")); return; }
    tasks.forEach(function (task) {
      var item = node("li");
      item.appendChild(taskLink(task, task.title || "View task"));
      item.appendChild(node("span", taskState(task.status) + " · Checked " + dateLabel(task.checked_at), "muted"));
      list.appendChild(item);
    });
  }
  function applyEmployee(data, updateConversation) {
    if ((Number.isInteger(data.history_generation) && data.history_generation < historyGeneration) ||
        (policy && data.policy && data.policy.revision < policy.revision)) { return; }
    policy = data.policy;
    available = data.available === true;
    conversationAvailable = data.conversation_available === true;
    statusAvailable = data.status_available === true;
    if (Number.isInteger(data.history_generation)) { historyGeneration = data.history_generation; }
    if (typeof data.history_revision === "string") { historyRevision = data.history_revision; }
    if (!policy || !Number.isInteger(policy.revision)) { throw new Error("Your companion policy could not be checked. Refresh to try again."); }
    var days = policy.retention_days;
    el("ec-policy-label").textContent = available ? (conversationAvailable ? "Ready for conversation and drafts" : "Ready for task questions") : "Companion unavailable";
    el("ec-badge").textContent = available ? (conversationAvailable ? "Drafts only" : "Task checks") : "Not enabled";
    el("ec-policy-summary").textContent = data.explanation || (available ? "Your own task status, under your administrator's policy." : "Ask your administrator about companion enrollment.");
    el("ec-retention").textContent = days === 0
      ? "New messages are not saved on the server. Refresh clears unsaved conversation text from this page, as does clearing history, reloading or leaving. AI follow-ups do not include earlier messages when history is not saved. Provider retention is separate."
      : "History expires after " + retentionLabel(days) + ". Expired messages are removed when you access history or an administrator updates your policy. You can clear it here.";
    el("ec-message-help").textContent = conversationAvailable
      ? "Ask for advice or a draft. Review the reply before using it; the companion cannot take actions."
      : "AI conversation is not enabled for you. You can ask task-status questions when your policy allows them.";
    el("ec-message").placeholder = conversationAvailable ? "Help me draft an update for my team." : "What is running?";
    if (updateConversation !== false) {
      // Only the server can reauthorize historic task-derived content. A fresh
      // snapshot clears unsaved turns instead of preserving unknown authority.
      messages = Array.isArray(data.history) ? data.history : [];
      renderMessages();
    }
    renderTasks(Array.isArray(data.tasks) ? data.tasks : []);
    if (data.active_turn && !replyRequestId) {
      replyRequestId = data.active_turn.request_id;
      replyPending = true;
      replyNotice("A reply is already being prepared. Refresh can update your active tasks while you wait. Check the reply before starting another request.", true, true);
    }
  }
  function selectEmployee() {
    var owner = el("ec-owner").value;
    var selected = policies.find(function (item) { return item.owner === owner; });
    selected = selected || { revision: 0, enabled: false, allowed_sources: [], allowed_tools: [], retention_days: 0 };
    el("ec-revision").value = String(selected.revision);
    el("ec-enabled").checked = selected.enabled === true;
    el("ec-source").checked = (selected.allowed_sources || []).includes("own_tasks");
    el("ec-tool").checked = (selected.allowed_tools || []).includes("task_status");
    el("ec-draft-tool").checked = (selected.allowed_tools || []).includes("draft_reply");
    el("ec-retention-days").value = String(selected.retention_days);
    el("ec-selection-summary").textContent = !owner ? "Choose an employee to review their policy." : selected.revision === 0 ? "Not enrolled. Review the options before enabling." : "Showing this employee's saved policy.";
    shareEmployeeSelection(owner);
    setBusy(busy);
  }
  function tableEmpty(container, text) {
    var row = node("tr");
    var cell = node("td", text);
    cell.colSpan = 4;
    row.appendChild(cell);
    container.appendChild(row);
  }
  function metadataCell(row, label, value) {
    var cell = node("td", value);
    cell.dataset.label = label;
    row.appendChild(cell);
  }
  function applyAdmin(data) {
    policies = Array.isArray(data.policies) ? data.policies : [];
    employees = Array.isArray(data.employees) ? data.employees : [];
    available = data.available === true;
    el("ec-policy-label").textContent = available ? "Workspace preview enabled" : "Workspace preview turned off";
    el("ec-badge").textContent = available ? "Drafts and task checks" : "Off";
    el("ec-policy-summary").textContent = data.explanation || (available ? "Each employee also needs an enabled policy." : "You can prepare employee policies while the workspace preview is off.");
    var owner = el("ec-owner");
    var selected = owner.value;
    owner.textContent = "";
    var placeholder = node("option", employees.length ? "Choose an employee" : "No employees available");
    placeholder.value = "";
    owner.appendChild(placeholder);
    employees.forEach(function (employee) {
      var option = node("option", employee.label || "Employee");
      option.value = employee.principal;
      owner.appendChild(option);
    });
    if (employees.some(function (employee) { return employee.principal === selected; })) { owner.value = selected; }
    var rows = el("ec-policies");
    rows.textContent = "";
    if (!policies.length) { tableEmpty(rows, "No employee policies saved yet. Choose an employee above to begin."); }
    policies.forEach(function (item) {
      var row = node("tr");
      metadataCell(row, "Employee", employeeName(item.owner));
      metadataCell(row, "Companion", item.enabled ? "Enabled" : "Disabled");
      var taskAccess = (item.allowed_sources || []).includes("own_tasks") && (item.allowed_tools || []).includes("task_status");
      var grants = [];
      if (taskAccess) { grants.push("Own task status"); }
      if ((item.allowed_tools || []).includes("draft_reply")) { grants.push("AI conversation and drafts"); }
      metadataCell(row, "Allowed help", grants.length ? grants.join("; ") : "No help enabled");
      metadataCell(row, "History", retentionLabel(item.retention_days));
      rows.appendChild(row);
    });
    var events = el("ec-events");
    events.textContent = "";
    var activity = Array.isArray(data.events) ? data.events : [];
    if (!activity.length) { tableEmpty(events, "No companion activity recorded yet. Activity appears here when you use your companion."); }
    var actions = {
      policy_updated: "Policy changed", policy_changed: "Policy changed", policy_saved: "Policy saved",
      reply: "Companion question answered", message: "Task question answered", message_answered: "Task question answered", read: "Task status checked",
      history_cleared: "Conversation history cleared", history_deleted: "Conversation history cleared",
      history_expired: "Expired conversation history removed", retention_pruned: "Expired conversation history removed", message_denied: "Question blocked by policy",
      turn_started: "AI reply started", draft_reply: "AI draft prepared", turn_failed: "AI reply failed",
      turn_expired: "AI reply expired", turn_cancelled: "AI reply cancelled"
    };
    activity.forEach(function (event) {
      var row = node("tr");
      metadataCell(row, "When", dateLabel(event.time));
      metadataCell(row, "Employee", employeeName(event.owner));
      metadataCell(row, "Activity", actions[event.action] || "Companion activity recorded");
      metadataCell(row, "By", employeeName(event.actor));
      events.appendChild(row);
    });
    selectEmployee();
  }
  async function refresh() {
    if (busy || blocked) { return; }
    setBusy(true);
    if (!admin && viewedReplyId) {
      el("ec-retained-reply").hidden = true;
      el("ec-retained-answer").textContent = "";
    }
    var version = conversationVersion;
    announce(admin ? "Loading saved policies and activity." : "Checking your policy and task status.");
    try {
      var data = await request(admin ? "/admin" : "");
      if (admin) { applyAdmin(data); } else { applyEmployee(data, version === conversationVersion); }
      loaded = true;
      stale = false;
      if (!admin) { shareOwnSelection(true); }
      announce(admin ? "Saved policies and activity are up to date." : available ? "Ready. Ask about your work." : "Your companion is unavailable. You can still clear your conversation history.");
    } catch (error) { failure(error); }
    finally { setBusy(false); }
    if (!admin && (openingReply || viewedReplyId) && loaded && !blocked && !stale) {
      viewedReplyId = openingReply || viewedReplyId;
      replyRequestId = viewedReplyId;
      openingReply = "";
      await checkReply();
    }
  }

  function requestId() {
    var id;
    if (window.crypto && typeof window.crypto.randomUUID === "function") {
      id = window.crypto.randomUUID().replace(/-/g, "");
    } else if (window.crypto && typeof window.crypto.getRandomValues === "function") {
      var bytes = window.crypto.getRandomValues(new Uint8Array(16));
      id = Array.from(bytes, function (value) { return value.toString(16).padStart(2, "0"); }).join("");
    } else { throw new Error("Your browser cannot safely identify this request. Use a current browser to ask for a reply."); }
    return String(Date.now()) + "." + id;
  }
  function acceptAnswer(data, question) {
    if (!data.message || typeof data.message.content !== "string" || !data.policy) {
      throw new Error("The answer could not be confirmed. Your question is still here. Check reply status before starting a new request.");
    }
    policy = data.policy;
    if (Number.isInteger(data.history_generation)) { historyGeneration = data.history_generation; }
    if (policy.retention_days === 0) {
      messages = messages.map(function (message) { return Object.assign({}, message, { sources: [] }); });
      messages = messages.concat([{ role: "user", content: question }, data.message]).slice(-100);
    } else {
      messages = Array.isArray(data.history) ? data.history : messages.concat([{ role: "user", content: question }, data.message]);
      // Only this response carries freshly authorized source links.
      if (messages.length && messages[messages.length - 1].role === "assistant") {
        messages[messages.length - 1] = data.message;
      }
    }
    conversationVersion += 1;
    renderMessages();
  }
  async function sendTaskQuestion(question, clearInput) {
    if (blocked || stale || busy || taskQuestionBusy || replyPending || !loaded || !statusAvailable) { return; }
    taskQuestionBusy = true;
    var generation = historyGeneration, epoch = clearEpoch;
    setBusy(busy);
    announce("Checking your task status without an AI model.");
    try {
      var data = await request("/messages", "POST", { message: question, mode: "task_status",
        expected_revision: policy.revision, expected_history_generation: generation });
      if (generation !== historyGeneration || epoch !== clearEpoch) { return; }
      acceptAnswer(data, question);
      if (clearInput) { el("ec-message").value = ""; }
      announce("Task check ready. Your ongoing work is unchanged.");
    } catch (error) { failure(error); }
    finally { taskQuestionBusy = false; setBusy(busy); }
  }
  async function checkReply() {
    if (!replyRequestId || blocked || receiptBusy || busy) { return; }
    receiptBusy = true;
    var id = replyRequestId;
    setBusy(busy);
    try {
      var data = await request("/requests/" + encodeURIComponent(id));
      if (id !== replyRequestId) { return; }
      var receipt = data.request;
      if (!receipt || receipt.request_id !== id) { throw new Error("Reply status could not be confirmed. Check again before starting a new request."); }
      if (data.policy) { applyEmployee(data, false); stale = false; }
      if (receipt.state === "pending") {
        el("ec-retained-reply").hidden = true;
        el("ec-retained-answer").textContent = "";
        replyPending = true;
        replyNotice("Your reply is still being prepared. Refresh can update your active tasks while you wait. Check again before starting another request.", true, true);
      } else if (["completed", "failed", "expired", "cancelled", "not_started"].includes(receipt.state)) {
        // Keep the direct response eligible while its request is still open.
        if (replyNetworkBusy === id) {
          replyNotice("Reply status was checked. Waiting for the open request to return to this page; no new request has been sent.", true, true);
          return;
        }
        replyPending = false;
        replyRequestId = "";
        newReplyWarning = true;
        if (Number.isInteger(data.history_generation)) { historyGeneration = data.history_generation; }
        if (policy && policy.retention_days > 0 && Array.isArray(data.history)) {
          messages = data.history;
          conversationVersion += 1;
          renderMessages();
        }
        var exactReply = data.retained_reply;
        el("ec-retained-reply").hidden = !(receipt.state === "completed" && exactReply && typeof exactReply.content === "string");
        el("ec-retained-answer").textContent = el("ec-retained-reply").hidden ? "" : exactReply.content;
        if (data.active_turn && data.active_turn.request_id !== id) {
          replyRequestId = data.active_turn.request_id;
          replyPending = true;
          replyNotice("Another reply is already being prepared. Refresh can update your active tasks; check this reply before starting a new one.", true, true);
          return;
        }
        var explanation = receipt.state === "completed"
          ? (exactReply && typeof exactReply.content === "string" ? "The reply completed. Its exact saved answer is shown here." : policy && policy.retention_days === 0 ? "The reply completed, but the answer cannot be recovered because history is not saved." : "The reply completed, but its exact answer is no longer saved or currently accessible. Available conversation is shown above.")
          : receipt.state === "not_started" ? "No request receipt was found. Earlier provider processing cannot be ruled out. The question has not been resent."
            : receipt.state === "cancelled" ? "The reply was cancelled. Any earlier provider processing may still be billed."
              : "This reply did not complete. Earlier provider processing may still be billed.";
        replyNotice(explanation + " Starting a new reply sends a separate request and may incur a new charge.", false, false);
      } else { throw new Error("Reply status is not yet known. Check again before starting a new request."); }
    } catch (error) {
      failure(error);
      if (!blocked) { replyNotice("Reply status could not be checked. No new request has been sent. Check again before asking for another reply.", false, true); }
    } finally { receiptBusy = false; setBusy(busy); }
  }

  el("ec-refresh").addEventListener("click", refresh);
  if (admin) {
    el("ec-owner").addEventListener("change", selectEmployee);
    el("ec-copilot").addEventListener("click", async function () {
      if (busy || blocked || !loaded || !el("ec-owner").value) { return; }
      var selectedOwner = el("ec-owner").value;
      setBusy(true);
      try {
        var data = await request("/admin");
        if (!(data.employees || []).some(function (employee) { return employee.principal === selectedOwner; })) {
          applyAdmin(data);
          announce("This employee is no longer available. Choose a current employee.", true);
          return;
        }
        shareEmployeeSelection(selectedOwner);
        var opener = document.getElementById("mv-copilot-fab");
        if (opener) {
          if (opener.getAttribute("aria-expanded") !== "true") { opener.click(); }
        } else { announce("Open Copilot to review this employee's saved policy and activity."); }
      } catch (error) { failure(error); }
      finally { setBusy(false); }
    });
    document.addEventListener("lightwork:product-operation-complete", function (event) {
      var detail = event.detail || {};
      if (!blocked && detail.operation === "companion.admin.policy" &&
          ["confirmed", "replayed", "unconfirmed"].includes(detail.status)) { refresh(); }
    });
    el("ec-policy-form").addEventListener("submit", async function (event) {
      event.preventDefault();
      if (busy || blocked || stale || !loaded || !el("ec-owner").value) { return; }
      var body = {
        owner: el("ec-owner").value, expected_revision: Number(el("ec-revision").value),
        enabled: el("ec-enabled").checked,
        allowed_sources: el("ec-source").checked ? ["own_tasks"] : [],
        allowed_tools: (el("ec-tool").checked ? ["task_status"] : []).concat(el("ec-draft-tool").checked ? ["draft_reply"] : []),
        retention_days: Number(el("ec-retention-days").value)
      };
      setBusy(true);
      announce("Saving this employee's policy.");
      try {
        await request("/admin/policy", "PUT", body);
        // Read the current workspace snapshot before claiming the page is current.
        var data = await request("/admin");
        applyAdmin(data);
        announce("Policy saved. The current settings are shown below.");
      } catch (error) { failure(error); }
      finally { setBusy(false); }
    });
  } else {
    el("ec-own-copilot").addEventListener("click", async function () {
      if (busy || blocked || !loaded) { return; }
      await refresh();
      if (blocked || stale || !loaded) { return; }
      shareOwnSelection(true);
      var opener = document.getElementById("mv-copilot-fab");
      if (opener && opener.getAttribute("aria-expanded") !== "true") { opener.click(); }
      else if (!opener) { announce("Open Copilot to check your current work or review a draft request."); }
    });
    document.addEventListener("lightwork:product-operation-complete", function (event) {
      var detail = event.detail || {};
      if (!blocked && detail.operation === "companion.draft") {
        viewedReplyId = "";
        el("ec-retained-reply").hidden = true;
        el("ec-retained-answer").textContent = "";
        refresh(); return;
      }
      if (blocked || detail.operation !== "companion.clear_history" ||
          !["confirmed", "replayed"].includes(detail.status)) { return; }
      // Invalidate in-flight replies before re-reading the owner-bound source.
      clearEpoch += 1;
      historyRevision = "";
      conversationVersion += 1;
      messages = [];
      replyPending = false;
      replyRequestId = "";
      viewedReplyId = "";
      el("ec-retained-reply").hidden = true;
      el("ec-retained-answer").textContent = "";
      newReplyWarning = false;
      el("ec-message").value = "";
      el("ec-reply-state").hidden = true;
      el("ec-clear-confirm").hidden = true;
      renderMessages();
      announce("Your companion conversation was cleared. Checking current status.");
      refresh();
    });
    el("ec-message-form").addEventListener("submit", async function (event) {
      event.preventDefault();
      if (busy || blocked || stale || replyPending || taskQuestionBusy || !loaded || !available) { return; }
      var input = el("ec-message");
      var question = input.value.trim();
      if (!question) { input.focus(); return; }
      if (!conversationAvailable) { await sendTaskQuestion(question, true); return; }
      var id;
      try { id = requestId(); }
      catch (error) { failure(error); return; }
      replyRequestId = id;
      viewedReplyId = "";
      el("ec-retained-reply").hidden = true;
      el("ec-retained-answer").textContent = "";
      replyPending = true;
      replyNetworkBusy = id;
      newReplyWarning = false;
      var generation = historyGeneration, epoch = clearEpoch;
      setBusy(busy);
      replyNotice("Your companion is preparing a draft. Refresh can update your active tasks while you wait.", true, true);
      try {
        var data = await request("/messages", "POST", { message: question, mode: "conversation", request_id: id,
          expected_revision: policy.revision, expected_history_generation: generation }, 120000);
        if (id !== replyRequestId || generation !== historyGeneration || epoch !== clearEpoch) { return; }
        acceptAnswer(data, question);
        input.value = "";
        replyPending = false;
        replyRequestId = "";
        el("ec-retained-reply").hidden = true;
        el("ec-retained-answer").textContent = "";
        replyNotice("Draft ready. Review it before use. No task or external action was performed.", false, false);
      } catch (error) {
        if (id !== replyRequestId) { return; }
        failure(error);
        if (!blocked) {
          replyNotice("The reply could not be confirmed. It may still complete or incur a provider charge. Your question is still here; check reply status before starting a new request.", false, true);
        }
      } finally { if (replyNetworkBusy === id) { replyNetworkBusy = ""; } setBusy(busy); if (!input.disabled) { input.focus(); } }
    });
    root.querySelectorAll("[data-question]").forEach(function (button) {
      button.addEventListener("click", function () {
        sendTaskQuestion(button.dataset.question, false);
      });
    });
    el("ec-check-reply").addEventListener("click", checkReply);
    el("ec-clear").addEventListener("click", function () {
      el("ec-clear-confirm").hidden = false;
      el("ec-clear-no").focus();
    });
    el("ec-clear-no").addEventListener("click", function () {
      el("ec-clear-confirm").hidden = true;
      el("ec-clear").focus();
    });
    el("ec-clear-yes").addEventListener("click", async function () {
      if (busy || blocked || !loaded) { return; }
      setBusy(true);
      announce("Clearing your conversation history.");
      try {
        if (!historyRevision) { throw new Error("Refresh your companion before clearing its conversation."); }
        var data = await request("/history", "DELETE", {expected_revision: historyRevision});
        if (Number.isInteger(data.history_generation)) { historyGeneration = data.history_generation; }
        if (typeof data.history_revision === "string") { historyRevision = data.history_revision; }
        conversationVersion += 1;
        messages = [];
        replyPending = false;
        replyRequestId = "";
        viewedReplyId = "";
        el("ec-retained-reply").hidden = true;
        el("ec-retained-answer").textContent = "";
        newReplyWarning = false;
        el("ec-message").value = "";
        el("ec-reply-state").hidden = true;
        renderMessages();
        el("ec-clear-confirm").hidden = true;
        announce("Your companion conversation has been cleared. Your tasks are unchanged.");
      } catch (error) { failure(error); }
      finally { setBusy(false); if (!el("ec-clear").disabled) { el("ec-clear").focus(); } }
    });
  }
  // Do not carry private content through the browser's page restoration cache.
  window.addEventListener("pagehide", function () { blocked = true; clearSensitiveView(); });
  window.addEventListener("pageshow", function (event) { if (event.persisted) { window.location.reload(); } });
  refresh();
})();
