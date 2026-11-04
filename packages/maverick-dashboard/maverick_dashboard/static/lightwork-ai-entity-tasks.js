/* AI-entity task operator workbench. Tenant, actor, entity authority, authority
   digest, retention policy, and storage remain server-owned. */
(function () {
  "use strict";

  var MAX_RESPONSE_BYTES = 64 * 1024;
  var ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
  var OPERATION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$/;

  function responseTooLarge() {
    var error = new Error("Lightwork returned more than this page can show. Narrow the filters and try again.");
    error.code = "response_too_large";
    return error;
  }

  function invalidResponse() {
    var error = new Error("Lightwork returned something unexpected. Refresh the page and try again.");
    error.code = "response_invalid_json";
    return error;
  }

  async function cancelBody(body) {
    if (!body || typeof body.cancel !== "function") return;
    try { await body.cancel(); }
    catch (_error) { /* The bounded request has already failed closed. */ }
  }

  async function boundedResponseText(response) {
    var declared = response.headers && response.headers.get("Content-Length");
    if (declared && /^\d+$/.test(declared) && Number(declared) > MAX_RESPONSE_BYTES) {
      await cancelBody(response.body);
      throw responseTooLarge();
    }
    if (!response.body || typeof response.body.getReader !== "function") {
      // A whole-body fallback cannot enforce the raw-byte ceiling before
      // allocation. Supported browsers expose a stream; otherwise fail closed.
      throw invalidResponse();
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
        try { await reader.cancel(); }
        catch (_error) { /* The size violation remains authoritative. */ }
        throw responseTooLarge();
      }
      text += decoder.decode(chunk.value, {stream: true});
    }
    return text + decoder.decode();
  }

  function isRecord(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }

  async function readBoundedJson(response) {
    var responseText = await boundedResponseText(response);
    if (!responseText) throw invalidResponse();
    var payload;
    try { payload = JSON.parse(responseText); }
    catch (_error) { throw invalidResponse(); }
    if (!isRecord(payload)) throw invalidResponse();
    return payload;
  }

  async function parseResponse(response) {
    var payload;
    try { payload = await readBoundedJson(response); }
    catch (error) {
      error.status = response.status;
      throw error;
    }
    if (!response.ok) {
      var failure = new Error(friendly(response.status));
      failure.status = response.status;
      failure.technical = typeof payload.detail === "string" ? payload.detail : "";
      throw failure;
    }
    return payload;
  }

  function friendly(status) {
    if (typeof window !== "undefined" && typeof window.mvErrorText === "function") {
      return window.mvErrorText({status: status}, "finish this");
    }
    if (status === 403) return "You do not have permission to do this. Ask an administrator.";
    if (status === 409) return "This changed since you opened it. Refresh the page and try again.";
    return "Something went wrong. Try again.";
  }

  function positiveInteger(raw, label, maximum) {
    var selected = Number(raw);
    if (!Number.isSafeInteger(selected) || selected < 1 || selected > maximum) {
      throw new Error("The page is out of date. Refresh it and try again.");
    }
    return selected;
  }

  function identifier(raw, label) {
    var selected = String(raw || "").trim();
    if (!ID_PATTERN.test(selected)) {
      throw new Error(label + " is not a valid choice. Choose it from the list.");
    }
    return selected;
  }

  function operationKey(raw) {
    var selected = String(raw || "").trim();
    if (!OPERATION_PATTERN.test(selected)) {
      throw new Error("The page is not ready yet. Refresh it and try again.");
    }
    return selected;
  }

  function splitRefs(raw) {
    var selected = String(raw || "").trim();
    if (!selected) return [];
    var seen = Object.create(null);
    var result = [];
    selected.split(",").forEach(function (candidate) {
      var reference = identifier(candidate, "A person you chose (not a valid reference)");
      if (!seen[reference]) {
        seen[reference] = true;
        result.push(reference);
      }
    });
    if (result.length > 64) throw new Error("No more than 64 collaborators are allowed.");
    return result;
  }

  function futureTimestamp(raw, label) {
    var milliseconds = Date.parse(String(raw || ""));
    if (!Number.isFinite(milliseconds) || milliseconds <= Date.now()) {
      throw new Error(label + " must be in the future.");
    }
    return milliseconds / 1000;
  }

  function buildCreatePayload(fields) {
    var title = String(fields.title || "").trim();
    if (!title || title.length > 500) throw new Error("Give the task a title (up to 500 characters).");
    var description = String(fields.description || "").trim();
    if (description.length > 16000) throw new Error("Keep the description under 16,000 characters.");
    var payload = {
      entity_id: identifier(fields.entity_id, "The AI system"),
      entity_revision: positiveInteger(fields.entity_revision, "Entity revision", 2147483647),
      kind: String(fields.kind),
      title: title,
      description: description,
      collaborator_refs: splitRefs(fields.collaborator_refs),
      priority: String(fields.priority),
      idempotency_key: operationKey(fields.idempotency_key)
    };
    if (["review", "remediation"].indexOf(payload.kind) === -1) {
      throw new Error("Choose a type of task.");
    }
    if (["low", "medium", "high", "critical"].indexOf(payload.priority) === -1) {
      throw new Error("That priority is not one of the choices. Choose a priority from the list.");
    }
    var assignee = String(fields.assignee_ref || "").trim();
    if (assignee) payload.assignee_ref = identifier(assignee, "The person assigned");
    var due = String(fields.due_at || "").trim();
    if (due) payload.due_at = futureTimestamp(due, "Due date");
    return payload;
  }

  function buildUpdatePayload(fields) {
    var payload = {
      expected_revision: positiveInteger(fields.expected_revision, "Expected revision", 2147483647),
      idempotency_key: operationKey(fields.idempotency_key)
    };
    var changes = 0;
    var status = String(fields.status || "");
    if (status) {
      if (["open", "in_progress", "blocked", "resolved", "dismissed"].indexOf(status) === -1) {
        throw new Error("That status is not one of the choices. Choose a status from the list.");
      }
      payload.status = status;
      changes += 1;
    }
    var priority = String(fields.priority || "");
    if (priority) {
      if (["low", "medium", "high", "critical"].indexOf(priority) === -1) {
        throw new Error("That priority is not one of the choices. Choose a priority from the list.");
      }
      payload.priority = priority;
      changes += 1;
    }
    var assigneeAction = String(fields.assignee_action || "keep");
    if (assigneeAction === "set") {
      payload.assignee_ref = identifier(fields.assignee_ref, "The person assigned");
      changes += 1;
    } else if (assigneeAction === "clear") {
      payload.assignee_ref = null;
      changes += 1;
    } else if (assigneeAction !== "keep") {
      throw new Error("The assignee change was not recognized. Refresh the page and try again.");
    }
    var collaboratorAction = String(fields.collaborator_action || "keep");
    if (collaboratorAction === "replace") {
      payload.collaborator_refs = splitRefs(fields.collaborator_refs);
      changes += 1;
    } else if (collaboratorAction === "clear") {
      payload.collaborator_refs = [];
      changes += 1;
    } else if (collaboratorAction !== "keep") {
      throw new Error("The collaborator change was not recognized. Refresh the page and try again.");
    }
    var dueAction = String(fields.due_action || "keep");
    if (dueAction === "set") {
      payload.due_at = futureTimestamp(fields.due_at, "Due date");
      changes += 1;
    } else if (dueAction === "clear") {
      payload.due_at = null;
      changes += 1;
    } else if (dueAction !== "keep") {
      throw new Error("The due date change was not recognized. Refresh the page and try again.");
    }
    if (changes === 0) throw new Error("Select at least one change to save. Nothing was changed.");
    return payload;
  }

  if (typeof window !== "undefined") {
    Object.defineProperty(window, "LightworkAIEntityTasksClient", {
      configurable: false,
      enumerable: false,
      writable: false,
      value: Object.freeze({
        MAX_RESPONSE_BYTES: MAX_RESPONSE_BYTES,
        readBoundedJson: readBoundedJson,
        parseResponse: parseResponse,
        splitRefs: splitRefs,
        buildCreatePayload: buildCreatePayload,
        buildUpdatePayload: buildUpdatePayload
      })
    });
  }

  if (typeof document === "undefined") return;
  var shell = document.getElementById("ai-entity-task-shell");
  if (!shell) return;
  var apiBase = shell.dataset.apiBase || "";
  var can = {
    operate: shell.dataset.canOperate === "true",
    audit: shell.dataset.canAudit === "true",
    admin: shell.dataset.canAdmin === "true"
  };
  var operations = document.getElementById("aet-operations");
  var readiness = document.getElementById("aet-readiness");
  var readinessDetail = document.getElementById("aet-readiness-detail");
  var statusMark = document.getElementById("aet-status-mark");
  var operationStatus = document.getElementById("aet-operation-status");
  var operationOutput = document.getElementById("aet-operation-output");
  var taskList = document.getElementById("aet-task-list");
  var listStatus = document.getElementById("aet-list-status");
  var listCount = document.getElementById("aet-list-count");
  var filterForm = document.getElementById("aet-filter-form");
  var createForm = document.getElementById("aet-create-form");
  var createControls = document.getElementById("aet-create-controls");
  var inventoryStatus = document.getElementById("aet-inventory-status");
  var inventoryLink = document.getElementById("aet-inventory-link");
  var updateForm = document.getElementById("aet-update-form");
  var updatePanel = document.getElementById("aet-update-panel");
  var entities = [];
  var people = [];
  var editing = null;
  var STATUS = {
    open: ["Open", "idle"], in_progress: ["In progress", "running"], blocked: ["Blocked", "warn"],
    resolved: ["Resolved", "ok"], dismissed: ["Dismissed", "idle"]
  };

  function field(form, name) {
    var selected = form.elements.namedItem(name);
    if (!selected || typeof selected.value !== "string") {
      throw new Error("The form is incomplete. Refresh the page and try again.");
    }
    return selected;
  }
  function human(value) {
    if (typeof window.mvHuman === "function") return window.mvHuman(value);
    var text = String(value || "").replace(/[_.-]+/g, " ").trim();
    return text ? text.charAt(0).toUpperCase() + text.slice(1) : "";
  }
  function setMark(label, state) {
    statusMark.textContent = label;
    statusMark.dataset.state = state;
    statusMark.className = "badge " + (state === "ready" ? "ok" : state === "failed" ? "warn" : "idle");
  }
  function technical(value) {
    operationOutput.textContent = value === undefined ? "" :
      typeof value === "string" ? value : JSON.stringify(value, null, 2);
  }
  function say(message, failed, details) {
    window.mvStatus(operationStatus, message, {error: !!failed});
    operationStatus.dataset.state = failed ? "failed" : "ready";
    technical(details);
  }
  function fail(error) {
    say(error && error.message ? error.message : "Something went wrong. Try again.", true,
      error && error.technical ? error.technical : undefined);
  }
  function reference(prefix) {
    if (window.crypto && typeof window.crypto.randomUUID === "function") return prefix + "-" + window.crypto.randomUUID();
    return prefix + "-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 12);
  }

  async function requestAt(url, options, limit) {
    var supplied = options || {};
    var selected = Object.assign({
      cache: "no-store",
      credentials: "same-origin",
      redirect: "error",
      referrerPolicy: "no-referrer"
    }, supplied);
    selected.headers = Object.assign({Accept: "application/json"}, supplied.headers || {});
    var response = await fetch(url, selected);
    if (!limit) return parseResponse(response);
    // Inventory and people lists are larger than one task record; read them
    // with their own ceiling, then apply the same parsing rules.
    var declared = response.headers && response.headers.get("Content-Length");
    if (declared && /^\d+$/.test(declared) && Number(declared) > limit) throw responseTooLarge();
    var text = await response.text();
    if (text.length > limit) throw responseTooLarge();
    var payload;
    try { payload = JSON.parse(text); } catch (_error) { throw invalidResponse(); }
    if (!isRecord(payload)) throw invalidResponse();
    if (!response.ok) {
      var failure = new Error(friendly(response.status));
      failure.status = response.status;
      throw failure;
    }
    return payload;
  }
  function request(path, options) { return requestAt(apiBase + path, options); }

  function clear(element) { while (element.firstChild) element.removeChild(element.firstChild); }
  function make(tag, className, text) {
    var element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = String(text);
    return element;
  }
  function formattedDate(value) {
    if (typeof value !== "number" || !Number.isFinite(value)) return "—";
    var date = new Date(value * 1000);
    return Number.isNaN(date.getTime()) ? "—" : window.mvDateAbsolute ? window.mvDateAbsolute(value) : date.toLocaleDateString();
  }
  function dateInputValue(value) {
    if (typeof value !== "number" || !Number.isFinite(value)) return "";
    var date = new Date(value * 1000);
    var month = String(date.getMonth() + 1).padStart(2, "0");
    var day = String(date.getDate()).padStart(2, "0");
    return date.getFullYear() + "-" + month + "-" + day;
  }
  function endOfDay(value) {
    if (!value) return "";
    var parts = String(value).split("-").map(Number);
    if (parts.length !== 3 || parts.some(function (part) { return !Number.isFinite(part); })) return "";
    return new Date(parts[0], parts[1] - 1, parts[2], 23, 59, 0).toISOString();
  }
  function entityName(entityId) {
    for (var i = 0; i < entities.length; i += 1) if (entities[i].asset_id === entityId) return entities[i].label;
    return "An AI system no longer in the inventory";
  }
  function personName(ref) {
    if (!ref) return "Nobody";
    for (var i = 0; i < people.length; i += 1) if (people[i].ref === ref) return people[i].label;
    return "Someone outside this list";
  }

  // ---- pickers ---------------------------------------------------------
  function fillSelect(select, items, keepFirst) {
    var first = keepFirst ? select.options[0] : null;
    var previous = select.value;
    clear(select);
    if (first) select.appendChild(first);
    items.forEach(function (item) {
      var option = document.createElement("option");
      option.value = item[0]; option.textContent = item[1];
      select.appendChild(option);
    });
    if (items.some(function (item) { return item[0] === previous; })) select.value = previous;
  }
  function fillCollaborators(box, selected) {
    Array.prototype.slice.call(box.querySelectorAll("label, p")).forEach(function (node) { node.remove(); });
    if (!people.length) { box.appendChild(make("p", "muted", "No people to choose from yet.")); return; }
    people.forEach(function (person) {
      var label = document.createElement("label");
      var box2 = document.createElement("input");
      box2.type = "checkbox"; box2.name = "collaborator"; box2.value = person.ref;
      box2.checked = Array.isArray(selected) && selected.indexOf(person.ref) >= 0;
      label.appendChild(box2); label.appendChild(document.createTextNode(" " + person.label));
      box.appendChild(label);
    });
  }
  function chosenCollaborators(box) {
    return Array.prototype.slice.call(box.querySelectorAll('input[name="collaborator"]:checked')).map(function (item) { return item.value; });
  }
  async function loadPickers() {
    var inventoryLoaded = false;
    try {
      var inventory = await requestAt("/api/v1/security/assurance/ai-inventory", {}, 4 * 1024 * 1024);
      if (!Array.isArray(inventory.assets)) throw invalidResponse();
      entities = inventory.assets.filter(function (asset) {
        return isRecord(asset) && ID_PATTERN.test(String(asset.asset_id || "")) && asset.status === "present";
      }).map(function (asset) {
        return {
          asset_id: asset.asset_id,
          revision: asset.revision,
          label: String(asset.display_name || "Unnamed AI system") + (asset.asset_type ? " (" + human(asset.asset_type) + ")" : "")
        };
      });
      inventoryLoaded = true;
    } catch (_error) {
      entities = [];
    }
    createControls.disabled = !can.operate || !inventoryLoaded || !entities.length;
    inventoryStatus.textContent = !inventoryLoaded
      ? "Could not load AI systems. Choose Check again above to retry. Existing tasks remain available."
      : !entities.length
        ? "No AI systems are ready to choose. Add one in AI inventory first."
        : entities.length + " AI " + (entities.length === 1 ? "system is" : "systems are") + " available.";
    inventoryLink.hidden = inventoryLoaded && !!entities.length;
    try {
      var directory = await requestAt("/api/v1/people/assignable", {}, 512 * 1024);
      people = Array.isArray(directory.items) ? directory.items.filter(function (item) {
        return isRecord(item) && ID_PATTERN.test(String(item.ref || ""));
      }).map(function (item) {
        return {ref: item.ref, label: String(item.label || item.ref) + (item.is_you ? " (you)" : "")};
      }) : [];
    } catch (_error) {
      people = [];
    }
    Array.prototype.forEach.call(document.querySelectorAll("[data-entity-picker]"), function (select) {
      fillSelect(select, entities.map(function (item) { return [item.asset_id, item.label]; }), true);
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-person-picker]"), function (select) {
      fillSelect(select, people.map(function (item) { return [item.ref, item.label]; }), true);
    });
    fillCollaborators(document.querySelector('[data-collaborator-picker="create"]'), []);
    if (!entities.length) {
      var createEntity = field(createForm, "entity_id");
      createEntity.options[0].textContent = inventoryLoaded
        ? "No AI systems in inventory yet" : "AI systems could not be loaded";
    }
  }

  // ---- list ------------------------------------------------------------
  function rowButton(label, handler, cls, aria) {
    var button = make("button", cls || "btn", label);
    button.type = "button";
    if (aria) button.setAttribute("aria-label", aria);
    button.addEventListener("click", function () {
      if (button.disabled) return;
      button.disabled = true;
      Promise.resolve().then(handler).catch(fail).then(function () { button.disabled = false; });
    });
    return button;
  }
  function renderTasks(payload) {
    clear(taskList);
    var items = Array.isArray(payload.items) ? payload.items : [];
    listCount.textContent = items.length + (items.length === 1 ? " task" : " tasks");
    if (!items.length) {
      var tr0 = make("tr");
      var td0 = make("td", "", can.operate ? "No tasks match. Use New task below to add one." : "No tasks match these filters.");
      td0.colSpan = 7; tr0.appendChild(td0); taskList.appendChild(tr0);
      return;
    }
    items.forEach(function (task) {
      if (!isRecord(task)) return;
      var tr = make("tr");
      var th = make("th", "", task.title || "Untitled task"); th.scope = "row"; tr.appendChild(th);
      tr.appendChild(make("td", "", entityName(task.entity_id)));
      var stateCell = make("td");
      var pair = STATUS[task.status] || [human(task.status), "idle"];
      stateCell.appendChild(make("span", "badge " + pair[1], pair[0]));
      tr.appendChild(stateCell);
      tr.appendChild(make("td", "", human(task.priority)));
      tr.appendChild(make("td", "", personName(task.assignee_ref)));
      tr.appendChild(make("td", "", formattedDate(task.due_at)));
      var actions = make("td");
      var wrap = make("div", "aet-actions");
      if (can.operate) wrap.appendChild(rowButton("Edit", function () { return openEdit(task); }, "btn", "Edit " + (task.title || "task")));
      wrap.appendChild(rowButton("History", function () { return history(task); }, "btn btn--ghost", "History of " + (task.title || "task")));
      actions.appendChild(wrap); tr.appendChild(actions);
      taskList.appendChild(tr);
    });
  }
  async function loadTasks() {
    listStatus.textContent = "Loading tasks…";
    try {
      var query = new URLSearchParams();
      ["entity_id", "status", "assignee_ref", "priority"].forEach(function (name) {
        var value = field(filterForm, name).value.trim();
        if (value) query.set(name, value);
      });
      query.set("limit", "200");
      var payload = await request("?" + query.toString());
      renderTasks(payload);
      listStatus.textContent = "Showing " + String(payload.count || 0) + " " + (payload.count === 1 ? "task" : "tasks") + ".";
      return payload;
    } catch (error) {
      clear(taskList);
      listCount.textContent = "0 tasks";
      listStatus.textContent = error && error.message ? error.message : "Couldn't load tasks. Refresh the page and try again.";
      throw error;
    }
  }

  // ---- edit and history --------------------------------------------------
  async function openEdit(task) {
    var record = await request("/" + encodeURIComponent(identifier(task.task_id, "The task")));
    editing = record;
    field(updateForm, "task_id").value = String(record.task_id || "");
    field(updateForm, "expected_revision").value = String(record.revision || "");
    field(updateForm, "status").value = record.status || "open";
    field(updateForm, "priority").value = record.priority || "medium";
    field(updateForm, "assignee_ref").value = record.assignee_ref || "";
    field(updateForm, "due_at").value = dateInputValue(record.due_at);
    fillCollaborators(document.querySelector('[data-collaborator-picker="update"]'), record.collaborator_refs || []);
    document.getElementById("aet-update-subject").textContent = (record.title || "Untitled task") + " · " + entityName(record.entity_id);
    updatePanel.hidden = false;
    var heading = document.getElementById("aet-update-title");
    if (heading && typeof heading.focus === "function") heading.focus();
  }
  async function history(task) {
    var payload = await request("/" + encodeURIComponent(identifier(task.task_id, "The task")) + "/history");
    var list = document.getElementById("aet-history-list");
    clear(list);
    var items = Array.isArray(payload.items) ? payload.items : [];
    items.forEach(function (item) {
      if (!isRecord(item)) return;
      var pair = STATUS[item.status] || [human(item.status)];
      list.appendChild(make("li", "", formattedDate(item.updated_at || item.created_at) + " — " + pair[0] +
        ", " + human(item.priority) + " priority, assigned to " + personName(item.assignee_ref)));
    });
    if (!items.length) list.appendChild(make("li", "", "No history yet. Changes to this task appear here."));
    document.getElementById("aet-history-panel").hidden = false;
    var heading = document.getElementById("aet-history-title");
    if (heading && typeof heading.focus === "function") heading.focus();
    say("Showing the history of " + (task.title || "the task") + ".", false, payload);
  }

  // ---- status ------------------------------------------------------------
  async function refreshStatus() {
    readiness.textContent = "Checking…";
    readinessDetail.textContent = "Checking availability before enabling actions.";
    setMark("Checking", "checking");
    operations.disabled = true;
    try {
      var payload = await request("/status");
      if (payload.ready === true && payload.enabled === true && payload.configured === true) {
        readiness.textContent = "Ready";
        readinessDetail.textContent = "Task controls are ready. Lightwork checks the current inventory item before each change.";
        setMark("Ready", "ready");
        operations.disabled = false;
        await loadPickers();
        try { await loadTasks(); } catch (_error) { /* shown in the list status */ }
        refreshRetention();
      } else if (payload.enabled !== true) {
        readiness.textContent = "Turned off";
        readinessDetail.textContent = "AI system tasks are turned off. Ask an administrator to turn them on.";
        setMark("Off", "failed");
        listStatus.textContent = "Tasks appear here once AI system tasks are turned on.";
        inventoryStatus.textContent = (window.LightworkI18n ? window.LightworkI18n.text("AI systems can be chosen once AI system tasks are turned on.") : "AI systems can be chosen once AI system tasks are turned on.");
      } else {
        readiness.textContent = "Setup not finished";
        readinessDetail.textContent = "AI system tasks are turned on, but setup isn't finished. Ask an administrator to complete it.";
        setMark("Not ready", "failed");
        listStatus.textContent = "Tasks appear here once an administrator finishes the setup.";
        inventoryStatus.textContent = (window.LightworkI18n ? window.LightworkI18n.text("AI systems can be chosen once an administrator finishes the setup.") : "AI systems can be chosen once an administrator finishes the setup.");
      }
    } catch (error) {
      readiness.textContent = "Unavailable";
      readinessDetail.textContent = error && error.message ? error.message : "Couldn't check availability. Refresh the page and try again.";
      setMark("Unavailable", "failed");
      // The list never started; say so instead of "Loading tasks…".
      listStatus.textContent = typeof window.mvErrorText === "function"
        ? window.mvErrorText(error, "load the tasks") : "Couldn't load the tasks. Choose Check again.";
      inventoryStatus.textContent = (window.LightworkI18n ? window.LightworkI18n.text("AI systems could not be checked. Choose Check again above to retry.") : "AI systems could not be checked. Choose Check again above to retry.");
    }
  }
  async function refreshRetention() {
    var summary = document.getElementById("aet-retention-summary");
    if (!can.audit) return;
    try {
      var payload = await request("/operations/retention-due?limit=1000");
      var count = Array.isArray(payload.items) ? payload.items.length : Number(payload.count) || 0;
      summary.textContent = count ? count + " expired " + (count === 1 ? "task is" : "tasks are") + " ready to be deleted." : "No tasks have expired.";
      var purge = document.getElementById("aet-purge-button");
      purge.textContent = count ? "Delete expired tasks (" + count + ")" : "Delete expired tasks";
      return count;
    } catch (error) {
      summary.textContent = error && error.message ? error.message : "Couldn't count expired tasks. Refresh the page and try again.";
      return 0;
    }
  }

  // ---- wiring ------------------------------------------------------------
  document.getElementById("aet-refresh-status").addEventListener("click", refreshStatus);
  filterForm.addEventListener("submit", function (event) {
    event.preventDefault();
    loadTasks().catch(function () {});
  });
  document.getElementById("aet-clear-filters").addEventListener("click", function () {
    filterForm.reset();
    loadTasks().catch(function () {});
  });
  document.getElementById("aet-update-cancel").addEventListener("click", function () {
    updatePanel.hidden = true;
    editing = null;
  });

  createForm.addEventListener("submit", async function (event) {
    event.preventDefault();
    try {
      var entityId = field(createForm, "entity_id").value;
      var entity = null;
      entities.forEach(function (item) { if (item.asset_id === entityId) entity = item; });
      if (!entity) throw new Error("Choose the AI system this task is about.");
      var due = field(createForm, "due_at").value;
      var payload = buildCreatePayload({
        entity_id: entity.asset_id,
        entity_revision: entity.revision,
        kind: field(createForm, "kind").value,
        title: field(createForm, "title").value,
        description: field(createForm, "description").value,
        assignee_ref: field(createForm, "assignee_ref").value,
        collaborator_refs: chosenCollaborators(document.querySelector('[data-collaborator-picker="create"]')).join(","),
        priority: field(createForm, "priority").value,
        due_at: endOfDay(due),
        idempotency_key: field(createForm, "idempotency_key").value || reference("create")
      });
      say("Creating the task…", false);
      var record = await request("", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)});
      createForm.reset();
      field(createForm, "idempotency_key").value = reference("create");
      fillCollaborators(document.querySelector('[data-collaborator-picker="create"]'), []);
      say("Task created: " + (record.title || "new task") + ".", false, record);
      await loadTasks();
    } catch (error) { fail(error); }
  });

  updateForm.addEventListener("submit", async function (event) {
    event.preventDefault();
    if (!editing) return;
    try {
      var status = field(updateForm, "status").value;
      var priority = field(updateForm, "priority").value;
      var assignee = field(updateForm, "assignee_ref").value;
      var dueValue = field(updateForm, "due_at").value;
      var collaborators = chosenCollaborators(document.querySelector('[data-collaborator-picker="update"]')).sort();
      var previousCollaborators = (editing.collaborator_refs || []).slice().sort();
      var collaboratorsChanged = collaborators.join(",") !== previousCollaborators.join(",");
      var dueChanged = dueValue !== dateInputValue(editing.due_at);
      var payload = buildUpdatePayload({
        expected_revision: field(updateForm, "expected_revision").value,
        idempotency_key: field(updateForm, "idempotency_key").value || reference("update"),
        status: status !== editing.status ? status : "",
        priority: priority !== editing.priority ? priority : "",
        assignee_action: assignee === (editing.assignee_ref || "") ? "keep" : assignee ? "set" : "clear",
        assignee_ref: assignee,
        collaborator_action: !collaboratorsChanged ? "keep" : collaborators.length ? "replace" : "clear",
        collaborator_refs: collaborators.join(","),
        due_action: !dueChanged ? "keep" : dueValue ? "set" : "clear",
        due_at: endOfDay(dueValue)
      });
      var taskId = encodeURIComponent(identifier(field(updateForm, "task_id").value, "The task"));
      say("Saving changes…", false);
      var record = await request("/" + taskId, {method: "PATCH", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)});
      field(updateForm, "idempotency_key").value = reference("update");
      updatePanel.hidden = true;
      editing = null;
      say("Changes saved to " + (record.title || "the task") + ".", false, record);
      await loadTasks();
    } catch (error) { fail(error); }
  });

  document.getElementById("aet-verify-integrity").addEventListener("click", async function () {
    try {
      var payload = await request("/operations/integrity");
      say("All task records are intact and unaltered.", false, payload);
    } catch (error) { fail(error); }
  });
  document.getElementById("aet-retention-due").addEventListener("click", function () {
    refreshRetention().then(function (count) {
      say(count ? count + " expired " + (count === 1 ? "task" : "tasks") + " can be deleted." : "No tasks have expired.", false);
    });
  });
  document.getElementById("aet-purge-form").addEventListener("submit", async function (event) {
    event.preventDefault();
    var ok = typeof window.mvConfirm === "function"
      ? await window.mvConfirm("Permanently delete finished or dismissed tasks whose keep-until date has passed? A record that they were deleted is kept. This can't be undone.", {okText: "Delete expired tasks"})
      : false;
    if (!ok) return;
    try {
      var payload = await request("/operations/purge-expired", {
        method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({limit: 1000})
      });
      var removed = Array.isArray(payload.removed) ? payload.removed.length : Number(payload.removed) || 0;
      say("Deleted " + removed + " expired " + (removed === 1 ? "task" : "tasks") + ".", false, payload);
      await loadTasks();
      refreshRetention();
    } catch (error) { fail(error); }
  });

  // A turned-off module shows its gate instead of this workbench's checks:
  // nothing is requested, and the page already says when tasks will appear.
  if (shell.dataset.moduleEnabled !== "false") refreshStatus();
}());
