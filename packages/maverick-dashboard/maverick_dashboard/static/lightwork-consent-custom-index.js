"use strict";

/* Find people by preference: searchable questions load as rows with buttons,
   the question and its answers are chosen from the published question sets,
   and every reference or version is carried from the chosen row. */
(function consentCustomIndexWorkbench() {
  const REQUEST_LIMIT = 64 * 1024;
  const RESPONSE_LIMIT = 512 * 1024;
  const opaquePattern = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
  const shell = document.getElementById("custom-index-shell");
  if (!shell) return;
  const CW = window.LightworkConsentWorkbench;

  const apiBase = shell.dataset.apiBase || "";
  const canAdmin = shell.dataset.canAdmin === "true";
  const canAudit = shell.dataset.canAudit === "true";
  const operations = document.getElementById("custom-index-operations");
  const runtimeStatus = document.getElementById("custom-index-runtime-status");
  const operationStatus = document.getElementById("custom-index-operation-status");
  const state = { indexes: [], next: null, questions: {}, selected: null, results: [] };
  const STATES = { pending: ["Not built yet", "warn"], ready: ["Ready to search", "ok"], stale: ["Needs rebuilding", "warn"], revoked: ["Removed", "idle"] };
  const ACTIONS = { index_created: "Made searchable", index_built: "Built", index_revoked: "Removed" };

  function $(id) { return document.getElementById(id); }
  function say(element, message, failed) { CW.say(element, message, failed); }
  function explain(element, error, action) {
    if (error && error.local) return say(element, error.message, true);
    if (error && error.status === 409) return say(element, "The answers changed since this question was built. Rebuild it, then search again.", true);
    return say(element, CW.errorText(error, action), true);
  }
  function localError(message) { const error = new Error(message); error.local = true; return error; }
  function opaque(value) {
    if (!opaquePattern.test(value)) throw localError("Choose a question from the list.");
    return value;
  }
  function selectedIndex() { return encodeURIComponent(opaque($("custom-index-selected-id").value)); }

  function boundedBody(payload) {
    const body = JSON.stringify(payload);
    if (new TextEncoder().encode(body).byteLength > REQUEST_LIMIT) throw localError("That search is too large. Choose fewer answers.");
    return body;
  }
  async function boundedResponse(response) {
    const declared = Number(response.headers.get("content-length"));
    if (Number.isFinite(declared) && declared > RESPONSE_LIMIT) throw new Error("oversized");
    if (!response.body || typeof response.body.getReader !== "function") {
      const text = await response.text();
      if (new TextEncoder().encode(text).byteLength > RESPONSE_LIMIT) throw new Error("oversized");
      return JSON.parse(text);
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder("utf-8", { fatal: true });
    let received = 0;
    let text = "";
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      received += chunk.value.byteLength;
      if (received > RESPONSE_LIMIT) { await reader.cancel(); throw new Error("oversized"); }
      text += decoder.decode(chunk.value, { stream: true });
    }
    text += decoder.decode();
    return JSON.parse(text);
  }
  async function request(path, options) {
    const response = await fetch(`${apiBase}${path}`, {
      cache: "no-store",
      credentials: "same-origin",
      redirect: "error",
      referrerPolicy: "no-referrer",
      ...(options || {}),
      headers: { Accept: "application/json", ...((options && options.headers) || {}) },
    });
    let payload;
    try { payload = await boundedResponse(response); }
    catch (_error) { const invalid = new Error("invalid response"); invalid.status = response.ok ? 0 : response.status; throw invalid; }
    if (!response.ok) { const failed = new Error("request failed"); failed.status = response.status; throw failed; }
    return payload;
  }
  function post(path, payload) {
    return request(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: boundedBody(payload) });
  }

  // Question sets from the profile-data page describe each question's answers.
  async function loadQuestions() {
    try {
      const data = await CW.client("/api/v1/consent/profile-data")("/catalogs?limit=500");
      (data.items || []).filter((c) => c.state === "published").forEach((catalog) => {
        (catalog.definitions || []).forEach((d) => {
          state.questions[d.preference_id] = { value_type: d.value_type, options: (d.options || []).map((o) => o.value_id) };
        });
      });
    } catch (_error) { /* answers fall back to what each index already knows */ }
  }

  async function loadIndexes(more) {
    try {
      const page = await request(`?limit=100${more && state.next ? "&cursor=" + encodeURIComponent(state.next) : ""}`);
      state.indexes = (more ? state.indexes : []).concat(page.items || []);
      state.next = page.next_cursor || null;
    } catch (error) { $("custom-index-table").replaceChildren(); explain(runtimeStatus, error, "load searchable questions"); return; }
    $("custom-index-more").hidden = !state.next;
    CW.table($("custom-index-table"), state.indexes, {
      label: "Searchable questions", name: (x) => CW.human(x.element_name),
      columns: [
        { label: "Question", value: (x) => CW.human(x.element_name) },
        { label: "Status", value: (x) => { const s = STATES[x.state] || [CW.human(x.state), "idle"]; return CW.badge(s[0], s[1]); } },
        { label: "Answers included", value: (x) => x.state === "pending" ? "" : x.entry_count },
        { label: "Last built", value: (x) => CW.when(x.built_at) },
      ],
      actions: [
        { label: "Search", when: (x) => canAdmin && x.state === "ready", run: (x) => openSearch(x) },
        { label: (x) => x.state === "pending" ? "Build now" : "Rebuild", when: (x) => canAdmin && x.state !== "revoked", run: (x, b) => build(x, b) },
        { label: "Remove", kind: "danger", when: (x) => canAdmin && x.state !== "revoked", run: (x, b) => revoke(x, b) },
      ],
      empty: { title: "No searchable questions yet.", body: "Make a published preference question searchable to find the people who gave an answer.", action: canAdmin ? { label: "Make a question searchable", run: openCreate } : null },
    });
  }

  function build(index, button) {
    return CW.busy(button, async () => {
      try {
        await post(`/${encodeURIComponent(opaque(index.index_id))}/build`, { expected_revision: index.revision, idempotency_key: CW.reference() });
        await loadIndexes(false); say(operationStatus, "“" + CW.human(index.element_name) + "” is ready to search.", false);
      } catch (error) { explain(operationStatus, error, "build the question"); }
    });
  }
  function revoke(index, button) {
    return CW.busy(button, async () => {
      if (!(await CW.confirm("Stop searching “" + CW.human(index.element_name) + "”? Its search data is deleted. People's answers are kept.", "Remove"))) return;
      try {
        await post(`/${encodeURIComponent(opaque(index.index_id))}/revoke`, { expected_revision: index.revision, idempotency_key: CW.reference() });
        await loadIndexes(false); say(operationStatus, "Removed.", false);
      } catch (error) { explain(operationStatus, error, "remove the question"); }
    });
  }

  // Make a question searchable
  const createForm = $("custom-index-create-form");
  function openCreate() {
    const taken = new Set(state.indexes.filter((x) => x.state !== "revoked").map((x) => x.element_name));
    const names = Object.keys(state.questions).filter((name) => !taken.has(name)).sort();
    CW.fill($("custom-index-element-name"), names.map((name) => ({ value: name, label: CW.human(name) })),
      names.length ? "" : "No more published questions. Add them on the Preference questions page.");
    CW.open(createForm, "#custom-index-element-name");
  }
  $("custom-index-new").addEventListener("click", openCreate);
  $("custom-index-create-cancel").addEventListener("click", () => { createForm.hidden = true; });
  createForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const element = opaque($("custom-index-element-name").value);
      $("custom-index-create-id").value = CW.slug("search-" + element, "search");
      await post("", { index_id: $("custom-index-create-id").value, element_name: element,
        idempotency_key: $("custom-index-create-operation").value || CW.reference() });
      createForm.hidden = true; await loadIndexes(false);
      say(operationStatus, "Now use “Build now” on its row so it can be searched.", false);
    } catch (error) { explain(operationStatus, error, "make the question searchable"); }
  });

  // Search
  const searchPanel = $("custom-index-search-panel");
  function answerControls(question) {
    const host = $("custom-index-search-value"); host.replaceChildren();
    const type = question ? question.value_type : "boolean";
    $("custom-index-value-type").value = type;
    if (type === "boolean") {
      const set = CW.el("fieldset"); set.appendChild(CW.el("legend", "", "Their answer"));
      const box = CW.el("div", "cw-checks");
      [["true", "Yes"], ["false", "No"]].forEach(([value, label], i) => {
        const l = CW.el("label"), input = document.createElement("input");
        input.type = "radio"; input.name = "value"; input.value = value; input.checked = i === 0; l.append(input, " " + label); box.appendChild(l);
      });
      set.appendChild(box); host.appendChild(set);
    } else if (type === "single_select") {
      const l = CW.el("label", "", "Their answer"), select = CW.fill(CW.el("select", "select"), question.options.map((o) => ({ value: o, label: CW.human(o) })));
      select.name = "value"; l.appendChild(select); host.appendChild(l);
    } else {
      const set = CW.el("fieldset"); set.appendChild(CW.el("legend", "", "They chose exactly these answers"));
      const box = CW.el("div", "cw-checks");
      question.options.forEach((o) => { const l = CW.el("label"), input = document.createElement("input"); input.type = "checkbox"; input.name = "value"; input.value = o; l.append(input, " " + CW.human(o)); box.appendChild(l); });
      set.appendChild(box); host.appendChild(set);
    }
  }
  function openSearch(index) {
    state.selected = index; state.results = [];
    $("custom-index-selected-id").value = index.index_id; $("custom-index-search-cursor").value = "";
    $("custom-index-search-title").textContent = "Search “" + CW.human(index.element_name) + "”";
    answerControls(state.questions[index.element_name]);
    $("custom-index-results").replaceChildren(); $("custom-index-results-more").hidden = true;
    CW.open(searchPanel);
  }
  $("custom-index-search-close").addEventListener("click", () => { searchPanel.hidden = true; });
  function searchValue() {
    const type = $("custom-index-value-type").value;
    const inputs = [...$("custom-index-search-value").querySelectorAll('[name="value"]')];
    if (type === "boolean") return (inputs.find((i) => i.checked) || { value: "true" }).value === "true";
    if (type === "single_select") return opaque(inputs[0].value);
    const chosen = inputs.filter((i) => i.checked).map((i) => i.value);
    if (!chosen.length) throw localError("Tick at least one answer.");
    return chosen;
  }
  async function runSearch(more) {
    const out = $("custom-index-results");
    try {
      const payload = { value: searchValue(), limit: 100 };
      if (more && $("custom-index-search-cursor").value) payload.cursor = $("custom-index-search-cursor").value;
      const page = await post(`/${selectedIndex()}/search`, payload);
      state.results = (more ? state.results : []).concat(page.profile_ids || []);
      $("custom-index-search-cursor").value = page.next_cursor || "";
      $("custom-index-results-more").hidden = !page.next_cursor;
      out.replaceChildren(CW.el("p", "", state.results.length ? state.results.length + " " + (state.results.length === 1 ? "person" : "people") + " found" + (page.next_cursor ? " so far." : ".") : "No one gave that answer."));
      if (state.results.length) {
        const host = CW.el("div"); out.appendChild(host);
        CW.table(host, state.results.map((id) => ({ id })), { label: "People found", columns: [{ label: "Person", value: (r) => r.id }] });
      }
    } catch (error) { out.replaceChildren(); explain(out, error, "search"); }
  }
  $("custom-index-search-form").addEventListener("submit", (event) => { event.preventDefault(); runSearch(false); });
  $("custom-index-results-more").addEventListener("click", () => runSearch(true));
  $("custom-index-more").addEventListener("click", () => loadIndexes(true));

  // History
  $("custom-index-history").addEventListener("click", (event) => CW.busy(event.currentTarget, async () => {
    try {
      const page = await request("/operations/history?limit=100");
      CW.table($("custom-index-history-table"), page.items || [], {
        label: "History",
        columns: [
          { label: "When", value: (e) => CW.when(e.occurred_at) },
          { label: "What happened", value: (e) => ACTIONS[e.action] || CW.human(e.action) },
          { label: "Question", value: (e) => { const x = state.indexes.find((i) => i.index_id === e.index_id); return x ? CW.human(x.element_name) : ""; } },
        ],
        empty: { title: "Nothing has happened yet.", body: "Changes to this index appear here once it is saved or used." },
      });
    } catch (error) { explain(operationStatus, error, "load the history"); }
  }));
  $("custom-index-integrity").addEventListener("click", (event) => CW.busy(event.currentTarget, async () => {
    try {
      const result = await request("/operations/integrity");
      say(operationStatus, result.ok ? "Checked " + (result.index_count || 0) + " searchable questions. Everything is intact." : "Some search records failed their check. Contact support.", !result.ok);
    } catch (error) { explain(operationStatus, error, "check the records"); }
  }));

  async function refreshStatus() {
    operations.disabled = true;
    try {
      const payload = await request("/status");
      if (payload.ready === true) {
        operations.disabled = false;
        say(runtimeStatus, "", false);
        await loadQuestions();
        if (canAdmin) await loadIndexes(false);
        else $("custom-index-table").replaceChildren(CW.el("p", "muted", "Only an administrator can see searchable questions."));
      } else if (payload.enabled === true) {
        say(runtimeStatus, "Searching is turned on but not ready yet. Ask an administrator to finish setting it up.", true);
        settleTable("Searchable questions appear here once an administrator finishes the setup.");
      } else {
        say(runtimeStatus, "Searching by preference is not turned on for this workspace. Ask an administrator to turn it on.", true);
        settleTable("Searchable questions appear here once this is turned on.");
      }
    } catch (error) {
      explain(runtimeStatus, error, "check availability");
      settleTable(CW.errorText(error, "load searchable questions"));
    }
  }
  // The list never loads while searching is unavailable; say why instead of "Loading…".
  function settleTable(message) { $("custom-index-table").replaceChildren(CW.el("p", "muted", message)); }
  if (!CW) { runtimeStatus.textContent = "This page could not finish loading. Reload the page."; return; }
  // A turned-off module shows its gate instead: nothing is checked or loaded,
  // and no second "not turned on" sentence appears under the banner.
  if (apiBase && shell.dataset.moduleEnabled !== "false") refreshStatus();
})();
