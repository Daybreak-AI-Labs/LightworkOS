(() => {
  "use strict";
  const root = document.getElementById("action-center");
  if (!root) return;
  const form = document.getElementById("ac-filters"), list = document.getElementById("ac-items");
  const status = document.getElementById("ac-status"), summary = document.getElementById("ac-summary");
  const coverage = document.getElementById("ac-coverage"), previous = document.getElementById("ac-previous");
  const next = document.getElementById("ac-next"), page = document.getElementById("ac-page");
  let model = null, offset = 0, busy = false, generation = 0, expired = false;
  const labels = {connection_attention:"Your connections needing attention",task_attention:"Your task questions and recovery",approval:"Approvals",flow_approval:"Flow approvals",evidence_source_approval:"Evidence source approvals",signoff:"Result approvals",assessment:"Assessments",project_review:"Project reviews",vendor_reconciliation:"Actions to double-check in other apps"};
  const ACTIONS = {"jira.create":"Create a Jira issue"};
  Object.assign(labels, {lifecycle_review:"Vendor lifecycle reviews",drop_authority_review:"DROP authority reviews",
    trust_center_review:"Trust Center access reviews",disclosure_review:"Privacy notice update reviews"});
  const OBSERVATIONS = {
    execution_attempt: { recorded: "Lightwork recorded the attempt" },
    provider_receipt: { recorded: "Jira confirmed it received the request", not_recorded: "No confirmation from Jira was recorded" },
    authoritative_readback: {
      not_completed: "Lightwork hasn't checked Jira yet", access_unavailable: "Lightwork couldn't check Jira (no access)",
      no_match: "Checked Jira: no matching issue found", multiple_matches: "Checked Jira: more than one matching issue found",
      readback_mismatch: "Checked Jira: an issue was found but it doesn't match", readback_unavailable: "Checking Jira didn't work",
      exact_match_verified: "Checked Jira: exactly one matching issue found",
    },
  };
  function person(value) { return String(value || "").replace(/^[a-z]+:/, ""); }
  function node(tag, text, className) {
    const el = document.createElement(tag); if (text !== undefined) el.textContent = text;
    if (className) el.className = className; return el;
  }
  function words(value) { return String(value || "unknown").replaceAll("_", " "); }
  const reconciliationReasons = new Set([
    "current_connection_access_unavailable", "no_matching_effect_observed",
    "multiple_matching_effects_observed", "matching_effect_content_mismatch",
    "authoritative_readback_unavailable", "receipt_recorded_readback_unverified",
    "attempt_result_unrecorded",
  ]);
  const readbackStates = new Set([
    "not_completed", "access_unavailable", "no_match", "multiple_matches",
    "readback_mismatch", "readback_unavailable", "exact_match_verified",
  ]);
  function exactObject(value, keys) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const actual = Object.keys(value);
    return actual.length === keys.length && keys.every(key => Object.prototype.hasOwnProperty.call(value, key));
  }
  const nonblank = (value, limit=2000) => typeof value === "string" && value.length > 0 &&
    value.length <= limit && value.trim() === value;
  const timestamp = (value, optional=false) => optional && value === null ||
    typeof value === "number" && Number.isFinite(value) && value > 0;
  function validObservation(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    if (value.kind === "execution_attempt") return exactObject(value,["kind","state","count","observed_at"]) &&
      value.state === "recorded" && Number.isInteger(value.count) && value.count >= 1 && timestamp(value.observed_at);
    if (value.kind === "provider_receipt") return exactObject(value,["kind","state"]) &&
      ["recorded","not_recorded"].includes(value.state);
    if (value.kind !== "authoritative_readback") return false;
    const allowed = new Set(["kind","state","observed_at","match_count","match_count_lower_bound"]);
    if (!Object.keys(value).every(key=>allowed.has(key)) ||
        !["kind","state","observed_at"].every(key=>Object.prototype.hasOwnProperty.call(value,key)) ||
        !readbackStates.has(value.state) || !timestamp(value.observed_at,true)) return false;
    const exact = value.match_count, lower = value.match_count_lower_bound;
    if (exact !== undefined && (!Number.isInteger(exact) || exact < 0)) return false;
    if (lower !== undefined && (!Number.isInteger(lower) || lower < 2)) return false;
    if (exact !== undefined && lower !== undefined) return false;
    if (value.state === "no_match" && exact !== 0) return false;
    if (value.state === "multiple_matches" &&
        !((Number.isInteger(exact) && exact >= 2) || (Number.isInteger(lower) && lower >= 2))) return false;
    if (value.state === "not_completed" && (value.observed_at !== null || exact !== undefined || lower !== undefined)) return false;
    if (value.state !== "not_completed" && value.observed_at === null) return false;
    return !["exact_match_verified","readback_mismatch"].includes(value.state) || exact === 1;
  }
  function reconciliationDetails(item) {
    const detail = item.reconciliation;
    if (!exactObject(detail,["schema","attempted_action","known_observations","uncertainty",
      "safe_next_check","responsible_operator","resolution"]) ||
        detail.schema !== "lightwork.vendor-onboarding.reconciliation-summary.v1") return null;
    const attempted = detail.attempted_action, observations = detail.known_observations;
    if (!exactObject(attempted,["operation_id","action","attempt_count","started_at","target"]) ||
        !/^VOP-[a-f0-9]{32}$/.test(attempted.operation_id) || attempted.action !== "jira.create" ||
        !Number.isInteger(attempted.attempt_count) || attempted.attempt_count < 1 ||
        !timestamp(attempted.started_at) || !exactObject(attempted.target,["provider","project"]) ||
        attempted.target.provider !== "jira" || !/^[A-Z][A-Z0-9_]{1,31}$/.test(attempted.target.project) ||
        !Array.isArray(observations) || observations.length !== 3 || !observations.every(validObservation)) return null;
    const byKind = new Map(observations.map(value=>[value.kind,value]));
    if (byKind.size !== 3 || !["execution_attempt","provider_receipt","authoritative_readback"].every(kind=>byKind.has(kind)) ||
        byKind.get("execution_attempt").count !== attempted.attempt_count ||
        byKind.get("execution_attempt").observed_at !== attempted.started_at) return null;
    const uncertainty = detail.uncertainty, next = detail.safe_next_check;
    if (!exactObject(uncertainty,["state","reason","explanation"]) || uncertainty.state !== "unresolved" ||
        !reconciliationReasons.has(uncertainty.reason) || !nonblank(uncertainty.explanation) ||
        !next || !["check_status","review_ambiguity","restore_access"].includes(next.kind) ||
        !exactObject(next,next.kind === "restore_access" ? ["kind","label","mode","href"] : ["kind","label","mode"]) ||
        !nonblank(next.label,500) || next.mode !== "read_only" ||
        (next.kind === "restore_access" && next.href !== "/connections")) return null;
    const expected = {
      current_connection_access_unavailable:["restore_access",null],
      no_matching_effect_observed:["check_status","no_match"],
      multiple_matching_effects_observed:["review_ambiguity","multiple_matches"],
      matching_effect_content_mismatch:["review_ambiguity","readback_mismatch"],
      authoritative_readback_unavailable:["check_status","readback_unavailable"],
      receipt_recorded_readback_unverified:["check_status","not_completed"],
      attempt_result_unrecorded:["check_status","not_completed"],
    }[uncertainty.reason];
    const receipt = byKind.get("provider_receipt"), readback = byKind.get("authoritative_readback");
    if (next.kind !== expected[0] || expected[1] !== null && readback.state !== expected[1] ||
        uncertainty.reason === "receipt_recorded_readback_unverified" && receipt.state !== "recorded" ||
        uncertainty.reason === "attempt_result_unrecorded" && receipt.state !== "not_recorded") return null;
    if (!exactObject(detail.responsible_operator,["principal","business_owner"]) ||
        !nonblank(detail.responsible_operator.principal,256) || !nonblank(detail.responsible_operator.business_owner,256) ||
        !exactObject(detail.resolution,["automatic_compensation_supported","unreviewed_replacement_allowed","requires_separate_review","explanation"]) ||
        detail.resolution.automatic_compensation_supported !== false ||
        detail.resolution.unreviewed_replacement_allowed !== false ||
        detail.resolution.requires_separate_review !== true || !nonblank(detail.resolution.explanation)) return null;
    return detail;
  }
  function pending(value) {
    busy = value; root.setAttribute("aria-busy", String(value));
    root.querySelectorAll("button,select").forEach(el => { el.disabled = value || expired; });
    if (!value && !expired) { previous.disabled = offset === 0; next.disabled = !model || !model.has_more; }
  }
  function invalidate() {
    expired = true; ++generation; model = null; list.replaceChildren(); coverage.replaceChildren(); summary.textContent = ""; page.textContent = "";
    pending(false);
  }
  async function request(url, options) {
    const writing = !!(options && options.method);
    return window.mvFetchJSON(url, {cache:"no-store", ...options,
      headers:{"X-Lightwork-Action-Context":root.dataset.context, ...(options && options.headers)},
      onAccess:invalidate, messages:{
        401:"Your sign-in or access changed. Sign in again and reload Action Center.",
        403:"Your sign-in or access changed. Sign in again and reload Action Center.",
        409:"This changed since the list loaded. Refresh the list and try again."}}, writing ? "save your choice" : "load your actions");
  }
  function render() {
    list.replaceChildren(); coverage.replaceChildren();
    summary.textContent = `${model.counts.unread} unread · ${model.counts.overdue} overdue · ${model.counts.snoozed} snoozed`;
    model.coverage.forEach(source => {
      if (source.limit === 99) {
        const states = {current:"Current available records checked.",disabled:"Turned off in Settings.",
          denied:"Not available with your current access. Open the full page or ask its administrator.",
          partial:"At most 99 records in each group were checked. Open the full review page for the remaining records; this list is incomplete.",
          unavailable:"Could not be checked. Refresh or open the full page; this list is incomplete."};
        coverage.append(node("li", `${labels[source.kind]}: ${states[source.status] || states.unavailable}`));
        return;
      }
      // A module that is turned off is not a load error.
      if (source.status !== "current" && source.status !== "disabled") coverage.append(node("li", `${labels[source.kind]} ${source.status === "partial" ? (source.kind === "evidence_source_approval" ? "cover only the first 64 saved source setups. Open Continuous evidence to review the current sources." : "include only the most recent 2,000 source records. Open the full module for older records.") : "could not be loaded. Refresh or open that module; this list is incomplete."}`));
    });
    if (!model.items.length) {
      const partial = model.coverage.some(source=>source.status !== "current" && source.status !== "disabled");
      const empty = node("div", undefined, "mv-empty");
      empty.append(node("p", partial ? "No items are visible in this filter. Some sources are incomplete or unavailable; refresh the page or choose another filter." : "You're all caught up.", "mv-empty__title"));
      const filtered = form.elements.view.value !== "active" || form.elements.kind.value !== "all" || form.elements.assignment.value !== "all";
      if (filtered) {
        const all = node("button", "Show everything", "btn"); all.type = "button";
        all.addEventListener("click", () => { form.elements.view.value = "all"; form.elements.kind.value = "all"; form.elements.assignment.value = "all"; offset = 0; load(); });
        empty.append(all);
      }
      list.append(empty);
    }
    model.items.forEach(item => {
      const article = node("article", undefined, "panel"); article.dataset.item = item.id; article.style.marginBlock = "var(--space-3)";
      article.append(node("h2", item.title));
      article.append(node("p", `${item.flow_run_id ? "Flow approval" : labels[item.kind]} · ${item.assignment === "mine" ? "Assigned to you" : "Available to review"} · ${item.read ? "Read" : "Unread"}`));
      article.append(node("p", item.reason, "muted"));
      const reconciliation = reconciliationDetails(item);
      if (item.kind === "vendor_reconciliation" && !reconciliation)
        throw new Error("Uncertain action details were incomplete. Refresh or open vendor onboarding directly.");
      if (reconciliation) {
        const details = node("section", undefined, "panel");
        details.append(node("h3", "What Lightwork knows"));
        const attempted = reconciliation.attempted_action;
        details.append(node("p", `What Lightwork tried: ${ACTIONS[attempted.action] || words(attempted.action)} · ${Number(attempted.attempt_count) || 0} recorded attempt${Number(attempted.attempt_count) === 1 ? "" : "s"} · Jira project ${attempted.target?.project || "unavailable"}.`));
        const observations = node("ul");
        reconciliation.known_observations.forEach(observation => {
          const count = Number.isInteger(observation.match_count) ? ` · ${observation.match_count} match${observation.match_count === 1 ? "" : "es"}` :
            Number.isInteger(observation.match_count_lower_bound) ? ` · at least ${observation.match_count_lower_bound} matches` : "";
          const sentence = (OBSERVATIONS[observation.kind] || {})[observation.state] || `${words(observation.kind)}: ${words(observation.state)}`;
          observations.append(node("li", `${sentence}${count}`));
        });
        details.append(observations);
        details.append(node("p", `What is unclear: ${reconciliation.uncertainty.explanation}`));
        details.append(node("p", `Safe next step: ${reconciliation.safe_next_check.label}. This check is read-only and cannot create another Jira task.`));
        if (reconciliation.safe_next_check.kind === "restore_access") {
          const access = node("a", "Resolve connection access", "btn");
          access.href = reconciliation.safe_next_check.href; details.append(access);
        }
        const operator = reconciliation.responsible_operator.principal || reconciliation.responsible_operator.business_owner || "an authorized operator";
        details.append(node("p", `Who looks after this: ${person(operator)}.`));
        details.append(node("p", reconciliation.resolution.explanation, "muted"));
        article.append(details);
      }
      if (item.due_at) article.append(node("p", `${item.overdue ? "Overdue" : "Due"}: ${(window.mvTimeAbsolute ? window.mvTimeAbsolute(item.due_at) : new Date(item.due_at * 1000).toLocaleString())}`, item.overdue ? "badge warn" : "muted"));
      if (item.snoozed) article.append(node("p", `Snoozed until ${(window.mvTimeAbsolute ? window.mvTimeAbsolute(item.snoozed_until) : new Date(item.snoozed_until * 1000).toLocaleString())}`, "muted"));
      const actions = node("div"); actions.style.cssText = "display:flex;flex-wrap:wrap;gap:var(--space-2);align-items:center;";
      if (item.assessment_id) {
        const review = node("button", "Review assessment", "btn btn--primary"); review.type="button";
        review.addEventListener("click", () => {
          if (window.mvAssessmentReview) window.mvAssessmentReview.open(item.assessment_id);
          else status.textContent = "The assessment reviewer could not load. Open the assessment from its department workspace.";
        }); actions.append(review);
      } else {
        const link = node("a", "Review", "btn btn--primary"); link.href = item.href; actions.append(link);
      }
      const read = node("button", item.read ? "Mark unread" : "Mark read", "btn"); read.type="button";
      read.dataset.preference="read";
      read.setAttribute("aria-label", `${item.read ? "Mark unread" : "Mark read"}: ${item.title}`);
      read.addEventListener("click", () => save(item, !item.read, item.snoozed ? item.snoozed_until : 0, "read")); actions.append(read);
      const snooze = node("button", item.snoozed ? "Show now" : "Snooze for one day", "btn"); snooze.type="button";
      snooze.dataset.preference="snooze";
      snooze.setAttribute("aria-label", `${item.snoozed ? "Show now" : "Snooze for one day"}: ${item.title}`);
      snooze.addEventListener("click", () => save(item, item.read, item.snoozed ? 0 : Date.now()/1000+86400, "snooze")); actions.append(snooze);
      if (!item.snoozed) {
        const week = node("button", "Snooze for a week", "btn btn--ghost"); week.type="button";
        week.setAttribute("aria-label", `Snooze for a week: ${item.title}`);
        week.addEventListener("click", () => save(item, item.read, Date.now()/1000+7*86400, "snooze")); actions.append(week);
      }
      article.append(actions); list.append(article);
    });
    page.textContent = model.total ? `${offset+1}–${Math.min(offset+model.limit,model.total)} of ${model.total}` : "0 items";
  }
  async function load(focus) {
    if (busy || expired) return;
    const attempt = ++generation;
    pending(true); status.textContent = "Loading your actions…";
    try {
      const query = new URLSearchParams({view:form.elements.view.value, kind:form.elements.kind.value,
        assignment:form.elements.assignment.value, offset:String(offset), limit:"50"});
      const result = await request(`/api/v1/action-center?${query}`);
      if (attempt !== generation) return;
      if (result.context !== root.dataset.context) { invalidate(); throw new Error("The account or workspace changed. Reload Action Center."); }
      model = result; render(); status.textContent = "List refreshed.";
    } catch (error) {
      model = null; list.replaceChildren(); coverage.replaceChildren(); summary.textContent = ""; page.textContent = "";
      status.textContent = error.message;
    } finally {
      if (attempt === generation) pending(false);
      if (focus && !expired) {
        const rows = [...list.querySelectorAll('article')];
        const row = rows.find(row => row.dataset.item === focus.id) || rows[Math.min(focus.index, rows.length-1)];
        const target = row?.querySelector('[data-preference="'+focus.kind+'"]') || status;
        if (target === status) status.tabIndex = -1;
        target.focus();
      }
    }
  }
  async function save(item, read, snoozedUntil, kind) {
    if (busy || expired || !model) return;
    const focus = {id:item.id, index:model.items.indexOf(item), kind};
    pending(true); status.textContent = "Saving your preference…";
    try {
      await request(`/api/v1/action-center/${encodeURIComponent(item.id)}/preference`, {method:"PUT",
        headers:{"Content-Type":"application/json", "X-Lightwork-Action-Context":model.context},
        body:JSON.stringify({expected_revision:model.revision, source_version:item.source_version,
          operation_id:(window.mvNewId ? window.mvNewId() : crypto.randomUUID()), read, snoozed_until:snoozedUntil})});
      pending(false); await load(focus);
    } catch (error) { status.textContent = error.message; pending(false); }
  }
  form.addEventListener("submit", event=>{event.preventDefault(); if (!busy) {offset=0; load();}});
  form.addEventListener("change", ()=>{if (!busy) {offset=0; load();}});
  previous.addEventListener("click", ()=>{if (!busy) {offset=Math.max(0,offset-50); load();}});
  next.addEventListener("click", ()=>{if (!busy && model && model.has_more) {offset+=50; load();}});
  window.addEventListener("pageshow", event=>{if (event.persisted) {++generation; model=null; list.replaceChildren(); busy=false; load();}});
  window.LightworkActionCenter = Object.freeze({
    async open(expectedContext, isCurrent) {
      const current = () => !expired && typeof isCurrent === "function" && isCurrent() &&
        /^[a-f0-9]{64}$/.test(expectedContext) && root.dataset.context === expectedContext;
      if (!current() || busy) throw new Error("Your account or selection changed. Open the current Action Center again.");
      await load();
      if (!current() || !model || model.context !== expectedContext)
        throw new Error("The current list could not be opened. Your filters were kept; refresh Action Center.");
      root.scrollIntoView({block:"start"}); form.elements.kind.focus();
      return true;
    }
  });
  load();
})();
