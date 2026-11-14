(function () {
"use strict";

/* AI evidence analysis page. Documents and review criteria are chosen from
   the workspace registry; analyses load as a list with row buttons. Record
   references, versions and fingerprints are carried from the chosen row or
   computed from the chosen file -- never typed. */

const shell = document.getElementById("evidence-shell");
const apiBase = shell ? shell.dataset.apiBase : "";
const can = {
  operate: Boolean(shell && shell.dataset.canOperate === "true"),
  audit: Boolean(shell && shell.dataset.canAudit === "true"),
  admin: Boolean(shell && shell.dataset.canAdmin === "true"),
  register: Boolean(shell && shell.dataset.canRegister === "true"),
};
const runtimeStatus = document.getElementById("runtime-status");
const operations = document.getElementById("evidence-operations");
const operationStatus = document.getElementById("operation-status");
const operationOutput = document.getElementById("operation-output");

const MEDIA = {
  "application/pdf": "pdf",
  "image/jpeg": "jpeg",
  "image/png": "png",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
  "text/plain": "text",
};
const STATUS = {
  pending_review: ["Waiting for review", "warn"],
  review_approved: ["Approved", "ok"],
  review_rejected: ["Rejected", "failed"],
  revoked: ["Withdrawn", "idle"],
};
const DISPOSITIONS = {
  evidence_supported: "Supported by the document",
  evidence_partial: "Partly supported",
  evidence_missing: "Not found in the document",
  indeterminate: "Unclear",
};
const REVOKE_REASONS = [
  { value: "document-replaced", label: "The document was replaced" },
  { value: "wrong-document", label: "The wrong document was analyzed" },
  { value: "criteria-changed", label: "The review criteria changed" },
  { value: "other", label: "Another reason" },
];

const state = { artifacts: [], criteria: [], analyses: [] };

function setStatus(element, message, failed = false) {
  window.mvStatus(element, message, {error: !!failed});
  element.dataset.state = failed ? "failed" : "ready";
}

function technical(value) {
  if (!operationOutput) return;
  operationOutput.textContent = value === undefined ? "" :
    typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

function human(value) {
  if (typeof window !== "undefined" && typeof window.mvHuman === "function") return window.mvHuman(value);
  const text = String(value || "").replace(/[_.:-]+/g, " ").trim();
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : "";
}

function when(ts) {
  if (typeof window !== "undefined" && typeof window.mvWhen === "function") return window.mvWhen(ts);
  return ts ? (window.mvTimeAbsolute ? window.mvTimeAbsolute(ts) : new Date(ts * 1000).toLocaleString()) : "";
}

function plainError(status, action) {
  if (typeof window !== "undefined" && typeof window.mvErrorText === "function") {
    return window.mvErrorText({ status }, action);
  }
  if (status === 403) return `Could not ${action}. You do not have permission to do this.`;
  if (status === 409) return `Could not ${action}. This changed since you opened it. Refresh the page and try again.`;
  return `Could not ${action}. Something went wrong. Try again.`;
}

async function apiRequest(path, options = {}, action = "finish this") {
  try {
    return await window.mvFetchJSON(`${apiBase}${path}`, {
      cache: "no-store", credentials: "same-origin", redirect: "error", referrerPolicy: "no-referrer", ...options,
      // The server's own detail stays out of the sentence: it is kept as technical text.
      messages: { 409: `Could not ${action}. This changed since you opened it. Refresh the page and try again.` },
    }, action);
  } catch (error) {
    if (error.unreadable) {
      const unexpected = new Error("Lightwork returned something unexpected. Refresh the page and try again.");
      unexpected.status = error.status;
      throw unexpected;
    }
    error.technical = typeof error.detail === "string" ? error.detail : "";
    throw error;
  }
}

async function run(label, operation) {
  setStatus(operationStatus, `${label}…`);
  technical(undefined);
  try {
    return await operation();
  } catch (error) {
    setStatus(operationStatus, error && error.message ? error.message : "Something went wrong. Try again.", true);
    technical(error && error.technical ? error.technical : undefined);
    throw error;
  }
}

function done(message, details) {
  setStatus(operationStatus, message);
  technical(details);
}

function reference(prefix) {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") return `${prefix}-${crypto.randomUUID()}`;
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 12)}`;
}

function slug(value, fallback) {
  const cleaned = String(value || "").normalize("NFKD").replace(/[^A-Za-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "").toLowerCase().slice(0, 100);
  return cleaned || fallback;
}

function documentName(artifactId) {
  const match = /^(.+)\.[0-9a-f]{8}$/.exec(String(artifactId || ""));
  return match ? human(match[1]) : `Document ${artifactId}`;
}

function artifactLabel(item) {
  return `${documentName(item.artifact_id)} (${human(item.case_ref)})`;
}

function option(select, value, label) {
  const item = document.createElement("option");
  item.value = value;
  item.textContent = label;
  select.appendChild(item);
}

function cell(text) {
  const td = document.createElement("td");
  td.textContent = text;
  return td;
}

function button(label, handler, cls = "btn") {
  const item = document.createElement("button");
  item.type = "button";
  item.className = cls;
  item.textContent = label;
  item.addEventListener("click", () => {
    if (item.disabled) return;
    item.disabled = true;
    Promise.resolve().then(handler).catch(() => {}).then(() => { item.disabled = false; });
  });
  return item;
}

// ---- pickers -----------------------------------------------------------
async function loadPickers() {
  const artifactSelect = document.getElementById("artifact-select");
  const criteriaSelect = document.getElementById("criteria-select");
  try {
    const [artifacts, criteria] = await Promise.all([
      apiRequest("/authorities/artifacts", {}, "load registered documents"),
      apiRequest("/authorities/criteria", {}, "load review criteria"),
    ]);
    state.artifacts = Array.isArray(artifacts.items) ? artifacts.items : [];
    state.criteria = Array.isArray(criteria.items) ? criteria.items : [];
  } catch (error) {
    state.artifacts = [];
    state.criteria = [];
    setStatus(operationStatus, error.message, true);
  }
  artifactSelect.textContent = "";
  option(artifactSelect, "", state.artifacts.length ? "Choose a document…" :
    can.register ? "No documents yet — register one below" : "No documents yet — ask an administrator to register one");
  state.artifacts.forEach((item, index) => option(artifactSelect, String(index), artifactLabel(item)));
  criteriaSelect.textContent = "";
  option(criteriaSelect, "", state.criteria.length ? "Choose review criteria…" : "No review criteria yet — ask an administrator to set them up");
  state.criteria.forEach((item, index) => option(
    criteriaSelect,
    String(index),
    `${human(item.criteria_set_id)} (${item.criterion_ids.length} ${item.criterion_ids.length === 1 ? "check" : "checks"})`,
  ));
}

// ---- analyses list -----------------------------------------------------
function summaryText(record) {
  const summary = record.summary || {};
  const total = Number(summary.total_criteria) || 0;
  const supported = Number(summary.evidence_supported) || 0;
  const justification = record.justification || {};
  const score = Number(justification.maximum_bps) > 0
    ? Math.round((Number(justification.score_bps) / Number(justification.maximum_bps)) * 100) : null;
  return `${supported} of ${total} supported` + (score === null ? "" : ` · score ${score}%`);
}

async function loadAnalyses() {
  const filter = document.getElementById("analysis-filter").value;
  const query = filter ? `?status=${encodeURIComponent(filter)}&limit=200` : "?limit=200";
  const payload = await apiRequest(`/analyses${query}`, {}, "load analyses");
  state.analyses = Array.isArray(payload.items) ? payload.items : [];
  renderAnalyses();
}

function renderAnalyses() {
  const tbody = document.getElementById("analyses-rows");
  tbody.textContent = "";
  if (!state.analyses.length) {
    const tr = document.createElement("tr");
    const td = cell(can.operate ? "No analyses here yet. Use Analyze a document above to start one." : "No analyses here yet. They appear here when an operator analyzes a document.");
    td.colSpan = 6;
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const record of state.analyses) {
    const tr = document.createElement("tr");
    const th = document.createElement("th");
    th.scope = "row";
    th.textContent = documentName(record.artifact && record.artifact.artifact_id);
    tr.appendChild(th);
    tr.appendChild(cell(human(record.criteria && record.criteria.criteria_set_id)));
    tr.appendChild(cell(summaryText(record)));
    const status = document.createElement("td");
    const badge = document.createElement("span");
    const pair = STATUS[record.status] || [human(record.status), "idle"];
    badge.className = `badge ${pair[1]}`;
    badge.textContent = pair[0];
    status.appendChild(badge);
    tr.appendChild(status);
    tr.appendChild(cell(when(record.created_at)));
    const actions = document.createElement("td");
    const wrap = document.createElement("div");
    wrap.className = "actions";
    wrap.appendChild(button("View findings", () => showDetail(record), "btn btn--ghost"));
    if (can.operate && record.status === "pending_review") {
      wrap.appendChild(button("Approve", () => review(record, "approve"), "btn btn--primary"));
      wrap.appendChild(button("Reject", () => review(record, "reject")));
    }
    if (can.admin && record.status !== "revoked") {
      wrap.appendChild(button("Withdraw", () => revoke(record), "btn btn--danger"));
    }
    if (can.audit) {
      wrap.appendChild(button("History", () => showHistory(record), "btn btn--ghost"));
    }
    actions.appendChild(wrap);
    tr.appendChild(actions);
    tbody.appendChild(tr);
  }
}

function showDetail(record) {
  const panel = document.getElementById("detail-panel");
  const body = document.getElementById("detail-body");
  body.textContent = "";
  const heading = document.createElement("p");
  heading.textContent = `${documentName(record.artifact && record.artifact.artifact_id)} checked against ${human(record.criteria && record.criteria.criteria_set_id)}: ${summaryText(record)}.`;
  body.appendChild(heading);
  const findings = Array.isArray(record.findings) ? record.findings : [];
  if (findings.length) {
    const list = document.createElement("ul");
    for (const finding of findings) {
      const item = document.createElement("li");
      const confidence = Number.isFinite(finding.confidence_bps) ? ` (confidence ${Math.round(finding.confidence_bps / 100)}%)` : "";
      item.textContent = `${human(finding.criterion_id)}: ${DISPOSITIONS[finding.disposition] || human(finding.disposition)}${confidence}`;
      list.appendChild(item);
    }
    body.appendChild(list);
  }
  const gaps = Array.isArray(record.gaps) ? record.gaps : [];
  if (gaps.length) {
    const title = document.createElement("h3");
    title.textContent = "What's missing and what to do";
    body.appendChild(title);
    const list = document.createElement("ul");
    for (const gap of gaps) {
      const item = document.createElement("li");
      item.textContent = `${human(gap.criterion_id)}: ${human(gap.gap_code)}. Suggested next step: ${human(gap.remediation_code)}.`;
      list.appendChild(item);
    }
    body.appendChild(list);
  }
  const review = record.human_review || {};
  const note = document.createElement("p");
  note.className = "help";
  note.textContent = review.decision ? `Reviewed ${when(review.reviewed_at)}: ${human(review.decision)}.` : "Not reviewed yet.";
  body.appendChild(note);
  panel.hidden = false;
  document.getElementById("detail-title").focus();
  technical(record);
}

async function ask(message, okText) {
  if (typeof window !== "undefined" && typeof window.mvConfirm === "function") return window.mvConfirm(message, { okText });
  return false;
}

async function review(record, decision) {
  const name = documentName(record.artifact && record.artifact.artifact_id);
  const ok = await ask(decision === "approve"
    ? `Approve the findings for ${name}? They can then be used as evidence.`
    : `Reject the findings for ${name}? They won't be used as evidence.`, decision === "approve" ? "Approve" : "Reject");
  if (!ok) return;
  await run(decision === "approve" ? "Approving" : "Rejecting", async () => {
    const payload = await apiRequest(`/analyses/${encodeURIComponent(record.analysis_id)}/review`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ expected_revision: record.revision, decision, idempotency_key: reference("review") }),
    }, decision === "approve" ? "approve the findings" : "reject the findings");
    await loadAnalyses();
    done(decision === "approve" ? `Findings for ${name} approved.` : `Findings for ${name} rejected.`, payload);
  });
}

async function revoke(record) {
  const name = documentName(record.artifact && record.artifact.artifact_id);
  let choice = null;
  if (typeof window !== "undefined" && typeof window.mvForm === "function") {
    choice = await window.mvForm(`Withdraw the analysis of ${name}`, [{
      key: "reason", label: "Why?", type: "select", required: true, default: "document-replaced",
      options: REVOKE_REASONS, help: "Withdrawn findings can no longer be used as evidence.",
    }], { okText: "Withdraw" });
  }
  if (!choice || !choice.reason) return;
  await run("Withdrawing", async () => {
    const payload = await apiRequest(`/analyses/${encodeURIComponent(record.analysis_id)}/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ expected_revision: record.revision, reason_code: choice.reason, idempotency_key: reference("revoke") }),
    }, "withdraw the analysis");
    await loadAnalyses();
    done(`The analysis of ${name} was withdrawn.`, payload);
  });
}

async function showHistory(record) {
  await run("Loading history", async () => {
    const payload = await apiRequest(`/analyses/${encodeURIComponent(record.analysis_id)}/history`, {}, "load the history");
    const items = Array.isArray(payload.items) ? payload.items : [];
    const body = document.getElementById("detail-body");
    body.textContent = "";
    const list = document.createElement("ol");
    for (const item of items) {
      const entry = document.createElement("li");
      const pair = STATUS[item.status] || [human(item.status)];
      entry.textContent = `${when(item.updated_at || item.created_at)} — ${pair[0]}`;
      list.appendChild(entry);
    }
    body.appendChild(list);
    document.getElementById("detail-panel").hidden = false;
    document.getElementById("detail-title").focus();
    done(`Showing ${items.length} ${items.length === 1 ? "step" : "steps"} in the history of ${documentName(record.artifact && record.artifact.artifact_id)}.`, payload);
  });
}

// ---- status ------------------------------------------------------------
// Nothing loads until analysis is available: say why in each loader instead
// of leaving "Loading…" there.
function settleLoaders(message) {
  for (const id of ["artifact-select", "criteria-select"]) {
    const select = document.getElementById(id);
    select.textContent = "";
    option(select, "", "Not available right now");
  }
  const tbody = document.getElementById("analyses-rows");
  tbody.textContent = "";
  const tr = document.createElement("tr");
  const td = cell(message);
  td.colSpan = 6;
  tr.appendChild(td);
  tbody.appendChild(tr);
}

async function refreshStatus() {
  setStatus(runtimeStatus, "Checking whether analysis is available…");
  operations.disabled = true;
  try {
    const payload = await apiRequest("/status", {}, "check availability");
    const tesseractDetected = payload.external_parser_binaries_detected &&
      payload.external_parser_binaries_detected.tesseract === true;
    const ocrNotice = tesseractDetected ? "" :
      " Text inside images can't be read on this installation. Upload a text or PDF version instead.";
    if (payload.ready === true && payload.operational_composition_verified === true) {
      setStatus(runtimeStatus, `Evidence analysis is ready.${ocrNotice}`);
      operations.disabled = false;
      return true;
    }
    if (payload.configured_for_operation_attempt === true) {
      setStatus(runtimeStatus, `Evidence analysis is set up. Your access is checked when you start.${ocrNotice}`);
      operations.disabled = false;
      return true;
    }
    if (payload.enabled === true) {
      setStatus(runtimeStatus, "Evidence analysis is turned on, but setup isn't finished. Ask an administrator to complete it.", true);
      settleLoaders("Analyses appear here once an administrator finishes the setup.");
    } else {
      setStatus(runtimeStatus, "Evidence analysis is turned off for this workspace. Ask an administrator to turn it on.", true);
      settleLoaders("Analyses appear here once AI evidence analysis is turned on.");
    }
  } catch (error) {
    setStatus(runtimeStatus, error.message, true);
    settleLoaders(plainError(error.status, "load analyses"));
  }
  return false;
}

async function loadAll() {
  const ready = await refreshStatus();
  if (!ready) return;
  await loadPickers();
  try {
    await loadAnalyses();
  } catch (error) {
    const tbody = document.getElementById("analyses-rows");
    tbody.textContent = "";
    const tr = document.createElement("tr");
    const td = cell(error.message);
    td.colSpan = 6;
    tr.appendChild(td);
    tbody.appendChild(tr);
  }
  await refreshRetention();
}

async function refreshRetention() {
  const summary = document.getElementById("retention-summary");
  if (!can.audit || !summary) return;
  try {
    const payload = await apiRequest("/retention/due?limit=500", {}, "count expired records");
    const count = Number(payload.count) || 0;
    summary.textContent = count ? `${count} expired ${count === 1 ? "record is" : "records are"} ready to be deleted.` : "No records have expired.";
    const purge = document.getElementById("purge-expired");
    if (purge) {
      purge.textContent = count ? `Delete expired records (${count})` : "Delete expired records";
      purge.disabled = !count;
    }
  } catch (error) {
    summary.textContent = error.message;
  }
}

// ---- wiring ------------------------------------------------------------
document.getElementById("refresh-status").addEventListener("click", () => { loadAll().catch(() => {}); });
document.getElementById("analysis-filter").addEventListener("change", () => {
  loadAnalyses().catch((error) => setStatus(operationStatus, error.message, true));
});

document.getElementById("analyze-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const fileInput = document.getElementById("artifact-file");
  const file = fileInput.files && fileInput.files[0];
  const artifact = state.artifacts[Number(document.getElementById("artifact-select").value)];
  const criteria = state.criteria[Number(document.getElementById("criteria-select").value)];
  try {
    await run("Analyzing the document", async () => {
      if (!artifact || document.getElementById("artifact-select").value === "") throw new Error("Choose a document first.");
      if (!criteria || document.getElementById("criteria-select").value === "") throw new Error("Choose review criteria first.");
      if (!file) throw new Error("Choose the document's file from your computer.");
      if (file.size !== artifact.byte_length) {
        throw new Error("That file doesn't match the registered document. Choose the same file that was registered.");
      }
      const metadata = {
        schema: "lightwork.ai-evidence.upload-metadata.v1",
        artifact_id: artifact.artifact_id,
        source_ref: artifact.source_ref,
        source_revision: artifact.source_revision,
        acquired_at: artifact.acquired_at,
        expected_artifact_authority_sha256: artifact.authority_sha256,
        criteria_set_id: criteria.criteria_set_id,
        expected_criteria_revision: criteria.revision,
        expected_criteria_authority_sha256: criteria.authority_sha256,
        idempotency_key: document.getElementById("analyze-operation-id").value || reference("analyze"),
      };
      let payload;
      try {
        payload = await apiRequest("/analyses", {
          method: "POST",
          body: file,
          headers: { "Content-Type": file.type, "X-Lightwork-Evidence-Metadata": JSON.stringify(metadata) },
        }, "analyze the document");
      } catch (error) {
        // The server compares the file with the registered fingerprint.
        if (error.status === 409) {
          error.message = "That file doesn't match the registered document, or the document or criteria changed. Choose the registered file, or refresh and try again.";
        }
        throw error;
      }
      document.getElementById("analyze-operation-id").value = reference("analyze");
      document.getElementById("analysis-filter").value = "pending_review";
      await loadAnalyses();
      done(`Analysis finished: ${summaryText(payload)}. It now waits for someone else to review it.`, payload);
    });
  } catch (_error) {
    // Status already rendered.
  } finally {
    fileInput.value = "";
  }
});

document.getElementById("register-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const fileInput = document.getElementById("register-file");
  const file = fileInput.files && fileInput.files[0];
  try {
    await run("Registering the document", async () => {
      if (!file) throw new Error("Choose the document to register.");
      if (!MEDIA[file.type]) throw new Error("That kind of file can't be analyzed. Use a PDF, JPEG or PNG image, Excel workbook or plain text file.");
      const matter = document.getElementById("register-matter").value.trim();
      if (!matter) throw new Error("Enter the case or matter the document belongs to.");
      const received = Date.parse(document.getElementById("register-received").value);
      if (!Number.isFinite(received) || received <= 0) throw new Error("Choose the date the document was received.");
      const query = new URLSearchParams({
        name: file.name,
        matter,
        received_at: String(received / 1000),
        valid_days: document.getElementById("register-valid").value || "90",
      });
      const payload = await apiRequest(`/authorities/artifacts/register?${query.toString()}`, {
        method: "POST",
        body: file,
        headers: { "Content-Type": file.type },
      }, "register the document");
      event.target.reset();
      await loadPickers();
      done(`${file.name} is registered and can now be analyzed.`, payload);
    });
  } catch (_error) {
    // Status already rendered.
  }
});

document.getElementById("verify-integrity").addEventListener("click", async () => {
  try {
    await run("Checking records", async () => {
      const payload = await apiRequest("/integrity", {}, "check the records");
      done(`All ${payload.analyses} ${payload.analyses === 1 ? "analysis is" : "analyses are"} intact and unaltered.`, payload);
    });
  } catch (_error) {
    // Status already rendered.
  }
});

const purgeButton = document.getElementById("purge-expired");
if (purgeButton) {
  purgeButton.addEventListener("click", async () => {
    const ok = await ask("Permanently delete every expired analysis record? This can't be undone.", "Delete");
    if (!ok) return;
    try {
      await run("Deleting expired records", async () => {
        const payload = await apiRequest("/retention/purge", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ limit: 500 }),
        }, "delete expired records");
        await refreshRetention();
        await loadAnalyses();
        done(`Deleted ${payload.analyses || 0} expired ${payload.analyses === 1 ? "record" : "records"}.`, payload);
      });
    } catch (_error) {
      // Status already rendered.
    }
  });
}

// A turned-off module shows its gate instead of this workbench's checks:
// nothing is requested, and the page already says when analyses will appear.
if (shell && apiBase && shell.dataset.moduleEnabled !== "false") {
  loadAll().catch(() => {});
}
})();
