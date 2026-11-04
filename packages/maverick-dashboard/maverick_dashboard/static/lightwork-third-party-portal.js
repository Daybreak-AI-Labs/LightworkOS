// Supplier questionnaire page (invitation-only, outside the dashboard).
//
// A supplier pastes the access code they were sent, answers the questions the
// invitation allows, adds evidence files and sends. Everything technical stays
// out of sight: the server measures each file's fingerprint, size and type from
// the file itself (this page never asks for them), request keys and versions
// are carried here, and replies are checked against a closed shape before
// anything is shown. The access code lives only in this page's memory and is
// sent only in the Authorization header. This page does not load the dashboard
// helpers (lightwork-ui.js); errorText() below is its own plain-language
// equivalent of mvErrorText().
(function thirdPartyCollaborationPortal(global) {
  "use strict";

  const CONTRACT_SCHEMA = "lightwork.third-party-collaboration-contract.v1";
  const RECEIPT_SCHEMA = "lightwork.third-party-collaboration-receipt.v1";
  const TOKEN_RE = /^tpc1\.[A-Za-z0-9_-]{43}$/;
  const ID_RE = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
  const SHA256_RE = /^[0-9a-f]{64}$/;
  const EXTENSION_RE = /\.([A-Za-z0-9]{1,10})$/;
  const PORTAL_PATH_RE = /^\/api\/v1\/external\/third-party-collaboration\/[A-Za-z0-9][A-Za-z0-9_-]{15,127}\/portal$/;
  const MAX_QUESTIONS = 1000;
  const MAX_ARTIFACTS = 100;
  const MAX_ARTIFACT_BYTES = 100 * 1024 * 1024;
  const RADIO_CHOICE_LIMIT = 6;
  const RESPONSE_TYPES = new Set([
    "boolean",
    "single_choice",
    "multi_choice",
    "integer",
    "text_ref",
  ]);
  const ARTIFACT_KINDS = new Set([
    "audit_report",
    "certification",
    "policy",
    "questionnaire",
    "test_report",
    "other_evidence",
  ]);
  const KIND_LABELS = Object.freeze({
    audit_report: "Audit report",
    certification: "Certificate",
    policy: "Policy document",
    questionnaire: "Completed questionnaire",
    test_report: "Test report",
    other_evidence: "Other supporting document",
  });
  const KIND_PLURALS = Object.freeze({
    audit_report: "audit reports",
    certification: "certificates",
    policy: "policy documents",
    questionnaire: "completed questionnaires",
    test_report: "test reports",
    other_evidence: "other supporting documents",
  });
  const DOMAIN_LABELS = Object.freeze({
    security: "Security",
    privacy: "Privacy",
    ethics: "Ethics",
    compliance: "Compliance",
    operational: "Operations",
    ai: "AI",
  });
  // The server names each file's type from its content; this turns that name
  // into words a supplier recognises.
  const FILE_TYPE_LABELS = Object.freeze({
    "application.pdf": "PDF document",
    "application.vnd.openxmlformats-officedocument.wordprocessingml.document": "Word document",
    "application.msword": "Word document",
    "application.rtf": "Word document",
    "application.vnd.oasis.opendocument.text": "Document",
    "application.vnd.openxmlformats-officedocument.spreadsheetml.sheet": "Spreadsheet",
    "application.vnd.ms-excel": "Spreadsheet",
    "application.vnd.oasis.opendocument.spreadsheet": "Spreadsheet",
    "text.csv": "Spreadsheet (comma-separated)",
    "application.vnd.openxmlformats-officedocument.presentationml.presentation": "Presentation",
    "application.vnd.ms-powerpoint": "Presentation",
    "application.vnd.oasis.opendocument.presentation": "Presentation",
    "application.vnd.ms-outlook": "Email message",
    "application.zip": "Compressed folder (ZIP)",
    "image.png": "Image",
    "image.jpeg": "Image",
    "image.gif": "Image",
    "image.webp": "Image",
    "image.tiff": "Image",
    "text.plain": "Text file",
  });
  const LIMITATION_LABELS = Object.freeze({
    respondent_attestations_are_unverified:
      "Your answers are recorded as your own statement. The organisation that invited you reviews them separately.",
    artifact_manifests_only_no_upload_bytes:
      "Files are checked when you add them. Lightwork keeps each file's size, type and a unique fingerprint, not the file itself, so keep your own copy.",
    no_network_or_email_delivery:
      "This page does not send email. Your invitation and access code come to you directly from the organisation.",
    no_model_inference:
      "No automated system fills in, changes or scores your answers.",
  });
  const WORDS = Object.freeze({
    ai: "AI",
    mfa: "MFA",
    sso: "SSO",
    soc2: "SOC 2",
    iso: "ISO",
    gdpr: "GDPR",
    ccpa: "CCPA",
    hipaa: "HIPAA",
    pci: "PCI",
    nist: "NIST",
    it: "IT",
    id: "ID",
    ids: "IDs",
    url: "URL",
    vpn: "VPN",
    pii: "personal data",
    dpa: "DPA",
    sla: "SLA",
    eu: "EU",
    us: "US",
    uk: "UK",
  });
  const QUESTION_STARTS = new Set([
    "do", "does", "did", "is", "are", "was", "were", "have", "has", "had",
    "can", "could", "will", "would", "should", "may", "how", "what", "which",
    "when", "where", "who", "why",
  ]);
  const CONTRACT_KEYS = new Set([
    "schema",
    "invitation_id",
    "vendor_ref",
    "assessment_id",
    "notice_ref",
    "notice_sha256",
    "artifact_policy",
    "questions",
    "required_question_ids",
    "answered_question_ids",
    "draft_revision",
    "draft_artifacts",
    "expires_at",
    "limitations",
  ]);
  const QUESTION_KEYS = new Set([
    "question_id",
    "domain",
    "prompt_ref",
    "response_type",
    "required",
    "options",
  ]);
  const POLICY_KEYS = new Set([
    "allowed_kinds",
    "maximum_artifacts",
    "maximum_total_bytes",
  ]);
  const ARTIFACT_KEYS = new Set([
    "artifact_id",
    "kind",
    "content_sha256",
    "size_bytes",
    "media_type_ref",
  ]);
  const EVIDENCE_RECEIPT_KEYS = new Set([
    "invitation_id",
    "artifact_id",
    "content_sha256",
    "size_bytes",
    "media_type_ref",
    "idempotent_replay",
  ]);
  const DRAFT_RECEIPT_KEYS = new Set([
    "invitation_id",
    "revision",
    "draft_sha256",
    "active_question_ids",
    "required_question_ids",
    "artifact_count",
    "idempotent_replay",
  ]);
  const FINAL_RECEIPT_KEYS = new Set([
    "schema",
    "invitation_id",
    "assessment_id",
    "assessment_revision",
    "assessment_integrity_sha256",
    "question_ids",
    "attestation_sha256",
    "evidence_status",
    "idempotent_replay",
  ]);

  // A reply that does not match the closed shape the page expects.
  class PortalContractError extends Error {
    constructor(message) {
      super(message);
      this.name = "PortalContractError";
    }
  }

  // A request that failed; `status` is 0 when the server was not reached.
  class PortalRequestError extends Error {
    constructor(status, timedOut) {
      super("portal request failed");
      this.name = "PortalRequestError";
      this.status = status;
      this.timedOut = Boolean(timedOut);
    }
  }

  // Something the supplier can fix; `message` is already a plain sentence.
  class PortalInputError extends Error {
    constructor(message, target) {
      super(message);
      this.name = "PortalInputError";
      this.target = target || null;
    }
  }

  function fail(message) {
    throw new PortalContractError(message);
  }

  function isRecord(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }

  function closedRecord(value, keys, label) {
    if (!isRecord(value)) fail(`The ${label} in the reply is not a set of fields.`);
    const actual = Object.keys(value);
    if (actual.length !== keys.size || actual.some((key) => !keys.has(key))) {
      fail(`The ${label} in the reply has fields this page does not expect.`);
    }
    for (const key of keys) {
      if (!Object.prototype.hasOwnProperty.call(value, key)) {
        fail(`The ${label} in the reply is missing a field.`);
      }
    }
    return value;
  }

  function integer(value, minimum, maximum, label) {
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
      fail(`The ${label} in the reply is outside the allowed range.`);
    }
    return value;
  }

  function finiteNumber(value, minimum, maximum, label) {
    if (typeof value !== "number" || !Number.isFinite(value) || value < minimum || value > maximum) {
      fail(`The ${label} in the reply is outside the allowed range.`);
    }
    return value;
  }

  function identifier(value, label) {
    if (typeof value !== "string" || !ID_RE.test(value)) {
      fail(`The ${label} in the reply is not in the expected form.`);
    }
    return value;
  }

  function digest(value, label) {
    if (typeof value !== "string" || !SHA256_RE.test(value)) {
      fail(`The ${label} in the reply is not in the expected form.`);
    }
    return value;
  }

  function boolean(value, label) {
    if (typeof value !== "boolean") fail(`The ${label} in the reply is not a yes or no value.`);
    return value;
  }

  function closedIdentifierList(value, label, maximum, allowed) {
    if (!Array.isArray(value) || value.length > maximum) {
      fail(`The ${label} in the reply has more items than allowed.`);
    }
    const result = value.map((item) => identifier(item, label));
    if (new Set(result).size !== result.length) fail(`The ${label} in the reply lists the same item twice.`);
    if (allowed && result.some((item) => !allowed.has(item))) {
      fail(`The ${label} in the reply has a value this page does not recognize.`);
    }
    return result;
  }

  function validateArtifactPolicy(value) {
    const item = closedRecord(value, POLICY_KEYS, "artifact policy");
    const kinds = closedIdentifierList(
      item.allowed_kinds,
      "allowed artifact kinds",
      ARTIFACT_KINDS.size,
      ARTIFACT_KINDS,
    );
    const maximumArtifacts = integer(
      item.maximum_artifacts,
      0,
      MAX_ARTIFACTS,
      "maximum artifacts",
    );
    const maximumTotalBytes = integer(
      item.maximum_total_bytes,
      0,
      MAX_ARTIFACT_BYTES,
      "maximum artifact bytes",
    );
    if (
      (maximumArtifacts === 0 && (kinds.length !== 0 || maximumTotalBytes !== 0)) ||
      (maximumArtifacts > 0 && (kinds.length === 0 || maximumTotalBytes === 0))
    ) {
      fail("The file limits for this request are inconsistent.");
    }
    return {
      allowed_kinds: kinds,
      maximum_artifacts: maximumArtifacts,
      maximum_total_bytes: maximumTotalBytes,
    };
  }

  function validateArtifact(value, policy, label) {
    const item = closedRecord(value, ARTIFACT_KEYS, label);
    const kind = identifier(item.kind, `${label} kind`);
    if (!policy.allowed_kinds.includes(kind)) fail(`The ${label} in the reply is a kind of file this request does not accept.`);
    return {
      artifact_id: identifier(item.artifact_id, `${label} ID`),
      kind,
      content_sha256: digest(item.content_sha256, `${label} content digest`),
      size_bytes: integer(item.size_bytes, 1, MAX_ARTIFACT_BYTES, `${label} size`),
      media_type_ref: identifier(item.media_type_ref, `${label} media type reference`),
    };
  }

  function validateQuestion(value) {
    const item = closedRecord(value, QUESTION_KEYS, "question");
    const responseType = item.response_type;
    if (typeof responseType !== "string" || !RESPONSE_TYPES.has(responseType)) {
      fail("A question asks for a kind of answer this page does not support.");
    }
    const options = closedIdentifierList(item.options, "question options", 1000);
    if (
      (["single_choice", "multi_choice"].includes(responseType) && options.length === 0) ||
      (!["single_choice", "multi_choice"].includes(responseType) && options.length !== 0)
    ) {
      fail("A question has choices that do not fit the kind of answer it asks for.");
    }
    return {
      question_id: identifier(item.question_id, "question ID"),
      domain: identifier(item.domain, "question domain"),
      prompt_ref: identifier(item.prompt_ref, "question prompt reference"),
      response_type: responseType,
      required: boolean(item.required, "question required flag"),
      options,
    };
  }

  function validateContract(value) {
    const item = closedRecord(value, CONTRACT_KEYS, "invitation contract");
    if (item.schema !== CONTRACT_SCHEMA) fail("The request uses a format this page does not support.");
    const policy = validateArtifactPolicy(item.artifact_policy);
    if (!Array.isArray(item.questions) || item.questions.length > MAX_QUESTIONS) {
      fail("The request has more questions than this page can show.");
    }
    const questions = item.questions.map(validateQuestion);
    const questionIds = questions.map((question) => question.question_id);
    const questionSet = new Set(questionIds);
    if (questionSet.size !== questionIds.length) fail("The request lists the same question twice.");
    const required = closedIdentifierList(
      item.required_question_ids,
      "required question IDs",
      MAX_QUESTIONS,
    );
    const answered = closedIdentifierList(
      item.answered_question_ids,
      "answered question IDs",
      MAX_QUESTIONS,
    );
    if (required.some((questionId) => !questionSet.has(questionId))) {
      fail("The request lists required questions that are not on this page.");
    }
    if (answered.some((questionId) => !questionSet.has(questionId))) {
      fail("The saved answers include questions that are not on this page.");
    }
    if (!Array.isArray(item.draft_artifacts) || item.draft_artifacts.length > policy.maximum_artifacts) {
      fail("The saved draft has more files than this request allows.");
    }
    const draftArtifacts = item.draft_artifacts.map((artifact) =>
      validateArtifact(artifact, policy, "draft artifact manifest"),
    );
    const artifactIds = draftArtifacts.map((artifact) => artifact.artifact_id);
    if (new Set(artifactIds).size !== artifactIds.length) {
      fail("The saved draft lists the same file twice.");
    }
    const totalBytes = draftArtifacts.reduce((total, artifact) => total + artifact.size_bytes, 0);
    if (totalBytes > policy.maximum_total_bytes) {
      fail("The saved draft has files larger than this request allows.");
    }
    if (!Array.isArray(item.limitations) || item.limitations.length !== 4) {
      fail("The request's list of limitations is incomplete.");
    }
    const limitations = closedIdentifierList(item.limitations, "contract limitations", 4);
    if (
      limitations.some((limitation) =>
        !Object.prototype.hasOwnProperty.call(LIMITATION_LABELS, limitation),
      ) ||
      new Set(limitations).size !== Object.keys(LIMITATION_LABELS).length
    ) {
      fail("The request's list of limitations is missing or not recognized.");
    }
    return {
      schema: CONTRACT_SCHEMA,
      invitation_id: identifier(item.invitation_id, "invitation ID"),
      vendor_ref: identifier(item.vendor_ref, "respondent reference"),
      assessment_id: identifier(item.assessment_id, "assessment ID"),
      notice_ref: identifier(item.notice_ref, "notice reference"),
      notice_sha256: digest(item.notice_sha256, "notice digest"),
      artifact_policy: policy,
      questions,
      required_question_ids: required,
      answered_question_ids: answered,
      draft_revision: integer(item.draft_revision, 0, 1000000, "draft revision"),
      draft_artifacts: draftArtifacts,
      expires_at: finiteNumber(item.expires_at, 1, 100000000000, "invitation expiry"),
      limitations,
    };
  }

  function validateEvidenceReceipt(value, policy) {
    const item = closedRecord(value, EVIDENCE_RECEIPT_KEYS, "evidence receipt");
    const maximum = policy ? policy.maximum_total_bytes : MAX_ARTIFACT_BYTES;
    return {
      invitation_id: identifier(item.invitation_id, "evidence invitation ID"),
      artifact_id: identifier(item.artifact_id, "evidence ID"),
      content_sha256: digest(item.content_sha256, "evidence content digest"),
      size_bytes: integer(item.size_bytes, 1, maximum, "evidence size"),
      media_type_ref: identifier(item.media_type_ref, "evidence media type reference"),
      idempotent_replay: boolean(item.idempotent_replay, "evidence replay flag"),
    };
  }

  function validateDraftReceipt(value) {
    const item = closedRecord(value, DRAFT_RECEIPT_KEYS, "draft receipt");
    const active = closedIdentifierList(
      item.active_question_ids,
      "active question IDs",
      MAX_QUESTIONS,
    );
    const required = closedIdentifierList(
      item.required_question_ids,
      "required question IDs",
      MAX_QUESTIONS,
    );
    if (required.some((questionId) => !new Set(active).has(questionId))) {
      fail("The saved draft lists required questions that are no longer in the request.");
    }
    return {
      invitation_id: identifier(item.invitation_id, "draft invitation ID"),
      revision: integer(item.revision, 1, 1000000, "draft revision"),
      draft_sha256: digest(item.draft_sha256, "draft digest"),
      active_question_ids: active,
      required_question_ids: required,
      artifact_count: integer(item.artifact_count, 0, MAX_ARTIFACTS, "artifact count"),
      idempotent_replay: boolean(item.idempotent_replay, "draft replay flag"),
    };
  }

  function validateFinalReceipt(value) {
    const item = closedRecord(value, FINAL_RECEIPT_KEYS, "final receipt");
    if (item.schema !== RECEIPT_SCHEMA) fail("The receipt for the sent answers uses a format this page does not support.");
    if (item.evidence_status !== "respondent_attestation_unverified") {
      fail("The receipt gives a file status this page does not recognize.");
    }
    return {
      schema: RECEIPT_SCHEMA,
      invitation_id: identifier(item.invitation_id, "final invitation ID"),
      assessment_id: identifier(item.assessment_id, "final assessment ID"),
      assessment_revision: integer(
        item.assessment_revision,
        1,
        1000000,
        "assessment revision",
      ),
      assessment_integrity_sha256: digest(
        item.assessment_integrity_sha256,
        "assessment integrity digest",
      ),
      question_ids: closedIdentifierList(item.question_ids, "final question IDs", MAX_QUESTIONS),
      attestation_sha256: digest(item.attestation_sha256, "attestation digest"),
      evidence_status: item.evidence_status,
      idempotent_replay: boolean(item.idempotent_replay, "final replay flag"),
    };
  }

  // ---- plain words -----------------------------------------------------------

  function human(value) {
    const words = String(value === null || value === undefined ? "" : value)
      .trim()
      .replace(/[-_.:]+/g, " ")
      .split(/\s+/)
      .filter(Boolean);
    if (!words.length) return "";
    const out = words
      .map((word) => {
        const key = word.toLowerCase();
        if (Object.prototype.hasOwnProperty.call(WORDS, key)) return WORDS[key];
        return /[A-Z].*[A-Z]/.test(word) ? word : key;
      })
      .join(" ");
    return out.charAt(0).toUpperCase() + out.slice(1);
  }

  function questionText(promptRef) {
    const stripped = String(promptRef).replace(/^(prompt|question|q)[-_.:]+/i, "");
    const text = human(stripped || promptRef);
    const first = text.split(" ")[0].toLowerCase();
    return QUESTION_STARTS.has(first) && !/[?.!]$/.test(text) ? `${text}?` : text;
  }

  function sizeText(sizeBytes) {
    if (sizeBytes < 1024) return "Less than 1 KB";
    if (sizeBytes < 1024 * 1024) {
      const kilo = sizeBytes / 1024;
      return `${kilo < 10 ? kilo.toFixed(1).replace(/\.0$/, "") : Math.round(kilo)} KB`;
    }
    const mega = sizeBytes / (1024 * 1024);
    return `${mega < 10 ? mega.toFixed(1).replace(/\.0$/, "") : Math.round(mega)} MB`;
  }

  function fileTypeText(mediaTypeRef) {
    return FILE_TYPE_LABELS[mediaTypeRef] || "Other file";
  }

  function listText(items) {
    if (items.length <= 1) return items.join("");
    return `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
  }

  function dateText(seconds) {
    const when = new Date(seconds * 1000);
    if (window.mvTimeAbsolute) return window.mvTimeAbsolute(seconds);
    try {
      return when.toLocaleString(undefined, { dateStyle: "long", timeStyle: "short" });
    } catch (_error) {
      return when.toLocaleString();
    }
  }

  function quoted(name) {
    return `“${name}”`;
  }

  // Plain-language failure text, in the same spirit as the dashboard's
  // mvErrorText(): never a status code, a class name or server wording.
  function errorText(error, action) {
    if (error instanceof PortalInputError) return error.message;
    const what = action ? `Could not ${action}. ` : "";
    if (error instanceof PortalContractError) {
      return `${what}The page received a reply it did not expect, so it stopped to keep your answers safe. Reload the page and try again.`;
    }
    const status = error instanceof PortalRequestError ? error.status : 0;
    if (!status) {
      if (error && error.timedOut) return `${what}It took too long. Check your connection and try again.`;
      return `${what}Lightwork could not be reached. Check your connection and try again.`;
    }
    if (status === 404) {
      return `${what}This access code no longer works. It may have expired, been replaced by a new one, or been cancelled. Ask the person who invited you for a new code.`;
    }
    if (status === 403) return `${what}That is not part of what this request lets you answer. Reload the page and try again.`;
    if (status === 409) return `${what}Your answers were changed somewhere else since this page opened. The latest version has been loaded; check your answers and try again.`;
    if (status === 413) return `${what}That file is too big for this request.`;
    if (status === 400 || status === 411 || status === 415) return `${what}The file could not be read. Choose it again and try once more.`;
    if (status === 422) return `${what}Some answers or files need fixing. Check what you entered and try again.`;
    if (status === 429) return `${what}Too many tries in a short time. Wait a minute and try again.`;
    return `${what}This is temporarily unavailable, so nothing was sent. Try again in a few minutes.`;
  }

  // ---- page state --------------------------------------------------------------

  const state = {
    initialized: false,
    credential: null,
    apiBase: null,
    contract: null,
    answerMemory: new Map(),
    files: [],
    fileNames: new Map(),
    pendingOperations: new Map(),
    activeControllers: new Set(),
    busy: false,
    dirty: false,
    lockArmed: false,
    nextControl: 0,
  };

  let elements = null;

  function element(id) {
    const value = global.document.getElementById(id);
    if (!value) fail("The page is missing parts it needs to show the request.");
    return value;
  }

  function setStatus(message, statusState) {
    if (!elements) return;
    elements.status.textContent = message;
    if (statusState) elements.status.dataset.state = statusState;
    else delete elements.status.dataset.state;
  }

  function text(parent, value) {
    parent.textContent = String(value);
  }

  function append(parent, tagName, value, className) {
    const child = global.document.createElement(tagName);
    if (value !== undefined && value !== null) text(child, value);
    if (className) child.className = className;
    parent.appendChild(child);
    return child;
  }

  function uniqueId(prefix) {
    state.nextControl += 1;
    return `${prefix}-${state.nextControl}`;
  }

  function labelled(parent, control, labelText, helpText) {
    const wrapper = append(parent, "div", null, "field");
    const label = append(wrapper, "label", labelText);
    label.htmlFor = control.id;
    wrapper.appendChild(control);
    if (helpText) {
      const help = append(wrapper, "p", helpText, "help");
      help.id = `${control.id}-help`;
      control.setAttribute("aria-describedby", help.id);
    }
    return wrapper;
  }

  function setBusy(value) {
    state.busy = value;
    for (const button of [
      elements.unlockButton,
      elements.lockButton,
      elements.addFilesButton,
      elements.saveDraftButton,
      elements.finalizeButton,
    ]) {
      button.disabled = value;
    }
  }

  function secureOperationId(action, body) {
    const fingerprint = JSON.stringify(body);
    const pending = state.pendingOperations.get(action);
    if (pending && pending.fingerprint === fingerprint) return pending.key;
    if (!global.crypto || typeof global.crypto.randomUUID !== "function") {
      fail("This browser cannot create the secure reference the page needs. Use an up-to-date browser.");
    }
    const key = `portal-${action}-${global.crypto.randomUUID()}`;
    state.pendingOperations.set(action, { fingerprint, key });
    return key;
  }

  // One request to the invitation's own endpoints. `options.raw` sends a file
  // as-is (no form encoding, no reading it in the page); the server measures it.
  async function portalRequest(route, method, body, options) {
    if (!state.credential || !state.apiBase) throw new PortalRequestError(404);
    const settings = options || {};
    const controller = new global.AbortController();
    state.activeControllers.add(controller);
    let timedOut = false;
    const timeout = global.setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, settings.timeoutMs || 15000);
    const headers = {
      Accept: "application/json",
      Authorization: `ThirdPartyInvitation ${state.credential}`,
    };
    let requestBody;
    if (settings.raw) {
      headers["Content-Type"] = "application/octet-stream";
      if (settings.extension) headers["X-Evidence-File-Extension"] = settings.extension;
      requestBody = body;
    } else if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      requestBody = JSON.stringify(body);
    }
    try {
      const response = await global.fetch(`${state.apiBase}${route}`, {
        method,
        headers,
        body: requestBody,
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
        referrerPolicy: "no-referrer",
        signal: controller.signal,
      });
      if (!response.ok) throw new PortalRequestError(response.status);
      const contentType = response.headers.get("content-type") || "";
      if (!contentType.toLowerCase().startsWith("application/json")) {
        throw new PortalContractError("The reply from the server was not in the expected format.");
      }
      return await response.json();
    } catch (error) {
      if (error instanceof PortalRequestError || error instanceof PortalContractError) throw error;
      throw new PortalRequestError(0, timedOut);
    } finally {
      global.clearTimeout(timeout);
      state.activeControllers.delete(controller);
    }
  }

  // ---- questions ---------------------------------------------------------------

  function choiceGroup(card, question, index, type, rememberedValues, optionLabel) {
    const group = append(card, "div", null, "choice-list");
    group.dataset.responseType = question.response_type;
    const name = `question-${index}`;
    for (const optionValue of question.options) {
      const label = append(group, "label");
      const input = append(label, "input");
      input.type = type;
      input.name = name;
      input.value = optionValue;
      input.id = uniqueId("choice");
      input.checked = rememberedValues.has(optionValue);
      input.dataset.answer = "true";
      append(label, "span", optionLabel(optionValue));
    }
    return group;
  }

  function renderQuestionControl(card, question, index, remembered) {
    const type = question.response_type;
    if (type === "boolean") {
      const values = new Set(typeof remembered === "boolean" ? [String(remembered)] : []);
      const group = choiceGroup(
        card,
        { ...question, options: ["true", "false"] },
        index,
        "radio",
        values,
        (value) => (value === "true" ? "Yes" : "No"),
      );
      group.setAttribute("role", "radiogroup");
      return group;
    }
    if (type === "single_choice" && question.options.length <= RADIO_CHOICE_LIMIT) {
      const values = new Set(typeof remembered === "string" ? [remembered] : []);
      const group = choiceGroup(card, question, index, "radio", values, human);
      group.setAttribute("role", "radiogroup");
      return group;
    }
    if (type === "single_choice") {
      const select = global.document.createElement("select");
      select.id = uniqueId("answer");
      select.dataset.answer = "true";
      append(select, "option", "Choose an answer").value = "";
      for (const optionValue of question.options) {
        append(select, "option", human(optionValue)).value = optionValue;
      }
      if (typeof remembered === "string" && question.options.includes(remembered)) {
        select.value = remembered;
      }
      labelled(card, select, "Your answer");
      return select;
    }
    if (type === "multi_choice") {
      append(card, "p", "Choose all that apply.", "help");
      const values = new Set(Array.isArray(remembered) ? remembered : []);
      return choiceGroup(card, question, index, "checkbox", values, human);
    }
    const input = global.document.createElement("input");
    input.id = uniqueId("answer");
    input.dataset.answer = "true";
    input.autocomplete = "off";
    if (type === "integer") {
      input.type = "number";
      input.inputMode = "numeric";
      input.min = "-1000000000";
      input.max = "1000000000";
      input.step = "1";
      if (Number.isSafeInteger(remembered)) input.value = String(remembered);
      labelled(card, input, "Your answer (a whole number)");
      return input;
    }
    input.type = "text";
    input.maxLength = 128;
    input.spellcheck = false;
    if (typeof remembered === "string") input.value = remembered;
    labelled(
      card,
      input,
      "Your answer",
      "A short reference, such as a policy or certificate number. Use letters, numbers, dots, dashes, underscores or colons, with no spaces.",
    );
    return input;
  }

  function renderQuestions(contract) {
    const fragment = global.document.createDocumentFragment();
    const answered = new Set(contract.answered_question_ids);
    for (const [index, question] of contract.questions.entries()) {
      const card = append(fragment, "fieldset", null, "question-card portal-question");
      card.dataset.questionId = question.question_id;
      card.dataset.responseType = question.response_type;
      card.dataset.required = String(question.required);
      const legend = append(card, "legend");
      append(legend, "span", questionText(question.prompt_ref), "question-text");
      append(
        legend,
        "span",
        question.required ? "Required" : "Optional",
        question.required ? "required-mark" : "optional-mark",
      );
      const meta = append(card, "div", null, "question-meta");
      append(meta, "span", `Topic: ${DOMAIN_LABELS[question.domain] || human(question.domain)}`, "chip");
      if (answered.has(question.question_id) && !state.answerMemory.has(question.question_id)) {
        append(
          card,
          "p",
          "You answered this in a saved version. For your privacy, saved answers are not shown again, so please answer it again before you send.",
          "answered-note",
        );
      }
      renderQuestionControl(card, question, index, state.answerMemory.get(question.question_id));
      const error = append(card, "p", null, "field-error");
      error.id = uniqueId("question-error");
      error.hidden = true;
      const clear = append(card, "button", "Clear answer", "secondary clear-answer");
      clear.type = "button";
      clear.addEventListener("click", () => {
        for (const input of card.querySelectorAll("input")) {
          if (input.type === "checkbox" || input.type === "radio") input.checked = false;
          else input.value = "";
        }
        for (const select of card.querySelectorAll("select")) select.value = "";
        state.answerMemory.delete(question.question_id);
        showFieldError(card, null);
        markDirty();
        setStatus("Answer cleared. Save to update which questions you are asked next.");
      });
    }
    if (contract.questions.length === 0) {
      append(fragment, "p", "There are no questions for you to answer right now.", "help");
    }
    elements.questions.replaceChildren(fragment);
    updateProgress();
  }

  function showFieldError(container, message) {
    const error = container.querySelector(".field-error");
    const controls = container.querySelectorAll("[data-answer], [data-file-field]");
    if (error) {
      error.textContent = message || "";
      error.hidden = !message;
    }
    for (const control of controls) {
      if (message) {
        control.setAttribute("aria-invalid", "true");
        if (error) {
          const described = (control.getAttribute("aria-describedby") || "").split(" ").filter(Boolean);
          if (!described.includes(error.id)) described.push(error.id);
          control.setAttribute("aria-describedby", described.join(" "));
        }
      } else {
        control.removeAttribute("aria-invalid");
        if (error) {
          const described = (control.getAttribute("aria-describedby") || "")
            .split(" ")
            .filter((item) => item && item !== error.id);
          if (described.length) control.setAttribute("aria-describedby", described.join(" "));
          else control.removeAttribute("aria-describedby");
        }
      }
    }
  }

  // The card's current answer: { value } when answered, { missing: true } when
  // empty, or { error } when what was entered cannot be accepted.
  function readQuestion(card) {
    const type = card.dataset.responseType;
    const question = state.contract.questions.find(
      (item) => item.question_id === card.dataset.questionId,
    );
    if (!question) fail("That question is not part of this request.");
    if (type === "multi_choice") {
      const checked = Array.from(card.querySelectorAll('input[type="checkbox"]:checked')).map(
        (input) => input.value,
      );
      if (checked.length === 0) return { missing: true };
      if (checked.some((value) => !question.options.includes(value))) fail("That answer is not one of the choices.");
      return { value: checked };
    }
    if (type === "boolean" || (type === "single_choice" && card.querySelector('input[type="radio"]'))) {
      const chosen = card.querySelector('input[type="radio"]:checked');
      if (!chosen) return { missing: true };
      if (type === "boolean") {
        if (chosen.value === "true") return { value: true };
        if (chosen.value === "false") return { value: false };
        fail("That answer is not Yes or No.");
      }
      if (!question.options.includes(chosen.value)) fail("That answer is not one of the choices.");
      return { value: chosen.value };
    }
    const control = card.querySelector("input[data-answer], select[data-answer]");
    const raw = control ? String(control.value).trim() : "";
    if (type === "integer" && control && control.validity && control.validity.badInput) {
      return { error: "Enter a whole number, like 12." };
    }
    if (raw === "") return { missing: true };
    if (type === "integer") {
      const parsed = Number(raw);
      if (!Number.isSafeInteger(parsed) || parsed < -1000000000 || parsed > 1000000000) {
        return { error: "Enter a whole number, like 12." };
      }
      return { value: parsed };
    }
    if (type === "text_ref") {
      if (!ID_RE.test(raw)) {
        return {
          error: "Use only letters, numbers, dots, dashes, underscores or colons, with no spaces, and start with a letter or number (up to 128 characters).",
        };
      }
      return { value: raw };
    }
    if (!question.options.includes(raw)) fail("That answer is not one of the choices.");
    return { value: raw };
  }

  function missingText(card) {
    return card.dataset.responseType === "boolean"
      ? "Choose Yes or No."
      : card.dataset.responseType === "multi_choice"
        ? "Choose at least one answer."
        : card.dataset.responseType === "single_choice"
          ? "Choose an answer."
          : "Answer this question before you send.";
  }

  function updateProgress() {
    if (!state.contract || !elements) return;
    const cards = Array.from(elements.questions.querySelectorAll(".portal-question"));
    let answered = 0;
    let requiredLeft = 0;
    for (const card of cards) {
      let result;
      try {
        result = readQuestion(card);
      } catch (_error) {
        result = { missing: true };
      }
      if (result.value !== undefined) answered += 1;
      else if (card.dataset.required === "true") requiredLeft += 1;
    }
    const total = cards.length;
    const parts = [`${answered} of ${total} ${total === 1 ? "question" : "questions"} answered`];
    if (requiredLeft) {
      parts.push(`${requiredLeft} required ${requiredLeft === 1 ? "question" : "questions"} left`);
    } else if (total) {
      parts.push("all required questions answered");
    }
    text(elements.questionProgress, parts.join(" · "));
  }

  // ---- evidence files -----------------------------------------------------------

  function filesFromContract(contract) {
    return contract.draft_artifacts.map((artifact) => ({
      artifact: {
        artifact_id: artifact.artifact_id,
        content_sha256: artifact.content_sha256,
        size_bytes: artifact.size_bytes,
        media_type_ref: artifact.media_type_ref,
      },
      kind: artifact.kind,
      supportIds: [],
    }));
  }

  function syncFilesFromPage() {
    for (const item of state.files) {
      if (!item.row) continue;
      const kind = item.row.querySelector('[data-file-field="kind"]');
      if (kind) item.kind = kind.value;
      item.supportIds = Array.from(
        item.row.querySelectorAll('[data-file-field="support"]:checked'),
      ).map((input) => input.value);
    }
  }

  function renderFileRow(item) {
    const policy = state.contract.artifact_policy;
    const row = append(elements.evidenceFiles, "li", null, "evidence-file portal-file");
    item.row = row;
    const name = state.fileNames.get(item.artifact.artifact_id) || null;
    const summary = append(row, "div", null, "file-summary");
    append(summary, "p", name || "File added earlier", "file-name");
    append(
      summary,
      "p",
      `${fileTypeText(item.artifact.media_type_ref)} · ${sizeText(item.artifact.size_bytes)}`,
      "file-facts",
    );
    const kind = global.document.createElement("select");
    kind.id = uniqueId("file-kind");
    kind.dataset.fileField = "kind";
    if (policy.allowed_kinds.length > 1) append(kind, "option", "Choose what this file is").value = "";
    for (const allowedKind of policy.allowed_kinds) {
      append(kind, "option", KIND_LABELS[allowedKind] || human(allowedKind)).value = allowedKind;
    }
    if (item.kind && policy.allowed_kinds.includes(item.kind)) kind.value = item.kind;
    labelled(row, kind, "What is this file?");
    const support = append(row, "fieldset", null, "support-list");
    append(support, "legend", "Which answers does it back up?");
    const selected = new Set(item.supportIds || []);
    if (state.contract.questions.length === 0) {
      append(support, "p", "There are no questions to link this file to yet.", "help");
    }
    for (const question of state.contract.questions) {
      const label = append(support, "label");
      const checkbox = append(label, "input");
      checkbox.type = "checkbox";
      checkbox.value = question.question_id;
      checkbox.checked = selected.has(question.question_id);
      checkbox.id = uniqueId("file-support");
      checkbox.dataset.fileField = "support";
      append(label, "span", questionText(question.prompt_ref));
    }
    const error = append(row, "p", null, "field-error");
    error.id = uniqueId("file-error");
    error.hidden = true;
    const remove = append(row, "button", "Remove", "secondary remove-file");
    remove.type = "button";
    remove.setAttribute("aria-label", `Remove ${name || "this file"}`);
    remove.addEventListener("click", () => {
      state.files = state.files.filter((candidate) => candidate !== item);
      row.remove();
      markDirty();
      updateFilePolicy();
      setStatus(`${name ? quoted(name) : "The file"} was removed from your list. Save to keep this change.`);
    });
    return row;
  }

  function usedBytes() {
    return state.files.reduce((total, item) => total + item.artifact.size_bytes, 0);
  }

  function updateFilePolicy() {
    const policy = state.contract.artifact_policy;
    if (policy.maximum_artifacts === 0) {
      text(elements.evidencePolicy, "This request does not ask for any files.");
      elements.addFilesButton.hidden = true;
      return;
    }
    const kinds = listText(policy.allowed_kinds.map((kind) => KIND_PLURALS[kind] || human(kind)));
    const used = state.files.length
      ? ` You have added ${state.files.length} (${sizeText(usedBytes())}).`
      : "";
    text(
      elements.evidencePolicy,
      `You can add up to ${policy.maximum_artifacts} ${policy.maximum_artifacts === 1 ? "file" : "files"}, up to ${sizeText(policy.maximum_total_bytes)} in total. Accepted: ${kinds}.${used}`,
    );
    elements.addFilesButton.hidden = false;
  }

  function renderFiles(contract, preserveLocal) {
    if (preserveLocal) {
      syncFilesFromPage();
      const local = new Set(state.files.map((item) => item.artifact.artifact_id));
      for (const item of filesFromContract(contract)) {
        if (!local.has(item.artifact.artifact_id)) state.files.push(item);
      }
    } else {
      state.files = filesFromContract(contract);
    }
    elements.evidenceFiles.replaceChildren();
    for (const item of state.files) renderFileRow(item);
    elements.evidenceEmpty.hidden = state.files.length !== 0 || contract.artifact_policy.maximum_artifacts === 0;
    updateFilePolicy();
  }

  function fileExtension(name) {
    const match = EXTENSION_RE.exec(String(name || ""));
    return match ? match[1].toLowerCase() : null;
  }

  function uploadTimeout(sizeBytes) {
    return Math.min(600000, 30000 + Math.ceil(sizeBytes / (256 * 1024)) * 1000);
  }

  function fileProblem(file, name) {
    const policy = state.contract.artifact_policy;
    if (state.files.length >= policy.maximum_artifacts) {
      return `You've reached the file limit for this request (${policy.maximum_artifacts} ${policy.maximum_artifacts === 1 ? "file" : "files"}). Remove a file to add another.`;
    }
    if (!file.size) return `${quoted(name)} is empty, so it cannot be added.`;
    if (file.size > policy.maximum_total_bytes) {
      return `${quoted(name)} is too big. Files for this request can add up to ${sizeText(policy.maximum_total_bytes)} in total.`;
    }
    if (usedBytes() + file.size > policy.maximum_total_bytes) {
      return `Adding ${quoted(name)} would go over the ${sizeText(policy.maximum_total_bytes)} allowed for this request. Remove a file or choose a smaller one.`;
    }
    return null;
  }

  // Check one chosen file on the server. Returns null when it was added, or a
  // plain sentence saying why it was not.
  function displayName(file) {
    return String(file.name || "Unnamed file").slice(0, 200);
  }

  async function addOneFile(file) {
    const name = displayName(file);
    const problem = fileProblem(file, name);
    if (problem) return problem;
    const placeholder = append(elements.evidenceFiles, "li", null, "evidence-file checking");
    append(placeholder, "p", name, "file-name");
    append(placeholder, "p", "Checking this file\u2026", "file-facts");
    elements.evidenceEmpty.hidden = true;
    setStatus(`Checking ${quoted(name)}\u2026`);
    try {
      const raw = await portalRequest("/evidence", "POST", file, {
        raw: true,
        extension: fileExtension(name),
        timeoutMs: uploadTimeout(file.size),
      });
      const receipt = validateEvidenceReceipt(raw, state.contract.artifact_policy);
      if (receipt.invitation_id !== state.contract.invitation_id) {
        fail("The file receipt belongs to a different request.");
      }
      if (receipt.size_bytes !== file.size) {
        return `${quoted(name)} changed while it was being checked. Choose it again.`;
      }
      if (state.files.some((item) => item.artifact.artifact_id === receipt.artifact_id)) {
        return `${quoted(name)} is already in your list.`;
      }
      state.fileNames.set(receipt.artifact_id, name);
      const policy = state.contract.artifact_policy;
      const item = {
        artifact: {
          artifact_id: receipt.artifact_id,
          content_sha256: receipt.content_sha256,
          size_bytes: receipt.size_bytes,
          media_type_ref: receipt.media_type_ref,
        },
        kind: policy.allowed_kinds.length === 1 ? policy.allowed_kinds[0] : "",
        supportIds: [],
      };
      state.files.push(item);
      renderFileRow(item);
      markDirty();
      return null;
    } catch (error) {
      if (error instanceof PortalRequestError && error.status === 413) {
        return `${quoted(name)} is too big for this request.`;
      }
      return errorText(error, `add ${quoted(name)}`);
    } finally {
      placeholder.remove();
      if (state.contract) {
        elements.evidenceEmpty.hidden = state.files.length !== 0;
        updateFilePolicy();
      }
    }
  }

  async function addFiles(fileList) {
    if (!state.contract || state.busy) return 0;
    const files = Array.from(fileList || []);
    if (!files.length) return 0;
    setBusy(true);
    const addedNames = [];
    const problems = [];
    try {
      for (const file of files) {
        if (!state.contract) break;
        const problem = await addOneFile(file);
        if (problem) problems.push(problem);
        else addedNames.push(displayName(file));
      }
    } finally {
      setBusy(false);
      elements.fileInput.value = "";
    }
    const added = addedNames.length;
    if (!state.contract) return added;
    const addedText = added === 1
      ? `${quoted(addedNames[0])} was checked and added.`
      : `${added} files were checked and added.`;
    if (problems.length) {
      const more = problems.length > 1 ? ` ${problems.length - 1} more could not be added either.` : "";
      setStatus(`${added ? `${addedText} ` : ""}${problems[0]}${more}`, "error");
    } else {
      setStatus(
        `${addedText} Choose what ${added === 1 ? "it is and which answers it backs" : "each one is and which answers it backs"} up, then save.`,
        "success",
      );
    }
    return added;
  }

  // ---- saving and sending ------------------------------------------------------

  function markDirty() {
    state.dirty = true;
    state.lockArmed = false;
  }

  function collectSubmission(requireComplete) {
    if (!state.contract) fail("The request details have not loaded.");
    const answers = {};
    const problems = [];
    for (const card of elements.questions.querySelectorAll(".portal-question")) {
      const questionId = identifier(card.dataset.questionId, "question ID");
      const result = readQuestion(card);
      if (result.error) {
        problems.push({ container: card, message: result.error });
        continue;
      }
      if (result.missing) {
        if (requireComplete && card.dataset.required === "true") {
          problems.push({ container: card, message: missingText(card) });
        } else {
          showFieldError(card, null);
        }
        continue;
      }
      showFieldError(card, null);
      state.answerMemory.set(questionId, result.value);
      answers[questionId] = { value: result.value, artifact_ids: [] };
    }
    if (Object.keys(answers).length > MAX_QUESTIONS) fail("This request has more answers than it has questions.");
    syncFilesFromPage();
    const policy = state.contract.artifact_policy;
    if (state.files.length > policy.maximum_artifacts) {
      throw new PortalInputError("You've reached the file limit for this request. Remove a file and try again.");
    }
    const artifacts = [];
    for (const item of state.files) {
      const name = state.fileNames.get(item.artifact.artifact_id);
      const label = name ? quoted(name) : "a file you added earlier";
      let message = null;
      if (!policy.allowed_kinds.includes(item.kind)) {
        message = `Choose what kind of document ${label} is.`;
      } else if (!item.supportIds.length) {
        message = `Tick at least one answer that ${label} backs up.`;
      } else {
        const unanswered = item.supportIds.find(
          (questionId) => !Object.prototype.hasOwnProperty.call(answers, questionId),
        );
        if (unanswered) {
          const question = state.contract.questions.find((q) => q.question_id === unanswered);
          message = `${name ? quoted(name) : "A file"} backs up “${question ? questionText(question.prompt_ref) : "a question"}”, which has no answer yet. Answer it or untick it.`;
        }
      }
      if (message) {
        problems.push({ container: item.row, message });
        continue;
      }
      if (item.row) showFieldError(item.row, null);
      const artifact = validateArtifact({ ...item.artifact, kind: item.kind }, policy, "artifact manifest");
      for (const questionId of item.supportIds) answers[questionId].artifact_ids.push(artifact.artifact_id);
      artifacts.push(artifact);
    }
    if (artifacts.reduce((total, artifact) => total + artifact.size_bytes, 0) > policy.maximum_total_bytes) {
      throw new PortalInputError(
        `Your files add up to more than the ${sizeText(policy.maximum_total_bytes)} allowed. Remove a file and try again.`,
      );
    }
    if (problems.length) {
      for (const problem of problems) {
        if (problem.container) showFieldError(problem.container, problem.message);
      }
      const first = problems[0];
      const focusTarget = first.container
        ? first.container.querySelector("input, select")
        : null;
      const summary = problems.length === 1
        ? first.message
        : `${problems.length} answers or files need attention. The first one: ${first.message}`;
      throw new PortalInputError(summary, focusTarget);
    }
    if (requireComplete && Object.keys(answers).length === 0) {
      throw new PortalInputError("Answer at least one question before you send.");
    }
    return { answers, artifacts };
  }

  function renderLimitations(contract) {
    const fragment = global.document.createDocumentFragment();
    for (const limitation of contract.limitations) {
      append(fragment, "li", LIMITATION_LABELS[limitation]);
    }
    append(
      fragment,
      "li",
      "Saved answers are kept safely but are not shown again after you close this page. If you come back later, answer the questions again before you send.",
    );
    append(
      fragment,
      "li",
      "Sending your answers does not mean they have been accepted. The organisation that invited you still reviews them.",
    );
    elements.contractLimitations.replaceChildren(fragment);
  }

  function renderContract(contract, preserveLocal) {
    state.contract = contract;
    text(elements.detailRequest, contract.invitation_id);
    text(elements.detailQuestionnaire, contract.assessment_id);
    text(elements.detailCompany, contract.vendor_ref);
    text(elements.detailNotice, human(contract.notice_ref.replace(/^notice[-_.:]+/i, "")) || contract.notice_ref);
    text(elements.detailNoticeFingerprint, contract.notice_sha256);
    text(elements.detailVersion, contract.draft_revision === 0 ? "Not saved yet" : contract.draft_revision);
    const expiry = new Date(contract.expires_at * 1000);
    elements.invitationExpiry.dateTime = expiry.toISOString();
    text(elements.invitationExpiry, dateText(contract.expires_at));
    renderLimitations(contract);
    renderQuestions(contract);
    renderFiles(contract, preserveLocal);
    elements.workspace.hidden = false;
    elements.unlockPanel.hidden = true;
    elements.receiptPanel.hidden = true;
  }

  async function loadContract(preserveLocal) {
    const raw = await portalRequest("/contract", "GET");
    const contract = validateContract(raw);
    if (state.contract && state.contract.invitation_id !== contract.invitation_id) {
      fail("The request changed to a different invitation while it was open.");
    }
    renderContract(contract, preserveLocal);
    return contract;
  }

  function lockPortal(message, showReceipt) {
    for (const controller of state.activeControllers) controller.abort();
    state.activeControllers.clear();
    state.credential = null;
    state.contract = null;
    state.answerMemory.clear();
    state.files = [];
    state.fileNames.clear();
    state.pendingOperations.clear();
    state.dirty = false;
    state.lockArmed = false;
    elements.credential.value = "";
    elements.credential.type = "password";
    elements.showCredential.checked = false;
    elements.attestation.checked = false;
    showFieldError(elements.attestationSection, null);
    elements.questions.replaceChildren();
    elements.evidenceFiles.replaceChildren();
    elements.contractLimitations.replaceChildren();
    for (const detail of [
      elements.detailRequest,
      elements.detailQuestionnaire,
      elements.detailCompany,
      elements.detailNotice,
      elements.detailNoticeFingerprint,
      elements.detailVersion,
    ]) {
      text(detail, "");
    }
    elements.workspace.hidden = true;
    elements.unlockPanel.hidden = Boolean(showReceipt);
    if (!showReceipt) elements.receiptPanel.hidden = true;
    setStatus(
      message || "You have closed this request and your access code was cleared from this page. Paste the code again to reopen it.",
      "success",
    );
  }

  async function unlock(rawCredential) {
    if (!state.initialized) fail("The page has not finished opening the request.");
    if (state.busy) return false;
    const candidate = typeof rawCredential === "string" ? rawCredential.trim() : "";
    elements.credential.value = "";
    if (!TOKEN_RE.test(candidate)) {
      setStatus(
        candidate
          ? "That access code is not complete. Copy the whole code from your invitation and paste it again."
          : "Paste the access code from your invitation to open your request.",
        "error",
      );
      elements.credential.setAttribute("aria-invalid", "true");
      elements.credential.focus();
      return false;
    }
    elements.credential.removeAttribute("aria-invalid");
    state.credential = candidate;
    state.answerMemory.clear();
    state.files = [];
    state.fileNames.clear();
    state.pendingOperations.clear();
    setBusy(true);
    setStatus("Opening your request…");
    try {
      await loadContract(false);
      state.dirty = false;
      setStatus("Your request is open. Answer the questions below, then save or send.", "success");
      elements.questions.querySelector("input, select")?.focus();
      return true;
    } catch (error) {
      state.credential = null;
      state.contract = null;
      state.answerMemory.clear();
      state.files = [];
      elements.workspace.hidden = true;
      elements.unlockPanel.hidden = false;
      const message = error instanceof PortalRequestError && error.status === 404
        ? "Could not open your request. Check that you copied the whole access code. If it still does not work, it may have expired or been replaced, so ask the person who invited you for a new one."
        : errorText(error, "open your request");
      setStatus(message, "error");
      elements.credential.focus();
      return false;
    } finally {
      setBusy(false);
    }
  }

  function showInputProblem(error, action) {
    setStatus(errorText(error, action), "error");
    if (error instanceof PortalInputError && error.target) error.target.focus();
  }

  async function saveDraft() {
    if (state.busy || !state.contract) return false;
    let payload;
    try {
      payload = collectSubmission(false);
    } catch (error) {
      showInputProblem(error, "save your answers");
      return false;
    }
    setBusy(true);
    setStatus("Saving your answers…");
    try {
      const withoutKey = {
        ...payload,
        expected_revision: state.contract.draft_revision,
      };
      const body = {
        ...withoutKey,
        idempotency_key: secureOperationId("draft", withoutKey),
      };
      const rawReceipt = await portalRequest("/draft", "PUT", body);
      const receipt = validateDraftReceipt(rawReceipt);
      if (receipt.invitation_id !== state.contract.invitation_id) {
        fail("The saved draft belongs to a different request.");
      }
      state.pendingOperations.delete("draft");
      await loadContract(true);
      state.dirty = false;
      state.lockArmed = false;
      setStatus(
        "Your answers are saved. Any follow-up questions based on your answers are now shown.",
        "success",
      );
      return true;
    } catch (error) {
      if (error instanceof PortalRequestError && error.status === 409) {
        try {
          await loadContract(true);
        } catch (_refreshError) {
          lockPortal("Your request changed and could not be reloaded safely. Paste your access code to open it again.", false);
          return false;
        }
      }
      setStatus(errorText(error, "save your answers"), "error");
      return false;
    } finally {
      setBusy(false);
    }
  }

  function renderReceipt(receipt, answerCount, fileCount) {
    text(elements.receiptRevision, receipt.assessment_revision);
    text(elements.receiptAssessmentFingerprint, receipt.assessment_integrity_sha256);
    text(elements.receiptConfirmationCode, receipt.attestation_sha256);
    text(elements.receiptEvidenceStatus, "Waiting for review");
    text(
      elements.receiptSummary,
      `${answerCount} ${answerCount === 1 ? "answer" : "answers"} and ${fileCount} ${fileCount === 1 ? "file" : "files"} sent on ${(window.mvTimeAbsolute ? window.mvTimeAbsolute(Date.now()) : new Date().toLocaleString())}.`,
    );
    elements.receiptPanel.hidden = false;
  }

  async function finalizeResponse() {
    if (state.busy || !state.contract) return false;
    let payload;
    try {
      payload = collectSubmission(true);
    } catch (error) {
      showInputProblem(error, "send your answers");
      return false;
    }
    if (elements.attestation.checked !== true) {
      const message = "Tick the box to confirm your answers before you send.";
      showFieldError(elements.attestationSection, message);
      setStatus(message, "error");
      elements.attestation.focus();
      return false;
    }
    showFieldError(elements.attestationSection, null);
    setBusy(true);
    setStatus("Sending your answers…");
    try {
      const withoutKey = {
        ...payload,
        attested: true,
        expected_draft_revision: state.contract.draft_revision,
      };
      const body = {
        ...withoutKey,
        idempotency_key: secureOperationId("final", withoutKey),
      };
      const rawReceipt = await portalRequest("/finalize", "POST", body);
      const receipt = validateFinalReceipt(rawReceipt);
      if (
        receipt.invitation_id !== state.contract.invitation_id ||
        receipt.assessment_id !== state.contract.assessment_id
      ) {
        fail("The receipt for the sent answers belongs to a different request.");
      }
      state.pendingOperations.delete("final");
      renderReceipt(receipt, Object.keys(payload.answers).length, payload.artifacts.length);
      lockPortal("Your answers have been sent. Your access code was cleared from this page.", true);
      return true;
    } catch (error) {
      if (error instanceof PortalRequestError && error.status === 409) {
        try {
          await loadContract(true);
        } catch (_refreshError) {
          lockPortal("Your request changed and could not be reloaded safely. Paste your access code to open it again.", false);
          return false;
        }
      }
      setStatus(errorText(error, "send your answers"), "error");
      return false;
    } finally {
      setBusy(false);
    }
  }

  function requestLock() {
    if (state.dirty && !state.lockArmed) {
      state.lockArmed = true;
      setStatus(
        "You have answers that are not saved. Choose Save my answers first, or choose Close and sign out again to leave without saving.",
        "error",
      );
      return;
    }
    lockPortal(null, false);
  }

  function bindDocument() {
    elements = {
      status: element("portal-status"),
      unlockPanel: element("unlock-panel"),
      unlockForm: element("unlock-form"),
      credential: element("invitation-credential"),
      showCredential: element("show-credential"),
      unlockButton: element("unlock-button"),
      workspace: element("workspace"),
      lockButton: element("lock-button"),
      invitationExpiry: element("invitation-expiry"),
      questionProgress: element("question-progress"),
      responseForm: element("response-form"),
      questions: element("questions"),
      evidencePolicy: element("evidence-policy"),
      evidenceEmpty: element("evidence-empty"),
      evidenceFiles: element("evidence-files"),
      addFilesButton: element("add-files-button"),
      fileInput: element("evidence-file-input"),
      attestationSection: element("attestation-section"),
      attestation: element("respondent-attestation"),
      saveDraftButton: element("save-draft-button"),
      finalizeButton: element("finalize-button"),
      contractLimitations: element("contract-limitations"),
      detailRequest: element("detail-request"),
      detailQuestionnaire: element("detail-questionnaire"),
      detailCompany: element("detail-company"),
      detailNotice: element("detail-notice"),
      detailNoticeFingerprint: element("detail-notice-fingerprint"),
      detailVersion: element("detail-version"),
      receiptPanel: element("receipt-panel"),
      receiptSummary: element("receipt-summary"),
      receiptRevision: element("receipt-revision"),
      receiptAssessmentFingerprint: element("receipt-assessment-fingerprint"),
      receiptConfirmationCode: element("receipt-confirmation-code"),
      receiptEvidenceStatus: element("receipt-evidence-status"),
    };
    elements.unlockForm.addEventListener("submit", (event) => {
      event.preventDefault();
      const supplied = elements.credential.value;
      elements.credential.value = "";
      void unlock(supplied);
    });
    elements.showCredential.addEventListener("change", () => {
      elements.credential.type = elements.showCredential.checked ? "text" : "password";
    });
    elements.lockButton.addEventListener("click", requestLock);
    elements.addFilesButton.addEventListener("click", () => {
      if (!state.contract || state.busy) return;
      elements.fileInput.value = "";
      elements.fileInput.click();
    });
    elements.fileInput.addEventListener("change", () => void addFiles(elements.fileInput.files));
    elements.responseForm.addEventListener("submit", (event) => event.preventDefault());
    const changed = (event) => {
      if (event.target === elements.attestation) {
        if (elements.attestation.checked) showFieldError(elements.attestationSection, null);
        return;
      }
      markDirty();
      const card = event.target.closest ? event.target.closest(".portal-question") : null;
      if (card && !card.querySelector(".field-error[hidden]")) {
        try {
          const result = readQuestion(card);
          if (!result.error && !result.missing) showFieldError(card, null);
        } catch (_error) {
          // A tampered control is rejected when saving.
        }
      }
      updateProgress();
    };
    elements.responseForm.addEventListener("change", changed);
    elements.responseForm.addEventListener("input", changed);
    elements.saveDraftButton.addEventListener("click", () => void saveDraft());
    elements.finalizeButton.addEventListener("click", () => void finalizeResponse());
  }

  function initialize() {
    if (state.initialized) return;
    const pathname = global.location ? global.location.pathname : "";
    if (!PORTAL_PATH_RE.test(pathname)) return;
    const removedFragment = Boolean(global.location.hash);
    if (removedFragment) {
      global.history.replaceState(null, "", pathname);
    }
    state.apiBase = pathname.slice(0, -"/portal".length);
    bindDocument();
    state.initialized = true;
    if (removedFragment) {
      setStatus(
        "Part of the web address was removed without being read. Paste your access code below; it never belongs in a link.",
        "error",
      );
    }
  }

  const publicApi = Object.freeze({
    unlock,
    lock: () => {
      if (state.initialized) lockPortal(null, false);
    },
    addFiles,
    saveDraft,
    send: finalizeResponse,
    validateContract,
    validateEvidenceReceipt,
    validateDraftReceipt,
    validateFinalReceipt,
    fileTypeText,
    sizeText,
    questionText,
  });
  Object.defineProperty(global, "LightworkThirdPartyPortal", {
    configurable: false,
    enumerable: true,
    writable: false,
    value: publicApi,
  });

  if (global.document) {
    if (global.document.readyState === "loading") {
      global.document.addEventListener("DOMContentLoaded", initialize, { once: true });
    } else {
      initialize();
    }
  }
})(globalThis);
