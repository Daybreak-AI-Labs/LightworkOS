// Run with: node --test packages/maverick-dashboard/tests/js/third_party_collaboration_portal.test.js
//
// The supplier questionnaire page: the real page markup (read from the Python
// module that serves it) plus the real script, in jsdom. Suppliers must never
// see or type sizes, types or fingerprints, and every message is plain.
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { JSDOM } = require("jsdom");

const folder = path.resolve(__dirname, "../../maverick_dashboard");
const source = fs.readFileSync(path.join(folder, "static/lightwork-third-party-portal.js"), "utf8");
const pageModule = fs.readFileSync(path.join(folder, "third_party_collaboration_portal.py"), "utf8");
const markup = /_PAGE = """([\s\S]*?)"""/.exec(pageModule)[1]
  .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "");
const TOKEN = `tpc1.${"A".repeat(43)}`;
const PORTAL_REF = "portal_ref_1234567890";
const API = `/api/v1/external/third-party-collaboration/${PORTAL_REF}`;
const PORTAL_URL = `https://supplier.example${API}/portal`;
const BANNED = /\b(mime|digest|manifest|bytes?|sha-?256|schema|payload|json|boolean|idempotency)\b/i;
const SHA = "c".repeat(64);
const ARTIFACT_ID = `evidence-${"0f".repeat(16)}`;
const SAVED_ARTIFACT_ID = `evidence-${"fe".repeat(16)}`;

function validContract(extra = {}) {
  return {
    schema: "lightwork.third-party-collaboration-contract.v1",
    invitation_id: "invite-1",
    vendor_ref: "respondent-1",
    assessment_id: "assessment-1",
    notice_ref: "notice.Vendor-privacy-notice",
    notice_sha256: "a".repeat(64),
    artifact_policy: {
      allowed_kinds: ["audit_report", "certification"],
      maximum_artifacts: 2,
      maximum_total_bytes: 10000,
    },
    questions: [
      {
        question_id: "encryption-at-rest",
        domain: "security",
        prompt_ref: "Do-you-encrypt-data-at-rest",
        response_type: "boolean",
        required: true,
        options: [],
      },
    ],
    required_question_ids: ["encryption-at-rest"],
    answered_question_ids: [],
    draft_revision: 0,
    draft_artifacts: [],
    expires_at: 2000086400,
    limitations: [
      "respondent_attestations_are_unverified",
      "artifact_manifests_only_no_upload_bytes",
      "no_network_or_email_delivery",
      "no_model_inference",
    ],
    ...extra,
  };
}

function allTypesContract() {
  return validContract({
    questions: [
      { question_id: "q-encrypt", domain: "security", prompt_ref: "Do-you-encrypt-data-at-rest", response_type: "boolean", required: true, options: [] },
      { question_id: "q-hosting", domain: "operational", prompt_ref: "prompt.hosting_model", response_type: "single_choice", required: false, options: ["own_data_centre", "public_cloud"] },
      { question_id: "q-region", domain: "privacy", prompt_ref: "Where-is-data-stored", response_type: "single_choice", required: false, options: ["eu", "us", "uk", "ca", "au", "jp", "sg"] },
      { question_id: "q-certs", domain: "compliance", prompt_ref: "Which-certifications-do-you-hold", response_type: "multi_choice", required: false, options: ["iso_27001", "soc2"] },
      { question_id: "q-staff", domain: "ai", prompt_ref: "How-many-staff-can-access-customer-data", response_type: "integer", required: false, options: [] },
      { question_id: "q-policy", domain: "security", prompt_ref: "Security-policy-number", response_type: "text_ref", required: false, options: [] },
    ],
    required_question_ids: ["q-encrypt"],
  });
}

function evidenceReceipt(file, extra = {}) {
  return {
    invitation_id: "invite-1",
    artifact_id: ARTIFACT_ID,
    content_sha256: SHA,
    size_bytes: file.size,
    media_type_ref: "application.pdf",
    idempotent_replay: false,
    ...extra,
  };
}

function draftReceipt() {
  return {
    invitation_id: "invite-1",
    revision: 1,
    draft_sha256: "b".repeat(64),
    active_question_ids: ["encryption-at-rest"],
    required_question_ids: ["encryption-at-rest"],
    artifact_count: 0,
    idempotent_replay: false,
  };
}

function finalReceipt() {
  return {
    schema: "lightwork.third-party-collaboration-receipt.v1",
    invitation_id: "invite-1",
    assessment_id: "assessment-1",
    assessment_revision: 2,
    assessment_integrity_sha256: "e".repeat(64),
    question_ids: ["encryption-at-rest"],
    attestation_sha256: "d".repeat(64),
    evidence_status: "respondent_attestation_unverified",
    idempotent_replay: false,
  };
}

async function portalPage({ contract = validContract(), url = PORTAL_URL, reply } = {}) {
  const dom = new JSDOM(markup, { url, runScripts: "outside-only" });
  const { window } = dom;
  const calls = [];
  let currentContract = contract;
  window.fetch = async (target, options = {}) => {
    const call = { url: String(target), method: options.method || "GET", options, body: options.body };
    calls.push(call);
    let answer = reply ? await reply(call) : undefined;
    if (answer === undefined) {
      if (call.url.endsWith("/contract")) answer = currentContract;
      else if (call.url.endsWith("/evidence")) answer = evidenceReceipt(call.body);
      else if (call.url.endsWith("/draft")) answer = draftReceipt();
      else if (call.url.endsWith("/finalize")) answer = finalReceipt();
    }
    const status = answer && answer.__status ? answer.__status : 200;
    return new Response(status === 200 ? JSON.stringify(answer) : JSON.stringify({ detail: "raw server words" }), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  };
  window.eval(source);
  const el = (id) => window.document.getElementById(id);
  async function settle() {
    for (let i = 0; i < 30; i += 1) await new Promise((resolve) => setImmediate(resolve));
  }
  function choose(files) {
    const input = el("evidence-file-input");
    Object.defineProperty(input, "files", { value: files, configurable: true });
    input.dispatchEvent(new window.Event("change", { bubbles: true }));
  }
  function bodyText() {
    return window.document.body.textContent.replace(/\s+/g, " ");
  }
  return {
    window,
    document: window.document,
    el,
    calls,
    settle,
    choose,
    bodyText,
    portal: window.LightworkThirdPartyPortal,
    setContract(value) { currentContract = value; },
  };
}

async function openPage(options) {
  const page = await portalPage(options);
  page.el("invitation-credential").value = `  ${TOKEN}\n`;
  page.el("unlock-form").dispatchEvent(new page.window.Event("submit", { cancelable: true }));
  await page.settle();
  return page;
}

function parserContext() {
  const context = {};
  vm.createContext(context);
  vm.runInContext(source, context, { filename: "lightwork-third-party-portal.js" });
  return context;
}

test("contract parser accepts only the exact server-owned surface", () => {
  const { LightworkThirdPartyPortal: portal } = parserContext();
  const normalized = portal.validateContract(validContract());
  assert.equal(normalized.schema, "lightwork.third-party-collaboration-contract.v1");
  assert.deepEqual(Array.from(normalized.required_question_ids), ["encryption-at-rest"]);
  assert.throws(() => portal.validateContract({ ...validContract(), tenant_id: "tenant-a" }), /fields this page does not expect/);
  assert.throws(() => portal.validateContract({ ...validContract(), provider_id: "provider-a" }), /fields this page does not expect/);
  assert.throws(() => portal.validateContract({ ...validContract(), risk_score: 99 }), /fields this page does not expect/);
  assert.throws(() => portal.validateContract({ ...validContract(), limitations: [] }), /limitations/);
});

test("contract parser enforces question visibility and file bounds", () => {
  const { LightworkThirdPartyPortal: portal } = parserContext();
  assert.throws(
    () => portal.validateContract({ ...validContract(), answered_question_ids: ["server-hidden-question"] }),
    /questions that are not on this page/,
  );
  assert.throws(
    () => portal.validateContract({
      ...validContract(),
      questions: [{ ...validContract().questions[0], response_type: "free_text" }],
    }),
    /kind of answer this page does not support/,
  );
  assert.throws(
    () => portal.validateContract({
      ...validContract(),
      draft_artifacts: [{
        artifact_id: "report-1",
        kind: "audit_report",
        content_sha256: "not-a-fingerprint",
        size_bytes: 100,
        media_type_ref: "application.pdf",
      }],
    }),
    /digest/,
  );
  assert.throws(
    () => portal.validateContract({
      ...validContract(),
      artifact_policy: { allowed_kinds: [], maximum_artifacts: 1, maximum_total_bytes: 100 },
    }),
    /inconsistent/,
  );
});

test("receipt parsers reject added scoring and identity claims", () => {
  const { LightworkThirdPartyPortal: portal } = parserContext();
  assert.equal(portal.validateDraftReceipt(draftReceipt()).revision, 1);
  assert.throws(() => portal.validateDraftReceipt({ ...draftReceipt(), score: 100 }), /fields this page does not expect/);
  assert.equal(portal.validateFinalReceipt(finalReceipt()).evidence_status, "respondent_attestation_unverified");
  assert.throws(() => portal.validateFinalReceipt({ ...finalReceipt(), verified_identity: true }), /fields this page does not expect/);
  const policy = { maximum_total_bytes: 100 };
  const file = { size: 20 };
  assert.equal(portal.validateEvidenceReceipt(evidenceReceipt(file), policy).size_bytes, 20);
  assert.throws(() => portal.validateEvidenceReceipt({ ...evidenceReceipt(file), tenant_id: "t" }, policy), /fields this page does not expect/);
  assert.throws(() => portal.validateEvidenceReceipt(evidenceReceipt({ size: 101 }), policy), /outside the allowed range/);
});

test("file sizes and types read as words, never raw units or type codes", () => {
  const { LightworkThirdPartyPortal: portal } = parserContext();
  assert.equal(portal.sizeText(512), "Less than 1 KB");
  assert.equal(portal.sizeText(2048), "2 KB");
  assert.equal(portal.sizeText(10 * 1024 * 1024), "10 MB");
  assert.equal(portal.sizeText(2.5 * 1024 * 1024), "2.5 MB");
  assert.equal(portal.fileTypeText("application.pdf"), "PDF document");
  assert.equal(
    portal.fileTypeText("application.vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    "Spreadsheet",
  );
  assert.equal(portal.fileTypeText("application.octet-stream"), "Other file");
  assert.equal(portal.questionText("Do-you-encrypt-data"), "Do you encrypt data?");
  assert.equal(portal.questionText("prompt.mfa_enforced"), "MFA enforced");
});

test("the access code is trimmed, kept in memory and sent only in Authorization", async () => {
  const page = await openPage();
  assert.equal(page.el("invitation-credential").value, "");
  assert.equal(page.calls.length, 1);
  const [call] = page.calls;
  assert.equal(new URL(call.url, PORTAL_URL).pathname, `${API}/contract`);
  assert.equal(call.options.headers.Authorization, `ThirdPartyInvitation ${TOKEN}`);
  assert.equal(call.options.credentials, "omit");
  assert.equal(call.options.cache, "no-store");
  assert.equal(call.options.redirect, "error");
  assert.equal(call.options.referrerPolicy, "no-referrer");
  assert.equal(call.url.includes(TOKEN), false);
  assert.equal(JSON.stringify(call.options).includes("tenant"), false);
  assert.equal(page.el("workspace").hidden, false);
  assert.equal(page.el("unlock-panel").hidden, true);
});

test("a wrong or partial access code gets a plain next step", async () => {
  const page = await portalPage({ reply: (call) => (call.url.endsWith("/contract") ? { __status: 404 } : undefined) });
  assert.equal(await page.portal.unlock("tpc1.short"), false);
  assert.match(page.el("portal-status").textContent, /not complete\. Copy the whole code/);
  assert.equal(page.calls.length, 0);
  assert.equal(await page.portal.unlock(TOKEN), false);
  const status = page.el("portal-status").textContent;
  assert.match(status, /Could not open your request\. Check that you copied the whole access code/);
  assert.doesNotMatch(status, /404|raw server words|invitation authority/);
  assert.equal(page.el("workspace").hidden, true);
});

test("every question type gets a real control and a clear required marker", async () => {
  const page = await openPage({ contract: allTypesContract() });
  const cards = [...page.document.querySelectorAll(".portal-question")];
  assert.equal(cards.length, 6);
  const legend = (card) => card.querySelector(".question-text").textContent;
  assert.equal(legend(cards[0]), "Do you encrypt data at rest?");
  assert.equal(cards[0].querySelector(".required-mark").textContent, "Required");
  assert.equal(cards[1].querySelector(".optional-mark").textContent, "Optional");
  assert.deepEqual(
    [...cards[0].querySelectorAll('input[type="radio"]')].map((input) => input.parentElement.textContent),
    ["Yes", "No"],
  );
  assert.deepEqual(
    [...cards[1].querySelectorAll("label span")].map((span) => span.textContent),
    ["Own data centre", "Public cloud"],
  );
  const select = cards[2].querySelector("select");
  assert.ok(select, "long choice lists use a dropdown");
  assert.equal(page.document.querySelector(`label[for="${select.id}"]`).textContent, "Your answer");
  assert.ok([...select.options].some((option) => option.textContent === "EU"));
  assert.equal(cards[3].querySelectorAll('input[type="checkbox"]').length, 2);
  assert.match(cards[3].textContent, /Choose all that apply\./);
  assert.equal(cards[4].querySelector("input").type, "number");
  assert.equal(cards[5].querySelector("input").type, "text");
  assert.match(cards[4].textContent, /Topic: AI/);
  assert.equal(page.el("question-progress").textContent, "0 of 6 questions answered · 1 required question left");
  for (const control of page.document.querySelectorAll("#questions input, #questions select")) {
    const labelled = control.closest("label") || page.document.querySelector(`label[for="${control.id}"]`);
    assert.ok(labelled, `control ${control.id} has a label`);
  }
  assert.doesNotMatch(page.bodyText(), BANNED);
  assert.doesNotMatch(page.bodyText(), /q-encrypt|own_data_centre|iso_27001|prompt\./);
});

test("choosing a file sends its bytes for the server to check and shows name, size and type only", async () => {
  const page = await openPage();
  const file = new page.window.File(["%PDF-1.7 certificate body"], "SOC2 report.PDF", { type: "application/pdf" });
  page.choose([file]);
  await page.settle();
  const upload = page.calls.find((call) => call.url.endsWith("/evidence"));
  assert.ok(upload, "the file was sent to be checked");
  assert.equal(upload.method, "POST");
  assert.equal(upload.body, file, "the file itself is sent; nothing is typed or computed by the supplier");
  assert.equal(upload.options.headers["Content-Type"], "application/octet-stream");
  assert.equal(upload.options.headers["X-Evidence-File-Extension"], "pdf");
  assert.equal(upload.options.headers.Authorization, `ThirdPartyInvitation ${TOKEN}`);
  const row = page.document.querySelector(".portal-file");
  assert.equal(row.querySelector(".file-name").textContent, "SOC2 report.PDF");
  assert.equal(row.querySelector(".file-facts").textContent, "PDF document · Less than 1 KB");
  assert.equal(page.document.querySelectorAll("#evidence-files input[type=text], #evidence-files input[type=number]").length, 0);
  assert.doesNotMatch(page.bodyText(), new RegExp(SHA));
  assert.doesNotMatch(page.bodyText(), BANNED);
  assert.match(page.el("portal-status").textContent, /“SOC2 report\.PDF” was checked and added\./);
  assert.match(page.el("evidence-policy").textContent, /up to 2 files, up to 9\.8 KB in total\. Accepted: audit reports and certificates\. You have added 1/);
  assert.equal(page.el("evidence-empty").hidden, true);
});

test("saving sends the server's own measurements with plain file and answer checks first", async () => {
  const page = await openPage();
  const file = new page.window.File(["%PDF-1.7 certificate body"], "iso-cert.pdf");
  page.choose([file]);
  await page.settle();
  const row = page.document.querySelector(".portal-file");
  page.el("save-draft-button").click();
  await page.settle();
  assert.equal(page.calls.filter((call) => call.url.endsWith("/draft")).length, 0);
  assert.equal(row.querySelector(".field-error").textContent, "Choose what kind of document “iso-cert.pdf” is.");
  assert.equal(row.querySelector("select").getAttribute("aria-invalid"), "true");
  row.querySelector("select").value = "certification";
  const support = row.querySelector('input[data-file-field="support"]');
  support.checked = true;
  page.el("save-draft-button").click();
  await page.settle();
  assert.match(row.querySelector(".field-error").textContent, /“Do you encrypt data at rest\?”, which has no answer yet/);
  page.document.querySelector('.portal-question input[value="true"]').checked = true;
  page.el("save-draft-button").click();
  await page.settle();
  const draft = page.calls.find((call) => call.url.endsWith("/draft"));
  assert.ok(draft, "the draft was saved once everything was fixed");
  const body = JSON.parse(draft.body);
  assert.deepEqual(body.artifacts, [{
    artifact_id: ARTIFACT_ID,
    kind: "certification",
    content_sha256: SHA,
    size_bytes: file.size,
    media_type_ref: "application.pdf",
  }]);
  assert.deepEqual(body.answers, {
    "encryption-at-rest": { value: true, artifact_ids: [ARTIFACT_ID] },
  });
  assert.equal(body.expected_revision, 0);
  assert.match(body.idempotency_key, /^portal-draft-/);
  assert.match(page.el("portal-status").textContent, /Your answers are saved\./);
  assert.equal(page.document.querySelector(".portal-file .file-name").textContent, "iso-cert.pdf");
  assert.equal(page.document.querySelector(".portal-file select").value, "certification");
});

test("files the page can already rule out never leave the browser", async () => {
  const page = await openPage();
  const empty = new page.window.File([], "blank.pdf");
  page.choose([empty]);
  await page.settle();
  assert.equal(page.el("portal-status").textContent, "“blank.pdf” is empty, so it cannot be added.");
  const huge = new page.window.File(["x".repeat(10001)], "scan.tiff");
  page.choose([huge]);
  await page.settle();
  assert.match(page.el("portal-status").textContent, /“scan\.tiff” is too big\. Files for this request can add up to 9\.8 KB in total\./);
  page.choose([
    new page.window.File(["%PDF one"], "one.pdf"),
    new page.window.File(["%PDF two"], "two.pdf"),
    new page.window.File(["%PDF three"], "three.pdf"),
  ]);
  await page.settle();
  // The fake server gives every file the same record, so the second is a repeat.
  const status = page.el("portal-status").textContent;
  assert.match(status, /“one\.pdf” was checked and added\. “two\.pdf” is already in your list\./);
  assert.equal(page.calls.filter((call) => call.url.endsWith("/evidence")).length, 3);
  assert.doesNotMatch(status, BANNED);
});

test("the file limit and server refusals read as plain sentences", async () => {
  let count = 0;
  const page = await openPage({
    reply: (call) => {
      if (!call.url.endsWith("/evidence")) return undefined;
      count += 1;
      if (count === 3) return { __status: 413 };
      return evidenceReceipt(call.body, { artifact_id: `evidence-${String(count).repeat(32)}` });
    },
  });
  page.choose([new page.window.File(["%PDF a"], "a.pdf"), new page.window.File(["%PDF b"], "b.pdf")]);
  await page.settle();
  assert.equal(page.document.querySelectorAll(".portal-file").length, 2);
  page.choose([new page.window.File(["%PDF c"], "c.pdf")]);
  await page.settle();
  assert.match(page.el("portal-status").textContent, /You've reached the file limit for this request \(2 files\)\./);
  page.document.querySelector(".portal-file .remove-file").click();
  page.choose([new page.window.File(["%PDF d"], "d.pdf")]);
  await page.settle();
  assert.equal(page.el("portal-status").textContent, "“d.pdf” is too big for this request.");
  assert.doesNotMatch(page.el("portal-status").textContent, /413|raw server words/);
});

test("sending checks required answers and the confirmation, then shows a plain receipt", async () => {
  const page = await openPage();
  page.el("finalize-button").click();
  await page.settle();
  assert.equal(page.calls.filter((call) => call.url.endsWith("/finalize")).length, 0);
  const card = page.document.querySelector(".portal-question");
  assert.equal(card.querySelector(".field-error").textContent, "Choose Yes or No.");
  assert.equal(page.el("portal-status").textContent, "Choose Yes or No.");
  card.querySelector('input[value="false"]').checked = true;
  card.querySelector('input[value="false"]').dispatchEvent(new page.window.Event("change", { bubbles: true }));
  assert.equal(card.querySelector(".field-error").hidden, true);
  page.el("finalize-button").click();
  await page.settle();
  assert.equal(page.el("portal-status").textContent, "Tick the box to confirm your answers before you send.");
  assert.equal(page.el("attestation-error").hidden, false);
  page.el("respondent-attestation").checked = true;
  page.el("finalize-button").click();
  await page.settle();
  const final = page.calls.find((call) => call.url.endsWith("/finalize"));
  const body = JSON.parse(final.body);
  assert.equal(body.attested, true);
  assert.equal(body.expected_draft_revision, 0);
  assert.deepEqual(body.answers, { "encryption-at-rest": { value: false, artifact_ids: [] } });
  assert.equal(page.el("receipt-panel").hidden, false);
  assert.equal(page.el("workspace").hidden, true);
  assert.match(page.el("receipt-summary").textContent, /^1 answer and 0 files sent on /);
  assert.equal(page.el("receipt-evidence-status").textContent, "Waiting for review");
  assert.equal(page.el("receipt-confirmation-code").closest("details").open, false);
  assert.match(page.el("portal-status").textContent, /Your answers have been sent\./);
  assert.doesNotMatch(page.bodyText(), BANNED);
  assert.equal(await page.portal.saveDraft(), false, "nothing more can be sent without the code");
});

test("server problems while saving never show codes or server wording", async () => {
  const page = await openPage({ reply: (call) => (call.url.endsWith("/draft") ? { __status: 422 } : undefined) });
  page.document.querySelector('.portal-question input[value="true"]').checked = true;
  page.el("save-draft-button").click();
  await page.settle();
  const status = page.el("portal-status").textContent;
  assert.equal(status, "Could not save your answers. Some answers or files need fixing. Check what you entered and try again.");
  assert.equal(page.el("portal-status").dataset.state, "error");
});

test("closing with unsaved answers asks for a second click, then clears everything", async () => {
  const page = await openPage();
  const yes = page.document.querySelector('.portal-question input[value="true"]');
  yes.checked = true;
  yes.dispatchEvent(new page.window.Event("change", { bubbles: true }));
  page.el("lock-button").click();
  assert.match(page.el("portal-status").textContent, /answers that are not saved/);
  assert.equal(page.el("workspace").hidden, false);
  page.el("lock-button").click();
  assert.equal(page.el("workspace").hidden, true);
  assert.equal(page.el("unlock-panel").hidden, false);
  assert.equal(page.document.querySelectorAll(".portal-question").length, 0);
  assert.equal(page.el("detail-request").textContent, "");
  assert.match(page.el("portal-status").textContent, /access code was cleared/);
});

test("saved files come back after reopening, with safeguards and technical details kept out of the way", async () => {
  const contract = validContract({
    answered_question_ids: ["encryption-at-rest"],
    draft_revision: 3,
    draft_artifacts: [{
      artifact_id: SAVED_ARTIFACT_ID,
      kind: "audit_report",
      content_sha256: SHA,
      size_bytes: 4 * 1024,
      media_type_ref: "application.vnd.openxmlformats-officedocument.wordprocessingml.document",
    }],
  });
  const page = await openPage({ contract });
  const row = page.document.querySelector(".portal-file");
  assert.equal(row.querySelector(".file-name").textContent, "File added earlier");
  assert.equal(row.querySelector(".file-facts").textContent, "Word document · 4 KB");
  assert.equal(row.querySelector("select").value, "audit_report");
  assert.match(page.bodyText(), /saved answers are not shown again/);
  const technical = page.el("detail-request").closest("details");
  assert.equal(technical.open, false);
  assert.equal(technical.querySelector("summary").textContent, "Technical details");
  assert.equal(page.el("detail-version").textContent, "3");
  assert.equal(page.el("detail-notice").textContent, "Vendor privacy notice");
  const safeguards = page.el("contract-limitations").closest("details");
  assert.equal(safeguards.querySelector("summary").textContent, "About this page's safeguards");
  assert.match(page.el("contract-limitations").textContent, /not the file itself, so keep your own copy/);
  assert.doesNotMatch(page.bodyText(), BANNED);
});

test("a web address with a fragment is cleaned without reading it", async () => {
  const page = await portalPage({ url: `${PORTAL_URL}#${TOKEN}` });
  assert.equal(page.window.location.hash, "");
  assert.match(page.el("portal-status").textContent, /removed without being read/);
});
