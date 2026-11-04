"use strict";

(function governedDocumentVaultClient(global) {
  const MAX_JSON_BYTES = 512 * 1024;
  const ABSOLUTE_MAX_DOCUMENT_BYTES = 100 * 1024 * 1024;
  const opaquePattern = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
  const recordPattern = /^[a-z][a-z0-9_.-]{0,95}$/;
  const operationPattern = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$/;
  const tokenPattern = /^lwddt_v1_[A-Za-z0-9_-]{43}$/;

  function failure(code, message, status) {
    const error = new Error(message);
    error.code = code;
    if (Number.isInteger(status)) error.status = status;
    return error;
  }

  function bounded(value, pattern, label) {
    if (typeof value !== "string" || !pattern.test(value.trim())) {
      throw failure("field_invalid", `${label} is not valid. Check it and try again.`);
    }
    return value.trim();
  }

  function integer(value, label, minimum, maximum) {
    if (typeof value === "string" && !/^(0|[1-9][0-9]*)$/.test(value.trim())) {
      throw failure("field_invalid", `${label} is not valid. Refresh the page and try again.`);
    }
    const selected = typeof value === "string" ? Number(value.trim()) : value;
    if (!Number.isSafeInteger(selected) || selected < minimum || selected > maximum) {
      throw failure("field_invalid", `${label} is not valid. Refresh the page and try again.`);
    }
    return selected;
  }

  function jsonBody(payload) {
    const body = JSON.stringify(payload);
    if (new TextEncoder().encode(body).byteLength > 64 * 1024) {
      throw failure("request_too_large", "That request is too large. Try again with less.");
    }
    return body;
  }

  async function readBoundedJson(response) {
    const declaredRaw = response.headers.get("content-length");
    const declared = declaredRaw === null ? null : Number(declaredRaw);
    if (declared !== null && Number.isFinite(declared) && declared > MAX_JSON_BYTES) {
      if (response.body && typeof response.body.cancel === "function") await response.body.cancel();
      throw failure("response_too_large", "Lightwork returned more than this page can show. Refresh and try again.", response.status);
    }
    let text;
    if (response.body && typeof response.body.getReader === "function") {
      const reader = response.body.getReader();
      const chunks = [];
      let total = 0;
      while (true) {
        const item = await reader.read();
        if (item.done) break;
        total += item.value.byteLength;
        if (total > MAX_JSON_BYTES) {
          if (typeof reader.cancel === "function") await reader.cancel();
          throw failure("response_too_large", "Lightwork returned more than this page can show. Refresh and try again.", response.status);
        }
        chunks.push(item.value);
      }
      const merged = new Uint8Array(total);
      let offset = 0;
      for (const chunk of chunks) { merged.set(chunk, offset); offset += chunk.byteLength; }
      text = new TextDecoder("utf-8", { fatal: true }).decode(merged);
    } else {
      text = await response.text();
      if (new TextEncoder().encode(text).byteLength > MAX_JSON_BYTES) {
        throw failure("response_too_large", "Lightwork returned more than this page can show. Refresh and try again.", response.status);
      }
    }
    try { return JSON.parse(text); }
    catch (_error) { throw failure("response_invalid_json", "Lightwork returned something unexpected. Refresh the page and try again.", response.status); }
  }

  function friendly(status, headers) {
    // Headers carry the turned-off reason, so "off" is never read as "no permission".
    if (typeof global.mvErrorText === "function") return global.mvErrorText({ status, headers }, "finish this");
    if (status === 403) return "You do not have permission to do this. Ask an administrator.";
    if (status === 404) return "That document no longer exists. Refresh the page to see the latest.";
    if (status === 409) return "This document changed since you opened the page. Refresh and try again.";
    if (status === 413) return "That file is too large.";
    if (status === 415) return "That kind of file can't be stored here. Try a PDF, image or office document.";
    return "Something went wrong. Try again.";
  }

  async function parseJsonResponse(response) {
    const payload = await readBoundedJson(response);
    if (!response.ok) {
      const error = failure("request_failed", friendly(response.status, response.headers), response.status);
      error.technical = payload && typeof payload.detail === "string" ? payload.detail : "";
      throw error;
    }
    return payload;
  }

  const api = Object.freeze({
    ABSOLUTE_MAX_DOCUMENT_BYTES,
    MAX_JSON_BYTES,
    bounded,
    integer,
    jsonBody,
    parseJsonResponse,
    readBoundedJson,
  });
  global.LightworkGovernedDocumentVaultClient = api;

  if (typeof document === "undefined") return;
  const shell = document.getElementById("document-vault-shell");
  if (!shell) return;
  const vaultBase = shell.dataset.vaultApiBase || "";
  const accessBase = shell.dataset.accessApiBase || "";
  const can = {
    admin: shell.dataset.canAdmin === "true",
    operate: shell.dataset.canOperate === "true",
    audit: shell.dataset.canAudit === "true",
  };
  const operations = document.getElementById("document-vault-operations");
  const runtimeStatus = document.getElementById("document-vault-runtime-status");
  const operationStatus = document.getElementById("document-vault-operation-status");
  const operationOutput = document.getElementById("document-vault-operation-output");
  let configuredMaxBytes = ABSOLUTE_MAX_DOCUMENT_BYTES;
  let allowedTypes = [];
  let documents = [];
  let highlighted = "";
  const AREAS = {
    administration: "Administration", ai_governance: "AI governance",
    consent_preferences: "Consent and preferences", data_use_governance: "Data use governance",
    privacy_automation: "Privacy", tech_risk_compliance: "Technology risk and compliance",
    third_party_management: "Third-party management",
  };
  const EVENTS = {
    "administration.governed_document.ingested": "A document was added",
    "administration.governed_document.revoked": "Sharing was stopped for a document",
    "administration.governed_document.retention_purged": "A document was permanently deleted",
  };

  function element(id) { return document.getElementById(id); }
  function field(id) { return element(id).value.trim(); }
  function human(value) {
    if (typeof global.mvHuman === "function") return global.mvHuman(value);
    const text = String(value || "").replace(/[_.-]+/g, " ").trim();
    return text ? text.charAt(0).toUpperCase() + text.slice(1) : "";
  }
  function when(ts) {
    if (typeof global.mvWhen === "function") return global.mvWhen(ts);
    return ts ? (window.mvTimeAbsolute ? window.mvTimeAbsolute(ts) : new Date(ts * 1000).toLocaleString()) : "";
  }
  function megabytes(bytes) {
    if (!Number.isFinite(bytes)) return "";
    if (bytes < 1024 * 1024) return Math.max(1, Math.round(bytes / 1024)) + " KB";
    return (Math.round(bytes / 104857.6) / 10) + " MB";
  }
  function reference() {
    if (global.crypto && typeof global.crypto.randomUUID === "function") return "vault-" + global.crypto.randomUUID();
    return "vault-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 12);
  }
  function setStatus(target, message, failed) {
    window.mvStatus(target, message, {error: !!failed});
    target.dataset.state = failed ? "failed" : "ready";
  }
  function technical(value) {
    operationOutput.textContent = value === undefined ? "" :
      typeof value === "string" ? value : JSON.stringify(value, null, 2);
  }
  async function ask(message, okText) {
    if (typeof global.mvConfirm === "function") return global.mvConfirm(message, { okText });
    return false;
  }

  async function requestJson(base, path, options) {
    const response = await fetch(`${base}${path}`, {
      cache: "no-store",
      credentials: "same-origin",
      redirect: "error",
      referrerPolicy: "no-referrer",
      ...(options || {}),
      headers: { Accept: "application/json", ...((options && options.headers) || {}) },
    });
    return parseJsonResponse(response);
  }

  function postJson(base, path, payload) {
    return requestJson(base, path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: jsonBody(payload),
    });
  }

  async function run(label, callback) {
    setStatus(operationStatus, `${label}…`, false);
    try {
      const result = await callback();
      return result;
    } catch (error) {
      const message = error && error.code ? error.message : "Something went wrong. Try again.";
      setStatus(operationStatus, message, true);
      technical(error && error.technical ? error.technical : undefined);
      throw error;
    }
  }
  function done(message, details) {
    setStatus(operationStatus, message, false);
    technical(details);
  }

  async function refreshStatus() {
    operations.disabled = true;
    setStatus(runtimeStatus, "Checking encrypted storage…", false);
    try {
      const payload = await requestJson(vaultBase, "/status");
      const limit = payload && payload.limits && payload.limits.max_document_bytes;
      if (Number.isSafeInteger(limit) && limit > 0 && limit <= ABSOLUTE_MAX_DOCUMENT_BYTES) configuredMaxBytes = limit;
      allowedTypes = payload && payload.limits && Array.isArray(payload.limits.allowed_media_types) ? payload.limits.allowed_media_types : [];
      if (payload.enabled === true && payload.configured === true && payload.ready === true) {
        operations.disabled = false;
        setStatus(runtimeStatus, `Encrypted storage is ready. Files can be up to ${megabytes(configuredMaxBytes)}.`, false);
        return true;
      }
      if (payload.enabled !== true) {
        setStatus(runtimeStatus, "The document vault is turned off for this workspace. An administrator can turn it on above.", true);
      } else if (payload.configured !== true) {
        setStatus(runtimeStatus, "Encrypted storage isn't set up yet. Ask an administrator to finish setting up the document vault.", true);
      } else {
        setStatus(runtimeStatus, "Encrypted storage failed its safety check, so it is locked. Ask an administrator to look into it.", true);
      }
    } catch (error) {
      setStatus(runtimeStatus, error && error.code ? error.message : "Couldn't check storage. Try again.", true);
    }
    return false;
  }

  function button(label, handler, cls) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = cls || "btn";
    b.textContent = label;
    b.addEventListener("click", () => {
      if (b.disabled) return;
      b.disabled = true;
      Promise.resolve().then(handler).catch(() => {}).then(() => { b.disabled = false; });
    });
    return b;
  }
  function cell(text) { const td = document.createElement("td"); td.textContent = text; return td; }

  function renderDocuments() {
    const tbody = element("document-vault-documents");
    tbody.textContent = "";
    if (!documents.length) {
      const tr = document.createElement("tr");
      const td = cell(can.admin ? "No documents yet. Use Add a document above to upload the first one." : "No documents yet. An administrator can add them.");
      td.colSpan = 7;
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    const now = Date.now() / 1000;
    for (const record of documents) {
      const tr = document.createElement("tr");
      if (record.document_ref === highlighted) tr.dataset.highlight = "true";
      const name = document.createElement("th");
      name.scope = "row";
      name.textContent = record.safe_display_name || "Untitled document";
      tr.appendChild(name);
      tr.appendChild(cell(AREAS[record.product_area] || human(record.product_area)));
      tr.appendChild(cell(human(record.record_type)));
      tr.appendChild(cell(megabytes(record.byte_size)));
      tr.appendChild(cell(when(record.created_at)));
      const status = document.createElement("td");
      const badge = document.createElement("span");
      const active = record.state === "active";
      badge.className = "badge " + (active ? "ok" : "idle");
      badge.textContent = active ? "Shared" : "Sharing stopped";
      status.appendChild(badge);
      tr.appendChild(status);
      const actions = document.createElement("td");
      const wrap = document.createElement("div");
      wrap.className = "document-vault-actions";
      const label = record.safe_display_name || "this document";
      if (active && can.admin && can.operate) {
        const download = button("Download", () => downloadDocument(record), "btn btn--primary");
        download.setAttribute("aria-label", `Download ${label}`);
        wrap.appendChild(download);
      }
      if (active && can.admin) {
        const share = button("Share one-time code", () => shareDocument(record));
        share.setAttribute("aria-label", `Share a one-time download code for ${label}`);
        wrap.appendChild(share);
        const revoke = button("Stop sharing", () => revokeDocument(record), "btn btn--danger");
        revoke.setAttribute("aria-label", `Stop sharing ${label}`);
        wrap.appendChild(revoke);
      }
      if (!active && can.admin && Number.isFinite(record.retained_until) && record.retained_until <= now) {
        const purge = button("Delete permanently", () => purgeDocument(record), "btn btn--danger");
        purge.setAttribute("aria-label", `Delete ${label} permanently`);
        wrap.appendChild(purge);
      }
      actions.appendChild(wrap);
      tr.appendChild(actions);
      tbody.appendChild(tr);
    }
  }

  async function refreshDocuments() {
    const payload = await requestJson(vaultBase, "/documents?limit=500");
    documents = Array.isArray(payload.items) ? payload.items : [];
    renderDocuments();
    return payload;
  }

  async function mint(record, ttlSeconds) {
    return postJson(accessBase, "/tokens", {
      document_ref: bounded(record.document_ref, opaquePattern, "The document"),
      ttl_seconds: integer(ttlSeconds, "The expiry", 30, 3600),
      max_uses: 1,
      idempotency_key: reference(),
    });
  }

  async function redeemAndSave(token, fallbackName) {
    const redemption = await postJson(accessBase, "/tokens/redeem", {
      download_token: bounded(token, tokenPattern, "That download code"),
      idempotency_key: reference(),
    });
    const response = await fetch(`${vaultBase}/delivery`, {
      method: "POST",
      body: jsonBody({ delivery_grant: redemption.delivery_grant }),
      headers: { Accept: "application/octet-stream", "Content-Type": "application/json" },
      cache: "no-store",
      credentials: "same-origin",
      redirect: "error",
      referrerPolicy: "no-referrer",
    });
    if (!response.ok) await parseJsonResponse(response);
    const declared = Number(response.headers.get("content-length"));
    if (!Number.isSafeInteger(declared) || declared < 0 || declared > configuredMaxBytes) {
      if (response.body && typeof response.body.cancel === "function") await response.body.cancel();
      throw failure("response_too_large", "The download didn't arrive complete. Try again.", response.status);
    }
    const blob = await response.blob();
    if (blob.size !== declared) throw failure("response_size_changed", "The download didn't arrive complete. Try again.");
    const disposition = response.headers.get("content-disposition") || "";
    const match = /filename\*=UTF-8''([^;]+)/i.exec(disposition);
    let name = fallbackName;
    if (!name && match) { try { name = decodeURIComponent(match[1]); } catch (_error) { name = ""; } }
    const objectUrl = URL.createObjectURL(blob);
    try {
      const anchor = document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = name || "document";
      anchor.rel = "noopener noreferrer";
      anchor.hidden = true;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
    } finally {
      URL.revokeObjectURL(objectUrl);
    }
    return { name: name || "document", size: blob.size, fingerprint: response.headers.get("x-content-sha256") };
  }

  function downloadDocument(record) {
    return run("Preparing your download", async () => {
      const minted = await mint(record, 60);
      if (typeof minted.download_token !== "string") throw failure("request_failed", "The download could not be prepared. Try again.");
      const saved = await redeemAndSave(minted.download_token, record.safe_display_name);
      done(`Downloaded ${saved.name}.`, saved);
    });
  }

  async function shareDocument(record) {
    let choice = { ttl: "300" };
    if (typeof global.mvForm === "function") {
      choice = await global.mvForm("Share a one-time download code", [{
        key: "ttl", label: "The code stops working after", type: "select", default: "300",
        options: [{ value: "300", label: "5 minutes" }, { value: "900", label: "15 minutes" }, { value: "3600", label: "1 hour" }],
        help: "Send the code to the person privately. It can be used once.",
      }], { okText: "Create code" });
      if (!choice) return undefined;
    }
    return run("Creating a download code", async () => {
      const minted = await mint(record, Number(choice.ttl || 300));
      if (typeof minted.download_token !== "string") throw failure("request_failed", "The code could not be created. Try again.");
      const box = element("document-vault-share-box");
      element("document-vault-share-text").textContent =
        `One-time code for ${record.safe_display_name || "the document"}: ${minted.download_token}`;
      box.dataset.code = minted.download_token;
      box.hidden = false;
      box.open = true;
      done("Code created. Copy it and send it privately; it works once.", undefined);
    });
  }

  async function revokeDocument(record) {
    const ok = await ask(`Stop sharing ${record.safe_display_name || "this document"}? No one will be able to download it any more. This can't be undone.`, "Stop sharing");
    if (!ok) return undefined;
    return run("Stopping sharing", async () => {
      const payload = await postJson(vaultBase, `/documents/${encodeURIComponent(bounded(record.document_ref, opaquePattern, "The document"))}/revoke`, {
        expected_revision: integer(record.authority_revision, "The document version", 1, 2147483647),
      });
      await refreshDocuments();
      done(`Sharing stopped for ${record.safe_display_name || "the document"}.`, payload);
    });
  }

  async function purgeDocument(record) {
    const ok = await ask(`Delete ${record.safe_display_name || "this document"} permanently? Its contents are erased and can't be recovered; only a record that it existed is kept.`, "Delete permanently");
    if (!ok) return undefined;
    return run("Deleting the document", async () => {
      const payload = await postJson(vaultBase, `/documents/${encodeURIComponent(bounded(record.document_ref, opaquePattern, "The document"))}/retention/purge`, {
        expected_revision: integer(record.authority_revision, "The document version", 1, 2147483647),
      });
      await refreshDocuments();
      done(`${record.safe_display_name || "The document"} was deleted permanently.`, payload);
    });
  }

  element("document-vault-ingest-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run("Uploading and encrypting", async () => {
      const input = element("document-vault-file");
      const file = input.files && input.files[0];
      if (!file) throw failure("field_invalid", "Choose a document to upload.");
      if (file.size < 1) throw failure("field_invalid", "That file is empty.");
      if (file.size > configuredMaxBytes) throw failure("field_invalid", `That file is too large. The limit is ${megabytes(configuredMaxBytes)}.`);
      const mediaType = file.type || "application/octet-stream";
      if (allowedTypes.length && !allowedTypes.includes(mediaType)) throw failure("field_invalid", "That kind of file can't be stored here. Try a PDF, image or office document.");
      const params = new URLSearchParams({
        product_area: field("document-vault-product-area"),
        record_type: bounded(field("document-vault-record-type"), recordPattern, "The type of document"),
        safe_display_name: file.name,
      });
      const response = await fetch(`${vaultBase}/documents?${params.toString()}`, {
        method: "POST",
        body: file,
        headers: { Accept: "application/json", "Content-Type": mediaType },
        cache: "no-store",
        credentials: "same-origin",
        redirect: "error",
        referrerPolicy: "no-referrer",
      });
      const payload = await parseJsonResponse(response);
      input.value = "";
      highlighted = payload.document && payload.document.document_ref || "";
      await refreshDocuments();
      done(`${file.name} was uploaded and encrypted.`, payload);
    }).catch(() => {});
  });

  element("document-vault-delivery-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run("Downloading", async () => {
      const saved = await redeemAndSave(field("document-vault-download-token"), "");
      element("document-vault-download-token").value = "";
      done(`Downloaded ${saved.name}.`, saved);
    }).catch(() => {});
  });

  element("document-vault-share-copy").addEventListener("click", () => {
    const code = element("document-vault-share-box").dataset.code || "";
    if (code && typeof global.mvCopy === "function") global.mvCopy(code);
  });

  element("document-vault-refresh-status").addEventListener("click", () => {
    refreshStatus().then((ready) => ready ? refreshDocuments() : undefined).catch(() => {});
  });
  element("document-vault-refresh-documents").addEventListener("click", () =>
    run("Refreshing documents", async () => { await refreshDocuments(); done("The list is up to date."); }).catch(() => {}));
  element("document-vault-audit").addEventListener("click", () => run("Loading history", async () => {
    const payload = await requestJson(vaultBase, "/audit/events?limit=100");
    const rows = element("document-vault-history-rows");
    rows.textContent = "";
    const items = Array.isArray(payload.items) ? payload.items : [];
    for (const item of items) {
      const tr = document.createElement("tr");
      tr.appendChild(cell(when(item.occurred_at)));
      tr.appendChild(cell(EVENTS[item.event_type] || human(String(item.event_type || "").split(".").pop())));
      rows.appendChild(tr);
    }
    if (!items.length) {
      const tr = document.createElement("tr");
      const td = cell("Nothing has happened in the vault yet. Add a document above to start its history.");
      td.colSpan = 2;
      tr.appendChild(td);
      rows.appendChild(tr);
    }
    element("document-vault-history").hidden = false;
    done(`Showing the last ${items.length} ${items.length === 1 ? "event" : "events"}.`, payload);
  }).catch(() => {}));
  element("document-vault-integrity").addEventListener("click", () => run("Checking every file", async () => {
    const payload = await requestJson(vaultBase, "/integrity");
    if (payload.ok !== true) throw failure("integrity_failed", "Some files could not be confirmed as unaltered. Ask an administrator to look into it.");
    done(`All ${payload.documents} ${payload.documents === 1 ? "document is" : "documents are"} intact and unaltered.`, payload);
  }).catch(() => {}));
  const reconcile = element("document-vault-reconcile");
  if (reconcile) {
    reconcile.addEventListener("click", () => run("Tidying up unfinished downloads", async () => {
      const payload = await postJson(vaultBase, "/maintenance/reconcile?limit=500", {});
      done("Unfinished downloads were tidied up.", payload);
    }).catch(() => {}));
  }

  refreshStatus().then(async (ready) => {
    if (!ready) {
      element("document-vault-documents").textContent = "";
      return;
    }
    await refreshDocuments();
    const requested = new URLSearchParams(window.location.search).get("document");
    if (!requested) return;
    await run("Finding the linked document", async () => {
      const ref = bounded(requested, /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/, "The link");
      const record = await requestJson(vaultBase, "/documents/" + encodeURIComponent(ref));
      if (!record || record.document_ref !== ref) throw failure("request_failed", "The linked document could not be found. Refresh the page to see the latest.");
      highlighted = ref;
      if (!documents.some((item) => item.document_ref === ref)) documents.unshift(record);
      renderDocuments();
      done(`Showing ${record.safe_display_name || "the linked document"} (highlighted in the list).`, undefined);
    });
  }).catch(() => {});
})(typeof globalThis === "undefined" ? this : globalThis);
