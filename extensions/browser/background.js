// All network requests remain in the extension worker and on loopback.
const DEFAULTS = { base: "http://127.0.0.1:8765", token: "" };
const session = chrome.storage.session || chrome.storage.local;
let starting = false;
const reads = new Map();

class ClientError extends Error {
  constructor(message, kind, status) { super(message); this.kind = kind; this.status = status; }
}

async function responseText(response, body) {
  const limit = 4 * 1024 * 1024;
  let raw = "", size = 0;
  const overflow = () => new ClientError("Dashboard response exceeds the client limit.", body ? "unknown" : "protocol");
  if (response.body && response.body.getReader) {
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    try {
      while (true) {
        const part = await reader.read();
        if (part.done) break;
        size += part.value.byteLength;
        if (size > limit) { await reader.cancel(); throw overflow(); }
        raw += decoder.decode(part.value, { stream: true });
      }
      return raw + decoder.decode();
    } finally { reader.releaseLock(); }
  }
  raw = await response.text();
  if (raw.length > limit) throw overflow();
  return raw;
}

async function settings() {
  const value = Object.assign({}, DEFAULTS, await chrome.storage.local.get(DEFAULTS));
  value.base = String(value.base).replace(/\/+$/, "");
  if (!/^http:\/\/127\.0\.0\.1(:\d+)?$/.test(value.base)) {
    throw new ClientError("Dashboard URL must be http://127.0.0.1[:port].", "configuration");
  }
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value.base + "\0" + value.token));
  value.scope = Array.from(new Uint8Array(digest), x => x.toString(16).padStart(2, "0")).join("");
  return value;
}

async function request(s, path, body, requestId, idempotencyKey) {
  const controller = new AbortController();
  if (!body && requestId) reads.set(requestId, controller);
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new ClientError(body ? "Start not confirmed. Check the dashboard before retrying." : "Dashboard request timed out.",
        body ? "unknown" : "transient"));
    }, 15000);
  });
  try {
    return await Promise.race([timeout, (async () => {
      const headers = { Accept: "application/json" };
      if (s.token) headers.Authorization = "Bearer " + s.token;
      if (body) headers["Content-Type"] = "application/json";
      if (idempotencyKey) headers["Idempotency-Key"] = idempotencyKey;
      const response = await fetch(s.base + path, { method: body ? "POST" : "GET", headers,
        body: body ? JSON.stringify(body) : undefined, signal: controller.signal, redirect: "error", cache: "no-store" });
      if (!response.ok) throw new ClientError("Dashboard replied HTTP " + response.status,
        response.status === 401 || response.status === 403 ? "access" :
          (body ? (response.status >= 500 || response.status === 408 ? "unknown" : "refused") :
            (response.status >= 500 || response.status === 408 || response.status === 429 ? "transient" : "refused")), response.status);
      const raw = await responseText(response, body);
      try { return JSON.parse(raw); }
      catch (_) { throw new ClientError("Dashboard returned an unreadable acknowledgement.", body ? "unknown" : "protocol"); }
    })()]);
  } catch (error) {
    if (error instanceof ClientError) throw error;
    throw new ClientError(body ? "Start not confirmed. Check the dashboard before retrying." : "Dashboard connection failed.",
      body ? "unknown" : "transient");
  } finally {
    clearTimeout(timer);
    if (requestId && reads.get(requestId) === controller) reads.delete(requestId);
  }
}

function pendingKey(s) { return "pendingGoal:" + s.scope; }

async function pendingFor(s) {
  return (await chrome.storage.local.get(pendingKey(s)))[pendingKey(s)] || null;
}

async function rememberAccepted(s, pending, goal) {
  if (!Number.isSafeInteger(goal?.id) || goal.id <= 0 || typeof goal.status !== "string") {
    throw new ClientError("Start response has no confirmed goal id. Use Check start status.", "unknown");
  }
  if ((await settings()).scope !== s.scope) {
    throw new ClientError("Connection changed while accepting the goal. The original key is retained for reconciliation.", "unknown");
  }
  // Persist acceptance before clearing the durable unresolved identity. A
  // crash between these writes can only repeat a read reconciliation.
  await session.set({ activeWatch: { scope: s.scope, goalId: goal.id,
    cursor: 0, events: [], complete: false, hasMore: false, result: "", status: goal.status, title: pending.title } });
  const current = await pendingFor(s);
  if (current?.key === pending.key) await chrome.storage.local.set({ [pendingKey(s)]: null });
  return goal;
}

async function reconcile(s) {
  if (starting) throw new ClientError("A start or reconciliation request is already pending.", "pending");
  starting = true;
  try {
    const pending = await pendingFor(s);
    if (!pending) return null;
    if (!pending.key) throw new ClientError("Legacy unconfirmed start requires dashboard review.", "unknown");
    const data = await request(s, "/api/v1/goal-submissions/receipt?kind=api", undefined, undefined, pending.key);
    if (data.state === "not_dispatched") {
      if (!pending.body) throw new ClientError("The original draft was not retained by this version. Review it in the dashboard.", "unknown");
      await checkCapturePolicy(s, pending.capturePolicy);
      if ((await settings()).scope !== s.scope) throw new ClientError("Connection changed. Reopen the popup before recovery.", "context");
      const goal = await request(s, "/api/v1/goals", pending.body, undefined, pending.key);
      return await rememberAccepted(s, pending, goal);
    }
    if (data.state !== "accepted") throw new ClientError("Start receipt is not confirmed.", "unknown");
    return await rememberAccepted(s, pending, data.goal);
  } finally { starting = false; }
}

async function checkCapturePolicy(s, capturePolicy) {
  if (!capturePolicy) return;
  const policy = await request(s, "/api/v1/extension/policy");
  if (policy.revision !== capturePolicy.revision ||
      (capturePolicy.form_values && !policy.form_values) ||
      (capturePolicy.page_structure && !policy.page_structure)) {
    throw new ClientError("Page sharing policy changed. Review the page again before sending.", "refused");
  }
}

async function startGoal(s, msg) {
  if (starting) throw new ClientError("A start request is already pending.", "pending");
  starting = true;
  try {
    if (await pendingFor(s)) {
      throw new ClientError("A previous start is unconfirmed. Check start status before starting again.", "unknown");
    }
    const retained = await chrome.storage.local.get(null);
    if (Object.entries(retained).filter(([key, value]) => key.startsWith("pendingGoal:") && value).length >= 8) {
      throw new ClientError("Eight connection scopes have unresolved starts. Reconcile one before starting more work.", "pending");
    }
    await checkCapturePolicy(s, msg.capturePolicy);
    const title = String(msg.title || "").slice(0, 200);
    const pending = { scope: s.scope, title, state: "pending", key: crypto.randomUUID(),
      body: { title, description: String(msg.description || "") }, capturePolicy: msg.capturePolicy };
    await chrome.storage.local.set({ [pendingKey(s)]: pending });
    try {
      const goal = await request(s, "/api/v1/goals", pending.body, undefined, pending.key);
      return await rememberAccepted(s, pending, goal);
    } catch (error) {
      // A conflict can mean a durable draft/legacy receipt already exists.
      const keep = !error.kind || ["unknown", "pending"].includes(error.kind) || error.status === 409;
      await chrome.storage.local.set({ [pendingKey(s)]: keep ? { ...pending, state: "unknown" } : null });
      if (keep) error.kind = "unknown";
      throw error;
    }
  } finally { starting = false; }
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      if (msg.type === "cancel") {
        reads.get(msg.requestId)?.abort();
        sendResponse({ ok: true });
        return;
      }
      const s = await settings();
      if (msg.scope && msg.scope !== s.scope) throw new ClientError("Dashboard connection changed. Reopen the popup.", "context");
      if (msg.type === "identity") {
        // Migration of a previously held session must not discard its unknown
        // outcome. Such entries lack a key and remain manual-review only.
        const legacy = (await session.get("pendingGoal")).pendingGoal;
        if (legacy?.scope === s.scope && !(await pendingFor(s))) {
          await chrome.storage.local.set({ [pendingKey(s)]: legacy });
          await session.set({ pendingGoal: null });
        }
        sendResponse({ ok: true, scope: s.scope, pending: await pendingFor(s) });
      } else if (msg.type === "capturePolicy") {
        sendResponse({ok:true, scope:s.scope, data:await request(s,"/api/v1/extension/policy")});
      } else if (msg.type === "chat") {
        sendResponse({ ok: true, scope: s.scope, goal: await startGoal(s, msg) });
      } else if (msg.type === "reconcile") {
        sendResponse({ ok: true, scope: s.scope, goal: await reconcile(s) });
      } else if (msg.type === "clearPending" && msg.reviewed === true && !starting) {
        const pending = await pendingFor(s);
        if (pending && !pending.key) await chrome.storage.local.set({ [pendingKey(s)]: null });
        else if (pending) throw new ClientError("Reconcile the saved request identity before a new start.", "unknown");
        sendResponse({ ok: true, scope: s.scope });
      } else if (msg.type === "events") {
        if (!Number.isSafeInteger(msg.goalId) || msg.goalId <= 0 ||
            !Number.isSafeInteger(msg.since) || msg.since < 0) throw new ClientError("Invalid replay request.", "protocol");
        const data = await request(s, "/api/v1/goals/" + msg.goalId + "/events?since=" + msg.since + "&limit=200",
          undefined, msg.requestId);
        sendResponse({ ok: true, scope: s.scope, data });
      } else sendResponse({ ok: false, kind: "protocol", error: "Unknown message type." });
    } catch (error) {
      sendResponse({ ok: false, kind: error.kind || "unknown", status: error.status,
        error: error.message || "Client request failed." });
    }
  })();
  return true;
});
