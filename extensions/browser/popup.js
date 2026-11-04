// Lightwork popup chat. Thin UI: every network call is delegated to the
// background service worker (see background.js), which talks only to the
// local dashboard. Plain JS, no build step.

const $ = (id) => document.getElementById(id);

let pollTimer = null;
let scope = "";
let watchState = null;
let generation = 0;
let polling = null;
let submitting = false;
let held = false;
let alive = true;
let activeRequestId = null;
let serial = 0;
let pageReview = null;
const session = chrome.storage.session || chrome.storage.local;
let persistence = Promise.resolve();

function controls() {
  $("send").disabled = $("send-page").disabled = !scope || submitting || held;
  $("clear-pending").hidden = !held;
}

function stopPolling() {
  clearTimeout(pollTimer);
  pollTimer = null;
  if (activeRequestId) chrome.runtime.sendMessage({ type: "cancel", requestId: activeRequestId }, () => {});
  activeRequestId = null;
}

function saveWatch(value, epoch) {
  persistence = persistence.catch(() => {}).then(async () => {
    if (epoch === generation && alive) await session.set({ activeWatch: value });
  });
  return persistence;
}

function renderWatch() {
  $("log").textContent = "";
  if (!watchState) return;
  if (watchState.title) appendEvent("you", watchState.title);
  for (const event of watchState.events) appendEvent(event.agent, event.content);
  if (watchState.complete && watchState.result) appendEvent("result", watchState.result);
  setStatus("goal #" + watchState.goalId + " — " + watchState.status +
    (watchState.hasMore ? " (loading remaining events)" : "") +
    (watchState.trimmed ? " · bounded history; open dashboard for full history" : ""));
}

function setStatus(text, isError) {
  const el = $("status");
  el.textContent = text || "";
  el.className = isError ? "err" : "hint";
}

function appendEvent(agent, content) {
  const p = document.createElement("p");
  p.className = "evt";
  const who = document.createElement("span");
  who.className = "who";
  who.textContent = agent + ": ";
  p.appendChild(who);
  // textContent only — agent output is untrusted text, never HTML.
  p.appendChild(document.createTextNode(content));
  $("log").appendChild(p);
  $("log").scrollTop = $("log").scrollHeight;
}

// background.js gives each dashboard request 15 s, and a page send (a chat
// message with a capture policy) makes two in a row: the policy check, then the
// start. Wait for all of them plus a margin before calling the worker silent.
const WORKER_REQUEST_MS = 15000;

function ask(msg) {
  return new Promise((resolve) => {
    let settled = false;
    const requests = msg.type === "chat" && msg.capturePolicy ? 2 : 1;
    const timer = setTimeout(() => finish({ ok: false, kind: msg.type === "chat" ? "unknown" : "transient",
      error: "Client request not confirmed. Check the dashboard before retrying a start." }),
    requests * WORKER_REQUEST_MS + 2000);
    function finish(value) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    }
    chrome.runtime.sendMessage(msg, (resp) => {
      if (chrome.runtime.lastError) {
        finish({ ok: false, kind: msg.type === "chat" ? "unknown" : "transient", error: chrome.runtime.lastError.message });
      } else {
        finish(resp || { ok: false, kind: "unknown", error: "No response." });
      }
    });
  });
}

async function poll() {
  if (!alive || !watchState || watchState.complete || polling === generation) return;
  const epoch = generation;
  polling = epoch;
  let delay = 2000;
  try {
    for (let page = 0; page < 10; page++) {
      activeRequestId = "popup-" + epoch + "-" + (++serial);
      const resp = await ask({ type: "events", scope, goalId: watchState.goalId,
        since: watchState.cursor, requestId: activeRequestId });
      if (epoch !== generation || !alive) return;
      activeRequestId = null;
      if (!resp.ok || resp.scope !== scope) {
        setStatus(resp.error || "Dashboard connection changed.", true);
        if (["access", "context", "protocol", "configuration", "refused"].includes(resp.kind) || (resp.ok && resp.scope !== scope)) {
          watchState = null;
          $("log").textContent = "";
          await saveWatch(null, epoch);
        }
        return;
      }
      watchState = LightworkClientProtocol.page(watchState, resp.data);
      renderWatch();
      await saveWatch(watchState, epoch);
      if (epoch !== generation || !alive || !watchState || watchState.complete || !watchState.hasMore) return;
      delay = 0; // Yield after ten pages; never drop a terminal run's backlog.
    }
  } catch (error) {
    if (epoch === generation && alive) {
      setStatus(error.message, true);
      watchState = null;
      await saveWatch(null, epoch);
    }
  } finally {
    if (polling === epoch) polling = null;
    if (epoch === generation && alive && watchState && !watchState.complete) pollTimer = setTimeout(poll, delay);
  }
}

async function startGoal(title, description, capturePolicy) {
  if (submitting || held || !scope || !alive) return;
  submitting = true;
  controls();
  const epoch = generation;
  setStatus("starting…");
  try {
    const resp = await ask({ type: "chat", scope, title, description, capturePolicy });
    if (epoch !== generation || !alive) return;
    if (!resp.ok || resp.scope !== scope) {
      held = ["unknown", "pending"].includes(resp.kind);
      setStatus(resp.error || "Dashboard connection changed; start not confirmed.", true);
      return;
    }
    stopPolling();
    generation++;
    watchState = { scope, goalId: resp.goal.id, cursor: 0, events: [], status: resp.goal.status,
      complete: false, hasMore: false, result: "", title };
    await saveWatch(watchState, generation);
    if ($("prompt").value.trim() === description) $("prompt").value = "";
    renderWatch();
    // An obsolete poll still owns the pending flag until its bounded request
    // returns; scheduling here prevents that old finally block reviving it.
    pollTimer = setTimeout(poll, 0);
  } finally {
    submitting = false;
    controls();
  }
}

async function sendChat() {
  const text = $("prompt").value.trim();
  if (!text) return;
  // First line becomes the goal title; the full text is the brief.
  const title = text.split("\n", 1)[0].slice(0, 200);
  await startGoal(title, text);
}

// Render the bounded, observe-only accessibility/DOM snapshot the content
// script returns into compact lines for the goal brief. Read-only formatting:
// the structured context is already capped by content.js; we keep it tight.
function renderStructured(structured) {
  if (!structured) return "";
  let out = "\n\n--- structured page context (observe-only) ---";
  if (structured.lang) out += "\nlang: " + structured.lang;
  const c = structured.counts || {};
  out += "\ncounts: " + (c.elements || 0) + " interactive, " + (c.landmarks || 0) + " landmarks";
  if (structured.truncated) out += " (truncated)";
  const landmarks = structured.landmarks || [];
  if (landmarks.length) {
    out += "\nlandmarks/headings:";
    for (const l of landmarks) {
      out += "\n  - " + l.tag + (l.role && l.role !== l.tag ? " [" + l.role + "]" : "") +
             (l.name ? ": " + l.name : "");
    }
  }
  const elements = structured.elements || [];
  if (elements.length) {
    out += "\ninteractive elements:";
    for (const e of elements) {
      let line = "\n  - " + (e.role || e.tag);
      if (e.name) line += ' "' + e.name + '"';
      if (e.type) line += " type=" + e.type;
      if (e.value) line += " value=" + JSON.stringify(e.value);
      if (e.disabled) line += " (disabled)";
      if (e.selector) line += "  @ " + e.selector;
      out += line;
    }
  }
  return out;
}

// "Send this page": ask the content script for {title, url, selection,
// structured} and ship it as goal context alongside whatever is in the chat
// box. Same user-triggered, localhost-only, bearer-gated path as before.
function reviewedDescription() {
  if (!pageReview) return "";
  const ctx = pageReview.context;
  let text = ($("prompt").value.trim() || "Review this page.") + "\n\n--- reviewed page source data ---";
  if ($("share-url").checked) text += "\ntitle: " + ctx.title + "\nurl: " + ctx.url;
  if ($("share-selection").checked && ctx.selection) text += "\nselection:\n" + ctx.selection;
  if ($("share-structure").checked && pageReview.policy.page_structure) {
    const structure = JSON.parse(JSON.stringify(ctx.structured || {}));
    if (!$('share-values').checked || !pageReview.policy.form_values) for (const item of structure.elements || []) delete item.value;
    text += renderStructured(structure);
  }
  if (!$('share-structure').checked && $('share-values').checked && pageReview.policy.form_values) {
    text += "\nVisible form values:\n" + (ctx.structured?.elements || []).filter(item => item.value).map(item => (item.name || item.tag) + ": " + item.value).join("\n");
  }
  return text;
}
function renderPageReview() {
  if (!pageReview) return;
  $("share-values").disabled = !pageReview.policy.form_values;
  if ($("share-values").disabled) $("share-values").checked = false;
  $("page-preview").textContent = reviewedDescription();
}
function cancelPageReview() {
  pageReview = null; $("page-preview").textContent = ""; $("page-review").hidden = true; $("send-page").focus();
}
async function sendPage() {
  if (submitting || held || !scope) return;
  const epoch = generation;
  const policy = await ask({ type: "capturePolicy", scope });
  if (epoch !== generation || !alive) return;
  if (!policy.ok) { setStatus(policy.error || "Capture policy is unavailable. No page was sent.", true); return; }
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab = tabs && tabs[0];
  if (!tab || tab.id === undefined) { setStatus("No active tab.", true); return; }
  chrome.tabs.sendMessage(tab.id, { type: "getPageContext", options:{structure:policy.data.page_structure || policy.data.form_values, formValues:policy.data.form_values} }, async (ctx) => {
    if (epoch !== generation || !alive || submitting || held) return;
    if (chrome.runtime.lastError || !ctx) { setStatus("Cannot read this page. Browser settings pages are unavailable.",true); return; }
    const preferences = (await chrome.storage.local.get("capturePreferences")).capturePreferences || {};
    if (epoch !== generation || !alive) return;
    pageReview = { context:ctx, policy:policy.data, epoch };
    $("share-url").checked = preferences.url !== false;
    $("share-selection").checked = preferences.selection !== false;
    $("share-structure").checked = policy.data.page_structure && preferences.structure === true;
    $("share-structure").disabled = !policy.data.page_structure;
    // Sensitive values require a fresh choice for every page, never a remembered opt-in.
    $("share-values").checked = false;
    $("page-policy").textContent = "This extension sends reviewed content to your local Lightwork dashboard. Lightwork may send it to its configured AI service (" + policy.data.model + ") and permitted tools under workspace policy. " + (policy.data.form_values ? "Visible form values are optional and off by default." : "Your administrator does not allow form values.");
    $("page-review").hidden = false; renderPageReview(); $("page-confirm").focus();
  });
}
async function confirmPageReview() {
  if (!pageReview || pageReview.epoch !== generation || submitting || held) return;
  const description = reviewedDescription();
  const reviewed = pageReview;
  const title = ($("prompt").value.trim().split("\n",1)[0] || "Review shared page context").slice(0,200);
  await chrome.storage.local.set({capturePreferences:{url:$("share-url").checked, selection:$("share-selection").checked, structure:$("share-structure").checked}});
  await startGoal(title, description, {revision:reviewed.policy.revision, form_values:$("share-values").checked, page_structure:$("share-structure").checked});
  cancelPageReview();
}

async function loadSettings() {
  const epoch = generation;
  const s = await chrome.storage.local.get({ base: "http://127.0.0.1:8765", token: "" });
  if (epoch !== generation || !alive) return;
  $("base").value = s.base;
  $("token").value = s.token;
  $("extension-settings").href = /^http:\/\/127\.0\.0\.1(:\d+)?$/.test(s.base) ? s.base + "/settings#settings-access" : "#";
  if (!s.token.trim()) { scope=""; controls(); setStatus("An access token is required. Ask your administrator, paste it in Settings, and save.",true); return; }
  $("dashboard").href = /^http:\/\/127\.0\.0\.1(:\d+)?$/.test(s.base) ? s.base : "#";
  const identity = await ask({ type: "identity" });
  if (epoch !== generation || !alive) return;
  if (!identity.ok) { setStatus(identity.error, true); return; }
  scope = identity.scope;
  held = Boolean(identity.pending);
  const saved = (await session.get("activeWatch")).activeWatch;
  if (epoch !== generation || !alive) return;
  watchState = saved && saved.scope === scope && Number.isSafeInteger(saved.goalId) &&
    Number.isSafeInteger(saved.cursor) && Array.isArray(saved.events) && saved.events.length <= 1000 ? saved : null;
  if (watchState) watchState = { ...watchState, complete: false, status: "checking current access…" };
  renderWatch();
  if (held) setStatus("A previous start is unconfirmed. Check start status to recover its original goal.", true);
  controls();
  if (watchState && !watchState.complete) pollTimer = setTimeout(poll, 0);
}

async function saveSettings() {
  let base = $("base").value.trim() || "http://127.0.0.1:8765";
  // Local-only by policy AND by manifest: host_permissions stop anything
  // beyond 127.0.0.1, so refuse other hosts here with a clear message.
  if (!/^http:\/\/127\.0\.0\.1(:\d+)?$/.test(base.replace(/\/+$/, ""))) {
    setStatus("dashboard URL must be http://127.0.0.1[:port]", true);
    return;
  }
  if (!$("token").value.trim()) { setStatus("An access token is required before the extension can connect.",true); return; }
  cancelPageReview();
  base = base.replace(/\/+$/, "");
  generation++;
  stopPolling();
  scope = "";
  watchState = null;
  $("log").textContent = "";
  controls();
  await chrome.storage.local.set({ base: base, token: $("token").value.trim() });
  await loadSettings();
}

document.addEventListener("DOMContentLoaded", () => {
  controls();
  loadSettings();
  $("send").addEventListener("click", sendChat);
  $("send-page").addEventListener("click", sendPage);
  $("page-confirm").addEventListener("click", confirmPageReview);
  $("page-cancel").addEventListener("click", cancelPageReview);
  for (const id of ["share-url","share-selection","share-structure","share-values"]) $(id).addEventListener("change",renderPageReview);
  $("save").addEventListener("click", saveSettings);
  $("clear-pending").addEventListener("click", async () => {
    if (!held || submitting) return;
    const epoch = generation;
    submitting = true;
    controls();
    try {
      const response = await ask({ type: "reconcile", scope });
      if (!alive || epoch !== generation) return;
      if (!response.ok || response.scope !== scope || !response.goal) {
        setStatus("Start remains unconfirmed. " + (response.error || "No receipt is visible yet.") + " No new request was sent.", true);
        return;
      }
      held = false;
      await loadSettings();
    } finally { submitting = false; controls(); }
  });
  $("prompt").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" && (ev.ctrlKey || ev.metaKey)) sendChat();
  });
});

window.addEventListener("pagehide", () => { alive = false; generation++; stopPolling(); });
