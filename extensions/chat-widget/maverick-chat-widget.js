/*
 * Lightwork embeddable widget.
 *
 * A dependency-free floating chat button for pages served from a Lightwork
 * dashboard's own origin; it talks to that dashboard's chat endpoint.
 * Self-hostable: it posts to YOUR dashboard origin, not a hosted service.
 *
 * Usage:
 *   <script src="/widget/maverick-chat-widget.js"
 *           data-maverick-url="https://your-dashboard.example.com"
 *           data-maverick-title="Ask Lightwork"></script>
 *
 * The page must be on that same origin: the widget sends the signed-in
 * session's cookies and the dashboard sets no CORS headers, so a
 * data-maverick-url on another origin is refused before anything is sent.
 */
(function () {
  "use strict";

  var script = document.currentScript;
  var BASE = (script && script.getAttribute("data-maverick-url")) || "";
  var TITLE = (script && script.getAttribute("data-maverick-title")) || "Lightwork";
  BASE = BASE.replace(/\/+$/, "");
  var busy = false;
  var unknown = false;
  var alive = true;
  var request = null;
  var pendingTimer = null;
  var pendingId = null;
  var expectedOrigin = new URL(BASE || location.origin, location.href).origin;
  var storageKey = "lightwork.pending-chat.v1:" + expectedOrigin;

  function el(tag, props, css) {
    var n = document.createElement(tag);
    if (props) Object.keys(props).forEach(function (k) {
      // Hyphenated keys (e.g. "aria-label") are attributes, not IDL
      // properties: assigning n["aria-label"] creates a dead expando and the
      // attribute is never set. Route those through setAttribute.
      if (k.indexOf("-") !== -1) { n.setAttribute(k, props[k]); }
      else { n[k] = props[k]; }
    });
    if (css) Object.keys(css).forEach(function (k) { n.style[k] = css[k]; });
    return n;
  }

  var panel = el("div", {id: "lightwork-widget-panel", role: "region", "aria-label": TITLE}, {
    position: "fixed", bottom: "calc(84px + env(safe-area-inset-bottom, 0px))", insetInlineEnd: "12px", width: "min(320px, calc(100% - 24px))", boxSizing: "border-box",
    maxHeight: "min(60dvh, calc(100dvh - 100px))", display: "none", flexDirection: "column",
    background: "#fff", border: "1px solid #ddd", borderRadius: "12px",
    // Let the whole panel scroll when a very short viewport cannot contain
    // the nonshrinking controls and receipt status together.
    boxShadow: "0 8px 30px rgba(0,0,0,.18)", overflowX: "hidden", overflowY: "auto",
    font: "14px/1.4 system-ui, sans-serif", zIndex: 2147483647
  });

  var header = el("div", { textContent: TITLE }, {
    padding: "10px 14px", flexShrink: "0", fontWeight: "600", background: "#111", color: "#fff"
  });
  var closeButton = el('button', {type: 'button', textContent: 'Close', 'aria-label': 'Close ' + TITLE}, {marginInlineStart: 'auto', minHeight: '44px'});
  header.style.display = 'flex'; header.style.alignItems = 'center'; header.appendChild(closeButton);
  var log = el("div", {'aria-label': 'Conversation'}, {
    flex: "1", minHeight: "0", overflowWrap: "anywhere", padding: "12px", overflowY: "auto", color: "#111"
  });
  var form = el("form", null, { display: "flex", flexShrink: "0", borderTop: "1px solid #eee" });
  var input = el("input", {
    type: "text", placeholder: "Type a goal…", "aria-label": "Message to Lightwork", required: true
  }, { flex: "1", minWidth: "0", boxSizing: "border-box", border: "0", padding: "12px" });
  var send = el("button", { type: "submit", textContent: "Send" }, {
    border: "0", background: "#111", color: "#fff", padding: "0 16px",
    cursor: "pointer"
  });
  form.appendChild(input); form.appendChild(send);
  panel.appendChild(header); panel.appendChild(log); panel.appendChild(form);
  var check = el("button", { type: "button", textContent: "Check start status", hidden: true }, {flexShrink: "0"});
  panel.appendChild(check);
  var status = el('p', {role: 'status', 'aria-live': 'polite', 'aria-atomic': 'true'}, {margin: '8px 12px', flexShrink: '0', color: '#111'});
  panel.appendChild(status);

  var fab = el("button", { textContent: "💬", "aria-label": TITLE }, {
    position: "fixed", bottom: "20px", right: "20px", width: "52px",
    height: "52px", borderRadius: "50%", border: "0", background: "#111",
    color: "#fff", fontSize: "22px", cursor: "pointer",
    boxShadow: "0 6px 20px rgba(0,0,0,.25)", zIndex: 2147483647
  });

  fab.setAttribute('aria-controls', panel.id); fab.setAttribute('aria-expanded', 'false');
  function line(who, text) {
    if (who === 'Lightwork') status.textContent = text;
    var row = el("div", null, { margin: "6px 0" });
    row.appendChild(el("b", { textContent: who + ": " }));
    row.appendChild(document.createTextNode(text));
    log.appendChild(row);
    log.scrollTop = log.scrollHeight;
  }

  function setOpen(open) {
    panel.style.display = open ? 'flex' : 'none';
    fab.setAttribute('aria-expanded', String(open));
    if (open) { fit(); input.focus(); }
    else { fab.hidden = false; fab.focus(); }
  }
  fab.addEventListener('click', function () { setOpen(panel.style.display !== 'flex'); });
  closeButton.addEventListener('click', function () { setOpen(false); });
  panel.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') { event.preventDefault(); setOpen(false); }
  });
  function fit() {
    if (panel.style.display !== 'flex') return;
    var viewport = window.visualViewport;
    var width = viewport ? viewport.width : window.innerWidth;
    var height = viewport ? viewport.height : window.innerHeight;
    var top = viewport ? viewport.offsetTop : 0;
    var left = viewport ? viewport.offsetLeft : 0;
    // A host's CSS zoom scales the widget too. Convert the visible bounds to
    // its layout units, keeping the person's enlarged text and controls.
    var scale = panel.getBoundingClientRect().width / panel.offsetWidth || 1;
    var compact = height / scale < 400;
    var gap = compact ? 12 : 84;
    // Keep the device's bottom inset in the same unzoomed layout units as
    // the visible bounds, reserving it in both position and available height.
    var safeBottom = 'env(safe-area-inset-bottom, 0px) / ' + scale;
    panel.style.width = Math.max(0, Math.min(320, width / scale - 24)) + 'px';
    panel.style.maxHeight = 'max(0px, calc(' + (height / scale - gap - 12) + 'px - ' + safeBottom + '))';
    panel.style.bottom = 'calc(' + ((window.innerHeight - height - top) / scale + gap) + 'px + ' + safeBottom + ')';
    var end = getComputedStyle(panel).direction === 'rtl' ? left : window.innerWidth - width - left;
    panel.style.insetInlineEnd = end / scale + 12 + 'px';
    // Short windows and the on-screen keyboard need the space normally kept
    // for the launcher. Close and Escape remain available in the open panel.
    fab.hidden = compact;
  }
  window.addEventListener('resize', fit);
  if (window.visualViewport) {
    window.visualViewport.addEventListener('resize', fit);
    window.visualViewport.addEventListener('scroll', fit);
  }

  function controls() {
    send.disabled = busy || unknown;
    form.setAttribute("aria-busy", String(busy));
    check.hidden = !unknown;
    check.disabled = busy;
  }

  function hold() {
    unknown = true;
    line("Lightwork", "Start not confirmed. Your draft is preserved. Check start status to recover the original request; no new start will be sent.");
  }

  function accepted(id, msg) {
    if (!Number.isSafeInteger(id) || id <= 0) throw new Error("Invalid goal receipt");
    var row = el("div", null, { margin: "6px 0" });
    row.appendChild(el("b", { textContent: "Lightwork: " }));
    row.appendChild(document.createTextNode("Goal accepted — "));
    row.appendChild(el("a", { textContent: "watch it live", href: BASE + "/chat/goal/" + id,
      target: "_blank", rel: "noopener" }));
    log.appendChild(row);
    status.textContent = "Task accepted. Open the task to follow its progress.";
    if (localStorage.getItem(storageKey) === pendingId) localStorage.removeItem(storageKey);
    pendingId = null;
    unknown = false;
    if (msg && input.value.trim() === msg) input.value = "";
  }

  function boundedFetch(path, options, parse) {
    var active = true;
    var controller = new AbortController();
    request = controller;
    var timer;
    var timeout = new Promise(function (_, reject) {
      timer = setTimeout(function () { controller.abort(); reject(new Error("Request not confirmed")); }, 15000);
      pendingTimer = timer;
    });
    var call = fetch(BASE + path, Object.assign({}, options, { credentials: "include", signal: controller.signal }));
    return Promise.race([timeout, call.then(function (response) {
      if (!active || !alive) throw new Error("Obsolete response");
      return parse(response);
    })]).finally(function () {
      active = false;
      clearTimeout(timer);
      if (pendingTimer === timer) pendingTimer = null;
      if (request === controller) request = null;
    });
  }

  async function readReceipt(response) {
    if (!response.ok || !response.body || !response.body.getReader) throw new Error("Receipt not available");
    var reader = response.body.getReader(), decoder = new TextDecoder(), size = 0, text = "";
    try {
      while (true) {
        var part = await reader.read();
        if (part.done) break;
        size += part.value.byteLength;
        if (size > 16384) { await reader.cancel(); throw new Error("Receipt too large"); }
        text += decoder.decode(part.value, { stream: true });
      }
      var data = JSON.parse(text + decoder.decode());
      if (data.state !== "accepted" || !data.goal || typeof data.goal.status !== "string") throw new Error("Invalid receipt");
      return data.goal;
    } finally { reader.releaseLock(); }
  }

  check.addEventListener("click", function () {
    if (busy || !unknown || !pendingId || !alive) return;
    busy = true;
    controls();
    boundedFetch("/api/v1/goal-submissions/receipt?kind=chat", {
      method: "GET", redirect: "error", cache: "no-store", headers: { "Accept": "application/json", "Idempotency-Key": pendingId }
    }, readReceipt).then(function (goal) {
      if (alive) accepted(goal.id);
    }).catch(function () {
      if (alive) line("Lightwork", "No confirmed receipt is visible yet. The original request remains held; no new start was sent.");
    }).finally(function () { busy = false; if (alive) controls(); });
  });

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var msg = input.value.trim();
    if (!msg || busy || unknown || !alive) return;
    if (expectedOrigin !== location.origin) {
      line("Lightwork", "Start refused before sending: this widget only works on the dashboard's own origin, but data-maverick-url names " +
        expectedOrigin + ". Serve the widget from the dashboard itself or remove the attribute.");
      return;
    }
    busy = true;
    status.textContent = "Sending your request. Waiting for its receipt.";
    line("You", msg);
    controls();
    try {
      if (localStorage.getItem(storageKey)) {
        pendingId = localStorage.getItem(storageKey);
        hold(); busy = false; controls(); return;
      }
      pendingId = crypto.randomUUID();
      localStorage.setItem(storageKey, pendingId);
    } catch (error) {
      busy = false;
      line("Lightwork", "Start refused before sending: secure request identity could not be retained.");
      controls(); return;
    }
    // /chat/send takes multipart form fields (title required) and answers
    // with a 303 redirect to the new goal page. fetch follows the redirect,
    // so a landed response whose URL contains /chat/goal/ IS the success
    // signal; link the user straight to the live goal.
    var fd = new FormData();
    var characters = Array.from(msg);
    fd.append("title", characters.length > 200 ? characters.slice(0, 199).join("") + "…" : msg);
    if (characters.length > 200) fd.append("description", msg);
    fd.append("submission_key", pendingId);
    boundedFetch("/chat/send", { method: "POST", body: fd }, async function (r) {
        if (!alive) return;
        if (!r.ok) {
          var detail = null;
          try { detail = await r.json(); } catch (_) { /* Fall back to the status if no JSON detail is available. */ }
          var failure = new Error(detail && typeof detail.detail === "string" ? detail.detail : "Dashboard replied HTTP " + r.status + ".");
          // A followed redirect can fail AFTER goal creation. Only a direct
          // client-error response proves the start was refused.
          failure.refused = !r.redirected && r.status >= 400 && r.status < 500 && r.status !== 409;
          throw failure;
        }
        var landed = new URL(r.url, location.href);
        var expected = new URL(BASE || location.origin, location.href);
        var m = landed.pathname.match(/^\/chat\/goal\/([1-9]\d*)$/);
        if (r.redirected && landed.origin === expected.origin && !landed.search && !landed.hash && m) {
          accepted(Number(m[1]), msg);
        } else {
          throw new Error("Start not confirmed. Open the dashboard to check your session and tasks before sending again.");
        }
      })
      .catch(function (err) {
        if (!alive) return;
        if (err.refused) {
          if (localStorage.getItem(storageKey) === pendingId) localStorage.removeItem(storageKey);
          pendingId = null;
          line("Lightwork", "Start refused. " + err.message);
        } else { hold(); }
        var link = el("a", { textContent: "Open dashboard", href: BASE || location.origin,
          target: "_blank", rel: "noopener" });
        log.appendChild(link);
      })
      .finally(function () {
        busy = false;
        controls();
      });
  });

  document.body.appendChild(panel);
  document.body.appendChild(fab);
  try {
    pendingId = localStorage.getItem(storageKey);
    if (pendingId && expectedOrigin === location.origin) { hold(); controls(); }
  } catch (_) { /* A new submission will refuse before dispatch if persistence is unavailable. */ }
  window.addEventListener("pagehide", function () {
    alive = false;
    clearTimeout(pendingTimer);
    if (request) request.abort();
  });
})();
