/*
 * maverick-widget.js — embeddable Lightwork status widget.
 *
 * Single self-contained file: no framework, no CDN, no external CSS.
 * Host this file at /widget/ on the dashboard origin using a static alias;
 * the dashboard does not mount this directory itself.
 * Embed:
 *
 *   <script src="/widget/maverick-widget.js"
 *           data-endpoint=""                 (default: same origin)
 *           data-token=""                    (optional bearer token — read
 *                                             the README before setting one)
 *           data-interval="15000"></script>
 *
 * It renders a floating status pill; clicking it expands a panel with
 * active / done / failed counts and the most recent finished result.
 *
 * Data source: GET {endpoint}/api/v1/goals?limit=100 — a real dashboard
 * endpoint (maverick_dashboard/api.py, router mounted at /api/v1). The
 * widget is read-only: it only ever issues GETs. When data-token is set it
 * sends exactly one auth header per request:
 *
 *   Authorization: Bearer <token>
 *
 * which is what the dashboard's bearer_auth middleware requires when
 * MAVERICK_DASHBOARD_TOKEN is set (query-string tokens were removed).
 * The dashboard sends no CORS headers, so this file must be served
 * same-origin with the dashboard or behind a reverse proxy that makes it
 * so — see README.md.
 *
 * Status buckets (statuses the world model actually writes — there is no
 * "failed" status today; blocked/cancelled are the failure outcomes):
 *   active: pending, active
 *   done:   done
 *   failed: blocked, cancelled (and "failed", defensively)
 */
(function () {
  "use strict";

  var script = document.currentScript;
  if (!script) { return; }

  var endpoint = (script.getAttribute("data-endpoint") || "").replace(/\/+$/, "");
  var token = script.getAttribute("data-token") || "";
  var interval = parseInt(script.getAttribute("data-interval") || "15000", 10);
  if (!(interval >= 5000)) { interval = 15000; } // floor: don't hammer the API

  var GOALS_PATH = "/api/v1/goals?limit=100";

  // --- DOM (Shadow DOM so host page CSS can't bleed in) -------------------
  var host = document.createElement("div");
  host.setAttribute("data-maverick-widget", "");
  var root = host.attachShadow ? host.attachShadow({ mode: "open" }) : host;

  var style = document.createElement("style");
  style.textContent = [
    ":host { all: initial; }",
    ".wrap { position: fixed; right: 16px; bottom: 16px; z-index: 2147483000;",
    "  font-family: system-ui, -apple-system, 'Segoe UI', sans-serif; }",
    ".pill { display: flex; align-items: center; gap: 8px; cursor: pointer;",
    "  background: #0b0e14; color: #e6e6e6; border: 1px solid #2a3142;",
    "  border-radius: 999px; padding: 8px 14px; font-size: 13px;",
    "  box-shadow: 0 4px 14px rgba(0,0,0,0.35); user-select: none; }",
    ".dot { width: 9px; height: 9px; border-radius: 50%; background: #6b7280; }",
    ".dot.ok { background: #34d399; } .dot.busy { background: #f5a623; }",
    ".dot.err { background: #ef4444; }",
    ".panel { display: none; position: absolute; right: 0; bottom: 44px;",
    "  width: 280px; background: #0b0e14; color: #e6e6e6;",
    "  border: 1px solid #2a3142; border-radius: 10px; padding: 12px;",
    "  box-shadow: 0 8px 24px rgba(0,0,0,0.45); font-size: 13px; }",
    ".panel.open { display: block; }",
    ".counts { display: flex; gap: 8px; margin-bottom: 10px; }",
    ".count { flex: 1; text-align: center; background: #131826;",
    "  border-radius: 8px; padding: 8px 4px; }",
    ".count b { display: block; font-size: 18px; }",
    ".count span { color: #9aa4b2; font-size: 11px; }",
    ".last { color: #9aa4b2; line-height: 1.4; max-height: 6.5em; overflow: hidden; }",
    ".last b { color: #e6e6e6; }",
    ".meta { margin-top: 8px; color: #5b6472; font-size: 11px; }"
  ].join("\n");

  var wrap = document.createElement("div");
  wrap.className = "wrap";
  wrap.innerHTML =
    '<div class="panel" part="panel">' +
    '  <div class="counts">' +
    '    <div class="count"><b id="n-active">–</b><span>active</span></div>' +
    '    <div class="count"><b id="n-done">–</b><span>done</span></div>' +
    '    <div class="count"><b id="n-failed">–</b><span>failed</span></div>' +
    "  </div>" +
    '  <div class="last" id="last">No finished runs yet.</div>' +
    '  <div class="meta" id="meta">connecting…</div>' +
    "</div>" +
    '<div class="pill" part="pill"><span class="dot" id="dot"></span><span id="label">Lightwork</span></div>';

  root.appendChild(style);
  root.appendChild(wrap);

  function el(id) { return root.querySelector("#" + id); }

  wrap.querySelector(".pill").addEventListener("click", function () {
    wrap.querySelector(".panel").classList.toggle("open");
  });

  // --- polling -------------------------------------------------------------
  function classify(goals) {
    var c = { active: 0, done: 0, failed: 0 };
    var lastFinished = null;
    for (var i = 0; i < goals.length; i++) {
      var g = goals[i];
      var s = g.status;
      if (s === "pending" || s === "active") {
        c.active += 1;
      } else if (s === "done") {
        c.done += 1;
        if (!lastFinished) { lastFinished = g; }
      } else if (s === "blocked" || s === "cancelled" || s === "failed") {
        c.failed += 1;
        if (!lastFinished) { lastFinished = g; }
      }
    }
    return { counts: c, last: lastFinished }; // goals come newest-first
  }

  function render(data) {
    var c = data.counts;
    el("n-active").textContent = String(c.active);
    el("n-done").textContent = String(c.done);
    el("n-failed").textContent = String(c.failed);
    el("label").textContent = "Lightwork · " + c.active + " active";
    var dot = el("dot");
    dot.className = "dot " + (c.active > 0 ? "busy" : "ok");
    if (data.last) {
      var result = data.last.result || "(no result text)";
      if (result.length > 220) { result = result.slice(0, 220) + "…"; }
      el("last").innerHTML = "";
      var b = document.createElement("b");
      b.textContent = "#" + data.last.id + " [" + data.last.status + "] " + data.last.title;
      el("last").appendChild(b);
      el("last").appendChild(document.createElement("br"));
      el("last").appendChild(document.createTextNode(result));
    } else { el("last").textContent = "No finished runs yet."; }
    el("meta").textContent = "updated " + new Date().toLocaleTimeString();
  }

  function renderError(msg) {
    el("dot").className = "dot err";
    el("label").textContent = "Lightwork · offline";
    el("meta").textContent = msg;
  }

  var alive = true, polling = false, pollTimer = null, pollController = null;
  function poll() {
    if (!alive || polling) return;
    polling = true;
    var headers = {};
    if (token) { headers["Authorization"] = "Bearer " + token; }
    var controller = new AbortController(), deadline, active = true;
    pollController = controller;
    var timeout = new Promise(function (_, reject) {
      deadline = setTimeout(function () {
        controller.abort();
        reject(new Error("Refresh timed out. Displayed results may be stale; retrying."));
      }, 15000);
    });
    var request = Promise.resolve().then(function () {
      return fetch(endpoint + GOALS_PATH, { headers: headers, cache: "no-store", signal: controller.signal });
    })
      .then(function (res) {
        if (res.status === 401 || res.status === 403) {
          throw new Error("unauthorized (" + res.status + ") — check token / origin");
        }
        if (!res.ok) { throw new Error("HTTP " + res.status); }
        return res.json();
      });
    Promise.race([timeout, request])
      .then(function (goals) { if (alive && active) render(classify(goals)); })
      .catch(function (e) { if (alive && active) renderError(e && e.message ? e.message : "unreachable"); })
      .finally(function () {
        active = false;
        clearTimeout(deadline);
        polling = false;
        if (pollController === controller) pollController = null;
        if (alive) pollTimer = setTimeout(poll, interval);
      });
  }

  window.addEventListener("pagehide", function () {
    alive = false;
    clearTimeout(pollTimer);
    if (pollController) pollController.abort();
  });

  function mount() {
    document.body.appendChild(host);
    poll();
  }

  if (document.body) { mount(); }
  else { document.addEventListener("DOMContentLoaded", mount); }
})();
