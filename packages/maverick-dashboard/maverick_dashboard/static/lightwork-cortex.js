/* Cortex — the company brain's page (Observe → Cortex).
   1. The lattice (#cortex-lattice): a fibonacci lattice, slowly turning,
      its nodes lighting as the workforce writes to it and as reads touch it.
      Pure canvas, no dependencies. Honors prefers-reduced-motion (one static
      frame, nothing lights) and pauses when scrolled out of view or the tab
      is hidden.
   2. The recall console: POSTs the labelled form to /api/v1/cortex/recall
      with the dashboard's same-origin convention (credentials: same-origin,
      a JSON body, the browser's Origin header as the CSRF proof) and renders
      the hits grouped by source with citation, score and text, plus the
      denied reasons and the audited flag. Every node is built with
      createElement/textContent: recalled text is data, never markup. */
(function () {
  "use strict";
  var root = document.getElementById("ctx-root");
  if (!root) { return; }
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var MONO = "11px ui-monospace, 'JetBrains Mono', Menlo, monospace";
  var GRAD = [[47, 124, 255], [139, 92, 246], [255, 138, 43]];
  function mix(t) {
    t = Math.max(0, Math.min(1, t));
    var i = t < 0.5 ? 0 : 1, f = t < 0.5 ? t * 2 : (t - 0.5) * 2, a = GRAD[i], b = GRAD[i + 1];
    return [a[0] + (b[0] - a[0]) * f | 0, a[1] + (b[1] - a[1]) * f | 0, a[2] + (b[2] - a[2]) * f | 0];
  }

  /* ---- 1. the lattice: a fibonacci sphere, lit by the workforce ---- */
  var lattice = (function () {
    var cv = document.getElementById("cortex-lattice");
    if (!cv || !cv.getContext) { return null; }
    var ctx = cv.getContext("2d");
    if (!ctx) { return null; }
    var W = cv.width || 640, H = cv.height || 480, dpr = Math.min(window.devicePixelRatio || 1, 2);
    var n = 520, pts = [], links = [], lit = [], P = [], t = 3, raf = 0, visible = true, last = 0, i, j, k;
    cv.width = W * dpr; cv.height = H * dpr; ctx.scale(dpr, dpr);
    for (i = 0; i < n; i++) {
      var y = 1 - (i / (n - 1)) * 2, r = Math.sqrt(1 - y * y), th = i * 2.399963;
      pts.push([Math.cos(th) * r, y, Math.sin(th) * r]);
      lit.push(0);
    }
    for (i = 0; i < n; i++) {
      var best = [];
      for (j = 0; j < n; j++) {
        if (i === j) { continue; }
        var p = pts[i], q = pts[j];
        var d = (p[0] - q[0]) * (p[0] - q[0]) + (p[1] - q[1]) * (p[1] - q[1]) + (p[2] - q[2]) * (p[2] - q[2]);
        if (best.length < 3 || d < best[2][0]) {
          best.push([d, j]);
          best.sort(function (a, b) { return a[0] - b[0]; });
          if (best.length > 3) { best.length = 3; }
        }
      }
      for (k = 0; k < best.length; k++) { if (best[k][1] > i) { links.push([i, best[k][1]]); } }
    }
    function project() {
      var R = H * 0.36, cx = W / 2, cy = H / 2, ay = t * 0.12, ax = Math.sin(t * 0.07) * 0.35;
      P.length = 0;
      for (var m = 0; m < n; m++) {
        var p = pts[m];
        var x = p[0] * Math.cos(ay) - p[2] * Math.sin(ay), z = p[0] * Math.sin(ay) + p[2] * Math.cos(ay);
        var yy = p[1] * Math.cos(ax) - z * Math.sin(ax);
        z = p[1] * Math.sin(ax) + z * Math.cos(ax);
        var s = 1 / (1.9 - z * 0.8);
        P.push([cx + x * R * s, cy + yy * R * s, z, s]);
      }
    }
    function running() { return !reduce && visible && !document.hidden; }
    function draw(now) {
      var dt = Math.min(0.05, (now - last) / 1000 || 0);
      last = now; t += dt;
      ctx.clearRect(0, 0, W, H);
      var g = ctx.createRadialGradient(W / 2, H / 2, 0, W / 2, H / 2, H * 0.6);
      g.addColorStop(0, "rgba(139,92,246,.22)");
      g.addColorStop(0.5, "rgba(255,138,43,.08)");
      g.addColorStop(1, "rgba(0,0,0,0)");
      ctx.fillStyle = g; ctx.fillRect(0, 0, W, H);
      project();
      ctx.lineWidth = 1;
      for (var l = 0; l < links.length; l++) {
        var a = P[links[l][0]], b = P[links[l][1]];
        var c = mix(((a[2] + b[2]) / 2 + 1) / 2), al = 0.10 + ((a[2] + b[2]) / 2 + 1) / 2 * 0.5;
        ctx.strokeStyle = "rgba(" + c[0] + "," + c[1] + "," + c[2] + "," + al + ")";
        ctx.beginPath(); ctx.moveTo(a[0], a[1]); ctx.lineTo(b[0], b[1]); ctx.stroke();
      }
      if (!reduce && Math.random() < 0.08) {
        var pick = Math.random() * n | 0;
        if (P[pick][2] > -0.1) { lit[pick] = 1; }
      }
      for (var m = 0; m < n; m++) {
        var q2 = P[m], cc = mix((q2[2] + 1) / 2);
        if (lit[m] > 0.02) {
          var gg = ctx.createRadialGradient(q2[0], q2[1], 0, q2[0], q2[1], 10 + lit[m] * 10);
          gg.addColorStop(0, "rgba(255,255,255," + lit[m] * 0.9 + ")");
          gg.addColorStop(1, "rgba(255,255,255,0)");
          ctx.fillStyle = gg; ctx.beginPath(); ctx.arc(q2[0], q2[1], 10 + lit[m] * 10, 0, 6.283); ctx.fill();
          lit[m] *= 0.96;
        }
        ctx.fillStyle = "rgba(" + cc[0] + "," + cc[1] + "," + cc[2] + "," + (0.3 + (q2[2] + 1) / 2 * 0.7) + ")";
        ctx.beginPath(); ctx.arc(q2[0], q2[1], 1.1 + q2[3] * 1.5, 0, 6.283); ctx.fill();
      }
      ctx.fillStyle = "#8E97AC"; ctx.font = MONO; ctx.textAlign = "left";
      ctx.fillText("Documents · skills · lessons · decisions · shared notes", 20, H - 18);
      raf = running() ? requestAnimationFrame(draw) : 0;
    }
    function resume() {
      if (!raf && running()) { last = performance.now(); raf = requestAnimationFrame(draw); }
    }
    if ("IntersectionObserver" in window) {
      new IntersectionObserver(function (entries) {
        visible = entries[0].isIntersecting;
        resume();
      }, { threshold: 0.05 }).observe(cv);
    }
    document.addEventListener("visibilitychange", resume);
    raf = requestAnimationFrame(draw);
    return {
      /* A read touched `count` nodes: light that many front-facing ones. */
      pulse: function (count) {
        if (reduce || !P.length) { return; }
        var want = Math.max(1, Math.min(n, count | 0)), tries = 0;
        while (want > 0 && tries++ < n) {
          var pick = Math.random() * n | 0;
          if (P[pick][2] > -0.1) { lit[pick] = 1; want--; }
        }
        resume();
      }
    };
  })();

  /* ---- 2. the recall console ---- */
  var apiBase = root.dataset.apiBase || "/api/v1/cortex";
  var LABELS = {};
  try { LABELS = JSON.parse(root.dataset.sourceLabels || "{}") || {}; } catch (_e) { LABELS = {}; }
  function sourceLabel(name) {
    return Object.prototype.hasOwnProperty.call(LABELS, name) ? LABELS[name]
      : (window.mvHuman ? window.mvHuman(name) : String(name));
  }

  /* Turn on a source that is off (lessons, outside assistants' notes) through
     the same admin-only feature switch the Learning page uses. */
  Array.prototype.forEach.call(document.querySelectorAll("[data-cortex-switch]"), function (btn) {
    btn.addEventListener("click", async function () {
      if (btn.disabled) { return; }
      var section = btn.getAttribute("data-cortex-switch");
      var label = btn.getAttribute("data-label") || "this source";
      var msg = document.querySelector('[data-cortex-switch-msg="' + section + '"]');
      var ok = window.mvConfirm ? await window.mvConfirm("Turn on " + label + " for everyone in this installation?",
        { okText: "Turn on" }) : false;
      if (!ok) { return; }
      btn.disabled = true; btn.setAttribute("aria-busy", "true");
      if (msg) { msg.textContent = "Turning on…"; }
      try {
        var r = await fetch("/api/v1/features/switches", {
          method: "POST", credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ section: section, enabled: true })
        });
        if (!r.ok) {
          var why = r.status === 409 ? "This is controlled by your installation settings, so it cannot be turned on here. Ask your administrator to turn it on."
            : window.mvErrorText(r, "turn this on");
          if (msg) { msg.textContent = why; }
          btn.disabled = false; btn.removeAttribute("aria-busy");
          return;
        }
        location.reload();
      } catch (error) {
        if (msg) { msg.textContent = window.mvErrorText(error, "turn this on"); }
        btn.disabled = false; btn.removeAttribute("aria-busy");
      }
    });
  });
  var form = document.getElementById("ctx-recall-form");
  var stateEl = document.getElementById("ctx-recall-state");
  var resultEl = document.getElementById("ctx-result");
  var metaEl = document.getElementById("ctx-result-meta");
  var deniedEl = document.getElementById("ctx-denied");
  var hitsEl = document.getElementById("ctx-hits");
  var submit = document.getElementById("ctx-recall-submit");
  if (!form || !stateEl || !resultEl || !metaEl || !deniedEl || !hitsEl || !submit) { return; }
  var maxResponseBytes = 4 * 1024 * 1024;
  var MAX_K = 50, DEFAULT_K = 5;

  function fail(message) {
    var error = new Error(message);
    error.code = "invalid_input";
    return error;
  }

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) { node.className = cls; }
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    return node;
  }


  async function readJson(response) {
    var declared = Number(response.headers.get("content-length") || 0);
    if (declared > maxResponseBytes) {
      if (response.body && typeof response.body.cancel === "function") { await response.body.cancel(); }
      throw fail("Too many results came back. Choose fewer sources or fewer results and try again.");
    }
    var text = await response.text();
    if (text.length > maxResponseBytes) { throw fail("Too many results came back. Choose fewer sources or fewer results and try again."); }
    var payload;
    try { payload = text ? JSON.parse(text) : {}; }
    catch (_error) { throw fail("The search response could not be read. Try again."); }
    if (!response.ok) {
      if (response.status === 403) {
        throw fail("You do not have access to search knowledge, or your session changed. Reload the page and try again.");
      }
      throw fail(window.mvErrorText ? window.mvErrorText(response, "search the memory") : "The search did not work. Try again.");
    }
    return payload;
  }

  function collect() {
    var data = new FormData(form);
    var query = String(data.get("query") || "").trim();
    var sources = data.getAll("sources").map(String);
    var domain = String(data.get("domain") || "").trim();
    var k = parseInt(String(data.get("k") || ""), 10);
    if (!query) { throw fail("Type what you would like to find first."); }
    if (!sources.length) { throw fail("Choose at least one source."); }
    var body = { query: query, sources: sources, k: isFinite(k) ? Math.min(MAX_K, Math.max(1, k)) : DEFAULT_K };
    if (domain) { body.domain = domain; }
    return body;
  }

  function chip(label, value) {
    var node = el("span", "ctx-chip");
    node.appendChild(el("span", "", label));
    node.appendChild(el("strong", "", value));
    return node;
  }

  function renderMeta(result) {
    metaEl.textContent = "";
    var hits = Array.isArray(result.hits) ? result.hits : [];
    metaEl.appendChild(el("span", "badge " + (result.audited ? "ok" : "denied"),
      result.audited ? "Recorded in the activity log" : "Not recorded in the activity log"));
    metaEl.appendChild(chip("Results: ", hits.length));
    var per = result.per_source || {};
    Object.keys(per).forEach(function (source) { metaEl.appendChild(chip(sourceLabel(source) + ": ", per[source])); });
  }

  function renderDenied(result) {
    deniedEl.textContent = "";
    var denied = result.denied || {};
    var names = Object.keys(denied);
    deniedEl.hidden = !names.length;
    if (!names.length) { return; }
    deniedEl.appendChild(el("strong", "", names.length === 1 ? "1 source did not answer" : names.length + " sources did not answer"));
    var list = el("ul");
    names.forEach(function (source) {
      var item = el("li");
      item.appendChild(el("strong", "", sourceLabel(source)));
      item.appendChild(document.createTextNode(": " + denied[source]));
      list.appendChild(item);
    });
    deniedEl.appendChild(list);
  }

  function renderHits(result) {
    hitsEl.textContent = "";
    var hits = Array.isArray(result.hits) ? result.hits : [];
    var order = Array.isArray(result.sources) ? result.sources.slice() : [];
    hits.forEach(function (hit) { if (order.indexOf(hit.source) < 0) { order.push(hit.source); } });
    if (!hits.length) {
      hitsEl.appendChild(el("p", "muted", "No results found for that search."));
      return;
    }
    order.forEach(function (source) {
      var mine = hits.filter(function (hit) { return hit.source === source; });
      if (!mine.length) { return; }
      var group = el("section", "ctx-group");
      group.appendChild(el("h3", "", sourceLabel(source) + " · " + mine.length));
      var list = el("ol", "ctx-hits");
      mine.forEach(function (hit) {
        var item = el("li", "ctx-hit");
        var head = el("div", "ctx-hit__head");
        head.appendChild(el("span", "ctx-hit__cite", hit.citation || "Source not recorded"));
        if (hit.kind) { head.appendChild(el("span", "badge", window.mvHuman ? window.mvHuman(hit.kind) : hit.kind)); }
        var score = Number(hit.score);
        if (isFinite(score) && score >= 0 && score <= 1) {
          head.appendChild(el("span", "", "Match " + Math.round(score * 100) + "%"));
        }
        item.appendChild(head);
        item.appendChild(el("p", "ctx-hit__text", hit.text || ""));
        list.appendChild(item);
      });
      group.appendChild(list);
      hitsEl.appendChild(group);
    });
  }

  async function recall(body) {
    var response = await fetch(apiBase + "/recall", {
      method: "POST",
      credentials: "same-origin",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return readJson(response);
  }

  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    if (submit.disabled) { return; }
    var body;
    try { body = collect(); }
    catch (error) { stateEl.textContent = error.message; return; }
    submit.disabled = true;
    submit.setAttribute("aria-busy", "true");
    stateEl.textContent = "Searching…";
    try {
      var result = await recall(body);
      renderMeta(result);
      renderDenied(result);
      renderHits(result);
      resultEl.hidden = false;
      var count = Array.isArray(result.hits) ? result.hits.length : 0;
      var asked = Object.keys(result.per_source || {}).length;
      stateEl.textContent = count + (count === 1 ? " result" : " results") + " from " + asked +
        (asked === 1 ? " source" : " sources") + (result.audited ? ". This search is recorded in the activity log."
          : ". This search could not be recorded in the activity log.");
      if (lattice) { lattice.pulse(Math.max(3, count * 2)); }
    } catch (error) {
      stateEl.textContent = error && error.code === "invalid_input" ? error.message
        : (window.mvErrorText ? window.mvErrorText(error, "search the memory") : "The search did not work. Try again.");
    } finally {
      submit.disabled = false;
      submit.removeAttribute("aria-busy");
    }
  });
})();
