/* <lightwork-analytics> — embeddable Lightwork analytics web component.
 *
 * Self-contained (Web Components API, no framework, no dependencies).
 * Renders total spend, an episode-cost sparkline, and a goals-by-status bar
 * chart from the dashboard's existing read endpoints:
 *
 *   GET <endpoint>/api/v1/spend
 *   GET <endpoint>/api/v1/goals?limit=100
 *
 * Attributes:
 *   endpoint  Dashboard base URL (default: "" = the page's own origin).
 *   token     Optional bearer, sent as "Authorization: Bearer <token>".
 *
 * HONEST LIMITS — read before embedding anywhere but the dashboard itself:
 *   - Same-origin: the dashboard sends NO CORS headers, so fetches from a
 *     page on another origin are blocked by the browser. Embed on a page the
 *     dashboard serves (see /embed-demo) or behind the same reverse proxy.
 *   - Token exposure: anyone who can read the embedding page's HTML can read
 *     the token and gains its granted API access. Do not put broad credentials
 *     in shared HTML. Prefer each viewer's own same-origin signed-in session.
 *   - No-token loopback mode needs no token attribute at all.
 *
 * The legacy <maverick-analytics> tag from before the Lightwork rebrand stays
 * registered as an alias so pages embedded earlier keep rendering.
 */
(function () {
  "use strict";
  if (typeof customElements === "undefined" || customElements.get("lightwork-analytics")) return;

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  // Hand-drawn inline-SVG sparkline (polyline over min..max).
  function sparklineSVG(values, w, h, stroke) {
    if (!values.length) return '<span class="muted">no data</span>';
    const lo = Math.min(...values), hi = Math.max(...values);
    const span = (hi - lo) || 1, n = values.length, pad = 2;
    const pts = values.map((v, i) => {
      const x = pad + (w - 2 * pad) * (n > 1 ? i / (n - 1) : 0.5);
      const y = pad + (h - 2 * pad) * (1 - (v - lo) / span);
      return x.toFixed(1) + "," + y.toFixed(1);
    }).join(" ");
    return '<svg width="' + w + '" height="' + h + '" role="img" aria-label="sparkline of ' +
      n + ' values from ' + lo.toFixed(4) + " to " + hi.toFixed(4) + '">' +
      '<polyline points="' + pts + '" fill="none" stroke="' + stroke + '" stroke-width="1.5"/></svg>';
  }

  // Hand-drawn horizontal bar chart for {label: count}.
  function barsSVG(counts, w, color, textColor) {
    const labels = Object.keys(counts).sort();
    if (!labels.length) return '<span class="muted">No tasks yet. Finished tasks appear here.</span>';
    const max = Math.max(...labels.map((k) => counts[k])) || 1;
    const rowH = 18;
    const rows = labels.map((k, i) => {
      const bw = Math.max(2, (w - 110) * (counts[k] / max));
      const y = i * rowH;
      return '<text x="0" y="' + (y + 12) + '" font-size="10" fill="' + textColor + '">' + esc(String(k).replace(/_/g, " ")) + "</text>" +
        '<rect x="70" y="' + (y + 3) + '" width="' + bw.toFixed(1) + '" height="10" rx="2" fill="' + color + '"></rect>' +
        '<text x="' + (74 + bw).toFixed(1) + '" y="' + (y + 12) + '" font-size="10" fill="' + textColor + '">' + counts[k] + "</text>";
    }).join("");
    return '<svg width="' + w + '" height="' + (labels.length * rowH) + '" role="img" aria-label="tasks by status: ' +
      labels.map((k) => esc(k) + " " + counts[k]).join(", ") + '">' + rows + "</svg>";
  }

  // Fetch failures from another site come back as a TypeError; say it plainly.
  function plain(e) {
    if (e && e.name === "TypeError") return "Blocked — this page is not allowed to read your Lightwork data.";
    return (e && e.message) || "Could not load this right now. Refresh the page and try again.";
  }

  class LightworkAnalytics extends HTMLElement {
    static get observedAttributes() { return ['endpoint', 'token']; }
    attributeChangedCallback() { if (this.isConnected && this.shadowRoot) this.connectedCallback(); }
    disconnectedCallback() { this._generation = (this._generation || 0) + 1; if (this._controller) this._controller.abort(); }
    connectedCallback() {
      const root = this.shadowRoot || this.attachShadow({ mode: "open" });
      root.innerHTML =
        "<style>" +
        ":host { display: block; font: 13px/1.5 -apple-system, 'Segoe UI', Roboto, sans-serif; " +
        "color: #e6edf3; background: #161b22; border: 1px solid #30363d; border-radius: 8px; " +
        "padding: 1rem; max-width: 420px; }" +
        "h2 { margin: 0 0 0.5rem; font-size: 0.75rem; text-transform: uppercase; " +
        "letter-spacing: 0.08em; color: #9aa3ad; }" +
        ".num { font-size: 1.6rem; font-weight: 600; }" +
        ".muted { color: #9aa3ad; }" +
        "section { margin-bottom: 0.9rem; }" +
        ".err { color: #f85149; }" +
        "</style>" +
        '<section><h2>Recorded runtime spend - all time</h2><div id="spend" class="muted">loading…</div></section>' +
        '<section><h2>Cost of recent episode attempts</h2><div id="trend" class="muted">loading…</div></section>' +
        '<section style="margin-bottom:0"><h2>Latest 100 accessible tasks - sample by status</h2><div id="goals" class="muted">loading…</div></section>';
      const scope = document.createElement('p');
      scope.textContent = 'Snapshot scope: recorded runtime spend across all time, recent episode costs, and a sample of at most 100 accessible tasks. Older tasks can be omitted; status bars are not workspace-wide totals.';
      root.appendChild(scope);
      const freshness = document.createElement('p'); freshness.id = 'freshness'; freshness.setAttribute('role', 'status'); root.appendChild(freshness);
      const refresh = document.createElement('button'); refresh.id = 'refresh'; refresh.type = 'button'; refresh.textContent = 'Refresh snapshot';
      refresh.addEventListener('click', () => this._load(root)); root.appendChild(refresh);
      this._load(root);
    }

    _fetch(path, signal) {
      const base = (this.getAttribute("endpoint") || "").replace(/\/+$/, "");
      const headers = { Accept: "application/json" };
      const token = this.getAttribute("token");
      if (token) headers.Authorization = "Bearer " + token;
      return fetch(base + path, { headers, signal, cache: 'no-store' }).then((r) => {
        if (!r.ok) {
          const e = new Error(r.status === 401 || r.status === 403
            ? "Sign-in needed — ask your administrator for an access key."
            : "Could not load this right now. Refresh the page and try again.");
          throw e;
        }
        return r.json();
      });
    }

    _load(root) {
      if (this._controller) this._controller.abort();
      const controller = this._controller = new AbortController();
      const generation = this._generation = (this._generation || 0) + 1;
      const timeout = setTimeout(() => controller.abort(), 20000);
      const refresh = root.getElementById('refresh'); refresh.disabled = true;
      root.getElementById('freshness').textContent = 'Refreshing the selected connection snapshot.';
      let failed = false;
      const put = (id, html, isErr) => {
        if (generation !== this._generation || !this.isConnected) return;
        const el = root.getElementById(id);
        el.innerHTML = html;
        el.className = isErr ? "err" : "";
      };
      const spending = this._fetch("/api/v1/spend", controller.signal).then((data) => {
        const total = data.total || {};
        put("spend", (window.mvMoney ? window.mvMoney(Number(total.dollars || 0)) : "$" + Number(total.dollars || 0).toFixed(2)) +
          ' <span class="muted">(' + (Number(total.runs) || 0) + " tasks)</span>");
        const costs = (data.episodes || [])
          .map((e) => Number(e.cost_dollars || 0))
          .reverse(); // API returns newest first; plot oldest -> newest
        put("trend", sparklineSVG(costs, 360, 42, "#3fb950"));
      }).catch((e) => {
        failed = true;
        const msg = plain(e);
        put("spend", esc(msg), true);
        put("trend", esc(msg), true);
      });
      const tasks = this._fetch("/api/v1/goals?limit=100", controller.signal).then((goals) => {
        const counts = {};
        (goals || []).forEach((g) => {
          const s = g.status || "unknown";
          counts[s] = (counts[s] || 0) + 1;
        });
        put("goals", barsSVG(counts, 360, "#3fb950", "#9aa3ad"));
      }).catch((e) => {
        failed = true;
        put("goals", esc(plain(e)), true);
      });
      Promise.allSettled([spending, tasks]).then(() => {
        clearTimeout(timeout);
        if (generation !== this._generation || !this.isConnected) return;
        refresh.disabled = false;
        root.getElementById('freshness').textContent = (failed ? 'Snapshot incomplete. Attempted ' : 'Snapshot loaded ') + (window.mvTimeAbsolute ? window.mvTimeAbsolute(Date.now()) : new Date().toLocaleString()) + '. Refresh to check current state.';
      });
    }
  }

  customElements.define("lightwork-analytics", LightworkAnalytics);
  // Legacy alias (pre-rebrand embeds). A subclass, because one constructor
  // cannot be registered under two names.
  if (!customElements.get("maverick-analytics")) {
    customElements.define("maverick-analytics", class extends LightworkAnalytics {});
  }
})();
