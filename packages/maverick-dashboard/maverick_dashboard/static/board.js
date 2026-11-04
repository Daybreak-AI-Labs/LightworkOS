/* LWBoard — the shared executive-board engine behind Overview / Spend /
 * Workforce (the same class of board as /privacy/board, generalized).
 *
 * One JSON payload per board (GET /api/v1/dashboards/{board}?days=N) is
 * client-rendered into KPI tiles (count-up value, delta chip vs the prior
 * window, sparkline), gradient area charts with a crosshair tooltip,
 * animated donuts, and labeled horizontal bars. A range slicer refetches;
 * the board auto-refreshes every 60s while visible.
 *
 * Everything draws from the design-system tokens (var(--brand) etc.) so the
 * boards restyle with the active theme, and every chart carries text labels
 * and aria descriptions — color never carries meaning alone. Animations are
 * skipped entirely under prefers-reduced-motion.
 */
window.LWBoard = (function () {
  'use strict';

  var REDUCED = window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // ---- tiny DOM/SVG helpers ------------------------------------------------
  function el(tag, cls, txt) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (txt != null) n.textContent = txt;
    return n;
  }
  function svg(tag, attrs) {
    var n = document.createElementNS('http://www.w3.org/2000/svg', tag);
    Object.keys(attrs || {}).forEach(function (k) { n.setAttribute(k, attrs[k]); });
    return n;
  }
  function fmt(n) { return (n == null ? 0 : n).toLocaleString(); }
  // The shared formats from lightwork-ui.js; the fallbacks only cover a
  // render that lands before the shell script has loaded.
  function money(n) {
    n = n == null ? 0 : n;
    return window.mvMoney ? window.mvMoney(n) : '$' + n.toLocaleString(undefined,
      { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }
  function now() { return window.mvTimeAbsolute ? window.mvTimeAbsolute(Date.now()) : new Date().toLocaleString(); }

  // ---- shared tooltip ------------------------------------------------------
  var tip = null;
  function ensureTip() {
    if (!tip) {
      tip = el('div', 'bd-tip');
      tip.hidden = true;
      document.body.appendChild(tip);
    }
    return tip;
  }
  function showTip(evt, lines) {
    var t = ensureTip();
    t.textContent = '';
    lines.forEach(function (ln, i) {
      t.appendChild(el('div', i ? '' : 'bd-tip__head', ln));
    });
    t.hidden = false;
    var pad = 14;
    var x = Math.min(evt.clientX + pad, window.innerWidth - t.offsetWidth - pad);
    var y = Math.max(evt.clientY - t.offsetHeight - pad, pad);
    t.style.left = x + 'px';
    t.style.top = y + 'px';
  }
  function hideTip() { if (tip) tip.hidden = true; }

  // ---- animated number -----------------------------------------------------
  function countUp(node, value, format) {
    var f = format || fmt;
    if (REDUCED || !value) { node.textContent = f(value); return; }
    var t0 = null, DUR = 450;
    function tick(ts) {
      if (!t0) t0 = ts;
      var p = Math.min((ts - t0) / DUR, 1);
      var eased = 1 - Math.pow(1 - p, 3);
      node.textContent = f(value * eased);
      if (p < 1) requestAnimationFrame(tick);
      else node.textContent = f(value);
    }
    requestAnimationFrame(tick);
  }

  // ---- KPI tile ------------------------------------------------------------
  function deltaChip(cur, prev, opts) {
    opts = opts || {};
    var chip = el('span', 'bd-chip');
    if (!prev && !cur) { chip.classList.add('flat'); chip.textContent = '—'; return chip; }
    var d = prev ? (cur - prev) / prev : 1;
    if (prev && Math.abs(d) < 0.005) {
      chip.classList.add('flat'); chip.textContent = '· flat'; return chip;
    }
    var up = cur > prev;
    var bad = opts.upIsBad ? up : !up;
    chip.classList.add(bad ? 'down' : 'up');
    // A tiny or empty baseline makes percentages absurd ("▲ 1367%") —
    // show the absolute change instead once the ratio stops being meaningful.
    var f = opts.format || fmt;
    chip.textContent = (up ? '▲ ' : '▼ ') +
      ((!prev || prev < 8 || Math.abs(d) > 4)
        ? (up ? '+' : '−') + f(Math.abs(cur - prev))
        : Math.abs(Math.round(d * 100)) + '%');
    chip.title = 'vs the previous window: ' + f(prev);
    return chip;
  }

  function sparkline(values, cls) {
    var W = 96, H = 30, n = values.length;
    var s = svg('svg', { viewBox: '0 0 ' + W + ' ' + H, width: W, height: H,
                         'aria-hidden': 'true' });
    if (!n) return s;
    var max = Math.max.apply(null, values.concat([1]));
    var step = W / Math.max(n - 1, 1);
    var pts = values.map(function (v, i) {
      return (i * step).toFixed(1) + ',' + (H - 2 - (v / max) * (H - 6)).toFixed(1);
    });
    var area = svg('path', {
      d: 'M' + pts.join(' L') + ' L' + W + ',' + H + ' L0,' + H + ' Z',
      'class': 'bd-spark__area ' + (cls || '') });
    var line = svg('polyline', { points: pts.join(' '), fill: 'none',
      'stroke-width': '1.6', 'stroke-linejoin': 'round',
      'stroke-linecap': 'round', 'class': 'bd-spark__line ' + (cls || '') });
    s.appendChild(area);
    s.appendChild(line);
    return s;
  }

  // cfg: {label, value, format, chip:{cur,prev,upIsBad}, sub, spark, sparkCls}
  function kpi(cfg) {
    var t = el('div', 'bd-kpi panel');
    var top = el('div', 'bd-kpi__top');
    top.appendChild(el('div', 'bd-kpi__label', cfg.label));
    if (cfg.chip) top.appendChild(deltaChip(cfg.chip.cur, cfg.chip.prev, cfg.chip));
    t.appendChild(top);
    var num = el('div', 'bd-kpi__num');
    t.appendChild(num);
    countUp(num, cfg.value || 0, cfg.format);
    var foot = el('div', 'bd-kpi__foot');
    if (cfg.sub) foot.appendChild(el('span', 'bd-kpi__sub', cfg.sub));
    if (cfg.spark && cfg.spark.length > 1) {
      foot.appendChild(sparkline(cfg.spark, cfg.sparkCls || 'brand'));
    }
    t.appendChild(foot);
    return t;
  }

  // ---- donut ---------------------------------------------------------------
  function arcPath(cx, cy, r0, r1, a0, a1) {
    function pt(r, a) {
      return (cx + r * Math.cos(a)).toFixed(2) + ' ' + (cy + r * Math.sin(a)).toFixed(2);
    }
    var large = (a1 - a0) > Math.PI ? 1 : 0;
    return 'M' + pt(r1, a0) + ' A' + r1 + ' ' + r1 + ' 0 ' + large + ' 1 ' + pt(r1, a1) +
           ' L' + pt(r0, a1) + ' A' + r0 + ' ' + r0 + ' 0 ' + large + ' 0 ' + pt(r0, a0) + ' Z';
  }

  // cfg: {segments:[{label,value,cls}], center, centerSub, aria, onSlice}
  function donut(box, cfg) {
    box.textContent = '';
    var wrap = el('div', 'viz-donut');
    var S = 176, R1 = 84, R0 = 62, C = S / 2;
    var s = svg('svg', { viewBox: '0 0 ' + S + ' ' + S, width: S, height: S,
                         role: 'img', 'aria-label': cfg.aria || '' });
    var total = cfg.segments.reduce(function (n, x) { return n + x.value; }, 0);
    var track = svg('circle', { cx: C, cy: C, r: (R0 + R1) / 2, fill: 'none',
      'stroke-width': R1 - R0, 'class': 'bd-donut__track' });
    s.appendChild(track);
    if (total) {
      var a = -Math.PI / 2;
      var gap = cfg.segments.filter(function (x) { return x.value; }).length > 1 ? 0.03 : 0;
      cfg.segments.forEach(function (seg) {
        if (!seg.value) return;
        var sweep = (seg.value / total) * Math.PI * 2;
        var p = svg('path', { d: arcPath(C, C, R0, R1, a + gap / 2, a + sweep - gap / 2),
                              'class': 'bd-donut__seg viz-fill-' + seg.cls });
        p.addEventListener('mousemove', function (evt) {
          showTip(evt, [seg.label, fmt(seg.value) + ' · ' +
                        Math.round(100 * seg.value / total) + '%']);
        });
        p.addEventListener('mouseleave', hideTip);
        if (cfg.onSlice) {
          p.classList.add('bd-clickable');
          p.addEventListener('click', function () { cfg.onSlice(seg); });
        }
        s.appendChild(p);
        a += sweep;
      });
    }
    var num = svg('text', { x: C, y: C - 2, 'text-anchor': 'middle',
                            'class': 'viz-donut__num' });
    num.textContent = cfg.center != null ? fmt(cfg.center) : fmt(total);
    var sub = svg('text', { x: C, y: C + 20, 'text-anchor': 'middle',
                            'class': 'viz-donut__sub' });
    sub.textContent = cfg.centerSub || '';
    s.appendChild(num);
    s.appendChild(sub);
    wrap.appendChild(s);
    var legend = el('ul', 'viz-legend');
    cfg.segments.forEach(function (seg) {
      var li = el('li', 'viz-legend__item' + (cfg.onSlice ? ' bd-clickable' : ''));
      var dot = el('span', 'viz-dot viz-bg-' + seg.cls);
      dot.setAttribute('aria-hidden', 'true');
      li.appendChild(dot);
      li.appendChild(el('span', 'viz-legend__label', seg.label));
      li.appendChild(el('span', 'viz-legend__val', fmt(seg.value)));
      if (cfg.onSlice) li.addEventListener('click', function () { cfg.onSlice(seg); });
      legend.appendChild(li);
    });
    wrap.appendChild(legend);
    box.appendChild(wrap);
  }

  // ---- area chart ----------------------------------------------------------
  // cfg: {data:[{...}], x:'d', series:[{key,label,cls}], yFmt, aria,
  //       xTick(v,i,n)->label|'' }
  var gradSeq = 0;
  function area(box, cfg) {
    box.textContent = '';
    var W = 720, H = 240, padL = 44, padR = 12, padT = 14, padB = 26;
    var iw = W - padL - padR, ih = H - padT - padB;
    var data = cfg.data || [];
    var s = svg('svg', { viewBox: '0 0 ' + W + ' ' + H, role: 'img',
                         'aria-label': cfg.aria || '', 'class': 'bd-area' });
    box.appendChild(s);
    if (!data.length) return;
    var max = 1;
    data.forEach(function (r) {
      cfg.series.forEach(function (sr) { max = Math.max(max, r[sr.key] || 0); });
    });
    max = max <= 4 ? 4 : Math.ceil(max / 4) * 4;
    var step = iw / Math.max(data.length - 1, 1);
    function X(i) { return padL + i * step; }
    function Y(v) { return padT + ih - (v / max) * ih; }
    var yF = cfg.yFmt || fmt;

    for (var g = 0; g <= 4; g++) {
      var v = (max / 4) * g;
      s.appendChild(svg('line', { x1: padL, x2: W - padR, y1: Y(v), y2: Y(v),
                                  'class': 'bd-area__grid' }));
      var yt = svg('text', { x: padL - 7, y: Y(v) + 3, 'text-anchor': 'end',
                             'class': 'bd-area__tick' });
      yt.textContent = yF(v);
      s.appendChild(yt);
    }
    var defs = svg('defs');
    cfg.series.forEach(function (sr) {
      sr._grad = 'bd-g' + (++gradSeq);
      var lg = svg('linearGradient', { id: sr._grad, x1: 0, y1: 0, x2: 0, y2: 1 });
      var s0 = svg('stop', { offset: '0%', 'stop-opacity': '0.30',
                             'class': 'viz-stop-' + sr.cls });
      var s1 = svg('stop', { offset: '100%', 'stop-opacity': '0',
                             'class': 'viz-stop-' + sr.cls });
      lg.appendChild(s0); lg.appendChild(s1);
      defs.appendChild(lg);
    });
    s.appendChild(defs);
    cfg.series.slice().reverse().forEach(function (sr) {
      var pts = data.map(function (r, i) {
        return X(i).toFixed(1) + ',' + Y(r[sr.key] || 0).toFixed(1);
      });
      s.appendChild(svg('path', {
        d: 'M' + pts.join(' L') + ' L' + X(data.length - 1).toFixed(1) + ',' +
           (padT + ih) + ' L' + padL + ',' + (padT + ih) + ' Z',
        fill: 'url(#' + sr._grad + ')' }));
      var line = svg('polyline', { points: pts.join(' '), fill: 'none',
        'stroke-width': '2', 'stroke-linejoin': 'round',
        'stroke-linecap': 'round', 'class': 'viz-stroke-' + sr.cls });
      if (!REDUCED) {
        var len = 0;
        for (var i = 1; i < data.length; i++) len += step;
        line.style.strokeDasharray = (len * 1.5) + 'px';
        line.style.strokeDashoffset = (len * 1.5) + 'px';
        line.getBoundingClientRect();
        line.style.transition = 'stroke-dashoffset .7s ease-out';
        requestAnimationFrame(function () { line.style.strokeDashoffset = '0'; });
      }
      s.appendChild(line);
    });
    var xt = cfg.xTick || function (r, i, n) {
      return (i % Math.ceil(n / 8) === 0) ? String(r[cfg.x] || '') : '';
    };
    data.forEach(function (r, i) {
      var lbl = xt(r, i, data.length);
      if (!lbl) return;
      var t = svg('text', { x: X(i), y: H - 8, 'text-anchor': 'middle',
                            'class': 'bd-area__tick' });
      t.textContent = lbl;
      s.appendChild(t);
    });
    var guide = svg('line', { y1: padT, y2: padT + ih, visibility: 'hidden',
                              'class': 'bd-area__guide' });
    s.appendChild(guide);
    var dots = cfg.series.map(function (sr) {
      var d = svg('circle', { r: 3.5, visibility: 'hidden',
                              'class': 'viz-fill-' + sr.cls });
      s.appendChild(d);
      return d;
    });
    var hover = svg('rect', { x: padL, y: padT, width: iw, height: ih,
                              fill: 'transparent' });
    hover.addEventListener('mousemove', function (evt) {
      var b = s.getBoundingClientRect();
      var px = (evt.clientX - b.left) * (W / b.width);
      var i = Math.max(0, Math.min(data.length - 1, Math.round((px - padL) / step)));
      guide.setAttribute('x1', X(i)); guide.setAttribute('x2', X(i));
      guide.setAttribute('visibility', 'visible');
      var lines = [cfg.tipHead ? cfg.tipHead(data[i]) : String(data[i][cfg.x] || '')];
      cfg.series.forEach(function (sr, k) {
        dots[k].setAttribute('cx', X(i));
        dots[k].setAttribute('cy', Y(data[i][sr.key] || 0));
        dots[k].setAttribute('visibility', 'visible');
        lines.push(sr.label + ': ' + yF(data[i][sr.key] || 0));
      });
      showTip(evt, lines);
    });
    hover.addEventListener('mouseleave', function () {
      guide.setAttribute('visibility', 'hidden');
      dots.forEach(function (d) { d.setAttribute('visibility', 'hidden'); });
      hideTip();
    });
    s.appendChild(hover);
    if (cfg.legend !== false && cfg.series.length > 1) {
      var lg2 = el('ul', 'viz-legend viz-legend--row');
      cfg.series.forEach(function (sr) {
        var li = el('li', 'viz-legend__item');
        var dot = el('span', 'viz-dot viz-bg-' + sr.cls);
        dot.setAttribute('aria-hidden', 'true');
        li.appendChild(dot);
        li.appendChild(el('span', 'viz-legend__label', sr.label));
        lg2.appendChild(li);
      });
      box.appendChild(lg2);
    }
  }

  // ---- horizontal bars -----------------------------------------------------
  // rows: [{label, value_text, pct, pct_bg, cls, title, onClick}]
  function hbars(box, rows, aria) {
    box.textContent = '';
    var wrap = el('div', 'viz-bars');
    if (aria) wrap.setAttribute('aria-label', aria);
    rows.forEach(function (r) {
      var row = el('div', 'viz-bars__row' + (r.onClick ? ' bd-clickable' : ''));
      if (r.title) row.title = r.title;
      row.appendChild(el('span', 'viz-bars__label', r.label));
      var track = el('span', 'viz-bars__track');
      if (r.pct_bg != null) {
        var bg = el('span', 'viz-bars__fill viz-bars__fill--bg' +
                          (r.cls ? ' viz-bg-' + r.cls : ''));
        bg.style.width = r.pct_bg + '%';
        track.appendChild(bg);
      }
      var fill = el('span', 'viz-bars__fill' + (r.cls ? ' viz-bg-' + r.cls : ''));
      fill.style.width = REDUCED ? r.pct + '%' : '0%';
      track.appendChild(fill);
      if (!REDUCED) {
        requestAnimationFrame(function () {
          fill.style.transition = 'width .55s ease-out';
          fill.style.width = r.pct + '%';
        });
      }
      row.appendChild(track);
      row.appendChild(el('span', 'viz-bars__val', r.value_text));
      if (r.onClick) row.addEventListener('click', r.onClick);
      wrap.appendChild(row);
    });
    box.appendChild(wrap);
  }

  // ---- per-run strip (thin columns) ---------------------------------------
  function strip(box, items, aria) {
    box.textContent = '';
    var wrap = el('div', 'viz-cols bd-strip');
    wrap.setAttribute('role', 'img');
    if (aria) wrap.setAttribute('aria-label', aria);
    var max = 1;
    items.forEach(function (it) { max = Math.max(max, it.v || 0); });
    items.forEach(function (it) {
      var col = el('div', 'viz-cols__col');
      if (it.title) col.title = it.title;
      var plot = el('div', 'viz-cols__plot');
      var bar = el('div', 'viz-cols__bar viz-bg-' + (it.cls || 'brand') +
                          (it.v ? '' : ' viz-cols__bar--zero'));
      bar.style.height = ((it.v || 0) / max * 100).toFixed(1) + '%';
      plot.appendChild(bar);
      col.appendChild(plot);
      wrap.appendChild(col);
    });
    box.appendChild(wrap);
  }

  // An empty chart or list: the shared compact empty state (window.mvEmpty
  // from lightwork-ui.js) — what will appear here, then (body) how to get the
  // first one, plus an optional {label, href} next step.
  function empty(box, msg, body, action) {
    box.textContent = '';
    if (window.mvEmpty) { box.appendChild(window.mvEmpty(msg, body, action, { compact: true })); return; }
    box.appendChild(el('p', 'bd-empty muted', body ? msg + '. ' + body : msg));
  }

  // Fold a daily series into 7-day buckets (sums) — long windows read as a
  // trend instead of day-to-day noise. Keeps the first day's label per bucket.
  function bucketWeekly(data, keys) {
    var out = [], cur = null;
    (data || []).forEach(function (r, i) {
      if (i % 7 === 0) {
        cur = { d: r.d };
        keys.forEach(function (k) { cur[k] = 0; });
        out.push(cur);
      }
      keys.forEach(function (k) { cur[k] += r[k] || 0; });
    });
    return out;
  }

  // ---- board shell ---------------------------------------------------------
  // cfg: {board, render(D), endpoint?} — wires the slicer (when the page has
  // one), stamp, fetch, and the 60s visible-tab refresh. `endpoint` overrides
  // the default board API for pages whose payload already exists elsewhere.
  function attach(cfg) {
    // The range the tab bar shows as chosen (an address like #range-30 may
    // have chosen it already); 90 days otherwise.
    var chosen = document.querySelector('[role="tab"][data-days][aria-selected="true"]');
    var days = chosen ? (parseInt(chosen.dataset.days, 10) || 90) : 90;
    var generation = 0, active = null, retired = false, updated = '';
    var stampEl = document.getElementById('bd-stamp');
    function stamp(msg) {
      if (stampEl) stampEl.textContent = msg;
    }
    function url() {
      if (cfg.endpoint) return cfg.endpoint;
      return '/api/v1/dashboards/' + cfg.board + '?days=' + days;
    }
    function load() {
      if (retired) return;
      var request = ++generation, selectedDays = days;
      if (active) active.abort();
      active = new AbortController();
      var controller = active;
      var timeout = setTimeout(function () { controller.abort(); }, 20000);
      stamp('Loading ' + selectedDays + ' days' + (updated ? ' · previous view: ' + updated : '') + '.');
      fetch(url(), {signal: controller.signal, credentials: 'same-origin', cache: 'no-store'})
        .then(function (r) {
          if (!r.ok) throw r;
          return r.json();
        })
        .then(function (D) {
          if (retired || request !== generation || selectedDays !== days) return;
          cfg.render(D);
          updated = selectedDays + ' days, checked ' + now();
          stamp('Showing ' + updated + ' · updates every minute');
        })
        .catch(function (e) {
          if (retired || request !== generation) return;
          if (e && e.status === 403) {
            stamp('These charts can include work from departments you cannot access. Ask an administrator to review your access. Your permitted tasks remain available in Chat.');
            clearInterval(poll);
            return;
          }
          var why = window.mvErrorText ? window.mvErrorText(e, 'load the board') : 'Could not load the board. Refresh the page and try again.';
          stamp(why + (updated ? ' Previous view retained: ' + updated + '.' : '') + ' Trying again in a minute.');
        }).finally(function () { clearTimeout(timeout); if (request === generation) active = null; });
    }
    // The time range is a shared tab bar (_tabs.html, lightwork-tabs.js),
    // which marks the chosen range; the arrow keys only move between ranges
    // and Enter or Space loads one.
    document.querySelectorAll('[role="tab"][data-days]').forEach(function (b) {
      b.addEventListener('click', function () {
        days = parseInt(b.dataset.days, 10) || 90;
        load();
      });
    });
    var poll = setInterval(function () { if (!document.hidden && !active) load(); }, 60000);
    window.addEventListener('pagehide', function () { retired = true; ++generation; clearInterval(poll); if (active) active.abort(); });
    window.addEventListener('pageshow', function (event) {
      if (!event.persisted || !retired) return;
      retired = false;
      poll = setInterval(function () { if (!document.hidden && !active) load(); }, 60000);
      load();
    });
    load();
  }

  return { attach: attach, kpi: kpi, donut: donut, area: area, hbars: hbars,
           strip: strip, empty: empty, sparkline: sparkline, el: el,
           bucketWeekly: bucketWeekly,
           fmt: fmt, money: money, showTip: showTip, hideTip: hideTip };
})();
