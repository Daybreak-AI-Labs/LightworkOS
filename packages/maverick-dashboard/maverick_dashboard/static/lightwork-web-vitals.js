/* Field Core Web Vitals ([analytics] web_vitals): a sample of page loads
   measures how fast the page showed its main content (LCP), answered clicks
   and key presses (INP) and stayed steady (CLS), the way Google's web-vitals
   library does, and sends the three numbers once, when the page is hidden.
   Only the path and "phone" or "desktop" go with them; the server keeps them
   as counts under the page's route (maverick/web_vitals.py). Loaded only when
   the setting is on, from this server (no outside script). */
(function () {
  'use strict';
  var script = document.currentScript;
  var rate = Number(script && script.dataset.sampleRate);
  if (!(rate > 0) || Math.random() >= rate || typeof PerformanceObserver !== 'function' || !navigator.sendBeacon) return;
  // A page loaded in a background tab paints when it is shown, so its LCP
  // would measure the wait for the person, not the page.
  var hiddenAtStart = document.visibilityState === 'hidden';
  var lcp = null, lcpDone = false, cls = 0, session = 0, first = 0, last = 0, interactions = {}, sent = false;
  function observe(type, each, options) {
    try {
      var observer = new PerformanceObserver(function (list) { list.getEntries().forEach(each); });
      observer.observe(Object.assign({type: type, buffered: true}, options || {}));
      return observer;
    } catch (_) { return null; }
  }
  var lcpObserver = observe('largest-contentful-paint', function (entry) {
    if (!lcpDone && !hiddenAtStart) lcp = Math.max(0, entry.startTime);
  });
  // LCP stops at the first input: later paints answer the person, not the load.
  function stopLcp() { lcpDone = true; if (lcpObserver) lcpObserver.disconnect(); }
  ['keydown', 'click', 'pointerdown'].forEach(function (type) { addEventListener(type, stopLcp, {once: true, capture: true}); });
  // CLS: the largest burst of unexpected shifts (gaps under 1 s, at most 5 s long).
  observe('layout-shift', function (entry) {
    if (entry.hadRecentInput) return;
    if (session && entry.startTime - last < 1000 && entry.startTime - first < 5000) session += entry.value;
    else { session = entry.value; first = entry.startTime; }
    last = entry.startTime;
    if (session > cls) cls = session;
  });
  // INP: each interaction's longest event; the slowest one, ignoring one in 50.
  function interaction(entry) {
    if (!entry.interactionId) return;
    interactions[entry.interactionId] = Math.max(interactions[entry.interactionId] || 0, entry.duration);
  }
  observe('event', interaction, {durationThreshold: 40});
  observe('first-input', interaction);
  function inp() {
    var durations = Object.keys(interactions).map(function (id) { return interactions[id]; }).sort(function (a, b) { return b - a; });
    return durations.length ? durations[Math.min(durations.length - 1, Math.floor(durations.length / 50))] : null;
  }
  function phone() {
    try { return matchMedia('(max-width: 760px)').matches || matchMedia('(pointer: coarse)').matches; } catch (_) { return false; }
  }
  function send() {
    if (sent) return;
    sent = true;
    var body = {path: location.pathname, device: phone() ? 'phone' : 'desktop'};
    if (lcp !== null) body.lcp = Math.round(lcp);
    body.cls = Math.round(cls * 10000) / 10000;
    var slowest = inp();
    if (slowest !== null) body.inp = Math.round(slowest);
    try { navigator.sendBeacon('/api/v1/telemetry/vitals', new Blob([JSON.stringify(body)], {type: 'application/json'})); } catch (_) { /* measurement never breaks the page */ }
  }
  document.addEventListener('visibilitychange', function () { if (document.visibilityState === 'hidden') send(); });
  addEventListener('pagehide', send);
}());
