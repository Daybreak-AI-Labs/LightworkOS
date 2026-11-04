// Usage research measure: count AI suggestions shown, used or dismissed, without
// names. Loaded only while [analytics] usage_measures is on; pages call
// window.mvSuggestion(kind, item, event). Nothing is sent when it is off.
(function () {
  'use strict';
  if (window.mvSuggestion) return;
  function typing() {
    var el = document.activeElement;
    return !!(el && (el.tagName === 'TEXTAREA' || (el.tagName === 'INPUT' && /^(text|search)$/i.test(el.type || 'text')))
      && String(el.value || '').trim());
  }
  window.mvSuggestion = function (kind, item, event) {
    try {
      var body = JSON.stringify({ kind: String(kind), item: String(item || '').slice(0, 500), event: event, typing: event === 'shown' && typing() });
      if (window.fetch) window.fetch('/api/v1/usage-measures/suggestion', { method: 'POST', credentials: 'same-origin', keepalive: true,
        headers: { 'Content-Type': 'application/json' }, body: body }).catch(function () { /* a lost count is acceptable */ });
    } catch (_) { /* measuring never breaks the page */ }
  };
})();
