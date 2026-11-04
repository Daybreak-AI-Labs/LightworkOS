// Tiny shared DOM/fetch helpers, Jinja-included INSIDE each page's IIFE (so
// nothing leaks to window). One copy: an auth-header or escaping change lands
// on every page that includes this, instead of being hand-synced per template.
function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
function api(url, opts) {
  return fetch(url, Object.assign({ headers: { 'Content-Type': 'application/json' } }, opts || {}));
}
