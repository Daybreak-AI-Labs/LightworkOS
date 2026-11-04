/* The Help menu on every page (_help_menu.html).
   "Get help from a person" opens the Help page's request form with this page,
   the task or run on it and the last error reference already filled in.
   Nothing is sent: the person reviews the request and chooses how to send it. */
(function () {
  'use strict';
  var KEY = 'lw-last-failure-reference';
  var REF = /^lw-failure-[0-9a-f]{32}$/;
  function remember(reference) {
    if (typeof reference !== 'string' || !REF.test(reference)) return;
    try { sessionStorage.setItem(KEY, reference); } catch (_) { /* private mode: nothing to remember */ }
  }
  function lastReference() {
    try { var value = sessionStorage.getItem(KEY) || ''; return REF.test(value) ? value : ''; } catch (_) { return ''; }
  }
  // Remember the reference of the last error the server reported, from a
  // failed request or from the error page itself.
  if (typeof window.fetch === 'function' && !window.fetch.lwHelpMenu) {
    var original = window.fetch;
    var observed = function () {
      return original.apply(this, arguments).then(function (response) {
        try { if (response && response.status >= 500) remember(response.headers.get('X-Lightwork-Failure-Reference')); } catch (_) {}
        return response;
      });
    };
    observed.lwHelpMenu = true;
    window.fetch = observed;
  }
  var shown = document.querySelector('[data-failure-reference]');
  if (shown) remember(shown.getAttribute('data-failure-reference'));

  function context(path) {
    var out = {from: path};
    var task = /^\/(?:chat\/goal|goals|tasks)\/(\d{1,16})(?:\/|$)/.exec(path);
    if (task) out.task = task[1];
    var run = /\/runs\/([A-Za-z0-9_-]{1,64})(?:\/|$)/.exec(path);
    if (run) out.run = run[1];
    var failure = lastReference();
    if (failure) out.failure = failure;
    return out;
  }
  function requestHref(path) {
    var values = context(path);
    var query = Object.keys(values).map(function (name) { return encodeURIComponent(name) + '=' + encodeURIComponent(values[name]); }).join('&');
    return '/help?' + query + '#get-help';
  }
  document.querySelectorAll('[data-get-help]').forEach(function (link) {
    link.href = requestHref(location.pathname);
  });
  var menu = document.getElementById('help-menu');
  if (menu) {
    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape' && menu.open) { menu.open = false; var summary = menu.querySelector('summary'); if (summary) summary.focus(); }
    });
    document.addEventListener('click', function (event) { if (menu.open && !menu.contains(event.target)) menu.open = false; });
  }
  // On the Help page, open the "How this works" section the link points at.
  function openTopic() {
    if (!/^#how-[a-z0-9-]{1,40}$/.test(location.hash)) return;
    var section = document.getElementById(location.hash.slice(1));
    if (section && section.tagName === 'DETAILS') { section.open = true; section.scrollIntoView({block: 'start'}); }
  }
  openTopic();
  window.addEventListener('hashchange', openTopic);
  if (typeof module !== 'undefined' && module.exports) module.exports = {context: context, requestHref: requestHref};
})();
/* Help page: copy the reviewed "Get help from a person" request, and keep the
   email link in step with what the person edited. */
(function () {
  'use strict';
  var body = document.getElementById('get-help-body');
  if (!body) return;
  var copy = document.getElementById('get-help-copy');
  var email = document.getElementById('get-help-email');
  var status = document.getElementById('get-help-status');
  function sync() {
    if (!email) return;
    email.href = 'mailto:' + encodeURIComponent(body.dataset.helpEmail || '').replace(/%40/g, '@') +
      '?subject=' + encodeURIComponent(body.dataset.helpSubject || '') + '&body=' + encodeURIComponent(body.value);
  }
  body.addEventListener('input', sync);
  if (copy) copy.addEventListener('click', function () {
    if (typeof window.mvCopy === 'function') window.mvCopy(body.value);
    if (status) status.textContent = 'Copied. Paste it into an email or chat message to the person who helps you.';
  });
})();
