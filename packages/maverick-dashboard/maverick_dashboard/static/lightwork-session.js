/* Sign-in timer (WCAG 2.2.1 Timing Adjustable).
 *
 * Two minutes before this browser's sign-in ends, ask whether to stay signed
 * in. A local sign-in is kept going in place (POST /auth/session/renew); a
 * company sign-in signs in again with the identity provider. When the sign-in
 * has ended, say so, keep what was typed on this page (this tab only, never
 * passwords, files or secret-looking fields) and come back here after
 * signing in again, with the typed values put back.
 *
 * The page's <meta name="lightwork-session-*"> tags carry the end time, the
 * server clock, how to stay signed in and where to sign in. Another tab may
 * have kept the session going, so the current end is read again before any
 * warning or notice.
 */
(function () {
  'use strict';
  var WARN_SECONDS = 120, KEEP_MINUTES = 120, LONGEST_WAIT = 6 * 3600 * 1000;
  var SECRET = /pass|secret|token|key|otp|code/i;
  function meta(name) { var m = document.querySelector('meta[name="' + name + '"]'); return m ? m.getAttribute('content') || '' : ''; }
  function t(text, values) {
    if (window.LightworkI18n) return window.LightworkI18n.text(text, values);
    return values ? text.replace(/\{([a-z]+)\}/g, function (whole, name) { return name in values ? String(values[name]) : whole; }) : text;
  }
  var here = window.location.pathname + window.location.search;
  var KEY = 'lightwork.session-kept:' + here;
  var signIn = meta('lightwork-session-sign-in') || '/auth/local-login';
  var renews = meta('lightwork-session-renew') === 'renew';
  var ends = parseInt(meta('lightwork-session-expires'), 10) || 0;
  var idleMinutes = parseInt(meta('lightwork-session-idle-minutes'), 10) || 0;
  var activityAt = 0, activityPending = null, statusTimer = null;
  // Server clock minus this computer's, so a wrong local clock never warns early or late.
  var skew = (parseInt(meta('lightwork-session-now'), 10) || Date.now() / 1000) - Date.now() / 1000;
  var timer = null, warned = false, asking = false, notice = null;

  function now() { return Date.now() / 1000 + skew; }
  function signInUrl() {
    return signIn + (signIn.indexOf('?') >= 0 ? '&' : '?') + 'return_to=' + encodeURIComponent(here);
  }

  // ---- keep what was typed ------------------------------------------------
  function keepable(c) {
    return c.name && !/^(password|file|hidden|submit|button|reset|image)$/.test(c.type || '') &&
      !SECRET.test(c.name) && !SECRET.test(c.id || '') && c.autocomplete !== 'one-time-code' &&
      !c.hasAttribute('data-mv-keep-off') && !c.disabled;
  }
  function formKey(form, index) { return form.id ? '#' + form.id : (form.getAttribute('action') || '') + '@' + index; }
  function snapshot() {
    var forms = [];
    Array.prototype.forEach.call(document.forms, function (form, index) {
      var values = {}, any = false;
      Array.prototype.forEach.call(form.elements, function (c) {
        if (!keepable(c)) return;
        if (c.type === 'checkbox' || c.type === 'radio') {
          values[c.name] = values[c.name] || [];
          if (c.checked) { values[c.name].push(c.value); any = true; }
        } else if (c.value) { values[c.name] = c.value; any = true; }
      });
      if (any) forms.push({key: formKey(form, index), values: values});
    });
    try {
      if (forms.length) sessionStorage.setItem(KEY, JSON.stringify({at: Date.now(), forms: forms}));
    } catch (_) { /* private mode: nothing more can be kept */ }
    return forms.length;
  }
  function untouched(c) {
    if (c.tagName === 'SELECT') {
      var shown = null, i;
      for (i = 0; i < c.options.length; i += 1) { if (c.options[i].defaultSelected) { shown = c.options[i]; break; } }
      return c.value === (shown ? shown.value : (c.options.length && !c.multiple ? c.options[0].value : ''));
    }
    return !c.value || c.value === c.defaultValue;
  }
  function restore() {
    var saved = null;
    try { saved = JSON.parse(sessionStorage.getItem(KEY) || 'null'); sessionStorage.removeItem(KEY); } catch (_) { return; }
    if (!saved || !Array.isArray(saved.forms) || Date.now() - saved.at > KEEP_MINUTES * 60000) return;
    var put = 0;
    Array.prototype.forEach.call(document.forms, function (form, index) {
      var entry = saved.forms.filter(function (f) { return f.key === formKey(form, index); })[0];
      if (!entry) return;
      Array.prototype.forEach.call(form.elements, function (c) {
        if (!keepable(c) || !(c.name in entry.values)) return;
        var v = entry.values[c.name];
        if (c.type === 'checkbox' || c.type === 'radio') c.checked = Array.isArray(v) && v.indexOf(c.value) >= 0;
        else if (untouched(c)) c.value = v;
        else return;
        c.dispatchEvent(new Event('input', {bubbles: true}));
        c.dispatchEvent(new Event('change', {bubbles: true}));
        put += 1;
      });
    });
    if (put) say(t('You are signed in again. What you typed before is back on this page. Check it, then save.'), false);
  }

  // ---- notices ---------------------------------------------------------------
  function say(text, ended) {
    if (!notice) {
      notice = document.createElement('div');
      notice.className = 'panel mv-session-notice';
      notice.setAttribute('role', ended ? 'alert' : 'status');
      var main = document.querySelector('main') || document.body;
      main.insertBefore(notice, main.firstChild);
    }
    notice.setAttribute('role', ended ? 'alert' : 'status');
    notice.textContent = '';
    var line = document.createElement('p'); line.textContent = text; notice.appendChild(line);
    if (ended) {
      var again = document.createElement('a');
      again.className = 'btn'; again.href = signInUrl(); again.textContent = t('Sign in again');
      again.addEventListener('click', function () { snapshot(); });
      notice.appendChild(again);
    }
    return notice;
  }
  function ended() {
    clearTimeout(timer);
    clearInterval(statusTimer);
    var kept = snapshot();
    say(t(kept ? 'Your sign-in has ended. What you typed on this page is kept. Sign in again to come back here and carry on.'
      : 'Your sign-in has ended. Sign in again to come back to this page.'), true);
    var link = notice.querySelector('a'), at = document.activeElement;
    var typing = at && (/^(INPUT|TEXTAREA|SELECT)$/.test(at.tagName) || at.isContentEditable);
    if (link && !typing) link.focus();
  }

  // ---- the timer -----------------------------------------------------------
  async function current() {
    try {
      var d = await window.mvFetchJSON('/auth/session/status', {cache: 'no-store', timeout: 15000}, 'check your sign-in');
      if (!d || d.signed_in !== true) return 0;
      skew = (d.now || Date.now() / 1000) - Date.now() / 1000;
      idleMinutes = d.idle_minutes || 0;
      return d.expires_at;
    } catch (_) { return ends; }   // offline: keep the time the page was given
  }
  function schedule() {
    clearTimeout(timer);
    var left = ends - now();
    var wait = (warned ? left : left - warningSeconds()) * 1000;
    timer = setTimeout(check, Math.max(0, Math.min(wait, LONGEST_WAIT)));
  }
  function warningSeconds() { return idleMinutes ? Math.min(WARN_SECONDS, idleMinutes * 15) : WARN_SECONDS; }
  async function activity(force) {
    if (activityPending) return activityPending;
    if (!ends || !idleMinutes || (!force && Date.now() - activityAt < Math.min(60000, idleMinutes * 15000))) return false;
    activityAt = Date.now();
    activityPending = (async function () {
      try {
        var d = await window.mvFetchJSON('/auth/session/activity', {method: 'POST', timeout: 15000}, 'keep your active sign-in current');
        if (!d || !d.expires_at) return false;
        skew = (d.now || Date.now() / 1000) - Date.now() / 1000;
        ends = d.expires_at; warned = false; schedule();
        return true;
      } catch (_) { return false; } // Failed activity never invents a later expiry.
      finally { activityPending = null; }
    }());
    return activityPending;
  }
  async function stay() {
    if (idleMinutes && await activity(true) && ends - now() > warningSeconds() + 1) return;
    if (!renews) { snapshot(); window.location.assign(signInUrl()); return; }
    try {
      // A company sign-in answers 409 here: it signs in again below instead.
      var d = await window.mvFetchJSON('/auth/session/renew', {method: 'POST', timeout: 15000}, 'keep you signed in');
      if (d && d.expires_at) {
        ends = d.expires_at; warned = false; schedule();
        if (window.mvToast) window.mvToast(t('You are still signed in.'), {quiet: true});
        return;
      }
    } catch (_) { /* fall through to signing in again */ }
    if (ends - now() > 0) { snapshot(); window.location.assign(signInUrl()); } else ended();
  }
  async function check() {
    ends = await current();
    var left = ends - now();
    if (!ends || left <= 0) { ended(); return; }
    if (left > warningSeconds() + 5) { warned = false; schedule(); return; }   // kept going elsewhere
    if (warned || asking) { warned = true; schedule(); return; }
    warned = true; schedule();
    var minutes = Math.max(1, Math.round(left / 60));
    var message = (minutes === 1 ? t('Your sign-in ends in about 1 minute.')
      : t('Your sign-in ends in about {minutes} minutes.', {minutes: minutes})) + ' ' +
      t('Stay signed in to keep working. What you typed stays on this page either way.');
    asking = true;
    var ok = false;
    try { ok = window.mvConfirm ? await window.mvConfirm(message, {okText: 'Stay signed in', cancelText: 'Not now'}) : false; }
    finally { asking = false; }
    if (ok) await stay();
  }

  restore();
  if (ends) {
    schedule();
    ['pointerdown', 'keydown', 'wheel', 'touchstart'].forEach(function (name) {
      document.addEventListener(name, function (event) {
        if (event.isTrusted && !document.hidden) activity(false);
      }, {passive: true});
    });
    // Current policy and other tabs may change the end time; reading never counts as activity.
    statusTimer = setInterval(async function () {
      if (document.hidden) return;
      var previous = ends; ends = await current();
      if (!ends || ends <= now()) { ended(); return; }
      if (ends !== previous) { warned = false; schedule(); }
    }, 60000);
  }
  window.LightworkSession = {check: check, snapshot: snapshot, restore: restore};
}());
