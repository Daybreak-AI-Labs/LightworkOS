(function () {
  'use strict';
  var payload = document.getElementById('lightwork-i18n-data'), data = {language: 'en', locale: 'en', catalog: {}};
  try { if (payload) data = JSON.parse(payload.textContent); } catch (_) { /* Honest English fallback. */ }
  // The synchronous, content-addressed asset precedes this script. A missing or
  // mismatched asset retains the same honest English fallback as unknown copy.
  if (!data.catalog && window.LightworkJourneyCatalog && window.LightworkJourneyCatalog.language === data.language) {
    data.catalog = window.LightworkJourneyCatalog.catalog;
  }
  // A bounded page-local record preserves language when a product formatter's
  // string result is subsequently handed to a status or toast controller.
  var formatted = new Map();
  function lookup(source) { return Object.prototype.hasOwnProperty.call(data.catalog || {}, source) ? data.catalog[source] : formatted.get(source) || {text: source, lang: 'en'}; }
  function text(source, values) {
    var row = lookup(source), value = row.text.replace(/\{([A-Za-z0-9_]+)\}/g, function (whole, name) { return values && Object.prototype.hasOwnProperty.call(values, name) ? String(values[name]) : whole; });
    if (formatted.size >= 256) formatted.delete(formatted.keys().next().value);
    formatted.set(value, {text:value, lang:row.lang}); return value;
  }
  function set(element, source, values) {
    if (!element || element.closest('[data-user-content]')) return;
    var row = lookup(source), cursor = 0, match, pattern = /\{([A-Za-z0-9_]+)\}/g;
    element.replaceChildren();
    while ((match = pattern.exec(row.text))) {
      element.appendChild(document.createTextNode(row.text.slice(cursor, match.index)));
      if (values && Object.prototype.hasOwnProperty.call(values, match[1])) {
        var value = document.createElement('bdi'); value.lang = 'und'; value.dir = 'auto';
        value.dataset.userContent = ''; value.textContent = String(values[match[1]]); element.appendChild(value);
      } else element.appendChild(document.createTextNode(match[0]));
      cursor = match.index + match[0].length;
    }
    element.appendChild(document.createTextNode(row.text.slice(cursor))); element.lang = row.lang;
    element.dir = row.lang === 'ar' ? 'rtl' : 'ltr'; element.dataset.productCopy = '';
  }
  function number(value, options) {
    var numeric = Number(value); if (!Number.isFinite(numeric)) return String(value);
    return new Intl.NumberFormat(data.locale || data.language || 'en', options || {}).format(numeric);
  }
  function browserLocale() {
    var wanted = [].concat(navigator.languages || [], navigator.language || []);
    for (var i = 0; i < wanted.length; i++) {
      try { if (wanted[i] && Intl.DateTimeFormat.supportedLocalesOf([wanted[i]]).length) return wanted[i]; } catch (_) { /* next */ }
    }
    return 'en-GB';
  }
  function formatDate(value, options) {
    // A product date without a time is a calendar date, not UTC midnight.
    var parts = typeof value === 'string' && /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
    var date = parts ? new Date(Number(parts[1]), Number(parts[2])-1, Number(parts[3])) : value instanceof Date ? value : new Date(typeof value === 'number' || /^\d+(?:\.\d+)?$/.test(value) ? Number(value) * 1000 : value);
    if (Number.isNaN(date.getTime())) return text('Unknown');
    // The same choice as mvTimeAbsolute in lightwork-ui.js: English pages follow
    // the reader's browser ("Oct 4, 2026, 2:01 PM EDT" in en-US, "4 Oct 2026,
    // 19:01 BST" in en-GB); a translated interface uses its locale.
    var day = {day: 'numeric', month: 'short', year: 'numeric'};
    var locale = !data.language || data.language === 'en' ? browserLocale() : data.locale || data.language;
    return new Intl.DateTimeFormat(locale, options || (parts ? day : Object.assign({hour: 'numeric', minute: '2-digit', timeZoneName: 'short'}, day))).format(date);
  }
  function plural(one, other, count) {
    var category = new Intl.PluralRules(data.locale || data.language || 'en').select(Number(count));
    return text(category === 'one' ? one : other, {count: number(count)});
  }
  function validation(form) {
    if (!form || form.dataset.productValidationBound) return;
    form.dataset.productValidationBound = 'true';
    form.addEventListener('invalid', function (event) {
      var field = event.target, validity = field.validity;
      if (!validity || validity.customError || !field.setCustomValidity) return;
      var source = validity.valueMissing ? 'Complete this field.' : validity.tooLong ? 'This value is too long.' : validity.typeMismatch ? 'Enter a valid value.' : 'Check this value.';
      var message = field._productValidationMessage;
      if (!message) {
        message = document.createElement('span'); message.className = 'product-validation'; message.setAttribute('role', 'alert');
        message.id = 'product-validation-' + Math.random().toString(36).slice(2);
        field.insertAdjacentElement('afterend', message); field._productValidationMessage = message;
        field.setAttribute('aria-describedby', [field.getAttribute('aria-describedby'), message.id].filter(Boolean).join(' '));
      }
      set(message, source); message.hidden = false; field.setCustomValidity(text(source));
    }, true);
    function clear(event) {
      var field = event.target;
      if (field._productValidationMessage) { field.setCustomValidity(''); field._productValidationMessage.hidden = true; }
    }
    form.addEventListener('input', clear); form.addEventListener('change', clear);
  }
  function translate(root) {
    (root || document).querySelectorAll('[data-i18n]').forEach(function (element) { set(element, element.getAttribute('data-i18n')); });
    (root || document).querySelectorAll('[data-product-date]').forEach(function (element) { if (!element.closest('[data-user-content]')) { element.textContent = formatDate(element.dataset.productDate); element.lang = data.locale || data.language; element.dir = 'auto'; } });
    (root || document).querySelectorAll('[data-product-number]').forEach(function (element) { if (!element.closest('[data-user-content]')) { element.textContent = number(element.dataset.productNumber); element.lang = data.locale || data.language; element.dir = 'auto'; } });
    (root || document).querySelectorAll('form[data-product-validation]').forEach(validation);
    // lightwork-ui.js formatted server times before this locale was known.
    if (data.language && data.language !== 'en' && window.mvFormatTimes) window.mvFormatTimes(root || document);
  }
  window.LightworkI18n = {text: text, set: set, languageFor: function (source) { return lookup(source).lang; }, has: function (source) { return Object.prototype.hasOwnProperty.call(data.catalog || {}, source); },
    number: number, formatDate: formatDate, plural: plural, translate: translate, validation: validation, locale: data.locale, language: data.language};
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function () { translate(); }); else translate();
})();
