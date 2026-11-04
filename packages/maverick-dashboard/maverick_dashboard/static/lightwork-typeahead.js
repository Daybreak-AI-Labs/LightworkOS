/* Shared typeahead: a <select data-typeahead> with hundreds of options becomes
   a search box with suggestions. The <select> stays in the document (hidden)
   as the value the page reads and submits; typing a suggestion sets it and
   fires its change event. Works with a native <datalist>, so it is keyboard
   and screen-reader accessible without extra widgetry. */
(function () {
  'use strict';
  var counter = 0;
  function enhance(select) {
    if (select.dataset.typeaheadReady) return;
    select.dataset.typeaheadReady = '1';
    var options = Array.prototype.slice.call(select.options).filter(function (o) { return o.value !== ''; });
    var byLabel = {}, byValue = {};
    options.forEach(function (o) { byLabel[o.textContent.trim().toLowerCase()] = o.value; byValue[o.value] = o.textContent.trim(); });
    var id = 'mv-typeahead-' + (++counter);
    var input = document.createElement('input');
    input.type = 'search'; input.className = select.className || 'input'; input.setAttribute('list', id);
    input.autocomplete = 'off'; input.id = select.id ? select.id + '-typeahead' : id + '-input';
    input.placeholder = select.dataset.typeaheadPlaceholder || ('Type to search ' + options.length.toLocaleString() + ' choices…');
    var label = select.id ? document.querySelector('label[for="' + select.id + '"]') : null;
    if (label) label.setAttribute('for', input.id);
    else if (select.getAttribute('aria-label')) input.setAttribute('aria-label', select.getAttribute('aria-label'));
    if (select.getAttribute('aria-describedby')) input.setAttribute('aria-describedby', select.getAttribute('aria-describedby'));
    var list = document.createElement('datalist'); list.id = id;
    options.forEach(function (o) { var opt = document.createElement('option'); opt.value = o.textContent.trim(); list.appendChild(opt); });
    var status = document.createElement('span'); status.className = 'mv-typeahead__status sr-only'; status.setAttribute('aria-live', 'polite');
    if (select.value && byValue[select.value]) input.value = byValue[select.value];
    function apply() {
      var key = input.value.trim().toLowerCase();
      var value = Object.prototype.hasOwnProperty.call(byLabel, key) ? byLabel[key] : '';
      if (!value && key) {
        // One partial match is as good as a pick: "oil" -> "Oil & Gas".
        var hits = Object.keys(byLabel).filter(function (l) { return l.indexOf(key) !== -1; });
        if (hits.length === 1) { value = byLabel[hits[0]]; input.value = byValue[value]; }
      }
      if (select.value !== value) { select.value = value; select.dispatchEvent(new Event('change', {bubbles: true})); }
      status.textContent = value ? 'Chosen: ' + byValue[value] : (key ? 'No exact match yet; keep typing or pick a suggestion.' : '');
    }
    input.addEventListener('change', apply);
    input.addEventListener('input', function () { if (!input.value.trim() && select.value) { select.value = ''; select.dispatchEvent(new Event('change', {bubbles: true})); } });
    select.hidden = true; select.setAttribute('aria-hidden', 'true'); select.tabIndex = -1;
    select.insertAdjacentElement('afterend', input);
    input.insertAdjacentElement('afterend', list);
    list.insertAdjacentElement('afterend', status);
    var form = select.form;
    if (form) form.addEventListener('submit', apply);
  }
  window.mvTypeahead = enhance;
  document.querySelectorAll('select[data-typeahead]').forEach(enhance);
})();
