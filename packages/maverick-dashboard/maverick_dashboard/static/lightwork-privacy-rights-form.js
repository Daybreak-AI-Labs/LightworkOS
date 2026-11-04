// Rights request form administration: properties (one public form per
// website or app), the public link and embed snippet, and the email
// templates the tracker sends, saved as numbered versions.
(function () {
  'use strict';
  var doc = document;
  var page = doc.getElementById('prf-page');
  if (!page) return;
  var canAdmin = page.getAttribute('data-can-admin') === 'yes';
  var BASE = '/api/v1/privacy/rights-form';
  var regimes = null;
  var templates = null;

  function $(id) { return doc.getElementById(id); }
  function text(el, value) { if (el) el.textContent = value; }
  function fail(el, failure, action) {
    // Turned off is not "no permission": offer Turn on in place when allowed.
    if (window.mvShowFeatureOff && window.mvShowFeatureOff(el, failure, action)) return;
    text(el, window.mvErrorText ? window.mvErrorText(failure, action) : 'Could not ' + action + '. Try again.');
  }
  function call(method, url, body) {
    return window.mvFetchJSON(url, { method: method, body: body });
  }
  function el(tag, attrs, children) {
    var node = doc.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === 'text') node.textContent = attrs[k]; else node.setAttribute(k, attrs[k]);
    });
    (children || []).forEach(function (c) { node.appendChild(c); });
    return node;
  }

  // ----- properties -------------------------------------------------------
  function checkbox(container, name, value, label, checked) {
    var input = el('input', { type: 'checkbox', name: name, value: value });
    input.checked = !!checked;
    container.appendChild(el('label', {}, [input, doc.createTextNode(' ' + label)]));
    return input;
  }
  function renderChoices(selected) {
    var jur = $('prf-jurisdictions'); jur.textContent = '';
    var def = $('prf-default'); def.textContent = '';
    regimes.regimes.forEach(function (r) {
      var box = checkbox(jur, 'jurisdictions', r.id, r.name, selected.jurisdictions.indexOf(r.id) !== -1);
      box.title = r.citation;
      box.addEventListener('change', syncDefault);
    });
    var unverified = regimes.unverified.map(function (u) { return u.name; });
    text($('prf-unverified'), unverified.length
      ? 'Not offered until verified against its source: ' + unverified.join('; ') + '.'
      : '');
    var types = $('prf-types'); types.textContent = '';
    regimes.request_types.forEach(function (t) {
      checkbox(types, 'request_types', t.id, t.label, selected.request_types.indexOf(t.id) !== -1);
    });
    syncDefault(selected.default_jurisdiction);
  }
  function syncDefault(keep) {
    var def = $('prf-default');
    var current = typeof keep === 'string' ? keep : def.value;
    def.textContent = '';
    doc.querySelectorAll('#prf-jurisdictions input:checked').forEach(function (box) {
      var name = (regimes.regimes.filter(function (r) { return r.id === box.value; })[0] || {}).name || box.value;
      def.appendChild(el('option', { value: box.value, text: name }));
    });
    if (current) def.value = current;
  }
  function fillForm(p) {
    var form = $('prf-property-form');
    form.slug.value = p.slug || ''; form.slug.readOnly = !!p.slug;
    form.name.value = p.name || ''; form.organisation.value = p.organisation || '';
    form.contact_email.value = p.contact_email || '';
    form.privacy_policy_url.value = p.privacy_policy_url || '';
    form.allowed_origins.value = (p.allowed_origins || []).join('\n');
    form.enabled.checked = p.enabled !== false;
    renderChoices({
      jurisdictions: p.jurisdictions || [],
      request_types: p.request_types || regimes.request_types.map(function (t) { return t.id; }),
      default_jurisdiction: p.default_jurisdiction || ''
    });
    text($('prf-editor-title'), p.slug ? 'Edit “' + p.name + '”' : 'Add a property');
  }
  function renderProperties(rows) {
    var box = $('prf-properties'); box.textContent = '';
    if (!rows.length) { box.appendChild(el('p', { class: 'muted', text: 'No properties yet. Add one on the right.' })); return; }
    rows.forEach(function (p) {
      var link = el('a', { href: p.public_url, target: '_blank', rel: 'noopener', text: p.public_url });
      var snippet = el('textarea', { class: 'textarea prf-snippet', readonly: '', rows: '2', 'aria-label': 'Embed code for ' + p.name });
      snippet.value = p.embed_snippet;
      var edit = el('button', { type: 'button', class: 'btn', text: 'Edit' });
      edit.addEventListener('click', function () { fillForm(p); $('prf-property-form').scrollIntoView(); });
      var copy = el('button', { type: 'button', class: 'btn btn--ghost', text: 'Copy link' });
      copy.addEventListener('click', function () {
        if (navigator.clipboard) navigator.clipboard.writeText(p.public_url);
        text(status, 'Link copied.');
      });
      var status = el('span', { role: 'status', class: 'muted' });
      var actions = [edit, copy];
      if (canAdmin) {
        var del = el('button', { type: 'button', class: 'btn btn--danger', text: 'Delete' });
        del.addEventListener('click', function () {
          // One action with a way back: the form's page keeps working
          // until the Undo time is up, then the form is deleted.
          var card = del.closest('.panel');
          if (card) card.hidden = true;
          window.mvUndo('Form for {name} deleted. Its page stops working.', { values: {name: p.name},
            action: 'delete the property',
            run: function (keepalive) { return fetch(BASE + '/properties/' + encodeURIComponent(p.slug), { method: 'DELETE', keepalive: keepalive, headers: { Accept: 'application/json' } }); },
            undo: function () { if (card) card.hidden = false; del.focus(); },
            done: function () { return loadProperties(); }
          });
        });
        actions.push(del);
      }
      actions.push(status);
      box.appendChild(el('div', { class: 'panel', style: 'margin-bottom: var(--space-3);' }, [
        el('h3', { style: 'margin-top:0;', text: p.name + (p.enabled ? '' : ' (off)') }),
        el('p', { class: 'muted', text: p.organisation + ' · ' + (p.jurisdictions || []).length + ' law(s) · ' + (p.request_types || []).length + ' request type(s)' }),
        el('p', {}, [link]),
        el('p', { class: 'muted', text: 'Preview the public page with the link above. To put the form on your own site, paste this:' }),
        snippet,
        el('div', { class: 'prf-actions' }, actions)
      ]));
    });
  }
  function loadProperties() {
    return call('GET', BASE + '/properties').then(function (data) { renderProperties(data.properties); })
      .catch(function (f) { fail($('prf-properties'), f, 'load the properties'); });
  }
  $('prf-property-form').addEventListener('submit', function (ev) {
    ev.preventDefault();
    var form = ev.target; var msg = $('prf-property-msg');
    var body = {
      name: form.name.value, organisation: form.organisation.value,
      contact_email: form.contact_email.value, privacy_policy_url: form.privacy_policy_url.value,
      default_jurisdiction: $('prf-default').value,
      jurisdictions: Array.prototype.map.call(doc.querySelectorAll('#prf-jurisdictions input:checked'), function (b) { return b.value; }),
      request_types: Array.prototype.map.call(doc.querySelectorAll('#prf-types input:checked'), function (b) { return b.value; }),
      allowed_origins: form.allowed_origins.value.split('\n').map(function (s) { return s.trim(); }).filter(Boolean),
      enabled: form.enabled.checked
    };
    text(msg, 'Saving…');
    call('PUT', BASE + '/properties/' + encodeURIComponent(form.slug.value.trim().toLowerCase()), body)
      .then(function () { text(msg, 'Saved.'); form.slug.readOnly = true; return loadProperties(); })
      .catch(function (f) { fail(msg, f, 'save the property'); });
  });
  $('prf-new').addEventListener('click', function () { fillForm({}); });

  // ----- templates --------------------------------------------------------
  function currentTemplate() {
    var family = $('prf-family').value, kind = $('prf-kind').value;
    return templates.templates.filter(function (t) { return t.family === family && t.kind === kind; })[0];
  }
  function showTemplate() {
    var t = currentTemplate(); if (!t) return;
    var form = $('prf-template-form');
    form.subject.value = t.subject; form.body.value = t.body;
    text($('prf-template-version'), t.source === 'default' ? 'Shipped wording (version 0)' : 'Version ' + t.version + ' saved by ' + (t.saved_by || 'an administrator'));
  }
  function loadTemplates() {
    return call('GET', BASE + '/templates').then(function (data) {
      templates = data;
      var fam = $('prf-family'), kind = $('prf-kind');
      if (!fam.options.length) {
        data.families.forEach(function (f) { fam.appendChild(el('option', { value: f.id, text: f.label })); });
        data.kinds.forEach(function (k) { kind.appendChild(el('option', { value: k.id, text: k.label })); });
        var list = $('prf-placeholders');
        Object.keys(data.placeholders).forEach(function (name) {
          list.appendChild(el('li', {}, [el('code', { text: '{' + name + '}' }), doc.createTextNode(' ' + data.placeholders[name])]));
        });
      }
      showTemplate();
    }).catch(function (f) { fail($('prf-template-msg'), f, 'load the templates'); });
  }
  $('prf-family').addEventListener('change', showTemplate);
  $('prf-kind').addEventListener('change', showTemplate);
  $('prf-template-form').addEventListener('submit', function (ev) {
    ev.preventDefault();
    var msg = $('prf-template-msg'); var form = ev.target;
    text(msg, 'Saving…');
    call('PUT', BASE + '/templates/' + $('prf-family').value + '/' + $('prf-kind').value,
      { subject: form.subject.value, body: form.body.value })
      .then(function () { text(msg, 'Saved.'); return loadTemplates(); })
      .catch(function (f) { fail(msg, f, 'save the template'); });
  });
  $('prf-template-reset').addEventListener('click', function () {
    var msg = $('prf-template-msg');
    call('POST', BASE + '/templates/' + $('prf-family').value + '/' + $('prf-kind').value + '/reset')
      .then(function () { text(msg, 'Back to the shipped wording.'); return loadTemplates(); })
      .catch(function (f) { fail(msg, f, 'reset the template'); });
  });

  if (!canAdmin) {
    ['prf-save', 'prf-template-save', 'prf-template-reset'].forEach(function (id) { var b = $(id); if (b) b.disabled = true; });
  }
  call('GET', BASE + '/regimes').then(function (data) { regimes = data; fillForm({}); return loadProperties(); })
    .then(loadTemplates)
    .catch(function (f) { fail($('prf-property-msg'), f, 'load the form settings'); });
})();
