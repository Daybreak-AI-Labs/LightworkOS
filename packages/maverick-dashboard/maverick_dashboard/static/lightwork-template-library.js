(function () {
  'use strict';
  var cards = Array.from(document.querySelectorAll('[data-template-name]'));
  var suggest = document.getElementById('templates-suggested');
  var all = document.getElementById('templates-all');
  var status = document.getElementById('templates-status');
  if (!suggest) return;
  // A plain sentence for a failed request; never the server's raw wording.
  function failText(response, action) {
    var status = response && typeof response.status === 'number' ? response.status : 0;
    if (status === 400 || status === 422) return 'Check the details: each one needs a value, and the finished task must be short enough for Chat.';
    if (status === 404) return 'This template is no longer available. Refresh the page.';
    if (status === 409) return 'This template changed since you opened it. Refresh the page and try again. Your details are still here.';
    if (window.mvErrorText) return window.mvErrorText(response, action);
    return 'Could not ' + action + '. Try again.';
  }
  function plain(text) { var e = new Error(text); e.plain = true; return e; }
  var find = document.getElementById('tplm-find');
  var none = document.getElementById('tplm-none');
  var filter = {mode: 'all', names: [], notice: '', request: 0};
  function renderFilters() {
    var query = find ? find.value.trim().toLowerCase() : '';
    var ordered = cards.slice(); var shown = 0;
    if (filter.mode === 'suggested') ordered.sort(function (a, b) {
      return filter.names.indexOf(a.dataset.templateName) - filter.names.indexOf(b.dataset.templateName);
    });
    ordered.forEach(function (card) {
      card.hidden = (filter.mode === 'suggested' && !filter.names.includes(card.dataset.templateName)) ||
        Boolean(query && (card.dataset.tplmText || '').indexOf(query) === -1);
      if (!card.hidden) shown++;
      card.parentElement.append(card);
    });
    if (none) none.hidden = shown !== 0;
    all.hidden = filter.mode === 'all';
    suggest.setAttribute('aria-pressed', String(filter.mode === 'suggested'));
    status.textContent = (filter.notice ? filter.notice + ' ' : '') + shown +
      (shown === 1 ? ' template' : ' templates') + (filter.mode === 'suggested' ? ' suggested for you' : '') +
      (query ? ' matching your search.' : '.');
  }
  if (find) find.addEventListener('input', renderFilters);
  cards.forEach(function (card) {
    var open = card.querySelector('[data-prepare-template]');
    if (!open) return;
    var form = card.querySelector('.template-prepare');
    open.addEventListener('click', function () { form.hidden = false; var first = form.querySelector('input, select, textarea, button'); if (first) first.focus(); });
    form.querySelector('[data-cancel-prepare]').addEventListener('click', function () { form.hidden = true; open.focus(); });
    function refreshInputs() {
      var values={}; form.querySelectorAll('[data-template-param]').forEach(function (input) { values[input.dataset.templateParam]=input.value; });
      form.querySelectorAll('[data-parameter-row]').forEach(function (row) {
        var when=JSON.parse(row.dataset.showWhen || '{}'), input=row.querySelector('[data-template-param]');
        row.hidden=Boolean(when.field && values[when.field] !== when.value); input.disabled=row.hidden;
        row.querySelector('.parameter-error').textContent=input.validity.valid || row.hidden ? '' : input.validationMessage;
      });
    }
    form.addEventListener('input',refreshInputs); form.addEventListener('change',refreshInputs); refreshInputs();
    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      var button = form.querySelector('[type="submit"]'); var message = form.querySelector('.prepare-status');
      if (button.disabled || !form.reportValidity()) return;
      var params = Object.create(null);
      form.querySelectorAll('[data-template-param]').forEach(function (input) { params[input.dataset.templateParam] = input.disabled ? '' : input.value; });
      button.disabled = true; message.textContent = 'Preparing your task…';
      try {
        var response = await fetch('/api/v1/templates/' + encodeURIComponent(card.dataset.templateName) + '/prepare', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({params:params})});
        if (!response.ok) throw plain(failText(response, 'prepare the task'));
        var result = await response.json();
        if (result.started !== false || typeof result.title !== 'string' || typeof result.description !== 'string' || typeof result.context !== 'string') throw plain('The task could not be prepared. Your details are still here. Try again.');
        sessionStorage.setItem('lightwork:template-draft:v1', JSON.stringify({title:result.title, description:result.description, context:result.context, connection_references:result.connection_references || [], created_at:Date.now()}));
        window.location.assign('/chat');
      } catch (error) { message.textContent = error && error.plain ? error.message : failText(error, 'prepare the task'); button.disabled = false; }
    });
  });
  all.addEventListener('click', function () {
    filter.request++; filter.mode = 'all'; filter.notice = ''; renderFilters();
  });
  suggest.addEventListener('click', async function () {
    if (suggest.disabled) return;
    var request = ++filter.request;
    suggest.disabled = true; status.textContent = 'Finding suggestions.';
    try {
      var response = await fetch('/api/v1/templates/suggested', {cache:'no-store'});
      if (!response.ok) throw plain('Suggestions are unavailable. Refresh the page and try again.');
      var result = await response.json();
      if (!Array.isArray(result.suggested)) throw plain('Suggestions could not be read. Refresh the page and try again.');
      if (request !== filter.request) return;
      filter.names = result.suggested.map(function (item) { return item.name; });
      filter.mode = filter.names.length ? 'suggested' : 'all';
      filter.notice = filter.names.length ? 'Review suggestions before use.' : 'No suggestions yet. Browse all templates below.';
      renderFilters();
    } catch (error) {
      if (request !== filter.request) return;
      filter.mode = 'all'; filter.notice = 'Suggestions are unavailable. You can still search all templates.'; renderFilters();
    } finally { suggest.disabled = false; }
  });
  renderFilters();
  document.querySelectorAll('.template-rating').forEach(function (form) {
    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      var button = form.querySelector('button'); var input = form.querySelector('select');
      if (button.disabled || !form.reportValidity()) return;
      var card = form.closest('[data-template-name]'); var message = form.querySelector('.rating-status');
      var stars = Number(input.value);
      button.disabled = true; input.disabled = true; message.textContent = 'Saving…';
      try {
        var response = await fetch('/api/v1/templates/' + encodeURIComponent(card.dataset.templateName) + '/rating', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({stars:stars})});
        if (!response.ok) throw plain(failText(response, 'save the rating'));
        var result = await response.json();
        if (result.saved !== true || result.name !== card.dataset.templateName || result.stars !== stars) throw plain('The rating could not be confirmed. Try again.');
        card.querySelector('.tplm__stars').textContent = '★'.repeat(stars) + '☆'.repeat(5-stars);
        message.textContent = 'Rating saved.';
      } catch (error) { message.textContent = error && error.plain ? error.message : failText(error, 'save the rating'); }
      finally { button.disabled = false; input.disabled = false; }
    });
  });
})();
