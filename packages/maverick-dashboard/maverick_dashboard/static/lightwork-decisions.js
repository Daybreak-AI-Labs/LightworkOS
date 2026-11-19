// Decisions a run is waiting for, on the Approvals page. Each card shows the
// question, the options with what each one does, and the run's
// recommendation. Choosing an option sends it; the run then continues.
(function () {
  'use strict';
  var root = document.getElementById('decision-requests');
  if (!root || typeof window.mvFetchJSON !== 'function') return;
  var list = root.querySelector('[data-decision-list]');
  var stateBox = document.getElementById('approvals-current-state');
  function count(n) { if (stateBox) stateBox.dataset.decisionCount = String(Math.max(0, n)); }
  var status = root.querySelector('[data-decision-status]');

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (text != null) node.textContent = text;
    if (cls) node.className = cls;
    return node;
  }

  function when(seconds) {
    try { return new Date(seconds * 1000).toLocaleString(); } catch (_) { return ''; }
  }

  function card(d) {
    var item = el('article', 'approval-item', null);
    item.id = 'decision-' + d.id;
    var head = el('div', 'approval-item__head', null);
    var title = el('h3', 'approval-item__title', d.question);
    title.id = 'decision-title-' + d.id;
    item.setAttribute('aria-labelledby', title.id);
    head.appendChild(title);
    head.appendChild(el('span', 'badge pending', d.area_label));
    item.appendChild(head);
    item.appendChild(el('p', null, 'Lightwork recommends option ' + d.recommended + '. ' + d.reason));
    item.appendChild(el('p', 'muted', 'Decide by ' + when(d.expires_at) + '. With no answer by then, the run stops without choosing.'));
    var form = el('form');
    var set = el('fieldset');
    set.appendChild(el('legend', null, 'Options'));
    d.options.forEach(function (o) {
      var row = el('div', 'decision-option', null);
      var input = el('input');
      input.type = 'radio'; input.name = 'decision-' + d.id; input.value = String(o.number);
      input.id = 'decision-' + d.id + '-option-' + o.number;
      input.required = true;
      if (!d.can_answer) input.disabled = true;
      var label = el('label');
      label.htmlFor = input.id;
      label.appendChild(el('strong', null, o.number + '. ' + o.label + (o.number === d.recommended ? ' (recommended)' : '')));
      label.appendChild(el('span', null, ' ' + o.effect));
      row.appendChild(input); row.appendChild(label);
      set.appendChild(row);
    });
    form.appendChild(set);
    var noteId = 'decision-' + d.id + '-note';
    var noteField = el('div', 'field decision-note', null);
    var noteLabel = el('label', null, 'Note for the run (optional)');
    noteLabel.htmlFor = noteId;
    var note = el('textarea', 'textarea', null);
    note.id = noteId; note.maxLength = 2000; note.rows = 3;
    if (!d.can_answer) note.disabled = true;
    noteField.appendChild(noteLabel); noteField.appendChild(note);
    form.appendChild(noteField);
    var actions = el('div', 'approval-actions', null);
    var send = el('button', 'btn', 'Send my choice');
    send.type = 'submit';
    if (!d.can_answer) send.disabled = true;
    actions.appendChild(send);
    var copilot = el('button', 'btn btn--ghost', 'Review with Copilot');
    copilot.type = 'button';
    copilot.addEventListener('click', function () {
      document.dispatchEvent(new CustomEvent('lightwork:copilot-selection', {detail: {selection: {kind: 'decision', id: d.id}}}));
      var panel = document.getElementById('mv-copilot');
      var opener = document.getElementById('mv-copilot-fab');
      if (panel && panel.hidden && opener) opener.click();
      said.textContent = 'Copilot is reviewing this decision. Your choice still needs your confirmation.';
    });
    actions.appendChild(copilot);
    form.appendChild(actions);
    if (!d.can_answer && d.why_not) form.appendChild(el('p', 'muted', d.why_not));
    if (d.restart_note) form.appendChild(el('p', 'muted', d.restart_note));
    var said = el('p'); said.setAttribute('role', 'status');
    form.appendChild(said);
    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      var picked = form.querySelector('input[type=radio]:checked');
      if (!picked) { said.textContent = 'Choose one option first.'; return; }
      send.disabled = true;
      try {
        var result = await window.mvFetchJSON('/api/v1/decisions/' + d.id + '/answer', {
          method: 'POST', body: {option: Number(picked.value), note: note.value}, serverDetail: '',
          timeout: 15000}, 'send your choice');
        said.textContent = result.message;
        set.disabled = true; note.disabled = true;
        if (stateBox) count((parseInt(stateBox.dataset.decisionCount, 10) || 1) - 1);
      } catch (error) {
        said.textContent = error.message;
        send.disabled = false;
      }
    });
    item.appendChild(form);
    return item;
  }

  async function load() {
    try {
      var data = await window.mvFetchJSON('/api/v1/decisions', {cache: 'no-store', timeout: 15000}, 'load decisions');
      // On a task's own page (data-goal-id) only that task's decisions show.
      var only = root.dataset.goal ? Number(root.dataset.goal) : null;
      var rows = (data.decisions || []).filter(function (d) { return only === null || d.goal_id === only; });
      list.textContent = '';
      rows.forEach(function (d) { list.appendChild(card(d)); });
      root.hidden = !rows.length;
      count(rows.length);
    } catch (error) {
      root.hidden = false;
      status.textContent = 'Decisions could not be loaded. Refresh this page.';
    }
  }
  load();
})();
