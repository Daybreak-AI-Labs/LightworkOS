/* Suggested edits to AI use rules (templates/_policy_suggestions.html, NOT-4).
   Lists open suggestions with exactly what each changes (removed words struck
   through, added words underlined), who or what proposed it and why. A person
   accepts (saved as the rules' next version) or rejects, with an optional
   reason. The AI assistant drafts a suggestion only when a person asks. */
(function () {
  'use strict';
  var API = '/api/v1/policy-suggestions';
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }
  function hidden(text) { return el('span', 'sr-only', text); }
  function call(url, body, action) {
    return window.mvFetchJSON(url, body ? {method: 'POST', body: body} : {}, action);
  }
  function errorText(error, action) {
    return (error && error.message) || (window.mvErrorText ? window.mvErrorText(error, action) : 'Could not ' + action + '.');
  }
  function changeLine(diff) {
    var line = el('p', 'mv-suggestions__diff');
    diff.forEach(function (part) {
      if (part.op === 'same') { line.appendChild(document.createTextNode(part.text)); return; }
      var mark = el(part.op === 'del' ? 'del' : 'ins');
      mark.append(hidden(part.op === 'del' ? ' removed: ' : ' added: '), document.createTextNode(part.text));
      line.append(mark, document.createTextNode(' '));
    });
    return line;
  }
  function setup(root) {
    if (root.dataset.suggestionsReady) return;
    root.dataset.suggestionsReady = '1';
    var kind = root.dataset.kind || 'ai-policy';
    var list = root.querySelector('[data-suggestion-list]');
    var ask = root.querySelector('[data-suggestion-ask]');
    var status = root.querySelector('[data-suggestion-status]');
    var rules = [];
    function say(node, text, error) {
      if (window.mvStatus) window.mvStatus(node, text, {error: !!error}); else node.textContent = text;
    }
    function decide(s, verb, reasonBox, note, buttons) {
      buttons.forEach(function (b) { b.disabled = true; });
      var action = verb === 'accept' ? 'accept the suggestion' : 'reject the suggestion';
      call(API + '/' + encodeURIComponent(s.id) + '/' + verb, {reason: reasonBox.value}, action).then(function (done) {
        load(verb === 'accept'
          ? 'Accepted for “' + s.document_title + '”. ' + (done.next_step || '')
          : 'Rejected. Nothing changed.');
      }, function (error) {
        buttons.forEach(function (b) { b.disabled = false; });
        say(note, errorText(error, action), true);
      });
    }
    function card(s, canDecide) {
      var item = el('article', 'mv-suggestions__item');
      item.id = 'suggestion-' + s.id;
      item.appendChild(el('h5', null, s.document_title + ' · ' + s.field_label));
      var who = s.proposer_kind === 'ai' ? 'Suggested by AI: ' + s.proposed_by : 'Suggested by ' + s.proposed_by;
      item.appendChild(el('p', 'assurance-muted', who + (s.reason ? '. Why: ' + s.reason : '.')));
      item.appendChild(changeLine(s.diff));
      var note = el('p', 'mv-suggestions__note');
      note.setAttribute('role', 'status');
      if (s.outdated) note.textContent = 'This changed since it was suggested, so the suggestion can only be rejected.';
      item.appendChild(note);
      if (!canDecide) return item;
      var label = el('label', 'mv-suggestions__reason', 'Reason (optional) ');
      var reasonBox = el('input', 'input'); reasonBox.maxLength = 1000; label.appendChild(reasonBox);
      var accept = el('button', 'btn', 'Accept change'); accept.type = 'button'; accept.disabled = !!s.outdated;
      var reject = el('button', 'btn btn--ghost', 'Reject change'); reject.type = 'button';
      var row = el('div', 'assurance-actions');
      row.append(label, accept, reject);
      item.appendChild(row);
      accept.addEventListener('click', function () { decide(s, 'accept', reasonBox, note, [accept, reject]); });
      reject.addEventListener('click', function () { decide(s, 'reject', reasonBox, note, [accept, reject]); });
      return item;
    }
    function recentLine(s) {
      var verb = s.state === 'accepted' ? 'Accepted' : 'Rejected';
      return el('li', null, s.document_title + ' · ' + s.field_label + ': ' + verb +
        (s.decided_by ? ' by ' + s.decided_by.replace(/^user:/, '') : '') +
        (s.decision_reason ? '. Reason: ' + s.decision_reason : '') + '.');
    }
    function fillParts() {
      var chosen = rules.find(function (r) { return r.id === ask.elements.id.value; });
      ask.elements.field.replaceChildren();
      (chosen ? chosen.parts : []).forEach(function (p) { ask.elements.field.appendChild(new Option(p.label, p.field)); });
    }
    function render(data, message) {
      list.replaceChildren();
      if (message) { var done = el('p', 'mv-suggestions__done', message); done.setAttribute('role', 'status'); list.appendChild(done); }
      if (!data.suggestions.length) {
        list.appendChild(window.mvEmpty ? window.mvEmpty('No suggested changes', 'Suggestions from agents, colleagues and the AI assistant appear here.', null, {compact: true})
          : el('p', 'assurance-muted', 'No suggested changes.'));
      }
      data.suggestions.forEach(function (s) { list.appendChild(card(s, data.can_decide)); });
      if (data.recent.length) {
        var details = el('details'); details.appendChild(el('summary', null, 'Recent decisions'));
        var ul = el('ul'); data.recent.forEach(function (s) { ul.appendChild(recentLine(s)); });
        details.appendChild(ul); list.appendChild(details);
      }
      rules = data.rules || [];
      if (!ask) return;
      ask.hidden = !(data.ai_on && rules.length);
      if (!ask.hidden && !ask.elements.id.options.length) {
        rules.forEach(function (r) { ask.elements.id.appendChild(new Option(r.title, r.id)); });
        fillParts();
      }
    }
    function load(message) {
      return call(API + '?kind=' + encodeURIComponent(kind), null, 'load the suggestions').then(function (data) { render(data, message); }, function (error) {
        list.replaceChildren(el('p', 'assurance-muted', errorText(error, 'load the suggestions')));
      });
    }
    if (ask) ask.elements.id.addEventListener('change', fillParts);
    if (ask) ask.addEventListener('submit', function (event) {
      event.preventDefault();
      var button = ask.querySelector('button[type="submit"]');
      button.disabled = true;
      say(status, 'Asking the AI assistant…');
      call(API + '/ai', {id: ask.elements.id.value, field: ask.elements.field.value,
        instruction: ask.elements.instruction.value}, 'get a suggestion').then(function () {
        ask.elements.instruction.value = '';
        say(status, 'Suggestion ready below. Nothing changes until someone accepts it.');
        return load();
      }, function (error) { say(status, errorText(error, 'get a suggestion'), true); }).then(function () { button.disabled = false; });
    });
    load();
  }
  function init() { document.querySelectorAll('[data-policy-suggestions]').forEach(setup); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
}());
