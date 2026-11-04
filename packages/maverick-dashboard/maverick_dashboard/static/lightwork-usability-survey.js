// The optional ease-of-use survey ([analytics] usability_survey). Loaded only
// when it is on and someone is signed in. It never opens a dialog or moves
// focus: the quarterly survey and the one question after a common task are
// panels after the page's own content -- added below it, so nothing already
// on screen moves when one arrives -- and "Not now" hides them for the quarter.
(function () {
  'use strict';
  var API = '/api/v1/usability-survey';
  var main = document.getElementById('content') || document.querySelector('main');
  if (!main || typeof fetch !== 'function') return;
  var SCALE5 = ['Strongly disagree', 'Disagree', 'Neither', 'Agree', 'Strongly agree'];
  var asked = {};

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text) node.textContent = text;
    return node;
  }
  function button(text, ghost) {
    var node = el('button', ghost ? 'btn btn--ghost' : 'btn', text);
    node.type = 'button';
    return node;
  }
  function failText(failure, what) {
    return typeof window.mvErrorText === 'function' ? window.mvErrorText(failure, what)
      : 'Could not ' + what + '. Try again.';
  }
  async function send(path, body) {
    return window.mvFetchJSON(API + path, {method: 'POST', body: body});
  }
  async function state(task) {
    return window.mvFetchJSON(API + (task ? '?task=' + encodeURIComponent(task) : ''));
  }
  function panel(id, title) {
    var box = el('section', 'panel mv-survey');
    box.id = id;
    box.setAttribute('aria-labelledby', id + '-title');
    var heading = el('h2', '', title);
    heading.id = id + '-title';
    box.appendChild(heading);
    var status = el('p', 'muted');
    status.setAttribute('role', 'status');
    box._status = status;
    main.appendChild(box);
    return box;
  }
  function radios(name, legend, labels, start) {
    var set = el('fieldset', 'mv-survey__item');
    set.appendChild(el('legend', '', legend));
    labels.forEach(function (label, index) {
      var row = el('label', 'mv-survey__choice');
      var input = el('input');
      input.type = 'radio'; input.name = name; input.value = String(start + index); input.required = true;
      row.appendChild(input);
      row.appendChild(document.createTextNode(' ' + label));
      set.appendChild(row);
    });
    return set;
  }
  function roleSelect(roles) {
    var label = el('label', 'mv-survey__role', 'Which best describes your work in Lightwork? (optional) ');
    var select = el('select', 'select');
    select.name = 'role';
    select.appendChild(new Option('Prefer not to say', ''));
    roles.forEach(function (role) { select.appendChild(new Option(role.label, role.value)); });
    label.appendChild(select);
    return label;
  }
  function finish(box, text) {
    Array.prototype.forEach.call(box.querySelectorAll('form, .mv-survey__actions'), function (node) { node.remove(); });
    box._status.textContent = text;
    box.appendChild(box._status);
  }
  async function skip(box, topic, what) {
    box._status.textContent = 'Saving…';
    try {
      await send('/dismiss', {topic: topic});
      finish(box, 'We will not ask about ' + what + ' again this quarter.');
    } catch (failure) {
      box._status.textContent = failText(failure, 'hide the question');
    }
  }

  function offerSurvey(data) {
    var box = panel('mv-survey-sus', 'Help make Lightwork easier to use');
    box.appendChild(el('p', '', 'Ten short statements, about two minutes. Your answers stay on this server and are reported by role, never by name.'));
    var actions = el('p', 'mv-survey__actions');
    var start = button('Answer 10 questions'), later = button('Not now', true);
    actions.appendChild(start); actions.appendChild(later);
    box.appendChild(actions);
    box.appendChild(box._status);
    later.addEventListener('click', function () { skip(box, 'sus', 'the survey'); });
    start.addEventListener('click', function () {
      actions.remove();
      var form = el('form', 'mv-survey__form');
      form.noValidate = true;
      form.appendChild(roleSelect(data.roles));
      data.sus_items.forEach(function (item, index) {
        form.appendChild(radios('sus-' + index, (index + 1) + '. ' + item, SCALE5, 1));
      });
      var row = el('p', 'mv-survey__actions');
      var submit = el('button', 'btn', 'Send my answers');
      submit.type = 'submit';
      var cancel = button('Not now', true);
      row.appendChild(submit); row.appendChild(cancel);
      form.appendChild(row);
      box.insertBefore(form, box._status);
      cancel.addEventListener('click', function () { skip(box, 'sus', 'the survey'); });
      form.addEventListener('submit', async function (event) {
        event.preventDefault();
        var answers = data.sus_items.map(function (_item, index) {
          var picked = form.querySelector('input[name="sus-' + index + '"]:checked');
          return picked ? Number(picked.value) : null;
        });
        var missing = answers.indexOf(null);
        if (missing !== -1) {
          box._status.textContent = 'Answer statement ' + (missing + 1) + ' to send your answers.';
          form.querySelector('input[name="sus-' + missing + '"]').focus();
          return;
        }
        submit.disabled = true;
        box._status.textContent = 'Saving…';
        try {
          await send('/sus', {answers: answers, role: form.elements.role.value});
          finish(box, 'Thank you. Your answers are saved.');
        } catch (failure) {
          submit.disabled = false;
          box._status.textContent = failText(failure, 'save your answers') + ' Your answers are still here.';
        }
      });
    });
  }

  async function askEase(task) {
    if (asked[task] || document.getElementById('mv-survey-seq')) return;
    asked[task] = true;
    var data;
    try { data = await state(task); } catch (_) { return; }
    if (!data.offer_seq) return;
    var label = (data.tasks.find(function (item) { return item.value === task; }) || {}).label || 'this task';
    var box = panel('mv-survey-seq', 'One question about what you just did');
    var form = el('form', 'mv-survey__form');
    form.noValidate = true;
    form.appendChild(radios('seq', data.seq_question + ' (You just tried to ' + label + '.)',
      ['1 Very difficult', '2', '3', '4', '5', '6', '7 Very easy'], 1));
    var row = el('p', 'mv-survey__actions');
    var submit = el('button', 'btn', 'Send my answer');
    submit.type = 'submit';
    var later = button('Not now', true);
    row.appendChild(submit); row.appendChild(later);
    form.appendChild(row);
    box.appendChild(form);
    box.appendChild(box._status);
    box._status.textContent = 'One optional question about ' + label + ' is at the end of this page.';
    later.addEventListener('click', function () { skip(box, 'seq:' + task, 'this task'); });
    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      var picked = form.querySelector('input[name="seq"]:checked');
      if (!picked) { box._status.textContent = 'Choose a number from 1 to 7 to send your answer.'; return; }
      submit.disabled = true;
      box._status.textContent = 'Saving…';
      try {
        await send('/seq', {task: task, rating: Number(picked.value)});
        finish(box, 'Thank you. Your answer is saved.');
      } catch (failure) {
        submit.disabled = false;
        box._status.textContent = failText(failure, 'save your answer') + ' Your answer is still here.';
      }
    });
  }

  // Finished top tasks.
  document.addEventListener('lightwork:settings-saved', function (event) {
    if (event.detail && event.detail.ids && event.detail.ids.length) askEase('change_setting');
  });
  document.addEventListener('lightwork:approval-decided', function () { askEase('decide_approval'); });
  var lastStatus = null;
  document.addEventListener('lightwork:task-projection', function (event) {
    var status = event.detail && event.detail.status;
    // Only a task seen finishing on this page counts, not opening an old result.
    if (status === 'done' && lastStatus && lastStatus !== 'done') askEase('run_task');
    lastStatus = status;
  });
  if (document.getElementById('invite-result')) askEase('invite_person');

  state('').then(function (data) { if (data.offer_sus) offerSurvey(data); }, function () {});
  window.mvAskEase = askEase;
})();
