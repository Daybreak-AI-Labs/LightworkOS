/* One-tap feedback on a finished result outside the task page, and on
   flow run results (/api/v1/flows/runs/{id}/feedback, see bindRun). It
   saves through the task page's own saved-answer feedback
   (/api/v1/goals/{id}/answer-feedback), so the same owner check, receipt and
   learning policy apply. A lost reply is retried only with the same
   operation reference, so one tap is never counted twice. */
(function () {
  'use strict';
  function say(node, text, failed) {
    if (!node) return;
    var words = window.LightworkI18n ? window.LightworkI18n.text(text) : text;
    if (window.mvStatus) window.mvStatus(node, words, {error: !!failed}); else node.textContent = words;
  }
  function bind(box) {
    var goal = Number(box.dataset.goal);
    if (!Number.isSafeInteger(goal) || goal <= 0 || box.dataset.feedbackReady) return;
    box.dataset.feedbackReady = 'true';
    var msg = box.querySelector('[data-feedback-msg]');
    var buttons = Array.prototype.slice.call(box.querySelectorAll('[data-rating]'));
    var url = '/api/v1/goals/' + goal + '/answer-feedback', key = 'lightwork-result-feedback:' + goal;
    function pending() { try { return JSON.parse(window.sessionStorage.getItem(key) || 'null'); } catch (_) { return null; } }
    function keep(value) { try { if (value) window.sessionStorage.setItem(key, JSON.stringify(value)); else window.sessionStorage.removeItem(key); } catch (_) { /* best effort */ } }
    async function rate(rating) {
      buttons.forEach(function (button) { button.disabled = true; });
      say(msg, 'Saving your feedback…');
      try {
        var current = await window.mvFetchJSON(url, {cache: 'no-store'}, 'read this result');
        if (!current || !current.eligible) { say(msg, 'This result cannot be rated here. Open it to give feedback.'); return; }
        var attempt = pending();
        if (!attempt || attempt.rating !== rating || attempt.revision !== current.revision) {
          attempt = {id: window.crypto.randomUUID().replace(/-/g, ''), rating: rating, revision: current.revision};
        }
        keep(attempt);
        var value = await window.mvFetchJSON(url, {method: 'POST', cache: 'no-store', body: {rating: rating, note: '', reason: '',
          revision: current.revision, expected_context: current.context, operation_id: attempt.id}}, 'save your feedback');
        keep(null);
        buttons.forEach(function (button) { button.setAttribute('aria-pressed', String(button.dataset.rating === rating)); });
        say(msg, (value && value.acknowledgement) || 'Thanks. Saved with this task.');
        if (rating === 'down' && msg) {
          var more = document.createElement('a'); more.href = '/chat/goal/' + goal + '#feedback';
          more.textContent = window.LightworkI18n ? window.LightworkI18n.text('Say what was wrong') : 'Say what was wrong';
          msg.append(' ', more);
        }
      } catch (error) {
        say(msg, window.mvErrorText ? window.mvErrorText(error, 'save your feedback') : 'Could not save your feedback. Try again.', true);
      } finally {
        buttons.forEach(function (button) { button.disabled = false; });
      }
    }
    buttons.forEach(function (button) { button.addEventListener('click', function () { rate(button.dataset.rating); }); });
  }
  // A flow run's result (flow_run.html): the run's own small store keeps only
  // the rating, one per run, so a repeated tap simply sets it again.
  function bindRun(box) {
    var run = String(box.dataset.run || '');
    if (!/^[A-Za-z0-9_.-]{1,128}$/.test(run) || box.dataset.feedbackReady) return;
    box.dataset.feedbackReady = 'true';
    var msg = box.querySelector('[data-feedback-msg]');
    var buttons = Array.prototype.slice.call(box.querySelectorAll('[data-rating]'));
    var url = '/api/v1/flows/runs/' + encodeURIComponent(run) + '/feedback';
    function show(value) {
      box.hidden = !(value && value.eligible);
      buttons.forEach(function (button) { button.setAttribute('aria-pressed', String(!!value && button.dataset.rating === value.rating)); });
    }
    function load() { window.mvFetchJSON(url, {cache: 'no-store'}, 'read this run').then(show).catch(function () { /* stays hidden */ }); }
    buttons.forEach(function (button) {
      button.addEventListener('click', function () {
        buttons.forEach(function (item) { item.disabled = true; });
        say(msg, 'Saving your feedback…');
        window.mvFetchJSON(url, {method: 'PUT', cache: 'no-store', body: {rating: button.dataset.rating}}, 'save your feedback')
          .then(function (value) { show(value); say(msg, 'Thanks. Saved with this run.'); })
          .catch(function (error) { say(msg, window.mvErrorText ? window.mvErrorText(error, 'save your feedback') : 'Could not save your feedback. Try again.', true); })
          .then(function () { buttons.forEach(function (item) { item.disabled = false; }); });
      });
    });
    document.addEventListener('lightwork:flow-run-finished', load);
    load();
  }
  function init() {
    document.querySelectorAll('[data-result-feedback]').forEach(bind);
    document.querySelectorAll('[data-flow-run-feedback]').forEach(bindRun);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
}());
