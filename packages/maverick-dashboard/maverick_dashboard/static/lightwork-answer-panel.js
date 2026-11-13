// Saved result projection; the composer and conversation history are never replaced.
(function () {
  'use strict';
  var panel = document.getElementById('answer-panel'); if (!panel) return;
  var goalId = panel.dataset.goal, context = panel.dataset.context;
  var message = document.getElementById('answer-refresh-status'), retry = document.getElementById('answer-refresh');
  var inFlight = null, generation = 0, lastStatus = panel.dataset.status, lastResult = null;
  var denied = false, forceAgain = false;
  var pendingSignoff = null, signoffRecoveryLoaded = false;
  var signoffCheckInFlight = false;
  var pendingFeedback = null, feedbackBusy = false;
  function say(node, source, values) {
    if (window.LightworkI18n) window.LightworkI18n.set(node, source, values);
    else node.textContent = source.replace(/\{(\w+)\}/g, function (_, key) { return values && values[key] !== undefined ? values[key] : _; });
  }
  function sourceText(node, value) { node.textContent = value; node.lang = 'und'; node.dir = 'auto'; node.dataset.userContent = '1'; }
  function cgErr(failure, action) { return window.mvErrorText(failure, action); }
  function dirty() {
    var editor = panel.querySelector('#edit-text'), note = panel.querySelector('#signoff-note'), feedback = panel.querySelector('#feedback-note');
    return !!((editor && (editor.readOnly || editor.value !== editor.dataset.savedText)) || (note && note.value.trim()) ||
      pendingFeedback || panel.querySelector('[data-reason][aria-pressed="true"]') ||
      (feedback && feedback.value !== (feedback.dataset.savedText || '')));
  }
  function clearPrivate() {
    denied = true; generation++;
    if (inFlight) inFlight.abort();
    document.dispatchEvent(new CustomEvent('lightwork:answer-panel-before-update'));
    panel.replaceChildren(); panel.dataset.version = '';
    say(message, 'Access to the saved result changed. Sign in or reopen the authorized task to continue.');
    retry.hidden = true;
  }
  function bind(panel) {
    if (panel.dataset.bound === '1') return; panel.dataset.bound = '1';
    // A hidden "changed since you last used it" notice stays hidden in
    // this browser. Bound here rather than by a script inside the panel:
    // refresh() refuses any fetched panel that carries a script.
    var notice = panel.querySelector('#answer-agent-notice');
    if (notice) {
      var noticeKey = 'lightwork-hidden-notice:' + notice.getAttribute('data-notice-key');
      try { if (window.localStorage.getItem(noticeKey)) notice.hidden = true; } catch (_) { /* no storage: the notice stays */ }
      var hideNotice = notice.querySelector('[data-hide-notice]');
      if (hideNotice) hideNotice.addEventListener('click', function () {
        notice.hidden = true;
        try { window.localStorage.setItem(noticeKey, '1'); } catch (_) { /* hidden for this view only */ }
      });
    }
    // Deliverable sign-off: record the human certify/reject decision, then
    // reload to show the signed-off state (and the hand-off download).
    (function () {
      panel.querySelectorAll('.signoff [data-when]').forEach(function (el) {
        var ts = parseFloat(el.getAttribute('data-when'));
        if (ts) el.textContent = window.mvWhen(ts);
      });
      var approve = panel.querySelector("#" + 'signoff-approve');
      var reject = panel.querySelector("#" + 'signoff-reject');
      var recover = panel.querySelector('#signoff-recover'), copilot = panel.querySelector('#signoff-copilot');
      if (!approve && !reject && !recover) return;
      var note = panel.querySelector("#" + 'signoff-note');
      var msg = panel.querySelector("#" + 'signoff-msg');
      var goalId = Number(panel.dataset.goal);
      // Bind the decision to the exact deliverable this page rendered. The
      // server rejects this version if a result or artifact changed meanwhile.
      var reviewedUpdatedAt = Number(panel.dataset.updatedAt);
      var btns = [approve, reject];
      var key = 'lightwork-result-review:' + panel.dataset.context + ':' + goalId;
      function liveReviewPanel() {
        var live = document.getElementById('answer-panel');
        return !denied && live && live.dataset.goal === String(goalId) && live.dataset.context === context ? live : null;
      }
      if (!signoffRecoveryLoaded) {
        try { pendingSignoff = JSON.parse(sessionStorage.getItem(key) || 'null'); } catch (_) {}
        if (pendingSignoff && (!/^[a-f0-9]{32}$/.test(pendingSignoff.id) || typeof pendingSignoff.version !== 'number')) pendingSignoff = null;
        signoffRecoveryLoaded = true;
      }
      function uncertain() {
        btns.forEach(function (b) { if (b) b.disabled = true; });
        if (recover) recover.hidden = false;
        say(msg, 'Your decision response was interrupted. Check the original receipt before making another decision. Nothing will be submitted again by this check.');
      }
      if (pendingSignoff) uncertain();
      if (recover) recover.disabled = signoffCheckInFlight;
      async function checkOriginal() {
        if (!pendingSignoff || !recover || signoffCheckInFlight) return;
        var attempt = pendingSignoff;
        signoffCheckInFlight = true;
        recover.disabled = true;
        try {
          var r = await fetch('/api/v1/goals/' + goalId + '/signoff?operation_id=' + attempt.id, {cache:'no-store'});
          if ([401,403,404].includes(r.status)) { clearPrivate(); return; }
          if (!r.ok) {
            var failure = await r.json().catch(function () { return {}; }), errorPanel = liveReviewPanel();
            if (errorPanel) window.mvRenderError(errorPanel.querySelector('#signoff-msg'), r, 'check the original decision', failure);
            return;
          }
          var value = await r.json();
          var live = liveReviewPanel();
          if (!live || !pendingSignoff || pendingSignoff.id !== attempt.id) return;
          say(live.querySelector('#signoff-msg'), value.message + (value.receipt && Number(live.dataset.updatedAt) !== attempt.version ? ' The result on this page has changed since that review.' : ''));
          if (value.receipt) {
            sessionStorage.removeItem(key); pendingSignoff = null; recover.hidden = true;
            var currentRecover = live.querySelector('#signoff-recover'); if (currentRecover) currentRecover.hidden = true;
            if (note && value.receipt.changed) note.value = '';
            window.mvRefreshAnswerPanel();
          }
        } catch (e) {
          var errorPanel = liveReviewPanel();
          if (errorPanel) say(errorPanel.querySelector('#signoff-msg'), 'The original receipt could not be checked. Try this check again; your decision has not been submitted again.');
        } finally {
          signoffCheckInFlight = false;
          var current = liveReviewPanel(), button = current && current.querySelector('#signoff-recover');
          if (button) button.disabled = false;
        }
      }
      if (recover) recover.addEventListener('click', checkOriginal);
      if (copilot) copilot.addEventListener('click', function () {
        document.dispatchEvent(new CustomEvent('lightwork:product-selection', {detail:{kind:'goal',id:goalId}}));
        var fab = document.getElementById('mv-copilot-fab'); if (fab) fab.click();
      });
      function submit(decision) {
        if (pendingSignoff) { uncertain(); return; }
        var identity = (window.mvNewId ? window.mvNewId() : window.crypto.randomUUID()).replace(/-/g, '');
        pendingSignoff = {id:identity,version:reviewedUpdatedAt};
        try { sessionStorage.setItem(key, JSON.stringify(pendingSignoff)); }
        catch (_) { pendingSignoff = null; say(msg, 'Your browser could not retain a recovery reference. Allow this site to save session data before recording a decision.'); return; }
        btns.forEach(function (b) { if (b) b.disabled = true; });
        msg.style.color = 'var(--muted)';
        say(msg, 'Recording…');
        window.mvFetchJSON('/api/v1/goals/' + goalId + '/signoff', {
          method: 'POST',
          body: {
            decision: decision,
            expected_updated_at: reviewedUpdatedAt,
            note: (note && note.value.trim()) || null,
            operation_id: identity,
            expected_context: panel.dataset.context,
          },
        }, 'record the approval').then(function (j) {
          if (!j || !j.receipt) { uncertain(); return; }
          sessionStorage.removeItem(key); pendingSignoff = null;
          if (note && j.receipt.changed) note.value = '';
          say(msg, j.receipt.message); window.mvRefreshAnswerPanel();
        }).catch(function (e) {
          msg.style.color = 'var(--danger)';
          // No answer (offline, timed out or unreadable): the outcome is unknown.
          if (!e.status) { uncertain(); return; }
          window.mvRenderError(msg, e, 'record the approval', e.payload || {});
          if ([401,403,404].includes(e.status)) { clearPrivate(); return; }
          if (e.status < 500) {
            sessionStorage.removeItem(key); pendingSignoff = null;
            if (e.status === 409) window.mvRefreshAnswerPanel();
            else btns.forEach(function (b) { if (b) b.disabled = false; });
          }
          else uncertain();
        });
      }
      if (approve) approve.addEventListener('click', function () { submit('approved'); });
      if (reject) reject.addEventListener('click', function () { submit('rejected'); });
    })();

    // Notes belong to the exact saved answer. Lost replies read the original
    // actor-bound receipt; they never submit another rating or learning signal.
    (function () {
      var box = panel.querySelector('#feedback');
      if (!box) return;
      var up = panel.querySelector('#feedback-up'), down = panel.querySelector('#feedback-down');
      var msg = panel.querySelector('#feedback-msg'), form = panel.querySelector('#feedback-form');
      var note = panel.querySelector('#feedback-note'), save = panel.querySelector('#feedback-save');
      var cancel = panel.querySelector('#feedback-cancel'), recover = panel.querySelector('#feedback-recover');
      var current = panel.querySelector('#feedback-saved'), review = panel.querySelector('#feedback-review');
      var key = 'lightwork-answer-feedback:' + context + ':' + goalId, binding = null, chosen = null, chosenReason = '';
      var reasonChips = Array.from(panel.querySelectorAll('[data-reason]'));
      var reasonQuestion = panel.querySelector('#feedback-reason-q');
      var reasonGroup = reasonChips.length ? reasonChips[0].closest('[role="group"]') : null;
      function reasons(rating) {
        if (reasonGroup) reasonGroup.hidden = rating !== 'down';
        if (reasonQuestion) { reasonQuestion.hidden = rating !== 'down'; say(reasonQuestion, 'What was wrong? This is optional.'); }
        chosenReason = '';
        reasonChips.forEach(function (chip) { chip.setAttribute('aria-pressed', 'false'); });
      }
      reasonChips.forEach(function (chip) {
        chip.addEventListener('click', function () {
          if (feedbackBusy || pendingFeedback || chosen !== 'down') return;
          chosenReason = chosenReason === chip.dataset.reason ? '' : chip.dataset.reason;
          reasonChips.forEach(function (other) { other.setAttribute('aria-pressed', String(other.dataset.reason === chosenReason)); });
        });
      });
      try { pendingFeedback = JSON.parse(sessionStorage.getItem(key) || 'null'); } catch (_) {}
      if (pendingFeedback && (!/^[a-f0-9]{32}$/.test(pendingFeedback.id) || !/^[a-f0-9]{64}$/.test(pendingFeedback.revision))) pendingFeedback = null;
      function live() { return !denied && document.getElementById('answer-panel') === panel && panel.dataset.context === context; }
      function lock() {
        [up,down,save,cancel].concat(reasonChips).forEach(function (button) { button.disabled = feedbackBusy || !!pendingFeedback || !binding; });
        note.readOnly = feedbackBusy || !!pendingFeedback;
        review.disabled = feedbackBusy; recover.disabled = feedbackBusy; recover.hidden = !pendingFeedback;
      }
      function show(rating) {
        [up,down].forEach(function (button) { var selected = button.dataset.rating === rating;
          button.classList.toggle('is-active', selected); button.setAttribute('aria-pressed', String(selected)); });
      }
      function display(value) {
        current.replaceChildren();
        if (!value) { say(current, 'No saved feedback is available in the current records.'); return; }
        var label = document.createElement('p');
        say(label, (value.rating === 'up' ? 'Useful' : 'Needs improvement') +
          (value.legacy ? ' · earlier feedback: the answer version was not recorded' : value.current_result ? ' · current answer' : ' · earlier answer') + ' · ' + window.mvWhen(value.recorded_at));
        current.appendChild(label);
        if (value.reason_label) { var reason = document.createElement('p'); say(reason, value.reason_label); current.appendChild(reason); }
        if (value.note) { var text = document.createElement('p'); sourceText(text, value.note); text.style.whiteSpace='pre-wrap'; current.appendChild(text); }
        if (!chosen) show(value.current_result ? value.rating : '');
      }
      async function request(operation, body) {
        var controller = new AbortController(), timer = setTimeout(function () { controller.abort(); }, 12000);
        try {
          var response = await fetch('/api/v1/goals/' + goalId + '/answer-feedback' + (operation ? '?operation_id=' + operation : ''),
            {method:body ? 'POST' : 'GET', headers:body ? {'Content-Type':'application/json'} : {},
             body:body ? JSON.stringify(body) : undefined, cache:'no-store', signal:controller.signal});
          if (!live()) throw new Error('The answer changed. Reopen it before continuing.');
          if (response.redirected || [401,403,404].includes(response.status)) { clearPrivate(); throw new Error('Access changed. Reopen the authorized task.'); }
          var value = await response.json();
          if (!response.ok) { var error = new Error(window.mvErrorText({status:response.status,detail:value.detail}, 'save your feedback')); error.refused=response.status<500; throw error; }
          if (value.context !== context) { clearPrivate(); throw new Error('Your account or workspace changed. Reopen the authorized task.'); }
          return value;
        } catch (error) {
          if (error.name === 'AbortError') throw new Error('The feedback response took too long to arrive.');
          if (error.name === 'TypeError') throw new Error('Lightwork could not be reached.');
          throw error;
        } finally { clearTimeout(timer); }
      }
      function forget() { sessionStorage.removeItem(key); pendingFeedback = null; }
      function accepted(value, original) {
        if (!value || !pendingFeedback || value.operation_id !== pendingFeedback.id) throw new Error('The original feedback could not be confirmed.');
        display(value); forget();
        if (value.current_result) { note.dataset.savedText = note.value; form.hidden=true; chosen=null; reasons(null); }
        say(msg, (original ? 'Your original feedback is saved.' : 'Feedback saved.') +
          (value.current_result ? '' : ' It applies to the earlier answer you reviewed.') +
          ' Feedback does not confirm that training completed.' +
          (value.acknowledgement ? ' ' + value.acknowledgement : value.signal_note ? ' ' + value.signal_note : ''));
      }
      async function check(original) {
        if (feedbackBusy) return;
        feedbackBusy=true; lock();
        try {
          var attempt = pendingFeedback, value = await request(original && attempt ? attempt.id : null);
          if (!live()) return;
          if (original && attempt) {
            if (value.feedback) accepted(value.feedback, true);
            else say(msg, 'No saved receipt for your original feedback was found. Its outcome is still unconfirmed. Nothing was submitted again; your note is kept.');
          } else { display(value.feedback); say(msg, 'Current saved feedback is shown. This does not establish the outcome of another request.'); }
          binding = value.eligible && value.updated_at === Number(panel.dataset.updatedAt) ? value.revision : null;
          if (!binding) say(msg, 'The saved answer changed. Your note is kept. Review the current answer before giving feedback.');
        } catch (error) { if (live()) say(msg, error.message + ' Your note is kept. Nothing was submitted again.'); }
        finally { feedbackBusy=false; if (live()) lock(); }
      }
      function choose(rating) {
        if (!binding || pendingFeedback || feedbackBusy) return;
        chosen=rating; show(rating); reasons(rating); form.hidden=false;
        say(panel.querySelector('#feedback-choice'), rating === 'up' ? 'You selected Useful.' : 'You selected Needs improvement.');
        note.focus();
      }
      form.addEventListener('submit', async function (event) {
        event.preventDefault(); if (!binding || !chosen || pendingFeedback || feedbackBusy || !form.reportValidity()) return;
        pendingFeedback={id:(window.mvNewId ? window.mvNewId() : window.crypto.randomUUID()).replace(/-/g,''),revision:binding};
        try { sessionStorage.setItem(key, JSON.stringify(pendingFeedback)); }
        catch (_) { pendingFeedback=null; say(msg, 'Your browser could not keep the original feedback reference. Allow session storage before saving; your note is kept.'); return; }
        feedbackBusy=true; lock(); say(msg, 'Saving your feedback…');
        try { var value = await request(null, {rating:chosen,note:note.value,reason:chosenReason,revision:binding,expected_context:context,operation_id:pendingFeedback.id});
          accepted(value.feedback, false);
          if (value.follow_up && value.follow_up.question) {
            say(msg, msg.textContent + ' ' + value.follow_up.question + ' You can select Needs improvement again to add an optional reason or note.');
          }
          // Answers keep missing: a person is one step away, with this task attached.
          var handOff = panel.querySelector('#feedback-hand-off');
          if (handOff) handOff.hidden = !(value.hand_off && value.hand_off.href);
          if (handOff && value.hand_off && /^\/help\?[^#]*#get-help$/.test(value.hand_off.href)) {
            handOff.querySelector('a').href = value.hand_off.href;
          }
        } catch (error) { if (live()) { if (error.refused) { forget(); binding=null; }
          say(msg, error.message + ' Your note is kept. ' + (pendingFeedback ? 'Check your original feedback before another save; nothing will be submitted again by that check.' : 'Review the current answer before trying again.')); } }
        finally { feedbackBusy=false; if (live()) lock(); }
      });
      up.addEventListener('click', function () { choose('up'); }); down.addEventListener('click', function () { choose('down'); });
      review.addEventListener('click', function () { check(false); }); recover.addEventListener('click', function () { check(true); });
      cancel.addEventListener('click', function () { form.hidden=true; chosen=null; reasons(null); note.value=''; note.dataset.savedText=''; show(''); });
      panel.querySelector('#feedback-copilot').addEventListener('click', function () {
        document.dispatchEvent(new CustomEvent('lightwork:product-selection', {detail:{kind:'goal',id:Number(goalId)}}));
        var fab=document.getElementById('mv-copilot-fab'); if (fab) fab.click();
      });
      lock(); check(false);
      if (pendingFeedback) say(msg, 'A feedback response was interrupted. Check your original feedback before saving again.');
    })();

    // One source and one handler for current-answer actions, including a live refresh.
    (function () {
      var copy = panel.querySelector('#copy-result');
      var print = panel.querySelector('#print-result');
      var share = panel.querySelector('#share-open');
      var saved = panel.querySelector('#saved-answer-source');
      var status = panel.querySelector('#answer-action-msg');
      function selectSavedAnswer() {
        saved.hidden = false; saved.focus(); saved.select();
        say(status, 'Copy was unavailable. The saved answer is selected; press Ctrl+C or Command+C.');
      }
      if (copy) copy.addEventListener('click', function () {
        var text = saved && saved.value;
        if (!text) { say(status, 'There is no saved answer to copy yet.'); return; }
        if (!navigator.clipboard || !navigator.clipboard.writeText) {
          selectSavedAnswer();
          return;
        }
        navigator.clipboard.writeText(text).then(function () { say(status, 'Copied.'); })
          .catch(selectSavedAnswer);
      });
      if (print) print.addEventListener('click', function () {
        if (window.LightworkThreadHistory) window.LightworkThreadHistory.printConversation(status);
        else say(status, 'Printing is still loading. Try again in a moment, or reload this conversation.');
      });
      if (share) share.addEventListener('click', function () {
        var details = document.getElementById('share-panel');
        if (!details) { say(status, 'Sharing is unavailable. Reload this conversation and try again.'); return; }
        details.open = true; share.setAttribute('aria-expanded', 'true');
        details.scrollIntoView({block:'nearest'});
        var create = details.querySelector('#share-create');
        if (create && !create.disabled) create.focus();
      });
    })();

    // Edit & save the deliverable: the human's revision replaces the result and
    // its distance from the agent's draft grounds a graded learning signal.
    (function () {
      var toggle = panel.querySelector("#" + 'edit-toggle');
      if (!toggle) return;
      var box = panel.querySelector("#" + 'edit-box');
      var textEl = panel.querySelector("#" + 'edit-text');
      var saveBtn = panel.querySelector("#" + 'edit-save');
      var editMsg = panel.querySelector("#" + 'edit-msg');
      var goalId = Number(panel.dataset.goal);
      toggle.addEventListener('click', function () {
        box.style.display = box.style.display === 'none' ? 'block' : 'none';
        if (box.style.display === 'block') textEl.focus();
      });
      var reviewedAt = Number(panel.dataset.updatedAt);
      var pendingEdit = null;
      var savedText = textEl.value;
      textEl.dataset.savedText = savedText;
      saveBtn.addEventListener('click', async function () {
        if (saveBtn.disabled) return;
        if (!pendingEdit || pendingEdit.text !== textEl.value || pendingEdit.expected_updated_at !== reviewedAt) {
          pendingEdit = {text: textEl.value, expected_updated_at: reviewedAt, operation_id: (window.mvNewId ? window.mvNewId() : crypto.randomUUID())};
        }
        saveBtn.disabled = true; textEl.readOnly = true;
        editMsg.style.color = 'var(--muted)'; say(editMsg, 'Saving.');
        try {
          var response = await fetch('/api/v1/goals/' + goalId + '/deliverable/edit', {
            method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(pendingEdit)
          });
          var receipt = await response.json();
          if (response.status === 409 && receipt.detail && receipt.detail.current_updated_at) {
            var compare = document.createElement('details');
            var heading = document.createElement('summary'); say(heading, 'Compare with the current saved result');
            var current = document.createElement('pre');
            if (receipt.detail.current_text) sourceText(current, receipt.detail.current_text); else say(current, '(empty)');
            var review = document.createElement('button'); review.type = 'button'; review.className = 'btn btn--ghost';
            say(review, 'Use this current version as the basis for my draft');
            review.addEventListener('click', function () {
              reviewedAt = receipt.detail.current_updated_at; pendingEdit = null; compare.remove();
              say(editMsg, 'Draft kept. Review it, then choose Save to apply it to the current result.');
            });
            compare.append(heading, current, review); box.append(compare); compare.open = true;
            say(editMsg, 'The result changed. Your draft is kept; compare before saving again.');
            return;
          }
          if (!response.ok || !receipt.revision) throw response;
          reviewedAt = receipt.revision; savedText = textEl.value; textEl.dataset.savedText = savedText; pendingEdit = null;
          setTimeout(function () { window.mvRefreshAnswerPanel(); }, 0);
          say(editMsg, 'Revision saved. Previous versions are kept; any earlier approval was cleared. Learning is a separate, policy-governed process.');
        } catch (failure) {
          editMsg.style.color = 'var(--danger)';
          say(editMsg, '{error} Your draft is kept. Retry uses the same save reference.', {error:cgErr(failure, 'save your edit')});
        } finally { saveBtn.disabled = false; textEl.readOnly = false; }
      });
    })();

    // Artifact version history: fetch on first expand, render newest-first with
    // a unified diff per version (server-computed). textContent throughout — no
    // untrusted content reaches innerHTML.
    panel.querySelectorAll('.artifact__history').forEach(function (d) {
      d.addEventListener('toggle', function () {
        if (!d.open || d.dataset.loaded) return;
        d.dataset.loaded = '1';
        const body = d.querySelector('.artifact__history-body');
        say(body, 'Loading…');
        body.classList.add('muted');
        const url = '/api/v1/goals/' + encodeURIComponent(d.dataset.goal) +
                    '/artifacts/history?title=' + encodeURIComponent(d.dataset.title);
        // A non-2xx (auth lapsed, goal gone, server error) must not render as
        // "No history." or leave "Loading…" forever with the loaded flag set.
        // Check the status, and on any failure show why and clear the flag so
        // the next toggle retries.
        fetch(url).then(function (r) {
          if (!r.ok) {
            return r.json().catch(function () { return {}; }).then(function (j) {
              throw new Error(cgErr(r, 'load earlier versions'));
            });
          }
          return r.json();
        }).then(function (j) {
          body.textContent = '';
          body.classList.remove('muted');
          const versions = (j.versions || []).slice().reverse();  // newest first
          if (!versions.length) { say(body, 'No history.'); return; }
          versions.forEach(function (v) {
            const wrap = document.createElement('div');
            wrap.className = 'artifact__version';
            const head = document.createElement('div');
            head.className = 'artifact__version-head';
            say(head, v.created_at ? 'Version {version} · {date}' : 'Version {version}', {version:v.version,
              date:v.created_at ? (window.LightworkI18n ? window.LightworkI18n.formatDate(v.created_at) : new Date(v.created_at * 1000).toLocaleString()) : ''});
            wrap.appendChild(head);
            if (v.diff) {
              const pre = document.createElement('pre');
              pre.className = 'artifact__diff'; pre.lang = 'und'; pre.dir = 'auto'; pre.dataset.userContent = '1';
              v.diff.split('\n').forEach(function (line) {
                const span = document.createElement('span');
                if (line[0] === '+') span.className = 'add';
                else if (line[0] === '-') span.className = 'del';
                span.textContent = line + '\n';
                pre.appendChild(span);
              });
              wrap.appendChild(pre);
            } else {
              const p = document.createElement('div');
              p.className = 'muted';
              say(p, '(initial version)');
              wrap.appendChild(p);
            }
            body.appendChild(wrap);
          });
        }).catch(function (e) {
          body.classList.add('muted');
          say(body, 'Could not load history: {error}. Close and reopen to retry.', {error:String(e && e.message || e)});
          delete d.dataset.loaded;
        });
      });
    });

  }
  async function refresh(force) {
    if (denied || document.hidden) return;
    if (inFlight) { forceAgain = true; return; }
    var ticket = ++generation, controller = new AbortController(); inFlight = controller;
    var timer = setTimeout(function () { controller.abort(); }, 12000);
    try {
      var response = await fetch('/chat/goal/' + goalId + '/answer-panel',
        {credentials:'same-origin', cache:'no-store', signal:controller.signal});
      if (ticket !== generation) return;
      if (response.redirected || [401,403,404].includes(response.status) ||
          (response.ok && response.headers.get('X-Lightwork-Context') !== context)) { clearPrivate(); return; }
      if (!response.ok) { var failure = await window.mvErrorResponse(response); throw failure; }
      var source = await response.text(); if (ticket !== generation) return;
      var parsed = new DOMParser().parseFromString(source, 'text/html');
      var next = parsed.getElementById('answer-panel');
      if (!next || next.dataset.goal !== goalId || next.dataset.context !== context ||
          parsed.querySelectorAll('#answer-panel').length !== 1 || next.querySelector('script')) throw new Error('projection unavailable');
      if (next.dataset.version === panel.dataset.version && next.dataset.operate === panel.dataset.operate) {
        if (next.dataset.runDetailsVersion !== panel.dataset.runDetailsVersion) {
          var runSlot = panel.querySelector('#answer-run-details-slot'), nextRunSlot = next.querySelector('#answer-run-details-slot');
          if (runSlot && nextRunSlot) runSlot.replaceChildren.apply(runSlot, Array.from(nextRunSlot.childNodes));
          panel.dataset.runDetailsVersion = next.dataset.runDetailsVersion;
        }
        retry.hidden = true; message.textContent = ''; return;
      }
      if (!force && dirty()) {
        retry.hidden = false;
        say(message, 'The saved result changed. Your unsaved edit or review note is kept. Refresh when you are ready to review the current version.');
        // A superseded result cannot be signed off through stale controls.
        panel.querySelectorAll('#signoff-approve,#signoff-reject,#feedback-up,#feedback-down,#feedback-save').forEach(function (node) { node.disabled = true; });
        if (next.dataset.operate !== '1') panel.querySelectorAll('button,input,textarea').forEach(function (node) { node.disabled = true; });
        return;
      }
      var focused = document.activeElement, inside = panel.contains(focused), focusId = inside ? focused.id : '';
      var scroller = document.getElementById('cs-scroll'), scrollTop = scroller ? scroller.scrollTop : 0;
      document.dispatchEvent(new CustomEvent('lightwork:answer-panel-before-update'));
      panel.replaceWith(next); panel = next;
      bind(panel); if (window.lwMarkdown) window.lwMarkdown.upgrade(panel);
      document.dispatchEvent(new CustomEvent('lightwork:answer-panel-updated', {detail:{goalId:goalId, version:panel.dataset.version}}));
      if (inside) { var target = focusId && panel.querySelector('#' + CSS.escape(focusId));
        if (target && !target.disabled) target.focus({preventScroll:true}); }
      if (scroller) scroller.scrollTop = scrollTop;
      retry.hidden = true; say(message, 'Saved result and controls updated.');
    } catch (failure) {
      if (ticket !== generation || denied) return;
      window.mvRenderError(message, failure, 'refresh the saved result');
      var kept = document.createElement('span'); say(kept, ' Your draft has been kept.'); message.append(kept); retry.hidden = false;
    } finally {
      clearTimeout(timer); if (inFlight === controller) inFlight = null;
      if (forceAgain && !denied) { forceAgain = false; setTimeout(function () { refresh(false); }, 0); }
    }
  }
  window.mvRefreshAnswerPanel = function () { return refresh(false); };
  retry.addEventListener('click', async function () {
    if (dirty() && !(await window.mvConfirm('Replace the unsaved result edit or review note with the current saved version? Your follow-up message will be kept.', {okText:'Refresh saved result', productCopy:true}))) return;
    refresh(true);
  });
  document.addEventListener('lightwork:task-projection', function (event) {
    var d = event.detail || {}, statusChanged = !!d.status && d.status !== lastStatus;
    var changed = statusChanged || d.result !== lastResult;
    lastStatus = d.status || lastStatus; lastResult = d.result;
    if (statusChanged && !d.terminal) {
      // A restarted task invalidates an older terminal fetch before it can
      // restore stale answer actions over the running conversation.
      generation++; if (inFlight) inFlight.abort(); inFlight = null; forceAgain = false;
      refresh(false); return;
    }
    if (d.artifactsChanged || (d.terminal && changed)) refresh(false);
  });
  document.addEventListener('lightwork:task-access-lost', clearPrivate);
  document.addEventListener('visibilitychange', function () { if (!document.hidden) refresh(false); });
  window.addEventListener('focus', function () { refresh(false); });
  window.addEventListener('beforeunload', function (event) { if (!denied && dirty()) { event.preventDefault(); event.returnValue = ''; } });
  var interval = setInterval(function () { if (['done','blocked','failed','cancelled'].includes(lastStatus)) refresh(false); }, 30000);
  window.addEventListener('pagehide', function () { generation++; if (inFlight) inFlight.abort(); clearInterval(interval); });
  bind(panel); refresh(false);
}());
