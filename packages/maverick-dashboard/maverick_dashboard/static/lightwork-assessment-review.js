/* The assessment review pop-out (_assessment_review.html holds its markup).
   Deferred, so a phone does not download and parse it before the first
   paint, and cached across the pages that offer the pop-out. */
  // window.mvAssessmentReview.open(id): fetch + render one assessment record,
  // with follow-up send-back. Pages wire their own triggers.
  (function() {
    const dlg = document.getElementById('arv-dialog');
    if (!dlg || window.mvAssessmentReview) return;
    const body = document.getElementById('arv-body');
    const riskEl = document.getElementById('arv-risk');
    const sendBtn = document.getElementById('arv-send');
    const statusEl = document.getElementById('arv-status');
    const approveBtn = document.getElementById('arv-approve');
    const rejectBtn = document.getElementById('arv-reject');
    const acceptBtn = document.getElementById('arv-accept');
    const triggerBtn = document.getElementById('arv-trigger');
    const cadenceWrap = document.getElementById('arv-cadence-wrap');
    const cadenceSel = document.getElementById('arv-cadence');
    let currentId = null;
    let currentRevision = null;
    let decidedInDialog = false;
    let viewGeneration = 0, answerBusy = false, answerDirty = false, selectedQuestion = '', currentQuestions = {};
    let currentCompletion = { answered: 0, total: 0, incomplete: false };

    function el(tag, cls, text) {
      const n = document.createElement(tag);
      if (cls) n.className = cls;
      if (text !== undefined) n.textContent = text;
      return n;
    }

    function riskClass(r) {
      return 'badge ' + (r === 'high' ? 'blocked' : r === 'medium' ? 'warn' : 'done');
    }

    const TYPE_LABEL = { pia: 'Privacy impact assessment', dpia: 'Data protection impact assessment',
      aira: 'AI risk assessment', tia: 'Transfer impact assessment', fria: 'Fundamental rights impact assessment',
      vendor_risk: 'Vendor risk review', vendor: 'Vendor risk review' };
    const ANSWER_LABEL = { yes: 'Yes', no: 'No', na: 'Not applicable', unknown: 'Unknown', partial: 'Partly' };
    const STATUS_LABEL = { approved: 'Approved', rejected: 'Rejected', pending_review: 'Waiting for review', needs_more: 'Waiting for answers' };
    function human(value) {
      if (typeof window !== 'undefined' && typeof window.mvHuman === 'function') return window.mvHuman(value);
      const text = String(value || '').replace(/[_-]+/g, ' ').trim();
      return text ? text.charAt(0).toUpperCase() + text.slice(1) : '';
    }
    function person(value) {
      return String(value || '').replace(/^(user|agent|service):/, '');
    }
    function inDays(days) {
      return days >= 0 ? 'in ' + days + (days === 1 ? ' day' : ' days') : (-days) + (days === -1 ? ' day' : ' days') + ' overdue';
    }
    function problem(response, action) {
      if (typeof window !== 'undefined' && typeof window.mvErrorText === 'function') return window.mvErrorText(response, action);
      return 'Could not ' + action + '. Try again.';
    }

    function questionnaireCompletion(rec) {
      const result = rec.result || {}, questions = rec.question_text || {};
      const total = Number.isInteger(result.total) ? result.total : Object.keys(questions).length;
      const answered = Number.isInteger(result.answered) ? result.answered : Object.keys(questions).filter(function (id) {
        return ['yes', 'no', 'na'].includes(((rec.answers || {})[id] || {}).answer);
      }).length;
      return { answered: answered, total: total, incomplete: total > 0 && answered < total };
    }

    function render(rec) {
      if (rec.question_text) currentQuestions = rec.question_text;
      else rec.question_text = currentQuestions;
      currentRevision = Number(rec.revision || 0);
      body.innerHTML = '';
      const res = rec.result || {};
      currentCompletion = questionnaireCompletion(rec);
      const incomplete = currentCompletion.incomplete;
      const hasAnswers = Object.keys(rec.answers || {}).length > 0;
      const inherent = res.inherent_risk || res.risk_rating || '?';
      const residual = res.residual_risk || res.risk_rating || '?';
      const inhEl = document.getElementById('arv-inherent');
      inhEl.textContent = incomplete ? (hasAnswers ? 'Risk before safeguards (provisional): ' + human(inherent) : 'Risk before safeguards: not yet assessed') : 'Risk before safeguards: ' + human(inherent);
      inhEl.className = incomplete ? 'badge warn' : riskClass(inherent);
      riskEl.textContent = incomplete ? (hasAnswers ? 'Risk after safeguards (provisional): ' + human(residual) : 'Risk after safeguards: not yet assessed') : 'Risk after safeguards: ' + human(residual);
      riskEl.className = incomplete ? 'badge warn' : riskClass(residual);
      const sub = el('p', 'muted');
      const controls = (!incomplete && res.risks_in_scope != null)
        ? ' · ' + (res.controls_in_place || 0) + ' of ' + res.risks_in_scope +
          ' in-scope risk areas controlled'
        : '';
      sub.append(rec.type ? (TYPE_LABEL[rec.type] || human(rec.type)) + ' · ' : '',
                 (rec.subject || '') + controls);
      body.appendChild(sub);
      if (incomplete) body.appendChild(el('p', 'arv__incomplete', 'Questionnaire incomplete: ' + currentCompletion.answered + ' of ' + currentCompletion.total + ' questions resolved. Unanswered questions and recorded Unknown answers still need resolution. Any risk estimate is provisional; approving now records a decision on an incomplete questionnaire.'));
      renderAnswerEditor(rec);

      if (rec.status === 'approved' || rec.status === 'rejected') {
        const line = el('p', null);
        line.appendChild(el('span',
          'badge ' + (rec.status === 'approved' ? 'done' : 'blocked'),
          STATUS_LABEL[rec.status] || human(rec.status)));
        let txt = rec.decided_by ? ' by ' + person(rec.decided_by) : '';
        if (rec.next_review_at) {
          const days = Math.ceil((rec.next_review_at * 1000 - Date.now()) / 86400000);
          txt += ' · next review ' + inDays(days);
        }
        const note = el('span', 'muted', txt);
        note.style.fontSize = 'var(--text-sm)';
        line.appendChild(note);
        body.appendChild(line);
      }

      // Risk acceptance (B11) and forced re-review reason (B14).
      const acc = rec.risk_acceptance;
      if (acc) {
        const expired = acc.expires_at && (acc.expires_at * 1000 <= Date.now());
        const days = acc.expires_at ? Math.ceil((acc.expires_at * 1000 - Date.now()) / 86400000) : null;
        const p = el('p', null);
        p.appendChild(el('span', 'badge ' + (expired ? 'blocked' : 'warn'),
          expired ? 'Risk acceptance expired' : 'Risk accepted'));
        p.appendChild(el('span', 'muted',
          (acc.accepted_by ? ' by ' + person(acc.accepted_by) : '') +
          (days != null ? (expired ? ' · expired' : ' · expires ' + inDays(days)) : '') +
          (acc.rationale ? ' — “' + acc.rationale + '”' : '')));
        p.style.fontSize = 'var(--text-sm)';
        body.appendChild(p);
      }
      if (rec.review_forced_at && rec.review_trigger_reason) {
        const p = el('p', null);
        p.appendChild(el('span', 'badge warn', 'Due for a new review'));
        p.appendChild(el('span', 'muted', ' · ' + rec.review_trigger_reason));
        p.style.fontSize = 'var(--text-sm)';
        body.appendChild(p);
      }
      // Risk trend (B12): the vendor's residual risk over successive reviews.
      if (!incomplete) renderTrend(rec);

      body.appendChild(el('div', 'arv__section', 'Answers'));
      const answers = rec.answers || {};
      const qtext = rec.question_text || {};
      Object.keys(answers).forEach(function (qid) {
        const row = el('div', 'arv__row');
        const meta = qtext[qid] || {};
        const q = el('div', 'arv__q', meta.text || human(qid));
        if (meta.section) q.appendChild(el('div', 'arv__note', meta.section));
        if (answers[qid].note) q.appendChild(el('div', 'arv__note', '“' + answers[qid].note + '”'));
        if (answers[qid].by) q.appendChild(el('div', 'arv__note', '— answered by ' + person(answers[qid].by)));
        const a = String(answers[qid].answer || '');
        const pill = el('span', 'badge ' + (a === 'no' || a === 'unknown' || !a ? 'warn' : 'done'), ANSWER_LABEL[a] || (a ? human(a) : 'Not answered'));
        const ans = el('div', 'arv__ans'); ans.appendChild(pill);
        row.append(q, ans); body.appendChild(row);
      });

      const findings = (rec.result && rec.result.findings) || [];
      if (findings.length) {
        body.appendChild(el('div', 'arv__section', 'Findings (' + findings.length + ')'));
        findings.forEach(function (f) {
          const row = el('div', 'arv__row');
          const q = el('div', 'arv__q', f.question || f.text || human(f.question_id));
          if (f.recommendation) q.appendChild(el('div', 'arv__note', f.recommendation));
          const sev = el('span', 'badge ' + (f.severity === 'high' ? 'blocked' : f.severity === 'medium' ? 'warn' : 'done'), f.kind === 'unverified' ? 'Not yet confirmed' : human(f.severity));
          const ans = el('div', 'arv__ans'); ans.appendChild(sev);
          row.append(q, ans); body.appendChild(row);
        });
      }

      const fups = rec.followups || [];
      if (fups.length) {
        body.appendChild(el('div', 'arv__section', 'Follow-up thread'));
        fups.forEach(function (f) {
          const row = el('div', 'arv__row');
          const q = el('div', 'arv__q', f.question);
          if (f.answer) q.appendChild(el('div', 'arv__note', 'Reply: ' + f.answer + (f.answered_by ? ' — ' + person(f.answered_by) : '')));
          const st = el('span', 'badge ' + (f.answer ? 'done' : 'warn'), f.answer ? 'Answered' : 'Waiting for a reply');
          const ans = el('div', 'arv__ans'); ans.appendChild(st);
          row.append(q, ans); body.appendChild(row);
        });
      }

      body.appendChild(el('div', 'arv__section', 'Ask for more detail'));
      const hint = el('p', 'muted', 'One question per line. We\'ll ask the requester these questions. The assessment waits until they answer.');
      hint.style.fontSize = 'var(--text-sm)';
      body.appendChild(hint);
      const ta = el('textarea');
      ta.id = 'arv-questions';
      ta.placeholder = 'e.g. Which sub-processors receive personal data under this contract?';
      ta.setAttribute('aria-label', 'Follow-up questions, one per line');
      body.appendChild(ta);
      sendBtn.style.display = '';
      cadenceWrap.style.display = 'flex';
      approveBtn.style.display = '';
      rejectBtn.style.display = '';
      // Accept-risk and re-review-now apply to a decided (or pending) record.
      acceptBtn.style.display = '';
      triggerBtn.style.display = (rec.status === 'approved') ? '' : 'none';
    }

    function renderAnswerEditor(rec) {
      answerDirty = false;
      if (rec.status !== 'pending_review' && rec.status !== 'needs_more') return;
      const questions = rec.question_text || {}, answers = rec.answers || {};
      const choices = Object.keys(questions).map(function (id) { return { key: 'q:' + id, id: id, text: questions[id].text, guidance: questions[id].guidance || '', saved: answers[id] || {} }; });
      (rec.followups || []).forEach(function (item) {
        choices.push({ key: 'f:' + item.id, id: item.id, text: item.question, followup: true, saved: { answer: item.answer || '', note: item.answer || '' } });
      });
      if (!choices.length) return;
      const section = el('details', 'arv__answer-editor'); section.open = true;
      section.appendChild(el('summary', '', 'Complete the questionnaire'));
      section.appendChild(el('p', 'muted', 'Record what you can confirm. Choose Unknown when information is missing. Saving answers updates findings; it does not approve the assessment.'));
      const form = el('form'), picker = el('select'), answer = el('select'), note = el('textarea');
      picker.id = 'arv-answer-question'; answer.id = 'arv-answer-value'; note.id = 'arv-answer-note'; note.maxLength = 4000;
      const questionLabel = el('label', '', 'Question'); questionLabel.htmlFor = picker.id;
      const answerLabel = el('label', '', 'Your answer'); answerLabel.htmlFor = answer.id;
      const noteLabel = el('label', '', 'Notes and supporting information (optional)'); noteLabel.htmlFor = note.id;
      choices.forEach(function (choice, index) {
        const option = el('option', '', (choice.followup ? 'Follow-up: ' : (index + 1) + '. ') + choice.text); option.value = choice.key; picker.appendChild(option);
      });
      [['', 'Choose an answer'], ['yes', 'Yes'], ['no', 'No'], ['na', 'Not applicable'], ['unknown', 'Unknown — information needed']].forEach(function (value) {
        const option = el('option', '', value[1]); option.value = value[0]; answer.appendChild(option);
      });
      const prompt = el('p'), guidance = el('p', 'muted'), save = el('button', 'btn btn--primary', 'Save answer'); save.type = 'submit';
      const discard = el('button', 'btn btn--ghost', 'Discard answer changes'); discard.type = 'button';
      let selected = choices.find(function (choice) { return choice.key === selectedQuestion; }) || choices.find(function (choice) { return !choice.saved.answer; }) || choices[0];
      const memoryContext = document.querySelector?.('meta[name="lightwork-search-context"]')?.content || '';
      const memoryHeaders = memoryContext ? {'X-Lightwork-Search-Context': memoryContext} : {};
      const memory = el('div'), memoryButton = el('button', 'btn', 'Find precedent answers'), restore = el('div');
      // An answer the AI suggested and a person later changed can go
      // back to the AI's original value, in the draft only, until saved.
      function aiOriginal(choice) {
        if (!choice || choice.followup || (choice.saved && choice.saved.ai_metadata)) return null;
        const items = (rec.answer_history || []).filter(function (item) {
          return item.question_id === choice.id && item.previous_answer && item.previous_answer.ai_metadata;
        });
        return items.length ? items[items.length - 1].previous_answer : null;
      }
      function renderRestore() {
        restore.textContent = '';
        const original = aiOriginal(selected);
        if (!original) return;
        restore.appendChild(el('p', 'muted', 'Suggested by AI before a person changed it: ' +
          (ANSWER_LABEL[original.answer] || original.answer) + (original.note ? ' (' + original.note + ')' : '') + '.'));
        const back = el('button', 'btn btn--ghost', 'Restore the AI suggestion'); back.type = 'button';
        back.addEventListener('click', async function () {
          if (answerBusy) return;
          if (answerDirty && !(await mvConfirm('Replace this unsaved answer with the AI suggestion?', {okText: 'Restore the AI suggestion'}))) return;
          answer.value = original.answer; note.value = original.note || ''; answerDirty = true;
          statusEl.textContent = 'The AI suggestion is back in this answer only. Review it and save when you can confirm it.';
        });
        restore.appendChild(back);
      }
      memoryButton.type = 'button';
      let memorySuggestions = {}, rejectedSuggestions = new Set(), appliedSuggestion = '';
      function sourceUrl(source, exact) {
        let url = '/api/v1/assessment-memory/fragment/' + encodeURIComponent(source.assessment_id) + '/' + encodeURIComponent(source.question_id);
        if (exact) url += '?revision=' + encodeURIComponent(source.source_revision) + '&policy_digest=' + encodeURIComponent(source.policy_digest);
        return url;
      }
      async function readSource(source, exact) {
        const value = await window.mvFetchJSON(sourceUrl(source, exact), {cache: 'no-store', headers: memoryHeaders,
          onAccess: () => { memorySuggestions = {}; memory.textContent = ''; },
          messages: {409: 'The source changed. Compare the current source and refresh suggestions before using it.'}}, 'open the source answer');
        if (memoryContext && value.context !== memoryContext) { memorySuggestions = {}; memory.textContent = ''; throw new Error('Workspace changed. Reopen the assessment.'); }
        return value;
      }
      function evidenceText(source) {
        const date = source.source_date ? (typeof mvDateAbsolute === 'function' ? mvDateAbsolute(source.source_date) : new Date(source.source_date * 1000).toLocaleDateString()) : 'Date unknown';
        return source.subject + ' / saved ' + date + ' / revision ' + source.source_revision +
          ' / questionnaire version ' + (source.policy_version == null ? 'unknown' : source.policy_version) +
          ' / approval owner: ' + (source.approval_owner ? person(source.approval_owner) : 'Not recorded') +
          '. ' + (source.reasons || []).join(' ');
      }
      function renderSuggestion() {
        memory.textContent = '';
        const choice = selected, suggestion = memorySuggestions[choice.id];
        if (choice.followup || !suggestion) return;
        if (rejectedSuggestions.has(choice.id)) { memory.appendChild(el('p', 'muted', 'This suggested value was rejected. Other question suggestions are unchanged.')); return; }
        const label = suggestion.state === 'current_approved' ? 'Current approved assessment precedent' : suggestion.state === 'stale_precedent' ? 'Stale precedent - renewed evidence needed' : 'Unreviewed precedent - not verified evidence';
        memory.appendChild(el('p', 'badge ' + (suggestion.state === 'current_approved' ? 'done' : 'warn'), label));
        memory.appendChild(el('p', '', 'Suggested answer: ' + (ANSWER_LABEL[suggestion.answer] || suggestion.answer) + '. ' + suggestion.why_reused));
        memory.appendChild(el('p', 'muted', Math.round(suggestion.confidence * 100) + '% agreement. ' + suggestion.confidence_meaning));
        (suggestion.sources || []).concat(suggestion.conflicts || []).forEach(function (source) {
          const card = el('details'), preview = el('div');
          card.appendChild(el('summary', '', (source.answer === suggestion.answer ? 'Supporting answer: ' : 'Conflicting answer: ') + source.subject));
          card.appendChild(el('p', 'muted', evidenceText(source)));
          const exact = el('button', 'btn btn--ghost', 'Open exact saved answer'), latest = el('button', 'btn btn--ghost', 'Compare current source');
          exact.type = latest.type = 'button';
          async function openSource(current) {
            const generation = viewGeneration, id = currentId;
            try { const value = await readSource(source, !current); if (generation !== viewGeneration || id !== currentId || selected !== choice) return;
              preview.textContent = ''; preview.appendChild(el('p', '', value.question + ': ' + (ANSWER_LABEL[value.answer] || value.answer)));
              preview.appendChild(el('p', '', value.note)); preview.appendChild(el('p', 'muted', evidenceText(value)));
              preview.appendChild(el('p', 'muted', 'Current questionnaire version: ' + value.current_policy_version + '. Your current question: ' + choice.text));
            } catch(error) { preview.textContent = error.message; }
          }
          exact.addEventListener('click', function () { openSource(false); }); latest.addEventListener('click', function () { openSource(true); });
          card.append(exact, latest, preview); memory.appendChild(card);
        });
        const use = el('button', 'btn', 'Use this value in my draft'), reject = el('button', 'btn btn--ghost', 'Reject this suggested value');
        use.type = reject.type = 'button';
        use.addEventListener('click', async function () {
          if (answerBusy) return;
          const generation = viewGeneration, id = currentId; use.disabled = true;
          try {
            const current = await Promise.all((suggestion.sources || []).map(source => readSource(source, true)));
            if (generation !== viewGeneration || id !== currentId || selected !== choice) return;
            if (current.some(source => source.state !== 'current_approved') && !(await mvConfirm('This value comes from stale or unreviewed precedent. Add it only as your draft for independent review?', {okText: 'Use in draft'}))) return;
            if (answerDirty && !(await mvConfirm('Replace this unsaved answer and note with the reviewed suggestion?', {okText: 'Replace draft'}))) return;
            if (generation !== viewGeneration || id !== currentId || selected !== choice || answerBusy) return;
            answer.value = suggestion.answer; note.value = suggestion.note || ''; answerDirty = true; appliedSuggestion = choice.id;
            statusEl.textContent = 'Suggestion added to this answer only. Review it and save when you can confirm it.';
          } catch(error) { statusEl.textContent = error.message; } finally { use.disabled = false; }
        });
        reject.addEventListener('click', function () {
          if (answerBusy) return;
          rejectedSuggestions.add(choice.id);
          if (appliedSuggestion === choice.id && answer.value === suggestion.answer && note.value === (suggestion.note || '')) hydrate(choice);
          renderSuggestion();
        });
        memory.append(use, reject);
      }
      memoryButton.addEventListener('click', async function () {
        const generation = viewGeneration, id = currentId; memoryButton.disabled = true;
        try {
          const value = await window.mvFetchJSON('/api/v1/assessment-memory/similar?subject=' + encodeURIComponent(rec.subject || '') + '&type=' + encodeURIComponent(rec.type || '') + '&exclude_id=' + encodeURIComponent(id), {cache:'no-store', headers: memoryHeaders}, 'find permitted precedents'); if (generation !== viewGeneration || id !== currentId) return;
          if (memoryContext && value.context !== memoryContext) throw new Error('Workspace changed. Reopen the assessment.');
          memorySuggestions = value.suggestions || {}; renderSuggestion();
          statusEl.textContent = Object.keys(memorySuggestions).length ? 'Precedents are advisory. Review each answer separately.' : 'No matching precedent answers are available.';
        } catch(error) { statusEl.textContent = error.message; } finally { memoryButton.disabled = false; }
      });
      function hydrate(choice) {
        selected = choice; selectedQuestion = choice.key; picker.value = choice.key;
        prompt.textContent = choice.text; guidance.textContent = choice.guidance || '';
        answer.value = choice.saved.answer || ''; note.value = choice.saved.note || '';
        answer.hidden = answerLabel.hidden = !!choice.followup; answer.disabled = !!choice.followup; answer.required = !choice.followup;
        note.required = !!choice.followup; noteLabel.textContent = choice.followup ? 'Your reply' : 'Notes and supporting information (optional)'; answerDirty = false;
        renderSuggestion(); renderRestore();
      }
      picker.addEventListener('change', async function () {
        const next = choices.find(function (choice) { return choice.key === picker.value; });
        if (!next) return;
        picker.disabled = true;
        try {
          if (answerDirty && !(await mvConfirm('Discard the unsaved answer before changing questions?', { okText: 'Discard changes' }))) { picker.value = selected.key; return; }
          hydrate(next);
        } finally { picker.disabled = answerBusy; }
      });
      answer.addEventListener('input', function () { answerDirty = true; }); note.addEventListener('input', function () { answerDirty = true; });
      discard.addEventListener('click', function () { if (!answerBusy) hydrate(selected); });
      form.append(questionLabel, picker, prompt, guidance, memoryButton, memory, restore, answerLabel, answer, noteLabel, note, save, discard);
      section.appendChild(form); body.appendChild(section); hydrate(selected);
      form.addEventListener('submit', async function (event) {
        event.preventDefault();
        if (answerBusy || !form.reportValidity()) return;
        const id = currentId, revision = currentRevision, generation = viewGeneration, choice = selected;
        const value = choice.followup ? note.value.trim() : answer.value;
        if (!value) { statusEl.textContent = 'Enter an answer before saving.'; return; }
        const controls = [picker, answer, note, save, discard, sendBtn, approveBtn, rejectBtn, acceptBtn, triggerBtn];
        const disabled = controls.map(function (control) { return control.disabled; });
        controls.forEach(function (control) { control.disabled = true; }); answerBusy = true; statusEl.textContent = 'Saving answer…';
        try {
          const path = choice.followup ? '/followups/' + encodeURIComponent(choice.id) + '/answer' : '/answers/' + encodeURIComponent(choice.id);
          const payload = { answer: value, expected_revision: revision };
          if (!choice.followup) payload.note = note.value.trim();
          const response = await fetch('/api/v1/assess/sessions/' + encodeURIComponent(id) + path, {
            method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)
          });
          const data = await response.json();
          if (generation !== viewGeneration || id !== currentId) return;
          if (!response.ok) throw new Error(response.status === 409 ? 'This assessment changed. Reload the latest version before saving this answer.' : problem(response, 'save the answer'));
          if (!data || typeof data !== 'object') throw new Error('The saved answer could not be confirmed. Reload the assessment before trying again.');
          const saved = choice.followup ? (data.followups || []).find(function (item) { return item.id === choice.id; }) : data.answers && data.answers[choice.id];
          if (!data || data.id !== id || !Number.isInteger(data.revision) || data.revision < revision || !saved || saved.answer !== value) throw new Error('The saved answer could not be confirmed. Reload the assessment before trying again.');
          answerDirty = false; decidedInDialog = true;
          const next = choices[choices.indexOf(choice) + 1]; selectedQuestion = next ? next.key : choice.key;
          render(data); statusEl.textContent = 'Answer saved. Continue the questionnaire or review the findings.';
          const focus = document.getElementById(choice.followup ? 'arv-answer-note' : 'arv-answer-value'); if (focus) focus.focus();
        } catch (error) {
          if (generation === viewGeneration && id === currentId) {
            statusEl.textContent = error.message || 'Could not save the answer. Check your connection.';
            const refresh = el('button', 'btn btn--ghost', 'Reload latest assessment'); refresh.type = 'button';
            refresh.addEventListener('click', async function () {
              if (answerDirty && !(await mvConfirm('Discard this unsaved answer and load the latest assessment?', { okText: 'Reload latest' }))) return;
              answerDirty = false; await reload();
            }); statusEl.appendChild(refresh);
          }
        } finally { answerBusy = false; controls.forEach(function (control, index) { control.disabled = disabled[index]; }); }
      });
      const history = (rec.answer_history || []).filter(function (item) { return item.previous_answer; });
      const replies = rec.followup_answer_history || [];
      if (history.length || replies.length) {
        const details = el('details'); details.appendChild(el('summary', '', 'Previous answers and source information'));
        history.forEach(function (item) {
          const old = item.previous_answer, question = questions[item.question_id];
          details.appendChild(el('p', '', (question ? question.text : human(item.question_id)) + ': ' + (ANSWER_LABEL[old.answer] || human(old.answer)) + (old.note ? ' — ' + old.note : '') + (old.by ? ' · ' + person(old.by) : '')));
          if (old.ai_metadata) {
            const meta = old.ai_metadata || {};
            const source = meta.source || meta.provider || meta.model || '';
            const confidence = typeof meta.confidence === 'number' ? Math.round((meta.confidence <= 1 ? meta.confidence * 100 : meta.confidence)) : null;
            details.appendChild(el('p', 'muted', 'Suggested by AI' + (source ? ' from ' + human(source) : '') + (confidence != null ? ', confidence ' + confidence + '%' : '') + '.'));
          }
        });
        replies.forEach(function (item) {
          const previous = item.previous_answer || {}, question = (rec.followups || []).find(function (followup) { return followup.id === item.followup_id; });
          details.appendChild(el('p', '', (question ? question.question : 'Follow-up') + ': ' + (previous.answer || 'No previous reply') + (previous.answered_by ? ' · ' + person(previous.answered_by) : '')));
        }); section.appendChild(details);
      }
    }

    const RISK_RANK = { minimal: 0, low: 1, medium: 2, high: 3 };
    async function renderTrend(rec) {
      if (!rec.subject) return;
      try {
        const data = await window.mvFetchJSON('/api/v1/assess/trend?subject=' +
          encodeURIComponent(rec.subject) + '&type=' + encodeURIComponent(rec.type || ''));
        const t = data.trend || [];
        if (t.length < 2) return;
        const arrow = data.direction === 'up' ? '▲ Risk rising'
          : data.direction === 'down' ? '▼ Risk falling'
          : data.direction === 'unknown' ? '? Trend unclear (review order unknown)' : '▬ Risk steady';
        const cls = data.direction === 'up' ? 'blocked'
          : data.direction === 'down' ? 'done' : 'warn';
        const p = el('p', null);
        p.appendChild(el('span', 'badge ' + cls, arrow));
        if (data.direction_reason) p.title = data.direction_reason;
        p.appendChild(el('span', 'muted', ' · ' +
          t.map(function (x) { return human(x.residual_risk); }).join(' → ') +
          ' (' + t.length + ' reviews)'));
        p.style.fontSize = 'var(--text-sm)';
        body.appendChild(p);
      } catch (e) { /* trend is advisory */ }
    }

    async function decide(decision) {
      if (answerBusy || answerDirty) { statusEl.textContent = 'Save or discard the answer changes before recording a review decision.'; return; }
      const id = currentId, revision = currentRevision, generation = viewGeneration;
      approveBtn.disabled = rejectBtn.disabled = true;
      try {
        if (decision === 'approved' && currentCompletion.incomplete && !(await mvConfirm('Only ' + currentCompletion.answered + ' of ' + currentCompletion.total + ' questions are resolved. Approve this incomplete questionnaire?', { okText: 'Approve incomplete' }))) return;
        if (id !== currentId || revision !== currentRevision || generation !== viewGeneration || answerBusy || answerDirty) return;
        statusEl.textContent = decision === 'approved' ? 'Approving…' : 'Rejecting…';
        const days = parseInt(cadenceSel.value, 10) || 0;
        const r = await fetch('/api/v1/assess/sessions/' + encodeURIComponent(id) + '/decide', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            decision: decision,
            cadence_days: days,
            expected_revision: revision
          })
        });
        if (!r.ok) throw new Error(problem(r, 'record the decision'));
        const rec = await r.json();
        if (id !== currentId || generation !== viewGeneration) return;
        decidedInDialog = true;
        statusEl.textContent = decision === 'approved'
          ? (days ? 'Approved — next review in ' + days + ' days.' : 'Approved.')
          : 'Rejected.';
        render(rec);
        // Let the host page react — on /approvals the linked approval-gate
        // row decides itself from this (the reviewer shouldn't have to click
        // twice for one decision).
        document.dispatchEvent(new CustomEvent('mv-assessment-decided', {
          detail: { id: id, decision: decision }
        }));
      } catch (e) {
        if (id === currentId && generation === viewGeneration) statusEl.textContent = e && /^Could not/.test(e.message) ? e.message : problem(e, 'record the decision');
      } finally {
        if (id === currentId && generation === viewGeneration) approveBtn.disabled = rejectBtn.disabled = false;
      }
    }
    approveBtn.addEventListener('click', function () { decide('approved'); });
    rejectBtn.addEventListener('click', function () { decide('rejected'); });

    async function reload(id = currentId, generation = viewGeneration) {
      // A refusal keeps what is shown.
      const record = await window.mvFetchJSON('/api/v1/assess/sessions/' + encodeURIComponent(id)).catch(() => null);
      if (record && id === currentId && generation === viewGeneration) render(record);
    }

    // Accept the residual risk (B11): named owner, rationale, expiry.
    acceptBtn.addEventListener('click', async function () {
      if (answerBusy || answerDirty) { statusEl.textContent = 'Save or discard the answer changes before accepting risk.'; return; }
      const values = await mvForm('Accept the remaining risk', [
        { key: 'rationale', label: 'Why is this risk acceptable?', type: 'text', required: true,
          placeholder: 'For example: compensating controls, business need' },
        { key: 'expires_days', label: 'Acceptance lasts', type: 'select', default: '365', required: true,
          options: [{ value: '90', label: '3 months' }, { value: '180', label: '6 months' }, { value: '365', label: '1 year' }] }
      ], { okText: 'Accept risk' });
      if (!values || !String(values.rationale || '').trim()) return;
      const rationale = String(values.rationale);
      const days = parseInt(values.expires_days, 10);
      if (!days || days < 1) { statusEl.textContent = 'Choose how long the acceptance lasts.'; return; }
      const id = currentId, revision = currentRevision, generation = viewGeneration;
      acceptBtn.disabled = true;
      statusEl.textContent = 'Recording risk acceptance…';
      try {
        const r = await fetch('/api/v1/assess/sessions/' + encodeURIComponent(id) + '/accept-risk', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ rationale: rationale.trim(), expires_days: days, expected_revision: revision })
        });
        if (!r.ok) throw new Error(problem(r, 'accept the risk'));
        if (id !== currentId || generation !== viewGeneration) return;
        statusEl.textContent = 'Risk accepted — it comes up for review again in ' + days + ' days.';
        await reload(id, generation);
      } catch (e) {
        if (id === currentId && generation === viewGeneration) statusEl.textContent = e && /^Could not/.test(e.message) ? e.message : problem(e, 'accept the risk');
      } finally { if (id === currentId && generation === viewGeneration) acceptBtn.disabled = false; }
    });

    // Force a re-review now (B14): an external event trigger.
    triggerBtn.addEventListener('click', async function () {
      if (answerBusy || answerDirty) { statusEl.textContent = 'Save or discard the answer changes before reopening review.'; return; }
      const values = await mvForm('Start a new review now', [
        { key: 'reason', label: 'Why?', type: 'select', required: true, default: 'Contract renewal',
          options: ['Contract renewal', 'New sub-processor', 'Material change', 'Other'] },
        { key: 'note', label: 'Details (optional)', type: 'text' }
      ], { okText: 'Start review' });
      if (!values || !values.reason) return;
      const reason = values.reason + (values.note ? ': ' + String(values.note).trim() : '');
      const id = currentId, revision = currentRevision, generation = viewGeneration;
      triggerBtn.disabled = true;
      statusEl.textContent = 'Flagging for re-review…';
      try {
        const r = await fetch('/api/v1/assess/sessions/' + encodeURIComponent(id) + '/trigger-review', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ reason: reason.trim(), expected_revision: revision })
        });
        if (!r.ok) throw new Error(problem(r, 'start a new review'));
        if (id !== currentId || generation !== viewGeneration) return;
        statusEl.textContent = 'A new review has been started.';
        await reload(id, generation);
        if (id !== currentId || generation !== viewGeneration) return;
        document.dispatchEvent(new CustomEvent('mv-assessment-decided', { detail: { id: id, decision: 'retriggered' } }));
      } catch (e) {
        if (id === currentId && generation === viewGeneration) statusEl.textContent = e && /^Could not/.test(e.message) ? e.message : problem(e, 'start a new review');
      } finally { if (id === currentId && generation === viewGeneration) triggerBtn.disabled = false; }
    });

    async function open(id) {
      if (answerBusy) { statusEl.textContent = 'Wait for the answer to finish saving before opening another assessment.'; return; }
      if (answerDirty && !(await mvConfirm('Discard this unsaved answer and open another assessment?', { okText: 'Discard changes' }))) return;
      const generation = ++viewGeneration; answerDirty = false; selectedQuestion = ''; currentQuestions = {};
      currentId = id;
      currentRevision = null;
      decidedInDialog = false;
      approveBtn.disabled = rejectBtn.disabled = acceptBtn.disabled = triggerBtn.disabled = sendBtn.disabled = false;
      statusEl.textContent = '';
      body.innerHTML = '<p class="muted">Loading…</p>';
      sendBtn.style.display = 'none';
      if (!dlg.open) dlg.showModal();
      try {
        const record = await window.mvFetchJSON('/api/v1/assess/sessions/' + encodeURIComponent(id), {}, 'load the assessment'); if (generation === viewGeneration) render(record);
      } catch (e) {
        if (generation !== viewGeneration) return;
        body.innerHTML = '';
        body.appendChild(el('p', 'muted', e && /^Could not/.test(e.message) ? e.message : problem(e, 'load the assessment')));
      }
    }

    sendBtn.addEventListener('click', async function () {
      if (answerBusy || answerDirty) { statusEl.textContent = 'Save or discard the answer changes before asking for more detail.'; return; }
      const ta = document.getElementById('arv-questions');
      const questions = (ta && ta.value || '').split('\n').map(function (s) { return s.trim(); }).filter(Boolean);
      if (!questions.length) { statusEl.textContent = 'Write at least one question first.'; return; }
      const id = currentId, revision = currentRevision, generation = viewGeneration;
      sendBtn.disabled = true;
      statusEl.textContent = 'Sending…';
      try {
        const r = await fetch('/api/v1/assess/sessions/' + encodeURIComponent(id) + '/followups', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            questions: questions,
            expected_revision: revision
          })
        });
        if (!r.ok) throw new Error(problem(r, 'send the questions'));
        const record = await r.json();
        if (id !== currentId || generation !== viewGeneration) return;
        statusEl.textContent = 'Sent — the requester will be asked ' + (questions.length === 1 ? 'this question.' : 'these ' + questions.length + ' questions.');
        render(record);
      } catch (e) {
        if (id === currentId && generation === viewGeneration) statusEl.textContent = e && /^Could not/.test(e.message) ? e.message : problem(e, 'send the questions');
      } finally {
        if (id === currentId && generation === viewGeneration) sendBtn.disabled = false;
      }
    });
    async function closeReview() {
      if (answerBusy) { statusEl.textContent = 'Wait for the answer to finish saving before closing this assessment.'; return; }
      if (answerDirty && !(await mvConfirm('Discard the unsaved answer and close this assessment?', { okText: 'Discard changes' }))) return;
      answerDirty = false; dlg.close();
    }
    document.getElementById('arv-close').addEventListener('click', closeReview);
    dlg.addEventListener('cancel', function (event) { event.preventDefault(); closeReview(); });
    // A decision changes the row the page shows (status badge, due date):
    // refresh once the reviewer is done, not mid-dialog.
    dlg.addEventListener('close', function () {
      viewGeneration++;
      if (decidedInDialog) location.reload();
    });

    window.mvAssessmentReview = { open: open };
    const linkedAssessment = new URLSearchParams(window.location.search).get('assessment');
    if (linkedAssessment && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(linkedAssessment)) {
      open(linkedAssessment);
    }
  })();
