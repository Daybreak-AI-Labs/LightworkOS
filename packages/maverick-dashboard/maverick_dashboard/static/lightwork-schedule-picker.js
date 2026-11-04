// Automations page: "Create a schedule". People choose what to run and when
// (every day, weekday, week or month at a time, in a time zone); the server
// turns those choices into the timetable and checks it. A custom timetable is
// accepted only from Technical details, and the server checks it too.
(() => {
  'use strict';
  const form = document.getElementById('auto-new-form');
  const original = document.getElementById('auto-create-original');
  if (!original) return;
  const $ = id => document.getElementById('auto-new-' + id);
  const originalMessage = document.getElementById('auto-create-original-message');
  const originalRead = document.getElementById('auto-create-original-read');
  const originalNext = document.getElementById('auto-create-original-next');
  const fields = window.mvFieldErrors;
  let options = null, busy = false, previewTimer = null, epoch = 0, context = null, pending = null, reviewed = null, confirmedOriginal = false;
  function make(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }
  function say(text, error) { if (form) window.mvStatus($('preview'), text, { error: !!error }); }
  function key() { return 'lightwork.schedule.create.original.' + context; }
  function retain(value) {
    try {
      if (value) { sessionStorage.setItem(key(), JSON.stringify(value)); if (sessionStorage.getItem(key()) !== JSON.stringify(value)) throw new Error(); }
      else sessionStorage.removeItem(key());
    } catch (_) { throw new Error('This browser could not retain the original request. Nothing was submitted. Allow storage for this site and review again.'); }
    pending = value; confirmedOriginal = false; original.hidden = !value; originalNext.hidden = true;
  }
  function cancelReview() { reviewed = null; if (form) { $('review').hidden = true; $('review-values').replaceChildren(); $('confirm').disabled = true; } }
  function clearPrivate() {
    epoch++; context = null; options = null; pending = null; confirmedOriginal = false; cancelReview(); original.hidden = true; originalMessage.textContent = '';
    if (form) { form.reset(); $('text').value = ''; $('title').value = ''; $('params').replaceChildren(); $('workflow').replaceChildren(); $('rerun').replaceChildren(); if (fields) fields.forget(form); }
  }
  function request(url, body) { return window.mvFetchJSON(url, {method: body ? 'POST' : 'GET', cache: 'no-store', body, timeout: 15000, onAccess: clearPrivate, onContext: clearPrivate}, 'check this schedule request'); }
  async function readOriginal() {
    if (!pending || busy) return false;
    const held = pending, captured = epoch; originalRead.disabled = true;
    try {
      const data = await request('/api/v1/schedules/create-original', {reference: held.reference});
      if (captured !== epoch || pending !== held || data.context !== context) return false;
      originalMessage.textContent = (data.title ? '“' + data.title + '”: ' : '') + data.message + ' ' + data.execution + (data.source_notice ? ' ' + data.source_notice : '');
      confirmedOriginal = data.found === true; originalNext.hidden = !confirmedOriginal || !form; original.hidden = false;
      if (confirmedOriginal) document.dispatchEvent(new CustomEvent('lightwork:schedules-changed'));
      return true;
    } catch (error) { if (captured === epoch) originalMessage.textContent = error.message + ' No creation was repeated.'; return false; }
    finally { originalRead.disabled = false; }
  }
  originalRead.addEventListener('click', () => void readOriginal());
  originalNext.addEventListener('click', () => { if (busy || !confirmedOriginal) return; retain(null); if (form) { document.getElementById('auto-new-sched').open = true; $('save').focus(); } });
  document.getElementById('auto-create-original-clear').addEventListener('click', async () => {
    if (busy || !pending) return;
    const held = pending, captured = epoch;
    const ok = await window.mvConfirm('Clear this reminder after checking current schedules? This does not prove the earlier request failed. A separate creation could duplicate an existing or still-pending schedule.', {okText: 'I checked current schedules'});
    if (ok && !busy && captured === epoch && pending === held) { retain(null); say('The reminder was cleared. The original outcome was not reported as failed or successful.'); }
  });
  ['lightwork:workspace-changed', 'lightwork:account-context-changed', 'lightwork:connection-access-lost'].forEach(name => { document.addEventListener(name, clearPrivate); window.addEventListener(name, clearPrivate); });
  async function restoreOriginal() {
    const captured = epoch;
    try {
      const value = await request('/api/v1/schedules/options');
      if (captured !== epoch || !/^[a-f0-9]{64}$/.test(value.context || '')) return;
      if (context && context !== value.context) { clearPrivate(); return; }
      context = value.context;
      let saved = null; try { saved = JSON.parse(sessionStorage.getItem(key()) || 'null'); } catch (_) { saved = null; }
      if (saved && typeof saved.reference === 'string') { pending = saved; original.hidden = false; originalMessage.textContent = 'An earlier creation may have been interrupted. Check its original outcome before creating another schedule.'; }
    } catch (_) { /* A refused current-context read must not reveal another account's reference. */ }
  }
  window.LightworkScheduleCreation = {openOriginal: async (expected, isCurrent = () => true) => {
    const captured = epoch; if (!isCurrent() || busy) return false;
    await restoreOriginal();
    if (captured !== epoch || context !== expected || !isCurrent() || busy || !pending) return false;
    original.hidden = false; originalRead.focus(); return true;
  }, openReview: async (expected, isCurrent = () => true) => {
    if (!form || busy || !isCurrent()) return false;
    const captured = epoch, before = draftStamp();
    await restoreOriginal();
    if (captured !== epoch || context !== expected || !isCurrent() || busy || before !== draftStamp()) return false;
    if (pending) { original.hidden = false; originalRead.focus(); return true; }
    document.getElementById('auto-new-sched').open = true; $('save').focus(); return true;
  }};
  void restoreOriginal();
  if (!form) return;
  // Problems are written next to their field and listed in a summary at the
  // top of the form (mvFieldErrors); nothing typed is cleared.
  form.addEventListener('mv:validate', event => {
    const kind = what(), error = event.detail.error;
    if (kind === 'workflow') {
      if (!$('workflow').value) error($('workflow'), 'Choose the workflow to run.');
      for (const input of $('params').querySelectorAll('input[data-param]')) {
        if (!input.value.trim()) error(input, 'Enter ' + human(input.dataset.param).toLowerCase() + ' for this workflow.');
      }
    } else if (kind === 'task') {
      if (!$('text').value.trim()) error($('text'), 'Describe the task to run. For example: Send me a summary of new support tickets.');
    } else if (!$('rerun').value) error($('rerun'), 'Choose the earlier task to run again.');
  });
  function failed(failure) {
    if (fields) fields.fail(form, failure, 'create the schedule'); else say(failure.message, true);
  }
  function human(value) { return typeof window.mvHuman === 'function' ? window.mvHuman(value) : String(value).replace(/[-_]+/g, ' '); }
  function when(epoch) {
    if (typeof window.mvWhen === 'function') return window.mvWhen(epoch);
    return (window.mvTimeAbsolute ? window.mvTimeAbsolute(epoch) : new Date(epoch * 1000).toLocaleString());
  }
  function what() { const pick = form.querySelector('input[name="what"]:checked'); return pick ? pick.value : 'workflow'; }
  function timetable() {
    const repeat = $('repeat').value;
    const days = Array.from($('days').querySelectorAll('input[type=checkbox]')).filter(c => c.checked).map(c => Number(c.value));
    const out = { repeat: repeat, at: /^\d{2}:\d{2}$/.test($('at').value) ? $('at').value : '09:00', days: days,
      day_of_month: Number($('dom').value) || 1, every_hours: Number($('every').value) || 1, zone: $('zone').value || 'UTC' };
    const advanced = $('advanced').value.trim();
    if (advanced) out.advanced = advanced.slice(0, 120);
    return out;
  }
  function sync() {
    const kind = what(), repeat = $('repeat').value;
    $('workflow-wrap').hidden = kind !== 'workflow';
    $('text-wrap').hidden = kind !== 'task';
    $('rerun-wrap').hidden = kind !== 'rerun';
    $('at-wrap').hidden = repeat === 'hourly';
    $('days').hidden = repeat !== 'weekly';
    $('dom-wrap').hidden = repeat !== 'monthly';
    $('every-wrap').hidden = repeat !== 'hourly';
  }
  function params() {
    const box = $('params');
    box.replaceChildren();
    const chosen = (options && options.workflows || []).find(w => w.name === $('workflow').value);
    (chosen ? chosen.params : []).forEach((name, index) => {
      const id = 'auto-new-param-' + index;
      const label = make('label', null, human(name));
      label.htmlFor = id;
      const input = make('input', 'input');
      input.id = id; input.dataset.param = name; input.maxLength = 2000;
      box.append(label, input);
    });
  }
  async function preview() {
    const captured = epoch, stamp = JSON.stringify(timetable());
    try {
      const data = await request('/api/v1/schedules/preview', {timetable: timetable()});
      if (captured !== epoch || stamp !== JSON.stringify(timetable()) || busy) return;
      const runs = Array.isArray(data.next_runs) ? data.next_runs.filter(n => typeof n === 'number') : [];
      say(runs.length ? 'Next runs: ' + runs.map(when).join(' · ') : 'This timetable has no upcoming runs.');
    } catch (error) { if (captured === epoch && stamp === JSON.stringify(timetable()) && !busy) say(error.message, true); }
  }
  function schedulePreview() { sync(); clearTimeout(previewTimer); previewTimer = setTimeout(preview, 300); }
  async function load() {
    const captured = epoch;
    let loaded;
    try {
      loaded = await request('/api/v1/schedules/options');
    } catch (_) { return; }
    if (!loaded || captured !== epoch) return;
    options = loaded;
    if (context && context !== options.context) { clearPrivate(); return; }
    context = options.context;
    const workflow = $('workflow');
    workflow.replaceChildren(make('option', null, (options.workflows || []).length ? 'Choose a workflow' : 'No saved workflows yet'));
    workflow.firstChild.value = '';
    (options.workflows || []).forEach(w => { const o = make('option', null, human(w.title || w.name)); o.value = w.name; workflow.append(o); });
    const rerun = $('rerun');
    rerun.replaceChildren(make('option', null, (options.tasks || []).length ? 'Choose a task' : 'No earlier tasks yet'));
    rerun.firstChild.value = '';
    (options.tasks || []).forEach(t => { const o = make('option', null, t.title); o.value = String(t.id); rerun.append(o); });
    const zone = $('zone');
    let local = 'UTC';
    try { local = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'; } catch (_) { local = 'UTC'; }
    const zones = Array.isArray(options.zones) ? options.zones : ['UTC'];
    zone.replaceChildren();
    zones.forEach(z => { const o = make('option', null, z.replace(/_/g, ' ')); o.value = z; zone.append(o); });
    zone.value = zones.includes(local) ? local : 'UTC';
    // Lists are filled now, so what was typed before a reload can go back in.
    if (fields) { fields.restore(form); params(); fields.restore(form); }
    schedulePreview();
  }
  form.addEventListener('change', event => { cancelReview(); if (event.target === $('workflow')) params(); schedulePreview(); });
  form.addEventListener('input', () => { cancelReview(); });
  $('advanced').addEventListener('input', schedulePreview);
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (busy) return;
    if (pending) { original.hidden = false; originalMessage.textContent = 'Check the original request above, then explicitly choose a separate schedule if needed.'; originalRead.focus(); return; }
    // Without the shared checker (it runs first, on submit), check here.
    if (!fields) {
      const missing = [];
      form.dispatchEvent(new CustomEvent('mv:validate', { detail: { error: (control, message) => missing.push([control, message]) } }));
      if (missing.length) { say(missing[0][1]); missing[0][0].focus(); return; }
    }
    const body = choices(), stamp = draftStamp(), captured = epoch;
    busy = true; $('save').disabled = true;
    try {
      if (!context) throw new Error('Current account choices are not ready. Reopen this form before reviewing.');
      const data = await request('/api/v1/schedules/create-review', {context, schedule: body});
      if (captured !== epoch) return;
      if (stamp !== draftStamp() || data.context !== context) { say('Your choices changed while the review was loading. They are kept; review them again.', true); return; }
      reviewed = {data, body, stamp};
      const box = $('review-values'); box.replaceChildren();
      const field = (label, value) => { box.append(make('dt', null, label), make('dd', null, value)); };
      field('Schedule name', data.title); if (data.earlier_task) field('Earlier task', data.earlier_task);
      field('Work to run', data.work);
      Object.entries(data.inputs).forEach(([name, value]) => field(human(name), value));
      field('Repeat', repeatLabel(body.timetable)); field('Time zone', body.timetable.zone);
      field('Next runs', data.next_runs.map(when).join('\n'));
      $('review-notice').textContent = data.notice; $('review').hidden = false; $('confirm').disabled = false; $('confirm').focus();
    } catch (error) { failed(error); }
    finally { busy = false; $('save').disabled = false; }
  });
  function choices() {
    const kind = what(), body = {what: kind, timetable: timetable()}, title = $('title').value.trim();
    if (title) body.title = title;
    if (kind === 'workflow') { body.template = $('workflow').value; body.params = {}; for (const input of $('params').querySelectorAll('input[data-param]')) body.params[input.dataset.param] = input.value.trim(); }
    else if (kind === 'task') body.text = $('text').value.trim();
    else body.goal_id = Number($('rerun').value);
    return body;
  }
  function draftStamp() { return JSON.stringify(Array.from(form.elements).filter(control => /^(INPUT|SELECT|TEXTAREA)$/.test(control.tagName)).map(control => [control.id, control.name, control.type, control.value, control.checked])); }
  function repeatLabel(value) {
    if (value.advanced) return 'Custom timetable: ' + value.advanced;
    if (value.repeat === 'hourly') return 'Every ' + value.every_hours + ' hour(s)';
    if (value.repeat === 'monthly') return 'Monthly on day ' + value.day_of_month + ' at ' + value.at + '. Months without that date are skipped.';
    if (value.repeat === 'weekly') return 'Weekly on ' + value.days.map(day => ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'][day]).join(', ') + ' at ' + value.at;
    return (value.repeat === 'weekdays' ? 'Every weekday' : 'Every day') + ' at ' + value.at;
  }
  $('cancel').addEventListener('click', () => { if (!busy) cancelReview(); });
  $('confirm').addEventListener('click', async () => {
    if (!reviewed || pending || busy) return;
    const held = reviewed, captured = epoch;
    if (held.stamp !== draftStamp()) { cancelReview(); say('Your choices changed. Review the current draft again.', true); return; }
    busy = true; $('confirm').disabled = true; $('save').disabled = true;
    try {
      retain({reference: held.data.reference, operation: held.data.operation});
      originalMessage.textContent = 'This exact request is retained. Check its original outcome if the reply is interrupted.';
      const data = await request('/api/v1/schedules/add', {...held.body, review_reference: held.data.reference, confirmed: true});
      if (captured !== epoch || !pending || pending.reference !== held.data.reference || data.context !== context) return;
      confirmedOriginal = data.found === true; originalNext.hidden = !confirmedOriginal;
      originalMessage.textContent = (data.title ? '“' + data.title + '”: ' : '') + data.message + ' ' + data.execution;
      if (held.stamp === draftStamp() && fields) { fields.clear(form); fields.forget(form); }
      cancelReview();
      if (confirmedOriginal) document.dispatchEvent(new CustomEvent('lightwork:schedules-changed'));
    } catch (error) { if (captured === epoch) { cancelReview(); say('The reply did not confirm this creation. Your draft is kept. Check the original request; do not submit it again blindly.', true); originalMessage.textContent = 'The reply did not confirm this creation. Keep your draft and check the original request above. Do not create it again blindly.'; originalRead.focus(); } }
    finally { busy = false; $('save').disabled = false; if (reviewed) $('confirm').disabled = false; }
  });
  sync();
  document.getElementById('auto-new-sched').addEventListener('toggle', function once() {
    if (this.open && !options) load();
  });
  function fromHash() { if (location.hash === '#auto-new-sched') { document.getElementById('auto-new-sched').open = true; if (!options) load(); } }
  window.addEventListener('hashchange', fromHash);
  fromHash();
})();
