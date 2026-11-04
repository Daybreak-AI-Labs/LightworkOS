// Ekko page: "Record activity". Starts the available app-in-front recorder
// or imports an existing activity file, then shows progress.
// Enrollment, limits and the recorder lease are all checked on the server.
(() => {
  'use strict';
  const root = document.getElementById('ekko-recording');
  if (!root) return;
  const $ = id => document.getElementById('ekko-rec-' + id);
  const MAX = 1000000;
  let busy = false;
  let availabilityRead = 0;
  let uncertainStart = null, activeSession = false, statusKnown = false, statusPending = false;
  function say(text) { window.mvStatus($('msg'), text); }
  function failText(failure, what) {
    return typeof window.mvErrorText === 'function' ? window.mvErrorText(failure, what) : 'Could not ' + what + '. Try again.';
  }
  function device() {
    const pick = window.LightworkEkkoDevice;
    const id = typeof pick === 'function' ? pick() : 'local-device';
    return /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$/.test(id) ? id : 'local-device';
  }
  function lock(state) {
    busy = state;
    $('import').disabled = $('watch').disabled = state || !statusKnown || activeSession || !!uncertainStart;
    $('check').disabled = statusPending; root.setAttribute('aria-busy', String(state));
  }
  async function checkWatching(report) {
    if (statusPending) return null;
    const chosen = device(), generation = availabilityRead;
    if (uncertainStart && uncertainStart.device !== chosen) {
      if (report) say('Return to the device where you started recording and check its watching status before recording again.');
      return null;
    }
    statusPending = true; lock(busy);
    try {
      const data = await window.mvFetchJSON('/api/v1/ekko/status?device_id=' + encodeURIComponent(chosen), {cache: 'no-store'}, 'check current watching status');
      if (generation !== availabilityRead || chosen !== device() || location.pathname !== '/ekko') return null;
      const session = data && data.session;
      if (!data || data.device_id !== chosen || !['waiting', 'live', 'stale'].includes(data.collector_state) || !(session === null || (session && typeof session.session_id === 'string'
          && ['created', 'running', 'paused', 'stopped', 'halted'].includes(session.state)))) throw new Error('The current watching status could not be checked.');
      const terminal = session && ['stopped', 'halted'].includes(session.state);
      statusKnown = true; activeSession = !!session && !terminal && (session.state === 'paused' || data.collector_state !== 'waiting');
      if (uncertainStart && session && !terminal && (session.session_id !== uncertainStart.before || data.collector_state !== 'waiting')) uncertainStart.observed = session.session_id;
      if (uncertainStart && session && (session.session_id !== uncertainStart.before || session.session_id === uncertainStart.observed)) {
        if (terminal) uncertainStart = null;
      }
      document.dispatchEvent(new CustomEvent('lightwork:ekko-recording-status', {detail: data}));
      if (report) say(activeSession ? 'Watching is ' + (session.state === 'paused' ? 'paused' : 'active') + '. Use Pause or Stop above before recording again.'
        : uncertainStart ? 'The earlier start remains unconfirmed. Activities may already have been kept. Check watching status again; do not repeat the start.'
          : 'No watching session is active on this device. This does not verify the outcome of an earlier recording.');
      return data;
    } catch (error) {
      statusKnown = false;
      if (report) say('Current watching status is unavailable. Activities may already have been kept. Use Pause or Stop above if shown; do not repeat an unconfirmed start.');
      return null;
    } finally { statusPending = false; lock(busy); }
  }
  function readText(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result || ''));
      reader.onerror = () => reject(reader.error);
      reader.readAsText(file);
    });
  }
  async function follow(job, live) {
    for (let tries = 0; tries < 43200; tries += 1) {
      await new Promise(resolve => setTimeout(resolve, tries ? 2000 : 500));
      let data;
      try { data = await window.mvFetchJSON('/api/v1/ekko/recording/' + job, { cache: 'no-store' }, 'check the recording'); }
      catch (error) { say('The recording outcome is unavailable. Activities may already have been kept. Check current watching status or use Pause or Stop above before recording again.'); return false; }
      if (data && data.state === 'running') { if (live) say('Recording. Use Pause or Stop above to end it.'); continue; }
      const result = data && data.result;
      if (!data || data.state !== 'done' || !result || !Number.isSafeInteger(result.recorded) || result.recorded < 0
          || !Number.isSafeInteger(result.skipped) || result.skipped < 0) {
        say('The recording outcome is unavailable. Activities may already have been kept. Check current watching status or use Pause or Stop above before recording again.'); return false;
      }
      const recorded = result.recorded, skipped = result.skipped;
      say((result.message ? result.message + ' ' : '') + 'Recorded ' + recorded + (recorded === 1 ? ' activity' : ' activities')
        + (skipped ? ' and skipped ' + skipped + ' that your enrollment doesn’t allow.' : '.'));
      return true;
    }
    say('The recording outcome could not be confirmed. Check current watching status or use Pause or Stop above before recording again.'); return false;
  }
  async function start(path, body, live) {
    const previous = await checkWatching(false);
    if (!previous) { say('Current watching status could not be checked. Nothing new was submitted. Check its status before recording.'); return; }
    if (activeSession || uncertainStart) { await checkWatching(true); return; }
    uncertainStart = {device: body.device_id, before: previous.session && previous.session.session_id, observed: null};
    let data;
    try { data = await window.mvFetchJSON(path, { method: 'POST', cache: 'no-store', body: body }, 'start recording'); }
    catch (error) {
      const detail = error.detail && error.detail.not_started === true ? error.detail : error.payload && error.payload.detail;
      if (detail && detail.not_started === true) { uncertainStart = null; say((typeof detail.message === 'string' ? detail.message : 'Recording was refused before it started.') + ' No recorder was started.'); }
      else say('The start reply could not be confirmed. Recording may already have started. Check current watching status or use Stop above before recording again.');
      await checkWatching(false); return;
    }
    if (!data || typeof data.job !== 'string' || !/^[a-f0-9]{32}$/.test(data.job)) {
      say('The start reply could not be confirmed. Recording may already have started. Check current watching status or use Stop above before recording again.');
      await checkWatching(false); return;
    }
    if (await follow(data.job, live)) uncertainStart = null;
    await checkWatching(false);
  }
  $('import').addEventListener('click', async () => {
    if (busy || uncertainStart || activeSession) return;
    if (!$('consent').checked) { say('Tick the box above to confirm what Ekko records.'); return; }
    const file = $('file').files && $('file').files[0];
    if (!file) { say('Choose an activity file first.'); return; }
    if (file.size > MAX) { say('That file is too large. Choose a file under 1 MB.'); return; }
    lock(true); say('Recording from the file…');
    try {
      const text = await readText(file);
      await start('/api/v1/ekko/recording/import', { device_id: device(), events: text.slice(0, MAX), acknowledge_capture_scope: true }, false);
    } catch (error) { say(failText(error, 'record from the file')); }
    finally { lock(false); }
  });
  $('watch').addEventListener('click', async () => {
    if (busy || uncertainStart || activeSession) return;
    if (!$('consent').checked) { say('Tick the box above to confirm what Ekko records.'); return; }
    lock(true); say('Starting the recorder…');
    try { await start('/api/v1/ekko/recording/watch', { device_id: device(), acknowledge_capture_scope: true }, true); }
    catch (error) { say(failText(error, 'start recording')); }
    finally { lock(false); }
  });
  $('check').addEventListener('click', () => checkWatching(true));
  function options(data) {
    if (!data || typeof data.active_app !== 'boolean' || typeof data.context !== 'string' || !/^[a-f0-9]{64}$/.test(data.context)
        || typeof data.availability_message !== 'string' || !data.availability_message || data.availability_message.length > 4000
        || typeof data.platform !== 'string' || !(data.observer === null || typeof data.observer === 'string')) {
      throw new Error('Recording availability could not be checked. Refresh this page before recording.');
    }
    return data;
  }
  function showAvailability(data) {
    $('watch').hidden = !data.active_app;
    $('availability').textContent = data.availability_message;
  }
  function modalOpen() {
    return Array.from(document.querySelectorAll('dialog[open], [role="dialog"][aria-modal="true"]')).some(dialog => !dialog.closest('#mv-copilot') && dialog.getClientRects().length);
  }
  function stamp() {
    return JSON.stringify({page: location.href, device: device(),
      fields: Array.from(document.querySelectorAll('input, select, textarea')).map(field => ({id: field.id, name: field.name,
        value: field.value, checked: field.checked, files: field.files ? Array.from(field.files).map(file => [file.name, file.size, file.lastModified]) : null})),
      details: Array.from(document.querySelectorAll('details')).map(detail => detail.open),
      dialogs: Array.from(document.querySelectorAll('dialog[open], [role="dialog"][aria-modal="true"]')).filter(dialog => dialog.getClientRects().length).map(dialog => dialog.id)});
  }
  const initialRead = ++availabilityRead;
  window.mvFetchJSON('/api/v1/ekko/recording/options', { cache: 'no-store' })
    .then(async data => { if (initialRead === availabilityRead && location.pathname === '/ekko') { showAvailability(options(data)); await checkWatching(false); } })
    .catch(error => {
      if (initialRead !== availabilityRead || location.pathname !== '/ekko') return;
      $('watch').hidden = true;
      $('availability').textContent = failText(error, 'check whether this computer can record activity');
    });
  function invalidateAvailability() {
    availabilityRead++;
    statusKnown = false; lock(busy);
    $('watch').hidden = true;
    $('availability').textContent = 'Your access or workspace changed. Reopen the recording controls before recording.';
  }
  ['lightwork:context-changed', 'lightwork:workspace-changed', 'lightwork:account-changed', 'lightwork:account-context-changed', 'lightwork:authority-changed'].forEach(event => {
    document.addEventListener(event, invalidateAvailability); window.addEventListener(event, invalidateAvailability);
  });
  document.addEventListener('lightwork:copilot-context-changed', event => { if (event.detail?.reason !== 'selection') invalidateAvailability(); });
  async function openControls(payload, handoff, discovery) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload) || Object.keys(payload).length
        || !handoff || typeof handoff.isCurrent !== 'function' || typeof handoff.context !== 'string' || !/^[a-f0-9]{64}$/.test(handoff.context)
        || !handoff.isCurrent() || location.pathname !== '/ekko' || busy || modalOpen() || !root.isConnected) return false;
    const before = stamp(), currentRead = ++availabilityRead;
    const current = () => currentRead === availabilityRead && handoff.isCurrent() && location.pathname === '/ekko' && !busy && !modalOpen() && root.isConnected && stamp() === before;
    try {
      const data = options(await window.mvFetchJSON('/api/v1/ekko/recording/options', {cache: 'no-store'}));
      if (!current() || data.context !== handoff.context) return false;
      if (discovery) {
        const heading = document.getElementById(discovery === 'planning' ? 'ekko-planning-heading' : 'ekko-opportunities-heading');
        if (!heading || !current()) return false;
        heading.scrollIntoView({block: 'nearest'}); heading.focus();
        document.dispatchEvent(new CustomEvent(discovery === 'planning' ? 'lightwork:ekko-planning-review' : 'lightwork:ekko-discovery-review'));
        return true;
      }
      showAvailability(data);
      await checkWatching(false);
      if (!current()) return false;
      root.scrollIntoView({block: 'nearest'}); $('consent').focus();
      return current();
    } catch (error) {
      if (current()) { $('watch').hidden = true; $('availability').textContent = failText(error, 'check whether this computer can record activity'); }
      return false;
    }
  }
  window.LightworkEkkoRecording = {
    openReview: (payload, handoff) => openControls(payload, handoff, false),
    openDiscovery: (payload, handoff) => openControls(payload, handoff, true),
    openPlanning: (payload, handoff) => openControls(payload, handoff, 'planning')
  };
})();
