/* Private downloads remain on their page; Copilot only opens these controls. */
(function () {
  'use strict';
  const root = document.querySelector('[data-report-context]');
  if (!root) return;
  const initial = root.dataset.reportContext || '';
  const rules = {
    soc2: ['/api/v1/compliance/downloads/soc2', 'lightwork-soc2-snapshot.json', 'application/json'],
    ai_inventory: ['/api/v1/compliance/downloads/ai-bom', 'lightwork-ai-inventory.cdx.json', 'application/json'],
    oscal: ['/api/v1/compliance/downloads/oscal', 'lightwork-assessment-results.oscal.json', 'application/json'],
    soa: ['/api/v1/compliance/downloads/soa', 'lightwork-statement-of-applicability.md', 'text/markdown'],
    public_key: ['/api/v1/consent/publishing/signing-key/public-key', 'lightwork-consent-public-key.json', 'application/json']
  };
  const buttons = Array.from(document.querySelectorAll('[data-report-download]'));
  let generation = 0, context = initial, controller = null, busy = false;
  const urls = new Set();
  function status(button, message) {
    const output = document.getElementById(button.dataset.reportStatus);
    if (output) { window.mvStatus ? window.mvStatus(output, message) : (output.textContent = message); }
  }
  function release() { urls.forEach(url => URL.revokeObjectURL(url)); urls.clear(); }
  function lock(value) { busy = value; buttons.forEach(button => { button.disabled = value || !context; }); }
  function clear() {
    ++generation; context = ''; if (controller) controller.abort(); release(); lock(false);
    buttons.forEach(button => status(button, 'Your account, workspace or access changed. Reload this page before downloading private information.'));
  }
  async function bounded(response, max) {
    if (Number(response.headers.get('Content-Length')) > max) throw new Error('This file is too large for a protected browser download. Nothing was offered.');
    if (!response.body) throw new Error('The file could not be read. Nothing was offered.');
    const reader = response.body.getReader(), chunks = []; let size = 0;
    try {
      while (true) {
        const part = await reader.read(); if (part.done) break;
        size += part.value.byteLength;
        if (size > max) throw new Error('This file is too large for a protected browser download. Nothing was offered.');
        chunks.push(part.value);
      }
      return new Blob(chunks, {type: response.headers.get('Content-Type') || ''});
    } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
  }
  async function checked(response) {
    if (response.redirected || !response.url.startsWith(location.origin + '/api/v1/')) throw new Error('Sign in again, then reload this page. No file was offered.');
    if (response.ok) return;
    if ([401, 403].includes(response.status)) clear();
    const failure = {status: response.status};
    try {
      const raw = await bounded(response, 64000);
      failure.detail = JSON.parse(await raw.text()).detail;
    } catch (_) { /* Keep the status; an unreadable error is never a report. */ }
    const error = new Error(window.mvErrorText ? window.mvErrorText(failure, 'download this file') : 'This file is unavailable. Try again from this page.');
    error.status = response.status; throw error;
  }
  async function catalog(signal, expected) {
    const response = await fetch('/api/v1/report-downloads', {credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal});
    await checked(response);
    if ((response.headers.get('Content-Type') || '').split(';')[0] !== 'application/json') throw new Error('Download access could not be verified. No file was offered.');
    const value = JSON.parse(await (await bounded(response, 64000)).text());
    if (!/^[a-f0-9]{64}$/.test(value.context) || value.context !== expected || !Array.isArray(value.choices) || value.max_bytes !== 8388608) {
      clear(); throw new Error('Your account or workspace changed. Reload this page before downloading private information.');
    }
    return value;
  }
  async function offer(button) {
    if (busy || !context) return;
    const kind = button.dataset.reportDownload, rule = rules[kind]; if (!rule) return;
    const assessment = document.getElementById('cmp-assessment');
    const selected = ['oscal', 'soa'].includes(kind) ? assessment?.value : '';
    if (['oscal', 'soa'].includes(kind) && !selected) { status(button, 'Choose an assessment first.'); assessment?.focus(); return; }
    const started = generation, expected = context; controller = new AbortController(); const own = controller;
    const timeout = setTimeout(() => own.abort(), 20000);
    const cancel = document.createElement('button'); cancel.type = 'button'; cancel.className = 'btn btn--ghost'; cancel.textContent = 'Cancel download';
    cancel.addEventListener('click', () => own.abort()); button.after(cancel); lock(true); status(button, 'Checking current access and preparing the file…');
    try {
      const current = await catalog(own.signal, expected);
      if (started !== generation || !current.choices.some(row => row.value === kind)) throw new Error('Current permission for this download is unavailable. No file was offered.');
      const url = rule[0] + (selected ? '?assessment=' + encodeURIComponent(selected) : '');
      const response = await fetch(url, {credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: own.signal, headers: {'X-Lightwork-Report-Context': expected}});
      await checked(response);
      if (response.headers.get('X-Lightwork-Report-Context') !== expected || (response.headers.get('Content-Type') || '').split(';')[0] !== rule[2] || !/^attachment\s*;/i.test(response.headers.get('Content-Disposition') || '')) throw new Error('This response is not the verified report file. Nothing was offered.');
      const keyRevision = kind === 'public_key' ? response.headers.get('X-Lightwork-Public-Key-Revision') : '';
      if (kind === 'public_key' && (!/^[a-f0-9]{64}$/.test(keyRevision) || current.choices.find(row => row.value === kind)?.revision !== keyRevision)) throw new Error('The signing key changed while preparing the file. Try the current download again; nothing was offered.');
      const blob = await bounded(response, current.max_bytes);
      const final = await catalog(own.signal, expected);
      if (started !== generation || !final.choices.some(row => row.value === kind) || (selected && assessment.value !== selected)) throw new Error('The selected assessment or your access changed. Your current choices were kept; no file was offered.');
      if (kind === 'public_key' && final.choices.find(row => row.value === kind)?.revision !== keyRevision) throw new Error('The signing key changed while preparing the file. Try the current download again; nothing was offered.');
      const object = URL.createObjectURL(blob); urls.add(object);
      const link = document.createElement('a'); link.href = object; link.download = rule[1]; document.body.appendChild(link); link.click(); link.remove();
      setTimeout(() => { URL.revokeObjectURL(object); urls.delete(object); }, 60000);
      status(button, 'The file was offered to this browser. Use its download controls to save it; receipt and storage are not independently confirmed.');
    } catch (failure) {
      if (started === generation) status(button, own.signal.aborted ? 'Download cancelled or timed out. Your choices were kept; try again when ready.' : failure instanceof TypeError || failure instanceof SyntaxError ? 'The download connection was interrupted or its response could not be verified. Your choices were kept; try again when ready.' : failure.message);
    } finally {
      clearTimeout(timeout); cancel.remove(); if (controller === own) controller = null;
      if (started === generation) lock(false);
    }
  }
  buttons.forEach(button => button.addEventListener('click', () => offer(button)));
  window.addEventListener('lightwork:context-changed', clear);
  window.addEventListener('lightwork:draft-context-changed', clear);
  document.addEventListener('lightwork:workspace-changed', clear);
  document.addEventListener('lightwork:account-context-changed', clear);
  window.addEventListener('pagehide', () => { ++generation; if (controller) controller.abort(); release(); });
  document.addEventListener('lightwork:copilot-context-changed', event => {
    if (event.detail?.reason === 'selection') return;
    // A catalog change is verified without adopting a different account.
    const stamp = generation, own = new AbortController(), timeout = setTimeout(() => own.abort(), 20000);
    catalog(own.signal, context).catch(failure => { if (stamp === generation && [401,403].includes(failure.status)) clear(); }).finally(() => clearTimeout(timeout));
  });
  window.LightworkReportDownloads = {open: async function (expected, kind, isCurrent = () => true) {
    const button = buttons.find(item => item.dataset.reportDownload === kind);
    if (!button || busy || expected !== context || !isCurrent()) return false;
    const stamp = generation, own = new AbortController(), timeout = setTimeout(() => own.abort(), 20000);
    try {
      const value = await catalog(own.signal, expected);
      if (stamp !== generation || expected !== context || !isCurrent() || !value.choices.some(row => row.value === kind)) return false;
      const target = button.hidden ? document.getElementById('cpp-signing-rotate') : ['oscal', 'soa'].includes(kind) ? document.getElementById('cmp-assessment') : button;
      if (!target || target.disabled || !isCurrent()) return false;
      target.scrollIntoView({block: 'center'}); target.focus(); return true;
    } catch (_) { return false; } finally { clearTimeout(timeout); }
  }};
  if (!/^[a-f0-9]{64}$/.test(context)) clear();
})();
