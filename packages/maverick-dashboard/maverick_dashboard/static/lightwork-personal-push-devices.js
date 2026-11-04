(function () {
  'use strict';
  const root = document.querySelector('[data-private-push]');
  if (!root) return;
  const find = key => root.querySelector('[data-push-' + key + ']');
  const form = find('register'), status = find('status'), list = find('list'), confirm = find('confirm');
  let snapshot = null, review = null, pending = '', busy = false, generation = 0, controller = null;
  const quietFields = ['timezone', 'quiet_enabled', 'quiet_start', 'quiet_end'];
  form.elements.timezone.value = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  function key() { return 'lightwork.private-destination.' + (snapshot ? snapshot.context : ''); }
  function notice(text) { status.textContent = text; }
  function invalidate() { review = null; confirm.checked = false; find('review').hidden = true; find('details').replaceChildren(); }
  function lock(value) {
    busy = value; root.querySelectorAll('button, input').forEach(element => { element.disabled = value; });
    find('apply').disabled = value || !review || !confirm.checked;
    find('register-button').disabled = value || !snapshot || !snapshot.external_available;
    list.querySelectorAll('[data-external-action]').forEach(button => { button.disabled = value || !snapshot.external_available; });
  }
  function clear() {
    generation++; if (controller) controller.abort(); snapshot = null; pending = ''; invalidate(); form.reset();
    list.replaceChildren(); find('note').textContent = ''; find('original').hidden = true;
    notice('Private destination information was cleared. Reload after signing in to the intended account and workspace.'); lock(false);
  }
  async function request(path, body) {
    const current = new AbortController(); controller = current;
    const timer = setTimeout(() => current.abort(), 20000);
    try {
      const response = await fetch('/api/v1/notifications/personal/destinations' + path, {
        method: body ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: current.signal,
        headers: body ? {'Content-Type': 'application/json', Accept: 'application/json'} : {Accept: 'application/json'},
        body: body ? JSON.stringify(body) : undefined});
      const raw = await response.text(); if (raw.length > 262144) throw new Error('The complete destination response could not be read. Nothing was repeated.');
      const value = JSON.parse(raw);
      if (!response.ok) { if ([401,403].includes(response.status)) clear(); throw new Error(typeof value.detail === 'string' ? value.detail : 'This destination action could not be confirmed. Nothing was repeated.'); }
      if (!value || !/^[a-f0-9]{64}$/.test(value.context) || (snapshot && value.context !== snapshot.context)) {
        clear(); throw new Error('Your account or workspace changed. Reload your notifications.');
      }
      return value;
    } finally { clearTimeout(timer); if (controller === current) controller = null; }
  }
  function quietDraft(container) {
    const value = {}; quietFields.forEach(name => { const input = container.querySelector('[name="' + name + '"]'); value[name] = name === 'quiet_enabled' ? input.checked : input.value; }); return value;
  }
  function quietControls(row, container) {
    const legend = document.createElement('legend'); legend.textContent = 'Quiet hours for ' + row.name; container.append(legend);
    [['timezone','Time zone','text'],['quiet_enabled','Hold notifications during these hours','checkbox'],['quiet_start','Quiet hours start','time'],['quiet_end','Quiet hours end','time']].forEach(([name,label,type]) => {
      const wrapper = document.createElement('label'), input = document.createElement('input'); input.name = name; input.type = type; input.className = type === 'checkbox' ? '' : 'input';
      if (type === 'checkbox') input.checked = row.quiet[name]; else { input.value = row.quiet[name]; input.required = true; if (name === 'timezone') { input.maxLength = 100; input.setAttribute('list','notification-timezones'); } }
      wrapper.append(document.createTextNode(label + ' '), input); const field = document.createElement('p'); field.append(wrapper); container.append(field);
    });
  }
  function render(value) {
    const drafts = new Map(); list.querySelectorAll('[data-destination-id]').forEach(card => drafts.set(card.dataset.destinationId, quietDraft(card)));
    snapshot = value; list.replaceChildren(); find('note').textContent = value.note;
    if (!value.devices.length) { const empty = document.createElement('p'); empty.textContent = 'No private destinations are registered to your account in this workspace.'; list.append(empty); }
    value.devices.forEach(row => {
      const card = document.createElement('article'); card.className = 'panel'; card.dataset.destinationId = row.id;
      const heading = document.createElement('h3'); heading.textContent = row.name + ' · ' + (row.active ? 'Enabled' : 'Paused'); card.append(heading);
      const explanation = document.createElement('p'); explanation.textContent = row.notice; card.append(explanation);
      const fieldset = document.createElement('fieldset'); quietControls({...row, quiet: drafts.get(row.id) || row.quiet}, fieldset); card.append(fieldset);
      [['quiet','Review quiet-hour changes'],[row.active ? 'pause' : 'enable',row.active ? 'Review pause' : 'Review enable'],['test','Review one private test'],['withdraw','Review removal']].forEach(([action,label]) => {
        const button = document.createElement('button'); button.type = 'button'; button.className = 'btn btn--ghost'; button.textContent = label;
        if (['enable','test'].includes(action)) button.dataset.externalAction = 'true';
        button.addEventListener('click', () => prepare({action, device: row.id, expected_revision: row.revision,
          ...(action === 'quiet' ? quietDraft(card) : {})})); card.append(button);
      });
      row.receipts.forEach(receipt => { const line = document.createElement('p'); line.textContent = new Date(receipt.at * 1000).toLocaleString() + ' · ' + receipt.message; card.append(line); });
      list.append(card);
    });
    try { pending = sessionStorage.getItem(key()) || ''; } catch (_) { /* Native original results remain retained. */ }
    find('original').hidden = !pending;
  }
  async function load() {
    const started = generation; const value = await request('');
    if (started !== generation) return false; render(value); return true;
  }
  async function prepare(body) {
    if (busy || !snapshot) return;
    const started = generation; invalidate(); lock(true);
    try {
      const value = await request('/review', {context: snapshot.context, ...body});
      if (started !== generation) return;
      value.details.forEach(text => { const paragraph = document.createElement('p'); paragraph.textContent = text; find('details').append(paragraph); });
      review = value; find('review').hidden = false; notice('Read the complete review, then confirm. This action has not been applied.');
    } catch (error) { if (started === generation) notice(error.message); }
    finally { lock(false); }
  }
  form.addEventListener('submit', event => {
    event.preventDefault(); if (!form.reportValidity()) return;
    prepare({action: 'register', name: form.elements.name.value, topic: form.elements.topic.value,
      access_token: form.elements.access_token.value, ...quietDraft(form)});
  });
  form.addEventListener('input', () => { if (!busy) { invalidate(); lock(false); } });
  list.addEventListener('input', () => { if (!busy) { invalidate(); lock(false); } });
  confirm.addEventListener('change', () => lock(busy));
  find('cancel').addEventListener('click', () => { invalidate(); lock(false); notice('Current setup kept. Your unfinished fields are still here.'); });
  find('apply').addEventListener('click', async () => {
    if (busy || !review || !confirm.checked) return;
    const started = generation, token = review.token, action = review.action; pending = token;
    try { sessionStorage.setItem(key(), token); } catch (_) { /* Never save plaintext credentials. */ }
    find('original').hidden = false; invalidate(); lock(true);
    try {
      const value = await request('/apply', {token, confirmed: true});
      if (started !== generation) return;
      notice(value.message);
      if (value.state === 'confirmed' && action === 'register') { form.reset(); form.elements.timezone.value = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'; }
      if (['confirmed','accepted','refused'].includes(value.state)) await load();
    } catch (_) { if (started === generation) notice('The action reply could not be confirmed. Read the original result before deciding what to do next. Nothing was automatically repeated.'); }
    finally { lock(false); }
  });
  find('original').addEventListener('click', async () => {
    if (busy || !snapshot || !pending) return;
    const started = generation; lock(true);
    try { const value = await request('/original', {token: pending}); if (started === generation) { notice(value.message); await load(); } }
    catch (error) { if (started === generation) notice(error.message); } finally { lock(false); }
  });
  find('refresh').addEventListener('click', async () => {
    if (busy) return; invalidate(); lock(true);
    try { await load(); } catch (error) { notice(error.message); } finally { lock(false); }
  });
  window.LightworkPersonalPush = {
    openReview: async function (context, options) {
      if (busy || !/^[a-f0-9]{64}$/.test(context) || (options && options.isCurrent && !options.isCurrent())) return false;
      const started = generation; lock(true);
      try {
        const value = await request('');
        if (started !== generation || value.context !== context || (options && options.isCurrent && !options.isCurrent())) return false;
        render(value); root.hidden = false;
        lock(false);
        const focus = review ? confirm : pending ? find('original') : form.elements.name;
        focus.focus(); root.scrollIntoView({block: 'start'});
        notice('Your private destination controls are open. Your unfinished fields and original result were kept.'); return true;
      } catch (error) { notice(error.message); return false; } finally { lock(false); }
    }
  };
  ['lightwork:workspace-changed','lightwork:account-context-changed','lightwork:personal-notifications-cleared'].forEach(name => document.addEventListener(name, clear));
  document.addEventListener('lightwork:personal-notifications-state', event => { if (snapshot && event.detail.context !== snapshot.context) clear(); });
  window.addEventListener('pagehide', clear);
  lock(true); load().catch(error => notice(error.message)).finally(() => lock(false));
}());
