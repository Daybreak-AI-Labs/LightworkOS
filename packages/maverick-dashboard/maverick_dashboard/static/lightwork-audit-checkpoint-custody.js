/* Native reviewed copies and read-only remote history recovery. No secret fields. */
(() => {
  'use strict';
  const root = document.getElementById('independent-checkpoint-custody');
  if (!root) return;
  const el = id => document.getElementById(id);
  const api = '/api/v1/audit/checkpoint-custody';
  let current = null, busy = false, selectedReview = null, accessLost = false;
  const labels = {review:'Waiting for independent review', approved:'Approved; requester can send',
    dispatching:'Copy admitted; read Original', unknown:'Copy unconfirmed; read Original',
    retained:'Exact version and retention confirmed', cancelled:'Cancelled before upload'};
  const person = value => value ? value.replace(/^user:/, '') : 'A second installation administrator is required';
  const node = (tag, text, cls) => { const item = document.createElement(tag); item.textContent = text;
    if (cls) item.className = cls; return item; };
  const notice = text => { el('acc-status').textContent = text; };
  const accessMessage = 'Your access changed. Sign in or reload the current page before continuing. The saved Original reference was kept.';
  function clearPrivate() {
    accessLost = true; current = null; selectedReview = null;
    el('acc-account').replaceChildren(new Option('Choose an account', ''));
    ['acc-requests', 'acc-review-result', 'acc-check-result'].forEach(id => el(id).replaceChildren());
    notice(accessMessage); lock(busy);
  }
  function unavailable(status) { const error = new Error(accessMessage); error.status = status; return error; }
  const slot = () => 'lightwork-audit-custody:' + current.context;
  const retained = () => { try { return localStorage.getItem(slot()); } catch (_) { return null; } };
  const remember = value => { try { localStorage.setItem(slot(), value); } catch (_) {
    throw new Error('This browser could not retain the Original request reference. No new copy was started.'); } };
  async function request(path, body) {
    if (accessLost) throw unavailable();
    const options = {cache:'no-store', onAccess:clearPrivate,
      messages:{unreadable:'The saved outcome could not be read. Keep this request and read Original.'},
      serverDetail:'The request could not be confirmed. Read Original before trying again.'};
    if (body !== undefined) { options.method = 'POST'; options.body = body; }
    let value;
    try { value = await window.mvFetchJSON(api + path, options, 'read the checkpoint copy'); }
    catch (error) { if (error.accessChanged) throw unavailable(error.status); throw error; }
    if (accessLost) throw unavailable();
    return value;
  }
  function lock(value) {
    busy = value;
    root.querySelectorAll('button, select, input').forEach(item => { item.disabled = accessLost || value || item.dataset.unavailable === 'true'; });
  }
  async function run(action) {
    if (busy || accessLost) return false;
    lock(true);
    try { await action(); return true; } catch (error) { notice(accessLost ? accessMessage : error.message); return false; }
    finally { lock(false); }
  }
  function button(text, action) {
    const item = node('button', text, 'btn btn--ghost'); item.type = 'button';
    item.addEventListener('click', () => run(action)); return item;
  }
  async function refresh({preserve = true} = {}) {
    const before = current, selected = el('acc-account').value;
    const value = await request('');
    if (accessLost) throw unavailable();
    if (before && before.context !== value.context) { clearPrivate(); throw unavailable(); }
    if (value.setup_required) {
      // Storage is not set up: say what to set up. There is no account or checkpoint to act on.
      current = null;
      el('acc-account').replaceChildren(new Option('Choose an account', ''));
      el('acc-review').dataset.unavailable = el('acc-check').dataset.unavailable = 'true';
      el('acc-requests').replaceChildren(node('p', 'No independent copies can be requested until storage is set up.', 'muted'));
      notice(value.setup_required);
      return value;
    }
    current = value;
    const choices = el('acc-account'); choices.replaceChildren(new Option('Choose an account', ''));
    value.accounts.forEach(account => choices.append(new Option(account.name, account.name)));
    if (preserve && value.accounts.some(account => account.name === selected)) choices.value = selected;
    el('acc-review').dataset.unavailable = !value.source || !value.accounts.length ? 'true' : 'false';
    el('acc-check').dataset.unavailable = !value.accounts.length ? 'true' : 'false';
    const source = value.source;
    notice(source ? `${value.note} Latest checkpoint ${source.sequence}, ${source.day}; retention ${value.retention_days.toLocaleString()} days.` : value.note);
    if (!value.accounts.length) notice('No matching saved Amazon account is available. Add your own account in Connections for ' + value.destination.bucket + ', ' + value.destination.region + '.');
    const list = el('acc-requests'); list.replaceChildren();
    list.append(node('p', value.request_scope, 'muted'));
    value.requests.slice().reverse().forEach(row => {
      const entry = node('div', '', 'ops-sub');
      entry.append(node('p', `Checkpoint ${row.sequence}, ${row.day} — ${labels[row.state] || 'Read the saved outcome'}`));
      entry.append(button('Read full review and Original', async () => show(await request('/' + row.id + '/original'))));
      list.append(entry);
    });
    if (!value.requests.length) list.append(node('p', 'No independent copies have been requested yet. Choose your saved Amazon account above, then choose Review a checkpoint copy.'));
    return value;
  }
  function show(row) {
    if (accessLost) return;
    selectedReview = row;
    const view = el('acc-review-result'); view.replaceChildren();
    view.append(node('h3', 'Full checkpoint copy review'));
    view.append(node('p', `${labels[row.state] || 'Read the saved outcome'}. Requester: ${person(row.requested_by)}. Reviewer: ${person(row.reviewed_by)}.`));
    if (row.workspace) view.append(node('p', 'Workspace: ' + row.workspace + '.'));
    view.append(node('p', `Copy ${row.checkpoint_count.toLocaleString()} signed checkpoints through ${row.sequence}, ${row.day}, using ${row.account}. Destination: ${row.destination.bucket}, ${row.destination.region}. Retain until ${new Date(row.retain_until).toLocaleString()}.`));
    view.append(node('p', row.statement));
    const history = document.createElement('details'); history.append(node('summary', 'Read every checkpoint included'));
    const items = document.createElement('ul');
    row.history.forEach(item => items.append(node('li', `${item.sequence}: ${item.day}, ${item.rows.toLocaleString()} recorded entries; ${item.kind === 'retirement' ? 'retired by policy' : item.kind === 'supersession' ? 'new history after an erasure' : 'history checkpoint'}.`)));
    history.append(items); view.append(history);
    if (row.result) view.append(node('p', row.result.message || 'Read the independently retained result.'));
    const actions = node('div', '', 'ops-actions');
    if (row.can_approve || row.can_apply || row.can_cancel) {
      const label = document.createElement('label'), check = document.createElement('input'); check.type = 'checkbox'; check.id = 'acc-confirm';
      label.append(check, document.createTextNode(' I reviewed the complete copy, people, destination and locked retention.')); view.append(label);
      const decide = async action => {
        if (!check.checked) throw new Error('Read the complete review and confirm it before continuing.');
        const value = await request('/' + row.id + '/' + action, {context:current.context,expected_revision:row.revision,confirm:true});
        show(value); await refresh();
      };
      if (row.can_approve) actions.append(button('Approve this copy independently', () => decide('approve')));
      if (row.can_apply) actions.append(button('Send the approved copy', () => decide('apply')));
      if (row.can_cancel) actions.append(button('Cancel before sending', () => decide('cancel')));
    }
    actions.append(button('Read Original without sending', async () => show(await request('/' + row.id + '/original'))));
    view.append(actions);
    actions.querySelector('button')?.focus();
  }
  function account() {
    const value = current.accounts.find(item => item.name === el('acc-account').value);
    if (!value) throw new Error('Choose your saved Amazon account.');
    return {context:current.context,account:value.name,account_revision:value.revision};
  }
  el('acc-review').addEventListener('click', () => run(async () => {
    const prior = retained();
    if (prior) {
      try { const saved = await request('/ACC-' + prior + '/original');
        if (saved.copy_may_exist || saved.can_apply || saved.state === 'review') { show(saved); return; }
      } catch (error) { if (!/no longer available/.test(error.message)) throw error; }
    }
    const reference = crypto.randomUUID().replaceAll('-', '');
    remember(reference); // before the first writer; a lost reply keeps Original.
    try { show(await request('/prepare', {...account(),inventory:current.inventory,reference})); await refresh(); }
    catch (error) { if (!accessLost) { const recovery = button('Read the saved Original request', async () => show(await request('/ACC-' + reference + '/original')));
      el('acc-review-result').replaceChildren(recovery); } throw error; }
  }));
  el('acc-check').addEventListener('click', () => run(async () => {
    const value = await request('/check', account());
    if (accessLost) return;
    const view = el('acc-check-result'); view.replaceChildren();
    const problems = {checkpoint_rollback:'Local checkpoints are older than independently retained history.', checkpoint_fork:'The local checkpoint was replaced with a different commitment.',
      checkpoint_missing:'Local checkpoint history is missing.', checkpoint_store_invalid:'The local checkpoint history could not be trusted.'};
    view.append(node('p', value.verified ? 'The current signed checkpoint history matches independently retained Amazon history.' : value.reason ||
      (value.problems || []).map(code => problems[code] || 'A signed history or lifecycle commitment did not match.').join(' ')));
    if (value.remote_sequence) view.append(node('p', `Newest independent checkpoint: ${value.remote_sequence}. Locked until ${new Date(value.retained_until).toLocaleString()}.`));
    if (value.scope) view.append(node('p', value.scope, 'muted'));
  }));
  el('acc-refresh').addEventListener('click', () => run(() => refresh()));
  window.LightworkAuditCheckpointCustody = {async openReview(context, {isCurrent} = {}) {
    if (accessLost) { notice(accessMessage); return false; }
    if (busy || !current || !/^[a-f0-9]{64}$/.test(context) || current.context !== context || (isCurrent && !isCurrent())) {
      notice('Your current work was kept. Finish the open request or reload the current history controls first.'); return false;
    }
    const inventory = current.inventory;
    const value = await request('');
    if (accessLost) return false;
    if (value.context !== context) { clearPrivate(); return false; }
    if (value.inventory !== inventory || (isCurrent && !isCurrent())) {
      notice('The available history, account or review changed. Your current selection was kept. Refresh the ordinary controls.'); return false;
    }
    root.scrollIntoView({block:'start',behavior:'smooth'});
    (selectedReview ? el('acc-review-result').querySelector('button') : el('acc-account'))?.focus();
    return true;
  }};
  ['lightwork:workspace-changed', 'lightwork:account-context-changed', 'lightwork:connection-access-lost'].forEach(name => document.addEventListener(name, clearPrivate));
  window.addEventListener('pagehide', clearPrivate);
  run(async () => {
    try { await refresh(); }
    catch (error) {
      // A failed first read must not leave the request list saying "Loading…".
      // When access was lost the page is locked (Refresh included) and says to
      // sign in or reload, so it must not also tell the person to use Refresh.
      // Nothing was read, so there is no account or checkpoint to act on; the
      // next successful refresh sets these from the real answer.
      if (!current) el('acc-review').dataset.unavailable = el('acc-check').dataset.unavailable = 'true';
      if (!current && !accessLost) el('acc-requests').replaceChildren(node('p', 'Saved copy requests could not be read. Use Refresh choices to try again.', 'muted'));
      throw error;
    }
    if (!current) return;
    const reference = retained();
    if (reference && /^[a-f0-9]{32}$/.test(reference)) {
      try { show(await request('/ACC-' + reference + '/original')); } catch (error) { notice(error.message); }
    }
  });
})();
