// Agents page: "Set up an agent for your business". Drafts an agent
// from a description (nothing is saved), shows it plainly for review, then
// adds it with its documents after a confirmation. The drafted agent
// stays on the server; approval refers to the draft, never re-sends it.
(() => {
  'use strict';
  const root = document.getElementById('biz-setup');
  if (!root) return;
  const $ = id => document.getElementById('biz-' + id);
  const base = '/api/v1/agents/business-setup';
  const RISK = { low: 'Low: only reads and drafts', medium: 'Medium: can take everyday actions' };
  const addedKey = 'lightwork-business-agent-added';
  let job = null, busy = false;
  function make(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }
  function say(text) { window.mvStatus($('status'), text); }
  try {
    const added = sessionStorage.getItem(addedKey);
    if (added) {
      sessionStorage.removeItem(addedKey);
      const message = JSON.parse(added);
      if (message && message.name) {
        const label = 'Added “' + human(message.name) + '”.' + (message.documents_loaded ? ' Loaded ' + message.documents_loaded + ' document parts into its memory.' : '')
          + (message.message ? ' ' + message.message : '');
        say(label);
        const editorStatus = document.getElementById('agent-msg');
        if (editorStatus) editorStatus.textContent = label;
      }
    }
  } catch (_) { /* Private browsing may disable session storage; the agent still opens. */ }
  function failText(failure, what) {
    return typeof window.mvErrorText === 'function' ? window.mvErrorText(failure, what) : 'Could not ' + what + '. Try again.';
  }
  function human(value) { return typeof window.mvHuman === 'function' ? window.mvHuman(value) : String(value).replace(/_/g, ' '); }
  function lock(state) { busy = state; $('draft').disabled = state; $('approve').disabled = state; $('discard').disabled = state; }
  async function wait(id, step) {
    for (let tries = 0; tries < 900; tries += 1) {
      await new Promise(resolve => setTimeout(resolve, tries ? 2000 : 500));
      const data = await window.mvFetchJSON(base + '/' + id + '?step=' + step, { cache: 'no-store' });
      if (data && data.state === 'running') continue;
      return data || {};
    }
    throw new Error('timeout');
  }
  function list(title, items) {
    const box = make('div');
    if (!items.length) return box;
    box.append(make('p', null, title));
    const ul = make('ul');
    items.forEach(item => ul.append(make('li', null, item)));
    box.append(ul);
    return box;
  }
  function review(agent, withAi) {
    const out = $('summary');
    out.replaceChildren();
    out.append(make('h3', null, human(agent.name)));
    if (agent.summary) out.append(make('p', null, agent.summary));
    out.append(make('p', 'muted', 'Highest risk it may take: ' + (RISK[agent.risk] || human(agent.risk))
      + (withAi ? ' · Drafted with AI' : ' · Drafted from a standard outline')));
    out.append(list('Actions it may use:', agent.can_use.map(human)));
    out.append(list('Actions it may never use:', agent.cannot_use.map(human)));
    out.append(list('It refuses to:', agent.refuses));
    out.append(list('How it works, step by step:', agent.steps.map(s => s.name + ': ' + s.instruction + (s.review ? ' (a person reviews this)' : ''))));
    out.append(list('Missing skills:', agent.gaps.map(g => g.need + ' — ' + g.how)));
    if (agent.instructions) {
      const details = make('details');
      details.append(make('summary', null, 'Its full instructions'), make('p', null, agent.instructions));
      out.append(details);
    }
    $('review').hidden = false;
  }
  $('form').addEventListener('submit', async event => {
    event.preventDefault();
    if (busy) return;
    const name = $('name').value.trim();
    if (!name) { say('Enter a name for the new agent.'); $('name').focus(); return; }
    lock(true); $('review').hidden = true; job = null;
    say('Drafting the agent. Nothing is saved yet…');
    try {
      let started;
      try {
        started = await window.mvFetchJSON(base + '/draft', { method: 'POST', cache: 'no-store', plainDetail: true,
          body: { name: name, description: $('what').value.trim(), industry: $('industry').value.trim(), use_ai: $('ai').value === 'ai' } }, 'draft the agent');
      } catch (error) {
        say(error.message);
        if (error.status === 409) $('name').focus();
        return;
      }
      if (!started || !/^[a-f0-9]{32}$/.test(String(started.job))) { say('The draft couldn’t be checked.'); return; }
      const data = await wait(started.job, 'draft');
      const result = data.result || {};
      if (data.state !== 'done' || result.ran !== true || !result.agent) { say(result.message || 'The draft couldn’t be made. Try again.'); return; }
      job = started.job;
      review(result.agent, result.with_ai === true);
      say('Review the draft below. Nothing is saved until you add it.');
    } catch (error) { say(failText(error, 'draft the agent')); }
    finally { lock(false); $('status').focus(); }
  });
  $('discard').addEventListener('click', () => { job = null; $('review').hidden = true; say('The draft was discarded. Nothing was saved.'); });
  $('approve').addEventListener('click', async () => {
    if (busy || !job) return;
    const files = Array.from($('docs').files || []);
    if (files.length > 10) { say('Choose at most 10 documents.'); return; }
    const ok = typeof window.mvConfirm === 'function' && await window.mvConfirm(
      'Add this agent for everyone in this workspace? It can start work within the limits shown.' + (files.length ? ' The documents you chose are loaded into its memory.' : ''),
      { okText: 'Add agent' });
    if (!ok) return;
    lock(true); say('Adding the agent…');
    try {
      const form = new FormData();
      form.append('confirm', 'true');
      files.forEach(file => form.append('documents', file));
      const started = await window.mvFetchJSON(base + '/' + job + '/approve', { method: 'POST', cache: 'no-store', body: form }, 'add the agent');
      const data = await wait(started.job, 'approve');
      const result = data.result || {};
      if (result.saved !== true) { say(result.message || 'The agent wasn’t added.'); return; }
      job = null; $('review').hidden = true;
      try { sessionStorage.setItem(addedKey, JSON.stringify(result)); } catch (_) { /* Open it anyway. */ }
      window.location.assign('/agents?name=' + encodeURIComponent(result.name) + '#agent-form');
    } catch (error) { say(failText(error, 'add the agent')); }
    finally { lock(false); $('status').focus(); }
  });
})();
