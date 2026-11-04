// Templates page: the community library. Lists what the configured libraries
// offer; an installation administrator can add one for everyone (checked on
// the server before it is saved).
(() => {
  'use strict';
  const root = document.getElementById('tplm-library');
  if (!root) return;
  const $ = id => document.getElementById('tplm-library-' + id);
  let busy = false;
  function make(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }
  function say(text) { window.mvStatus($('status'), text); }
  function failText(failure, what) {
    return typeof window.mvErrorText === 'function' ? window.mvErrorText(failure, what) : 'Could not ' + what + '. Try again.';
  }
  function label(name) { return typeof window.mvHuman === 'function' ? window.mvHuman(name) : name.replace(/[-_]+/g, ' '); }
  async function add(row, button) {
    const ok = typeof window.mvConfirm === 'function' && await window.mvConfirm(
      'Add “' + label(row.name) + '” from the community library? It comes from outside your organisation and becomes available to everyone here.',
      { okText: 'Add template' });
    if (!ok) return;
    button.disabled = true;
    say('Adding…');
    try {
      const data = await window.mvFetchJSON('/api/v1/templates/community/add',
        { method: 'POST', cache: 'no-store', body: { name: row.name, confirm: true } }, 'add the template');
      if (!data || data.added !== true) { say((data && data.message) || 'The template wasn’t added.'); button.disabled = false; return; }
      button.textContent = 'Added';
      say('Added “' + label(row.name) + '”. Reload the page to use it.');
    } catch (error) { say(failText(error, 'add the template')); button.disabled = false; }
  }
  async function load() {
    if (busy) return;
    busy = true; $('load').disabled = true; say('Loading the library…');
    try {
      const data = await window.mvFetchJSON('/api/v1/templates/community', { cache: 'no-store' }, 'load the library');
      const list = $('list');
      list.replaceChildren();
      if (!data || data.available === false) { say((data && data.message) || 'The library can’t be reached right now.'); return; }
      const rows = Array.isArray(data.templates) ? data.templates : [];
      rows.forEach(row => {
        const item = make('li', 'mv-row');
        const text = make('div', 'mv-row__main');
        text.append(make('p', 'mv-row__title', label(row.name)));
        if (row.summary) text.append(make('p', 'muted', row.summary));
        if (row.ratings > 0) text.append(make('p', 'muted', 'Rated ' + Number(row.rating).toFixed(1) + ' of 5 by ' + row.ratings + (row.ratings === 1 ? ' team' : ' teams')));
        item.append(text);
        if (row.installed) item.append(make('span', 'badge', 'Already added'));
        else if (data.can_add) {
          const button = make('button', 'btn btn--ghost', 'Add to templates');
          button.type = 'button';
          button.setAttribute('aria-label', 'Add ' + label(row.name) + ' to templates');
          button.addEventListener('click', () => add(row, button));
          item.append(button);
        }
        list.append(item);
      });
      say(rows.length ? rows.length + (rows.length === 1 ? ' library template.' : ' library templates.')
        + (data.can_add ? '' : ' An administrator can add them for everyone.') : 'The library has no templates right now.');
    } catch (error) { say(failText(error, 'load the library')); }
    finally { busy = false; $('load').disabled = false; }
  }
  $('load').addEventListener('click', load);
})();
