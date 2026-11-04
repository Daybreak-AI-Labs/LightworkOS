/* Fixed ordinary controls; guidance never reads drafts or activates an action. */
(() => {
  'use strict';
  const PAGES = ['/start', '/chat', '/goals', '/connections', '/automations', '/learned'];
  const page = location.pathname;
  if (!PAGES.includes(page)) return;
  let current = null, index = 0, dialog = null, offer = null, marked = null, generation = 0, openingFocus = null;
  const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
  const node = (tag, text, cls) => { const value = document.createElement(tag); if (text !== undefined) value.textContent = text; if (cls) value.className = cls; return value; };
  function key() { return `lightwork-tour:${current.context}:${page}`; }
  function saved() { try { return JSON.parse(localStorage.getItem(key()) || 'null'); } catch (_) { return null; } }
  function remember(state) { try { localStorage.setItem(key(), JSON.stringify({index, state})); } catch (_) { /* guidance still works without persistence */ } }
  function unmark() { if (marked) marked.classList.remove('lw-tour-target'); marked = null; }
  function removeOffer() { if (offer) offer.remove(); offer = null; }
  function restoreFocus() { const target = openingFocus?.isConnected && visible(openingFocus) && !openingFocus.disabled ? openingFocus : offer?.querySelector('button') || document.getElementById('content'); if (target) target.focus({preventScroll:true}); }
  function pause() { remember('paused'); if (dialog) { dialog.close(); dialog.remove(); dialog = null; } unmark(); notice(true); restoreFocus(); }
  function stop() { generation += 1; unmark(); removeOffer(); if (dialog) { dialog.close(); dialog.remove(); dialog = null; } current = null; }
  function say(text) { if (typeof window.mvToast === 'function') window.mvToast(text, {error:true}); else if (offer) { const line = offer.querySelector('p'); if (typeof window.mvStatus === 'function') window.mvStatus(line, text, {error:true}); else line.textContent = text; } }
  async function fresh() {
    const started = ++generation;
    const value = await window.mvFetchJSON(`/api/v1/help/product-tour?page=${encodeURIComponent(page)}`, {cache:'no-store', plainDetail:true});
    if (started !== generation || location.pathname !== page) throw new Error('The page changed. Open its current tour again.');
    if (!value || value.page !== page || !hex(value.context) || !hex(value.revision) || !Array.isArray(value.steps) || !Array.isArray(value.pages)) throw new Error('The current tour could not be read. Your work is unchanged.');
    if (current && current.context !== value.context) { stop(); throw new Error('Your account or workspace changed. Reload this page before opening its tour.'); }
    if (!value.available) { stop(); throw new Error(value.detail || 'Guided help is unavailable on this page. Your work is unchanged.'); }
    current = value;
    return value;
  }
  function button(text, action, cls = 'btn btn--ghost') {
    const value = node('button', text, cls); value.type = 'button';
    value.addEventListener('click', async () => { value.disabled = true; try { await action(); } catch (error) { say(error.message || 'Guided help could not open. Your work is unchanged.'); } finally { if (value.isConnected) value.disabled = false; } });
    return value;
  }
  function notice(resume) {
    removeOffer();
    offer = node('aside', undefined, 'lw-tour-offer glass-surface'); offer.setAttribute('aria-label', 'A quick product tour');
    offer.append(node('h2', resume ? 'Your tour is paused' : 'Get to know Lightwork'), node('p', resume ? 'Your draft stays intact. Continue when you are ready.' : 'See where to give work, add supporting material and review results. The tour changes no settings and starts no work.'));
    const actions = node('div', undefined, 'lw-tour__actions');
    actions.append(button(resume ? 'Continue tour' : 'Take a quick tour', () => open(), 'btn btn--primary'), button('Not now', () => { remember('paused'); removeOffer(); }));
    offer.append(actions);
    const area = document.getElementById('cs-scroll') || document.getElementById('content');
    if (area) area.prepend(offer);
  }
  function visible(value) { return value && !value.hidden && value.getClientRects().length > 0 && getComputedStyle(value).visibility !== 'hidden'; }
  async function point() {
    const stepId = current.steps[index]?.id;
    await fresh();
    const step = current.steps.find(item => item.id === stepId);
    if (!step || document.querySelector('dialog[open]') !== dialog) throw new Error('This control changed or another review is open. Your draft is unchanged.');
    const target = document.getElementById(step.target);
    if (!target) throw new Error('This control is not available in the current page. No action was taken.');
    let parent = target;
    while (parent) { if (parent.tagName === 'DETAILS') parent.open = true; parent = parent.parentElement; }
    if (!visible(target)) throw new Error('This control is not available in the current setup. No action was taken.');
    const focus = document.getElementById(step.focus) || target;
    dialog.close(); dialog.remove(); dialog = null; unmark(); marked = target; target.classList.add('lw-tour-target');
    remember('active'); notice(true);
    target.scrollIntoView({block:'center'});
    if (visible(focus) && !focus.disabled) { if (!focus.matches('button,input,select,textarea,a,[tabindex]')) focus.setAttribute('tabindex','-1'); focus.focus({preventScroll:true}); }
  }
  function show() {
    if (!current) return;
    if (document.querySelector('dialog[open]') && document.querySelector('dialog[open]') !== dialog) throw new Error('Finish or close your current review first. Your entered details are kept.');
    removeOffer(); unmark();
    if (dialog) dialog.remove();
    index = Math.max(0, Math.min(index, current.steps.length - 1));
    const step = current.steps[index];
    dialog = node('dialog', undefined, 'lw-tour glass-surface'); dialog.setAttribute('aria-labelledby','lw-tour-title');
    const title = node('h2', step.title); title.id = 'lw-tour-title';
    dialog.append(node('p', `Step ${index + 1} of ${current.steps.length} · This page`, 'lw-tour__eyebrow'), title, node('p', step.body, 'lw-tour__copy'));
    const actions = node('div', undefined, 'lw-tour__actions');
    actions.append(button('Show me', point, 'btn btn--primary'));
    if (index > 0) actions.append(button('Back', async () => { await fresh(); index -= 1; remember('active'); show(); }));
    actions.append(button(index + 1 < current.steps.length ? 'Next' : 'Finish tour', async () => {
      await fresh();
      if (index + 1 < current.steps.length) { index += 1; remember('active'); show(); }
      else { remember('viewed'); dialog.close(); dialog.remove(); dialog = null; unmark(); restoreFocus(); if (typeof window.mvToast === 'function') window.mvToast('You viewed this page tour. No work or setup was marked complete.'); }
    }), button('Pause tour', pause));
    actions.append(button('Restart tour', async () => { await fresh(); index = 0; remember('active'); show(); }));
    dialog.append(actions);
    const details = node('details'); details.append(node('summary', 'Explore other pages'));
    const links = node('div', undefined, 'lw-tour__pages');
    current.pages.filter(item => item.page !== page && PAGES.includes(item.page)).forEach(item => {
      const link = node('a', item.label); link.href = item.page; link.target = '_blank'; link.rel = 'noopener'; links.append(link);
    });
    details.append(node('p','Other pages open in a new tab so your current draft stays here.','lw-tour__note'), links);
    dialog.append(details, node('p', current.detail, 'lw-tour__note'));
    dialog.addEventListener('cancel', event => { event.preventDefault(); pause(); });
    document.body.append(dialog); dialog.showModal(); actions.querySelector('button').focus();
  }
  async function open() { openingFocus = document.activeElement; await fresh(); const stored = saved(); index = Number.isInteger(stored?.index) ? stored.index : 0; remember('active'); show(); return true; }
  window.LightworkProductTour = {openReview: async (descriptor, options = {}) => {
    const same = () => typeof options.isCurrent === 'function' && options.isCurrent() && location.pathname === page;
    if (!same() || Object.keys(descriptor || {}).length || !hex(options.context)) return false;
    try { const value = await fresh(); if (!same() || value.context !== options.context) return false; openingFocus = document.activeElement; const stored = saved(); index = Number.isInteger(stored?.index) ? stored.index : 0; remember('active'); show(); return true; }
    catch (_) { return false; }
  }};
  document.querySelectorAll('[data-product-tour-open]').forEach(control => control.addEventListener('click', () => open().catch(error => say(error.message))));
  fresh().then(() => { if (page === '/start' && location.hash === '#product-tour') { open().catch(error => say(error.message)); return; } const stored = saved(); if (!stored) { index = 0; notice(false); } else if (stored.state === 'active') { index = stored.index || 0; notice(true); } }).catch(() => { stop(); });
})();
