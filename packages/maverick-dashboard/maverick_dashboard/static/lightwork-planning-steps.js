// "Show planning steps": runs the plan, work and review loop on this task's
// request in the background and shows the trace. The task is never changed.
(() => {
  'use strict';
  const root = document.getElementById('planning-steps');
  if (!root) return;
  const goal = root.dataset.goal || '';
  if (!/^\d+$/.test(goal)) return;
  const $ = id => document.getElementById('ps-' + id);
  const STATUS = {
    done: 'The AI review considered the request met.',
    max_iterations: 'This attempt reached the rounds you chose. Its result is incomplete.',
    stalled: 'This attempt stopped without a revised plan. Its result is incomplete.',
    no_plan: 'The AI did not produce usable planning steps.',
    review_unavailable: 'The AI review could not be read. Earlier step outputs are an incomplete attempt.'
  };
  const VERDICT = { done: 'The AI considered the request met', revise: 'Plan changed', 'continue': 'Further work requested', unavailable: 'Not confirmed' };
  let busy = false;
  function product(node, text, values) {
    if (window.LightworkI18n) window.LightworkI18n.set(node, text, values);
    else node.textContent = text.replace(/\{(\w+)\}/g, (_, key) => values && values[key] !== undefined ? values[key] : _);
  }
  function translated(text) { return window.LightworkI18n ? window.LightworkI18n.text(text) : text; }
  function make(tag, cls, text, source = false) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) {
      if (source) { node.textContent = text; node.lang = 'und'; node.dir = 'auto'; node.dataset.userContent = '1'; }
      else product(node, text);
    }
    return node;
  }
  function say(text) { product($('status'), text); }
  function failText(failure) {
    return typeof window.mvErrorText === 'function' ? window.mvErrorText(failure, 'show the planning steps')
      : 'Could not show the planning steps. Try again.';
  }
  function valid(data) {
    return data && data.ran === true && Array.isArray(data.plan) && Array.isArray(data.steps) && Array.isArray(data.reviews)
      && data.plan.every(s => typeof s === 'string') && data.steps.every(s => s && typeof s.step === 'string' && typeof s.output === 'string')
      && data.reviews.every(r => r && Object.hasOwn(VERDICT, r.verdict) && typeof r.notes === 'string')
      && Object.hasOwn(STATUS, data.status) && Number.isFinite(data.cost) && data.cost >= 0;
  }
  function show(data) {
    const out = $('result');
    out.replaceChildren();
    if (data.plan.length) {
      const plan = make('section');
      plan.append(make('h3', null, 'The plan'));
      const list = make('ol');
      data.plan.forEach(step => list.append(make('li', null, step, true)));
      plan.append(list);
      out.append(plan);
    }
    if (data.steps.length) {
      const work = make('section');
      work.append(make('h3', null, 'What each step produced'));
      data.steps.forEach(step => {
        const block = make('details');
        block.append(make('summary', null, step.step, true), make('p', null, step.output || 'No output.', !!step.output));
        work.append(block);
      });
      out.append(work);
    }
    if (data.reviews.length) {
      const reviews = make('section');
      reviews.append(make('h3', null, 'Reviews'));
      const items = make('ol');
      data.reviews.forEach(r => {
        const item = make('li', null, VERDICT[r.verdict] || 'Reviewed');
        if (r.notes) item.append(document.createTextNode(': '), make('span', null, r.notes, true));
        items.append(item);
      });
      reviews.append(items);
      out.append(reviews);
    }
    const cost = window.mvMoney ? window.mvMoney(data.cost) : data.cost < 0.01 ? translated('less than one cent') : '$' + data.cost.toFixed(2);
    const summary = make('p', 'muted');
    product(summary, '{status} Recorded AI cost: {cost}. Nothing about the task was changed.', {status:translated(STATUS[data.status]), cost:cost});
    out.append(summary);
    out.hidden = false;
  }
  $('run').addEventListener('click', async () => {
    if (busy) return;
    busy = true; $('run').disabled = true; $('result').hidden = true;
    say('Working out the planning steps. This can take a few minutes…');
    try {
      const response = await fetch('/api/v1/goals/' + goal + '/planning-steps', {
        method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ passes: Number($('passes').value) || 2 })
      });
      if (!response.ok) { say(failText(response)); return; }
      const started = await response.json();
      if (!started || !/^[a-f0-9]{32}$/.test(String(started.job))) { say('The request couldn’t be checked. Try again.'); return; }
      for (let tries = 0; tries < 600; tries += 1) {
        await new Promise(resolve => setTimeout(resolve, tries ? 2000 : 500));
        const poll = await fetch('/api/v1/goals/' + goal + '/planning-steps/' + started.job, {
          credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' }
        });
        if (!poll.ok) { say(failText(poll)); return; }
        const job = await poll.json();
        if (job && job.state === 'running') continue;
        const data = job && job.result;
        if (data && data.ran === false) { say(typeof data.message === 'string' ? data.message : 'This couldn’t be started.'); return; }
        if (!valid(data)) { say((data && typeof data.message === 'string' && data.message) || 'The planning steps couldn’t be checked. Try again.'); return; }
        show(data);
        say(data.status === 'done' ? 'The planning attempt is ready below.' : STATUS[data.status]);
        return;
      }
      say('This is taking longer than expected. Check back later.');
    } catch (error) {
      say(failText(error));
    } finally {
      busy = false; $('run').disabled = false; $('status').focus();
    }
  });
})();
