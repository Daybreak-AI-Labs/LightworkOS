(() => {
  'use strict';
  async function readJSON(response) {
    if (!(response.headers.get('content-type') || '').toLowerCase().startsWith('application/json')) throw new Error('The complete response could not be verified. No request was repeated.');
    const reader=response.body.getReader(), chunks=[];let size=0;
    for(;;){const next=await reader.read();if(next.done)break;size+=next.value.length;if(size>262144){await reader.cancel();throw new Error('The complete response is too large. No request was repeated.');}chunks.push(next.value);}
    const bytes=new Uint8Array(size);let position=0;chunks.forEach(chunk=>{bytes.set(chunk,position);position+=chunk.length;});return JSON.parse(new TextDecoder().decode(bytes));
  }
  // Ends the restricted flow's proof on the server. Its outcome is not shown; the reviewed choice is kept.
  const endFlow = path => { fetch(path, {method:'POST', credentials:'same-origin', cache:'no-store', redirect:'error'}).catch(() => {}); };
  const recovery = document.querySelector('[data-saml-recovery]');
  if (recovery) {
    const find = name => recovery.querySelector('[data-saml-' + name + ']');
    const email = find('email'), phrase = find('phrase'), code = find('code'), choices = find('recovery-original'), host = find('recovery-review'), status = find('recovery-status');
    let generation = 0, busy = false, reviewed = null;
    const say = text => { status.textContent = text; };
    const stamp = () => JSON.stringify([email.value, phrase.value, code ? code.value : '', choices.value]);
    const credentials = () => ({email: email.value.trim(), password: phrase.value, code: code ? code.value.trim() : ''});
    const invalidate = () => { reviewed = null; host.replaceChildren(); host.hidden = true; };
    const lock = value => { busy = value; recovery.querySelectorAll('button').forEach(button => { button.disabled = value; }); };
    async function request(path, body) {
      const abort = new AbortController(), timer = setTimeout(() => abort.abort(), 20000);
      try {
        const response = await fetch('/auth/company-saml-recovery' + path, {method:'POST', credentials:'same-origin', cache:'no-store', redirect:'error',
          headers:{'Content-Type':'application/json'}, body:JSON.stringify(body), signal:abort.signal});
        // A sign-in or access refusal discards private entries even when a gateway answers it without a JSON body.
        if (response.status === 401 || response.status === 403) { generation++; phrase.value = ''; if (code) code.value = ''; choices.replaceChildren(); invalidate(); }
        const data = await readJSON(response);
        if (!response.ok) {
          throw new Error(typeof data.detail === 'string' ? data.detail.slice(0,2000) : 'The request was refused. Read its original outcome before another review.');
        }
        return data;
      } finally { clearTimeout(timer); }
    }
    find('lookup').addEventListener('click', async () => {
      if (busy) return; const started = generation, entered = stamp(); lock(true); invalidate();
      try { const data = await request('/lookup', credentials()); if (started !== generation || entered !== stamp()) return;
        const previous = choices.value; choices.replaceChildren(new Option('Choose a dated request',''), ...data.requests.map(row => new Option(row.label,row.value)));
        if ([...choices.options].some(option => option.value === previous)) choices.value = previous;
        say('Retained originals loaded. Reading an outcome never repeats a change.');
      } catch (error) { say(error.message); } finally { lock(false); }
    });
    find('original-read').addEventListener('click', async () => {
      if (busy || !choices.value) return; const started = generation, entered = stamp(); lock(true);
      try { const data = await request('/original', {...credentials(),operation:choices.value}); if (started === generation && entered === stamp()) say(data.message); }
      catch (error) { say(error.message); } finally { lock(false); }
    });
    find('restore-review').addEventListener('click', async () => {
      if (busy || !choices.value) return; const started = generation, entered = stamp(); lock(true); invalidate();
      try {
        const data = await request('/review', {...credentials(),operation:choices.value}); if (started !== generation || entered !== stamp()) return;
        Object.entries(data.changes).forEach(([name,value]) => { const label=document.createElement('strong'), text=document.createElement('p'); label.textContent=name; text.textContent=value; host.append(label,text); });
        const label=document.createElement('label'), ack=document.createElement('input'); ack.type='checkbox'; ack.dataset.confirm=''; label.append(ack,' I reviewed the complete restoration.');
        const cancel=document.createElement('button'), save=document.createElement('button'); cancel.type=save.type='button'; cancel.className=save.className='btn'; cancel.textContent='Cancel'; save.textContent='Restore previous choice'; save.disabled=true;
        reviewed={...data,entered}; ack.addEventListener('change',()=>{save.disabled=!ack.checked || busy;}); cancel.addEventListener('click',()=>{invalidate();endFlow('/auth/company-saml-recovery/cancel');say('Nothing was submitted. Your entered work is kept.');});
        save.addEventListener('click',async()=>{
          if (busy || !reviewed || !ack.checked || reviewed.entered!==stamp()) {invalidate();say('Your choices changed. Review them again.');return;}
          const admitted=reviewed, current=generation; lock(true); invalidate();
          if (![...choices.options].some(option=>option.value===admitted.operation)) choices.add(new Option('Last submitted restoration',admitted.operation));
          choices.value=admitted.operation;
          try { sessionStorage.setItem('lightwork-saml-recovery-original',admitted.operation); } catch (_) { /* Native history remains. */ }
          try { const result=await request('/apply',{...credentials(),token:admitted.token,confirmed:true}); if(current===generation)say(result.message); }
          catch(error){say(error.message+' Read the original outcome; do not repeat the restoration.');} finally {lock(false);}
        });
        host.append(label,cancel,save); host.hidden=false; ack.focus(); say('Read the complete restoration before confirming it.');
      } catch(error){say(error.message);} finally{lock(false);const save=host.querySelector('button:last-child');if(save)save.disabled=true;}
    });
    recovery.addEventListener('input',event=>{if(!event.target.hasAttribute('data-confirm'))invalidate();}); choices.addEventListener('change',invalidate);
    lock(false); return;
  }
  const panel = document.querySelector('[data-saml-setup]');
  if (!panel) return;
  const form = panel.querySelector('[data-saml-files]'), review = panel.querySelector('[data-saml-review]');
  const message = panel.querySelector('[data-saml-status]'), requests = panel.querySelector('[data-saml-original]');
  const base = '/api/v1/settings/single-sign-on';
  let context = '', generation = 0, busy = false, pending = '', prepared = null;
  const say = text => { message.textContent = text; };
  const snapshot = () => [...form.elements].filter(el => el.name).map(el => el.type === 'file' ? el.files[0] || null : el.value);
  const same = stamp => { const now = snapshot(); return now.length === stamp.length && now.every((value, i) => value === stamp[i]); };
  const discardReview = () => { prepared = null; review.replaceChildren(); review.hidden = true; };
  const lock = active => { busy = active; panel.querySelectorAll('button').forEach(button => { button.disabled = active || !context; }); };
  const clear = () => { generation += 1; context = ''; form.reset(); requests.replaceChildren(); pending = ''; discardReview();
    panel.querySelector('[data-saml-activation-phrase]').value=''; if(activationCode)activationCode.value=''; panel.querySelector('[data-saml-check]').replaceChildren();
    const currentReview=panel.querySelector('[data-saml-activation-changes]');currentReview.replaceChildren();currentReview.hidden=true;
    const provider=panel.querySelector('[data-saml-provider]');provider.removeAttribute('href');provider.hidden=true;
    say('Your account or access changed. Private sign-in files and choices were cleared.'); };
  async function call(path, options = {}) {
    const abort = new AbortController(), timeout = setTimeout(() => abort.abort(), 20000);
    try {
      const response = await fetch(base + path, { credentials: 'same-origin', redirect: 'error', cache: 'no-store', ...options, signal: abort.signal });
      if (response.status === 401 || response.status === 403) clear();
      const data = await readJSON(response);
      if (!response.ok) {
        throw new Error(typeof data.detail === 'string' ? data.detail : 'This sign-in operation was refused. Your entered work is kept.');
      }
      if (context && data.context && data.context !== context) { clear(); throw new Error('Your current sign-in context changed. Private choices were cleared.'); }
      return data;
    } catch (error) {
      if (error instanceof TypeError) throw new Error('The response could not be confirmed. Your entered work is kept. Read the original request before another save.');
      throw error;
    } finally { clearTimeout(timeout); }
  }
  const json = body => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  function render(value, target) {
    if (value && typeof value === 'object') {
      const list = document.createElement('dl');
      Object.entries(value).forEach(([name, item]) => {
        const label = document.createElement('dt'), answer = document.createElement('dd');
        label.textContent = Array.isArray(value) ? 'Item ' + (Number(name) + 1) : name;
        render(item, answer); list.append(label, answer);
      });
      target.append(list);
    } else {
      const text = document.createElement('p'); text.textContent = typeof value === 'boolean' ? value ? 'Yes' : 'No' : String(value ?? 'Not supplied');
      text.style.overflowWrap = 'anywhere'; target.append(text);
    }
  }
  async function refresh(isCurrent = () => true) {
    const started = generation, data = await call('');
    if (started !== generation || !isCurrent()) return false;
    if (context && context !== data.context) { clear(); return false; }
    context = data.context;
    panel.querySelector('[data-saml-runtime]').textContent = data.runtime.message;
    const checks = panel.querySelector('[data-saml-check]'), selectedCheck = checks.value;
    checks.replaceChildren(new Option('Choose a verified sign-in',''), ...data.checks.map(row => new Option(row.label,row.value)));
    if ([...checks.options].some(option=>option.value===selectedCheck)) checks.value=selectedCheck;
    const selected = requests.value || pending;
    requests.replaceChildren(new Option('Choose a dated request', ''), ...data.requests.map(row => new Option(row.label, row.value)));
    if ([...requests.options].some(option => option.value === selected)) requests.value = selected;
    if (!busy) lock(false);
    return true;
  }
  form.addEventListener('input', discardReview);
  form.addEventListener('change', discardReview);
  form.addEventListener('submit', async event => {
    event.preventDefault(); if (busy) return;
    const started = generation, stamp = snapshot(); lock(true); discardReview();
    try {
      const body = new FormData(form); body.set('context', context);
      const data = await call('/review', { method: 'POST', body });
      if (started !== generation || !same(stamp)) { say('The files or provider details changed during review. Your entered work is kept; review it again.'); return; }
      prepared = { ...data, stamp }; pending = data.operation;
      try { sessionStorage.setItem('lightwork-saml-original:' + context, pending); } catch (_) { /* native retained list remains */ }
      render(data.changes, review);
      const notice = document.createElement('p'); notice.textContent = data.notice; review.append(notice);
      const label = document.createElement('label'), confirm = document.createElement('input'); confirm.type = 'checkbox';
      label.append(confirm, ' I reviewed these files and their complete effect.');
      const cancel = document.createElement('button'), save = document.createElement('button');
      cancel.type = save.type = 'button'; cancel.textContent = 'Cancel'; save.textContent = 'Save inactive setup'; save.className = cancel.className = 'btn'; save.disabled = true;
      confirm.addEventListener('change', () => { save.disabled = !confirm.checked; });
      cancel.addEventListener('click', () => { discardReview(); say('No sign-in settings changed. Your files and entered details are kept; the reviewed upload remains encrypted.'); form.elements.name.focus(); });
      save.addEventListener('click', async () => {
        if (busy || !prepared || !confirm.checked || !same(prepared.stamp)) { say('Review your current files and details again before saving.'); return; }
        const admitted = prepared, currentGeneration = generation; lock(true); discardReview();
        try {
          const result = await call('/apply', json({ operation: admitted.operation, context, confirmed: true }));
          if (currentGeneration !== generation) return;
          say(result.message);
          if (result.confirmed && same(admitted.stamp)) form.reset();
          await refresh();
        } catch (error) { if (currentGeneration === generation) say(error.message + ' Read the original setup outcome; do not repeat the save.'); }
        finally { lock(false); }
      });
      review.append(label, cancel, save); review.hidden = false; say('Read the full inactive setup before saving.');
    } catch (error) { if (started === generation) say(error.message); }
    finally { lock(false); if (review.querySelector('input[type=checkbox]')) review.querySelector('button:last-child').disabled = true; }
  });
  panel.querySelector('[data-saml-read]').addEventListener('click', async () => {
    if (busy) return; const selected = requests.value || pending;
    if (!selected) { say('Choose a dated original setup request.'); return; }
    const started = generation; lock(true);
    try { const result = await call('/original/' + encodeURIComponent(selected) + '?context=' + encodeURIComponent(context)); if (started === generation) say(result.message); }
    catch (error) { if (started === generation) say(error.message); } finally { lock(false); }
  });
  panel.querySelector('[data-saml-try]').addEventListener('click', async () => {
    if (busy) return; const popup = window.open('about:blank', '_blank'), started = generation; lock(true);
    try {
      const data = await call('/try', { method: 'POST' });
      if (started !== generation) { popup?.close(); return; }
      const url = new URL(data.authorization_url); if (url.protocol !== 'https:') throw new Error('The provider sign-in address is unavailable.');
      if (popup) { popup.opener = null; popup.location.href = url.href; }
      else { const link = panel.querySelector('[data-saml-provider]'); link.href = url.href; link.hidden = false; }
      say('Continue to your provider. This test does not enable single sign-on or grant a role. Reload current checks when you return.');
    } catch (error) { popup?.close(); if (started === generation) say(error.message); } finally { lock(false); }
  });
  const checks = panel.querySelector('[data-saml-check]'), phrase = panel.querySelector('[data-saml-activation-phrase]'), activationHost = panel.querySelector('[data-saml-activation-changes]');
  const activationCode = panel.querySelector('[data-saml-activation-code]');
  const codeValue = () => (activationCode ? activationCode.value.trim() : '');
  const invalidateActivation = () => {activationHost.replaceChildren();activationHost.hidden=true;};
  const activationStamp = () => JSON.stringify([checks.value,phrase.value,activationCode ? activationCode.value : '',context]);
  const reload = document.createElement('button');reload.type='button';reload.className='btn';reload.textContent='Read current sign-in checks';checks.parentElement.before(reload);
  reload.addEventListener('click',async()=>{if(busy)return;const started=generation;lock(true);discardReview();invalidateActivation();try{if(await refresh())say('Current sign-in checks loaded. Nothing was changed.');}catch(error){if(started===generation)say(error.message);}finally{lock(false);}});
  panel.querySelector('[data-saml-activation-review]').addEventListener('click',async()=>{
    if(busy)return;const started=generation, entered=activationStamp();lock(true);discardReview();invalidateActivation();
    try{
      const data=await call('/activation-review',json({check:checks.value,password:phrase.value,code:codeValue(),context}));
      if(started!==generation || entered!==activationStamp()){if(started===generation)say('Your choices changed during review. Keep them and review again.');return;}
      render(data.changes,activationHost);const label=document.createElement('label'),ack=document.createElement('input');ack.type='checkbox';label.append(ack,' I reviewed the complete activation.');
      const cancel=document.createElement('button'),save=document.createElement('button');cancel.type=save.type='button';cancel.className=save.className='btn';cancel.textContent='Cancel';save.textContent='Enable checked single sign-on';save.disabled=true;
      ack.addEventListener('change',()=>{save.disabled=!ack.checked || busy;});cancel.addEventListener('click',()=>{invalidateActivation();endFlow('/api/v1/settings/single-sign-on/cancel');say('Nothing was submitted. Your entered work is kept.');});
      save.addEventListener('click',async()=>{
        if(busy || !ack.checked || entered!==activationStamp()){invalidateActivation();say('Your choices changed. Review them again.');return;}
        const current=generation;lock(true);invalidateActivation();
        try{sessionStorage.setItem('lightwork-saml-activation-original',data.operation);}catch(_){/* Native recovery history remains. */}
        try{const result=await call('/activate',json({token:data.token,confirmed:true}));if(current===generation){say(result.message+' Use the separate original-owner recovery link to read this original or review restoration.');if(result.confirmed){phrase.value='';if(activationCode)activationCode.value='';}}}
        catch(error){if(current===generation)say(error.message+' Read the original through the owner recovery link; do not repeat activation.');}finally{lock(false);}
      });
      activationHost.append(label,cancel,save);activationHost.hidden=false;ack.focus();say('Read the complete activation before confirming it.');
    }catch(error){if(started===generation)say(error.message);}finally{lock(false);const save=activationHost.querySelector('button:last-child');if(save)save.disabled=true;}
  });
  phrase.addEventListener('input',invalidateActivation);checks.addEventListener('change',invalidateActivation);
  if(activationCode)activationCode.addEventListener('input',invalidateActivation);
  panel.addEventListener('input',event=>{if(form.contains(event.target))invalidateActivation();});
  document.addEventListener('lightwork:copilot-context-changed',invalidateActivation);
  document.addEventListener('lightwork:copilot-context-changed', event => { if (event.detail?.reason === 'selection') discardReview(); else clear(); });
  ['lightwork:workspace-changed', 'lightwork:account-context-changed'].forEach(name => document.addEventListener(name, clear));
  window.addEventListener('lightwork:copilot-context-changed', clear);
  window.LightworkCompanySamlSetup = { async open(expected, original = false, isCurrent = () => true) {
    const started = generation, stamp = snapshot(), previous=activationStamp();
    if (busy || !isCurrent() || !await refresh(isCurrent) || started !== generation || !isCurrent() || !same(stamp) || previous!==activationStamp() || context !== expected) return false;
    panel.scrollIntoView({ block: 'start' }); (original ? requests : form.elements.name).focus(); return isCurrent();
  } };
  lock(false);
  refresh().then(() => { try { pending = sessionStorage.getItem('lightwork-saml-original:' + context) || ''; } catch (_) {} }).catch(error => say(error.message));
})();
