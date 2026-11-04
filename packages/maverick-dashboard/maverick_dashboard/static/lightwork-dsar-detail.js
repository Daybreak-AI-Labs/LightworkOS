// One privacy request: every step is a button (start, confirm identity, add a
// system, check Microsoft 365, create the secure link, collect, erase, close).
(function () {
  'use strict';
  var doc = document;
  var page = doc.getElementById('dsar-page');
  if (!page) return;
  var requestId = page.getAttribute('data-request-id');
  var subject = page.getAttribute('data-subject') || '';
  var channel = page.getAttribute('data-channel') || '';
  var fulfillmentId = page.getAttribute('data-fulfillment-id');
  var revision = parseInt(page.getAttribute('data-revision') || '0', 10);
  var statusEl = doc.getElementById('dsar-status');
  var base = '/api/v1/privacy/dsar/';

  function $(id) { return doc.getElementById(id); }
  function say(text) { window.mvStatus(statusEl, text); }
  function fail(failure, action) {
    say(window.mvErrorText ? window.mvErrorText(failure, action) : 'Could not ' + action + '. Try again.');
  }
  // A refused change carries a plain sentence saying what is missing; show it.
  function failPlain(failure, action) {
    if (!failure || (failure.status !== 422 && failure.status !== 409)) {
      fail(failure, action); return;
    }
    var plain = window.mvPlainDetail ? window.mvPlainDetail(failure.detail) : '';
    if (plain) say('Could not ' + action + '. ' + plain); else fail(failure, action);
  }
  function ask(message, okText) {
    return window.mvConfirm ? window.mvConfirm(message, { okText: okText }) : Promise.resolve(false);
  }
  function form(title, fields, okText) {
    return window.mvForm ? window.mvForm(title, fields, { okText: okText }) : Promise.resolve(null);
  }
  function call(method, url, body) {
    return window.mvFetchJSON(url, {method: method, body: body});
  }
  function reloadSoon() { setTimeout(function () { location.reload(); }, 700); }
  function human(v) { return window.mvHuman ? window.mvHuman(v) : String(v); }
  function on(id, handler) { var el = $(id); if (el) el.addEventListener('click', handler); }

  // Keep only the encrypted native review, never personal outcome fields, in
  // the browser. An uncertain Close is read back; it is not sent again.
  var closePointerKey = 'lightwork:privacy-outcome-original:' + requestId;
  var closePending = null, closeBusy = false;
  try { closePending = JSON.parse(sessionStorage.getItem(closePointerKey) || 'null'); } catch (_) { /* The native reader still refuses malformed custody. */ }
  function retainClose(value) {
    closePending = value;
    try { if (value) sessionStorage.setItem(closePointerKey, JSON.stringify(value)); else sessionStorage.removeItem(closePointerKey); } catch (_) { /* The current page still keeps the original. */ }
    if ($('dsar-close-original')) $('dsar-close-original').hidden = !value;
  }
  retainClose(closePending);
  async function originalClose() {
    if (!closePending || closeBusy) return;
    closeBusy = true;
    try {
      var result = await call('POST', base + encodeURIComponent(requestId) + '/handling/original', { token: closePending.token });
      say(result.message + (result.audit_pending ? ' The activity receipt is still pending; the outcome itself is saved.' : ''));
      if (result.confirmed) { retainClose(null); reloadSoon(); }
      else $('dsar-close-fresh-review').hidden = result.new_review_available !== true;
    } catch (failure) { fail(failure, 'read the original outcome'); }
    finally { closeBusy = false; }
  }
  on('dsar-close-original', originalClose);
  on('dsar-close-fresh-review', function () {
    ask('The native reader confirmed that the old review expired without a saved outcome. Start a new review of the current request? Nothing will run or close yet.', 'Start a fresh review').then(function (ok) {
      if (!ok) return; retainClose(null); $('dsar-close-fresh-review').hidden = true; closeRequest(false);
    });
  });
  async function reviewAndClose(body, recordOnly) {
    if (closePending) { say('Read the earlier original outcome before preparing another close. Nothing new was sent.'); return; }
    if (closeBusy) return;
    closeBusy = true;
    try {
      var review = await call('POST', base + encodeURIComponent(requestId) + '/handling/review', { outcome: body });
      if (!review || typeof review.token !== 'string' || !review.outcome || typeof review.summary !== 'string') throw new Error('The complete outcome review could not be read.');
      if (!await ask(review.summary, recordOnly ? 'Record the reviewed outcome' : 'Close with this statement')) return;
      retainClose({ token: review.token });
      try {
        var result = await call('POST', base + encodeURIComponent(requestId) + '/close', Object.assign({}, review.outcome, { review_token: review.token }));
        if (!result || result.status !== 'closed' || !result.outcome || !result.outcome.operation_id || !Object.keys(review.outcome).every(function (key) { return result.outcome[key] === review.outcome[key]; })) throw new Error('The exact saved outcome could not be confirmed.');
        retainClose(null);
        var cleanup = result.export_cleanup;
        say(cleanup && cleanup.status === 'failed' ? cleanup.message : 'Your reviewed outcome statement was recorded.'); reloadSoon();
      } catch (_) { say('The outcome reply could not be confirmed. Read original outcome; Close will not be sent again automatically.'); }
    } catch (failure) { failPlain(failure, 'review the complete outcome'); }
    finally { closeBusy = false; }
  }
  window.LightworkDSARHandling = { openReview: async function (_selection, options) {
    options = options || {};
    var current = options.isCurrent || function () { return true; };
    if (!current() || !/^[a-f0-9]{64}$/.test(options.context || '') || location.pathname !== '/privacy/dsar/' + requestId) return false;
    try {
      var fresh = await call('GET', base + encodeURIComponent(requestId) + '/handling');
      if (!current() || fresh.context !== options.context || fresh.outcome_recorded) return false;
      var control = $('dsar-handle') || $('dsar-close') || $('dsar-record-outcome');
      if (!control) return false;
      // Focus the existing control. No form is replaced and no write starts.
      control.scrollIntoView({ block: 'center', behavior: 'auto' }); control.focus(); return current();
    } catch (_) { say('Current access to the privacy outcome controls could not be confirmed. Your entries are kept.'); return false; }
  } };

  // Where the "Completed" notice's secure link comes from, by page state.
  var LINK_HELP = {
    ready: 'Create it under "3. Send them a secure link" below, then paste it here.',
    unverified: 'Confirm who they are under "Answering the request" below, then create the link there and paste it here.',
    not_started: 'Press "Start answering" below to create a secure link, or paste a link from another system.',
    off: 'Paste the link where the requester can download their answer. To create one in Lightwork, turn on answering data requests below.'
  };

  var METHODS = [
    { value: 'email_challenge', label: 'Confirmed by email' },
    { value: 'account_login', label: 'Signed in to their account' },
    { value: 'document_check', label: 'Checked an ID document' },
    { value: 'in_person', label: 'Checked in person' },
    { value: 'verified_by_processor', label: 'Checked by a service provider' },
    { value: 'other', label: 'Another way' },
  ];

  on('dsar-acknowledge', function () {
    call('POST', base + encodeURIComponent(requestId) + '/acknowledge').then(function () {
      say('Receipt marked as confirmed.'); reloadSoon();
    }).catch(function (f) { fail(f, 'mark receipt confirmed'); });
  });

  on('dsar-extend', function () {
    form('Record an extension', [
      { key: 'reason', label: 'Why do you need more time?', type: 'text', required: true,
        placeholder: 'For example: many systems to search', help: 'This reason goes into the notice you send.' },
      { key: 'days', label: 'Extra days (leave empty for the full two months under GDPR)', type: 'text',
        placeholder: '45' },
    ], 'Record').then(function (values) {
      if (!values) return;
      var body = { reason: values.reason };
      if (values.days) body.days = parseInt(values.days, 10);
      return call('POST', base + encodeURIComponent(requestId) + '/extend', body).then(function () {
        say('Extension recorded. Now send the extension notice.'); reloadSoon();
      });
    }).catch(function (f) { fail(f, 'record the extension'); });
  });

  on('dsar-verify-manual', function () {
    form('Confirm identity another way', [
      { key: 'method', label: 'How did you confirm it?', type: 'select',
        options: METHODS.filter(function (m) { return m.value !== 'email_challenge'; }), default: 'document_check', required: true },
      { key: 'reference', label: 'Where is the proof kept?', type: 'text', required: true,
        placeholder: 'For example: support ticket 4521' },
    ], 'Confirm').then(function (values) {
      if (!values) return;
      return call('POST', base + encodeURIComponent(requestId) + '/verify', values).then(function () {
        say('Identity confirmed; the request is now open.'); reloadSoon();
      });
    }).catch(function (f) { fail(f, 'confirm identity'); });
  });

  doc.querySelectorAll('.dsar-send').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var kind = btn.getAttribute('data-kind');
      var fields = [];
      if (kind === 'refusal') {
        fields.push({ key: 'lawful_basis', label: 'Lawful basis for refusing (goes to the requester)', type: 'text', required: true });
      }
      if (kind === 'completion') {
        fields.push({ key: 'secure_link', label: 'Secure link', type: 'text', required: true,
          placeholder: 'https://…/dsar/response/…', help: LINK_HELP[page.getAttribute('data-fulfillment-state')] || LINK_HELP.off });
        fields.push({ key: 'secure_link_expires', label: 'Link expires on (YYYY-MM-DD)', type: 'text', required: true });
      }
      var ready = fields.length ? form('Send: ' + human(kind), fields, 'Send') : ask('Send the "' + human(kind) + '" notice to the requester now?', 'Send');
      ready.then(function (values) {
        if (!values) return;
        var body = { kind: kind };
        if (typeof values === 'object') Object.keys(values).forEach(function (k) { body[k] = values[k]; });
        return call('POST', base + encodeURIComponent(requestId) + '/send', body).then(function (out) {
          say(out.sent ? 'Notice sent.' : ['Notice not sent.', out.problem, out.next_step].filter(Boolean).join(' '));
          reloadSoon();
        });
      }).catch(function (f) { fail(f, 'send the notice'); });
    });
  });

  on('dsar-start', function () {
    call('POST', base + encodeURIComponent(requestId) + '/fulfillment').then(function () {
      say('Started. Next, confirm who they are.'); reloadSoon();
    }).catch(function (f) { fail(f, 'start answering this request'); });
  });

  on('dsar-identity', function () {
    form('Confirm identity', [
      { key: 'method', label: 'How did you confirm it?', type: 'select', options: METHODS, default: 'email_challenge', required: true },
      { key: 'reference', label: 'Where is the proof kept?', type: 'text', required: true,
        placeholder: 'For example: support ticket 4521', help: 'A note or reference so others can find the proof later.' },
    ], 'Confirm').then(function (values) {
      if (!values) return;
      return call('POST', base + 'fulfillment/' + encodeURIComponent(fulfillmentId) + '/identity', {
        method: values.method, reference: values.reference, revision: revision,
      }).then(function () { say('Identity confirmed.'); reloadSoon(); });
    }).catch(function (f) { fail(f, 'confirm their identity'); });
  });

  on('dsar-source', function () {
    form('Add a system you searched', [
      { key: 'source', label: 'System', type: 'text', required: true, placeholder: 'For example: Salesforce' },
      { key: 'reference', label: 'What you did', type: 'text', required: true, placeholder: 'For example: exported their contact record' },
      { key: 'items', label: 'Records found', type: 'number', default: 0, required: true },
    ], 'Add').then(function (values) {
      if (!values) return;
      var items = parseInt(values.items, 10);
      if (!(items >= 0)) { say('Enter how many records were found (0 or more).'); return; }
      return call('POST', base + 'fulfillment/' + encodeURIComponent(fulfillmentId) + '/sources', {
        source: values.source, reference: values.reference, items: items, revision: revision,
      }).then(function () { say('Added.'); reloadSoon(); });
    }).catch(function (f) { fail(f, 'add that system'); });
  });

  on('dsar-m365', function () {
    var button = $('dsar-m365');
    if (button.disabled) return;
    button.disabled = true;
    say('Checking Microsoft 365…');
    call('POST', base + encodeURIComponent(requestId) + '/collect-microsoft365', { revision: revision }).then(function (body) {
      if (typeof body.revision === 'number' && body.revision > 0) revision = body.revision;
      say(body.message || 'Microsoft 365 check is incomplete.');
      if (body.complete === true) reloadSoon();
    }).catch(function (f) {
      if (f && f.status === 503) { say('Microsoft 365 is not connected. Ask an administrator to connect it.'); return; }
      if (f && f.status === 422) { say('This person is not a Microsoft 365 account, so their data must be collected another way.'); return; }
      fail(f, 'check Microsoft 365');
    }).finally(function () { button.disabled = false; });
  });

  on('dsar-link', function () {
    form('Create a secure link', [
      { key: 'hours', label: 'Link works for', type: 'select', default: '72', options: [
        { value: '24', label: '1 day' }, { value: '72', label: '3 days' },
        { value: '168', label: '7 days' }, { value: '336', label: '14 days' },
      ] },
      { key: 'single', label: 'Allow it to be opened only once', type: 'bool', default: true },
    ], 'Create link').then(function (values) {
      if (!values) return;
      var body = { expires_hours: parseInt(values.hours || '72', 10), revision: revision };
      if (values.single) body.max_reads = 1;
      return call('POST', base + 'fulfillment/' + encodeURIComponent(fulfillmentId) + '/response', body).then(function (res) {
        var box = $('dsar-link-box');
        $('dsar-link-url').value = location.origin + res.response_path;
        box.hidden = false;
        $('dsar-link-url').focus();
        say('Link created. Copy it now; it will not be shown again.');
        if (res.revision) { revision = res.revision; page.setAttribute('data-revision', String(revision)); }
      });
    }).catch(function (f) { fail(f, 'create the link'); });
  });
  on('dsar-link-copy', function () {
    var v = $('dsar-link-url').value;
    if (window.mvCopy) window.mvCopy(v);
  });

  on('dsar-fulfill', function () {
    var kind = page.getAttribute('data-kind');
    var msg = kind === 'access' || kind === 'portability'
      ? 'Collect everything Lightwork holds about ' + subject + '? This saves an export for the request; it does not send a response.'
      : 'Mark this request ready for deletion? Their data is erased in the next step.';
    ask(msg, 'Continue').then(function (ok) {
      if (!ok) return;
      call('POST', base + encodeURIComponent(requestId) + '/fulfill').then(function () {
        say('Done.'); reloadSoon();
      }).catch(function (f) { fail(f, 'complete this step'); });
    });
  });

  on('dsar-download', function () {
    var button = $('dsar-download');
    ask('Download the collected personal data for review? Keep the file secure. Lightwork records that you were authorized to access it; this does not send anything to the requester.',
      'Download for review').then(async function (ok) {
      if (!ok) return;
      button.disabled = true;
      try {
        var response = await window.mvFetchJSON(base + encodeURIComponent(requestId) + '/export', {
          method: 'POST', cache: 'no-store', raw: true
        });
        var url = URL.createObjectURL(await response.blob());
        var link = doc.createElement('a');
        link.href = url; link.download = requestId + '-data.json';
        doc.body.appendChild(link); link.click(); link.remove();
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
        say('The package was prepared for download. Check your browser downloads; it has not been sent to the requester.');
      } catch (failure) { fail(failure, 'download the collected data'); }
      finally { button.disabled = false; }
    });
  });

  // Closing records what happened, so the program report counts a request
  // as answered only when an answer is on record.
  var lastErasure = '';
  function localDay() {
    var d = new Date();
    function two(n) { return (n < 10 ? '0' : '') + n; }
    return d.getFullYear() + '-' + two(d.getMonth() + 1) + '-' + two(d.getDate());
  }
  function closeRequest(recordOnly) {
    if (closePending) { say('Read the earlier original outcome first. Nothing new was sent.'); return; }
    var title = recordOnly ? 'Record how it was answered' : 'Close this request';
    var erasure = page.getAttribute('data-kind') === 'erasure';
    var actionNeeded = ['access', 'portability', 'erasure'].indexOf(page.getAttribute('data-kind')) < 0;
    var hint = page.getAttribute('data-answer-hint') || '';
    var unconfirmed = page.getAttribute('data-identity') === 'unverified';
    var chosen = '';
    return form(title, [
      { key: 'kind', label: 'What happened?', type: 'select', required: true, default: 'answered',
        help: unconfirmed ? 'Their identity is not confirmed. Confirm it before sending them their data or deleting it.' : undefined,
        options: [
        { value: 'answered', label: erasure ? 'We answered them (data erased, or kept for a lawful reason)' : actionNeeded ? 'We completed the requested action and sent the answer' : 'We sent them the answer' },
        { value: 'refused', label: 'We refused, with a lawful reason' },
        { value: 'withdrawn', label: 'They withdrew the request' },
        { value: 'no_response', label: 'Closed without an answer' }
      ] }
    ], 'Next').then(function (first) {
      if (!first) return null;
      chosen = first.kind || 'answered';
      var fields = [];
      if (chosen === 'answered' || chosen === 'refused') {
        if (chosen === 'answered' && actionNeeded) fields.push({ key: 'note', label: 'What was changed or stopped, and in which systems?', type: 'text', required: true,
          help: 'Describe work already completed. Saving this statement does not change a connected system.' });
        fields.push({ key: 'answered_on', label: 'Date the answer was sent', type: 'date', required: true, default: localDay() });
        if (chosen === 'answered' && erasure) {
          fields.push({ key: 'erasure', label: 'What happened to their data?', type: 'select', required: true, default: 'erased', options: [
            { value: 'erased', label: 'Erased everywhere we found it' },
            { value: 'not_erased', label: 'Kept, for a lawful reason' }
          ] });
          fields.push({ key: 'lawful_basis', label: 'Lawful reason for keeping it (only if kept)', type: 'text' });
        }
        if (chosen === 'refused') {
          fields.push({ key: 'lawful_basis', label: 'Lawful reason for refusing', type: 'text', required: true });
        }
        fields.push({ key: 'reference', label: 'Where is the proof kept?', type: 'text', required: true,
          default: lastErasure || hint, placeholder: 'For example: sent from the privacy inbox, ticket 4521' });
      } else {
        fields.push({ key: 'note', label: chosen === 'withdrawn' ? 'How did they withdraw it? (optional)' : 'Why is there no answer? (optional)', type: 'text' });
      }
      return form(title, fields, recordOnly ? 'Record' : 'Close request');
    }).then(function (values) {
      if (!values) return;
      var body = { kind: chosen };
      Object.keys(values).forEach(function (key) { body[key] = values[key]; });
      if (body.erasure === 'not_erased' && !body.lawful_basis) {
        say('Add the lawful reason for keeping their data, then try again.');
        return;
      }
      return reviewAndClose(body, recordOnly);
    }).catch(function (f) { failPlain(f, recordOnly ? 'record the answer' : 'close the request'); });
  }
  // A closed access or portability request whose saved export could not be
  // removed offers the cleanup again instead of a second close.
  function retryCleanup() {
    ask('Try removing this request’s saved export again?', 'Retry cleanup').then(function (ok) {
      if (!ok) return;
      call('POST', base + encodeURIComponent(requestId) + '/close').then(function (result) {
        var cleanup = result && result.export_cleanup;
        say(cleanup && cleanup.status === 'failed' ? cleanup.message : 'Saved export cleanup complete.');
        reloadSoon();
      }).catch(function (f) { failPlain(f, 'remove the saved export'); });
    });
  }
  on('dsar-close', function () {
    if (page.getAttribute('data-status') === 'closed') { retryCleanup(); return; }
    closeRequest(false);
  });
  on('dsar-record-outcome', function () { closeRequest(true); });
  on('dsar-handle', function () { closeRequest(false); });
  if (location.hash === '#close' && $('dsar-close') && page.getAttribute('data-status') !== 'closed') closeRequest(false);

  // Erasure: pick the matching person (by their identifier) and erase.
  on('dsar-erase', function () {
    call('GET', '/api/v1/compliance/people').then(function (body) {
      // The request's own channel is where it arrived (often email), not
      // necessarily where the person chatted, so match on the person only
      // and list the request's channel first.
      var people = (body.people || []).filter(function (p) { return p.user === subject; });
      people.sort(function (a, b) { return (b.channel === channel) - (a.channel === channel); });
      if (!people.length) {
        say('Lightwork holds no conversations for ' + subject + '. There is nothing to erase here; close the request once other systems are done.');
        return null;
      }
      var options = people.map(function (p, i) {
        return { value: String(i), label: p.person + ' (' + p.channel_label + ')' };
      });
      return form('Erase their data', [
        { key: 'who', label: 'Which account', type: 'select', options: options, default: '0', required: true },
      ], 'Next').then(function (values) {
        if (!values) return null;
        var chosen = people[parseInt(values.who || '0', 10)];
        return ask('Permanently erase everything Lightwork holds about ' + chosen.person +
          ' on ' + chosen.channel_label + '? This cannot be undone.', 'Erase').then(function (ok) {
          if (!ok) return null;
          return call('POST', '/api/v1/compliance/people/erase', { channel: chosen.channel, user: chosen.user }).then(function (res) {
            if (res.clean !== false) lastErasure = 'Lightwork: ' + (res.message || 'erased') + ' (' + localDay() + ')';
            say((res.message || 'Erased.') + (res.clean === false
              ? ' Keep this request open until the erasure is certified.'
              : ' You can now close the request.'));
          });
        });
      });
    }).catch(function (f) { fail(f, 'erase their data'); });
  });

  // Where to search: a readable checklist.
  on('dsar-worksheet', function () {
    var out = $('dsar-worksheet-result');
    out.textContent = 'Checking where to search…';
    call('GET', base + encodeURIComponent(requestId) + '/estate-worksheet').then(function (w) {
      out.textContent = '';
      var h = doc.createElement('h3'); h.textContent = 'Where to search'; out.appendChild(h);
      var ul = doc.createElement('ul'); ul.className = 'dsar-list';
      function item(text) { var li = doc.createElement('li'); li.textContent = text; ul.appendChild(li); }
      var holdings = w.platform_holdings || {};
      var held = holdings.sections || {};
      var counts = held && typeof held === 'object' && !Array.isArray(held) ? Object.values(held) : [];
      var total = counts.reduce(function (n, count) { return n + count; }, 0);
      if (holdings.error || holdings.enabled !== true) item('Lightwork itself: its records could not be checked. The count is unknown; try this checklist again before completing the search.');
      else if (holdings.resolved === false) item('Lightwork itself: could not match this person to one account, so its own records are not counted here.');
      else if (holdings.resolved !== true || !counts.length || !counts.every(function (count) { return Number.isSafeInteger(count) && count >= 0; }) || !Number.isSafeInteger(total)) item('Lightwork itself: the record count could not be confirmed. Try this checklist again.');
      else item('Lightwork itself: ' + total + ' record(s) found.');
      var dm = w.data_map || {};
      if (dm.error) item('Your data map could not be checked. Other systems remain unconfirmed; try again before completing the search.');
      else if (dm.enabled) {
        (dm.assets || []).forEach(function (a) {
          var cats = (a.categories || []).map(function (c) { return human(c).toLowerCase(); });
          item(human(a.system || 'System') + ' – ' + (a.name || 'data store') +
            (cats.length ? ' (holds ' + cats.join(', ') + ')' : ''));
        });
        if (!(dm.assets || []).length) item('Your data map lists no systems that hold personal details.');
        if ((dm.assets || []).length === 100) item('This checklist shows up to 100 data-map locations. Review your complete data map for any others.');
      } else {
        item('Your data map is not set up, so other systems are not listed.');
      }
      var processors = w.processors || {};
      var vendors = processors.vendors || [];
      vendors.forEach(function (v) { item('Ask vendor ' + v.name + ' for their records.'); });
      if (processors.error) item('Your vendor register could not be checked. Vendor coverage remains unconfirmed; try again before completing the search.');
      else if (!processors.enabled) item('Your vendor register is off, so vendors are not listed.');
      else if (vendors.length === 100) item('This checklist shows up to 100 vendors. Review your complete vendor register for any others.');
      var documents = w.documents || {};
      var docs = documents.hits || [];
      docs.forEach(function (d) { item('Document: ' + (d.title || d.name || 'untitled')); });
      if (documents.error) item('Connected documents could not be searched. Document coverage remains unconfirmed; try again before completing the search.');
      else if (!documents.enabled) item('Document search is off, so connected documents are not checked.');
      else item('The connected-source search shows up to eight matching documents; it is not a complete inventory.');
      out.appendChild(ul);
    }).catch(function (f) { out.textContent = 'The search checklist is unavailable. Its coverage is unknown; try again.'; fail(f, 'load the search checklist'); });
  });
})();
