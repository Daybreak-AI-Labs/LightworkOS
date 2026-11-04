// Public website chat section of the Channels page: list, add, rotate and stop websites,
// and read recent messages. Everything the page shows is inserted as text. Nothing here
// keeps a key or a message in browser storage; a new key is shown once and then cleared.
(function () {
  'use strict';
  var root = document.querySelector('[data-public-chat]');
  if (!root) return;
  var API = '/api/v1/public-chat/sites';
  var byId = function (id) { return document.getElementById(id); };
  var statusLine = byId('pc-status'), sites = byId('pc-sites'), create = byId('pc-create');
  var newButton = byId('pc-new'), secret = byId('pc-secret'), messages = byId('pc-messages');
  var messageBody = byId('pc-messages-body'), messageSite = '', busy = false, currentKey = '';

  function say(text, failed) { window.mvStatus(statusLine, text, { error: !!failed }); }
  function call(path, options, action) {
    // serverDetail: the server's own plain sentence is shown when it sends one; this is the fallback.
    return window.mvFetchJSON(API + path, Object.assign({ cache: 'no-store', serverDetail: 'That did not work. Try again.' }, options || {}), action);
  }
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }
  function button(label, name, onClick, danger) {
    var node = el('button', danger ? 'btn btn--danger' : 'btn', label);
    node.type = 'button';
    node.setAttribute('aria-label', label + ' for ' + name);
    node.addEventListener('click', onClick);
    return node;
  }
  function when(seconds) {
    var date = new Date(Number(seconds) * 1000);
    return isNaN(date.getTime()) ? '' : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  }
  function setBusy(value) {
    if (newButton) newButton.disabled = value;
    byId('pc-save').disabled = value;
  }
  // One action at a time; a refusal shows the server's own plain sentence.
  function run(task) {
    if (busy) return Promise.resolve();
    busy = true;
    setBusy(true);
    return Promise.resolve().then(task).catch(function (error) {
      say(error && error.message ? error.message : 'That did not work. Try again.', true);
    }).then(function () {
      busy = false;
      setBusy(false);
    });
  }

  function snippet(value) {
    return '<script src="' + window.location.origin + '/public/chat/v1/widget.js" data-key="' + value +
      '" async><\/script>';
  }
  function showKey(value) {
    currentKey = value;
    byId('pc-key').textContent = value;
    byId('pc-snippet').textContent = snippet(value);
    secret.hidden = false;
    secret.setAttribute('tabindex', '-1');
    secret.focus();
  }
  function hideKey() {
    currentKey = '';
    byId('pc-key').textContent = '';
    byId('pc-snippet').textContent = '';
    secret.hidden = true;
  }
  byId('pc-copy-key').addEventListener('click', function () { if (currentKey) window.mvCopy(currentKey); });
  byId('pc-copy-snippet').addEventListener('click', function () { if (currentKey) window.mvCopy(snippet(currentKey)); });
  byId('pc-secret-done').addEventListener('click', hideKey);

  function hideMessages() {
    messageSite = '';
    messageBody.replaceChildren();
    messages.hidden = true;
  }
  function renderMessages(site, list) {
    messageSite = site.id;
    byId('pc-messages-heading').textContent = 'Recent messages: ' + site.display_name;
    var newest = list.slice().reverse();
    var nodes = [];
    if (!newest.length) {
      nodes.push(window.mvEmpty('No messages yet', 'Messages appear here after a visitor chats with this website. ' +
        'If none arrive, check that its website code is on the site.', null, { compact: true }));
    } else {
      var listing = el('ol');
      newest.forEach(function (item) {
        var entry = el('li');
        var who = item.role === 'visitor' ? 'Visitor' : 'Assistant';
        entry.append(el('p', 'muted ch-help', who + ' · ' + when(item.created_at)), el('p', null, String(item.text)));
        listing.append(entry);
      });
      nodes.push(listing);
      if (list.length >= 50) nodes.push(el('p', 'muted ch-help', 'Showing the 50 most recent messages.'));
    }
    messageBody.replaceChildren(...nodes);
    messages.hidden = false;
  }
  function showMessages(site) {
    return run(function () {
      return call('/' + encodeURIComponent(site.id) + '/transcripts?limit=50', {}, 'read the messages')
        .then(function (data) {
          renderMessages(site, Array.isArray(data.messages) ? data.messages : []);
          say('Recent messages are shown below. Opening them is recorded in the activity log.');
        });
    });
  }

  function rotate(site) {
    return run(function () {
      return window.mvConfirm('Rotate the key for ' + site.display_name + '? The current key stops working at once, ' +
        'and open chats on this website end. Put the new website code on the site before visitors can chat again.',
        { okText: 'Rotate key', danger: true }).then(function (ok) {
          if (!ok) return null;
          return call('/' + encodeURIComponent(site.id) + '/rotate', { method: 'POST' }, 'rotate the key')
            .then(function (data) {
              showKey(data.publishable_key);
              return loadSites().then(function () { say('New key created. Copy it now; it is shown only once.'); });
            });
        });
    });
  }
  function stop(site) {
    return run(function () {
      return window.mvConfirm('Stop ' + site.display_name + '? Its key and addresses stop at once, open chats end, ' +
        'and every stored message for it is deleted. This cannot be undone.', { okText: 'Stop website', danger: true })
        .then(function (ok) {
          if (!ok) return null;
          return call('/' + encodeURIComponent(site.id) + '/revoke', { method: 'POST' }, 'stop the website')
            .then(function () {
              if (messageSite === site.id) hideMessages();
              return loadSites().then(function () {
                say('Website stopped. Its key no longer works and its stored messages were deleted.');
              });
            });
        });
    });
  }

  function renderSites(list) {
    if (!list.length) {
      sites.replaceChildren(el('p', 'muted', 'No websites yet. Add one to get a key for its website code.'));
      return;
    }
    var table = el('table'), head = el('thead'), headRow = el('tr'), body = el('tbody');
    ['Website', 'Addresses', 'Specialist', 'Status', 'Spent today', 'Actions'].forEach(function (label) {
      var heading = el('th', label);
      heading.setAttribute('scope', 'col');
      headRow.append(heading);
    });
    head.append(headRow);
    table.append(head, body);
    list.forEach(function (site) {
      var active = site.state === 'active';
      var row = el('tr'), actions = el('td');
      if (active) {
        actions.append(button('Recent messages', site.display_name, function () { showMessages(site); }));
        actions.append(' ', button('Rotate key', site.display_name, function () { rotate(site); }));
        actions.append(' ', button('Stop website', site.display_name, function () { stop(site); }, true));
      }
      row.append(
        el('td', null, site.display_name),
        el('td', null, (site.origins || []).join(', ')),
        el('td', null, String(site.specialist).replace(/_/g, ' ')),
        el('td', active ? 'badge active' : 'badge', active ? 'Active' : 'Stopped'),
        el('td', null, '$' + Number(site.spent_today_dollars || 0).toFixed(2) + ' of $' +
          Number(site.daily_cap_dollars).toFixed(2) + ' today'),
        actions);
      body.append(row);
    });
    sites.replaceChildren(table);
  }
  function loadSites() {
    return call('', {}, 'load your websites').then(function (data) {
      renderSites(Array.isArray(data.sites) ? data.sites : []);
    });
  }

  if (newButton) {
    newButton.addEventListener('click', function () {
      var opening = create.hidden;
      create.hidden = !opening;
      newButton.setAttribute('aria-expanded', String(opening));
      if (opening) create.elements.display_name.focus();
    });
  }
  byId('pc-cancel').addEventListener('click', function () {
    create.reset();
    create.hidden = true;
    if (newButton) {
      newButton.setAttribute('aria-expanded', 'false');
      newButton.focus();
    }
  });
  create.addEventListener('submit', function (event) {
    event.preventDefault();
    var f = create.elements;
    var body = {
      display_name: f.display_name.value.trim(),
      origins: f.origins.value.split(/\r?\n/).map(function (line) { return line.trim(); }).filter(Boolean),
      specialist: f.specialist.value,
      greeting: f.greeting.value.trim(),
      daily_cap_dollars: Number(f.daily_cap_dollars.value),
      messages_per_session: Number(f.messages_per_session.value),
      messages_per_minute: Number(f.messages_per_minute.value),
      messages_per_client_per_day: Number(f.messages_per_client_per_day.value),
      retention_days: Number(f.retention_days.value)
    };
    run(function () {
      return call('', { method: 'POST', body: body }, 'add the website').then(function (created) {
        create.reset();
        create.hidden = true;
        if (newButton) newButton.setAttribute('aria-expanded', 'false');
        showKey(created.publishable_key);
        return loadSites().then(function () {
          say('Website added. Copy its key and website code now. The key is shown only once.');
        });
      });
    });
  });

  run(function () {
    return loadSites().catch(function () {
      sites.replaceChildren(el('p', 'muted', 'Websites could not be loaded. Reload this page to try again.'));
      say('Websites could not be loaded. Reload this page to try again.', true);
    });
  });
})();
