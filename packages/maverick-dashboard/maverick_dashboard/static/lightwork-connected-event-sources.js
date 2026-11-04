(function () {
  'use strict';
  var API = '/api/v1/connected-event-sources';
  var names = ['sharepoint_files', 'salesforce_records', 'servicenow_tickets', 'teams_messages'];
  function create() {
    var source = '', draft = {}, review = null, container, catalog, generation = 0, checked;
    function clearReview() {
      review = null;
      if (checked) checked.checked = false;
      var result = container && container.querySelector('[data-source-review]');
      if (result) result.remove();
    }
    function select(key, label, choices, value, change) {
      var wrap = document.createElement('div'); wrap.className = 'field';
      var name = document.createElement('label'), input = document.createElement('select');
      input.id = 'auto-connected-' + key; input.required = true; name.htmlFor = input.id; name.textContent = label;
      [{value: '', label: 'Choose ' + label.toLowerCase()}].concat(choices).forEach(function (choice) {
        var option = document.createElement('option'); option.value = choice.value; option.textContent = choice.label; input.appendChild(option);
      });
      input.value = value || '';
      input.addEventListener('change', function () { clearReview(); change(input.value); });
      wrap.appendChild(name); wrap.appendChild(input); container.appendChild(wrap);
      return input;
    }
    function say(text) {
      var message = container.querySelector('[data-source-message]');
      if (!message) { message = document.createElement('p'); message.dataset.sourceMessage = ''; message.className = 'auto__hint'; message.setAttribute('role', 'status'); container.appendChild(message); }
      window.mvStatus(message, text);
    }
    function choices() { return {context: catalog.context, source: source, connection: draft.connection || '', selection: draft.selection || {}}; }
    function call(path, body) { return window.mvFetchJSON(API + path, {method: body ? 'POST' : 'GET', body: body}, 'review the connected source'); }
    async function picked(step, selected, sequence) {
      var data = await call('/pickers', Object.assign(choices(), {step: step, selection: selected}));
      if (sequence !== generation) return null;
      return data.choices;
    }
    function changed(key, value) {
      draft.selection[key] = value;
      if (key === 'site') { delete draft.selection.drive; draft.selection.folder = 'root'; }
      if (key === 'drive') draft.selection.folder = 'root';
      if (key === 'team') delete draft.selection.channel;
      if (key === 'object' && value !== 'Opportunity') draft.selection.closed_only = false;
      render(source, draft, container);
    }
    async function render(nextSource, initial, box) {
      source = nextSource; draft = Object.assign({}, initial, {connection: initial.connection || '', selection: Object.assign({}, initial.selection || {})});
      container = box; clearReview(); container.textContent = ''; var sequence = ++generation;
      try {
        catalog = await call('/catalog');
        if (sequence !== generation) return;
        var accounts = catalog.connections.filter(function (row) { return row.source === source; });
        select('connection', 'Connected account', accounts, draft.connection, function (value) { render(source, {connection: value, selection: {}}, container); });
        if (!accounts.length) { say('No account for this source is available to you. Connect it in Connections, then choose this source again.'); return; }
        if (!draft.connection) return;
        var selected = draft.selection, values;
        if (source === 'sharepoint_files') {
          values = await picked('sites', {}, sequence); if (!values) return;
          select('site', 'Site', values, selected.site, function (value) { changed('site', value); });
          if (!selected.site) return;
          values = await picked('drives', {site: selected.site}, sequence); if (!values) return;
          select('drive', 'Document library', values, selected.drive, function (value) { changed('drive', value); });
          if (!selected.drive) return;
          values = await picked('folders', {drive: selected.drive, folder: draft.browseFolder || 'root'}, sequence); if (!values) return;
          var folders = [{value: 'root', label: 'Library root'}].concat(values);
          if (selected.folder && !folders.some(function (row) { return row.value === selected.folder; })) folders.push({value: selected.folder, label: draft.folderLabel || 'Selected folder'});
          var folderInput = select('folder', 'Folder', folders, selected.folder || 'root', function (value) { selected.folder = value; draft.folderLabel = folderInput.options[folderInput.selectedIndex].textContent; });
          selected.folder = selected.folder || 'root';
          var browse = document.createElement('button'); browse.type = 'button'; browse.className = 'btn btn--ghost'; browse.textContent = 'Browse inside the selected folder';
          browse.addEventListener('click', function () { draft.browseFolder = selected.folder; render(source, draft, container); }); container.appendChild(browse);
        } else if (source === 'teams_messages') {
          values = await picked('teams', {}, sequence); if (!values) return;
          select('team', 'Team', values, selected.team, function (value) { changed('team', value); });
          if (!selected.team) return;
          values = await picked('channels', {team: selected.team}, sequence); if (!values) return;
          select('channel', 'Channel', values, selected.channel, function (value) { selected.channel = value; });
        } else if (source === 'salesforce_records') {
          selected.object = selected.object || 'Opportunity'; selected.closed_only = selected.closed_only === true;
          select('object', 'Record type', catalog.objects, selected.object, function (value) { changed('object', value); });
          if (selected.object === 'Opportunity') select('closed', 'When to start', [{value: 'new', label: 'A new opportunity appears'}, {value: 'closed', label: 'An opportunity is first observed as closed'}], selected.closed_only ? 'closed' : 'new', function (value) { selected.closed_only = value === 'closed'; });
        } else {
          selected.table = selected.table || 'incident'; select('table', 'Ticket type', catalog.tables, selected.table, function (value) { selected.table = value; });
        }
        var preview = document.createElement('button'); preview.type = 'button'; preview.className = 'btn btn--ghost'; preview.textContent = 'Check source and review';
        preview.addEventListener('click', async function () {
          if (Array.from(container.querySelectorAll('select')).some(function (input) { return !input.reportValidity(); })) return;
          preview.disabled = true; clearReview(); say('Reading the selected source. Nothing is being armed.');
          try {
            var result = await call('/preview', choices()); if (sequence !== generation) return;
            review = result; var panel = document.createElement('section'); panel.className = 'panel'; panel.dataset.sourceReview = '';
            var heading = document.createElement('h3'); heading.textContent = 'Dated source review'; panel.appendChild(heading);
            var fields = [['Checked', result.checked_at], ['Account', result.account], ['Destination', result.destination]];
            Object.keys(result.details).forEach(function (key) { fields.push([key, result.details[key]]); });
            fields.push(['Existing items remembered', result.existing_items], ['Example item names', result.sample_names.join(', ') || 'No current items']);
            var dl = document.createElement('dl'); fields.forEach(function (field) { var dt = document.createElement('dt'), dd = document.createElement('dd'); dt.textContent = field[0]; dd.textContent = field[1]; dl.appendChild(dt); dl.appendChild(dd); }); panel.appendChild(dl);
            var note = document.createElement('p'); note.textContent = result.notice; panel.appendChild(note);
            var label = document.createElement('label'); checked = document.createElement('input'); checked.type = 'checkbox'; label.appendChild(checked); label.appendChild(document.createTextNode(' I reviewed this dated source, account and baseline.')); panel.appendChild(label); container.appendChild(panel);
            say('Source snapshot ready for review. Future event delivery remains unconfirmed.');
          } catch (error) { say(window.mvErrorText(error, 'check this source')); }
          finally { preview.disabled = false; }
        });
        container.appendChild(preview);
        say(catalog.notice);
      } catch (error) { if (sequence === generation) say(window.mvErrorText(error, 'load the connected source')); }
    }
    return {isConnected: function (value) { return names.indexOf(value) !== -1; }, render: render,
      draft: function () { return draft; }, clear: function () { ++generation; clearReview(); },
      config: function () { if (!review || !checked || !checked.checked) throw new Error('Check the connected source and confirm its dated review before creating the automation.'); return {review_token: review.review_token}; },
      summary: function () { return review ? review.account + ', checked ' + review.checked_at + ', ' + review.existing_items + ' existing items remembered' : ''; },
      retainOriginal: async function (body) {
        var result = await call('/original-plan', {review_token: body.config.review_token, name: body.name, template: body.template || '', flow: body.flow || '', params: body.params || {}, interval_seconds: body.interval_seconds || 0});
        try { sessionStorage.setItem('lightwork.connected-event-original', JSON.stringify({original_token: result.original_token})); }
        catch (_error) { throw new Error('The original creation plan could not be retained in this browser. Nothing was armed.'); }
        return result;
      },
      original: async function () {
        var saved;
        try { saved = JSON.parse(sessionStorage.getItem('lightwork.connected-event-original') || 'null'); } catch (_error) { saved = null; }
        if (!saved || !saved.original_token) throw new Error('No original connected-source creation plan is retained in this browser. Read the automation list.');
        return call('/original-read', saved);
      }};
  }
  window.LwConnectedEventSource = {create: create};
}());
