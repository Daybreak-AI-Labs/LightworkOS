(function () {
  'use strict';
  var editor = document.getElementById('conversation-organization'), browser = document.getElementById('conversation-browser');
  if (!editor && !browser) return;
  var expectedContext = (editor || browser).dataset.context;
  function node(tag, text) { var item = document.createElement(tag); item.textContent = text; return item; }
  async function api(path, options) {
    var DENIED = 'Your account, conversation or access changed. Reload this page.';
    var opts = Object.assign({cache: 'no-store', timeout: 12000, plainDetail: true, accessStatuses: [401, 403, 404],
      onAccess: function (error) { error.denied = true; },
      messages: {401: DENIED, 403: DENIED, 404: DENIED}}, options);
    opts.headers = Object.assign({'Content-Type': 'application/json', 'X-Lightwork-Conversation-Context': expectedContext}, options && options.headers);
    var value = await window.mvFetchJSON('/api/v1/conversations' + path, opts, opts.method ? 'save the conversation' : 'load your conversations');
    if (!value || value.context !== expectedContext) {
      var error = new Error(DENIED); error.denied = true; throw error;
    }
    return value;
  }
  if (editor) {
    var title = document.getElementById('conversation-name'), pin = document.getElementById('conversation-pin'), archive = document.getElementById('conversation-archive');
    var save = document.getElementById('conversation-save'), refresh = document.getElementById('conversation-refresh'), undo = document.getElementById('conversation-undo'), message = document.getElementById('conversation-organization-status');
    var model = null, prior = null, dirty = false, busy = false, operation = null;
    var channel = typeof BroadcastChannel === 'function' ? new BroadcastChannel('lightwork-conversation-' + expectedContext) : null;
    function project(value, preserveInput) {
      model = value; save.disabled = false;
      if (!preserveInput) { title.value = value.title; title.placeholder = value.original_title; pin.checked = value.pinned; archive.checked = value.archived; dirty = false; }
      document.querySelectorAll('[data-conversation-root="' + value.root_id + '"]').forEach(function (link) {
        link.textContent = (value.pinned ? 'Pinned: ' : '') + (value.title || value.original_title); link.title = value.title || value.original_title;
        if (value.archived && link.closest('li')) link.closest('li').hidden = true;
        else if (link.closest('li')) link.closest('li').hidden = false;
      });
      document.title = (value.title || value.original_title) + ' · Lightwork';
    }
    async function load(preserveInput) {
      try { var value = await api('/' + editor.dataset.goal + '/organization');
        if (preserveInput && dirty && model && value.revision !== model.revision) { message.textContent = 'Saved organization changed in another window. Your inputs are kept; Refresh saved values lets you review the current version before editing again.'; return; }
        project(value, preserveInput);
      }
      catch (error) { message.textContent = error.message; if (error.denied) { title.value = ''; pin.checked = false; archive.checked = false; model = null; save.disabled = true; } }
    }
    async function change(values, isUndo) {
      if (!model || busy) return; busy = true;
      var controls = Array.from(editor.querySelectorAll('input,button')); controls.forEach(function (control) { control.disabled = true; });
      var before = {title: model.title, pinned: model.pinned, archived: model.archived};
      if (!operation) operation = crypto.randomUUID();
      try {
        var value = await api('/' + editor.dataset.goal + '/organization', {method: 'PUT', body: JSON.stringify(Object.assign({}, values, {expected_revision: model.revision, operation_id: operation}))});
        prior = isUndo ? null : before; operation = null; project(value, false); undo.hidden = !prior;
        message.textContent = isUndo ? 'Previous organization restored. Task and audit history are unchanged.' : 'Saved for every turn in this conversation. Task and audit history are unchanged.';
        if (channel) channel.postMessage({root_id: value.root_id});
      } catch (error) { message.textContent = error.message; if (error.denied) { title.value = ''; model = null; } }
      finally { busy = false; controls.forEach(function (control) { control.disabled = false; }); save.disabled = !model; }
    }
    editor.addEventListener('input', function () { dirty = true; operation = null; });
    editor.addEventListener('submit', function (event) { event.preventDefault(); change({title: title.value, pinned: pin.checked, archived: archive.checked}, false); });
    refresh.addEventListener('click', async function () { if (dirty && !(await mvConfirm('Replace your unsaved organization inputs with the currently saved values?', {okText: 'Load saved values'}))) return; operation = null; load(false); }); undo.addEventListener('click', function () { if (prior) { operation = null; change(prior, true); } });
    window.addEventListener('focus', function () { if (!busy) load(dirty); });
    if (channel) channel.onmessage = function (event) { if (model && event.data && event.data.root_id === model.root_id && !busy) load(dirty); };
    window.addEventListener('pagehide', function () { if (channel) channel.close(); });
    load(false);
  }
  if (browser) {
    var form = document.getElementById('conversation-search'), list = document.getElementById('conversation-results'), more = document.getElementById('conversation-more'), status = document.getElementById('conversation-search-status');
    var query = document.getElementById('conversation-query'), view = document.getElementById('conversation-view'), cursor = null, seen = new Set(), inFlight = false;
    async function search(append) {
      if (inFlight) return; inFlight = true; more.disabled = true;
      var controls = Array.from(form.querySelectorAll('input,select,button')); controls.forEach(function (control) { control.disabled = true; });
      if (!append) { cursor = null; seen.clear(); list.replaceChildren(); }
      try {
        var parameters = new URLSearchParams({q: query.value.trim(), view: view.value}); if (cursor) parameters.set('before_id', cursor);
        var data = await api('?' + parameters);
        data.items.forEach(function (item) {
          if (seen.has(item.root_id)) return; seen.add(item.root_id);
          var article = node('article', ''), link = node('a', item.display_title), note = node('p', (item.pinned ? 'Pinned. ' : '') + (item.archived ? 'Archived. ' : '') + item.snippet);
          link.href = '/chat/goal/' + item.matched_goal_id; article.append(link, note); list.append(article);
        });
        cursor = data.before_id; more.hidden = !data.has_more;
        status.textContent = seen.size + ' matching conversations loaded. ' + (data.has_more ? 'Older history remains; continue scanning below. ' : 'Reached the end of the authorized history. ') + data.scope;
      } catch (error) { status.textContent = error.message; if (error.denied) { list.replaceChildren(); seen.clear(); more.hidden = true; } }
      finally { inFlight = false; more.disabled = false; controls.forEach(function (control) { control.disabled = false; }); }
    }
    form.addEventListener('submit', function (event) { event.preventDefault(); search(false); }); more.addEventListener('click', function () { search(true); }); search(false);
  }
}());
