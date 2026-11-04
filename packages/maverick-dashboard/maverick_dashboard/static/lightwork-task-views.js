(function () {
  'use strict';
  var root = document.getElementById('task-views'); if (!root) return;
  var form = document.getElementById('task-views-form'), name = document.getElementById('task-view-name');
  var list = document.getElementById('task-views-list'), status = document.getElementById('task-views-status');
  var review = document.getElementById('task-view-review'), copy = document.getElementById('task-view-review-copy');
  var confirm = document.getElementById('task-view-confirm'), dismiss = document.getElementById('task-view-dismiss');
  var refresh = document.getElementById('task-views-refresh'), state = null, pending = null, uncertain = null;
  var busy = false, expired = false, generation = 0, controller = null;
  function say(message) { window.mvStatus(status, message); }
  function lock(value) {
    busy = value; root.setAttribute('aria-busy', String(value));
    root.querySelectorAll('button,input').forEach(function (node) { node.disabled = value || expired; });
    form.querySelector('button').disabled = value || expired || !state;
  }
  function invalidate() {
    expired = true; ++generation; if (controller) controller.abort(); state = null; pending = null; uncertain = null;
    list.replaceChildren(); review.hidden = true; name.value = ''; lock(false);
    say('Your account or workspace changed. Reload Tasks before using saved views.');
  }
  async function request(url, options) {
    var owner = new AbortController(); controller = owner;
    try {
      var data = await window.mvFetchJSON(url, Object.assign({cache: 'no-store'}, options, {signal: owner.signal, timeout: 15000,
        onAccess: invalidate, messages: {409: 'Saved views changed. Refresh and review again; your view name is kept.',
          timeout: 'The request timed out. Refresh saved views to check the current state; no retry was sent.'}}), options && options.method ? 'save the view' : 'load your saved views');
      if (data && data.detail && data.detail.code === 'context_changed') { invalidate(); throw new Error('Context changed.'); }
      if (!data || !Array.isArray(data.views) || typeof data.revision !== 'string' || typeof data.context !== 'string') throw new Error('The saved-view response could not be verified. Refresh the page and try again.');
      if (state && state.context !== data.context) { invalidate(); throw new Error('Context changed.'); }
      return data;
    } catch (error) {
      if (error.detail && error.detail.code === 'context_changed') invalidate();
      throw error;
    } finally { if (controller === owner) controller = null; }
  }
  function render() {
    list.replaceChildren();
    if (!state.views.length) {
      if (window.mvEmpty) list.appendChild(window.mvEmpty('No saved task views yet', 'Views you save appear here. Search or filter your tasks, then name the view below to save it.', null, {compact:true}));
      else { var empty=document.createElement('p'); empty.textContent='No saved task views yet.'; list.appendChild(empty); }
    }
    state.views.forEach(function (view) {
      var row=document.createElement('p'), link=document.createElement('a'), remove=document.createElement('button');
      // Derive the destination from typed values; stored URLs are never trusted.
      link.href='/goals?' + new URLSearchParams({q:view.params.q, status:view.params.status}).toString();
      link.textContent=view.name; link.lang='und'; link.dir='auto'; row.appendChild(link);
      var description=document.createElement('span'); description.textContent=' — '+view.status_label+(view.params.q ? ': '+view.params.q : ''); description.dir='auto'; row.appendChild(description);
      remove.type='button'; remove.className='btn btn--ghost'; remove.textContent='Remove'; remove.setAttribute('aria-label','Remove '+view.name);
      remove.addEventListener('click',function () { prepare(view.name,view.params,true); }); row.appendChild(remove); list.appendChild(row);
    });
  }
  function filters() {
    return window.LightworkTaskFilters ? window.LightworkTaskFilters.current() : {q:'',status:''};
  }
  function prepare(label, values, deleting) {
    if (!state || busy || expired) return;
    pending={name:label.trim(), q:values.q, status:values.status, deleting:deleting, context:state.context, expected_revision:state.revision};
    var existing=state.views.find(function (view) { return view.name === pending.name; });
    copy.textContent=deleting ? 'Remove saved view “'+pending.name+'”? Tasks and results stay unchanged.' :
      (existing ? 'Replace' : 'Save')+' view “'+pending.name+'” with search “'+(values.q || 'any text')+'” and status '+(values.status || 'all tasks')+'?'+
      (existing ? ' Current search: “'+(existing.params.q || 'any text')+'”; status: '+existing.status_label+'.' : '');
    confirm.textContent=deleting ? 'Confirm removal' : 'Confirm save'; review.hidden=false; confirm.focus();
  }
  async function load() {
    if (busy || expired) return; var attempt=++generation; lock(true); pending=null; review.hidden=true;
    // The shared loading state: words only when the list takes over 300 ms.
    var wait=window.mvLoading ? window.mvLoading(list,{text:'Loading your saved views…'}) : null;
    try {
      var current=await request('/api/v1/views?task_filters=true'); if (wait) await wait.done(); if (attempt !== generation || expired) return;
      state=current; render();
      if (uncertain) {
        var saved=state.views.find(function (view) { return view.name === uncertain.name; });
        var matches=uncertain.deleting ? !saved : saved && saved.params.q === uncertain.q && saved.params.status === uncertain.status;
        say(matches ? 'Current saved views match your last reviewed change. This check sent no change and does not identify who saved it.' : 'Current saved views are shown. Your last request is not confirmed; review these values before making another change.'); uncertain=null;
      } else say(state.other_views ? 'Your task views are ready. Other saved dashboard views are preserved.' : 'Your task views are ready.');
    } catch (error) { if (wait) await wait.done(); if (!expired && attempt === generation) say(error.message); }
    finally { if (attempt === generation) lock(false); }
  }
  form.addEventListener('submit',function (event) { event.preventDefault(); if (form.reportValidity()) prepare(name.value,filters(),false); });
  dismiss.addEventListener('click',function () { pending=null; review.hidden=true; name.focus(); });
  confirm.addEventListener('click',async function () {
    if (!pending || busy || expired) return; var item=pending, attempt=++generation; lock(true);
    try {
      var body={context:item.context, expected_revision:item.expected_revision, q:item.q, status:item.status};
      var result=await request('/api/v1/views/'+encodeURIComponent(item.name)+'?task_filters=true',
        {method:item.deleting ? 'DELETE' : 'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
      if (attempt !== generation || expired) return;
      if (result[item.deleting ? 'deleted' : 'saved'] !== item.name) throw new Error('The saved-view acknowledgement could not be verified. Refresh to check the current state.');
      state=result; pending=null; uncertain=null; review.hidden=true; render();
      say(item.deleting ? 'The saved view was removed.' : 'The saved view is available on your account in this workspace.'); name.focus();
    } catch (error) {
      if (!expired && attempt === generation) { uncertain=item; pending=null; review.hidden=true; say(error.message); }
    } finally { if (attempt === generation) lock(false); }
  });
  refresh.addEventListener('click',load);
  window.addEventListener('lightwork:context-changed',invalidate);
  window.addEventListener('pagehide',function () { ++generation; expired=true; if (controller) controller.abort(); });
  load();
})();
