{% raw %}
(function () {
  'use strict';
  var SVG = 'http://www.w3.org/2000/svg';
  var W = 176, H = 64;                 // node card size
  var KIND_ICON = { agent: '🧠', action: '⚙️', branch: '🔀', switch: '🔃',
                    foreach: '🔁', while: '🔄', parallel: '🔱', approval: '✅',
                    delay: '⏱', wait_event: '📥', scope: '🛡', subflow: '📎', setvar: '📝' };
  var BODY_KINDS = { foreach: '🔁 Steps repeated for each item', while: '🔄 Steps repeated', scope: '🛡 Steps that might fail' };
  // Plain names for each kind of step (shared with the Steps view).
  var KIND_LABEL = { agent: 'AI task', action: 'Connected action', branch: 'Decision', switch: 'Choose a path',
    foreach: 'Repeat for each item', while: 'Repeat while', parallel: 'Run together', approval: 'Approval',
    delay: 'Wait', wait_event: 'Wait for another app', scope: 'Handle a failure',
    subflow: 'Run another flow', setvar: 'Update data' };
  function kindLabel(k) { return KIND_LABEL[k] || human(k || 'step'); }
  function human(v) {
    if (window.mvHuman) return window.mvHuman(v);
    v = String(v == null ? '' : v).replace(/[_.-]+/g, ' ').trim();
    return v.charAt(0).toUpperCase() + v.slice(1);
  }
  function stepName(n) { return (n && (n.label || '').trim()) || (n ? kindLabel(n.kind) : 'step'); }
  // Duration choices shown as words; values are seconds.
  var durationOptions = FDDurations.durationOptions;
  var durationText = FDDurations.durationText;
  var retryWaitOptions = FDDurations.retryWaitOptions;

  var flow = { id: '', name: '', start: '', nodes: [] };
  var rootFlow = flow;  // the top-level flow (save/run/history operate on this)
  var stack = [];       // drill-in frames: {flow, selected} for each level above root
  var crumbs = ['Main flow'];   // breadcrumb labels; length === stack.length + 1
  var proposals = {};   // node_id -> {to_kind, reason, inferred_tool} from grounded per-node outcomes
  var impacts = {};     // node_id -> {changed, applied, impact} measured before/after a rewrite
  var signals = { nodes: {}, trigger: null };   // grounded per-node stats + trigger reliability
  var runState = {};    // node_id -> {status, outcome} from the last/live run
  var runCursor = null; // node a paused run is waiting on
  var flowInputs = [];  // declared manual-run inputs [{key,type,label,required,default}]
  var toolCatalog = {}; // tool name -> {description, params[], category} for the action picker
  var actionFieldsChecking = false;
  var toolCategories = [];   // display-ordered category names from the server
  var toolFilterCategory = ''; // '' = all; else browse one category in the picker
  var flowSchema = {};  // output key -> {type, keys[]} learned from real runs (nested pills)
  var toolQuery = '';   // the action search box's text
  var toolResults = [], toolTotal = 0, toolNext = null, toolLoading = false, toolError = '';
  var toolRequest = 0;
  var people = [];      // [{ref, label}] who can be asked to approve
  var savedFlows = [];  // [{id, name, inputs}] other saved flows (for "Run another flow")
  var flowNames = {};   // flow id -> name
  var selected = null;
  var multiSel = {};        // node id -> true when marquee-selected (group drag/delete)
  var selectedEdge = null;  // {from, port} when an edge is selected (click to select, Del to cut)
  var view = { x: 40, y: 20, k: 1 };
  var idSeq = 0;
  var undoStack = [], redoStack = [], pendingSnap = null;   // serialized rootFlow snapshots
  var chatHistory = [];     // copilot transcript: {role, content}
  var lastRunId = null;     // most recent run started here (grounds "why did it fail?")
  var runGen = 0;           // bumped per run so a superseded watch stops painting
  var activeES = null;      // the live run's EventSource, closed when a new run starts

  var fd = document.querySelector('.fd');
  var canvas = document.getElementById('fd-canvas');
  var vp = document.getElementById('fd-viewport');
  var gNodes = document.getElementById('fd-nodes');
  var gEdges = document.getElementById('fd-edges');
  var tempEdge = document.getElementById('fd-temp-edge');
  var props = document.getElementById('fd-props');
  var msg = document.getElementById('fd-msg');
  var nameInput = document.getElementById('fd-name');
  var idInput = document.getElementById('fd-id');
  var saveButton = document.getElementById('fd-save');
  var publishButton = document.getElementById('fd-publish');
  var cleanDraft = null;
  var saveInFlight = false;
  var publishInFlight = false;
  var retireInFlight = false;
  var runInFlight = false;
  var applyInFlight = false;
  var unconfirmedApply = null;
  function unresolvedApply(node) {
    return unconfirmedApply && unconfirmedApply.flow === rootFlow.id &&
      unconfirmedApply.node === node.id && unconfirmedApply.version === rootFlow.version;
  }
  var draftGeneration = 0;
  var pendingDraft = null;
  var draftRecovery = null;

  function recoveryPayload() {
    return {format:1, editor:JSON.parse(draftSnapshot()),
      base:{id:rootFlow.id, version:rootFlow.version || 0, revision:rootFlow.revision || ''},
      brief:(document.getElementById('fd-nl') || {}).value || ''};
  }
  async function restoreRecovery(payload) {
    if (!payload || payload.format !== 1 || !payload.editor || !payload.editor.flow || !Array.isArray(payload.editor.flow.nodes) || !payload.base) throw new Error('This recovery copy is not a supported flow draft.');
    var state = payload.editor, source = payload.base;
    if (!Number.isInteger(source.version) || source.version < 0 || typeof source.id !== 'string' || typeof source.revision !== 'string' ||
        typeof state.id !== 'string' || typeof state.name !== 'string' || !Array.isArray(state.inputs) || typeof payload.brief !== 'string') throw new Error('This saved copy of the flow is missing some of its fields, so it was not restored. Current work was kept.');
    var pending = [state.flow];
    while (pending.length) {
      var graph = pending.pop();
      if (!graph || !Array.isArray(graph.nodes) || !graph.nodes.every(function (node) { return node && typeof node.id === 'string' && typeof node.kind === 'string'; })) throw new Error('This saved copy of the flow has steps that could not be read, so it was not restored. Current work was kept.');
      graph.nodes.forEach(function (node) { if (node.body) pending.push(node.body); });
    }
    var before = JSON.stringify(recoveryPayload());
    if (source.version) {
      var response = await apiFetch('/api/v1/flows/' + encodeURIComponent(source.id));
      var current = response.ok && await (typeof FDRecipeInputs !== 'undefined' && typeof response.text === 'function'
        ? FDRecipeInputs.responseJson(response) : response.json());
      if (!current || current.id !== source.id || current.revision !== source.revision || current.version !== source.version) throw new Error('The saved flow changed after this recovery copy. Current work was kept. Compare the copies and copy your edits into the latest flow before saving.');
      FDRecipeInputs.inheritEvidence(state.flow, current);
    }
    if (before !== JSON.stringify(recoveryPayload())) throw new Error('Your newer canvas edits were kept. Review the recovery copy again.');
    FDRecipeInputs.flowText(state.flow);
    pushHistory();
    rootFlow = JSON.parse(JSON.stringify(state.flow)); flow = rootFlow;
    rootFlow.version = source.version; rootFlow.revision = source.revision;
    stack = []; crumbs = ['Main flow']; selected = null; selectedEdge = null;
    flowInputs = JSON.parse(JSON.stringify(state.inputs || []));
    idInput.value = state.id; nameInput.value = state.name;
    [['fd-maxsec','max_seconds'],['fd-maxdollars','max_dollars'],['fd-schedule','schedule'],['fd-tz','timezone'],['fd-maxconc','max_concurrent']].forEach(function (pair) {
      var field = document.getElementById(pair[0]); if (field) field.value = state[pair[1]];
    });
    var notify = document.getElementById('fd-notify'); if (notify) notify.checked = !!state.notify;
    if (document.getElementById('fd-notify-on')) document.getElementById('fd-notify-on').value = state.notify_on || 'all';
    var brief = document.getElementById('fd-nl'); if (brief) brief.value = payload.brief || '';
    proposals = {}; impacts = {}; runState = {}; runCursor = null;
    renderCrumbs(); syncScheduleControls(); render(); renderProps();
  }
  function initializeRecovery() {
    var source = canvas.getAttribute('data-flow-id') || 'new';
    if (!window.mvDraftRecovery || (draftRecovery && draftRecovery.source === source)) return;
    if (draftRecovery) { draftRecovery.dispose(); draftRecovery.panel.remove(); }
    draftRecovery = window.mvDraftRecovery.create({key:'flow-designer:' + source,
      host:document.getElementById('content'), read:recoveryPayload, restore:restoreRecovery});
    if (draftRecovery) draftRecovery.source = source;
  }

  function draftSnapshot() {
    // Keep the editable object rather than the wire serialization: buffered
    // invalid Params JSON and nested sub-flow drafts are user work too. Runtime
    // version/publication metadata is excluded so a successful save can update
    // CAS tokens without making an otherwise unchanged canvas look dirty.
    var editableFlow = FDDraft.editableFlow(rootFlow, FDActionFields.validDetails);
    return JSON.stringify({
      flow: editableFlow,
      id: idInput.value,
      name: nameInput.value,
      inputs: flowInputs,
      notify: !!((document.getElementById('fd-notify') || {}).checked),
      notify_on: ((document.getElementById('fd-notify-on') || {}).value || 'all'),
      max_seconds: ((document.getElementById('fd-maxsec') || {}).value || ''),
      max_dollars: ((document.getElementById('fd-maxdollars') || {}).value || ''),
      schedule: ((document.getElementById('fd-schedule') || {}).value || ''),
      timezone: ((document.getElementById('fd-tz') || {}).value || ''),
      max_concurrent: ((document.getElementById('fd-maxconc') || {}).value || '')
    });
  }
  function markClean(snapshot) { cleanDraft = snapshot || draftSnapshot(); }
  function draftIsDirty() { return cleanDraft !== null && cleanDraft !== draftSnapshot(); }
  function syncSaveButtons() {
    var busy = saveInFlight || publishInFlight || applyInFlight || retireInFlight || actionFieldsChecking;
    saveButton.disabled = busy;
    publishButton.disabled = busy;
    var more = document.getElementById('fd-more');
    if (more) more.hidden = !rootFlow.id || (!rootFlow.version && !canvas.getAttribute('data-flow-id'));
    var off = document.getElementById('fd-turn-off');
    if (off) off.disabled = busy || !rootFlow.published;
    var del = document.getElementById('fd-delete-flow');
    if (del) del.disabled = busy;
    props.querySelectorAll('[data-apply-node]').forEach(function (button) {
      var nodeId = button.getAttribute('data-apply-node');
      button.disabled = busy || !proposals[nodeId] || !!unresolvedApply({id: nodeId});
    });
  }
  function canonicalizeSavedFlow(id) {
    // The workflow builder's Steps mode keeps the saved flow in its own address,
    // so a reload, Back and Copilot's flow controls stay on this tab.
    var path = window.location.pathname === '/workflow-builder'
      ? '/workflow-builder?mode=steps&flow=' + encodeURIComponent(id)
      : '/flows/designer/' + encodeURIComponent(id);
    if (window.location.pathname + window.location.search !== path) {
      window.history.replaceState(window.history.state, '', path);
    }
    canvas.setAttribute('data-flow-id', id);
    if (draftRecovery && draftRecovery.source !== id) { initializeRecovery(); if (draftRecovery) draftRecovery.changed(); }
    var box = document.querySelector('.fd-hero .hero-statebox');
    if (box) {
      var stateName = box.querySelector('.hero-statebox__row strong');
      var badge = box.querySelector('.badge');
      if (stateName) stateName.textContent = 'Editing “' + (rootFlow.name || nameInput.value || 'this flow') + '”';
      if (badge) { badge.textContent = 'Saved flow'; badge.className = 'badge ok'; }
    }
  }
  window.addEventListener('beforeunload', function (event) {
    if (!draftIsDirty()) return;
    event.preventDefault();
    event.returnValue = '';
  });

  function el(tag, attrs, text) {
    var e = document.createElementNS(SVG, tag);
    for (var k in (attrs || {})) e.setAttribute(k, attrs[k]);
    if (text != null) e.textContent = text;
    return e;
  }

  // ---- undo/redo: whole-editor snapshots, including unfinished work.
  // Save serialization deliberately drops buffers/blank rows; history must not. ----
  function snapState() {
    return FDHistory.snapshot({ rootFlow: rootFlow, idInput: idInput, nameInput: nameInput,
      flowInputs: flowInputs, document: document, recipeInputs: FDRecipeInputs });
  }
  // An explicit creation receipt can bind the exact unsaved history that
  // preceded that request. Empty revisions alone never match saved history.
  var firstSaveHistory = null;
  function pushHistory() {
    var s = snapState();
    if (undoStack[undoStack.length - 1] === s) return;
    undoStack.push(s);
    if (undoStack.length > 50) undoStack.shift();
    redoStack = [];
  }
  function histFocus() { pendingSnap = snapState(); }
  function histBlur() {
    if (pendingSnap && pendingSnap !== snapState()) {
      undoStack.push(pendingSnap);
      if (undoStack.length > 50) undoStack.shift();
      redoStack = [];
    }
    pendingSnap = null;
  }
  function restoreState(s) {
    var restored = FDHistory.restore(s, rootFlow, firstSaveHistory, FDRecipeInputs);
    var f = restored.flow, settings = restored.settings;
    stack = []; crumbs = ['Main flow']; renderCrumbs();
    flow = f;
    flow.nodes = (f.nodes || []).map(function (nd, i) { return normalizeNode(nd, i); });
    rootFlow = flow;
    flowInputs = JSON.parse(JSON.stringify(settings.inputs || []));
    [['fd-maxsec', 'max_seconds'], ['fd-maxdollars', 'max_dollars'], ['fd-schedule', 'schedule'],
      ['fd-tz', 'timezone'], ['fd-maxconc', 'max_concurrent']].forEach(function (pair) {
      var field = document.getElementById(pair[0]);
      if (field) field.value = settings[pair[1]] == null ? '' : settings[pair[1]];
    });
    var notify = document.getElementById('fd-notify'); if (notify) notify.checked = !!settings.notify;
    if (document.getElementById('fd-notify-on')) document.getElementById('fd-notify-on').value = settings.notify_on || 'all';
    syncScheduleControls();
    var samplePanel = document.getElementById('fd-test-data');
    if (samplePanel) samplePanel.hidden = rootFlow.learned_recipe != null;
    nameInput.value = settings.name == null ? flow.name : settings.name;
    idInput.value = settings.id == null ? flow.id : settings.id;
    selected = null; selectedEdge = null;
    autoLayout(); render(); renderProps();
    if (typeof window !== 'undefined' && typeof window.dispatchEvent === 'function')
      window.dispatchEvent(new Event('lightwork:flow-loaded'));
  }
  function undo() {
    if (!undoStack.length) { say('Nothing to undo.'); return; }
    redoStack.push(snapState());
    restoreState(undoStack.pop());
    say('↶ undone');
  }
  function redo() {
    if (!redoStack.length) { say('Nothing to redo.'); return; }
    undoStack.push(snapState());
    restoreState(redoStack.pop());
    say('↷ redone');
  }
  function nodeById(id) { for (var i = 0; i < flow.nodes.length; i++) if (flow.nodes[i].id === id) return flow.nodes[i]; return null; }
  function newId() { var id; do { id = 'n' + (idSeq++); } while (nodeById(id)); return id; }
  function say(t, err) { if (window.mvStatus) window.mvStatus(msg, t || '', {error: !!err}); else msg.textContent = t || ''; msg.style.color = err ? 'var(--danger)' : 'var(--muted)'; }
  var trunc = FDPresentation.truncate;
  function summary(node) {
    return FDPresentation.summary(node, {
      human: human, conditionText: conditionText, durationText: durationText,
      flowNames: flowNames, kindLabel: kindLabel
    });
  }
  function ports(node) { return FDPresentation.ports(node, W); }
  function runClass(id) { return FDPresentation.runClass(id, runCursor, runState); }
  function runBadge(id) { return FDPresentation.runBadge(id, runCursor, runState); }

  function render() {
    if (draftRecovery) draftRecovery.changed();
    FDCanvas.render({ flow: flow, view: view, selected: selected, multiSel: multiSel,
      selectedEdge: selectedEdge, proposals: proposals, width: W, height: H, icons: KIND_ICON },
      { document: document, viewport: vp, edges: gEdges, nodes: gNodes },
      { core: FDCore, ports: ports, nodeById: nodeById, el: el, runClass: runClass,
        runBadge: runBadge, summary: summary, kindLabel: kindLabel, truncate: trunc });
    // Skip the minimap rebuild mid-drag; mouseup refreshes it when the drag settles.
    if (!drag || drag.kind === 'connect' || drag.kind === 'marquee') renderMinimap();
  }

  // ---- minimap: a scaled overview with the viewport rect; click to jump ----
  var MINI_W = 160, MINI_H = 110, MINI_PAD = 8;
  function miniScale() { return FDCanvas.miniScale(flow, view, canvas, W, H, MINI_W, MINI_H, MINI_PAD); }
  function renderMinimap() {
    FDCanvas.renderMinimap(flow, view, canvas, W, H, MINI_W, MINI_H, MINI_PAD, document, el);
  }

  // ---- coordinate + interaction ----
  function worldPt(evt) {
    var r = canvas.getBoundingClientRect();
    return { x: (evt.clientX - r.left - view.x) / view.k, y: (evt.clientY - r.top - view.y) / view.k };
  }
  var drag = null;   // {kind:'node'|'pan'|'connect', ...}

  canvas.addEventListener('mousedown', function (evt) {
    var portEl = evt.target.closest('[data-port]');
    var nodeEl = evt.target.closest('[data-node]');
    var edgeEl = evt.target.closest('[data-edge-from]');
    if (portEl) {
      drag = { kind: 'connect', from: portEl.getAttribute('data-node'), port: portEl.getAttribute('data-port') };
      evt.preventDefault(); return;
    }
    if (edgeEl) {
      var ef = edgeEl.getAttribute('data-edge-from'), ep = edgeEl.getAttribute('data-edge-port');
      if (selectedEdge && selectedEdge.from === ef && selectedEdge.port === ep) {
        deleteEdge(selectedEdge);              // second click on a selected edge cuts it
      } else {
        selectedEdge = { from: ef, port: ep };
        selected = null; renderProps(); render();
        say('Connection selected — click it again (or press Delete) to remove it.');
      }
      evt.preventDefault(); return;
    }
    selectedEdge = null;
    if (nodeEl) {
      var id = nodeEl.getAttribute('data-node');
      var n = nodeById(id), p = worldPt(evt);
      if (multiSel[id] && Object.keys(multiSel).length > 1) {
        // dragging one selected node moves the whole marquee selection
        var offs = {};
        flow.nodes.forEach(function (m) { if (multiSel[m.id]) offs[m.id] = { dx: p.x - m.x, dy: p.y - m.y }; });
        drag = { kind: 'group', offs: offs };
        evt.preventDefault(); return;
      }
      multiSel = {};
      selectNode(id);
      drag = { kind: 'node', id: id, dx: p.x - n.x, dy: p.y - n.y };
      evt.preventDefault(); return;
    }
    if (evt.shiftKey) {           // shift-drag on empty canvas: marquee select
      var mp = worldPt(evt);
      // ex/ey start AT the origin (a click with no drag = an empty box), so the
      // mouseup reader needs no undefined-guard.
      drag = { kind: 'marquee', sx: mp.x, sy: mp.y, ex: mp.x, ey: mp.y };
      evt.preventDefault(); return;
    }
    drag = { kind: 'pan', sx: evt.clientX - view.x, sy: evt.clientY - view.y };
    canvas.classList.add('panning');
    multiSel = {};
    selectNode(null);
  });
  gNodes.addEventListener('keydown', function (evt) {
    var nodeEl = evt.target.closest('[data-node]');
    if (!nodeEl) return;
    var id = nodeEl.getAttribute('data-node');
    var n = nodeById(id); if (!n) return;
    if (evt.key === 'Enter' || evt.key === ' ') {
      evt.preventDefault(); evt.stopPropagation(); selectNode(id); return;
    }
    var dx = 0, dy = 0;
    var step = evt.shiftKey ? 48 : 16;
    if (evt.key === 'ArrowLeft') dx = -step;
    else if (evt.key === 'ArrowRight') dx = step;
    else if (evt.key === 'ArrowUp') dy = -step;
    else if (evt.key === 'ArrowDown') dy = step;
    else return;
    evt.preventDefault(); evt.stopPropagation();
    pushHistory(); selected = id; multiSel = {};
    n.x += dx; n.y += dy;
    renderProps(); render();
    say('Moved ' + stepName(n) + '.');
  });
  canvas.addEventListener('keydown', function (evt) {
    if (evt.target !== canvas) return;
    var handled = true;
    if (evt.key === 'ArrowLeft') view.x += 32;
    else if (evt.key === 'ArrowRight') view.x -= 32;
    else if (evt.key === 'ArrowUp') view.y += 32;
    else if (evt.key === 'ArrowDown') view.y -= 32;
    else if (evt.key === '+' || evt.key === '=') view.k = Math.min(2.2, view.k * 1.1);
    else if (evt.key === '-' || evt.key === '_') view.k = Math.max(0.35, view.k * 0.9);
    else if (evt.key === '0' || evt.key === 'Home') { zoomToFit(); evt.preventDefault(); return; }
    else handled = false;
    if (handled) { evt.preventDefault(); render(); }
  });
  function deleteEdge(edge) {
    var n = nodeById(edge.from);
    if (n) { pushHistory(); n[edge.port] = null; }
    selectedEdge = null; render(); renderProps();
    say('Connection removed.');
  }
  canvas.addEventListener('dblclick', function (evt) {
    var nodeEl = evt.target.closest('[data-node]'); if (!nodeEl) return;
    var n = nodeById(nodeEl.getAttribute('data-node')); if (!n) return;
    if (BODY_KINDS[n.kind]) { evt.preventDefault(); enterSub(n, n.kind); }
    else if (n.kind === 'parallel') { evt.preventDefault(); enterSub(n, 'parallel', 0); }
  });
  window.addEventListener('mousemove', function (evt) {
    if (!drag) return;
    if (drag.kind === 'node') {
      var n = nodeById(drag.id); if (!n) return;
      var p = worldPt(evt);
      // snap to a 16px grid so hand-laid flows line up without guides
      n.x = Math.round((p.x - drag.dx) / 16) * 16;
      n.y = Math.round((p.y - drag.dy) / 16) * 16;
      render();
    } else if (drag.kind === 'group') {
      var gp = worldPt(evt);
      flow.nodes.forEach(function (m) {
        var o = drag.offs[m.id]; if (!o) return;
        m.x = Math.round((gp.x - o.dx) / 16) * 16;
        m.y = Math.round((gp.y - o.dy) / 16) * 16;
      });
      render();
    } else if (drag.kind === 'marquee') {
      var mq = document.getElementById('fd-marquee');
      var mp2 = worldPt(evt);
      drag.ex = mp2.x; drag.ey = mp2.y;
      mq.style.display = '';
      mq.setAttribute('x', Math.min(drag.sx, mp2.x)); mq.setAttribute('y', Math.min(drag.sy, mp2.y));
      mq.setAttribute('width', Math.abs(mp2.x - drag.sx)); mq.setAttribute('height', Math.abs(mp2.y - drag.sy));
    } else if (drag.kind === 'pan') {
      view.x = evt.clientX - drag.sx; view.y = evt.clientY - drag.sy; render();
    } else if (drag.kind === 'connect') {
      var from = nodeById(drag.from); if (!from) return;
      var pd = ports(from).filter(function (x) { return x.key === drag.port; })[0] || { x: W / 2 };
      var px = from.x * view.k + view.x + (pd.x) * view.k, py = (from.y + H) * view.k + view.y;
      var r = canvas.getBoundingClientRect();
      var mx = evt.clientX - r.left, my = evt.clientY - r.top;
      tempEdge.style.display = ''; tempEdge.removeAttribute('transform');
      tempEdge.setAttribute('d', 'M' + ((px)) + ' ' + (py) + ' L ' + mx + ' ' + my);
      // The temp edge is built in screen space but lives inside the (translated +
      // scaled) viewport, so apply the viewport's exact inverse: undo the scale
      // AND the translate under that scale -> scale(1/k) THEN translate(-x,-y)
      // (SVG applies the rightmost transform first).
      tempEdge.setAttribute('transform', 'scale(' + (1 / view.k) + ') translate(' + (-view.x) + ',' + (-view.y) + ')');
    }
  });
  window.addEventListener('mouseup', function (evt) {
    canvas.classList.remove('panning');
    tempEdge.style.display = 'none';
    if (drag && drag.kind === 'marquee') {
      document.getElementById('fd-marquee').style.display = 'none';
      var x0 = Math.min(drag.sx, drag.ex), x1 = Math.max(drag.sx, drag.ex);
      var y0 = Math.min(drag.sy, drag.ey), y1 = Math.max(drag.sy, drag.ey);
      multiSel = {};
      flow.nodes.forEach(function (n) {
        var cx = n.x + W / 2, cy = n.y + H / 2;
        if (cx >= x0 && cx <= x1 && cy >= y0 && cy <= y1) multiSel[n.id] = true;
      });
      selected = null;
      var count = Object.keys(multiSel).length;
      say(count ? count + ' node' + (count === 1 ? '' : 's') + ' selected — drag to move together, Delete to remove.' : '');
      renderProps(); render();
      drag = null; return;
    }
    if (drag && drag.kind === 'connect') {
      var nodeEl = evt.target.closest('[data-node]');
      if (nodeEl) {
        var to = nodeEl.getAttribute('data-node'), from = nodeById(drag.from);
        if (from && to !== from.id) { pushHistory(); from[drag.port] = to; renderProps(); render(); }
      }
    }
    var wasDragging = drag && (drag.kind === 'node' || drag.kind === 'group' || drag.kind === 'pan');
    drag = null;
    // The minimap is skipped mid-drag (see render); refresh it once now that the
    // drag settled, so it isn't left stale.
    if (wasDragging) renderMinimap();
  });
  canvas.addEventListener('wheel', function (evt) {
    evt.preventDefault();
    var f = evt.deltaY < 0 ? 1.1 : 0.9;
    var nk = Math.max(0.35, Math.min(2.2, view.k * f));
    var r = canvas.getBoundingClientRect(), mx = evt.clientX - r.left, my = evt.clientY - r.top;
    view.x = mx - (mx - view.x) * (nk / view.k); view.y = my - (my - view.y) * (nk / view.k);
    view.k = nk; render();
  }, { passive: false });

  // ---- nodes ----
  function addNode(kind) {
    pushHistory();
    var n = normalizeNode({ id: newId(), kind: kind,
      x: Math.round((-view.x + 220) / view.k), y: Math.round((-view.y + 80) / view.k) }, 0);
    // an edge is selected -> insert the new node INTO that edge
    if (selectedEdge) {
      var from = nodeById(selectedEdge.from);
      if (from) {
        n.next = from[selectedEdge.port] || null;
        from[selectedEdge.port] = n.id;
        var tgt = n.next && nodeById(n.next);
        n.x = tgt && from ? Math.round((from.x + tgt.x) / 2) + 24 : from.x + 24;
        n.y = tgt && from ? Math.round((from.y + tgt.y) / 2) : from.y + 110;
        selectedEdge = null;
        flow.nodes.push(n); selectNode(n.id); render();
        say('Added between the two steps.');
        return;
      }
    }
    // else place under the currently selected node if any
    var sel = selected && nodeById(selected);
    if (sel) { n.x = sel.x; n.y = sel.y + 110; if (!sel.next && sel.kind !== 'branch') sel.next = n.id; }
    if (!flow.nodes.length) flow.start = n.id;
    flow.nodes.push(n); selectNode(n.id); render();
  }
  function deleteNode(id) {
    pushHistory();
    flow.nodes = flow.nodes.filter(function (n) { return n.id !== id; });
    flow.nodes.forEach(function (n) {
      ['next', 'if_true', 'if_false', 'on_error', 'on_expire'].forEach(function (k) { if (n[k] === id) n[k] = null; });
      // Also clear a switch node's case targets, or the deleted id survives in
      // cases[].to (invisible on canvas, but serialized + routed on Run).
      (n.cases || []).forEach(function (c) { if (c.to === id) c.to = null; });
    });
    if (flow.start === id) flow.start = flow.nodes.length ? flow.nodes[0].id : '';
    selectNode(null); render();
  }
  function deleteSelection() {
    var ids = Object.keys(multiSel);
    if (!ids.length) return;
    pushHistory();
    flow.nodes = flow.nodes.filter(function (n) { return !multiSel[n.id]; });
    flow.nodes.forEach(function (n) {
      ['next', 'if_true', 'if_false', 'on_error', 'on_expire'].forEach(function (k) { if (multiSel[n[k]]) n[k] = null; });
      (n.cases || []).forEach(function (c) { if (multiSel[c.to]) c.to = null; });
    });
    if (multiSel[flow.start]) flow.start = flow.nodes.length ? flow.nodes[0].id : '';
    multiSel = {};
    selectNode(null); render();
    say('Removed ' + ids.length + ' step' + (ids.length === 1 ? '' : 's') + '.');
  }
  // Build an independent copy of a serialized node with a fresh id and ALL
  // outgoing edges cleared -- so a clone never smuggles a stale reference to the
  // original's downstream. The one place the edge-field list is maintained
  // (next/if_true/if_false/on_error AND a switch node's cases[].to).
  function makeClone(serialized, x, y) {
    var copy = normalizeNode(JSON.parse(JSON.stringify(serialized)), 0);
    copy.id = newId();
    copy.x = x; copy.y = y;
    copy.next = null; copy.if_true = null; copy.if_false = null; copy.on_error = null; copy.on_expire = null;
    if (copy.cases && copy.cases.length) copy.cases = copy.cases.map(function (c) { return { value: c.value, to: null }; });
    return copy;
  }
  function duplicateNode(id) {
    var src = nodeById(id); if (!src) return;
    pushHistory();
    var copy = makeClone(FDCore.serializeNode(src), (src.x || 0) + 30, (src.y || 0) + 40);
    flow.nodes.push(copy); selectNode(copy.id); render();
    say('Duplicated ' + stepName(src) + '.');
  }
  function selectNode(id) {
    selected = id; if (id) selectedEdge = null; renderProps(); render();
    if (flow === rootFlow && rootFlow.id) {
      document.dispatchEvent(new CustomEvent('lightwork:copilot-selection', {detail: {
        selection: id ? {kind: 'flow', id: rootFlow.id, node_id: id} : {kind: 'flow', id: rootFlow.id}
      }}));
    }
  }
  var clipboard = null;    // serialized node (Ctrl+C), pasted with Ctrl+V
  function copyNode(id) {
    var n = nodeById(id); if (!n) return;
    clipboard = FDCore.serializeNode(n);
    say('Copied ' + stepName(n) + ' — press Ctrl+V to paste it.');
  }
  function pasteNode() {
    if (!clipboard) { say('Nothing copied yet. Select a step and choose Copy first.'); return; }
    pushHistory();
    var copy = makeClone(clipboard, (clipboard.x || 60) + 32, (clipboard.y || 60) + 48);
    flow.nodes.push(copy); selectNode(copy.id); render();
    say('Pasted a copy of ' + stepName(copy) + '.');
  }
  function zoomToFit() {
    var r = canvas.getBoundingClientRect();
    view = FDCore.fitView(flow.nodes, r.width, r.height, W, H, 40);
    render();
  }

  // ---- nested sub-flow editing (foreach body / parallel branches) ----
  // Pure serialization/normalization lives in FDCore (flow_designer_core.js) so
  // it's unit-testable under node without a DOM.
  var normalizeNode = FDCore.normalizeNode;
  function normalizeFlow(f) {
    // Upgrade a raw nested-flow dict's nodes into editable node objects (in place,
    // so the parent node's body/branches[i] keeps the same reference).
    f.nodes = (f.nodes || []).map(normalizeNode);
    if (!f.start && f.nodes.length) f.start = f.nodes[0].id;
  }
  function commitFlowRaw(f) {
    // Invalid text remains buffered so drilling into another canvas cannot
    // erase it. Save reports the path and leaves the textarea intact.
    return FDCore.commitRawParams(f);
  }
  function enterSub(node, kind, index) {
    commitFlowRaw(flow);
    var sub, label;
    if (BODY_KINDS[kind]) {
      if (!node.body) node.body = { id: '', name: 'body', start: '', nodes: [] };
      sub = node.body; label = (node.label ? node.label + ' · ' : '') + BODY_KINDS[kind];
    } else {
      node.branches = node.branches || [];
      if (!node.branches[index]) node.branches[index] = { id: '', name: 'branch ' + (index + 1), start: '', nodes: [] };
      sub = node.branches[index]; label = '🔱 ' + (node.label || 'Run together') + ' · path ' + (index + 1);
    }
    normalizeFlow(sub);
    stack.push({ flow: flow, selected: selected });
    crumbs.push(label);
    flow = sub; selected = null;
    if (window.__fdShowCanvas) window.__fdShowCanvas();
    autoLayout(); renderCrumbs(); render(); renderProps();
  }
  function exitToDepth(d) {
    commitFlowRaw(flow);
    while (stack.length > d) { var fr = stack.pop(); flow = fr.flow; selected = fr.selected; }
    crumbs.length = d + 1;
    renderCrumbs(); render(); renderProps();
  }
  function renderCrumbs() {
    var c = document.getElementById('fd-crumbs'); if (!c) return;
    c.textContent = '';
    if (!stack.length) { c.classList.remove('on'); return; }   // hidden at the root
    c.classList.add('on');
    crumbs.forEach(function (label, i) {
      if (i) c.appendChild(document.createTextNode(' ▸ '));
      if (i < crumbs.length - 1) {
        var b = document.createElement('button'); b.type = 'button'; b.className = 'fd__crumb';
        b.textContent = label; b.addEventListener('click', function () { exitToDepth(i); });
        c.appendChild(b);
      } else {
        var s = document.createElement('span'); s.className = 'fd__crumb fd__crumb--cur'; s.textContent = label; c.appendChild(s);
      }
    });
  }

  // ---- property panel ----
  var fieldSeq = 0;
  function field(label, inputEl) {
    var wrap = document.createElement('div'); wrap.className = 'field';
    var l = document.createElement('label'); l.textContent = label;
    var labelId = 'fd-field-label-' + (++fieldSeq);
    if (inputEl && /^(INPUT|SELECT|TEXTAREA)$/.test(inputEl.tagName)) {
      if (!inputEl.id) inputEl.id = 'fd-field-' + fieldSeq;
      l.htmlFor = inputEl.id;
    } else if (inputEl) {
      l.id = labelId;
      if (!inputEl.getAttribute('aria-label') && !inputEl.getAttribute('aria-labelledby')) {
        inputEl.setAttribute('aria-labelledby', labelId);
      }
    }
    wrap.appendChild(l); wrap.appendChild(inputEl); return wrap;
  }
  function input(val, oninput, ph) {
    var i = document.createElement('input'); i.className = 'input'; i.value = val || ''; if (ph) i.placeholder = ph;
    if (oninput) i.addEventListener('input', function () { oninput(i.value); });
    i.addEventListener('focus', histFocus); i.addEventListener('blur', histBlur);
    return i;
  }
  function textarea(val, oninput, ph) {
    var t = document.createElement('textarea'); t.className = 'input'; t.value = val || ''; if (ph) t.placeholder = ph;
    t.addEventListener('input', function () { oninput(t.value); });
    t.addEventListener('focus', histFocus); t.addEventListener('blur', histBlur);
    return t;
  }
  function select(val, opts, onchange) {
    var s = document.createElement('select'); s.className = 'input';
    opts.forEach(function (o) { var op = document.createElement('option'); op.value = o.v; op.textContent = o.t; if (o.v === val) op.selected = true; s.appendChild(op); });
    s.addEventListener('change', function () { onchange(s.value); }); return s;
  }
  // Small row editor: name/value pairs (used for action settings, saved data
  // and inputs passed to another flow). Never a code box.
  function pairRows(container, obj, opts) {
    Object.keys(obj).forEach(function (k, idx) {
      var row = document.createElement('div'); row.className = 'fd__pair';
      var shown = human(k);
      var keyIn = input(shown, null, opts.keyPlaceholder || 'Name');
      keyIn.setAttribute('aria-label', (opts.keyAria || 'Name') + ' ' + (idx + 1));
      keyIn.addEventListener('change', function () {
        if (keyIn.value.trim() === shown) return;
        var nv = slugKey(keyIn.value);
        if (nv && nv !== k) { obj[nv] = obj[k]; delete obj[k]; renderProps(); render(); }
      });
      var valIn = input(obj[k] == null ? '' : String(obj[k]), function (v) { obj[k] = v; }, opts.valuePlaceholder || 'Value');
      valIn.setAttribute('aria-label', (opts.valueAria || 'Value for') + ' ' + human(k));
      var rm = document.createElement('button'); rm.className = 'btn btn--ghost'; rm.type = 'button'; rm.textContent = 'Remove';
      rm.setAttribute('aria-label', 'Remove ' + human(k));
      rm.addEventListener('click', function () { delete obj[k]; renderProps(); render(); });
      row.appendChild(keyIn); row.appendChild(valIn); row.appendChild(rm);
      container.appendChild(row);
      var pills = pillsRow(selected, valIn); if (pills) container.appendChild(pills);
    });
  }
  function addButton(text, onClick) {
    var b = document.createElement('button'); b.className = 'btn btn--ghost'; b.type = 'button'; b.style.width = '100%';
    b.textContent = text; b.addEventListener('click', onClick); return b;
  }
  function stepChoices(n, none) {
    return [{ v: '', t: none }].concat(flow.nodes.filter(function (m) { return m.id !== n.id; })
      .map(function (m) { return { v: m.id, t: stepName(m) + ' (' + kindLabel(m.kind) + ')' }; }));
  }
  function keyChoices(n, cur, none) {
    var keys = availableKeys(n.id);
    var opts = [{ v: '', t: none || 'Choose information…' }].concat(keys.map(function (k) { return { v: k, t: human(k) }; }));
    if (cur && keys.indexOf(cur) < 0) opts.push({ v: cur, t: human(cur) });
    return opts;
  }
  function numberSelect(value, choices, onchange) {
    var cur = String(value == null ? '' : value);
    var opts = choices.slice();
    if (cur && !opts.some(function (o) { return o.v === cur; })) opts.push({ v: cur, t: cur });
    return select(cur || opts[0].v, opts, onchange);
  }
  function renderProps() {
    // Preserve focus + caret in the action search field across a rebuild:
    // the debounced registry search repaints this panel while the user is
    // still typing in it (loadTools -> renderProps).
    var _toolCaret = null;
    if (document.activeElement && document.activeElement.id === 'fd-tool-input') {
      try { _toolCaret = document.activeElement.selectionStart; } catch (e) { _toolCaret = -1; }
    }
    props.textContent = '';
    var selCount = Object.keys(multiSel).length;
    if (selCount) {
      var mh = document.createElement('div'); mh.style.fontWeight = '600'; mh.style.marginBottom = 'var(--space-3)';
      mh.textContent = selCount + ' steps selected';
      props.appendChild(mh);
      props.appendChild(hint('Drag any selected step to move the group. Delete removes them all; Esc clears the selection.'));
      var db = document.createElement('button'); db.className = 'btn btn--ghost btn--danger'; db.type = 'button';
      db.textContent = 'Delete ' + selCount + ' steps';
      db.addEventListener('click', deleteSelection);
      props.appendChild(db);
      return;
    }
    if (!selected) {
      var p = document.createElement('p'); p.className = 'fd__empty';
      p.textContent = 'Select a step to change it, or add one. Connect steps by dragging from a step’s bottom dot to another step, or choose the next step in its settings. Shift-drag selects several.';
      props.appendChild(p);
      // Flow-level: questions asked each time someone starts the flow by hand.
      var ih = document.createElement('div'); ih.style.fontWeight = '600'; ih.style.margin = 'var(--space-4) 0 var(--space-2)';
      ih.textContent = 'Questions to ask when someone starts this flow'; props.appendChild(ih);
      flowInputs.forEach(function (spec, ii) {
        var row = document.createElement('div'); row.className = 'fd__pair';
        var qIn = input(spec.label || (spec.key ? human(spec.key) : ''), function (v) {
          spec.label = v;
          if (!spec._keyLocked) spec.key = slugKey(v);
        }, 'For example: Customer name');
        qIn.setAttribute('aria-label', 'Question ' + (ii + 1));
        if (spec.key && !spec.label) spec._keyLocked = true;
        var typeSel = select(spec.type || 'text',
          [{ v: 'text', t: 'Text' }, { v: 'number', t: 'Number' }, { v: 'bool', t: 'Yes or no' }, { v: 'date', t: 'Date' }],
          function (v) { spec.type = v; });
        typeSel.setAttribute('aria-label', 'Answer type for question ' + (ii + 1));
        var reqWrap = document.createElement('label'); reqWrap.className = 'fd__check';
        var reqCb = document.createElement('input'); reqCb.type = 'checkbox'; reqCb.checked = !!spec.required;
        reqCb.addEventListener('change', function () { spec.required = reqCb.checked; });
        reqWrap.appendChild(reqCb); reqWrap.appendChild(document.createTextNode('Required'));
        var rm = document.createElement('button'); rm.className = 'btn btn--ghost'; rm.type = 'button'; rm.textContent = 'Remove';
        rm.setAttribute('aria-label', 'Remove question ' + (ii + 1));
        rm.addEventListener('click', function () { flowInputs.splice(ii, 1); renderProps(); renderSampleFields(); });
        row.appendChild(qIn); row.appendChild(typeSel); row.appendChild(reqWrap); row.appendChild(rm);
        props.appendChild(row);
      });
      props.appendChild(addButton('Add a question', function () { flowInputs.push({ key: '', label: '', type: 'text', required: false }); renderProps(); renderSampleFields(); }));
      props.appendChild(hint('Lightwork asks these each time someone starts the flow, and checks the answers.'));
      return;
    }
    var n = nodeById(selected); if (!n) return;
    var head = document.createElement('div'); head.style.fontWeight = '600'; head.style.marginBottom = 'var(--space-3)';
    head.textContent = (KIND_ICON[n.kind] || '') + ' ' + kindLabel(n.kind);
    props.appendChild(head);
    if (flow === rootFlow && n.kind === 'agent' && n.learned_operator && n.learned_fallback === false) {
      var tryStep = document.createElement('button'); tryStep.type = 'button'; tryStep.className = 'btn btn--ghost';
      tryStep.textContent = 'Try only this step';
      tryStep.addEventListener('click', function () {
        if (window.LWWorkflowStepChecks) void window.LWWorkflowStepChecks.openSelected();
        else say('The step controls could not be opened. Refresh this page; your work is kept.', true);
      });
      props.appendChild(tryStep);
    }
    props.appendChild(field('Step name (optional)', input(n.label, function (v) { n.label = v; render(); }, 'Shown on the step')));
    if (n.kind === 'agent') {
      var briefTa = textarea(n.brief, function (v) { n.brief = v; render(); }, 'Summarize the customer request and draft a reply');
      props.appendChild(withPills(n.id, field('Brief (what the agent should do)', briefTa), briefTa));
      if (n.learned_operator != null) {
        props.appendChild(hint(n.learned_fallback === false
          ? 'Taught local rules are attached. An answer is produced only when all retained rules agree. Remove the rules before changing the brief or output.'
          : 'Taught local rules are attached. The AI task handles inputs these rules cannot resolve. Remove the rules before changing the brief or output.'));
        var removeLearned = document.createElement('button');
        removeLearned.className = 'btn btn--ghost'; removeLearned.type = 'button';
        removeLearned.textContent = 'Remove taught rules';
        removeLearned.addEventListener('click', function () {
          pushHistory(); delete n.learned_operator; renderProps(); render();
        });
        props.appendChild(removeLearned);
      }
    }
    if (n.kind === 'action' && FDActionFields.boundRecipeAction(flow, n)) {
      props.appendChild(field('Reviewed action', hint(human(n.tool))));
      props.appendChild(hint('The reviewed examples supply this action’s details when the workflow runs. Each proposed action still requires its own approval. Use Teach to change the learned rules.'));
      var teachLink = document.createElement('a'); teachLink.className = 'btn btn--ghost';
      teachLink.href = '/flows/' + encodeURIComponent(rootFlow.id) + '/teach'; teachLink.textContent = 'Review or improve in Teach';
      props.appendChild(teachLink);
      return;
    }
    if (n.kind === 'action') {
      if (toolCategories.length) {
        var catOpts = [{ v: '', t: 'All kinds of actions' }].concat(
          toolCategories.map(function (c) { return { v: c, t: human(c) }; }));
        var catSel = select(toolFilterCategory, catOpts, function (v) {
          if (toolSearchTimer) clearTimeout(toolSearchTimer);
          toolFilterCategory = v;
          toolQuery = '';
          loadTools('', v);
        });
        props.appendChild(field('Kind of action', catSel));
      }
      // Search narrows the list; the choice itself is a dropdown of real actions.
      var toolSearch = input(toolQuery, function (v) { toolQuery = v; scheduleToolSearch(v); }, 'Search actions, for example “Slack”');
      toolSearch.id = 'fd-tool-input';
      props.appendChild(field('Find an action', toolSearch));
      var names = toolResults.slice();
      if (n.tool && names.indexOf(n.tool) < 0) names.unshift(n.tool);
      var toolOpts = [{ v: '', t: names.length ? 'Choose an action…' : 'No matching actions — try another search' }]
        .concat(names.map(function (name) { return { v: name, t: human(name) }; }));
      var toolSel = select(n.tool || '', toolOpts, function (v) { n.tool = v; render(); renderProps(); });
      toolSel.id = 'fd-tool-select';
      props.appendChild(field('Action', toolSel));
      var toolStatus = hint(toolLoading ? 'Finding actions…' : toolError ||
        (toolResults.length + ' of ' + toolTotal + ' actions shown.'));
      toolStatus.setAttribute('role', 'status');
      props.appendChild(toolStatus);
      if (toolError || toolNext !== null) {
        var moreTools = addButton(toolError ? 'Try again' : 'Show more actions', function () {
          loadTools(toolQuery.trim().length >= 2 ? toolQuery.trim() : '', toolFilterCategory,
            toolError ? (toolResults.length ? toolNext : 0) : toolNext);
        });
        moreTools.disabled = toolLoading;
        props.appendChild(moreTools);
      }
      var meta = toolCatalog[n.tool];
      if (meta && meta.description) { var th = document.createElement('p'); th.className = 'toolhint'; th.textContent = meta.description; props.appendChild(th); }
      n.params = n.params || {};
      if (n._paramsRaw !== undefined) {
        try { var parsedRaw = JSON.parse(n._paramsRaw || '{}'); if (parsedRaw && typeof parsedRaw === 'object' && !Array.isArray(parsedRaw)) n.params = parsedRaw; delete n._paramsRaw; }
        catch (e) { /* keep the buffered text; Save explains which step needs attention */ }
      }
      if (n.tool) {
        var actionHost = document.createElement('div'); actionHost.className = 'fd-action-fields';
        actionHost.textContent = 'Loading this action’s details…'; props.appendChild(actionHost);
        var requestedTool = n.tool;
        function showActionFields(refresh) {
          FDActionFields.load(requestedTool, refresh).then(function (contract) {
            if (!actionHost.isConnected || selected !== n.id || n.tool !== requestedTool) return;
            FDActionFields.mount(actionHost, n, contract, function () { render(); }, {
              sources: availableKeys(n.id).map(function (key) { return { key: key, label: human(key) }; })
            });
          }).catch(function (error) {
            if (!actionHost.isConnected || n.tool !== requestedTool) return;
            actionHost.replaceChildren(hint(error.message));
            if (error.message.indexOf('protected connection information') >= 0) {
              var connectionLink = document.createElement('a'); connectionLink.href = '/connections';
              connectionLink.className = 'btn btn--ghost'; connectionLink.textContent = 'Open Connections';
              actionHost.appendChild(connectionLink);
            }
            actionHost.appendChild(addButton('Try loading action details again', function () { showActionFields(true); }));
          });
        }
        showActionFields(false);
      }
    }
    if (n.kind === 'branch') {
      props.appendChild(conditionField(n, 'Question to decide the path'));
      props.appendChild(hint('Drag the green (Yes) and red (No) dots to the next steps, or choose them below.'));
    }
    if (n.kind === 'switch') {
      props.appendChild(field('Choose the path by', select(n.condition || '', keyChoices(n, n.condition), function (v) { n.condition = v; render(); })));
      var cwrap = document.createElement('div'); cwrap.className = 'field';
      var cl = document.createElement('div'); cl.className = 'fd__label'; cl.textContent = 'Paths (when the value is… go to…)'; cwrap.appendChild(cl);
      var targets = stepChoices(n, 'Choose a step…');
      (n.cases = n.cases || []).forEach(function (c, ci) {
        var rowc = document.createElement('div'); rowc.className = 'fd__pair';
        var vi = input(c.value != null ? String(c.value) : '', function (v) { c.value = v; render(); }, 'Value');
        vi.setAttribute('aria-label', 'Path ' + (ci + 1) + ' value');
        var ts = select(c.to || '', targets, function (v) { c.to = v || null; render(); });
        ts.setAttribute('aria-label', 'Path ' + (ci + 1) + ' next step');
        var rm = document.createElement('button'); rm.className = 'btn btn--ghost'; rm.type = 'button'; rm.textContent = 'Remove';
        rm.setAttribute('aria-label', 'Remove path ' + (ci + 1));
        rm.addEventListener('click', function () { n.cases.splice(ci, 1); renderProps(); render(); });
        rowc.appendChild(vi); rowc.appendChild(ts); rowc.appendChild(rm); cwrap.appendChild(rowc);
      });
      cwrap.appendChild(addButton('Add a path', function () { n.cases.push({ value: '', to: null }); renderProps(); }));
      props.appendChild(cwrap);
      props.appendChild(hint('When nothing matches, the flow continues to this step’s usual next step.'));
    }
    if (n.kind === 'while') {
      props.appendChild(conditionField(n, 'Keep repeating while'));
      props.appendChild(field('At most', numberSelect(n.limit || '', [{ v: '', t: '100 times (default)' }, { v: '5', t: '5 times' }, { v: '10', t: '10 times' }, { v: '25', t: '25 times' }, { v: '50', t: '50 times' }],
        function (v) { n.limit = parseInt(v, 10) || 0; })));
      var wbodyN = (n.body && n.body.nodes && n.body.nodes.length) || 0;
      var wb = addButton('Edit the repeated steps (' + wbodyN + ')', function () { enterSub(n, 'while'); });
      props.appendChild(field('Repeated steps', wb));
      props.appendChild(hint('The repeated steps can change the information this question checks, so the repeat ends on its own.'));
    }
    if (n.kind === 'wait_event') {
      var waitPrompt = input(n.prompt, function (v) { n.prompt = v; render(); }, 'For example: the payment to be confirmed');
      props.appendChild(withPills(n.id, field('Waiting for (shown while paused)', waitPrompt), waitPrompt));
      props.appendChild(hint('The flow pauses here until the connected app sends a signal. Anything the app sends is added to the flow’s information.'));
    }
    if (n.kind === 'scope') {
      var sbodyN = (n.body && n.body.nodes && n.body.nodes.length) || 0;
      props.appendChild(field('Steps that might fail', addButton('Edit these steps (' + sbodyN + ')', function () { enterSub(n, 'scope'); })));
      props.appendChild(field('If they fail, go to', select(n.on_error || '', stepChoices(n, 'Stop the run'), function (v) { n.on_error = v || null; render(); })));
      props.appendChild(hint('The step you choose can see what went wrong.'));
    }
    if (n.kind === 'foreach') {
      props.appendChild(field('Repeat for each item in', select(n.items || '', keyChoices(n, n.items, 'Choose a list…'), function (v) { n.items = v; render(); })));
      props.appendChild(field('At most', numberSelect(n.limit || '', [{ v: '', t: 'Every item (maximum 1,000)' }, { v: '10', t: 'First 10 items' }, { v: '50', t: 'First 50 items' }, { v: '100', t: 'First 100 items' }],
        function (v) { n.limit = parseInt(v, 10) || 0; })));
      props.appendChild(hint('If there are more than 1,000 items, this step stops before processing them. Choose a specific limit to process a smaller batch. Earlier steps may have completed.'));
      var bodyN = (n.body && n.body.nodes && n.body.nodes.length) || 0;
      props.appendChild(field('Steps for each item', addButton('Edit these steps (' + bodyN + ')', function () { enterSub(n, 'foreach'); })));
      var conc = document.createElement('label'); conc.className = 'fd__check';
      var cb = document.createElement('input'); cb.type = 'checkbox'; cb.checked = !!n.concurrent;
      cb.addEventListener('change', function () { n.concurrent = cb.checked; if (cb.checked && !(n.concurrency > 0)) n.concurrency = 4; render(); renderProps(); });
      conc.appendChild(cb); conc.appendChild(document.createTextNode('Handle several items at once'));
      props.appendChild(conc);
      if (n.concurrent) {
        props.appendChild(field('How many at once', numberSelect(n.concurrency || '', [{ v: '', t: 'Shared workflow limit' }, { v: '2', t: '2' }, { v: '4', t: '4' }, { v: '8', t: '8' }],
          function (v) { n.concurrency = parseInt(v, 10) || 0; })));
      }
      props.appendChild(hint('Each item is available to the repeated steps as “Item”.'));
    }
    if (n.kind === 'parallel') {
      var wrap = document.createElement('div'); wrap.className = 'field';
      var wl = document.createElement('div'); wl.className = 'fd__label'; wl.textContent = 'Paths that run at the same time'; wrap.appendChild(wl);
      (n.branches || []).forEach(function (br, bi) {
        var cnt = (br && br.nodes && br.nodes.length) || 0;
        var rowb = document.createElement('div'); rowb.className = 'fd__pair';
        var edit = document.createElement('button'); edit.className = 'btn btn--ghost'; edit.type = 'button';
        edit.textContent = 'Edit path ' + (bi + 1) + ' (' + cnt + (cnt === 1 ? ' step)' : ' steps)'); edit.addEventListener('click', function () { enterSub(n, 'parallel', bi); });
        var rm = document.createElement('button'); rm.className = 'btn btn--ghost'; rm.type = 'button'; rm.textContent = 'Remove';
        rm.setAttribute('aria-label', 'Remove path ' + (bi + 1));
        rm.addEventListener('click', function () { n.branches.splice(bi, 1); renderProps(); render(); });
        rowb.appendChild(edit); rowb.appendChild(rm); wrap.appendChild(rowb);
      });
      wrap.appendChild(addButton('Add a path', function () { n.branches = n.branches || []; n.branches.push({ id: '', name: 'path ' + (n.branches.length + 1), start: '', nodes: [] }); renderProps(); render(); }));
      props.appendChild(wrap);
      props.appendChild(hint('Each path runs on its own at the same time; their results are combined afterwards.'));
    }
    if (n.kind === 'approval') {
      var approvalPrompt = input(n.prompt, function (v) { n.prompt = v; render(); }, 'For example: Send this reply?');
      props.appendChild(withPills(n.id, field('What should the person approve?', approvalPrompt), approvalPrompt));
      var who = [{ v: '', t: 'Anyone who can approve' }].concat(people.map(function (pp) { return { v: pp.ref, t: pp.label }; }));
      if (n.assignee && !people.some(function (pp) { return pp.ref === n.assignee; })) who.push({ v: n.assignee, t: human(n.assignee) });
      props.appendChild(field('Who should be asked', select(n.assignee || '', who, function (v) { n.assignee = v; })));
      var chWrap = document.createElement('div'); chWrap.className = 'field';
      var chl = document.createElement('div'); chl.className = 'fd__label'; chl.textContent = 'Extra answers besides Approve and Reject (optional)'; chWrap.appendChild(chl);
      (n.choices = n.choices || []).forEach(function (choice, ci) {
        var rowch = document.createElement('div'); rowch.className = 'fd__pair';
        var ci0 = input(choice, function (v) { n.choices[ci] = v.trim(); }, 'For example: Hold');
        ci0.setAttribute('aria-label', 'Extra answer ' + (ci + 1));
        var rmc = document.createElement('button'); rmc.className = 'btn btn--ghost'; rmc.type = 'button'; rmc.textContent = 'Remove';
        rmc.setAttribute('aria-label', 'Remove extra answer ' + (ci + 1));
        rmc.addEventListener('click', function () { n.choices.splice(ci, 1); renderProps(); });
        rowch.appendChild(ci0); rowch.appendChild(rmc); chWrap.appendChild(rowch);
      });
      chWrap.appendChild(addButton('Add an answer', function () { n.choices.push(''); renderProps(); }));
      props.appendChild(chWrap);
      props.appendChild(field('Stop waiting after', select(String(Math.round(n.expires_after || 0)), durationOptions(n.expires_after, 'Never — wait until someone decides'),
        function (v) { n.expires_after = parseFloat(v) || 0; render(); renderProps(); })));
      if (!n.expires_after) props.appendChild(hint('This step keeps waiting. A review window lasts seven days; the owner can request a fresh review without repeating completed steps.'));
      if (n.expires_after) {
        props.appendChild(field('When time runs out', select(n.on_expire || '', stepChoices(n, 'Reject the request').map(function (o) {
          return o.v ? { v: o.v, t: 'Go to ' + o.t } : o;
        }), function (v) { n.on_expire = v || null; render(); })));
      }
      var fwrap = document.createElement('div'); fwrap.className = 'field';
      var fl = document.createElement('div'); fl.className = 'fd__label'; fl.textContent = 'Questions to ask the approver (optional)'; fwrap.appendChild(fl);
      (n.form = n.form || []).forEach(function (fld, fi) {
        var frow = document.createElement('div'); frow.className = 'fd__pair';
        var lb = input(fld.label || (fld.name ? human(fld.name) : ''), function (v) { fld.label = v; if (!fld._keyLocked) fld.name = slugKey(v); }, 'For example: Reason');
        if (fld.name && !fld.label) fld._keyLocked = true;
        lb.setAttribute('aria-label', 'Approver question ' + (fi + 1));
        var rm = document.createElement('button'); rm.className = 'btn btn--ghost'; rm.type = 'button'; rm.textContent = 'Remove';
        rm.setAttribute('aria-label', 'Remove approver question ' + (fi + 1));
        rm.addEventListener('click', function () { n.form.splice(fi, 1); renderProps(); });
        frow.appendChild(lb); frow.appendChild(rm); fwrap.appendChild(frow);
      });
      fwrap.appendChild(addButton('Add a question', function () { n.form.push({ name: '', label: '' }); renderProps(); }));
      props.appendChild(fwrap);
      props.appendChild(hint('The decision and the approver’s answers are saved, so a later “Choose a path” step can use them.'));
    }
    if (n.kind === 'delay') {
      props.appendChild(field('How long to wait', select(String(Math.round(n.seconds || 0)), durationOptions(n.seconds, 'No wait'),
        function (v) { n.seconds = parseFloat(v) || 0; render(); })));
    }
    if (n.kind === 'subflow') {
      var flowOpts = [{ v: '', t: savedFlows.length ? 'Choose a saved flow…' : 'No other saved flows yet' }].concat(
        savedFlows.filter(function (f) { return f.id !== rootFlow.id; }).map(function (f) { return { v: f.id, t: f.name || human(f.id) }; }));
      if (n.flow_ref && !flowOpts.some(function (o) { return o.v === n.flow_ref; })) flowOpts.push({ v: n.flow_ref, t: human(n.flow_ref) });
      props.appendChild(field('Flow to run', select(n.flow_ref || '', flowOpts, function (v) { n.flow_ref = v; render(); renderProps(); })));
      n.subflow_inputs = n.subflow_inputs || {};
      var child = savedFlows.filter(function (f) { return f.id === n.flow_ref; })[0];
      var declared = (child && child.inputs) || [];
      var si = document.createElement('div'); si.className = 'field';
      var sil = document.createElement('div'); sil.className = 'fd__label'; sil.textContent = 'Information to give it'; si.appendChild(sil);
      if (declared.length) {
        declared.forEach(function (spec) {
          if (!spec || !spec.key) return;
          var vin = input(n.subflow_inputs[spec.key] == null ? '' : String(n.subflow_inputs[spec.key]), function (v) {
            if (v === '') delete n.subflow_inputs[spec.key]; else n.subflow_inputs[spec.key] = v;
          }, 'Type a value or insert a result');
          si.appendChild(withPills(n.id, field(spec.label || human(spec.key), vin), vin));
        });
      } else {
        pairRows(si, n.subflow_inputs, { keyPlaceholder: 'Name', valuePlaceholder: 'Value or earlier result', keyAria: 'Information name', valueAria: 'Value for' });
        si.appendChild(addButton('Add information', function () { var key = 'input_' + (Object.keys(n.subflow_inputs).length + 1); n.subflow_inputs[key] = ''; renderProps(); render(); }));
      }
      props.appendChild(si);
      props.appendChild(hint(Object.keys(n.subflow_inputs).length
        ? 'The other flow sees only the information listed here. Its result comes back under the name below.'
        : 'With nothing listed, the other flow can use all of this flow’s information and its results come back here.'));
    }
    if (n.kind === 'setvar') {
      var sv = document.createElement('div'); sv.className = 'field';
      var svl = document.createElement('div'); svl.className = 'fd__label'; svl.textContent = 'Information to save'; sv.appendChild(svl);
      n.assignments = n.assignments || {};
      pairRows(sv, n.assignments, { keyPlaceholder: 'Name, for example: status', valuePlaceholder: 'Value or earlier result', keyAria: 'Information name', valueAria: 'Value for' });
      sv.appendChild(addButton('Add information', function () { var key = 'value_' + (Object.keys(n.assignments).length + 1); n.assignments[key] = ''; renderProps(); render(); }));
      props.appendChild(sv);
    }
    if (['agent', 'action', 'foreach', 'parallel', 'while', 'approval', 'subflow'].indexOf(n.kind) >= 0)
      props.appendChild(field('Name this result (so later steps can use it)', input(n.output, function (v) { n.output = slugKey(v) || v; }, 'For example: summary')));
    // What happens when this step fails (collapsed; sensible defaults).
    if (['agent', 'action', 'subflow'].indexOf(n.kind) >= 0) {
      var fails = document.createElement('details'); fails.className = 'fd__fails';
      var fs = document.createElement('summary'); fs.textContent = 'If this step fails'; fails.appendChild(fs);
      if (n.kind !== 'subflow') {
        fails.appendChild(field('Try again', numberSelect(n.retries || 0, [{ v: '0', t: 'Don’t try again' }, { v: '1', t: 'Once' }, { v: '2', t: 'Twice' }, { v: '3', t: '3 times' }],
          function (v) { n.retries = parseInt(v, 10) || 0; })));
        var retryHelp = document.createElement('p'); retryHelp.className = 'muted'; retryHelp.id = 'fd-retry-wait-help';
        function describeRetryWait() {
          var requested = Number(n.retry_backoff) || 0, effective = Math.min(30, Math.max(0, requested));
          retryHelp.textContent = (requested > 30 ? 'The saved request is ' + durationText(requested) + ', but each wait is limited to 30 seconds. Choose a supported wait to change it. ' : requested < 0 ? 'The saved request is ' + durationText(requested) + '; no wait is used. Choose a supported wait to change it. ' : '') +
            (effective ? 'When another try is allowed, the first wait is ' + durationText(effective) + '; later waits double, up to 30 seconds. ' : 'When another try is allowed, no wait is requested. ') +
            'The run’s time limit can stop work sooner. AI tasks and actions that are unsafe to repeat or have an uncertain result are not repeated automatically.';
        }
        var retryChoice = select(String(Number(n.retry_backoff) || 0), retryWaitOptions(n.retry_backoff),
          function (v) { pushHistory(); n.retry_backoff = parseFloat(v) || 0; describeRetryWait(); });
        retryChoice.setAttribute('aria-describedby', retryHelp.id);
        fails.appendChild(field('First wait between tries', retryChoice)); describeRetryWait(); fails.appendChild(retryHelp);
        fails.appendChild(field(n.kind === 'action' ? 'Expected wait' : 'Give up after', select(String(Math.round(n.timeout || 0)), durationOptions(n.timeout, n.kind === 'action' ? 'No wait target' : 'No time limit'),
          function (v) { n.timeout = parseFloat(v) || 0; })));
        if (n.kind === 'action') {
          var timeoutHelp = document.createElement('p'); timeoutHelp.className = 'muted';
          timeoutHelp.textContent = 'This does not stop an action already in progress. Lightwork waits for its recorded outcome so a completed action is not mistaken for a failure and repeated.';
          fails.appendChild(timeoutHelp);
        }
      }
      fails.appendChild(field('Then go to', select(n.on_error || '', stepChoices(n, 'Stop the run'), function (v) { n.on_error = v || null; render(); })));
      if (n.retries || n.timeout || n.on_error) fails.open = true;
      props.appendChild(fails);
    }
    // Every canvas connection also has a keyboard-operable equivalent.
    ports(n).forEach(function (port) {
      var connectionLabel = port.key === 'if_true' ? 'If yes, go to'
        : (port.key === 'if_false' ? 'If no, go to' : 'Next step');
      props.appendChild(field(connectionLabel, select(n[port.key] || '', stepChoices(n, 'End the flow here'), function (v) {
        pushHistory(); n[port.key] = v || null; render();
      })));
    });
    // last run outcome for this step (from the live/last run overlay)
    var rs = runState[n.id];
    if (rs || n.id === runCursor) {
      var badge = runBadge(n.id);
      var rl = document.createElement('p'); rl.className = 'fd__empty'; rl.style.marginTop = 'var(--space-2)';
      rl.textContent = 'Last run: ' + (n.id === runCursor ? 'waiting here'
        : (rs.outcome === 1 ? 'worked' : (rs.outcome === 0 ? 'failed' : (rs.status === 'true' ? 'answered yes' : (rs.status === 'false' ? 'answered no' : 'ran')))))
        + (rs && rs.seconds != null ? ' · took ' + (rs.seconds < 1 ? 'under a second' : Math.round(rs.seconds) + ' seconds') : '') + ' ' + badge;
      props.appendChild(rl);
    }
    var sig = signals.nodes[n.id];
    if (sig && sig.n) {
      var sl = document.createElement('p'); sl.className = 'fd__empty'; sl.style.marginTop = 'var(--space-2)';
      var pct = Math.round(sig.mean * 100);
      if (n.kind === 'approval') sl.textContent = '🧑‍⚖️ People approved ' + pct + '% of ' + sig.n + ' requests';
      else sl.textContent = '📊 Worked in ' + pct + '% of ' + sig.n + ' runs';
      props.appendChild(sl);
    }
    var imp = impacts[n.id];
    if (imp && imp.changed && imp.impact) {
      var d = imp.impact.delta;
      var il = document.createElement('p'); il.className = 'fd__empty'; il.style.marginTop = 'var(--space-2)';
      il.textContent = '📈 Since this step became ' + (imp.applied && imp.applied.to_kind === 'action' ? 'a fixed action' : 'an AI task') + ': '
        + (typeof d === 'number' ? (d >= 0 ? '+' : '') + Math.round(d * 100) + '% compared with before'
          : 'still measuring (' + (imp.impact.after && imp.impact.after.n || 0) + ' runs so far)');
      props.appendChild(il);
    }
    // self-rewrite proposal for this node (from grounded per-node outcomes)
    var prop = flow === rootFlow ? proposals[n.id] : null;
    if (prop) {
      var pbox = document.createElement('div');
      pbox.style.cssText = 'margin-top:var(--space-3);padding:var(--space-2);border:1px solid var(--accent);border-radius:8px;';
      var pl = document.createElement('p'); pl.className = 'fd__empty'; pl.style.marginBottom = 'var(--space-2)';
      pl.textContent = '💡 ' + prop.reason;
      var pb = document.createElement('button'); pb.className = 'btn btn--primary'; pb.type = 'button';
      pb.setAttribute('data-apply-node', n.id);
      pb.disabled = saveInFlight || publishInFlight || applyInFlight || !!unresolvedApply(n);
      pb.textContent = prop.to_kind === 'action'
        ? 'Review action and inputs'
        : 'Review: let the AI handle this step';
      pb.addEventListener('click', function () { applyProposal(n, prop, pb); });
      pbox.appendChild(pl); pbox.appendChild(pb); props.appendChild(pbox);
    }
    // actions
    var row = document.createElement('div'); row.style.display = 'flex'; row.style.gap = 'var(--space-2)'; row.style.marginTop = 'var(--space-3)'; row.style.flexWrap = 'wrap';
    if (n.id !== flow.start) {
      var mk = document.createElement('button'); mk.className = 'btn btn--ghost'; mk.type = 'button'; mk.textContent = 'Make this the first step';
      mk.addEventListener('click', function () { flow.start = n.id; render(); renderProps(); });
      row.appendChild(mk);
    }
    var dup = document.createElement('button'); dup.className = 'btn btn--ghost'; dup.type = 'button'; dup.textContent = 'Duplicate';
    dup.title = 'Ctrl+D';
    dup.addEventListener('click', function () { duplicateNode(n.id); });
    var del = document.createElement('button'); del.className = 'btn btn--ghost btn--danger'; del.type = 'button'; del.textContent = 'Delete step';
    del.addEventListener('click', function () { deleteNode(n.id); });
    row.appendChild(dup); row.appendChild(del); props.appendChild(row);
    if (_toolCaret !== null) {
      var _ti = document.getElementById('fd-tool-input');
      if (_ti) {
        _ti.focus();
        if (_toolCaret >= 0) { try { _ti.setSelectionRange(_toolCaret, _toolCaret); } catch (e) {} }
      }
    }
  }
  function slugKey(v) {
    return String(v || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 48);
  }
  function hint(t) { var p = document.createElement('p'); p.className = 'fd__empty'; p.textContent = t; return p; }

  // ---- data pills: what THIS node can reference, one click to insert ----
  function availableKeys(nodeId) {
    var keys = FDCore.upstreamOutputs(flow, nodeId);
    // Nested keys learned from real runs: for an upstream output that produced
    // an object/array-of-objects, offer key.field so the user needn't guess.
    keys.slice().forEach(function (k) {
      var shape = flowSchema[k];
      if (shape && shape.keys && shape.keys.length) {
        shape.keys.forEach(function (f) {
          var nested = k + '.' + f;
          if (keys.indexOf(nested) < 0) keys.push(nested);
        });
      }
    });
    // The questions asked at start and the sample test values are the flow's
    // starting information.
    flowInputs.forEach(function (i) { if (i.key && keys.indexOf(i.key) < 0) keys.push(i.key); });
    Object.keys(sampleData().data).forEach(function (k) { if (keys.indexOf(k) < 0) keys.push(k); });
    return keys;
  }
  function insertAtCursor(target, text) {
    var s = target.selectionStart, e = target.selectionEnd, v = target.value;
    if (s == null) { target.value = v + text; }
    else { target.value = v.slice(0, s) + text + v.slice(e); target.selectionStart = target.selectionEnd = s + text.length; }
    target.dispatchEvent(new Event('input', { bubbles: false }));
    target.focus();
  }
  function pillsRow(nodeId, target, raw) {
    var keys = availableKeys(nodeId);
    if (!keys.length) return null;
    var row = document.createElement('div'); row.className = 'fd__pills';
    keys.forEach(function (k) {
      var b = document.createElement('button'); b.type = 'button'; b.className = 'fd__pill';
      b.textContent = '+ ' + human(k); b.title = 'Insert the result “' + human(k) + '”';
      b.addEventListener('mousedown', function (evt) { evt.preventDefault(); });   // keep target's focus
      b.addEventListener('click', function () { insertAtCursor(target, raw ? k : '{{' + k + '}}'); });
      row.appendChild(b);
    });
    return row;
  }
  function withPills(nodeId, fieldEl, target, raw) {
    var pills = pillsRow(nodeId, target, raw);
    if (pills) fieldEl.appendChild(pills);
    return fieldEl;
  }
  function jsonOr(v) { try { return v && (typeof v === 'object') ? JSON.stringify(v, null, 2) : (v || ''); } catch (e) { return ''; } }

  // Ordinary grouped questions use the exact native condition grammar.
  var COND_OPS = FDCore.COND_OPS;
  var OP_WORDS = { '==': 'is', '!=': 'is not', '>': 'is more than', '<': 'is less than',
    '>=': 'is at least', '<=': 'is at most', 'contains': 'contains' };
  function conditionText(c) {
    if (!c) return '';
    try {
      return FDCore.parseCondition(c).map(function (group) {
        return group.map(function (question) {
          return human(question.key) + ' ' + (question.op === 'truthy' ? 'is yes or non-empty' :
            (OP_WORDS[question.op] || question.op) + ' ' + (question.kind === 'boolean' ? (question.value === 'true' ? 'Yes' : 'No') : question.value));
        }).join(' and ');
      }).join(' — or — ');
    } catch (_) { return 'Saved question — open its settings to review editing options'; }
  }
  function conditionField(n, label) {
    var wrap = document.createElement('div'); wrap.className = 'field';
    var l = document.createElement('div'); l.className = 'fd__label'; l.textContent = label;
    var conditionLabelId = 'fd-condition-label-' + (++fieldSeq);
    l.id = conditionLabelId; wrap.appendChild(l);
    var groups;
    try { groups = n._conditionQuestions || FDCore.parseCondition(n.condition); }
    catch (error) {
      wrap.appendChild(hint(error.message));
      wrap.appendChild(addButton('Replace with new questions', function () {
        n.condition = ''; delete n._conditionQuestions; delete n._conditionProblem; renderProps(); render();
      }));
      return wrap;
    }
    var mode = groups.length > 1 ? 'any' : 'all';
    var editor = document.createElement('div'); editor.className = 'fd__condition-groups'; wrap.appendChild(editor);
    var notice = document.createElement('p'); notice.className = 'muted'; notice.setAttribute('role', 'status'); wrap.appendChild(notice);
    function blank() { return {key: '', op: '==', kind: 'text', value: ''}; }
    function commit() {
      n._conditionQuestions = groups;
      try { n.condition = FDCore.conditionQuestions(groups); delete n._conditionProblem; notice.textContent = ''; }
      catch (error) { n._conditionProblem = error.message; notice.textContent = error.message + ' Finish these questions before saving.'; }
      render();
    }
    function draw() {
      editor.replaceChildren();
      var match = select(mode, [{v: 'all', t: 'Match all of these questions'}, {v: 'any', t: 'Match any of these groups'}], function (value) {
        mode = value;
        if (mode === 'all') groups = [groups.flat()];
        else if (groups.length === 1) groups = groups[0].map(function (question) { return [question]; });
        commit(); draw();
      });
      match.setAttribute('aria-label', label + ': which questions must match'); editor.appendChild(match);
      groups.forEach(function (group, groupIndex) {
        var section = document.createElement('fieldset'); section.className = 'fd__condition-group'; section.style.minWidth = '0';
        var legend = document.createElement('legend'); legend.textContent = mode === 'all' ? 'Every question must match' : 'Group ' + (groupIndex + 1) + ' — every question must match';
        section.appendChild(legend); editor.appendChild(section);
        group.forEach(function (question, questionIndex) {
          var row = document.createElement('div'); row.className = 'fd__pair'; row.style.flexWrap = 'wrap';
          row.dataset.conditionQuestion = String(groupIndex + 1) + '-' + String(questionIndex + 1);
          var name = label + ', group ' + (groupIndex + 1) + ', question ' + (questionIndex + 1);
          var keySel = select(question.key, keyChoices(n, question.key, 'Choose information…'), function (value) { question.key = value; commit(); });
          keySel.setAttribute('aria-label', name + ': information to check'); row.appendChild(keySel);
          var opSel = select(question.op, COND_OPS.map(function (operator) { return {v: operator, t: OP_WORDS[operator] || operator}; }).concat([{v: 'truthy', t: 'is yes or non-empty'}]), function (value) { question.op = value; commit(); draw(); });
          opSel.setAttribute('aria-label', name + ': comparison'); row.appendChild(opSel);
          if (question.op !== 'truthy') {
            var kindSel = select(question.kind, [{v: 'text', t: 'Text'}, {v: 'number', t: 'Number'}, {v: 'boolean', t: 'Yes or No'}], function (value) {
              question.kind = value; delete question.literal; if (value === 'boolean') question.value = 'true'; commit(); draw();
            });
            kindSel.setAttribute('aria-label', name + ': value type'); row.appendChild(kindSel);
            var valueInput = question.kind === 'boolean'
              ? select(question.value, [{v: 'true', t: 'Yes'}, {v: 'false', t: 'No'}], function (value) { question.value = value; delete question.literal; commit(); })
              : input(question.value, function (value) { question.value = value; delete question.literal; commit(); }, question.kind === 'number' ? 'Number to compare' : 'Text to compare');
            valueInput.setAttribute('aria-label', name + ': value'); row.appendChild(valueInput);
          }
          var remove = addButton('Remove question', function () {
            group.splice(questionIndex, 1); if (!group.length) groups.splice(groupIndex, 1); if (!groups.length) groups = [[blank()]]; commit(); draw();
          });
          remove.setAttribute('aria-label', name + ': remove question'); row.appendChild(remove); section.appendChild(row);
        });
        var add = addButton('Add question to this group', function () { group.push(blank()); commit(); draw(); });
        add.disabled = groups.reduce(function (count, item) { return count + item.length; }, 0) >= 64; section.appendChild(add);
      });
      if (mode === 'any') {
        var addGroup = addButton('Add another matching group', function () { groups.push([blank()]); commit(); draw(); });
        addGroup.disabled = groups.length >= 32 || groups.reduce(function (count, item) { return count + item.length; }, 0) >= 64; editor.appendChild(addGroup);
      }
    }
    draw();
    if (n._conditionProblem) notice.textContent = n._conditionProblem + ' Finish these questions before saving.';
    wrap.appendChild(hint('Groups give you alternative paths. Within a group, every question must match. Zero, No and empty text do not match “is yes or non-empty”.'));
    if (!availableKeys(n.id).length) wrap.appendChild(hint('Name an earlier step’s result, or add a question asked at start, to choose it here.'));
    return wrap;
  }

  // ---- serialize / api ----
  function commitRawFields() {
    return FDCore.commitRawParams(rootFlow).concat(FDActionFields.check(rootFlow), FDCore.conditionProblems(rootFlow));
  }
  var serializeFlow = FDCore.serializeFlow;
  function toApiFlow() {
    return FDWire.toApiFlow({ document: document, rootFlow: rootFlow, idInput: idInput,
      nameInput: nameInput, flowInputs: flowInputs, serializeFlow: serializeFlow });
  }
  // ---- schedule picker: frequency, days, time and time zone -> timetable ----
  var scheduleWords = FDSchedule.words;
  var parseSchedule = FDSchedule.parse;
  function schedEl(id) { return document.getElementById(id); }
  function buildSchedule() {
    var days = Array.prototype.filter.call(document.querySelectorAll('#fd-sched-days input[type=checkbox]'), function (c) { return c.checked; })
      .map(function (c) { return c.value; });
    return FDSchedule.build({
      freq: (schedEl('fd-sched-freq') || {}).value || '',
      time: (schedEl('fd-sched-time') || {}).value || '09:00',
      cron: (schedEl('fd-schedule') || {}).value || '',
      every: (schedEl('fd-sched-every') || {}).value,
      minute: (schedEl('fd-sched-minute') || {}).value,
      days: days,
      dom: (schedEl('fd-sched-dom') || {}).value
    });
  }
  function showScheduleParts() {
    var freq = (schedEl('fd-sched-freq') || {}).value || '';
    var rows = { 'fd-sched-days': freq === 'weekly', 'fd-sched-dom-row': freq === 'monthly',
      'fd-sched-minute-row': freq === 'hourly', 'fd-sched-every-row': freq === 'hourly',
      'fd-sched-time-row': ['daily', 'weekdays', 'weekly', 'monthly'].indexOf(freq) >= 0,
      'fd-sched-tz-row': freq !== '' };
    Object.keys(rows).forEach(function (id) { var e = schedEl(id); if (e) e.hidden = !rows[id]; });
    var words = schedEl('fd-sched-words'), cron = ((schedEl('fd-schedule') || {}).value || '').trim();
    if (words) words.textContent = cron ? 'Runs ' + scheduleWords(cron) + '. Publish to turn schedule changes on.' : 'Runs only when started by hand or by another app.';
    var note = schedEl('fd-sched-note');
    if (note) {
      var parsed = parseSchedule(cron);
      note.textContent = parsed.freq === 'monthly' && Number(parsed.dom) > 28
        ? 'Months without this date are skipped. Choose a day from 1 to 28 if it must run every month.'
        : parsed.freq === 'hourly'
          ? 'Uses clock times in the selected time zone, starting at midnight. Clock changes may skip or repeat a run.' : '';
      note.hidden = !note.textContent;
    }
  }
  function syncScheduleControls() {
    var schedule = schedEl('fd-schedule'), freqSel = schedEl('fd-sched-freq');
    if (!schedule || !freqSel) return;
    var parsed = parseSchedule(schedule.value);
    var customOpt = freqSel.querySelector ? freqSel.querySelector('option[value="custom"]') : null;
    if (customOpt) customOpt.hidden = parsed.freq !== 'custom';
    freqSel.value = parsed.freq;
    if (parsed.every != null && schedEl('fd-sched-every')) schedEl('fd-sched-every').value = String(parsed.every);
    if (parsed.time && schedEl('fd-sched-time')) schedEl('fd-sched-time').value = parsed.time;
    if (parsed.minute != null && schedEl('fd-sched-minute')) schedEl('fd-sched-minute').value = String(Number(parsed.minute));
    if (parsed.dom && schedEl('fd-sched-dom')) schedEl('fd-sched-dom').value = String(Number(parsed.dom));
    if (parsed.days) Array.prototype.forEach.call(document.querySelectorAll('#fd-sched-days input[type=checkbox]'), function (c) {
      c.checked = parsed.days.indexOf(c.value) >= 0;
    });
    showScheduleParts();
  }
  function chooseSchedule() {
    var schedule = schedEl('fd-schedule');
    if ((schedEl('fd-sched-freq') || {}).value !== 'custom') {
      var next = buildSchedule();
      if (schedule.value !== next) { pushHistory(); schedule.value = next; }
    }
    var tz = schedEl('fd-tz');
    if (tz && !tz.value && schedule.value) { try { tz.value = Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) { /* keep UTC */ } }
    showScheduleParts();
  }
  function fillTimeZones() {
    var tz = schedEl('fd-tz'); if (!tz || tz.options.length > 1) return;
    var zones = [];
    try { zones = Intl.supportedValuesOf('timeZone'); } catch (e) {
      zones = ['America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles', 'Europe/London',
        'Europe/Paris', 'Europe/Berlin', 'Asia/Kolkata', 'Asia/Singapore', 'Asia/Tokyo', 'Australia/Sydney'];
    }
    zones.forEach(function (z) {
      var o = document.createElement('option'); o.value = z;
      var parts = z.split('/'); o.textContent = parts.length > 1 ? parts.slice(1).join(' / ').replace(/_/g, ' ') + ' (' + parts[0].replace(/_/g, ' ') + ')' : z.replace(/_/g, ' ');
      tz.appendChild(o);
    });
  }
  function setSelectValue(id, value, label) {
    var sel = schedEl(id); if (!sel) return;
    var v = value == null ? '' : String(value);
    if (sel.tagName === 'SELECT' && v && !Array.prototype.some.call(sel.options, function (o) { return o.value === v; })) {
      var o = document.createElement('option'); o.value = v; o.textContent = label ? label(v) : v; sel.appendChild(o);
    }
    sel.value = v;
  }
  // ---- sample answers for a test: one box per question asked at start ----
  function renderSampleFields() {
    var box = schedEl('fd-sample-fields'); if (!box) return;
    var prior = sampleData().data;
    box.textContent = '';
    var keys = [];
    flowInputs.forEach(function (spec) {
      if (!spec.key || keys.indexOf(spec.key) >= 0) return; keys.push(spec.key);
      var inp = document.createElement('input'); inp.className = 'input';
      inp.id = 'fd-sample-' + spec.key; inp.setAttribute('data-sample-key', spec.key);
      inp.value = prior[spec.key] || '';
      box.appendChild(field(spec.label || human(spec.key), inp));
    });
    Object.keys(prior).forEach(function (k) {
      if (keys.indexOf(k) >= 0) return;
      addSampleRow(k, prior[k]);
    });
    if (!keys.length && !Object.keys(prior).length) box.appendChild(hint('Add questions under “Questions to ask when someone starts this flow” (select no step to see them), or add a sample value below.'));
  }
  function addSampleRow(k, v) {
    var box = schedEl('fd-sample-fields'); if (!box) return;
    var row = document.createElement('div'); row.className = 'fd__pair fd__sample-extra';
    var n = input(k ? human(k) : '', null, 'Name'); n.setAttribute('data-extra-name', ''); n.setAttribute('aria-label', 'Sample value name');
    var val = input(v || '', null, 'Value'); val.setAttribute('data-extra-value', ''); val.setAttribute('aria-label', 'Sample value');
    var rm = document.createElement('button'); rm.className = 'btn btn--ghost'; rm.type = 'button'; rm.textContent = 'Remove';
    rm.addEventListener('click', function () { row.remove(); });
    row.appendChild(n); row.appendChild(val); row.appendChild(rm); box.appendChild(row);
  }
  function fromApiFlow(f, savedSnapshot) {
    runState = {}; runCursor = null; impacts = {};
    stack = []; crumbs = ['Main flow']; renderCrumbs();
    signals = { nodes: {}, trigger: null };
    var sigEl = document.getElementById('fd-signal'); if (sigEl) sigEl.hidden = true;
    var lg = document.getElementById('fd-legend'); if (lg) lg.classList.remove('on');
    flow = { id: f.id || '', name: f.name || '', start: f.start || '', nodes: [],
      max_seconds: f.max_seconds || 0, version: parseInt(f.version, 10) || 0,
      revision: String(f.revision || ''), published: !!f.published,
      learned_recipe: f.learned_recipe == null ? null : JSON.parse(JSON.stringify(f.learned_recipe)),
      recipe_lineage: f.recipe_lineage == null ? null : JSON.parse(JSON.stringify(f.recipe_lineage)),
      recipe_teaching: f.recipe_teaching == null ? null : JSON.parse(JSON.stringify(f.recipe_teaching)),
      _fdEvidence: f._fdEvidence == null ? null : JSON.parse(JSON.stringify(f._fdEvidence)),
      published_version: parseInt(f.published_version, 10) || 0,
      published_revision: String(f.published_revision || '') };
    var notifyEl = document.getElementById('fd-notify'); if (notifyEl) notifyEl.checked = !!f.notify;
    if (document.getElementById('fd-notify-on')) document.getElementById('fd-notify-on').value = f.notify_on || 'all';
    var mdEl = document.getElementById('fd-maxdollars'); if (mdEl) mdEl.value = f.max_dollars || '';
    var schEl = document.getElementById('fd-schedule'); if (schEl) schEl.value = f.schedule || '';
    syncScheduleControls();
    if (document.getElementById('fd-tz')) setSelectValue('fd-tz', f.timezone || '');
    if (document.getElementById('fd-maxsec')) setSelectValue('fd-maxsec', f.max_seconds || '', function (v) { return durationText(Number(v)); });
    if (document.getElementById('fd-maxconc')) setSelectValue('fd-maxconc', f.max_concurrent || '', function (v) { return 'Up to ' + v + ' at once'; });
    flowInputs = (f.inputs || []).map(function (i) { return Object.assign({}, i); });
    if (document.getElementById('fd-sample-fields')) renderSampleFields();
    (f.nodes || []).forEach(function (nd, i) { flow.nodes.push(normalizeNode(nd, i)); });
    rootFlow = flow;
    var samplePanel = document.getElementById('fd-test-data');
    if (samplePanel) samplePanel.hidden = rootFlow.learned_recipe != null;
    autoLayout();
    nameInput.value = flow.name; idInput.value = flow.id;
    selected = null; selectedEdge = null; view = { x: 40, y: 20, k: 1 }; render(); renderProps();
    syncSaveButtons();
    if (savedSnapshot) markClean();
    if (typeof window !== 'undefined' && typeof window.dispatchEvent === 'function')
      window.dispatchEvent(new Event('lightwork:flow-loaded'));
  }
  function autoLayout() {
    var need = flow.nodes.some(function (n) { return !n.x && !n.y; });
    if (!need) return;
    var col = {}, depth = {}, seen = {};
    var order = [], queue = flow.start ? [flow.start] : (flow.nodes[0] ? [flow.nodes[0].id] : []);
    while (queue.length) {
      var id = queue.shift(); if (seen[id]) continue; seen[id] = 1;
      var n = nodeById(id); if (!n) continue; order.push(n);
      var d = depth[id] || 0;
      ['next', 'if_true', 'if_false'].forEach(function (k) { if (n[k] && !seen[n[k]]) { depth[n[k]] = d + 1; queue.push(n[k]); } });
    }
    flow.nodes.forEach(function (n) { if (!(n.id in depth) && n.id !== flow.start) depth[n.id] = 0; });
    var rowCount = {};
    flow.nodes.forEach(function (n) {
      var d = depth[n.id] || 0; rowCount[d] = (rowCount[d] || 0);
      n.x = 60 + rowCount[d] * 220; n.y = 40 + d * 110; rowCount[d]++;
    });
  }

  function apiFetch(url, opts) { return FDTransport.fetchJson(fetch, url, opts); }
  var ACTION_WORDS = { Save: 'save the flow', Publish: 'publish the flow', Run: 'start the run',
    Draft: 'draft the flow', Apply: 'apply the suggestion' };
  function workflowsOff(response) {
    var headers = response && response.headers;
    return headers && typeof headers.get === 'function'
      ? headers.get('X-Lightwork-Feature-Off') === 'workflows'
      : fd.dataset.flowEngineOn !== 'true';
  }
  function failText(response, action) {
    var what = ACTION_WORDS[action] || String(action || 'do that').toLowerCase();
    if (response && response.status === 403 && workflowsOff(response))
      return 'Workflows are turned off. ' + (fd.dataset.canManageFlows === 'true'
        ? 'Turn them on in Learning, then try again.'
        : 'Ask the person who manages this installation to turn them on.');
    if (window.mvErrorText) return window.mvErrorText(response, what);
    var status = response && response.status;
    if (status === 409) return 'Could not ' + what + '. This flow was changed since you opened it. Reload it and try again.';
    return 'Could not ' + what + '. Try again.';
  }
  // Problems in words, naming the step ("The step “Send to Slack” needs an action chosen.").
  function problemText(f) {
    var list = FDCore.plainProblems ? FDCore.plainProblems(f) : FDCore.validateFlow(f);
    return list.slice(0, 3).join(' ');
  }
  // The sample answers entered for a test (one box per question asked at
  // start, plus any extra name/value rows).
  function sampleData() {
    var out = {}, box = document.getElementById('fd-sample-fields');
    if (!box || !box.querySelectorAll) return { data: out };
    Array.prototype.forEach.call(box.querySelectorAll('[data-sample-key]'), function (inp) {
      var v = (inp.value || '').trim(); if (v) out[inp.getAttribute('data-sample-key')] = v;
    });
    Array.prototype.forEach.call(box.querySelectorAll('.fd__sample-extra'), function (row) {
      var k = slugKey((row.querySelector('[data-extra-name]') || {}).value), v = ((row.querySelector('[data-extra-value]') || {}).value || '').trim();
      if (k && v) out[k] = v;
    });
    return { data: out };
  }
  function unconfirmedMutation(action) { return FDTransport.unconfirmedMutation(action); }
  async function readMutationResult(response, action) {
    return FDTransport.readMutationResult(response, action, {
      recipeInputs: typeof FDRecipeInputs !== 'undefined' ? FDRecipeInputs : null, failText: failText
    });
  }
  function validPublication(result) { return FDTransport.validPublication(result); }
  function slugify(s) {
    return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);
  }
  async function save(forApply) {
    if (saveInFlight || actionFieldsChecking || retireInFlight || (applyInFlight && forApply !== true)) return false;
    var checkedFlow = rootFlow, checkedSnapshot = draftSnapshot();
    actionFieldsChecking = true; syncSaveButtons();
    say('Checking the workflow’s current action details…');
    try { await FDActionFields.ready(rootFlow, true); }
    catch (error) { say(error.message, true); return false; }
    finally { actionFieldsChecking = false; syncSaveButtons(); }
    if (rootFlow !== checkedFlow || draftSnapshot() !== checkedSnapshot) {
      say('The workflow changed while its action details loaded. Your newer edits are kept; review them and save again.', true);
      return false;
    }
    var bad = commitRawFields();
    if (bad.length) { say(FDActionFields.check(rootFlow)[0] || 'Some action settings aren’t filled in correctly. Check the steps and try again.', true); renderProps(); return false; }
    var body = toApiFlow();
    if (!body.id) { body.id = slugify(body.name); idInput.value = body.id; }   // auto-id from the name
    if (!body.id) { say('Give the flow a name (top-left).', true); return false; }
    if (!body.nodes.length) { say('Add at least one step.', true); return false; }
    var verrs = FDCore.validateFlow(body);
    if (verrs.length) { say('Before saving: ' + problemText(body), true); return false; }
    if (verrs.length) { say('Fix first: ' + verrs.slice(0, 3).join(' · '), true); return false; }
    var creationHistory = body.version === 0 && body.revision === ''
      ? { sourceId: rootFlow.id, snapshots: undoStack.concat(redoStack, pendingSnap ? [pendingSnap] : []) } : null;
    rootFlow.id = body.id;
    var savedDraftSnapshot = draftSnapshot();
    saveInFlight = true; syncSaveButtons();
    say('Saving…');
    try {
      var response = await apiFetch('/api/v1/flows', {
        method: 'POST', body: '{"flow":' + FDRecipeInputs.flowText(body) + '}'
      });
      var result = await readMutationResult(response, 'Save');
      if (result.id !== body.id || !Number.isInteger(result.version) || result.version < 1 ||
          typeof result.revision !== 'string' || !result.revision.trim() || !validPublication(result)) {
        throw new Error(unconfirmedMutation('Save'));
      }
      rootFlow.version = result.version;
      rootFlow.revision = result.revision;
      rootFlow.published = result.published;
      rootFlow.published_version = result.published_version || 0;
      rootFlow.published_revision = result.published_revision;
      if (creationHistory) {
        creationHistory.receipt = { id: result.id, version: result.version, revision: result.revision,
          published: result.published, published_version: result.published_version || 0,
          published_revision: result.published_revision };
        firstSaveHistory = creationHistory;
      }
      markClean(savedDraftSnapshot);
      canonicalizeSavedFlow(rootFlow.id);
      var disconnected = FDCore.unreachableNodeIds ? FDCore.unreachableNodeIds(body) : [];
      say(disconnected.length ? 'Saved draft. ' + disconnected.length +
        ' step' + (disconnected.length === 1 ? ' is' : 's are') +
        ' not connected and will not run until connected.' : 'Saved ✓', !!disconnected.length);
      if (window.__fdStepsRefresh) window.__fdStepsRefresh();
      return true;
    } catch (e) {
      say(e.message || unconfirmedMutation('Save'), true); return false;
    } finally {
      saveInFlight = false; syncSaveButtons();
    }
  }
  async function publishFlow() {
    if (publishInFlight || saveInFlight || applyInFlight || retireInFlight) return;
    publishInFlight = true; syncSaveButtons();
    // Publish is the explicit activation authority. Save the reviewed canvas as
    // a draft, then bind activation to the exact CAS tokens the save returned.
    try {
      if (!(await save())) return;
      if (FDCore.unreachableNodeIds && FDCore.unreachableNodeIds(rootFlow).length) {
        say('Before publishing: ' + problemText(rootFlow), true);
        return;
      }
      var response = await apiFetch('/api/v1/flows/' + encodeURIComponent(rootFlow.id) + '/publish', {
        method: 'POST', body: JSON.stringify({
          version: rootFlow.version, revision: rootFlow.revision
        })
      });
      var result = await readMutationResult(response, 'Publish');
      if (result.id !== rootFlow.id || !validPublication(result) || !result.published ||
          result.published_version !== rootFlow.version) {
        throw new Error(unconfirmedMutation('Publish'));
      }
      rootFlow.published = true;
      rootFlow.published_version = result.published_version;
      rootFlow.published_revision = result.published_revision;
      say('Published — version ' + rootFlow.published_version + ' is now the one that runs.');
    } catch (e) {
      say(e.message || unconfirmedMutation('Publish'), true);
    } finally {
      publishInFlight = false; syncSaveButtons();
    }
  }
  async function retireFlow(action, button) {
    if (retireInFlight || saveInFlight || publishInFlight || applyInFlight ||
        !rootFlow.id || (!rootFlow.version && !canvas.getAttribute('data-flow-id'))) return;
    retireInFlight = true; syncSaveButtons();
    try {
      await window.LightworkFlowRetirement.change(rootFlow.id, action, {
        button: button, dirty: draftIsDirty(), name: rootFlow.name,
        onDone: function () {
          if (action === 'delete') {
            markClean();
            window.location.assign('/workflows');
          } else {
            rootFlow.published = false;
            rootFlow.published_version = 0;
            rootFlow.published_revision = '';
            say('Turned off. New automatic starts have stopped; existing runs may continue.');
          }
        }
      });
    } finally {
      retireInFlight = false; syncSaveButtons();
      var more = document.getElementById('fd-more');
      if (more) more.open = false;
    }
  }
  function inputFields(definitions) {
    // The declared manual-run inputs as an mvForm field spec.
    return (definitions || flowInputs).filter(function (s) { return (s.key || '').trim(); }).map(function (s) {
      return { key: s.key, label: s.label || s.key, type: (s.type || 'text'),
               required: !!s.required, default: (s.default != null ? s.default : undefined) };
    });
  }
  var learnedInputPending = false;
  function run(dryRun, expected) {
    if (runInFlight || learnedInputPending) return Promise.resolve({status: 'busy'});
    if (expected && rootFlow.id !== expected.flowId) return Promise.resolve({status: 'stale'});
    var data = {};
    var learnedPlan = null;
    var pinnedDraft = JSON.stringify(rootFlow), pinnedSnapshot = draftSnapshot(), selectedFlow = rootFlow, releaseId = '';
    function unchanged() { return JSON.stringify(rootFlow) === pinnedDraft && draftSnapshot() === pinnedSnapshot; }
    async function proceed() {
      if (runInFlight) return;
      var url, payload;
      if (dryRun) {
        try { await FDActionFields.ready(rootFlow, true); }
        catch (error) { say(error.message, true); return; }
        if (runInFlight) return;
        var bad = commitRawFields();
        if (bad.length) { say(FDActionFields.check(rootFlow)[0] || 'Some action settings aren’t filled in correctly. Check the steps and try again.', true); renderProps(); return; }
        var draftBody = toApiFlow();
        if (!draftBody.id) draftBody.id = slugify(draftBody.name);
        if (!draftBody.id) { say('Give the flow a name (top-left).', true); return; }
        if (!draftBody.nodes.length) { say('Add at least one step.', true); return; }
        var errors = FDCore.validateFlow(draftBody);
        if (errors.length) { say('Before testing: ' + problemText(draftBody), true); return; }
        // The unsaved graph is the execution input. This endpoint does not save,
        // publish, or let a draft schedule enter the scheduler inventory.
        url = '/api/v1/flows/dry-run'; payload = { flow: draftBody, data: data };
      } else {
        url = '/api/v1/flows/' + encodeURIComponent(selectedFlow.id) + '/run';
        payload = { data: data, dry_run: false, expected_release_id: releaseId };
      }
      var buttons = ['fd-run', 'fd-run-real'].map(function (id) { return document.getElementById(id); });
      runInFlight = true;
      buttons.forEach(function (button) { button.disabled = true; button.setAttribute('aria-busy', 'true'); });
      try {
        var response = await apiFetch(url, { method: 'POST',
          body: FDRecipeInputs.payloadText(learnedPlan, payload) });
        var result = await readMutationResult(response, 'Run');
        if (typeof result.run_id !== 'string' || !result.run_id.trim() ||
            typeof result.status !== 'string' || !result.status.trim() || result.dry_run !== dryRun) {
          throw new Error(unconfirmedMutation('Run'));
        }
        runState = {}; runCursor = null; lastRunId = result.run_id;
        say(dryRun ? 'Test started — nothing is sent to other apps.' : 'Run started.');
        document.getElementById('fd-legend').classList.add('on');
        watchRun(result.run_id);
        return {status: 'started', run_id: result.run_id};
      } catch (e) {
        say(e.message || unconfirmedMutation('Run'), true);
        return {status: 'unconfirmed'};
      } finally {
        runInFlight = false;
        buttons.forEach(function (button) { button.disabled = false; button.removeAttribute('aria-busy'); });
        var invoker = document.getElementById(dryRun ? 'fd-run' : 'fd-run-real');
        if (learnedPlan && invoker && typeof invoker.focus === 'function' &&
            (document.activeElement === document.body || document.activeElement === invoker)) invoker.focus();
      }
    }
    async function prepare() {
      if (!dryRun) {
        if (!rootFlow.id) { say('Publish the reviewed workflow before running it.', true); return {status: 'refused'}; }
        say('Loading the published workflow…');
        var previewResponse = await apiFetch('/api/v1/flows/' + encodeURIComponent(rootFlow.id) + '/published');
        var preview = await readMutationResult(previewResponse, 'Published workflow');
        if (!preview.flow || preview.flow.id !== rootFlow.id || !Array.isArray(preview.flow.nodes) ||
            typeof preview.release_id !== 'string' || !/^[0-9a-f]{64}$/.test(preview.release_id))
          throw new Error('The published workflow could not be confirmed. Reload it before trying again.');
        if (expected && preview.release_id !== expected.releaseId) {
          say('The published workflow changed. Refresh and review it again.', true);
          return {status: 'stale'};
        }
        selectedFlow = preview.flow; releaseId = preview.release_id;
      }
      if (!unchanged()) { say('The workflow changed. Open the input form again.', true); return {status: 'stale'}; }
      var title = (dryRun ? 'Test' : 'Run published') + ' “' + (selectedFlow.name || selectedFlow.id || 'workflow') + '”';
      if (expected && selectedFlow.learned_recipe == null) return {status: 'stale'};
      if (selectedFlow.learned_recipe != null) {
        learnedPlan = FDRecipeInputs.plan(selectedFlow.learned_recipe);
        data = await FDRecipeInputs.prompt(learnedPlan, {title: title, okText: dryRun ? 'Test workflow' : 'Run published',
          restoreFocus: document.getElementById(dryRun ? 'fd-run' : 'fd-run-real')});
        if (data === null) { say('Run cancelled.'); return {status: 'cancelled'}; }
      } else {
        data = typeof sampleData === 'function' ? sampleData().data : {};
        var fields = inputFields(dryRun ? flowInputs : (selectedFlow.inputs || []));
        if (fields.length) {
          var values = await window.mvForm(title, fields, {okText: dryRun ? 'Test workflow' : 'Run published'});
          if (values === null) { say('Run cancelled.'); return {status: 'cancelled'}; }
          Object.keys(values).forEach(function (key) { data[key] = values[key]; });
        } else if (!dryRun && !(await window.mvConfirm('Run the published version? This starts real work and uses connected services.', {okText: 'Run published'}))) {
          say('Run cancelled.'); return {status: 'cancelled'};
        }
      }
      if (!unchanged()) { say('The workflow changed while entering inputs. Open the form again.', true); return {status: 'stale'}; }
      return await proceed();
    }
    learnedInputPending = true;
    return prepare().catch(function (error) {
      say(error.message || 'Could not open workflow inputs. Refresh the page and try again.', true);
      return {status: 'unconfirmed'};
    }).finally(function () { learnedInputPending = false; });
  }
  window.LightworkFlowRun = Object.freeze({
    open: function (flowId, releaseId) {
      if (typeof flowId !== 'string' || !/^[0-9a-f]{64}$/.test(releaseId || ''))
        return Promise.resolve({status: 'refused'});
      return run(false, {flowId: flowId, releaseId: releaseId});
    }
  });
  function runUrl(runId) {
    return '/flows/' + encodeURIComponent(rootFlow.id) + '/runs/' + encodeURIComponent(runId);
  }
  function sayWithRunLink(text, runId) {
    say(text);
    var a = document.createElement('a'); a.href = runUrl(runId); a.textContent = 'Open the run →';
    a.style.marginLeft = '6px';
    msg.appendChild(a);
  }
  function handleRunUpdate(run, runId) {
    // Paint one run snapshot onto the canvas; returns true when the run has
    // reached a state that needs no further watching.
    runState = run.nodes || {};
    runCursor = (['paused_approval', 'paused_delay', 'paused_event'].indexOf(run.status) >= 0) ? run.cursor : null;
    render(); if (selected) renderProps();
    if (run.status === 'paused_approval') { sayWithRunLink('⏸ Waiting for someone to approve —', runId); return true; }
    if (run.status === 'paused_event') { sayWithRunLink('📥 Waiting for a signal from another app —', runId); return true; }
    if (run.status === 'budget_limited') {
      sayWithRunLink('Saved work is waiting for a larger spending allowance. Review and continue this run —', runId);
      return true;
    }
    if (run.status === 'indeterminate') {
      sayWithRunLink('⚠️ We couldn’t tell whether the last step finished in the other app. Check it there before running again —', runId);
      return true;
    }
    if (run.status === 'failed') {
      sayWithRunLink(runSummary(run) + ' ·', runId);
      offerFixIt(runId);
      return true;
    }
    if (['completed', 'rejected'].indexOf(run.status) >= 0) { sayWithRunLink(runSummary(run) + ' ·', runId); return true; }
    return false;
  }
  function watchRun(runId) {
    // Live status over SSE; falls back to polling where EventSource or the
    // stream isn't available (older proxies, stream-slot exhaustion).
    // Supersede any previous run's watch: close its stream and bump the
    // generation so a stale snapshot/poll can't repaint over the new run.
    if (activeES) { try { activeES.close(); } catch (e) {} activeES = null; }
    var gen = ++runGen;
    if (typeof EventSource === 'undefined') { pollRun(runId, 0, gen); return; }
    var es;
    try { es = new EventSource('/api/v1/flows/runs/' + encodeURIComponent(runId) + '/events'); }
    catch (e) { pollRun(runId, 0, gen); return; }
    activeES = es;
    var gotAny = false;
    function drop() { es.close(); if (activeES === es) activeES = null; }
    function onSnap(evt) {
      if (gen !== runGen) { drop(); return; }   // a newer run started; stop
      gotAny = true;
      try { if (handleRunUpdate(JSON.parse(evt.data), runId)) drop(); } catch (e) { /* keep streaming */ }
    }
    es.addEventListener('snapshot', onSnap);
    es.addEventListener('terminal', function (evt) { onSnap(evt); drop(); });
    es.addEventListener('timeout', function () { drop(); pollRun(runId, 0, gen); });
    es.onerror = function () {
      // never connected -> fall back to polling; a drop mid-stream lets
      // EventSource retry on its own
      if (!gotAny) { drop(); pollRun(runId, 0, gen); }
    };
  }
  function pollRun(runId, tick, gen) {
    // Poll until a terminal/paused state: fast at first, backing off to 3s so a
    // long run keeps updating the canvas instead of silently going dark.
    if (gen != null && gen !== runGen) return;   // superseded by a newer run
    apiFetch('/api/v1/flows/runs/' + encodeURIComponent(runId))
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (run) {
        if (gen != null && gen !== runGen) return;
        if (!run) return;
        if (handleRunUpdate(run, runId)) return;
        var wait = Math.min(3000, 900 + (tick || 0) * 150);
        setTimeout(function () { pollRun(runId, (tick || 0) + 1, gen); }, wait);
      }).catch(function () {});
  }
  function offerFixIt(runId) {
    // One-click repair: open the copilot pre-armed with a diagnose+fix turn
    // grounded in the failed run's trace.
    var a = document.createElement('button');
    a.className = 'btn btn--ghost'; a.type = 'button'; a.textContent = 'Ask the assistant to fix it';
    a.style.marginLeft = '6px';
    a.addEventListener('click', function () {
      lastRunId = runId;
      chatToggle(true);
      var inp = document.getElementById('fd-chat-input');
      inp.value = 'The last run failed. Diagnose why from the run trace and propose the smallest patch that fixes it.';
      chatSend();
    });
    msg.appendChild(a);
  }
  function runSummary(run) {
    var ok = 0, err = 0, ns = run.nodes || {};
    for (var k in ns) { if (ns[k].outcome === 1) ok++; else if (ns[k].outcome === 0) err++; }
    var head = run.status === 'completed' ? '✓ Finished' : (run.status === 'rejected' ? '✋ Rejected' : '⚠ The run stopped with a problem');
    var cost = run.cost_dollars ? ' · ' + (window.mvMoney ? window.mvMoney(run.cost_dollars) : '$' + Number(run.cost_dollars).toFixed(2)) : '';
    var ORIGINS = { webhook: 'started by another app', schedule: 'started on schedule', event_trigger: 'started by a new item' };
    var origin = (run.origin && run.origin !== 'manual')
      ? ' · ' + (run.origin.indexOf('event:v2:') === 0
        ? 'Started by ' + human(run.origin.split(':').slice(4).join(':'))
        : (ORIGINS[run.origin] || human(run.origin))) : '';
    return head + ' · ' + ok + ' step' + (ok === 1 ? '' : 's') + ' worked' + (err ? ', ' + err + ' failed' : '') + cost + origin;
  }
  async function draft() {
    var desc = document.getElementById('fd-nl').value.trim();
    if (!desc) { say('Describe your workflow first.', true); return; }
    if (saveInFlight || publishInFlight || applyInFlight) {
      say('Wait for the current save or apply to finish before drafting.', true); return;
    }
    var snapshot = draftSnapshot(), flowId = idInput.value || '';
    if (pendingDraft && pendingDraft.description === desc && pendingDraft.flowId === flowId &&
        pendingDraft.snapshot === snapshot) return;
    var generation = ++draftGeneration;
    pendingDraft = { description: desc, flowId: flowId, snapshot: snapshot };
    var button = document.getElementById('fd-draft');
    var retry = document.getElementById('fd-draft-retry');
    if (retry) retry.hidden = true;
    if (button) button.setAttribute('aria-busy', 'true');
    say('Drafting… (a few seconds)');
    try {
      var response = await apiFetch('/api/v1/flows/draft', {
        method: 'POST', body: JSON.stringify({ description: desc, flow_id: flowId })
      });
      var result = await readMutationResult(response, 'Draft');
      if (generation !== draftGeneration) return;
      // A newer request owns the result; edits made while the model was working
      // also remain authoritative, including buffered invalid JSON fields.
      if (draftSnapshot() !== snapshot || document.getElementById('fd-nl').value.trim() !== desc ||
          saveInFlight || publishInFlight || applyInFlight) {
        say('The draft was not loaded because the workflow or description changed. Your edits were kept; draft again when ready.', true);
        if (retry) retry.hidden = false;
        return;
      }
      var draftedFlow = result.flow;
      if (!draftedFlow || typeof draftedFlow !== 'object' || Array.isArray(draftedFlow) ||
          !Array.isArray(draftedFlow.nodes) || !draftedFlow.nodes.length ||
          draftedFlow.nodes.some(function (node) { return !node || typeof node !== 'object' || Array.isArray(node); }) ||
          FDCore.validateFlow(draftedFlow).length) {
        throw new Error('Draft could not be loaded. Your current workflow was kept; try drafting again.');
      }
      pushHistory();                    // the pre-draft canvas is one Ctrl+Z away
      fromApiFlow(draftedFlow);
      var draftNotes = Array.isArray(result.notes) ? result.notes : [];
      say(typeof draftNotes[0] === 'string'
        ? draftNotes[0] : 'Drafted ✓ — review the steps, then save.', !!draftNotes.length);
      if (retry) retry.hidden = !draftNotes.length;
    } catch (e) {
      if (generation === draftGeneration) {
        say(e.message || 'Could not draft the flow. Try again.', true);
        if (retry) retry.hidden = false;
      }
    } finally {
      if (generation === draftGeneration) {
        pendingDraft = null;
        if (button) button.removeAttribute('aria-busy');
      }
    }
  }
  function load(id, expectedDraftSnapshot) {
    var loadingFlow = rootFlow;
    return apiFetch('/api/v1/flows/' + encodeURIComponent(id)).then(function (r) {
      if (!r.ok) { say('Could not load flow', true); return; }
      return (typeof FDRecipeInputs !== 'undefined' && typeof r.text === 'function'
        ? FDRecipeInputs.responseJson(r) : r.json()).then(function (saved) {
        if (expectedDraftSnapshot !== undefined &&
            (rootFlow !== loadingFlow || draftSnapshot() !== expectedDraftSnapshot)) {
          say('Applied on the server. Your newer canvas edits were kept; reload when ready to inspect the applied version.');
          return;
        }
        fromApiFlow(saved, true);
        loadSuggestions(id);
        loadSchema(id);
      });
    }).catch(function (e) { say(failText(e, 'open this flow'), true); });
  }
  function loadSchema(id) {
    // learned output shapes -> nested data pills (order.total, etc.)
    apiFetch('/api/v1/flows/' + encodeURIComponent(id) + '/schema')
      .then(function (r) { return r.ok ? r.json() : { schema: {} }; })
      .then(function (j) { flowSchema = j.schema || {}; if (selected) renderProps(); })
      .catch(function () {});
  }
  function loadSuggestions(id) {
    // self-rewrite suggestions (harden a reliable agent / soften a flaky action)
    apiFetch('/api/v1/flows/' + encodeURIComponent(id) + '/proposals').then(function (r) {
      return r.ok ? r.json() : { proposals: [] };
    }).then(function (j) {
      proposals = {};
      (j.proposals || []).forEach(function (p) { proposals[p.node_id] = p; });
      if (j.proposals && j.proposals.length) say('💡 ' + j.proposals.length + (j.proposals.length === 1 ? ' suggestion' : ' suggestions') + ' — select a step marked 💡 to see it.');
      if (selected) renderProps();
    }).catch(function () {});
    // measured impact of changes already applied (before/after), via the aggregate
    apiFetch('/api/v1/flows/insights').then(function (r) { return r.ok ? r.json() : { flows: [] }; })
      .then(function (j) {
        impacts = {};
        (j.flows || []).forEach(function (f) {
          if (f.flow_id !== id) return;
          (f.changes || []).forEach(function (ch) { impacts[ch.node_id] = { changed: true, applied: ch, impact: ch.impact }; });
        });
        if (selected) renderProps();
      }).catch(function () {});
    // grounded learning signals: per-node success, approval accept-rate, trigger reliability
    apiFetch('/api/v1/flows/' + encodeURIComponent(id) + '/signals').then(function (r) {
      return r.ok ? r.json() : { nodes: {}, trigger: null };
    }).then(function (j) {
      signals = { nodes: j.nodes || {}, trigger: j.trigger || null };
      var lg = document.getElementById('fd-signal');
      if (lg) {
        if (signals.trigger && signals.trigger.n) {
          lg.textContent = '📊 Automatic runs worked ' + Math.round(signals.trigger.mean * 100) +
            '% of the time (' + signals.trigger.n + ' runs)';
          lg.hidden = false;
        } else { lg.hidden = true; }
      }
      if (selected) renderProps();
    }).catch(function () {});
  }
  async function applyProposal(n, prop, button, expectedReview) {
    // Persisted apply: save the current graph, review the current action and
    // inputs, then enact the swap as a new measured draft version.
    if (applyInFlight || saveInFlight || publishInFlight || retireInFlight) return;
    // Proposal IDs address root nodes only; nested bodies may reuse those IDs.
    if (flow !== rootFlow || rootFlow.nodes.indexOf(n) < 0) {
      say('Select the current step in the main flow before applying its suggestion.', true); return;
    }
    if (unresolvedApply(n)) {
      say('Read Earlier versions and reload the saved flow before trying another change. The earlier save is not confirmed here.', true); return;
    }
    if (prop.to_kind === 'agent' && draftIsDirty()) {
      say('Your entered workflow was kept. Save its current draft before reviewing replacement instructions.', true); return;
    }
    var applyingFlow = rootFlow, fromKind = n.kind, confirmed = false, applySent = false, uncertain = false;
    var body = { node_id: n.id, to_kind: prop.to_kind, tool: n.tool || prop.inferred_tool || '', brief: n.brief || n.label || '' };
    applyInFlight = true;
    if (button) button.disabled = true;
    syncSaveButtons();
    try {
      if (prop.to_kind !== 'agent' && !(await save(true))) return;
      if (rootFlow !== applyingFlow || draftIsDirty()) {
        say('The workflow changed while saving. Your edits were kept; review the suggestion and apply again.', true);
        return;
      }
      var flowId = rootFlow.id, snapshot = draftSnapshot();
      body.version = rootFlow.version;
      body.revision = rootFlow.revision;
      if (prop.to_kind === 'action' || prop.to_kind === 'agent') {
        if (!window.LightworkFlowRewrite) {
          say('The action review is unavailable. Refresh the designer and try again.', true); return;
        }
        var reviewed = await window.LightworkFlowRewrite.prepare(flowId, prop, body.tool, expectedReview);
        if (!reviewed) { say('Review cancelled. The flow was not changed.'); return; }
        if (rootFlow !== applyingFlow || draftSnapshot() !== snapshot ||
            reviewed.version !== body.version || reviewed.revision !== body.revision) {
          say('The flow changed during review. Your edits were kept; review the suggestion again.', true); return;
        }
        body = reviewed;
      }
      say('Applying suggestion…');
      applySent = true;
      var response = await apiFetch('/api/v1/flows/' + encodeURIComponent(flowId) + '/apply', {
        method: 'POST', body: JSON.stringify(body)
      });
      var result = await readMutationResult(response, 'Apply');
      if (result.id !== flowId || result.node_id !== body.node_id || result.from_kind !== fromKind ||
          result.to_kind !== body.to_kind || !Number.isInteger(result.version) || result.version <= body.version) {
        throw new Error(unconfirmedMutation('Apply'));
      }
      confirmed = true;
      if (rootFlow === applyingFlow) delete proposals[body.node_id];
      if (rootFlow !== applyingFlow || draftSnapshot() !== snapshot) {
        say('Applied on the server. Your newer canvas edits were kept; reload when ready to inspect the applied version.');
        return;
      }
      say('Applied ✓ — now version ' + result.version + '. Results appear as new runs finish.');
      await load(flowId, snapshot);                  // retain edits made during the refresh too
    } catch (e) {
      uncertain = applySent && (!response || response.status >= 500 || response.ok);
      if (uncertain) unconfirmedApply = {flow: flowId, node: body.node_id, version: body.version};
      say(uncertain ? 'The replacement save result could not be confirmed. Read Earlier versions and reload the saved flow before trying another change. Your entered instructions were kept; do not apply this request again.' : (e.message || unconfirmedMutation('Apply')), true);
    } finally {
      applyInFlight = false;
      if (button) button.disabled = confirmed || uncertain;
      if (uncertain && selected) renderProps();
      syncSaveButtons();
    }
  }
  async function receiveSofteningHandoff(query) {
    query = query || new URLSearchParams(location.search);
    var step = query.get('review_softening');
    if (!step) return;
    var binding = query.get('review_binding'), context = query.get('review_context');
    if (!/^[a-f0-9]{64}$/.test(binding || '') || !/^[a-f0-9]{64}$/.test(context || '') || draftIsDirty()) {
      say('Your current work was kept. Reopen the current suggestion before reviewing replacement instructions.', true); return;
    }
    var node = rootFlow.nodes.find(function (item) { return item.id === step; });
    if (!node || node.kind !== 'action') {
      say('The selected action changed. Open its current suggestions.', true); return;
    }
    selectNode(step);
    await applyProposal(node, {node_id: step, to_kind: 'agent'}, null, {binding: binding, context: context});
  }
  document.addEventListener('click', function (event) {
    var anchor = event.target.closest && event.target.closest('a[href]');
    if (!anchor) return;
    var target;
    try { target = new URL(anchor.href, location.href); } catch (_) { return; }
    if (target.origin !== location.origin || target.pathname !== location.pathname ||
        !target.searchParams.has('review_softening')) return;
    event.preventDefault();
    receiveSofteningHandoff(target.searchParams);
  });
  function showHistory() {
    if (!rootFlow.id) { say('Save the flow first.', true); return; }
    if (window.__fdShowProps) window.__fdShowProps();
    apiFetch('/api/v1/flows/' + encodeURIComponent(rootFlow.id) + '/versions')
      .then(function (r) { if (!r.ok) throw r; return r.json(); })
      .then(function (j) {
        selected = null; render();
        props.textContent = '';
        var h = document.createElement('div'); h.style.fontWeight = '600'; h.style.marginBottom = 'var(--space-3)';
        h.textContent = 'Earlier versions';
        props.appendChild(h);
        var versions = j.versions || [];
        if (!versions.length) props.appendChild(hint('No earlier versions yet. Each save keeps a version you can go back to.'));
        versions.forEach(function (v) {
          var row = document.createElement('div'); row.className = 'field';
          var when = v.saved_at || v.created_at || v.updated;
          var who = v.saved_by || v.author || '';
          var lbl = document.createElement('div');
          lbl.textContent = 'Version ' + v.version + ' — ' + v.nodes + (v.nodes === 1 ? ' step' : ' steps')
            + (when && window.mvWhen ? ' · saved ' + window.mvWhen(when) : '') + (who ? ' by ' + who : '')
            + (v.version === rootFlow.version ? ' (current)' : '');
          row.appendChild(lbl);
          if (v.version !== rootFlow.version) {
            var rb = document.createElement('button'); rb.className = 'btn btn--ghost'; rb.type = 'button'; rb.textContent = 'Restore this version';
            rb.addEventListener('click', function () { rollback(v.version); });
            row.appendChild(rb);
          }
          props.appendChild(row);
        });
      }).catch(function (e) { say(failText(e, 'load earlier versions'), true); });
  }
  async function rollback(version) {
    var ok = await (window.mvConfirm ? window.mvConfirm('Restore version ' + version + '? It becomes the current draft; your current version stays in the list.', { okText: 'Restore' }) : Promise.resolve(false));
    if (!ok) return;
    apiFetch('/api/v1/flows/' + encodeURIComponent(rootFlow.id) + '/rollback', {
      method: 'POST',
      body: JSON.stringify({
        version: version,
        current_version: rootFlow.version,
        revision: rootFlow.revision
      })
    })
      .then(function (r) { return r.json().catch(function () { return {}; }).then(function (j) { return { ok: r.ok, r: r, j: j }; }); })
      .then(function (res) {
        if (!res.ok) { say(failText(res.r, 'restore that version'), true); return; }
        say('Restored — now version ' + res.j.version + '.'); load(rootFlow.id);
      }).catch(function (e) { say(failText(e, 'restore that version'), true); });
  }

  var EXAMPLES = [
    'When a new GitHub issue is opened, summarize it and post to Slack, but ask me before posting',
    'Every morning, pull yesterday’s Stripe charges and email me a one-paragraph summary',
    'When a HubSpot deal is marked won, create an onboarding task in Asana and notify the team',
  ];
  function buildExamples() {
    var box = document.getElementById('fd-examples'); if (!box) return;
    EXAMPLES.forEach(function (ex) {
      var c = document.createElement('button'); c.type = 'button'; c.className = 'fd__chip';
      c.textContent = '✨ ' + trunc(ex, 40); c.title = ex;
      c.addEventListener('click', function () { var nl = document.getElementById('fd-nl'); nl.value = ex; nl.focus(); });
      box.appendChild(c);
    });
  }
  // ---- export / import (flow JSON as a file) ----
  function exportJson() {
    var bad = commitRawFields();
    if (bad.length) { say('Some action settings aren’t filled in correctly. Check the steps and try again.', true); return; }
    var body = toApiFlow();
    var wire;
    try { wire = FDRecipeInputs.flowText(body); }
    catch (error) { say(error.message, true); return; }
    var blob = new Blob([wire], { type: 'application/json' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = (body.id || slugify(body.name) || 'flow') + '.json';
    a.click();
    URL.revokeObjectURL(a.href);
    say('A copy was downloaded.');
  }
  function importJsonFile(file) {
    var reader = new FileReader();
    reader.onload = function () {
      try {
        var f = FDRecipeInputs.parseText(String(reader.result || ''));
        if (!f || !Array.isArray(f.nodes)) throw new Error('not a flow');
        pushHistory();
        fromApiFlow(f);
        say('Opened the saved copy — review it, then save.');
      } catch (e) { say('That file isn’t a Lightwork flow.', true); }
    };
    reader.readAsText(file);
  }

  // ---- triggers panel: everything that starts THIS flow, in one place ----
  function showTriggers() {
    if (!rootFlow.id) { say('Save the flow first.', true); return; }
    if (window.__fdShowProps) window.__fdShowProps();
    selected = null; render();
    props.textContent = '';
    var h = document.createElement('div'); h.style.fontWeight = '600'; h.style.marginBottom = 'var(--space-3)';
    h.textContent = 'What starts this flow';
    props.appendChild(h);
    var sch = ((document.getElementById('fd-schedule') || {}).value || '').trim();
    props.appendChild(hint(sch ? ('⏰ On a schedule: ' + scheduleWords(sch) + '. Change it under Schedule, then publish.')
                               : '⏰ No schedule. Choose one under Schedule.'));
    apiFetch('/api/v1/triggers').then(function (r) { return r.ok ? r.json() : { triggers: [] }; })
      .then(function (j) {
        var mine = (j.triggers || []).filter(function (t) { return t.flow === rootFlow.id; });
        var address = window.location.origin + (j.webhook_url || '/webhook/run');
        var wl = document.createElement('div'); wl.className = 'field';
        var lab = document.createElement('div'); lab.className = 'fd__label'; lab.textContent = '📡 Started by another app';
        wl.appendChild(lab);
        mine.forEach(function (t) {
          var row = document.createElement('div'); row.className = 'fd__pair';
          var nm = document.createElement('span'); nm.textContent = '“' + t.name + '”';
          var copy = document.createElement('button'); copy.className = 'btn btn--ghost'; copy.type = 'button'; copy.textContent = 'Copy address';
          copy.addEventListener('click', function () { if (window.mvCopy) window.mvCopy(address); });
          var rm = document.createElement('button'); rm.className = 'btn btn--ghost btn--danger'; rm.type = 'button'; rm.textContent = 'Remove';
          rm.setAttribute('aria-label', 'Remove the start “' + t.name + '”');
          rm.addEventListener('click', function () {
            // One action with a way back: removed when Undo ends.
            row.hidden = true;
            window.mvUndo('“{name}” removed. The other app can no longer start this flow.', { values: {name: t.name},
              action: 'remove it',
              run: function (keepalive) { return apiFetch('/api/v1/triggers/' + encodeURIComponent(t.name), { method: 'DELETE', keepalive: keepalive }); },
              undo: function () { row.hidden = false; rm.focus(); },
              done: function () { showTriggers(); }
            });
          });
          row.appendChild(nm); row.appendChild(copy); row.appendChild(rm); wl.appendChild(row);
        });
        if (mine.length) wl.appendChild(hint('In the other app, send a web request to the copied address and include the start’s name.'));
        else wl.appendChild(hint('None yet. Use “Let another app start this flow” below.'));
        wl.appendChild(addButton('Let another app start this flow', function () {
          apiFetch('/api/v1/triggers', { method: 'POST', body: JSON.stringify({ flow: rootFlow.id }) })
            .then(function (r) { return r.json().catch(function () { return {}; }).then(function (jj) { return { ok: r.ok, r: r, j: jj }; }); })
            .then(function (res) {
              if (!res.ok) { say(failText(res.r, 'set that up'), true); return; }
              if (!res.j.secret_configured) {
                say('Almost ready — an administrator must create the security key in Settings before other apps can start flows.', true);
                var link = document.createElement('a'); link.href = '/settings#webhook-secret'; link.textContent = ' Open Settings';
                msg.appendChild(link);
              }
              showTriggers();
            }).catch(function (e) { say(failText(e, 'set that up'), true); });
        }));
        props.appendChild(wl);
      }).catch(function () {});
    apiFetch('/api/v1/event-triggers').then(function (r) { return r.ok ? r.json() : { triggers: [] }; })
      .then(function (j) {
        var mine = (j.triggers || []).filter(function (t) { return t.flow === rootFlow.id; });
        var el2 = document.createElement('div'); el2.className = 'field';
        var lab2 = document.createElement('div'); lab2.className = 'fd__label'; lab2.textContent = '🛰 Started when new items arrive';
        el2.appendChild(lab2);
        mine.forEach(function (t) {
          var d = document.createElement('div'); d.className = 'fd__empty';
          d.textContent = '“' + t.name + '” — ' + human(t.source); el2.appendChild(d);
        });
        var link = document.createElement('a'); link.href = '/automations#auto-event-section';
        link.textContent = (mine.length ? 'Manage' : 'Set one up') + ' on the Automations page →';
        el2.appendChild(link); props.appendChild(el2);
      }).catch(function () {});
  }

  // ---- gallery: curated starter graphs (one click -> editable canvas) ----
  function loadGallery() {
    apiFetch('/api/v1/flows/gallery').then(function (r) {
        // Flow engine off (the default install): say so up front instead of
        // letting the user build a whole flow and only learn it on Save.
        if (r.status === 403) {
          var msg = document.getElementById('fd-msg');
          if (msg && !msg.textContent) {
            if (!workflowsOff(r)) {
              msg.textContent = 'You do not have access to workflows. Ask an administrator.';
            } else {
              msg.textContent = 'Workflows are turned off. You can design a flow and download a copy, '
                + 'but saving and running need the person who manages this installation to turn workflows on.';
              if (fd.dataset.canManageFlows === 'true') {
                var on = document.createElement('a'); on.href = '/learning#lrn-flows-on'; on.textContent = ' Turn on workflows';
                msg.appendChild(on);
              }
            }
          }
        }
        return r.ok ? r.json() : { flows: [] };
      })
      .then(function (j) {
        var box = document.getElementById('fd-examples'); if (!box) return;
        (j.flows || []).forEach(function (g) {
          var c = document.createElement('button'); c.type = 'button'; c.className = 'fd__chip';
          c.textContent = '📋 ' + g.name; c.title = (g.description || '') + ' (loads onto the canvas)';
          c.addEventListener('click', function () {
            pushHistory();
            fromApiFlow(g);
            var schEl = document.getElementById('fd-schedule');
            if (schEl && g.schedule) schEl.value = g.schedule;
            if (typeof syncScheduleControls === 'function') syncScheduleControls();
            say('Loaded “' + g.name + '” — edit it, or tell the assistant what to change.');
          });
          box.appendChild(c);
        });
      }).catch(function () {});
  }

  // ---- copilot chat: converse to build, edit, explain, and repair the flow ----
  var chatGeneration = 0;
  var chatPending = [];
  var chatSavedKeys = ['version', 'revision', 'published', 'published_version', 'published_revision'];
  function chatSavedState() {
    return JSON.stringify(chatSavedKeys.map(function (key) { return rootFlow[key]; }));
  }
  function chatBusy() { return saveInFlight || publishInFlight || applyInFlight || !!pendingDraft; }
  function chatMsgEl(role, text) {
    var d = document.createElement('div'); d.className = 'fd__chat-msg ' + role; d.textContent = text; return d;
  }
  function chatAppend(role, text) {
    var log = document.getElementById('fd-chat-log');
    var el = chatMsgEl(role, text);
    log.appendChild(el);
    log.scrollTop = log.scrollHeight;
    return el;
  }
  function placeNewNodes(f) {
    // Give canvas positions to nodes the copilot just added (patched nodes keep
    // theirs), so an AI edit lands NEXT TO its neighbors instead of re-laying
    // out the user's whole arrangement.
    var byId = {};
    (f.nodes || []).forEach(function (n) { byId[n.id] = n; });
    var maxY = 40;
    (f.nodes || []).forEach(function (n) { if (n.y) maxY = Math.max(maxY, n.y); });
    (f.nodes || []).forEach(function (n) {
      if (n.x || n.y) return;
      var pred = (f.nodes || []).filter(function (m) {
        return m !== n && (m.next === n.id || m.if_true === n.id || m.if_false === n.id || m.on_error === n.id);
      })[0];
      if (pred && (pred.x || pred.y)) { n.x = (pred.x || 0) + 24; n.y = (pred.y || 0) + 110; }
      else { n.x = 60; n.y = maxY + 110; }
      maxY = Math.max(maxY, n.y);
    });
  }
  function chatRequest(text) {
    if (chatBusy()) {
      say('Wait for the current workflow update to finish, then ask Copilot again.', true);
      return null;
    }
    var bad = commitRawFields();
    if (bad.length) { say('Finish correcting the highlighted step settings before asking Copilot.', true); return null; }
    var snapshot = draftSnapshot(), savedState = chatSavedState();
    if (chatPending.some(function (request) {
      return request.text === text && request.base === rootFlow && request.snapshot === snapshot &&
        request.savedState === savedState && request.draftGeneration === draftGeneration;
    })) {
      say('Copilot is already working on that request. Your message has been kept.');
      return null;
    }
    var body, wire;
    try {
      body = { message: text, flow: toApiFlow(), history: chatHistory.concat([{ role: 'user', content: text }]).slice(-12), run_id: lastRunId || '' };
      // Preserve retained evidence's exact numbers in both directions, just as
      // Save/Test do. JSON.stringify alone changes integral floats into ints.
      wire = FDRecipeInputs.payloadText(null, body);
    } catch (e) {
      say('This workflow could not be prepared for Copilot. Save your changes, reopen it, and try again.', true);
      return null;
    }
    var request = { text: text, base: rootFlow, snapshot: snapshot, savedState: savedState,
      draftGeneration: draftGeneration, generation: ++chatGeneration,
      historyEntry: { role: 'user', content: text } };
    chatPending.push(request);
    chatAppend('user', text);
    chatHistory.push(request.historyEntry);
    // Keep each reply beside its own instruction even when requests finish
    // out of order. An older reply is never described as a later instruction.
    var replyBox = document.createElement('div');
    document.getElementById('fd-chat-log').appendChild(replyBox);
    function reply(role, value) {
      var log = document.getElementById('fd-chat-log');
      var follow = log.scrollTop + log.clientHeight >= log.scrollHeight - 40;
      var element = replyBox.appendChild(chatMsgEl(role, value));
      if (follow) log.scrollTop = log.scrollHeight;
      return element;
    }
    var thinking = reply('note', 'Working on your request…');
    function clearThinking() { if (thinking && thinking.parentNode) thinking.parentNode.removeChild(thinking); }
    function recover(message) {
      var note = reply('note', message);
      var button = document.createElement('button');
      button.type = 'button'; button.className = 'btn btn--ghost';
      button.textContent = 'Update for current workflow';
      button.addEventListener('click', function () {
        if (button.disabled) return;
        var next = chatRequest(text);
        if (!next) return;
        button.disabled = true;
        button.setAttribute('aria-busy', 'true');
        next.finished.finally(function () {
          button.disabled = false; button.removeAttribute('aria-busy');
        });
      });
      note.appendChild(document.createElement('br')); note.appendChild(button);
    }
    request.finished = apiFetch('/api/v1/flows/chat', { method: 'POST', body: wire })
      .then(async function (response) {
        if (!response.ok) throw new Error('Copilot request failed');
        return typeof FDRecipeInputs !== 'undefined' && typeof response.text === 'function'
          ? FDRecipeInputs.responseJson(response) : response.json();
      })
      .then(function (j) {
        clearThinking();
        if (!j || typeof j !== 'object' || Array.isArray(j) || typeof j.reply !== 'string') throw new Error('Invalid Copilot reply');
        reply('assistant', j.reply);
        var current = request.generation === chatGeneration && request.base === rootFlow &&
          request.snapshot === draftSnapshot() && request.savedState === chatSavedState() &&
          request.draftGeneration === draftGeneration && !chatBusy();
        var entry = { role: 'assistant', content: j.reply };
        // Preserve request order in the next conversation, with an explicit
        // distinction between suggested and applied edits.
        chatHistory.splice(chatHistory.indexOf(request.historyEntry) + 1, 0, entry);
        (Array.isArray(j.notes) ? j.notes : []).forEach(function (nt) { if (typeof nt === 'string') reply('note', nt); });
        if (j.flow) {
          entry.content = 'Suggestion only; not applied to the workflow. ' + j.reply;
          if (!current) {
            recover('Your newer work was kept. This suggestion was not applied. Ask Copilot to update it for your current workflow.');
            return;
          }
          if (typeof j.flow !== 'object' || Array.isArray(j.flow) || !Array.isArray(j.flow.nodes) ||
              FDCore.validateFlow(j.flow).length) throw new Error('Invalid Copilot flow');
          // Copilot edits do not save or publish. Never let its response replace
          // the current server-issued compare-and-set/publication metadata.
          chatSavedKeys.forEach(function (key) { j.flow[key] = rootFlow[key]; });
          FDRecipeInputs.flowText(j.flow);
          pushHistory();                                      // "undo what the AI did" is one Ctrl+Z
          placeNewNodes(j.flow);
          var keep = { x: view.x, y: view.y, k: view.k };
          fromApiFlow(j.flow);
          view = keep; render();
          entry.content = 'Applied to the editable draft; not saved or published. ' + j.reply;
          reply('note', 'Suggestion applied to your draft. Review the steps before saving. You can undo this change.');
          say('Copilot updated your draft. Review the steps before saving.');
        }
      }).catch(function () {
        clearThinking();
        recover('Copilot could not complete this update. Your workflow was kept. You can try again with your current workflow.');
      }).finally(function () {
        chatPending = chatPending.filter(function (pending) { return pending !== request; });
      });
    return request;
  }
  function chatSend() {
    var inp = document.getElementById('fd-chat-input');
    var text = (inp.value || '').trim();
    if (text && chatRequest(text)) inp.value = '';
  }
  function chatToggle(showOnly) {
    var box = document.getElementById('fd-chat');
    var open = showOnly === true || (showOnly !== false && !box.classList.contains('on'));
    box.hidden = !open; box.classList.toggle('on', open);
    var toggle = document.getElementById('fd-chat-toggle');
    toggle.setAttribute('aria-expanded', String(open));
    if (open) document.getElementById('fd-chat-input').focus();
    else toggle.focus();
  }
  function chatKeydown(event) {
    if (event.key === 'Escape') {
      event.preventDefault(); event.stopPropagation(); chatToggle(false);
    }
  }

  function loadTools(q, category, offset) {
    q = q || ''; category = category || ''; offset = offset || 0;
    var request = ++toolRequest;
    toolLoading = true; toolError = '';
    if (!offset) { toolResults = []; toolTotal = 0; toolNext = null; }
    if (selected) renderProps();
    var params = [];
    if (q) params.push('q=' + encodeURIComponent(q));
    if (category) params.push('category=' + encodeURIComponent(category));
    if (offset) params.push('offset=' + offset);
    var url = '/api/v1/flows/tools' + (params.length ? ('?' + params.join('&')) : '');
    apiFetch(url).then(function (r) { if (!r.ok) throw r; return r.json(); })
      .then(function (j) {
        if (request !== toolRequest) return;
        if (j.categories && j.categories.length) toolCategories = j.categories;
        // A search replaces the choices (keeping the step's current action).
        var keep = {};
        if (!offset) {
          flow.nodes.forEach(function (n) { if (n.tool && toolCatalog[n.tool]) keep[n.tool] = toolCatalog[n.tool]; });
          toolCatalog = keep;
        }
        (j.tools || []).forEach(function (t) {
          toolCatalog[t.name] = { description: t.description || '', params: t.params || [], category: t.category || '' };
          if (toolResults.indexOf(t.name) < 0) toolResults.push(t.name);
        });
        toolTotal = Number.isInteger(j.total) ? j.total : toolResults.length;
        toolNext = Number.isInteger(j.next_offset) ? j.next_offset : null;
        toolLoading = false;
        FDActionFields.ready(rootFlow, false).catch(function () { /* The selected action shows its own recovery control. */ });
        if (selected) renderProps();
      }).catch(function () {
        if (request !== toolRequest) return;
        toolLoading = false; toolNext = offset || null;
        toolError = 'Could not load actions. Your current step is unchanged. Try again.';
        if (selected) renderProps();
      });
  }
  // Debounced registry search: typing in an action node's tool field searches
  // EVERY live connector (built-ins + enabled enterprise connectors), narrowed
  // to the chosen category when one is picked. An empty query with a category
  // browses that whole bucket; an empty query with no category = curated set.
  var toolSearchTimer = null;
  function scheduleToolSearch(q) {
    if (toolSearchTimer) clearTimeout(toolSearchTimer);
    // A prior response must not replace the results for text just entered.
    toolRequest++;
    toolNext = null; toolLoading = true;
    toolSearchTimer = setTimeout(function () {
      loadTools((q || '').trim().length >= 2 ? q.trim() : '', toolFilterCategory);
    }, 250);
  }

  // ---- wire ----
  document.querySelectorAll('[data-add]').forEach(function (b) {
    b.addEventListener('click', function () { addNode(b.getAttribute('data-add')); });
  });
  document.getElementById('fd-draft').addEventListener('click', draft);
  document.getElementById('fd-draft-retry').addEventListener('click', draft);
  document.getElementById('fd-nl').addEventListener('input', function () {
    document.getElementById('fd-draft-retry').hidden = true;
  });
  ['fd-sched-freq', 'fd-sched-time', 'fd-sched-dom', 'fd-sched-minute', 'fd-sched-every'].forEach(function (id) {
    var e = document.getElementById(id); if (e) e.addEventListener('change', chooseSchedule);
  });
  Array.prototype.forEach.call(document.querySelectorAll('#fd-sched-days input[type=checkbox]'), function (c) {
    c.addEventListener('change', chooseSchedule);
  });
  fillTimeZones();
  syncScheduleControls();
  var sampleAdd = document.getElementById('fd-sample-add');
  if (sampleAdd) sampleAdd.addEventListener('click', function () { addSampleRow('', ''); });
  renderSampleFields();
  // People who can be asked to approve, and other saved flows (for pickers).
  fetch('/api/v1/people/assignable').then(function (r) { return r.ok ? r.json() : { items: [] }; })
    .then(function (j) {
      // An approver is stored as something a notification can reach (an email
      // where there is one), never as a one-way fingerprint.
      people = (j.items || []).filter(function (x) { return x && x.ref; }).map(function (x) {
        return { ref: /^person:/.test(x.ref) ? String(x.label || '').replace(/\s*\(.*\)$/, '') : x.ref, label: x.label };
      }).filter(function (x) { return x.ref; });
      if (selected) renderProps();
    })
    .catch(function () {});
  fetch('/api/v1/flows').then(function (r) { return r.ok ? r.json() : { flows: [] }; })
    .then(function (j) {
      savedFlows = (j.flows || []).filter(function (f) { return f && f.id; });
      savedFlows.forEach(function (f) { flowNames[f.id] = f.name || human(f.id); });
      if (selected) renderProps(); render();
    }).catch(function () {});
  document.getElementById('fd-save').addEventListener('click', function () { save(); });
  document.getElementById('fd-publish').addEventListener('click', publishFlow);
  document.getElementById('fd-turn-off').addEventListener('click', function () { retireFlow('off', this); });
  document.getElementById('fd-delete-flow').addEventListener('click', function () { retireFlow('delete', this); });
  document.addEventListener('lightwork:product-operation-complete', function (event) {
    var outcome = event.detail || {};
    if (outcome.status !== 'confirmed') return;
    if (outcome.operation === 'learning.workflow_delete') {
      markClean(); window.location.assign('/workflows');
    } else if (outcome.operation === 'learning.workflow_harden') {
      say('New draft version saved. Review and publish it when ready.');
      if (!draftIsDirty()) load(rootFlow.id);
    } else if (outcome.operation === 'learning.workflow_turn_off') {
      rootFlow.published = false;
      rootFlow.published_version = 0;
      rootFlow.published_revision = '';
      syncSaveButtons();
      say('Turned off. New automatic starts have stopped; existing runs may continue.');
    }
  });
  document.getElementById('fd-run').addEventListener('click', function () { run(true); });
  document.getElementById('fd-run-real').addEventListener('click', function () { run(false); });
  document.getElementById('fd-history').addEventListener('click', showHistory);
  document.getElementById('fd-undo').addEventListener('click', undo);
  document.getElementById('fd-redo').addEventListener('click', redo);
  document.getElementById('fd-fit').addEventListener('click', zoomToFit);
  document.getElementById('fd-triggers').addEventListener('click', showTriggers);
  document.getElementById('fd-minimap').addEventListener('mousedown', function (evt) {
    // click the overview to center the canvas on that spot
    evt.preventDefault();
    var mm = document.getElementById('fd-minimap');
    var mr = mm.getBoundingClientRect();
    var s = miniScale();
    var wx = (evt.clientX - mr.left - MINI_PAD) / s.k + s.minX;
    var wy = (evt.clientY - mr.top - MINI_PAD) / s.k + s.minY;
    var r = canvas.getBoundingClientRect();
    view.x = r.width / 2 - wx * view.k;
    view.y = r.height / 2 - wy * view.k;
    render();
  });
  document.getElementById('fd-export').addEventListener('click', exportJson);
  document.getElementById('fd-import-json').addEventListener('click', function () {
    document.getElementById('fd-import-file').click();
  });
  document.getElementById('fd-import-file').addEventListener('change', function (e) {
    if (e.target.files && e.target.files[0]) { importJsonFile(e.target.files[0]); e.target.value = ''; }
  });
  document.getElementById('fd-chat-toggle').addEventListener('click', function () { chatToggle(); });
  document.getElementById('fd-chat-close').addEventListener('click', function () { chatToggle(false); });
  document.getElementById('fd-chat').addEventListener('keydown', chatKeydown);
  document.getElementById('fd-chat-form').addEventListener('submit', function (e) { e.preventDefault(); chatSend(); });
  document.getElementById('fd-nl').addEventListener('keydown', function (e) { if (e.key === 'Enter') draft(); });
  nameInput.addEventListener('input', function () { rootFlow.name = nameInput.value; });
  // keyboard: Delete removes the selected node/edge, Esc deselects, Ctrl+Z/Y
  // undo/redo, Ctrl+D duplicates (all no-ops while typing in a field). Delete,
  // duplicate and paste are also no-ops while focus is on a list, a button or
  // anything inside a dialog, so a key meant for that control cannot change
  // the flow behind it.
  document.addEventListener('keydown', function (e) {
    var tag = (e.target && e.target.tagName) || '';
    var typing = tag === 'INPUT' || tag === 'TEXTAREA' || (e.target && e.target.isContentEditable);
    var control = typing || tag === 'SELECT' || tag === 'BUTTON' ||
      !!(e.target && e.target.closest && e.target.closest('dialog, [role="dialog"], [role="alertdialog"]'));
    var mod = e.ctrlKey || e.metaKey;
    if (mod && !typing && (e.key === 'z' || e.key === 'Z')) { e.preventDefault(); if (e.shiftKey) redo(); else undo(); return; }
    if (mod && !typing && (e.key === 'y' || e.key === 'Y')) { e.preventDefault(); redo(); return; }
    if (mod && !control && (e.key === 'd' || e.key === 'D') && selected) { e.preventDefault(); duplicateNode(selected); return; }
    if (mod && !typing && (e.key === 'c' || e.key === 'C') && selected) { e.preventDefault(); copyNode(selected); return; }
    if (mod && !control && (e.key === 'v' || e.key === 'V')) { e.preventDefault(); pasteNode(); return; }
    if (e.key === 'Escape' && !typing) { selected = null; selectedEdge = null; multiSel = {}; render(); renderProps(); }
    else if ((e.key === 'Delete' || e.key === 'Backspace') && !control) {
      if (selectedEdge) { e.preventDefault(); deleteEdge(selectedEdge); }
      else if (Object.keys(multiSel).length) { e.preventDefault(); deleteSelection(); }
      else if (selected) { e.preventDefault(); deleteNode(selected); }
    }
  });

  async function receiveAuthoringHandoff(blocked) {
    var raw, handoff;
    try {
      raw = sessionStorage.getItem('lightwork.authoring-handoff');
      sessionStorage.removeItem('lightwork.authoring-handoff');
      if (!raw) return;
      handoff = JSON.parse(raw);
    } catch (e) { say('The prepared draft could not be read. Go back and prepare it again.', true); return; }
    if (!handoff || handoff.kind !== 'flow' || typeof handoff.brief !== 'string' || !handoff.brief.trim() ||
        Array.from(handoff.brief).length > 8000 || typeof handoff.context !== 'string' || !handoff.context ||
        !Number.isFinite(handoff.created_at) || Date.now() - handoff.created_at < 0 || Date.now() - handoff.created_at > 600000) {
      say('This prepared draft cannot be used or has expired. Go back and prepare a brief of 8,000 characters or fewer.', true); return;
    }
    var brief = document.getElementById('fd-nl');
    function hasDraft() { return brief.value.trim() || draftIsDirty() || rootFlow.id || rootFlow.name || rootFlow.nodes.length; }
    if (blocked || hasDraft()) { say('Your existing draft was kept. The suggestion was not loaded.'); return; }
    var touched = false;
    function markTouched() { touched = true; }
    ['input', 'change', 'click'].forEach(function (event) { document.addEventListener(event, markTouched, true); });
    try {
      var response = await fetch('/api/v1/templates/draft-context');
      var current = await response.json();
      if (!response.ok || !current || current.context !== handoff.context) throw new Error('workspace mismatch');
      if (touched || hasDraft()) { say('Your current work was kept. The suggestion was not loaded.'); return; }
      if (handoff.flow !== undefined) {
        var suggested = handoff.flow;
        var nodes = suggested && suggested.nodes;
        var first = Array.isArray(nodes) && nodes.find(function (node) { return node && node.id === suggested.start; });
        if (!suggested || typeof suggested !== 'object' || Array.isArray(suggested) ||
            !Array.isArray(nodes) || !nodes.length ||
            nodes.some(function (node) { return !node || typeof node !== 'object' || Array.isArray(node); }) ||
            !first || first.kind !== 'approval' || !first.next ||
            FDCore.validateFlow(suggested).length) {
          say('The suggested workflow could not be loaded. Return to Ekko and prepare it again.', true); return;
        }
        fromApiFlow(suggested);
        brief.value = handoff.brief;
        say('Suggested steps ready. Review them, then save when ready.');
        return;
      }
      brief.value = handoff.brief;
      say('Brief ready. Review it, then choose Draft when you are ready.');
    } catch (e) {
      say('The prepared draft could not be verified in this workspace. Go back and prepare it again.', true);
    } finally {
      ['input', 'change', 'click'].forEach(function (event) { document.removeEventListener(event, markTouched, true); });
    }
  }

  buildExamples();
  loadGallery();
  loadTools();
  var editId = canvas.getAttribute('data-flow-id');
  var seedEl = document.getElementById('fd-seed');
  var seed = null;
  if (seedEl) { try { seed = FDRecipeInputs.parseText(seedEl.textContent); } catch (e) { seed = null; } }
  // Baseline the untouched blank canvas immediately. Loading an existing flow
  // replaces this with its server snapshot; gallery/import/AI drafts remain
  // dirty and therefore receive the unload warning until saved.
  markClean();
  if (editId) load(editId, new URLSearchParams(location.search).has('review_softening') ? draftSnapshot() : undefined)
    .then(function () { initializeRecovery(); return receiveSofteningHandoff(); });
  else if (seed && seed.nodes) {   // ?from_template= -> the template as a 1-node flow
    fromApiFlow(seed);
    say('Loaded the template as a flow — add branches, approvals, or loops around it.');
  } else { render(); renderProps(); }
  receiveAuthoringHandoff(!!(editId || (seed && seed.nodes)));
  if (!editId) initializeRecovery();
  window.addEventListener('lightwork:drafts-ready', function () {
    if (editId && !rootFlow.version) return;
    initializeRecovery();
  });

  // The friendly Steps view renders the LIVE graph (not just the server seed),
  // so nodes built on the canvas show up the moment you switch views.
  window.__fdLiveFlow = toApiFlow;
  // The Steps view edits the same live graph through these helpers.
  function linearOrder() { return FDGraph.linearOrder(rootFlow, flow); }
  function moveStep(id, dir) {
    if (flow !== rootFlow) return false;
    var order = linearOrder();
    var i = order.findIndex(function (n) { return n.id === id; }), j = i + dir;
    if (i < 0 || j < 0 || j >= order.length) return false;
    var simple = order.every(function (n) { return ports(n).length === 1 && !(n.cases && n.cases.length); });
    var chained = order.every(function (n, k) { return k === order.length - 1 ? !n.next : n.next === order[k + 1].id; });
    if (!simple || !chained) { say('This flow has more than one path. Use the Advanced canvas to change the order.', true); return false; }
    pushHistory();
    var t = order[i]; order[i] = order[j]; order[j] = t;
    order.forEach(function (n, k) { n.next = k < order.length - 1 ? order[k + 1].id : null; });
    rootFlow.start = order[0].id;
    autoLayoutForce(); render(); return true;
  }
  function autoLayoutForce() { flow.nodes.forEach(function (n) { n.x = 0; n.y = 0; }); autoLayout(); }
  // The steps a run can reach from the first step, over every way out of a step.
  function reachableIds() { return FDGraph.reachableIds(rootFlow, FDCore); }
  // Where a new step can attach on a reachable path.
  function openEnds() { return FDGraph.openEnds(rootFlow, flow, FDCore, stepName); }
  function addStepAtEnd(kind, end) {
    if (flow !== rootFlow) exitToDepth(0);
    var ends = openEnds(), at = null;
    if (end) ends.forEach(function (e) { if (!at && e.id === end.id && e.port === end.port) at = e; });
    if (!at) at = ends[0] || null;
    if (!at && rootFlow.start && rootFlow.nodes.length) {
      say('Every step already leads somewhere. Use the Advanced canvas to connect a new step.', true);
      return null;
    }
    var target = at && nodeById(at.id);
    selected = target ? target.id : null; selectedEdge = null;
    addNode(kind);
    // addNode only chains a plain step; a Decision's Yes/No path is wired here so the
    // new step is never left disconnected.
    if (target && at.port !== 'next') {
      var added = nodeById(selected);
      target[at.port] = added.id;
      added.x = target.x + (at.port === 'if_true' ? -1 : 1) * Math.round(W * 0.6);
      render();
    }
    return selected;
  }
  // Which way each Decision path leads, by step id (a path left unset continues to `next`).
  function pathsOf(n) { return FDGraph.pathsOf(n); }
  window.__fdEngine = {
    order: function () {
      var reach = reachableIds();
      return linearOrder().map(function (n) {
        return { id: n.id, kind: n.kind, title: stepName(n), summary: summary(n), start: n.id === rootFlow.start,
          reachable: !!reach[n.id], paths: pathsOf(n) };
      });
    },
    ends: openEnds,
    select: function (id) { if (flow !== rootFlow) exitToDepth(0); multiSel = {}; selectNode(id); },
    remove: function (id) { if (flow !== rootFlow) exitToDepth(0); deleteNode(id); },
    move: moveStep,
    add: addStepAtEnd,
    selected: function () { return selected; },
    kindLabel: kindLabel,
    conditionText: conditionText
  };
  var _render = render;
  render = function () { _render(); if (window.__fdStepsRefresh) window.__fdStepsRefresh(); };
})();
{% endraw %}
