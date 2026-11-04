// SVG graph rendering. The editor supplies the current state and its callbacks.
var FDCanvas = (function () {
  'use strict';
  function render(state, dom, helpers) {
    var flow = state.flow, view = state.view, selected = state.selected;
    var multiSel = state.multiSel, selectedEdge = state.selectedEdge, proposals = state.proposals;
    var vp = dom.viewport, gEdges = dom.edges, gNodes = dom.nodes;
    var W = state.width, H = state.height, KIND_ICON = state.icons;
    var ports = helpers.ports, nodeById = helpers.nodeById, el = helpers.el;
    var runClass = helpers.runClass, runBadge = helpers.runBadge;
    var summary = helpers.summary, kindLabel = helpers.kindLabel, trunc = helpers.truncate;
    var focusedNode = dom.document.activeElement && dom.document.activeElement.getAttribute
      ? dom.document.activeElement.getAttribute('data-node') : null;
    vp.setAttribute('transform', 'translate(' + view.x + ',' + view.y + ') scale(' + view.k + ')');
    gEdges.textContent = ''; gNodes.textContent = '';
    // edges
    flow.nodes.forEach(function (n) {
      ports(n).forEach(function (p) {
        var tgt = n[p.key]; if (!tgt) return;
        var t = nodeById(tgt); if (!t) return;
        var px = n.x + p.x, py = n.y + H, tx = t.x + W / 2, ty = t.y;
        var d = 'M' + px + ' ' + py + ' C ' + px + ' ' + (py + 46) + ', ' + tx + ' ' + (ty - 46) + ', ' + tx + ' ' + ty;
        var isSel = selectedEdge && selectedEdge.from === n.id && selectedEdge.port === p.key;
        gEdges.appendChild(el('path', { class: 'fd-edge ' + p.cls + (isSel ? ' selected' : ''), d: d }));
        // invisible fat twin so a 2px curve is actually clickable (click = select,
        // Delete = cut; a second click on the same edge also cuts)
        var hit = el('path', { class: 'fd-edge-hit', d: d });
        hit.setAttribute('data-edge-from', n.id); hit.setAttribute('data-edge-port', p.key);
        gEdges.appendChild(hit);
        if (p.label) gEdges.appendChild(el('text', { class: 'fd-edge-label', x: px + 4, y: py + 14 }, p.label));
      });
    });
    var unreachable = flow.start && helpers.core.unreachableNodeIds
      ? helpers.core.unreachableNodeIds(flow) : [];
    // nodes
    flow.nodes.forEach(function (n) {
      var g = el('g', { class: 'fd-node' + ((n.id === selected || multiSel[n.id]) ? ' selected' : '') + (n.id === flow.start ? ' start' : '') + runClass(n.id),
                        transform: 'translate(' + n.x + ',' + n.y + ')' });
      if (unreachable.indexOf(n.id) >= 0) g.setAttribute('opacity', '0.45');
      g.setAttribute('data-node', n.id);
      g.setAttribute('tabindex', '0');
      g.setAttribute('role', 'button');
      g.setAttribute('aria-label', (n.label || summary(n)) + ', ' + kindLabel(n.kind)
        + ' step' + (n.id === flow.start ? ', first step' : '')
        + (unreachable.indexOf(n.id) >= 0 ? ', not connected and will never run' : '')
        + '. Press Enter to edit; use arrow keys to move.');
      g.setAttribute('aria-pressed', n.id === selected ? 'true' : 'false');
      g.appendChild(el('rect', { class: 'card', width: W, height: H, rx: 10 }));
      g.appendChild(el('rect', { class: 'swatch k-' + n.kind, x: 0, y: 0, width: 8, height: H, rx: 4 }));
      g.appendChild(el('text', { class: 'kind', x: 16, y: 20 }, (KIND_ICON[n.kind] || '') + ' ' + kindLabel(n.kind)));
      g.appendChild(el('text', { x: 16, y: 40 }, trunc(n.label || summary(n), 26)));
      var badge = runBadge(n.id);
      if (badge) g.appendChild(el('text', { class: 'runbadge', x: W - 20, y: 20 }, badge));
      if (proposals[n.id]) {
        var lamp = el('text', { class: 'runbadge', x: W - (badge ? 40 : 20), y: 20 }, '💡');
        lamp.appendChild(el('title', {}, 'Suggestion — select this step to review it'));
        g.appendChild(lamp);
      }
      if (n.id === flow.start) g.appendChild(el('text', { x: 16, y: 56, class: 'fd-edge-label' }, '▶ First step'));
      ports(n).forEach(function (p) {
        var c = el('circle', { class: 'port', cx: p.x, cy: H, r: 6 });
        c.setAttribute('data-port', p.key); c.setAttribute('data-node', n.id);
        g.appendChild(c);
      });
      gNodes.appendChild(g);
    });
    if (focusedNode) {
      Array.prototype.some.call(gNodes.querySelectorAll('[data-node]'), function (node) {
        if (node.getAttribute('data-node') !== focusedNode) return false;
        node.focus(); return true;
      });
    }
  }
  function miniScale(flow, view, canvas, W, H, MINI_W, MINI_H, MINI_PAD) {
    var minX = 0, minY = 0, maxX = 400, maxY = 300;
    if (flow.nodes.length) {
      minX = Infinity; minY = Infinity; maxX = -Infinity; maxY = -Infinity;
      flow.nodes.forEach(function (n) {
        minX = Math.min(minX, n.x); minY = Math.min(minY, n.y);
        maxX = Math.max(maxX, n.x + W); maxY = Math.max(maxY, n.y + H);
      });
    }
    var r = canvas.getBoundingClientRect();
    // include the visible viewport so the view rect always fits on the map
    minX = Math.min(minX, -view.x / view.k); minY = Math.min(minY, -view.y / view.k);
    maxX = Math.max(maxX, (-view.x + r.width) / view.k); maxY = Math.max(maxY, (-view.y + r.height) / view.k);
    var k = Math.min((MINI_W - 2 * MINI_PAD) / Math.max(1, maxX - minX),
                     (MINI_H - 2 * MINI_PAD) / Math.max(1, maxY - minY));
    return { minX: minX, minY: minY, k: k };
  }
  function renderMinimap(flow, view, canvas, W, H, MINI_W, MINI_H, MINI_PAD, document, el) {
    var mm = document.getElementById('fd-minimap'); if (!mm) return;
    mm.textContent = '';
    var s = miniScale(flow, view, canvas, W, H, MINI_W, MINI_H, MINI_PAD);
    flow.nodes.forEach(function (n) {
      mm.appendChild(el('rect', { class: 'mini-node',
        x: MINI_PAD + (n.x - s.minX) * s.k, y: MINI_PAD + (n.y - s.minY) * s.k,
        width: Math.max(2, W * s.k), height: Math.max(2, H * s.k), rx: 1 }));
    });
    var r = canvas.getBoundingClientRect();
    mm.appendChild(el('rect', { class: 'mini-view',
      x: MINI_PAD + (-view.x / view.k - s.minX) * s.k,
      y: MINI_PAD + (-view.y / view.k - s.minY) * s.k,
      width: (r.width / view.k) * s.k, height: (r.height / view.k) * s.k }));
  }

  return { render: render, miniScale: miniScale, renderMinimap: renderMinimap };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = FDCanvas;
