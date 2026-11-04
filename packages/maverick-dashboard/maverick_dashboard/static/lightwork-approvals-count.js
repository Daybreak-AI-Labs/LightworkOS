/* The Approvals header ("N requests waiting") follows the queue: a decision,
 * an undo or a send-back in _approvals_queue.html changes it at once, as the
 * list does. Words come from the journey catalog in the person's language.
 */
(function () {
  'use strict';
  var box = document.getElementById('approvals-current-state');
  var queue = document.getElementById('approval-queue');
  if (!box || !queue || typeof MutationObserver !== 'function') return;
  function tr(source, values) {
    if (window.LightworkI18n) return window.LightworkI18n.text(source, values);
    return source.replace(/\{([a-z]+)\}/g, function (whole, name) { return values && name in values ? String(values[name]) : whole; });
  }
  function refresh() {
    var open = queue.querySelectorAll(':scope > article.approval-item').length + (parseInt(box.dataset.flowCount, 10) || 0);
    var hidden = parseInt(box.dataset.privateCount, 10) || 0;
    var checked = box.dataset.coverage === 'current';
    var name = box.querySelector('.hero-statebox__row strong');
    if (name) {
      name.textContent = open ? (open === 1 ? tr('1 request waiting') : tr('{count} requests waiting', {count: open}))
        : hidden ? (hidden === 1 ? tr("1 request is waiting that you can't open here")
          : tr("{count} requests are waiting that you can't open here", {count: hidden}))
        : tr('0 requests waiting');
    }
    var badge = box.querySelector('.hero-statebox__row .badge');
    if (badge) {
      badge.textContent = tr(open || box.dataset.inChat === '1' ? 'Action needed'
        : hidden ? 'Waiting' : checked ? 'All clear' : 'Check needed');
      badge.className = 'badge ' + (open || hidden || !checked ? 'warn' : 'ok');
    }
  }
  new MutationObserver(refresh).observe(queue, {childList: true});
}());
