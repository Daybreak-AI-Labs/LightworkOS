(function () {
  'use strict';
  const links = Array.from(document.querySelectorAll('.personal-notification-link'));
  if (!links.length || links[0].dataset.enabled !== 'true' || location.pathname === '/notifications') return;
  let controller = null;

  function show(unseen, partial) {
    const label = unseen ? 'Your notifications, ' + unseen + ' new' : 'Your notifications';
    links.forEach(function (link) {
      const count = link.querySelector('.notification-count');
      count.classList.remove('notification-count--error');
      count.hidden = unseen === 0;
      count.textContent = unseen > 99 ? '99+' : String(unseen);
      link.setAttribute('aria-label', label + (partial ? '. Some assigned decisions could not be checked.' : ''));
      link.title = partial ? 'Some notifications could not be checked. Open your inbox to refresh.' : label;
    });
  }

  async function check() {
    if (document.hidden || controller) return;
    controller = new AbortController();
    try {
      const value = await window.mvFetchJSON('/api/v1/notifications/personal/summary', {
        cache: 'no-store', signal: controller.signal, timeout: 12000,
      });
      if (!Number.isSafeInteger(value.unseen) || value.unseen < 0) throw new Error('Unavailable');
      show(value.unseen, value.partial === true);
    } catch (_) {
      if (!document.hidden) {
        links.forEach(function (link) {
          const count = link.querySelector('.notification-count');
          count.hidden = false;
          count.textContent = '!';
          count.classList.add('notification-count--error');
          link.setAttribute('aria-label', 'Your notifications could not be checked. Open your inbox to refresh.');
          link.title = 'Notifications could not be checked. Open your inbox to refresh.';
        });
      }
    } finally {
      controller = null;
    }
  }

  document.addEventListener('visibilitychange', check);
  window.addEventListener('pagehide', function () { if (controller) controller.abort(); });
  setInterval(check, 30000);
  check();
})();
