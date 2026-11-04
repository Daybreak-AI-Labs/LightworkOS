// Routine edits under a slow phone network. A measurement,
// not a test: it records numbers and fails nothing. Not run by `npm test`.
//
//   node measure_routine_edits.js --base http://127.0.0.1:8765 [--out edits.json]
//
// Against a running dashboard with seeded data (approvals, people), for each
// routine edit it reports:
//   feedbackMs  - input to the first visible change on the page, with Chrome's
//                 "Slow 4G" network and a 4x slower CPU (target: <= 100 ms);
//   settledMs   - input to the server's answer under the same conditions;
//   failure     - with the request blocked: whether an error is shown and the
//                 earlier state is restored or an Undo is offered (target: both);
//   serverMs    - the request's own time on an unthrottled network (rubric:
//                 POST/PATCH/DELETE p75 < 500 ms), with the p75 over all edits.
// Edits the page does not offer (missing seed data, a role without access)
// are reported as "not available", never as passing.
'use strict';
const {chromium} = require('playwright');
const fs = require('node:fs');

const args = Object.fromEntries(process.argv.slice(2).reduce((a, v, i, all) => (v.startsWith('--') ? a.concat([[v.slice(2), all[i + 1]]]) : a), []));
const BASE = args.base || 'http://127.0.0.1:8765';
// Chrome DevTools "Slow 4G": 562.5 ms latency, 1.4 Mbit/s down, 675 kbit/s up.
const SLOW_4G = {offline: false, latency: 562.5, downloadThroughput: Math.floor(1474.56 * 1024 / 8), uploadThroughput: Math.floor(675 * 1024 / 8)};

// Each edit: the page, how to find its control, and what restoring looks like.
const EDITS = [
  {name: 'approve a request', path: '/approvals',
    control: 'article.approval-item:not([data-risk="high"]):not([data-risk="critical"]) button.approval-btn[data-action="approve"]',
    restored: page => page.locator('article.approval-item button.approval-btn[data-action="approve"]').count().then(n => n > 0)},
  {name: 'reject a request', path: '/approvals',
    control: 'article.approval-item:not([data-risk="high"]):not([data-risk="critical"]) button.approval-btn[data-action="deny"]',
    // Rejecting asks for an optional reason first; the request goes when it is given.
    confirm: async page => { await page.fill('#mv-form-fields input', 'Not needed'); await page.click('#mv-form-ok'); },
    restored: page => page.locator('article.approval-item button.approval-btn[data-action="deny"]').count().then(n => n > 0)},
  {name: 'give a person a role', path: '/users', control: '#give-role-form [type="submit"]',
    prepare: async page => {
      await page.selectOption('#give-role-form select[name="principal"]', {index: 1}).catch(() => {});
      await page.selectOption('#give-role-form select[name="role"]', {index: 1}).catch(() => {});
    },
    // Kept as chosen, so the person can try again.
    restored: page => page.locator('#give-role-form select[name="principal"]').inputValue().then(value => value !== '')},
  {name: 'turn the daily summary on or off', path: '/me', control: '#digest-form [type="submit"]',
    prepare: async page => { await page.locator('#digest-form input[name="digest_enabled"]').click(); },
    restored: page => page.locator('#digest-form input[name="digest_enabled"]').count().then(n => n > 0)},
  {name: 'change notification preferences', path: '/notifications', control: '#notification-preferences [type="submit"]',
    prepare: async page => { await page.locator('#notification-preferences input[name="quiet_enabled"]').click(); }},
  {name: 'pin a page to the sidebar', path: '/goals', control: 'main button:has-text("Pin to sidebar")',
    state: page => page.locator('#page-pin-toggle').getAttribute('aria-pressed')},
  // The form's first submit button is Preview, which only reads.
  {name: 'save the workspace spending limit', path: '/spending-limits', control: '#limit-workspace button[type="submit"]:not([formmethod="get"])',
    prepare: async page => {
      await page.check('#limit-workspace input[name="choice"][value="limit"]').catch(() => {});
      await page.locator('#limit-workspace input[name="amount"]').fill('250').catch(() => {});
    },
    restored: page => page.locator('#limit-workspace input[name="amount"]').inputValue().then(value => value === '250')},
];

async function ready(page) {
  await page.waitForLoadState('networkidle', {timeout: 8000}).catch(() => {});
}

// Records the wall-clock time of the input and of the first change on the
// page after it, reported out of the page so a save that loads the next page
// still counts.
const PROBE = `(() => {
  let armed = false;
  new MutationObserver(() => { if (armed) { armed = false; window.__lwEditMark('change', Date.now()); } })
    .observe(document, {subtree: true, childList: true, attributes: true, characterData: true});
  addEventListener('pointerdown', () => { armed = true; window.__lwEditMark('input', Date.now()); }, {capture: true});
})();`;

async function attempt(browser, edit, mode) {
  const context = await browser.newContext({viewport: {width: 390, height: 844}, isMobile: true, hasTouch: true, extraHTTPHeaders: {Origin: BASE}});
  const marks = {input: null, change: null};
  await context.exposeBinding('__lwEditMark', (_source, kind, at) => {
    if (kind === 'input') { marks.input = at; marks.change = null; } else if (marks.change === null) marks.change = at;
  });
  await context.addInitScript(PROBE);
  const page = await context.newPage();
  const result = {mode};
  try {
    await page.goto(BASE + edit.path); await ready(page);
    const control = page.locator(edit.control).first();
    if (!(await control.count())) return {mode, available: false};
    if (edit.prepare) await edit.prepare(page);
    const before = edit.state ? await edit.state(page) : null;
    const cdp = await context.newCDPSession(page);
    if (mode !== 'server') {
      await cdp.send('Network.enable'); await cdp.send('Network.emulateNetworkConditions', SLOW_4G);
      await cdp.send('Emulation.setCPUThrottlingRate', {rate: 4});
    }
    if (mode === 'blocked') await page.route('**/*', route => (route.request().method() === 'GET' ? route.continue() : route.abort('failed')));
    const answered = page.waitForResponse(response => response.request().method() !== 'GET', {timeout: 30000}).catch(() => null);
    const failed = page.waitForEvent('requestfailed', {timeout: 30000}).catch(() => null);
    await control.click();
    if (edit.confirm) await edit.confirm(page);
    const response = mode === 'blocked' ? await failed : await answered;
    const answeredAt = Date.now();
    await page.waitForTimeout(300);
    if (marks.input !== null && marks.change !== null) result.feedbackMs = marks.change - marks.input;
    if (response && mode !== 'blocked') {
      result.status = response.status();
      const t = response.request().timing();
      if (t.responseStart >= 0 && t.requestStart >= 0) result.serverMs = Math.round(t.responseStart - t.requestStart);
      if (marks.input !== null) result.settledMs = answeredAt - marks.input;
    }
    if (mode === 'blocked') {
      await page.waitForTimeout(1500);
      result.errorShown = await page.evaluate(() => [...document.querySelectorAll('[role="alert"], .mv-status--error, .mv-toast--error, [data-mv-loading-error], [data-mv-error-summary]:not([hidden])')]
        .some(node => node.textContent.trim().length > 0 && node.getClientRects().length > 0));
      result.undoOffered = await page.locator('button:has-text("Undo"):visible').count() > 0;
      result.restored = edit.restored ? await edit.restored(page) : edit.state ? (await edit.state(page)) === before : null;
    }
    return result;
  } catch (error) {
    return {mode, error: String(error.message || error).split('\n')[0].slice(0, 200)};
  } finally {
    await context.close();
  }
}

function p75(values) {
  const sorted = values.filter(Number.isFinite).sort((a, b) => a - b);
  return sorted.length ? sorted[Math.min(sorted.length - 1, Math.ceil(0.75 * sorted.length) - 1)] : null;
}

(async () => {
  const browser = await chromium.launch();
  const rows = [];
  for (const edit of EDITS) {
    const row = {edit: edit.name, path: edit.path};
    for (const mode of ['slow', 'blocked', 'server']) row[mode] = await attempt(browser, edit, mode);
    rows.push(row);
    console.log(JSON.stringify(row));
  }
  await browser.close();
  const report = {base: BASE, measuredAt: new Date().toISOString(), rows,
    feedbackP75Ms: p75(rows.map(r => r.slow.feedbackMs)), serverP75Ms: p75(rows.map(r => r.server.serverMs)),
    failuresHandled: rows.filter(r => r.blocked.errorShown && (r.blocked.undoOffered || r.blocked.restored)).length,
    edits: rows.filter(r => r.slow.available !== false).length};
  console.log(JSON.stringify({feedbackP75Ms: report.feedbackP75Ms, serverP75Ms: report.serverP75Ms, failuresHandled: report.failuresHandled, of: report.edits}));
  if (args.out) fs.writeFileSync(args.out, JSON.stringify(report, null, 1));
})();
