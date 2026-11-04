// Actual web chat widget in a same-origin host, with synthetic receipt transport.
// CSS content zoom and a controlled visualViewport are explicit emulations;
// the safe-area style contract does not qualify a nonzero native device inset,
// a native virtual keyboard, or human screen-reader speech.
const {test, expect} = require('@playwright/test');
const fs = require('node:fs');
const path = require('node:path');
const widget = fs.readFileSync(path.resolve(__dirname, '../../../../extensions/chat-widget/maverick-chat-widget.js'), 'utf8');

async function host(page, {width = 320, height = 740, direction = 'ltr', zoom = 1, keyboardHeight} = {}) {
  await page.setViewportSize({width, height});
  await page.route('**/__widget_acceptance_host', route => route.fulfill({contentType: 'text/html', body:
    '<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width, initial-scale=1"></head>' +
    '<body><button id="before">Host action before chat</button><button id="after">Host action after chat</button></body></html>'}));
  await page.goto('/__widget_acceptance_host');
  await page.evaluate(({direction, zoom, keyboardHeight}) => {
    localStorage.clear(); document.documentElement.dir = direction; document.documentElement.style.zoom = String(zoom);
    if (keyboardHeight) {
      const viewport = new EventTarget();
      Object.assign(viewport, {height: innerHeight, width: innerWidth, offsetTop: 0, offsetLeft: 0});
      Object.defineProperty(window, 'visualViewport', {value: viewport, configurable: true});
    }
  }, {direction, zoom, keyboardHeight});
  await page.addScriptTag({content: widget});
  const button = page.getByRole('button', {name: 'Lightwork', exact: true});
  await button.focus(); await page.keyboard.press('Enter');
  await expect(page.getByRole('textbox', {name: 'Message to Lightwork'})).toBeFocused();
  if (keyboardHeight) await page.evaluate(height => {
    window.visualViewport.height = height;
    window.visualViewport.dispatchEvent(new Event('resize'));
  }, keyboardHeight);
  return {panel: page.getByRole('region', {name: 'Lightwork', exact: true}), button,
    input: page.getByRole('textbox', {name: 'Message to Lightwork'}), status: page.getByRole('status')};
}

async function panelFits(page) {
  const state = await page.evaluate(() => {
    const panel = document.getElementById('lightwork-widget-panel'), rect = panel.getBoundingClientRect();
    const viewport = window.visualViewport, top = viewport ? viewport.offsetTop : 0;
    const bottom = top + (viewport ? viewport.height : innerHeight);
    const controls = [...panel.querySelectorAll('input, button, [role="status"]')].filter(node =>
      !node.hidden && getComputedStyle(node).display !== 'none' && (node.getAttribute('role') !== 'status' || node.textContent))
      .map(node => {const r = node.getBoundingClientRect(); return {name: node.getAttribute('aria-label') || node.textContent,
        left: r.left, right: r.right, top: r.top, bottom: r.bottom, width: r.width, height: r.height};});
    return {viewport: {width: innerWidth, top, bottom}, panel: {left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom,
      scroll: panel.scrollWidth, width: panel.clientWidth},
      styles: {bottom: panel.style.bottom, maxHeight: panel.style.maxHeight}, controls};
  });
  // Desktop Chromium reports a zero safe-area inset. Require the live fit()
  // styles to retain the device term in both positioning and height limits.
  expect(state.styles.bottom).toContain('env(safe-area-inset-bottom');
  expect(state.styles.maxHeight).toContain('env(safe-area-inset-bottom');
  expect(state.panel.left, JSON.stringify(state)).toBeGreaterThanOrEqual(-1);
  expect(state.panel.right, JSON.stringify(state)).toBeLessThanOrEqual(state.viewport.width + 1);
  expect(state.panel.top, JSON.stringify(state)).toBeGreaterThanOrEqual(state.viewport.top - 1);
  expect(state.panel.bottom, JSON.stringify(state)).toBeLessThanOrEqual(state.viewport.bottom + 1);
  expect(state.panel.scroll, JSON.stringify(state)).toBeLessThanOrEqual(state.panel.width + 1);
  for (const control of state.controls) {
    expect(control.width, JSON.stringify(control)).toBeGreaterThan(0);
    expect(control.height, JSON.stringify(control)).toBeGreaterThan(0);
    expect(control.left, JSON.stringify(control)).toBeGreaterThanOrEqual(state.panel.left - 1);
    expect(control.right, JSON.stringify(control)).toBeLessThanOrEqual(state.panel.right + 1);
    expect(control.top, JSON.stringify(control)).toBeGreaterThanOrEqual(Math.max(state.panel.top, state.viewport.top) - 1);
    expect(control.bottom, JSON.stringify(control)).toBeLessThanOrEqual(Math.min(state.panel.bottom, state.viewport.bottom) + 1);
  }
}

test.beforeEach(async ({context, page, baseURL}) => {
  await context.route('**/*', route => new URL(route.request().url()).origin === new URL(baseURL).origin
    ? route.continue() : route.abort('blockedbyclient'));
  page.__widgetErrors = []; page.on('pageerror', error => page.__widgetErrors.push(error.message));
});
test.afterEach(async ({page}, info) => {
  await info.attach('widget-rendered-state', {body: await page.screenshot(), contentType: 'image/png'});
  expect(page.__widgetErrors).toEqual([]);
});

for (const layout of [
  {name: '320px portrait', width: 320, height: 740},
  {name: 'landscape', width: 740, height: 320},
  {name: '200% content zoom', width: 640, height: 950, zoom: 2},
  {name: '320px RTL', width: 320, height: 740, direction: 'rtl'},
  {name: 'emulated keyboard viewport', width: 390, height: 844, keyboardHeight: 310},
]) test(`widget controls and uncertain receipt fit ${layout.name}`, async ({page}, info) => {
  await page.route('**/chat/send', route => route.fulfill({status: 503, contentType: 'application/json', body: '{}'}));
  const ui = await host(page, layout);
  await panelFits(page);
  await ui.input.fill('Keep this request while its result is unknown.');
  await page.keyboard.press('Enter');
  await expect(ui.status).toContainText('Start not confirmed');
  await expect(page.getByRole('button', {name: 'Check start status'})).toBeVisible();
  await panelFits(page);
  if (layout.name === 'landscape' || layout.name === '200% content zoom') {
    await info.attach(`widget-unknown-receipt-${layout.name}`, {body: await page.screenshot(), contentType: 'image/png'});
  }
  await ui.input.press('Escape');
  await expect(ui.panel).toBeHidden(); await expect(ui.button).toBeFocused();
});

test('keyboard follows pending, refused, unknown and accepted receipts without duplicate starts', async ({page}) => {
  let posts = 0, held, phase = 'pending';
  await page.route('**/chat/send', async route => {
    posts++;
    if (phase === 'pending') { held = route; return; }
    await route.fulfill({status: 503, contentType: 'application/json', body: '{}'});
  });
  let receipts = 0;
  await page.route('**/api/v1/goal-submissions/receipt?kind=chat', route => {
    receipts++; return route.fulfill({contentType: 'application/json', body: JSON.stringify({state: 'accepted', goal: {id: 4242, status: 'pending'}})});
  });
  const ui = await host(page);
  await ui.input.fill('A keyboard-authored request'); await page.keyboard.press('Enter');
  await expect(ui.status).toHaveText('Sending your request. Waiting for its receipt.');
  await expect(ui.panel.locator('form')).toHaveAttribute('aria-busy', 'true');
  await expect(page.getByRole('button', {name: 'Send', exact: true})).toBeDisabled();
  await expect.poll(() => Boolean(held)).toBe(true);
  await page.keyboard.press('Enter'); expect(posts).toBe(1);
  await held.fulfill({status: 403, contentType: 'application/json', body: JSON.stringify({detail: 'This synthetic account cannot start a task.'})});
  await expect(ui.status).toContainText('Start refused');
  await expect(ui.input).toHaveValue('A keyboard-authored request');
  phase = 'unknown'; await ui.input.press('Enter');
  await expect(ui.status).toContainText('Start not confirmed'); expect(posts).toBe(2);
  await expect(page.getByRole('button', {name: 'Send', exact: true})).toBeDisabled();
  await ui.input.focus(); await page.keyboard.press('Tab');
  await expect(page.getByRole('button', {name: 'Check start status'})).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(ui.status).toHaveText('Task accepted. Open the task to follow its progress.');
  expect(posts).toBe(2); expect(receipts).toBe(1);
  await expect(ui.panel.getByRole('link', {name: 'watch it live'})).toHaveAttribute('href', '/chat/goal/4242');
  await expect(ui.status).toHaveAttribute('aria-live', 'polite');
  await expect(ui.status).toHaveAttribute('aria-atomic', 'true');
  expect(await ui.panel.locator('[aria-label="Conversation"]').getAttribute('aria-live')).toBeNull();
  await ui.panel.getByRole('button', {name: 'Close Lightwork'}).focus(); await page.keyboard.press('Enter');
  await expect(ui.button).toBeFocused(); await expect(ui.button).toHaveAttribute('aria-expanded', 'false');
  await page.keyboard.press('Enter'); await expect(ui.input).toBeFocused();
  // The widget is a non-modal region; Tab can leave it for the host page.
  let escaped = false;
  for (let i = 0; i < 12; i++) {
    await page.keyboard.press('Tab');
    if (await page.evaluate(() => ['before', 'after'].includes(document.activeElement.id))) { escaped = true; break; }
  }
  expect(escaped).toBe(true);
});

test('a 200px keyboard viewport scrolls uncertain status and keeps receipt and Close reachable', async ({page}, info) => {
  let posts = 0, receipts = 0;
  await page.route('**/chat/send', route => {
    posts++; return route.fulfill({status: 503, contentType: 'application/json', body: '{}'});
  });
  await page.route('**/api/v1/goal-submissions/receipt?kind=chat', route => {
    receipts++; return route.fulfill({status: 503, contentType: 'application/json', body: '{}'});
  });
  const ui = await host(page, {width: 390, height: 844, keyboardHeight: 200});
  const check = page.getByRole('button', {name: 'Check start status'});
  const close = page.getByRole('button', {name: 'Close Lightwork'});
  async function reachable(control) {
    const state = await control.evaluate(node => {
      const box = node.getBoundingClientRect(), panel = node.closest('[role="region"]').getBoundingClientRect();
      const viewport = window.visualViewport;
      const hit = document.elementFromPoint(box.left + box.width / 2, box.top + box.height / 2);
      return {box: {top: box.top, bottom: box.bottom, left: box.left, right: box.right},
        panel: {top: panel.top, bottom: panel.bottom, left: panel.left, right: panel.right},
        viewport: {top: viewport.offsetTop, bottom: viewport.offsetTop + viewport.height},
        pointerReachable: node === hit || node.contains(hit)};
    });
    expect(state.panel.top, JSON.stringify(state)).toBeGreaterThanOrEqual(state.viewport.top - 1);
    expect(state.panel.bottom, JSON.stringify(state)).toBeLessThanOrEqual(state.viewport.bottom + 1);
    expect(state.box.top, JSON.stringify(state)).toBeGreaterThanOrEqual(state.panel.top - 1);
    expect(state.box.bottom, JSON.stringify(state)).toBeLessThanOrEqual(state.panel.bottom + 1);
    expect(state.box.left, JSON.stringify(state)).toBeGreaterThanOrEqual(state.panel.left - 1);
    expect(state.box.right, JSON.stringify(state)).toBeLessThanOrEqual(state.panel.right + 1);
    expect(state.pointerReachable, JSON.stringify(state)).toBe(true);
  }
  await ui.input.fill('Keep the draft while the keyboard leaves little room.');
  await page.keyboard.press('Enter');
  await expect(ui.status).toContainText('Start not confirmed');
  expect(await ui.panel.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
  // User scrolling must reveal the entire status; no DOM scrollTop assignment
  // or locator scrollIntoView may conceal an overflow:hidden failure here.
  await ui.panel.hover({position: {x: 20, y: 120}});
  await page.mouse.wheel(0, 600);
  await expect.poll(() => ui.panel.evaluate(node => node.scrollTop)).toBeGreaterThan(0);
  await reachable(ui.status);
  await info.attach('widget-200px-unknown-status', {body: await page.screenshot(), contentType: 'image/png'});
  await ui.input.focus(); await page.keyboard.press('Tab');
  await expect(check).toBeFocused(); await reachable(check);
  await check.click();
  await expect(ui.status).toContainText('No confirmed receipt is visible yet');
  expect(posts).toBe(1); expect(receipts).toBe(1);
  await expect(ui.input).toHaveValue('Keep the draft while the keyboard leaves little room.');
  for (let i = 0; i < 6 && !(await close.evaluate(node => node === document.activeElement)); i++) {
    await page.keyboard.press('Shift+Tab');
  }
  await expect(close).toBeFocused(); await reachable(close);
  await info.attach('widget-200px-close-reachable', {body: await page.screenshot(), contentType: 'image/png'});
  await close.click();
  await expect(ui.panel).toBeHidden(); await expect(ui.button).toBeFocused();
});
