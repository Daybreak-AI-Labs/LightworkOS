// Real local pages and API responses; the server supplies synthetic identities
// and bounded local data. CSS content zoom is explicit, not native WebView QA.
const {test, expect} = require('@playwright/test');

test.beforeEach(async ({context, page, baseURL}) => {
  await context.route('**/*', route => new URL(route.request().url()).origin === new URL(baseURL).origin
    ? route.continue() : route.abort('blockedbyclient'));
  page.__errors = []; page.__failed = [];
  page.on('pageerror', error => page.__errors.push(error.message));
  page.on('console', message => {if (message.type() === 'error') page.__errors.push(message.text());});
  page.on('requestfailed', request => page.__failed.push({url: request.url(), error: request.failure().errorText}));
});

test.afterEach(async ({page}, info) => {
  await info.attach('navigation-state', {body: await page.screenshot({fullPage: true}), contentType: 'image/png'});
  await info.attach('browser-diagnostics', {body: JSON.stringify({errors: page.__errors, failed: page.__failed}, null, 2), contentType: 'application/json'});
  expect(page.__errors).toEqual([]);
  expect(page.__failed).toEqual([]);
});

async function fits(page) {
  const bounds = await page.evaluate(() => ({width: document.documentElement.clientWidth,
    scroll: document.documentElement.scrollWidth, path: location.pathname,
    overflowing: [...document.querySelectorAll('main *')].filter(node => {
      const box = node.getBoundingClientRect();
      return box.width && box.right > document.documentElement.clientWidth + 1 && !node.closest('[hidden]');
    }).slice(0, 8).map(node => ({tag: node.tagName, id: node.id, class: node.className})),
    dialogs: [...document.querySelectorAll('dialog[open]')].map(node => ({width: node.clientWidth, scroll: node.scrollWidth})),
    heroes: [...document.querySelectorAll('.hero')].map(hero => {
      const box = hero.getBoundingClientRect(), title = hero.querySelector('.hero-title'), lede = hero.querySelector('.hero-lede');
      const range = document.createRange(); if (title) range.selectNodeContents(title);
      return {title: title && title.textContent, left: box.left, right: box.right, width: box.width,
        text: title ? [...range.getClientRects()].map(rect => ({left: rect.left, right: rect.right})) : [],
        copyWidth: lede && lede.getBoundingClientRect().width};
    })}));
  expect(bounds.scroll, JSON.stringify(bounds)).toBeLessThanOrEqual(bounds.width + 1);
  for (const dialog of bounds.dialogs) expect(dialog.scroll).toBeLessThanOrEqual(dialog.width + 1);
  // Document overflow alone misses text clipped inside overflow:hidden cards.
  for (const hero of bounds.heroes) {
    for (const text of hero.text) {
      expect(text.left, `Left-clipped heading: ${hero.title}`).toBeGreaterThanOrEqual(hero.left - 1);
      expect(text.right, `Right-clipped heading: ${hero.title}`).toBeLessThanOrEqual(hero.right + 1);
    }
    if (hero.copyWidth !== null) expect(hero.copyWidth, `Unusable introductory copy width: ${hero.title}`)
      .toBeGreaterThanOrEqual(Math.min(320, hero.width / 2) - 1);
  }
}

for (const zoom of [1, 2]) test(`five customer destinations support keyboard navigation and browser history at ${zoom * 100}% content zoom`, async ({page}, info) => {
  await page.setViewportSize({width: 1280, height: 950});
  await page.addInitScript(value => {
    document.addEventListener('DOMContentLoaded', () => {document.documentElement.style.zoom = String(value);});
  }, zoom);
  // The finder's settings search (60 ms debounce) asks again as a name is
  // typed, and a busy server can answer an earlier partial name last. Count
  // them so Enter waits for every answer.
  let settingsInFlight = 0;
  const settingsSearch = request => new URL(request.url()).pathname === '/api/v1/settings/search';
  page.on('request', request => { if (settingsSearch(request)) settingsInFlight += 1; });
  for (const settled of ['requestfinished', 'requestfailed'])
    page.on(settled, request => { if (settingsSearch(request)) settingsInFlight -= 1; });
  await page.goto('/start');
  // Knowledge is the governed knowledge-access page; the legacy Cortex console
  // is an advanced tool that no longer appears in customer navigation.
  const destinations = [['Tasks', '/goals'], ['Connections', '/connections'], ['Knowledge', '/knowledge-access'], ['Results', '/deliverables'], ['Settings', '/settings']];
  for (const [label, path] of destinations) {
    await expect(page.locator('#navfinder-dialog')).toHaveAttribute('data-navfinder-ready', 'true');
    await page.keyboard.press('Control+k');
    await expect(page.locator('#navfinder-input')).toBeFocused();
    // Typing also schedules the finder's records search (300 ms debounce) and
    // the answer re-renders the results, so wait for it before selecting: the
    // selection stays put and Enter never aborts an in-flight request.
    const recordsSearched = page.waitForResponse(response => response.url().endsWith('/api/v1/records/search'), {timeout: 10000});
    const settingsSearched = page.waitForResponse(response => response.url().endsWith(`/api/v1/settings/search?q=${encodeURIComponent(label)}`), {timeout: 10000});
    await page.keyboard.type(label);
    await recordsSearched;
    await settingsSearched;
    await expect.poll(() => settingsInFlight).toBe(0);
    const choice = page.locator(`#navfinder-results a[href="${path}"]`);
    await expect(choice).toBeVisible();
    // Select the existing registry option with the keyboard, including when
    // search also matches secondary pages; no synthetic focus jump or click.
    for (let n = 0; n < 120 && await choice.getAttribute('aria-selected') !== 'true'; n++) await page.keyboard.press('ArrowDown');
    await expect(choice).toHaveAttribute('aria-selected', 'true');
    await fits(page);
    await page.keyboard.press('Enter');
    // Settings paints its chosen section on the server and writes no fragment
    // on load (that would make the page jump), so every address is exact.
    await expect(page).toHaveURL(new RegExp(`${path}$`));
    await expect(page).toHaveTitle(new RegExp(`^${label}`));
    await expect(page.locator('main')).toBeVisible();
    await expect.poll(() => page.evaluate(() => Number(getComputedStyle(document.documentElement).zoom))).toBe(zoom);
    await fits(page);
    await info.attach(`${label.toLowerCase()}-${zoom * 100}`, {body: await page.screenshot(), contentType: 'image/png'});
    // Likewise let the destination finish its own requests before history
    // navigation leaves it.
    await page.waitForLoadState('networkidle');
    // Headless Chromium does not implement the browser chrome Alt+Left action.
    // This exercises actual history navigation separately from page keyboard UI.
    await page.goBack({waitUntil: 'domcontentloaded'});
    await expect(page).toHaveURL(/\/start$/);
  }
});

test('restricted customer sees no admin or research destination and direct pages deny access', async ({page, context, baseURL}) => {
  await context.setExtraHTTPHeaders({Origin: baseURL, 'X-Browser-Principal': 'browser-colleague'});
  await page.goto('/goals');
  for (const path of ['/settings', '/connections', '/learning', '/benchmarks']) {
    await expect(page.locator(`#sidebar a[href="${path}"], #navfinder-results a[href="${path}"]`)).toHaveCount(0);
    const response = await context.request.get(path);
    expect(response.status()).toBe(403);
    expect(await response.text()).not.toContain('Synthetic captured deliverable');
  }
  // Tasks and Results also sit in the "Most used" list above the groups, so
  // each destination is checked where it lives: the quick link is visible at
  // once, the group link after its group is opened from the keyboard.
  for (const path of ['/goals', '/knowledge-access', '/deliverables']) {
    const quick = page.locator(`#sidebar .navquick-list a[href="${path}"]`);
    await expect(quick).toHaveCount(path === '/knowledge-access' ? 0 : 1);
    if (await quick.count()) await expect(quick).toBeVisible();
    const link = page.locator(`#sidebar .navgrp a[href="${path}"]`);
    await expect(link).toHaveCount(1);
    const toggle = link.locator('xpath=ancestor::div[contains(@class, "navgrp")]').locator('.navgrp__toggle');
    if (await toggle.getAttribute('aria-expanded') === 'false') {
      await toggle.focus(); await toggle.press('Enter');
    }
    await expect(link).toBeVisible();
  }
});

for (const zoom of [1, 2]) test(`Settings sections remain keyboard usable at ${zoom * 100}% content zoom`, async ({page}, info) => {
  await page.setViewportSize({width: 1280, height: 950});
  await page.addInitScript(value => {
    document.addEventListener('DOMContentLoaded', () => {document.documentElement.style.zoom = String(value);});
  }, zoom);
  await page.goto('/settings');
  const general = page.getByRole('tab', {name: 'General', exact: true});
  await expect(general).toHaveAttribute('aria-selected', 'true');
  await general.focus();
  for (const label of ['General', 'Models', 'Connections', 'Features', 'Access', 'Maintenance']) {
    const tab = page.getByRole('tab', {name: label, exact: true});
    await expect(tab).toBeFocused();
    await expect(tab).toHaveAttribute('aria-selected', 'true');
    await fits(page);
    await info.attach(`settings-${label.toLowerCase()}-${zoom * 100}`, {body: await page.screenshot(), contentType: 'image/png'});
    await page.keyboard.press('ArrowRight');
  }
  await expect(general).toBeFocused();
});
