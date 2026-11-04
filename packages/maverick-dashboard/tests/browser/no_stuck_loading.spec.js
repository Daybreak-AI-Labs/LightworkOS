const {test, expect} = require('@playwright/test');

// Ratchet: a page never stays on "Loading…" or "Checking…". Whether its
// data arrives, is empty, or fails, each placeholder settles into data, an
// empty state or a plain error with a next step. Lazy sections are scrolled
// into view first, as a person would. Add a page here when it gains loaders.
const PAGES = ['/immune', '/security/assurance', '/audit', '/ai-entity-tasks', '/third-party/collaboration'];

async function stuckLoaders(page) {
  await page.waitForLoadState('networkidle');
  const height = await page.evaluate(() => document.body.scrollHeight);
  for (let y = 0; y < height; y += 600) {
    await page.evaluate(top => window.scrollTo(0, top), y);
    await page.waitForTimeout(150);
  }
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(1500);
  return page.evaluate(() => [...document.querySelectorAll('main *')].filter(element => {
    if (element.children.length) return false;
    const box = element.getBoundingClientRect();
    if (!(box.width > 0 && box.height > 0) || getComputedStyle(element).visibility === 'hidden') return false;
    return /^(Loading|Checking)\b/.test(element.textContent.trim());
  }).map(element => (element.id ? '#' + element.id + ' ' : '') + element.textContent.trim().slice(0, 80)));
}

for (const failing of [false, true]) {
  for (const path of PAGES) {
    test(`${path} settles with ${failing ? 'every request failing' : 'its own data'}`, async ({page, context, baseURL}) => {
      const errors = [];
      page.on('pageerror', error => errors.push(error.message));
      await context.route('**/*', route => new URL(route.request().url()).origin === new URL(baseURL).origin
        ? route.continue() : route.abort());
      if (failing) {
        await page.route(/\/api\/v1\/(immune|security|audit|ai-entity-tasks|third-party|people|vendors)\b/, route =>
          route.fulfill({status: 503, json: {detail: 'unavailable'}}));
      }
      await page.goto(path);
      expect(await stuckLoaders(page)).toEqual([]);
      expect(errors).toEqual([]);
    });
  }
}
