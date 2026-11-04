// Chromium media emulation checks real helper + real controller callsites.
// This is not OS/device/human motion-sensitivity qualification.
const {test, expect} = require('@playwright/test');
const {fixture, reply, setup, names} = require('./motion_fixture');

for (const name of names) test(`${name} reveal actions re-read reduced motion and preserve focus`, async ({page, context, baseURL}) => {
  const data = fixture(name), errors = [], unexpected = [];
  page.on('pageerror', error => errors.push(error.message));
  await context.route('**/*', route => new URL(route.request().url()).origin === new URL(baseURL).origin
    ? route.continue() : route.abort('blockedbyclient'));
  await page.route('**/api/**', async route => {
    try { await route.fulfill({contentType: 'application/json', body: JSON.stringify(reply(name, new URL(route.request().url()).pathname, route.request().method()))}); }
    catch (error) { unexpected.push(error.message); await route.fulfill({status: 500, contentType: 'application/json', body: '{}'}); }
  });
  await page.route('**/__motion_acceptance_host', route => route.fulfill({contentType: 'text/html', body:
    '<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width, initial-scale=1"></head><body><main>' + data.markup + '</main></body></html>'}));
  await page.setViewportSize({width: 1000, height: 700});
  await page.goto('/__motion_acceptance_host');
  await page.addStyleTag({content: data.css});
  // The shell's helpers load first, as in base.html; the fixture's stand-ins
  // for the confirmation dialogs then replace the real ones.
  await page.addScriptTag({content: data.shell});
  await page.evaluate(({def, setupSource}) => (0, eval)('(' + setupSource + ')(window, ' + JSON.stringify(def) + ')'), {def: {root: data.root, api: data.api}, setupSource: setup.toString()});
  await page.evaluate(() => {
    window.__reveals = [];
    const nativeScroll = Element.prototype.scrollIntoView;
    Element.prototype.scrollIntoView = function (options) {
      window.__reveals.push({id: this.id, behavior: options.behavior, block: options.block});
      return nativeScroll.call(this, options);
    };
  });
  await page.addScriptTag({content: data.helpers});
  await page.addScriptTag({content: data.source});
  await expect(page.locator(data.ready).first()).toBeVisible();
  // Toggle the media preference in the same loaded page: no cached preference.
  for (const reducedMotion of ['reduce', 'no-preference']) {
    await page.emulateMedia({reducedMotion});
    for (const step of data.steps) {
      await page.evaluate(() => { window.__reveals.length = 0; });
      const trigger = step.trigger ? page.locator(step.trigger).first()
        : page.locator(step.within).getByRole('button', {name: step.label, exact: true}).first();
      await trigger.focus(); await page.keyboard.press('Enter');
      await expect.poll(() => page.evaluate(() => window.__reveals)).toEqual([
        {id: step.target, behavior: reducedMotion === 'reduce' ? 'instant' : 'smooth', block: 'nearest'},
      ]);
      await expect(page.locator(step.focus || '#' + step.target)).toBeFocused();
      await expect(page.locator('#' + step.target)).toBeInViewport();
      await expect(page.locator('#' + step.target)).toHaveAttribute('tabindex', '-1');
    }
  }
  expect(unexpected).toEqual([]); expect(errors).toEqual([]);
});
