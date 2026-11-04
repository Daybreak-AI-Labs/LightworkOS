const {test, expect} = require('@playwright/test');

// Settings must not write #settings-general into the address while the page
// is still loading: Chrome would then scroll to that section when loading
// finished (scrollY 739) and start keyboard focus there, so the first Tab
// would land on the theme menu instead of the top of the page.
test('Settings opens at the top and the first Tab starts at the top of the page', async ({page, context, baseURL}) => {
  await context.route('**/*', route => new URL(route.request().url()).origin === new URL(baseURL).origin ? route.continue() : route.abort('blockedbyclient'));
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  await page.setViewportSize({width: 1280, height: 900});
  await page.goto('/settings', {waitUntil: 'load'});
  await expect(page.locator('#navfinder-dialog')).toHaveAttribute('data-navfinder-ready', 'true');
  expect(new URL(page.url()).hash).toBe('');
  expect(await page.evaluate(() => window.scrollY)).toBe(0);
  await expect(page.locator('[data-settings-tab="general"]')).toHaveAttribute('aria-selected', 'true');

  await page.keyboard.press('Tab');
  const focus = await page.evaluate(() => {
    const focusable = Array.from(document.querySelectorAll('a[href], button, input, select, textarea, [tabindex]'))
      .find(node => !node.disabled && node.tabIndex >= 0 && node.getClientRects().length > 0);
    const active = document.activeElement;
    return {first: active === focusable, insideContent: document.getElementById('content').contains(active), id: active.id};
  });
  // The skip link, once nothing precedes it in the shell (the workspace line
  // still does on branches without that fix), and never a settings control.
  expect(focus.first).toBe(true);
  expect(focus.insideContent).toBe(false);
  expect(focus.id).not.toBe('settings-theme');
  expect(await page.evaluate(() => window.scrollY)).toBe(0);

  // A person's own switch is still kept in the address for a reload.
  await page.locator('[data-settings-tab="access"]').click();
  expect(new URL(page.url()).hash).toBe('#settings-access');
  await page.reload({waitUntil: 'load'});
  await expect(page.locator('[data-settings-tab="access"]')).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#settings-access')).toBeVisible();
  expect(errors).toEqual([]);
});
