// The command menu, keyboard shortcuts and pinned/recent pages in real Chromium
// against the real dashboard. A second synthetic administrator is used so the
// pins and recent pages this spec creates never change another spec's sidebar;
// its pins are reset to the role's starting set afterwards.
const {test, expect} = require('@playwright/test');

const PERSON = 'browser-learning-reviewer';

test.beforeEach(async ({context, page, baseURL}) => {
  await context.setExtraHTTPHeaders({Origin: baseURL, 'X-Browser-Principal': PERSON});
  await context.route('**/*', route => new URL(route.request().url()).origin === new URL(baseURL).origin
    ? route.continue() : route.abort('blockedbyclient'));
  page.__errors = []; page.__posts = [];
  page.on('pageerror', error => page.__errors.push(error.message));
  page.on('console', message => {if (message.type() === 'error') page.__errors.push(message.text());});
  page.on('request', request => {if (request.method() !== 'GET') page.__posts.push(new URL(request.url()).pathname);});
});

test.afterEach(async ({page, request, baseURL}, info) => {
  await info.attach('command-menu-state', {body: await page.screenshot({fullPage: true}), contentType: 'image/png'});
  // Back to the role's starting pins (the preference's product default).
  const headers = {Origin: baseURL, 'X-Browser-Principal': PERSON};
  const current = await (await request.get('/api/v1/preferences', {headers})).json();
  const reset = await request.post('/api/v1/preferences', {headers, data: {
    expected_revision: current.revision, context: current.context, scope: 'personal', changes: {favorites: null}}});
  expect(reset.status()).toBe(200);
  expect(page.__errors).toEqual([]);
});

async function ready(page, path) {
  await page.goto(path);
  await expect(page.locator('#navfinder-dialog')).toHaveAttribute('data-navfinder-ready', 'true');
  await expect(page.locator('#shortcuts-dialog')).toHaveAttribute('data-shortcuts-ready', 'true');
}

async function command(page, query) {
  await page.keyboard.press('Control+k');
  const input = page.locator('#navfinder-input');
  await expect(input).toBeFocused();
  await input.fill(query);
}

test('commands open the page\'s own confirmations and never decide or stop anything themselves', async ({page}) => {
  await page.setViewportSize({width: 1280, height: 900});
  await ready(page, '/overview');
  await expect(page.locator('#navfinder-title')).toHaveText('Search or run a command');
  // Emergency stop: the command presses the stop control, which asks first.
  await expect(page.locator('#halt-label')).not.toHaveText('checking');
  await command(page, '> pause');
  await expect(page.locator('#navfinder-action-halt')).toHaveAttribute('aria-selected', 'true');
  await page.keyboard.press('Enter');
  await expect(page.locator('#navfinder-dialog')).not.toBeVisible();
  await expect(page.locator('#mv-confirm')).toBeVisible();
  await expect(page.locator('#mv-confirm-ok')).toHaveText('Stop work');
  await page.locator('#mv-confirm-cancel').click();
  await expect(page.locator('#mv-confirm')).not.toBeVisible();
  // Approve or reject…: a list of waiting requests that open their cards.
  await command(page, '> approve');
  await page.keyboard.press('Enter');
  await expect(page.locator('#navfinder-mode')).toBeVisible();
  const allApprovals = page.locator('#navfinder-results a[id^="navfinder-choice-"][href="/approvals"]');
  await expect(allApprovals).toBeVisible();
  for (const href of await page.locator('#navfinder-results a[id^="navfinder-choice-"]').evaluateAll(links => links.map(link => link.getAttribute('href')))) {
    expect(href).toMatch(/^\/(?:approvals(?:#approval-[A-Za-z0-9_-]+)?|flows\/[^/]+\/runs\/[^?]+\?approval_review=1)$/);
  }
  await page.keyboard.press('Escape');
  await expect(page.locator('#navfinder-mode')).toBeHidden();
  await expect(page.locator('#navfinder-dialog')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.locator('#navfinder-dialog')).not.toBeVisible();
  // Nothing the menu did sent a decision or a stop.
  expect(page.__posts.filter(path => /\/api\/v1\/(?:halt|approvals\/)/.test(path))).toEqual([]);
  // A pages-only search shows pages and no commands; New task opens the composer.
  await command(page, '/ tasks');
  await expect(page.locator('#navfinder-results a[href="/goals"]')).toBeVisible();
  await expect(page.locator('#navfinder-results [data-navfinder-action]:visible')).toHaveCount(0);
  await page.locator('#navfinder-input').fill('> new task');
  await expect(page.locator('#navfinder-action-new-task')).toHaveAttribute('aria-selected', 'true');
  await page.keyboard.press('Enter');
  // This person has no tasks yet, so Overview shows the first-task composer:
  // New task focuses it in place instead of leaving the page.
  const firstTask = page.locator('form[action="/chat/send"] textarea[name="title"]');
  await expect(page).toHaveURL(/\/overview$/);
  await expect(page.locator('#navfinder-dialog')).not.toBeVisible();
  await expect(firstTask).toBeFocused();
  // From a page without a composer, New task opens the chat composer.
  await ready(page, '/goals');
  await command(page, '> new task');
  await expect(page.locator('#navfinder-action-new-task')).toHaveAttribute('aria-selected', 'true');
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/\/chat$/);
  // The composer is the page's first field (it takes focus when it can be
  // used; this fixture has no AI service, so it waits disabled).
  await expect(page.locator('form[action="/chat/send"] textarea[name="title"]')).toBeVisible();
});

test('? opens help and shortcuts, go-to keys move between pages, and typing is never hijacked', async ({page}) => {
  await page.setViewportSize({width: 1280, height: 900});
  await ready(page, '/overview');
  // A page that starts in a text field (Overview's task field on a first
  // visit) keeps ? as a character there.
  const field = page.locator('main input[name="title"]');
  if (await field.count() && await field.evaluate(node => node === document.activeElement)) {
    await page.keyboard.press('?');
    await expect(field).toHaveValue('?');
    await expect(page.locator('#shortcuts-dialog')).not.toBeVisible();
    await field.fill('');
  }
  await page.evaluate(() => document.activeElement && document.activeElement.blur());
  await page.keyboard.press('?');
  const dialog = page.locator('#shortcuts-dialog');
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole('link', {name: 'Help and diagnostics'})).toHaveAttribute('href', '/help');
  const listed = await dialog.locator('[data-shortcut]').evaluateAll(rows => rows.map(row => row.getAttribute('data-shortcut')));
  expect(listed).toEqual(['mod+k', '/', '?', 'g h', 'g t', 'g a', 'g r', 'g s']);
  await page.keyboard.press('Escape');
  await expect(dialog).not.toBeVisible();
  // The sidebar's Help entry, right below Search, opens the same dialog.
  await page.locator('#shortcuts-open').click();
  await expect(dialog).toBeVisible();
  await page.locator('#shortcuts-close').click();
  await expect(page.locator('#shortcuts-open')).toBeFocused();
  // g then t: Tasks.
  await page.evaluate(() => document.activeElement && document.activeElement.blur());
  await page.keyboard.press('g');
  await page.keyboard.press('t');
  await expect(page).toHaveURL(/\/goals$/);
  await expect(page.locator('#navfinder-dialog')).toHaveAttribute('data-navfinder-ready', 'true');
  // Typing g, t, / or ? into a field types them.
  await page.keyboard.press('Control+k');
  await page.locator('#navfinder-input').fill('');
  await page.keyboard.type('gt/?');
  await expect(page.locator('#navfinder-input')).toHaveValue('gt/?');
  // Still on Tasks: the search only gives itself an address (?find=).
  await expect(page).toHaveURL(/\/goals\?find=gt%2F%3F$/);
  await page.keyboard.press('Escape');
  // / opens the command menu (from anywhere that is not a field).
  await page.evaluate(() => document.activeElement && document.activeElement.blur());
  await page.keyboard.press('/');
  await expect(page.locator('#navfinder-input')).toBeFocused();
  await expect(page.locator('#navfinder-input')).toHaveValue('');
  await page.keyboard.press('Escape');
});

test('pages are pinned and unpinned from the page and the command menu, reordered by keyboard, and remembered', async ({page}) => {
  await page.setViewportSize({width: 1280, height: 900});
  await ready(page, '/overview');
  const pins = page.locator('#navpins-list');
  // An administrator starts from Settings, Users and Activity log.
  await expect(pins.locator('li')).toHaveCount(3);
  const toggle = page.locator('#page-pin-toggle');
  await expect(toggle).toHaveAttribute('aria-pressed', 'false');
  await toggle.click();
  await expect(toggle).toHaveAttribute('aria-pressed', 'true');
  await expect(pins.locator('a[href="/overview"]')).toBeVisible();
  await page.reload();
  await expect(page.locator('#navpins-list a[href="/overview"]')).toBeVisible();
  // Reorder from the keyboard: Edit, then Move up on the page just pinned.
  await page.locator('#navpins-edit').focus();
  await page.keyboard.press('Enter');
  const up = page.locator('#navpins-list li[data-pin="/overview"] [data-pin-op="up"]');
  await up.focus();
  await page.keyboard.press('Enter');
  await expect(up).toBeFocused();
  await expect(page.locator('#navpins-status')).toHaveText('Moved Overview up.');
  const order = async () => page.locator('#navpins-list li').evaluateAll(items => items.map(item => item.getAttribute('data-pin')));
  expect((await order()).indexOf('/overview')).toBe(2);
  await page.reload();
  expect((await order()).indexOf('/overview')).toBe(2);
  // Unpin from the command menu.
  await expect(page.locator('#navfinder-dialog')).toHaveAttribute('data-navfinder-ready', 'true');
  await command(page, '> unpin');
  await expect(page.locator('#navfinder-action-pin')).toContainText('Unpin this page');
  await page.keyboard.press('Enter');
  await expect(page.locator('#navpins-list a[href="/overview"]')).toHaveCount(0);
  await expect(page.locator('#page-pin-toggle')).toHaveAttribute('aria-pressed', 'false');
});

test('recent pages list where the person has been, never the page shown', async ({page}) => {
  await page.setViewportSize({width: 1280, height: 900});
  for (const path of ['/spend', '/savings', '/workforce']) {
    // The page asks to be remembered once it has loaded.
    const remembered = page.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/navigation/recent');
    await ready(page, path);
    expect((await (await remembered).json()).recorded).toBe(true);
  }
  await ready(page, '/overview');
  const recent = await page.locator('[data-nav-list="recent"] a').evaluateAll(links => links.map(link => link.getAttribute('href')));
  expect(recent.slice(0, 3)).toEqual(['/workforce', '/savings', '/spend']);
  expect(recent).not.toContain('/overview');
});
