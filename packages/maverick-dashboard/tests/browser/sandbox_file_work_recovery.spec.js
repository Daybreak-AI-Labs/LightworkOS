// Real Permissions template in Chromium with synthetic first-run Docker state.
// The API mutation and policy precedence are covered by Python integration tests.
const {test, expect} = require('@playwright/test');

test.skip(process.env.LIGHTWORK_BROWSER_SHOW_VENDOR_SETUP !== '1',
  'Synthetic first-run sandbox state requires LIGHTWORK_BROWSER_SHOW_VENDOR_SETUP=1.');

test.beforeEach(async ({context, baseURL}) => {
  await context.route('**/*', route => new URL(route.request().url()).origin === new URL(baseURL).origin
    ? route.continue() : route.abort('blockedbyclient'));
});

function status(backend, blocked = ['shell', 'write_file', 'apply_patch', 'str_replace_editor'], other = []) {
  return {
    backend,
    backends: {
      local: {available: true},
      docker: {available: true},
      podman: {available: false},
    },
    file_work: {blocked_tools: blocked, other_policy_blocks: other},
  };
}

test('local first run explains why file work needs a container', async ({page}) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/api/v1/sandbox/status', route => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(status('local')),
  }));

  await page.goto('/permissions');
  const card = page.locator('#file-work-card');
  await expect(card).toBeVisible();
  await expect(card).toContainText('Start Docker or Podman');
  await expect(page.locator('#file-work-enable')).toBeHidden();
  expect(errors).toEqual([]);
});

test('Docker recovery asks first, checks the readback, and keeps other rules visible', async ({page}) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  let current = status('docker');
  const writes = [];
  await page.route('**/api/v1/sandbox/status', route => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(current),
  }));
  await page.route('**/api/v1/sandbox/file-work/enable', route => {
    writes.push(route.request().postDataJSON());
    current = status('docker', [], ['shell']);
    return route.fulfill({status: 200, contentType: 'application/json',
      body: JSON.stringify({backend: 'docker', file_work: current.file_work})});
  });

  await page.goto('/permissions');
  const button = page.locator('#file-work-enable');
  await expect(button).toBeVisible();
  await expect(button).toHaveText('Allow file work in Docker container');
  await button.click();
  await expect(page.locator('#mv-confirm-msg')).toContainText('run programs and change files');
  await page.locator('#mv-confirm-cancel').click();
  expect(writes).toEqual([]);

  await button.click();
  await page.locator('#mv-confirm-ok').click();
  await expect(page.locator('#file-work-card')).toContainText('other organization rules');
  await expect(button).toBeHidden();
  expect(writes).toEqual([{confirm: true}]);
  expect(errors).toEqual([]);
});
