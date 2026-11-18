const {test, expect} = require('@playwright/test');

const catalogPath = '/api/v1/starter-teams';
const catalog = {
  context: 'synthetic-workspace',
  preview_only: true,
  teams: [],
  setups: [],
  synthetic_demo: {id: 'generic_synthetic_demo', label: 'Generic synthetic example'},
};

function watchRequests(page) {
  const requests = [];
  page.on('request', request => {
    const {pathname} = new URL(request.url());
    if (pathname.startsWith(catalogPath) || pathname === '/api/v1/starter-team-schedules') {
      requests.push([request.method(), pathname]);
    }
  });
  return requests;
}

test('an empty preview-only catalogue offers a read-only fictional example', async ({page}) => {
  const requests = watchRequests(page);
  await page.route('**' + catalogPath, route => route.fulfill({json: catalog}));
  const samplePath = catalogPath + '/preview/generic_synthetic_demo';
  await page.route('**' + samplePath, route => route.fulfill({json: {
    mode: 'synthetic_preview', saved: false,
    output: {deliverable: 'Fictional review package', findings: []},
  }}));
  await page.goto('/starter-teams');
  await expect(page.locator('#st-message')).toContainText('No teams are available in this workspace');
  await expect(page.locator('#st-team')).toBeDisabled();
  await expect(page.locator('#st-preview-panel')).toBeHidden();
  await expect(page.locator('#st-setup-panel')).toBeHidden();
  await expect(page.locator('#st-schedules-panel')).toBeHidden();
  const sample = page.getByRole('button', {name: 'Preview generic example'});
  await expect(sample).toBeEnabled();
  expect(requests).toEqual([['GET', catalogPath]]);
  await sample.click();
  const result = page.locator('#st-generic-result');
  await expect(result).toContainText('Fictional review package');
  await expect(result).toContainText('not saved');
  expect(requests).toEqual([['GET', catalogPath], ['GET', samplePath]]);
});

test('a catalogue timeout can be retried without loading schedules', async ({page}) => {
  const requests = watchRequests(page);
  await page.clock.install();
  let attempts = 0;
  await page.route('**' + catalogPath, async route => {
    if (++attempts === 1) return; // Keep the first response pending until the client times out.
    await route.fulfill({json: catalog});
  });
  const firstRequest = page.waitForRequest(request => new URL(request.url()).pathname === catalogPath);
  await page.goto('/starter-teams');
  await firstRequest;
  await page.clock.fastForward(11000);
  const retry = page.getByRole('button', {name: 'Retry loading teams'});
  await expect(page.locator('#st-message')).toContainText('Loading teams took too long');
  await expect(retry).toBeEnabled();
  await expect(page.getByRole('button', {name: 'Preview generic example'})).toBeHidden();
  await retry.click();
  await expect(page.getByRole('button', {name: 'Preview generic example'})).toBeEnabled();
  expect(requests).toEqual([['GET', catalogPath], ['GET', catalogPath]]);
  await expect(page.locator('#st-schedules-panel')).toBeHidden();
});
