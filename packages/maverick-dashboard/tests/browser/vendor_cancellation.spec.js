const {test, expect} = require('@playwright/test');
const API = '/api/v1/vendor-onboarding/cases';

test.beforeEach(async ({context, page, baseURL}) => {
  await context.route('**/*', route => new URL(route.request().url()).origin === new URL(baseURL).origin
    ? route.continue() : route.abort('blockedbyclient'));
  page.__uncaught = [];
  page.on('pageerror', error => page.__uncaught.push(error.message));
});
test.afterEach(async ({page, context}, info) => {
  await info.attach('cancellation-rendered-state', {body: await page.screenshot({fullPage: true}), contentType: 'image/png'});
  expect(page.__uncaught).toEqual([]);
  await context.unrouteAll({behavior: 'ignoreErrors'});
});

async function ok(response) {
  expect(response.ok(), await response.text()).toBeTruthy();
  return response.json();
}
async function intake(request, name) {
  return ok(await request.post(API, {data: {vendor_name: name, document_id: 'browser-policy',
    project: 'VEND', purpose: 'Synthetic cancellation browser acceptance'}}));
}
async function open(page, row, width) {
  await page.setViewportSize({width, height: 850});
  await page.goto('/third-party/vendor-onboarding?case=' + row.id);
  await expect(page.locator('#vo-message')).toContainText('Linked request loaded');
}
async function confirm(page, reason) {
  await page.locator('#vo-cancellation-reason').fill(reason);
  await page.locator('#vo-cancellation-confirm').focus();
  await page.locator('#vo-cancellation-confirm').press('Space');
  await expect(page.locator('#vo-cancellation-confirm')).toBeChecked();
}
async function fitsAndCapture(page, info) {
  const size = await page.evaluate(() => ({client: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth}));
  expect(size.scroll).toBeLessThanOrEqual(size.client + 1);
  const presentation = await page.locator('#vo-cancellation-confirm').evaluate(input => {
    const box = input.getBoundingClientRect(), text = input.closest('label').querySelector('span').getBoundingClientRect();
    return {gap: text.left - box.right, width: box.width,
      whitespace: getComputedStyle(document.getElementById('vo-cancellation-status')).whiteSpace};
  });
  expect(presentation.width).toBeLessThan(30);
  expect(presentation.gap).toBeGreaterThanOrEqual(0);
  expect(presentation.gap).toBeLessThan(17);
  expect(presentation.whitespace).toBe('pre-line');
  await info.attach('cancellation-controls', {body: await page.locator('section[aria-labelledby="vo-cancellation-title"]').screenshot(), contentType: 'image/png'});
}

test('mobile cancellation requires a reason and explicit decision, persists on reload, and dispatches nothing', async ({page, request}, info) => {
  const before = await ok(await request.get('/__browser_fixture'));
  const row = await intake(request, 'Browser pre-dispatch cancellation');
  await open(page, row, 320);
  let attempts = 0;
  page.on('request', request => { if (request.method() === 'POST' && request.url().endsWith('/cancel')) attempts++; });
  await page.locator('#vo-cancel').click();
  await expect(page.locator('#vo-message')).toContainText('Enter a reason');
  await page.locator('#vo-cancellation-reason').fill('The request is no longer needed');
  await page.locator('#vo-cancel').click();
  await expect(page.locator('#vo-message')).toContainText('Confirm that cancellation');
  expect(attempts).toBe(0);
  await confirm(page, 'The request is no longer needed');
  await page.locator('#vo-cancel').click();
  await expect(page.locator('#vo-cancellation-status')).toContainText('No ticket creation was dispatched');
  await expect(page.locator('#vo-cancel')).toBeDisabled();
  await expect(page.locator('#vo-collect')).toBeDisabled();
  expect(attempts).toBe(1);
  await page.reload();
  await expect(page.locator('#vo-cancellation-status')).toContainText('The request is no longer needed');
  await expect(page.locator('#vo-execute')).toBeDisabled();
  expect((await ok(await request.get('/__browser_fixture'))).ticket_creates).toBe(before.ticket_creates);
  await fitsAndCapture(page, info);
});

test('desktop cancellation preserves the ticket from an in-app delivery and permits readback without acceptance', async ({page, request}, info) => {
  const before = await ok(await request.get('/__browser_fixture'));
  const row = await intake(request, 'Browser delivered cancellation');
  await open(page, row, 1280);
  await page.locator('#vo-collect').click();
  await expect(page.locator('#vo-assess')).toBeEnabled();
  await page.locator('#vo-assess').click();
  await expect(page.locator('#vo-rationale')).toBeEnabled();
  await page.locator('#vo-rationale').fill('Synthetic reviewer approved this local ticket fixture');
  await page.locator('#vo-review-approve').click();
  await expect(page.locator('#vo-prepare')).toBeEnabled();
  await page.locator('#vo-prepare').click();
  await expect(page.locator('#vo-approve')).toBeEnabled();
  await expect(page.locator('#vo-operation')).toContainText('Lightwork recommends this; nothing happens until you approve it.');
  // The plain approval card: target, contents, before/after, effects, open
  // assumptions and who approves until when, then the full reviewed ticket.
  await expect(page.locator('#vo-operation')).toContainText('in Jira project VEND.');
  await expect(page.locator('#vo-operation')).toContainText('What the ticket contains:');
  await expect(page.locator('#vo-operation')).toContainText('Before: ');
  await expect(page.locator('#vo-operation')).toContainText('After: ');
  await expect(page.locator('#vo-operation')).toContainText("This can't be undone automatically:");
  await expect(page.locator('#vo-operation')).toContainText("Things Lightwork couldn't confirm:");
  await expect(page.locator('#vo-operation')).toContainText("You're approving as browser-reviewer. This approval expires");
  await expect(page.locator('#vo-operation')).toContainText('THE TICKET');
  await page.locator('#vo-approve').click();
  await expect(page.locator('#vo-execute')).toBeEnabled();
  await page.locator('#vo-execute').click();
  await expect(page.locator('#vo-accept')).toBeEnabled();
  await confirm(page, 'Stop local work and retain the existing ticket for review');
  await page.locator('#vo-cancel').click();
  await expect(page.locator('#vo-cancellation-status')).toContainText('remains recorded as an external effect');
  await expect(page.locator('#vo-outcome')).toContainText('Cancelled request; no acceptance decision');
  await expect(page.locator('#vo-accept')).toBeDisabled();
  await expect(page.locator('#vo-execute')).toBeDisabled();
  await page.getByRole('button', {name: 'Recheck retained ticket', exact: true}).click();
  await expect(page.locator('#vo-message')).toContainText('Saved');
  const final = await ok(await request.get(API + '/' + row.id));
  expect(final.stage).toBe('cancelled');
  expect(final.operation.state).toBe('verified');
  expect(final.outcome).toBeNull();
  expect((await ok(await request.get('/__browser_fixture'))).ticket_creates).toBe(before.ticket_creates + 1);
  await fitsAndCapture(page, info);
});

test('failed cancellation preserves the reason and stale state requires a refreshed human decision', async ({page, request}, info) => {
  const row = await intake(request, 'Browser cancellation interruption');
  await open(page, row, 375);
  const reason = 'Preserve this decision through an interrupted request';
  await confirm(page, reason);
  let attempts = 0;
  // Only a server reason already written as a plain sentence reaches the
  // person (mvPlainDetail), so the synthetic reason ends with a full stop.
  await page.route('**/cases/' + row.id + '/cancel', async route => {
    if (++attempts === 1) return route.fulfill({status: 503, contentType: 'application/json',
      body: JSON.stringify({detail: {code: 'fixture_unavailable', message: 'Synthetic connection interruption.'}})});
    return route.continue();
  });
  await page.locator('#vo-cancel').click();
  await expect(page.locator('#vo-message')).toContainText('Synthetic connection interruption');
  await expect(page.locator('#vo-cancellation-reason')).toHaveValue(reason);
  await expect(page.locator('#vo-cancellation-confirm')).toBeChecked();
  await ok(await request.post(API + '/' + row.id + '/collect-evidence', {data: {expected_revision: row.revision}}));
  await page.locator('#vo-cancel').click();
  await expect(page.locator('#vo-message')).toContainText('Someone else updated this request, so the latest version');
  await expect(page.locator('#vo-cancellation-reason')).toHaveValue('');
  await expect(page.locator('#vo-cancellation-confirm')).not.toBeChecked();
  await confirm(page, 'Reviewed the refreshed request; cancel local work');
  await page.locator('#vo-cancel').click();
  await expect(page.locator('#vo-cancellation-status')).toContainText('No ticket creation was dispatched');
  expect(attempts).toBe(3);
  await fitsAndCapture(page, info);
});
