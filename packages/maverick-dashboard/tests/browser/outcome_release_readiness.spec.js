const {test, expect} = require('@playwright/test');

// Every pilot change is saved through its complete review: read it, confirm, then save.
async function saveReviewed(page) {
  const review = page.locator('#op-guided-review');
  await expect(review.getByRole('heading', {name: 'Review every detail before saving'})).toBeVisible();
  const save = review.getByRole('button', {name: 'Save reviewed change'});
  await expect(save).toBeDisabled();
  await review.getByRole('checkbox', {name: 'I reviewed the complete source, scope and proposed change.'}).check();
  await save.click();
}
const CONTROLS = '/api/v1/outcome-pilot-controls';

test('an operator can recover, freeze, and read an ordinary pilot in a new browser session', async ({page, context, browser, baseURL}) => {
  test.setTimeout(90000);
  await context.setExtraHTTPHeaders({Origin: baseURL, 'X-Browser-Principal': 'browser-outcome-readiness-owner'});
  await page.goto('/outcome-pilots');
  expect((await page.request.get('/api/v1/outcome-pilots/independent-review')).status()).toBe(403);
  await page.locator('#op-plan-details > summary').click();
  const status = page.locator('#op-candidate-status');
  const candidate = page.locator('#op-candidate');
  await expect(status).toContainText('installation administrator');
  await expect(candidate).toBeDisabled();
  await expect(page.locator('#op-plan [name="title"]')).toBeEnabled();

  const interrupted = route => route.fulfill({status: 503, contentType: 'application/json',
    body: JSON.stringify({detail: 'Synthetic release service interruption'})});
  await page.route('**/api/v1/outcome-pilots/release-candidates', interrupted);
  await page.locator('#op-candidate-refresh').click();
  await expect(status).toContainText('Check release readiness again');
  await expect(status).not.toContainText('Synthetic release service interruption');
  await expect(candidate).toBeDisabled();
  await page.unroute('**/api/v1/outcome-pilots/release-candidates', interrupted);
  await page.locator('#op-candidate-refresh').click();
  await expect(status).toContainText('installation administrator');

  await page.getByText('Prepare a task without starting it', {exact: true}).click();
  const preparation = page.locator('#op-prepare');
  for (let i = 1; i <= 4; i++) {
    await preparation.locator('[name="title"]').fill('Readiness case ' + i);
    await page.locator('#op-specialist').selectOption({index: 1});
    await preparation.locator('[name="description"]').fill('Held browser fixture task ' + i);
    await preparation.getByRole('button', {name: 'Save prepared task'}).click();
    await saveReviewed(page);
    await expect(page.locator('#op-prepared')).toContainText('Prepared: Readiness case ' + i);
  }
  const plan = page.locator('#op-plan');
  await plan.locator('[name="title"]').fill('Workflow pilot despite release setup');
  await plan.locator('[name="customer"]').fill('Synthetic internal team');
  await plan.locator('[name="workflow"]').fill('Review held tasks');
  await plan.locator('[name="criteria"]').fill('A human checks the saved work');
  for (let i = 0; i < 4; i++) {
    await page.locator('#op-planned-cases select').nth(i).selectOption({label: 'Task: Readiness case ' + (i + 1)});
  }
  const interruptedSave = route => route.fulfill({status: 503, contentType: 'application/json',
    body: JSON.stringify({detail: 'Synthetic pilot save interruption'})});
  // The interruption hits the plan's review request; nothing is saved.
  await page.route('**' + CONTROLS + '/review', interruptedSave);
  await plan.getByRole('button', {name: 'Save and freeze plan'}).click();
  await expect(page.locator('#op-status')).toContainText('Could not save that.');
  await expect(page.locator('#op-status')).not.toContainText('Synthetic pilot save interruption');
  await expect(plan.locator('[name="title"]')).toHaveValue('Workflow pilot despite release setup');
  await expect(page.locator('#op-planned-cases select').first()).toHaveValue(/goal:/);
  await page.unroute('**' + CONTROLS + '/review', interruptedSave);
  const created = page.waitForResponse(response => response.request().method() === 'POST' &&
    new URL(response.url()).pathname === CONTROLS + '/save');
  await plan.getByRole('button', {name: 'Save and freeze plan'}).click();
  await saveReviewed(page);
  const result = await created;
  expect(result.status()).toBe(200);
  const outcome = await result.json();
  expect(outcome.confirmed).toBe(true);
  const id = new URL(outcome.href, baseURL).searchParams.get('pilot');
  expect(id).toMatch(/^OPL-[a-f0-9]{48}$/);
  await expect(page.locator('#op-report')).toContainText('Workflow pilot despite release setup');
  await expect(page.locator('#op-report')).toContainText('0 accepted / 4 planned');
  await expect(page.locator('#op-report')).not.toContainText('Frozen improvement release');
  const report = await (await page.request.get('/api/v1/outcome-pilots/' + id)).json();
  expect(report).toMatchObject({id, title: 'Workflow pilot despite release setup', state: 'frozen'});
  expect(report.release_binding).toBeNull();

  const reopened = await browser.newContext({baseURL, extraHTTPHeaders: {
    Origin: baseURL, 'X-Browser-Principal': 'browser-outcome-readiness-owner',
  }});
  try {
    const secondPage = await reopened.newPage();
    await secondPage.goto('/outcome-pilots');
    await secondPage.locator('#op-selected').selectOption(id);
    await expect(secondPage.locator('#op-report')).toContainText('Workflow pilot despite release setup');
    await expect(secondPage.locator('#op-report')).toContainText('0 accepted / 4 planned');
  } finally {
    await reopened.close();
  }
});
