const {test, expect} = require('@playwright/test');

test.beforeEach(async ({context, page, baseURL}) => {
  await context.route('**/*', route => new URL(route.request().url()).origin === new URL(baseURL).origin
    ? route.continue() : route.abort('blockedbyclient'));
  page.__errors = [];
  page.on('pageerror', error => page.__errors.push(error.message));
  page.on('console', message => { if (message.type() === 'error') page.__errors.push(message.text()); });
});

test.afterEach(async ({page}, info) => {
  const screenshot = info.outputPath('learned-skill-admission.png');
  await page.screenshot({path: screenshot, fullPage: true});
  await info.attach('learned-skill-admission', {path: screenshot, contentType: 'image/png'});
  expect(page.__errors).toEqual([]);
});

test('administrator reviews a local suggestion, admits its exact version and withdraws it', async ({page, request}) => {
  const setup = await request.post('/__browser_fixture/learned-skills/setup');
  expect(setup.ok()).toBeTruthy();
  const source = await setup.json();
  await page.setViewportSize({width: 1280, height: 900});
  await page.goto('/skills');
  const suggestion = page.locator('#to-learned-list');
  await expect(suggestion).toContainText('Customer renewal timing');
  await expect(suggestion).toContainText('Check customer renewal timing with the account owner');
  await expect(suggestion.locator('a[href="/chat/goal/' + source.goal_id + '"]')).toBeVisible();
  const denied = await request.get('/api/v1/skills/learned-candidates',
    {headers: {'X-Browser-Principal': 'browser-colleague'}});
  expect(denied.status()).toBe(403);

  // Adding is a reviewed change: the exact instructions are shown, and the add stays
  // disabled until the administrator confirms they read them.
  await suggestion.getByRole('button', {name: 'Review adding this skill'}).click();
  const review = page.locator('#to-learned-review');
  await expect(review.getByRole('heading', {name: 'Review this skill before adding it'})).toBeVisible();
  const add = review.getByRole('button', {name: 'Add reviewed skill'});
  await expect(add).toBeDisabled();
  await review.getByLabel('I reviewed this exact change and all displayed instructions.').check();
  await add.click();
  await expect(page.locator('#to-learned-status')).toContainText('Your original reviewed skill was added.');
  await expect(page.locator('#to-learned-added')).toContainText(/customer renewal timing/i);
  await expect(page.locator('#installed-skills [data-skill="customer-renewal-timing"]')).toBeVisible();

  // Hold the page's second load request so the removal button exists while
  // the panel is still loading; a click then must wait, not be dropped.
  await page.route('**/api/v1/skills/learned-requests', async route => {
    await new Promise(resolve => setTimeout(resolve, 1500));
    await route.continue();
  });
  await page.reload();
  await expect(page.locator('#to-learned-added')).toContainText(/customer renewal timing/i);
  await expect(page.locator('#to-learned-list')).toBeEmpty();
  await page.locator('#to-learned-added').getByRole('button', {name: /Review removal of customer renewal timing/i}).click();
  await expect(review.getByRole('heading', {name: 'Review this skill removal'})).toBeVisible();
  const remove = review.getByRole('button', {name: 'Remove reviewed skill'});
  await expect(remove).toBeDisabled();
  await review.getByLabel('I reviewed this exact change and all displayed instructions.').check();
  await remove.click();
  await expect(page.locator('#to-learned-result')).toContainText('Your original skill change');
  await expect(page.locator('#installed-skills [data-skill="customer-renewal-timing"]')).toHaveCount(0);

  await page.setViewportSize({width: 320, height: 900});
  const bounds = await page.evaluate(() => ({width: document.documentElement.clientWidth,
    scroll: document.documentElement.scrollWidth}));
  expect(bounds.scroll).toBeLessThanOrEqual(bounds.width + 1);
});
