const {test, expect} = require('@playwright/test');

test('automations renders saved starts and loads schedule setup after the shared UI initializes', async ({page, context, baseURL}) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await context.route('**/*', route => new URL(route.request().url()).origin === new URL(baseURL).origin
    ? route.continue() : route.abort());
  await page.route('**/api/v1/schedules', route => route.fulfill({json: {
    context: 'synthetic-workspace',
    schedules: [{id: 7, title: 'Daily intake review', cron: '0 9 * * *', zone: 'UTC', state: 'active'}],
  }}));
  await page.route('**/api/v1/triggers', route => route.fulfill({json: {
    secret_configured: true,
    triggers: [{name: 'New request', template: 'triage', template_title: 'Triage new requests'}],
  }}));
  await page.route('**/api/v1/automation-runs?*', route => route.fulfill({json: {summary: {}, runs: []}}));
  await page.route('**/api/v1/schedules/options', route => route.fulfill({json: {
    workflows: [{name: 'triage', title: 'Triage new requests', params: ['subject']}],
    tasks: [], zones: ['UTC'],
  }}));

  await page.goto('/automations');
  await expect(page.locator('#auto-sched-list')).toContainText('Daily intake review');
  await expect(page.locator('#auto-trig-list')).toContainText('New request');
  await page.locator('#auto-new-sched > summary').focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('#auto-new-workflow option[value="triage"]')).toHaveText('Triage new requests');
  await page.locator('#auto-new-workflow').selectOption('triage');
  await expect(page.locator('#auto-new-params input[data-param="subject"]')).toBeVisible();
  expect(errors).toEqual([]);
});

test('an RSS source can be attached to a published flow and checked from the page', async ({page, context, baseURL}) => {
  const errors = [];
  const posts = [];
  let created = false;
  page.on('pageerror', error => errors.push(error.message));
  await context.route('**/*', route => new URL(route.request().url()).origin === new URL(baseURL).origin
    ? route.continue() : route.abort());
  await page.route('**/api/v1/templates', route => route.fulfill({json: {templates: []}}));
  await page.route('**/api/v1/flows', route => route.fulfill({json: {flows: [
    {id: 'draft', name: 'Draft flow', published: false},
    {id: 'ready', name: 'Review new posts', published: true},
  ]}}));
  await page.route('**/api/v1/event-triggers', async route => {
    if (route.request().method() === 'POST') {
      posts.push(route.request().postDataJSON());
      created = true;
      await route.fulfill({status: 201, json: {name: 'new-posts'}});
    } else {
      await route.fulfill({json: {sources: ['rss', 'custom_source'], triggers: created ? [{
        name: 'new-posts', flow: 'ready', source: 'rss', config: {url: 'https://example.org/feed.xml'},
        cursor: '', interval_seconds: 0,
      }] : []}});
    }
  });
  await page.route('**/api/v1/event-triggers/history?*', route => route.fulfill({json: {history: []}}));
  await page.route('**/api/v1/event-triggers/outcomes', route => route.fulfill({json: {outcomes: {}}}));
  await page.route('**/api/v1/event-triggers/poll', route => route.fulfill({json: {
    polled: 1, triggers: [{name: 'new-posts', fired: [], fired_flows: [12], notes: []}],
  }}));
  await page.goto('/automations');
  await page.locator('#auto-event-setup > summary').click();
  await page.locator('#auto-event-target-kind').selectOption('flow');
  await expect(page.locator('#auto-event-template option[value="ready"]')).toHaveText('Review new posts');
  await expect(page.locator('#auto-event-template option[value="draft"]')).toHaveCount(0);
  await page.locator('#auto-event-template').selectOption('ready');
  await page.locator('#auto-event-source').selectOption('rss');
  await expect(page.locator('#auto-source-url')).toBeVisible();
  await expect(page.locator('#auto-source-url')).toHaveAttribute('required', '');
  await page.locator('#auto-source-url').fill('https://example.org/feed.xml');
  await page.locator('#auto-event-name').fill('New posts');
  await page.locator('#auto-event-create').click();
  await expect(page.locator('#auto-event-list')).toContainText('new-posts');
  expect(posts).toEqual([{
    source: 'rss', config: {url: 'https://example.org/feed.xml'},
    name: 'New posts', interval_seconds: 0, params: {}, flow: 'ready',
  }]);
  await page.locator('#auto-event-poll').click();
  await expect(page.locator('#auto-event-msg')).toContainText('1 run started');
  expect(errors).toEqual([]);
});
