const {test, expect} = require('@playwright/test');

async function fixture(request) {
  const response = await request.post('/__browser_fixture/conversation-share');
  expect(response.status(), await response.text()).toBe(200);
  return response.json();
}

async function mint(request, goalId) {
  const previewResponse = await request.post(`/api/v1/goals/${goalId}/share/preview?scope=conversation`, {data: {}});
  expect(previewResponse.status(), await previewResponse.text()).toBe(200);
  const preview = await previewResponse.json();
  const response = await request.post(`/api/v1/goals/${goalId}/share`, {data: {
    confirm: true, scope: 'conversation', source_sha256: preview.source.sha256,
    lifetime_seconds: 3600, label: 'Reviewed conversation'
  }});
  expect(response.status(), await response.text()).toBe(201);
  return response.json();
}

test('owner reviews full conversation, recipient reads exact transcript, and owner revokes it', async ({browser, page, request}) => {
  const {goal_id} = await fixture(request);
  await page.goto(`/chat/goal/${goal_id}`);
  await page.locator('#share-panel summary').click();
  await expect(page.locator('#share-scope')).toHaveValue('result');
  await page.locator('#share-scope').selectOption('conversation');
  await page.getByRole('button', {name: 'Review share link'}).click();
  const review = page.getByRole('region', {name: 'Review public link'});
  await expect(review).toContainText('What can we automate first?');
  await expect(review).toContainText('Which location matters?');
  await expect(review).toContainText('Chattanooga');
  await expect(review).toContainText('Approved initial answer.');
  await expect(review).toContainText('Build the next step');
  await expect(review).toContainText('Start with the next step.');
  await expect(review).not.toContainText('INTERNAL ROOT NOTES');
  await expect(review).not.toContainText('PRIVATE ATTACHMENT BODY');
  expect((await (await request.get(`/api/v1/goals/${goal_id}/share`)).json()).links).toHaveLength(0);

  await page.getByRole('button', {name: 'Create this public link'}).click();
  await expect(page.locator('#share-url')).toBeVisible();
  const url = await page.locator('#share-url').inputValue();
  const recipient = await browser.newContext({extraHTTPHeaders: {'X-Browser-Principal': 'browser-colleague'}});
  try {
    const recipientPage = await recipient.newPage();
    await recipientPage.goto(url);
    await expect(recipientPage.getByRole('region', {name: 'Shared conversation'}).locator('.turn')).toHaveCount(5);
    const transcript = recipientPage.getByRole('region', {name: 'Shared conversation'});
    await expect(transcript).toContainText('What can we automate first?');
    await expect(transcript).toContainText('Which location matters?');
    await expect(transcript).toContainText('Chattanooga');
    await expect(transcript).toContainText('Approved initial answer.');
    await expect(transcript).toContainText('Start with the next step.');
    await expect(recipientPage.locator('body')).not.toContainText('INTERNAL ROOT NOTES');
    await expect(recipientPage.locator('body')).not.toContainText('PRIVATE ATTACHMENT BODY');

    await page.getByRole('button', {name: 'Revoke', exact: true}).click();
    await page.getByRole('button', {name: 'Revoke link', exact: true}).click();
    await expect(page.locator('#share-list li')).toContainText('revoked');
    const revoked = await recipientPage.goto(url);
    expect(revoked.status()).toBe(404);
  } finally {
    await recipient.close();
  }
});

test('changed approved source and rejected release fail closed on existing conversation links', async ({request}) => {
  const changed = await fixture(request);
  const changedLink = await mint(request, changed.goal_id);
  expect((await request.get(changedLink.url)).status()).toBe(200);
  expect((await request.post(`/__browser_fixture/conversation-share/${changed.root_id}/change-source`)).status()).toBe(200);
  expect((await request.get(changedLink.url)).status()).toBe(404);
  const changedList = await (await request.get(`/api/v1/goals/${changed.goal_id}/share`)).json();
  expect(changedList.links[0].state).toBe('source changed');

  const rejected = await fixture(request);
  const rejectedLink = await mint(request, rejected.goal_id);
  expect((await request.get(rejectedLink.url)).status()).toBe(200);
  expect((await request.post(`/__browser_fixture/conversation-share/${rejected.root_id}/reject`)).status()).toBe(200);
  expect((await request.get(rejectedLink.url)).status()).toBe(404);
});

test('lost owner access clears a reviewed preview and a fresh authenticated load recovers', async ({page, context, request}) => {
  const {goal_id} = await fixture(request);
  await page.goto(`/chat/goal/${goal_id}`);
  await page.locator('#share-panel summary').click();
  await page.locator('#share-scope').selectOption('conversation');
  await context.setExtraHTTPHeaders({'X-Browser-Principal': 'browser-colleague'});
  await page.getByRole('button', {name: 'Review share link'}).click();
  await expect(page.locator('body')).toContainText('This task is read-only');
  await expect(page.locator('#share-create')).toBeDisabled();
  await expect(page.getByRole('region', {name: 'Review public link'})).toBeHidden();
  expect((await (await request.get(`/api/v1/goals/${goal_id}/share`)).json()).links).toHaveLength(0);

  await context.setExtraHTTPHeaders({'X-Browser-Principal': 'browser-reviewer'});
  await page.reload();
  await page.locator('#share-panel summary').click();
  await page.locator('#share-scope').selectOption('conversation');
  await page.getByRole('button', {name: 'Review share link'}).click();
  await expect(page.getByRole('region', {name: 'Review public link'})).toContainText('Approved initial answer.');
});
