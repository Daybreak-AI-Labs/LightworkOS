const {test, expect} = require('@playwright/test');

test('a provider failure stops the task and offers a connection route', async ({page, request}) => {
  const created = await request.post('/__browser_fixture/chat');
  expect(created.status(), await created.text()).toBe(200);
  const {goal_id} = await created.json();
  await page.goto(`/chat/goal/${goal_id}`);

  const failed = await request.post(`/__browser_fixture/chat/${goal_id}/provider-fail`);
  expect(failed.status(), await failed.text()).toBe(200);
  await expect(page.locator('#status')).toHaveAttribute('data-status', 'blocked');
  await expect(page.locator('#status')).toHaveText('Stopped');
  await expect(page.locator('#halt-card')).toBeVisible();
  await expect(page.locator('#halt-reason')).toContainText("couldn't reach the AI service");
  await expect(page.locator('#halt-action-link')).toHaveAttribute('href', '/settings?focus=ai-provider#settings-integrations');
  await expect(page.locator('#halt-resume')).toHaveText('Review retry after checking AI');
  await expect(page.locator('#halt-budget')).toBeHidden();
  await expect(page.locator('[data-budget-launch]')).toBeHidden();

  await page.reload();
  await expect(page.locator('#status')).toHaveText('Stopped');
  await expect(page.locator('#halt-action-link')).toHaveAttribute('href', '/settings?focus=ai-provider#settings-integrations');
  await expect(page.locator('#halt-resume')).toHaveText('Review retry after checking AI');
  await expect(page.locator('#halt-budget')).toBeHidden();
});

test('a prepared workflow pilot keeps its start action and allowance review after replay', async ({page, request}) => {
  const created = await request.post('/__browser_fixture/chat');
  const {goal_id} = await created.json();
  expect((await request.post(`/__browser_fixture/chat/${goal_id}/pilot-prepared`)).status()).toBe(200);
  await page.goto(`/chat/goal/${goal_id}`);
  await expect(page.locator('#halt-title')).toHaveText('Ready to start');
  await expect(page.locator('#halt-resume')).toHaveText('Review task start');
  await expect(page.locator('[data-budget-launch]')).toBeVisible();
  await page.reload();
  await expect(page.locator('#halt-resume')).toHaveText('Review task start');
  await expect(page.locator('[data-budget-launch]')).toBeVisible();
});
