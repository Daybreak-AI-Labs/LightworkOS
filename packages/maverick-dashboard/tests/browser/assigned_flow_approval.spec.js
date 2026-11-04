const {test, expect} = require('@playwright/test');

test('assigned reviewer finds the paused flow, reviews exact values, and records one decision', async ({page, context, request, baseURL}) => {
  await context.route('**/*', route => new URL(route.request().url()).origin === new URL(baseURL).origin
    ? route.continue() : route.abort('blockedbyclient'));
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));

  const seeded = await request.post('/__browser_fixture/flow-approval/setup');
  expect(seeded.status()).toBe(200);
  const {flow_id: flowId, run_id: runId, provider_calls: providerCalls} = await seeded.json();
  expect(providerCalls).toBe(0);

  await page.goto('/approvals');
  const approval = page.locator(`#flow-approval-${runId}`);
  await expect(approval).toContainText('Approve paying Acme Corp 5000?');
  await expect(approval).not.toContainText('{{vendor}}');
  await expect(page.locator('body')).not.toContainText('OWNER-PRIVATE-DATA');

  await page.goto('/action-center');
  const item = page.locator('#ac-items article').filter({hasText: 'Approve paying Acme Corp 5000?'});
  await expect(item).toContainText('Assigned to you');
  await item.getByRole('link', {name: 'Review', exact: true}).click();
  await expect(page).toHaveURL(new RegExp(`/flows/${flowId}/runs/${runId}\\?approval_review=1$`));
  await expect(page.locator('#fr-title')).toHaveText('Flow approval request');
  await expect(page.locator('.fr__review[aria-label="What you are approving"]'))
    .toContainText('Approve paying Acme Corp 5000?');
  await expect(page.locator('#fr-steps')).toBeHidden();
  await expect(page.locator('body')).not.toContainText('OWNER-PRIVATE-DATA');

  const decision = page.waitForResponse(response => response.url().endsWith(`/flows/runs/${runId}/resume`)
    && response.request().method() === 'POST');
  await page.locator('#fr-actions').getByRole('button', {name: 'Approve', exact: true}).click();
  expect((await decision).status()).toBe(200);
  await expect(page.locator('#fr-status')).toHaveText('Decision recorded');
  await expect(page.locator('#fr-actions')).toContainText('The flow owner can follow what happens next.');
  await expect(page.locator('#fr-actions').getByRole('button', {name: 'Approve'})).toHaveCount(0);
  await expect(page.locator('#fr-actions').getByRole('button', {name: 'Reject'})).toHaveCount(0);
  await expect(page.locator('#fr-actions').getByRole('link', {name: 'Back to Approvals'})).toBeVisible();
  expect(errors).toEqual([]);
});
