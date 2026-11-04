const {test, expect} = require('@playwright/test');

const jd = `Accounts Payable Specialist

Own vendor invoices and payment preparation.

- Process vendor invoices against purchase orders and receipts
- Reconcile supplier statements and flag discrepancies
- Prepare weekly payment runs for human approval
- Maintain vendor records for the monthly close`;

test('job description matching and drafting tell the truth in Agent Factory', async ({page}) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('/agents');
  await page.locator('#jd-card summary').click();
  await page.locator('#jd-text').fill(jd);
  await page.locator('#jd-match').click();
  await expect(page.locator('#jd-results .panel').first()).toBeVisible();
  await expect(page.locator('#jd-results')).not.toContainText('100% match');
  await expect(page.locator('#jd-results')).toContainText('shared terms');
  const blocked = page.locator('#jd-results .jd-hire-btn:disabled');
  if (await blocked.count()) await expect(page.locator('#jd-results')).toContainText('Review setup');

  await page.locator('#jd-draft').click();
  await page.locator('#mvf-title').fill('Accounts Payable Specialist');
  await page.locator('#mv-form-ok').click();
  await expect(page).toHaveURL(/\/agents\?new=1/);
  await expect(page.locator('#f-description')).toHaveValue('Accounts Payable Specialist');
  await expect(page.locator('#agent-msg')).toContainText('bullet points');
  await expect(page.locator('#wf-steps .wf-name').first()).toHaveValue(/Process vendor invoices/);
  expect(errors).toEqual([]);
});

test('built-in specialist editor does not offer actions or risk above its base', async ({page}) => {
  await page.goto('/agents?name=cx_triage');
  const form = page.locator('#agent-form');
  await expect(form).toHaveAttribute('data-has-base', '1');
  const base = (await form.getAttribute('data-base-allow')).split(/\s+/).filter(Boolean);
  const allowed = await page.locator('#f-allow').inputValue();
  expect(allowed.split(/\s+/).filter(Boolean).every(tool => base.includes(tool))).toBe(true);
  if (!base.includes('shell')) await expect(page.locator('#skill-chips')).not.toContainText('Run commands');
  const baseRisk = await form.getAttribute('data-base-risk');
  if (baseRisk !== 'high') await expect(page.locator('#risk-seg button[data-risk="high"]')).toBeDisabled();
});
