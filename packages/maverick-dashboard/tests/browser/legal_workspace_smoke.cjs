/* Native legal journey; run with legal_workspace_server.py. Provider output is synthetic. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');

(async () => {
  const base = process.env.LIGHTWORK_BROWSER_URL || 'http://127.0.0.1:8910';
  const browser = await chromium.launch({headless: true});
  const page = await browser.newPage({viewport: {width: 1440, height: 1050}});
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  async function field(name, value) {
    const locator = page.locator('#legal-input-' + name);
    const tag = await locator.evaluate(node => node.tagName);
    if (tag === 'SELECT') await locator.selectOption(value);
    else await locator.fill(String(value));
  }
  async function submit({interrupt = false} = {}) {
    await page.locator('#legal-review-button').click();
    await page.locator('#legal-review[open]').waitFor();
    if (interrupt) await page.route('**/api/v1/legal/confirm', async route => { await route.fetch(); await route.abort('failed'); }, {times: 1});
    await page.locator('#legal-confirm').click();
    if (interrupt) {
      await page.locator('#legal-original').waitFor({state: 'visible'});
      await page.reload();
      await page.locator('#legal-review[open]').waitFor();
      assert(await page.locator('#legal-confirm').isDisabled());
      await page.locator('#legal-original').click();
    }
    await page.locator('#legal-review').waitFor({state: 'hidden'});
    await page.waitForFunction(() => document.getElementById('legal-message').textContent.includes('operation is recorded'));
  }
  async function action(name) {
    await page.getByRole('button', {name: 'More matter operations', exact: true}).click();
    await page.locator('#legal-action').selectOption(name);
  }
  try {
    await page.goto(base + '/legal');
    await page.waitForFunction(() => document.getElementById('legal-message').textContent.includes('Current authorized'));
    await page.locator('#legal-new').click();
    for (const [key, value] of Object.entries({title: 'Acme supplier renewal', area: 'commercial', objective: 'Decide whether to renew the supplier agreement.', department: 'Procurement', business_owner: 'Taylor Morgan', jurisdiction: 'Tennessee', priority: 'important'})) await field(key, value);
    await submit({interrupt: true});
    await page.locator('#legal-matter-title').filter({hasText: 'Acme supplier renewal'}).waitFor();
    await action('source');
    for (const [key, value] of Object.entries({title: 'Supplier agreement — executed', kind: 'agreement', reference: 'Executed agreement, section 4', text: 'Give notice by 2027-01-01.\nLiability is capped at fees paid.', status: 'executed'})) await field(key, value);
    await submit();
    await action('assignment');
    const sourceId = await page.locator('#legal-input-source_ids option').first().getAttribute('value');
    await field('role_id', 'commercial_associate'); await field('title', 'Review renewal and liability terms');
    await field('instructions', 'Prepare an issue brief for supervising counsel.'); await field('source_ids', [sourceId]);
    await submit();
    await action('run'); await submit();
    await page.getByRole('heading', {name: 'Draft for supervising counsel'}).waitFor();
    assert(await page.getByText('Which approved playbook applies to this supplier?').count() > 0);
    await action('review_assignment'); await field('state', 'accepted'); await field('note', 'Source passages checked; this draft accurately identifies the missing playbook.'); await submit();
    await action('engagement');
    for (const [key, value] of Object.entries({firm: 'Example Legal LLP', contact: 'Jordan Smith', scope: 'Evaluate termination options', deliverables: 'Options memorandum', budget: '2500', max_hourly_rate: '400'})) await field(key, value);
    await submit();
    for (const state of ['conflicts_cleared', 'approved']) { await action('review_engagement'); await field('state', state); await field('note', 'Confirmed engagement requirements with counsel.'); await submit(); }
    await action('invoice');
    for (const [key, value] of Object.entries({reference: 'INV-100', amount: '2700', hourly_rate: '450', description: 'Termination options memorandum'})) await field(key, value);
    await submit();
    await page.getByRole('button', {name: 'Invoices (1)', exact: true}).click();
    assert(await page.getByText('Recorded invoices exceed the engagement budget.').count() > 0);
    await action('packet'); await field('title', 'Acme counsel instruction packet'); await field('instructions', 'Please analyze termination options and identify assumptions.'); await field('source_ids', [sourceId]); await submit();
    await page.getByRole('button', {name: 'Counsel packets (1)', exact: true}).click();
    const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('link', {name: 'Download reviewed packet'}).click()]);
    assert.equal(download.suggestedFilename(), 'counsel-packet.txt');
    const inventory = await (await page.request.get(base + '/api/v1/legal')).json();
    assert.equal(inventory.matters.length, 1, 'lost reply must not duplicate the matter');
    const forbidden = await page.request.get(base + '/api/v1/legal/matters/' + inventory.matters[0].id, {headers: {'X-Browser-Principal': 'browser-colleague'}});
    assert.equal(forbidden.status(), 403, 'unshared matters remain private');
    await page.locator('#legal-back').click(); await page.locator('#legal-team-toggle').click();
    assert.equal(await page.locator('#legal-team article').count(), 9);
    await page.evaluate(() => window.scrollTo(0, 0));
    const output = process.env.LIGHTWORK_SCREENSHOT_DIR;
    if (output) { fs.mkdirSync(output, {recursive: true}); await page.screenshot({path: path.join(output, 'legal-desktop.png'), fullPage: true}); }
    await page.setViewportSize({width: 390, height: 844});
    await page.evaluate(() => window.scrollTo(0, 0));
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'no horizontal overflow on mobile');
    if (output) await page.screenshot({path: path.join(output, 'legal-mobile.png'), fullPage: true});
    await page.route('**/api/v1/legal', route => route.fulfill({status: 401, contentType: 'text/html', body: '<html>Sign in</html>'}), {times: 1});
    await page.locator('#legal-refresh').click();
    await page.waitForFunction(() => document.getElementById('legal-matters').childElementCount === 0);
    assert(!(await page.locator('body').textContent()).includes('Acme supplier renewal'), 'expired access must clear private content');
    assert.deepEqual(errors, []);
    console.log('PASS: legal intake, recovery, evidence, worker draft/review, counsel, invoice exceptions, packet export, ACL and responsive layouts');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
