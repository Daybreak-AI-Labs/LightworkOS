/* Run against starter_teams_server.py; Chromium and Playwright must be installed. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');

(async () => {
  const base = process.env.LIGHTWORK_BROWSER_URL || 'http://127.0.0.1:8909';
  const browser = await chromium.launch({headless: true, executablePath: process.env.LIGHTWORK_CHROMIUM || undefined});
  const page = await browser.newPage({viewport: {width: 1440, height: 1100}});
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', entry => { if (entry.type() === 'error') console.error('Browser console:', entry.text()); });
  page.on('requestfailed', request => console.error('Failed request:', request.url(), request.failure().errorText));
  try {
    await page.goto(base + '/starter-teams');
    await page.locator('#st-team option[value="order_management"]').waitFor({state: 'attached', timeout: 15000});
    await page.locator('#st-team').selectOption('order_management');
    await page.locator('#st-owner').fill('Taylor — order operations');
    await page.locator('#st-scope').fill('Synthetic browser order portfolio');
    await page.locator('#st-setup-review').click();
    await page.locator('#st-review[open]').waitFor();
    await page.locator('#st-confirm').click();
    await page.locator('#st-review').waitFor({state: 'hidden'});
    await page.waitForFunction(() => document.getElementById('st-saved').value.startsWith('STS-'));
    const setupId = await page.locator('#st-saved').inputValue();
    await page.locator('#st-sample').click();
    await page.locator('#st-review[open]').waitFor();
    await page.route('**/api/v1/starter-teams/confirm', async route => { await route.fetch(); await route.abort('failed'); }, {times: 1});
    await page.locator('#st-confirm').click();
    await page.locator('#st-original').waitFor({state: 'visible'});
    await page.reload();
    await page.locator('#st-review[open]').waitFor();
    assert(await page.locator('#st-confirm').isDisabled(), 'reload recovery must not silently repeat a write');
    await page.locator('#st-original').click();
    await page.locator('#st-review').waitFor({state: 'hidden'});
    await page.getByRole('heading', {name: 'Sample result', exact: true}).waitFor();
    const catalog = await (await page.request.get(base + '/api/v1/starter-teams')).json();
    const team = catalog.teams.find(item => item.id === 'order_management');
    const quote = value => '"' + String(value === null ? '' : value).replaceAll('"', '""') + '"';
    for (const table of team.inputs) {
      const rows = team.sample.tables[table.key];
      const csv = [table.columns.join(','), ...rows.map(row => table.columns.map(column => quote(row[column])).join(','))].join('\n');
      await page.locator('[data-table="' + table.key + '"]').fill(csv);
    }
    await page.locator('#st-date').fill(team.sample.as_of);
    const before = await page.locator('[data-table]').first().inputValue();
    await page.locator('#st-refresh').click();
    await page.waitForTimeout(500);
    assert.equal(await page.locator('[data-table]').first().inputValue(), before, 'refresh must preserve entered CSV');
    await page.locator('#st-inputs-review').click();
    await page.locator('#st-review[open]').waitFor();
    await page.locator('#st-confirm').click();
    await page.locator('#st-review').waitFor({state: 'hidden'});
    await page.getByRole('heading', {name: 'Your record checks', exact: true}).waitFor();
    const cases = await (await page.request.get(base + '/api/v1/starter-teams/setups/' + setupId + '/cases')).json();
    const supplied = cases.cases.find(row => row.mode === 'supplied_export');
    assert(supplied.output.findings.length > 0);
    await page.locator('#st-pause').click();
    await page.locator('#st-review[open]').waitFor();
    await page.locator('#st-confirm').click();
    await page.locator('#st-review').waitFor({state: 'hidden'});
    assert(await page.locator('#st-sample').isDisabled());
    await page.locator('#st-pause').click();
    await page.locator('#st-review[open]').waitFor();
    await page.locator('#st-confirm').click();
    await page.locator('#st-review').waitFor({state: 'hidden'});
    await page.goto(base + '/starter-teams#case-' + supplied.id);
    await page.locator('#case-' + supplied.id).waitFor();
    assert.equal(await page.locator('#st-saved').inputValue(), setupId);
    await page.waitForFunction(() => document.getElementById('st-team').value === 'order_management');
    assert.equal(await page.locator('h1').count(), 1);
    await page.locator('#sts-setup option[value="' + setupId + '"]').waitFor({state: 'attached'});
    await page.locator('#sts-setup').selectOption(setupId);
    await page.locator('#sts-create-review').click();
    await page.locator('#sts-review[open]').waitFor();
    await page.locator('#sts-confirm').click();
    await page.locator('#sts-review').waitFor({state: 'hidden'});
    await page.waitForFunction(() => Boolean(document.getElementById('sts-saved').value));
    await page.locator('#sts-pause').click();
    await page.locator('#sts-review[open]').waitFor();
    await page.locator('#sts-confirm').click();
    await page.locator('#sts-review').waitFor({state: 'hidden'});
    assert(await page.locator('#sts-tick').isDisabled());
    await page.locator('#sts-pause').click();
    await page.locator('#sts-review[open]').waitFor();
    await page.locator('#sts-confirm').click();
    await page.locator('#sts-review').waitFor({state: 'hidden'});
    await page.waitForLoadState('networkidle');
    await page.locator('#case-' + supplied.id).waitFor();
    await page.evaluate(() => window.scrollTo(0, 0));
    const output = process.env.LIGHTWORK_SCREENSHOT_DIR;
    if (output) { fs.mkdirSync(output, {recursive: true}); await page.screenshot({path: path.join(output, 'starter-teams-desktop.png'), fullPage: true}); await page.screenshot({path: path.join(output, 'starter-teams-desktop-overview.png')}); }
    await page.setViewportSize({width: 390, height: 844});
    await page.waitForLoadState('networkidle');
    await page.locator('#case-' + supplied.id).waitFor();
    await page.evaluate(() => window.scrollTo(0, 0));
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'mobile page must not overflow');
    if (output) { await page.screenshot({path: path.join(output, 'starter-teams-mobile.png'), fullPage: true}); await page.screenshot({path: path.join(output, 'starter-teams-mobile-overview.png')}); }
    assert.deepEqual(errors, [], 'no browser JavaScript errors');
    console.log(JSON.stringify({passed: true, journey: 'setup, sample, lost-response reload recovery, CSV inputs, preserved edits, pause/resume, deep links, schedule create/pause/resume, desktop/mobile', cases: cases.cases.length}));
  } catch (error) {
    console.error('Page state:', await page.locator('body').innerText(), 'Browser errors:', errors);
    if (process.env.LIGHTWORK_SCREENSHOT_DIR) await page.screenshot({path: path.join(process.env.LIGHTWORK_SCREENSHOT_DIR, 'starter-teams-failure.png'), fullPage: true});
    throw error;
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
