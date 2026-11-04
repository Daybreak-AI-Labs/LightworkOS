// APP10 browser boundary: synthetic API data against the real authenticated page.
const {test, expect} = require('@playwright/test');
const crypto = require('node:crypto');

test.beforeEach(async ({context, page, baseURL}) => {
  await context.route('**/*', route => new URL(route.request().url()).origin === new URL(baseURL).origin
    ? route.continue() : route.abort('blockedbyclient'));
  page.__errors = [];
  page.on('pageerror', error => page.__errors.push(error.message));
  page.on('console', message => { if (message.type() === 'error') page.__errors.push(message.text()); });
});

test.afterEach(async ({page}, info) => {
  const screenshot = info.outputPath('knowledge-access.png');
  await page.screenshot({path: screenshot, fullPage: true});
  await info.attach('knowledge-access', {path: screenshot, contentType: 'image/png'});
  expect(page.__errors).toEqual([]);
});

const sha = character => character.repeat(64);
const canonical = value => {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
};
const sourceRef = {kind: 'dataset', asset_id: 'customer-evidence-with-a-very-long-exact-identifier',
  version: 'v2026.09.08', manifest_sha256: sha('1'), schema: 'lightwork.research-registry-ref.v1'};
const modelRef = {kind: 'model', asset_id: 'candidate-derived-from-customer-evidence',
  version: 'v7', manifest_sha256: sha('2'), schema: 'lightwork.research-registry-ref.v1'};

function record() {
  return {schema: 'lightwork.knowledge-rights-request.v1', id: 'knowledge-req-' + '3'.repeat(40),
    revision: 1, request_type: 'deletion', status: 'submitted', source_reference: sourceRef,
    requested_by: 'user:browser-reviewer', reason: 'Synthetic customer removal rehearsal.',
    proposed_correction: null, source_use_status: 'unchanged_pending_review',
    raw_record_status: 'pending_source_review', retention_review_status: 'required',
    decision: null, decided_by: null,
    decision_evidence_sha256: null, created_at: 1700000000, updated_at: 1700000001,
    derivatives: [{reference: modelRef, current_state: 'approved',
      required_action: 'retire_or_retrain_model', authority_owner: 'research_registry_lineage',
      workflow_state: 'pending_source_review'}],
    derivatives_at_request: [{reference: modelRef, current_state: 'approved',
      required_action: 'retire_or_retrain_model', authority_owner: 'research_registry_lineage',
      workflow_state: 'pending_source_review'}], lineage_revalidated_before_return: true,
    weight_influence_notice: 'Deleting or excluding a raw source does not erase its influence from learned weights. Affected models require a documented retirement or retraining assessment.',
    training_permission_notice: 'Access to search, deploy, or export a source does not grant permission to train on it.'};
}

function item() {
  return {schema: 'lightwork.knowledge-detail.v1', reference: sourceRef,
    title: '<script>Synthetic customer evidence</script>',
    summary: 'Synthetic governed summary. No customer, provider, or production system was contacted. ' + 'Long-content-token-'.repeat(18),
    content_available: true, claim_state: 'verified', observed_at: 1700000000,
    verified_at: 1700000100, source: {authority_owner: 'research_registry', source_ref: 'catalog:browser-workspace/' + 'long-source-segment/'.repeat(18) + 'v1',
      version: sourceRef.version, content_sha256: sha('4'), provenance_kind: 'source',
      license_id: 'synthetic-fixture-only', usage_constraints: ['tenant_only', 'separate_training_permission_required']},
    eligibility: {state: 'eligible', checked_at: 1700000200, purpose: 'product_research',
      permitted_action: 'export', fresh_until: 4102444800, consent_until: null,
      approval_sha256: sha('5'), requested_action: 'read', actor: 'user:browser-reviewer',
      actor_authorization_sha256: sha('6')}, cache: {owner: 'knowledge_access_process_projection', hit: true,
      content_revalidated_before_return: true},
    correction_history: [record()], training_permission_notice:
      'Access to search, deploy, or export a source does not grant permission to train on it.'};
}

function exportEnvelope(context) {
  const source = item();
  source.eligibility = {...source.eligibility, requested_action: 'export',
    actor_authorization_sha256: sha('7')};
  const evidence = {schema: 'lightwork.knowledge-export-authority-evidence.v1',
    tenant: 'browser-workspace', actor: 'user:browser-reviewer',
    actor_authorization_sha256: sha('7'), purpose: 'product_research', action: 'export',
    sources: [{reference: source.reference, content_sha256: source.source.content_sha256,
      approval_sha256: source.eligibility.approval_sha256}]};
  return {context, schema: 'lightwork.knowledge-export.v1', tenant: 'browser-workspace',
    actor: 'user:browser-reviewer', actor_authorization_sha256: sha('7'),
    purpose: 'product_research', items: [source], count: 1, complete: true,
    authority_evidence: {...evidence,
      binding_sha256: crypto.createHash('sha256').update(canonical(evidence)).digest('hex')},
    qualification: {local_control_validation: 'passed_at_request_time',
      external_store_and_customer_qualification: 'qualification_pending'},
    training_permission_notice: 'Separate permission is required.'};
}

async function pageContext(request) {
  const response = await request.get('/knowledge-access');
  expect(response.status()).toBe(200);
  const match = (await response.text()).match(/id="knowledge-access"[\s\S]*?data-context="([a-f0-9]{64})"/);
  expect(match).not.toBeNull();
  return match[1];
}

function requestBatch(context, items, url) {
  const view = url.searchParams.get('view') || 'active';
  return {context, schema: 'lightwork.knowledge-rights-requests.v1', items,
    count: items.length, can_review: true, view, archived: view === 'archive',
    ready_to_archive: view === 'ready', next_cursor: null, complete: true,
    scanned: items.length, notice: 'Source restrictions and legal holds were checked for this batch.'};
}

for (const width of [320, 1280]) test(`knowledge access is usable and honest at ${width}px`, async ({page, request}) => {
  await page.setViewportSize({width, height: 940});
  const context = await pageContext(request);
  await page.route('**/api/v1/knowledge-access/**', async route => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith('/task-policy')) return route.fallback();
    if (url.pathname.endsWith('/request-batches') && route.request().method() === 'GET') {
      return route.fulfill({json: requestBatch(context, [record()], url)});
    }
    if (url.pathname.endsWith('/search')) {
      await new Promise(resolve => setTimeout(resolve, 600));
      return route.fulfill({json: {context, schema: 'lightwork.knowledge-search.v1', query: 'customer',
        tenant: 'browser-workspace', actor: 'user:browser-reviewer', actor_authorization_sha256: sha('6'),
        purpose: 'product_research', items: [item()], count: 1, matched: 1,
        omitted_ineligible: 1, truncated: false, authority_checks: 'Current checks passed.',
        status: 'matched', complete: true, incomplete_reasons: [], next_cursor: null,
        training_permission_notice: 'Separate permission is required.'}});
    }
    if (url.pathname.endsWith('/detail')) return route.fulfill({json: {context, ...item()}});
    return route.fulfill({status: 404, json: {detail: 'Synthetic route unavailable'}});
  });
  await page.goto('/knowledge-access');
  await expect(page.getByRole('heading', {name: 'Knowledge', exact: true, level: 1})).toBeVisible();
  await expect(page.locator('.ka-lede')).toContainText('Find knowledge you can use now');
  await expect(page.locator('#ka-requests')).toContainText('retire or retrain the model');
  await expect(page.locator('#ka-requests')).toContainText('does not erase its influence from learned weights');

  await page.locator('#ka-query').fill('customer');
  await page.getByRole('button', {name: 'Search current sources'}).click();
  await expect(page.locator('#ka-status')).toHaveText(/Searching currently eligible sources/);
  await expect(page.locator('#ka-results')).toContainText('<script>Synthetic customer evidence</script>');
  await expect(page.locator('#ka-results script')).toHaveCount(0);
  await expect(page.locator('#ka-search-note')).toContainText('withheld because current access could not be revalidated');
  await page.getByRole('button', {name: 'View details for <script>Synthetic customer evidence</script>'}).click();
  await expect(page.locator('#ka-detail-panel')).toBeVisible();
  await expect(page.locator('#ka-detail')).toContainText('revalidated cache hit');
  await expect(page.locator('#ka-detail')).toContainText('does not grant permission to train');
  await expect(page.locator('#ka-submit-request')).toBeEnabled();
  await expect(page.locator('#ka-detail-heading')).toBeFocused();

  await page.locator('#ka-query').focus();
  await page.keyboard.press('Tab');
  await expect(page.locator('#ka-purpose')).toBeFocused();
  // The result limit is a fixed hidden value now, so it is not a tab stop.
  await expect(page.locator('#ka-limit')).toHaveAttribute('type', 'hidden');
  await page.keyboard.press('Tab');
  await expect(page.locator('#ka-retry-purposes')).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.locator('#ka-search')).toBeFocused();

  const overflow = await page.evaluate(() => ({viewport: document.documentElement.clientWidth,
    page: document.documentElement.scrollWidth, elements: [...document.querySelectorAll('.ka-shell *')]
      .filter(node => !node.closest('[hidden]') && node.getBoundingClientRect().width &&
        node.getBoundingClientRect().right > document.documentElement.clientWidth + 1)
      .slice(0, 8).map(node => ({tag: node.tagName, id: node.id, text: node.textContent.slice(0, 50)}))}));
  expect(overflow.page, JSON.stringify(overflow)).toBeLessThanOrEqual(overflow.viewport + 1);
  expect(overflow.elements, JSON.stringify(overflow)).toEqual([]);
});

test('empty and revoked states remove stale content and explain the next step', async ({page, request}) => {
  const context = await pageContext(request);
  let searches = 0;
  await page.route('**/api/v1/knowledge-access/**', route => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith('/task-policy')) return route.fallback();
    if (url.pathname.endsWith('/request-batches')) return route.fulfill({json: requestBatch(context, [], url)});
    if (url.pathname.endsWith('/search')) {
      searches += 1;
      return route.fulfill({json: {context, schema: 'lightwork.knowledge-search.v1', query: '',
        tenant: 'browser-workspace', actor: 'user:browser-reviewer', actor_authorization_sha256: sha('6'),
        purpose: 'product_research', items: searches === 1 ? [item()] : [],
        count: searches === 1 ? 1 : 0, matched: searches === 1 ? 1 : 0,
        omitted_ineligible: searches === 1 ? 0 : 1, truncated: false,
        status: searches === 1 ? 'matched' : 'no_match', complete: true,
        incomplete_reasons: [], next_cursor: null,
        authority_checks: 'Current checks passed.', training_permission_notice: 'Separate permission.'}});
    }
    if (url.pathname.endsWith('/detail')) return route.fulfill({status: 409,
      json: {detail: 'Current source access is unavailable. Request fresh access or evidence.'}});
    return route.fulfill({status: 404, json: {detail: 'Synthetic route unavailable'}});
  });
  await page.goto('/knowledge-access');
  await page.locator('#ka-search').click();
  await expect(page.locator('#ka-results')).toContainText('Synthetic customer evidence');
  await page.getByRole('button', {name: /View details/}).click();
  await expect(page.locator('#ka-status')).toContainText("This changed since you loaded it, or current access couldn't be confirmed.");
  await expect(page.locator('#ka-status')).not.toContainText('Request fresh access or evidence');
  await expect(page.locator('#ka-detail-panel')).toBeHidden();
  await expect(page.locator('#ka-submit-request')).toBeDisabled();
  await page.locator('#ka-search').click();
  await expect(page.locator('#ka-results')).toContainText('No currently eligible sources matched');
  await expect(page.locator('#ka-results')).not.toContainText('Synthetic customer evidence');
  await expect(page.locator('#ka-export')).toBeDisabled();
  page.__errors = page.__errors.filter(message =>
    !message.includes('Failed to load resource: the server responded with a status of 409'));
});

test('export verifies the complete authority binding with browser Web Crypto', async ({page, request}) => {
  const context = await pageContext(request);
  await page.route('**/api/v1/knowledge-access/**', route => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith('/task-policy')) return route.fallback();
    if (url.pathname.endsWith('/request-batches')) return route.fulfill({json: requestBatch(context, [], url)});
    if (url.pathname.endsWith('/search')) return route.fulfill({json: {context,
      schema: 'lightwork.knowledge-search.v1', tenant: 'browser-workspace',
      actor: 'user:browser-reviewer', actor_authorization_sha256: sha('6'), query: '',
      purpose: 'product_research', items: [item()], count: 1, matched: 1,
      omitted_ineligible: 0, truncated: false, authority_checks: 'Current checks passed.',
      status: 'matched', complete: true, incomplete_reasons: [], next_cursor: null,
      training_permission_notice: 'Separate permission is required.'}});
    if (url.pathname.endsWith('/export')) return route.fulfill({json: exportEnvelope(context)});
    return route.fulfill({status: 404, json: {detail: 'Synthetic route unavailable'}});
  });
  await page.goto('/knowledge-access');
  await page.locator('#ka-search').click();
  await expect(page.locator('#ka-export')).toBeEnabled();
  const download = page.waitForEvent('download');
  await page.locator('#ka-export').click();
  await download;
  await expect(page.locator('#ka-status')).toContainText('Exported 1 currently eligible source');
});

test('an applying source retirement can be recovered in the app by exact replay', async ({page, request}) => {
  const context = await pageContext(request);
  const rationale = 'Exact prior browser recovery rationale';
  const evidence = crypto.createHash('sha256').update(rationale).digest('hex');
  const applying = {...record(), status: 'applying', revision: 2, decision: 'approve',
    decided_by: 'user:browser-reviewer', decision_evidence_sha256: evidence};
  const approved = {...applying, status: 'approved', revision: 3,
    source_use_status: 'revoked_for_new_use', raw_record_status: 'source_version_retired',
    derivatives: [{...applying.derivatives[0], current_state: 'revoked',
      workflow_state: 'model_retirement_confirmed_retraining_unverified'}]};
  let completed = false;
  let submitted;
  await page.route('**/api/v1/knowledge-access/**', async route => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith('/task-policy')) return route.fallback();
    if (url.pathname.endsWith('/request-batches') && route.request().method() === 'GET') {
      const current = completed ? approved : applying;
      return route.fulfill({json: requestBatch(context, [current], url)});
    }
    if (url.pathname.endsWith('/decision')) {
      submitted = route.request().postDataJSON();
      completed = true;
      return route.fulfill({json: {context, ...approved}});
    }
    return route.fulfill({status: 404, json: {detail: 'Synthetic route unavailable'}});
  });

  await page.goto('/knowledge-access');
  await expect(page.locator('#ka-requests')).toContainText('Recovery is waiting');
  await expect(page.locator('#ka-requests')).toContainText('currently approved');
  await page.locator('#ka-requests details > summary').click();
  await page.locator('#ka-requests textarea').fill(rationale);
  await page.locator('#ka-requests input[type="checkbox"]').check();
  await page.getByRole('button', {name: 'Finish the approved removal'}).click();
  await expect(page.locator('#ka-status')).toContainText('The source is no longer used.');
  await expect(page.locator('#ka-requests')).toContainText('Model retirement confirmed retraining unverified');
  expect(submitted).toMatchObject({expected_revision: 2, decision: 'approve',
    evidence_sha256: evidence, confirm: true});
});

test('authenticated browser uses the real APP10 API for search, detail, and retention', async ({page, request}) => {
  const setup = await request.post('/__browser_fixture/knowledge-access/setup');
  expect(setup.status()).toBe(200);
  const fixture = await setup.json();
  expect(fixture).toMatchObject({synthetic: true, provider_calls: 0, outbound_calls: 'blocked'});

  await page.goto('/knowledge-access');
  await expect(page.locator('#ka-requests')).toContainText('No correction');
  await page.locator('#ka-query').fill('synthetic governed browser policy');
  await page.getByRole('button', {name: 'Search current sources'}).click();
  await expect(page.locator('#ka-results')).toContainText('Synthetic governed browser policy');
  await expect(page.locator('#ka-results')).toContainText('real APP10 registry');
  await page.getByRole('button', {name: 'View details for Synthetic governed browser policy'}).click();
  await expect(page.locator('#ka-detail')).toContainText('revalidated cache hit');
  await expect(page.locator('#ka-detail')).toContainText('browser-reviewer');

  const form = page.locator('#ka-request-form');
  await form.locator('select[name="request_type"]').selectOption('deletion');
  await form.locator('textarea[name="reason"]').fill('Preserve, then process this synthetic deletion.');
  await form.locator('input[name="confirm"]').check();
  await page.getByRole('button', {name: 'Submit request'}).click();
  await expect(page.locator('#ka-requests')).toContainText('Preserve, then process');
  await page.locator('#ka-requests details', {hasText: 'Preserve, then process'}).locator('summary').click();

  const holdBox = page.locator('.ka-review', {hasText: 'Preservation hold'});
  await holdBox.getByLabel(/^Name of the legal matter/).fill('browser-matter-2026');
  await holdBox.getByLabel(/^Legal or preservation basis/).fill('Synthetic preservation duty.');
  await holdBox.getByLabel(/^Hold expires/).fill('2099-01-01T00:00');
  await holdBox.getByText('I checked the matter, the reason and the end date.').click();
  await holdBox.getByRole('button', {name: 'Place a legal hold on this deletion request'}).click();
  await expect(page.locator('#ka-requests')).toContainText('browser-matter-2026 is active');
  await page.locator('#ka-requests details', {hasText: 'Preserve, then process'}).locator('summary').click();

  const releaseBox = page.locator('.ka-review', {hasText: 'Preservation hold'});
  await releaseBox.getByLabel('Why the hold can be released').fill('Synthetic duty ended.');
  await releaseBox.getByText('I verified the preservation duty').click();
  await releaseBox.getByRole('button', {name: 'Release the legal hold'}).click();
  await expect(page.locator('#ka-requests')).toContainText('browser-matter-2026 is released');
  await expect(page.locator('#ka-requests')).toContainText('Synthetic duty ended');

  const colleaguePage = await request.get('/knowledge-access', {
    headers: {'X-Browser-Principal': 'browser-colleague'}
  });
  expect(colleaguePage.status()).toBe(200);
  const colleagueMatch = (await colleaguePage.text()).match(
    /id="knowledge-access"[\s\S]*?data-context="([a-f0-9]{64})"/
  );
  expect(colleagueMatch).not.toBeNull();
  const denied = await request.post('/api/v1/knowledge-access/search', {
    headers: {'X-Browser-Principal': 'browser-colleague'},
    data: {context: colleagueMatch[1], query: '', purpose: 'product_research', limit: 20}
  });
  expect(denied.status()).toBe(409);
  expect(await denied.text()).not.toContain('real APP10 registry');
});

test('an administrator can archive a finished real request in the page while its source stays blocked', async ({page, request}) => {
  const setup = await request.post('/__browser_fixture/knowledge-access/setup');
  expect(setup.status()).toBe(200);
  const fixture = await setup.json();
  await page.goto('/knowledge-access');
  await page.locator('#ka-query').fill('synthetic governed browser policy');
  await page.getByRole('button', {name: 'Search current sources'}).click();
  await page.getByRole('button', {name: 'View details for Synthetic governed browser policy'}).click();
  const form = page.locator('#ka-request-form');
  await form.locator('select[name="request_type"]').selectOption('exclusion');
  await form.locator('textarea[name="reason"]').fill('Synthetic archive review.');
  await form.locator('input[name="confirm"]').check();
  await page.getByRole('button', {name: 'Submit request'}).click();
  const card = page.locator('.ka-request', {hasText: 'Synthetic archive review.'});
  await expect(card).toBeVisible();
  await card.locator('summary').click();
  await card.locator('.ka-review textarea').fill('Independent synthetic review confirmed.');
  await card.locator('.ka-review input[type="checkbox"]').check();
  await card.getByRole('button', {name: 'Approve and stop using this source'}).click();
  await expect(card).toContainText('approved');
  await page.getByRole('button', {name: 'Ready to archive'}).click();
  // The view reloads its cards; open the new card, not the one being replaced.
  await expect(page.locator('#ka-status')).toHaveText('Showing finished requests ready to archive.');
  await card.locator('summary').click();
  await expect(card.getByRole('button', {name: 'Move to finished archive'})).toBeVisible();
  page.once('dialog', dialog => dialog.accept());
  await card.getByRole('button', {name: 'Move to finished archive'}).click();
  await expect(page.locator('#ka-requests')).toContainText('No finished requests are ready to archive');
  await page.getByRole('button', {name: 'View finished archive'}).click();
  await expect(page.locator('#ka-requests')).toContainText('Synthetic archive review.');
  await expect(page.locator('#ka-requests')).toContainText('Retained in the finished archive');
  await page.getByRole('button', {name: 'View active requests'}).click();
  await page.getByRole('button', {name: 'View finished archive'}).click();
  await expect(page.locator('#ka-requests')).toContainText('Synthetic archive review.');
  const blocked = await request.post('/api/v1/knowledge-access/detail', {data: {
    context: fixture.context, reference: fixture.reference, purpose: 'product_research'
  }});
  expect(blocked.status()).toBe(409);
});

test('a colleague can recover their own older archived request in the page', async ({page, request}) => {
  const prepared = await request.post('/__browser_fixture/knowledge-access/archived-owner');
  expect(prepared.status()).toBe(200);
  const {id} = await prepared.json();
  await page.setExtraHTTPHeaders({'X-Browser-Principal': 'browser-colleague'});
  await page.goto('/knowledge-access');
  await expect(page.locator('#knowledge-access')).toHaveAttribute('data-can-review', 'false');
  await page.locator('#ka-archive-reference').fill(id);
  await page.getByRole('button', {name: 'Find archived request'}).click();
  await expect(page.locator('#ka-requests')).toContainText('Synthetic colleague archive receipt.');
  await expect(page.locator('#ka-requests')).toContainText('Retained in the finished archive');
  await expect(page.locator('#ka-requests')).toContainText(id);
  await expect(page.locator('#ka-requests .ka-review')).toHaveCount(0);
});
