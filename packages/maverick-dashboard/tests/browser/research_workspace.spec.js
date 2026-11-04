// Real authenticated page and assets with an explicitly synthetic UI response.
// Python route tests independently exercise the governed registry/run stores.
const {test, expect} = require('@playwright/test');

test.beforeEach(async ({context, page, baseURL}) => {
  await context.route('**/*', route => new URL(route.request().url()).origin === new URL(baseURL).origin
    ? route.continue() : route.abort('blockedbyclient'));
  page.__errors = [];
  page.on('pageerror', error => page.__errors.push(error.message));
  page.on('console', message => { if (message.type() === 'error') page.__errors.push(message.text()); });
});

test.afterEach(async ({page}, info) => {
  await info.attach('research-workspace', {body:await page.screenshot({fullPage:true}), contentType:'image/png'});
  expect(page.__errors).toEqual([]);
});

const digest = value => value.repeat(64);
const reference = {kind:'dataset', asset_id:'synthetic-browser-cases', version:'v1',
  manifest_sha256:digest('d'), schema:'lightwork.research-registry-ref.v1'};

function model(context) {
  return {context, jobs:[], review_queue:[], can_dispatch:false, execution_available:false,
    evaluators:[], settings:{settings_sha256:'', enabled:false, valid:false, writable:false,
      source:'unavailable'}, registry:{datasets:[{reference, kind:'dataset', state:'approved',
        revision:2, registered_by:'user:browser-researcher', created_at:1, updated_at:2,
        source_ref:'artifact:synthetic-browser-cases/v1', license_id:'synthetic-fixture-only',
        license_evidence_sha256:digest('1'), allowed_purposes:['product_research'],
        usage_constraints:['synthetic_fixture_only'], provenance_kind:'synthetic',
        content_sha256:digest('2'), data_use_action:'analyze', data_use_decision_id:'synthetic-decision',
        data_use_decision_sha256:digest('3'), consent_record_id:null, consent_evidence_sha256:null,
        parent_datasets:[], synthetic_provenance:{generator_id:'browser-fixture',
          generator_version:'v1', seed:17}, approval:{approved_by:'user:browser-reviewer'},
        revocation:null, eligibility:{state:'eligible', checked_purposes:['product_research'],
          detail:'Current checks passed.'}}], models:[], can_review:true, truncated:false,
      consent_authority_available:false, training_receipt_verification:'server_policy_on_demand'},
    governed_runs:[{run_id:'synthetic-browser-run', created_by:'user:browser-researcher',
      status:'queued', revision:2, created_at:1, updated_at:2, manifest_sha256:digest('4'),
      manifest:{experiment_id:'synthetic-baseline', experiment_version:'v1', action:'analyze',
        purpose:'product_research', seed:17, code_revision:'a'.repeat(40), environment_id:'local',
        environment_version:'v1', dataset_refs:[reference], resource_caps:{max_wall_seconds:60,
          max_provider_calls:0, max_storage_bytes:1024, max_cost:'0', currency:'USD'}},
      cost_summary:{effective_amounts:{USD:'1.25'}, incomplete:true, effective_event_count:2},
      attempts:[{number:1, status:'queued', costs:[{cost:{category:'compute', basis:'invoice',
        amount:'1.25', currency:'USD', quantity:null, unit:null, incomplete_reason:null,
        evidence_sha256:digest('5'), source_ref_sha256:digest('6')}},{cost:{category:'storage',
        basis:'unknown', amount:null, currency:null, quantity:null, unit:null,
        incomplete_reason:'synthetic provider report pending', evidence_sha256:digest('7'),
        source_ref_sha256:digest('8')}}], metrics:[]}]}], governed_runs_truncated:false,
    governed_execution:{available:false, state:'unavailable',
      detail:'No trusted dataset materialization and dispatch adapter is configured.'}};
}

for (const width of [360, 1280]) test(`governed research stays usable and honest at ${width}px`, async ({page, request}) => {
  await page.setViewportSize({width, height:960});
  const pageResponse = await request.get('/research');
  expect(pageResponse.status()).toBe(200);
  const match = (await pageResponse.text()).match(/id="research-lab" data-context="([a-f0-9]{64})"/);
  expect(match).not.toBeNull();
  const context = match[1];
  await page.route('**/api/v1/research', route => route.fulfill({json:model(context)}));
  await page.goto('/research');
  await page.locator('#research-governed-refresh').click();
  await expect(page.locator('#research-registry-items')).toContainText('Synthetic fixture');
  await expect(page.locator('#research-governed-runs')).toContainText('USD 1.25');
  await expect(page.locator('#research-governed-runs')).toContainText('Synthetic provider report pending');
  // Without an approved run and an available executor, Start is not offered at all.
  await expect(page.getByRole('button', {name:'Start run', exact:true})).toHaveCount(0);
  await expect(page.locator('#research-materialization-state')).toContainText('blocked before data access');
  const costs = page.getByText('Compute · Invoice · USD 1.25', {exact: true});
  await expect(costs).toBeHidden();
  await page.getByText('Attempt 1 · queued').click();
  // Expanding the attempt shows each recorded cost; its evidence fingerprint
  // stays in the downloadable run record, not on screen.
  await expect(costs).toBeVisible();
  await expect(page.locator('#research-governed-runs')).not.toContainText(digest('5'));
  const overflow = await page.evaluate(() => ({viewport:document.documentElement.clientWidth,
    page:document.documentElement.scrollWidth, elements:[...document.querySelectorAll('.research-workspace *')]
      .filter(node => !node.closest('[hidden]') && node.getBoundingClientRect().width &&
        node.getBoundingClientRect().right > document.documentElement.clientWidth + 1)
      .slice(0, 5).map(node => ({tag:node.tagName, id:node.id, text:node.textContent.slice(0, 40)}))}));
  expect(overflow.page, JSON.stringify(overflow)).toBeLessThanOrEqual(overflow.viewport + 1);
  expect(overflow.elements, JSON.stringify(overflow)).toEqual([]);
});
