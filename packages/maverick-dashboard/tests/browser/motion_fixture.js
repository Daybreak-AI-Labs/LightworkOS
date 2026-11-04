// Real templates/controllers with deterministic synthetic records. This fixture
// exercises reveal interactions; it does not qualify backend authority or data.
const fs = require('node:fs');
const path = require('node:path');
const folder = path.resolve(__dirname, '../../maverick_dashboard');
const read = file => fs.readFileSync(path.join(folder, file), 'utf8');
const shared = read('static/lightwork-ui.js');
const reveal = shared.match(/window\.mvReveal = function[\s\S]*?\n};/);
if (!reveal) throw new Error('The real mvReveal helper could not be located');
const ME = 'tpl-principal-' + '1'.repeat(32);
const vendor = {vendor_id: 'vendor-x', display_label: 'Acme Corp', revision: 7, state: 'active', territories: ['GLOBAL']};
const question = {question_id: 'Do-you-encrypt-data', prompt_ref: 'Do-you-encrypt-data', domain: 'security', response_type: 'boolean', required: true, options: [], risk_rules: []};
const template = {template_id: 'security-review', version: 1, title_ref: 'Security-review', state: 'approved', revision: 2, authored_by: 'tpl-principal-' + '2'.repeat(32), questions: [question]};
const assessment = {assessment_id: 'assessment-1', vendor_ref: 'vend-acme', template_id: 'security-review', template_version: 1, owner_ref: ME, assignments: {[question.question_id]: ME}, responses: {}, tasks: [], route: 'not_evaluated', recommendations: [], revision: 3};
const invitation = {invitation_id: 'invitation-1', vendor_ref: 'vend-acme', assessment_id: 'assessment-1', template_id: template.template_id, template_version: 1, respondent_ref: 'vendor-contact.vend-acme', allowed_question_ids: [question.question_id], status: 'active', revision: 4, expires_at: 1893456000, legal_hold: false};
const entities = [{entity_ref_sha256: 'a'.repeat(64), entity_kind: 'governance_resource', origin: 'suite_capture', source_id: 'privacy_automation', record_count: 3}, {entity_ref_sha256: 'b'.repeat(64), entity_kind: 'vendor', origin: 'entity_graph'}];
const relationships = [{source_entity_ref_sha256: entities[0].entity_ref_sha256, relation_type: 'assesses', target_entity_ref_sha256: entities[1].entity_ref_sha256}];
const definitions = {
  collaboration: {template: 'third_party_collaboration', controller: 'third-party-collaboration', root: 'tpc-root', api: '/api/v1/third-party/collaboration', ready: '#tpc-invitations button', steps: [
    {trigger: '#tpc-invite', target: 'tpc-invite-panel', focus: '#tpc-invite-form [name="assessment"]'},
    {within: '#tpc-invitations', label: 'Send a new link', target: 'tpc-once'},
  ]},
  contracts: {template: 'third_party_contracts', controller: 'third-party-contracts', root: 'third-party-contracts-shell', api: '/api/v1/third-party/contracts', ready: '#tpc-record-list button', steps: [
    {within: '#tpc-record-list', label: 'View details', target: 'tpc-detail'},
    {within: '#tpc-record-list', label: 'Edit', target: 'tpc-editor', focus: '#tpc-create-form [name="title"]'},
  ]},
  intelligence: {template: 'third_party_intelligence', controller: 'third-party-intelligence', root: 'tpi-root', api: '/api/v1/third-party/intelligence', ready: '#tpi-cases button', steps: [
    {within: '#tpi-runs', label: 'Possible matches', target: 'tpi-findings'},
    {within: '#tpi-cases', label: 'Open', target: 'tpi-case-detail'},
  ]},
  lifecycle: {template: 'third_party_lifecycle', controller: 'third-party-lifecycle', root: 'tpl-root', api: '/api/v1/third-party/lifecycle', ready: '#tpl-offboarding button', steps: [
    {trigger: '#tpl-new-template', target: 'tpl-template-form', focus: '#tpl-template-form [name="title"]'},
    {within: '#tpl-assessments', label: 'Open', target: 'tpl-assessment-detail'},
    {within: '#tpl-offboarding', label: 'Tasks', target: 'tpl-plan-detail'},
  ]},
  inventory: {template: 'shared_governance_inventory', controller: 'shared-governance-inventory', root: 'sgi-root', api: '/api/v1/governance/inventory', ready: '#sgi-entity-rows button', steps: [
    {trigger: '#sgi-entity-rows button', target: 'sgi-links-title'},
  ]},
};

function fixture(name) {
  const def = definitions[name];
  const markup = read('templates/' + def.template + '.html')
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/{% if not (?:contracts_[a-z_]+|inventory_can_[a-z]+) %}[\s\S]*?{% endif %}/g, '')
    .replace(/{%-?[\s\S]*?-?%}/g, '').replace(/{{[\s\S]*?}}/g, '');
  // shell: the whole of lightwork-ui.js, which base.html loads before page
  // scripts (mvFetchJSON, mvStatus, mvErrorText as well as mvReveal).
  return {...def, markup, css: read('static/lightwork.css'), reveal: reveal[0], shell: shared,
    helpers: read('static/lightwork-record-workflows.js'), source: read('static/lightwork-' + def.controller + '.js')};
}

function reply(name, pathname, method = 'GET') {
  if (pathname === '/api/v1/vendors') return {vendors: [{id: 'vend-acme', name: 'Acme Corp'}]};
  if (pathname === '/api/v1/choices/people') return {people: [{value: 'user:ann@example.com', label: 'Ann'}]};
  // Named sign-in is set up, so questionnaire authoring is offered.
  if (pathname.endsWith('/people')) return {me: ME, items: [{value: ME, label: 'Me'}], named_signin: true};
  const p = pathname.replace(definitions[name].api, '');
  if (name === 'collaboration') {
    if (pathname.endsWith('/lifecycle/templates')) return {items: [template]};
    if (pathname.endsWith('/lifecycle/assessments')) return {items: [{...assessment, assignments: {[question.question_id]: invitation.respondent_ref}}]};
    if (p === '/sharing') return {portal_path: '/api/v1/external/third-party-collaboration/portal_ref_1234567890/portal', limits: {invitation_seconds: 604800, retention_seconds: 31536000, max_artifacts: 20, max_artifact_bytes: 10485760}};
    if (p === '/invitations' && method === 'GET') return {items: [invitation], next_after: null};
    if (p === '/invitations/invitation-1/rotate' && method === 'POST') return {invitation, token: 'tpc1.' + 'A'.repeat(43), token_disclosed: true};
  }
  if (name === 'contracts') {
    if (p === '/status') return {enabled: true, configured: true, ready: true};
    if (pathname === '/api/v1/third-party/intelligence/vendors') return {items: [vendor]};
    if (!p) return {items: [{record_id: 'contract-1', record_kind: 'contract', vendor_id: vendor.vendor_id, title_ref: 'Acme-master-agreement', owner_ref: 'user:ann.at.example.com', status: 'active', revision: 4, lifecycle: {agreement_type: 'master_services', agreement_ref: 'doc.Legal-drive', renewal_mode: 'manual', expires_at: 1893456000, notice_period_days: 30}, field_schema: [], field_values: {}, formulas: [], computed_values: {}}]};
  }
  if (name === 'intelligence') {
    if (p === '/me') return {principal_ref: 'tpi-principal-' + '1'.repeat(32)};
    if (p === '/status') return {provider_runtime: {enabled_providers: []}, provider_scheduler: {running: false}};
    if (p === '/vendors') return {items: [vendor]};
    if (p === '/screening/runs') return {items: [{run_id: 'run-1', vendor_id: vendor.vendor_id, requested_kinds: ['sanctions'], state: 'open', revision: 1}]};
    if (p === '/edd/cases') return {items: [{case_id: 'case-1', vendor_id: vendor.vendor_id, reason: 'Review', severity: 'medium', state: 'open', tasks: [], evidence: [], revision: 1}]};
    if (['/sources', '/snapshots', '/risk/policies', '/risk/decisions', '/monitors', '/monitoring/alerts', '/exchange/consents', '/alert-recipients', '/outbox', '/screening/runs/run-1/findings'].includes(p)) return {items: []};
  }
  if (name === 'lifecycle') {
    if (p === '/templates') return {items: [template]};
    if (p === '/assessments') return {items: [assessment]};
    if (p === '/lifecycles') return {items: [{lifecycle_id: 'lc-1', vendor_ref: 'vend-acme', owner_ref: ME, stage: 'offboarding', dependencies: [], offboarding_plan_id: 'plan-1', revision: 1}]};
    if (p === '/offboarding') return {items: [{plan_id: 'plan-1', lifecycle_id: 'lc-1', state: 'in_progress', tasks: [], blockers: [], revision: 1}]};
  }
  if (name === 'inventory') {
    if (p === '/status') return {enabled: true, ready: true, complete: true, active: {snapshot_id: 'snap-1', revision: 4, integrity_sha256: 'c'.repeat(64)}, sources: [{source_id: 'privacy_automation', complete: true}]};
    if (p === '/snapshots/current') return {projection: {entities, relationships}};
    if (p === '/snapshots') return {items: [{snapshot_id: 'snap-1', version: 4, state: 'available', entity_count: 2, payload_available: true}]};
    if (p === '/entities') return {items: entities, total_matching: 2, next_cursor: null};
    if (p === '/relationships') return {items: relationships, total_matching: 1, next_cursor: null};
  }
  throw new Error('Unexpected motion fixture request: ' + method + ' ' + pathname);
}

function setup(window, def) {
  Object.assign(window.document.getElementById(def.root).dataset, {api: def.api, apiBase: def.api,
    lifecycleApi: '/api/v1/third-party/lifecycle', canAdmin: 'true', canAudit: 'true', canOperate: 'true'});
  // Synthetic preparation only, so rotate can reach the real one-time reveal.
  // Confirmation/dialog semantics are not part of this motion qualification.
  window.mvForm = async () => ({expires: '7'});
  window.mvConfirm = async () => true;
  window.mvErrorText = (_, action) => 'Could not ' + action + '.';
}
module.exports = {fixture, reply, setup, names: Object.keys(definitions)};
