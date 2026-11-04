(function () {
  'use strict';
  const root = document.querySelector('[data-vendor-profile]');
  if (!root) return;
  const id = root.dataset.vendorProfile, API = '/api/v1/vendor-profiles';
  const status = root.querySelector('[data-vp-status]'), content = root.querySelector('[data-vp-content]');
  const review = root.querySelector('[data-vp-review]'), original = root.querySelector('[data-vp-original]');
  const storageKey = 'lightwork.vendor-profile.original.' + id;
  let state, generation = 0, busy = false;
  const translations = {owner_review: 'Ready for owner review', under_review: 'Under review', not_evaluated: 'Not evaluated yet', incomplete: 'Waiting for answers', remediation_required: 'Fixes needed', escalation_required: 'Escalation needed', auto_approved: 'Automatically approved under the risk policy', human_review: 'A person needs to review', offboarded: 'No longer used', onboarding: 'Onboarding', active: 'Active', suspended: 'Suspended', offboarding: 'Offboarding', completed: 'Completed', waived: 'Waived with recorded evidence', open: 'Open', approved: 'Approved', rejected: 'Rejected', draft: 'Draft', manual: 'Manual', automatic: 'Automatic', none: 'None', limited: 'Limited', internal: 'Internal', public: 'Public', confidential: 'Confidential', restricted: 'Restricted'};
  const words = value => translations[value] || String(value || '').replace(/[_-]+/g, ' ').replace(/^./, letter => letter.toUpperCase());
  const labels = {name: 'Vendor name', display_label: 'Vendor name', category: 'Service category', criticality: 'Business importance', inherent_risk_level: 'Inherent risk', data_access_level: 'Access to company data', territories: 'Countries', service_categories: 'Services', owner: 'Owner', owner_ref: 'Recorded owner', registered_by: 'Registered by', requested_by: 'Requested by', linked_by: 'Linked by', recorded_by: 'Recorded by', authored_by: 'Questionnaire author', approved_by: 'Questionnaire reviewer', actor_ref: 'Decision owner', stage: 'Lifecycle stage', state: 'State', status: 'Status', route: 'Assessment outcome', highest_severity: 'Highest flagged risk', reason_codes: 'Reasons for the outcome', recommendations: 'Recommended follow-up', tasks: 'Follow-up tasks', dependencies: 'Connected systems, access and data', responses: 'Recorded answers', assignments: 'Assigned respondents', template_id: 'Questionnaire', template_version: 'Questionnaire edition', prompt_ref: 'Question', response_type: 'Answer format', question_id: 'Question', required: 'Answer required', options: 'Available answers', risk_rules: 'Rules for flagging risk', mitigation_rules: 'Follow-up rules', evidence_refs: 'Recorded supporting evidence', reference: 'Reference', reason_code: 'Decision reason', task_code: 'Follow-up', recommendation_code: 'Recommended action', retention_seconds: 'Keep period in seconds', retained_until: 'Keep until', registered_at: 'Registered at', created_at: 'Recorded at', updated_at: 'Last updated', requested_at: 'Requested at', linked_at: 'Linked at', recorded_at: 'Recorded at', initiated_at: 'Screening started', decided_at: 'Decision recorded', observed_at: 'Observed at', valid_until: 'Valid until', expires_at: 'Expires at', effective_at: 'Effective at', renews_at: 'Renews at', revision: 'Record edition', activation_assessment: 'Assessment used for activation', highest_risk: 'Highest risk', title_ref: 'Agreement or review name', record_kind: 'Record type', lifecycle: 'Agreement and engagement details', field_schema: 'Custom field definitions', field_values: 'Recorded custom fields', formulas: 'Entered calculations', computed_values: 'Calculated values', agreement_type: 'Agreement type', agreement_ref: 'Where the agreement is kept', governing_law_ref: 'Governing law', renewal_mode: 'Renewal', notice_period_days: 'Notice period in days', field_type: 'Field type', sensitivity: 'Visibility', operator: 'Comparison', value: 'Answer or value', note: 'Note', severity: 'Importance', condition: 'Applies when', retention: 'Keep period'};
  const bookkeeping = new Set(['schema', '_audit_pending', 'request_sha256', 'payload_sha256', 'tenant_sha256', 'history_head_sha256', 'audit_head_sha256']);
  Object.assign(labels, {vendor_jurisdiction_codes: 'Countries', vendor_classification_refs: 'Services', vendor_type: 'Vendor role', vendor_criticality: 'Business importance', vendor_revision: 'Vendor edition', parent_contract_id: 'Related agreement'});
  const identity = value => /^((tpl|tpi|contract|tpc)-principal-|[a-f0-9]{64}$)/.test(String(value || ''));
  function timeLabel(value) { return value ? new Date(value * 1000).toLocaleString() : 'Not recorded'; }
  function businessValue(key, value) {
    if (key.endsWith('_at') || ['retained_until', 'valid_until'].includes(key)) return timeLabel(value);
    if (key === 'inherent_risk_level') return ['Unrated', 'Very low', 'Low', 'Medium', 'High', 'Critical'][value] + ' (' + value + ' of 5)';
    if (key === 'criticality' && typeof value === 'number') return ['Unrated', 'Very low', 'Low', 'Medium', 'High', 'Critical'][value];
    if (key === 'highest_severity' && value === null) return 'No flagged risk';
    if (key === 'territories' || key === 'vendor_jurisdiction_codes') return value.map(code => { try { return new Intl.DisplayNames(undefined, {type: 'region'}).of(code); } catch (_) { return code; } });
    if (key === 'vendor_classification_refs') return value.map(words);
    if (typeof value === 'string' && value.startsWith('user:')) return value.slice(5);
    return typeof value === 'string' && !/^https?:\/\//.test(value) && !/^[A-Z]{2,4}-/.test(value) ? words(value) : value;
  }
  const node = (tag, text, parent) => { const element = document.createElement(tag); if (text !== undefined) element.textContent = text; if (parent) parent.append(element); return element; };
  function display(parent, value, budget = {remaining: 20000}, depth = 0) {
    if (--budget.remaining < 0 || depth > 20) throw new Error('This complete vendor review exceeds its display limit. Nothing can be confirmed.');
    if (Array.isArray(value)) { if (!value.length) node('p', 'None recorded', parent); else value.forEach(child => display(node('section', undefined, parent), child, budget, depth + 1)); }
    else if (value && typeof value === 'object') {
      const entries = Object.entries(value).filter(([key]) => !bookkeeping.has(key));
      const verification = entries.filter(([key, child]) => key.endsWith('_sha256') || identity(child) || ['id', 'tenant_id', 'vendor_id', 'register_vendor_id', 'lifecycle_id', 'assessment_id', 'record_id', 'run_id', 'decision_id', 'policy_id', 'case_id', 'offboarding_plan_id', 'encrypted_profile_ref', 'profile_key_ref', 'vendor_ref', 'vendor_issuer_ref'].includes(key));
      const business = entries.filter(entry => !verification.includes(entry) && !(Array.isArray(entry[1]) && !entry[1].length) && !(entry[1] === null && ['activation_assessment', 'condition'].includes(entry[0])));
      const dl = node('dl', undefined, parent);
      business.forEach(([key, child]) => { node('dt', labels[key] || words(key), dl); display(node('dd', undefined, dl), businessValue(key, child), budget, depth + 1); });
      if (verification.length) { const details = node('details', undefined, parent); node('summary', 'Verification details', details); const facts = node('dl', undefined, details);
        verification.filter(([_key, child]) => child !== null && child !== '').forEach(([key, child]) => { node('dt', key.endsWith('_sha256') ? 'Verification code' : key === 'tenant_id' ? 'Workspace' : labels[key] || 'Record reference', facts); node('dd', String(child), facts); });
      }
    }
    else node('span', value === null || value === undefined || value === '' ? 'Not recorded' : typeof value === 'boolean' ? value ? 'Yes' : 'No' : String(value), parent);
  }
  async function request(path, body, epoch = generation) {
    let response, value;
    const controller = new AbortController(), deadline = setTimeout(() => controller.abort(), 20000);
    try { response = await fetch(API + path, {method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', mode: 'same-origin', redirect: 'error', cache: 'no-store', signal: controller.signal, headers: body === undefined ? {} : {'Content-Type': 'application/json'}, ...(body === undefined ? {} : {body: JSON.stringify(body)})}); value = await response.json(); }
    catch (_) { throw new Error('The reply is unconfirmed. Read the retained original before submitting a separate decision.'); }
    finally { clearTimeout(deadline); }
    if (epoch !== generation) throw new Error('The current vendor view changed. Reopen its complete review.');
    if ([401, 403].includes(response.status)) { state = undefined; content.replaceChildren(); review.replaceChildren(); original.replaceChildren(); }
    if (!response.ok) throw new Error(typeof value.detail === 'string' ? value.detail : 'This current vendor outcome is unavailable. Read its original.');
    return value;
  }
  function link(parent, text, href) { const value = node('a', text, parent); value.href = href; value.className = 'btn'; }
  function button(parent, text, handler) { const value = node('button', text, parent); value.type = 'button'; value.className = 'btn'; value.addEventListener('click', handler); return value; }
  function select(parent, label, rows, optional) { const field = node('label', label, parent), input = node('select', undefined, field); input.className = 'input'; node('option', optional || 'Choose…', input).value = ''; rows.forEach(row => { node('option', row.label, input).value = row.value; }); return input; }
  function reason(parent) { const label = node('label', 'Reason for this decision', parent), input = node('textarea', undefined, label); input.className = 'input'; input.maxLength = 500; input.minLength = 8; input.required = true; return input; }
  function outcomes(value) { original.replaceChildren(); node('p', value.message, original); if (!value.confirmed) node('p', 'This does not establish that every intended effect completed. Read retained original steps before a separate new decision.', original); display(original, value.results || []); }
  async function readOriginal() {
    if (busy) return; busy = true;
    try { const saved = JSON.parse(sessionStorage.getItem(storageKey) || 'null'); if (!saved?.token) throw new Error('No retained vendor review is available in this browser.'); outcomes(await request('/read-original', {token: saved.token, confirmed: true})); }
    catch (error) { status.textContent = error.message; } finally { busy = false; }
  }
  async function showReview(body) {
    if (busy) return; busy = true; review.replaceChildren();
    const epoch = generation;
    try { const value = await request('/' + encodeURIComponent(id) + '/review', {...body, context: state.context});
      value.changes.forEach(row => { node('h3', row.label, review); display(review, row.after); });
      const label = node('label', undefined, review), consent = node('input', undefined, label); consent.type = 'checkbox'; label.append(document.createTextNode(' I reviewed this complete identity, assessment, risk and contract decision.'));
      const apply = button(review, 'Confirm this vendor decision', async () => {
        if (busy || !consent.checked || epoch !== generation) return;
        busy = true; apply.disabled = true;
        try { sessionStorage.setItem(storageKey, JSON.stringify({token: value.token, operation: value.operation}));
          const result = await request('/apply', {token: value.token, confirmed: true}); review.replaceChildren(); outcomes(result); status.textContent = result.message;
        } catch (error) { review.replaceChildren(); status.textContent = error.message + ' Read the original; this request will not be repeated.'; }
        finally { busy = false; await load(false); }
      });
      apply.disabled = true; consent.addEventListener('change', () => { apply.disabled = !consent.checked || busy || epoch !== generation; });
      button(review, 'Cancel review', () => { if (!busy) { generation++; review.replaceChildren(); } });
      status.textContent = 'Read every current setting and consequence. Nothing has been submitted.'; consent.focus();
    } catch (error) { status.textContent = error.message; } finally { busy = false; }
  }
  function section(title) { const host = node('section', undefined, content); host.className = 'panel'; node('h3', title, host); return host; }
  function render() {
    content.replaceChildren();
    const summary = section('Current vendor view');
    node('p', 'Register status: ' + words(state.vendor.status) + '. Importance: ' + words(state.vendor.criticality) + '.', summary);
    node('p', 'Tracked lifecycle: ' + (state.lifecycle.length ? state.lifecycle.map(row => words(row.stage)).join(', ') : 'Not started') + '.', summary);
    node('p', state.activation_blocked || 'The latest evaluated assessment is ready for an explicit owner activation decision.', summary);
    Object.entries(state.modules).forEach(([module, message]) => { if (message !== 'Available') node('p', words(module) + ': ' + message, summary); });
    const assessments = section('Assessments and open tasks');
    state.assessments.forEach(row => { node('p', words(row.route) + ' · ' + (row.highest_severity ? words(row.highest_severity) + ' risk' : 'No assessed risk level') + ' · ' + row.tasks.filter(task => task.status === 'open').length + ' open tasks', assessments); });
    if (!state.assessments.length) node('p', 'No lifecycle assessment is linked to this registered vendor.', assessments);
    link(assessments, 'Open this vendor’s assessments and lifecycle', '/third-party/lifecycle?registered_vendor=' + encodeURIComponent(id));
    const risk = section('Screening and risk decisions');
    if (!state.intelligence.length) node('p', 'No Intelligence identity is linked. Names alone do not establish a match.', risk);
    state.intelligence.forEach(row => { node('p', row.display_label + ' · inherent risk ' + row.inherent_risk_level + ' of 5', risk); });
    state.screening.sort((a, b) => b.initiated_at - a.initiated_at).slice(0, 5).forEach(row => node('p', 'Screening: ' + words(row.state) + ' · ' + new Date(row.initiated_at * 1000).toLocaleString(), risk));
    state.decisions.sort((a, b) => b.decided_at - a.decided_at).slice(0, 5).forEach(row => node('p', 'Risk decision: ' + words(row.status) + ' · ' + new Date(row.decided_at * 1000).toLocaleString(), risk));
    node('p', state.due_diligence.filter(row => row.state !== 'closed').length + ' retained due diligence reviews; inspect their actual task and decision status before activation.', risk);
    link(risk, 'Open screening for this registered vendor', '/third-party/intelligence?registered_vendor=' + encodeURIComponent(id));
    if (!state.intelligence.length && state.unbound_profiles.length) { const selected = select(risk, 'Existing intelligence identity to link', state.unbound_profiles), why = reason(risk);
      button(risk, 'Review linking this existing identity', () => showReview({action: 'bind', intelligence: selected.value, reason: why.value}));
    }
    const contracts = section('Contracts and engagements');
    state.contracts.forEach(row => node('p', words(row.title_ref) + ' · ' + words(row.status), contracts));
    if (!state.contracts.length) node('p', 'No retained contract or engagement is linked to this vendor’s Intelligence identity.', contracts);
    link(contracts, 'Open Contracts using this existing vendor identity', '/third-party/contracts?registered_vendor=' + encodeURIComponent(id));
    const activation = section('Review activation');
    node('p', 'The current registered vendor and any selected tracked lifecycle will be marked active. Existing screening, risk decisions and contracts are retained. Activation is an owner decision; it does not certify the vendor.', activation);
    if (state.activation) { const tracked = select(activation, 'Tracked lifecycle to activate with the master record', state.lifecycle.map(row => ({value: row.lifecycle_id, label: words(row.stage) + ' · ' + row.lifecycle_id})), 'Master register only'), why = reason(activation);
      button(activation, 'Review current assessment and activate', () => showReview({action: 'activate', lifecycle: tracked.value || null, reason: why.value}));
    } else node('p', state.activation_blocked, activation);
    node('p', state.notice, content);
  }
  async function load(clearReview = true) { if (clearReview) { generation++; review.replaceChildren(); } try { state = await request('/' + encodeURIComponent(id)); render(); if (clearReview) status.textContent = 'Current linked vendor records are ready.'; } catch (error) { status.textContent = error.message; } }
  root.querySelector('[data-vp-refresh]').addEventListener('click', () => { if (!busy) load(); });
  root.querySelector('[data-vp-read]').addEventListener('click', readOriginal);
  ['lightwork:account-context-changed', 'lightwork:workspace-changed', 'lightwork:authority-changed', 'lightwork:copilot-context-changed'].forEach(event => document.addEventListener(event, () => { generation++; state = undefined; content.replaceChildren(); review.replaceChildren(); original.replaceChildren(); status.textContent = 'Your account or workspace changed. Reopen the current vendor view.'; }));
  load();
}());
