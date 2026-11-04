(function () {
  'use strict';

  const host = document.getElementById('op-accounting-summary');
  const root = document.getElementById('outcome-pilots');
  const previousButton = document.getElementById('op-accounting-previous');
  const nextButton = document.getElementById('op-accounting-next');
  if (!host || !root) return;

  const MAX_PAGE = 100;
  const MAX_EVENTS = 5000;
  const MAX_CURRENCIES = MAX_EVENTS;
  const MAX_TIMESTAMP = 253402300799;
  const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$/;
  const SHA256 = /^[0-9a-f]{64}$/;
  const MONEY = /^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/;
  const CURRENCY = /^[A-Z]{3}$/;
  const COST_CATEGORIES = new Set([
    'allocation', 'evaluation', 'exception', 'generation', 'human', 'inference',
    'other', 'retrieval', 'review', 'rework', 'retry', 'search', 'setup',
    'storage', 'support', 'update',
  ]);
  const PROVIDER_USAGE_CATEGORIES = new Set([
    'evaluation', 'generation', 'inference', 'retrieval', 'search', 'storage', 'update',
  ]);
  const ALLOCATION_METHODS = new Set([
    'direct', 'equal_share', 'operator_estimate', 'unattributed', 'usage_weighted',
  ]);
  const ATTEMPT_STATES = new Set(['cancelled', 'failed', 'succeeded', 'unknown']);
  const COST_BASES = new Set(['estimated', 'observed', 'settled', 'unknown']);
  const SOURCE_ASSURANCES = new Set([
    'application_observation', 'operator_assertion', 'local_signed_receipt',
    'authenticated_provider_invoice',
  ]);
  const previousCursors = [];
  let currentCursor = '';
  let nextCursor = null;
  let pageRequest = 0;
  let renderGeneration = 0;

  class ProjectionError extends Error {}

  const NEXT = ' Refresh the page and try again.';
  const fail = message => { throw new ProjectionError(message); };
  const node = (tag, value, className) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (value !== undefined) element.textContent = value;
    return element;
  };
  function object(value, label) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      fail(label + ' is missing from the report.' + NEXT);
    }
    return value;
  }
  function text(value, label, limit, optional) {
    if (optional && value === null) return null;
    if (typeof value !== 'string' || value.length < 1 || value.length > limit) {
      fail(label + ' is missing or too long.' + NEXT);
    }
    return value;
  }
  function opaque(value, label, limit, optional) {
    const result = text(value, label, limit, optional);
    if (result !== null && /[\u0000-\u001f\u007f]/.test(result)) fail(label + ' contains characters this page cannot show.' + NEXT);
    return result;
  }
  function identifier(value, label) {
    const result = opaque(value, label, 200, false);
    if (!ID.test(result)) fail(label + ' is missing a valid reference.' + NEXT);
    return result;
  }
  function sha256(value, label) {
    if (typeof value !== 'string' || !SHA256.test(value)) fail(label + ' is missing a valid fingerprint.' + NEXT);
    return value;
  }
  function enumeration(value, label, allowed) {
    if (typeof value !== 'string' || !allowed.has(value)) fail(label + ' has a value this page does not recognise.' + NEXT);
    return value;
  }
  function boolean(value, label) {
    if (typeof value !== 'boolean') fail(label + ' must be yes or no.' + NEXT);
    return value;
  }
  function count(value, label, maximum) {
    if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
      fail(label + ' must be a whole number of 0 or more.' + NEXT);
    }
    return value;
  }
  function timestamp(value, label, optional) {
    if (optional && value === null) return null;
    if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0 || value > MAX_TIMESTAMP) {
      fail(label + ' must be a date and time.' + NEXT);
    }
    return value;
  }
  function money(value, label, optional) {
    if (optional && value === null) return null;
    if (typeof value !== 'string' || value.length > 64 || !MONEY.test(value)) {
      fail(label + ' must be an amount of money.' + NEXT);
    }
    return value;
  }
  function currency(value, label, optional) {
    if (optional && value === null) return null;
    if (typeof value !== 'string' || !CURRENCY.test(value)) fail(label + ' uses a currency Lightwork does not recognise.' + NEXT);
    return value;
  }
  function array(value, label, maximum) {
    if (!Array.isArray(value) || value.length > maximum) fail(label + ' is missing or lists too many items.' + NEXT);
    return value;
  }
  function cursor(value, label, optional) {
    if (optional && value === null) return null;
    if (typeof value !== 'string' || value.length > 64 || !/^[A-Za-z0-9][A-Za-z0-9_.:-]*$/.test(value)) {
      fail(label + ' is not a valid link to the next page.' + NEXT);
    }
    return value;
  }
  function safeMessage(error) {
    return error instanceof ProjectionError
      ? error.message
      : 'Outcome accounting could not be verified. Refresh the page and try again.';
  }
  function status(value, label, allowed) {
    const row = object(value, label);
    enumeration(row.status, label + ' status', allowed);
    text(row.reason, label + ' reason', 1000, false);
    return row;
  }
  function totals(value, label) {
    const rows = object(value, label);
    const entries = Object.entries(rows);
    if (entries.length > MAX_CURRENCIES) fail(label + ' lists too many currencies.' + NEXT);
    entries.forEach(([code, amount]) => {
      currency(code, label + ' currency', false);
      money(amount, label + ' amount', false);
    });
    return entries;
  }
  function overflowCurrencies(value, label) {
    const rows = array(value, label, MAX_CURRENCIES);
    const seen = new Set();
    rows.forEach(code => {
      currency(code, label + ' currency', false);
      if (seen.has(code)) fail(label + ' lists the same currency twice.' + NEXT);
      seen.add(code);
    });
    return rows;
  }

  function providerOrFailedAttemptEvidence(event) {
    const providerUsage = PROVIDER_USAGE_CATEGORIES.has(event.category) ||
      event.budget_reconciliation !== null ||
      event.source_assurance === 'authenticated_provider_invoice' ||
      event.pricing_evidence !== null ||
      (
        event.category === 'allocation' &&
        event.source_assurance === 'application_observation' &&
        event.allocation_method === 'operator_estimate' &&
        event.source_ref.startsWith('outcome-pilot:') &&
        event.source_ref.includes(':provider-allocation:')
      );
    return providerUsage || event.attempt_state === 'failed' || event.category === 'retry';
  }

  function validateCostSummary(value, detailed) {
    const costs = object(value, 'Cost summary');
    boolean(costs.complete, 'Cost completeness');
    boolean(costs.coverage_complete, 'Cost coverage');
    boolean(costs.attempt_states_complete, 'Attempt coverage');
    enumeration(
      costs.settlement_status, 'Cost settlement',
      new Set(['incomplete', 'settled', 'estimated', 'observed']),
    );
    const knownTotals = totals(costs.known_totals, 'Recorded cost totals');
    const overflows = overflowCurrencies(
      costs.aggregate_overflow_currencies, 'Cost aggregate overflow',
    );
    if (knownTotals.some(([code]) => overflows.includes(code))) {
      fail('Cost totals and aggregate overflow conflict.');
    }
    const eventCount = count(costs.event_count, 'Current cost event count', MAX_EVENTS);
    const unknownCount = count(costs.unknown_event_count, 'Unknown cost event count', MAX_EVENTS);
    const additiveUnknownCount = count(
      costs.additive_unknown_event_count, 'Unknown additive cost event count', MAX_EVENTS,
    );
    const failedAttemptCount = count(costs.failed_attempt_count, 'Failed attempt count', MAX_EVENTS);
    const failedEventCount = count(costs.failed_attempt_event_count, 'Failed cost event count', MAX_EVENTS);
    const invoiceCount = count(costs.authenticated_provider_invoice_count, 'Provider invoice count', MAX_EVENTS);
    const receiptCount = count(costs.local_signed_receipt_count, 'Signed receipt count', MAX_EVENTS);
    const reconciledCount = count(costs.reconciled_reservation_count, 'Reservation count', MAX_EVENTS);
    count(costs.budget_overrun_count, 'Budget overrun count', MAX_EVENTS);
    const informationalCount = count(
      costs.informational_event_count, 'Informational cost event count', MAX_EVENTS,
    );
    const coverageCount = count(costs.coverage_event_count, 'Coverage event count', MAX_EVENTS);
    const additiveCount = count(costs.additive_event_count, 'Additive cost event count', MAX_EVENTS);
    count(costs.superseded_event_count, 'Superseded cost event count', MAX_EVENTS);
    text(costs.display, 'Cost display', 1000, false);
    if (
      unknownCount > eventCount || additiveUnknownCount > unknownCount ||
      additiveCount + informationalCount + coverageCount !== eventCount ||
      failedEventCount > eventCount ||
      invoiceCount > eventCount || receiptCount > eventCount ||
      invoiceCount + receiptCount > eventCount || reconciledCount > eventCount ||
      failedAttemptCount > failedEventCount
    ) fail('Cost event counts do not reconcile.');
    if (costs.complete && (
      costs.settlement_status === 'incomplete' || additiveUnknownCount || overflows.length
    )) {
      fail('Cost completeness does not reconcile.');
    }
    if (!costs.complete && costs.settlement_status !== 'incomplete') {
      fail('Cost completeness does not reconcile.');
    }
    if (detailed) {
      const events = array(costs.events, 'Cost events', MAX_EVENTS);
      const ids = new Set();
      events.forEach(event => {
        validateCostEvent(event);
        if (ids.has(event.id)) fail('Cost event identity is duplicated.');
        ids.add(event.id);
      });
      const current = events.filter(event => event.current);
      const failedRefs = new Set(
        current.filter(event => event.attempt_state === 'failed').map(event => event.attempt_ref),
      );
      const additive = current.filter(event => event.aggregation === 'additive');
      const unresolvedProviderOrAttempt = current.filter(event =>
        providerOrFailedAttemptEvidence(event) &&
        (event.amount === null || event.attempt_state === 'unknown'),
      );
      const attemptStatesComplete =
        additive.every(event => event.attempt_state !== 'unknown') &&
        unresolvedProviderOrAttempt.every(event => event.attempt_state !== 'unknown');
      if (
        current.length !== eventCount ||
        attemptStatesComplete !== costs.attempt_states_complete ||
        current.filter(event => event.amount === null).length !== unknownCount ||
        current.filter(event => event.aggregation === 'additive' && event.amount === null).length !== additiveUnknownCount ||
        additive.length !== additiveCount ||
        current.filter(event => event.aggregation === 'informational').length !== informationalCount ||
        current.filter(event => event.aggregation === 'coverage').length !== coverageCount ||
        current.filter(event => event.attempt_state === 'failed').length !== failedEventCount ||
        failedRefs.size !== failedAttemptCount ||
        current.filter(event => event.source_assurance === 'authenticated_provider_invoice').length !== invoiceCount ||
        current.filter(event => event.source_assurance === 'local_signed_receipt').length !== receiptCount ||
        current.filter(event => event.budget_reconciliation !== null).length !== reconciledCount ||
        events.filter(event => !event.current && event.current_reason === 'superseded').length !== costs.superseded_event_count
      ) fail('Detailed cost events do not reconcile.');
    }
    return costs;
  }

  function validatePricingEvidence(value) {
    if (value === null) return null;
    const pricing = object(value, 'Pricing evidence');
    opaque(pricing.model_id, 'Pricing model', 512, false);
    money(pricing.input_per_mtok, 'Input token rate', false);
    money(pricing.output_per_mtok, 'Output token rate', false);
    opaque(pricing.source, 'Pricing source', 2048, false);
    text(pricing.as_of, 'Pricing date', 64, false);
    text(pricing.fetched_at, 'Pricing retrieval time', 128, false);
    currency(pricing.currency, 'Pricing currency', false);
    if (
      typeof pricing.confidence !== 'number' || !Number.isFinite(pricing.confidence) ||
      pricing.confidence < 0 || pricing.confidence > 1
    ) fail('The pricing record gives a confidence outside 0 to 1. Refresh the page and try again.');
    boolean(pricing.verified, 'Pricing verification');
    opaque(pricing.rate_card_version, 'Rate-card version', 256, false);
    opaque(pricing.evidence_id, 'Pricing evidence identity', 256, false);
    text(pricing.pricing_basis, 'Pricing basis', 1000, false);
    text(pricing.applicability, 'Pricing applicability', 1000, false);
    return pricing;
  }

  function validateReconciliation(value) {
    if (value === null) return null;
    const row = object(value, 'Budget reconciliation');
    opaque(row.reservation_ref, 'Reservation reference', 512, false);
    money(row.reserved_amount, 'Reserved amount', false);
    money(row.final_amount, 'Final reservation amount', true);
    currency(row.currency, 'Reservation currency', false);
    money(row.delta, 'Reservation delta', true);
    enumeration(
      row.status, 'Reservation status',
      new Set(['held', 'unknown', 'matched', 'released', 'overrun']),
    );
    opaque(row.verification_authority, 'Reservation authority', 512, false);
    if ((row.status === 'held' || row.status === 'unknown') !== (row.final_amount === null)) {
      fail('Reservation settlement does not reconcile.');
    }
    if ((row.final_amount === null) !== (row.delta === null)) {
      fail('Reservation settlement does not reconcile.');
    }
    return row;
  }

  function validateCostEvent(value) {
    const event = object(value, 'Cost event');
    event.id = identifier(event.id, 'Cost event identity');
    enumeration(event.category, 'Cost category', COST_CATEGORIES);
    enumeration(event.attempt_state, 'Cost attempt state', ATTEMPT_STATES);
    enumeration(event.basis, 'Cost basis', COST_BASES);
    enumeration(event.aggregation, 'Cost aggregation', new Set(['additive', 'informational', 'coverage']));
    enumeration(event.coverage, 'Cost coverage', new Set(['partial', 'complete']));
    enumeration(event.budget_state, 'Budget state', new Set([
      'not_applicable', 'within_limit', 'limit_exceeded', 'metering_failed',
    ]));
    enumeration(event.source_assurance, 'Cost source assurance', SOURCE_ASSURANCES);
    event.amount = money(event.amount, 'Cost amount', true);
    event.currency = currency(event.currency, 'Cost currency', true);
    if ((event.amount === null) !== (event.currency === null)) fail('Cost amount and currency do not reconcile.');
    if ((event.amount === null) !== (event.basis === 'unknown')) fail('Unknown cost basis does not reconcile.');
    event.quantity = money(event.quantity, 'Cost quantity', true);
    event.unit = text(event.unit, 'Cost unit', 32, true);
    if ((event.quantity === null) !== (event.unit === null)) fail('Cost quantity and unit do not reconcile.');
    event.unknown_reason = text(event.unknown_reason, 'Unknown cost reason', 1000, true);
    if ((event.amount === null) !== (event.unknown_reason !== null)) fail('Unknown cost reason does not reconcile.');
    event.source_ref = text(event.source_ref, 'Cost source', 512, false);
    event.source_version = sha256(event.source_version, 'Cost source version');
    event.attempt_ref = opaque(event.attempt_ref, 'Cost attempt', 512, false);
    event.correction_of = event.correction_of === null ? null : identifier(event.correction_of, 'Cost correction');
    event.correction_reason = text(
      event.correction_reason === undefined ? null : event.correction_reason,
      'Cost correction reason', 2000, true,
    );
    event.allocation_method = enumeration(
      event.allocation_method === undefined ? 'direct' : event.allocation_method,
      'Cost allocation method', ALLOCATION_METHODS,
    );
    event.allocation_assumption = text(
      event.allocation_assumption === undefined ? null : event.allocation_assumption,
      'Cost allocation assumption', 2000, true,
    );
    if (event.allocation_method !== 'direct' && event.allocation_assumption === null) {
      fail('Cost allocation assumption is missing.');
    }
    event.evidence_note = text(
      event.evidence_note === undefined ? null : event.evidence_note,
      'Cost evidence details', 4000, true,
    );
    event.actor = text(event.actor, 'Cost actor', 4096, false);
    event.recorded_at = timestamp(event.recorded_at, 'Cost time', false);
    event.current = boolean(event.current, 'Current cost state');
    event.current_reason = enumeration(
      event.current_reason, 'Current cost reason',
      new Set(['current', 'superseded', 'not_yet_effective', 'expired']),
    );
    event.coverage_scope_sha256 = event.coverage_scope_sha256 === null
      ? null : sha256(event.coverage_scope_sha256, 'Cost coverage scope');
    event.evidence_ref = opaque(event.evidence_ref, 'Cost evidence reference', 512, true);
    event.evidence_sha256 = event.evidence_sha256 === null
      ? null : sha256(event.evidence_sha256, 'Cost evidence digest');
    event.verification_authority = opaque(
      event.verification_authority, 'Cost evidence authority', 512, true,
    );
    const exactEvidence = event.source_assurance === 'local_signed_receipt' ||
      event.source_assurance === 'authenticated_provider_invoice';
    if (exactEvidence !== (
      event.evidence_ref !== null && event.evidence_sha256 !== null &&
      event.verification_authority !== null
    )) fail('Cost evidence assurance does not reconcile.');
    event.pricing_evidence = validatePricingEvidence(event.pricing_evidence);
    if (event.pricing_evidence && event.pricing_evidence.currency !== event.currency) {
      fail('The pricing record uses a different currency from the cost. Refresh the page and try again.');
    }
    if (
      event.pricing_evidence &&
      ((!event.pricing_evidence.verified && event.basis === 'observed') || event.amount === null)
    ) fail('The pricing record does not support how this cost was worked out. Refresh the page and try again.');
    event.budget_reconciliation = validateReconciliation(event.budget_reconciliation);
    if (
      event.budget_reconciliation && event.budget_reconciliation.final_amount !== null &&
      (event.budget_reconciliation.final_amount !== event.amount ||
       event.budget_reconciliation.currency !== event.currency)
    ) fail('The settled budget amount does not match the recorded cost. Refresh the page and try again.');
    return event;
  }

  function validateRecordSummary(value) {
    const record = object(value, 'Outcome record');
    record.id = identifier(record.id, 'Outcome record identity');
    count(record.revision, 'Outcome revision', Number.MAX_SAFE_INTEGER);
    opaque(record.admission_id, 'Admission identity', 512, false);
    opaque(record.work_item_id, 'Work item identity', 512, false);
    opaque(record.owner_id, 'Outcome owner', 256, false);
    text(record.acceptance_contract_ref, 'Acceptance contract', 512, false);
    timestamp(record.admitted_at, 'Admission time', false);
    enumeration(record.disposition, 'Outcome disposition', new Set(['active', 'cancelled', 'completed', 'failed']));
    status(record.technical_outcome, 'Technical outcome', new Set(['verified', 'failed', 'unresolved']));
    status(record.business_outcome, 'Business outcome', new Set(['accepted', 'rejected', 'unresolved']));
    sha256(record.evidence_version, 'Evidence version');
    count(record.observation_count, 'Observation count', MAX_EVENTS);
    count(record.decision_count, 'Decision count', MAX_EVENTS);
    count(record.disposition_count, 'Disposition count', MAX_EVENTS);
    validateCostSummary(record.costs, false);
    return record;
  }

  function recordCategory(record) {
    if (record.disposition === 'cancelled') return 'cancelled';
    if (record.disposition === 'failed' || record.technical_outcome.status === 'failed') return 'failed';
    if (record.business_outcome.status === 'accepted') return 'accepted';
    if (record.business_outcome.status === 'rejected') return 'rejected';
    return 'unresolved';
  }

  function validatePortfolio(data, requestedCursor) {
    const report = object(data, 'Outcome accounting');
    if (
      report.schema !== 'lightwork.outcome-accounting-portfolio.v1' ||
      report.context !== context || report.reconciles !== true
    ) fail('The outcome accounting is for a different account or workspace, or its totals do not add up. Refresh the page and try again.');
    const admitted = count(report.admitted, 'Admission count', MAX_PAGE);
    const categoryNames = ['accepted', 'rejected', 'failed', 'cancelled', 'unresolved'];
    const categories = object(report.categories, 'Outcome categories');
    const categoryValues = categoryNames.map(name => count(categories[name], name, MAX_PAGE));
    if (categoryValues.reduce((total, value) => total + value, 0) !== admitted) {
      fail('Outcome categories do not reconcile.');
    }
    const records = array(report.records, 'Outcome records', MAX_PAGE).map(validateRecordSummary);
    if (records.length !== admitted || new Set(records.map(row => row.id)).size !== records.length) {
      fail('Outcome records do not reconcile.');
    }
    const derivedCategories = Object.fromEntries(categoryNames.map(name => [name, 0]));
    records.forEach(record => { derivedCategories[recordCategory(record)] += 1; });
    if (categoryNames.some(name => derivedCategories[name] !== categories[name])) {
      fail('Outcome categories do not reconcile.');
    }

    const costs = object(report.costs, 'Portfolio costs');
    const knownTotals = totals(costs.known_totals, 'Recorded cost totals');
    const overflows = overflowCurrencies(costs.aggregate_overflow_currencies, 'Cost aggregate overflow');
    if (knownTotals.some(([code]) => overflows.includes(code))) fail('Recorded cost totals do not reconcile. Refresh the page and try again.');
    const totalsComplete = boolean(costs.totals_complete, 'Cost total completeness');
    if (totalsComplete !== (overflows.length === 0)) fail('Cost total completeness does not reconcile.');
    const incomplete = count(costs.incomplete_records, 'Incomplete cost count', MAX_PAGE + 1);
    const attempts = count(costs.failed_attempts, 'Failed attempt count', MAX_PAGE * MAX_EVENTS);
    text(costs.basis, 'Portfolio cost basis', 1000, false);
    const expectedIncomplete = records.filter(record => !record.costs.complete).length + (overflows.length ? 1 : 0);
    if (
      incomplete !== expectedIncomplete ||
      attempts !== records.reduce((total, record) => total + record.costs.failed_attempt_count, 0)
    ) fail('Portfolio cost coverage does not reconcile.');

    const page = object(report.page, 'Outcome accounting page');
    if (count(page.limit, 'Accounting page limit', 200) !== MAX_PAGE) fail('The page of outcome accounting is not the one this page asked for. Refresh the page and try again.');
    const returnedCursor = page.cursor === null ? '' : cursor(page.cursor, 'Accounting cursor', false);
    if (returnedCursor !== requestedCursor || typeof page.has_more !== 'boolean') {
      fail('The page of outcome accounting is not the one this page asked for. Refresh the page and try again.');
    }
    boolean(page.scope_complete, 'Accounting scope coverage');
    count(page.scanned_records, 'Scanned record count', 501);
    if (page.scope_complete !== (!requestedCursor && !page.has_more)) {
      fail('Outcome accounting scope does not reconcile.');
    }
    const following = page.has_more
      ? cursor(page.next_cursor, 'Next accounting cursor', false)
      : (page.next_cursor === null ? null : fail('The link to the next page of outcome accounting is not valid. Refresh the page and try again.'));
    return {
      report, admitted, categoryNames, categoryValues, records, costs, knownTotals,
      overflows, incomplete, incompleteRecords: records.filter(record => !record.costs.complete).length,
      attempts, following,
    };
  }

  function validateObservation(value) {
    const row = object(value, 'Outcome observation');
    identifier(row.id, 'Observation identity');
    opaque(row.source_id, 'Observation source', 512, false);
    sha256(row.source_version, 'Observation source version');
    enumeration(row.result, 'Observation result', new Set(['confirmed', 'contradictory', 'missing', 'unavailable']));
    boolean(row.authoritative, 'Observation authority');
    text(row.summary, 'Observation summary', 4000, false);
    timestamp(row.observed_at, 'Observation time', false);
    timestamp(row.valid_until, 'Observation expiry', true);
    if (row.valid_until !== null && row.valid_until <= row.observed_at) fail('An observation expires before it was made. Refresh the page and try again.');
    if (row.correction_of !== null) identifier(row.correction_of, 'Observation correction');
    text(row.actor, 'Observation actor', 4096, false);
    boolean(row.current, 'Current observation state');
    enumeration(row.current_reason, 'Current observation reason', new Set([
      'current', 'superseded', 'not_yet_effective', 'expired',
    ]));
    return row;
  }

  function validateDecision(value) {
    const row = object(value, 'Outcome decision');
    identifier(row.id, 'Decision identity');
    enumeration(row.decision, 'Decision', new Set(['accepted', 'rejected', 'unresolved']));
    text(row.rationale, 'Decision rationale', 4000, false);
    sha256(row.evidence_version, 'Decision evidence version');
    text(row.actor, 'Decision actor', 4096, false);
    timestamp(row.decided_at, 'Decision time', false);
    if (row.supersedes_ref !== null) identifier(row.supersedes_ref, 'Superseded decision');
    boolean(row.current, 'Current decision state');
    enumeration(row.current_reason, 'Current decision reason', new Set([
      'current', 'superseded', 'evidence_changed_or_expired',
    ]));
    return row;
  }

  function validateDisposition(value) {
    const row = object(value, 'Outcome disposition history');
    identifier(row.id, 'Disposition identity');
    enumeration(row.disposition, 'Disposition history state', new Set(['active', 'cancelled', 'completed', 'failed']));
    text(row.reason, 'Disposition reason', 4000, false);
    text(row.actor, 'Disposition actor', 4096, false);
    timestamp(row.recorded_at, 'Disposition time', false);
    return row;
  }

  function validateDetail(data, summary) {
    const detail = object(data, 'Outcome detail');
    if (detail.context !== context || detail.id !== summary.id) {
      fail('The outcome detail is for a different account, workspace or record. Refresh the page and try again.');
    }
    identifier(detail.id, 'Outcome detail identity');
    const revision = count(detail.revision, 'Outcome detail revision', Number.MAX_SAFE_INTEGER);
    if (revision < summary.revision) fail('Outcome detail is older than the visible record.');
    if (detail.work_item_id !== summary.work_item_id || detail.owner_id !== summary.owner_id) {
      fail('The outcome detail is for a different account, workspace or record. Refresh the page and try again.');
    }
    opaque(detail.admission_id, 'Detail admission identity', 512, false);
    opaque(detail.work_item_id, 'Detail work item identity', 512, false);
    opaque(detail.owner_id, 'Detail owner', 256, false);
    text(detail.acceptance_contract_ref, 'Detail acceptance contract', 512, false);
    timestamp(detail.admitted_at, 'Detail admission time', false);
    enumeration(detail.disposition, 'Detail disposition', new Set(['active', 'cancelled', 'completed', 'failed']));
    status(detail.technical_outcome, 'Detail technical outcome', new Set(['verified', 'failed', 'unresolved']));
    status(detail.business_outcome, 'Detail business outcome', new Set(['accepted', 'rejected', 'unresolved']));
    sha256(detail.evidence_version, 'Detail evidence version');
    detail.observations = array(detail.observations, 'Outcome observations', MAX_EVENTS).map(validateObservation);
    detail.decisions = array(detail.decisions, 'Outcome decisions', MAX_EVENTS).map(validateDecision);
    detail.dispositions = array(detail.dispositions, 'Outcome dispositions', MAX_EVENTS).map(validateDisposition);
    detail.costs = validateCostSummary(detail.costs, true);
    const contract = object(detail.platform_contract, 'Outcome platform contract');
    if (
      contract.schema !== 'lightwork.contract.outcome-record.v1' ||
      contract.schema_version !== 1 || contract.id !== detail.id ||
      contract.owner_id !== detail.owner_id || contract.work_item_id !== detail.work_item_id ||
      contract.revision !== detail.revision
    ) fail('The outcome detail\'s source does not match the record. Refresh the page and try again.');
    opaque(contract.tenant_id, 'Outcome contract tenant', 256, false);
    const contractCost = object(contract.cost, 'Outcome contract cost');
    enumeration(contractCost.state, 'Outcome contract cost state', new Set(['exact', 'unknown']));
    if (contractCost.state === 'exact') {
      currency(contractCost.currency, 'Exact contract currency', false);
      money(contractCost.amount, 'Exact contract amount', false);
    } else {
      text(contractCost.reason, 'Unknown contract cost reason', 256, false);
    }
    return detail;
  }

  function assuranceLabel(value) {
    return ({
      authenticated_provider_invoice: 'Authenticated provider invoice',
      local_signed_receipt: 'Local signed receipt',
      application_observation: 'Application observation',
      operator_assertion: 'Operator assertion',
    })[value];
  }
  function settlementLabel(value) {
    return ({
      settled: 'settled', observed: 'observed', estimated: 'estimated', incomplete: 'unknown or incomplete',
    })[value];
  }
  function costBasisLabel(value) {
    return ({
      settled: 'settled from verified evidence', observed: 'observed by the application',
      estimated: 'estimated from rate evidence', unknown: 'unknown',
    })[value];
  }
  function budgetStateLabel(value) {
    return ({
      not_applicable: 'not applicable', within_limit: 'within the limit',
      limit_exceeded: 'limit exceeded', metering_failed: 'metering unavailable',
    })[value];
  }
  function currentReasonLabel(value) {
    return ({
      current: 'current', superseded: 'superseded',
      not_yet_effective: 'not yet effective', expired: 'expired',
      evidence_changed_or_expired: 'evidence changed or expired',
    })[value];
  }
  function contractCostReason(reason) {
    return reason === 'cost_not_settled_by_authenticated_provider_invoice'
      ? 'The complete total is not backed entirely by authenticated provider invoice evidence.'
      : 'The record does not have a complete, authenticated single-currency total.';
  }
  function displayTime(value) {
    return window.mvTimeAbsolute ? window.mvTimeAbsolute(value) : new Date(value * 1000).toISOString();
  }

  function renderAssurance(validated) {
    const invoiceEvents = validated.records.reduce(
      (total, record) => total + record.costs.authenticated_provider_invoice_count, 0,
    );
    const receiptEvents = validated.records.reduce(
      (total, record) => total + record.costs.local_signed_receipt_count, 0,
    );
    const observedRecords = validated.records.filter(record => record.costs.settlement_status === 'observed').length;
    const estimatedRecords = validated.records.filter(record => record.costs.settlement_status === 'estimated').length;
    const exactInvoiceRecords = validated.records.filter(record => {
      const cost = record.costs;
      return cost.complete && cost.settlement_status === 'settled' &&
        Object.keys(cost.known_totals).length === 1 && cost.event_count > 0 &&
        cost.authenticated_provider_invoice_count === cost.additive_event_count;
    }).length;
    const unknownEvents = validated.records.reduce(
      (total, record) => total + record.costs.unknown_event_count, 0,
    );
    const section = node('section', undefined, 'op-accounting-assurance');
    const list = node('ul');
    [
      'Exact authenticated provider invoice cost: ' + exactInvoiceRecords + ' record' + (exactInvoiceRecords === 1 ? '' : 's') + '.',
      'Authenticated provider invoice evidence: ' + invoiceEvents + ' current event' + (invoiceEvents === 1 ? '' : 's') + '.',
      'Local signed receipt evidence: ' + receiptEvents + ' current event' + (receiptEvents === 1 ? '' : 's') + '.',
      'Observed cost: ' + observedRecords + ' complete record' + (observedRecords === 1 ? '' : 's') + '.',
      'Estimated cost: ' + estimatedRecords + ' complete record' + (estimatedRecords === 1 ? '' : 's') + '.',
      'Unknown or incomplete cost: ' + validated.incompleteRecords + ' record' +
        (validated.incompleteRecords === 1 ? '' : 's') + '; ' + unknownEvents +
        ' current unpriced event' + (unknownEvents === 1 ? '' : 's') + '.',
      validated.overflows.length
        ? 'Aggregate overflow: totals for ' + validated.overflows.join(', ') + ' exceed the supported display bound and are not shown as zero.'
        : 'Aggregate overflow: none detected on this page.',
    ].forEach(value => list.appendChild(node('li', value)));
    section.append(
      node('h3', 'Cost assurance on this page'),
      node('p', 'An exact count requires complete single-currency cost and authenticated invoice evidence for every current event. Other invoice and receipt counts describe source evidence. Observed, estimated, and incomplete counts describe whole records, so these counts can overlap.'),
      list,
    );
    return section;
  }

  function appendHistory(section, titleText, rows, describe) {
    section.appendChild(node('h4', titleText));
    if (!rows.length) {
      section.appendChild(node('p', 'None recorded.'));
      return;
    }
    const list = node('ul');
    rows.forEach(row => list.appendChild(node('li', describe(row))));
    section.appendChild(list);
  }

  function renderCostEvent(event) {
    const item = node('li', undefined, 'op-accounting-cost-event');
    const details = node('details');
    const amount = event.amount === null ? 'Amount unknown' : event.currency + ' ' + event.amount;
    details.appendChild(node(
      'summary',
      event.category.charAt(0).toUpperCase() + event.category.slice(1) + ' · ' + amount +
      ' · attempt ' + event.attempt_state + ' · ' + costBasisLabel(event.basis) + ' · ' +
      (event.current ? 'current' : currentReasonLabel(event.current_reason)),
    ));
    details.appendChild(node(
      'p',
      'Source assurance: ' + assuranceLabel(event.source_assurance) +
      '. Source: ' + event.source_ref + '. Version: ' + event.source_version +
      '. Recorded: ' + displayTime(event.recorded_at) + '.',
    ));
    details.appendChild(node(
      'p',
      'Accounting: ' + event.aggregation + ' · ' + event.coverage + ' coverage · budget ' +
      budgetStateLabel(event.budget_state) + ' · attempt ' + event.attempt_ref +
      (event.quantity === null ? '.' : ' · quantity ' + event.quantity + ' ' + event.unit + '.'),
    ));
    details.appendChild(node(
      'p',
      'Allocation: ' + event.allocation_method.replaceAll('_', ' ') +
      (event.allocation_assumption === null ? '.' : ' · ' + event.allocation_assumption),
    ));
    if (event.evidence_note !== null) {
      details.appendChild(node('p', 'Evidence details: ' + event.evidence_note));
    }
    if (event.correction_reason !== null) {
      details.appendChild(node('p', 'Correction reason: ' + event.correction_reason));
    }
    if (event.unknown_reason !== null) details.appendChild(node('p', 'Why cost is unknown: ' + event.unknown_reason));
    if (event.evidence_ref !== null) {
      details.appendChild(node(
        'p',
        'Verified evidence: ' + event.evidence_ref + ' · SHA-256 ' + event.evidence_sha256 +
        ' · authority ' + event.verification_authority + '.',
      ));
    }
    if (event.pricing_evidence !== null) {
      const pricing = event.pricing_evidence;
      details.appendChild(node(
        'p',
        'Rate evidence: ' + (pricing.verified ? 'verified' : 'unverified estimate') +
        ' · ' + pricing.model_id + ' · input ' + pricing.currency + ' ' + pricing.input_per_mtok +
        '/M tokens · output ' + pricing.currency + ' ' + pricing.output_per_mtok +
        '/M tokens · as of ' + pricing.as_of + ' · source ' + pricing.source + '.',
      ));
      details.appendChild(node(
        'p',
        'Applicability: ' + pricing.applicability + ' Pricing basis: ' + pricing.pricing_basis +
        ' Confidence: ' + pricing.confidence + '. Rate card: ' + pricing.rate_card_version +
        '. Evidence: ' + pricing.evidence_id + '. Retrieved: ' + pricing.fetched_at + '.',
      ));
    }
    if (event.budget_reconciliation !== null) {
      const reservation = event.budget_reconciliation;
      details.appendChild(node(
        'p',
        'Provider reservation: ' + reservation.status + ' · reserved ' + reservation.currency + ' ' +
        reservation.reserved_amount + ' · final ' +
        (reservation.final_amount === null ? 'unknown' : reservation.currency + ' ' + reservation.final_amount) +
        ' · adjustment ' + (reservation.delta === null ? 'unknown' : reservation.currency + ' ' + reservation.delta) +
        ' · authority ' + reservation.verification_authority + '.',
      ));
    }
    if (event.correction_of !== null) details.appendChild(node('p', 'Corrects cost event ' + event.correction_of + '.'));
    item.appendChild(details);
    return item;
  }

  function renderDetail(detail, region) {
    const provenance = node('section', undefined, 'op-accounting-provenance');
    provenance.append(
      node('h4', 'Record provenance'),
      node('p', 'Outcome record: ' + detail.id + '. Admission: ' + detail.admission_id + '. Work item: ' + detail.work_item_id + '.'),
      node('p', 'Acceptance contract: ' + detail.acceptance_contract_ref + '. Evidence version: ' + detail.evidence_version + '.'),
      node('p', 'Technical outcome: ' + detail.technical_outcome.status + '. Human outcome: ' + detail.business_outcome.status + '. Disposition: ' + detail.disposition + '.'),
      node(
        'p',
        detail.platform_contract.cost.state === 'exact'
          ? 'Portable cost conclusion: exact ' + detail.platform_contract.cost.currency + ' ' + detail.platform_contract.cost.amount + '.'
          : 'Portable cost conclusion: unknown. ' + contractCostReason(detail.platform_contract.cost.reason),
      ),
    );
    appendHistory(
      provenance, 'Evidence observations', detail.observations,
      row => (row.current ? 'Current' : currentReasonLabel(row.current_reason)) + ' · ' +
        (row.authoritative ? 'authoritative' : 'non-authoritative') + ' · ' + row.result +
        ' · ' + row.source_id + ' · version ' + row.source_version + ' · observed ' +
        displayTime(row.observed_at) + (row.valid_until === null ? '' : ' · valid until ' + displayTime(row.valid_until)) +
        ' · by ' + row.actor + ' · ' + row.summary,
    );
    appendHistory(
      provenance, 'Human decisions', detail.decisions,
      row => (row.current ? 'Current' : currentReasonLabel(row.current_reason)) + ' · ' + row.decision +
        ' · ' + row.actor + ' · decided ' + displayTime(row.decided_at) + ' · ' + row.rationale,
    );
    appendHistory(
      provenance, 'Disposition history', detail.dispositions,
      row => row.disposition + ' · ' + row.actor + ' · recorded ' +
        displayTime(row.recorded_at) + ' · ' + row.reason,
    );

    const costSection = node('section', undefined, 'op-accounting-cost-detail');
    costSection.append(
      node('h4', 'Cost events'),
      node(
        'p',
        'Cost status: ' + settlementLabel(detail.costs.settlement_status) + '. ' +
        detail.costs.display + ' Failed attempts: ' + detail.costs.failed_attempt_count +
        '. Provider invoice events: ' + detail.costs.authenticated_provider_invoice_count +
        '. Local signed receipt events: ' + detail.costs.local_signed_receipt_count + '.',
      ),
    );
    if (!detail.costs.events.length) {
      costSection.appendChild(node('p', 'No cost events have been recorded.'));
    } else {
      const list = node('ol');
      detail.costs.events.forEach(event => list.appendChild(renderCostEvent(event)));
      costSection.appendChild(list);
    }
    region.replaceChildren(provenance, costSection);
  }

  async function loadDetail(summary, region, button, generation) {
    button.disabled = true;
    button.setAttribute('aria-expanded', 'true');
    region.hidden = false;
    region.setAttribute('aria-busy', 'true');
    region.replaceChildren(node('p', 'Loading record evidence…'));
    try {
      const response = await fetch(
        '/api/v1/outcome-accounting/' + encodeURIComponent(summary.id),
        {
          cache: 'no-store', credentials: 'same-origin',
          headers: {'X-Lightwork-Pilot-Context': context},
        },
      );
      if (!response.ok) fail('Outcome record evidence is unavailable. Refresh the page and try again.');
      let data;
      try { data = await response.json(); } catch (_) { fail('Outcome record evidence could not be read. Refresh the page and try again.'); }
      const detail = validateDetail(data, summary);
      if (generation !== renderGeneration || !region.isConnected) return;
      renderDetail(detail, region);
      region.dataset.loaded = 'true';
      button.textContent = 'Hide evidence details';
      button.setAttribute('aria-label', 'Hide evidence for ' + summary.work_item_id);
    } catch (error) {
      if (generation !== renderGeneration || !region.isConnected) return;
      delete region.dataset.loaded;
      region.replaceChildren(node(
        'p', safeMessage(error) + ' No record details were displayed. Refresh or retry after access is restored.',
      ));
      button.textContent = 'Retry evidence details';
      button.setAttribute('aria-label', 'Retry evidence for ' + summary.work_item_id);
    } finally {
      if (generation === renderGeneration && button.isConnected) {
        button.disabled = false;
        region.setAttribute('aria-busy', 'false');
      }
    }
  }

  function renderRecord(record, index, generation) {
    const article = node('article', undefined, 'op-accounting-record');
    const titleId = 'op-accounting-record-title-' + index;
    const buttonId = 'op-accounting-detail-button-' + index;
    const regionId = 'op-accounting-detail-' + index;
    const heading = node('h3', 'Work item ' + record.work_item_id);
    heading.id = titleId;
    article.setAttribute('aria-labelledby', titleId);
    const totalEntries = Object.entries(record.costs.known_totals);
    const totalsText = totalEntries.length
      ? totalEntries.map(([code, amount]) => code + ' ' + amount).join(' · ')
      : 'no priced total';
    article.append(
      heading,
      node('p', 'Outcome: ' + recordCategory(record) + ' · technical ' + record.technical_outcome.status +
        ' · human ' + record.business_outcome.status + ' · disposition ' + record.disposition + '.'),
      node('p', 'Cost: ' + settlementLabel(record.costs.settlement_status) + ' · ' + totalsText +
        ' · authenticated invoices ' + record.costs.authenticated_provider_invoice_count +
        ' · local signed receipts ' + record.costs.local_signed_receipt_count +
        (record.costs.aggregate_overflow_currencies.length
          ? ' · total overflow ' + record.costs.aggregate_overflow_currencies.join(', ') + '.'
          : '.')),
    );
    const button = node('button', 'Review evidence details', 'btn');
    button.type = 'button';
    button.id = buttonId;
    button.setAttribute('aria-controls', regionId);
    button.setAttribute('aria-expanded', 'false');
    button.setAttribute('aria-label', 'Review evidence for ' + record.work_item_id);
    const region = node('div', undefined, 'op-accounting-record-detail');
    region.id = regionId;
    region.hidden = true;
    region.setAttribute('role', 'region');
    region.setAttribute('aria-labelledby', buttonId);
    button.addEventListener('click', () => {
      if (region.dataset.loaded === 'true') {
        region.hidden = !region.hidden;
        button.setAttribute('aria-expanded', String(!region.hidden));
        button.textContent = (region.hidden ? 'Review' : 'Hide') + ' evidence details';
        button.setAttribute(
          'aria-label', (region.hidden ? 'Review' : 'Hide') + ' evidence for ' + record.work_item_id,
        );
        return;
      }
      if (!button.disabled) loadDetail(record, region, button, generation);
    });
    article.append(button, region);
    return article;
  }

  function navigation() {
    if (previousButton) previousButton.disabled = previousCursors.length === 0;
    if (nextButton) nextButton.disabled = nextCursor === null;
  }

  function render(data, requestedCursor) {
    const validated = validatePortfolio(data, requestedCursor);
    const generation = ++renderGeneration;
    const fragments = [
      node(
        'p',
        validated.admitted + ' admitted record' + (validated.admitted === 1 ? '' : 's') +
        ' shown · ' + validated.categoryNames.map(
          (name, index) => validated.categoryValues[index] + ' ' + name,
        ).join(' · '),
      ),
      node(
        'p',
        validated.knownTotals.length
          ? 'Known recorded cost: ' + validated.knownTotals.map(([code, amount]) => code + ' ' + amount).join(' · ')
          : 'No priced aggregate cost can be displayed.',
      ),
      node(
        'p',
        validated.incompleteRecords + ' record' + (validated.incompleteRecords === 1 ? '' : 's') +
        (validated.incompleteRecords === 1 ? ' has' : ' have') +
        ' incomplete cost; unknown amounts are not zero. ' +
        validated.attempts + ' failed attempts retain recorded cost.',
      ),
      renderAssurance(validated),
    ];
    if (validated.report.page.has_more) {
      fragments.push(node('p', 'Additional admitted records exist outside this bounded page.'));
    }
    const records = node('section', undefined, 'op-accounting-records');
    records.appendChild(node('h3', 'Visible outcome records'));
    if (!validated.records.length) records.appendChild(node('p', 'No admitted outcome records are visible in this scope. Records appear here when a pilot task finishes and its outcome is recorded.'));
    validated.records.forEach((record, index) => records.appendChild(renderRecord(record, index, generation)));
    fragments.push(records);
    host.replaceChildren(...fragments);
    nextCursor = validated.following;
    navigation();
  }

  function projectionFailure(error) {
    renderGeneration += 1;
    nextCursor = null;
    host.setAttribute('aria-busy', 'false');
    navigation();
    const message = safeMessage(error);
    host.replaceChildren(node(
      'p', /\b(Refresh|Reload|Try)\b/.test(message)
        ? message : message + ' Refresh this page after access or configuration is restored.',
    ));
  }

  async function loadPage(requestedCursor) {
    const requestNumber = ++pageRequest;
    host.setAttribute('aria-busy', 'true');
    if (previousButton) previousButton.disabled = true;
    if (nextButton) nextButton.disabled = true;
    const query = requestedCursor
      ? '?limit=' + MAX_PAGE + '&cursor=' + encodeURIComponent(requestedCursor)
      : '?limit=' + MAX_PAGE;
    let data;
    try {
      data = await window.mvFetchJSON('/api/v1/outcome-accounting' + query, {
        cache: 'no-store', headers: {'X-Lightwork-Pilot-Context': context},
      }, 'load outcome accounting');
    } catch (error) {
      fail(error.unreadable ? 'Outcome accounting could not be read. Refresh the page and try again.' : error.message);
    }
    if (requestNumber !== pageRequest) return false;
    render(data, requestedCursor);
    host.setAttribute('aria-busy', 'false');
    currentCursor = requestedCursor;
    return true;
  }

  async function changePage(target, rememberCurrent) {
    try {
      if (!await loadPage(target)) return;
      if (rememberCurrent) previousCursors.push(rememberCurrent);
      else previousCursors.pop();
      navigation();
    } catch (error) {
      projectionFailure(error);
    }
  }

  if (nextButton) nextButton.addEventListener('click', () => {
    if (nextCursor !== null) changePage(nextCursor, currentCursor || '__first__');
  });
  if (previousButton) previousButton.addEventListener('click', () => {
    if (previousCursors.length) {
      const previous = previousCursors[previousCursors.length - 1];
      changePage(previous === '__first__' ? '' : previous, null);
    }
  });

  let context;
  try {
    context = opaque(root.dataset.context, 'Outcome accounting context', 512, false);
  } catch (error) {
    projectionFailure(error);
    return;
  }
  loadPage('').catch(projectionFailure);
})();
