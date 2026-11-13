(function () {
  'use strict';

  const root = document.getElementById('outcome-pilots');
  const host = document.getElementById('ov-summary');
  const statusHost = document.getElementById('ov-status');
  const pilotSelector = document.getElementById('ov-pilot');
  const selector = document.getElementById('ov-record');
  const loadMoreButton = document.getElementById('ov-load-more');
  const refreshButton = document.getElementById('ov-refresh');
  const exportButton = document.getElementById('ov-export');
  const selectedSummary = document.getElementById('ov-selected-summary');
  const baselineForm = document.getElementById('ov-baseline-form');
  const costForm = document.getElementById('ov-cost-form');
  const costCoverage = document.getElementById('ov-cost-coverage');
  const costRelationshipHelp = document.getElementById('ov-cost-relationship-help');
  const commercialForm = document.getElementById('ov-commercial-form');
  if (!root || !host || !statusHost || !pilotSelector || !selector || !loadMoreButton ||
      !refreshButton || !exportButton || !selectedSummary || !baselineForm || !costForm ||
      !costCoverage || !costRelationshipHelp || !commercialForm) return;

  const context = root.dataset.context || '';
  // The pilots script closes this report with the rest of the page when access
  // is lost or pilots are off (data-value-locked). A request that finishes
  // later must not open a control again.
  const closed = () => root.dataset.valueLocked === 'true';
  const CONTEXT = /^[^\u0000-\u001f\u007f]{1,512}$/;
  const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$/;
  const MONEY = /^(?:-?(?:0|[1-9][0-9]*))(?:\.[0-9]+)?$/;
  const CURRENCY = /^[A-Z]{3}$/;
  const PILOT_ID = /^OPL-[A-Za-z0-9_-]{1,196}$/;
  const PAGE_CURSOR = /^[A-Za-z0-9_.:-]{1,256}$/;
  const CATEGORIES = ['accepted', 'rejected', 'failed', 'cancelled', 'unresolved'];
  const COST_COVERAGE_FAMILIES = [
    'provider_usage', 'failed_attempts', 'setup', 'review',
    'exception', 'rework', 'support', 'allocation',
  ];
  const COMPARISON = new Set(['measured', 'modeled', 'unavailable']);
  const MISSING_COMPONENTS = new Set([
    'baseline_cost', 'baseline_human_time', 'delivered_cost_coverage',
    'cost_currency_alignment', 'cost_comparison_overflow', 'delivered_human_time',
  ]);
  const MAX_CASES = 10000;
  const MAX_TIMESTAMP = 253402300799;
  const EXPORT_ENVELOPE = Object.freeze({
    schema: 'lightwork.outcome-value-export-envelope.v1',
    digest_algorithm: 'SHA-256',
    digest_encoding: 'lowercase-hex',
    canonicalization: 'lightwork.canonical-json-tree-f64-utf8hex.v1',
    node_encoding: 'tagged-arrays-null-[tag]-others-[tag,value]',
    object_encoding: 'sorted-[utf8hex-key,node]-pairs',
    string_encoding: 'utf-8-lowercase-hex',
    number_encoding: 'ieee-754-binary64-big-endian-lowercase-hex',
    object_key_order: 'utf-8-byte-lexicographic',
    array_order: 'preserved',
    serialization: 'compact-json-utf-8',
  });
  const EXPORT_EXCLUDED_FIELDS = Object.freeze([
    'context', 'export_envelope.digest_sha256',
  ]);
  let cohort = null;
  let generation = 0;
  let pilotCursor = '';
  let pilotListLoading = false;
  const retryOperations = new WeakMap();

  class ProjectionError extends Error {}
  const NEXT = ' Refresh the page and try again.';
  const fail = message => { throw new ProjectionError(message); };
  const node = (tag, value, className) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (value !== undefined) element.textContent = value;
    return element;
  };
  const object = (value, label) => {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(label + ' is missing from the report.' + NEXT);
    return value;
  };
  const array = (value, label, maximum) => {
    if (!Array.isArray(value) || value.length > maximum) fail(label + ' is missing or lists too many items.' + NEXT);
    return value;
  };
  const count = (value, label, maximum = Number.MAX_SAFE_INTEGER) => {
    if (!Number.isSafeInteger(value) || value < 0 || value > maximum) fail(label + ' must be a whole number of 0 or more.' + NEXT);
    return value;
  };
  const text = (value, label, maximum, optional = false) => {
    if (optional && value === null) return null;
    if (typeof value !== 'string' || value.length < 1 || value.length > maximum || /[\u0000-\u001f\u007f]/.test(value)) {
      fail(label + ' is missing, too long or contains characters this page cannot show.' + NEXT);
    }
    return value;
  };
  const money = (value, label, optional = false) => {
    if (optional && value === null) return null;
    if (typeof value !== 'string' || value.length > 96 || !MONEY.test(value)) fail(label + ' must be an amount of money.' + NEXT);
    return value;
  };
  const timestamp = (value, label, optional = false) => {
    if (optional && value === null) return null;
    if (typeof value !== 'number' || !Number.isFinite(value) ||
        value <= 0 || value > MAX_TIMESTAMP) fail(label + ' must be a date and time.' + NEXT);
    return value;
  };
  function outcomeCategory(outcome) {
    if (outcome.disposition === 'cancelled') return 'cancelled';
    if (outcome.disposition === 'failed' || outcome.technical_outcome.status === 'failed') {
      return 'failed';
    }
    if (outcome.business_outcome.status === 'accepted') return 'accepted';
    if (outcome.business_outcome.status === 'rejected') return 'rejected';
    return 'unresolved';
  }
  function totals(value, label) {
    const rows = object(value, label);
    Object.entries(rows).forEach(([code, amount]) => {
      if (!CURRENCY.test(code)) fail(label + ' uses a currency Lightwork does not recognise.' + NEXT);
      money(amount, label + ' amount');
    });
    return rows;
  }
  function decimal(value) {
    const negative = value.startsWith('-');
    const unsigned = negative ? value.slice(1) : value;
    const [whole, fraction = ''] = unsigned.split('.');
    const units = BigInt((whole + fraction).replace(/^0+(?=\d)/, '') || '0');
    return {units: negative ? -units : units, scale: fraction.length};
  }
  function addDecimal(left, right) {
    const scale = Math.max(left.scale, right.scale);
    const leftUnits = left.units * (10n ** BigInt(scale - left.scale));
    const rightUnits = right.units * (10n ** BigInt(scale - right.scale));
    return {units: leftUnits + rightUnits, scale};
  }
  function decimalEqual(left, right) {
    const aligned = addDecimal(left, {units: -right.units, scale: right.scale});
    return aligned.units === 0n;
  }
  function addTotal(target, code, amount) {
    target[code] = addDecimal(target[code] || {units: 0n, scale: 0}, decimal(amount));
  }
  function totalsEqual(rendered, derived, ignored = new Set()) {
    const renderedKeys = Object.keys(rendered).filter(code => !ignored.has(code)).sort();
    const derivedKeys = Object.keys(derived).filter(code => !ignored.has(code)).sort();
    if (renderedKeys.join('\u0000') !== derivedKeys.join('\u0000')) return false;
    return renderedKeys.every(code => decimalEqual(decimal(rendered[code]), derived[code]));
  }
  function comparison(value, component) {
    const result = object(value, component + ' comparison');
    if (!COMPARISON.has(result.status)) fail(component + ' comparison has an unknown status.' + NEXT);
    array(result.missing_records, component + ' missing records', MAX_CASES).forEach(identifier => {
      if (typeof identifier !== 'string' || !ID.test(identifier)) fail(component + ' comparison lists a missing record without a valid reference.' + NEXT);
    });
    const savingsKey = component === 'Human-time' ? 'minutes_saved' : 'net_savings';
    money(result[savingsKey], component + ' savings', true);
    if (component === 'Cost') money(result.roi_percent, 'ROI', true);
    if (result.status === 'unavailable' && (result[savingsKey] !== null || (component === 'Cost' && result.roi_percent !== null))) {
      fail(component + ' incomplete comparison exposed savings.');
    }
    if (result.overflow !== undefined) {
      if (typeof result.overflow !== 'boolean' || (result.overflow && result.status !== 'unavailable')) {
        fail(component + ' comparison is marked as too large to add up, but still shows a total.' + NEXT);
      }
    }
    if (result.reason !== undefined) text(result.reason, component + ' comparison reason', 1000);
    if (result.status !== 'unavailable') {
      if (result.missing_records.length || result[savingsKey] === null) {
        fail(component + ' complete comparison is missing evidence.');
      }
      if (component === 'Cost') {
        if (!CURRENCY.test(result.currency || '')) fail('The cost comparison uses a currency Lightwork does not recognise. Refresh the page and try again.');
        money(result.baseline_total, 'Comparison baseline total');
        money(result.delivered_total, 'Comparison delivered total');
      }
    }
    if (result.measured_positive_roi === true && result.status !== 'measured') {
      fail('The report says return on investment was measured, but the comparison was not measured. Refresh the page and try again.');
    }
    if (component === 'Cost' && result.measured_positive_roi !== undefined) {
      if (typeof result.measured_positive_roi !== 'boolean') {
        fail('The report does not say clearly whether return on investment was measured. Refresh the page and try again.');
      }
      if (result.measured_positive_roi && (
        result.roi_percent === null || decimal(result.roi_percent).units <= 0n
      )) fail('Positive measured ROI conflicts with the reported ROI.');
    }
    return result;
  }
  function utf8Hex(value) {
    if (typeof TextEncoder !== 'function') {
      fail('This browser cannot verify the exported cohort evidence.');
    }
    return Array.from(new TextEncoder().encode(value), byte =>
      byte.toString(16).padStart(2, '0')).join('');
  }
  function numberHex(value) {
    if (!Number.isFinite(value)) {
      fail('The exported cohort evidence contains an unsupported number.');
    }
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setFloat64(0, value, false);
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
  }
  function exportCanonicalNode(value) {
    if (value === null) return ['null'];
    if (typeof value === 'boolean') return ['boolean', value ? 'true' : 'false'];
    if (typeof value === 'string') return ['string', utf8Hex(value)];
    if (typeof value === 'number') return ['number', numberHex(value)];
    if (Array.isArray(value)) return ['array', value.map(exportCanonicalNode)];
    if (typeof value === 'object') {
      const pairs = Object.entries(value).map(([key, item]) => [
        utf8Hex(key), exportCanonicalNode(item),
      ]);
      pairs.sort((left, right) => left[0] < right[0] ? -1 : left[0] > right[0] ? 1 : 0);
      return ['object', pairs];
    }
    fail('The exported cohort evidence contains an unsupported value.');
  }
  function exportCanonicalBytes(report) {
    const unsigned = {...report};
    delete unsigned.context;
    unsigned.export_envelope = {...object(unsigned.export_envelope, 'Export envelope')};
    delete unsigned.export_envelope.digest_sha256;
    return new TextEncoder().encode(JSON.stringify(exportCanonicalNode(unsigned)));
  }
  async function verifyExportEnvelope(report) {
    const envelope = object(report.export_envelope, 'Export envelope');
    const expectedKeys = [...Object.keys(EXPORT_ENVELOPE), 'excluded_fields', 'digest_sha256'].sort();
    if (Object.keys(envelope).sort().join('\u0000') !== expectedKeys.join('\u0000') ||
        Object.entries(EXPORT_ENVELOPE).some(([key, value]) => envelope[key] !== value)) {
      fail('The exported cohort evidence is not audit-bound.');
    }
    const excluded = array(envelope.excluded_fields, 'Export envelope exclusions', 2);
    if (excluded.length !== EXPORT_EXCLUDED_FIELDS.length ||
        excluded.some((value, index) => value !== EXPORT_EXCLUDED_FIELDS[index]) ||
        !/^[a-f0-9]{64}$/.test(envelope.digest_sha256 || '')) {
      fail('The exported cohort evidence is not audit-bound.');
    }
    if (!globalThis.crypto || !globalThis.crypto.subtle) {
      fail('This browser cannot verify the exported cohort evidence.');
    }
    const digest = await globalThis.crypto.subtle.digest(
      'SHA-256', exportCanonicalBytes(report),
    );
    const actual = Array.from(new Uint8Array(digest), byte =>
      byte.toString(16).padStart(2, '0')).join('');
    if (actual !== envelope.digest_sha256) {
      fail('The exported cohort evidence is not audit-bound.');
    }
  }
  function validateCohort(value, expectedSchema) {
    const report = object(value, 'Cohort value report');
    if (report.schema !== expectedSchema || report.context !== context || report.reconciles !== true ||
        report.pilot_id !== pilotSelector.value) {
      fail('The cohort report is for a different account, workspace or pilot. Refresh the page and try again.');
    }
    text(report.plan_version, 'Pilot plan version', 64);
    text(report.admission_manifest_sha256, 'Admission manifest', 64);
    if (!/^[a-f0-9]{64}$/.test(report.plan_version) ||
        !/^[a-f0-9]{64}$/.test(report.admission_manifest_sha256)) {
      fail('The cohort report is not bound to a frozen pilot manifest.');
    }
    const binding = object(report.cohort_binding, 'Cohort binding');
    if (binding.acceptance_contract_ref !==
          'outcome-pilot:' + report.pilot_id + ':' + report.plan_version ||
        !/^[a-f0-9]{64}$/.test(binding.record_ids_sha256 || '')) {
      fail('The cohort report is incomplete or in a format this page cannot read. Refresh the page and try again.');
    }
    const admitted = count(report.admitted, 'Admitted denominator', MAX_CASES);
    if (count(binding.record_count, 'Bound cohort count', MAX_CASES) !== admitted) {
      fail('The cohort report\'s case count does not match the list of cases it covers. Refresh the page and try again.');
    }
    if (expectedSchema === 'lightwork.outcome-value-export.v1') {
      if (!/^[a-f0-9]{64}$/.test(report.cohort_sha256 || '') ||
          typeof report.generated_at !== 'number' || !Number.isFinite(report.generated_at) ||
          report.generated_at <= 0) {
        fail('The exported cohort evidence is not audit-bound.');
      }
      array(report.limitations, 'Export limitations', 32).forEach(
        limitation => text(limitation, 'Export limitation', 2000),
      );
    }
    const categories = object(report.categories, 'Outcome categories');
    const categoryTotal = CATEGORIES.reduce(
      (total, name) => total + count(categories[name], name + ' count', MAX_CASES), 0,
    );
    if (categoryTotal !== admitted) fail('Outcome categories do not reconcile.');
    const cases = array(report.cases, 'Cohort cases', MAX_CASES);
    if (cases.length !== admitted) fail('Admitted cases do not reconcile.');
    const ids = new Set();
    const derivedCategories = Object.fromEntries(CATEGORIES.map(name => [name, 0]));
    const caseTotals = {};
    let caseFailedAttempts = 0;
    let caseIncompleteCosts = 0;
    let caseRenewals = 0;
    let caseExpansions = 0;
    cases.forEach(value => {
      const item = object(value, 'Cohort case');
      const outcome = object(item.outcome, 'Cohort outcome');
      if (typeof outcome.id !== 'string' || !ID.test(outcome.id) || ids.has(outcome.id)) {
        fail('A case in the cohort report is missing its reference or is listed twice. Refresh the page and try again.');
      }
      ids.add(outcome.id);
      text(outcome.admission_id, 'Admission identity', 512);
      text(outcome.work_item_id, 'Work item', 512);
      if (!outcome.admission_id.startsWith(report.pilot_id + ':') ||
          outcome.acceptance_contract_ref !== binding.acceptance_contract_ref) {
        fail('A cohort case does not belong to the selected frozen pilot.');
      }
      count(outcome.revision, 'Outcome revision');
      if (!['active', 'cancelled', 'completed', 'failed'].includes(outcome.disposition)) {
        fail('A case in the cohort report has an unknown state. Refresh the page and try again.');
      }
      const technical = object(outcome.technical_outcome, 'Technical outcome');
      if (!['verified', 'failed', 'unresolved'].includes(technical.status)) {
        fail('A case in the cohort report has an unknown technical result. Refresh the page and try again.');
      }
      text(technical.reason, 'Technical outcome reason', 1000);
      const business = object(outcome.business_outcome, 'Business outcome');
      if (!['accepted', 'rejected', 'unresolved'].includes(business.status)) {
        fail('A case in the cohort report has an unknown business result. Refresh the page and try again.');
      }
      text(business.reason, 'Business outcome reason', 1000);
      const outcomeCosts = object(outcome.costs, 'Case delivered cost');
      const outcomeTotals = totals(outcomeCosts.known_totals, 'Case delivered total');
      Object.entries(outcomeTotals).forEach(([code, amount]) => addTotal(caseTotals, code, amount));
      caseFailedAttempts += count(
        outcomeCosts.failed_attempt_count, 'Case failed attempts', 5000,
      );
      if (typeof outcomeCosts.complete !== 'boolean') fail('A case in the cohort report does not say whether all its costs are counted. Refresh the page and try again.');
      if (!outcomeCosts.complete) caseIncompleteCosts += 1;
      count(item.value_revision, 'Value revision');
      if (!CATEGORIES.includes(item.category) || item.category !== outcomeCategory(outcome)) {
        fail('A case in the cohort report is in the wrong category for its outcome. Refresh the page and try again.');
      }
      derivedCategories[item.category] += 1;
      const timestamps = object(item.timestamps, 'Case timestamps');
      timestamp(timestamps.admitted_at, 'Case admission time');
      [
        ['last_observed_at', 'Case last observation time'],
        ['last_decided_at', 'Case last decision time'],
        ['last_disposition_at', 'Case last disposition time'],
        ['last_cost_at', 'Case last cost time'],
        ['last_baseline_at', 'Case last baseline time'],
      ].forEach(([key, label]) => timestamp(timestamps[key], label, true));
      const itemComparison = object(item.comparison, 'Case comparison');
      const cost = object(itemComparison.cost, 'Case cost comparison');
      if (!COMPARISON.has(cost.status)) fail('A case\'s cost comparison has an unknown status. Refresh the page and try again.');
      if (cost.status === 'unavailable' && (cost.net_savings !== null || cost.roi_percent !== null)) {
        fail('Incomplete case comparison exposed ROI.');
      }
      if (cost.overflow !== undefined) {
        if (typeof cost.overflow !== 'boolean' || (cost.overflow && cost.status !== 'unavailable')) {
          fail('A case\'s cost comparison is marked as too large to add up, but still shows a total. Refresh the page and try again.');
        }
      }
      if (cost.reason !== undefined) text(cost.reason, 'Case cost comparison reason', 1000);
      if (cost.status !== 'unavailable') {
        money(cost.net_savings, 'Case net savings');
        money(cost.roi_percent, 'Case ROI', true);
        const baseline = object(cost.baseline, 'Case baseline cost');
        const delivered = object(cost.delivered, 'Case delivered cost');
        money(baseline.value, 'Case baseline amount');
        money(delivered.amount, 'Case delivered amount');
        if (!CURRENCY.test(baseline.currency) || delivered.currency !== baseline.currency) {
          fail('A case\'s cost comparison mixes currencies or uses one Lightwork does not recognise. Refresh the page and try again.');
        }
      }
      const human = object(itemComparison.human_effort, 'Case human-time comparison');
      if (!COMPARISON.has(human.status)) fail('A case\'s time comparison has an unknown status. Refresh the page and try again.');
      if ((human.status === 'unavailable') !== (human.minutes_saved === null)) {
        fail('Case human-time comparison is incomplete.');
      }
      if (human.minutes_saved !== null) money(human.minutes_saved, 'Case minutes saved');
      const missingComponents = array(
        itemComparison.missing_components, 'Missing case components', MISSING_COMPONENTS.size,
      );
      if (new Set(missingComponents).size !== missingComponents.length ||
          missingComponents.some(component => !MISSING_COMPONENTS.has(component))) {
        fail('The list of missing case parts could not be read. Refresh the page and try again.');
      }
      if (typeof itemComparison.measured_positive_roi !== 'boolean' ||
          itemComparison.measured_positive_roi !== (
            cost.status === 'measured' && cost.roi_percent !== null &&
            decimal(cost.roi_percent).units > 0n && human.status === 'measured'
          )) fail('A case says return on investment was measured, but its cost and time were not both measured. Refresh the page and try again.');
      if (human.status === 'unavailable' && cost.status !== 'unavailable') {
        fail('A case with incomplete human-time evidence exposed ROI.');
      }
      if (item.baseline !== null) {
        const baseline = object(item.baseline, 'Current baseline');
        const baselineCost = object(baseline.cost, 'Current baseline cost');
        const baselineHuman = object(baseline.human_effort, 'Current baseline human time');
        if (!['observed', 'estimated', 'unknown'].includes(baselineCost.basis) ||
            !['observed', 'estimated', 'unknown'].includes(baselineHuman.basis)) {
          fail('The current baseline does not say whether its figures were observed, estimated or unknown. Refresh the page and try again.');
        }
        money(baselineCost.value, 'Current baseline cost value', true);
        money(baselineHuman.value, 'Current baseline human-time value', true);
        if (baselineCost.basis === 'unknown') {
          if (baselineCost.value !== null || baselineCost.currency !== null) {
            fail('Unknown baseline cost exposed a value.');
          }
          text(baselineCost.unknown_reason, 'Unknown baseline cost reason', 1000);
        } else if (baselineCost.value === null || !CURRENCY.test(baselineCost.currency || '')) {
          fail('The current baseline cost has no amount or uses a currency Lightwork does not recognise. Refresh the page and try again.');
        }
        if (baselineHuman.basis === 'unknown') {
          if (baselineHuman.value !== null) fail('Unknown baseline human time exposed a value.');
          text(baselineHuman.unknown_reason, 'Unknown baseline human-time reason', 1000);
        } else if (baselineHuman.value === null) {
          fail('Current baseline human time is missing.');
        }
      }
      caseRenewals += count(item.renewal_count, 'Renewal count', 5000);
      caseExpansions += count(item.expansion_count, 'Expansion count', 5000);
    });
    if (CATEGORIES.some(name => derivedCategories[name] !== categories[name])) {
      fail('Outcome categories do not match the admitted cases.');
    }
    const costs = object(report.costs, 'Cohort costs');
    const knownTotals = totals(costs.known_totals, 'Cohort total');
    const categoryTotals = object(costs.category_totals, 'Cost category totals');
    const categorizedTotals = {};
    Object.entries(categoryTotals).forEach(([name, values]) => {
      text(name, 'Cost category', 32);
      Object.entries(totals(values, 'Cost category total')).forEach(
        ([code, amount]) => addTotal(categorizedTotals, code, amount),
      );
    });
    const unknownCounts = object(costs.unknown_event_counts_by_category, 'Unknown cost counts');
    Object.entries(unknownCounts).forEach(([name, value]) => {
      text(name, 'Unknown cost category', 32);
      count(value, 'Unknown cost count', MAX_CASES * 5000);
    });
    const overflow = new Set(array(
      costs.aggregate_overflow_currencies, 'Aggregate overflow currencies', 100,
    ).map(code => {
      if (!CURRENCY.test(code)) fail('The report lists a currency Lightwork does not recognise. Refresh the page and try again.');
      return code;
    }));
    if (overflow.size !== costs.aggregate_overflow_currencies.length) {
      fail('Aggregate overflow currencies contain duplicates.');
    }
    if (!totalsEqual(knownTotals, caseTotals, overflow) ||
        !totalsEqual(knownTotals, categorizedTotals, overflow)) {
      fail('Cohort cost totals do not reconcile to case and category totals.');
    }
    const incompleteRecords = count(costs.incomplete_records, 'Incomplete cost records', MAX_CASES);
    const failedAttempts = count(costs.failed_attempts, 'Failed attempts', MAX_CASES * 5000);
    if (incompleteRecords !== caseIncompleteCosts || failedAttempts !== caseFailedAttempts) {
      fail('Cohort cost counts do not reconcile to admitted cases.');
    }
    if (typeof costs.complete !== 'boolean' || typeof costs.allocation_assumptions_explicit !== 'boolean') {
      fail('The cost coverage details could not be read. Refresh the page and try again.');
    }
    if (costs.complete && (
      costs.incomplete_records !== 0 || overflow.size || !costs.allocation_assumptions_explicit
    )) fail('Complete cost conflicts with missing or overflowing evidence.');
    const aggregate = object(report.comparison, 'Cohort comparison');
    comparison(aggregate.cost, 'Cost');
    comparison(aggregate.human_effort, 'Human-time');
    if (aggregate.human_effort.status === 'unavailable' &&
        aggregate.cost.status !== 'unavailable') {
      fail('Incomplete cohort human-time evidence exposed ROI.');
    }
    if (aggregate.cost.measured_positive_roi === true &&
        aggregate.human_effort.status !== 'measured') {
      fail('Positive measured cohort ROI lacks measured human-time evidence.');
    }
    if ((!costs.complete || !report.scope_complete) && aggregate.cost.status !== 'unavailable') {
      fail('Incomplete cohort cost exposed a comparison.');
    }
    if (!report.scope_complete && aggregate.human_effort.status !== 'unavailable') {
      fail('Partial cohort scope exposed a comparison.');
    }
    if (aggregate.commercial_records_included !== false || report.commercial_separate_from_savings !== true) {
      fail('Commercial evidence was mixed into operational savings.');
    }
    const commercial = object(report.commercial, 'Commercial evidence');
    const renewals = array(commercial.renewals, 'Renewals', MAX_CASES * 10);
    const expansions = array(commercial.expansions, 'Expansions', MAX_CASES * 10);
    const commercialCounts = object(report.commercial_counts, 'Commercial counts');
    const renewalCount = count(commercialCounts.renewals, 'Commercial renewal count', MAX_CASES * 5000);
    const expansionCount = count(commercialCounts.expansions, 'Commercial expansion count', MAX_CASES * 5000);
    if (renewalCount !== caseRenewals || expansionCount !== caseExpansions) {
      fail('Commercial totals do not reconcile to admitted cases.');
    }
    if (typeof report.commercial_records_complete !== 'boolean' ||
        (report.commercial_records_complete && (
          renewals.length !== renewalCount || expansions.length !== expansionCount
        )) || renewals.length > renewalCount || expansions.length > expansionCount) {
      fail('The count of renewals or expansions does not match the records listed. Refresh the page and try again.');
    }
    if (!report.commercial_records_complete && report.scope_complete) {
      fail('Incomplete commercial evidence claimed a complete cohort.');
    }
    if (typeof report.scope_complete !== 'boolean') fail('The cohort report does not say whether it covers every case. Refresh the page and try again.');
    return {report, cases, costs, aggregate, commercial};
  }

  const displayTotals = values => {
    const entries = Object.entries(values);
    return entries.length ? entries.map(([code, amount]) => code + ' ' + amount).join(' · ') : 'No priced total';
  };
  const titleCase = value => value.replaceAll('_', ' ').replace(/\b\w/g, character => character.toUpperCase());
  const displayTimestamp = value => value === null
    ? 'not recorded' : window.mvTimeAbsolute ? window.mvTimeAbsolute(value) : new Date(value * 1000).toISOString();
  const friendlyWorkItem = value => {
    const separator = value.indexOf(':');
    const visible = separator === -1 ? value : value.slice(separator + 1);
    return titleCase(visible.replaceAll('-', ' '));
  };
  function comparisonText(result, kind) {
    if (result.status === 'unavailable') {
      const countText = result.missing_records.length
        ? ' Missing evidence affects ' + result.missing_records.length + ' admitted case' + (result.missing_records.length === 1 ? '.' : 's.')
        : '';
      const reasonText = result.reason ? ' Reason: ' + result.reason + '.' : '';
      return kind === 'Human time'
        ? kind + ' comparison unavailable. No minutes saved are reported.' + countText + reasonText
        : kind + ' comparison unavailable. No net savings or ROI is reported.' + countText + reasonText;
    }
    if (kind === 'Human time') {
      return (result.status === 'measured' ? 'Measured from operator-recorded evidence' : 'Modeled') +
        ' human-time change: ' + result.minutes_saved + ' minutes saved.';
    }
    return (result.status === 'measured' ? 'Measured from operator-recorded evidence' : 'Modeled') +
      ' cost change: ' + result.currency + ' ' + result.net_savings + ' net savings' +
      (result.roi_percent === null ? '; ROI unavailable because the baseline is zero.' : '; ROI ' + result.roi_percent + '%.');
  }
  function card(title, lines) {
    const section = node('section', undefined, 'ov-summary-card');
    section.appendChild(node('h3', title));
    lines.forEach(line => section.appendChild(node('p', line)));
    return section;
  }
  function render(validated) {
    const {report, cases, costs, aggregate, commercial} = validated;
    const grid = node('div', undefined, 'ov-summary-grid');
    grid.append(
      card('All admitted outcomes', [
        report.admitted + ' admitted case' + (report.admitted === 1 ? '' : 's') + '.',
        CATEGORIES.map(name => name + ' ' + report.categories[name]).join(' · '),
        report.scope_complete ? 'The full bounded cohort is included.' : 'The cohort exceeds the bounded report scope; comparisons are withheld.',
      ]),
      card('Delivered cost', [
        displayTotals(costs.known_totals) + '.',
        costs.incomplete_records + ' case' + (costs.incomplete_records === 1 ? '' : 's') + ' with incomplete cost · ' +
          costs.failed_attempts + ' failed attempt' + (costs.failed_attempts === 1 ? '' : 's') + '.',
        costs.allocation_assumptions_explicit ? 'Shared allocation assumptions are explicit.' : 'A shared allocation assumption is missing.',
      ]),
      card('Savings evidence', [
        comparisonText(aggregate.cost, 'Cost'),
        comparisonText(aggregate.human_effort, 'Human time'),
      ]),
      card('Commercial evidence', [
        report.commercial_counts.renewals + ' current renewal record' + (report.commercial_counts.renewals === 1 ? '' : 's') + '.',
        report.commercial_counts.expansions + ' current expansion record' + (report.commercial_counts.expansions === 1 ? '' : 's') + '.',
        report.commercial_records_complete ? 'All commercial records in this bounded cohort are included.' : 'Commercial detail exceeds the bounded report; download is withheld.',
        'Commercial records are excluded from operational savings.',
      ]),
    );
    const breakdown = node('section', undefined, 'ov-summary-card');
    breakdown.appendChild(node('h3', 'Cost categories'));
    const rows = Object.entries(costs.category_totals);
    if (!rows.length) {
      breakdown.appendChild(node('p', 'No priced cost categories are available. Unknown cost remains unknown.'));
    } else {
      const list = node('ul');
      rows.forEach(([name, values]) => list.appendChild(node('li', titleCase(name) + ': ' + displayTotals(values))));
      breakdown.appendChild(list);
    }
    const unknownRows = Object.entries(costs.unknown_event_counts_by_category);
    breakdown.appendChild(node('h4', 'Unknown cost events by category'));
    if (!unknownRows.length) {
      breakdown.appendChild(node('p', 'No unknown cost events are reported by category.'));
    } else {
      const unknownList = node('ul');
      unknownRows.forEach(([name, value]) => unknownList.appendChild(node(
        'li', titleCase(name) + ': ' + value + ' unknown event' + (value === 1 ? '.' : 's.'),
      )));
      breakdown.appendChild(unknownList);
    }
    host.replaceChildren(grid, breakdown);

    const selected = selector.value;
    selector.replaceChildren(node('option', 'Choose an admitted case'));
    selector.firstChild.value = '';
    cases.forEach(item => {
      const work = friendlyWorkItem(item.outcome.work_item_id);
      const category = titleCase(item.category);
      const label = work.toLocaleLowerCase() === category.toLocaleLowerCase()
        ? category + ' case' : work + ' · ' + category;
      const option = node('option', label);
      option.value = item.outcome.id;
      selector.appendChild(option);
    });
    if (cases.some(item => item.outcome.id === selected)) selector.value = selected;
    renderSelected();
    exportButton.disabled = closed() || !report.scope_complete;
    statusHost.textContent = 'Exact pilot cohort refreshed. ' + report.admitted + ' admitted case' + (report.admitted === 1 ? '' : 's') + ' shown.';
  }

  function renderSelected() {
    if (!cohort || !selector.value) {
      selectedSummary.textContent = 'Choose a case to review or add evidence.';
      if (baselineForm) baselineForm.elements.correction_reason.required = false;
      return;
    }
    const item = cohort.cases.find(row => row.outcome.id === selector.value);
    if (!item) {
      selectedSummary.textContent = 'The selected case is no longer available. Refresh the cohort.';
      return;
    }
    const baseline = item.baseline;
    if (baselineForm) baselineForm.elements.correction_reason.required = baseline !== null;
    const baselineText = baseline === null
      ? 'No baseline evidence is recorded.'
      : 'Current baseline: ' +
        (baseline.cost.basis === 'unknown' ? 'cost unknown' : baseline.cost.currency + ' ' + baseline.cost.value + ' ' + baseline.cost.basis) +
        '; ' + (baseline.human_effort.basis === 'unknown' ? 'human time unknown' : baseline.human_effort.value + ' minutes ' + baseline.human_effort.basis) + '.';
    const work = friendlyWorkItem(item.outcome.work_item_id);
    const category = titleCase(item.category);
    const label = work.toLocaleLowerCase() === category.toLocaleLowerCase()
      ? category + ' case' : work + ' · ' + category;
    const missing = item.comparison.missing_components;
    const missingText = 'Missing comparison components: ' +
      (missing.length ? missing.join(', ') : 'none') + '.';
    const timestamps = item.timestamps;
    const timestampText = [
      ['admitted_at', 'Admitted'],
      ['last_observed_at', 'Last observed'],
      ['last_decided_at', 'Last decided'],
      ['last_disposition_at', 'Last disposition'],
      ['last_cost_at', 'Last cost'],
      ['last_baseline_at', 'Last baseline'],
    ].map(([key, name]) => name + ': ' + displayTimestamp(timestamps[key]) + '.').join(' ');
    selectedSummary.textContent = label + '. ' + baselineText +
      ' ' + item.renewal_count + ' renewal and ' + item.expansion_count + ' expansion record' +
      (item.renewal_count + item.expansion_count === 1 ? '.' : 's.') +
      ' ' + missingText + ' ' + timestampText;
  }

  // Resolves true when this load rendered the cohort, false when it failed,
  // and null when a newer load took over (that one owns what is shown).
  async function load() {
    const request = ++generation;
    if (!pilotSelector.value) {
      cohort = null;
      host.replaceChildren(node('p', 'Choose a frozen pilot to calculate its exact admitted cohort.'));
      selector.replaceChildren(node('option', 'Choose an admitted case'));
      selector.firstChild.value = '';
      exportButton.disabled = true;
      statusHost.textContent = 'No pilot cohort selected. Choose a cohort above to see its value.';
      return false;
    }
    statusHost.textContent = 'Loading the exact pilot cohort…';
    statusHost.setAttribute('aria-busy', 'true');
    refreshButton.disabled = true;
    exportButton.disabled = true;
    try {
      const response = await fetch(
        '/api/v1/outcome-accounting/cohort?pilot_id=' + encodeURIComponent(pilotSelector.value), {
        cache: 'no-store', credentials: 'same-origin',
        headers: {'X-Lightwork-Pilot-Context': context},
      });
      if (!response.ok) fail('The cohort value report is unavailable. Refresh the page and try again.');
      let payload;
      try { payload = await response.json(); } catch (_) { fail('The cohort value report could not be read. Refresh the page to try again.'); }
      const validated = validateCohort(payload, 'lightwork.outcome-value-cohort.v1');
      if (request !== generation) return null;
      cohort = validated;
      render(validated);
      return true;
    } catch (error) {
      if (request !== generation) return null;
      cohort = null;
      selector.replaceChildren(node('option', 'Choose an admitted case'));
      selector.firstChild.value = '';
      host.replaceChildren(node(
        'p', error instanceof ProjectionError ? error.message : 'The cohort value report could not be verified. Refresh the page and try again.',
      ));
      statusHost.textContent = 'No cohort totals or ROI were displayed.';
      return false;
    } finally {
      if (request === generation) {
        statusHost.setAttribute('aria-busy', 'false');
        refreshButton.disabled = closed();
        exportButton.disabled = closed() || !cohort || !cohort.report.scope_complete;
      }
    }
  }

  function validatePilotPage(value, requestedCursor) {
    const payload = object(value, 'Pilot list');
    if (payload.context !== context || typeof payload.partial !== 'boolean') {
      fail('The pilot list is for a different account or workspace, or does not say whether it is complete. Refresh the page and try again.');
    }
    const page = object(payload.page, 'Pilot page');
    if (Object.keys(page).sort().join('\u0000') !== 'has_more\u0000next_cursor' ||
        typeof page.has_more !== 'boolean' || payload.partial !== page.has_more) {
      fail('The page of pilots is incomplete or in a format this page cannot read. Refresh the page and try again.');
    }
    let nextCursor = '';
    if (page.has_more) {
      if (typeof page.next_cursor !== 'string' || !PAGE_CURSOR.test(page.next_cursor) ||
          page.next_cursor === requestedCursor) {
        fail('The link to the next page of pilots is not valid. Refresh the page and try again.');
      }
      nextCursor = page.next_cursor;
    } else if (page.next_cursor !== null) {
      fail('The link to the next page of pilots is not valid. Refresh the page and try again.');
    }
    const items = array(payload.items, 'Pilot list', MAX_CASES).map(itemValue => {
      const item = object(itemValue, 'Pilot');
      if (typeof item.id !== 'string' || !PILOT_ID.test(item.id)) {
        fail('A pilot in the list is missing a valid reference. Refresh the page and try again.');
      }
      return {id: item.id, title: text(item.title, 'Pilot title', 200)};
    });
    return {items, hasMore: page.has_more, nextCursor};
  }

  function appendPilotOptions(items, reset) {
    const prior = pilotSelector.value;
    if (reset) {
      pilotSelector.replaceChildren(node('option', 'Choose a frozen pilot'));
      pilotSelector.firstChild.value = '';
    }
    const existing = new Set([...pilotSelector.options].map(option => option.value));
    items.forEach(item => {
      if (existing.has(item.id)) return;
      const option = node('option', item.title);
      option.value = item.id;
      pilotSelector.appendChild(option);
      existing.add(item.id);
    });
    if (prior && existing.has(prior)) pilotSelector.value = prior;
    else if (reset && pilotSelector.options.length > 1) pilotSelector.selectedIndex = 1;
  }

  async function loadPilots(cursor = '', append = false) {
    if (pilotListLoading) return false;
    pilotListLoading = true;
    pilotSelector.disabled = true;
    loadMoreButton.disabled = true;
    try {
      const path = '/api/v1/outcome-pilots?limit=100' +
        (cursor ? '&cursor=' + encodeURIComponent(cursor) : '');
      const response = await fetch(path, {
        cache: 'no-store', credentials: 'same-origin',
        headers: {'X-Lightwork-Pilot-Context': context},
      });
      if (!response.ok) fail('Pilot cohorts are unavailable. Refresh the page and try again.');
      let raw;
      try { raw = await response.json(); } catch (_) { fail('The pilot list could not be read. Refresh the page and try again.'); }
      const page = validatePilotPage(raw, cursor);
      appendPilotOptions(page.items, !append);
      pilotCursor = page.nextCursor;
      loadMoreButton.hidden = !page.hasMore;
      if (append) {
        statusHost.textContent = page.hasMore
          ? 'Another pilot cohort page loaded. More cohorts are available.'
          : 'All pilot cohorts for this account and workspace are available.';
      } else {
        await load();
      }
      return true;
    } catch (error) {
      pilotCursor = '';
      loadMoreButton.hidden = true;
      if (append) {
        statusHost.textContent = error instanceof ProjectionError
          ? error.message : 'More pilot cohorts could not be verified. Refresh the page and try again.';
      } else {
        cohort = null;
        host.replaceChildren(node('p', error instanceof ProjectionError
          ? error.message : 'Pilot cohorts could not be verified. Refresh the page and try again.'));
        statusHost.textContent = 'No cohort totals or ROI were displayed.';
      }
      return false;
    } finally {
      pilotListLoading = false;
      pilotSelector.disabled = closed();
      loadMoreButton.disabled = closed() || !pilotCursor;
    }
  }

  function selectedCase() {
    if (!cohort || !selector.value) throw new ProjectionError('Choose an admitted case first.');
    const item = cohort.cases.find(row => row.outcome.id === selector.value);
    if (!item) throw new ProjectionError('The selected case is no longer in this cohort. Refresh first.');
    return item;
  }
  const optional = value => {
    const result = value.trim();
    return result || null;
  };
  function operationId(prefix) {
    const suffix = self.crypto && typeof self.crypto.randomUUID === 'function'
      ? self.crypto.randomUUID().replaceAll('-', '')
      : String(Date.now()) + String(Math.random()).slice(2);
    return prefix + suffix.slice(0, 64);
  }
  function retryablePayload(form, prefix, payload) {
    const signature = JSON.stringify(Object.fromEntries(
      Object.entries(payload).filter(([key]) => key !== 'expected_revision'),
    ));
    const previous = retryOperations.get(form);
    const operation = previous && previous.signature === signature
      ? previous.operation : operationId(prefix);
    retryOperations.set(form, {signature, operation});
    return {...payload, operation_id: operation};
  }
  async function save(form, path, payload) {
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    statusHost.textContent = 'Saving evidence…';
    try {
      const response = await fetch(path, {
        method: 'POST', cache: 'no-store', credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-Lightwork-Pilot-Context': context,
        },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        const message = response.status === 409
          ? 'The record changed. Refresh and review the latest evidence before saving.'
          : response.status === 422
            ? 'The evidence is incomplete or conflicts with the current record. Check every field and correction explanation.'
            : 'The evidence could not be saved. Try again.';
        throw new ProjectionError(message);
      }
      const verified = await load();
      if (verified === false) {
        throw new ProjectionError(
          'The save response was received, but the updated cohort could not be verified. Your entries and retry identity remain available.',
        );
      }
      retryOperations.delete(form);
      form.reset();
      if (form === baselineForm) syncBaselineControls();
      if (form === costForm) syncCostControls();
      if (form === commercialForm) syncCommercialControls();
      // A null result means a newer refresh replaced this readback: the save
      // itself succeeded, and that refresh shows the current cohort.
      statusHost.textContent = verified
        ? 'Evidence saved and the exact pilot cohort was recalculated.'
        : 'Evidence saved. The cohort was refreshed again while this was saving, so the newer refresh is shown.';
    } catch (error) {
      statusHost.textContent = error instanceof ProjectionError
        ? error.message : 'The evidence could not be saved. Your entries remain in the form. Try again.';
    } finally {
      button.disabled = closed();
    }
  }

  function requireWhen(control, active) {
    control.disabled = closed() || !active;
    control.required = active;
  }
  function syncBasis(form, basisName, amountName, currencyName, reasonName) {
    const unknown = form.elements[basisName].value === 'unknown';
    requireWhen(form.elements[amountName], !unknown);
    if (currencyName) requireWhen(form.elements[currencyName], !unknown);
    requireWhen(form.elements[reasonName], unknown);
  }
  function syncBaselineControls() {
    syncBasis(baselineForm, 'cost_basis', 'cost_amount', 'currency', 'cost_unknown_reason');
    syncBasis(baselineForm, 'human_basis', 'human_minutes', null, 'human_unknown_reason');
  }
  function syncCostControls() {
    syncBasis(costForm, 'basis', 'amount', 'currency', 'unknown_reason');
    const relationship = costForm.elements.total_relationship.value;
    const includedDetail = relationship === 'included_in_current_total';
    costForm.elements.total_relationship.setCustomValidity(
      includedDetail || relationship === 'additional_to_current_total'
        ? '' : 'Choose whether this detail is already included or is an additional cost.',
    );
    costRelationshipHelp.textContent = includedDetail
      ? 'Breakdown only keeps this detail visible without adding it again. Choose it only when a current all-in total already includes this amount.'
      : 'Additional cost increases the current delivered total by this amount.';
    costCoverage.disabled = closed() || includedDetail;
    costForm.elements.complete_coverage.disabled = closed() || includedDetail;
    if (includedDetail) costForm.elements.complete_coverage.checked = false;
    requireWhen(
      costForm.elements.allocation_assumption,
      costForm.elements.allocation_method.value !== 'direct',
    );
    const hasQuantity = Boolean(
      costForm.elements.quantity.value.trim() || costForm.elements.unit.value.trim(),
    );
    costForm.elements.quantity.required = hasQuantity;
    costForm.elements.unit.required = hasQuantity;
    const completing = costForm.elements.complete_coverage.checked;
    COST_COVERAGE_FAMILIES.forEach(family => {
      const status = costForm.elements['coverage_' + family + '_status'];
      const note = costForm.elements['coverage_' + family + '_note'];
      status.required = completing;
      note.required = completing;
      status.setCustomValidity(
        completing && status.value === 'unknown'
          ? 'Choose Included in total or Confirmed zero before marking coverage complete.' : '',
      );
    });
  }
  function syncCommercialControls() {
    syncBasis(commercialForm, 'basis', 'amount', 'currency', 'unknown_reason');
  }
  baselineForm.elements.cost_basis.addEventListener('change', syncBaselineControls);
  baselineForm.elements.human_basis.addEventListener('change', syncBaselineControls);
  costForm.elements.basis.addEventListener('change', syncCostControls);
  costForm.elements.total_relationship.addEventListener('change', syncCostControls);
  costForm.elements.allocation_method.addEventListener('change', syncCostControls);
  costForm.elements.quantity.addEventListener('input', syncCostControls);
  costForm.elements.unit.addEventListener('input', syncCostControls);
  costForm.elements.complete_coverage.addEventListener('change', syncCostControls);
  COST_COVERAGE_FAMILIES.forEach(family => {
    costForm.elements['coverage_' + family + '_status'].addEventListener(
      'change', syncCostControls,
    );
  });
  commercialForm.elements.basis.addEventListener('change', syncCommercialControls);
  syncBaselineControls();
  syncCostControls();
  syncCommercialControls();
  baselineForm.addEventListener('submit', event => {
    event.preventDefault();
    try {
      const item = selectedCase();
      const fields = baselineForm.elements;
      const costUnknown = fields.cost_basis.value === 'unknown';
      const humanUnknown = fields.human_basis.value === 'unknown';
      const payload = {
        expected_revision: item.value_revision,
        cost_basis: fields.cost_basis.value,
        cost_amount: costUnknown ? null : optional(fields.cost_amount.value),
        currency: costUnknown ? null : optional(fields.currency.value.toUpperCase()),
        cost_unknown_reason: costUnknown ? optional(fields.cost_unknown_reason.value) : null,
        human_basis: fields.human_basis.value,
        human_minutes: humanUnknown ? null : optional(fields.human_minutes.value),
        human_unknown_reason: humanUnknown ? optional(fields.human_unknown_reason.value) : null,
        source_ref: fields.source_ref.value.trim(),
        evidence_note: fields.evidence_note.value.trim(),
        correction_reason: optional(fields.correction_reason.value),
      };
      save(
        baselineForm,
        '/api/v1/outcome-accounting/' + encodeURIComponent(item.outcome.id) + '/baseline',
        retryablePayload(baselineForm, 'baseline_', payload),
      );
    } catch (error) { statusHost.textContent = error.message; }
  });
  costForm.addEventListener('submit', event => {
    event.preventDefault();
    try {
      const item = selectedCase();
      const fields = costForm.elements;
      const unknown = fields.basis.value === 'unknown';
      const completeCoverage = fields.complete_coverage.checked;
      const coverageDeclarations = completeCoverage ? Object.fromEntries(
        COST_COVERAGE_FAMILIES.map(family => [family, {
          status: fields['coverage_' + family + '_status'].value,
          note: fields['coverage_' + family + '_note'].value.trim(),
        }]),
      ) : null;
      const payload = {
        expected_revision: item.outcome.revision,
        category: fields.category.value,
        attempt_state: fields.attempt_state.value,
        basis: fields.basis.value,
        total_relationship: fields.total_relationship.value,
        amount: unknown ? null : optional(fields.amount.value),
        currency: unknown ? null : optional(fields.currency.value.toUpperCase()),
        unknown_reason: unknown ? optional(fields.unknown_reason.value) : null,
        quantity: optional(fields.quantity.value), unit: optional(fields.unit.value),
        source_ref: fields.source_ref.value.trim(), evidence_note: fields.evidence_note.value.trim(),
        allocation_method: fields.allocation_method.value,
        allocation_assumption: fields.allocation_method.value === 'direct'
          ? null : optional(fields.allocation_assumption.value),
        correction_reason: optional(fields.correction_reason.value),
        complete_coverage: completeCoverage,
        coverage_declarations: coverageDeclarations,
      };
      save(
        costForm,
        '/api/v1/outcome-accounting/' + encodeURIComponent(item.outcome.id) + '/costs',
        retryablePayload(costForm, 'cost_', payload),
      );
    } catch (error) { statusHost.textContent = error.message; }
  });
  commercialForm.addEventListener('submit', event => {
    event.preventDefault();
    try {
      const item = selectedCase();
      const fields = commercialForm.elements;
      const unknown = fields.basis.value === 'unknown';
      const payload = {
        expected_revision: item.value_revision,
        kind: fields.kind.value,
        stage: fields.stage.value, basis: fields.basis.value,
        amount: unknown ? null : optional(fields.amount.value),
        currency: unknown ? null : optional(fields.currency.value.toUpperCase()),
        unknown_reason: unknown ? optional(fields.unknown_reason.value) : null,
        source_ref: fields.source_ref.value.trim(), note: fields.note.value.trim(),
        correction_reason: optional(fields.correction_reason.value),
      };
      save(
        commercialForm,
        '/api/v1/outcome-accounting/' + encodeURIComponent(item.outcome.id) + '/commercial',
        retryablePayload(commercialForm, 'commercial_', payload),
      );
    } catch (error) { statusHost.textContent = error.message; }
  });

  refreshButton.addEventListener('click', load);
  pilotSelector.addEventListener('change', load);
  loadMoreButton.addEventListener('click', () => {
    if (pilotCursor) loadPilots(pilotCursor, true);
  });
  selector.addEventListener('change', renderSelected);
  exportButton.addEventListener('click', async () => {
    exportButton.disabled = true;
    statusHost.textContent = 'Preparing the complete report…';
    try {
      const response = await fetch(
        '/api/v1/outcome-accounting/cohort/export?pilot_id=' +
          encodeURIComponent(pilotSelector.value), {
        cache: 'no-store', credentials: 'same-origin',
        headers: {'X-Lightwork-Pilot-Context': context},
      });
      if (!response.ok) fail('The complete report is unavailable. Refresh the page and try again.');
      const payload = await response.json();
      validateCohort(payload, 'lightwork.outcome-value-export.v1');
      await verifyExportEnvelope(payload);
      const blob = new Blob([JSON.stringify(payload, null, 2)], {type: 'application/json'});
      const url = URL.createObjectURL(blob);
      const link = node('a');
      link.href = url;
      link.download = 'lightwork-outcome-value-report.json';
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      statusHost.textContent = 'Value evidence report downloaded.';
    } catch (error) {
      statusHost.textContent = error instanceof ProjectionError
        ? error.message : 'The complete report could not be verified or downloaded. Try again.';
    } finally {
      exportButton.disabled = closed() || !cohort || !cohort.report.scope_complete;
    }
  });

  if (!CONTEXT.test(context)) {
    host.replaceChildren(node('p', 'This page is open for a different account or workspace. Reload this page.'));
    statusHost.textContent = 'No cohort data was requested.';
    refreshButton.disabled = true;
    loadMoreButton.disabled = true;
    loadMoreButton.hidden = true;
    return;
  }
  loadPilots();
}());
