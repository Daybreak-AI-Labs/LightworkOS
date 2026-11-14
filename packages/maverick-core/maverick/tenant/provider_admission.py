"""Durable organization holds for physical calls, separate from task limits.

The tenant roster and UsageLedger remain the organization policy/accounting
authority. This store bridges dispatch to acknowledged cumulative usage. Holds
are never deleted, but a hold admitted on an earlier UTC day stops counting
against today's cap; a provider receipt is required to resolve an uncertain
call.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import threading
import uuid
from contextlib import contextmanager
from contextvars import ContextVar

from ..budget import BudgetExceeded
from ..file_lock import (
    atomic_create_text,
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
)
from ..paths import current_tenant_id_strict, data_dir

_LOCK = threading.RLock()
_CURRENT: ContextVar[object | None] = ContextVar('organization_provider_budget', default=None)
_ID = re.compile(r'[a-f0-9]{32}\Z')


class OrganizationBudgetExceeded(BudgetExceeded):
    """The current organization allowance cannot admit this physical attempt."""


def _amount(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError('organization accounting amount must be numeric')
    if not math.isfinite(value) or value < 0:
        raise ValueError('organization accounting amount must be finite and non-negative')
    return float(value)


def _path(tenant):
    return data_dir('usage', 'provider_holds.json', tenant=tenant)


def _load(tenant, *, run_ids=(), key=None, scopes=()):
    path = _path(tenant)
    marker = path.with_suffix('.required')
    if not path.exists():
        if marker.exists():
            raise ValueError('organization provider accounting is missing')
        data = {'version': 1, 'runs': {}, 'calls': {}, 'plans': {}}
    else:
        ensure_private_file(path)
        if path.stat().st_size > 16 * 1024 * 1024:
            raise ValueError('organization pending provider accounting exceeds its size limit')
        data = json.loads(atomic_read_text(path))
    if (not isinstance(data, dict) or data.get('version') != 1
            or not isinstance(data.get('runs'), dict) or not isinstance(data.get('calls'), dict)):
        raise ValueError('invalid organization provider accounting')
    data.setdefault('plans', {})
    from . import _provider_archive
    _provider_archive.include(tenant, data, run_ids=run_ids, key=key, scopes=scopes)
    if not isinstance(data['plans'], dict):
        raise ValueError('invalid organization settlement plans')
    for scope, plan in data['plans'].items():
        if not _ID.fullmatch(scope) or not isinstance(plan, dict):
            raise ValueError('invalid organization settlement scope')
        _amount(plan.get('baseline'))
    for identity, run in data['runs'].items():
        if (not _ID.fullmatch(identity) or not isinstance(run, dict)
                or not isinstance(run.get('principal'), str) or not run['principal'].strip()
                or not isinstance(run.get('scope'), str) or not run['scope'].strip()
                or type(run.get('direct')) is not bool):
            raise ValueError('invalid organization run binding')
    for key, call in data['calls'].items():
        if (not isinstance(call, dict) or call.get('run_id') not in data['runs']
                or call.get('state') not in {'held', 'unknown', 'settled', 'not_dispatched'}
                or type(call.get('released')) is not bool
                or not isinstance(call.get('provider'), str)
                or not isinstance(call.get('request_id'), str)
                or key != _key(call['provider'], call['request_id'])
                or (call.get('reference') is not None and not isinstance(call['reference'], str))):
            raise ValueError('invalid organization attempt identity')
        _amount(call.get('projected'))
        if call['state'] == 'settled':
            _amount(call.get('actual'))
        elif call.get('actual') is not None:
            raise ValueError('unsettled organization call has actual cost')
    return data


def _save(tenant, data):
    from . import _provider_archive
    data = copy.deepcopy(data)
    _provider_archive.compact(tenant, data)
    path = _path(tenant)
    ensure_private_directory(path.parent)
    marker = path.with_suffix('.required')
    try:
        atomic_create_text(marker, 'organization provider accounting v1\n')
    except FileExistsError:
        ensure_private_file(marker)
    encoded = json.dumps(data, allow_nan=False, sort_keys=True)
    if len(encoded.encode()) > 16 * 1024 * 1024:
        raise ValueError('organization provider accounting exceeds its size limit')
    atomic_write_text(path, encoded, mode=0o600)


@contextmanager
def _locked(tenant):
    path = _path(tenant)
    ensure_private_directory(path.parent)
    with _LOCK, cross_process_lock(path, strict=True):
        yield


def _key(provider, request_id):
    return hashlib.sha256(json.dumps([provider, request_id]).encode()).hexdigest()


def initialize_budget(budget):
    tenant = current_tenant_id_strict()
    bound = getattr(budget, '_organization_tenant', tenant)
    if bound != tenant:
        raise ValueError('budget organization identity changed')
    if not tenant:
        return None
    budget._organization_tenant = tenant
    if not getattr(budget, '_organization_run_id', None):
        budget._organization_run_id = uuid.uuid4().hex
        budget._organization_run_ids = [budget._organization_run_id]
    return tenant


def bind_budget(budget, principal, scope=None):
    if not initialize_budget(budget):
        return None
    previous = getattr(budget, '_organization_principal', None)
    if previous is not None and previous != principal:
        raise ValueError('budget organization principal changed')
    budget._organization_principal = principal
    budget._organization_scope = scope or getattr(
        budget, '_organization_scope', budget._organization_run_id)
    return budget._organization_scope


def current_budget():
    """The run budget bound by :func:`run_scope`, if any."""
    return _CURRENT.get()


@contextmanager
def run_scope(budget, principal):
    bind_budget(budget, principal)
    token = _CURRENT.set(budget)
    try:
        yield
    finally:
        _CURRENT.reset(token)


def _held(call, today=None):
    """What an unacknowledged call still counts against TODAY's cap. A call's
    cost belongs to the UTC day it was admitted -- the same day the usage
    ledger books spend under -- so a hold from an earlier day (a goal that died
    before its ledger acknowledgement, or a cost that never became known) stops
    counting when that day ends instead of shrinking every future day's cap."""
    if call['released'] or call['state'] == 'not_dispatched':
        return 0.0
    from ..quotas import _today
    if call.get('day', today or _today()) != (today or _today()):
        return 0.0
    if call['state'] == 'settled':
        return call['actual']
    # An unknown zero projection is not evidence of a free failed request.
    if call['state'] == 'unknown' and call['projected'] == 0:
        return math.inf
    return call['projected']


def outstanding(tenant):
    from ..quotas import _today
    today = _today()
    return sum(_held(call, today) for call in _load(tenant)['calls'].values())


def reserve_call(provider, request_id, projected, *, projection_known=True, budget=None):
    """Atomic admission against current organization policy, before dispatch."""
    from . import registry

    tenant = current_tenant_id_strict()
    if not tenant:
        return None
    projected = _amount(projected)
    budget = budget or _CURRENT.get()
    if budget is not None:
        initialize_budget(budget)
    with registry._locked(strict=True):
        registry.assert_tenant_active(tenant)
        cap = registry._tenant_daily_cap(tenant)
        if cap <= 0:
            cap = 0  # Still keep receipts if an administrator enables a cap mid-run.
        if cap > 0 and not projection_known:
            raise OrganizationBudgetExceeded('Organization cap requires a priced provider projection')
        with _locked(tenant):
            key = _key(provider, request_id)
            data = _load(tenant, key=key, run_ids=getattr(budget, '_organization_run_ids', ()))
            if key in data['calls']:
                raise ValueError('organization physical attempt identity was already used')
            from ..quotas import _today
            today = _today()
            held = sum(_held(call, today) for call in data['calls'].values())
            used = registry.tenant_spend_today(tenant) + registry._legacy_outstanding_reservations(tenant)
            if cap > 0 and (not math.isfinite(used + held) or used + held >= cap or used + held + projected > cap):
                raise OrganizationBudgetExceeded(
                    f'Organization {tenant!r} daily cap cannot admit ${projected:.6f}; '
                    f'${used:.6f} recorded/legacy held plus ${held:.6f} pending, cap ${cap:.6f}')
            if budget is None:
                from ..connections import current_principal
                principal = current_principal() or 'local'
                identity = uuid.uuid4().hex
                run = {'principal': principal, 'scope': identity, 'direct': True}
            else:
                principal = getattr(budget, '_organization_principal', None)
                if principal is None:
                    from ..connections import current_principal
                    principal = (getattr(_CURRENT.get(), '_organization_principal', None)
                                 or current_principal() or 'local')
                scope = bind_budget(budget, principal)
                identity = budget._organization_run_id
                run = {'principal': principal, 'scope': scope, 'direct': False}
            previous = data['runs'].get(identity)
            if previous is not None and previous != run:
                from ..quotas import UsageLedger
                if (previous['principal'] != principal or previous['direct'] != run['direct']
                        or UsageLedger().settlement(previous['scope'], principal) is not None):
                    raise ValueError('organization run binding changed after settlement')
            data['runs'][identity] = run
            data['calls'][key] = {'provider': provider, 'request_id': request_id,
                                  'run_id': identity, 'projected': projected, 'actual': None,
                                  'state': 'held', 'released': False, 'reference': None,
                                  'day': today}
            _save(tenant, data)
    return tenant, key


def attach_reference(handle, reference):
    if handle is None:
        return
    tenant, key = handle
    if current_tenant_id_strict() != tenant:
        raise ValueError('organization attempt tenant changed')
    with _locked(tenant):
        data = _load(tenant, key=key)  # an earlier day's hold may be archived
        call = data['calls'][key]
        if call['reference'] not in (None, reference):
            raise ValueError('organization provider receipt changed')
        call['reference'] = reference
        _save(tenant, data)


def cancel_before_dispatch(handle):
    """Only a failed admission may release this known-not-dispatched hold."""
    if handle is None:
        return
    tenant, key = handle
    with _locked(tenant):
        data = _load(tenant, key=key)  # an earlier day's hold may be archived
        call = data['calls'][key]
        if call['state'] != 'held':
            raise ValueError('cannot cancel a dispatched organization attempt')
        call['state'] = 'not_dispatched'
        call['released'] = True
        _save(tenant, data)


def _scope_calls(data, scope, principal):
    run_ids = {identity for identity, run in data['runs'].items()
               if run['scope'] == scope and run['principal'] == principal}
    return [call for call in data['calls'].values() if call['run_id'] in run_ids]


def _acknowledge_scope(tenant, data, scope, principal, *, direct=False):
    """Reconcile against one cumulative receipt, never a second per-call bill."""
    from ..quotas import UsageLedger

    ledger = UsageLedger(data_dir('usage', 'ledger.json', tenant=tenant))
    receipt = ledger.settlement(scope, principal)
    if receipt is None and not direct:
        return
    calls = _scope_calls(data, scope, principal)
    actual = sum(call['actual'] for call in calls if call['state'] == 'settled')
    total = receipt['total'] if receipt is not None else {'dollars': 0, 'in_tokens': 0, 'out_tokens': 0}
    plan = data['plans'].get(scope)
    if plan is None:
        if not direct:
            return  # No durable evidence tying these receipts to this goal's charge.
        plan = data['plans'][scope] = {'baseline': 0.0}
        _save(tenant, data)
    ledger.record_cumulative(principal, scope, max(total['dollars'], plan['baseline'] + actual),
                             total['in_tokens'], total['out_tokens'])
    # A durable ledger acknowledgement precedes release. A crash before this
    # save merely double-counts conservatively; replay recovers the same receipt.
    for call in calls:
        if call['state'] == 'settled':
            call['released'] = True


def settle_call(provider, request_id, reference, actual, *, tenant=None):
    """Settle under the tenant the call was ADMITTED under (``tenant``, carried
    on the reservation), never whichever tenant the settling code happens to
    run as -- a settlement in another context silently left the hold forever."""
    tenant = tenant or current_tenant_id_strict()
    if not tenant:
        return
    # Legacy provider receipts may have no organization hold; do not invent one.
    key = _key(provider, request_id)
    with _locked(tenant):
        data = _load(tenant, key=key)
        if key not in data['calls']:
            return
        call = data['calls'][key]
        if call['reference'] != reference or call['state'] == 'not_dispatched':
            raise ValueError('organization provider receipt does not match')
        if call['state'] == 'settled':
            if actual != call['actual']:
                raise ValueError('organization cost receipt conflicts')
        elif actual is None:
            call['state'] = 'unknown'
        else:
            call.update(state='settled', actual=_amount(actual))
        # Publish evidence before the possibly-failing UsageLedger write.
        _save(tenant, data)
        run = data['runs'][call['run_id']]
        _acknowledge_scope(tenant, data, run['scope'], run['principal'], direct=run['direct'])
        _save(tenant, data)


def known_total(budget):
    tenant = initialize_budget(budget)
    if not tenant:
        return 0.0
    identities = set(budget._organization_run_ids)
    data = _load(tenant, run_ids=identities)
    principal = getattr(budget, '_organization_principal', None)
    for identity in identities:
        if identity in data['runs'] and data['runs'][identity]['principal'] != principal:
            raise ValueError('organization run principal does not match settlement')
    return sum(call['actual'] for call in data['calls'].values()
               if call['run_id'] in identities and call['state'] == 'settled')


def prepare_budget(budget, principal, scope, dollars):
    """Persist the charge/receipt relationship before writing the usage ledger.

    A later provider correction adds to the retained nonreceipt baseline. It
    cannot disappear underneath a larger historical task-counter total.
    """
    tenant = initialize_budget(budget)
    if not tenant:
        return dollars
    with _locked(tenant):
        data = _load(tenant, run_ids=budget._organization_run_ids, scopes=(scope,))
        for identity in budget._organization_run_ids:
            if identity in data['runs']:
                run = data['runs'][identity]
                if run['principal'] != principal:
                    raise ValueError('organization settlement principal changed')
                from ..quotas import UsageLedger
                if run['scope'] != scope and UsageLedger().settlement(run['scope'], principal) is not None:
                    # An absorbed child already billed its own scope. Preserve
                    # that identity so later corrections cannot be billed twice.
                    continue
                run['scope'] = scope
        calls = _scope_calls(data, scope, principal)
        if not calls:
            return dollars
        actual = sum(call['actual'] for call in calls if call['state'] == 'settled')
        prior = data['plans'].get(scope, {'baseline': 0.0})
        baseline = max(prior['baseline'], dollars - actual, 0.0)
        data['plans'][scope] = {'baseline': baseline}
        _save(tenant, data)
        return baseline + actual


def acknowledge_budget(budget, principal, scope):
    tenant = initialize_budget(budget)
    if not tenant:
        return
    with _locked(tenant):
        data = _load(tenant, run_ids=budget._organization_run_ids, scopes=(scope,))
        _acknowledge_scope(tenant, data, scope, principal)
        _save(tenant, data)


def foreign_settled_totals(budget, scope):
    """Amounts already billed by absorbed child scopes, not this goal scope."""
    total = {'dollars': 0.0, 'in_tokens': 0, 'out_tokens': 0}
    tenant = initialize_budget(budget)
    if not tenant:
        return total
    from ..quotas import UsageLedger
    identities = set(budget._organization_run_ids)
    data = _load(tenant, run_ids=identities)
    principal = budget._organization_principal
    scopes = {data['runs'][identity]['scope'] for identity in identities if identity in data['runs']}
    ledger = UsageLedger(data_dir('usage', 'ledger.json', tenant=tenant))
    for foreign in scopes - {scope}:
        receipt = ledger.settlement(foreign, principal)
        if receipt is None:
            continue
        members = {identity for identity, run in data['runs'].items() if run['scope'] == foreign}
        if not members.issubset(identities):
            raise ValueError('cannot absorb only part of a settled organization scope')
        for key in total:
            total[key] += receipt['total'][key]
    return total


def snapshot(budget):
    if not getattr(budget, '_organization_tenant', None):
        return None
    return {'tenant': budget._organization_tenant,
            'principal': getattr(budget, '_organization_principal', None),
            'run_ids': list(budget._organization_run_ids)}


def merge_snapshot(budget, saved):
    if saved is None:
        return
    tenant = initialize_budget(budget)
    if (not isinstance(saved, dict) or saved.get('tenant') != tenant
            or not isinstance(saved.get('run_ids'), list)
            or not all(isinstance(v, str) and _ID.fullmatch(v) for v in saved['run_ids'])):
        raise ValueError('checkpoint organization identity does not match current tenant')
    principal = getattr(budget, '_organization_principal', None)
    if saved.get('principal') != principal:
        raise ValueError('checkpoint organization principal does not match current principal')
    budget._organization_run_ids = list(dict.fromkeys(budget._organization_run_ids + saved['run_ids']))


def merge_budget(budget, other):
    saved = snapshot(other)
    if saved is None:
        return
    from ..connections import current_principal
    principal = (getattr(budget, '_organization_principal', None)
                 or getattr(_CURRENT.get(), '_organization_principal', None)
                 or current_principal() or 'local')
    bind_budget(budget, principal)
    # A never-dispatched child may have an identity but no principal yet.
    if saved['principal'] is None:
        data = _load(saved['tenant'])
        if any(identity in data['runs'] for identity in saved['run_ids']):
            raise ValueError('unbound child owns organization provider receipts')
        saved['principal'] = principal
    merge_snapshot(budget, saved)
