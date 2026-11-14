"""Organization caps admit physical attempts, never arbitrary task allotments."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick import provider_cost_cap as provider
from maverick.budget import Budget, budget_from_config
from maverick.checkpoint import restore_budget, snapshot_budget
from maverick.orchestrator import _QuotaUsageSettlement
from maverick.paths import tenant_scope
from maverick.quotas import UsageLedger
from maverick.tenant import provider_admission as organization
from maverick.tenant import registry


@pytest.fixture(autouse=True)
def tenant(monkeypatch):
    monkeypatch.setenv('MAVERICK_TENANT', 'acme')
    registry.create_tenant('acme', max_daily_dollars=10)
    monkeypatch.setattr(provider, 'caps_from_config', dict)
    monkeypatch.setattr(provider, '_shared_world', lambda: None)


def start_budget():
    budget = budget_from_config()
    settlement = _QuotaUsageSettlement(principal='user:alice', budget=budget, domain=None)
    return budget, settlement


def attempt(budget, amount=3, name='openai'):
    return provider.reserve(name, amount, organization_budget=budget)


def test_constructing_uncapped_and_explicit_budgets_consumes_no_allowance():
    budgets = [budget_from_config(), budget_from_config(max_dollars=7)]
    assert budgets[0].max_dollars is None
    assert budgets[1].max_dollars == 7
    assert registry.tenant_remaining_today('acme') == 10
    assert all(not hasattr(b, '_tenant_reservation_id') for b in budgets)


def test_current_organization_cap_applies_to_uncapped_task_before_each_attempt():
    budget, _ = start_budget()
    first = attempt(budget, 6)
    assert first is not None  # real provider receipt even without provider cap
    registry.set_quota('acme', 7)
    with pytest.raises(organization.OrganizationBudgetExceeded, match='Organization.*cap'):
        attempt(budget, 2, 'anthropic')
    assert registry.tenant_remaining_today('acme') == 1


def test_concurrent_physical_attempts_share_one_current_cap():
    barrier = threading.Barrier(4)

    def dispatch(index):
        with tenant_scope(tenant='acme'):
            budget, _ = start_budget()
            barrier.wait(timeout=10)
            try:
                return attempt(budget, 3, f'fixture-{index}')
            except organization.OrganizationBudgetExceeded:
                return None

    with ThreadPoolExecutor(max_workers=4) as pool:
        receipts = list(pool.map(dispatch, range(4)))
    assert sum(receipt is not None for receipt in receipts) == 3
    assert registry.tenant_remaining_today('acme') == 1


def test_known_cost_is_charged_once_and_unknown_attempt_survives_goal_end(monkeypatch):
    budget, settlement = start_budget()
    known, uncertain = attempt(budget, 3), attempt(budget, 4, 'anthropic')
    provider.settle(known, 2)
    provider.settle(uncertain, None)
    budget.dollars = 2
    settlement.record()
    settlement.record()
    assert UsageLedger().usage('user:alice')['dollars'] == 2
    assert registry.tenant_remaining_today('acme') == 4
    # Uncertain organization holds have no timeout/backstop expiry.
    monkeypatch.setattr(registry.time, 'time', lambda: 9_999_999_999)
    assert organization.outstanding('acme') == 4
    assert registry.tenant_remaining_today('acme') <= 6


def test_late_provider_reconciliation_uses_same_goal_receipt_and_is_idempotent():
    budget, settlement = start_budget()
    known, uncertain = attempt(budget, 3), attempt(budget, 4, 'anthropic')
    provider.settle(known, 2)
    provider.settle(uncertain, None)
    budget.dollars = 2
    settlement.record()
    # Reconstruct only the durable provider identity: no original Budget/ticket
    # object is needed by an operator reconciliation after process loss.
    restored = provider.Reservation(uncertain.provider, uncertain.period, uncertain.request_id,
                                    uncertain.projected, uncertain.path, uncertain.shared)
    provider.settle(restored, 1)
    provider.settle(restored, 1)
    assert UsageLedger().usage('user:alice')['dollars'] == 3
    assert registry.tenant_remaining_today('acme') == 7
    again = _QuotaUsageSettlement(principal='user:alice', budget=budget, domain=None)
    again.record()
    assert UsageLedger().usage('user:alice')['dollars'] == 3


def test_receipt_known_cost_above_budget_counter_is_not_lost():
    budget, settlement = start_budget()
    receipt = attempt(budget, 2)
    provider.settle(receipt, 3)
    # For example, acknowledged response usage arrived after a caller stopped
    # before copying its counters. The authoritative cost is still charged.
    budget.dollars = 0
    settlement.record()
    assert UsageLedger().usage('user:alice')['dollars'] == 3
    assert registry.tenant_remaining_today('acme') == 7


def test_late_cost_adds_to_historical_nonreceipt_usage_baseline():
    registry.set_quota('acme', 30)
    budget, settlement = start_budget()
    provider.settle(attempt(budget, 3), 2)
    uncertain = attempt(budget, 4, 'anthropic')
    provider.settle(uncertain, None)
    # Historical usage without receipt identities (for example an old snapshot).
    budget.dollars = 10
    settlement.record()
    assert registry.tenant_spend_today('acme') == 10
    provider.settle(uncertain, 1)
    provider.settle(uncertain, 1)
    assert registry.tenant_spend_today('acme') == 11
    _QuotaUsageSettlement(principal='user:alice', budget=budget, domain=None).record()
    assert registry.tenant_spend_today('acme') == 11


def test_enabling_organization_cap_keeps_receipts_from_uncapped_period():
    registry.set_quota('acme', 0)
    budget, settlement = start_budget()
    provider.settle(attempt(budget, 2), 1)
    registry.set_quota('acme', 3)
    assert registry.tenant_remaining_today('acme') == 2
    with pytest.raises(organization.OrganizationBudgetExceeded):
        attempt(budget, 3)
    budget.dollars = 1
    settlement.record()
    assert registry.tenant_spend_today('acme') == 1


def test_released_history_is_archived_but_replay_and_resume_keep_receipt_identity():
    budget, settlement = start_budget()
    receipt = attempt(budget, 3)
    provider.settle(receipt, 2)
    budget.dollars = 2
    saved = snapshot_budget(budget)
    settlement.record()
    assert organization._load('acme')['calls'] == {}
    assert organization._load('acme')['runs'] == {}
    provider.settle(receipt, 2)
    assert organization.known_total(budget) == 2
    restored, final = start_budget()
    restore_budget(saved, into=restored)
    final.record()
    assert registry.tenant_spend_today('acme') == 2
    assert organization.outstanding('acme') == 0
    with pytest.raises(provider.ProviderAccountingUnavailable):
        provider.reserve(receipt.provider, 3, request_id=receipt.request_id,
                         organization_budget=restored)


def test_lost_required_archive_fails_closed_after_completed_calls():
    from maverick.paths import data_dir
    budget, settlement = start_budget()
    provider.settle(attempt(budget, 2), 1)
    budget.dollars = 1
    settlement.record()
    data_dir('usage', 'provider_history.sqlite3', tenant='acme').unlink()
    with pytest.raises(provider.ProviderAccountingUnavailable):
        attempt(budget, 1)


def test_interrupted_archive_creation_does_not_block_provider_calls():
    # A crash between creating the history file and writing its schema left
    # a zero-byte database; every later reserve_call failed on "no such table".
    from maverick.paths import data_dir
    path = data_dir('usage', 'provider_history.sqlite3', tenant='acme')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b'')
    budget, _ = start_budget()
    assert attempt(budget, 1) is not None


def test_archive_commit_before_hot_removal_can_replay_without_double_charge(monkeypatch):
    from maverick.tenant import _provider_archive
    budget, settlement = start_budget()
    receipt = attempt(budget, 3)
    provider.settle(receipt, 2)
    budget.dollars = 2
    compact = _provider_archive.compact

    def fail_after_archive(tenant, data):
        compact(tenant, data)
        if not data['calls']:
            raise OSError('interrupted before hot-store removal')

    with monkeypatch.context() as patch:
        patch.setattr(_provider_archive, 'compact', fail_after_archive)
        settlement.record()
    assert registry.tenant_spend_today('acme') == 2
    assert organization.outstanding('acme') == 2  # conservative duplicate remains
    provider.settle(receipt, 2)
    assert registry.tenant_spend_today('acme') == 2
    assert organization.outstanding('acme') == 0
    assert organization._load('acme')['calls'] == {}


def test_compacting_other_closed_scope_never_removes_unknown_attempt():
    pending, finish_pending = start_budget()
    receipt = attempt(pending, 4)
    provider.settle(receipt, None)
    finish_pending.record()
    closed, finish_closed = start_budget()
    provider.settle(attempt(closed, 2), 1)
    closed.dollars = 1
    finish_closed.record()
    hot = organization._load('acme')
    assert len(hot['calls']) == 1
    assert next(iter(hot['calls'].values()))['state'] == 'unknown'
    assert organization.outstanding('acme') == 4
    assert registry.tenant_remaining_today('acme') == 5


def test_empty_goals_do_not_accumulate_settlement_plans():
    for _ in range(3):
        _budget, settlement = start_budget()
        settlement.record()
    assert organization._load('acme')['plans'] == {}


def test_failed_usage_ack_keeps_known_holds(monkeypatch):
    budget, settlement = start_budget()
    receipt = attempt(budget, 3)
    provider.settle(receipt, 2)
    budget.dollars = 2
    monkeypatch.setattr('maverick.quotas.record_usage', lambda *a, **k: False)
    settlement.record()
    assert organization.outstanding('acme') == 2
    assert UsageLedger().usage('user:alice')['dollars'] == 0


def test_crash_between_usage_ack_and_hold_release_recovers_without_double_charge(monkeypatch):
    budget, settlement = start_budget()
    receipt = attempt(budget, 3)
    provider.settle(receipt, 2)
    budget.dollars = 2
    with monkeypatch.context() as patch:
        patch.setattr(organization, 'acknowledge_budget', lambda *a: (_ for _ in ()).throw(OSError('crash')))
        settlement.record()
    assert UsageLedger().usage('user:alice')['dollars'] == 2
    assert organization.outstanding('acme') == 2
    provider.settle(receipt, 2)
    assert organization.outstanding('acme') == 0
    assert UsageLedger().usage('user:alice')['dollars'] == 2


def test_provider_admission_failure_releases_only_known_not_dispatched_org_hold(monkeypatch):
    budget, _ = start_budget()
    monkeypatch.setattr(provider, 'caps_from_config', lambda: {'openai': 0.5})
    with pytest.raises(provider.ProviderCapExceeded):
        attempt(budget, 2)
    assert registry.tenant_remaining_today('acme') == 10


def test_reference_publication_failure_before_dispatch_cleans_both_holds(monkeypatch):
    budget, _ = start_budget()
    attach = organization.attach_reference

    def fail_after_write(*args):
        attach(*args)
        raise OSError('publication acknowledgement lost before dispatch')

    monkeypatch.setattr(organization, 'attach_reference', fail_after_write)
    with pytest.raises(OSError, match='acknowledgement'):
        attempt(budget, 2)
    assert registry.tenant_remaining_today('acme') == 10
    assert provider.check('openai').spent == 0


def test_checkpoint_merges_preflight_and_saved_run_identities():
    old, _ = start_budget()
    provider.settle(attempt(old, 3), 2)
    old.dollars = 2
    saved = snapshot_budget(old)
    new, settlement = start_budget()
    provider.settle(attempt(new, 2), 1)
    new.dollars = 1
    restore_budget(saved, into=new)
    assert len(new._organization_run_ids) == 2
    assert new.dollars == 3
    settlement.record()
    assert UsageLedger().usage('user:alice')['dollars'] == 3
    assert organization.outstanding('acme') == 0


@pytest.mark.parametrize('changed', ['tenant', 'principal'])
def test_checkpoint_cannot_merge_foreign_organization_scope(changed):
    old, _ = start_budget()
    saved = snapshot_budget(old)
    saved['_organization'][changed] = 'different'
    current, _ = start_budget()
    with pytest.raises(ValueError, match='organization'):
        restore_budget(saved, into=current)
    assert current.dollars == 0


def test_absorb_merges_child_attempts_but_keeps_unknown_holds():
    parent, settlement = start_budget()
    child = Budget()
    with organization.run_scope(parent, 'user:alice'):
        provider.settle(attempt(child, 3), 2)
        provider.settle(attempt(child, 4, 'anthropic'), None)
    child.dollars = 2
    parent.absorb(child)
    settlement.record()
    assert UsageLedger().usage('user:alice')['dollars'] == 2
    assert organization.outstanding('acme') == 4


def test_absorbed_already_settled_child_and_late_correction_are_not_charged_twice():
    parent, parent_settlement = start_budget()
    child, child_settlement = start_budget()
    provider.settle(attempt(child, 2), 1)
    uncertain = attempt(child, 2, 'anthropic')
    provider.settle(uncertain, None)
    child.dollars = 1
    child_settlement.record()
    parent.absorb(child)
    provider.settle(attempt(parent, 2), 1)
    parent.dollars += 1
    parent_settlement.record()
    assert registry.tenant_spend_today('acme') == 2
    provider.settle(uncertain, 1)
    assert registry.tenant_spend_today('acme') == 3
    _QuotaUsageSettlement(principal='user:alice', budget=parent, domain=None).record()
    assert registry.tenant_spend_today('acme') == 3


def test_checkpoint_scope_can_bind_after_preflight_before_acknowledgement():
    budget, settlement = start_budget()
    provider.settle(attempt(budget, 2), 1)
    scope = '1' * 32
    organization.bind_budget(budget, 'user:alice', scope)
    settlement.scope = scope
    provider.settle(attempt(budget, 2), 1)
    budget.dollars = 2
    settlement.record()
    assert registry.tenant_spend_today('acme') == 2
    assert organization.outstanding('acme') == 0


def test_direct_metered_call_settles_own_scope_and_goal_tool_uses_goal_scope():
    assert provider.metered_provider_call('openai', lambda: 'direct',
                                         projected_dollars=2, actual_dollars=1) == 'direct'
    assert registry.tenant_spend_today('acme') == 1
    budget, settlement = start_budget()
    with organization.run_scope(budget, 'user:alice'):
        provider.metered_provider_call('openai', lambda: 'goal tool',
                                      projected_dollars=3, actual_dollars=2)
    assert registry.tenant_spend_today('acme') == 1
    budget.dollars = 2
    settlement.record()
    assert registry.tenant_spend_today('acme') == 3
    assert organization.outstanding('acme') == 0


def test_corrupt_or_lost_established_store_never_reopens_allowance():
    budget, _ = start_budget()
    attempt(budget, 3)
    path = organization._path('acme')
    path.unlink()
    with pytest.raises(provider.ProviderAccountingUnavailable):
        attempt(budget, 1)
    assert not path.exists()


def test_no_active_tenant_preserves_unattributed_library_call(monkeypatch):
    monkeypatch.delenv('MAVERICK_TENANT')
    with tenant_scope(tenant=None):
        assert provider.reserve('openai', 1) is None


def test_physical_retry_tracker_holds_each_attempt(monkeypatch):
    from maverick import llm
    budget, settlement = start_budget()
    monkeypatch.setattr(llm, '_response_call_accounting',
                        lambda model, response, cache, **kwargs: (None, None, None) if response is None
                        else (1, 'estimated', None))
    sequence = llm._new_provider_attempt_sequence(default_category='other', operation_prefix='fixture')
    tracker = llm._ProviderAttemptTracker('anthropic', llm.MODEL_SONNET, budget, 1, 3,
                                          sequence=sequence, service='fixture')
    first = tracker.before_attempt()
    tracker.after_attempt(first, None, TimeoutError('uncertain provider response'))
    second = tracker.before_attempt()
    response = type('Response', (), {})()
    tracker.after_attempt(second, response, None)
    tracker.finalize(response)
    budget.dollars = 1
    settlement.record()
    assert organization.outstanding('acme') == 3
    assert registry.tenant_spend_today('acme') == 1
