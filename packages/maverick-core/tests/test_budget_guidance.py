"""Budget guidance regressions; intentionally not executed in the audit build."""
from copy import deepcopy

from maverick import budget_guidance as guidance


class Store:
    def __init__(self):
        self.rows = {}
        self.created = 0

    def get(self, identity):
        return deepcopy(self.rows.get(identity))

    def create(self, row, **_):
        assert row['id'] not in self.rows
        self.created += 1
        self.rows[row['id']] = deepcopy(row)
        return deepcopy(row)


def view(*, remaining=10, period='2026-09'):
    return {'observed_at': 1790812800, 'person': {'cap': None}, 'workspace': {'cap': None},
            'providers': [{'provider': 'configured', 'period': period, 'cap': 100, 'remaining': remaining}]}


def test_threshold_receipt_deduplicates_same_person_and_provider_period(monkeypatch):
    store = Store()
    monkeypatch.setattr(guidance, '_warnings_store', lambda: store)
    monkeypatch.setattr(guidance, 'policy', lambda: {'guidance': True, 'warnings': True, 'warning_thresholds': [.8]})
    guidance.observe_warnings('user:a', view())
    later = view()
    later['observed_at'] += 86400
    guidance.observe_warnings('user:a', later)
    assert store.created == 1
    guidance.observe_warnings('user:b', later)
    assert store.created == 2
    guidance.observe_warnings('user:a', view(period='2026-10'))
    assert store.created == 3


def test_unknown_headroom_is_not_a_zero_charge_or_threshold(monkeypatch):
    store = Store()
    monkeypatch.setattr(guidance, '_warnings_store', lambda: store)
    monkeypatch.setattr(guidance, 'policy', lambda: {'guidance': True, 'warnings': True, 'warning_thresholds': [.8]})
    assert guidance.observe_warnings('user:a', view(remaining=None)) == []
    assert store.created == 0


def test_disabled_warnings_do_not_write_or_change_accounting(monkeypatch):
    monkeypatch.setattr(guidance, 'policy', lambda: {'guidance': True, 'warnings': False, 'warning_thresholds': [.8]})
    monkeypatch.setattr(guidance, '_warnings_store', lambda: (_ for _ in ()).throw(AssertionError('no store mutation')))
    assert guidance.observe_warnings('user:a', view(remaining=0)) == []


def test_preview_resolves_the_same_task_limits_as_launch(monkeypatch, tmp_path):
    from maverick import runner

    monkeypatch.setenv('MAVERICK_HOME', str(tmp_path))
    monkeypatch.delenv('MAVERICK_CONFIG', raising=False)
    monkeypatch.delenv('MAVERICK_BUDGET_DOLLARS', raising=False)
    monkeypatch.setattr(runner, '_operator_default_dollars', None)
    monkeypatch.setattr(runner, '_operator_default_wall_seconds', None)
    assert guidance.preview(None)['effective'] == {'max_dollars': 2.0, 'max_wall_seconds': 1800.0}
    # Without a config file a requested limit may exceed only the first-install
    # default, exactly as REST, worker and CLI launches resolve it.
    requested = guidance.preview(None, max_dollars=10.0, max_wall_seconds=3600.0)['effective']
    launched = {'max_dollars': runner.requested_goal_dollars(10.0),
                'max_wall_seconds': runner.requested_goal_wall_seconds(3600.0)}
    assert requested == launched == {'max_dollars': 10.0, 'max_wall_seconds': 3600.0}
    # An operator-set ceiling still narrows the request on both sides.
    monkeypatch.setattr('maverick.config.get_budget_overrides',
                        lambda: {'max_dollars': 5.0, 'max_wall_seconds': 600.0})
    requested = guidance.preview(None, max_dollars=10.0, max_wall_seconds=3600.0)['effective']
    launched = {'max_dollars': runner.requested_goal_dollars(10.0),
                'max_wall_seconds': runner.requested_goal_wall_seconds(3600.0)}
    assert requested == launched == {'max_dollars': 5.0, 'max_wall_seconds': 600.0}
