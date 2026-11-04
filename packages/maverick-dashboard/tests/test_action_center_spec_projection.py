"""Empty owner queues avoid specialist discovery without caching authority."""
from types import SimpleNamespace

import pytest
from maverick_dashboard import action_center as center
from maverick_dashboard import action_center_api as api


class World:
    def __init__(self, rows):
        self.rows = rows
        self.queries = []
        self.signoff_ids = []

    def list_goals(self, **query):
        self.queries.append(query)
        return self.rows

    def signoffs_for_goals(self, ids):
        self.signoff_ids.append(ids)
        return {}


def goal(identifier=1, domain="forecast"):
    return SimpleNamespace(id=identifier, domain=domain, title="Private forecast",
                           owner="user:alice", updated_at=20)


def test_empty_owner_queue_does_not_load_specialist_specs():
    world = World([])

    def unavailable_specs():
        pytest.fail("An empty owner queue must not discover specialist packs")

    assert center._signoff_source(world, "user:alice", unavailable_specs) == (
        [], [{"kind": "signoff", "status": "current"}],
    )
    assert world.queries == [{"status": "done", "owner": "user:alice",
                              "limit": center.SOURCE_LIMIT + 1, "order": "desc"}]
    assert world.signoff_ids == [[]]


def test_lazy_api_specs_recheck_current_suite_scope_on_every_projection(monkeypatch):
    import importlib

    from maverick import assessment

    app = importlib.import_module("maverick_dashboard.app")
    world = World([goal(), goal(2, "restricted")])
    request = SimpleNamespace(allowed=frozenset({"finance"}))
    loads, scopes = [], []
    monkeypatch.setattr(api, "caller_principal", lambda request: "user:alice")
    monkeypatch.setattr(api, "goal_owner_filter", lambda request: "user:alice")
    monkeypatch.setattr(api.config, "get_features", dict)
    monkeypatch.setattr(assessment, "custom_template_records", dict)
    monkeypatch.setattr(app, "_world", lambda: world)

    def load_specs():
        loads.append(True)
        return [{"domain": "forecast", "suite": "finance", "suites": ["finance"],
                 "gate": "human", "deliverable": "Forecast"},
                {"domain": "restricted", "suite": "finance", "suites": ["finance", "legal"],
                 "gate": "human", "deliverable": "Hidden"}]

    def current_scope(current_request):
        scopes.append(current_request.allowed)
        return current_request.allowed

    def collect(current_world, *, owner, specs, **kwargs):
        assert callable(specs)
        return center._signoff_source(current_world, owner, specs)

    monkeypatch.setattr(app, "_deliverable_specs", load_specs)
    monkeypatch.setattr(api, "caller_suites", current_scope)
    monkeypatch.setattr(api.action_center, "collect", collect)
    rows, coverage = api._model(request)
    assert [row["href"] for row in rows] == ["/chat/goal/1"]
    assert coverage == [{"kind": "signoff", "status": "current"}]
    request.allowed = frozenset()
    assert api._model(request) == ([], coverage)
    assert len(loads) == 2 and scopes == [frozenset({"finance"}), frozenset()]
    assert world.signoff_ids == [[1], []]
    world.rows = []
    assert api._model(request) == ([], coverage)
    assert len(loads) == 2


def test_bounded_queue_retains_partial_coverage_and_only_projects_bounded_rows(monkeypatch):
    monkeypatch.setattr(center, "SOURCE_LIMIT", 1)
    world = World([goal(1), goal(2)])
    rows, coverage = center._signoff_source(world, "user:alice", lambda: [
        {"domain": "forecast", "gate": "human", "deliverable": "Forecast"},
    ])
    assert [row["href"] for row in rows] == ["/chat/goal/1"]
    assert coverage == [{"kind": "signoff", "status": "partial"}]
    assert world.signoff_ids == [[1]]


def test_nonempty_queue_spec_failure_is_unavailable_not_clear():
    world = World([goal()])

    def broken_scope():
        raise OSError("private configuration failure")

    assert center._signoff_source(world, "user:alice", broken_scope) == (
        [], [{"kind": "signoff", "status": "unavailable"}],
    )
    assert world.signoff_ids == []
