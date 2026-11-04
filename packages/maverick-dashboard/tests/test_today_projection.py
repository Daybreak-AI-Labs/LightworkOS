from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from maverick import domain, templates
from maverick_dashboard import product_operations_today as operations
from maverick_dashboard import today_projection as today


def test_template_choices_never_publish_ownerless_installed_or_other_person(monkeypatch, tmp_path):
    user = tmp_path / 'user'
    cases = {'mine': ('user:a', user / 'mine.md'), 'theirs': ('user:b', user / 'theirs.md'),
             'legacy': ('', user / 'legacy.md'), 'bundled': ('', tmp_path / 'bundled' / 'sample.md')}
    monkeypatch.setattr(today.auth, 'caller_principal', lambda request: 'user:a')
    monkeypatch.setattr(today.auth, 'has_permission', lambda *args: True)
    monkeypatch.setattr(templates, 'list_templates', lambda: list(cases))
    monkeypatch.setattr(templates, 'user_templates_dir', lambda: user)
    monkeypatch.setattr(templates, '_BUNDLED_CANDIDATES', [tmp_path / 'bundled'])
    monkeypatch.setattr(templates, 'load_template', lambda name: SimpleNamespace(name=name, owner=cases[name][0], path=cases[name][1], title=name))
    assert set(today.template_choices(object())) == {'mine', 'bundled'}


def test_active_projection_does_not_hide_old_active_tasks_behind_recent_completed(monkeypatch):
    mine = SimpleNamespace(id=7, owner='user:a', status='active', title='Old but active', updated_at=1, domain='general')
    other = SimpleNamespace(id=8, owner='user:b', status='active', title='Private', updated_at=2, domain='general')
    seen = []
    def goals(**kwargs):
        seen.append(kwargs)
        return [mine, other] if kwargs['status'] == 'active' else []
    monkeypatch.setattr(today.auth, 'suite_allowed', lambda *args: True)
    monkeypatch.setattr(today.auth, 'can_access_goal', lambda *args: True)
    monkeypatch.setattr(domain, 'suite_for', lambda name: None)
    result = today._tasks(object(), SimpleNamespace(list_goals=goals), 'user:a', 1000)
    assert [row['title'] for row in result['active']] == ['Old but active']
    assert all(row['owner'] == 'user:a' for row in seen)


def test_hiding_decisions_changes_layout_only_and_preserves_card_order(monkeypatch):
    state = {'values': {'today_cards': ['tasks', 'decisions', 'recent'], 'template_favorites': []}}
    monkeypatch.setattr(operations.native, '_state', lambda request: state)
    _, changes = operations._changes(object(), {'action': 'hide', 'item': 'decisions'})
    assert changes == {'today_cards': ['tasks', 'recent']}
    assert state['values']['today_cards'] == ['tasks', 'decisions', 'recent']
    _, changes = operations._changes(object(), {'action': 'move_up', 'item': 'recent'})
    assert changes == {'today_cards': ['tasks', 'recent', 'decisions']}


def test_no_pin_after_template_access_revoked(monkeypatch):
    monkeypatch.setattr(operations.native, '_state', lambda request: {'values': {'template_favorites': []}})
    monkeypatch.setattr(operations.projection, 'template_choices', lambda request: {})
    with pytest.raises(HTTPException) as error:
        operations._changes(object(), {'action': 'pin_template', 'item': 'private'})
    assert error.value.status_code == 403


def _row(kind, assignment, title):
    return {"kind": kind, "assignment": assignment, "title": title, "href": "#", "reason": "r"}


def test_today_lists_what_waits_on_this_person_and_only_counts_the_shared_queue(monkeypatch):
    from maverick_dashboard import action_center_api

    model = {
        "items": [
            _row("assessment", "available", "Fabrikam Freight"),
            _row("assessment", "mine", "My vendor review"),
            _row("approval", "mine", "Archive drafts"),
            _row("connection_attention", "mine", "Not a decision"),
        ],
        "coverage": [
            {"kind": "assessment", "status": "current"},
            {"kind": "connection_attention", "status": "disabled"},
            {"kind": "approval", "status": "unavailable"},
            {"kind": "signoff", "status": "partial"},
            {"kind": "task_attention", "status": "unavailable"},
        ],
        "generated_at": 1.0,
    }
    monkeypatch.setattr(action_center_api, "require_enabled", lambda request: None)
    monkeypatch.setattr(action_center_api, "_model", lambda request: model)
    out = today._decisions(object())
    assert [row["title"] for row in out["items"]] == ["My vendor review", "Archive drafts"]
    assert out["count"] == 2 and out["available"] == 1
    # Only real problems with the decision sources are reported: a turned-off
    # module or a source that loaded fine says nothing.
    assert [(c["kind"], c["status"]) for c in out["coverage"]] == [
        ("approval", "unavailable"), ("signoff", "partial")]
    assert [c["label"] for c in out["coverage"]] == ["Approvals", "Result approvals"]
