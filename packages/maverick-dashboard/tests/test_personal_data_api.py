"""Account-bound personal-data route regressions for deferred execution."""
import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from maverick_dashboard import personal_data_api as api


def test_learning_exclusion_never_accepts_admin_as_other_owner(monkeypatch):
    world = SimpleNamespace(get_goal=lambda goal: SimpleNamespace(id=goal, owner="user:employee"))
    monkeypatch.setattr(api, "_write_actor", lambda *a: "user:admin")
    monkeypatch.setattr(api, "_actor", lambda *a: "user:admin")
    monkeypatch.setattr(api, "_app", lambda: SimpleNamespace(_world=lambda: world))
    with pytest.raises(HTTPException) as error:
        api.exclude_learning(None, 5, api.ContextIn(context="0" * 64))
    assert error.value.status_code == 403


def test_source_view_filters_exact_owned_conversation(monkeypatch):
    monkeypatch.setattr(api, "_actor", lambda _: "user:alice")
    monkeypatch.setattr(api.personal_memory, "owned_scopes", lambda _: [{"channel": "slack", "user_id": "bound-alice"}])
    world = SimpleNamespace(list_conversations=lambda: [SimpleNamespace(id=5, channel="slack", user_id="bound-bob")],
                            recent_turns=lambda *a, **kw: pytest.fail("must not read another owner's turns"))
    monkeypatch.setattr(api, "_app", lambda: SimpleNamespace(_world=lambda: world))
    with pytest.raises(HTTPException) as error:
        api.source(None, 5, 7)
    assert error.value.status_code == 404


def test_private_json_responses_are_not_cacheable():
    response = api._call(lambda: {"note": "private"})
    assert response.headers["cache-control"] == "private, no-store"
    assert json.loads(response.body) == {"note": "private"}
