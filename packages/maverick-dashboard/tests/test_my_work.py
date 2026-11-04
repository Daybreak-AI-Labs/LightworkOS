"""Private work projection scopes before reading; missing sources stay explicit."""
from types import SimpleNamespace

from maverick_dashboard import my_work_api as work


def test_readonly_work_is_exact_owner_scoped_and_does_not_claim_external_completion(monkeypatch):
    from maverick_dashboard import app

    seen = []
    own = SimpleNamespace(id=1, owner="user:alice", title="Own result", status="done", updated_at=12)
    foreign = SimpleNamespace(id=2, owner="user:bob", title="Must stay private", status="active", updated_at=13)
    class World:
        def list_goals(self, **kwargs):
            seen.append(kwargs)
            return [own, foreign]  # defensive filtering survives a malformed adapter
    monkeypatch.setattr(app, "_world", lambda: World())
    monkeypatch.setattr(work, "caller_principal", lambda _: "user:alice")
    monkeypatch.setattr(work, "has_permission", lambda *_: False)
    monkeypatch.setattr(work, "assert_goal_access", lambda *_: None)
    monkeypatch.setattr(work, "context_for", lambda _: "a" * 64)
    result = work._model(object())
    assert seen[0]["owner"] == "user:alice"
    assert [row["title"] for row in result["items"]] == ["Own result"]
    assert "does not verify external delivery" in result["items"][0]["detail"]
    assert any(row["state"] == "not permitted" for row in result["coverage"])


def test_auth_off_projection_does_not_expand_to_named_employee_work(monkeypatch):
    from maverick_dashboard import app

    class World:
        def list_goals(self, **kwargs):
            assert kwargs["owner"] == ""
            raise OSError("source unavailable")
    monkeypatch.setattr(app, "_world", lambda: World())
    monkeypatch.setattr(work, "caller_principal", lambda _: None)
    monkeypatch.setattr(work, "has_permission", lambda *_: False)
    monkeypatch.setattr(work, "context_for", lambda _: "a" * 64)
    result = work._model(object())
    assert result["items"] == []
    assert result["coverage"][0]["state"] == "unavailable"


def test_task_rows_use_the_same_status_words_as_the_task_page(monkeypatch):
    from maverick_dashboard import app

    goals = [SimpleNamespace(id=3, owner="user:alice", title="Stopped one", status="cancelled", updated_at=5),
             SimpleNamespace(id=4, owner="user:alice", title="Running one", status="active", updated_at=6)]

    class World:
        def list_goals(self, **kwargs):
            return goals
    monkeypatch.setattr(app, "_world", lambda: World())
    monkeypatch.setattr(work, "caller_principal", lambda _: "user:alice")
    monkeypatch.setattr(work, "has_permission", lambda *_: False)
    monkeypatch.setattr(work, "assert_goal_access", lambda *_: None)
    monkeypatch.setattr(work, "context_for", lambda _: "a" * 64)
    states = {row["title"]: row["state"] for row in work._model(object())["items"]}
    assert states == {"Stopped one": "Stopped", "Running one": "Working"}
