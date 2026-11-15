"""The remember_outcome_key tool: a run links an external business id to its
episode so a later real-world outcome can ground it. Registered only when the
learning loop ([consequence]) is on."""
from __future__ import annotations

from maverick import consequence
from maverick.tools.outcome_link import remember_outcome_key


class _Ep:
    def __init__(self, id):
        self.id = id


class _World:
    def __init__(self, episodes):
        self._episodes = episodes

    def list_episodes(self, goal_id=None, limit=50):
        return self._episodes[:limit]


def test_tool_links_key_to_latest_episode(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick.paths.data_dir", lambda *p, **k: tmp_path.joinpath(*p))
    consequence.reset_shared()
    tool = remember_outcome_key(_World([_Ep(55)]), goal_id=7)
    msg = tool.fn({"key": "invoice:INV-3"})
    assert "Linked" in msg
    assert consequence.shared_correlation().resolve("invoice:INV-3") == (7, 55)


def test_tool_does_not_claim_a_refused_learning_write(monkeypatch):
    monkeypatch.setattr(consequence, "link_outcome_key", lambda *args: False)
    tool = remember_outcome_key(_World([_Ep(55)]), goal_id=7)
    assert tool.fn({"key": "invoice:INV-3"}).startswith("ERROR: outcome key was not linked")


def test_failed_persistent_link_is_not_visible_in_memory(tmp_path):
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")
    store = consequence.CorrelationStore(path=blocked / "links.ndjson")
    assert store.link("invoice:INV-3", 7, 55) is False
    assert store.resolve("invoice:INV-3") is None


def test_tool_runs_through_the_registry_with_a_dict_payload(tmp_path, monkeypatch):
    """The registry calls every executor as fn(args) with ONE dict. The tool used
    to take ``key=`` and crashed on every live call ('dict' has no attribute
    'strip'), so no run could ever link an outcome."""
    import asyncio

    from maverick.tools import ToolRegistry

    monkeypatch.setattr("maverick.paths.data_dir", lambda *p, **k: tmp_path.joinpath(*p))
    consequence.reset_shared()
    reg = ToolRegistry()
    reg.register(remember_outcome_key(_World([_Ep(55)]), goal_id=7))

    out = asyncio.run(reg.run("remember_outcome_key", {"key": "renewal-2026"}))

    assert out.startswith("Linked"), out
    assert consequence.shared_correlation().resolve("renewal-2026") == (7, 55)


def test_tool_through_the_registry_rejects_a_missing_key():
    import asyncio

    from maverick.tools import ToolRegistry

    reg = ToolRegistry()
    reg.register(remember_outcome_key(_World([_Ep(1)]), goal_id=1))

    for payload in ({}, {"key": None}, {"key": "   "}):
        out = asyncio.run(reg.run("remember_outcome_key", payload))
        assert out.startswith("ERROR: remember_outcome_key requires a non-empty"), out


def test_tool_requires_key():
    tool = remember_outcome_key(_World([_Ep(1)]), goal_id=1)
    assert tool.fn({"key": "  "}).startswith("ERROR")


def test_tool_requires_active_goal():
    tool = remember_outcome_key(None, goal_id=None)
    assert tool.fn({"key": "x"}).startswith("ERROR")


def test_tool_handles_no_episode_yet():
    tool = remember_outcome_key(_World([]), goal_id=1)
    assert tool.fn({"key": "x"}).startswith("ERROR")


def test_tool_registered_only_when_consequence_on(tmp_path, monkeypatch):
    from maverick.sandbox import LocalBackend
    from maverick.tools import base_registry
    from maverick.world_model import WorldModel
    w = WorldModel(path=tmp_path / "world.db")
    sb = LocalBackend(workdir=tmp_path)

    monkeypatch.delenv("MAVERICK_CONSEQUENCE", raising=False)
    monkeypatch.setattr("maverick.config.get_consequence", lambda: {"enable": False})
    reg = base_registry(w, sb, goal_id=1)
    assert "remember_outcome_key" not in {t.name for t in reg.all()}

    monkeypatch.setenv("MAVERICK_CONSEQUENCE", "1")
    reg2 = base_registry(w, sb, goal_id=1)
    assert "remember_outcome_key" in {t.name for t in reg2.all()}


def test_only_the_owning_run_or_an_operator_can_relink_a_key(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick.paths.data_dir", lambda *p, **k: tmp_path.joinpath(*p))
    consequence.reset_shared()
    assert "Linked" in remember_outcome_key(_World([_Ep(55)]), goal_id=7).fn({"key": "invoice:INV-9"})
    # Another run cannot take the key (and its reward).
    taken = remember_outcome_key(_World([_Ep(80)]), goal_id=8).fn({"key": "invoice:INV-9"})
    assert taken.startswith("ERROR:") and "another task" in taken
    assert consequence.shared_correlation().resolve("invoice:INV-9") == (7, 55)
    # The owning run may move it to its later episode; an operator may reassign it.
    assert "Linked" in remember_outcome_key(_World([_Ep(56)]), goal_id=7).fn({"key": "invoice:INV-9"})
    assert consequence.shared_correlation().resolve("invoice:INV-9") == (7, 56)
    assert consequence.link_outcome_key("invoice:INV-9", 8, 80, operator=True) is True
    assert consequence.shared_correlation().resolve("invoice:INV-9") == (8, 80)


def test_a_follow_up_in_the_same_thread_may_relink_the_key(tmp_path, monkeypatch):
    from types import SimpleNamespace

    # Chat turns are children of the thread root (7): turns 8 and 9 are
    # siblings; 20 belongs to someone else under the same root id shape.
    tree = {7: (None, "ana"), 8: (7, "ana"), 9: (7, "ana"), 20: (7, "bo")}

    class _Tree(_World):
        def get_goal(self, goal_id):
            parent, owner = tree[goal_id]
            return SimpleNamespace(id=goal_id, parent_id=parent, owner=owner)

    monkeypatch.setattr("maverick.paths.data_dir", lambda *p, **k: tmp_path.joinpath(*p))
    consequence.reset_shared()
    assert "Linked" in remember_outcome_key(_Tree([_Ep(80)]), goal_id=8).fn({"key": "deal:D-1"})
    assert "Linked" in remember_outcome_key(_Tree([_Ep(90)]), goal_id=9).fn({"key": "deal:D-1"})
    assert "Linked" in remember_outcome_key(_Tree([_Ep(70)]), goal_id=7).fn({"key": "deal:D-1"})
    assert consequence.shared_correlation().resolve("deal:D-1") == (7, 70)
    other = remember_outcome_key(_Tree([_Ep(99)]), goal_id=20).fn({"key": "deal:D-1"})
    assert other.startswith("ERROR:") and "another task" in other
