"""Per-goal file-write quota."""
from __future__ import annotations

from maverick import file_quota


def test_disabled_by_default_allows_everything():
    file_quota.reset("g")
    ok, msg = file_quota.check_and_add(10**9, goal_id="g", limit=0)
    assert ok and msg == ""


def test_accumulates_and_blocks_over_cap():
    file_quota.reset("g")
    assert file_quota.check_and_add(600, goal_id="g", limit=1000) == (True, "")
    # 600 + 300 = 900 <= 1000 -> allowed
    assert file_quota.check_and_add(300, goal_id="g", limit=1000)[0] is True
    # 900 + 200 = 1100 > 1000 -> blocked, and NOT added
    ok, msg = file_quota.check_and_add(200, goal_id="g", limit=1000)
    assert ok is False and "quota exceeded" in msg
    # the blocked bytes weren't counted, so a smaller write still fits
    assert file_quota.check_and_add(100, goal_id="g", limit=1000)[0] is True
    file_quota.reset("g")


def test_reset_clears_accounting():
    file_quota.reset("g")
    file_quota.check_and_add(900, goal_id="g", limit=1000)
    file_quota.reset("g")
    assert file_quota.check_and_add(900, goal_id="g", limit=1000)[0] is True
    file_quota.reset("g")


def test_goals_are_independent():
    file_quota.reset("a")
    file_quota.reset("b")
    file_quota.check_and_add(900, goal_id="a", limit=1000)
    # b has its own budget
    assert file_quota.check_and_add(900, goal_id="b", limit=1000)[0] is True
    file_quota.reset("a")
    file_quota.reset("b")


def test_write_file_tool_enforces_when_configured(monkeypatch, tmp_path):
    # Wire-in: with a tiny configured cap, write_file refuses the over-cap write.
    from maverick.sandbox import build_sandbox
    from maverick.tools.fs import write_file

    file_quota.reset("default")
    monkeypatch.setattr(file_quota, "_limit_bytes", lambda: 50)
    tool = write_file(build_sandbox(workdir=str(tmp_path)))
    ok = tool.fn({"path": "a.txt", "content": "x" * 40})
    assert ok.startswith("wrote")
    blocked = tool.fn({"path": "b.txt", "content": "y" * 40})  # 40+40 > 50
    assert blocked.startswith("ERROR") and "quota exceeded" in blocked
    file_quota.reset("default")


def test_base_registry_write_file_quota_is_scoped_by_goal(monkeypatch, tmp_path):
    from maverick.sandbox import build_sandbox
    from maverick.tools import base_registry

    class DummyWorld:
        def ask(self, question, goal_id=None):
            return 1

        def list_attachments(self, goal_id):
            return []

    file_quota.reset("default")
    file_quota.reset("101")
    file_quota.reset("202")
    monkeypatch.setattr(file_quota, "_limit_bytes", lambda: 50)

    sandbox = build_sandbox(workdir=str(tmp_path))
    goal101 = base_registry(DummyWorld(), sandbox, goal_id=101).get("write_file")
    goal202 = base_registry(DummyWorld(), sandbox, goal_id=202).get("write_file")

    assert goal101.fn({"path": "goal101.txt", "content": "x" * 40}).startswith("wrote")
    assert goal202.fn({"path": "goal202.txt", "content": "y" * 20}).startswith("wrote")

    blocked = goal101.fn({"path": "goal101-over.txt", "content": "z" * 20})
    assert blocked.startswith("ERROR") and "quota exceeded" in blocked

    file_quota.reset("default")
    file_quota.reset("101")
    file_quota.reset("202")


def test_write_file_tool_unaffected_when_off(monkeypatch, tmp_path):
    from maverick.sandbox import build_sandbox
    from maverick.tools.fs import write_file

    monkeypatch.setattr(file_quota, "_limit_bytes", lambda: 0)
    tool = write_file(build_sandbox(workdir=str(tmp_path)))
    assert tool.fn({"path": "big.txt", "content": "z" * 100000}).startswith("wrote")
