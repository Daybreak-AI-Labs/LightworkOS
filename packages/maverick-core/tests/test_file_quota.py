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


def test_editor_and_spreadsheet_writes_count_against_the_goal_quota(monkeypatch, tmp_path):
    # Every workspace write tool charges the same per-goal quota as write_file,
    # so switching tools cannot step around the cap.
    from maverick.sandbox import build_sandbox
    from maverick.tools import base_registry

    class DummyWorld:
        def ask(self, question, goal_id=None):
            return 1

        def list_attachments(self, goal_id):
            return []

    file_quota.reset("303")
    monkeypatch.setattr(file_quota, "_limit_bytes", lambda: 100)
    reg = base_registry(DummyWorld(), build_sandbox(workdir=str(tmp_path)), goal_id=303)
    editor, sheet = reg.get("str_replace_editor"), reg.get("spreadsheet")

    assert editor.fn({"command": "create", "path": "a.txt", "file_text": "x" * 40}).startswith("created")
    blocked = editor.fn({"command": "str_replace", "path": "a.txt",
                         "old_str": "x" * 40, "new_str": "y" * 70})
    assert blocked.startswith("ERROR") and "quota exceeded" in blocked
    assert (tmp_path / "a.txt").read_text() == "x" * 40
    blocked = sheet.fn({"op": "write", "path": "b.csv", "rows": [["z" * 70]]})
    assert blocked.startswith("ERROR") and "quota exceeded" in blocked
    assert not (tmp_path / "b.csv").exists()
    file_quota.reset("303")


def test_a_write_that_fails_gives_its_bytes_back(monkeypatch, tmp_path):
    """The quota is charged before the write. A write that then fails wrote
    nothing, so it must not use up the run's allowance."""
    from maverick.sandbox import build_sandbox
    from maverick.tools import str_edit
    from maverick.tools.fs import write_file

    file_quota.reset("default")
    monkeypatch.setattr(file_quota, "_limit_bytes", lambda: 50)
    sandbox = build_sandbox(workdir=str(tmp_path))
    (tmp_path / "folder").mkdir()
    tool = write_file(sandbox)

    failed = tool.fn({"path": "folder", "content": "x" * 40})  # a folder cannot be written
    assert failed.startswith("ERROR") and "quota" not in failed
    assert tool.fn({"path": "a.txt", "content": "y" * 40}).startswith("wrote")

    # The editor charges the same quota, and gives back the same way.
    file_quota.reset("default")

    def _disk_full(*_args, **_kwargs):
        raise OSError("no space left on device")

    monkeypatch.setattr(str_edit, "write_text_contained", _disk_full)
    editor = str_edit.str_replace_editor(sandbox)
    failed = editor.fn({"command": "create", "path": "b.txt", "file_text": "z" * 40})
    assert failed.startswith("ERROR") and "no space" in failed
    assert file_quota.check_and_add(40, goal_id="default")[0] is True

    # A refund never takes the count below zero or touches another run.
    file_quota.reset("default")
    file_quota.refund(10, goal_id="default")
    assert file_quota.check_and_add(50, goal_id="default")[0] is True
    file_quota.reset("default")
