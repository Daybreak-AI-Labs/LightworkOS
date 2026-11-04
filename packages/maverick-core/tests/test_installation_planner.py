"""Planner is evidence; it cannot bypass protected-state admission."""
import contextlib

import pytest
from maverick import installation_planner as planner


def test_protected_differences_offer_forward_options(tmp_path, monkeypatch):
    core = planner.recovery
    monkeypatch.setattr(core, "_locked", contextlib.nullcontext)
    monkeypatch.setattr(core, "_scope", contextlib.nullcontext)
    monkeypatch.setattr(core, "_directory", lambda identifier: tmp_path)
    monkeypatch.setattr(core, "_runtime", lambda: tmp_path / "runtime")
    monkeypatch.setattr(core, "blockers", list)
    monkeypatch.setattr(core, "_read", lambda path: {"status": "upgraded", "before": {"sha256": "sha"}, "new_runtime_sha256": "sha", "old_version": "1.0.0", "new": {"version": "1.2.3"}})
    monkeypatch.setattr(planner.backup, "_sha256", lambda path: "sha")
    monkeypatch.setattr(planner.backup, "compare_backup", lambda path: {"protected_changes": 1, "items": [{"path": "tenant/world.db", "protected": True, "change": "changed"}], "live_state_sha256": "new"})
    result = planner.plan("a" * 32)
    assert result["rollback_candidate"] is False
    assert result["blockers"][0]["code"] == "protected_state_changed"
    assert result["affected"][0]["path"] == "tenant/world.db"
    assert result["authorization_required"] is True
    assert {action["id"] for action in result["actions"]} == {"repair_current", "workspace_recovery", "save_plan"}


def plan_environment(tmp_path, monkeypatch, *, record=None, blockers=list):
    core = planner.recovery
    monkeypatch.setattr(core, "_locked", contextlib.nullcontext)
    monkeypatch.setattr(core, "_scope", contextlib.nullcontext)
    monkeypatch.setattr(core, "_directory", lambda identifier: tmp_path)
    monkeypatch.setattr(core, "_runtime", lambda: tmp_path / "runtime")
    monkeypatch.setattr(core, "blockers", blockers)
    monkeypatch.setattr(core, "_read", lambda path: record if record is not None else (_ for _ in ()).throw(FileNotFoundError(str(path))))
    return core


def test_an_unknown_recovery_point_is_a_refusal_not_a_raw_file_error(tmp_path, monkeypatch):
    core = plan_environment(tmp_path, monkeypatch)
    with pytest.raises(core.MaintenanceError, match="Select an installation recovery point"):
        planner.plan("a" * 32)


def test_a_coordination_blocker_that_cannot_be_read_becomes_a_reason(tmp_path, monkeypatch):
    def unreadable():
        raise planner.recovery.MaintenanceError("A workspace folder name is not portable.")
    plan_environment(tmp_path, monkeypatch, record={"status": "authorized"}, blockers=unreadable)
    result = planner.plan("a" * 32)
    assert result["rollback_candidate"] is False
    assert result["blockers"][0] == {"code": "coordinated_resources", "message": "A workspace folder name is not portable."}


def test_operating_system_errors_never_put_local_paths_in_a_shared_plan(tmp_path, monkeypatch):
    plan_environment(tmp_path, monkeypatch, record={"status": "upgraded", "before": {"sha256": "sha"}, "new_runtime_sha256": "x"})
    def unreadable(path):
        raise PermissionError(13, "Access is denied", r"C:\Users\Someone\Lightwork\before.tgz")
    monkeypatch.setattr(planner.backup, "_sha256", unreadable)
    result = planner.plan("a" * 32)
    message = next(row["message"] for row in result["blockers"] if row["code"] == "evidence_unavailable")
    assert "Someone" not in message and "before.tgz" not in message


def test_the_snapshot_comparison_does_not_run_while_the_installation_lock_is_held(tmp_path, monkeypatch):
    core = plan_environment(tmp_path, monkeypatch, record={
        "status": "upgraded", "before": {"sha256": "sha"}, "new_runtime_sha256": "sha"})
    held = []
    @contextlib.contextmanager
    def lock():
        held.append(True)
        try:
            yield
        finally:
            held.pop()
    monkeypatch.setattr(core, "_locked", lock)
    monkeypatch.setattr(planner.backup, "_sha256", lambda path: "sha")
    seen = []
    def compare(path):
        seen.append(bool(held))
        return {"protected_changes": 0, "items": [], "live_state_sha256": "live"}
    monkeypatch.setattr(planner.backup, "compare_backup", compare)
    assert planner.plan("a" * 32)["rollback_candidate"] is True
    assert seen == [False]
