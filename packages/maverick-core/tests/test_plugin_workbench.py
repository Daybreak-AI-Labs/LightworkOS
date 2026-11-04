"""Authored qualification regressions; never require real plugin/provider/Docker calls."""
from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest
from maverick import plugin_workbench as workbench

_REAL_SNAPSHOT = workbench.snapshot


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(workbench, "data_dir", lambda: tmp_path)
    from maverick import plugin_execution_pins
    monkeypatch.setattr(plugin_execution_pins, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(workbench, "config", lambda: {"workbench": True, "workbench_image": "sha256:" + "a" * 64})
    row = {"eligible": True, "name": "example", "distribution": "example-dist", "version": "1",
           "entry": "example:tool", "content_sha256": "b" * 64, "fingerprint": "c" * 64,
           "permission_denial_checked": True}
    monkeypatch.setattr(workbench, "snapshot", lambda: [row])
    return row


def test_duplicate_operation_cannot_replay_a_container(monkeypatch, isolated):
    from maverick.sandbox.research import ResearchContainerRunner
    calls = []
    def fake_run(self, files, **kwargs):
        payload = json.loads(files["sample.json"])
        calls.append(payload)
        with kwargs["effect_guard"]():
            pass
        return SimpleNamespace(reason="completed", exit_code=0, cleanup_verified=True,
            image_id="sha256:" + "a" * 64, policy_sha256="d" * 64,
            stdout=json.dumps({"operation": payload["operation"], "phase": "dispatch"}) + "\n" + json.dumps({"operation": payload["operation"], "phase": "result",
                "schema_valid": True, "sample_valid": True, "completed": True,
                "content_sha256": payload["content_sha256"], "result_sha256": hashlib.sha256(b"null").hexdigest()}))
    monkeypatch.setattr(ResearchContainerRunner, "run", fake_run)
    args = ("f" * 64, "1" * 32, isolated["fingerprint"], {"value": "synthetic"}, "sample")
    receipt = workbench.run_check(*args, authorize=lambda: None)
    assert receipt["state"] == "passed_scoped_check"
    with pytest.raises(ValueError, match="already recorded"):
        workbench.run_check(*args, authorize=lambda: None)
    assert len(calls) == 1
    ledger = workbench._read(workbench._path("f" * 64))
    assert "synthetic" not in json.dumps(ledger)
    assert ledger["checks"]["1" * 32]["replay"] == "never"


def test_timeout_before_plugin_dispatch_does_not_qualify(monkeypatch, isolated):
    from maverick.sandbox.research import ResearchContainerRunner
    monkeypatch.setattr(ResearchContainerRunner, "run", lambda *a, **k: SimpleNamespace(
        reason="timeout", exit_code=-9, cleanup_verified=True, image_id="a", policy_sha256="b", stdout=""))
    receipt = workbench.run_check("f" * 64, "2" * 32, isolated["fingerprint"], {}, "timeout", authorize=lambda: None)
    assert receipt["state"] == "not_qualified"
    assert receipt["plugin_dispatch_observed"] is False
    assert receipt["external_outcome"] == "unknown; no replay"


def test_malformed_schema_cannot_publish_ready(monkeypatch, isolated):
    from maverick.sandbox.research import ResearchContainerRunner
    monkeypatch.setattr(ResearchContainerRunner, "run", lambda *a, **k: SimpleNamespace(
        reason="completed", exit_code=1, cleanup_verified=True, image_id="a", policy_sha256="b", stdout=""))
    receipt = workbench.run_check("f" * 64, "3" * 32, isolated["fingerprint"], {}, "sample", authorize=lambda: None)
    assert receipt["state"] == "not_qualified"
    with pytest.raises(ValueError, match="sample, timeout and cancellation"):
        workbench.publish("f" * 64, isolated["fingerprint"], "Restore reviewed previous plugin and inspect affected work.", authorize=lambda: None)


def test_upgrade_invalidates_prior_qualification(monkeypatch, isolated):
    workbench._edit("f" * 64, lambda state: state["checks"].update({"1" * 32: {
        "id": "1" * 32, "fingerprint": isolated["fingerprint"], "state": "passed_scoped_check"}}))
    monkeypatch.setattr(workbench, "snapshot", lambda: [{**isolated, "fingerprint": "0" * 64}])
    assert workbench.history("f" * 64)["checks"][0]["current"] is False
    with pytest.raises(ValueError, match="changed"):
        workbench.selected(isolated["fingerprint"])


def test_task_pin_survives_registry_rebuild(monkeypatch, isolated):
    from maverick import connections, plugin_lock, plugins
    from maverick.audit import writer
    monkeypatch.setattr(plugins, "_entry_points", lambda _: [SimpleNamespace(name="example")])
    monkeypatch.setattr(plugins, "_ep_dist_name", lambda _: "example-dist")
    monkeypatch.setattr(plugins, "_gate", lambda *args: True)
    monkeypatch.setattr(plugins, "_allowed_plugin_names", lambda: None)
    monkeypatch.setattr(plugins, "_permission_policy", lambda: (set(), True))
    called = []
    fingerprint = ["a" * 64]
    monkeypatch.setattr(plugin_lock, "_dist_content_hash", lambda _: fingerprint[0])
    monkeypatch.setattr(connections, "current_principal", lambda: "employee:alice")
    def factory():
        return SimpleNamespace(fn=lambda args: called.append(args) or "done")
    token = writer.set_goal_context(42)
    try:
        first = workbench.pinned_factory("example", "example-dist", factory)()
        assert first.fn({"original": True}) == "done"
        fingerprint[0] = "b" * 64
        replacement = workbench.pinned_factory("example", "example-dist", factory)
        with pytest.raises(PermissionError, match="earlier plugin version"):
            replacement()
        assert called == [{"original": True}]
    finally:
        writer.reset_goal_context(token)


def test_snapshot_never_imports_denied_entry_point(monkeypatch, isolated):
    from maverick import plugin_lock, plugins
    ep = SimpleNamespace(name="denied", value="denied:tool", dist=SimpleNamespace(version="1"))
    ep.load = lambda: pytest.fail("metadata qualification must not import a plugin")
    monkeypatch.setattr(plugins, "_PLUGIN_GROUPS", ("maverick.tools",))
    monkeypatch.setattr(plugins, "_entry_points", lambda _: [ep])
    monkeypatch.setattr(plugins, "_find_manifest", lambda _: None)
    monkeypatch.setattr(plugins, "_ep_dist_name", lambda _: "denied-dist")
    monkeypatch.setattr(plugins, "_allowed_plugin_names", lambda: set())
    monkeypatch.setattr(plugins, "_permission_policy", lambda: (set(), True))
    monkeypatch.setattr(plugin_lock, "_dist_content_hash", lambda _, **kwargs: "a" * 64)
    rows = _REAL_SNAPSHOT()
    assert rows[0]["eligible"] is False
    assert rows[0]["permission_denial_checked"] is True


@pytest.mark.parametrize("mode", ["timeout", "cancellation"])
def test_fast_completion_is_reported_without_fabricated_interruption(monkeypatch, isolated, mode):
    from maverick.sandbox.research import ResearchContainerRunner
    def complete(self, files, **kwargs):
        payload = json.loads(files["sample.json"])
        frames = [{"operation": payload["operation"], "phase": "dispatch"},
                  {"operation": payload["operation"], "phase": "result", "schema_valid": True,
                   "sample_valid": True, "completed": True, "content_sha256": payload["content_sha256"],
                   "result_sha256": hashlib.sha256(b"null").hexdigest()}]
        return SimpleNamespace(reason="completed", exit_code=0, cleanup_verified=True,
            image_id="sha256:" + "a" * 64, policy_sha256="d" * 64, stdout="\n".join(json.dumps(row) for row in frames))
    monkeypatch.setattr(ResearchContainerRunner, "run", complete)
    result = workbench.run_check("f" * 64, "4" * 32, isolated["fingerprint"], {}, mode, authorize=lambda: None)
    assert result["state"] == "passed_scoped_check"
    assert result["completion_observed"] is True
    assert result["interruption_observed"] is False
    assert result["check_observation"] == "exact result completed before interruption"


def test_publication_retains_observed_scope_and_is_idempotent(isolated):
    context = "f" * 64
    def seed(state):
        for index, mode in enumerate(("sample", "timeout", "cancellation")):
            state["checks"][str(index)] = {"id": str(index), "fingerprint": isolated["fingerprint"],
                "state": "passed_scoped_check", "cleanup_verified": True, "permission_denial_checked": True,
                "mode": mode, "completion_observed": True, "interruption_observed": False}
    workbench._edit(context, seed)
    first = workbench.publish(context, isolated["fingerprint"], "Restore the prior reviewed package; inspect stopped work.", authorize=lambda: None, operation="5" * 32)
    second = workbench.publish(context, isolated["fingerprint"], "Restore the prior reviewed package; inspect stopped work.", authorize=lambda: None, operation="5" * 32)
    assert first == second
    assert len(workbench.history(context)["publications"]) == 1
    assert all(not row["interruption_observed"] for row in first["observations"])


def test_crash_after_dispatch_stays_unknown_and_cannot_be_replayed(monkeypatch, isolated):
    from maverick.sandbox.research import ResearchContainerRunner
    calls = []
    def interrupted(self, files, **kwargs):
        payload = json.loads(files["sample.json"])
        calls.append(payload["operation"])
        return SimpleNamespace(reason="completed", exit_code=1, cleanup_verified=True,
            image_id="sha256:" + "a" * 64, policy_sha256="d" * 64,
            stdout=json.dumps({"operation": payload["operation"], "phase": "dispatch"}))
    monkeypatch.setattr(ResearchContainerRunner, "run", interrupted)
    args = ("f" * 64, "6" * 32, isolated["fingerprint"], {}, "sample")
    result = workbench.run_check(*args, authorize=lambda: None)
    assert result["state"] == "not_qualified" and result["invocation_outcome"] == "unknown"
    assert result["external_outcome"] == "unknown; no replay"
    with pytest.raises(ValueError, match="already recorded"):
        workbench.run_check(*args, authorize=lambda: None)
    assert calls == ["6" * 32]
