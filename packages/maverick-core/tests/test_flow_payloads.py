"""Complete business data must survive recovery without expanding public previews."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from maverick.flow import execution, payloads, store
from maverick.flow.ir import Flow, FlowNode


@pytest.fixture(autouse=True)
def isolated_keys(tmp_path, monkeypatch):
    from maverick.tenant import kms

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_KMS_KEK", "19" * 32)  # pragma: allowlist secret -- synthetic key
    monkeypatch.setattr(kms, "_dek_cache", {})


def large_data():
    return {"document": "The customer ordered ten blue pens. " * 260 + "END_OF_DOCUMENT",
            "rows": list(range(600)), "fields": {str(i): i for i in range(600)}}


def row(run_id="checkpoint"):
    return store.FlowRun(run_id=run_id, flow_id="example", status="paused_delay",
                         owner="user:alice", data=large_data(), input_data=large_data())


def raw_row(run_id="checkpoint"):
    return json.loads((store._runs_dir() / f"{run_id}.json").read_text("utf-8"))


def artifact(run_id="checkpoint"):
    ref = raw_row(run_id)["data_state"]
    directory = hashlib.sha256(run_id.encode()).hexdigest()
    return store._runs_dir().parent / "run_payloads" / directory / (ref["sha256"] + ".bin")


def test_complete_checkpoint_private_artifact_and_bounded_api():
    from maverick_dashboard.api import _run_out

    run = row()
    store.save_run(run)
    saved = raw_row()
    assert saved["data_state"]["kind"] == "artifact"
    assert "END_OF_DOCUMENT" not in json.dumps(saved["data"])
    assert b"The customer ordered" not in artifact().read_bytes()
    loaded = store.load_run(run.run_id)
    assert run.data == loaded.data == large_data()
    assert loaded.input_data == large_data()
    assert store.list_runs()[0].data == large_data()
    output = _run_out(loaded)
    assert len(output["data"]["rows"]) == 501
    assert len(json.dumps(output["data"]).encode()) < payloads.PREVIEW_BYTES
    assert "data_state" not in output


@pytest.mark.skipif(os.name != "nt", reason="Windows extended-length paths")
def test_long_windows_home_reloads_and_reclaims_encrypted_checkpoint(tmp_path, monkeypatch):
    from maverick.file_lock import _windows_extended_path

    # Keep the run row and lock short enough to isolate the deeper encrypted
    # artifact path, including the per-run SHA-256 directory.
    padding = max(1, 180 - len(os.path.abspath(tmp_path)) - 1)
    home = tmp_path / ("h" * padding)
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    run = row("long-checkpoint")
    store.save_run(run)

    def artifact_path():
        record = store._read_json(store._runs_dir() / f"{run.run_id}.json")
        assert record["data_state"]["kind"] == "artifact"
        digest = record["data_state"]["sha256"]
        run_dir = hashlib.sha256(run.run_id.encode()).hexdigest()
        return Path(_windows_extended_path(
            store._runs_dir().parent / "run_payloads" / run_dir / f"{digest}.bin"
        ))

    first = artifact_path()
    assert first.is_file()
    assert store.load_run(run.run_id).data == large_data()

    run.data["document"] += " updated"
    store.save_run(run)
    second = artifact_path()
    assert second != first and second.is_file()
    assert not first.exists()
    assert [item.name for item in second.parent.glob("*.bin")] == [second.name]
    assert store.load_run(run.run_id).data == run.data

    assert store.delete_run(run.run_id)
    assert not second.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows extended-length paths")
def test_maximum_tenant_segment_checkpoint_survives_index_rebuild_and_delete():
    from maverick.paths import MAX_TENANT_SEGMENT_LENGTH, data_dir, tenant_scope

    with tenant_scope(tenant="t" * MAX_TENANT_SEGMENT_LENGTH):
        run = row("tenant-limit")
        plain_lock = data_dir("flows", "runs") / f".{run.run_id}.checkpoint.lock"
        assert len(os.path.abspath(plain_lock)) > 260
        assert str(store._runs_dir()).startswith("\\\\?\\")

        store.save_run(run)
        assert "\\\\?\\" not in json.dumps(raw_row(run.run_id))
        first = artifact(run.run_id)
        assert first.is_file()
        assert store.load_run(run.run_id).data == large_data()
        assert [item.run_id for item in store.list_run_metadata()] == [run.run_id]
        assert store.list_runs()[0].data == large_data()

        store.rebuild_run_index()
        assert store.list_runs()[0].data == large_data()
        run.data["document"] += " updated"
        store.save_run(run)
        second = artifact(run.run_id)
        assert second != first and second.is_file()
        assert not first.exists()
        assert store.load_run(run.run_id).data == run.data

        assert store.delete_run(run.run_id)
        assert not second.exists()
        store.rebuild_run_index()
        assert store.list_run_metadata() == []


def test_delay_restart_resume_matches_uninterrupted_business_values():
    flow = Flow(id="resume-complete", name="Complete", start="produce", nodes={
        "produce": FlowNode(id="produce", kind="agent", brief="produce", output="batch", next="wait"),
        "wait": FlowNode(id="wait", kind="delay", seconds=1, next="consume"),
        "consume": FlowNode(id="consume", kind="agent", brief="consume", output="result"),
    })
    expected = large_data()
    paused = execution.execute(flow, agent_runner=lambda *_a: (expected, None),
                               action_runner=lambda *_a: (None, None),
                               record_outcomes=False, now=lambda: 1000., data={"input": expected})
    assert paused.status == "paused_delay"
    code = """
import json, sys
from maverick.flow import execution, store
run = store.load_run(sys.argv[1])
flow = store.load_flow_snapshot(run.definition_digest)
result = execution.execute(flow, agent_runner=lambda brief, data: (data['batch'], None),
    action_runner=lambda *a: (None, None), resume_run_id=run.run_id,
    record_outcomes=False, now=lambda: 1002.)
print(json.dumps({'status':result.status,'data':result.data['result'], 'input':result.input_data}))
"""
    proc = subprocess.run([sys.executable, "-c", code, paused.run_id],
                          capture_output=True, text=True, timeout=30, check=True,
                          env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)})
    resumed = json.loads(proc.stdout)
    assert resumed["status"] == "completed"
    assert resumed["data"] == expected
    assert resumed["input"] == {"input": expected}


def test_secret_redaction_covers_tail_and_structured_values_before_encryption():
    from maverick.paths import current_tenant_id_strict
    from maverick.tenant.kms import unseal_for_tenant

    secret = "sk-" + "a" * 40  # pragma: allowlist secret -- synthetic credential
    run = row()
    run.data["document"] += " " + secret
    run.data["nested"] = {"password": "synthetic-private-value"}  # pragma: allowlist secret - synthetic redaction fixture
    store.save_run(run)
    clear = unseal_for_tenant(current_tenant_id_strict(), artifact().read_bytes()).decode()
    assert secret not in clear
    assert "synthetic-private-value" not in clear
    assert "END_OF_DOCUMENT" in clear
    assert store.load_run(run.run_id).data["nested"]["password"] == "***redacted***"


@pytest.mark.parametrize("damage", ["missing", "bytes", "owner", "flow", "reference", "tenant"])
def test_unavailable_or_mismatched_artifact_never_falls_back_to_preview(damage, monkeypatch):
    run = row()
    store.save_run(run)
    path = artifact()
    saved = raw_row()
    if damage == "missing":
        path.unlink()
    elif damage == "bytes":
        original = path.read_bytes()
        damaged = original[:-1] + bytes([original[-1] ^ 1])
        assert damaged != original
        path.write_bytes(damaged)
    elif damage == "owner":
        saved["owner"] = "user:other"
    elif damage == "flow":
        saved["flow_id"] = "other"
    elif damage == "reference":
        saved["data_state"]["sha256"] = "../elsewhere"
    elif damage == "tenant":
        # Same bytes/path copied into another scope still cannot be opened.
        original_blob = path.read_bytes()
        monkeypatch.setattr("maverick.paths.current_tenant_id_strict", lambda: "other-tenant")
        from maverick.file_lock import atomic_write_bytes

        copied = store._runs_dir().parent / "run_payloads" / path.parent.name / path.name
        atomic_write_bytes(copied, original_blob)
    store._write_json(store._runs_dir() / (run.run_id + ".json"), saved)
    with pytest.raises(payloads.FlowPayloadError):
        store.load_run(run.run_id)


def test_failed_publication_preserves_previous_complete_generation(monkeypatch):
    run = row()
    store.save_run(run)
    before = artifact()
    old_write = store._write_json
    monkeypatch.setattr(store, "_write_json", lambda *_a: (_ for _ in ()).throw(OSError("disk full")))
    run.data["document"] += "new value"
    with pytest.raises(OSError, match="disk full"):
        store.save_run(run)
    assert store.load_run(run.run_id).data == large_data()
    assert before.exists()
    monkeypatch.setattr(store, "_write_json", old_write)
    store.save_run(run)
    assert not before.exists()
    assert len(list(artifact().parent.glob("*.bin"))) == 1
    assert store.load_run(run.run_id).data == run.data


def test_metadata_only_save_reuses_artifact_and_delete_reclaims():
    run = row()
    store.save_run(run)
    before = artifact()
    run.status = "resuming"
    store.save_run(run)
    assert artifact() == before
    assert store.delete_run(run.run_id)
    assert not before.exists()


def test_redaction_failure_and_quotas_do_not_commit_partial_data(monkeypatch):
    run = row()
    store.save_run(run)
    before = raw_row()
    with monkeypatch.context() as patch:
        patch.setattr("maverick.safety.secret_detector.redact",
                      lambda *_a: (_ for _ in ()).throw(RuntimeError("redactor unavailable")))
        with pytest.raises(payloads.FlowPayloadError, match="safely prepared"):
            store.save_run(run)
    assert raw_row() == before
    with monkeypatch.context() as patch:
        patch.setattr(payloads, "MAX_BYTES", 100)
        with pytest.raises(payloads.FlowPayloadError, match="quota"):
            store.save_run(run)
    assert raw_row() == before


def test_legacy_complete_data_upgrades_but_loss_markers_require_recovery():
    run = store.FlowRun(run_id="legacy", flow_id="old", status="paused_delay", data={"a": 1})
    target = store._runs_dir() / "legacy.json"
    store._write_json(target, run.to_dict())
    loaded = store.load_run("legacy")
    assert loaded.data == {"a": 1}
    store.save_run(loaded)
    assert raw_row("legacy")["data_state"]["kind"] == "inline"
    legacy = run.to_dict()
    legacy["data"] = {"lost": "old text…[truncated]"}
    store._write_json(target, legacy)
    with pytest.raises(payloads.FlowPayloadError, match="legacy.*incomplete"):
        store.load_run("legacy")


def test_approval_card_binds_tail_beyond_preview_without_exposing_it():
    from maverick.approval_cards import digest
    from maverick_dashboard.automation_queue import current_flow_approval_card

    flow = Flow(id="full-review", name="Review", start="gate", nodes={
        "gate": FlowNode(id="gate", kind="approval", prompt="Review this batch", next="done"),
        "done": FlowNode(id="done", kind="agent", brief="consume"),
    })
    expected = large_data()
    paused = execution.execute(flow, data=expected, agent_runner=lambda *_a: (None, None),
                               action_runner=lambda *_a: (None, None), record_outcomes=False)
    loaded = store.load_run(paused.run_id)
    card = current_flow_approval_card(loaded)
    assert card["inputs"]["run_data_format"] == payloads.SCHEMA
    assert card["inputs"]["run_data_sha256"] == digest(expected)
    assert "END_OF_DOCUMENT" not in json.dumps(card)
    loaded.data["document"] += "tampered tail"
    with pytest.raises(store.FlowSnapshotError, match="stale or invalid"):
        current_flow_approval_card(loaded)


def test_complete_values_survive_authenticated_approval_resume():
    from maverick.flow.approvals import flow_decision_attestation_material, paused_operation_binding
    from maverick_dashboard.approval_authority import issue_flow_decision_attestation

    expected = large_data()
    flow = Flow(id="approval-complete", name="Review", start="gate", nodes={
        "gate": FlowNode(id="gate", kind="approval", prompt="Review this batch", next="consume"),
        "consume": FlowNode(id="consume", kind="agent", brief="consume", output="result"),
    })
    paused = execution.execute(flow, data={"batch": expected},
                               agent_runner=lambda *_a: (None, None),
                               action_runner=lambda *_a: (None, None), record_outcomes=False)
    loaded = store.load_run(paused.run_id)
    binding = paused_operation_binding(loaded)
    material = flow_decision_attestation_material(
        loaded, inputs=None, operation_binding_sha256=binding,
        authority_binding_sha256="", decision="approved", decided_by="system:direct")
    attestation = issue_flow_decision_attestation(
        None, material=material, expires_at=loaded.human["approval_card"]["expires_at"])
    result = execution.execute(
        flow, agent_runner=lambda _brief, data: (data["batch"], None),
        action_runner=lambda *_a: (None, None), resume_run_id=loaded.run_id,
        decision="approved", decided_by="system:direct", approval_binding_sha256=binding,
        approval_decision_attestation=attestation, record_outcomes=False)
    assert result.status == "completed"
    assert result.data["result"] == expected
    assert result.input_data == {"batch": expected}


def test_checkpoint_read_excludes_reclaim_until_its_generation_is_loaded(monkeypatch):
    import concurrent.futures
    import threading

    run = row()
    store.save_run(run)
    reached = threading.Event()
    release = threading.Event()
    original_read = payloads._read_artifact

    def hold_read(path):
        reached.set()
        assert release.wait(5)
        return original_read(path)

    monkeypatch.setattr(payloads, "_read_artifact", hold_read)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        reader = pool.submit(store.load_run, run.run_id)
        assert reached.wait(5)
        run.data["document"] += "updated"
        writer = pool.submit(store.save_run, run)
        release.set()
        assert reader.result(timeout=5).data == large_data()
        writer.result(timeout=5)
    assert store.load_run(run.run_id).data == run.data


def test_corrupt_row_never_reclaims_its_artifact_or_overwrites_it():
    run = row()
    store.save_run(run)
    retained = artifact()
    target = store._runs_dir() / (run.run_id + ".json")
    target.write_text("{broken", encoding="utf-8")
    with pytest.raises(payloads.FlowPayloadError, match="unreadable"):
        store.load_run(run.run_id)
    with pytest.raises(payloads.FlowPayloadError, match="unreadable"):
        store.save_run(run)
    assert retained.exists()


def test_deep_complete_json_and_tuple_normalization_survive_storage():
    nested = {"value": (1, 2, 3)}
    for _ in range(20):
        nested = {"child": nested}
    run = store.FlowRun(run_id="deep", flow_id="f", status="paused_delay", data=nested)
    store.save_run(run)
    expected = json.loads(json.dumps(nested))
    assert run.data == store.load_run(run.run_id).data == expected
    assert raw_row(run.run_id)["data_state"]["kind"] == "artifact"
    assert "…" in json.dumps(run.to_dict()["data"], ensure_ascii=False)
