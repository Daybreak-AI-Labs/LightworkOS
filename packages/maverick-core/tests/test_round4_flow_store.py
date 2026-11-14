"""Recovery and immutable-release regressions for the flow store."""
from __future__ import annotations

import hashlib
import json
import time
from contextlib import contextmanager

import pytest
from maverick.flow import lifecycle, selective_qualification, store
from maverick.flow.ir import Flow, FlowNode

from test_support.action_episode_native import (
    ALLOWED,
    INPUTS,
    TOOL_SCHEMAS,
    _context,
    _schema,
    _start,
)
from test_support.action_episode_native import native as native


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    from maverick import world_model
    from maverick.tenant import kms

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_KMS_KEK", "28" * 32)  # pragma: allowlist secret -- synthetic key
    monkeypatch.setattr(kms, "_dek_cache", {})
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")


def _flow(identity="flow", *, owner="", retries=0, schedule=""):
    return Flow(id=identity, name=identity, owner=owner, schedule=schedule, start="a",
                nodes={"a": FlowNode(id="a", kind="agent", brief="Do work", retries=retries)})


def _publish(flow):
    saved = store.save_flow(flow)
    return store.publish_flow(saved.id, expected_version=saved.version,
                              expected_revision=saved.revision)


def test_saved_retry_ceiling_does_not_make_release_unloadable(monkeypatch):
    monkeypatch.setenv("MAVERICK_FLOW_MAX_NODE_RETRIES", "3")
    source = _flow()
    source.nodes["a"] = FlowNode(id="a", kind="action", tool="web_search", retries=3)
    release = _publish(source)
    monkeypatch.setenv("MAVERICK_FLOW_MAX_NODE_RETRIES", "1")
    loaded = store.load_flow_snapshot(release["definition_digest"])
    assert loaded.nodes["a"].retries == 1


@pytest.mark.parametrize("damage", ["object", "pointer"])
def test_bad_release_is_reported_without_blocking_or_cancelling_other_crons(monkeypatch, damage):
    from maverick_dashboard import automation_queue as aq

    monkeypatch.setattr(aq, "_queue", None)
    monkeypatch.setattr(aq, "_worker", None)
    monkeypatch.setattr(aq, "_worker_threads", [])
    bad = _publish(_flow("bad", schedule="0 9 * * *"))
    aq._reconcile_flow_crons()
    original = aq._pending(aq.FLOW_CRON_KIND)[0].id
    _publish(_flow("good", schedule="0 10 * * *"))
    if damage == "object":
        (store._objects_dir() / f"{bad['definition_digest']}.json").unlink()
    else:
        store._published_pointer_path("bad").write_text("not JSON", encoding="utf-8")
    with pytest.raises(store.FlowSnapshotError):
        store.list_published_bundles()  # Existing complete-inventory callers still refuse.
    bundles, problems = store.list_published_bundles(with_problems=True)
    assert [flow.id for flow, _release in bundles] == ["good"]
    assert len(problems) == 1
    aq._reconcile_flow_crons()
    jobs = {job.payload["flow_id"]: job.id for job in aq._pending(aq.FLOW_CRON_KIND)}
    assert jobs["bad"] == original and "good" in jobs


def _lose_payload(run):
    store.save_run(run)
    raw = store._read_json(store._runs_dir() / f"{run.run_id}.json")
    root = store._runs_dir().parent / "run_payloads"
    path = root / hashlib.sha256(run.run_id.encode()).hexdigest() / (raw["data_state"]["sha256"] + ".bin")
    path.unlink()


def test_missing_old_artifact_does_not_prevent_saving_replacement():
    run = store.FlowRun(run_id="replacement", flow_id="flow", status="running", data={"text": "plain text " * 6000})
    _lose_payload(run)
    run.status, run.data = "failed", {}
    store.save_run(run)
    assert store.load_run(run.run_id).status == "failed"
    assert store.load_run(run.run_id).data == {}


@pytest.mark.parametrize("crash", [False, True])
def test_lifecycle_quarantines_missing_payload_without_replaying_or_hiding_crash(crash):
    run = store.FlowRun(run_id="lost", flow_id="flow", status="running", data={"text": "plain text " * 6000})
    if crash:
        store.save_run(run)
    else:
        _lose_payload(run)
    calls = []

    def perform(flow, **kwargs):
        calls.append(flow.id)
        _lose_payload(run)
        raise RuntimeError("original execution failure")

    wrapped = lifecycle.serialize_runs(perform, safe_failure=str)
    if crash:
        with pytest.raises(RuntimeError, match="original execution failure"):
            wrapped(_flow(), resume_run_id=run.run_id)
    else:
        from maverick.flow.payloads import FlowPayloadError
        with pytest.raises(FlowPayloadError):
            wrapped(_flow(), run_id=run.run_id, owner="another-owner")
        assert store._read_json(store._runs_dir() / f"{run.run_id}.json")["status"] == "running"
        result = wrapped(_flow(), run_id=run.run_id)
        assert result.status == "indeterminate" and calls == []
    recovered = store.load_run(run.run_id)
    assert recovered.status == "indeterminate" and recovered.data == {}


def test_rollback_keeps_owner_validates_and_reads_target_inside_lock(monkeypatch):
    first = store.save_flow(_flow())
    changed = first.copy()
    changed.owner = "bob"
    store.save_flow(changed)
    held = []
    original_lock, original_load = store._definitions_lock, store.load_version

    @contextmanager
    def observed_lock():
        with original_lock():
            held.append(True)
            try:
                yield
            finally:
                held.pop()

    def load_target(*args):
        assert held, "rollback target was read before locking"
        return original_load(*args)

    monkeypatch.setattr(store, "_definitions_lock", observed_lock)
    monkeypatch.setattr(store, "load_version", load_target)
    restored = store.rollback_flow(first.id, version=1)
    assert restored.owner == "bob" and restored.version == 3
    invalid = _flow("invalid")
    invalid.nodes["a"] = FlowNode(id="a", kind="action", tool="unclassified_tool")
    store.save_flow(invalid)
    store.save_flow(_flow("invalid"))
    with pytest.raises(store.FlowVersionConflict, match="invalid|unclassified|approval"):
        store.rollback_flow("invalid", version=1)
    assert store.load_flow("invalid").version == 2


def test_load_definition_rejects_spelling_and_encoded_path_aliases():
    store.save_flow(_flow("abc"))
    assert store.load_flow("  abc  ") is None
    original = store.save_flow(_flow("a/b")).to_dict()
    assert store.load_flow(store._safe_id("a/b")) is None
    with pytest.raises(store.FlowVersionConflict, match="different flow id"):
        store.save_flow(_flow(store._safe_id("a/b")))
    assert store.load_flow("a/b").to_dict() == original


def test_nested_included_workflow_changes_selective_component_identity():
    grandchild = _flow("grandchild")
    nested = Flow(id="nested", name="Nested", start="call", nodes={
        "call": FlowNode(id="call", kind="subflow", flow_ref="grandchild"),
    })
    child = Flow(id="child", name="Child", start="scope", nodes={
        "scope": FlowNode(id="scope", kind="scope", body=nested),
    })
    parent = Flow(id="parent", name="Parent", start="call", nodes={
        "call": FlowNode(id="call", kind="subflow", flow_ref="child", subflow_inputs={"x": "{{x}}"}, output="result"),
    })
    resolve = {"child": child, "grandchild": grandchild}.get
    before = selective_qualification.plan(parent, {"child": "same", "grandchild": "old"}, resolve)
    after = selective_qualification.plan(parent, {"child": "same", "grandchild": "new"}, resolve)
    assert before[0]["source"] != after[0]["source"]


@pytest.mark.parametrize("change", ["deleted", "owner", "revision", "run"])
def test_expired_evidence_is_erased_even_when_source_cannot_be_loaded(native, monkeypatch, change):
    from maverick.flow import action_episode_review as review
    from maverick.flow.approvals import paused_operation_binding
    from maverick_dashboard import automation_queue as aq

    selected = review.ActionEpisodeReviewService(lambda *_args: True)
    source, run = _start()
    expiry = time.time() + 3600
    row = selected.enroll(_context(), source.id, run.run_id,
        expected_pause_binding=paused_operation_binding(store.load_run(run.run_id)),
        allowed_tools=ALLOWED, input_schema=_schema(INPUTS), tool_data_schemas=TOOL_SCHEMAS, retain_until=expiry)
    if change == "deleted":
        store.delete_flow(source.id)
    elif change == "run":
        store.delete_run(run.run_id)
    else:
        path = store._flows_dir() / f"{source.id}.json"
        raw = json.loads(path.read_text())
        raw[change] = "replacement"
        path.write_text(json.dumps(raw))
    monkeypatch.setattr(aq, "_reconcile_flow_crons", lambda: None)
    monkeypatch.setattr(aq, "_run_for_active_tenants", lambda _label, fn: fn() or True)
    aq._handle_flow_sweep()
    assert "sensitive_envelope" in selected.records.get(row["id"])
    monkeypatch.setattr(review.time, "time", lambda: expiry + 1)
    aq._handle_flow_sweep()
    expired = selected.records.get(row["id"])
    assert expired["status"] == "expired" and "sensitive_envelope" not in expired


def test_publication_refuses_structurally_invalid_child_drafts():
    child = _flow("child")
    child.nodes["a"] = FlowNode(id="a", kind="action", tool="unclassified_tool")
    store.save_flow(child)
    parent = store.save_flow(Flow(id="parent", name="Parent", start="call", nodes={
        "call": FlowNode(id="call", kind="subflow", flow_ref="child"),
    }))
    with pytest.raises(store.FlowSnapshotError, match="subflow.*cannot be published"):
        store.publish_flow(parent.id, expected_version=parent.version, expected_revision=parent.revision)
    assert store.load_published_bundle(parent.id) is None


@pytest.mark.parametrize("operation", ["delete", "unpublish"])
def test_missing_draft_can_be_revoked_without_bypassing_pointer_cas(operation):
    flow = _flow()
    release = _publish(flow)
    (store._flows_dir() / f"{flow.id}.json").unlink()
    operation = store.delete_flow if operation == "delete" else store.unpublish_flow
    with pytest.raises(store.FlowVersionConflict):
        operation(flow.id, expected_version=flow.version, expected_revision="wrong",
                  expected_release_id=release["release_id"])
    assert store.load_published_bundle(flow.id) is not None
    assert operation(flow.id, expected_version=flow.version, expected_revision=flow.revision,
                     expected_release_id=release["release_id"])
    assert store.load_published_bundle(flow.id) is None
