"""Flow definition versioning: every save snapshots the prior version, and a
rollback restores an earlier one non-destructively (the rollback is itself a new
version, so nothing is ever lost)."""
from __future__ import annotations

import json
import os

import pytest
from maverick.flow import Flow, FlowNode, store


def _dd(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick.paths.data_dir", lambda *p, **k: tmp_path.joinpath(*p))


def _flow(brief="do a"):
    return Flow(id="f", name="F", start="a",
                nodes={"a": FlowNode(id="a", kind="agent", brief=brief)})


def test_disconnected_steps_are_draftable_but_cannot_be_published(tmp_path, monkeypatch):
    _dd(tmp_path, monkeypatch)
    flow = _flow()
    flow.nodes["approval"] = FlowNode(
        id="approval", kind="approval", prompt="Approve payment", label="Approve payment",
    )
    saved = store.save_flow(flow)
    assert saved.unreachable_node_ids() == ["approval"]
    with pytest.raises(store.FlowSnapshotError, match="Approve payment.*can never run"):
        store.publish_flow(saved.id, expected_version=saved.version,
                           expected_revision=saved.revision)
    saved.nodes["a"].next = "approval"
    connected = store.save_flow(saved, expected_version=saved.version,
                                expected_revision=saved.revision)
    release = store.publish_flow(connected.id, expected_version=connected.version,
                                 expected_revision=connected.revision)
    assert release["definition_version"] == connected.version


def test_disconnected_nested_step_blocks_publication(tmp_path, monkeypatch):
    _dd(tmp_path, monkeypatch)
    body = _flow()
    body.nodes["unused"] = FlowNode(id="unused", kind="agent", brief="Never reached")
    flow = Flow(id="nested", name="Nested", start="loop", nodes={
        "loop": FlowNode(id="loop", kind="foreach", items="rows", body=body),
    })
    saved = store.save_flow(flow)
    with pytest.raises(store.FlowSnapshotError, match="unused.*can never run"):
        store.publish_flow(saved.id, expected_version=saved.version,
                           expected_revision=saved.revision)


def test_referenced_child_draft_must_be_connected_before_parent_publication(tmp_path, monkeypatch):
    _dd(tmp_path, monkeypatch)
    child = Flow(id="child", name="Child", start="a", nodes={
        "a": FlowNode(id="a", kind="agent", brief="First"),
        "unused": FlowNode(id="unused", kind="agent", brief="Never reached"),
    })
    saved_child = store.save_flow(child)
    parent = store.save_flow(Flow(id="parent", name="Parent", start="call", nodes={
        "call": FlowNode(id="call", kind="subflow", flow_ref="child"),
    }))
    # Saving and ordinary snapshots remain possible while the child is a draft.
    assert store.snapshot_current_flow_bundle(parent.id)[2]["child"] is not None
    with pytest.raises(store.FlowSnapshotError, match="subflow 'child'.*unused.*can never run"):
        store.publish_flow(parent.id, expected_version=parent.version,
                           expected_revision=parent.revision)

    saved_child.nodes["a"].next = "unused"
    store.save_flow(saved_child, expected_version=saved_child.version,
                    expected_revision=saved_child.revision)
    release = store.publish_flow(parent.id, expected_version=parent.version,
                                 expected_revision=parent.revision)
    assert release["subflow_digests"]["child"]


def test_branch_default_edge_does_not_make_an_unusable_step_reachable():
    flow = Flow(id="branch", name="Branch", start="choose", nodes={
        "choose": FlowNode(id="choose", kind="branch", condition="amount > 100",
                           if_true="yes", if_false="no", next="unused"),
        "yes": FlowNode(id="yes", kind="agent", brief="yes"),
        "no": FlowNode(id="no", kind="agent", brief="no"),
        "unused": FlowNode(id="unused", kind="agent", brief="never"),
    })
    assert flow.unreachable_node_ids() == ["unused"]


@pytest.mark.skipif(os.name != "nt", reason="Windows extended-length paths")
def test_maximum_tenant_segment_definition_publication_and_idempotency(tmp_path, monkeypatch):
    from maverick.paths import MAX_TENANT_SEGMENT_LENGTH, data_dir, tenant_scope

    home = tmp_path / ("h" * max(1, 90 - len(os.path.abspath(tmp_path)) - 1))
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    with tenant_scope(tenant="t" * MAX_TENANT_SEGMENT_LENGTH):
        assert len(os.path.abspath(data_dir("flows") / ".definitions.lock")) > 260
        saved = store.save_flow(_flow("first"))
        assert store.load_flow(saved.id).nodes["a"].brief == "first"
        assert [item.id for item in store.list_flows()] == [saved.id]
        assert [item["id"] for item in store.list_flow_summaries()] == [saved.id]

        current = store.save_flow(_flow("second"), expected_version=1,
                                  expected_revision=saved.revision)
        assert [item.version for item in store.list_versions(current.id)] == [1, 2]
        assert store.load_version(current.id, 1).nodes["a"].brief == "first"
        release = store.publish_flow(current.id, expected_version=current.version,
                                     expected_revision=current.revision)
        assert store.load_published_bundle(current.id)[1]["release_id"] == release["release_id"]
        assert [item[0].id for item in store.list_published_bundles()] == [current.id]

        with store.idempotency_lock(current.id, "request"):
            assert store.save_idempotency_claim(current.id, "request", "first-run", overwrite=False)
            assert not store.save_idempotency_claim(current.id, "request", "second-run", overwrite=False)
        claim = store._read_json(store._idempotency_claim_path(current.id, "request"))
        assert claim["run_id"] == "first-run"
        assert "\\\\?\\" not in json.dumps({"flow": current.to_dict(),
                                                "release": release, "claim": claim})

        store._write_json(store._schema_dir() / f"{current.id}.json", {"field": "string"})
        snapshot = store._objects_dir() / f"{release['definition_digest']}.json"
        store._write_json(snapshot, {"id": "tampered"})
        with pytest.raises(store.FlowSnapshotError, match="corrupt"):
            store.publish_flow(current.id, expected_version=current.version,
                               expected_revision=current.revision)

        assert store.delete_flow(current.id)
        assert store.list_flows() == []
        assert store.list_versions(current.id) == []
        assert store.list_published_bundles() == []
        assert store.load_flow_schema(current.id) == {}


def test_first_save_is_version_1(tmp_path, monkeypatch):
    _dd(tmp_path, monkeypatch)
    saved = store.save_flow(_flow())
    assert saved.version == 1
    assert store.load_flow("f").version == 1
    assert [v.version for v in store.list_versions("f")] == [1]


def test_each_save_bumps_and_snapshots_the_prior(tmp_path, monkeypatch):
    _dd(tmp_path, monkeypatch)
    store.save_flow(_flow("v1 brief"))
    store.save_flow(_flow("v2 brief"))
    store.save_flow(_flow("v3 brief"))
    cur = store.load_flow("f")
    assert cur.version == 3 and cur.nodes["a"].brief == "v3 brief"
    assert [v.version for v in store.list_versions("f")] == [1, 2, 3]
    assert store.load_version("f", 1).nodes["a"].brief == "v1 brief"
    assert store.load_version("f", 2).nodes["a"].brief == "v2 brief"


def test_rollback_restores_prior_as_a_new_version(tmp_path, monkeypatch):
    _dd(tmp_path, monkeypatch)
    store.save_flow(_flow("original"))
    store.save_flow(_flow("regrettable change"))
    restored = store.rollback_flow("f")            # default: the previous version
    assert restored.version == 3 and restored.nodes["a"].brief == "original"
    assert store.load_flow("f").nodes["a"].brief == "original"
    # the rolled-back-from version is still recoverable -- nothing was destroyed
    assert store.load_version("f", 2).nodes["a"].brief == "regrettable change"


def test_rollback_to_a_specific_version(tmp_path, monkeypatch):
    _dd(tmp_path, monkeypatch)
    store.save_flow(_flow("one"))
    store.save_flow(_flow("two"))
    store.save_flow(_flow("three"))
    restored = store.rollback_flow("f", version=1)
    assert restored.version == 4 and restored.nodes["a"].brief == "one"


def test_rollback_unknown_version_returns_none(tmp_path, monkeypatch):
    _dd(tmp_path, monkeypatch)
    store.save_flow(_flow())
    assert store.rollback_flow("f", version=99) is None


def test_delete_clears_history_so_a_reused_id_starts_clean(tmp_path, monkeypatch):
    _dd(tmp_path, monkeypatch)
    store.save_flow(_flow("a"))
    store.save_flow(_flow("b"))
    assert store.delete_flow("f") is True
    assert store.load_flow("f") is None
    assert store.list_versions("f") == []
    store.save_flow(_flow("new"))
    assert store.load_flow("f").version == 1


def test_save_refuses_raw_credentials_without_mutating_current_or_history(
    tmp_path, monkeypatch,
):
    _dd(tmp_path, monkeypatch)
    store.save_flow(_flow("safe"))

    with pytest.raises(ValueError, match="raw credentials"):
        store.save_flow(_flow("API_TOKEN=sk-proj-abcdefghijklmnopqrstuvwx"))  # pragma: allowlist secret

    assert store.load_flow("f").nodes["a"].brief == "safe"
    assert [version.version for version in store.list_versions("f")] == [1]


def test_save_allows_vault_references(tmp_path, monkeypatch):
    _dd(tmp_path, monkeypatch)
    flow = Flow(
        id="f", name="F", start="a",
        nodes={
            "a": FlowNode(
                id="a", kind="action", tool="slack_post",
                params={"authorization": "{{secret('SLACK_TOKEN')}}"},
            )
        },
    )

    saved = store.save_flow(flow)

    assert saved.nodes["a"].params["authorization"] == "{{secret('SLACK_TOKEN')}}"


def test_save_rejects_oversized_definition_before_writing(tmp_path, monkeypatch):
    _dd(tmp_path, monkeypatch)
    flow = _flow("x" * (store._MAX_FLOW_DEFINITION_BYTES + 1))

    with pytest.raises(ValueError, match="storage limit"):
        store.save_flow(flow)

    assert store.load_flow("f") is None
