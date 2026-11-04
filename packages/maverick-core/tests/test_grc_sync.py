"""Outbound GRC sync: idempotent delivery, round-trip links, honest failure.

The invariants that matter: a re-run with unchanged sources sends nothing; a
changed source becomes an update to the SAME remote record, never a duplicate
create; an unparseable-but-successful create is terminal rather than blindly
retried; and only bounded pointer content ever leaves the platform.
"""
from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError

import pytest
from maverick import config, grc_sync
from maverick.paths import tenant_scope

_CONFIG = """[evidence_graph]
enable = true

[model_risk_assurance]
enable = true
gate_promotions = false

[grc_sync]
enable = true
connector = "servicenow"
findings_path = "/api/now/table/sn_grc_issue"
acceptances_path = "/api/now/table/sn_risk_acknowledgement"
incidents_path = "/api/now/table/incident"
backlink_base = "https://lightwork.example.com"
"""


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    (tmp_path / "config.toml").write_text(_CONFIG, encoding="utf-8")
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _sources(monkeypatch, *, findings=(), incidents=(), accepted_ids=()):
    from maverick import model_risk_assurance as mra

    monkeypatch.setattr(mra, "findings", lambda **_kwargs: list(findings))
    monkeypatch.setattr(mra, "list_incidents", lambda **_kwargs: list(incidents))
    monkeypatch.setattr(
        mra,
        "current_risk_acceptance",
        lambda finding, **_kwargs: (
            {"id": "MRX-1"} if finding.get("id") in accepted_ids else None
        ),
    )


def _finding(identifier="MRF-open", summary="Asset has no accountable owner."):
    return {
        "id": identifier,
        "asset_id": "MAA-" + "a" * 32,
        "severity": "high",
        "summary": summary,
        "finding_sha256": "f" * 64,
        "details": {"internal": "never leaves"},
        "citations": [{"record_id": "MRE-1", "relation": "supports"}],
    }


def _incident():
    return {
        "id": "MRI-one",
        "asset_id": "MAA-" + "b" * 32,
        "severity": "critical",
        "summary": "The triage model misrouted an emergency case.",
        "payload_sha256": "0" * 64,
    }


class _Writer:
    def __init__(self, responses=None):
        self.calls: list[tuple[str, str, dict]] = []
        self.responses = list(responses or [])

    def __call__(self, op, path, body):
        self.calls.append((op, path, dict(body)))
        if self.responses:
            return self.responses.pop(0)
        return json.dumps({"result": {"sys_id": f"sys{len(self.calls):04d}"}})


def _held(monkeypatch):
    _sources(monkeypatch, findings=[_finding()])
    writer = _Writer(["ERROR: post request failed (Timeout)"])
    grc_sync.run_sync(actor="user:admin", writer=writer)
    row = grc_sync.list_outbound()[0]
    payload = writer.calls[0][2]
    calls = []
    remote = {**payload, "sys_id": "sys0001", "sys_updated_on": "2026-09-05 12:00:00"}

    def reader(path, params):
        calls.append((path, params))
        return json.dumps({"result": [dict(remote)]})

    return row, writer, reader, remote, calls


def test_reconciliation_reads_exact_attempt_then_records_human_decision_without_resending(monkeypatch):
    row, writer, reader, remote, calls = _held(monkeypatch)
    inspected = grc_sync.inspect_delivery(row["id"], expected_revision=row["revision"],
                                           actor="user:admin", reader=reader)
    assert inspected["inspection"]["matched"] is True
    assert calls[0][1]["sysparm_query"] == "correlation_id=MRF-open"
    resolved = grc_sync.resolve_delivery(row["id"], expected_revision=inspected["revision"],
        actor="user:admin", note="Compared the original content with the external record.",
        evidence_sha256=inspected["inspection"]["evidence_sha256"], reader=reader)
    assert resolved["status"] == "delivered"
    assert resolved["remote_id"] == remote["sys_id"]
    assert resolved["reconciliation"]["reviewer"] == "user:admin"
    assert len(calls) == 2 and calls[1][0].endswith("/sys0001")
    grc_sync.run_sync(actor="user:admin", writer=writer)
    assert len(writer.calls) == 1


def test_original_attempt_survives_source_change_and_next_sync_patches_same_record(monkeypatch):
    row, writer, reader, remote, _ = _held(monkeypatch)
    changed = _finding(summary="A changed finding after the ambiguous send.")
    changed["finding_sha256"] = "a" * 64
    _sources(monkeypatch, findings=[changed])
    inspected = grc_sync.inspect_delivery(row["id"], expected_revision=row["revision"],
                                           actor="user:admin", reader=reader)
    assert inspected["inspection"]["matched"] is True
    grc_sync.resolve_delivery(row["id"], expected_revision=inspected["revision"],
        actor="user:admin", note="Verified original attempt before updating.",
        evidence_sha256=inspected["inspection"]["evidence_sha256"], reader=reader)
    grc_sync.run_sync(actor="user:admin", writer=writer)
    assert len(writer.calls) == 2
    assert writer.calls[-1][0] == "patch"
    assert writer.calls[-1][1].endswith("/" + remote["sys_id"])


@pytest.mark.parametrize("mode", ["none", "duplicate", "changed", "wrong_id"])
def test_unverified_external_result_cannot_clear_hold(monkeypatch, mode):
    row, writer, _, remote, _ = _held(monkeypatch)
    rows = [remote]
    if mode == "none":
        rows = []
    elif mode == "duplicate":
        rows = [remote, dict(remote)]
    elif mode == "changed":
        remote["short_description"] = "different"
    else:
        remote["sys_id"] = "different_id"
    inspected = grc_sync.inspect_delivery(row["id"], expected_revision=row["revision"],
        actor="user:admin", remote_id="sys0001", reader=lambda *_: json.dumps({"result": rows}))
    assert inspected["inspection"]["matched"] is False
    with pytest.raises(grc_sync.GRCSyncStateError):
        grc_sync.resolve_delivery(row["id"], expected_revision=inspected["revision"],
            actor="user:admin", note="Cannot verify.", evidence_sha256=inspected["inspection"]["evidence_sha256"])
    result = grc_sync.resolve_delivery(row["id"], expected_revision=inspected["revision"],
        actor="user:admin", note="Contacted the record owner; awaiting evidence.")
    assert result["status"] == "dispatch_unconfirmed"
    assert result["reconciliation"]["decision"] == "kept_held"
    assert len(writer.calls) == 1


@pytest.mark.parametrize("change", ["version", "payload", "actor", "expiry", "future", "revision", "target"])
def test_confirmation_rechecks_content_identity_freshness_revision_and_target(monkeypatch, change):
    row, _, reader, remote, _ = _held(monkeypatch)
    inspected = grc_sync.inspect_delivery(row["id"], expected_revision=row["revision"],
        actor="user:admin", reader=reader)
    revision = inspected["revision"]
    actor = "user:admin"
    if change == "version":
        remote["sys_updated_on"] = "2026-09-05 12:05:00"
    elif change == "payload":
        remote["short_description"] = "changed after comparison"
    elif change == "actor":
        actor = "user:other"
    elif change in {"expiry", "future"}:
        checked_at = inspected["inspection"]["checked_at"]
        monkeypatch.setattr(grc_sync.time, "time", lambda: checked_at + (301 if change == "expiry" else -1))
    elif change == "revision":
        revision = row["revision"]
    else:
        reader.target_sha256 = "b" * 64
    with pytest.raises((grc_sync.GRCSyncStateError, grc_sync.RecordConflict)):
        grc_sync.resolve_delivery(row["id"], expected_revision=revision, actor=actor,
            note="Review the stored comparison.", reader=reader,
            evidence_sha256=inspected["inspection"]["evidence_sha256"])
    assert grc_sync.list_outbound()[0]["status"] == "dispatch_unconfirmed"


def test_reconciliation_is_workspace_isolated_and_rejects_destination_change(monkeypatch):
    with tenant_scope(tenant="workspace-a"):
        row, _, reader, _, _ = _held(monkeypatch)
        grc_sync._STORE.update(row["id"], lambda value: value["dispatch"].update(target_sha256="a" * 64),
                              expected_revision=row["revision"], actor="user:admin", action="test_snapshot")
        reader.target_sha256 = "b" * 64
        with pytest.raises(grc_sync.GRCSyncStateError, match="destination changed"):
            grc_sync.inspect_delivery(row["id"], expected_revision=row["revision"] + 1,
                                      actor="user:admin", reader=reader)
    with tenant_scope(tenant="workspace-b"):
        with pytest.raises(grc_sync.GRCSyncStateError, match="not found"):
            grc_sync.inspect_delivery(row["id"], expected_revision=row["revision"],
                                      actor="user:admin", reader=reader)


def test_legacy_changed_source_and_unreadable_response_remain_held(monkeypatch):
    row, _, reader, _, _ = _held(monkeypatch)
    grc_sync._STORE.update(row["id"], lambda value: value.pop("dispatch"),
                          expected_revision=row["revision"], actor="user:admin", action="test_legacy")
    _sources(monkeypatch, findings=[])
    with pytest.raises(grc_sync.GRCSyncStateError, match="Original delivery content"):
        grc_sync.inspect_delivery(row["id"], expected_revision=row["revision"] + 1,
                                  actor="user:admin", reader=reader)
    for response in ["ERROR: get request failed (Timeout)", "<html>Error</html>", "null", "[1]", "[{}, {}, {}]"]:
        with pytest.raises(grc_sync.GRCSyncStateError):
            grc_sync._remote_rows(response)


def test_config_gate_is_default_off_and_hostile_values_are_refused(tmp_path):
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    assert grc_sync.enabled() is False
    with pytest.raises(grc_sync.GRCSyncConfigError, match="enable"):
        grc_sync.run_sync(actor="ops")

    (tmp_path / "config.toml").write_text(
        '[grc_sync]\nenable = true\nfindings_path = "/x"\nextra = 1\n',
        encoding="utf-8",
    )
    config.reset_config_cache()
    with pytest.raises(grc_sync.GRCSyncConfigError, match="unknown"):
        grc_sync.get_grc_sync_config()

    for hostile in ("no-slash", "/has?query", "/dot/../dot", "/frag#ment"):
        (tmp_path / "config.toml").write_text(
            f'[grc_sync]\nenable = true\nfindings_path = "{hostile}"\n',
            encoding="utf-8",
        )
        config.reset_config_cache()
        with pytest.raises(grc_sync.GRCSyncConfigError, match="path"):
            grc_sync.get_grc_sync_config()

    (tmp_path / "config.toml").write_text(
        '[grc_sync]\nenable = true\nfindings_path = "/x"\n'
        'backlink_base = "http://plain.example.com"\n',
        encoding="utf-8",
    )
    config.reset_config_cache()
    with pytest.raises(grc_sync.GRCSyncConfigError, match="HTTPS"):
        grc_sync.get_grc_sync_config()


def test_delivery_is_idempotent_and_carries_the_round_trip_link(monkeypatch):
    open_finding = _finding("MRF-open")
    accepted = _finding("MRF-accepted", "Residual risk accepted by the CRO.")
    _sources(
        monkeypatch,
        findings=[open_finding, accepted],
        incidents=[_incident()],
        accepted_ids={"MRF-accepted"},
    )
    writer = _Writer()

    result = grc_sync.run_sync(actor="ops", writer=writer)

    assert result["delivered_count"] == 3
    assert result["failure_count"] == 0
    paths = sorted(path for _op, path, _body in writer.calls)
    assert paths == [
        "/api/now/table/incident",
        "/api/now/table/sn_grc_issue",
        "/api/now/table/sn_risk_acknowledgement",
    ]
    body = next(b for _o, p, b in writer.calls if p.endswith("sn_grc_issue"))
    # Round-trip link and bounded pointer content only.
    assert body["correlation_id"] == "MRF-open"
    assert body["correlation_display"] == "Lightwork"
    assert body["u_lightwork_url"] == "https://lightwork.example.com/security/assurance"
    assert "f" * 64 in body["description"]
    assert "never leaves" not in json.dumps(body)
    assert "MRE-1" not in json.dumps(body)
    assert len(body["short_description"]) <= 160

    rows = grc_sync.list_outbound()
    assert {row["status"] for row in rows} == {"delivered"}
    assert all(row["remote_id"].startswith("sys") for row in rows)

    # Unchanged sources: nothing is sent again.
    again = grc_sync.run_sync(actor="ops", writer=writer)
    assert again["delivered_count"] == 0
    assert again["unchanged_count"] == 3
    assert len(writer.calls) == 3


def test_typed_success_records_remote_id_and_never_replays(monkeypatch):
    from maverick.tool_results import ToolOutcome, ToolResultState

    _sources(monkeypatch, findings=[_finding()])
    writer = _Writer([ToolOutcome(ToolResultState.SUCCEEDED, '{"result":{"sys_id":"sys123"}}')])
    first = grc_sync.run_sync(actor="ops", writer=writer)
    assert first["delivered_count"] == 1
    row = grc_sync.list_outbound()[0]
    assert row["status"] == "delivered" and row["remote_id"] == "sys123"
    grc_sync.run_sync(actor="ops", writer=writer)
    assert len(writer.calls) == 1


def test_typed_unknown_remains_held_even_with_success_looking_content(monkeypatch):
    from maverick.tool_results import ToolOutcome, ToolResultState

    _sources(monkeypatch, findings=[_finding()])
    writer = _Writer([ToolOutcome(ToolResultState.INDETERMINATE, '{"result":{"sys_id":"sys123"}}')])
    grc_sync.run_sync(actor="ops", writer=writer)
    row = grc_sync.list_outbound()[0]
    assert row["status"] == "dispatch_unconfirmed"
    grc_sync.run_sync(actor="ops", writer=writer)
    assert len(writer.calls) == 1


def test_typed_failed_read_is_never_used_for_reconciliation():
    from maverick.tool_results import ToolOutcome, ToolResultState

    with pytest.raises(grc_sync.GRCSyncStateError, match="could not verify"):
        grc_sync._remote_rows(ToolOutcome(ToolResultState.FAILED, '{"result":[]}'))


def test_changed_source_updates_the_same_remote_record(monkeypatch):
    finding = _finding("MRF-open")
    _sources(monkeypatch, findings=[finding])
    writer = _Writer()
    first = grc_sync.run_sync(actor="ops", writer=writer)
    remote_id = first["delivered"][0]["remote_id"]

    changed = dict(finding, summary="Now remediated twice.", finding_sha256="e" * 64)
    _sources(monkeypatch, findings=[changed])
    second = grc_sync.run_sync(actor="ops", writer=writer)

    assert second["delivered_count"] == 1
    op, path, body = writer.calls[-1]
    assert op == "patch"
    assert path == f"/api/now/table/sn_grc_issue/{remote_id}"
    assert "Now remediated twice." in body["description"]
    row = grc_sync.list_outbound()[0]
    assert row["status"] == "delivered"
    assert row["remote_id"] == remote_id
    assert row["attempts"] == 2


def test_failed_delivery_records_a_bounded_error_and_retries(monkeypatch):
    _sources(monkeypatch, findings=[_finding()])
    writer = _Writer(responses=["ERROR: post (400): upstream request failed" + "x" * 900])

    first = grc_sync.run_sync(actor="ops", writer=writer)
    assert first["failure_count"] == 1
    row = grc_sync.list_outbound()[0]
    assert row["status"] == "failed"
    assert row["attempts"] == 1
    assert len(row["last_error"]) <= 500

    second = grc_sync.run_sync(actor="ops", writer=writer)
    assert second["delivered_count"] == 1
    assert grc_sync.list_outbound()[0]["status"] == "delivered"


def test_concurrent_dispatch_cannot_create_the_same_remote_record_twice(monkeypatch):
    _sources(monkeypatch, findings=[_finding()])
    entered = threading.Event()
    release = threading.Event()
    calls = []

    def writer(op, path, body):
        calls.append((op, path, body))
        entered.set()
        assert release.wait(5), "synthetic writer was not released"
        return json.dumps({"result": {"sys_id": "synthetic-remote"}})

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(grc_sync.run_sync, actor="first", writer=writer)
        assert entered.wait(5)
        second = pool.submit(grc_sync.run_sync, actor="second", writer=writer)
        try:
            second.result(timeout=1)
        except TimeoutError:
            pass  # A broken implementation reached the blocked writer twice.
        finally:
            release.set()
        first.result(timeout=5)
        second_result = second.result(timeout=5)
    assert len(calls) == 1
    assert second_result["blocked_count"] == 1


def test_failed_patch_is_reported_as_failure_and_retries_the_same_remote_id(monkeypatch):
    finding = _finding()
    _sources(monkeypatch, findings=[finding])
    writer = _Writer()
    first = grc_sync.run_sync(actor="ops", writer=writer)
    remote_id = first["delivered"][0]["remote_id"]
    _sources(monkeypatch, findings=[dict(finding, finding_sha256="e" * 64)])
    writer.responses.append("ERROR: patch (503): unavailable")
    failed = grc_sync.run_sync(actor="ops", writer=writer)
    assert failed["delivered_count"] == 0
    assert failed["failure_count"] == 1
    assert grc_sync.list_outbound()[0]["remote_id"] == remote_id
    assert grc_sync.run_sync(actor="ops", writer=writer)["delivered_count"] == 1
    assert [op for op, _path, _body in writer.calls] == ["post", "patch", "patch"]


def test_uncertain_writer_exception_is_held_instead_of_recreated(monkeypatch):
    _sources(monkeypatch, findings=[_finding()])
    calls = []

    def interrupted_writer(*args):
        calls.append(args)
        raise TimeoutError("synthetic response lost after remote create")

    first = grc_sync.run_sync(actor="ops", writer=interrupted_writer)
    second = grc_sync.run_sync(actor="ops", writer=interrupted_writer)
    assert len(calls) == 1
    assert first["blocked_count"] == second["blocked_count"] == 1
    assert first["delivered_count"] == 0


@pytest.mark.parametrize("response", [
    "ERROR: servicenow request failed (ReadTimeout)",
    "ERROR: connector configuration or request failed (RuntimeError)",
    "ERROR: post (503): upstream request failed",
    "INDETERMINATE: connector request may have executed; reconcile before retrying.",
    None,
])
def test_uncertain_connector_response_is_held_instead_of_recreated(monkeypatch, response):
    _sources(monkeypatch, findings=[_finding()])
    writer = _Writer(responses=[response])
    first = grc_sync.run_sync(actor="ops", writer=writer)
    second = grc_sync.run_sync(actor="ops", writer=writer)
    assert len(writer.calls) == 1
    assert first["delivered_count"] == second["delivered_count"] == 0
    assert first["blocked_count"] == second["blocked_count"] == 1
    assert grc_sync.list_outbound()[0]["status"] == "dispatch_unconfirmed"


def test_actual_rest_writer_lost_response_cannot_create_twice(monkeypatch):
    from contextlib import contextmanager

    import httpx
    from maverick.tools import _ssrf

    _sources(monkeypatch, findings=[_finding()])
    monkeypatch.setenv("SERVICENOW_INSTANCE_URL", "https://synthetic.example.com")
    monkeypatch.setenv("SERVICENOW_TOKEN", "synthetic-test-token")
    calls = []

    class Client:
        def stream(self, *args, **kwargs):
            calls.append(args)
            raise httpx.ReadTimeout("synthetic response lost after remote create")

    @contextmanager
    def fake_client(*args, **kwargs):
        yield Client()

    monkeypatch.setattr(_ssrf, "safe_client", fake_client)
    first = grc_sync.run_sync(actor="ops")
    second = grc_sync.run_sync(actor="ops")
    assert len(calls) == 1
    assert first["blocked_count"] == second["blocked_count"] == 1
    assert first["delivered_count"] == 0
    assert grc_sync.list_outbound()[0]["status"] == "dispatch_unconfirmed"


def test_lost_local_delivery_receipt_keeps_remote_create_claimed(monkeypatch):
    from maverick.privacy_ops import RecordConflict

    _sources(monkeypatch, findings=[_finding()])
    writer = _Writer()
    original_update = grc_sync._STORE.update  # noqa: SLF001

    def lose_delivery_receipt(*args, **kwargs):
        if kwargs.get("action") == "deliver_grc_outbound":
            raise RecordConflict("synthetic receipt persistence conflict")
        return original_update(*args, **kwargs)

    monkeypatch.setattr(grc_sync._STORE, "update", lose_delivery_receipt)  # noqa: SLF001
    assert grc_sync.run_sync(actor="ops", writer=writer)["failure_count"] == 1
    monkeypatch.setattr(grc_sync._STORE, "update", original_update)  # noqa: SLF001
    assert grc_sync.run_sync(actor="ops", writer=writer)["blocked_count"] == 1
    assert len(writer.calls) == 1
    assert grc_sync.list_outbound()[0]["status"] == "dispatching"


def test_unparseable_create_is_terminal_never_a_duplicate(monkeypatch):
    finding = _finding()
    _sources(monkeypatch, findings=[finding])
    writer = _Writer(responses=["created but not json"])

    first = grc_sync.run_sync(actor="ops", writer=writer)
    assert first["delivered_count"] == 1
    row = grc_sync.list_outbound()[0]
    assert row["status"] == "delivered_unconfirmed"
    assert row["remote_id"] is None

    # Even a changed source never re-creates: the remote id is unknown, and a
    # second POST would duplicate the record.
    changed = dict(finding, finding_sha256="d" * 64)
    _sources(monkeypatch, findings=[changed])
    second = grc_sync.run_sync(actor="ops", writer=writer)
    assert second["delivered_count"] == 0
    assert second["blocked_count"] == 1
    assert "resolve the outbound record manually" in second["blocked"][0]["reason"]
    assert len(writer.calls) == 1

    # A hostile remote id is treated as unparseable, not trusted.
    assert grc_sync._remote_id_from(  # noqa: SLF001
        json.dumps({"result": {"sys_id": "x" * 300}})
    ) is None
    assert grc_sync._remote_id_from(  # noqa: SLF001
        json.dumps({"result": {"sys_id": "id with spaces"}})
    ) is None


def test_outbound_ledger_is_tenant_scoped(monkeypatch):
    _sources(monkeypatch, findings=[_finding()])
    with tenant_scope(tenant="alpha"):
        grc_sync.run_sync(actor="ops", writer=_Writer())
        assert len(grc_sync.list_outbound()) == 1
    with tenant_scope(tenant="beta"):
        assert grc_sync.list_outbound() == []


def test_run_bounds_and_kind_gating(monkeypatch, tmp_path):
    _sources(monkeypatch, findings=[_finding()], incidents=[_incident()])
    with pytest.raises(ValueError, match="limit"):
        grc_sync.run_sync(actor="ops", writer=_Writer(), limit=0)

    # Disabling a kind's path keeps that kind local.
    (tmp_path / "config.toml").write_text(
        _CONFIG.replace('incidents_path = "/api/now/table/incident"\n', ""),
        encoding="utf-8",
    )
    config.reset_config_cache()
    writer = _Writer()
    result = grc_sync.run_sync(actor="ops", writer=writer)
    assert result["delivered_count"] == 1
    assert all("incident" not in path for _o, path, _b in writer.calls)
