"""Signed restore must not reopen a completed or ambiguous external delivery.

Provider source listing, audit delivery and the external writer are synthetic;
governed records, signed archives and reviewed P7 restoration are real. No
network or normal runtime background workers are started by these tests.
"""
from __future__ import annotations

import hashlib
import json
from urllib.parse import parse_qs, urlsplit

import pytest
from maverick import (
    audit,
    backup,
    client,
    config,
    crypto_at_rest,
    file_lock,
    grc_sync,
    workspace_recovery,
)
from maverick import grc_outbound_sync as gos
from maverick import grc_vendor_transports as gvt
from maverick import model_risk_assurance as mra
from maverick.paths import data_dir


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "replay-workspace")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    for key in (
        "MAVERICK_BACKUP_SIGNING_KEY", "MAVERICK_TENANT", "MAVERICK_WORLD_BACKEND",
        "MAVERICK_GOVERNED_RECORDS_BACKEND", "MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES",
        "MAVERICK_GRPC_DISPATCH_TARGET", "MAVERICK_PG_DSN", "MAVERICK_KNOWLEDGE_DSN",
        "MAVERICK_QUEUE_REDIS_DSN", "QDRANT_URL", "REDIS_URL",
    ):
        monkeypatch.delenv(key, raising=False)
    cfg = {"grc_sync": {"enable": True, "connector": "servicenow",
                        "findings_path": "/api/now/table/sn_grc_issue"}}
    monkeypatch.setattr(config, "load_config", lambda: cfg)
    monkeypatch.setattr(config, "load_global_config", lambda: cfg)
    monkeypatch.setattr(config, "config_source_errors", lambda **_: [])
    monkeypatch.setattr(workspace_recovery, "application_identity", lambda: "synthetic-replay-build")
    monkeypatch.setattr(crypto_at_rest, "_KEY_PATH", tmp_path / "shared-keys" / "at_rest.key")
    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    finding = {"id": "MRF-existing", "asset_id": "MAA-" + "a" * 32,
               "severity": "high", "summary": "Synthetic existing finding",
               "finding_sha256": "f" * 64, "citations": []}
    monkeypatch.setattr(mra, "findings", lambda **_: [finding])
    monkeypatch.setattr(mra, "list_incidents", lambda **_: [])
    monkeypatch.setattr(mra, "current_risk_acceptance", lambda *_args, **_: None)
    client.reset_client_cache()
    root = file_lock.ensure_private_directory(data_dir())
    file_lock.atomic_write_text(root / "document.txt", "original user content")
    workspace_recovery.configure_key()
    yield root
    client.reset_client_cache()


@pytest.mark.parametrize("outcome", ["delivered", "dispatch_unconfirmed"])
@pytest.mark.parametrize("late_delivery", [False, True], ids=["prepare", "after-review"])
def test_p7_refuses_to_rewind_real_grc_delivery_authority(workspace, outcome, late_delivery):
    snapshot = workspace_recovery.create()
    review = None
    if late_delivery:
        review = workspace_recovery.prepare_restore(snapshot["id"], isolated=True, actor="reviewer")
    calls = []

    def synthetic_writer(operation, path, body):
        calls.append((operation, path, dict(body)))
        if outcome == "dispatch_unconfirmed":
            return "ERROR: post request failed (Timeout)"
        return json.dumps({"result": {"sys_id": "synthetic-remote-record"}})

    grc_sync.run_sync(actor="user:reviewer", writer=synthetic_writer)
    assert len(calls) == 1 and calls[0][0] == "post"
    stored = grc_sync.list_outbound()[0]
    assert stored["status"] == outcome
    before = {p.name: file_lock.atomic_read_bytes(p) for p in (workspace / "grc_sync_outbound").glob("*.json")}
    snapshots_before = workspace_recovery.list_snapshots()
    with pytest.raises(backup.BackupError, match="external-action history"):
        if review is None:
            workspace_recovery.prepare_restore(snapshot["id"], isolated=True, actor="reviewer")
        else:
            workspace_recovery.apply_restore(review["review"], review["target"], isolated=True, actor="reviewer")
    assert workspace_recovery.list_snapshots() == snapshots_before
    assert before == {p.name: file_lock.atomic_read_bytes(p) for p in (workspace / "grc_sync_outbound").glob("*.json")}
    assert (workspace / "document.txt").read_text() == "original user content"
    assert (workspace_recovery._store() / "review.json").exists() is late_delivery
    if review is not None:
        saved = json.loads(file_lock.atomic_read_text(workspace_recovery._store() / "review.json"))
        assert saved["review"] == review["review"]
    repeat = grc_sync.run_sync(actor="user:reviewer", writer=synthetic_writer)
    assert len(calls) == 1
    assert repeat["unchanged_count" if outcome == "delivered" else "blocked_count"] == 1
    with backup.recovery_scope(workspace, "replay-workspace", workspace_recovery._key()):
        comparison = backup.compare_backup(workspace_recovery._archive(snapshot["id"]))
        assert comparison["protected_changes"] == 1
        assert next(row for row in comparison["items"] if row["path"].endswith(".json"))["protected"] is True


@pytest.mark.parametrize("namespace", [
    "grc_sync_outbound", "grc_outbound_sync_states", "grc_outbound_sync_events",
    "vendor_onboarding", "discovery_containment_actions",
])
@pytest.mark.parametrize("prefix", ["", "tenants/second/"])
@pytest.mark.parametrize("mutation", ["added", "changed", "deleted"])
def test_grc_authority_union_is_protected_in_workspace_and_whole_home(tmp_path, prefix, mutation, namespace):
    root = file_lock.ensure_private_directory(tmp_path / "live")
    file_lock.atomic_write_text(root / "document.txt", "unchanged")
    path = root / prefix / namespace / "GRC-existing.json"
    file_lock.ensure_private_directory(path.parent)
    if mutation != "added":
        file_lock.atomic_write_text(path, '{"status":"pending","revision":1}')
    archive = tmp_path / "selected.tgz"
    with backup.recovery_scope(root, "guard-scope", bytes(range(32))):
        backup.create_backup(archive)
        if mutation == "deleted":
            path.unlink()
        else:
            file_lock.atomic_write_text(path, '{"status":"delivered","revision":2}')
        result = backup.compare_backup(archive)
        assert result["protected_changes"] == 1
        assert result["items"][0]["change"] == mutation
        with pytest.raises(backup.BackupError, match="external-action history"):
            backup.assert_accounting_unchanged(archive)


def test_unchanged_delivery_authority_allows_document_and_ordinary_lock_changes(tmp_path):
    root = file_lock.ensure_private_directory(tmp_path / "live")
    store = file_lock.ensure_private_directory(root / "grc_sync_outbound")
    file_lock.atomic_write_text(store / "GRC-existing.json", '{"status":"delivered"}')
    file_lock.atomic_write_text(root / "document.txt", "before")
    archive = tmp_path / "selected.tgz"
    with backup.recovery_scope(root, "guard-scope", bytes(range(32))):
        backup.create_backup(archive)
        file_lock.atomic_write_text(root / "document.txt", "after")
        file_lock.atomic_write_text(store / "GRC-existing.json.lock", "ordinary lock")
        backup.assert_accounting_unchanged(archive)
        result = backup.compare_backup(archive)
        assert result["protected_changes"] == 0


class _SyntheticServiceNow:
    """Unique current idempotency field, preserving external rows across restore."""

    def __init__(self):
        self.rows = {}
        self.mutations = []

    def request(self, method, url, *, headers, json_body, timeout, max_response_bytes):
        parts = urlsplit(url)
        assert parts.hostname == "synthetic.service-now.com"
        assert parts.path.startswith("/api/now/table/sn_grc_issue")
        query = parse_qs(parts.query)
        if method == "GET":
            if "sysparm_query" in query:
                key = query["sysparm_query"][0].split("=", 1)[1]
                result = [row for row in self.rows.values() if row["u_lightwork_idempotency_key"] == key]
            else:
                result = self.rows[parts.path.rsplit("/", 1)[1]]
        elif method == "POST":
            assert all(row["u_lightwork_idempotency_key"] != json_body["u_lightwork_idempotency_key"]
                       for row in self.rows.values())
            identifier = f"{len(self.rows) + 1:032x}"
            result = {**json_body, "sys_id": identifier, "sys_mod_count": "0"}
            self.rows[identifier] = result
            self.mutations.append(method)
        elif method == "PATCH":
            identifier = parts.path.rsplit("/", 1)[1]
            prior = self.rows[identifier]
            assert headers["If-Match"] == prior["sys_mod_count"]
            result = {**prior, **json_body, "sys_mod_count": str(int(prior["sys_mod_count"]) + 1)}
            self.rows[identifier] = result
            self.mutations.append(method)
        else:
            raise AssertionError(method)
        return gvt.VendorHTTPResponse(200, {}, json.dumps({"result": result}).encode())


def test_p7_preserves_semantic_grc_revision_and_external_identity(workspace):
    snapshot = workspace_recovery.create()
    target = gos.GRCSystem.SERVICENOW_IRM
    bridge = gos.GRCOutboundSync(policy=gos.GRCOutboundPolicy(enabled=True, allowed_targets=frozenset({target})))
    http = _SyntheticServiceNow()
    transport = gvt.ServiceNowIRMTransport(base_url="https://synthetic.service-now.com", http=http,
                                         secret_resolver=lambda _: "synthetic-credential")

    def source(revision):
        return gos.FindingSource(finding_id="MRF-existing", asset_id="MAA-" + "a" * 32,
                                 finding_type="evaluation_evidence_missing", severity="high",
                                 summary="Synthetic existing finding", source_revision=revision,
                                 source_digest=hashlib.sha256(str(revision).encode()).hexdigest())

    first = bridge.sync(source(1), target=target, transport=transport, actor="reviewer")
    second = bridge.sync(source(2), target=target, transport=transport, actor="reviewer")
    assert http.mutations == ["POST", "PATCH"] and len(http.rows) == 1
    assert first["external"]["id"] == second["external"]["id"]
    with pytest.raises(gos.GRCOutboundConflict, match="older"):
        bridge.sync(source(1), target=target, transport=transport, actor="reviewer")
    with pytest.raises(backup.BackupError, match="external-action history"):
        workspace_recovery.prepare_restore(snapshot["id"], isolated=True, actor="reviewer")
    assert not (workspace_recovery._store() / "review.json").exists()
    assert len(workspace_recovery.list_snapshots()) == 1
    with backup.recovery_scope(workspace, "replay-workspace", workspace_recovery._key()):
        comparison = backup.compare_backup(workspace_recovery._archive(snapshot["id"]))
        protected = [row for row in comparison["items"] if row["protected"]]
        assert {row["path"].split("/")[0] for row in protected} == {
            "grc_outbound_sync_states", "grc_outbound_sync_events",
        }
    # The retained current record still blocks the stale source. If it were
    # erased, the real adapter would create a second remote record: the unique
    # remote idempotency field now contains v2, so lookup cannot recover v1.
    with pytest.raises(gos.GRCOutboundConflict, match="older"):
        bridge.sync(source(1), target=target, transport=transport, actor="reviewer")
    assert bridge.sync(source(2), target=target, transport=transport, actor="reviewer")["status"] == "delivered"
    assert http.mutations == ["POST", "PATCH"] and len(http.rows) == 1


@pytest.mark.parametrize("ambiguous", [False, True], ids=["verified", "lost-response"])
def test_vendor_operation_cannot_regain_approval_through_restore(workspace, ambiguous):
    from maverick.governed_operations import ServiceContext
    from maverick.vendor_onboarding import VendorOnboardingService
    from maverick.vendor_onboarding_adapters import (
        EvidenceDocument,
        FakeGoogleDriveEvidence,
        FakeJiraTickets,
    )

    cfg = config.load_config()
    for name in ("vendor_onboarding", "vendor_management", "ai_vendor_risk", "model_risk_assurance"):
        cfg[name] = {"enable": True}
    now = 1_800_000_000.0
    ctx = ServiceContext("replay-workspace", "reviewer@example.test", "procurement",
                         "reviewer@example.test", "jira", human=True)
    documents = FakeGoogleDriveEvidence({(ctx.tenant, "security-paper"): EvidenceDocument(
        "security-paper", "1", now - 86400, b"Data is encrypted at rest and in transit.")})
    tickets = FakeJiraTickets()
    tickets.timeout_after_success = ambiguous
    service = VendorOnboardingService(documents, tickets, lambda *_: True, clock=lambda: now)
    row = service.intake(ctx, "Synthetic vendor", "security-paper", "VEND", "Synthetic recovery review")
    row = service.collect_evidence(ctx, row["id"], row["revision"])
    row = service.assess(ctx, row["id"], row["revision"])
    row = service.review(ctx, row["id"], row["revision"], "approved", "Restricted synthetic pilot")
    row = service.prepare_action(ctx, row["id"], row["revision"])
    row = service.approve_action(
        ctx,
        row["id"],
        row["revision"],
        row["operation"]["approval_card"]["binding_sha256"],
    )
    snapshot = workspace_recovery.create()
    executed = service.execute(ctx, row["id"])
    expected = "reconciliation_required" if ambiguous else "verified"
    assert executed["operation"]["state"] == expected and tickets.creates == 1
    with pytest.raises(backup.BackupError, match="external-action history"):
        workspace_recovery.prepare_restore(snapshot["id"], isolated=True, actor="reviewer")
    assert not (workspace_recovery._store() / "review.json").exists()
    assert len(workspace_recovery.list_snapshots()) == 1
    assert service.get(ctx, row["id"])["operation"]["state"] == expected
    service.execute(ctx, row["id"])
    assert tickets.creates == 1 and len(tickets.state) == 1


@pytest.mark.parametrize("ambiguous", [False, True], ids=["committed", "lost-response"])
def test_containment_action_cannot_repeat_through_restore(workspace, monkeypatch, ambiguous):
    from maverick import agent_control_plane as acp
    from maverick import ai_discovery_sensors as discovery
    from maverick import discovery_containment as containment
    from maverick import external_agents

    class LostControlReceipt(BaseException):
        pass

    for name in ("MAVERICK_CONTROL_PLANE", "MAVERICK_EXTERNAL_AGENTS"):
        monkeypatch.setenv(name, "1")
    config.load_config()["ai_discovery_sensors"] = {"enable": True}
    now = 1_800_000_000.0
    sensors = discovery.DiscoverySensorService(clock=lambda: now)
    preparer = discovery.SensorActor("user:preparer")
    reviewer = discovery.SensorActor("user:reviewer")
    pending = sensors.register_sensor(sensor_name="synthetic-directory", sensor_type="identity_directory",
                                      config_sha256="a" * 64, actor=preparer)
    sensor = sensors.approve_sensor(pending["sensor_id"], expected_revision=pending["revision"], actor=reviewer)
    sensors.ingest_observation(sensor["sensor_id"], sensor_revision=sensor["sensor_revision"],
                              config_sha256=sensor["config_sha256"], observation=discovery.NormalizedDiscoveryObservation(
                                  event_sha256="b" * 64, observed_at=now, ai_service_code="openai",
                                  ai_product_code="chatgpt", provider_code="openai", domain_category="identity_directory",
                                  deployment_type="saas", environment_code="production", context_codes=("managed_device",)))
    finding = sensors.aggregate_findings()["findings"][0]["finding_sha256"]
    external_agents.enroll("synthetic-replay-agent", "custom", max_risk="high", max_dollars=10)
    service = containment.DiscoveryContainmentService(sensor_service=sensors, clock=lambda: now)
    binding = service.prepare_binding(finding, agent_principal="agent:synthetic-replay-agent", actor=preparer)
    binding = service.approve_binding(binding["binding_id"], expected_revision=binding["revision"], actor=reviewer)
    calls = []

    def synthetic_control(principal, **kwargs):
        calls.append((principal, dict(kwargs)))
        if ambiguous:
            raise LostControlReceipt
        return acp.ControlResult("contain", principal, True)

    monkeypatch.setattr(acp, "contain", synthetic_control)

    def execute():
        return service.execute(binding["binding_id"], action="contain", reason_code="synthetic_review",
                               operation_key="same_operation", actor=discovery.SensorActor("user:operator"))

    snapshot = workspace_recovery.create()
    if ambiguous:
        with pytest.raises(LostControlReceipt):
            execute()
    else:
        assert execute()["status"] == "committed"
    expected = "indeterminate" if ambiguous else "committed"
    assert execute()["status"] == expected and len(calls) == 1
    with pytest.raises(backup.BackupError, match="external-action history"):
        workspace_recovery.prepare_restore(snapshot["id"], isolated=True, actor="reviewer")
    assert not (workspace_recovery._store() / "review.json").exists()
    assert len(workspace_recovery.list_snapshots()) == 1
    assert execute()["status"] == expected and len(calls) == 1
