from __future__ import annotations

import copy
import gc
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import maverick.customer_sandbox_lifecycle as lifecycle_module
import pytest
from maverick.customer_sandbox_lifecycle import (
    CustomerSandboxConfigError,
    CustomerSandboxConflict,
    CustomerSandboxIntegrityError,
    CustomerSandboxLifecycleStore,
    CustomerSandboxNotFound,
    CustomerSandboxPermissionDenied,
    CustomerSandboxProvisioningError,
    CustomerSandboxValidationError,
    LocalCustomerSandboxProvisioner,
    SourceTenantConfiguration,
    enabled,
    require_enabled,
)

NOW = 2_100_000_000.0
MODULES = (
    "ai_governance",
    "consent_preferences",
    "data_use_governance",
    "privacy_automation",
    "tech_risk_compliance",
    "third_party_management",
)


def _make_directory_alias(target: Path, alias: Path) -> None:
    try:
        os.symlink(target, alias, target_is_directory=True)
        return
    except OSError:
        if os.name != "nt":
            raise
    completed = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(alias), str(target)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise OSError(completed.stderr or completed.stdout)


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _safe_config() -> dict[str, object]:
    return {
        "ai_governance": {
            "enabled": True,
            "mode": "review",
            "limits": {"items": 1},
        },
        "consent_preferences": {
            "enable": True,
            "publishing": {"enable": True, "require_signed_publications": True},
            "public_api": {
                "enable": True,
                "token_ttl_seconds": 900,
                "max_request_bytes": 65_536,
                "max_response_bytes": 262_144,
                "requests_per_minute": 120,
            },
            "scanner": {
                "enable": True,
                "notice_proposals": {"enable": True},
                "scheduler": {"enable": True, "poll_seconds": 60, "claim_limit": 4},
                "max_pages": 100,
                "max_depth": 4,
            },
            "standards": {"gpc": True, "dnt": True, "gpp": False, "tcf": False},
            "delivery": {
                "enable": True,
                "max_attempts": 3,
                "retry_base_seconds": 30,
                "retry_max_seconds": 300,
            },
            "analytics": {
                "enable": True,
                "min_cohort_size": 20,
                "retention_days": 30,
            },
            "edge_cache": {
                "enable": True,
                "max_age_seconds": 60,
                "stale_if_error_seconds": 300,
            },
            "limits": {
                "profile_page_size": 100,
                "receipt_page_size": 100,
                "request_body_bytes": 65_536,
            },
            "storage": {"backend": "sqlite", "dsn_secret_ref": "vault:must-drop"},
        },
        "data_use_governance": {
            "enable": True,
            "compiler": {"enable": True, "max_operations": 500},
            "enforcement": {"enable": True, "require_four_eyes": True},
            "provider_audit": {
                "enable": True,
                "audit_window_seconds": 3_600,
                "retention_seconds": 86_400,
                "scheduler": {"enable": True, "poll_seconds": 60},
            },
            "scheduler": {"enable": True, "history_limit": 500},
            "snowflake": {
                "enable": True,
                "origin": "https://provider.example",
                "credential_secret_ref": "vault:must-drop",
            },
            "limits": {"max_assets": 10_000, "max_fields": 100_000},
        },
        "privacy_automation": {
            "enable": True,
            "data_discovery": {"enable": True},
            "rights_orchestration": {"enable": True},
        },
        "tech_risk_compliance": {
            "enable": True,
            "policy_publication_links": {"enable": True},
            "scoping": {"enable": True},
            "scope_actions": {"enable": True},
            "continuous_evidence": {
                "enable": True,
                "enabled_collectors": ["local_soc2_v1"],
            },
        },
        "third_party_management": {
            "enable": True,
            "intelligence": {
                "enable": True,
                "providers": {
                    "enable": True,
                    "enabled_providers": ["riskrecon"],
                },
            },
            "lifecycle": {"enable": True},
        },
    }


class Authorities:
    def __init__(self) -> None:
        self.config = _safe_config()
        self.revision = 1
        self.principal = "global-admin-requester"
        self.gate = True
        self.now = NOW
        self.production_targets: set[str] = set()

    def source(self, tenant_id: str) -> SourceTenantConfiguration:
        if tenant_id != "production-a":
            raise KeyError(tenant_id)
        return SourceTenantConfiguration(
            tenant_id=tenant_id,
            revision=self.revision,
            config_sha256=_digest(self.config),
            config=copy.deepcopy(self.config),
        )

    def require_enabled(self) -> None:
        if not self.gate:
            raise CustomerSandboxConfigError("customer_sandbox_lifecycle_disabled")


def _store(
    tmp_path: Path,
    authorities: Authorities,
    *,
    provisioner: LocalCustomerSandboxProvisioner | None = None,
) -> CustomerSandboxLifecycleStore:
    return CustomerSandboxLifecycleStore(
        tmp_path / "lifecycle.sqlite3",
        source_resolver=authorities.source,
        principal_resolver=lambda: authorities.principal,
        provisioner=provisioner or LocalCustomerSandboxProvisioner(tmp_path / "sandboxes"),
        config_gate=authorities.require_enabled,
        target_collision_resolver=lambda target: target in authorities.production_targets,
        clock=lambda: authorities.now,
    )


def _request(store: CustomerSandboxLifecycleStore, modules=MODULES):
    return store.request_sandbox(
        "sandbox-operation-1",
        source_tenant_id="production-a",
        target_sandbox_id="production-a-sandbox",
        module_allowlist=modules,
        expires_at=NOW + 3_600,
        retained_until=NOW + 7_200,
        plan="sandbox-small",
        quota_bytes=64 * 1024,
        idempotency_key="request-1",
    )


def _activate(store: CustomerSandboxLifecycleStore, authorities: Authorities):
    record = _request(store)
    authorities.principal = "global-admin-approver"
    record = store.approve_sandbox(
        record.sandbox_id,
        expected_revision=record.revision,
        idempotency_key="approve-1",
    )
    authorities.principal = "global-admin-operator"
    return store.provision_sandbox(
        record.sandbox_id,
        expected_revision=record.revision,
        idempotency_key="provision-1",
    )


def test_default_off_gate_is_exact() -> None:
    assert enabled({}) is False
    assert enabled({"customer_sandbox_lifecycle": {"enable": False}}) is False
    assert enabled({"customer_sandbox_lifecycle": {"enable": True}}) is True
    with pytest.raises(CustomerSandboxConfigError, match="disabled"):
        require_enabled({})


def test_status_discloses_workspace_and_audit_integrity_boundaries(tmp_path: Path) -> None:
    store = _store(tmp_path, Authorities())
    status = store.status()
    assert status["workspace_integrity_verified"] is False
    assert status["audit_chain_keyed"] is False
    assert status["disabled_admission_replay_blocked"] is True


def test_six_module_snapshot_is_sanitized_immutable_and_source_unchanged(
    tmp_path: Path,
) -> None:
    authorities = Authorities()
    source_before = copy.deepcopy(authorities.config)
    authorities.config["unrelated_runtime"] = {
        "api_token": "must-never-cross",
        "raw_world_database": "must-never-cross",
    }
    source_before = copy.deepcopy(authorities.config)
    store = _store(tmp_path, authorities)

    active = _activate(store, authorities)

    assert active.state == "active"
    assert active.module_allowlist == tuple(sorted(MODULES))
    assert authorities.config == source_before
    snapshot_files = list((tmp_path / "sandboxes" / "tenants").rglob("*-*.json"))
    assert len(snapshot_files) == 1
    raw = snapshot_files[0].read_text(encoding="utf-8")
    assert "must-never-cross" not in raw
    assert "api_token" not in raw
    assert "raw_world_database" not in raw
    assert "local_soc2_v1" not in raw
    assert "riskrecon" not in raw
    payload = json.loads(raw)
    assert set(payload["modules"]) == set(MODULES)
    assert store.verify_integrity()["valid"] is True


@pytest.mark.parametrize(
    "injected",
    [
        {"api_token": "secret-value"},
        {"nested": {"credential_ref": "vault:prod/key"}},
        {"nested": {"safe_ref": "${PRODUCTION_SECRET}"}},
        {"provider_origin": "https://provider.example"},
        {"database_path": "tenant.sqlite3"},
        {"contact_email": "ordinary-looking-value"},
        {"account_name": "ordinary-looking-value"},
        {"access_key_id": "ordinary-looking-value"},
        {"dsn": "ordinary-looking-value"},
        {"mode": "arbitrary-customer-specific-value"},
    ],
)
def test_secret_provider_and_raw_material_fail_closed(
    tmp_path: Path,
    injected: dict[str, object],
) -> None:
    authorities = Authorities()
    authorities.config["ai_governance"] = injected
    store = _store(tmp_path, authorities)
    with pytest.raises(CustomerSandboxValidationError, match="prohibited"):
        _request(store, ("ai_governance",))
    assert not list((tmp_path / "sandboxes" / "tenants").iterdir())


def test_unsupported_module_and_source_target_confusion_fail_closed(tmp_path: Path) -> None:
    authorities = Authorities()
    store = _store(tmp_path, authorities)
    with pytest.raises(CustomerSandboxValidationError, match="allowlist"):
        _request(store, ("unsupported_section",))
    with pytest.raises(CustomerSandboxValidationError, match="source_target_conflict"):
        store.request_sandbox(
            "same-target",
            source_tenant_id="production-a",
            target_sandbox_id="production-a",
            module_allowlist=("ai_governance",),
            expires_at=NOW + 3_600,
            retained_until=NOW + 7_200,
            plan="sandbox-small",
            quota_bytes=8_192,
            idempotency_key="same-target",
        )


def test_snapshot_approval_requires_independent_current_authority(tmp_path: Path) -> None:
    authorities = Authorities()
    store = _store(tmp_path, authorities)
    requested = _request(store)
    with pytest.raises(CustomerSandboxPermissionDenied, match="four_eyes"):
        store.approve_sandbox(
            requested.sandbox_id,
            expected_revision=requested.revision,
            idempotency_key="same-reviewer",
        )
    authorities.config["ai_governance"] = {"enabled": False}
    authorities.revision += 1
    authorities.principal = "other-admin"
    with pytest.raises(CustomerSandboxConflict, match="source_authority_changed"):
        store.approve_sandbox(
            requested.sandbox_id,
            expected_revision=requested.revision,
            idempotency_key="stale-source-review",
        )


def test_idempotency_replay_key_reuse_and_disabled_replay(tmp_path: Path) -> None:
    authorities = Authorities()
    store = _store(tmp_path, authorities)
    requested = _request(store)
    assert _request(store) == requested
    with pytest.raises(CustomerSandboxConflict, match="idempotency_conflict"):
        store.request_sandbox(
            "different-operation",
            source_tenant_id="production-a",
            target_sandbox_id="different-sandbox",
            module_allowlist=("ai_governance",),
            expires_at=NOW + 3_600,
            retained_until=NOW + 7_200,
            plan="sandbox-small",
            quota_bytes=8_192,
            idempotency_key="request-1",
        )
    authorities.principal = "reviewer"
    approved = store.approve_sandbox(
        requested.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key="approve-disabled-test",
    )
    authorities.gate = False
    with pytest.raises(CustomerSandboxConfigError, match="disabled"):
        store.provision_sandbox(
            approved.sandbox_id,
            expected_revision=approved.revision,
            idempotency_key="provision-disabled-test",
        )


def test_request_replay_uses_stable_inputs_and_persisted_source_identity(
    tmp_path: Path,
) -> None:
    authorities = Authorities()
    store = _store(tmp_path, authorities)
    requested = _request(store)
    accepted_source_revision = requested.source_revision
    accepted_source_digest = requested.source_config_sha256

    authorities.now += 120
    authorities.revision += 1
    authorities.config["ai_governance"] = {
        "enabled": True,
        "mode": "strict-review",
        "limits": {"items": 2},
    }

    replayed = _request(store)
    assert replayed == requested
    assert replayed.source_revision == accepted_source_revision
    assert replayed.source_config_sha256 == accepted_source_digest
    assert replayed.source_config_sha256 != _digest(authorities.config)


def test_create_and_resync_approval_replay_after_transition(tmp_path: Path) -> None:
    authorities = Authorities()
    store = _store(tmp_path, authorities)
    requested = _request(store)
    authorities.principal = "create-approver"
    approved = store.approve_sandbox(
        requested.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key="create-approval-replay",
    )
    authorities.now = float("nan")
    assert (
        store.approve_sandbox(
            requested.sandbox_id,
            expected_revision=requested.revision,
            idempotency_key="create-approval-replay",
        )
        == approved
    )

    authorities.now = NOW
    authorities.principal = "operator"
    active = store.provision_sandbox(
        approved.sandbox_id,
        expected_revision=approved.revision,
        idempotency_key="create-approval-provision",
    )
    authorities.revision += 1
    authorities.config["ai_governance"] = {
        "enabled": True,
        "mode": "strict-review",
        "limits": {"items": 2},
    }
    authorities.principal = "resync-requester"
    proposal = store.request_resync(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key="approval-replay-resync-request",
    )
    authorities.principal = "resync-approver"
    resync_approved = store.approve_sandbox(
        proposal.sandbox_id,
        expected_revision=proposal.revision,
        idempotency_key="resync-approval-replay",
    )
    authorities.now += 1
    assert (
        store.approve_sandbox(
            proposal.sandbox_id,
            expected_revision=proposal.revision,
            idempotency_key="resync-approval-replay",
        )
        == resync_approved
    )


def test_resync_request_replay_precedes_state_clock_and_source_preconditions(
    tmp_path: Path,
) -> None:
    authorities = Authorities()
    store = _store(tmp_path, authorities)
    active = _activate(store, authorities)
    authorities.revision += 1
    authorities.config["ai_governance"] = {
        "enabled": True,
        "mode": "strict-review",
        "limits": {"items": 2},
    }
    authorities.principal = "resync-requester"
    proposal = store.request_resync(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key="advancing-resync-request",
    )
    accepted_source_revision = proposal.source_revision
    accepted_source_digest = proposal.source_config_sha256

    authorities.now += 120
    authorities.revision += 1
    authorities.config["ai_governance"] = {
        "enabled": False,
        "mode": "review",
        "limits": {"items": 3},
    }
    replayed = store.request_resync(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key="advancing-resync-request",
    )

    assert replayed == proposal
    assert replayed.source_revision == accepted_source_revision
    assert replayed.source_config_sha256 == accepted_source_digest
    assert replayed.source_config_sha256 != _digest(authorities.config)


def test_expiry_replay_precedes_wall_clock_precondition(tmp_path: Path) -> None:
    authorities = Authorities()
    store = _store(tmp_path, authorities)
    active = _activate(store, authorities)
    authorities.now = active.expires_at + 1
    expired = store.expire_sandbox(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key="expiry-clock-replay",
    )

    authorities.now = float("nan")
    assert (
        store.expire_sandbox(
            active.sandbox_id,
            expected_revision=active.revision,
            idempotency_key="expiry-clock-replay",
        )
        == expired
    )


class FailsAfterWriteOnce(LocalCustomerSandboxProvisioner):
    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.fail = True

    def apply(self, snapshot, *, expected_workspace_sha256):
        receipt = super().apply(
            snapshot,
            expected_workspace_sha256=expected_workspace_sha256,
        )
        if self.fail:
            self.fail = False
            raise RuntimeError("simulated process loss after durable write")
        return receipt


class HardCrashesBeforeApplyOnce(LocalCustomerSandboxProvisioner):
    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.fail = True

    def apply(self, snapshot, *, expected_workspace_sha256):
        if self.fail:
            self.fail = False
            raise SystemExit("simulated hard crash before apply")
        return super().apply(
            snapshot,
            expected_workspace_sha256=expected_workspace_sha256,
        )


class HardCrashesAfterApplyOnce(LocalCustomerSandboxProvisioner):
    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.fail = True

    def apply(self, snapshot, *, expected_workspace_sha256):
        receipt = super().apply(
            snapshot,
            expected_workspace_sha256=expected_workspace_sha256,
        )
        if self.fail:
            self.fail = False
            raise SystemExit("simulated hard crash after durable apply")
        return receipt


def test_partial_provision_recovers_without_duplicate_copy(tmp_path: Path) -> None:
    authorities = Authorities()
    provisioner = FailsAfterWriteOnce(tmp_path / "sandboxes")
    store = _store(tmp_path, authorities, provisioner=provisioner)
    requested = _request(store)
    authorities.principal = "reviewer"
    approved = store.approve_sandbox(
        requested.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key="partial-approve",
    )
    authorities.principal = "operator"
    with pytest.raises(CustomerSandboxProvisioningError, match="retryable"):
        store.provision_sandbox(
            approved.sandbox_id,
            expected_revision=approved.revision,
            idempotency_key="partial-provision",
        )
    pending = store.get_sandbox(approved.sandbox_id)
    assert pending.state == "provisioning"
    with pytest.raises(CustomerSandboxConflict, match="retry_required"):
        store.provision_sandbox(
            approved.sandbox_id,
            expected_revision=approved.revision,
            idempotency_key="partial-provision",
        )
    assert store.get_sandbox(approved.sandbox_id).attempts == 1
    recovered = store.provision_sandbox(
        pending.sandbox_id,
        expected_revision=pending.revision,
        idempotency_key="partial-retry",
        retry=True,
    )
    assert recovered.state == "active"
    assert len(list((tmp_path / "sandboxes" / "tenants").rglob("*-*.json"))) == 1


@pytest.mark.parametrize(
    "provisioner_type",
    [HardCrashesBeforeApplyOnce, HardCrashesAfterApplyOnce],
)
def test_same_key_provision_recovers_hard_crash_around_apply(
    tmp_path: Path,
    provisioner_type: type[LocalCustomerSandboxProvisioner],
) -> None:
    authorities = Authorities()
    provisioner = provisioner_type(tmp_path / "sandboxes")
    store = _store(tmp_path, authorities, provisioner=provisioner)
    requested = _request(store)
    authorities.principal = "reviewer"
    approved = store.approve_sandbox(
        requested.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key="hard-crash-approve",
    )
    authorities.principal = "operator"

    with pytest.raises(SystemExit, match="simulated hard crash"):
        store.provision_sandbox(
            approved.sandbox_id,
            expected_revision=approved.revision,
            idempotency_key="hard-crash-provision",
        )

    recovered = store.provision_sandbox(
        approved.sandbox_id,
        expected_revision=approved.revision,
        idempotency_key="hard-crash-provision",
    )
    assert recovered.state == "active"
    assert store.verify_integrity()["valid"] is True


def test_set_status_exact_predecessor_retry_adopts_durable_successor(
    tmp_path: Path,
) -> None:
    authorities = Authorities()
    provisioner = LocalCustomerSandboxProvisioner(tmp_path / "sandboxes")
    store = _store(tmp_path, authorities, provisioner=provisioner)
    active = _activate(store, authorities)
    predecessor = active.workspace_sha256
    assert predecessor is not None

    changed = provisioner.set_status(
        target_sandbox_id=active.target_sandbox_id,
        expected_workspace_sha256=predecessor,
        status="suspended",
    )
    replayed = provisioner.set_status(
        target_sandbox_id=active.target_sandbox_id,
        expected_workspace_sha256=predecessor,
        status="suspended",
    )

    assert replayed.no_change is True
    assert replayed.workspace_sha256 == changed.workspace_sha256


def test_apply_rejects_valid_same_owner_drift_and_corrupt_registry(
    tmp_path: Path,
) -> None:
    authorities = Authorities()
    provisioner = LocalCustomerSandboxProvisioner(tmp_path / "sandboxes")
    store = _store(tmp_path, authorities, provisioner=provisioner)
    active = _activate(store, authorities)
    assert active.workspace_sha256 is not None
    with store._connection() as connection:
        snapshot = store._snapshot(connection, active)

    drifted = provisioner.set_status(
        target_sandbox_id=active.target_sandbox_id,
        expected_workspace_sha256=active.workspace_sha256,
        status="suspended",
    )
    with pytest.raises(CustomerSandboxConflict, match="target_authority_changed"):
        provisioner.apply(
            snapshot,
            expected_workspace_sha256=active.workspace_sha256,
        )
    assert provisioner.inspect(active.target_sandbox_id).workspace_sha256 == drifted.workspace_sha256

    registry_path = provisioner.root / "sandbox-tenant-registry.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    registry["sandboxes"][0]["workspace_sha256"] = "0" * 64
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    with pytest.raises(CustomerSandboxIntegrityError, match="target_authority_corrupt"):
        provisioner.apply(
            snapshot,
            expected_workspace_sha256=active.workspace_sha256,
        )


def test_suspend_resume_fresh_resync_expiry_and_destroy(tmp_path: Path) -> None:
    authorities = Authorities()
    store = _store(tmp_path, authorities)
    active = _activate(store, authorities)
    suspended = store.suspend_sandbox(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key="suspend-1",
    )
    resumed = store.resume_sandbox(
        active.sandbox_id,
        expected_revision=suspended.revision,
        idempotency_key="resume-1",
    )
    with pytest.raises(CustomerSandboxConflict, match="resync_no_change"):
        store.request_resync(
            active.sandbox_id,
            expected_revision=resumed.revision,
            idempotency_key="no-change-resync",
        )
    authorities.config["ai_governance"] = {
        "enabled": True,
        "mode": "strict-review",
        "limits": {"items": 2},
    }
    authorities.revision += 1
    authorities.principal = "resync-requester"
    resync = store.request_resync(
        active.sandbox_id,
        expected_revision=resumed.revision,
        idempotency_key="resync-request",
    )
    authorities.principal = "resync-approver"
    resync = store.approve_sandbox(
        active.sandbox_id,
        expected_revision=resync.revision,
        idempotency_key="resync-approve",
    )
    authorities.principal = "operator"
    active = store.provision_sandbox(
        active.sandbox_id,
        expected_revision=resync.revision,
        idempotency_key="resync-provision",
    )
    suspended = store.suspend_sandbox(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key="suspend-for-destroy",
    )
    authorities.principal = "destroy-requester"
    destroy_requested = store.request_destroy(
        active.sandbox_id,
        expected_revision=suspended.revision,
        idempotency_key="destroy-request",
    )
    with pytest.raises(CustomerSandboxPermissionDenied, match="four_eyes"):
        store.approve_destroy(
            active.sandbox_id,
            expected_revision=destroy_requested.revision,
            idempotency_key="destroy-same-approver",
        )
    authorities.principal = "destroy-approver"
    destroy_approved = store.approve_destroy(
        active.sandbox_id,
        expected_revision=destroy_requested.revision,
        idempotency_key="destroy-approve",
    )
    authorities.principal = "destroy-operator"
    destroyed = store.destroy_sandbox(
        active.sandbox_id,
        expected_revision=destroy_approved.revision,
        idempotency_key="destroy-final",
    )
    assert destroyed.state == "destroyed"
    assert not list((tmp_path / "sandboxes" / "tenants").iterdir())
    assert store.verify_integrity()["valid"] is True


def test_concurrent_cas_allows_one_transition(tmp_path: Path) -> None:
    authorities = Authorities()
    store = _store(tmp_path, authorities)
    active = _activate(store, authorities)

    def suspend(key: str):
        try:
            return store.suspend_sandbox(
                active.sandbox_id,
                expected_revision=active.revision,
                idempotency_key=key,
            ).state
        except CustomerSandboxConflict as exc:
            return exc.error_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(suspend, ("concurrent-a", "concurrent-b")))
    assert results.count("suspended") == 1
    assert results.count("sandbox_revision_conflict") == 1


def test_target_collision_and_path_traversal_are_confined(tmp_path: Path) -> None:
    authorities = Authorities()
    provisioner = LocalCustomerSandboxProvisioner(tmp_path / "sandboxes")
    store = _store(tmp_path, authorities, provisioner=provisioner)
    with pytest.raises((CustomerSandboxValidationError, ValueError)):
        store.request_sandbox(
            "path-traversal",
            source_tenant_id="production-a",
            target_sandbox_id="../outside",
            module_allowlist=("ai_governance",),
            expires_at=NOW + 3_600,
            retained_until=NOW + 7_200,
            plan="sandbox-small",
            quota_bytes=8_192,
            idempotency_key="path-traversal",
        )
    assert not (tmp_path / "outside").exists()
    _request(store)
    with pytest.raises(CustomerSandboxConflict, match="collision"):
        store.request_sandbox(
            "second-operation",
            source_tenant_id="production-a",
            target_sandbox_id="production-a-sandbox",
            module_allowlist=("ai_governance",),
            expires_at=NOW + 3_600,
            retained_until=NOW + 7_200,
            plan="sandbox-small",
            quota_bytes=8_192,
            idempotency_key="target-collision",
        )


def test_tampered_idempotency_replay_and_integrity_scan_fail_closed(tmp_path: Path) -> None:
    authorities = Authorities()
    store = _store(tmp_path, authorities)
    _request(store)
    database = tmp_path / "lifecycle.sqlite3"
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT key_sha256,result_json FROM customer_sandbox_operations"
        ).fetchone()
        assert row is not None
        payload = json.loads(row[1])
        payload["state"] = "active"
        connection.execute(
            "UPDATE customer_sandbox_operations SET result_json=? WHERE key_sha256=?",
            (json.dumps(payload), row[0]),
        )
    with pytest.raises(CustomerSandboxIntegrityError, match="record_corrupt"):
        _request(store)
    with pytest.raises(CustomerSandboxIntegrityError, match="operation_corrupt"):
        store.verify_integrity()


def _destroy_approved(store: CustomerSandboxLifecycleStore, authorities: Authorities):
    active = _activate(store, authorities)
    suspended = store.suspend_sandbox(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key="destroy-helper-suspend",
    )
    authorities.principal = "destroy-helper-requester"
    requested = store.request_destroy(
        active.sandbox_id,
        expected_revision=suspended.revision,
        idempotency_key="destroy-helper-request",
    )
    authorities.principal = "destroy-helper-approver"
    return store.approve_destroy(
        active.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key="destroy-helper-approve",
    )


def test_destroy_rechecks_exact_owner_before_recursive_delete(tmp_path: Path) -> None:
    authorities = Authorities()
    store = _store(tmp_path, authorities)
    approved = _destroy_approved(store, authorities)
    owner = next((tmp_path / "sandboxes" / "tenants").rglob("owner.json"))
    payload = json.loads(owner.read_text(encoding="utf-8"))
    payload["sandbox_id"] = "attacker-owned"
    owner.write_text(json.dumps(payload), encoding="utf-8")
    authorities.principal = "destroy-helper-operator"
    with pytest.raises(CustomerSandboxConflict, match="target_authority_changed"):
        store.destroy_sandbox(
            approved.sandbox_id,
            expected_revision=approved.revision,
            idempotency_key="destroy-owner-tampered",
        )
    assert owner.exists()


def test_destructive_and_tombstone_replay_precede_invalid_clock(tmp_path: Path) -> None:
    authorities = Authorities()
    store = _store(tmp_path, authorities)
    approved = _destroy_approved(store, authorities)
    authorities.principal = "destroy-replay-operator"
    destroyed = store.destroy_sandbox(
        approved.sandbox_id,
        expected_revision=approved.revision,
        idempotency_key="destroy-invalid-clock-replay",
    )
    authorities.now = float("nan")
    assert (
        store.destroy_sandbox(
            approved.sandbox_id,
            expected_revision=approved.revision,
            idempotency_key="destroy-invalid-clock-replay",
        )
        == destroyed
    )

    authorities.now = destroyed.retained_until + 1
    authorities.principal = "purge-replay-operator"
    tombstone = store.purge_destroyed_sandbox(
        destroyed.sandbox_id,
        expected_revision=destroyed.revision,
        idempotency_key="purge-invalid-clock-replay",
    )
    authorities.now = float("nan")
    assert (
        store.purge_destroyed_sandbox(
            destroyed.sandbox_id,
            expected_revision=destroyed.revision,
            idempotency_key="purge-invalid-clock-replay",
        )
        == tombstone
    )


def test_retention_purge_is_bounded_to_elapsed_destroyed_records(tmp_path: Path) -> None:
    authorities = Authorities()
    store = _store(tmp_path, authorities)
    active = _activate(store, authorities)
    with pytest.raises(CustomerSandboxConflict, match="requires_destroyed"):
        store.purge_destroyed_sandbox(
            active.sandbox_id,
            expected_revision=active.revision,
            idempotency_key="purge-active",
        )
    suspended = store.suspend_sandbox(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key="purge-suspend",
    )
    authorities.principal = "purge-requester"
    requested = store.request_destroy(
        active.sandbox_id,
        expected_revision=suspended.revision,
        idempotency_key="purge-destroy-request",
    )
    authorities.principal = "purge-approver"
    approved = store.approve_destroy(
        active.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key="purge-destroy-approve",
    )
    authorities.principal = "purge-operator"
    destroyed = store.destroy_sandbox(
        active.sandbox_id,
        expected_revision=approved.revision,
        idempotency_key="purge-destroy",
    )
    with pytest.raises(CustomerSandboxConflict, match="retention_not_elapsed"):
        store.purge_destroyed_sandbox(
            destroyed.sandbox_id,
            expected_revision=destroyed.revision,
            idempotency_key="purge-final",
        )
    authorities.now = NOW + 7_201
    tombstone = store.purge_destroyed_sandbox(
        destroyed.sandbox_id,
        expected_revision=destroyed.revision,
        idempotency_key="purge-final",
    )
    assert tombstone == store.get_tombstone(destroyed.sandbox_id)
    assert tombstone == store.purge_destroyed_sandbox(
        destroyed.sandbox_id,
        expected_revision=destroyed.revision,
        idempotency_key="purge-final",
    )
    assert store.history(destroyed.sandbox_id)[0].action == "sandbox_retention_purged"
    integrity = store.verify_integrity()
    assert integrity["records"] == 0
    assert integrity["snapshots"] == 0
    assert integrity["operations"] == 0
    assert integrity["tombstones"] == 1


def test_workspace_quota_bounds_cumulative_snapshot_history(tmp_path: Path) -> None:
    authorities = Authorities()
    authorities.config = {
        "ai_governance": {"enabled": True, "risk_levels": ["review"] * 250}
    }
    store = _store(tmp_path, authorities)
    requested = store.request_sandbox(
        "quota-operation",
        source_tenant_id="production-a",
        target_sandbox_id="quota-sandbox",
        module_allowlist=("ai_governance",),
        expires_at=NOW + 3_600,
        retained_until=NOW + 7_200,
        plan="sandbox-small",
        quota_bytes=4_096,
        max_attempts=1,
        idempotency_key="quota-request",
    )
    authorities.principal = "quota-approver"
    approved = store.approve_sandbox(
        requested.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key="quota-approve",
    )
    authorities.principal = "quota-operator"
    active = store.provision_sandbox(
        approved.sandbox_id,
        expected_revision=approved.revision,
        idempotency_key="quota-provision",
    )
    authorities.config["ai_governance"] = {
        "enabled": True,
        "risk_levels": ["monitor"] * 250,
    }
    authorities.revision += 1
    authorities.principal = "quota-resync-requester"
    resync = store.request_resync(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key="quota-resync-request",
    )
    authorities.principal = "quota-resync-approver"
    resync = store.approve_sandbox(
        active.sandbox_id,
        expected_revision=resync.revision,
        idempotency_key="quota-resync-approve",
    )
    authorities.principal = "quota-operator"
    with pytest.raises(CustomerSandboxProvisioningError, match="retryable"):
        store.provision_sandbox(
            active.sandbox_id,
            expected_revision=resync.revision,
            idempotency_key="quota-resync-provision",
        )
    files = [path for path in (tmp_path / "sandboxes" / "tenants").rglob("*") if path.is_file()]
    assert sum(path.stat().st_size for path in files) <= 4_096
    assert len([path for path in files if path.parent.name == "snapshots"]) == 1
    restored = store.get_sandbox(active.sandbox_id)
    assert restored.state == "active"
    assert restored.snapshot_revision == 1
    assert restored.last_error_code == "sandbox_resync_rolled_back"


class StatusAckLostProvisioner(LocalCustomerSandboxProvisioner):
    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.fail_status: str | None = None

    def set_status(self, **kwargs):
        receipt = super().set_status(**kwargs)
        if kwargs["status"] == self.fail_status:
            self.fail_status = None
            raise RuntimeError("simulated lost acknowledgement")
        return receipt


def test_status_transitions_adopt_deterministic_lost_ack(tmp_path: Path) -> None:
    authorities = Authorities()
    provisioner = StatusAckLostProvisioner(tmp_path / "sandboxes")
    store = _store(tmp_path, authorities, provisioner=provisioner)
    active = _activate(store, authorities)
    provisioner.fail_status = "suspended"
    with pytest.raises(CustomerSandboxProvisioningError, match="retryable"):
        store.suspend_sandbox(
            active.sandbox_id,
            expected_revision=active.revision,
            idempotency_key="lost-suspend",
        )
    assert store.get_sandbox(active.sandbox_id).state == "active"
    suspended = store.suspend_sandbox(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key="lost-suspend",
    )
    provisioner.fail_status = "active"
    with pytest.raises(CustomerSandboxProvisioningError, match="retryable"):
        store.resume_sandbox(
            active.sandbox_id,
            expected_revision=suspended.revision,
            idempotency_key="lost-resume",
        )
    resumed = store.resume_sandbox(
        active.sandbox_id,
        expected_revision=suspended.revision,
        idempotency_key="lost-resume",
    )
    authorities.now = resumed.expires_at
    provisioner.fail_status = "expired"
    with pytest.raises(CustomerSandboxProvisioningError, match="retryable"):
        store.expire_sandbox(
            active.sandbox_id,
            expected_revision=resumed.revision,
            idempotency_key="lost-expire",
        )
    expired = store.expire_sandbox(
        active.sandbox_id,
        expected_revision=resumed.revision,
        idempotency_key="lost-expire",
    )
    assert expired.state == "expired"


class ClockAdvancingProvisioner(LocalCustomerSandboxProvisioner):
    def __init__(self, root: Path, authorities: Authorities) -> None:
        super().__init__(root)
        self.authorities = authorities

    def apply(self, snapshot, *, expected_workspace_sha256):
        receipt = super().apply(
            snapshot,
            expected_workspace_sha256=expected_workspace_sha256,
        )
        self.authorities.now = snapshot.expires_at
        return receipt


class StagedExpiryClock:
    def __init__(self) -> None:
        self.expiry: float | None = None
        self.reads = 0

    def __call__(self) -> float:
        if self.expiry is None:
            return NOW
        self.reads += 1
        return NOW if self.reads == 1 else self.expiry


class ExpiryRecoveryProvisioner(LocalCustomerSandboxProvisioner):
    def __init__(
        self,
        root: Path,
        authorities: Authorities,
        *,
        boundary: str,
        fault: str,
        staged_clock: StagedExpiryClock | None = None,
    ) -> None:
        super().__init__(root)
        self.authorities = authorities
        self.boundary = boundary
        self.fault = fault
        self.staged_clock = staged_clock
        self.armed = True
        self.fail_expiry = False

    def apply(self, snapshot, *, expected_workspace_sha256):
        receipt = super().apply(
            snapshot,
            expected_workspace_sha256=expected_workspace_sha256,
        )
        if self.armed:
            self.armed = False
            self.fail_expiry = True
            if self.boundary == "inner":
                self.authorities.now = snapshot.expires_at
            else:
                assert self.staged_clock is not None
                self.staged_clock.expiry = snapshot.expires_at
        return receipt

    def _save_registry(self, records):
        if (
            self.fail_expiry
            and self.fault == "oserror"
            and any(row.get("status") == "expired" for row in records.values())
        ):
            self.fail_expiry = False
            raise OSError("simulated expiry manifest-before-registry failure")
        return super()._save_registry(records)

    def set_status(self, *, target_sandbox_id, expected_workspace_sha256, status):
        receipt = super().set_status(
            target_sandbox_id=target_sandbox_id,
            expected_workspace_sha256=expected_workspace_sha256,
            status=status,
        )
        if self.fail_expiry and self.fault == "system_exit" and status == "expired":
            self.fail_expiry = False
            raise SystemExit("simulated process death after durable expiry status")
        return receipt


def test_expiry_blocks_delayed_provision_and_resume_and_closes_finalization(
    tmp_path: Path,
) -> None:
    authorities = Authorities()
    store = _store(tmp_path / "delayed", authorities)
    requested = _request(store)
    authorities.principal = "expiry-approver"
    approved = store.approve_sandbox(
        requested.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key="expiry-approve",
    )
    authorities.now = approved.expires_at
    with pytest.raises(CustomerSandboxConflict, match="expired"):
        store.provision_sandbox(
            approved.sandbox_id,
            expected_revision=approved.revision,
            idempotency_key="expired-before-provision",
        )
    assert not list((tmp_path / "delayed" / "sandboxes" / "tenants").iterdir())

    authorities = Authorities()
    store = _store(tmp_path / "resume", authorities)
    active = _activate(store, authorities)
    suspended = store.suspend_sandbox(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key="expiry-suspend",
    )
    authorities.now = suspended.expires_at
    with pytest.raises(CustomerSandboxConflict, match="expired"):
        store.resume_sandbox(
            suspended.sandbox_id,
            expected_revision=suspended.revision,
            idempotency_key="expired-resume",
        )
    assert store.get_sandbox(suspended.sandbox_id).state == "suspended"

    authorities = Authorities()
    advancing = ClockAdvancingProvisioner(tmp_path / "crossing" / "sandboxes", authorities)
    store = _store(tmp_path / "crossing", authorities, provisioner=advancing)
    requested = _request(store)
    authorities.principal = "crossing-approver"
    approved = store.approve_sandbox(
        requested.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key="crossing-approve",
    )
    completed = store.provision_sandbox(
        approved.sandbox_id,
        expected_revision=approved.revision,
        idempotency_key="crossing-provision",
    )
    assert completed.state == "expired"
    assert advancing.inspect(completed.target_sandbox_id).status == "expired"


@pytest.mark.parametrize("boundary", ["inner", "outer"])
@pytest.mark.parametrize("fault", ["oserror", "system_exit"])
def test_expiry_status_write_splits_reconcile_on_exact_key(
    tmp_path: Path,
    boundary: str,
    fault: str,
) -> None:
    authorities = Authorities()
    staged_clock = StagedExpiryClock() if boundary == "outer" else None
    provisioner = ExpiryRecoveryProvisioner(
        tmp_path / "sandboxes",
        authorities,
        boundary=boundary,
        fault=fault,
        staged_clock=staged_clock,
    )
    if staged_clock is None:
        store = _store(tmp_path, authorities, provisioner=provisioner)
    else:
        store = CustomerSandboxLifecycleStore(
            tmp_path / "lifecycle.sqlite3",
            source_resolver=authorities.source,
            principal_resolver=lambda: authorities.principal,
            provisioner=provisioner,
            config_gate=authorities.require_enabled,
            target_collision_resolver=(
                lambda target: target in authorities.production_targets
            ),
            clock=staged_clock,
        )
    requested = _request(store)
    authorities.principal = "expiry-recovery-approver"
    approved = store.approve_sandbox(
        requested.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key="expiry-recovery-approve",
    )
    authorities.principal = "expiry-recovery-operator"
    if fault == "system_exit":
        with pytest.raises(SystemExit, match="durable expiry"):
            store.provision_sandbox(
                approved.sandbox_id,
                expected_revision=approved.revision,
                idempotency_key="expiry-recovery-provision",
            )
        completed = store.provision_sandbox(
            approved.sandbox_id,
            expected_revision=approved.revision,
            idempotency_key="expiry-recovery-provision",
        )
    else:
        completed = store.provision_sandbox(
            approved.sandbox_id,
            expected_revision=approved.revision,
            idempotency_key="expiry-recovery-provision",
        )
        assert store.provision_sandbox(
            approved.sandbox_id,
            expected_revision=approved.revision,
            idempotency_key="expiry-recovery-provision",
        ) == completed
    authority = provisioner.inspect(completed.target_sandbox_id)
    assert completed.state == "expired"
    assert authority is not None
    assert authority.status == "expired"
    assert authority.workspace_sha256 == completed.workspace_sha256


def test_destroy_recovers_rmtree_before_registry_ack_and_rejects_tamper(
    tmp_path: Path,
) -> None:
    authorities = Authorities()
    provisioner = LocalCustomerSandboxProvisioner(tmp_path / "sandboxes")
    store = _store(tmp_path, authorities, provisioner=provisioner)
    approved = _destroy_approved(store, authorities)
    target = next((tmp_path / "sandboxes" / "tenants").iterdir())
    shutil.rmtree(target)
    authorities.principal = "destroy-recovery-operator"
    destroyed = store.destroy_sandbox(
        approved.sandbox_id,
        expected_revision=approved.revision,
        idempotency_key="destroy-lost-ack",
    )
    assert destroyed.state == "destroyed"

    authorities = Authorities()
    second_root = tmp_path / "tampered"
    provisioner = LocalCustomerSandboxProvisioner(second_root / "sandboxes")
    store = _store(second_root, authorities, provisioner=provisioner)
    approved = _destroy_approved(store, authorities)
    target = next((second_root / "sandboxes" / "tenants").iterdir())
    shutil.rmtree(target)
    registry = second_root / "sandboxes" / "sandbox-tenant-registry.json"
    payload = json.loads(registry.read_text(encoding="utf-8"))
    payload["sandboxes"][0]["workspace_sha256"] = "0" * 64
    registry.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CustomerSandboxIntegrityError, match="authority_corrupt"):
        store.destroy_sandbox(
            approved.sandbox_id,
            expected_revision=approved.revision,
            idempotency_key="destroy-tampered-registry",
        )


def test_destroy_same_key_recovers_partial_quarantine_rmtree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorities = Authorities()
    provisioner = LocalCustomerSandboxProvisioner(tmp_path / "sandboxes")
    store = _store(tmp_path, authorities, provisioner=provisioner)
    approved = _destroy_approved(store, authorities)
    target = provisioner._target_path(approved.target_sandbox_id)
    quarantine = provisioner._quarantine_path(approved.target_sandbox_id)
    real_rmtree = shutil.rmtree
    crashed = False

    def partial_rmtree(path, *args, **kwargs):
        nonlocal crashed
        selected = Path(path)
        if selected == quarantine and not crashed:
            crashed = True
            (selected / "current.json").unlink()
            raise SystemExit("simulated process death during partial rmtree")
        return real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(shutil, "rmtree", partial_rmtree)
    authorities.principal = "partial-destroy-operator"
    with pytest.raises(SystemExit, match="partial rmtree"):
        store.destroy_sandbox(
            approved.sandbox_id,
            expected_revision=approved.revision,
            idempotency_key="partial-destroy-final",
        )
    assert not target.exists()
    assert quarantine.exists()
    assert not (quarantine / "current.json").exists()

    destroyed = store.destroy_sandbox(
        approved.sandbox_id,
        expected_revision=approved.revision,
        idempotency_key="partial-destroy-final",
    )
    assert destroyed.state == "destroyed"
    assert not quarantine.exists()
    assert not provisioner._destroy_marker_path(approved.target_sandbox_id).exists()


def test_destroy_rejects_link_swap_and_handles_worst_case_name(tmp_path: Path) -> None:
    authorities = Authorities()
    store = _store(tmp_path / "link", authorities)
    approved = _destroy_approved(store, authorities)
    target = next((tmp_path / "link" / "sandboxes" / "tenants").iterdir())
    saved = target.with_name("saved-owned-target")
    outside = tmp_path / "outside-do-not-delete"
    outside.mkdir()
    marker = outside / "marker.txt"
    marker.write_text("preserve", encoding="utf-8")
    target.rename(saved)
    try:
        _make_directory_alias(outside, target)
    except OSError:
        pytest.skip("directory symlinks and junctions are unavailable on this host")
    with pytest.raises(CustomerSandboxIntegrityError, match="path_escape"):
        store.destroy_sandbox(
            approved.sandbox_id,
            expected_revision=approved.revision,
            idempotency_key="destroy-link-swap",
        )
    assert marker.read_text(encoding="utf-8") == "preserve"

    authorities = Authorities()
    root = tmp_path / "long-name"
    store = _store(root, authorities)
    requested = store.request_sandbox(
        "long-operation",
        source_tenant_id="production-a",
        target_sandbox_id="t" * 128,
        module_allowlist=MODULES,
        expires_at=NOW + 3_600,
        retained_until=NOW + 7_200,
        plan="sandbox-small",
        quota_bytes=64 * 1024,
        idempotency_key="long-request",
    )
    authorities.principal = "long-approver"
    approved = store.approve_sandbox(
        requested.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key="long-approve",
    )
    active = store.provision_sandbox(
        approved.sandbox_id,
        expected_revision=approved.revision,
        idempotency_key="long-provision",
    )
    suspended = store.suspend_sandbox(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key="long-suspend",
    )
    authorities.principal = "long-destroy-requester"
    requested = store.request_destroy(
        active.sandbox_id,
        expected_revision=suspended.revision,
        idempotency_key="long-destroy-request",
    )
    authorities.principal = "long-destroy-approver"
    approved = store.approve_destroy(
        active.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key="long-destroy-approve",
    )
    destroyed = store.destroy_sandbox(
        active.sandbox_id,
        expected_revision=approved.revision,
        idempotency_key="long-destroy",
    )
    assert destroyed.state == "destroyed"


class RegistryWriteAckLostProvisioner(LocalCustomerSandboxProvisioner):
    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.fail_next_registry_write = False

    def _save_registry(self, records):
        if self.fail_next_registry_write:
            self.fail_next_registry_write = False
            raise OSError("simulated crash between manifest and registry writes")
        return super()._save_registry(records)


class CollisionJournalProvisioner(LocalCustomerSandboxProvisioner):
    def __init__(self, root: Path, authorities: Authorities) -> None:
        super().__init__(root)
        self.authorities = authorities
        self.trigger_after_revision: int | None = None
        self.hard_crash_after_cleanup = False
        self.crash_recreation_registry = False

    def apply(self, snapshot, *, expected_workspace_sha256):
        receipt = super().apply(
            snapshot,
            expected_workspace_sha256=expected_workspace_sha256,
        )
        if self.trigger_after_revision == snapshot.snapshot_revision:
            self.trigger_after_revision = None
            self.authorities.production_targets.add(snapshot.target_sandbox_id)
        return receipt

    def begin_collision_cleanup(self, snapshot, *, expected_workspace_sha256):
        receipt = super().begin_collision_cleanup(
            snapshot,
            expected_workspace_sha256=expected_workspace_sha256,
        )
        if self.hard_crash_after_cleanup:
            self.hard_crash_after_cleanup = False
            raise SystemExit("simulated process death after collision cleanup")
        return receipt

    def _save_registry(self, records):
        if self.crash_recreation_registry:
            self.crash_recreation_registry = False
            raise SystemExit("simulated process death before recreation registry save")
        return super()._save_registry(records)


def test_status_transition_reconciles_manifest_registry_split_brain(tmp_path: Path) -> None:
    authorities = Authorities()
    provisioner = RegistryWriteAckLostProvisioner(tmp_path / "sandboxes")
    store = _store(tmp_path, authorities, provisioner=provisioner)
    active = _activate(store, authorities)
    provisioner.fail_next_registry_write = True
    with pytest.raises(CustomerSandboxProvisioningError, match="retryable"):
        store.suspend_sandbox(
            active.sandbox_id,
            expected_revision=active.revision,
            idempotency_key="split-suspend",
        )
    suspended = store.suspend_sandbox(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key="split-suspend",
    )
    assert suspended.state == "suspended"
    assert provisioner.inspect(suspended.target_sandbox_id).status == "suspended"


def test_production_target_collision_blocks_activation_but_allows_cleanup(
    tmp_path: Path,
) -> None:
    authorities = Authorities()
    store = _store(tmp_path / "before", authorities)
    requested = _request(store)
    authorities.principal = "collision-approver"
    approved = store.approve_sandbox(
        requested.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key="collision-approve",
    )
    authorities.production_targets.add(approved.target_sandbox_id)
    with pytest.raises(CustomerSandboxConflict, match="target_collision"):
        store.provision_sandbox(
            approved.sandbox_id,
            expected_revision=approved.revision,
            idempotency_key="collision-provision",
        )
    assert not list((tmp_path / "before" / "sandboxes" / "tenants").iterdir())

    authorities = Authorities()
    store = _store(tmp_path / "active", authorities)
    active = _activate(store, authorities)
    authorities.production_targets.add(active.target_sandbox_id)
    with pytest.raises(CustomerSandboxConflict, match="target_collision"):
        store.request_resync(
            active.sandbox_id,
            expected_revision=active.revision,
            idempotency_key="collision-resync",
        )
    suspended = store.suspend_sandbox(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key="collision-suspend",
    )
    with pytest.raises(CustomerSandboxConflict, match="target_collision"):
        store.resume_sandbox(
            active.sandbox_id,
            expected_revision=suspended.revision,
            idempotency_key="collision-resume",
        )
    authorities.principal = "collision-destroy-requester"
    requested = store.request_destroy(
        active.sandbox_id,
        expected_revision=suspended.revision,
        idempotency_key="collision-destroy-request",
    )
    authorities.principal = "collision-destroy-approver"
    approved = store.approve_destroy(
        active.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key="collision-destroy-approve",
    )
    destroyed = store.destroy_sandbox(
        active.sandbox_id,
        expected_revision=approved.revision,
        idempotency_key="collision-destroy",
    )
    assert destroyed.state == "destroyed"


@pytest.mark.parametrize("window", ["pre_manifest", "manifest_before_registry"])
def test_completed_collision_marker_recovers_partial_recreation_same_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    window: str,
) -> None:
    authorities = Authorities()
    provisioner = CollisionJournalProvisioner(tmp_path / "sandboxes", authorities)
    store = _store(tmp_path, authorities, provisioner=provisioner)
    requested = _request(store)
    authorities.principal = "journal-approver"
    approved = store.approve_sandbox(
        requested.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key="journal-approve",
    )
    provisioner.trigger_after_revision = 1
    provisioner.hard_crash_after_cleanup = True
    authorities.principal = "journal-operator"
    with pytest.raises(SystemExit, match="after collision cleanup"):
        store.provision_sandbox(
            approved.sandbox_id,
            expected_revision=approved.revision,
            idempotency_key="journal-provision",
        )
    marker = provisioner._collision_marker_path(approved.target_sandbox_id)
    assert provisioner._read_collision_marker(marker)["state"] == "completed"
    with pytest.raises(CustomerSandboxConflict, match="target_collision"):
        store.provision_sandbox(
            approved.sandbox_id,
            expected_revision=approved.revision,
            idempotency_key="journal-provision",
        )

    authorities.production_targets.clear()
    if window == "pre_manifest":
        real_atomic_write = lifecycle_module.atomic_write_text
        crashed = False

        def crash_before_manifest(path, value, *args, **kwargs):
            nonlocal crashed
            if Path(path).name == "current.json" and not crashed:
                crashed = True
                raise SystemExit("simulated process death before recreation manifest")
            return real_atomic_write(path, value, *args, **kwargs)

        monkeypatch.setattr(
            lifecycle_module,
            "atomic_write_text",
            crash_before_manifest,
        )
    else:
        provisioner.crash_recreation_registry = True
    with pytest.raises(SystemExit, match="recreation"):
        store.provision_sandbox(
            approved.sandbox_id,
            expected_revision=approved.revision,
            idempotency_key="journal-provision",
        )

    completed = store.provision_sandbox(
        approved.sandbox_id,
        expected_revision=approved.revision,
        idempotency_key="journal-provision",
    )
    assert completed.state == "active"
    assert provisioner.inspect(completed.target_sandbox_id) is not None
    assert not marker.exists()
    assert not provisioner._provision_marker_path(
        completed.target_sandbox_id
    ).exists()


def test_target_collision_authority_is_mandatory(tmp_path: Path) -> None:
    authorities = Authorities()
    with pytest.raises(CustomerSandboxConfigError, match="target_authority_unavailable"):
        CustomerSandboxLifecycleStore(
            tmp_path / "missing-target-authority.sqlite3",
            source_resolver=authorities.source,
            principal_resolver=lambda: authorities.principal,
            provisioner=LocalCustomerSandboxProvisioner(tmp_path / "sandboxes"),
            config_gate=authorities.require_enabled,
            clock=lambda: authorities.now,
        )


class AlwaysFailsProvisioner(LocalCustomerSandboxProvisioner):
    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.fail = True

    def apply(self, snapshot, *, expected_workspace_sha256):
        if self.fail:
            raise RuntimeError("simulated terminal create failure")
        return super().apply(
            snapshot,
            expected_workspace_sha256=expected_workspace_sha256,
        )


def _terminal_create_failure(
    tmp_path: Path,
    authorities: Authorities,
    provisioner: AlwaysFailsProvisioner,
):
    store = _store(tmp_path, authorities, provisioner=provisioner)
    requested = store.request_sandbox(
        "terminal-create",
        source_tenant_id="production-a",
        target_sandbox_id="terminal-create-target",
        module_allowlist=("ai_governance",),
        expires_at=NOW + 3_600,
        retained_until=NOW + 7_200,
        plan="sandbox-small",
        quota_bytes=16_384,
        max_attempts=1,
        idempotency_key="terminal-create-request",
    )
    authorities.principal = "terminal-create-approver"
    approved = store.approve_sandbox(
        requested.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key="terminal-create-approve",
    )
    authorities.principal = "terminal-create-operator"
    with pytest.raises(CustomerSandboxProvisioningError, match="retryable"):
        store.provision_sandbox(
            approved.sandbox_id,
            expected_revision=approved.revision,
            idempotency_key="terminal-create-provision",
        )
    return store, store.get_sandbox(approved.sandbox_id)


def _four_eyes_abandon(store, authorities, record, *, suffix: str):
    authorities.principal = f"abandon-requester-{suffix}"
    requested = store.request_abandon(
        record.sandbox_id,
        expected_revision=record.revision,
        idempotency_key=f"abandon-request-{suffix}",
    )
    with pytest.raises(CustomerSandboxPermissionDenied, match="four_eyes"):
        store.approve_abandon(
            record.sandbox_id,
            expected_revision=requested.revision,
            idempotency_key=f"abandon-same-{suffix}",
        )
    authorities.principal = f"abandon-approver-{suffix}"
    approved = store.approve_abandon(
        record.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key=f"abandon-approve-{suffix}",
    )
    return store.abandon_failed_sandbox(
        record.sandbox_id,
        expected_revision=approved.revision,
        idempotency_key=f"abandon-final-{suffix}",
    )


@pytest.mark.parametrize("state", ["requested", "approved"])
def test_stale_initial_request_or_approval_has_four_eyes_abandon(
    tmp_path: Path,
    state: str,
) -> None:
    authorities = Authorities()
    store = _store(tmp_path, authorities)
    record = _request(store, modules=("ai_governance",))
    if state == "approved":
        authorities.principal = "stale-create-approver"
        record = store.approve_sandbox(
            record.sandbox_id,
            expected_revision=record.revision,
            idempotency_key="stale-create-approve",
        )
    tombstone = _four_eyes_abandon(store, authorities, record, suffix=state)
    assert tombstone.sandbox_id == record.sandbox_id
    assert store.list_sandboxes() == ()


@pytest.mark.parametrize("boundary", ["owner", "snapshot", "current", "registry"])
def test_terminal_create_partial_boundaries_are_exactly_abandonable(
    tmp_path: Path,
    boundary: str,
) -> None:
    authorities = Authorities()
    provisioner = AlwaysFailsProvisioner(tmp_path / "sandboxes")
    store, failed = _terminal_create_failure(tmp_path, authorities, provisioner)
    provisioner.fail = False
    with store._connection() as connection:
        snapshot = store._snapshot(connection, failed)
    provisioner.apply(snapshot, expected_workspace_sha256=failed.workspace_sha256)
    target = provisioner._target_path(failed.target_sandbox_id)
    registry = provisioner.root / "sandbox-tenant-registry.json"
    if boundary != "registry":
        registry.unlink()
    if boundary in {"owner", "snapshot"}:
        (target / "current.json").unlink()
    if boundary == "owner":
        shutil.rmtree(target / "snapshots")
    tombstone = _four_eyes_abandon(store, authorities, failed, suffix=boundary)
    assert tombstone.sandbox_id == failed.sandbox_id
    assert not target.exists()
    with pytest.raises(CustomerSandboxNotFound):
        store.get_sandbox(failed.sandbox_id)


def test_disabled_gate_allows_only_exact_owner_remediation(tmp_path: Path) -> None:
    authorities = Authorities()
    store = _store(tmp_path, authorities)
    active = _activate(store, authorities)
    authorities.gate = False
    assert store.status()["enabled"] is False
    assert store.get_sandbox(active.sandbox_id).state == "active"
    assert len(store.list_sandboxes()) == 1
    with pytest.raises(CustomerSandboxConfigError, match="disabled"):
        store.request_resync(
            active.sandbox_id,
            expected_revision=active.revision,
            idempotency_key="disabled-resync",
        )
    suspended = store.suspend_sandbox(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key="disabled-suspend",
    )
    authorities.principal = "disabled-destroy-requester"
    requested = store.request_destroy(
        active.sandbox_id,
        expected_revision=suspended.revision,
        idempotency_key="disabled-destroy-request",
    )
    authorities.principal = "disabled-destroy-approver"
    approved = store.approve_destroy(
        active.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key="disabled-destroy-approve",
    )
    destroyed = store.destroy_sandbox(
        active.sandbox_id,
        expected_revision=approved.revision,
        idempotency_key="disabled-destroy",
    )
    assert destroyed.state == "destroyed"


@pytest.mark.parametrize("approved", [False, True])
def test_resync_remediation_retires_proposal_and_replay_before_new_resync(
    tmp_path: Path,
    approved: bool,
) -> None:
    authorities = Authorities()
    store = _store(tmp_path, authorities)
    active = _activate(store, authorities)
    authorities.config["ai_governance"] = {"enabled": True, "mode": "monitor"}
    authorities.revision = 2
    authorities.principal = "resync-requester"
    proposal = store.request_resync(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key="reusable-resync-key",
    )
    if approved:
        authorities.principal = "resync-approver"
        proposal = store.approve_sandbox(
            active.sandbox_id,
            expected_revision=proposal.revision,
            idempotency_key="resync-approval",
        )
    suspended = store.suspend_sandbox(
        active.sandbox_id,
        expected_revision=proposal.revision,
        idempotency_key="resync-emergency-suspend",
    )
    assert suspended.snapshot_revision == 1
    resumed = store.resume_sandbox(
        active.sandbox_id,
        expected_revision=suspended.revision,
        idempotency_key="resync-emergency-resume",
    )
    authorities.principal = "resync-requester"
    replacement = store.request_resync(
        active.sandbox_id,
        expected_revision=resumed.revision,
        idempotency_key="reusable-resync-key",
    )
    assert replacement.snapshot_revision == 2
    assert store.verify_integrity()["resync_baselines"] == 1


def test_expired_pending_resync_can_enter_destroy_cleanup(tmp_path: Path) -> None:
    authorities = Authorities()
    store = _store(tmp_path, authorities)
    active = _activate(store, authorities)
    authorities.now = active.expires_at
    expired = store.expire_sandbox(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key="expire-before-resync",
    )
    authorities.config["ai_governance"] = {"enabled": True, "mode": "monitor"}
    authorities.revision = 2
    proposal = store.request_resync(
        active.sandbox_id,
        expected_revision=expired.revision,
        idempotency_key="expired-resync",
    )
    authorities.principal = "expired-destroy-requester"
    destroy_requested = store.request_destroy(
        active.sandbox_id,
        expected_revision=proposal.revision,
        idempotency_key="expired-destroy-request",
    )
    assert destroy_requested.snapshot_revision == 1


def test_existing_only_authority_is_exact_and_never_recreates_database(tmp_path: Path) -> None:
    authorities = Authorities()
    store = _store(tmp_path, authorities)
    assert store.list_sandboxes() == ()
    existing = CustomerSandboxLifecycleStore(
        tmp_path / "lifecycle.sqlite3",
        source_resolver=authorities.source,
        principal_resolver=lambda: authorities.principal,
        provisioner=LocalCustomerSandboxProvisioner(
            tmp_path / "sandboxes", existing_only=True
        ),
        config_gate=authorities.require_enabled,
        target_collision_resolver=lambda _target: False,
        clock=lambda: authorities.now,
        existing_only=True,
    )
    db = tmp_path / "lifecycle.sqlite3"
    db.unlink()
    with pytest.raises(CustomerSandboxConfigError, match="existing_authority_invalid"):
        existing.list_sandboxes()
    assert not db.exists()


@pytest.mark.parametrize("kind", ["zero", "malformed", "partial"])
def test_existing_only_rejects_uninitialized_database_without_writes(
    tmp_path: Path,
    kind: str,
) -> None:
    authorities = Authorities()
    _store(tmp_path, authorities)
    db = tmp_path / "lifecycle.sqlite3"
    if kind == "zero":
        db.write_bytes(b"")
    elif kind == "malformed":
        db.write_bytes(b"not a sqlite authority")
    else:
        db.unlink()
        connection = sqlite3.connect(db)
        connection.execute("CREATE TABLE customer_sandboxes(sandbox_id TEXT PRIMARY KEY)")
        connection.commit()
        connection.close()
    before = db.read_bytes()
    with pytest.raises(CustomerSandboxConfigError, match="existing_authority_invalid"):
        CustomerSandboxLifecycleStore(
            db,
            source_resolver=authorities.source,
            principal_resolver=lambda: authorities.principal,
            provisioner=LocalCustomerSandboxProvisioner(
                tmp_path / "sandboxes", existing_only=True
            ),
            config_gate=authorities.require_enabled,
            target_collision_resolver=lambda _target: False,
            clock=lambda: authorities.now,
            existing_only=True,
        )
    assert db.read_bytes() == before


def test_apply_rejects_interior_link_before_resync_write(tmp_path: Path) -> None:
    authorities = Authorities()
    provisioner = LocalCustomerSandboxProvisioner(tmp_path / "sandboxes")
    store = _store(tmp_path, authorities, provisioner=provisioner)
    active = _activate(store, authorities)
    target = provisioner._target_path(active.target_sandbox_id)
    snapshots = target / "snapshots"
    saved = target / "saved-snapshots"
    snapshots.rename(saved)
    outside = tmp_path / "outside-snapshots"
    outside.mkdir()
    try:
        _make_directory_alias(outside, snapshots)
    except OSError:
        pytest.skip("directory symlinks and junctions are unavailable on this host")
    authorities.config["ai_governance"] = {"enabled": True, "mode": "monitor"}
    authorities.revision = 2
    proposal = store.request_resync(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key="link-resync-request",
    )
    authorities.principal = "link-resync-approver"
    proposal = store.approve_sandbox(
        active.sandbox_id,
        expected_revision=proposal.revision,
        idempotency_key="link-resync-approve",
    )
    with pytest.raises(CustomerSandboxProvisioningError, match="retryable"):
        store.provision_sandbox(
            active.sandbox_id,
            expected_revision=proposal.revision,
            idempotency_key="link-resync-provision",
        )
    assert list(outside.iterdir()) == []


def test_verify_integrity_closes_malformed_snapshot_and_baseline_json(tmp_path: Path) -> None:
    authorities = Authorities()
    store = _store(tmp_path / "snapshot", authorities)
    _request(store)
    with sqlite3.connect(tmp_path / "snapshot" / "lifecycle.sqlite3") as connection:
        connection.execute(
            "UPDATE customer_sandbox_snapshots SET snapshot_json='{'"
        )
    with pytest.raises(CustomerSandboxIntegrityError, match="snapshot_history_corrupt"):
        store.verify_integrity()

    authorities = Authorities()
    store = _store(tmp_path / "baseline", authorities)
    active = _activate(store, authorities)
    authorities.config["ai_governance"] = {"enabled": True, "mode": "monitor"}
    authorities.revision = 2
    store.request_resync(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key="baseline-tamper-resync",
    )
    with sqlite3.connect(tmp_path / "baseline" / "lifecycle.sqlite3") as connection:
        connection.execute(
            "UPDATE customer_sandbox_resync_baselines SET baseline_json='{'"
        )
    with pytest.raises(CustomerSandboxIntegrityError, match="resync_baseline_corrupt"):
        store.verify_integrity()


@pytest.mark.parametrize("window", ["renamed", "removed", "completed"])
def test_abandon_recovers_each_destructive_lost_ack_window(
    tmp_path: Path,
    window: str,
) -> None:
    authorities = Authorities()
    provisioner = AlwaysFailsProvisioner(tmp_path / "sandboxes")
    store, failed = _terminal_create_failure(tmp_path, authorities, provisioner)
    provisioner.fail = False
    with store._connection() as connection:
        snapshot = store._snapshot(connection, failed)
    provisioner.apply(snapshot, expected_workspace_sha256=failed.workspace_sha256)
    authorities.principal = "lost-abandon-requester"
    requested = store.request_abandon(
        failed.sandbox_id,
        expected_revision=failed.revision,
        idempotency_key=f"lost-abandon-request-{window}",
    )
    authorities.principal = "lost-abandon-approver"
    approved = store.approve_abandon(
        failed.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key=f"lost-abandon-approve-{window}",
    )
    fingerprint = approved.workspace_sha256
    assert fingerprint is not None
    target = provisioner._target_path(approved.target_sandbox_id)
    quarantine = provisioner._quarantine_path(approved.target_sandbox_id)
    marker = provisioner._abandon_marker_path(approved.target_sandbox_id)
    if window in {"renamed", "removed"}:
        intent = provisioner._abandon_marker_material(
            sandbox_id=approved.sandbox_id,
            target_sandbox_id=approved.target_sandbox_id,
            snapshot_sha256=approved.snapshot_sha256,
            fingerprint=fingerprint,
            quota_bytes=approved.quota_bytes,
            state="intent",
        )
        provisioner._write_abandon_marker(marker, intent)
        target.replace(quarantine)
        if window == "removed":
            shutil.rmtree(quarantine)
    else:
        provisioner.abandon(
            sandbox_id=approved.sandbox_id,
            target_sandbox_id=approved.target_sandbox_id,
            snapshot_sha256=approved.snapshot_sha256,
            quota_bytes=approved.quota_bytes,
            expected_fingerprint=fingerprint,
        )
    tombstone = store.abandon_failed_sandbox(
        failed.sandbox_id,
        expected_revision=approved.revision,
        idempotency_key=f"lost-abandon-final-{window}",
    )
    assert tombstone.sandbox_id == failed.sandbox_id
    assert not target.exists()
    assert not quarantine.exists()
    assert provisioner._read_abandon_marker(marker)["state"] == "completed"
    assert store.abandon_failed_sandbox(
        failed.sandbox_id,
        expected_revision=approved.revision,
        idempotency_key=f"lost-abandon-final-{window}",
    ) == tombstone


def test_abandon_same_key_recovers_partial_quarantine_rmtree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorities = Authorities()
    provisioner = AlwaysFailsProvisioner(tmp_path / "sandboxes")
    store, failed = _terminal_create_failure(tmp_path, authorities, provisioner)
    provisioner.fail = False
    with store._connection() as connection:
        snapshot = store._snapshot(connection, failed)
    provisioner.apply(snapshot, expected_workspace_sha256=failed.workspace_sha256)
    authorities.principal = "partial-abandon-requester"
    requested = store.request_abandon(
        failed.sandbox_id,
        expected_revision=failed.revision,
        idempotency_key="partial-abandon-request",
    )
    authorities.principal = "partial-abandon-approver"
    approved = store.approve_abandon(
        failed.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key="partial-abandon-approve",
    )
    target = provisioner._target_path(approved.target_sandbox_id)
    quarantine = provisioner._quarantine_path(approved.target_sandbox_id)
    real_rmtree = shutil.rmtree
    crashed = False

    def partial_rmtree(path, *args, **kwargs):
        nonlocal crashed
        selected = Path(path)
        if selected == quarantine and not crashed:
            crashed = True
            (selected / "current.json").unlink()
            raise SystemExit("simulated process death during partial abandon rmtree")
        return real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(shutil, "rmtree", partial_rmtree)
    with pytest.raises(SystemExit, match="partial abandon rmtree"):
        store.abandon_failed_sandbox(
            failed.sandbox_id,
            expected_revision=approved.revision,
            idempotency_key="partial-abandon-final",
        )
    assert not target.exists()
    assert quarantine.exists()
    assert not (quarantine / "current.json").exists()

    tombstone = store.abandon_failed_sandbox(
        failed.sandbox_id,
        expected_revision=approved.revision,
        idempotency_key="partial-abandon-final",
    )
    assert tombstone.sandbox_id == failed.sandbox_id
    assert not quarantine.exists()


def test_pre_owner_create_intent_can_be_abandoned_and_target_reused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorities = Authorities()
    provisioner = LocalCustomerSandboxProvisioner(tmp_path / "sandboxes")
    store = _store(tmp_path, authorities, provisioner=provisioner)
    requested = store.request_sandbox(
        "pre-owner-failure",
        source_tenant_id="production-a",
        target_sandbox_id="pre-owner-target",
        module_allowlist=MODULES,
        expires_at=NOW + 3_600,
        retained_until=NOW + 7_200,
        plan="sandbox-small",
        quota_bytes=64 * 1024,
        max_attempts=1,
        idempotency_key="pre-owner-request",
    )
    authorities.principal = "pre-owner-approver"
    approved = store.approve_sandbox(
        requested.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key="pre-owner-approve",
    )
    target = provisioner._target_path(approved.target_sandbox_id)
    marker = provisioner._provision_marker_path(approved.target_sandbox_id)
    real_ensure = lifecycle_module.ensure_private_directory
    crashed = False

    def fail_target_ensure(path, *args, **kwargs):
        nonlocal crashed
        if Path(path) == target and not crashed:
            crashed = True
            raise OSError("simulated failure before target creation")
        return real_ensure(path, *args, **kwargs)

    monkeypatch.setattr(
        lifecycle_module,
        "ensure_private_directory",
        fail_target_ensure,
    )
    authorities.principal = "pre-owner-operator"
    with pytest.raises(CustomerSandboxProvisioningError, match="retryable"):
        store.provision_sandbox(
            approved.sandbox_id,
            expected_revision=approved.revision,
            idempotency_key="pre-owner-provision",
        )
    failed = store.get_sandbox(approved.sandbox_id)
    assert failed.state == "failed"
    assert not target.exists()
    assert marker.exists()

    _four_eyes_abandon(store, authorities, failed, suffix="pre-owner")
    assert not marker.exists()
    replacement = store.request_sandbox(
        "pre-owner-replacement",
        source_tenant_id="production-a",
        target_sandbox_id=approved.target_sandbox_id,
        module_allowlist=MODULES,
        expires_at=NOW + 3_600,
        retained_until=NOW + 7_200,
        plan="sandbox-small",
        quota_bytes=64 * 1024,
        idempotency_key="pre-owner-replacement-request",
    )
    authorities.principal = "pre-owner-replacement-approver"
    replacement = store.approve_sandbox(
        replacement.sandbox_id,
        expected_revision=replacement.revision,
        idempotency_key="pre-owner-replacement-approve",
    )
    replacement = store.provision_sandbox(
        replacement.sandbox_id,
        expected_revision=replacement.revision,
        idempotency_key="pre-owner-replacement-provision",
    )
    assert replacement.state == "active"


class FailsResyncProvisioner(LocalCustomerSandboxProvisioner):
    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.fail_resync = True

    def apply(self, snapshot, *, expected_workspace_sha256):
        if self.fail_resync and snapshot.snapshot_revision > 1:
            raise RuntimeError("simulated resync failure")
        return super().apply(
            snapshot,
            expected_workspace_sha256=expected_workspace_sha256,
        )


class FailsAfterResyncWriteOnce(LocalCustomerSandboxProvisioner):
    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.fail_resync = True

    def apply(self, snapshot, *, expected_workspace_sha256):
        receipt = super().apply(
            snapshot,
            expected_workspace_sha256=expected_workspace_sha256,
        )
        if self.fail_resync and snapshot.snapshot_revision > 1:
            self.fail_resync = False
            raise RuntimeError("simulated failure after durable resync successor")
        return receipt


class FailsProposalRegistryWriteOnce(RegistryWriteAckLostProvisioner):
    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.fail_resync_registry = True

    def apply(self, snapshot, *, expected_workspace_sha256):
        if self.fail_resync_registry and snapshot.snapshot_revision > 1:
            self.fail_resync_registry = False
            self.fail_next_registry_write = True
        return super().apply(
            snapshot,
            expected_workspace_sha256=expected_workspace_sha256,
        )


class FailsRollbackRegistryWriteOnce(LocalCustomerSandboxProvisioner):
    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.fail_resync = True
        self.fail_rollback_registry = False

    def _save_registry(self, records):
        if self.fail_rollback_registry:
            self.fail_rollback_registry = False
            raise OSError("simulated rollback manifest-before-registry crash")
        return super()._save_registry(records)

    def apply(self, snapshot, *, expected_workspace_sha256):
        receipt = super().apply(
            snapshot,
            expected_workspace_sha256=expected_workspace_sha256,
        )
        if self.fail_resync and snapshot.snapshot_revision > 1:
            self.fail_resync = False
            self.fail_rollback_registry = True
            raise RuntimeError("simulated failure after durable resync successor")
        return receipt


class HardCrashesRollbackRegistryOnce(LocalCustomerSandboxProvisioner):
    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.fail_resync = True
        self.hard_crash_rollback = False

    def _save_registry(self, records):
        if self.hard_crash_rollback:
            self.hard_crash_rollback = False
            raise SystemExit("simulated process death during rollback registry save")
        return super()._save_registry(records)

    def apply(self, snapshot, *, expected_workspace_sha256):
        receipt = super().apply(
            snapshot,
            expected_workspace_sha256=expected_workspace_sha256,
        )
        if self.fail_resync and snapshot.snapshot_revision > 1:
            self.fail_resync = False
            self.hard_crash_rollback = True
            raise RuntimeError("simulated terminal resync failure")
        return receipt


class FailsSuspendedRollbackStatusRegistryOnce(LocalCustomerSandboxProvisioner):
    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.fail_resync = True
        self.fail_suspended_status = False

    def _save_registry(self, records):
        if self.fail_suspended_status and any(
            row.get("status") == "suspended" for row in records.values()
        ):
            self.fail_suspended_status = False
            raise OSError("simulated suspended rollback status registry failure")
        return super()._save_registry(records)

    def apply(self, snapshot, *, expected_workspace_sha256):
        receipt = super().apply(
            snapshot,
            expected_workspace_sha256=expected_workspace_sha256,
        )
        if self.fail_resync and snapshot.snapshot_revision > 1:
            self.fail_resync = False
            self.fail_suspended_status = True
            raise RuntimeError("simulated terminal resync failure")
        return receipt


class ExpiryCrossingStatusRegistryFailure(LocalCustomerSandboxProvisioner):
    def __init__(self, root: Path, authorities: Authorities) -> None:
        super().__init__(root)
        self.authorities = authorities
        self.fail_expired_status = False

    def _save_registry(self, records):
        if self.fail_expired_status and any(
            row.get("status") == "expired" for row in records.values()
        ):
            self.fail_expired_status = False
            raise OSError("simulated expiry status registry failure")
        return super()._save_registry(records)

    def apply(self, snapshot, *, expected_workspace_sha256):
        receipt = super().apply(
            snapshot,
            expected_workspace_sha256=expected_workspace_sha256,
        )
        if snapshot.snapshot_revision > 1:
            self.authorities.now = snapshot.expires_at
            self.fail_expired_status = True
        return receipt


def _activate_one_attempt(
    store: CustomerSandboxLifecycleStore,
    authorities: Authorities,
    *,
    prefix: str,
):
    requested = store.request_sandbox(
        f"{prefix}-sandbox",
        source_tenant_id="production-a",
        target_sandbox_id=f"{prefix}-target",
        module_allowlist=MODULES,
        expires_at=NOW + 3_600,
        retained_until=NOW + 7_200,
        plan="sandbox-small",
        quota_bytes=64 * 1024,
        max_attempts=1,
        idempotency_key=f"{prefix}-create",
    )
    authorities.principal = f"{prefix}-create-approver"
    approved = store.approve_sandbox(
        requested.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key=f"{prefix}-create-approve",
    )
    authorities.principal = f"{prefix}-operator"
    return store.provision_sandbox(
        approved.sandbox_id,
        expected_revision=approved.revision,
        idempotency_key=f"{prefix}-create-provision",
    )


def _approve_changed_resync(
    store: CustomerSandboxLifecycleStore,
    authorities: Authorities,
    active,
    *,
    prefix: str,
):
    authorities.revision += 1
    authorities.config["ai_governance"] = {"enabled": True, "mode": "monitor"}
    authorities.principal = f"{prefix}-requester"
    proposal = store.request_resync(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key=f"{prefix}-request",
    )
    authorities.principal = f"{prefix}-approver"
    return store.approve_sandbox(
        proposal.sandbox_id,
        expected_revision=proposal.revision,
        idempotency_key=f"{prefix}-approve",
    )


@pytest.mark.parametrize(
    "provisioner_type",
    [
        FailsAfterResyncWriteOnce,
        FailsProposalRegistryWriteOnce,
        FailsRollbackRegistryWriteOnce,
    ],
)
def test_terminal_resync_rollback_recovers_exact_successor_and_write_splits(
    tmp_path: Path,
    provisioner_type: type[LocalCustomerSandboxProvisioner],
) -> None:
    authorities = Authorities()
    provisioner = provisioner_type(tmp_path / "sandboxes")
    store = _store(tmp_path, authorities, provisioner=provisioner)
    requested = store.request_sandbox(
        "durable-resync-rollback",
        source_tenant_id="production-a",
        target_sandbox_id="durable-resync-rollback-target",
        module_allowlist=MODULES,
        expires_at=NOW + 3_600,
        retained_until=NOW + 7_200,
        plan="sandbox-small",
        quota_bytes=64 * 1024,
        max_attempts=1,
        idempotency_key="durable-resync-create",
    )
    authorities.principal = "durable-resync-create-approver"
    approved = store.approve_sandbox(
        requested.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key="durable-resync-create-approve",
    )
    authorities.principal = "durable-resync-operator"
    active = store.provision_sandbox(
        approved.sandbox_id,
        expected_revision=approved.revision,
        idempotency_key="durable-resync-create-provision",
    )
    baseline_snapshot = active.snapshot_sha256

    authorities.revision += 1
    authorities.config["ai_governance"] = {
        "enabled": True,
        "mode": "strict-review",
        "limits": {"items": 2},
    }
    authorities.principal = "durable-resync-requester"
    proposal = store.request_resync(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key="durable-resync-request",
    )
    authorities.principal = "durable-resync-approver"
    proposal = store.approve_sandbox(
        proposal.sandbox_id,
        expected_revision=proposal.revision,
        idempotency_key="durable-resync-approve",
    )
    authorities.principal = "durable-resync-operator"
    with pytest.raises(CustomerSandboxProvisioningError, match="retryable"):
        store.provision_sandbox(
            proposal.sandbox_id,
            expected_revision=proposal.revision,
            idempotency_key="durable-resync-provision",
        )

    restored = store.get_sandbox(active.sandbox_id)
    authority = provisioner.inspect(active.target_sandbox_id)
    assert restored.state == "active"
    assert restored.snapshot_revision == 1
    assert restored.snapshot_sha256 == baseline_snapshot
    assert authority is not None
    assert authority.snapshot_sha256 == restored.snapshot_sha256
    assert authority.workspace_sha256 == restored.workspace_sha256
    assert store.verify_integrity()["resync_baselines"] == 0


def test_terminal_resync_discards_completed_marker_partial_before_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorities = Authorities()
    provisioner = CollisionJournalProvisioner(tmp_path / "sandboxes", authorities)
    store = _store(tmp_path, authorities, provisioner=provisioner)
    requested = store.request_sandbox(
        "marker-terminal-resync",
        source_tenant_id="production-a",
        target_sandbox_id="marker-terminal-resync-target",
        module_allowlist=MODULES,
        expires_at=NOW + 3_600,
        retained_until=NOW + 7_200,
        plan="sandbox-small",
        quota_bytes=64 * 1024,
        max_attempts=2,
        idempotency_key="marker-terminal-create",
    )
    authorities.principal = "marker-terminal-create-approver"
    approved = store.approve_sandbox(
        requested.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key="marker-terminal-create-approve",
    )
    authorities.principal = "marker-terminal-operator"
    active = store.provision_sandbox(
        approved.sandbox_id,
        expected_revision=approved.revision,
        idempotency_key="marker-terminal-create-provision",
    )
    proposal = _approve_changed_resync(
        store,
        authorities,
        active,
        prefix="marker-terminal-resync",
    )
    provisioner.trigger_after_revision = proposal.snapshot_revision
    authorities.principal = "marker-terminal-operator"
    with pytest.raises(CustomerSandboxProvisioningError, match="retryable"):
        store.provision_sandbox(
            proposal.sandbox_id,
            expected_revision=proposal.revision,
            idempotency_key="marker-terminal-first",
        )
    retry_record = store.get_sandbox(active.sandbox_id)
    assert retry_record.state == "provisioning"
    authorities.production_targets.clear()
    real_atomic_write = lifecycle_module.atomic_write_text
    failed = False

    def fail_recreation_manifest(path, value, *args, **kwargs):
        nonlocal failed
        if Path(path).name == "current.json" and not failed:
            failed = True
            raise OSError("simulated handled recreation manifest failure")
        return real_atomic_write(path, value, *args, **kwargs)

    monkeypatch.setattr(
        lifecycle_module,
        "atomic_write_text",
        fail_recreation_manifest,
    )
    with pytest.raises(CustomerSandboxProvisioningError, match="retryable"):
        store.provision_sandbox(
            retry_record.sandbox_id,
            expected_revision=retry_record.revision,
            idempotency_key="marker-terminal-second",
            retry=True,
        )

    restored = store.get_sandbox(active.sandbox_id)
    authority = provisioner.inspect(active.target_sandbox_id)
    assert restored.state == "active"
    assert restored.snapshot_sha256 == active.snapshot_sha256
    assert authority is not None
    assert authority.workspace_sha256 == restored.workspace_sha256
    assert not provisioner._collision_marker_path(active.target_sandbox_id).exists()


def _terminal_collision_resync(
    tmp_path: Path,
    authorities: Authorities,
    provisioner: CollisionJournalProvisioner,
):
    store = _store(tmp_path, authorities, provisioner=provisioner)
    active = _activate_one_attempt(store, authorities, prefix="baseline-intent")
    proposal = _approve_changed_resync(
        store,
        authorities,
        active,
        prefix="baseline-intent-resync",
    )
    provisioner.trigger_after_revision = proposal.snapshot_revision
    authorities.principal = "baseline-intent-operator"
    return store, active, proposal


@pytest.mark.parametrize("fault", ["oserror", "system_exit"])
def test_terminal_resync_recovers_baseline_pre_owner_create_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    authorities = Authorities()
    provisioner = CollisionJournalProvisioner(tmp_path / "sandboxes", authorities)
    store, active, proposal = _terminal_collision_resync(
        tmp_path,
        authorities,
        provisioner,
    )
    real_atomic_write = lifecycle_module.atomic_write_text
    failed = False

    def fail_baseline_owner(path, value, *args, **kwargs):
        nonlocal failed
        if Path(path).name == "owner.json" and not failed:
            failed = True
            if fault == "system_exit":
                raise SystemExit("simulated baseline owner process death")
            raise OSError("simulated baseline owner write failure")
        return real_atomic_write(path, value, *args, **kwargs)

    monkeypatch.setattr(lifecycle_module, "atomic_write_text", fail_baseline_owner)
    if fault == "system_exit":
        with pytest.raises(SystemExit, match="baseline owner"):
            store.provision_sandbox(
                proposal.sandbox_id,
                expected_revision=proposal.revision,
                idempotency_key="baseline-intent-provision",
            )
        with pytest.raises(CustomerSandboxProvisioningError, match="rolled_back"):
            store.provision_sandbox(
                proposal.sandbox_id,
                expected_revision=proposal.revision,
                idempotency_key="baseline-intent-provision",
            )
    else:
        with pytest.raises(CustomerSandboxProvisioningError, match="retryable"):
            store.provision_sandbox(
                proposal.sandbox_id,
                expected_revision=proposal.revision,
                idempotency_key="baseline-intent-provision",
            )
    restored = store.get_sandbox(active.sandbox_id)
    authority = provisioner.inspect(active.target_sandbox_id)
    assert restored.snapshot_sha256 == active.snapshot_sha256
    assert restored.state == "suspended"
    assert authority is not None
    assert authority.workspace_sha256 == restored.workspace_sha256
    assert not provisioner._provision_marker_path(active.target_sandbox_id).exists()
    assert not provisioner._collision_marker_path(active.target_sandbox_id).exists()


def test_terminal_resync_recovers_baseline_marker_unlink_process_death(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorities = Authorities()
    provisioner = CollisionJournalProvisioner(tmp_path / "sandboxes", authorities)
    store, active, proposal = _terminal_collision_resync(
        tmp_path,
        authorities,
        provisioner,
    )
    marker = provisioner._provision_marker_path(active.target_sandbox_id)
    real_unlink = Path.unlink
    crashed = False

    def crash_marker_unlink(path: Path, *args, **kwargs):
        nonlocal crashed
        if path == marker and not crashed:
            crashed = True
            raise SystemExit("simulated baseline marker unlink process death")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", crash_marker_unlink)
    with pytest.raises(SystemExit, match="marker unlink"):
        store.provision_sandbox(
            proposal.sandbox_id,
            expected_revision=proposal.revision,
            idempotency_key="baseline-unlink-provision",
        )
    assert marker.exists()
    with pytest.raises(CustomerSandboxProvisioningError, match="rolled_back"):
        store.provision_sandbox(
            proposal.sandbox_id,
            expected_revision=proposal.revision,
            idempotency_key="baseline-unlink-provision",
        )
    restored = store.get_sandbox(active.sandbox_id)
    authority = provisioner.inspect(active.target_sandbox_id)
    assert restored.snapshot_sha256 == active.snapshot_sha256
    assert authority is not None
    assert authority.workspace_sha256 == restored.workspace_sha256
    assert not marker.exists()


def test_same_key_resumes_terminal_rollback_after_process_death(tmp_path: Path) -> None:
    authorities = Authorities()
    provisioner = HardCrashesRollbackRegistryOnce(tmp_path / "sandboxes")
    store = _store(tmp_path, authorities, provisioner=provisioner)
    requested = store.request_sandbox(
        "rollback-process-death",
        source_tenant_id="production-a",
        target_sandbox_id="rollback-process-death-target",
        module_allowlist=MODULES,
        expires_at=NOW + 3_600,
        retained_until=NOW + 7_200,
        plan="sandbox-small",
        quota_bytes=64 * 1024,
        max_attempts=1,
        idempotency_key="rollback-death-create",
    )
    authorities.principal = "rollback-death-create-approver"
    approved = store.approve_sandbox(
        requested.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key="rollback-death-create-approve",
    )
    authorities.principal = "rollback-death-operator"
    active = store.provision_sandbox(
        approved.sandbox_id,
        expected_revision=approved.revision,
        idempotency_key="rollback-death-create-provision",
    )
    authorities.revision += 1
    authorities.config["ai_governance"] = {"enabled": True, "mode": "monitor"}
    authorities.principal = "rollback-death-requester"
    proposal = store.request_resync(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key="rollback-death-request",
    )
    authorities.principal = "rollback-death-approver"
    proposal = store.approve_sandbox(
        proposal.sandbox_id,
        expected_revision=proposal.revision,
        idempotency_key="rollback-death-approve",
    )
    authorities.principal = "rollback-death-operator"
    with pytest.raises(SystemExit, match="process death"):
        store.provision_sandbox(
            proposal.sandbox_id,
            expected_revision=proposal.revision,
            idempotency_key="rollback-death-provision",
        )
    with pytest.raises(CustomerSandboxProvisioningError, match="rolled_back"):
        store.provision_sandbox(
            proposal.sandbox_id,
            expected_revision=proposal.revision,
            idempotency_key="rollback-death-provision",
        )

    restored = store.get_sandbox(active.sandbox_id)
    authority = provisioner.inspect(active.target_sandbox_id)
    assert restored.state == "active"
    assert restored.snapshot_sha256 == active.snapshot_sha256
    assert authority is not None
    assert authority.workspace_sha256 == restored.workspace_sha256


def test_suspended_baseline_rollback_recovers_status_registry_split(
    tmp_path: Path,
) -> None:
    authorities = Authorities()
    provisioner = FailsSuspendedRollbackStatusRegistryOnce(tmp_path / "sandboxes")
    store = _store(tmp_path, authorities, provisioner=provisioner)
    active = _activate_one_attempt(store, authorities, prefix="suspended-rollback")
    suspended = store.suspend_sandbox(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key="suspended-rollback-suspend",
    )
    proposal = _approve_changed_resync(
        store,
        authorities,
        suspended,
        prefix="suspended-rollback-resync",
    )
    authorities.principal = "suspended-rollback-operator"
    with pytest.raises(CustomerSandboxProvisioningError, match="retryable"):
        store.provision_sandbox(
            proposal.sandbox_id,
            expected_revision=proposal.revision,
            idempotency_key="suspended-rollback-provision",
        )

    restored = store.get_sandbox(active.sandbox_id)
    authority = provisioner.inspect(active.target_sandbox_id)
    assert restored.state == "suspended"
    assert authority is not None
    assert authority.status == "suspended"
    assert authority.workspace_sha256 == restored.workspace_sha256


def test_expiry_crossing_reconciles_proposal_status_split(
    tmp_path: Path,
) -> None:
    authorities = Authorities()
    provisioner = ExpiryCrossingStatusRegistryFailure(
        tmp_path / "sandboxes",
        authorities,
    )
    store = _store(tmp_path, authorities, provisioner=provisioner)
    active = _activate_one_attempt(store, authorities, prefix="expiry-rollback")
    proposal = _approve_changed_resync(
        store,
        authorities,
        active,
        prefix="expiry-rollback-resync",
    )
    authorities.principal = "expiry-rollback-operator"
    completed = store.provision_sandbox(
        proposal.sandbox_id,
        expected_revision=proposal.revision,
        idempotency_key="expiry-rollback-provision",
    )

    restored = store.get_sandbox(active.sandbox_id)
    authority = provisioner.inspect(active.target_sandbox_id)
    assert completed == restored
    assert restored.state == "expired"
    assert restored.snapshot_sha256 == proposal.snapshot_sha256
    assert authority is not None
    assert authority.status == "expired"
    assert authority.workspace_sha256 == restored.workspace_sha256


@pytest.mark.parametrize("window", ["quarantine_present", "quarantine_removed"])
def test_resync_rollback_recovers_exact_collision_destroy_windows(
    tmp_path: Path,
    window: str,
) -> None:
    authorities = Authorities()
    provisioner = LocalCustomerSandboxProvisioner(tmp_path / "sandboxes")
    store = _store(tmp_path, authorities, provisioner=provisioner)
    active = _activate(store, authorities)
    assert active.workspace_sha256 is not None
    authorities.revision += 1
    authorities.config["ai_governance"] = {
        "enabled": True,
        "mode": "strict-review",
        "limits": {"items": 2},
    }
    authorities.principal = "destroy-window-requester"
    proposal = store.request_resync(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key=f"destroy-window-request-{window}",
    )
    with store._connection() as connection:
        baseline_snapshot = store._snapshot(connection, active)
        proposal_snapshot = store._snapshot(connection, proposal)
    provisioner.apply(
        proposal_snapshot,
        expected_workspace_sha256=active.workspace_sha256,
    )
    target = provisioner._target_path(active.target_sandbox_id)
    quarantine = provisioner._quarantine_path(active.target_sandbox_id)
    if window == "quarantine_present":
        target.replace(quarantine)
    else:
        shutil.rmtree(target)

    receipt = provisioner.restore_resync_baseline(
        baseline_snapshot,
        expected_workspace_sha256=active.workspace_sha256,
        proposal_snapshot_sha256=proposal.snapshot_sha256,
    )
    authority = provisioner.inspect(active.target_sandbox_id)
    assert receipt.snapshot_sha256 == active.snapshot_sha256
    assert authority is not None
    assert authority.snapshot_sha256 == active.snapshot_sha256
    assert not quarantine.exists()


def test_resync_rollback_rejects_missing_target_with_baseline_registry(
    tmp_path: Path,
) -> None:
    authorities = Authorities()
    provisioner = LocalCustomerSandboxProvisioner(tmp_path / "sandboxes")
    store = _store(tmp_path, authorities, provisioner=provisioner)
    active = _activate(store, authorities)
    authorities.revision += 1
    authorities.config["ai_governance"] = {"enabled": True, "mode": "monitor"}
    proposal = store.request_resync(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key="baseline-registry-missing-target-request",
    )
    with store._connection() as connection:
        baseline_snapshot = store._snapshot(connection, active)
    shutil.rmtree(provisioner._target_path(active.target_sandbox_id))

    with pytest.raises(CustomerSandboxIntegrityError, match="registry_drift"):
        provisioner.restore_resync_baseline(
            baseline_snapshot,
            expected_workspace_sha256=active.workspace_sha256,
            proposal_snapshot_sha256=proposal.snapshot_sha256,
        )


def test_terminal_failed_resync_can_cancel_then_reuse_snapshot_revision_and_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorities = Authorities()
    provisioner = FailsResyncProvisioner(tmp_path / "sandboxes")
    store = _store(tmp_path, authorities, provisioner=provisioner)
    requested = store.request_sandbox(
        "failed-resync",
        source_tenant_id="production-a",
        target_sandbox_id="failed-resync-target",
        module_allowlist=("ai_governance",),
        expires_at=NOW + 3_600,
        retained_until=NOW + 7_200,
        plan="sandbox-small",
        quota_bytes=16_384,
        max_attempts=1,
        idempotency_key="failed-resync-create",
    )
    authorities.principal = "failed-resync-create-approver"
    approved = store.approve_sandbox(
        requested.sandbox_id,
        expected_revision=requested.revision,
        idempotency_key="failed-resync-create-approve",
    )
    active = store.provision_sandbox(
        approved.sandbox_id,
        expected_revision=approved.revision,
        idempotency_key="failed-resync-create-provision",
    )
    authorities.config["ai_governance"] = {"enabled": True, "mode": "monitor"}
    authorities.revision = 2
    authorities.principal = "failed-resync-requester"
    proposal = store.request_resync(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key="failed-resync-reusable-key",
    )
    authorities.principal = "failed-resync-approver"
    proposal = store.approve_sandbox(
        active.sandbox_id,
        expected_revision=proposal.revision,
        idempotency_key="failed-resync-approve",
    )
    monkeypatch.setattr(store, "_rollback_terminal_resync", lambda *_args: False)
    with pytest.raises(CustomerSandboxProvisioningError, match="retryable"):
        store.provision_sandbox(
            active.sandbox_id,
            expected_revision=proposal.revision,
            idempotency_key="failed-resync-provision",
        )
    failed = store.get_sandbox(active.sandbox_id)
    assert failed.state == "failed"
    with pytest.raises(CustomerSandboxConflict, match="revision_conflict"):
        store.provision_sandbox(
            active.sandbox_id,
            expected_revision=failed.revision - 1,
            idempotency_key="failed-resync-stale-recovery",
            retry=True,
        )
    with pytest.raises(CustomerSandboxConflict, match="retry_required"):
        store.provision_sandbox(
            active.sandbox_id,
            expected_revision=failed.revision,
            idempotency_key="failed-resync-nonretry-recovery",
        )
    suspended = store.suspend_sandbox(
        active.sandbox_id,
        expected_revision=failed.revision,
        idempotency_key="failed-resync-cancel",
    )
    provisioner.fail_resync = False
    resumed = store.resume_sandbox(
        active.sandbox_id,
        expected_revision=suspended.revision,
        idempotency_key="failed-resync-resume",
    )
    authorities.principal = "failed-resync-requester"
    replacement = store.request_resync(
        active.sandbox_id,
        expected_revision=resumed.revision,
        idempotency_key="failed-resync-reusable-key",
    )
    assert replacement.snapshot_revision == 2


def test_successful_resync_destroy_and_elapsed_retention_purge(tmp_path: Path) -> None:
    authorities = Authorities()
    store = _store(tmp_path, authorities)
    active = _activate(store, authorities)
    authorities.config["ai_governance"] = {"enabled": True, "mode": "monitor"}
    authorities.revision = 2
    authorities.principal = "purge-resync-requester"
    proposal = store.request_resync(
        active.sandbox_id,
        expected_revision=active.revision,
        idempotency_key="purge-resync-request",
    )
    authorities.principal = "purge-resync-approver"
    proposal = store.approve_sandbox(
        active.sandbox_id,
        expected_revision=proposal.revision,
        idempotency_key="purge-resync-approve",
    )
    current = store.provision_sandbox(
        active.sandbox_id,
        expected_revision=proposal.revision,
        idempotency_key="purge-resync-provision",
    )
    suspended = store.suspend_sandbox(
        active.sandbox_id,
        expected_revision=current.revision,
        idempotency_key="purge-resync-suspend",
    )
    authorities.principal = "purge-resync-destroy-requester"
    destroy_requested = store.request_destroy(
        active.sandbox_id,
        expected_revision=suspended.revision,
        idempotency_key="purge-resync-destroy-request",
    )
    authorities.principal = "purge-resync-destroy-approver"
    destroy_approved = store.approve_destroy(
        active.sandbox_id,
        expected_revision=destroy_requested.revision,
        idempotency_key="purge-resync-destroy-approve",
    )
    destroyed = store.destroy_sandbox(
        active.sandbox_id,
        expected_revision=destroy_approved.revision,
        idempotency_key="purge-resync-destroy",
    )
    authorities.now = destroyed.retained_until
    tombstone = store.purge_destroyed_sandbox(
        active.sandbox_id,
        expected_revision=destroyed.revision,
        idempotency_key="purge-resync-retention",
    )
    assert tombstone.sandbox_id == active.sandbox_id


def test_every_lifecycle_connection_is_closed_when_its_call_returns(
    tmp_path: Path, monkeypatch
) -> None:
    # CPython 3.12 keeps an unclosed sqlite3 connection alive until a cyclic GC pass,
    # so GC is disabled here: any connection left open by a call stays open.
    opened: list[sqlite3.Connection] = []
    real_connect = sqlite3.connect

    class _PragmaFails(sqlite3.Connection):
        def execute(self, sql, *args):
            if sql == "PRAGMA foreign_keys=ON" and fail_pragma["on"]:
                raise sqlite3.OperationalError("pragma failed")
            return super().execute(sql, *args)

    fail_pragma = {"on": True}

    def recording_connect(*args, **kwargs):
        connection = real_connect(*args, factory=_PragmaFails, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr(lifecycle_module.sqlite3, "connect", recording_connect)
    gc.disable()
    try:
        with pytest.raises(sqlite3.OperationalError):
            _store(tmp_path, Authorities())
        fail_pragma["on"] = False
        store = _store(tmp_path, Authorities())
        store.status()
    finally:
        gc.enable()
    assert len(opened) >= 2  # the connection whose PRAGMA failed, and the working store
    for connection in opened:
        with pytest.raises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")


def test_lifecycle_connection_closes_when_row_setup_fails(tmp_path: Path, monkeypatch) -> None:
    # Same GC-disabled rule as above: an unclosed connection stays open until a GC pass.
    store = _store(tmp_path, Authorities())
    opened: list[sqlite3.Connection] = []
    real_connect = sqlite3.connect

    class _RowSetupFails(sqlite3.Connection):
        def __setattr__(self, name, value):
            if name == "row_factory":
                raise sqlite3.OperationalError("row setup failed")
            super().__setattr__(name, value)

    def recording_connect(*args, **kwargs):
        connection = real_connect(*args, factory=_RowSetupFails, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr(lifecycle_module.sqlite3, "connect", recording_connect)
    gc.disable()
    try:
        with pytest.raises(sqlite3.OperationalError):
            store._connect()
    finally:
        gc.enable()
    assert len(opened) == 1
    with pytest.raises(sqlite3.ProgrammingError):
        opened[0].execute("SELECT 1")
