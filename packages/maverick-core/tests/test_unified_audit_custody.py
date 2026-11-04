from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
from maverick import unified_audit_custody as custody


def _config(
    *,
    checkpoint: bool = True,
    worm: bool = False,
    siem: bool = False,
    revision: int = 1,
) -> dict:
    return {
        "audit": {
            "sign": True,
            "unified": {
                "enable": True,
                "custody": {
                    "enable": True,
                    "authority_revision": revision,
                    "checkpoint_enable": checkpoint,
                    "worm_enable": worm,
                    "siem_enable": siem,
                    "siem_destination_template": (
                        "https://siem.example/tenants/{tenant_sha256}/raw" if siem else ""
                    ),
                    "max_siem_events_per_run": 100,
                    "retry_backoff_seconds": 5,
                    "max_retry_backoff_seconds": 60,
                },
            },
            "worm": {
                "provider": "local",
                "retention_days": 365,
            },
        }
    }


def test_settings_are_default_off_and_require_exact_remote_namespace() -> None:
    assert custody.settings_from(
        {"audit": {"sign": True, "unified": {"enable": True}}},
        tenant_id="tenant-a",
    ).enable is False
    bad = _config(checkpoint=False, siem=True)
    bad["audit"]["unified"]["custody"]["siem_destination_template"] = (
        "https://siem.example/raw?tenant={tenant_sha256}"
    )
    with pytest.raises(custody.UnifiedAuditCustodyError, match="path segment"):
        custody.settings_from(bad, tenant_id="tenant-a")
    bad["audit"]["unified"]["custody"]["siem_destination_template"] = (
        "tcp://siem.example:514/{tenant_sha256}"
    )
    with pytest.raises(custody.UnifiedAuditCustodyError, match="HTTPS"):
        custody.settings_from(bad, tenant_id="tenant-a")


def test_s3_requires_explicit_tenant_namespace_template() -> None:
    cfg = _config(checkpoint=False, worm=True)
    cfg["audit"]["worm"] = {
        "provider": "s3",
        "bucket": "audit-lock",
        "prefix": "lightwork/audit/",
    }
    with pytest.raises(custody.UnifiedAuditCustodyError, match="prefix"):
        custody.settings_from(cfg, tenant_id="tenant-a")
    cfg["audit"]["worm"]["prefix"] = "lightwork/{tenant_sha256}/audit"
    assert custody.settings_from(cfg, tenant_id="tenant-a").worm_enable is True


def test_readiness_is_side_effect_free_and_candid(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    cfg = _config(checkpoint=False, siem=True)
    runtime = custody.UnifiedAuditCustodyRuntime(
        tenant_id="tenant-a",
        config_loader=lambda: cfg,
    )
    status = runtime.readiness()
    assert status["ready"] is True
    assert status["siem_delivery"] == "at_least_once"
    assert status["automatic_sealing_performed"] is False
    assert status["independent_operation_verified"] is False
    assert status["s3_object_lock_acceptance_verified"] is False
    assert not tmp_path.exists() or not tuple(tmp_path.rglob("*"))


def test_run_composes_worm_and_bounded_siem_with_durable_cursor(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    cfg = _config(checkpoint=False, worm=True, siem=True)
    calls: list[tuple] = []
    cursor = {"day": "2026-09-01", "line": 1, "row_sha256": "a" * 64}
    monkeypatch.setattr(custody, "_verify_audit", lambda _path: ())
    monkeypatch.setattr(custody, "_build_worm_sink", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(
        custody,
        "_siem_batch",
        lambda *_args, **_kwargs: (["{\"projection_event_id\":\"x\"}"], cursor),
    )

    def push(**kwargs):
        calls.append(("worm", kwargs["today"], kwargs["retention_days"]))
        return {"2026-08-31.ndjson": "already pushed"}

    def forward(lines, destination):
        material = list(lines)
        calls.append(("siem", material, destination))
        return len(material)

    runtime = custody.UnifiedAuditCustodyRuntime(
        tenant_id="tenant-a",
        config_loader=lambda: cfg,
        clock=lambda: 1_788_220_800.0,
        worm_pusher=push,
        siem_forwarder=forward,
    )
    result = runtime.run_once()
    assert result.worm_files_custodied == 1
    assert result.siem_events_forwarded == 1
    assert calls[0][0] == "worm"
    assert calls[1][0] == "siem"
    tenant_digest = status_digest = runtime.readiness()["tenant_namespace_sha256"]
    assert tenant_digest in calls[1][2]
    state = custody._load_state(runtime._state_path)
    assert state["cursor"] == cursor
    assert state["state_sha256"] == custody._state_digest(state)
    assert status_digest not in runtime._state_path.name


def test_same_revision_drift_fails_closed_and_enters_bounded_backoff(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    first = _config(checkpoint=False, siem=True)
    changed = deepcopy(first)
    changed["audit"]["unified"]["custody"]["max_siem_events_per_run"] = 101
    loads = [first, changed]
    monkeypatch.setattr(custody, "_verify_audit", lambda _path: ())
    monkeypatch.setattr(
        custody,
        "_siem_batch",
        lambda *_args, **_kwargs: (["event"], None),
    )

    def loader():
        return loads.pop(0) if loads else changed

    runtime = custody.UnifiedAuditCustodyRuntime(
        tenant_id="tenant-a",
        config_loader=loader,
        clock=lambda: 100.0,
        siem_forwarder=lambda *_args, **_kwargs: 1,
    )
    with pytest.raises(custody.UnifiedAuditCustodyError, match="changed during"):
        runtime.run_once()
    state = custody._load_state(runtime._state_path)
    assert state["consecutive_failures"] == 1
    assert state["next_retry_at"] == 105.0
    runtime._config_loader = lambda: first
    with pytest.raises(custody.UnifiedAuditCustodyBackoff):
        runtime.run_once()


def test_authority_revision_rollback_and_same_revision_rewrite_are_refused() -> None:
    state = custody._default_state()
    state = custody._apply_authority(
        state,
        tenant_sha256="a" * 64,
        revision=2,
        digest="b" * 64,
    )
    with pytest.raises(custody.UnifiedAuditCustodyError, match="rollback"):
        custody._apply_authority(
            state,
            tenant_sha256="a" * 64,
            revision=1,
            digest="b" * 64,
        )
    with pytest.raises(custody.UnifiedAuditCustodyError, match="without a revision"):
        custody._apply_authority(
            state,
            tenant_sha256="a" * 64,
            revision=2,
            digest="c" * 64,
        )
