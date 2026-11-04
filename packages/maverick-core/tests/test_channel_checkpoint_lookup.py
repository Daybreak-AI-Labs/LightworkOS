"""Recovery source lookup binds actor, held item and current configured account."""
import contextlib
from types import SimpleNamespace

import pytest
from maverick import channel_recovery_controls as controls
from maverick import config
from maverick import workspace_recovery as recovery
from maverick_channels import recovery_lookup as sources


@pytest.fixture
def held(tmp_path, monkeypatch):
    channel = SimpleNamespace(name="imessage", _account=lambda: "exact-source")
    item = {"id": "a" * 32, "category": "channel_authority", "state": "unresolved", "source": "held.json", "record_id": sources.record_identity(channel), "channel_binding": {}, "readback_template": {"namespace": "imessage-intake-cursors"}}
    marker = {"state": "reconciliation_required", "bootstrap_id": "bootstrap", "actor": "admin", "target": "workspace", "restored_at": 1}
    record = {"id": item["record_id"], "last_rowid": 5, "restore_hold": {"state": "unresolved"}}
    monkeypatch.setattr(recovery, "_locked", contextlib.nullcontext)
    monkeypatch.setattr(recovery, "_read_bootstrap", lambda **kwargs: marker)
    monkeypatch.setattr(recovery, "_classified_bootstrap_reconciliation", lambda value: ([item], {}))
    monkeypatch.setattr(recovery, "_root", lambda: tmp_path)
    monkeypatch.setattr(recovery, "current_tenant_id_strict", lambda: "workspace")
    monkeypatch.setattr(controls, "_current_record", lambda *args, **kwargs: record)
    monkeypatch.setattr(config, "load_config", lambda: {"channels": {"imessage": {"enabled": True}}})
    monkeypatch.setattr(sources, "configured", lambda *args: channel)
    return item, marker, record, channel


def run(held):
    item, marker, _, _ = held
    return recovery.channel_checkpoint_lookup(item["id"], expected_review_token=controls.review_token(marker, item), before=None, isolated=True, actor="admin")


def test_outage_leaves_hold_and_prior_authority_unchanged(held, monkeypatch):
    def unavailable(*args, **kwargs):
        raise OSError("private connection/path/token detail")
    monkeypatch.setattr(sources, "lookup", unavailable)
    result = run(held)
    assert result["available"] is False and result["candidates"] == []
    assert "private connection" not in str(result)
    assert held[2]["last_rowid"] == 5 and held[0]["state"] == "unresolved"


def test_changed_source_identity_is_not_queried(held, monkeypatch):
    monkeypatch.setattr(sources, "configured", lambda *args: SimpleNamespace(name="imessage", _account=lambda: "other-source"))
    monkeypatch.setattr(sources, "lookup", lambda *args, **kwargs: pytest.fail("wrong source must not be read"))
    with pytest.raises(recovery.RecoveryError, match="differs"):
        run(held)


def test_success_is_metadata_only_and_does_not_resolve(held, monkeypatch):
    monkeypatch.setattr(sources, "lookup", lambda *args, **kwargs: {"candidates": [{"position": "7"}], "next_before": None})
    result = run(held)
    assert result["available"] is True
    assert held[2]["last_rowid"] == 5 and held[0]["state"] == "unresolved"
