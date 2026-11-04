"""Configuration changes never rewrite an already-running process receipt."""
from types import SimpleNamespace

import pytest
from maverick import runtime_configuration as runtime


def setting(reader="maverick_dashboard.app", path=("dashboard", "compress"), env=()):
    return SimpleNamespace(reader=reader, path=path, env=env)


def captured(config, environment=None, at=100):
    return {**runtime.snapshot(config, environment or {}), "captured_at": at, "valid": True}


@pytest.fixture
def isolated(monkeypatch):
    from maverick import crypto_at_rest, paths
    monkeypatch.setattr(crypto_at_rest, "seal", lambda value: value)
    monkeypatch.setattr(crypto_at_rest, "unseal", lambda value: value)
    monkeypatch.setattr(paths, "current_tenant_id_strict", lambda: None)


def test_restart_receipt_and_heartbeat_preserve_original_value(tmp_path, isolated):
    clock = [101]
    old = captured({"dashboard": {"compress": False}})
    desired = runtime.snapshot({"dashboard": {"compress": True}}, {})
    process = runtime.Reporter("dashboard", directory=tmp_path, captured=old, clock=lambda: clock[0])
    assert process.renew()
    clock[0] += 30
    assert process.renew()
    observed, unavailable = runtime.records(directory=tmp_path, now=clock[0])
    value = runtime.setting_status(setting(), desired, observed, unavailable=unavailable)
    assert value["state"] == "pending_restart"
    process.close()
    restarted = runtime.Reporter("dashboard", directory=tmp_path,
        captured=captured({"dashboard": {"compress": True}}, at=clock[0]), clock=lambda: clock[0])
    restarted.renew()
    observed, unavailable = runtime.records(directory=tmp_path, now=clock[0])
    assert runtime.setting_status(setting(), desired, observed, unavailable=unavailable)["state"] == "acknowledged"
    restarted.close()


def test_stale_wrong_consumer_and_tenant_receipts_cannot_confirm(tmp_path, isolated):
    value = captured({"dashboard": {"compress": True}})
    process = runtime.Reporter("worker", directory=tmp_path, captured=value, clock=lambda: 101)
    process.renew()
    observed, _ = runtime.records(directory=tmp_path, now=102)
    assert runtime.setting_status(setting(), value, observed)["state"] == "unconfirmed"
    assert runtime.setting_status(setting("maverick.worker", ("queue", "backend")), value, observed)["state"] == "acknowledged"
    observed, _ = runtime.records(directory=tmp_path, now=250)
    assert runtime.setting_status(setting("maverick.worker", ("queue", "backend")), value, observed)["state"] == "unconfirmed"
    process.global_scope = False
    process.renew()
    observed, _ = runtime.records(directory=tmp_path, now=102)
    assert runtime.setting_status(setting("maverick.worker", ("queue", "backend")), value, observed)["state"] == "unconfirmed"


def test_source_and_environment_changes_remain_pending_without_exposing_values(tmp_path, isolated):
    secret = "test-only-private-channel-token"
    original = captured({"channels": {"matrix": {"token": secret}}}, {"MATRIX_TOKEN": secret})
    process = runtime.Reporter("channels", directory=tmp_path, captured=original, clock=lambda: 101)
    process.renew()
    assert secret not in process.path.read_text()
    observed, _ = runtime.records(directory=tmp_path, now=102)
    desired = runtime.snapshot({"channels": {"matrix": {"token": secret}}}, {"MATRIX_TOKEN": "changed"})
    row = setting("maverick.server", ("channels", "matrix", "token"), ("MATRIX_TOKEN",))
    result = runtime.setting_status(row, desired, observed)
    assert result["state"] == "pending_restart"
    assert secret not in str(result)


def test_first_capture_and_broken_receipts_stay_honest(tmp_path, isolated, monkeypatch):
    monkeypatch.setattr(runtime, "_CAPTURE", None)
    runtime.remember({"dashboard": {"compress": False}}, valid=False)
    old = runtime._CAPTURE.copy()
    runtime.remember({"dashboard": {"compress": True}})
    assert old == runtime._CAPTURE
    assert runtime.Reporter("dashboard", directory=tmp_path, captured=old).renew() is False
    (tmp_path / "broken.enc").write_bytes(b"not a receipt")
    observed, unavailable = runtime.records(directory=tmp_path, now=100)
    assert unavailable
    assert runtime.setting_status(setting(), runtime.snapshot({}, {}), observed, unavailable=unavailable)["state"] == "unconfirmed"
