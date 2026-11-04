"""HTTP-plane load harness: concurrent clients, no 5xx, admission holds.

Small fleet here (CI keeps this cheap); the module's defaults are the real
load shape for standalone runs (``python -m maverick_dashboard.load_harness``).
"""
from __future__ import annotations

import pytest
from maverick_dashboard import load_harness


@pytest.fixture(autouse=True)
def _fresh_world(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    for name in (
        "MAVERICK_ENTERPRISE", "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_DASHBOARD_REQUIRE_AUTH", "MAVERICK_OIDC_ENABLED",
        "MAVERICK_PROXY_AUTH",
    ):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "config.toml").write_text(
        "[vendor_management]\nenable = true\n", encoding="utf-8")
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    import maverick_dashboard.api as api
    api._world_cache.clear()
    yield
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    api._world_cache.clear()


def test_guarantees_hold_under_concurrent_clients(tmp_path):
    proof = load_harness.run_load(
        tmp_path / "world.db", workers=4, requests=6)
    # A string message: pytest shortens a long non-string one past the failing response.
    assert proof["ok"] is True, f"{proof['checks']} {proof.get('unexpected')} {proof.get('statuses')}"
    assert proof["checks"]["no_5xx"] is True
    assert proof["checks"]["contended_name_is_one_record"] is True
    assert proof["checks"]["requests_all_metered"] is True
    assert proof["requests_issued"] == 4 * 6 * 5
    # The status spread is intended traffic only: reads, admits, CAS losers.
    assert set(proof["statuses"]) <= {"200", "201", "409"}


def test_refuses_a_mispinned_world():
    with pytest.raises(RuntimeError, match="pin the environment"):
        load_harness.run_load(load_harness.Path("/nowhere/world.db"))


def test_guarantees_hold_over_a_real_loopback_socket(tmp_path):
    """The same assertions across a real HTTP parser and socket. A claim
    that only survives without a socket is not a claim about production —
    this transport is what caught the harness sending a stale Origin that
    the app's CSRF check (correctly) refused."""
    proof = load_harness.run_load(
        tmp_path / "world.db", workers=2, requests=2, transport="http")
    # A string message: pytest shortens a long non-string one past the failing response.
    assert proof["ok"] is True, f"{proof['checks']} {proof.get('unexpected')} {proof.get('statuses')}"
    assert proof["transport"] == "http"
    assert proof["requests_issued"] == 2 * 2 * 5
    assert set(proof["statuses"]) <= {"200", "201", "409"}
    assert proof["checks"]["no_5xx"] is True
    assert proof["checks"]["world_db_integrity_ok"] is True


def test_unknown_transport_is_refused(tmp_path):
    with pytest.raises(ValueError, match="transport"):
        load_harness.run_load(tmp_path / "world.db", transport="carrier-pigeon")
