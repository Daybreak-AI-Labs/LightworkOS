from __future__ import annotations

import pytest
from maverick._mcp_parent_guard import ParentGuardError, arm_from_environment

_PID = "MAVERICK_MCP_PARENT_PID"
_STARTED = "MAVERICK_MCP_PARENT_STARTED_EPOCH_MILLIS"
_TOKEN = "MAVERICK_MCP_PARENT_TOKEN"
_READY = "MAVERICK_MCP_PARENT_READY_FILE"
_RELEASE = "MAVERICK_MCP_PARENT_RELEASE_FILE"
_KEYS = (_PID, _STARTED, _TOKEN, _READY, _RELEASE)


def _clear_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in _KEYS:
        monkeypatch.delenv(key, raising=False)


def test_parent_guard_is_inert_without_tagged_launcher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_contract(monkeypatch)
    assert arm_from_environment() is False


@pytest.mark.parametrize(
    ("pid", "started"),
    [
        ("not-a-pid", "1"),
        ("1", "not-a-time"),
        ("0", "1"),
        ("1", "0"),
        ("+1", "1"),
        ("1", " 1"),
    ],
)
def test_parent_guard_rejects_malformed_process_identity(
    monkeypatch: pytest.MonkeyPatch,
    pid: str,
    started: str,
) -> None:
    _clear_contract(monkeypatch)
    monkeypatch.setenv(_PID, pid)
    monkeypatch.setenv(_STARTED, started)
    monkeypatch.setenv(_TOKEN, "maverick-mcp-owner-test-contract")

    with pytest.raises(ParentGuardError):
        arm_from_environment()


def test_parent_guard_rejects_partial_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_contract(monkeypatch)
    monkeypatch.setenv(_PID, "123")

    with pytest.raises(ParentGuardError, match="incomplete"):
        arm_from_environment()


def test_parent_guard_rejects_unscoped_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_contract(monkeypatch)
    monkeypatch.setenv(_PID, "123")
    monkeypatch.setenv(_STARTED, "456")
    monkeypatch.setenv(_TOKEN, "not-a-java-launch-token")

    with pytest.raises(ParentGuardError, match="ownership token"):
        arm_from_environment()
