"""Capability self-report tool."""
from __future__ import annotations

import json

import pytest
from maverick.tools.capability_query import capability_query


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    # No config -> all-permissive, default-open grant.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("MAVERICK_ENFORCE_CAPABILITIES", raising=False)
    yield


def test_enforced_off_by_default():
    out = capability_query().fn({"op": "enforced"})
    assert "OFF" in out


def test_enforced_on_with_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENFORCE_CAPABILITIES", "1")
    out = capability_query().fn({"op": "enforced"})
    assert "ON" in out


def test_list_reports_all_permissive_grant():
    out = capability_query(user_id="alice").fn({"op": "list"})
    data = json.loads(out)
    assert data["principal"] == "alice"
    assert data["allow_tools"] == "(all)"
    assert data["enforced"] is False


def test_per_user_policy_applies_to_the_reported_grant(tmp_path):
    cfg = tmp_path / ".maverick"
    cfg.mkdir()
    (cfg / "config.toml").write_text('[security.users.alice]\nmax_risk = "low"\n')
    data = json.loads(capability_query(user_id="alice").fn({"op": "list"}))
    assert data["max_risk"] == "low"
    out = capability_query(user_id="alice").fn({"op": "check", "tool": "shell"})
    assert "denied" in out


def test_check_permitted_when_open():
    out = capability_query().fn({"op": "check", "tool": "read_file"})
    assert "permitted" in out
    assert "advisory" in out  # enforcement off -> advisory note


def test_check_requires_tool_name():
    assert capability_query().fn({"op": "check"}).startswith("ERROR")


def test_unknown_op():
    assert capability_query().fn({"op": "bogus"}).startswith("ERROR")


def test_check_non_string_tool_does_not_crash():
    out = capability_query().fn({"op": "check", "tool": 5})
    assert not out.startswith("Traceback")
    assert out.startswith("ERROR") or "permitted" in out or "denied" in out
