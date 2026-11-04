"""Installer contract for the installation-owned Research lab profile."""
from __future__ import annotations

import hashlib

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 CI
    import tomli as tomllib


def test_research_execution_is_explicitly_disabled_by_default(monkeypatch):
    from maverick_installer import wizard

    monkeypatch.setattr(wizard, "_q_confirm", lambda *args, **kwargs: False)
    assert wizard.pick_research_execution() == {"enable": False}


def test_research_execution_picker_hashes_expected_line_and_bounds_queue(monkeypatch):
    from maverick_installer import wizard

    answers = iter([
        "sha256:" + "1" * 64,
        "acceptance",
        "v2",
        "accepted",
        "999999",
    ])
    monkeypatch.setattr(wizard, "_q_confirm", lambda *args, **kwargs: True)
    monkeypatch.setattr(wizard, "_q_text", lambda *args, **kwargs: next(answers))

    result = wizard.pick_research_execution()

    assert result["enable"] is True
    assert result["queue_seconds"] == 86400
    assert result["evaluators"] == {
        "acceptance": {
            "version": "v2",
            "stdout_sha256": hashlib.sha256(b"accepted\n").hexdigest(),
        }
    }


def test_research_execution_toml_round_trip_uses_controller_schema():
    from maverick_installer import wizard

    expected = {
        "enable": True,
        "image_id": "sha256:" + "2" * 64,
        "queue_seconds": 600,
        "evaluators": {
            "smoke": {"version": "v1", "stdout_sha256": "3" * 64},
        },
        "limits": {
            "timeout_seconds": 5.0,
            "output_bytes": 4096,
            "memory_bytes": 67108864,
            "scratch_bytes": 2097152,
            "pids": 16,
            "cpus": 0.25,
        },
    }
    parsed = tomllib.loads("\n".join(wizard._cfg_research_execution(expected)))
    assert parsed["research_execution"] == expected
    assert tomllib.loads("\n".join(
        wizard._cfg_research_execution({"enable": False})
    )) == {"research_execution": {"enable": False}}


def test_research_execution_writer_refuses_mutable_or_unbounded_profiles():
    from maverick_installer import wizard

    with pytest.raises(ValueError):
        wizard._cfg_research_execution({
            "enable": True,
            "image_id": "python:latest",
            "queue_seconds": 3600,
            "evaluators": {"smoke": {"version": "v1", "stdout_sha256": "4" * 64}},
        })
    with pytest.raises(ValueError):
        wizard._cfg_research_execution({
            "enable": True,
            "image_id": "sha256:" + "5" * 64,
            "queue_seconds": 1,
            "evaluators": {"smoke": {"version": "v1", "stdout_sha256": "4" * 64}},
        })
