"""A real disposable native undo race and the closed sharing boundary."""
import json

import pytest
from maverick import approval_challenges as challenges


def test_closed_challenge_replays_native_undo_without_customer_settings(tmp_path, monkeypatch):
    config = tmp_path / "challenge.toml"
    config.write_text("[approval_challenges]\nenable=true\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config))
    monkeypatch.setenv("MAVERICK_TENANT", "practice-test-workspace")
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "practice-test-client")
    monkeypatch.setenv("OPENAI_API_KEY", "private-test-key-never-exported")
    artifact = challenges.compile_challenge("round_changed", 2)
    exported = json.dumps(artifact).encode()
    assert challenges.parse(exported) == artifact
    with pytest.raises(ValueError, match="supported practice file"):
        challenges.parse(json.dumps({**artifact, "private_incident": "never-export-this"}).encode())
    with pytest.raises(ValueError):
        challenges.parse(b'{"family": ["claim_changed"]}')
    result = challenges.check_native(artifact)
    assert result["fault_variant_reproduced"] is True
    assert result["native_guard_blocked"] is True
    assert result["native_vote_recorded"] is False
    assert result["customer_queue_changed"] is False
    assert result["adapter_version"] == challenges.adapter_version()
    assert "practice-test-workspace" not in exported.decode()
    assert "private-test-key" not in exported.decode()
    assert not list(tmp_path.rglob("modeled-fault.db"))
    assert not list(tmp_path.rglob("native-receiver.db"))
