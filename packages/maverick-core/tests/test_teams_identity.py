"""Teams account links: one-time link codes."""
from __future__ import annotations

import pytest
from maverick import teams_identity


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(teams_identity, "_audit", lambda *a, **k: None)


def test_redeem_respects_the_link_cap_and_wrong_guesses_do_not_rewrite(monkeypatch):
    code = teams_identity.issue_link_code("user:carol")
    writes = []
    real_write = teams_identity._write
    monkeypatch.setattr(teams_identity, "_write", lambda data: writes.append(1) or real_write(data))
    assert teams_identity.redeem_link_code("DEADBEEF", "someone") is None
    assert writes == []

    monkeypatch.setattr(teams_identity, "MAX_LINKS", 0)
    assert teams_identity.redeem_link_code(code, "carol-object-id") is None
    monkeypatch.setattr(teams_identity, "MAX_LINKS", 10)
    # The refused redemption left the code usable.
    assert teams_identity.redeem_link_code(
        code, "carol-object-id", conversation={"service_url": "https://x", "conversation_id": "c" * 5000},
    ) == "user:carol"
    row = teams_identity.link_for("carol-object-id")
    assert len(row["conversation"]["conversation_id"]) == 2048
