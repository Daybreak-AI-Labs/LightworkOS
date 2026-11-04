"""An approved oversight canary must never authorize anything: not the real
operation it was modelled on, not any other consumer of approvals."""
from __future__ import annotations

import random

import pytest
from maverick import external_agents as xa


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    (tmp_path / "config.toml").write_text(
        "[external_agents]\nenable = true\nmint_approval = true\n"
        "[immune]\ncanaries = true\n", encoding="utf-8")
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def test_an_approved_canary_cannot_mint_the_credential_it_was_modelled_on():
    from maverick.approval_cards import decode_approval_detail
    from maverick.immune import oversight
    from maverick.world_model import WorldModel
    xa.enroll("sf-quotebot", "agentforce", description="q", owner="jordan@corp.test",
              department="sales", max_risk="medium", max_dollars=5.0,
              enrolled_by="admin@corp.test")
    with pytest.raises(xa.MintApprovalPending) as exc:
        xa.mint_token("sf-quotebot", "rest", minted_by="admin@corp.test")
    real = exc.value.approval_id
    world = WorldModel()
    canary = oversight.generate_canary(world, rng=random.Random(1))
    assert canary["modelled_on"] == real
    row, source = world.get_approval(canary["approval_id"]), world.get_approval(real)
    assert row.provenance is None and source.provenance == "external_agents"
    card, orig = decode_approval_detail(row.detail), decode_approval_detail(source.detail)
    for section in ("target", "parameters"):
        assert card[section]["sha256"] != orig[section]["sha256"]
    assert all(card["inputs"][k] != v for k, v in orig["inputs"].items())
    world.decide_approval(real, "denied", decided_by="lead@corp.test")
    world.decide_approval(canary["approval_id"], "approved", decided_by="reviewer@corp.test")
    with pytest.raises(xa.ExternalAgentsError):
        xa.mint_token("sf-quotebot", "rest", minted_by="admin@corp.test",
                      mint_approval_id=canary["approval_id"])
