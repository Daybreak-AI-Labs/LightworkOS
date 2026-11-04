"""`maverick trust` admin: the JSON managed-registry overlay (add/rotate/revoke
without editing TOML) and the CLI surface that drives it."""
from __future__ import annotations

import pytest
from maverick import agent_trust, client


@pytest.fixture(autouse=True)
def _isolated_home(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CLIENT_ID", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    client.reset_client_cache()
    yield
    client.reset_client_cache()


# ---- managed registry overlay ---------------------------------------------


def test_put_and_load_merges_managed():
    agent_trust.put_agent({"id": "vega", "pubkey": "ab" * 32,
                           "allow_tools": ["read_file"], "direction": "both"})
    reg = agent_trust.load_registry({})  # config has no agents; managed supplies vega
    assert "vega" in reg
    assert reg["vega"].allow_tools == frozenset({"read_file"})


def test_managed_registry_and_parent_are_private():
    from maverick.file_lock import private_path_is_restricted

    agent_trust.put_agent({"id": "vega", "pubkey": "ab" * 32})
    path = agent_trust.managed_path()
    assert private_path_is_restricted(path)
    assert private_path_is_restricted(path.parent, 0o700)


def test_put_replaces_same_id():
    agent_trust.put_agent({"id": "vega", "max_risk": "low"})
    agent_trust.put_agent({"id": "vega", "max_risk": "high"})
    reg = agent_trust.load_registry({})
    assert reg["vega"].max_risk == "high"
    # exactly one managed entry for vega
    assert sum(1 for e in agent_trust._load_managed() if e["id"] == "vega") == 1


def test_remove_agent():
    agent_trust.put_agent({"id": "vega"})
    assert agent_trust.remove_agent("vega") is True
    assert "vega" not in agent_trust.load_registry({})
    assert agent_trust.remove_agent("vega") is False


def test_revoke_blocks_via_is_active():
    agent_trust.put_agent({"id": "vega", "pubkey": "ab" * 32})
    assert agent_trust.set_revoked("vega", True) is True
    reg = agent_trust.load_registry({})
    assert reg["vega"].is_active()[0] is False
    d = agent_trust.decide_inbound("vega", registry=reg, enforced=True)
    assert d.denied and d.rule == "revoked"
    agent_trust.set_revoked("vega", False)
    assert agent_trust.load_registry({})["vega"].is_active()[0] is True


def test_managed_overrides_config_entry():
    cfg = {"agent_trust": {"agents": [{"id": "vega", "max_risk": "low"}]}}
    assert agent_trust.load_registry(cfg)["vega"].max_risk == "low"
    agent_trust.put_agent({"id": "vega", "max_risk": "high"})
    assert agent_trust.load_registry(cfg)["vega"].max_risk == "high"  # managed wins


def test_corrupt_managed_store_invalidates_entire_registry():
    """A lost managed revocation must not expose the looser TOML entry."""
    path = agent_trust.managed_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not-json", encoding="utf-8")

    cfg = {"agent_trust": {"agents": [{"id": "vega", "max_risk": "high"}]}}
    assert agent_trust.load_registry(cfg) == {}


def test_malformed_managed_entry_invalidates_entire_registry():
    import json

    path = agent_trust.managed_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([
        {"id": "vega", "max_risk": "low"},
        {"id": "rigel", "allow_tools": {"read_file": True}},
    ]), encoding="utf-8")

    assert agent_trust.load_registry({}) == {}


def test_mutator_refuses_to_overwrite_corrupt_managed_store():
    path = agent_trust.managed_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    original = "{not-json"
    path.write_text(original, encoding="utf-8")

    with pytest.raises(agent_trust.AgentTrustError, match="managed registry"):
        agent_trust.put_agent({"id": "vega", "max_risk": "low"})
    assert path.read_text(encoding="utf-8") == original


def test_put_invalid_raises():
    with pytest.raises(agent_trust.AgentTrustError):
        agent_trust.put_agent({"id": "BAD ID"})


def test_put_rejects_malformed_pubkey():
    with pytest.raises(agent_trust.AgentTrustError, match="invalid pubkey"):
        agent_trust.put_agent({"id": "vega", "pubkey": "not-a-hex-key"})
    assert "vega" not in agent_trust.load_registry({})


def test_managed_path_is_client_scoped(monkeypatch):
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "acme")
    client.reset_client_cache()
    assert "tenants/acme" in str(agent_trust.managed_path()).replace("\\", "/")


def test_local_pubkey():
    pytest.importorskip("cryptography")
    pk = agent_trust.local_pubkey()
    assert isinstance(pk, str) and len(pk) == 64


# ---- CLI ------------------------------------------------------------------


def _run(*args):
    from click.testing import CliRunner
    from maverick.cli import main
    return CliRunner().invoke(main, list(args))


def test_cli_add_list_show_verify_revoke_rm():
    r = _run("trust", "add", "vega", "--pubkey", "ab" * 32,
             "--allow-tools", "read_file", "--max-risk", "medium",
             "--direction", "both")
    assert r.exit_code == 0 and "saved" in r.output

    r = _run("trust", "list")
    assert r.exit_code == 0 and "vega" in r.output

    r = _run("trust", "show", "vega")
    assert r.exit_code == 0 and "read_file" in r.output

    # verify replays the decision
    r = _run("trust", "verify", "vega", "--tools", "read_file")
    assert r.exit_code == 0 and "ALLOW" in r.output
    r = _run("trust", "verify", "vega", "--tools", "shell")
    assert r.exit_code == 0 and "DENY" in r.output

    r = _run("trust", "revoke", "vega")
    assert r.exit_code == 0 and "revoked" in r.output
    r = _run("trust", "verify", "vega")
    assert "DENY" in r.output and "revoked" in r.output

    r = _run("trust", "rm", "vega")
    assert r.exit_code == 0 and "removed" in r.output


def test_cli_rejects_malformed_pubkey():
    r = _run("trust", "add", "vega", "--pubkey", "not-a-hex-key")
    assert r.exit_code != 0
    assert "invalid pubkey" in r.output
    assert "vega" not in agent_trust.load_registry({})


def test_cli_show_unknown_errors():
    r = _run("trust", "show", "ghost")
    assert r.exit_code != 0


def test_cli_status_runs():
    r = _run("trust", "status")
    assert r.exit_code == 0 and "agent trust plane" in r.output


# ---- concurrency: the registry mutators must not lose updates --------------

def test_concurrent_puts_do_not_lose_agents():
    """put_agent does a lock-free load-modify-save; without serialization two
    concurrent puts both load the same registry and the second save clobbers
    the first -- a registered agent silently vanishes. All N must survive."""
    import threading

    n = 24
    errors: list[Exception] = []

    def make(i: int):
        try:
            agent_trust.put_agent({"id": f"agent{i:03d}", "max_risk": "low"})
        except (agent_trust.AgentTrustError, OSError) as e:
            errors.append(e)

    threads = [threading.Thread(target=make, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors[:3]
    ids = {e.get("id") for e in agent_trust._load_managed()}
    assert len([i for i in ids if i and i.startswith("agent")]) == n


def test_concurrent_revoke_is_not_lost_against_a_put():
    """A set_revoked(True) racing a put_agent on a DIFFERENT id must not be
    clobbered -- a lost revoke leaves a revoked external agent trusted."""
    import threading

    agent_trust.put_agent({"id": "vega", "pubkey": "ab" * 32})
    barrier = threading.Barrier(2)

    def revoke():
        barrier.wait()
        agent_trust.set_revoked("vega", True)

    def other_put():
        barrier.wait()
        agent_trust.put_agent({"id": "rigel", "max_risk": "low"})

    ts = [threading.Thread(target=revoke), threading.Thread(target=other_put)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

    by_id = {e.get("id"): e for e in agent_trust._load_managed()}
    assert by_id["vega"].get("revoked") is True   # the revoke survived
    assert "rigel" in by_id                        # and so did the concurrent add
