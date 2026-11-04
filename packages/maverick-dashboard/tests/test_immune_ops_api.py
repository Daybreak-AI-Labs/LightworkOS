"""Safety monitoring extras: a reviewer test you write yourself and the check
for chains of assistants where private data could get out -- ``maverick
immune canary`` and ``maverick immune network`` as buttons."""
from __future__ import annotations

import html as _html
import json
import re

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
BANNED = re.compile(
    r"\b(tenant|principal|payload|endpoint|schema|uuid|sha-?256|digest|json|revision|"
    r"idempoten\w*|lease|toml|yaml|stdout|traceback|canary|trifecta|swarm)\b|/api/v1|HTTP \d{3}|"
    r"maverick |MAVERICK_|\[\w+\]",
    re.IGNORECASE,
)
CANARY = {"action": "Pay invoice 4411", "detail": "Pay Acme Ltd $4,200 to account 11-22-33.",
          "decision_class": "payments", "flaw": "The account number was changed last week.", "risk": "high"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash_app

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    (tmp_path / "config.toml").write_text("[immune]\ncanaries = true\n", encoding="utf-8")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    import maverick.runtime_overrides as ro
    monkeypatch.setattr(ro, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    dash_app._world_cache.clear()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers=ORIGIN)
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    dash_app._world_cache.clear()


def _as(monkeypatch, role: str, who: str = "user:someone"):
    from maverick_dashboard import auth, rbac
    rbac.set_role(who, role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: who)


def test_written_reviewer_test_lands_in_the_queue_and_keeps_its_mistake_private(client, monkeypatch):
    import maverick.audit as audit_pkg
    from maverick.audit import writer
    from maverick.immune import _ledger, oversight
    from maverick_dashboard import app as dash_app

    seen: list[dict] = []
    real = writer.audit_event

    def spy(kind, **payload):
        seen.append({"kind": kind, **payload})
        return real(kind, **payload)
    monkeypatch.setattr(audit_pkg, "audit_event", spy)
    r = client.post("/api/v1/immune/canaries/written", json=CANARY)
    assert r.status_code == 200, r.text
    assert "changed last week" not in r.text and r.json()["planted"] == 1
    approvals = dash_app._world().pending_approvals()
    assert [a.action for a in approvals] == ["Pay invoice 4411"]
    ledger = _ledger.read(oversight.ledger_path())
    assert ledger[-1]["flaw"] == CANARY["flaw"] and ledger[-1]["class"] == "payments"
    recorded = [row for row in seen if row.get("action") == "plant_written_reviewer_test"]
    assert recorded and "flaw" not in json.dumps(recorded)


def test_written_reviewer_test_refusals(client, monkeypatch, tmp_path):
    assert client.post("/api/v1/immune/canaries/written", json={**CANARY, "risk": "extreme"}).status_code == 422
    assert client.post("/api/v1/immune/canaries/written", json={**CANARY, "flaw": ""}).status_code == 422
    assert client.post("/api/v1/immune/canaries/written",
                       json={**CANARY, "detail": "x" * 5000}).status_code == 422
    assert client.post("/api/v1/immune/canaries/written",
                       json={**CANARY, "requested_by": "user:nobody"}).status_code == 422
    from maverick import config
    (tmp_path / "config.toml").write_text("[immune]\ncanaries = false\n", encoding="utf-8")
    config.reset_config_cache()
    off = client.post("/api/v1/immune/canaries/written", json=CANARY)
    assert off.status_code == 409 and "turned off" in off.json()["detail"]
    _as(monkeypatch, "auditor")
    assert client.post("/api/v1/immune/canaries/written", json=CANARY).status_code == 403


def test_network_check_for_a_described_set_of_assistants(client, monkeypatch):
    graph = {"agents": {"reader": ["read_email"], "writer": ["write_file"], "sender": ["http_post"]},
             "flows": [["reader", "writer"], ["writer", "sender"]]}
    r = client.post("/api/v1/immune/network/check", json={"graph": json.dumps(graph)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["assistants"] == 3
    assert not BANNED.search(body["summary"])
    bad = client.post("/api/v1/immune/network/check",
                      json={"graph": json.dumps({"agents": {"a": ["x"]}, "flows": [["a", "ghost"]]})})
    assert bad.status_code == 422
    assert client.post("/api/v1/immune/network/check", json={"graph": "not a map"}).status_code == 422
    assert client.post("/api/v1/immune/network/check", json={"graph": "x" * 600_000}).status_code == 422
    _as(monkeypatch, "operator")
    assert client.post("/api/v1/immune/network/check", json={}).status_code == 403


def test_network_check_for_the_installed_assistants(client, monkeypatch):
    from maverick.immune import network

    calls = []
    real = network.roster_graph

    def roster(domains=None, *, swarm=False, levels=None, grounding=None):
        calls.append((swarm, levels, grounding))
        return real({}, swarm=swarm, levels=levels, grounding=grounding)
    monkeypatch.setattr(network, "roster_graph", roster)
    r = client.post("/api/v1/immune/network/check", json={"shared_messaging": True})
    assert r.status_code == 200, r.text
    r = client.post("/api/v1/immune/network/check", json={"levels": False, "grounding": True})
    assert r.status_code == 200, r.text
    assert calls == [(True, None, None), (False, False, True)]


def _aero(monkeypatch):
    from maverick import domain
    aero = {k: v for k, v in domain.available_domains().items() if k.startswith("aero_")}
    monkeypatch.setattr(domain, "available_domains", lambda: aero)
    return aero


def test_what_if_dials_reach_the_check_and_nothing_else(client, monkeypatch):
    import os
    _aero(monkeypatch)
    monkeypatch.setenv("MAVERICK_WORKFORCE_LEVELS", "0")
    monkeypatch.setenv("MAVERICK_WORKFORCE_DATA_GROUNDING", "0")
    before = dict(os.environ)
    live = client.post("/api/v1/immune/network/check", json={}).json()
    what_if = client.post("/api/v1/immune/network/check", json={"levels": True, "grounding": False}).json()
    assert live["assistants"] == what_if["assistants"]
    # Letting assistants act on their own adds ways out (email, notify, calendar).
    assert what_if["total"] > live["total"]
    assert dict(os.environ) == before
    again = client.post("/api/v1/immune/network/check", json={}).json()
    assert again == live
    assert client.post("/api/v1/immune/network/check", json={"levels": "maybe"}).status_code == 422


def test_a_what_if_never_changes_live_assistants_even_during_a_concurrent_request(client, monkeypatch):
    """While a what-if check with autonomy levels on is half way through, the
    environment is untouched, a live assistant's tools are unchanged and a
    concurrent live check reports the installation's real setting."""
    import os
    import threading

    from maverick import domain

    aero = _aero(monkeypatch)
    monkeypatch.setenv("MAVERICK_WORKFORCE_LEVELS", "0")
    monkeypatch.setenv("MAVERICK_WORKFORCE_DATA_GROUNDING", "0")
    baseline = client.post("/api/v1/immune/network/check", json={}).json()
    profile = aero["aero_airworthiness"]
    real = domain.domain_capability
    live_tools_before = real(profile, None, "agent:aero_airworthiness").allow_tools
    inside, release = threading.Event(), threading.Event()

    def paused(*args, **kwargs):
        if kwargs.get("levels") is True and not inside.is_set():
            inside.set()
            release.wait(10)
        return real(*args, **kwargs)
    monkeypatch.setattr(domain, "domain_capability", paused)
    writes: list[str] = []
    real_putenv, real_unsetenv = os.putenv, os.unsetenv
    monkeypatch.setattr(os, "putenv", lambda k, v: (writes.append(k), real_putenv(k, v)))
    monkeypatch.setattr(os, "unsetenv", lambda k: (writes.append(k), real_unsetenv(k)))

    results: dict[str, dict] = {}

    def run(name, body):
        results[name] = client.post("/api/v1/immune/network/check", json=body).json()

    what_if = threading.Thread(target=run, args=("what_if", {"levels": True}))
    what_if.start()
    try:
        assert inside.wait(30), "the what-if check did not start"
        # Mid-flight: nothing global changed and live assistants are as before.
        assert os.environ["MAVERICK_WORKFORCE_LEVELS"] == "0"
        assert real(profile, None, "agent:aero_airworthiness").allow_tools == live_tools_before
        concurrent = threading.Thread(target=run, args=("live", {}))
        concurrent.start()
        concurrent.join(60)
        assert results["live"] == baseline
    finally:
        release.set()
        what_if.join(60)
    assert results["what_if"]["total"] > baseline["total"]
    assert not [k for k in writes if k.startswith("MAVERICK_WORKFORCE")]
    assert os.environ["MAVERICK_WORKFORCE_LEVELS"] == "0"


def test_immune_page_shows_the_new_controls_plainly(client, monkeypatch):
    page = client.get("/immune").text
    for control in ("ops-canary-form", "ops-canary-flaw", "ops-network-run", "ops-network-shared",
                    "ops-network-file", "ops-network-levels", "ops-network-grounding"):
        assert f'id="{control}"' in page
    start = page.index('id="ops-immune"')
    section = page[start:page.index("</section>", start)]
    text = _html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", section)))
    assert not BANNED.search(text)
    _as(monkeypatch, "auditor")
    page = client.get("/immune").text
    assert 'id="ops-canary-form"' not in page and 'id="ops-network-run"' in page


@pytest.mark.parametrize(("undoable", "held"), [(None, True), (True, True), (False, False)])
def test_a_written_reviewer_test_matches_the_undo_of_the_request_it_imitates(client, undoable, held):
    # A task's step can be undone for a moment after a decision; a merge, a
    # settings change or agent access cannot. The test approval matches.
    from maverick.channel_approvals import held_for_undo
    from maverick_dashboard import app as dash_app

    body = dict(CANARY) if undoable is None else {**CANARY, "undoable": undoable}
    assert client.post("/api/v1/immune/canaries/written", json=body).status_code == 200
    (approval,) = dash_app._world().pending_approvals()
    assert held_for_undo(approval) is held
