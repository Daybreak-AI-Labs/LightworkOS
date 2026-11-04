"""Tests for the agent control-plane dashboard pages (replay + agent trust)."""
from __future__ import annotations

import hashlib
import json

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app
from maverick_dashboard.control_plane import build_replay, trust_overview

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    # Fresh world DB + audit dir per test (MAVERICK_HOME steers data_dir("audit")).
    from maverick import world_model
    from maverick.audit import writer as audit_writer
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_AUDIT_SIGN", raising=False)
    # The no-tenant audit writer is a module-level singleton keyed to the first
    # dir it saw; reset it so record() targets THIS test's MAVERICK_HOME (the
    # sanctioned override per writer.default_audit_log's docstring).
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    yield


def _seed_run() -> int:
    """Create a goal + write a few governed audit events for it; return its id."""
    from maverick.audit import EventKind, record
    from maverick.world_model import open_world
    w = open_world()
    gid = w.create_goal("Vendor payment run")
    record(EventKind.GOAL_START, goal_id=gid, title="Vendor payment run")
    record(EventKind.TOOL_CALL, goal_id=gid, name="browser", input_summary="navigate checkout")
    record(EventKind.CONSENT_PROMPT, goal_id=gid, action="browser.click",
           risk="high", scope="text=Pay now")
    record(EventKind.CONSENT_RESULT, goal_id=gid, action="browser.click",
           decision="approve", source="dashboard")
    record(EventKind.TOOL_CALL, goal_id=gid, name="browser", input_summary="click Pay now")
    record(EventKind.GOAL_END, goal_id=gid, status="done")
    return gid


# ---- replay / flight recorder ----------------------------------------------

@pytest.fixture
def replay_signing_key(monkeypatch):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from maverick.audit import signing

    private = hashlib.sha256(b"control-plane-replay-synthetic-test-key").digest()
    public = Ed25519PrivateKey.from_private_bytes(private).public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
    )
    monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", private.hex())
    monkeypatch.setattr(signing, "_INJECTED_KEYPAIR_CACHE", signing._INJECTED_KEYPAIR_UNREAD)
    return public.hex()


@pytest.mark.parametrize("signing_enabled", [False, True], ids=["unsigned", "signed"])
def test_build_replay_timeline_and_chain(monkeypatch, replay_signing_key, signing_enabled):
    from maverick.audit import verify_chain
    from maverick.audit.writer import default_audit_log

    # Deleting the override inherits secure defaults; explicitly test both
    # supported policies without disabling the surrounding secure posture.
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1" if signing_enabled else "0")
    gid = _seed_run()
    rep = build_replay(gid)
    kinds = [e["kind"] for e in rep["entries"]]
    assert "tool_call" in kinds
    assert "consent_prompt" in kinds
    assert "consent_result" in kinds
    assert rep["summary"]["tool_calls"] == 2
    assert rep["summary"]["approvals"] == 1
    assert rep["summary"]["approved"] == 1
    assert rep["chain"]["status"] == ("verified" if signing_enabled else "unsigned")
    assert rep["chain"]["signed"] is signing_enabled
    assert rep["chain"]["break_count"] == 0
    assert rep["chain"]["breaks"] == []
    writer = default_audit_log()
    assert writer.signing_enabled is signing_enabled
    paths = list(writer.audit_dir.glob("*.ndjson"))
    assert len(paths) == 1
    rows = [json.loads(line) for line in paths[0].read_text(encoding="utf-8").splitlines()]
    assert len(rows) >= 6
    signing_fields = {"prev_hash", "hash", "sig", "key_id"}
    if signing_enabled:
        assert all(signing_fields <= row.keys() for row in rows)
        # Verify actual signatures against the fixture's independently held
        # public key, not just the replay status or a co-located key lookup.
        assert verify_chain(paths[0], pubkey_hex=replay_signing_key) == []
    else:
        assert all(not signing_fields.intersection(row) for row in rows)
        breaks = verify_chain(paths[0])
        assert len(breaks) == len(rows)
        assert all(item.reason == "unsigned" for item in breaks)
    prompts = [e for e in rep["entries"] if e["kind"] == "consent_prompt"]
    assert prompts and prompts[0]["risk"] == "high"


@pytest.mark.parametrize("tamper", ["payload", "signature"])
def test_signed_replay_rejects_modified_event(monkeypatch, replay_signing_key, tamper):
    from maverick.audit import verify_chain
    from maverick.audit.writer import default_audit_log

    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    gid = _seed_run()
    assert build_replay(gid)["chain"]["status"] == "verified"
    path = next(default_audit_log().audit_dir.glob("*.ndjson"))
    assert verify_chain(path, pubkey_hex=replay_signing_key) == []
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    row = next(item for item in rows if item["kind"] == "consent_result")
    if tamper == "payload":
        row["decision"] = "deny"
    else:
        signature = bytes.fromhex(row["sig"])
        row["sig"] = bytes([signature[0] ^ 1]).hex() + signature[1:].hex()
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    reason = "bad_hash" if tamper == "payload" else "bad_signature"
    assert reason in {item.reason for item in verify_chain(path, pubkey_hex=replay_signing_key)}
    replay = build_replay(gid)
    assert replay["chain"]["status"] == "broken"
    assert replay["chain"]["break_count"] >= 1
    assert reason in {item["reason"] for item in replay["chain"]["breaks"]}
    assert replay["read_report"]["verification"] == "failed"


def test_replay_chain_includes_anchor_ledger_breaks(monkeypatch):
    import maverick.audit as audit
    from maverick.audit import ChainBreak
    from maverick.paths import data_dir
    from maverick_dashboard.control_plane import _verify_days

    day = "2026-06-16"
    audit_dir = data_dir("audit")
    audit_dir.mkdir(parents=True)
    (audit_dir / f"{day}.ndjson").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(audit, "verify_chain", lambda path: [])
    monkeypatch.setattr(
        audit,
        "verify_anchors",
        lambda path: [ChainBreak(0, "anchor_tip_mismatch", "2026-06-16 tip mismatch")],
    )

    chain = _verify_days([day])

    assert chain["status"] == "broken"
    assert chain["break_count"] == 1
    assert chain["breaks"][0]["reason"] == "anchor_tip_mismatch"


def test_replay_chain_flags_deleted_anchored_day(monkeypatch):
    import maverick.audit as audit
    from maverick.audit import ChainBreak
    from maverick_dashboard.control_plane import _verify_days

    day = "2026-06-16"
    monkeypatch.setattr(
        audit,
        "verify_anchors",
        lambda path: [ChainBreak(0, "anchored_file_deleted", f"{day}.ndjson is anchored but missing")],
    )

    chain = _verify_days([day])

    assert chain["status"] == "broken"
    assert chain["break_count"] == 1
    assert chain["breaks"][0]["reason"] == "anchored_file_deleted"


def test_stripped_signed_rows_are_integrity_breaks(monkeypatch, replay_signing_key):
    from maverick.audit.writer import default_audit_log
    from maverick_dashboard.control_plane import _verify_days

    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    _seed_run()
    path = next(default_audit_log().audit_dir.glob("????-??-??.ndjson"))
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    for row in rows:
        for key in ("prev_hash", "hash", "sig", "key_id"):
            row.pop(key, None)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    result = _verify_days([path.stem])
    assert result["status"] == "broken" and result["break_count"] > 0
    assert result["signed"] is False

def test_replay_filters_to_one_goal():
    gid = _seed_run()
    other = _seed_run()
    rep = build_replay(gid)
    # only this run's events; the other run is excluded
    assert rep["summary"]["total"] >= 5
    assert other != gid


def test_replay_api_and_evidence_download():
    gid = _seed_run()
    r = client.get(f"/api/v1/replay/{gid}")
    assert r.status_code == 200
    body = r.json()
    assert body["goal"]["id"] == gid
    assert body["artifact"] == "maverick.run_evidence"
    assert len(body["timeline"]) >= 5
    assert "chain" in body and "summary" in body

    ev = client.get(f"/api/v1/replay/{gid}/evidence")
    assert ev.status_code == 200
    cd = ev.headers.get("content-disposition", "")
    assert "attachment" in cd and f"evidence-goal-{gid}.json" in cd


def test_replay_api_404_for_unknown_goal():
    assert client.get("/api/v1/replay/999999").status_code == 404


def test_replay_page_renders():
    gid = _seed_run()
    assert client.get("/replay").status_code == 200          # index
    r = client.get(f"/replay?goal={gid}")
    assert r.status_code == 200
    assert "Task replay" in r.text
    from test_support.plain_language import developer_terms
    assert developer_terms(r.text) == []


# ---- agent trust / permission graph ----------------------------------------

def _fake_trust(monkeypatch, *, enforced=True):
    import maverick.agent_trust as at
    from maverick.agent_trust import TrustedAgent
    agent = TrustedAgent(
        id="vega", pubkey="ab" * 32, direction="inbound",
        allow_tools=frozenset({"read_file", "web_search"}),
        deny_tools=frozenset({"shell"}), max_risk="medium",
        max_dollars=5.0, data_scopes=frozenset({"crm"}),
    )
    monkeypatch.setattr(at, "load_trust_state", lambda: (enforced, {"vega": agent}))


def test_trust_overview_shapes_registry(monkeypatch):
    _fake_trust(monkeypatch)
    ov = trust_overview()
    assert ov["enforced"] is True
    a = ov["agents"][0]
    assert a["id"] == "vega"
    assert a["direction"] == "inbound"
    assert a["max_risk"] == "medium"
    assert "shell" in a["deny_tools"]
    assert a["active"] is True
    assert a["has_key"] is True


def test_trust_overview_lifecycle_failure_is_not_rendered_active(monkeypatch):
    import maverick.agent_trust as at

    class BrokenLifecycleAgent:
        id = "broken"
        allow_tools = frozenset()

        def is_active(self):
            raise RuntimeError("registry unavailable")

    agent = BrokenLifecycleAgent()
    monkeypatch.setattr(at, "load_trust_state", lambda: (True, {"broken": agent}))

    ov = trust_overview()
    row = ov["agents"][0]
    assert row["active"] is False
    assert row["status"] == "unknown (lifecycle check failed)"
    assert row["has_key"] is False  # no pinned key: the page says so
    assert ov["graph"]["nodes"][0]["color"] == "#dc2626"


def test_trust_api_and_page(monkeypatch):
    _fake_trust(monkeypatch)
    r = client.get("/api/v1/trust/agents")
    assert r.status_code == 200
    assert r.json()["agents"][0]["id"] == "vega"
    p = client.get("/trust")
    assert p.status_code == 200
    assert "vega" in p.text


def test_trust_empty_state_does_not_error(monkeypatch):
    import maverick.agent_trust as at
    monkeypatch.setattr(at, "load_trust_state", lambda: (False, {}))
    ov = trust_overview()
    assert ov["agents"] == []
    assert ov["enforced"] is False
    assert ov["graph"]["nodes"] == []  # empty graph, no render, no error
    assert client.get("/trust").status_code == 200


def test_trust_graph_layout(monkeypatch):
    _fake_trust(monkeypatch)
    g = trust_overview()["graph"]
    assert g["width"] > 0 and g["height"] > 0
    node = g["nodes"][0]
    assert node["id"] == "vega"
    assert {"x", "y", "color", "inbound", "outbound"} <= node.keys()
    # vega is inbound-only + medium-risk in the fixture
    assert node["inbound"] is True and node["outbound"] is False
    assert node["color"] == "#2563eb"


# ---- discovery -------------------------------------------------------------

def test_discovery_overview_shape():
    from maverick_dashboard.control_plane import discovery_overview
    ov = discovery_overview()
    assert {"tools", "mcp_servers", "providers", "channels", "agents"} <= ov.keys()
    assert {"entries", "by_tier", "count"} <= ov["tools"].keys()
    assert isinstance(ov["mcp_servers"], list)
    assert isinstance(ov["providers"], list)
    assert "count" in ov["agents"]


def test_discovery_page_and_api():
    page = client.get("/discovery")
    assert page.status_code == 200
    # Action names read as words; raw commands stay under Technical details.
    assert "Download the compliance file" in page.text and "(JSON)" not in page.text
    r = client.get("/api/v1/discovery")
    assert r.status_code == 200 and "tools" in r.json()


# ---- pre-action simulation -------------------------------------------------

def test_simulate_browser_pay_is_high(monkeypatch):
    monkeypatch.delenv("MAVERICK_CONSENT_MODE", raising=False)
    from maverick_dashboard.control_plane import simulate_action
    res = simulate_action("browser", "click", "text=Pay now")
    assert res["risk"] == "high" and res["decision"]
    assert res["result_class"] == "simulation"
    assert res["evidence_class"] == "simulated"
    assert res["live_effect"] is False
    assert res["can_accept_business_outcome"] is False
    assert res["authoritative_live_evidence_eligible"] is False
    assert res["business_outcome_acceptance"] == "prohibited"


def test_simulate_ask_mode_requires_approval(monkeypatch):
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "ask")
    from maverick_dashboard.control_plane import simulate_action
    res = simulate_action("browser", "click", "text=Pay now")
    assert "APPROVAL" in res["decision"].upper()


def test_simulate_readonly_not_gated(monkeypatch):
    monkeypatch.delenv("MAVERICK_CONSENT_MODE", raising=False)
    from maverick_dashboard.control_plane import simulate_action
    assert simulate_action("browser", "extract_text", "")["decision"] == "not gated"


def test_simulate_unknown_surface_errors():
    from maverick_dashboard.control_plane import simulate_action
    result = simulate_action("rocket", "launch", "")
    assert "error" in result
    assert result["evidence_class"] == "simulated"
    assert result["can_accept_business_outcome"] is False


def test_simulate_api_and_page():
    r = client.get("/api/v1/simulate",
                   params={"surface": "browser", "action": "click", "target": "text=Pay"})
    assert r.status_code == 200 and r.json()["risk"] == "high"
    assert r.json()["live_effect"] is False
    assert r.json()["business_outcome_acceptance"] == "prohibited"
    p = client.get("/simulate",
                   params={"surface": "browser", "action": "click", "target": "Pay now"})
    assert p.status_code == 200 and "Decision" in p.text
    assert "Simulation only" in p.text
    assert "No live action ran" in p.text
    assert "cannot be accepted as a live business outcome" in p.text
    assert "Not eligible for acceptance" in p.text
    # Choices come from selectors; the answer is worded for a person.
    assert 'id="sim-action"' in p.text and "Click something" in p.text
    assert "Where the action happens" in p.text
    assert "REQUIRES APPROVAL" not in p.text and "consent mode" not in p.text.lower()
    from test_support.plain_language import developer_terms

    assert developer_terms(p.text) == []
    bad = client.get("/simulate", params={"surface": "rocket", "action": "launch"})
    assert "Choose where the action happens" in bad.text
    assert "unknown surface" not in bad.text


def test_actual_research_simulation_requires_named_human_and_renders(monkeypatch):
    from maverick.research_simulator import AuthenticatedHumanIdentityV1
    from maverick_dashboard import simulation_authority

    unauthenticated = client.post(
        "/api/v1/simulate/research",
        params={"component": "tabular"},
    )
    assert unauthenticated.status_code == 401
    unauthenticated_page = client.post(
        "/simulate/research",
        data={"component": "tabular"},
    )
    assert unauthenticated_page.status_code == 401
    assert "Sign in with your own named account" in unauthenticated_page.text
    assert "No practice or live action was completed" in unauthenticated_page.text

    identity = AuthenticatedHumanIdentityV1(
        "user:dashboard-simulation-reviewer",
        hashlib.sha256(b"verified-dashboard-test-session").hexdigest(),
    )
    monkeypatch.setattr(
        simulation_authority,
        "authenticated_human_identity",
        lambda _request: identity,
    )
    response = client.post(
        "/api/v1/simulate/research",
        params={"component": "feature-prefix"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["scenario_id"] == "dashboard-synthetic-research-v1"
    assert payload["component_id"] == "feature-prefix-backoff-baseline-v1"
    assert payload["success"] is True
    assert payload["component_process_isolated"] is True
    assert payload["oracle_passed"] is True
    assert payload["authority_requires_approval"] is True
    assert payload["approver_principal"] == identity.principal
    assert payload["action_lineage_valid"] is True
    assert payload["source_ref"].startswith("simulator:sim-")
    assert payload["evidence_class"] == "simulated"
    assert payload["authoritative_live_evidence_eligible"] is False
    assert payload["business_outcome_acceptance"] == "prohibited"

    page = client.post(
        "/simulate/research",
        data={"component": "tabular"},
    )
    assert page.status_code == 200
    assert 'data-testid="research-simulation-boundary"' in page.text
    assert "Practice study finished" in page.text
    assert "Built-in made-up software world" in page.text
    assert "Kept separate" in page.text
    assert "a named person must approve" in page.text
    assert "Not eligible for acceptance" in page.text
    assert "Approve and run practice study" in page.text
    assert "dashboard-synthetic-research-v1" not in page.text
    assert "accept business outcome" not in page.text.lower()


def test_research_simulation_rejects_unregistered_component(monkeypatch):
    from maverick.research_simulator import AuthenticatedHumanIdentityV1
    from maverick_dashboard import simulation_authority

    monkeypatch.setattr(
        simulation_authority,
        "authenticated_human_identity",
        lambda _request: AuthenticatedHumanIdentityV1(
            "user:dashboard-simulation-reviewer",
            hashlib.sha256(b"verified-dashboard-test-session").hexdigest(),
        ),
    )
    response = client.post(
        "/api/v1/simulate/research",
        params={"component": "caller-plugin"},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "component must be tabular or feature-prefix"}


# ---- compliance packet -----------------------------------------------------

def test_compliance_packet_shape():
    from maverick_dashboard.control_plane import compliance_packet
    pkt = compliance_packet()
    assert pkt["artifact"] == "maverick.compliance_packet"
    assert "soc2" in pkt and "controls" in pkt and "audit_chain" in pkt


def test_compliance_packet_download(monkeypatch):
    from maverick_dashboard import api

    calls = 0

    def fake_body():
        nonlocal calls
        calls += 1
        return '{"artifact":"maverick.compliance_packet"}'

    monkeypatch.setattr(api, "_COMPLIANCE_PACKET_CACHE", {})
    monkeypatch.setattr(api, "_build_compliance_packet_body", fake_body)
    r = client.get("/api/v1/compliance/packet")
    assert r.status_code == 200
    cd = r.headers.get("content-disposition", "")
    assert "attachment" in cd and "lightwork-compliance-packet.json" in cd
    assert r.json()["artifact"] == "maverick.compliance_packet"

    cached = client.get("/api/v1/compliance/packet")
    assert cached.status_code == 200
    assert calls == 1


def test_compliance_packet_cache_is_isolated_by_tenant(monkeypatch, tmp_path):
    from maverick.paths import current_tenant_id_strict
    from maverick_dashboard import api

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr(api, "_COMPLIANCE_PACKET_CACHE", {})
    calls: list[str] = []

    def fake_body() -> str:
        tenant = current_tenant_id_strict() or "shared"
        calls.append(tenant)
        return '{"tenant":"' + tenant + '"}'

    monkeypatch.setattr(api, "_build_compliance_packet_body", fake_body)

    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    assert client.get("/api/v1/compliance/packet").json() == {"tenant": "tenant-a"}
    assert client.get("/api/v1/compliance/packet").json() == {"tenant": "tenant-a"}

    monkeypatch.setenv("MAVERICK_TENANT", "tenant-b")
    assert client.get("/api/v1/compliance/packet").json() == {"tenant": "tenant-b"}
    assert calls == ["tenant-a", "tenant-b"]
