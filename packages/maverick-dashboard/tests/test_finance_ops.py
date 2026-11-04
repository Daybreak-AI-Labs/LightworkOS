"""Finance compliance surfaces: the regulatory license register, the
finance command center payload, and the binder's finance evidence."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _fresh_world(tmp_path, monkeypatch):
    from maverick import config, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    config.reset_config_cache()
    import maverick_dashboard.api as api
    api._world_cache.clear()
    yield
    config.reset_config_cache()
    api._world_cache.clear()


def _seed(subject="Q3 ITGC batch", type_="itgc", risky=True):
    from maverick.assessment import (
        AssessmentSession,
        get_template,
        save_session,
    )
    s = AssessmentSession(type=type_, subject=subject)
    for q in get_template(type_).questions:
        s.record(q.id, q.risk_answer if risky
                 else ("no" if q.risk_answer == "yes" else "yes"))
    save_session(s)
    return s


def _decide(sid, decision="approved"):
    from maverick.assessment import load_saved
    rev = load_saved(sid)["revision"]
    assert client.post(f"/api/v1/assess/sessions/{sid}/decide",
                       json={"decision": decision, "cadence_days": 365,
                             "expected_revision": rev}).status_code == 200


# --- the register ----------------------------------------------------------
def test_register_roundtrip_and_renewal_advances_from_deadline():
    from maverick.license_registry import (
        add_license,
        list_licenses,
        renew,
        runway,
    )
    rec = add_license(name="Money transmitter", jurisdiction="NY",
                      authority="NYDFS", license_number="MT-104512",
                      cadence_days=365)
    soon = add_license(name="Lender license", jurisdiction="CA",
                       authority="DFPI", license_number="60DBO-1",
                       renewal_at=time.time() + 5 * 86400, cadence_days=365)
    rows = list_licenses()
    assert [r["id"] for r in rows] == [soon["id"], rec["id"]]  # soonest first
    assert rows[0]["band"] == "d0_30" and rows[1]["band"] == "d90_plus"
    r = runway()
    assert r["total"] == 2 and r["jurisdictions"] == 2 and r["due_90d"] == 1
    # Renewing advances FROM the deadline, not from today.
    before = rows[0]["renewal_at"]
    renewed = renew(soon["id"], note="filed via NMLS, receipt #881",
                    by="tester")
    assert renewed["renewal_at"] == pytest.approx(before + 365 * 86400)
    assert renewed["evidence"][0]["note"].startswith("filed via NMLS")
    assert any(h["event"] == "renewed" for h in renewed["history"])


def test_license_api_crud_and_404():
    created = client.post("/api/v1/licenses", json={
        "name": "Insurance producer", "jurisdiction": "TX",
        "authority": "TDI", "license_number": "IP-9",
        "cadence_days": 730})
    assert created.status_code == 201
    lid = created.json()["id"]
    listing = client.get("/api/v1/licenses").json()
    assert listing["runway"]["total"] == 1
    assert listing["licenses"][0]["license_number"] == "IP-9"
    assert client.post(f"/api/v1/licenses/{lid}/evidence",
                       json={"note": "bond certificate on file"}
                       ).status_code == 200
    assert client.post(f"/api/v1/licenses/{lid}/renew",
                       json={"note": "renewed online"}).status_code == 200
    assert client.post("/api/v1/licenses/lic-nope/renew",
                       json={}).status_code == 404


# --- the finance board -----------------------------------------------------
def test_finance_board_payload_is_department_scoped_and_honest():
    passed = _seed("ITGC access mgmt", "itgc")
    failed = _seed("SOX JE control", "sox_control")
    _seed("Vendor PIA", "pia")           # privacy — must NOT count here
    _decide(passed.id, "approved")
    _decide(failed.id, "rejected")
    client.post("/api/v1/licenses", json={
        "name": "MT license", "jurisdiction": "NY", "authority": "NYDFS",
        "license_number": "MT-1", "cadence_days": 365})

    d = client.get("/api/v1/finance/board").json()
    assert d["kpis"]["assessments"] == 2      # the PIA stayed in privacy
    assert d["control_tests"] == {"passed": 1, "total": 2, "pct": 50.0}
    assert d["close_readiness"]["total"] == 0
    assert d["licenses"]["total"] == 1
    # SoD lint runs over the shipped packs (or reports honestly why not).
    assert "conflicts" in d["sod"]
    # Posture carries the not-an-audit-opinion disclaimer verbatim.
    assert "not" in d["finance_posture"]["disclaimer"].lower()
    assert d["finance_posture"]["total"] >= 5
    assert d["learning"]["decided"] == 2 and d["learning"]["first_pass"] == 1


def test_finance_board_page_and_workspace_links():
    assert "Finance command center" in client.get("/finance/board").text
    page = client.get("/finance").text
    assert "/finance/board" in page and "Licences" in page


def test_binder_carries_finance_evidence():
    client.post("/api/v1/licenses", json={
        "name": "MT license", "jurisdiction": "WA", "authority": "DFI",
        "license_number": "MT-7", "cadence_days": 365})
    binder = client.get("/api/v1/audit/binder").json()
    fin = binder["finance"]
    assert fin["licenses"]["total"] == 1
    assert "sod" in fin and "posture" in fin
    assert "disclaimer" in fin["posture"]


def test_finance_sod_lint_matches_full_scan_and_reuses_the_catalogue(monkeypatch):
    # The /finance/board SoD figure must equal a fresh scan of every shipped
    # pack filtered to finance/bank names, and a warm call must not parse the
    # ~2,000-pack catalogue again (it cost ~700 ms per request before).
    import maverick_dashboard.api as api
    from maverick import domain
    from maverick.finance.sod_linter import lint_roster

    packs = {n: d for n, d in domain.load_domains(domain.builtin_dir()).items()
             if n.startswith(("finance", "bank"))}
    conflicts = lint_roster(packs)
    expected = {"packs": len(packs), "conflicts": len(conflicts),
                "detail": [str(c) for c in conflicts[:5]]}
    assert expected["packs"] > 100
    assert api._finance_sod() == expected

    parses = []
    real_load = domain.load_domain
    monkeypatch.setattr(domain, "load_domain",
                        lambda path: (parses.append(path), real_load(path))[1])
    assert api._finance_sod() == expected
    assert parses == []
