"""Security checks on Lightwork's own activity (/security/threats): which
defenses are on, security events, a sweep for signs of attack and fixes for
security gaps -- ``maverick security posture / detections``, ``maverick
hunt`` and ``maverick remediate`` as buttons."""
from __future__ import annotations

import datetime as _dt
import html as _html
import re

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
BASE = "/api/v1/security/own"
BANNED = re.compile(
    r"\b(tenant|principal|payload|endpoint|schema|uuid|sha-?256|digest|json|revision|"
    r"idempoten\w*|lease|toml|yaml|stdout|traceback|shield_block|capability_denied)\b|/api/v1|"
    r"HTTP \d{3}|maverick |MAVERICK_|\[\w+\]",
    re.IGNORECASE,
)


@pytest.fixture
def client(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash_app

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT", "MAVERICK_ENTERPRISE",
                 "MAVERICK_SECURITY_AUTOFIX"):
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


def _attack_rows():
    from maverick.audit import audit_event
    audit_event("shield_block", agent="worker-1", reason="prompt injection")
    audit_event("capability_denied", agent="worker-2", tool="wire_transfer")
    audit_event("capability_denied", agent="worker-2", tool="wire_transfer")


def test_defenses_list_is_plain_with_a_link_for_each_that_is_off(client):
    body = client.get(f"{BASE}/posture").json()
    keys = {d["key"] for d in body["defenses"]}
    assert keys == {"shield", "capabilities", "audit_signing", "agent_trust", "egress_control"}
    signing = next(d for d in body["defenses"] if d["key"] == "audit_signing")
    assert signing["on"] is False and signing["href"] == "/compliance"
    assert "off" in body["summary"] and not BANNED.search(body["summary"])


def test_security_events_and_sweep_read_the_activity_log(client):
    _attack_rows()
    events = client.get(f"{BASE}/detections").json()
    assert events["total"] == 3
    whats = {d["what"] for d in events["detections"]}
    assert whats == {"Attempt to trick an assistant", "Assistant tried a tool it is not allowed"}
    # Written before signing was on, so the list says it cannot be proven.
    assert events["proven"] is False and events["notes"]
    high = client.get(f"{BASE}/detections", params={"severity": "high"}).json()
    assert high["total"] == 3
    today = _dt.datetime.now(_dt.timezone.utc).date().isoformat()
    sweep = client.post(f"{BASE}/sweep", json={"since": today, "until": today}).json()
    assert sweep["entries_checked"] >= 3
    kinds = {f["what"]: f["count"] for f in sweep["findings"]}
    assert kinds["Assistant tried to go beyond its limits"] == 2
    assert kinds["Harmful request blocked"] == 1
    assert not BANNED.search(sweep["summary"])


def test_reading_security_events_needs_the_activity_log_permission(client, monkeypatch):
    _as(monkeypatch, "operator")
    assert client.get(f"{BASE}/posture").status_code == 200
    assert client.get(f"{BASE}/detections").status_code == 403
    assert client.post(f"{BASE}/sweep", json={}).status_code == 403
    assert client.get(f"{BASE}/fixes").status_code == 403
    _as(monkeypatch, "viewer", "user:vic")
    assert client.get(f"{BASE}/posture").status_code == 403


def test_bounded_inputs(client):
    assert client.get(f"{BASE}/detections", params={"severity": "extreme"}).status_code == 422
    assert client.post(f"{BASE}/sweep", json={"since": "2026-99-01"}).status_code == 422
    assert client.post(f"{BASE}/sweep", json={"since": "2026-02-01", "until": "2026-01-01"}).status_code == 422
    assert client.post(f"{BASE}/sweep", json={"since": "2020-01-01", "until": "2026-01-01"}).status_code == 422
    assert client.post(f"{BASE}/fixes/apply", json={"control": "Anything", "confirm": True}).status_code == 422


def test_fixes_are_shown_first_and_applied_only_when_confirmed(client, monkeypatch, tmp_path):
    from maverick import config, remediation

    plan = client.get(f"{BASE}/fixes").json()
    gap = next(f for f in plan["fixes"] if f["control"] == "Tamper-evident audit")
    assert gap["automatic"] is True and gap["can_apply"] is False  # automatic fixes are off
    assert plan["automatic_fixes_on"] is False

    monkeypatch.setattr(remediation, "auto_fix_enabled", lambda: True)
    plan = client.get(f"{BASE}/fixes").json()
    gap = next(f for f in plan["fixes"] if f["control"] == "Tamper-evident audit")
    assert gap["can_apply"] is True and "sign = true" in gap["technical"]
    assert not (tmp_path / "config.toml").exists()   # showing the fix changed nothing

    refused = client.post(f"{BASE}/fixes/apply", json={"control": "Tamper-evident audit"})
    assert refused.status_code == 409 and not (tmp_path / "config.toml").exists()
    done = client.post(f"{BASE}/fixes/apply", json={"control": "Tamper-evident audit", "confirm": True})
    assert done.status_code == 200, done.text
    assert done.json()["applied"] is True
    assert "sign = true" in (tmp_path / "config.toml").read_text()
    from maverick.audit.reader import iter_events
    kinds = [(e.get("kind"), e.get("action")) for e in iter_events()]
    # Who asked is recorded first; the kernel then records the change itself.
    assert kinds.index(("control_plane_action", "security_fix_apply")) < kinds.index(("config_remediated", None))
    config.reset_config_cache()


def test_applying_a_fix_is_for_installation_administrators(client, monkeypatch):
    from maverick_dashboard import rbac
    _as(monkeypatch, "viewer", "user:alice")
    rbac.set_tenant_role("acme", "user:alice", "admin")
    from maverick.paths import reset_tenant, set_tenant
    token = set_tenant("acme")
    try:
        r = client.post(f"{BASE}/fixes/apply", json={"control": "Tamper-evident audit", "confirm": True})
    finally:
        reset_tenant(token)
    assert r.status_code == 403


def test_threats_page_shows_the_new_sections_in_plain_words(client):
    page = client.get("/security/threats").text
    for control in ("ops-sec-defenses", "ops-sec-load", "ops-sec-sweep", "ops-sec-fixes-load",
                    "ops-sec-since", "ops-sec-until", "ops-sec-severity"):
        assert f'id="{control}"' in page
    start = page.index('id="ops-sec"')
    section = page[start:page.index("</section>", start)]
    text = _html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", section)))
    assert not BANNED.search(text)
