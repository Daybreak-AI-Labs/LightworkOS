"""Activity log checkpoints from the /audit page: publish, check, keep a
receipt and retire -- the ``maverick audit checkpoint`` commands as buttons.
Permissions, workspace scoping, recorded-before-acting, confirmation and
plain wording."""
from __future__ import annotations

import html as _html
import json
import os
import re

import pytest
from fastapi.testclient import TestClient

pytest.importorskip("cryptography", reason="checkpoints are always signed")

ORIGIN = {"Origin": "http://127.0.0.1"}
BASE = "/api/v1/audit/checkpoints"
DAY = "2026-01-01"
BANNED = re.compile(
    r"\b(tenant|principal|payload|endpoint|schema|uuid|sha-?256|digest|json|revision|"
    r"idempoten\w*|lease|toml|yaml|stdout|traceback|sequence)\b|/api/v1|HTTP \d{3}|maverick |MAVERICK_",
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
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT", "MAVERICK_CLIENT_ID",
                 "MAVERICK_AUDIT_SIGNING_KEY", "MAVERICK_AUDIT_SIGNING_KEY_WRAPPED"):
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


def _write_day(rows: int = 3):
    from maverick.audit.reader import resolve_audit_dir
    from maverick.audit.signing import AuditSigner

    audit_dir = resolve_audit_dir(None)
    audit_dir.mkdir(parents=True, exist_ok=True)
    signer = AuditSigner(audit_dir / f"{DAY}.ndjson")
    for index in range(rows):
        assert signer.write({"ts": 1_767_225_600.0 + index, "kind": "tool_call", "agent": "worker-0"})
    return audit_dir / f"{DAY}.ndjson"


def _recorded(monkeypatch):
    import maverick.audit as audit_pkg
    from maverick.audit import writer

    seen: list[dict] = []
    real = writer.audit_event

    def spy(kind, **payload):
        seen.append({"kind": kind, **payload})
        return real(kind, **payload)
    monkeypatch.setattr(audit_pkg, "audit_event", spy)
    return seen


def _visible(page: str, root_id: str) -> str:
    start = page.index(f'id="{root_id}"')
    section = page[start:page.index("</section>", start)]
    section = re.sub(r"<(script|style)\b.*?</\1>", " ", section, flags=re.DOTALL)
    section = re.sub(r"<[^>]+>", " ", section)
    return _html.unescape(re.sub(r"\s+", " ", section))


def test_reading_and_checking_need_the_activity_log_permission(client, monkeypatch):
    _write_day()
    _as(monkeypatch, "viewer")
    assert client.get(BASE).status_code == 403
    assert client.post(f"{BASE}/verify", json={}).status_code == 403
    assert client.get(f"{BASE}/1/receipt").status_code == 403
    _as(monkeypatch, "auditor", "user:aud")
    listing = client.get(BASE)
    assert listing.status_code == 200, listing.text
    assert {"day": DAY, "has_checkpoint": False} in listing.json()["days"]
    # Reading is not changing: an auditor cannot publish or retire.
    assert client.post(f"{BASE}/publish", json={"day": DAY}).status_code == 403
    assert client.post(f"{BASE}/retire", json={"sequence": 1, "confirm": True}).status_code == 403


def test_publish_is_recorded_first_then_listed_and_verified_with_a_kept_receipt(client, monkeypatch):
    _write_day()
    seen = _recorded(monkeypatch)
    published = client.post(f"{BASE}/publish", json={"day": DAY})
    assert published.status_code == 200, published.text
    assert published.json() == {"published": True, "sequence": 1, "day": DAY}
    assert [r for r in seen if r.get("action") == "audit_checkpoint_publish"][0]["day"] == DAY

    listing = client.get(BASE).json()
    assert listing["total"] == 1 and {"day": DAY, "has_checkpoint": True} in listing["days"]
    row = listing["checkpoints"][0]
    assert row["day"] == DAY and row["entries"] == 3 and row["kind"] == "Checkpoint"
    assert row["can_retire"] is False
    assert "sha256" not in row  # fingerprints stay on the server

    receipt = client.get(f"{BASE}/1/receipt")
    assert receipt.status_code == 200
    assert receipt.headers["content-disposition"].startswith('attachment; filename="activity-log-checkpoint-1')
    kept = receipt.json()
    assert kept["sequence"] == 1 and len(kept["fingerprint"]) == 64

    checked = client.post(f"{BASE}/verify", json={"receipt": receipt.text}).json()
    assert checked == {"intact": True, "none_yet": False, "pinned": True, "keys_pinned": False,
                       "problems": [], "technical": []}
    # Publishing the same unchanged day again adds nothing.
    assert client.post(f"{BASE}/publish", json={"day": DAY}).json()["sequence"] == 1


def test_a_changed_day_is_reported_in_plain_words(client):
    day_file = _write_day(4)
    assert client.post(f"{BASE}/publish", json={"day": DAY}).status_code == 200
    lines = day_file.read_text(encoding="utf-8").splitlines(keepends=True)
    day_file.write_text("".join(lines[:-1]), encoding="utf-8")   # quietly drop the last entry
    checked = client.post(f"{BASE}/verify", json={}).json()
    assert checked["intact"] is False and checked["problems"]
    assert all(not BANNED.search(p) for p in checked["problems"])
    assert checked["technical"]


def test_bad_input_is_refused_before_anything_happens(client, monkeypatch):
    _write_day()
    seen = _recorded(monkeypatch)
    assert client.post(f"{BASE}/publish", json={"day": "2026-13-40"}).status_code == 422
    assert client.post(f"{BASE}/publish", json={"day": "2025-01-01"}).status_code == 422
    assert client.post(f"{BASE}/publish", json={"day": "../etc/x"}).status_code == 422
    assert client.post(f"{BASE}/publish", json={"day": DAY, "extra": 1}).status_code == 422
    assert client.post(f"{BASE}/verify", json={"receipt": "x" * 5000}).status_code == 422
    assert client.post(f"{BASE}/verify", json={"receipt": "{\"kind\": \"other\"}"}).status_code == 422
    assert client.get(f"{BASE}/0/receipt").status_code == 422
    assert client.get(f"{BASE}/7/receipt").status_code == 404
    # "After an erasure" needs an earlier checkpoint for the day.
    assert client.post(f"{BASE}/publish", json={"day": DAY, "after_erasure": True}).status_code == 409
    assert not [r for r in seen if r.get("action") == "audit_checkpoint_publish"]


def test_a_refused_activity_record_publishes_nothing(client, monkeypatch):
    _write_day()
    import maverick.audit as audit_pkg
    from maverick.audit import AuditRefused

    def refuse(kind, **payload):
        raise AuditRefused("refused")
    with monkeypatch.context() as patch:
        patch.setattr(audit_pkg, "audit_event", refuse)
        r = client.post(f"{BASE}/publish", json={"day": DAY})
    assert r.status_code == 503 and "nothing was changed" in r.json()["detail"]
    assert client.get(BASE).json()["total"] == 0


def test_retire_needs_confirmation_and_a_day_deleted_by_policy(client, monkeypatch):
    _write_day()
    assert client.post(f"{BASE}/publish", json={"day": DAY}).status_code == 200
    r = client.post(f"{BASE}/retire", json={"sequence": 1})
    assert r.status_code == 409 and "Confirm" in r.json()["detail"]
    kept = client.post(f"{BASE}/retire", json={"sequence": 1, "confirm": True})
    assert kept.status_code == 409 and "still kept" in kept.json()["detail"]
    assert client.post(f"{BASE}/retire", json={"sequence": 9, "confirm": True}).status_code == 409

    # Once the policy has deleted the day, the server names the checkpoint to
    # the kernel itself: the page only sent the row it showed.
    from maverick.audit import checkpoints
    from maverick_dashboard import audit_ops_api
    monkeypatch.setattr(audit_ops_api, "_retired_by_policy", lambda: {DAY})
    listing = client.get(BASE).json()
    assert listing["checkpoints"][0]["can_retire"] is True
    calls = []

    def retire(audit_dir, checkpoint_dir, **kwargs):
        calls.append(kwargs)
        return checkpoint_dir / "x"
    monkeypatch.setattr(checkpoints, "retire_checkpoint", retire)
    seen = _recorded(monkeypatch)
    done = client.post(f"{BASE}/retire", json={"sequence": 1, "confirm": True})
    assert done.status_code == 200 and done.json() == {"retired": True, "day": DAY}
    assert calls[0]["lifecycle_reason"] == "retention_purge"
    assert len(calls[0]["supersedes_checkpoint_sha256"]) == 64
    assert [r for r in seen if r.get("action") == "audit_checkpoint_retire"][0]["day"] == DAY


def test_a_workspace_admin_publishes_only_in_their_own_workspace(client, monkeypatch):
    from maverick.paths import reset_tenant, set_tenant
    from maverick_dashboard import rbac

    _as(monkeypatch, "viewer", "user:alice")
    rbac.set_tenant_role("acme", "user:alice", "admin")
    token = set_tenant("other")
    try:
        assert client.post(f"{BASE}/publish", json={"day": DAY}).status_code == 403
        assert client.get(BASE).status_code == 403
    finally:
        reset_tenant(token)
    token = set_tenant("acme")
    try:
        _write_day()
        r = client.post(f"{BASE}/publish", json={"day": DAY})
        assert r.status_code == 200, r.text
    finally:
        reset_tenant(token)


def test_audit_page_shows_the_checkpoint_buttons_in_plain_words(client, monkeypatch):
    page = client.get("/audit").text
    for control in ("ops-ckpt-publish", "ops-ckpt-verify", "ops-ckpt-day", "ops-ckpt-receipt"):
        assert f'id="{control}"' in page
    assert "lightwork-ops-panels.js" in page
    assert not BANNED.search(_visible(page, "ops-ckpt"))
    _as(monkeypatch, "auditor", "user:aud")
    page = client.get("/audit").text
    assert 'id="ops-ckpt-verify"' in page and 'id="ops-ckpt-publish"' not in page


def test_changes_from_another_site_are_refused(client):
    _write_day()
    cross_site = TestClient(client.app, base_url="http://127.0.0.1")
    assert cross_site.post(f"{BASE}/publish", json={"day": DAY}).status_code == 403
    assert cross_site.post(f"{BASE}/retire", json={"sequence": 1, "confirm": True}).status_code == 403
    assert cross_site.post("/api/v1/security/own/fixes/apply",
                           json={"control": "Tamper-evident audit", "confirm": True}).status_code == 403
    assert cross_site.post("/api/v1/compliance/people/documents/erase",
                           json={"channel": "slack", "user": "U1", "confirm": True,
                                 "confirm_name": "U1"}).status_code == 403
    assert client.get(BASE).json()["total"] == 0


# ---- where checkpoints live and which keys may sign them -----------------------

SETTINGS = f"{BASE}/settings"


def _other_key() -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    public = Ed25519PrivateKey.generate().public_key()
    return public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()


def _cli_verify(folder, *keys) -> int:
    from click.testing import CliRunner
    from maverick.cli import main

    args = ["audit", "checkpoint", "verify", "--checkpoint-dir", str(folder)]
    for key in keys:
        args += ["--pubkey", key]
    return CliRunner().invoke(main, args).exit_code



def test_checkpoint_settings_are_for_installation_administrators(client, monkeypatch):
    from maverick.paths import reset_tenant, set_tenant
    from maverick_dashboard import rbac

    _as(monkeypatch, "auditor", "user:aud")
    assert client.get(SETTINGS).status_code == 200
    assert client.post(f"{SETTINGS}/folder", json={"folder": "", "confirm": True}).status_code == 403
    assert client.post(f"{SETTINGS}/keys", json={"own_key": True}).status_code == 403
    _as(monkeypatch, "viewer", "user:alice")
    rbac.set_tenant_role("acme", "user:alice", "admin")
    token = set_tenant("acme")
    try:  # a workspace administrator cannot change an installation-wide setting
        assert client.post(f"{SETTINGS}/folder/check", json={"folder": "/tmp"}).status_code == 403
        assert client.post(f"{SETTINGS}/keys/remove", json={"fingerprint": "AAAA", "confirm": True}).status_code == 403
        assert client.get(SETTINGS).status_code == 403
    finally:
        reset_tenant(token)
    assert TestClient(client.app, base_url="http://127.0.0.1").post(f"{SETTINGS}/folder", json={"folder": ""}).status_code == 403


def test_a_chosen_folder_is_checked_on_the_server_and_confirmed(client, monkeypatch, tmp_path):
    allowed = tmp_path / "allowed"
    (allowed / "worm").mkdir(parents=True)
    monkeypatch.setenv("MAVERICK_SETTINGS_PATH_ROOTS", os.pathsep.join((str(allowed), str(tmp_path / "mh"))))
    _write_day()
    check = client.post(f"{SETTINGS}/folder/check", json={"folder": str(allowed / "worm")})
    assert check.status_code == 200 and check.json()["ok"] is True
    outside = client.post(f"{SETTINGS}/folder/check", json={"folder": str(tmp_path)})
    assert outside.status_code == 422 and "only uses locations" in outside.json()["detail"]
    assert client.post(f"{SETTINGS}/folder/check", json={"folder": "worm"}).status_code == 422
    assert client.post(f"{SETTINGS}/folder/check", json={"folder": str(allowed / "missing")}).status_code == 422
    home = client.post(f"{SETTINGS}/folder/check", json={"folder": str(tmp_path / "mh")})
    assert home.status_code == 422 and "outside Lightwork" in home.json()["detail"]
    assert client.post(f"{SETTINGS}/folder/check", json={"folder": "x" * 2000}).status_code == 422

    seen = _recorded(monkeypatch)
    unconfirmed = client.post(f"{SETTINGS}/folder", json={"folder": str(allowed / "worm")})
    assert unconfirmed.status_code == 409 and client.get(SETTINGS).json()["default_folder"] is True
    saved = client.post(f"{SETTINGS}/folder", json={"folder": str(allowed / "worm"), "confirm": True})
    assert saved.status_code == 200 and saved.json()["saved"] is True
    row = [r for r in seen if r.get("action") == "audit_checkpoint_folder"][0]
    assert row["folder"] == str(allowed / "worm") and row["previous"] == "default"

    assert client.post(f"{BASE}/publish", json={"day": DAY}).status_code == 200
    assert (allowed / "worm" / "audit-checkpoint-00000000000000000001.ndjson").exists()
    assert client.get(BASE).json()["total"] == 1
    assert client.post(f"{BASE}/verify", json={}).json()["intact"] is True
    # The same folder, checked from the terminal, agrees.
    assert _cli_verify(allowed / "worm") == 0
    # Back to the default: its own (empty) history.
    assert client.post(f"{SETTINGS}/folder", json={"folder": "", "confirm": True}).status_code == 200
    assert client.get(BASE).json()["total"] == 0


def test_pinned_keys_are_used_like_the_terminal_options(client, monkeypatch):
    _write_day()
    assert client.post(f"{BASE}/publish", json={"day": DAY}).status_code == 200
    seen = _recorded(monkeypatch)
    own = client.post(f"{SETTINGS}/keys", json={"own_key": True})   # the first pin narrows: no confirmation
    assert own.status_code == 200 and own.json()["saved"] is True
    view = client.get(SETTINGS).json()
    assert view["own_key_pinned"] is True and view["keys"][0]["own"] is True
    fingerprint = view["keys"][0]["fingerprint"]
    assert re.fullmatch(r"[0-9A-F]{4}( [0-9A-F]{4}){3}", fingerprint)
    assert client.post(f"{BASE}/verify", json={}).json()["keys_pinned"] is True
    assert client.post(f"{BASE}/publish", json={"day": DAY}).status_code == 200

    other = _other_key()
    widen = client.post(f"{SETTINGS}/keys", json={"key": other})
    assert widen.status_code == 409 and "Nothing was changed" in widen.json()["detail"]
    assert client.post(f"{SETTINGS}/keys", json={"key": "not a key"}).status_code == 422
    assert client.post(f"{SETTINGS}/keys", json={"key": other, "confirm": True}).status_code == 200
    rows = [r for r in seen if str(r.get("action", "")).startswith("audit_checkpoint_key")]
    assert len(rows) == 2 and all(set(r) >= {"fingerprint"} for r in rows)
    assert "BEGIN PUBLIC KEY" not in json.dumps(seen, default=str)

    # Only the other key pinned: this installation's checkpoints are no longer
    # trusted, exactly as with the terminal's --pubkey.
    assert client.post(f"{SETTINGS}/keys/remove", json={"fingerprint": fingerprint}).status_code == 200
    checked = client.post(f"{BASE}/verify", json={}).json()
    assert checked["intact"] is False and checked["problems"]
    from maverick_dashboard import audit_checkpoint_settings as store
    from maverick_dashboard import audit_ops_api
    assert _cli_verify(audit_ops_api._checkpoint_dir(), *store.load()["keys"]) != 0
    refused = client.post(f"{BASE}/publish", json={"day": DAY})
    assert refused.status_code == 409 and "Pin its key below" in refused.json()["detail"]

    last = client.get(SETTINGS).json()["keys"][0]["fingerprint"]
    loosen = client.post(f"{SETTINGS}/keys/remove", json={"fingerprint": last})
    assert loosen.status_code == 409
    assert client.post(f"{SETTINGS}/keys/remove", json={"fingerprint": last, "confirm": True}).status_code == 200
    assert client.post(f"{BASE}/verify", json={}).json()["intact"] is True
    assert client.post(f"{SETTINGS}/keys/remove", json={"fingerprint": last, "confirm": True}).status_code == 404


def test_damaged_settings_fail_closed(client, tmp_path):
    _write_day()
    (tmp_path / "mh" / "audit-checkpoint-settings.json").write_text("{not json", encoding="utf-8")
    assert client.get(SETTINGS).status_code == 503
    assert client.post(f"{BASE}/publish", json={"day": DAY}).status_code == 503
    assert client.post(f"{BASE}/verify", json={}).status_code == 503


def test_audit_page_shows_the_settings_to_installation_administrators_only(client, monkeypatch):
    page = client.get("/audit").text
    for control in ("ops-ckpt-folder", "ops-ckpt-folder-check", "ops-ckpt-folder-save", "ops-ckpt-key-file",
                    "ops-ckpt-key-paste", "ops-ckpt-key-own"):
        assert f'id="{control}"' in page
    assert not BANNED.search(_visible(page, "ops-ckpt"))
    from maverick.paths import reset_tenant, set_tenant
    from maverick_dashboard import rbac
    _as(monkeypatch, "viewer", "user:alice")
    rbac.set_tenant_role("acme", "user:alice", "admin")
    token = set_tenant("acme")
    try:
        page = client.get("/audit").text
    finally:
        reset_tenant(token)
    assert 'id="ops-ckpt-publish"' in page and 'id="ops-ckpt-folder"' not in page
