"""Signed consent publishing: key custody, publish-time signatures, signed answers.

``[consent_preferences.publishing] require_signed_publications`` signs every
publish, restore and withdrawal with the workspace's Ed25519 key, and the
public consent service signs the configuration it serves. The key is created
or replaced on the Banner and Preference Center page by a global
administrator, stored sealed, never shown (only its public half, by
fingerprint and as a download), audited, and the server's environment key
wins. With the setting off nothing is signed and nothing served changes.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from maverick import consent_publication_signing as signing
from maverick.consent_publishing import PublishingSigningUnavailable
from maverick_dashboard.app import app

from test_support.consent_public_seed import browser_headers, seed

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
KEY_API = "/api/v1/consent/publishing/signing-key"
SETTINGS_API = "/api/v1/settings/catalog"
CONFIGURATION = "/api/v1/public/consent/configuration"
SWITCH = "consent_preferences.publishing.require_signed_publications"
ROOT_A = ("root-a", b"a" * 32)
ROOT_B = ("root-b", b"b" * 32)
SDK = Path(__file__).parents[1] / "maverick_dashboard" / "static" / "lightwork-consent-sdk.js"


def _policy(*roots, required: bool = True) -> signing.SigningPolicy:
    return signing.SigningPolicy(
        required=required,
        custody=signing.SigningCustody(roots=tuple(roots), managed_by_server=False),
    )


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    for name in (signing.ENV, "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_CONFIG",
                 "MAVERICK_CONFIG_OVERLAY", "MAVERICK_DASHBOARD_ADMINS"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


@pytest.fixture()
def audit_rows(monkeypatch):
    import maverick.audit as audit

    rows: list[dict] = []
    monkeypatch.setattr(audit, "audit_event",
                        lambda kind, **payload: rows.append({"kind": kind, **payload}) or True)
    return rows


def _digest(value: object) -> str:
    return hashlib.sha256(signing.canonical(value)).hexdigest()


def _served_digest(served: dict) -> str:
    """configuration_sha256 recomputed from exactly what a website renders."""
    return _digest({
        "publication_sha256": served["publication"]["publication_sha256"],
        "property_id": served["property"]["property_id"],
        "property_revision": served["property"]["revision"],
        "consent_group_id": served["property"]["consent_group_id"],
        "rule_id": served["rule"]["rule_id"],
        "rule_sha256": served["rule"]["rule_sha256"],
        "locale": served["rule"]["locale"],
        "configuration": served["configuration"],
    })


def _website_accepts(served: dict, key: dict) -> bool:
    """What a website that checks signatures does (the SDK, in Python)."""
    signature = served.get("signature")
    if not signature or signature["key_id"] != key["key_id"]:
        return False
    statement = signature["statement"]
    bound = (
        statement["configuration_sha256"] == served["configuration_sha256"] == _served_digest(served)
        and statement["publication_sha256"] == served["publication"]["publication_sha256"]
        and statement["policy_sha256"] == served["policy_sha256"]
    )
    return bound and signing.verify(key["public_key"], signature["signature"],
                                    signing.canonical(statement))


# ------------------------------------------------------------- sign/verify
def test_sign_verify_round_trip_and_tampered_statement_refused():
    custody = _policy(ROOT_A).custody
    signer = custody.signer_for("tenant-a")
    assert signer.key_id == signing.key_id_for(signer.public_key_hex)
    assert "seed" not in repr(signer) and "a" * 32 not in repr(custody)
    statement = signing.publication_statement(signer.key_id, {
        "property_id": "web-main", "publication_id": "publication-1",
        "publication_sha256": "1" * 64})
    signature = signer.sign(signing.canonical(statement))
    assert signing.verify(signer.public_key_hex, signature, signing.canonical(statement))
    tampered = {**statement, "publication_sha256": "2" * 64}
    assert not signing.verify(signer.public_key_hex, signature, signing.canonical(tampered))
    # Each workspace has its own key: another workspace's key never vouches.
    other = custody.signer_for("tenant-b")
    assert other.public_key_hex != signer.public_key_hex
    assert not signing.verify(other.public_key_hex, signature, signing.canonical(statement))
    assert not signing.verify(signer.public_key_hex, "0" * 128, signing.canonical(statement))
    assert not signing.verify("not-a-key", signature, signing.canonical(statement))


def test_publishing_signs_inside_the_publication_and_the_signature_verifies(tmp_path):
    env = seed(tmp_path, signing=lambda: _policy(ROOT_A))
    publication = env.publication
    signer = _policy(ROOT_A).custody.signer_for("tenant-a")
    assert publication["signature"]["key_id"] == signer.key_id
    statement = signing.publication_statement(signer.key_id, publication)
    assert signing.verify(signer.public_key_hex, publication["signature"]["signature"],
                          signing.canonical(statement))
    record = env.publishing.publication_signature(
        "tenant-a", publication["publication_id"],
        trusted_public_keys=frozenset({signer.public_key_hex}))
    assert record["key_id"] == signer.key_id and record["public_key"] == signer.public_key_hex
    # Signatures are as immutable as the publications they sign.
    with sqlite3.connect(env.publishing.path) as connection, pytest.raises(sqlite3.DatabaseError):
        connection.execute("UPDATE consent_publication_signatures SET signature = 'x'")


def test_publishing_is_refused_without_a_key_but_a_withdrawal_is_not(tmp_path):
    state = {"policy": _policy(ROOT_A, required=False)}
    env = seed(tmp_path, signing=lambda: state["policy"])
    assert "signature" not in env.publication
    state["policy"] = _policy()  # signing required, no key in custody
    with pytest.raises(PublishingSigningUnavailable, match="no signing key"):
        env.publishing.rollback("tenant-a", "web-main", env.publication["publication_id"],
                                expected_property_revision=1, expected_publication_revision=1,
                                idempotency_key="rollback-without-key")
    withdrawn = env.publishing.withdraw("tenant-a", "web-main", expected_property_revision=1,
                                        expected_publication_revision=1,
                                        idempotency_key="withdraw-without-key")
    assert withdrawn["action"] == "withdraw" and "signature" not in withdrawn


def test_setting_off_keeps_publications_and_answers_exactly_as_before(tmp_path):
    env = seed(tmp_path, signing=lambda: _policy(ROOT_A, required=False))
    assert "signature" not in env.publication
    served = env.client.get(CONFIGURATION, headers=browser_headers())
    assert served.status_code == 200 and "signature" not in served.json()
    with sqlite3.connect(env.publishing.path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM consent_publication_signatures").fetchone()[0] == 0


# ------------------------------------------------------------ served answers
def test_served_configuration_is_signed_and_covers_what_is_shown(tmp_path):
    env = seed(tmp_path, signing=lambda: _policy(ROOT_A))
    served = env.client.get(CONFIGURATION, headers=browser_headers()).json()
    key = signing.public_key_document(_policy(ROOT_A).custody.signer_for("tenant-a"))
    signature = served["signature"]
    assert signature["key_id"] == key["key_id"] and signature["algorithm"] == "Ed25519"
    assert signature["statement"]["publication_key_id"] == env.publication["signature"]["key_id"]
    assert _website_accepts(served, key)
    # Any change to what is shown, or to the policy it is bound to, is refused.
    for path, value in ((("configuration", "notice", "title"), "Something else"),
                        (("policy_sha256",), "0" * 64),
                        (("rule", "locale"), "fr-FR")):
        tampered = json.loads(json.dumps(served))
        node = tampered
        for part in path[:-1]:
            node = node[part]
        node[path[-1]] = value
        assert not _website_accepts(tampered, key), path
    # A different workspace's key is not trusted.
    other = signing.public_key_document(_policy(ROOT_A).custody.signer_for("tenant-b"))
    assert not _website_accepts(served, other)


def test_tampered_or_untrusted_publications_are_served_unsigned(tmp_path):
    state = {"policy": _policy(ROOT_A)}
    env = seed(tmp_path, signing=lambda: state["policy"])
    # After the key is replaced the old signature is still trusted, the answer
    # is signed with the new key and names the key that signed the publication.
    state["policy"] = _policy(ROOT_B, ROOT_A)
    served = env.client.get(CONFIGURATION, headers=browser_headers()).json()
    new_key = signing.public_key_document(_policy(ROOT_B).custody.signer_for("tenant-a"))
    assert served["signature"]["key_id"] == new_key["key_id"]
    assert served["signature"]["statement"]["publication_key_id"] == (
        env.publication["signature"]["key_id"])
    assert _website_accepts(served, new_key)
    # A key this installation no longer keeps cannot vouch for a publication.
    state["policy"] = _policy(ROOT_B)
    assert "signature" not in env.client.get(CONFIGURATION, headers=browser_headers()).json()
    # A publication signature changed in the database is not vouched for either.
    state["policy"] = _policy(ROOT_A)
    with sqlite3.connect(env.publishing.path) as connection:
        connection.execute("DROP TRIGGER consent_publication_signatures_no_update")
        connection.execute("UPDATE consent_publication_signatures SET signature = ?",
                           ("0" * 128,))
    served = env.client.get(CONFIGURATION, headers=browser_headers())
    assert served.status_code == 200 and "signature" not in served.json()


@pytest.mark.skipif(shutil.which("node") is None, reason="needs Node.js")
def test_the_consent_script_refuses_unsigned_or_tampered_configuration(tmp_path):
    """The real SDK checks the real server's signature (canonical JSON agrees)."""
    env = seed(tmp_path, signing=lambda: _policy(ROOT_A))
    served = env.client.get(CONFIGURATION, headers=browser_headers()).json()
    key = signing.public_key_document(_policy(ROOT_A).custody.signer_for("tenant-a"))
    tampered = json.loads(json.dumps(served))
    tampered["configuration"]["purposes"][0]["title"] = "Something else"
    unsigned = {k: v for k, v in served.items() if k != "signature"}
    cases = {"signed": (served, [key]), "tampered": (tampered, [key]),
             "unsigned": (unsigned, [key]), "unchecked": (unsigned, None),
             "other-key": (served, [signing.public_key_document(
                 _policy(ROOT_B).custody.signer_for("tenant-a"))])}
    script = """
const fs = require("fs"), vm = require("vm"), crypto = require("crypto");
const [source, cases] = [fs.readFileSync(process.argv[1], "utf8"), JSON.parse(fs.readFileSync(0, "utf8"))];
(async () => {
  const results = {};
  for (const [name, [configuration, keys]] of Object.entries(cases)) {
    const context = { crypto: crypto.webcrypto, TextEncoder, console,
      btoa: (v) => Buffer.from(v, "binary").toString("base64"),
      localStorage: { getItem: () => null, setItem: () => {} },
      fetch: async () => ({ ok: true, status: 200, headers: { get: () => null },
                             text: async () => JSON.stringify(configuration) }) };
    context.window = context;
    vm.createContext(context);
    vm.runInContext(source, context);
    const options = { endpoint: "https://consent.test/api/v1/public/consent",
                      clientCredential: "c".repeat(40) };
    if (keys) options.publicationKeys = keys;
    try { await new context.LightworkConsent(options).loadConfiguration(); results[name] = "accepted"; }
    catch (error) { results[name] = error.message; }
  }
  process.stdout.write(JSON.stringify(results));
})();
"""
    completed = subprocess.run(["node", "-e", script, str(SDK)], input=json.dumps(cases),
                               capture_output=True, text=True, timeout=60, check=True)
    results = json.loads(completed.stdout)
    refusal = "consent configuration is not signed by a trusted key"
    assert results == {"signed": "accepted", "tampered": refusal, "unsigned": refusal,
                       "unchecked": "accepted", "other-key": refusal}


# ------------------------------------------------------------- key custody
def _rotate(**extra):
    return client.post(f"{KEY_API}/rotate", json={"confirm": True, **extra})


def test_signing_key_is_created_sealed_audited_and_never_shown(audit_rows):
    from maverick import config

    before = client.get(KEY_API)
    assert before.status_code == 200 and before.json()["configured"] is False
    assert client.get(f"{KEY_API}/public-key").status_code == 404
    created = _rotate()
    assert created.status_code == 200, created.text
    state = created.json()
    key = state["key"]
    assert state["configured"] is True and state["managed_by_server"] is False
    assert key["fingerprint"] == signing.fingerprint(key["public_key"])
    root = config.load_global_config()[signing.SECTION][signing.KEYRING_KEY]["current"]["root"]
    stored = config.dashboard_overrides_path().read_text(encoding="utf-8")
    assert root not in stored and "MVKAR1:" in stored
    for text in (created.text, client.get(KEY_API).text):
        assert root not in text and root.split(":", 1)[1] not in text
    download = client.get(f"{KEY_API}/public-key")
    assert download.status_code == 200 and download.json() == key
    assert "attachment" in download.headers["content-disposition"]
    assert key["key_id"] in download.headers["content-disposition"]
    assert [(r["section"], r["key"], r["old"], r["new"], r["key_id"]) for r in audit_rows] == [
        (signing.SECTION, "signing_key", "not set", "created", key["key_id"])]
    assert all(root not in repr(row) for row in audit_rows)


def test_replacing_the_key_keeps_earlier_signatures_trusted(audit_rows):
    first = _rotate().json()["key"]
    second = _rotate().json()
    assert second["key"]["key_id"] != first["key_id"] and second["retired_keys"] == 1
    custody = signing.custody()
    assert custody.signer_for("tenant-a").key_id == second["key"]["key_id"]
    assert custody.trusted_public_keys("tenant-a") == {first["public_key"],
                                                       second["key"]["public_key"]}
    for _ in range(4):
        assert _rotate().status_code == 200
    assert len(signing.custody().roots) == 1 + signing.MAX_PREVIOUS_ROOTS
    assert [r["new"] for r in audit_rows] == ["created"] + ["replaced"] * 5


def test_only_installation_administrators_can_change_the_key(monkeypatch, audit_rows):
    from maverick_dashboard import auth, rbac

    assert TestClient(app, base_url="http://127.0.0.1").post(f"{KEY_API}/rotate", json={"confirm": True}).status_code == 403
    assert _rotate(extra="field").status_code == 422
    assert client.post(f"{KEY_API}/rotate", json={"confirm": False}).status_code == 422
    rbac.set_role("user:vera", "viewer")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:vera")
    assert client.get(KEY_API).status_code == 403
    assert _rotate().status_code == 403
    assert [row for row in audit_rows if row["kind"] != "access_grant_changed"] == []


def test_the_server_key_wins_and_cannot_be_replaced_here(monkeypatch, audit_rows):
    in_app = _rotate().json()["key"]
    monkeypatch.setenv(signing.ENV, "hex:" + "c3" * 32)
    state = client.get(KEY_API).json()
    assert state["managed_by_server"] is True and state["key"]["key_id"] != in_app["key_id"]
    server = signing.custody()
    assert server.signer_for("tenant-a").key_id == state["key"]["key_id"]
    # What the app's key already signed still verifies.
    assert in_app["public_key"] in server.trusted_public_keys("tenant-a")
    assert _rotate().status_code == 409
    # A malformed server key never falls back to the app's key.
    monkeypatch.setenv(signing.ENV, "too-short")
    with pytest.raises(signing.PublicationSigningUnavailable):
        signing.custody().signer_for("tenant-a")


# ------------------------------------------------- the setting takes effect
def _save(value, confirm=False):
    from test_support.settings_pages import save_catalog

    return save_catalog(client, SETTINGS_API, json={"changes": [{"id": SWITCH, "value": value}],
                                           "confirm": confirm})


def test_saved_setting_takes_effect_and_turning_it_off_needs_confirmation(tmp_path, audit_rows):
    assert signing.signing_required() is False
    assert "signature" not in seed(tmp_path / "off").publication
    assert _save(True).status_code == 200
    assert signing.signing_required() is True
    with pytest.raises(PublishingSigningUnavailable):
        seed(tmp_path / "no-key")
    key = _rotate().json()["key"]
    env = seed(tmp_path / "signed")
    assert env.publication["signature"]["key_id"] == key["key_id"]
    served = env.client.get(CONFIGURATION, headers=browser_headers()).json()
    assert _website_accepts(served, key)
    # Turning signing off loosens a protection: confirm first.
    refused = _save(False)
    assert refused.status_code == 409
    assert signing.signing_required() is True
    assert _save(False, confirm=True).status_code == 200
    assert signing.signing_required() is False
    assert "signature" not in env.client.get(CONFIGURATION, headers=browser_headers()).json()
    changes = [(r["key"], r["old"], r["new"]) for r in audit_rows if r["kind"] == "setting_changed"
               and r["key"] == "require_signed_publications"]
    assert len(changes) == 2
