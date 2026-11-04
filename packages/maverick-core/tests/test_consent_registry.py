"""Consent receipts: salted digests, self-checking receipts, projections.

The assertions that matter: the raw subject reference never appears in a
stored record or export; each event's receipt hash recomputes exactly; the
preference projection reflects the latest event per purpose; and the
OneTrust importer maps status vocabulary and skips what it cannot map.
"""
from __future__ import annotations

import hashlib
import json
import time

import pytest
from maverick import config
from maverick import consent_registry as cr

_SALT = "unit-test-salt-0123456789abcdef"


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    (tmp_path / "config.toml").write_text(
        f'[consent_registry]\nenable = true\nsubject_salt = "{_SALT}"\n',
        encoding="utf-8",
    )
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _grant(subject="alice@example.com", purpose="marketing emails"):
    return cr.record_consent(
        subject, purpose=purpose, status="granted",
        policy_version="2026-01", channel="web", actor="ops",
    )


def test_registry_is_off_by_default_and_salt_is_mandatory(tmp_path):
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    assert cr.enabled() is False
    with pytest.raises(cr.ConsentRegistryConfigError, match="enable"):
        _grant()
    # Enabled but with a salt too short to pseudonymize anything: refused.
    (tmp_path / "config.toml").write_text(
        '[consent_registry]\nenable = true\nsubject_salt = "short"\n',
        encoding="utf-8",
    )
    config.reset_config_cache()
    assert cr.enabled() is False
    with pytest.raises(cr.ConsentRegistryConfigError, match="subject_salt"):
        _grant()


def test_subject_reference_is_stored_only_as_a_salted_digest():
    record = _grant()
    expected = hashlib.sha256(
        f"consent-subject:{_SALT}:alice@example.com".encode()
    ).hexdigest()[:32]
    assert record["subject_digest"] == expected
    assert "alice" not in json.dumps(record)
    for row in cr.export_receipts():
        assert "alice" not in json.dumps(row)


def test_receipt_hash_recomputes_exactly():
    record = _grant()
    event = dict(record["history"][0])
    claimed = event.pop("receipt_sha256")
    recomputed = hashlib.sha256(
        json.dumps(
            {
                "subject": record["subject_digest"],
                "purpose": record["purpose"],
                **event,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    assert claimed == recomputed


def test_preferences_reflect_the_latest_event_per_purpose():
    _grant()
    _grant(purpose="product analytics")
    cr.withdraw_consent(
        "alice@example.com", purpose="marketing emails",
        policy_version="2026-02", channel="web", actor="ops",
    )
    prefs = cr.subject_preferences("alice@example.com")
    assert prefs["purposes"]["marketing_emails"]["status"] == "withdrawn"
    assert prefs["purposes"]["product_analytics"]["status"] == "granted"
    posture = cr.consent_posture()
    assert posture["records"] == 2
    assert posture["by_purpose"]["marketing_emails"]["withdrawn"] == 1

    record = cr.record_consent(
        "alice@example.com", purpose="marketing emails", status="granted",
        policy_version="2026-03", channel="mobile", actor="ops",
    )
    assert len(record["history"]) == 3
    assert record["current_status"] == "granted"


def test_status_channel_and_time_are_validated():
    with pytest.raises(ValueError, match="status"):
        cr.record_consent(
            "bob", purpose="p", status="maybe",
            policy_version="v1", channel="web", actor="ops",
        )
    with pytest.raises(ValueError, match="channel"):
        cr.record_consent(
            "bob", purpose="p", status="granted",
            policy_version="v1", channel="carrier-pigeon", actor="ops",
        )
    with pytest.raises(ValueError, match="recorded_at"):
        cr.record_consent(
            "bob", purpose="p", status="granted",
            policy_version="v1", channel="web", actor="ops",
            recorded_at=-5.0,
        )
    with pytest.raises(ValueError, match="future"):
        cr.record_consent(
            "bob", purpose="p", status="granted",
            policy_version="v1", channel="web", actor="ops",
            recorded_at=time.time() + 3600,
        )


def test_onetrust_import_maps_statuses_and_skips_the_unmappable():
    csv_text = (
        "Data Subject Identifier,Purpose,Consent Status,"
        "Purpose Version,Transaction Date\n"
        "carol@example.com,Newsletters,Opt-In,3.1,2026-02-01T10:00:00Z\n"
        "dave@example.com,Newsletters,Withdrawn,3.1,2026-02-02\n"
        "erin@example.com,Newsletters,Pending,3.1,2026-02-03\n"
        ",Newsletters,Opt-In,3.1,2026-02-04\n"
    )
    result = cr.import_onetrust_consents(csv_text, imported_by="ops")
    assert result == {"imported": 2, "skipped": 2}
    granted = cr.subject_preferences("carol@example.com")
    assert granted["purposes"]["newsletters"]["status"] == "granted"
    withdrawn = cr.subject_preferences("dave@example.com")
    assert withdrawn["purposes"]["newsletters"]["status"] == "withdrawn"
    # The export timestamp survived the import (2026-02-01T10:00:00Z).
    record_time = granted["purposes"]["newsletters"]["last_recorded_at"]
    assert abs(record_time - 1769940000.0) < 1.0


def test_notices_are_immutable_versions_receipts_can_resolve():
    saved = cr.publish_notice("2026-01", "We process your data to ...",
                              actor="dpo")
    assert saved["version"] == "2026-01"
    assert saved["text_sha256"] == hashlib.sha256(
        b"We process your data to ...").hexdigest()
    # Published versions never change -- a revision is a new version.
    from maverick.governed_records import RecordConflict
    with pytest.raises(RecordConflict):
        cr.publish_notice("2026-01", "Different wording", actor="dpo")
    with pytest.raises(ValueError, match="empty"):
        cr.publish_notice("2026-02", "   ", actor="dpo")

    assert cr.get_notice("2026-01")["text"].startswith("We process")
    assert cr.get_notice("nope") is None
    listing = cr.list_notices()
    assert listing[0]["version"] == "2026-01"
    assert "text" not in listing[0]

    _grant()  # binds policy_version 2026-01
    cr.record_consent(
        "bob@example.com", purpose="analytics", status="granted",
        policy_version="2026-99", channel="web", actor="ops",
    )
    coverage = cr.notice_coverage()
    assert coverage["covered"] is False
    assert coverage["uncovered_versions"] == ["2026-99"]
    cr.publish_notice("2026-99", "Newer notice text.", actor="dpo")
    assert cr.notice_coverage()["covered"] is True


def test_site_scan_reports_cookies_and_known_trackers():
    page = """
    <html><head>
      <script src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>
      <script src="/static/app.js"></script>
      <script src="https://cdn.example-partner.io/widget.js"></script>
      <img src="https://www.acme.example/logo.png">
      <iframe src="https://player.example-video.net/embed/1"></iframe>
    </head><body></body></html>
    """

    def fetcher(url):
        assert url == "https://www.acme.example/"
        return (
            {"set-cookie": [
                "session=abc; Secure; HttpOnly; SameSite=Lax",
                "tracker_id=xyz; Domain=.acme.example",
            ]},
            page,
        )

    report = cr.scan_site("https://www.acme.example/", fetcher=fetcher)
    assert [row["name"] for row in report["cookies"]] == [
        "session", "tracker_id"]
    assert report["cookies"][0]["secure"] is True
    assert report["cookies"][0]["same_site"] == "Lax"
    assert report["cookies"][1]["secure"] is False
    assert "www.googletagmanager.com" in report["third_party_hosts"]
    assert "cdn.example-partner.io" in report["third_party_hosts"]
    assert "player.example-video.net" in report["third_party_hosts"]
    # Same-site loads are not third-party.
    assert "www.acme.example" not in report["third_party_hosts"]
    assert report["known_trackers"] == ["www.googletagmanager.com"]


def test_site_scan_requires_https():
    with pytest.raises(ValueError, match="https"):
        cr.scan_site("http://www.acme.example/", fetcher=lambda _u: ({}, ""))


def test_backdated_event_never_flips_a_newer_withdrawal():
    # A OneTrust backfill imports an OLD grant after the subject already
    # withdrew: history keeps both, the projection keeps the withdrawal.
    cr.record_consent(
        "alice@example.com", purpose="marketing", status="withdrawn",
        policy_version="2026-02", channel="web", actor="ops",
        recorded_at=2_000.0,
    )
    saved = cr.record_consent(
        "alice@example.com", purpose="marketing", status="granted",
        policy_version="2025-01", channel="import", actor="importer",
        recorded_at=1_000.0,
    )
    assert saved["current_status"] == "withdrawn"
    assert saved["policy_version"] == "2026-02"
    assert saved["last_recorded_at"] == 2_000.0
    assert saved["first_recorded_at"] == 1_000.0
    assert len(saved["history"]) == 2
    prefs = cr.subject_preferences("alice@example.com")
    assert prefs["purposes"]["marketing"]["status"] == "withdrawn"


def test_legacy_future_grant_cannot_pin_the_current_choice():
    saved = cr.record_consent(
        "alice@example.com", purpose="marketing", status="withdrawn",
        policy_version="2026-02", channel="web", actor="ops",
    )
    future = {**saved["history"][-1], "status": "granted",
              "recorded_at": time.time() + 86400 * 365}

    def legacy(value):
        value["history"].append(future)
        value["current_status"] = "granted"
        value["last_recorded_at"] = future["recorded_at"]

    cr._RECEIPTS.update(saved["id"], legacy, expected_revision=saved["revision"],
                        action="legacy_fixture", actor="ops")
    assert cr.subject_preferences("alice@example.com")["purposes"]["marketing"]["status"] == "withdrawn"
    assert cr.consent_posture()["by_purpose"]["marketing"]["withdrawn"] == 1
    assert cr.export_receipts()[0]["current_status"] == "withdrawn"
    repaired = cr.record_consent(
        "alice@example.com", purpose="marketing", status="withdrawn",
        policy_version="2026-03", channel="web", actor="ops",
    )
    assert repaired["current_status"] == "withdrawn"
    assert repaired["last_recorded_at"] < future["recorded_at"]


def test_accepted_sender_clock_skew_cannot_outrank_later_withdrawal():
    row = {"history": [
        {"status": "granted", "recorded_at": 1300.0, "received_at": 1000.0},
        {"status": "withdrawn", "recorded_at": 1001.0, "received_at": 1001.0},
    ]}
    assert cr._latest_valid_event(row, 1002.0)["status"] == "withdrawn"


def test_site_scan_ignores_relative_src_paths():
    # A relative path with a doubled slash must not be read as a host.
    page = """
    <script src="assets//img/app.js"></script>
    <img src="images/logo//large.png">
    <script src="//cdn.example-partner.io/w.js"></script>
    <iframe src="https://player.example-video.net/embed/1"></iframe>
    """
    report = cr.scan_site(
        "https://www.acme.example/", fetcher=lambda _u: ({}, page)
    )
    assert report["third_party_hosts"] == [
        "cdn.example-partner.io", "player.example-video.net"]


def _signed(body: bytes, ts: int,
            secret: bytes = b"whsec-0123456789abcdef") -> str:
    import hmac as hmac_mod

    return hmac_mod.new(secret, f"{ts}.".encode() + body,
                        hashlib.sha256).hexdigest()


def _now() -> int:
    import time as time_module

    return int(time_module.time())


def test_webhook_requires_its_knob_and_a_real_secret(tmp_path, monkeypatch):
    body = b"{}"
    ts = _now()
    # Enabled registry, webhook knob off -> config refusal.
    monkeypatch.setenv("MAVERICK_CONSENT_WEBHOOK_SECRET",
                       "whsec-0123456789abcdef")
    with pytest.raises(cr.ConsentRegistryConfigError, match="webhook_enable"):
        cr.ingest_consent_webhook(body, _signed(body, ts), ts)
    (tmp_path / "config.toml").write_text(
        f'[consent_registry]\nenable = true\nwebhook_enable = true\n'
        f'subject_salt = "{_SALT}"\n', encoding="utf-8")
    config.reset_config_cache()
    # Short secret -> refused before any signature math.
    monkeypatch.setenv("MAVERICK_CONSENT_WEBHOOK_SECRET", "short")
    with pytest.raises(cr.ConsentRegistryConfigError, match="16"):
        cr.ingest_consent_webhook(body, _signed(body, ts), ts)


def _enable_webhook(tmp_path, monkeypatch):
    (tmp_path / "config.toml").write_text(
        f'[consent_registry]\nenable = true\nwebhook_enable = true\n'
        f'subject_salt = "{_SALT}"\n', encoding="utf-8")
    config.reset_config_cache()
    monkeypatch.setenv("MAVERICK_CONSENT_WEBHOOK_SECRET",
                       "whsec-0123456789abcdef")


def test_webhook_verifies_hmac_then_maps_events(tmp_path, monkeypatch):
    _enable_webhook(tmp_path, monkeypatch)
    ts = _now()
    body = json.dumps({"events": [
        {"subject": "alice@example.com", "purpose": "marketing",
         "status": "OPT_IN"},
        {"subject": "bob@example.com", "purpose": "marketing",
         "status": "mystery"},
    ]}).encode()
    with pytest.raises(PermissionError, match="signature"):
        cr.ingest_consent_webhook(body, "sha256=" + "0" * 64, ts)
    result = cr.ingest_consent_webhook(
        body, "sha256=" + _signed(body, ts), ts)
    assert result == {"imported": 1, "skipped": 1}
    prefs = cr.subject_preferences("alice@example.com")
    assert prefs["purposes"]["marketing"]["status"] == "granted"
    # A backdated push can never flip the projection back.
    newer = json.dumps({"subject": "alice@example.com",
                        "purpose": "marketing", "status": "withdrawn",
                        "recorded_at": float(ts + 1)}).encode()
    cr.ingest_consent_webhook(newer, _signed(newer, ts), ts)
    stale = json.dumps({"subject": "alice@example.com",
                        "purpose": "marketing", "status": "granted",
                        "recorded_at": float(ts - 3600)}).encode()
    cr.ingest_consent_webhook(stale, _signed(stale, ts), ts)
    prefs = cr.subject_preferences("alice@example.com")
    assert prefs["purposes"]["marketing"]["status"] == "withdrawn"


def test_webhook_non_ascii_signature_is_a_mismatch_not_a_crash(tmp_path, monkeypatch):
    # The signature header is sender-controlled; a non-ASCII value used to
    # raise TypeError from hmac.compare_digest instead of the mismatch refusal.
    _enable_webhook(tmp_path, monkeypatch)
    ts = _now()
    body = json.dumps({"subject": "alice@example.com", "purpose": "marketing",
                       "status": "OPT_IN"}).encode()
    for signature in ("sha256=" + "é" * 64, "ÿ" + _signed(body, ts)[1:]):
        with pytest.raises(PermissionError, match="signature"):
            cr.ingest_consent_webhook(body, signature, ts)
    assert cr.subject_preferences("alice@example.com")["purposes"] == {}


def test_webhook_replay_guard(tmp_path, monkeypatch):
    _enable_webhook(tmp_path, monkeypatch)
    body = json.dumps({"subject": "alice@example.com",
                       "purpose": "marketing", "status": "granted"}).encode()
    # A stale signed timestamp is refused outright.
    stale_ts = _now() - 3600
    with pytest.raises(PermissionError, match="replay"):
        cr.ingest_consent_webhook(body, _signed(body, stale_ts), stale_ts)
    # The timestamp is INSIDE the signature: shifting it invalidates.
    ts = _now()
    with pytest.raises(PermissionError, match="signature"):
        cr.ingest_consent_webhook(body, _signed(body, ts), ts - 1)
    # An event with no recorded_at anchors to the SIGNED time -- so a
    # replay inside the window cannot flip a withdrawal recorded after
    # the original delivery.
    cr.ingest_consent_webhook(body, _signed(body, ts), ts)
    cr.record_consent(
        "alice@example.com", purpose="marketing", status="withdrawn",
        policy_version="2026-02", channel="web", actor="ops",
        recorded_at=float(ts + 1),
    )
    cr.ingest_consent_webhook(body, _signed(body, ts), ts)  # the replay
    prefs = cr.subject_preferences("alice@example.com")
    assert prefs["purposes"]["marketing"]["status"] == "withdrawn"


def test_webhook_rejects_non_json_and_oversized_batches(tmp_path, monkeypatch):
    _enable_webhook(tmp_path, monkeypatch)
    ts = _now()
    junk = b"not json"
    with pytest.raises(ValueError, match="JSON"):
        cr.ingest_consent_webhook(junk, _signed(junk, ts), ts)
    big = json.dumps({"events": [
        {"subject": "s", "purpose": "p", "status": "granted"}
    ] * 101}).encode()
    with pytest.raises(ValueError, match="100"):
        cr.ingest_consent_webhook(big, _signed(big, ts), ts)
    with pytest.raises(ValueError, match="timestamp"):
        cr.ingest_consent_webhook(junk, _signed(junk, ts), "soon")


def test_webhook_survives_a_crashing_event(tmp_path, monkeypatch):
    _enable_webhook(tmp_path, monkeypatch)
    ts = _now()
    real = cr.record_consent

    def flaky(subject, **kwargs):
        if "bob" in subject:
            raise RuntimeError("backend hiccup")
        return real(subject, **kwargs)

    monkeypatch.setattr(cr, "record_consent", flaky)
    body = json.dumps({"events": [
        {"subject": "alice@example.com", "purpose": "m", "status": "granted"},
        {"subject": "bob@example.com", "purpose": "m", "status": "granted"},
        {"subject": "carol@example.com", "purpose": "m", "status": "granted"},
    ]}).encode()
    out = cr.ingest_consent_webhook(body, _signed(body, ts), ts)
    # A crashing event skips; the rest of the batch still lands.
    assert out == {"imported": 2, "skipped": 1}
