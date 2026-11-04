"""The public rights-request form: intake, anti-abuse, verification, status."""
from __future__ import annotations

import pytest
from maverick import config
from maverick import public_rights_form as prf

_NOW = 1_790_000_000.0  # 2026-09-21 UTC (a Monday)
_CONFIG = (
    "[privacy_ops]\nenable = true\n\n[privacy_automation]\nenable = true\n\n"
    "[privacy_automation.public_rights_form]\nenable = true\n"
    "requests_per_ip_per_hour = 3\nrequests_per_email_per_day = 2\n"
    "verification_ttl_hours = 1\n"
)


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_ENCRYPTION_KEY", raising=False)
    from maverick import audit, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit, "record", lambda *_a, **_k: True)
    monkeypatch.setattr(audit, "record_global", lambda *_a, **_k: True)
    (tmp_path / "config.toml").write_text(_CONFIG, encoding="utf-8")
    config.reset_config_cache()
    prf.reset_limits()
    sent: list[dict] = []

    def sender(to, subject, body):
        sent.append({"to": to, "subject": subject, "body": body})
        return True, ""

    prf.set_mail_sender(sender)
    yield sent
    prf.set_mail_sender(None)
    prf.reset_limits()
    config.reset_config_cache()


@pytest.fixture
def prop():
    return prf.upsert_property("shop", {
        "name": "Acme Shop", "organisation": "Acme Ltd",
        "contact_email": "privacy@acme.example",
        "jurisdictions": ["eu_gdpr", "us_ca_ccpa"],
        "default_jurisdiction": "eu_gdpr",
        "request_types": ["access", "deletion", "opt_out"],
        "allowed_origins": ["https://shop.acme.example"],
    }, actor="admin")


def _answer(question: str) -> int:
    a, b = [int(w) for w in question.replace("?", "").split() if w.isdigit()]
    return a + b


def _payload(now=_NOW, **over):
    challenge = prf.new_challenge(now=now)
    body = {
        "email": "Casey@Example.com", "name": "Casey", "relationship": "customer",
        "request_type": "access", "jurisdiction": "eu_gdpr", "message": "Please.",
        "authorised_agent": False, "website": "",
        "challenge_token": challenge["token"],
        "challenge_answer": _answer(challenge["question"]),
    }
    body.update(over)
    return body


def _submit(payload, ip="203.0.113.7", now=_NOW):
    return prf.submit("shop", payload, client_ip=ip, base_url="https://acme.example/", now=now)


def _link(sent, kind_marker):
    body = sent[-1]["body"]
    return next(line for line in body.splitlines() if kind_marker in line).strip()


def test_off_by_default(tmp_path):
    (tmp_path / "config.toml").write_text("[privacy_ops]\nenable = true\n", encoding="utf-8")
    config.reset_config_cache()
    assert prf.enabled() is False
    assert prf.form_definition("shop") is None
    with pytest.raises(prf.PublicRightsFormConfigError):
        _submit(_payload())


def test_property_round_trip_and_validation(prop):
    assert prop["slug"] == "shop" and prop["enabled"] is True
    assert prf.get_property("SHOP")["name"] == "Acme Shop"
    with pytest.raises(prf.PublicRightsFormError):
        prf.upsert_property("bad slug!", {}, actor="admin")
    with pytest.raises(prf.PublicRightsFormError, match="verified jurisdiction"):
        prf.upsert_property("x1", {"jurisdictions": ["ca_quebec"], "name": "n",
                                   "organisation": "o", "contact_email": "a@b.co"},
                            actor="admin")
    with pytest.raises(prf.PublicRightsFormError, match="allowed origins"):
        prf.upsert_property("x1", {"jurisdictions": ["eu_gdpr"], "name": "n",
                                   "organisation": "o", "contact_email": "a@b.co",
                                   "allowed_origins": ["http://insecure.example"]},
                            actor="admin")
    updated = prf.upsert_property("shop", {**prop, "name": "Acme Store"}, actor="admin")
    assert updated["name"] == "Acme Store" and updated["revision"] == prop["revision"] + 1
    assert [p["slug"] for p in prf.list_properties()] == ["shop"]
    assert prf.delete_property("shop", actor="admin") is True
    assert prf.get_property("shop") is None


def test_form_definition_offers_only_granted_rights(prop):
    form = prf.form_definition("shop")
    by_id = {row["id"]: row for row in form["jurisdictions"]}
    assert by_id["eu_gdpr"]["rights"] == ["access", "deletion"]
    assert by_id["us_ca_ccpa"]["rights"] == ["access", "deletion", "opt_out"]
    assert form["default_jurisdiction"] == "eu_gdpr"
    assert "plus" in form["challenge"]["question"]
    assert prf.form_definition("nope") is None


def test_happy_path_creates_unverified_request_and_sends_link(prop, _isolate):
    sent = _isolate
    out = _submit(_payload())
    assert out["accepted"] is True and "If that email" in out["message"]
    from maverick import privacy_ops

    rows = privacy_ops.list_dsars()
    assert len(rows) == 1
    row = rows[0]
    assert row["status"] == "unverified" and row["source"] == "public_form"
    assert row["subject_id"] == "casey@example.com"
    assert row["jurisdiction"] == "eu_gdpr" and row["kind"] == "access"
    assert row["requester"]["property"] == "shop"
    assert row["public_form"]["verify_used_at"] is None
    assert "verify" not in str(row["public_form"].get("verify_token", ""))
    assert len(sent) == 1 and sent[0]["to"] == "casey@example.com"
    assert "/rights/verify/" in sent[0]["body"] and "/rights/status/" in sent[0]["body"]
    assert row["public_form"]["emails"][-1] == {
        **row["public_form"]["emails"][-1], "kind": "verification", "sent": True}


def test_honeypot_is_dropped_silently(prop, _isolate):
    out = _submit(_payload(website="http://spam.example"))
    assert out["accepted"] is True
    from maverick import privacy_ops

    assert privacy_ops.list_dsars() == [] and _isolate == []


def test_challenge_failures(prop):
    with pytest.raises(prf.ChallengeFailed):
        _submit(_payload(challenge_answer=99))
    good = _payload()
    _submit(good)
    with pytest.raises(prf.ChallengeFailed):  # single use
        _submit(good, ip="203.0.113.8")
    stale = prf.new_challenge(now=_NOW - 3600)
    with pytest.raises(prf.ChallengeFailed):
        _submit(_payload(challenge_token=stale["token"],
                         challenge_answer=_answer(stale["question"])), ip="203.0.113.9")
    assert prf.check_challenge("garbage", "3") is False


def test_non_ascii_challenge_signature_is_a_failed_challenge(prop):
    # The token comes back from an anonymous browser; accented text where the
    # signature belongs is a wrong answer, not a server error.
    challenge = prf.new_challenge(now=_NOW)
    expires, nonce, _signature = challenge["token"].split(".")
    forged = f"{expires}.{nonce}.{'é' * 64}"
    answer = _answer(challenge["question"])
    assert prf.check_challenge(forged, answer, now=_NOW) is False
    with pytest.raises(prf.ChallengeFailed):
        _submit(_payload(challenge_token=forged, challenge_answer=answer))


def test_rate_limits_per_ip_and_per_email(prop):
    for _ in range(3):
        _submit(_payload(email=f"{_}@example.com"))
    with pytest.raises(prf.RateLimited):
        _submit(_payload())
    # Another address is fine, but the same email hits its daily cap.
    _submit(_payload(email="same@example.com"), ip="198.51.100.1")
    _submit(_payload(email="same@example.com"), ip="198.51.100.2")
    with pytest.raises(prf.RateLimited):
        _submit(_payload(email="same@example.com"), ip="198.51.100.3")
    # The hourly window slides.
    _submit(_payload(now=_NOW + 3601, email="later@example.com"), now=_NOW + 3601)


def test_validation_messages_never_mention_whether_an_email_is_known(prop):
    # Every attempt counts against the address limit, so each uses its own.
    with pytest.raises(prf.PublicRightsFormError, match="valid email"):
        _submit(_payload(email="not-an-email"), ip="198.51.100.11")
    with pytest.raises(prf.PublicRightsFormError, match="not available under"):
        _submit(_payload(request_type="opt_out", jurisdiction="eu_gdpr"), ip="198.51.100.12")
    with pytest.raises(prf.PublicRightsFormError, match="relationship"):
        _submit(_payload(relationship="alien"), ip="198.51.100.13")
    with pytest.raises(prf.PublicRightsFormError, match="at most"):
        _submit(_payload(message="x" * 4001), ip="198.51.100.14")
    # The same acceptance text whether or not anyone with that email exists;
    # only each request's own reference differs.
    first = _submit(_payload(email="new@example.com"))
    second = _submit(_payload(email="new@example.com"), ip="198.51.100.9")
    assert first["reference"] != second["reference"]

    def without_reference(out):
        return {**out, "reference": "", "message": out["message"].replace(out["reference"], "")}

    assert without_reference(first) == without_reference(second)


def test_verification_link_valid_then_reused_then_expired(prop, _isolate):
    sent = _isolate
    _submit(_payload())
    verify_url = _link(sent, "/rights/verify/")
    token = verify_url.rsplit("/", 1)[1]
    assert prf.verify("wrong-token", now=_NOW + 10) is None
    view = prf.verify(token, now=_NOW + 10)
    assert view["status"] == "open" and view["verified"] is True
    assert view["reference"].startswith("DSAR-")
    assert view["due_date"] == "2026-10-21"  # GDPR: one calendar month
    from maverick import privacy_ops

    row = privacy_ops.list_dsars()[0]
    assert row["verification"]["method"] == "email_challenge"
    assert row["verification"]["verified_by"] == "public-rights-form"
    assert [e["kind"] for e in row["public_form"]["emails"]] == ["verification", "acknowledgement"]
    assert sent[-1]["subject"].startswith("We received your privacy request")
    # Reuse is refused.
    assert prf.verify(token, now=_NOW + 20) is None
    # A fresh request's link expires after the configured hour.
    _submit(_payload(email="late@example.com"), ip="198.51.100.5")
    late = _link(sent, "/rights/verify/").rsplit("/", 1)[1]
    assert prf.verify(late, now=_NOW + 3601) is None


def test_a_failed_verification_does_not_burn_the_link(prop, _isolate, monkeypatch):
    from maverick import privacy_ops

    _submit(_payload())
    token = _link(_isolate, "/rights/verify/").rsplit("/", 1)[1]
    real = privacy_ops.verify_dsar

    def broken(*args, **kwargs):
        raise OSError("disk unavailable")
    monkeypatch.setattr(privacy_ops, "verify_dsar", broken)
    with pytest.raises(OSError):
        prf.verify(token, now=_NOW + 10)
    assert privacy_ops.list_dsars()[0]["status"] == "unverified"
    monkeypatch.setattr(privacy_ops, "verify_dsar", real)
    view = prf.verify(token, now=_NOW + 20)  # the same link still works
    assert view is not None and view["status"] == "open" and view["verified"] is True
    assert prf.verify(token, now=_NOW + 30) is None  # and is single-use once it has


def test_a_failed_acknowledgement_does_not_fail_a_completed_verification(prop, _isolate, monkeypatch):
    from maverick import privacy_ops

    _submit(_payload())
    token = _link(_isolate, "/rights/verify/").rsplit("/", 1)[1]

    def broken(*args, **kwargs):
        raise OSError("disk unavailable")
    monkeypatch.setattr(prf, "send_notice", broken)
    view = prf.verify(token, now=_NOW + 10)
    assert view is not None and view["status"] == "open" and view["verified"] is True
    assert privacy_ops.list_dsars()[0]["status"] == "open"
    assert prf.verify(token, now=_NOW + 20) is None  # still single-use


def test_verification_mirrors_into_fulfillment_when_that_module_is_on(prop, _isolate, tmp_path):
    (tmp_path / "config.toml").write_text(
        _CONFIG + "\n[dsar_fulfillment]\nenable = true\n", encoding="utf-8")
    config.reset_config_cache()
    _submit(_payload())
    token = _link(_isolate, "/rights/verify/").rsplit("/", 1)[1]
    view = prf.verify(token, now=_NOW + 5)
    from maverick import dsar_fulfillment

    record = dsar_fulfillment.get_fulfillment(view["reference"])
    assert record["identity"]["status"] == "verified"
    assert record["identity"]["method"] == "email_challenge"
    assert record["identity"]["verified_by"] == "public-rights-form"
    assert "email_challenge" in dsar_fulfillment.IDENTITY_METHODS_PERFORMED


def test_status_token_shows_progress_without_an_account(prop, _isolate):
    _submit(_payload())
    status_token = _link(_isolate, "/rights/status/").rsplit("/", 1)[1]
    view = prf.status(status_token, now=_NOW + 5)
    assert view["status"] == "unverified" and view["verified"] is False
    assert view["request_type_label"] == "a copy of your data"
    assert "opened_by" not in view and "requester" not in view
    assert prf.status("nope", now=_NOW) is None
    assert prf.status(status_token, now=_NOW + 91 * 86_400) is None


def test_send_notice_uses_family_templates_and_logs(prop, _isolate):
    sent = _isolate
    _submit(_payload(jurisdiction="us_ca_ccpa"))
    from maverick import privacy_ops

    request_id = privacy_ops.list_dsars()[0]["id"]
    with pytest.raises(prf.PublicRightsFormError, match="lawful basis"):
        prf.send_notice(request_id, "refusal", actor="ops")
    with pytest.raises(prf.PublicRightsFormError, match="record the extension"):
        prf.send_notice(request_id, "extension", actor="ops")
    privacy_ops.extend_dsar(request_id, reason="many systems to search", days=30,
                            extended_by="ops")
    out = prf.send_notice(request_id, "extension", actor="ops")
    assert out["sent"] is True and "many systems to search" in sent[-1]["body"]
    refused = prf.send_notice(request_id, "refusal", actor="ops",
                              extra={"lawful_basis": "Cannot verify identity"})
    assert "Cannot verify identity" in sent[-1]["body"]
    assert "Attorney General" in sent[-1]["body"]  # us_state family wording
    assert refused["template_version"] == 0
    done = prf.send_notice(request_id, "completion", actor="ops",
                           extra={"secure_link": "https://acme.example/dsar/response/abc",
                                  "secure_link_expires": "2026-11-01"})
    assert done["sent"] is True and "/dsar/response/abc" in sent[-1]["body"]
    kinds = [e["kind"] for e in privacy_ops.get_dsar(request_id)["public_form"]["emails"]]
    assert kinds == ["verification", "extension", "refusal", "completion"]


def test_unsent_email_is_logged_not_lost(prop, _isolate):
    prf.set_mail_sender(lambda *_: (False, "smtp down"))
    _submit(_payload())
    from maverick import privacy_ops

    entry = privacy_ops.list_dsars()[0]["public_form"]["emails"][-1]
    assert entry["sent"] is False and entry["reason"] == "smtp down"


def test_default_sender_without_account_reports_not_sent(monkeypatch):
    monkeypatch.delenv("EMAIL_USER", raising=False)
    monkeypatch.delenv("EMAIL_APP_PASSWORD", raising=False)
    sent, reason = prf._default_sender("a@b.co", "s", "b")
    assert sent is False and "no sending account" in reason


_NO_ACCOUNT = "no sending account configured ([email] / EMAIL_USER)"


def test_acceptance_gives_a_reference_and_promises_email_only_when_sent(prop, _isolate):
    out = _submit(_payload())
    from maverick import privacy_ops

    reference = privacy_ops.list_dsars()[0]["id"]
    assert out["reference"] == reference and out["email_sent"] is True
    assert reference in out["message"] and "If that email" in out["message"]

    prf.set_mail_sender(lambda *_: (False, _NO_ACCOUNT))
    out = _submit(_payload(email="other@example.com"), ip="198.51.100.4")
    reference = next(r["id"] for r in privacy_ops.list_dsars() if r["subject_id"] == "other@example.com")
    assert out["email_sent"] is False and out["reference"] == reference
    assert reference in out["message"]
    assert "we have sent" not in out["message"].lower()
    assert "privacy@acme.example" in out["message"]  # who to contact instead


def test_honeypot_answers_in_the_same_shape_without_a_record(prop, _isolate):
    real = _submit(_payload())
    bot = _submit(_payload(email="bot@example.com", website="http://spam.example"),
                  ip="198.51.100.9")
    from maverick import privacy_ops

    assert set(bot) == set(real)
    assert bot["email_sent"] is real["email_sent"]
    assert bot["reference"].startswith("DSAR-") and bot["reference"] != real["reference"]
    assert [r["subject_id"] for r in privacy_ops.list_dsars()] == ["casey@example.com"]


def test_notice_log_counts_only_notices_that_were_sent(prop, _isolate):
    prf.set_mail_sender(lambda *_: (False, _NO_ACCOUNT))
    _submit(_payload())
    from maverick import privacy_ops

    record = privacy_ops.list_dsars()[0]
    log = prf.notice_log(record)
    assert log["sent"] == 0 and log["not_sent"] == 1
    item = log["items"][0]
    assert item["sent"] is False and item["label"] == "Confirm the email address"
    assert item["problem"] == "Lightwork has no email account to send from."
    assert "Settings" in item["next_step"] and "another way" in item["next_step"]
    assert "EMAIL_USER" in item["technical"]
    assert "EMAIL_USER" not in item["problem"] + item["next_step"]
    prf.set_mail_sender(lambda *_: (True, ""))
    prf.send_notice(record["id"], "identity_followup", actor="ops")
    log = prf.notice_log(privacy_ops.get_dsar(record["id"]))
    assert log["sent"] == 1 and log["not_sent"] == 1


def test_send_result_explains_an_unsent_notice_plainly(prop, _isolate):
    _submit(_payload())
    from maverick import privacy_ops

    request_id = privacy_ops.list_dsars()[0]["id"]
    prf.set_mail_sender(lambda *_: (False, _NO_ACCOUNT))
    out = prf.send_notice(request_id, "acknowledgement", actor="ops")
    assert out["sent"] is False
    assert out["problem"] == "Lightwork has no email account to send from."
    assert out["next_step"]


def test_a_sent_refusal_is_a_recorded_answer_with_its_lawful_reason(prop, _isolate):
    _submit(_payload())
    from maverick import privacy_ops

    request_id = privacy_ops.list_dsars()[0]["id"]
    prf.send_notice(request_id, "refusal", actor="ops",
                    extra={"lawful_basis": "Manifestly unfounded"})
    privacy_ops.close_dsar(request_id, closed_by="ops")
    entry = privacy_ops.get_dsar(request_id)["public_form"]["emails"][-1]
    assert entry["kind"] == "refusal" and entry["lawful_basis"] == "Manifestly unfounded"
    dsar = privacy_ops.program_report(assessment_types={"none"})["dsar"]
    assert dsar["answered"] == 1 and dsar["closed_without_response"] == 0


def test_an_unsent_completion_is_not_an_answer(prop, _isolate):
    _submit(_payload())
    from maverick import privacy_ops

    request_id = privacy_ops.list_dsars()[0]["id"]
    prf.set_mail_sender(lambda *_: (False, _NO_ACCOUNT))
    prf.send_notice(request_id, "completion", actor="ops",
                    extra={"secure_link": "https://acme.example/dsar/response/abc",
                           "secure_link_expires": "2026-11-01"})
    privacy_ops.close_dsar(request_id, closed_by="ops")
    dsar = privacy_ops.program_report(assessment_types={"none"})["dsar"]
    assert dsar["answered"] == 0 and dsar["closed_without_response"] == 1
