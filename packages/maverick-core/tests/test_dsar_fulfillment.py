"""DSAR fulfillment: identity gate, token hygiene, delivery-time redaction.

The assertions that matter: no response link mints before a named human
records identity verification; the token is stored only as a digest and
never re-readable; expiry and wrong tokens read identically as None; the
delivered bundle is scrubbed of third-party identifiers while the
subject's own reference survives; the CLI's method choices cannot drift
from the module's vocabulary.
"""
from __future__ import annotations

import time

import pytest
from maverick import config
from maverick import dsar_fulfillment as df


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import audit, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit, "record", lambda *_a, **_k: True)
    monkeypatch.setattr(audit, "record_global", lambda *_a, **_k: True)
    (tmp_path / "config.toml").write_text(
        "[dsar_fulfillment]\nenable = true\n\n[privacy_ops]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _request(subject="alice@example.com"):
    from maverick import privacy_ops

    return privacy_ops.open_dsar(subject, "access", opened_by="ops")


def test_off_by_default(tmp_path):
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    assert df.enabled() is False
    with pytest.raises(df.DsarFulfillmentConfigError, match="enable"):
        df.open_fulfillment("DSAR-1", actor="ops")


def test_open_requires_a_real_request_and_is_idempotent():
    with pytest.raises(KeyError, match="no such DSAR"):
        df.open_fulfillment("DSAR-nope", actor="ops")
    request = _request()
    first = df.open_fulfillment(request["id"], actor="ops")
    again = df.open_fulfillment(request["id"], actor="ops")
    assert first["id"] == again["id"]
    assert first["identity"]["status"] == "unverified"


def test_identity_gates_the_response_and_vocabulary_is_fixed():
    request = _request()
    record = df.open_fulfillment(request["id"], actor="ops")
    with pytest.raises(df.DsarFulfillmentError, match="identity"):
        df.prepare_response(
            record["id"], actor="ops", expected_revision=record["revision"])
    with pytest.raises(ValueError, match="method"):
        df.record_identity_verification(
            record["id"], method="trust_me", reference="x",
            actor="ops", expected_revision=record["revision"])
    verified = df.record_identity_verification(
        record["id"], method="document_check", reference="passport scan ref",
        actor="carol", expected_revision=record["revision"])
    assert verified["identity"]["verified_by"] == "carol"


def test_token_lifecycle_and_delivery_time_redaction():
    request = _request()
    record = df.open_fulfillment(request["id"], actor="ops")
    record = df.record_identity_verification(
        record["id"], method="email_challenge", reference="challenge-1",
        actor="ops", expected_revision=record["revision"])
    link = df.prepare_response(
        record["id"], actor="ops", expected_revision=record["revision"])
    token = link["response_path"].rsplit("/", 1)[-1]
    # The stored record carries only the digest, and reads hide even that.
    status = df.get_fulfillment(request["id"])
    assert "token_sha256" not in (status["response"] or {})
    response = df.response_for_token(token)
    assert response is not None
    assert response["request_id"] == request["id"]
    # The subject's own reference survives the third-party scrub.
    assert response["subject_id"] == "alice@example.com"
    assert df.response_for_token("not-the-token") is None
    # Delivery is stamped on first read.
    assert df.get_fulfillment(request["id"])["response"]["delivered_at"]


@pytest.mark.parametrize("channel", ["email", ""])
def test_channel_binding_survives_fulfillment_and_ambiguity_does_not_burn_link(channel):
    from maverick import privacy_ops, world_model

    world = world_model.WorldModel(world_model.DEFAULT_DB)
    for name, message in [("email", "requested channel content"), ("slack", "other subject content")]:
        conversation = world.get_or_create_conversation(name, "shared-id")
        world.append_turn(conversation.id, "user", message)
    request = privacy_ops.open_dsar("shared-id", "access", channel=channel, opened_by="ops")
    record = df.open_fulfillment(request["id"], actor="ops")
    record = df.record_identity_verification(record["id"], method="account_login", reference="verified-identity", actor="ops", expected_revision=record["revision"])
    link = df.prepare_response(record["id"], actor="ops", expected_revision=record["revision"])
    token = link["response_path"].rsplit("/", 1)[-1]
    if channel:
        response = df.response_for_token(token)
        conversations = response["bundle"]["world"]["conversations"]
        assert len(conversations) == 1 and conversations[0]["channel"] == "email"
        assert conversations[0]["turns"][0]["content"] == "requested channel content"
    else:
        with pytest.raises(RuntimeError, match="ambiguous"):
            df.response_for_token(token)
        status = df.get_fulfillment(request["id"])["response"]
        assert not status.get("delivered_at") and status.get("reads_used", 0) == 0
    world.close()


def test_expired_tokens_read_as_none(monkeypatch):
    request = _request()
    record = df.open_fulfillment(request["id"], actor="ops")
    record = df.record_identity_verification(
        record["id"], method="account_login", reference="session-9",
        actor="ops", expected_revision=record["revision"])
    link = df.prepare_response(
        record["id"], actor="ops", expected_revision=record["revision"],
        expires_hours=1)
    token = link["response_path"].rsplit("/", 1)[-1]
    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + 2 * 3600)
    assert df.response_for_token(token) is None


def test_bundle_redaction_scrubs_third_parties_keeps_subject():
    scrubbed = df._redact_bundle(
        {"subject": "alice@example.com",
         "note": "escalated by bob@example.com from 10.0.0.7"},
        "alice@example.com",
    )
    assert scrubbed["subject"] == "alice@example.com"
    assert "bob@example.com" not in scrubbed["note"]
    assert "10.0.0.7" not in scrubbed["note"]


def test_collection_sources_are_bounded_and_logged():
    request = _request()
    record = df.open_fulfillment(request["id"], actor="ops")
    saved = df.record_collection_source(
        record["id"], source="vendor:acme", reference="ticket-1", items=2,
        actor="ops", expected_revision=record["revision"])
    assert saved["sources"][0]["items"] == 2
    with pytest.raises(ValueError, match="non-negative"):
        df.record_collection_source(
            record["id"], source="vendor:acme", reference="t", items=-1,
            actor="ops", expected_revision=saved["revision"])


def test_cli_method_choices_match_the_module_vocabulary():
    from maverick.cli import _compliance_groups as cli

    choices = None
    for param in cli.dsar_fulfill_verify.params:
        if param.name == "method":
            choices = tuple(param.type.choices)
    assert choices == df.IDENTITY_METHODS


def test_read_cap_burns_the_link():
    request = _request()
    record = df.open_fulfillment(request["id"], actor="ops")
    record = df.record_identity_verification(
        record["id"], method="document_check", reference="scan-1",
        actor="ops", expected_revision=record["revision"])
    link = df.prepare_response(
        record["id"], actor="ops", expected_revision=record["revision"],
        max_reads=1)
    token = link["response_path"].rsplit("/", 1)[-1]
    first = df.response_for_token(token)
    assert first is not None
    assert first["access_policy"] == {
        "expires_at": first["access_policy"]["expires_at"],
        "max_reads": 1, "reads_used": 1}
    # Strict single-use: the second read is gone, same as a wrong token.
    assert df.response_for_token(token) is None
    with pytest.raises(ValueError, match="max_reads"):
        df.prepare_response(record["id"], actor="ops",
                            expected_revision=3, max_reads=0)


def test_store_conflict_mid_flow_surfaces_as_conflict_not_corruption():
    from maverick.governed_records import RecordConflict

    request = _request()
    record = df.open_fulfillment(request["id"], actor="ops")

    def explode(*_a, **_k):
        raise RecordConflict("concurrent writer")

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(df._STORE, "update", explode)
        # Mutations propagate the conflict (the API maps it to 409)...
        with pytest.raises(RecordConflict):
            df.record_identity_verification(
                record["id"], method="other", reference="x",
                actor="ops", expected_revision=record["revision"])
    # ...and the record is untouched.
    assert df.get_fulfillment(request["id"])["identity"]["status"] == "unverified"


def test_public_token_read_contention_reads_as_absent(monkeypatch):
    from maverick.governed_records import RecordConflict

    request = _request()
    record = df.open_fulfillment(request["id"], actor="ops")
    record = df.record_identity_verification(
        record["id"], method="other", reference="x",
        actor="ops", expected_revision=record["revision"])
    link = df.prepare_response(
        record["id"], actor="ops", expected_revision=record["revision"])
    token = link["response_path"].rsplit("/", 1)[-1]

    def contend(*_a, **_k):
        raise RecordConflict("racing delivery")

    monkeypatch.setattr(df._STORE, "update", contend)
    # The public surface never turns contention into an error page; the
    # requester simply retries the link.
    assert df.response_for_token(token) is None


def test_graph_collection_counts_footprint_and_moves_no_content():
    request = _request()  # alice@example.com — a Graph-addressable UPN
    record = df.open_fulfillment(request["id"], actor="ops")
    calls: list[str] = []

    def fetcher(url: str) -> dict:
        calls.append(url)
        if "/messages" in url:
            return {"value": [{"id": f"m{i}"} for i in range(3)],
                    "@odata.nextLink": "https://graph.microsoft.com/next"}
        return {"value": [{"id": "f1"}]}

    out = df.collect_graph_sources(
        request["id"], actor="ops",
        expected_revision=record["revision"], fetcher=fetcher)

    assert [c.split("?")[0] for c in calls] == [
        "https://graph.microsoft.com/v1.0/users/alice%40example.com/messages",
        "https://graph.microsoft.com/v1.0/users/alice%40example.com"
        "/drive/root/children"]
    assert all("$select=id" in c for c in calls)   # ids only, never bodies
    sources = out["record"]["sources"]
    assert [(s["source"], s["items"]) for s in sources] == [
        ("graph:outlook_mail", 3), ("graph:onedrive_files", 1)]
    assert "more exist" in sources[0]["reference"]
    assert out["probes"][0]["more"] is True


def test_graph_collection_refuses_non_upn_subjects_and_needs_a_token(
    monkeypatch,
):
    from maverick import privacy_ops

    opaque = privacy_ops.open_dsar("customer #4471", "access",
                                   opened_by="ops")
    record = df.open_fulfillment(opaque["id"], actor="ops")
    with pytest.raises(ValueError, match="userPrincipalName"):
        df.collect_graph_sources(opaque["id"], actor="ops",
                                 expected_revision=record["revision"],
                                 fetcher=lambda _u: {"value": []})
    monkeypatch.delenv("MAVERICK_GRAPH_TOKEN", raising=False)
    request = _request()
    opened = df.open_fulfillment(request["id"], actor="ops")
    with pytest.raises(df.DsarFulfillmentConfigError, match="GRAPH_TOKEN"):
        df.collect_graph_sources(request["id"], actor="ops",
                                 expected_revision=opened["revision"])


def test_graph_collection_survives_a_missing_drive():
    request = _request()
    record = df.open_fulfillment(request["id"], actor="ops")

    def fetcher(url: str) -> dict:
        if "/drive/" in url:
            raise df.DsarFulfillmentError("Microsoft Graph returned HTTP 404")
        return {"value": []}

    out = df.collect_graph_sources(
        request["id"], actor="ops",
        expected_revision=record["revision"], fetcher=fetcher)
    assert out["probes"][0] == {"source": "graph:outlook_mail",
                                "collected": True, "items": 0, "more": False}
    assert out["probes"][1]["collected"] is False
    assert "404" in out["probes"][1]["error"]
    # The mailbox probe still landed on the record; the drive did not.
    assert [s["source"] for s in out["record"]["sources"]] == [
        "graph:outlook_mail"]
