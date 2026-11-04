"""Focused HTTP contracts for the consumer Consent & Preferences data plane."""
from __future__ import annotations

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})

API = "/api/v1/consent"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64


@pytest.fixture(autouse=True)
def _isolated_consent_plane(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer

    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[consent_preferences]\nenable = true\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in (
        "MAVERICK_DASHBOARD_ADMINS",
        "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_DASHBOARD_REQUIRE_AUTH",
        "MAVERICK_OIDC_ENABLED",
        "MAVERICK_PROXY_AUTH",
        "MAVERICK_TENANT_BY_USER",
    ):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    yield config_path
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()


def _ok(response, expected: int = 200) -> dict:
    assert response.status_code == expected, response.text
    return response.json()


def _context() -> dict:
    return {
        "jurisdiction": "us-state-ca",
        "country_code": "us",
        "region_code": "US-CA",
        "collection_point": "preference-center",
        "asserted_source": "client",
    }


def _policy_body(
    *,
    version: int = 1,
    expected_current_version: int | None = None,
) -> dict:
    body = {
        "policy_id": "privacy-notice",
        "version": version,
        "purposes": {"analytics": "consent", "marketing": "consent"},
        "notice_sha256": DIGEST_A,
        "effective_at": time.time() - 60,
    }
    if expected_current_version is not None:
        body["expected_current_version"] = expected_current_version
    return body


def _profile_body(
    profile_id: str = "profile-001",
    *,
    identity_kind: str = "known",
    subject_sha256: str = DIGEST_B,
    idempotency_key: str = "create-profile-001",
) -> dict:
    return {
        "profile_id": profile_id,
        "identity_kind": identity_kind,
        "subject_sha256": subject_sha256,
        "idempotency_key": idempotency_key,
    }


def _preference_body(
    *,
    action: str = "grant",
    purpose_id: str = "analytics",
    expected_revision: int = 0,
    idempotency_key: str = "preference-001",
    retention_until: float | None = None,
) -> dict:
    body = {
        "policy_id": "privacy-notice",
        "policy_version": 1,
        "context": _context(),
        "choices": [
            {
                "purpose_id": purpose_id,
                "action": action,
                "channel": "all",
                "vendor_id": "all",
            }
        ],
        "expected_revision": expected_revision,
        "idempotency_key": idempotency_key,
    }
    if retention_until is not None:
        body["retention_until"] = retention_until
    return body


def _publish_policy() -> dict:
    return _ok(client.post(f"{API}/policies", json=_policy_body()), 201)


def _create_profile(**overrides) -> dict:
    return _ok(client.post(f"{API}/profiles", json=_profile_body(**overrides)), 201)


def test_capability_is_default_off(_isolated_consent_plane: Path) -> None:
    from maverick import config

    _isolated_consent_plane.write_text("", encoding="utf-8")
    config.reset_config_cache()

    response = client.get(f"{API}/summary")

    assert response.status_code == 403
    assert "disabled" in response.json()["detail"]


def test_every_route_requires_an_explicit_strict_tenant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)

    response = client.get(f"{API}/summary")

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "select an active tenant before using consent records"
    )


def test_policy_profile_receipt_gpc_and_enforcement_lifecycle() -> None:
    policy = _publish_policy()
    assert policy["version"] == 1
    assert policy["purposes"] == {
        "analytics": "consent",
        "marketing": "consent",
    }
    policies = _ok(client.get(f"{API}/policies"))
    assert policies["truncated"] is False
    assert [item["policy_id"] for item in policies["policies"]] == [
        "privacy-notice"
    ]

    profile = _create_profile()
    assert profile["revision"] == 0
    assert profile["subject_sha256"] == DIGEST_B
    profiles = _ok(client.get(f"{API}/profiles"))
    assert profiles["profiles"] == [profile]
    assert profiles["truncated"] is False

    receipt = _ok(
        client.post(
            f"{API}/profiles/profile-001/preferences",
            json=_preference_body(),
        ),
        201,
    )
    assert receipt["profile_revision"] == 1
    assert receipt["policy_version"] == 1
    assert receipt["context"]["geolocation"]["country_code"] == "US"
    assert receipt["context"]["geolocation"]["verified"] is False
    allowed = _ok(
        client.post(
            f"{API}/decisions",
            json={
                "profile_id": "profile-001",
                "purpose_id": "analytics",
                "policy_id": "privacy-notice",
                "policy_version": 1,
            },
        )
    )
    assert allowed["allowed"] is True
    assert allowed["reason"] == "explicit_grant"
    assert allowed["receipt_sha256"] == receipt["receipt_sha256"]

    signal = _ok(
        client.post(
            f"{API}/profiles/profile-001/privacy-signals",
            json={
                "signal": "gpc",
                "purposes": ["marketing"],
                "policy_id": "privacy-notice",
                "policy_version": 1,
                "context": _context(),
                "expected_revision": 1,
                "idempotency_key": "gpc-001",
            },
        ),
        201,
    )
    assert signal["profile_revision"] == 2
    assert signal["context"]["privacy_signal"] == "gpc"
    denied = _ok(
        client.post(
            f"{API}/decisions",
            json={
                "profile_id": "profile-001",
                "purpose_id": "marketing",
                "policy_id": "privacy-notice",
            },
        )
    )
    assert denied["allowed"] is False
    assert denied["reason"] == "explicit_deny"

    summary = _ok(client.get(f"{API}/summary"))
    assert summary["policies"] == 1
    assert summary["profiles"] == 1
    assert summary["receipts"] == 2
    assert summary["outbox_events"] == 3


def test_idempotent_replay_cas_and_rebinding_conflicts() -> None:
    _publish_policy()
    first_profile = _create_profile()
    assert _create_profile() == first_profile

    rebound = _profile_body(subject_sha256=DIGEST_C)
    response = client.post(f"{API}/profiles", json=rebound)
    assert response.status_code == 409
    assert "idempotency key" in response.json()["detail"]

    first_receipt = _ok(
        client.post(
            f"{API}/profiles/profile-001/preferences",
            json=_preference_body(),
        ),
        201,
    )
    replay = _ok(
        client.post(
            f"{API}/profiles/profile-001/preferences",
            json=_preference_body(),
        ),
        201,
    )
    assert replay == first_receipt
    assert _ok(client.get(f"{API}/summary"))["receipts"] == 1

    changed = _preference_body(
        action="deny",
        expected_revision=1,
        idempotency_key="preference-001",
    )
    assert client.post(
        f"{API}/profiles/profile-001/preferences", json=changed
    ).status_code == 409
    stale = _preference_body(
        action="deny",
        expected_revision=0,
        idempotency_key="preference-002",
    )
    assert client.post(
        f"{API}/profiles/profile-001/preferences", json=stale
    ).status_code == 409

    _ok(
        client.post(
            f"{API}/policies",
            json=_policy_body(version=2, expected_current_version=1),
        ),
        201,
    )
    bad_cas = client.post(
        f"{API}/policies",
        json=_policy_body(version=3, expected_current_version=1),
    )
    assert bad_cas.status_code == 409


def test_known_and_anonymous_profiles_link_into_one_consent_authority() -> None:
    _publish_policy()
    _create_profile(profile_id="known-001", idempotency_key="known-001")
    _create_profile(
        profile_id="anon-001",
        identity_kind="anonymous",
        subject_sha256=DIGEST_C,
        idempotency_key="anon-001",
    )
    link = _ok(
        client.post(
            f"{API}/profiles/link",
            json={
                "known_profile_id": "known-001",
                "anonymous_profile_id": "anon-001",
                "expected_known_revision": 0,
                "expected_anonymous_revision": 0,
                "idempotency_key": "link-001",
            },
        )
    )
    assert link["known_revision"] == 1
    assert link["anonymous_revision"] == 1
    _ok(
        client.post(
            f"{API}/profiles/known-001/preferences",
            json=_preference_body(
                expected_revision=1,
                idempotency_key="known-preference-001",
            ),
        ),
        201,
    )

    decision = _ok(
        client.post(
            f"{API}/decisions",
            json={
                "profile_id": "anon-001",
                "purpose_id": "analytics",
                "policy_id": "privacy-notice",
            },
        )
    )
    assert decision["allowed"] is True
    assert decision["reason"] == "explicit_grant"


def test_tracker_scan_and_tracker_bound_enforcement() -> None:
    _publish_policy()
    _create_profile()
    _ok(
        client.post(
            f"{API}/profiles/profile-001/preferences",
            json=_preference_body(),
        ),
        201,
    )
    tracker_body = {
        "kind": "web_tracker",
        "vendor_id": "all",
        "purpose_ids": ["analytics"],
        "status": "approved",
        "expected_revision": 0,
        "idempotency_key": "tracker-001",
    }
    tracker = _ok(
        client.put(f"{API}/trackers/tracker-analytics", json=tracker_body)
    )
    assert tracker["revision"] == 1
    assert _ok(client.get(f"{API}/trackers"))["trackers"] == [tracker]

    scan_body = {
        "scan_id": "scan-001",
        "observations": [
            {
                "asset_ref": "asset-home",
                "tracker_id": "tracker-analytics",
                "location_ref": "head",
                "evidence_sha256": DIGEST_C,
            }
        ],
        "observed_at": time.time(),
        "source_sha256": DIGEST_D,
        "idempotency_key": "scan-001",
    }
    admitted = _ok(client.post(f"{API}/scans", json=scan_body), 201)
    assert admitted["admitted"] is True
    assert admitted["admitted_count"] == 1
    scan = _ok(client.get(f"{API}/scans/scan-001"))
    assert scan["truncated"] is False
    assert scan["observations"][0]["tracker_id"] == "tracker-analytics"

    allowed = _ok(
        client.post(
            f"{API}/decisions",
            json={
                "profile_id": "profile-001",
                "purpose_id": "analytics",
                "policy_id": "privacy-notice",
                "tracker_id": "tracker-analytics",
            },
        )
    )
    assert allowed["allowed"] is True
    unknown = _ok(
        client.post(
            f"{API}/decisions",
            json={
                "profile_id": "profile-001",
                "purpose_id": "analytics",
                "policy_id": "privacy-notice",
                "tracker_id": "unregistered-tracker",
            },
        )
    )
    assert unknown["allowed"] is False
    assert unknown["reason"] == "tracker_not_approved"

    rejected = dict(scan_body)
    rejected["scan_id"] = "scan-unknown"
    rejected["idempotency_key"] = "scan-unknown"
    rejected["observations"] = [
        {
            **scan_body["observations"][0],
            "tracker_id": "unregistered-tracker",
        }
    ]
    response = client.post(f"{API}/scans", json=rejected)
    assert response.status_code == 422
    assert _ok(client.get(f"{API}/scans/scan-unknown"))["observations"] == []


def test_outbox_ack_is_destination_scoped_idempotent_and_replayable() -> None:
    _create_profile()
    page = _ok(client.get(f"{API}/sync/app-east"))
    assert page["destination_id"] == "app-east"
    assert len(page["events"]) == 1
    event = page["events"][0]

    ack = _ok(
        client.post(
            f"{API}/sync/app-east/{event['event_id']}/ack",
            json={"idempotency_key": "ack-001"},
        )
    )
    assert ack["event_id"] == event["event_id"]
    assert _ok(
        client.post(
            f"{API}/sync/app-east/{event['event_id']}/ack",
            json={"idempotency_key": "ack-001"},
        )
    ) == ack
    assert _ok(client.get(f"{API}/sync/app-east"))["events"] == []

    replay = _ok(
        client.get(f"{API}/sync/app-east", params={"include_acked": True})
    )
    assert replay["replay"] is True
    assert [item["event_id"] for item in replay["events"]] == [event["event_id"]]
    assert len(_ok(client.get(f"{API}/sync/app-west"))["events"]) == 1


def test_export_access_log_retention_and_operational_purge_preserve_receipts() -> None:
    now = time.time()
    _publish_policy()
    _create_profile()
    receipt = _ok(
        client.post(
            f"{API}/profiles/profile-001/preferences",
            json=_preference_body(retention_until=now + 300),
        ),
        201,
    )
    tracker_body = {
        "kind": "web_tracker",
        "vendor_id": "all",
        "purpose_ids": ["analytics"],
        "status": "approved",
        "expected_revision": 0,
        "idempotency_key": "tracker-retention",
    }
    _ok(client.put(f"{API}/trackers/tracker-retention", json=tracker_body))
    _ok(
        client.post(
            f"{API}/scans",
            json={
                "scan_id": "scan-retention",
                "observations": [
                    {
                        "asset_ref": "asset-retention",
                        "tracker_id": "tracker-retention",
                        "location_ref": "head",
                        "evidence_sha256": DIGEST_C,
                    }
                ],
                "observed_at": now,
                "source_sha256": DIGEST_D,
                "idempotency_key": "scan-retention",
            },
        ),
        201,
    )

    export = _ok(
        client.get(
            f"{API}/profiles/profile-001/export",
            params={"access_purpose": "data-subject-access", "receipt_limit": 1},
        )
    )
    assert export["receipts"][0]["receipt_sha256"] == receipt["receipt_sha256"]
    access = _ok(client.get(f"{API}/profiles/profile-001/access-log"))
    assert access["events"][0]["export_sha256"] == export["export_sha256"]

    cutoff = now + 600
    due = _ok(client.get(f"{API}/retention/due", params={"before": cutoff}))
    assert due["receipts"][0]["receipt_sha256"] == receipt["receipt_sha256"]
    assert due["receipts_deleted"] is False
    purged = _ok(
        client.post(
            f"{API}/retention/purge",
            json={"before": cutoff, "limit": 100},
        )
    )
    assert purged == {
        "scan_observations_deleted": 1,
        "access_events_deleted": 1,
        "receipts_deleted": 0,
    }
    assert _ok(client.get(f"{API}/summary"))["receipts"] == 1
    assert _ok(client.get(f"{API}/scans/scan-retention"))["observations"] == []
    assert _ok(
        client.get(f"{API}/profiles/profile-001/access-log")
    )["events"] == []


def test_request_and_read_bounds_fail_closed_without_partial_writes() -> None:
    _publish_policy()
    _create_profile()
    too_many_choices = _preference_body()
    too_many_choices["choices"] = [
        {
            "purpose_id": f"purpose-{number}",
            "action": "deny",
            "channel": "all",
            "vendor_id": "all",
        }
        for number in range(129)
    ]
    response = client.post(
        f"{API}/profiles/profile-001/preferences", json=too_many_choices
    )
    assert response.status_code == 422
    assert _ok(client.get(f"{API}/summary"))["receipts"] == 0

    assert client.get(f"{API}/profiles", params={"limit": 0}).status_code == 422
    assert client.get(f"{API}/profiles", params={"limit": 501}).status_code == 422
    assert client.get(
        f"{API}/profiles/profile-001/export",
        params={"access_purpose": "bounded-test", "receipt_limit": 501},
    ).status_code == 422
    assert client.get(
        f"{API}/profiles/profile-001/access-log", params={"limit": 501}
    ).status_code == 422
    assert client.get(
        f"{API}/sync/destination", params={"limit": 501}
    ).status_code == 422

    tracker_body = {
        "kind": "web_tracker",
        "vendor_id": "all",
        "purpose_ids": ["analytics"],
        "status": "approved",
        "expected_revision": 0,
        "idempotency_key": "tracker-bounds",
    }
    _ok(client.put(f"{API}/trackers/tracker-bounds", json=tracker_body))
    too_many_observations = {
        "scan_id": "scan-too-large",
        "observations": [
            {
                "asset_ref": f"asset-{number}",
                "tracker_id": "tracker-bounds",
                "location_ref": "head",
                "evidence_sha256": DIGEST_C,
            }
            for number in range(513)
        ],
        "observed_at": time.time(),
        "source_sha256": DIGEST_D,
        "idempotency_key": "scan-too-large",
    }
    assert client.post(f"{API}/scans", json=too_many_observations).status_code == 422
    assert _ok(client.get(f"{API}/scans/scan-too-large"))["observations"] == []


def test_cross_tenant_reads_writes_and_outbox_are_isolated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _publish_policy()
    profile_a = _create_profile()
    tenant_a_summary = _ok(client.get(f"{API}/summary"))
    assert tenant_a_summary["profiles"] == 1

    monkeypatch.setenv("MAVERICK_TENANT", "tenant-b")
    tenant_b_summary = _ok(client.get(f"{API}/summary"))
    assert tenant_b_summary["profiles"] == 0
    assert tenant_b_summary["policies"] == 0
    assert _ok(client.get(f"{API}/profiles"))["profiles"] == []
    assert _ok(client.get(f"{API}/sync/app-east"))["events"] == []
    assert client.get(
        f"{API}/profiles/profile-001/export",
        params={"access_purpose": "cross-tenant-probe"},
    ).status_code == 404

    profile_b = _create_profile(subject_sha256=DIGEST_D)
    assert profile_b["profile_id"] == profile_a["profile_id"]
    assert _ok(client.get(f"{API}/summary"))["profiles"] == 1

    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    assert _ok(client.get(f"{API}/summary")) == tenant_a_summary
    assert _ok(client.get(f"{API}/profiles"))["profiles"] == [profile_a]


def test_people_paging_and_lookup_bind_the_current_workspace(monkeypatch: pytest.MonkeyPatch) -> None:
    _create_profile(profile_id="person-1", idempotency_key="person-1")
    _create_profile(profile_id="person-2", subject_sha256=DIGEST_C, idempotency_key="person-2")
    first = _ok(client.get(f"{API}/profiles", params={"limit": 1}))
    assert first["next_after"] == "person-1"
    headers = {"X-Lightwork-Profile-Context": first["context"]}
    assert client.get(f"{API}/profiles", params={"after": "person-1"}).status_code == 409
    following = _ok(client.get(f"{API}/profiles", params={"after": "person-1"}, headers=headers))
    assert [row["profile_id"] for row in following["profiles"]] == ["person-2"]
    result = _ok(client.post(f"{API}/profiles/lookup", json={"profile_ids": ["person-2", "unavailable"]}, headers=headers))
    assert result["missing"] == ["unavailable"]
    assert "subject_sha256" not in result["profiles"][0]
    assert client.post(f"{API}/profiles/lookup", json={"profile_ids": ["person-2"] * 2}).status_code == 422
    assert client.post(f"{API}/profiles/lookup", json={"profile_ids": [f"person-{number}" for number in range(101)]}).status_code == 422
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-b")
    assert client.get(f"{API}/profiles", headers=headers).status_code == 409
    assert client.post(f"{API}/profiles/lookup", json={"profile_ids": ["person-2"]}, headers=headers).status_code == 409
    assert _ok(client.post(f"{API}/profiles/lookup", json={"profile_ids": ["person-2"]}))["missing"] == ["person-2"]


def test_consent_analytics_is_independently_gated_and_cohort_suppressed(
    _isolated_consent_plane: Path,
) -> None:
    from maverick import config

    query = {
        "start_at": time.time() - 3_600,
        "end_at": time.time() + 3_600,
        "dimensions": ["purpose_id", "action"],
        "min_cohort_size": 2,
    }
    disabled = client.post(f"{API}/analytics/snapshot", json=query)
    assert disabled.status_code == 403
    assert "analytics is disabled" in disabled.json()["detail"]

    _isolated_consent_plane.write_text(
        "[consent_preferences]\n"
        "enable = true\n"
        "[consent_preferences.analytics]\n"
        "enable = true\n"
        "min_cohort_size = 2\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    _publish_policy()
    for number, digest in ((1, DIGEST_B), (2, DIGEST_C)):
        profile_id = f"profile-{number}"
        _create_profile(
            profile_id=profile_id,
            subject_sha256=digest,
            idempotency_key=f"create-{number}",
        )
        _ok(
            client.post(
                f"{API}/profiles/{profile_id}/preferences",
                json=_preference_body(idempotency_key=f"preference-{number}"),
            ),
            201,
        )

    report = _ok(client.post(f"{API}/analytics/snapshot", json=query))
    assert report["complete"] is True
    assert report["source_profile_count"] == 2
    assert report["source_receipt_count"] == 2
    assert report["cells"] == [
        {
            "dimensions": {"purpose_id": "analytics", "action": "grant"},
            "unique_profiles": 2,
            "receipt_events": 2,
            "choice_events": 2,
        }
    ]
    serialized = str(report)
    assert "profile-1" not in serialized
    assert "profile-2" not in serialized
    assert "subject_sha256" not in serialized

    suppressed = dict(query)
    suppressed["min_cohort_size"] = 3
    hidden = _ok(client.post(f"{API}/analytics/snapshot", json=suppressed))
    assert hidden["cells"] == []
    assert hidden["source_profile_count"] is None
    assert hidden["source_receipt_count"] is None

    duplicate = dict(query)
    duplicate["dimensions"] = ["action", "action"]
    assert client.post(
        f"{API}/analytics/snapshot", json=duplicate
    ).status_code == 422
