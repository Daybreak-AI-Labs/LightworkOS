from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict
from pathlib import Path

import pytest
from maverick import config
from maverick.consent_analytics import (
    ConsentAnalytics,
    ConsentAnalyticsConfigError,
    ConsentAnalyticsUnavailable,
    ConsentAnalyticsValidationError,
    enabled,
    require_enabled,
)
from maverick.consent_preferences import (
    ConsentContext,
    ConsentPreferenceStore,
    PreferenceChoice,
)

NOW = 1_800_000_000.0


class Clock:
    def __init__(self) -> None:
        self.value = NOW

    def __call__(self) -> float:
        self.value += 1
        return self.value


class IdFactory:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self, prefix: str) -> str:
        self.value += 1
        return f"{prefix}-{self.value:08d}"


@pytest.fixture(autouse=True)
def analytics_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "config_source_errors", lambda **_kwargs: {})
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "consent_preferences": {
                "enable": True,
                "analytics": {"enable": True},
            }
        },
    )


@pytest.fixture
def authority(tmp_path: Path) -> tuple[ConsentPreferenceStore, ConsentAnalytics]:
    path = tmp_path / "consent.sqlite3"
    store = ConsentPreferenceStore(path, clock=Clock(), id_factory=IdFactory())
    return store, ConsentAnalytics(path)


def _context(region: str = "US-CA") -> ConsentContext:
    return ConsentContext(
        jurisdiction="us-state-ca",
        country_code="US",
        region_code=region,
        collection_point="privacy-center",
        asserted_source="client",
    )


def _seed_profile(
    store: ConsentPreferenceStore,
    number: int,
    *,
    tenant: str = "tenant-a",
    action: str = "grant",
) -> None:
    profile_id = f"profile-{number}"
    store.create_profile(
        tenant,
        profile_id,
        "known",
        hashlib.sha256(f"subject-{tenant}-{number}".encode()).hexdigest(),
        f"profile-create-{number}",
    )
    store.record_preferences(
        tenant,
        profile_id,
        "privacy-notice",
        1,
        _context(),
        [PreferenceChoice("analytics", action)],
        expected_revision=0,
        idempotency_key=f"preference-{number}",
        actor_sha256="c" * 64,
    )


def _seed_policy(store: ConsentPreferenceStore, tenant: str = "tenant-a") -> None:
    store.publish_policy(
        tenant,
        "privacy-notice",
        1,
        {"analytics": "consent"},
        "a" * 64,
        NOW - 10,
        expected_current_version=0,
    )


def test_enabled_requires_independent_analytics_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert enabled() is True
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {"consent_preferences": {"enable": True}},
    )
    assert enabled() is False
    with pytest.raises(ConsentAnalyticsConfigError):
        require_enabled()
    monkeypatch.setattr(config, "config_source_errors", lambda: ["invalid"])
    assert enabled() is False


def test_snapshot_uses_canonical_unicode_tenant_identity(
    authority: tuple[ConsentPreferenceStore, ConsentAnalytics],
) -> None:
    store, analytics = authority
    decomposed = "Acme Cafe\u0301 Corp"
    canonical = "Acme Caf\u00e9 Corp"
    _seed_policy(store, decomposed)
    _seed_profile(store, 1, tenant=decomposed)
    _seed_profile(store, 2, tenant=decomposed)

    report = analytics.snapshot(
        canonical,
        NOW - 100,
        NOW + 100,
        ["purpose_id"],
        min_cohort_size=2,
    )

    assert report.tenant_sha256 == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert report.source_profile_count == 2
    assert report.source_receipt_count == 2


def test_snapshot_aggregates_unique_profiles_and_suppresses_small_cells(
    authority: tuple[ConsentPreferenceStore, ConsentAnalytics],
) -> None:
    store, analytics = authority
    _seed_policy(store)
    _seed_profile(store, 1)
    _seed_profile(store, 2)
    _seed_profile(store, 3, action="deny")

    report = analytics.snapshot(
        "tenant-a",
        NOW - 100,
        NOW + 100,
        ["purpose_id", "action", "country_code"],
        min_cohort_size=2,
    )

    assert report.complete is True
    assert report.source_profile_count == 3
    assert report.source_receipt_count == 3
    assert report.suppressed_cells == 1
    assert len(report.cells) == 1
    cell = report.cells[0]
    assert cell.dimensions == {
        "purpose_id": "analytics",
        "action": "grant",
        "country_code": "US",
    }
    assert cell.unique_profiles == cell.receipt_events == cell.choice_events == 2
    assert "event trends do not represent current preference state" in report.limitations

    serialized = json.dumps(asdict(report), sort_keys=True)
    assert "profile-1" not in serialized
    assert "profile-2" not in serialized
    assert "subject-" not in serialized


def test_snapshot_digest_binds_the_exact_privacy_bounded_result(
    authority: tuple[ConsentPreferenceStore, ConsentAnalytics],
) -> None:
    store, analytics = authority
    _seed_policy(store)
    _seed_profile(store, 1)
    _seed_profile(store, 2)
    report = analytics.snapshot(
        "tenant-a",
        NOW - 100,
        NOW + 100,
        ["day"],
        min_cohort_size=2,
    )

    body = asdict(report)
    digest = body.pop("snapshot_sha256")
    assert hashlib.sha256(
        json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest() == digest


def test_entire_result_hides_counts_below_global_threshold(
    authority: tuple[ConsentPreferenceStore, ConsentAnalytics],
) -> None:
    store, analytics = authority
    _seed_policy(store)
    _seed_profile(store, 1)

    report = analytics.snapshot(
        "tenant-a",
        NOW - 100,
        NOW + 100,
        ["action"],
        min_cohort_size=2,
    )

    assert report.cells == ()
    assert report.source_profile_count is None
    assert report.source_receipt_count is None
    assert "entire result suppressed" in report.limitations[-1]


def test_source_and_result_bounds_are_explicit_not_clean_claims(
    authority: tuple[ConsentPreferenceStore, ConsentAnalytics],
) -> None:
    store, analytics = authority
    _seed_policy(store)
    for number in range(1, 4):
        _seed_profile(store, number)
    _seed_profile(store, 4, action="deny")
    _seed_profile(store, 5, action="deny")

    source_limited = analytics.snapshot(
        "tenant-a",
        NOW - 100,
        NOW + 100,
        ["action"],
        min_cohort_size=2,
        max_receipts=2,
    )
    assert source_limited.source_truncated is True
    assert source_limited.complete is False
    assert any("source receipt limit" in item for item in source_limited.limitations)

    row_limited = analytics.snapshot(
        "tenant-a",
        NOW - 100,
        NOW + 100,
        ["action"],
        min_cohort_size=2,
        max_rows=1,
    )
    assert row_limited.complete is False
    assert len(row_limited.cells) == 1
    assert any("result row limit" in item for item in row_limited.limitations)


def test_tenant_filter_prevents_cross_tenant_aggregation(
    authority: tuple[ConsentPreferenceStore, ConsentAnalytics],
) -> None:
    store, analytics = authority
    _seed_policy(store, "tenant-a")
    _seed_policy(store, "tenant-b")
    _seed_profile(store, 1, tenant="tenant-a")
    _seed_profile(store, 2, tenant="tenant-a")
    _seed_profile(store, 1, tenant="tenant-b")

    tenant_a = analytics.snapshot(
        "tenant-a",
        NOW - 100,
        NOW + 100,
        ["action"],
        min_cohort_size=2,
    )
    tenant_b = analytics.snapshot(
        "tenant-b",
        NOW - 100,
        NOW + 100,
        ["action"],
        min_cohort_size=2,
    )
    assert tenant_a.source_profile_count == 2
    assert tenant_b.source_profile_count is None
    assert tenant_b.cells == ()


def test_corrupt_receipt_authority_fails_closed_without_partial_results(
    authority: tuple[ConsentPreferenceStore, ConsentAnalytics],
) -> None:
    store, analytics = authority
    _seed_policy(store)
    _seed_profile(store, 1)
    with sqlite3.connect(store.path) as conn:
        conn.execute("DROP TRIGGER consent_receipts_no_update")
        conn.execute("UPDATE consent_receipts SET choices_json = 'not-json'")

    with pytest.raises(ConsentAnalyticsUnavailable, match="stored receipt choices"):
        analytics.snapshot(
            "tenant-a",
            NOW - 100,
            NOW + 100,
            ["action"],
            min_cohort_size=2,
        )


def test_missing_authority_and_invalid_queries_fail_closed(tmp_path: Path) -> None:
    analytics = ConsentAnalytics(tmp_path / "missing.sqlite3")
    with pytest.raises(ConsentAnalyticsUnavailable, match="unavailable"):
        analytics.snapshot(
            "tenant-a", NOW - 100, NOW + 100, ["action"], min_cohort_size=2
        )
    assert not analytics.path.exists()

    with pytest.raises(ConsentAnalyticsValidationError, match="later"):
        analytics.snapshot(
            "tenant-a", NOW, NOW, ["action"], min_cohort_size=2
        )
    with pytest.raises(ConsentAnalyticsValidationError, match="unsupported"):
        analytics.snapshot(
            "tenant-a", NOW, NOW + 1, ["profile_id"], min_cohort_size=2
        )
    with pytest.raises(ConsentAnalyticsValidationError, match="unique"):
        analytics.snapshot(
            "tenant-a", NOW, NOW + 1, ["action", "action"], min_cohort_size=2
        )
    with pytest.raises(ConsentAnalyticsValidationError, match="between"):
        analytics.snapshot(
            "tenant-a", NOW, NOW + 1, ["action"], min_cohort_size=1
        )


def test_installation_cohort_floor_and_look_back_limit(
    authority: tuple[ConsentPreferenceStore, ConsentAnalytics],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import time as time_module

    from maverick.consent_analytics import analytics_limits

    assert analytics_limits() == (10, 2, None)
    settings = {"enable": True, "min_cohort_size": 25, "retention_days": 30}
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {"consent_preferences": {"enable": True, "analytics": settings}},
    )
    assert analytics_limits() == (25, 25, 30)
    _store, analytics = authority
    now = time_module.time()
    snapshot = analytics.snapshot("tenant-a", now - 90 * 86_400, now, ["purpose_id"],
                                  min_cohort_size=2)
    # A request can never go below the installation's smallest cohort, and
    # the period starts no earlier than the look-back limit allows.
    assert snapshot.min_cohort_size == 25
    assert snapshot.start_at >= now - 30 * 86_400 - 5
    assert any("look-back" in item for item in snapshot.limitations)
    with pytest.raises(ConsentAnalyticsValidationError, match="look-back"):
        analytics.snapshot("tenant-a", now - 90 * 86_400, now - 60 * 86_400, ["purpose_id"])
    settings["min_cohort_size"] = 1
    with pytest.raises(ConsentAnalyticsConfigError):
        analytics_limits()
