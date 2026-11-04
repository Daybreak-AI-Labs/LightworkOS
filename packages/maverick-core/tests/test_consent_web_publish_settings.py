from __future__ import annotations

import contextlib
import gc
import sqlite3
from dataclasses import replace

import pytest
from maverick import consent_web_publish_settings as web


def _authority(**changes: object) -> web.WebsitePublishingAuthority:
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "property_id": "website-main",
        "property_kind": "web",
        "property_revision": 3,
        "property_sha256": "a" * 64,
        "publication_id": "publication-7",
        "publication_revision": 7,
        "publication_sha256": "b" * 64,
        "publication_bundle_sha256": "c" * 64,
        "publication_action": "publish",
        "publication_property_revision": 3,
    }
    values.update(changes)
    return web.WebsitePublishingAuthority(**values)  # type: ignore[arg-type]


def _settings(**changes: object) -> web.WebsitePublishSettings:
    values: dict[str, object] = {
        "sdk_version": "2.4.1",
        "geolocation_reconsent": (
            web.GeolocationReconsent("CA-QC", 180),
            web.GeolocationReconsent("US", 365),
        ),
        "analytics_tracking_enabled": True,
        "analytics_category_assignments": (
            web.AnalyticsCategoryAssignment("google_analytics", "analytics"),
        ),
        "common_trackers": ("google_analytics",),
        "cookie_same_site": "lax",
        "cookie_domain_separation": "host_only",
        "spa_reload_on_route_change": True,
        "csp_nonce_required": True,
        "automatic_refresh_seconds": 300,
    }
    values.update(changes)
    return web.WebsitePublishSettings(**values)  # type: ignore[arg-type]


class _Resolver:
    def __init__(self) -> None:
        self.current = _authority()
        self.calls: list[tuple[str, str]] = []

    def __call__(
        self, tenant_id: str, property_id: str
    ) -> web.WebsitePublishingAuthority:
        self.calls.append((tenant_id, property_id))
        return self.current


@pytest.fixture()
def fixture(tmp_path):
    resolver = _Resolver()
    clock = [1_700_000_000.0]
    store = web.WebPublishSettingsStore(
        tmp_path / "settings.sqlite3",
        tenant_id="tenant-a",
        publishing_authority_resolver=resolver,
        principal_resolver=lambda: "administrator-1",
        retention_seconds=60,
        clock=lambda: clock[0],
    )
    return store, resolver, clock


def test_exact_nested_gate_is_default_off_and_rejects_unknowns() -> None:
    assert web.WebPublishSettingsConfig.from_mapping({}).enable is False
    assert web.WebPublishSettingsConfig.from_mapping(
        {"consent_preferences": {"publishing": {"web_settings": {}}}}
    ).enable is False
    enabled = web.WebPublishSettingsConfig.from_mapping(
        {
            "consent_preferences": {
                "enable": True,
                "publishing": {
                    "enable": True,
                    "web_settings": {"enable": True, "retention_seconds": 60},
                },
            }
        }
    )
    assert enabled.enable is True
    with pytest.raises(web.WebPublishSettingsConfigError):
        web.WebPublishSettingsConfig.from_mapping(
            {
                "consent_preferences": {
                    "publishing": {"web_settings": {"enable": True}}
                }
            }
        )
    with pytest.raises(web.WebPublishSettingsConfigError):
        web.WebPublishSettingsConfig.from_mapping(
            {
                "consent_preferences": {
                    "enable": True,
                    "publishing": {
                        "enable": True,
                        "web_settings": {"enable": True, "surprise": True},
                    },
                }
            }
        )


def test_closed_settings_reject_nonce_values_and_inconsistent_trackers() -> None:
    mapping = _settings().as_mapping()
    mapping["csp_nonce"] = "must-never-be-stored"
    with pytest.raises(web.WebPublishSettingsValidationError):
        web.WebsitePublishSettings.from_mapping(mapping)
    with pytest.raises(web.WebPublishSettingsValidationError):
        _settings(
            analytics_category_assignments=(
                web.AnalyticsCategoryAssignment("meta_pixel", "advertising"),
            )
        )
    with pytest.raises(web.WebPublishSettingsValidationError):
        _settings(cookie_same_site="caller-defined")


def test_create_activate_and_public_projection_are_exact_and_sdk_safe(fixture) -> None:
    store, resolver, _clock = fixture
    created = store.create_version(
        property_id="website-main",
        settings=_settings(),
        expected_head_revision=0,
        idempotency_key="create:website-main:1",
    )
    assert created["head_revision"] == 1
    assert created["state"] == "draft"
    activated = store.activate_version(
        property_id="website-main",
        version_id=str(created["version_id"]),
        expected_head_revision=1,
        idempotency_key="activate:website-main:1",
    )
    assert activated["head_revision"] == 2
    projection = store.public_projection(property_id="website-main")
    assert projection["ready"] is True
    assert projection["browser_property_acceptance_verified"] is False
    assert projection["property"] == {"revision": 3, "sha256": "a" * 64}
    assert projection["publication"] == {
        "id": "publication-7",
        "revision": 7,
        "sha256": "b" * 64,
        "bundle_sha256": "c" * 64,
    }
    assert projection["settings"]["csp"] == {"nonce_required": True}  # type: ignore[index]
    assert "nonce" not in str(projection).replace("nonce_required", "")
    assert len(resolver.calls) >= 3


def test_authority_drift_is_visible_on_read_and_fails_public_ready(fixture) -> None:
    store, resolver, _clock = fixture
    created = store.create_version(
        property_id="website-main",
        settings=_settings(),
        expected_head_revision=0,
        idempotency_key="create:drift:1",
    )
    store.activate_version(
        property_id="website-main",
        version_id=str(created["version_id"]),
        expected_head_revision=1,
        idempotency_key="activate:drift:1",
    )
    resolver.current = replace(
        resolver.current,
        publication_revision=8,
        publication_sha256="d" * 64,
    )
    assert store.get_head(property_id="website-main").authority_current is False
    projection = store.public_projection(property_id="website-main")
    assert projection["ready"] is False
    assert projection["reason"] == "settings_authority_stale_or_inactive"
    with pytest.raises(web.WebPublishSettingsConflict):
        store.activate_version(
            property_id="website-main",
            version_id=str(created["version_id"]),
            expected_head_revision=2,
            idempotency_key="activate:drift:2",
        )


def test_new_version_rebinds_changed_publication_and_clears_stale_active(fixture) -> None:
    store, resolver, _clock = fixture
    first = store.create_version(
        property_id="website-main",
        settings=_settings(),
        expected_head_revision=0,
        idempotency_key="create:rebind:1",
    )
    store.activate_version(
        property_id="website-main",
        version_id=str(first["version_id"]),
        expected_head_revision=1,
        idempotency_key="activate:rebind:1",
    )
    resolver.current = replace(
        resolver.current,
        publication_revision=8,
        publication_sha256="d" * 64,
    )
    second = store.create_version(
        property_id="website-main",
        settings=_settings(sdk_version="2.5.0"),
        expected_head_revision=2,
        idempotency_key="create:rebind:2",
    )
    assert second["state"] == "draft"
    assert second["active_version_id"] is None
    assert store.get_version(
        property_id="website-main", version_id=str(second["version_id"])
    ).authority_current is True


def test_idempotency_replay_and_cas_conflicts_are_deterministic(fixture) -> None:
    store, _resolver, _clock = fixture
    first = store.create_version(
        property_id="website-main",
        settings=_settings(),
        expected_head_revision=0,
        idempotency_key="create:idempotent:1",
    )
    replay = store.create_version(
        property_id="website-main",
        settings=_settings(),
        expected_head_revision=0,
        idempotency_key="create:idempotent:1",
    )
    assert replay["version_id"] == first["version_id"]
    assert replay["idempotent_replay"] is True
    assert len(store.list_versions(property_id="website-main")) == 1
    with pytest.raises(web.WebPublishSettingsConflict):
        store.create_version(
            property_id="website-main",
            settings=_settings(sdk_version="9.0.0"),
            expected_head_revision=1,
            idempotency_key="create:idempotent:1",
        )
    with pytest.raises(web.WebPublishSettingsConflict):
        store.create_version(
            property_id="website-main",
            settings=_settings(),
            expected_head_revision=0,
            idempotency_key="create:cas:wrong",
        )


def test_rollback_and_withdrawal_change_only_the_cas_head(fixture) -> None:
    store, _resolver, _clock = fixture
    first = store.create_version(
        property_id="website-main",
        settings=_settings(sdk_version="1.0.0"),
        expected_head_revision=0,
        idempotency_key="create:lifecycle:1",
    )
    store.activate_version(
        property_id="website-main",
        version_id=str(first["version_id"]),
        expected_head_revision=1,
        idempotency_key="activate:lifecycle:1",
    )
    second = store.create_version(
        property_id="website-main",
        settings=_settings(sdk_version="2.0.0"),
        expected_head_revision=2,
        idempotency_key="create:lifecycle:2",
    )
    store.activate_version(
        property_id="website-main",
        version_id=str(second["version_id"]),
        expected_head_revision=3,
        idempotency_key="activate:lifecycle:2",
    )
    rolled = store.rollback(
        property_id="website-main",
        target_version_id=str(first["version_id"]),
        expected_head_revision=4,
        idempotency_key="rollback:lifecycle:1",
    )
    assert rolled["active_version_id"] == first["version_id"]
    withdrawn = store.withdraw(
        property_id="website-main",
        expected_head_revision=5,
        idempotency_key="withdraw:lifecycle:1",
    )
    assert withdrawn["state"] == "withdrawn"
    assert store.public_projection(property_id="website-main")["ready"] is False
    assert len(store.list_versions(property_id="website-main")) == 2


def test_publishing_withdrawal_makes_projection_explicitly_not_ready(fixture) -> None:
    store, resolver, _clock = fixture
    resolver.current = replace(resolver.current, publication_action="withdraw")
    projection = store.public_projection(property_id="website-main")
    assert projection == {
        "schema": web.PUBLIC_PROJECTION_SCHEMA,
        "enabled": True,
        "ready": False,
        "reason": "publication_withdrawn_or_stale",
        "property_id": "website-main",
        "browser_property_acceptance_verified": False,
    }
    with pytest.raises(web.WebPublishSettingsConflict):
        store.create_version(
            property_id="website-main",
            settings=_settings(),
            expected_head_revision=0,
            idempotency_key="create:withdrawn:1",
        )


def test_retention_purge_leaves_integrity_tombstone(fixture) -> None:
    store, _resolver, clock = fixture
    first = store.create_version(
        property_id="website-main",
        settings=_settings(sdk_version="1.0.0"),
        expected_head_revision=0,
        idempotency_key="create:retention:1",
    )
    second = store.create_version(
        property_id="website-main",
        settings=_settings(sdk_version="2.0.0"),
        expected_head_revision=1,
        idempotency_key="create:retention:2",
    )
    store.activate_version(
        property_id="website-main",
        version_id=str(second["version_id"]),
        expected_head_revision=2,
        idempotency_key="activate:retention:2",
    )
    clock[0] += 61
    purged = store.purge_version(
        property_id="website-main",
        version_id=str(first["version_id"]),
        expected_head_revision=3,
        idempotency_key="purge:retention:1",
    )
    assert purged["purged"] is True
    assert len(str(purged["tombstone_sha256"])) == 64
    with pytest.raises(web.WebPublishSettingsNotFound):
        store.get_version(
            property_id="website-main", version_id=str(first["version_id"])
        )
    assert store.verify_integrity()["tombstone_count"] == 1


def test_integrity_and_recovery_are_candid(fixture) -> None:
    store, _resolver, _clock = fixture
    store.create_version(
        property_id="website-main",
        settings=_settings(),
        expected_head_revision=0,
        idempotency_key="create:integrity:1",
    )
    integrity = store.verify_integrity()
    assert integrity["valid"] is True
    assert integrity["external_worm_anchor_verified"] is False
    recovery = store.recovery_status()
    assert recovery["ready"] is True
    assert recovery["external_backup_restore_verified"] is False
    assert recovery["browser_property_acceptance_verified"] is False


def test_tampered_immutable_version_is_detected(fixture) -> None:
    store, _resolver, _clock = fixture
    store.create_version(
        property_id="website-main",
        settings=_settings(),
        expected_head_revision=0,
        idempotency_key="create:tamper:1",
    )
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TRIGGER web_publish_settings_versions_immutable")
        connection.execute(
            "UPDATE web_publish_settings_versions SET settings_sha256=?",
            ("f" * 64,),
        )
    with pytest.raises(web.WebPublishSettingsIntegrityError):
        store.verify_integrity()


def _assert_closed(connections):
    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")


def test_every_settings_connection_is_closed_when_its_call_returns(tmp_path, monkeypatch) -> None:
    # CPython 3.12 keeps an unclosed sqlite3 connection alive until a cyclic GC pass,
    # so GC is disabled here: any connection left open by a call stays open.
    opened = []
    real_connect = sqlite3.connect
    fail_pragma = {"on": True}

    class _PragmaFails(sqlite3.Connection):
        def execute(self, sql, *args):
            if sql == "PRAGMA foreign_keys=ON" and fail_pragma["on"]:
                raise sqlite3.OperationalError("pragma failed")
            return super().execute(sql, *args)

    def recording_connect(*args, **kwargs):
        connection = real_connect(*args, factory=_PragmaFails, **kwargs)
        opened.append(connection)
        return connection

    def build():
        return web.WebPublishSettingsStore(
            tmp_path / "settings.sqlite3",
            tenant_id="tenant-a",
            publishing_authority_resolver=_Resolver(),
            principal_resolver=lambda: "administrator-1",
            retention_seconds=60,
            clock=lambda: 1_700_000_000.0,
        )

    monkeypatch.setattr(web.sqlite3, "connect", recording_connect)
    gc.disable()
    try:
        with pytest.raises(web.WebPublishSettingsError):
            build()
        fail_pragma["on"] = False
        before = len(opened)
        store = build()
        assert len(opened) > before, "__init__"
        _assert_closed(opened[before:])
        calls = [
            ("get_head", lambda: store.get_head(property_id="website-main")),
            # The lookup of a version that does not exist ends in an expected error.
            (
                "get_version",
                lambda: store.get_version(property_id="website-main", version_id="version-missing"),
            ),
            ("list_versions", lambda: store.list_versions(property_id="website-main")),
            ("public_projection", lambda: store.public_projection(property_id="website-main")),
            ("audit_history", store.audit_history),
            ("verify_integrity", store.verify_integrity),
            ("recovery_status", store.recovery_status),
        ]
        for name, call in calls:
            before = len(opened)
            with contextlib.suppress(web.WebPublishSettingsError):
                call()
            assert len(opened) > before, name
            _assert_closed(opened[before:])
    finally:
        gc.enable()
    _assert_closed(opened)


class _SharedSession:
    """Stands in for a shared Postgres session: it forwards to sqlite3 but is not one."""

    def __init__(self, inner):
        object.__setattr__(self, "_inner", inner)
        object.__setattr__(self, "closes", [])

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def __setattr__(self, name, value):
        setattr(self._inner, name, value)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return self._inner.__exit__(*exc)

    def close(self):
        self.closes.append(True)


class _SetupFailsSession(_SharedSession):
    def execute(self, sql, *args):
        if sql.startswith("PRAGMA"):
            raise sqlite3.OperationalError("pragma failed")
        return self._inner.execute(sql, *args)


def _shared_web_store(tmp_path):
    return web.WebPublishSettingsStore(
        tmp_path / "settings.sqlite3",
        tenant_id="tenant-a",
        publishing_authority_resolver=_Resolver(),
        principal_resolver=lambda: "administrator-1",
        retention_seconds=60,
        clock=lambda: 1_700_000_000.0,
    )


def test_shared_sessions_are_left_to_their_own_release(tmp_path, monkeypatch) -> None:
    # The store commits or rolls back a shared session; closing it stays with that session.
    store = _shared_web_store(tmp_path)
    sessions = []

    def shared_connect(path, *, timeout=10.0, **_):
        session = _SharedSession(sqlite3.connect(str(path), timeout=timeout, isolation_level=None))
        sessions.append(session)
        return session

    monkeypatch.setattr(web.consent_storage, "shared", lambda: True)
    monkeypatch.setattr(web.consent_storage, "connect", shared_connect)
    gc.disable()
    try:
        store.verify_integrity()
        assert sessions and all(session.closes == [] for session in sessions)
    finally:
        gc.enable()
        for session in sessions:
            session._inner.close()


def test_shared_setup_failure_is_left_to_the_session_owner(tmp_path, monkeypatch) -> None:
    store = _shared_web_store(tmp_path)
    sessions = []

    def shared_connect(path, *, timeout=10.0, **_):
        session = _SetupFailsSession(sqlite3.connect(str(path), timeout=timeout, isolation_level=None))
        sessions.append(session)
        return session

    monkeypatch.setattr(web.consent_storage, "shared", lambda: True)
    monkeypatch.setattr(web.consent_storage, "connect", shared_connect)
    gc.disable()
    try:
        with pytest.raises(web.WebPublishSettingsIntegrityError):
            store.verify_integrity()
        assert sessions and all(session.closes == [] for session in sessions)
    finally:
        gc.enable()
        for session in sessions:
            session._inner.close()
