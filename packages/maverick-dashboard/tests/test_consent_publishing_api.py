"""HTTP contracts for consent experience publishing and rollback."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
API = "/api/v1/consent/publishing"
DIGEST = "a" * 64


@pytest.fixture(autouse=True)
def isolated_publishing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer

    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[consent_preferences]\n"
        "enable = true\n"
        "[consent_preferences.publishing]\n"
        "enable = true\n"
        "require_signed_publications = true\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    # require_signed_publications is on: every publish here is signed.
    monkeypatch.setenv("MAVERICK_CONSENT_PUBLICATION_SIGNING_KEY", "hex:" + "5a" * 32)
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


def _version(**values) -> dict:
    return {
        "version": 1,
        "expected_current_version": 0,
        "idempotency_key": values.pop("idempotency_key"),
        **values,
    }


def _property() -> dict:
    return _ok(
        client.put(
            f"{API}/properties/web-main",
            json={
                "kind": "web",
                "consent_group_id": "consumer-global",
                "expected_revision": 0,
                "idempotency_key": "property-create",
                "web_domains": ["example.test"],
                "origin_allowlist": ["https://www.example.test"],
            },
        )
    )


def _content() -> None:
    _ok(
        client.post(
            f"{API}/purposes/analytics/versions",
            json=_version(
                idempotency_key="purpose-1",
                title_key="purpose.title",
                description_key="purpose.description",
                lawful_basis="consent",
                required=False,
                default_choice="denied",
            ),
        ),
        201,
    )
    _ok(
        client.post(
            f"{API}/topics/product-email/versions",
            json=_version(
                idempotency_key="topic-1",
                purpose_id="analytics",
                purpose_version=1,
                title_key="topic.title",
                description_key="topic.description",
                default_choice="denied",
            ),
        ),
        201,
    )
    _ok(
        client.post(
            f"{API}/custom-preferences/personalization/versions",
            json=_version(
                idempotency_key="custom-1",
                title_key="preference.title",
                description_key="preference.description",
                value_type="boolean",
                option_ids=[],
                required=False,
            ),
        ),
        201,
    )
    _ok(
        client.post(
            f"{API}/notices/privacy-notice/versions",
            json=_version(
                idempotency_key="notice-1",
                title_key="notice.title",
                body_key="notice.body",
                document_sha256=DIGEST,
            ),
        ),
        201,
    )
    messages = {
        "purpose.title": "Analytics",
        "purpose.description": "Measure service performance",
        "topic.title": "Product email",
        "topic.description": "Choose product updates",
        "preference.title": "Personalization",
        "preference.description": "Personalize the experience",
        "notice.title": "Your choices",
        "notice.body": "Choose how data is used.",
        "template.title": "Privacy choices",
        "template.body": "Control your preferences.",
        "action.accept": "Accept all",
        "action.reject": "Reject all",
        "action.manage": "Manage preferences",
        "action.save": "Save choices",
        "brand.display_name": "Example",
        "brand.heading": "Example Privacy Trust Center",
        "brand.description": "Manage your choices and volunteered data.",
    }
    _ok(
        client.post(
            f"{API}/translations/consumer-copy/en-US/versions",
            json=_version(
                idempotency_key="translation-1",
                messages=messages,
            ),
        ),
        201,
    )
    _ok(
        client.post(
            f"{API}/themes/brand-default/versions",
            json=_version(
                idempotency_key="theme-1",
                display_name_key="brand.display_name",
                heading_key="brand.heading",
                description_key="brand.description",
                primary_color="174b3f",
                primary_text_color="ffffff",
                surface_color="ffffff",
                text_color="16211d",
            ),
        ),
        201,
    )
    _ok(
        client.post(
            f"{API}/templates/standard-banner/versions",
            json=_version(
                idempotency_key="template-1",
                surface="banner",
                title_key="template.title",
                body_key="template.body",
                actions={
                    "accept_all": "action.accept",
                    "reject_all": "action.reject",
                    "manage_preferences": "action.manage",
                    "save_preferences": "action.save",
                },
                theme_token_id="brand-default",
                theme_token_version=1,
            ),
        ),
        201,
    )
    rule = {
        "rule_id": "global",
        "priority": 1,
        "jurisdictions": [],
        "country_codes": [],
        "region_codes": [],
        "locales": ["en-US"],
        "default_locale": "en-US",
        "consent_mode": "opt_in",
        "purposes": [{"id": "analytics", "version": 1}],
        "topics": [{"id": "product-email", "version": 1}],
        "custom_preferences": [{"id": "personalization", "version": 1}],
        "notice": {"id": "privacy-notice", "version": 1},
        "template": {"id": "standard-banner", "version": 1},
        "translation_catalog_id": "consumer-copy",
        "translation_versions": {"en-US": 1},
    }
    _ok(
        client.post(
            f"{API}/rule-groups/production/versions",
            json=_version(idempotency_key="rules-1", rules=[rule]),
        ),
        201,
    )


def test_publishing_is_independently_default_off(isolated_publishing: Path) -> None:
    from maverick import config

    isolated_publishing.write_text(
        "[consent_preferences]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()

    response = client.put(
        f"{API}/properties/web-main",
        json={
            "kind": "web",
            "consent_group_id": "consumer-global",
            "expected_revision": 0,
            "idempotency_key": "property-create",
            "web_domains": ["example.test"],
            "origin_allowlist": ["https://www.example.test"],
        },
    )
    assert response.status_code == 403
    assert "publishing is disabled" in response.json()["detail"]


def test_full_preview_publish_history_and_rollback_lifecycle() -> None:
    property_record = _property()
    assert property_record["revision"] == 1
    _content()

    preview = _ok(
        client.post(
            f"{API}/properties/web-main/preview",
            json={"rule_group_id": "production", "rule_group_version": 1},
        )
    )
    assert len(preview["bundle_sha256"]) == 64
    assert preview["bundle"]["property"]["record_sha256"] == (property_record["record_sha256"])
    assert any(item["resource_kind"] == "theme" for item in preview["bundle"]["resources"])

    publication = _ok(
        client.post(
            f"{API}/properties/web-main/publish",
            json={
                "rule_group_id": "production",
                "rule_group_version": 1,
                "expected_property_revision": 1,
                "expected_publication_revision": 0,
                "idempotency_key": "publish-1",
            },
        ),
        201,
    )
    assert publication["publication_revision"] == 1
    assert publication["action"] == "publish"
    assert (
        _ok(
            client.post(
                f"{API}/properties/web-main/publish",
                json={
                    "rule_group_id": "production",
                    "rule_group_version": 1,
                    "expected_property_revision": 1,
                    "expected_publication_revision": 0,
                    "idempotency_key": "publish-1",
                },
            ),
            201,
        )
        == publication
    )

    rollback = _ok(
        client.post(
            f"{API}/properties/web-main/rollback",
            json={
                "target_publication_id": publication["publication_id"],
                "expected_property_revision": 1,
                "expected_publication_revision": 1,
                "idempotency_key": "rollback-1",
            },
        ),
        201,
    )
    assert rollback["publication_revision"] == 2
    assert rollback["action"] == "rollback"
    assert rollback["source_publication_id"] == publication["publication_id"]

    history = _ok(client.get(f"{API}/properties/web-main/history"))
    assert history["truncated"] is False
    assert [item["publication_revision"] for item in history["items"]] == [2, 1]


def test_http_boundary_rejects_cas_rebinding_executable_text_and_unknown_fields() -> None:
    _property()
    stale = client.put(
        f"{API}/properties/web-main",
        json={
            "kind": "web",
            "consent_group_id": "different-group",
            "expected_revision": 0,
            "idempotency_key": "property-stale",
            "web_domains": ["example.test"],
            "origin_allowlist": ["https://www.example.test"],
        },
    )
    assert stale.status_code == 409

    executable = client.post(
        f"{API}/translations/consumer-copy/en-US/versions",
        json=_version(
            idempotency_key="translation-executable",
            messages={"notice.body": "javascript:alert(1)"},
        ),
    )
    assert executable.status_code == 422

    low_contrast = client.post(
        f"{API}/themes/unsafe/versions",
        json=_version(
            idempotency_key="theme-low-contrast",
            display_name_key="brand.display_name",
            heading_key="brand.heading",
            description_key="brand.description",
            primary_color="ffffff",
            primary_text_color="eeeeee",
            surface_color="ffffff",
            text_color="16211d",
        ),
    )
    assert low_contrast.status_code == 422
    assert "4.5:1 contrast" in low_contrast.json()["detail"]

    unknown = client.post(
        f"{API}/purposes/analytics/versions",
        json={
            **_version(
                idempotency_key="purpose-unknown",
                title_key="purpose.title",
                description_key="purpose.description",
                lawful_basis="consent",
                required=False,
                default_choice="denied",
            ),
            "tenant_id": "tenant-b",
        },
    )
    assert unknown.status_code == 422


def test_publishing_authority_is_strictly_tenant_isolated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _property()
    _content()
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-b")

    assert client.get(f"{API}/properties/web-main/history").status_code == 404
    tenant_b = _property()
    assert tenant_b["property_id"] == "web-main"
    assert tenant_b["revision"] == 1

    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    preview = _ok(
        client.post(
            f"{API}/properties/web-main/preview",
            json={"rule_group_id": "production", "rule_group_version": 1},
        )
    )
    assert preview["bundle"]["property"]["property_id"] == "web-main"


def test_withdraw_route_is_strict_cas_idempotent_and_publicly_denying() -> None:
    _property()
    _content()
    published = _ok(
        client.post(
            f"{API}/properties/web-main/publish",
            json={
                "rule_group_id": "production",
                "rule_group_version": 1,
                "expected_property_revision": 1,
                "expected_publication_revision": 0,
                "idempotency_key": "publish-before-api-withdraw",
            },
        ),
        201,
    )
    payload = {
        "expected_property_revision": 1,
        "expected_publication_revision": 1,
        "idempotency_key": "api-withdraw-once",
    }
    withdrawn = _ok(
        client.post(f"{API}/properties/web-main/withdraw", json=payload),
        201,
    )
    assert withdrawn["action"] == "withdraw"
    assert withdrawn["publication_revision"] == 2
    assert withdrawn["source_publication_id"] == published["publication_id"]
    assert (
        _ok(
            client.post(f"{API}/properties/web-main/withdraw", json=payload),
            201,
        )
        == withdrawn
    )
    assert (
        _ok(
            client.post(
                f"{API}/properties/web-main/withdraw",
                json={
                    **payload,
                    "expected_publication_revision": 2,
                    "idempotency_key": "api-withdraw-no-change",
                },
            ),
            201,
        )
        == withdrawn
    )
    stale = client.post(
        f"{API}/properties/web-main/withdraw",
        json={**payload, "idempotency_key": "api-withdraw-stale"},
    )
    assert stale.status_code == 409

    history = _ok(client.get(f"{API}/properties/web-main/history"))
    assert [item["action"] for item in history["items"]] == ["withdraw", "publish"]
    from maverick_dashboard import consent_publishing_api

    _ops, tenant, store = consent_publishing_api._authority()
    resolved = store.resolve_public_configuration(
        tenant,
        "web-main",
        server_origin="https://www.example.test",
        requested_locale="en-US",
    )
    assert resolved["allowed"] is False
    assert resolved["reason"] == "withdrawn"


@pytest.mark.parametrize(
    "forbidden",
    (
        "tenant_id",
        "actor_ref",
        "source_publication_id",
        "target_publication_id",
        "bundle",
        "content",
        "key_ref",
    ),
)
def test_withdraw_route_forbids_all_caller_selected_authority(forbidden: str) -> None:
    response = client.post(
        f"{API}/properties/web-main/withdraw",
        json={
            "expected_property_revision": 1,
            "expected_publication_revision": 1,
            "idempotency_key": "withdraw-extra-forbidden",
            forbidden: "caller-selected",
        },
    )
    assert response.status_code == 422


def test_withdraw_route_requires_global_admin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maverick_dashboard import consent_publishing_api

    permissions: list[str] = []

    def deny(_request, permission: str) -> None:
        permissions.append(permission)
        raise HTTPException(status_code=403, detail="admin required")

    monkeypatch.setattr(consent_publishing_api, "require_global_permission", deny)
    response = client.post(
        f"{API}/properties/web-main/withdraw",
        json={
            "expected_property_revision": 1,
            "expected_publication_revision": 1,
            "idempotency_key": "withdraw-without-admin",
        },
    )
    assert response.status_code == 403
    assert permissions == ["admin"]

def test_catalog_search_and_versions_are_tenant_scoped_even_in_a_shared_database(tmp_path, monkeypatch):
    from maverick import consent_publishing
    from maverick_dashboard import consent_publishing_api
    shared = consent_publishing.ConsentPublishingStore(tmp_path / "shared.sqlite3")
    monkeypatch.setattr(consent_publishing_api, "_store", lambda ops, tenant: shared)
    _property()
    _content()
    listing = _ok(client.get(API + "/catalog/purposes?q=ANALYT"))
    assert listing["total"] == 1 and listing["items"][0]["resource_id"] == "analytics"
    assert "payload" not in listing["items"][0]
    version = _ok(client.get(API + "/catalog/purposes/analytics/versions/1"))
    assert version["payload"]["title_key"] == "purpose.title"
    assert _ok(client.get(API + "/catalog/properties"))["items"][0]["revision"] == 1
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-b")
    assert _ok(client.get(API + "/catalog/purposes"))["items"] == []
    assert _ok(client.get(API + "/catalog/properties"))["items"] == []
    assert client.get(API + "/catalog/purposes/analytics/versions/1").status_code == 404


def test_catalog_pagination_exposes_each_exact_version():
    _content()
    _ok(client.post(API + "/purposes/analytics/versions", json={
        "version": 2, "expected_current_version": 1, "idempotency_key": "purpose-second",
        "title_key": "purpose.title", "description_key": "purpose.description",
        "lawful_basis": "consent", "required": False, "default_choice": "denied",
    }), 201)
    latest = _ok(client.get(API + "/catalog/purposes"))
    assert [item["version"] for item in latest["items"]] == [2]
    first = _ok(client.get(API + "/catalog/purposes?resource_id=analytics&limit=1"))
    assert first["total"] == 2 and first["next_offset"] == 1
    second = _ok(client.get(API + "/catalog/purposes?resource_id=analytics&limit=1&offset=1"))
    assert second["items"][0]["version"] == 1 and second["next_offset"] is None
    assert client.get(API + "/catalog/purposes?limit=51").status_code == 422
    assert client.get(API + "/catalog/purposes/analytics/versions/0").status_code == 422

def test_catalog_stale_workspace_and_permission_denials_happen_before_record_queries(monkeypatch):
    from maverick_dashboard import consent_publishing_api
    _property()
    mismatch = client.get(API + "/catalog/properties", headers={"X-Lightwork-Expected-Tenant": "tenant-b"})
    assert mismatch.status_code == 409
    def deny(request, permission):
        assert permission == "operate"
        raise HTTPException(status_code=403, detail="not permitted")
    monkeypatch.setattr(consent_publishing_api, "require_permission", deny)
    monkeypatch.setattr(consent_publishing_api, "_authority", lambda: pytest.fail("authority read before permission check"))
    assert client.get(API + "/catalog/properties").status_code == 403
