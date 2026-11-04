from __future__ import annotations

from maverick.config_lint import lint_config


def _messages(config: dict) -> list[str]:
    return [finding.message for finding in lint_config(config)]


def test_document_access_and_incident_attachment_config_is_closed_and_valid() -> None:
    config = {
        "audit": {"sign": True},
        "administration_document_access": {
            "enable": True,
            "default_ttl_seconds": 300,
            "max_ttl_seconds": 900,
            "max_uses": 2,
            "delivery_grant_ttl_seconds": 60,
            "retention_seconds": 31_536_000,
        },
        "governed_document_vault": {
            "enable": True,
            "max_document_bytes": 26_214_400,
            "max_documents": 100_000,
            "retention_seconds": 31_536_000,
            "grant_ttl_seconds": 60,
            "claim_lease_seconds": 30,
            "stream_chunk_bytes": 65_536,
            "allowed_media_types": ["application/pdf", "image/png"],
        },
        "incident_attachment_metadata": {
            "enable": True,
            "retention_seconds": 31_536_000,
            "attachment_ttl_seconds": 604_800,
            "max_attachments": 100_000,
            "allowed_media_types": ["application/pdf", "image/png"],
        },
    }

    assert lint_config(config) == []


def test_document_access_requires_signed_audit_and_consistent_ttls() -> None:
    messages = _messages(
        {
            "administration_document_access": {
                "enable": True,
                "default_ttl_seconds": 901,
                "max_ttl_seconds": 900,
                "delivery_grant_ttl_seconds": 901,
            }
        }
    )

    assert any("requires audit.sign" in message for message in messages)
    assert any("default TTL cannot exceed" in message for message in messages)
    assert any("delivery grant TTL cannot exceed" in message for message in messages)


def test_incident_attachments_require_document_access_and_closed_media_types() -> None:
    messages = _messages(
        {
            "incident_attachment_metadata": {
                "enable": True,
                "allowed_media_types": ["application/pdf", "application/pdf"],
            }
        }
    )

    assert any("requires administration_document_access.enable" in message for message in messages)
    assert any("unique non-empty product allowlist" in message for message in messages)


def test_document_access_integer_bounds_and_unknown_keys_are_rejected() -> None:
    findings = lint_config(
        {
            "administration_document_access": {
                "enable": False,
                "max_uses": 11,
                "secret_path": "forbidden",
            },
            "incident_attachment_metadata": {
                "enable": False,
                "attachment_ttl_seconds": 59,
                "object_store_url": "https://forbidden.example",
            },
            "governed_document_vault": {
                "enable": False,
                "stream_chunk_bytes": 1_024,
                "allowed_media_types": ["application/pdf", "application/pdf"],
                "object_store_url": "https://forbidden.example",
            },
        }
    )
    messages = [finding.message for finding in findings]

    assert any("max_uses must be an integer between 1 and 10" in message for message in messages)
    assert any(
        "attachment_ttl_seconds must be an integer between 60" in message for message in messages
    )
    assert any('unknown key "secret_path"' in message for message in messages)
    assert any('unknown key "object_store_url"' in message for message in messages)
    assert any(
        "stream_chunk_bytes must be an integer between 4096" in message for message in messages
    )
    assert any("document vault media types must be a unique" in message for message in messages)


def test_governed_document_vault_requires_document_access() -> None:
    messages = _messages({"governed_document_vault": {"enable": True}})

    assert any("requires administration_document_access.enable" in message for message in messages)


def test_incident_media_types_must_be_a_subset_of_enabled_stock_vault() -> None:
    messages = _messages(
        {
            "audit": {"sign": True},
            "administration_document_access": {"enable": True},
            "governed_document_vault": {
                "enable": True,
                "allowed_media_types": ["application/pdf"],
            },
            "incident_attachment_metadata": {
                "enable": True,
                "allowed_media_types": ["application/pdf", "image/png"],
            },
        }
    )

    assert any("must be a subset" in message for message in messages)


def test_external_incident_resolver_does_not_require_vault_media_subset() -> None:
    messages = _messages(
        {
            "audit": {"sign": True},
            "administration_document_access": {"enable": True},
            "incident_attachment_metadata": {
                "enable": True,
                "allowed_media_types": ["image/webp"],
            },
        }
    )

    assert not any("must be a subset" in message for message in messages)
