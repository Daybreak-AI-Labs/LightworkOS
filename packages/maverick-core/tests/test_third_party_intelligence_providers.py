"""Closed provider contracts for third-party intelligence feeds."""

from __future__ import annotations

import hashlib

import pytest
from maverick import third_party_intelligence_providers as providers

TENANT = "tenant-feed-a"
NOW = 1_800_000_000.0


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def request(provider: str = "riskrecon") -> providers.ProviderRequest:
    return providers.ProviderRequest(
        tenant_id=TENANT,
        provider=provider,
        source_id="source-cyber",
        source_revision=2,
        source_integrity_sha256=digest("source"),
        kind="cyber_posture",
        capability="monitoring",
        key_id="provider-key-v1",
    )


def record(name: str) -> dict[str, object]:
    return {
        "record_id": name,
        "observation_sha256": digest(f"observation:{name}"),
        "evidence_sha256": digest(f"evidence:{name}"),
        "citation": {
            "citation_id": f"citation-{name}",
            "title": "Licensed provider evidence",
            "uri": "https://api.riskrecon.com/evidence",
            "pinpoint": name,
        },
    }


def page(
    query: dict[str, str],
    *,
    records: list[dict[str, object]],
    complete: bool = True,
    next_cursor: str | None = None,
    reasons: list[str] | None = None,
) -> dict[str, object]:
    return {
        "schema": "lightwork.riskrecon-observation-page.v1",
        "tenant_id": query["tenant_id"],
        "provider": query["provider"],
        "source_id": query["source_id"],
        "source_revision": int(query["source_revision"]),
        "source_integrity_sha256": query["source_integrity_sha256"],
        "capability": query["capability"],
        "key_id": query["key_id"],
        "kind": query["kind"],
        "dataset_revision": "dataset-v1",
        "observed_at": NOW - 10,
        "valid_until": NOW + 600,
        "complete": complete,
        "incomplete_reason_codes": reasons or [],
        "next_cursor": next_cursor,
        "records": records,
    }


class Transport:
    def __init__(self, responder=None) -> None:
        self.responder = responder
        self.calls: list[dict[str, object]] = []

    def get_json(self, **kwargs):
        self.calls.append(kwargs)
        query = dict(kwargs["query"])
        if self.responder is not None:
            return self.responder(query)
        return page(query, records=[record("one")])


def factory(transport: Transport) -> providers.ThirdPartyProviderFactory:
    return providers.ThirdPartyProviderFactory(
        transport=transport,
        enabled_providers=["riskrecon"],
    )


def test_named_provider_factory_is_closed_fixed_host_get_only() -> None:
    assert providers.available_provider_concepts() == (
        "generic_approved",
        "hacknotice",
        "iss_corporate_solutions",
        "riskrecon",
        "securityscorecard",
        "supplywisdom",
    )
    transport = Transport()
    adapter = factory(transport).create(
        "riskrecon",
        "https://api.riskrecon.com/licensed-feed",
    )
    secret = object()
    credential = providers.CredentialBinding("provider-key-v1", secret)
    result = adapter.collect(request(), credential)
    assert result.coverage_complete is True
    assert result.record_count == result.cursor_count == 1
    assert result.provider == "riskrecon"
    assert result.key_id_sha256 == digest("provider-key-v1")
    assert len(result.citations) == 1
    assert transport.calls == [
        {
            "host": "api.riskrecon.com",
            "path": "/api/v1/third-party-observations",
            "query": {
                "tenant_id": TENANT,
                "provider": "riskrecon",
                "source_id": "source-cyber",
                "source_revision": "2",
                "source_integrity_sha256": digest("source"),
                "capability": "monitoring",
                "key_id": "provider-key-v1",
                "kind": "cyber_posture",
            },
            "credential": secret,
            "maximum_response_bytes": 512 * 1024,
            "timeout_seconds": 20.0,
        }
    ]
    assert "secret" not in repr(result).lower()
    assert repr(secret) not in repr(credential)


def test_provider_request_accepts_canonical_unicode_tenant_only() -> None:
    value = providers.ProviderRequest(
        tenant_id="Acme Caf\u00e9 Group",
        provider="riskrecon",
        source_id="source-cyber",
        source_revision=2,
        source_integrity_sha256=digest("source"),
        kind="cyber_posture",
        capability="monitoring",
        key_id="provider-key-v1",
    )
    assert value.tenant_id == "Acme Caf\u00e9 Group"
    with pytest.raises(providers.ThirdPartyProviderProtocolError, match="canonical"):
        providers.ProviderRequest(
            tenant_id="Acme Cafe\u0301 Group",
            provider="riskrecon",
            source_id="source-cyber",
            source_revision=2,
            source_integrity_sha256=digest("source"),
            kind="cyber_posture",
            capability="monitoring",
            key_id="provider-key-v1",
        )


def test_factory_rejects_disabled_unknown_or_provenance_host_drift() -> None:
    transport = Transport()
    disabled = providers.ThirdPartyProviderFactory(
        transport=transport,
        enabled_providers=[],
    )
    with pytest.raises(providers.ThirdPartyProviderConfigError, match="not enabled"):
        disabled.create("riskrecon", "https://api.riskrecon.com/feed")
    with pytest.raises(providers.ThirdPartyProviderConfigError, match="supported"):
        providers.ThirdPartyProviderFactory(
            transport=transport,
            enabled_providers=["attacker-provider"],
        )
    with pytest.raises(providers.ThirdPartyProviderConfigError, match="host"):
        factory(transport).create("riskrecon", "https://attacker.example/feed")
    with pytest.raises(providers.ThirdPartyProviderConfigError, match="query"):
        factory(transport).create(
            "riskrecon",
            "https://api.riskrecon.com/feed?token=must-not-persist",
        )
    with pytest.raises(providers.ThirdPartyProviderConfigError, match="fixed host"):
        providers.ThirdPartyProviderFactory(
            transport=transport,
            enabled_providers=["generic_approved"],
        )


@pytest.mark.parametrize(
    ("provider", "host", "path", "schema"),
    [
        (
            "riskrecon",
            "api.riskrecon.com",
            "/api/v1/third-party-observations",
            "lightwork.riskrecon-observation-page.v1",
        ),
        (
            "securityscorecard",
            "api.securityscorecard.io",
            "/companies/observations",
            "lightwork.securityscorecard-observation-page.v1",
        ),
        (
            "hacknotice",
            "api.hacknotice.com",
            "/v1/vendor-observations",
            "lightwork.hacknotice-observation-page.v1",
        ),
        (
            "supplywisdom",
            "licensed-supplywisdom.customer.example",
            "/v1/third-party-observations",
            "lightwork.supplywisdom-observation-page.v1",
        ),
        (
            "iss_corporate_solutions",
            "licensed-iss.customer.example",
            "/v1/third-party-observations",
            "lightwork.iss-corporate-solutions-observation-page.v1",
        ),
        (
            "generic_approved",
            "intelligence.customer.example",
            "/v1/third-party-observations",
            "lightwork.generic-approved-observation-page.v1",
        ),
    ],
)
def test_every_provider_concept_has_a_fixed_get_contract(
    provider: str,
    host: str,
    path: str,
    schema: str,
) -> None:
    def respond(query):
        result = page(query, records=[record(provider)])
        result["schema"] = schema
        return result

    transport = Transport(respond)
    provider_factory = providers.ThirdPartyProviderFactory(
        transport=transport,
        enabled_providers=[provider],
        generic_approved_host=(host if provider == "generic_approved" else None),
        named_provider_hosts=(
            {provider: host}
            if provider in {"supplywisdom", "iss_corporate_solutions"}
            else None
        ),
    )
    adapter = provider_factory.create(provider, f"https://{host}/licensed-feed")
    result = adapter.collect(
        request(provider),
        providers.CredentialBinding("provider-key-v1", object()),
    )
    assert result.provider == provider
    assert transport.calls[0]["host"] == host
    assert transport.calls[0]["path"] == path


def test_named_vendor_gateway_authorities_require_exact_explicit_enrollment() -> None:
    transport = Transport()
    with pytest.raises(providers.ThirdPartyProviderConfigError, match="enrolled host"):
        providers.ThirdPartyProviderFactory(
            transport=transport,
            enabled_providers=["supplywisdom"],
        )
    with pytest.raises(providers.ThirdPartyProviderConfigError, match="disabled"):
        providers.ThirdPartyProviderFactory(
            transport=transport,
            enabled_providers=["riskrecon"],
            named_provider_hosts={
                "supplywisdom": "licensed-supplywisdom.customer.example"
            },
        )
    factory_with_host = providers.ThirdPartyProviderFactory(
        transport=transport,
        enabled_providers=["supplywisdom"],
        named_provider_hosts={
            "supplywisdom": "licensed-supplywisdom.customer.example"
        },
    )
    with pytest.raises(providers.ThirdPartyProviderConfigError, match="authority"):
        factory_with_host.create(
            "supplywisdom",
            "https://licensed-supplywisdom.customer.example:8443/feed",
        )


def test_bounded_pagination_is_complete_and_deterministic() -> None:
    def respond(query):
        if "cursor" not in query:
            return page(
                query,
                records=[record("one")],
                complete=False,
                next_cursor="cursor-2",
            )
        assert query["cursor"] == "cursor-2"
        return page(query, records=[record("two")])

    transport = Transport(respond)
    adapter = factory(transport).create(
        "riskrecon",
        "https://api.riskrecon.com/feed",
    )
    result = adapter.collect(
        request(),
        providers.CredentialBinding("provider-key-v1", "transient-secret"),
    )
    assert result.record_count == result.cursor_count == 2
    assert [item.citation_id for item in result.citations] == [
        "citation-one",
        "citation-two",
    ]
    assert "transient-secret" not in repr(result)


@pytest.mark.parametrize("mutation", ["extra", "tenant", "key", "kind"])
def test_response_schema_and_authority_pins_fail_closed(mutation: str) -> None:
    def respond(query):
        result = page(query, records=[record("one")])
        if mutation == "extra":
            result["raw_payload"] = "must-not-pass"
        elif mutation == "tenant":
            result["tenant_id"] = "tenant-other"
        elif mutation == "key":
            result["key_id"] = "provider-key-other"
        else:
            result["kind"] = "breach_intelligence"
        return result

    adapter = factory(Transport(respond)).create(
        "riskrecon",
        "https://api.riskrecon.com/feed",
    )
    with pytest.raises(providers.ThirdPartyProviderProtocolError):
        adapter.collect(
            request(),
            providers.CredentialBinding("provider-key-v1", object()),
        )


def test_incomplete_terminal_page_and_cursor_cycle_fail_closed() -> None:
    incomplete = factory(
        Transport(
            lambda query: page(
                query,
                records=[record("one")],
                complete=False,
                reasons=["upstream_truncated"],
            )
        )
    ).create("riskrecon", "https://api.riskrecon.com/feed")
    with pytest.raises(providers.ThirdPartyProviderIncompleteError, match="truncated"):
        incomplete.collect(
            request(),
            providers.CredentialBinding("provider-key-v1", object()),
        )

    partial_with_cursor = factory(
        Transport(
            lambda query: page(
                query,
                records=[record("one")],
                complete=False,
                next_cursor="cursor-2",
                reasons=["upstream_truncated"],
            )
        )
    ).create("riskrecon", "https://api.riskrecon.com/feed")
    with pytest.raises(providers.ThirdPartyProviderIncompleteError, match="truncated"):
        partial_with_cursor.collect(
            request(),
            providers.CredentialBinding("provider-key-v1", object()),
        )

    cycle = factory(
        Transport(
            lambda query: page(
                query,
                records=[record(f"item-{query.get('cursor', 'first')}")],
                complete=False,
                next_cursor="same-cursor",
            )
        )
    ).create("riskrecon", "https://api.riskrecon.com/feed")
    with pytest.raises(providers.ThirdPartyProviderProtocolError, match="cycle"):
        cycle.collect(
            request(),
            providers.CredentialBinding("provider-key-v1", object()),
        )


def test_provider_citation_cannot_smuggle_query_credentials() -> None:
    def respond(query):
        item = record("one")
        item["citation"]["uri"] = "https://api.riskrecon.com/evidence?token=raw-secret"
        return page(query, records=[item])

    adapter = factory(Transport(respond)).create(
        "riskrecon",
        "https://api.riskrecon.com/feed",
    )
    with pytest.raises(providers.ThirdPartyProviderProtocolError, match="query"):
        adapter.collect(
            request(),
            providers.CredentialBinding("provider-key-v1", object()),
        )


def test_transport_failure_drops_raw_exception_details() -> None:
    def fail(_query):
        raise TimeoutError("raw-provider-secret-detail")

    adapter = factory(Transport(fail)).create(
        "riskrecon",
        "https://api.riskrecon.com/feed",
    )
    with pytest.raises(providers.ThirdPartyProviderError) as raised:
        adapter.collect(
            request(),
            providers.CredentialBinding("provider-key-v1", object()),
        )
    assert raised.value.__cause__ is None
    assert "raw-provider-secret-detail" not in str(raised.value)
