"""Bundled third-party intelligence provider transport and composition."""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from maverick import third_party_intelligence_providers as providers

TENANT = "tenant-provider-composition"
TOKEN = "licensed-provider-token-never-returned"


def enrollment(
    provider: str,
    source_id: str,
    credential_ref: str,
    *,
    state: str = "active",
) -> providers.ProviderCredentialEnrollment:
    return providers.ProviderCredentialEnrollment(
        tenant_id=TENANT,
        provider=provider,
        source_id=source_id,
        credential_ref=credential_ref,
        key_id=f"{provider}-key-v1",
        revision=1,
        state=state,
    )


def query(provider: str = "supplywisdom") -> dict[str, str]:
    return {
        "tenant_id": TENANT,
        "provider": provider,
        "source_id": "source-supply",
        "source_revision": "3",
        "source_integrity_sha256": "a" * 64,
        "capability": "monitoring",
        "key_id": f"{provider}-key-v1",
        "kind": "operational_resilience",
    }


class Response:
    def __init__(
        self,
        body: bytes,
        *,
        status: int = 200,
        content_type: str = "application/json",
    ) -> None:
        self.status_code = status
        self.headers = {
            "content-type": content_type,
            "content-length": str(len(body)),
        }
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def iter_bytes(self):
        yield self._body


class Client:
    def __init__(self, response: Response | Exception, calls: list[dict[str, object]]) -> None:
        self.response = response
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def stream(self, method: str, url: str, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def install_safe_client(monkeypatch, response: Response | Exception):
    from maverick.tools import _ssrf

    calls: list[dict[str, object]] = []

    def safe_client(url: str, **kwargs):
        calls.append({"safe_client_url": url, **kwargs})
        return Client(response, calls)

    monkeypatch.setattr(_ssrf, "safe_client", safe_client)
    return calls


def transport() -> providers.ProductionThirdPartyHTTPSJSONTransport:
    return providers.ProductionThirdPartyHTTPSJSONTransport(
        {
            "supplywisdom": (
                "licensed-supplywisdom.customer.example",
                "/v1/third-party-observations",
            )
        }
    )


def test_composition_is_closed_lazy_and_truthful_about_live_readiness() -> None:
    resolutions: list[str] = []

    def resolve(reference: str) -> str | None:
        resolutions.append(reference)
        return TOKEN

    composition = providers.ThirdPartyProviderComposition(
        enabled_providers=["supplywisdom", "iss_corporate_solutions"],
        named_provider_hosts={
            "supplywisdom": "licensed-supplywisdom.customer.example",
            "iss_corporate_solutions": "licensed-iss.customer.example",
        },
        credential_enrollments=[
            enrollment("supplywisdom", "source-supply", "SUPPLYWISDOM_TOKEN"),
            enrollment(
                "iss_corporate_solutions",
                "source-iss",
                "ISS_CORPORATE_SOLUTIONS_TOKEN",
            ),
        ],
        secret_resolver=resolve,
    )
    status = composition.readiness()
    assert status["configuration_ready"] is True
    assert status["ready"] is False
    assert status["ready_requires_source_credential_check"] is True
    assert status["transport_hardened"] is True
    assert status["readiness_provider_network_io"] is False
    assert status["licensed_provider_credential_verified"] is False
    assert status["live_provider_acceptance_verified"] is False
    assert resolutions == []
    binding = composition.credential_resolver(
        TENANT,
        "SUPPLYWISDOM_TOKEN",
        "supplywisdom",
        "source-supply",
    )
    assert binding.key_id == "supplywisdom-key-v1"
    assert isinstance(binding.secret, providers.ProviderBearerCredential)
    assert TOKEN not in repr(binding)
    assert TOKEN not in repr(binding.secret)
    assert resolutions == ["SUPPLYWISDOM_TOKEN"]
    source_status = composition.credential_authority.source_readiness(
        tenant_id=TENANT,
        credential_ref="SUPPLYWISDOM_TOKEN",
        provider="supplywisdom",
        source_id="source-supply",
        verify_secret=True,
    )
    assert source_status["ready"] is True
    assert source_status["secret_value_returned"] is False
    assert resolutions == ["SUPPLYWISDOM_TOKEN", "SUPPLYWISDOM_TOKEN"]


def test_disabled_composition_is_side_effect_free_and_not_ready() -> None:
    composition = providers.ThirdPartyProviderComposition(
        enabled_providers=[],
        credential_enrollments=[],
    )
    status = composition.readiness()
    assert status["enabled_providers"] == []
    assert status["resolved_endpoints"] == {}
    assert status["configured"] is False
    assert status["ready"] is False


def test_credential_authority_rejects_cross_tenant_ambiguity_and_revocation() -> None:
    item = enrollment("supplywisdom", "source-supply", "SUPPLYWISDOM_TOKEN")
    with pytest.raises(providers.ThirdPartyProviderConfigError, match="ambiguous"):
        providers.DeploymentCredentialAuthority([item, item])

    authority = providers.DeploymentCredentialAuthority(
        [
            enrollment(
                "supplywisdom",
                "source-supply",
                "SUPPLYWISDOM_TOKEN",
                state="revoked",
            )
        ],
        secret_resolver=lambda _reference: TOKEN,
    )
    with pytest.raises(providers.ThirdPartyProviderCredentialError) as revoked:
        authority.resolve(
            TENANT,
            "SUPPLYWISDOM_TOKEN",
            "supplywisdom",
            "source-supply",
        )
    assert revoked.value.code == "credential_revoked"
    assert revoked.value.revoked is True
    with pytest.raises(providers.ThirdPartyProviderCredentialError) as crossed:
        authority.resolve(
            "tenant-other",
            "SUPPLYWISDOM_TOKEN",
            "supplywisdom",
            "source-supply",
        )
    assert crossed.value.code == "credential_not_enrolled"


def test_bundled_transport_is_exact_get_only_bounded_and_dns_pinned(
    monkeypatch,
) -> None:
    body = json.dumps({"schema": "closed", "records": []}).encode()
    calls = install_safe_client(monkeypatch, Response(body))
    selected = transport()
    credential = providers.ProviderBearerCredential(TOKEN)
    result = selected.get_json(
        host="licensed-supplywisdom.customer.example",
        path="/v1/third-party-observations",
        query=query(),
        credential=credential,
        maximum_response_bytes=512 * 1024,
        timeout_seconds=20.0,
    )
    assert result == {"schema": "closed", "records": []}
    request_call = calls[1]
    assert request_call["method"] == "GET"
    assert request_call["follow_redirects"] is False
    assert request_call["headers"]["Authorization"] == f"Bearer {TOKEN}"
    parsed = urlsplit(str(request_call["url"]))
    assert parsed.scheme == "https"
    assert parsed.hostname == "licensed-supplywisdom.customer.example"
    assert parse_qs(parsed.query)["source_revision"] == ["3"]
    assert TOKEN not in str(request_call["url"])
    assert selected.dns_pinned is True
    assert selected.redirects_followed is False
    assert selected.get_only is True

    with pytest.raises(providers.ThirdPartyProviderConfigError, match="enrolled endpoint"):
        selected.get_json(
            host="attacker.example",
            path="/v1/third-party-observations",
            query=query(),
            credential=credential,
            maximum_response_bytes=512 * 1024,
            timeout_seconds=20.0,
        )


@pytest.mark.parametrize(
    ("response", "error_type", "code", "retryable", "ambiguous"),
    [
        (
            Response(b"{}", status=302),
            providers.ThirdPartyProviderTransportError,
            "provider_redirect_rejected",
            False,
            False,
        ),
        (
            httpx.ReadTimeout("upstream detail must be discarded"),
            providers.ThirdPartyProviderTransportError,
            "provider_transport_ambiguous",
            True,
            True,
        ),
        (
            Response(b'{"schema":"one","schema":"two"}'),
            providers.ThirdPartyProviderProtocolError,
            None,
            None,
            None,
        ),
    ],
)
def test_transport_failures_are_sanitized_and_classified(
    monkeypatch,
    response,
    error_type,
    code,
    retryable,
    ambiguous,
) -> None:
    install_safe_client(monkeypatch, response)
    with pytest.raises(error_type) as raised:
        transport().get_json(
            host="licensed-supplywisdom.customer.example",
            path="/v1/third-party-observations",
            query=query(),
            credential=providers.ProviderBearerCredential(TOKEN),
            maximum_response_bytes=512 * 1024,
            timeout_seconds=20.0,
        )
    if isinstance(raised.value, providers.ThirdPartyProviderTransportError):
        assert raised.value.code == code
        assert raised.value.retryable is retryable
        assert raised.value.ambiguous is ambiguous
    assert "upstream detail" not in str(raised.value)


def test_transport_refuses_private_fetch_override(monkeypatch) -> None:
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    with pytest.raises(providers.ThirdPartyProviderTransportError) as raised:
        transport().get_json(
            host="licensed-supplywisdom.customer.example",
            path="/v1/third-party-observations",
            query=query(),
            credential=providers.ProviderBearerCredential(TOKEN),
            maximum_response_bytes=512 * 1024,
            timeout_seconds=20.0,
        )
    assert raised.value.code == "provider_private_override_rejected"
    assert raised.value.retryable is False
