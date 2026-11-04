from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from maverick.ai_identity_governance_connectors import (
    BoundedHTTPResponse,
    ConnectorConfig,
    ConnectorLimits,
    EntraIdentityGovernanceAdapter,
    IdentityGovernanceConfigError,
    IdentityGovernanceLimitError,
    IdentityGovernanceProtocolError,
    IdentityGovernanceTransportError,
    IdentityGovernanceUnsupportedError,
    OktaIdentityGovernanceAdapter,
    PurviewGovernanceAdapter,
    configured_connectors,
    enabled,
    retry_classification,
)

SP_ID = "11111111-1111-4111-8111-111111111111"
AGENT_ID = "22222222-2222-4222-8222-222222222222"
GRANT_ID = "33333333-3333-4333-8333-333333333333"
RESOURCE_ID = "44444444-4444-4444-8444-444444444444"
ROLE_ID = "55555555-5555-4555-8555-555555555555"
PURVIEW_ID = "66666666-6666-4666-8666-666666666666"


class RecordingTransport:
    def __init__(self, handler):
        self.handler = handler
        self.calls: list[dict[str, Any]] = []

    def request(
        self,
        method,
        url,
        *,
        headers,
        json_body,
        timeout,
        max_response_bytes,
    ):
        call = {
            "method": method,
            "url": url,
            "headers": dict(headers),
            "json_body": json_body,
            "timeout": timeout,
            "max_response_bytes": max_response_bytes,
        }
        self.calls.append(call)
        return self.handler(call)


def _response(call, payload, *, status=200, headers=None, final_url=None):
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return BoundedHTTPResponse(
        status_code=status,
        headers=headers or {},
        body=body,
        final_url=call["url"] if final_url is None else final_url,
    )


def _entra_config(**overrides):
    values = {
        "provider": "entra",
        "enable": True,
        "tenant_id": "00000000-0000-4000-8000-000000000000",
        "base_url": "https://graph.microsoft.com",
        "credential_secret_ref": "ENTRA_DISCOVERY_TOKEN",
        "limits": ConnectorLimits(max_pages=20, retry_attempts=2),
    }
    values.update(overrides)
    return ConnectorConfig(**values)


def _okta_config(**overrides):
    values = {
        "provider": "okta",
        "enable": True,
        "tenant_id": "tenant-okta-prod",
        "base_url": "https://tenant.okta.com",
        "credential_secret_ref": "OKTA_DISCOVERY_TOKEN",
        "limits": ConnectorLimits(max_pages=20, retry_attempts=2),
    }
    values.update(overrides)
    return ConnectorConfig(**values)


def _purview_config(**overrides):
    values = {
        "provider": "purview",
        "enable": True,
        "tenant_id": "purview-tenant",
        "base_url": "https://account.purview.azure.com",
        "credential_secret_ref": "PURVIEW_DISCOVERY_TOKEN",
        "limits": ConnectorLimits(max_pages=20, retry_attempts=2),
    }
    values.update(overrides)
    return ConnectorConfig(**values)


def _empty_grants(call):
    return _response(call, {"value": []})


def test_feature_is_default_off_and_does_not_touch_provider_config():
    resolver_called = False

    def resolver(_reference):
        nonlocal resolver_called
        resolver_called = True
        return "secret"

    assert enabled(None) is False
    assert enabled({}) is False
    assert configured_connectors(
        {"enable": False, "entra": "intentionally-unvalidated"},
        transports={},
        secret_resolver=resolver,
    ) == ()
    assert resolver_called is False


@pytest.mark.parametrize(
    ("provider", "url"),
    [
        ("entra", "http://graph.microsoft.com"),
        ("entra", "https://127.0.0.1"),
        ("entra", "https://graph.microsoft.com.evil.test"),
        ("entra", "https://graph.microsoft.com@evil.test"),
        ("okta", "https://tenant.okta.com.evil.test"),
        ("okta", "https://localhost"),
        ("purview", "https://account.purview.azure.com.evil.test"),
        ("purview", "https://169.254.169.254"),
    ],
)
def test_base_url_allowlists_reject_ssrf(provider, url):
    with pytest.raises(IdentityGovernanceConfigError):
        ConnectorConfig(
            provider=provider,
            enable=True,
            tenant_id="tenant",
            base_url=url,
            credential_secret_ref="SAFE_SECRET_REF",
        )


@pytest.mark.parametrize(
    "reference", ["raw bearer value", "sk-live-secret", "vault://secret", "A", "A\nB"]
)
def test_credentials_must_be_secret_references(reference):
    with pytest.raises(IdentityGovernanceConfigError):
        _entra_config(credential_secret_ref=reference)


def test_entra_normalizes_service_agent_identities_and_grants_without_pii():
    def handler(call):
        path = urlsplit(call["url"]).path
        if path == "/v1.0/servicePrincipals":
            return _response(
                call,
                {
                    "value": [
                        {
                            "id": SP_ID,
                            "displayName": "Secret Payroll Agent",
                            "notificationEmailAddresses": ["owner@example.com"],
                            "accountEnabled": True,
                            "servicePrincipalType": "ManagedIdentity",
                            "appRoleAssignmentRequired": True,
                        },
                        {
                            "id": AGENT_ID,
                            "displayName": "Confidential Research Agent",
                            "accountEnabled": False,
                            "servicePrincipalType": "ServiceIdentity",
                            "appRoleAssignmentRequired": False,
                        },
                    ]
                },
            )
        if path.endswith("/appRoleAssignedTo") and SP_ID in path:
            return _response(
                call,
                {
                    "value": [
                        {
                            "id": GRANT_ID,
                            "principalId": SP_ID,
                            "resourceId": RESOURCE_ID,
                            "appRoleId": ROLE_ID,
                            "principalType": "ServicePrincipal",
                            "principalDisplayName": "Do not retain me",
                        }
                    ]
                },
            )
        return _empty_grants(call)

    transport = RecordingTransport(handler)
    adapter = EntraIdentityGovernanceAdapter(
        _entra_config(),
        transport=transport,
        secret_resolver=lambda reference: (
            "super-secret-token" if reference == "ENTRA_DISCOVERY_TOKEN" else None
        ),
        clock=lambda: 0,
        sleep=lambda _seconds: None,
    )
    snapshot = adapter.collect()

    assert [item.identity_kind for item in snapshot.identities] == [
        "managed_identity",
        "agent_identity",
    ]
    assert snapshot.grants[0].subject_kind == "service_principal"
    assert snapshot.coverage == "bounded_read_only_snapshot"
    assert snapshot.live_acceptance_verified is False
    assert snapshot.complete_inventory_claimed is False
    encoded = json.dumps(asdict(snapshot), sort_keys=True)
    for forbidden in (
        "super-secret-token",
        "ENTRA_DISCOVERY_TOKEN",
        SP_ID,
        AGENT_ID,
        GRANT_ID,
        RESOURCE_ID,
        ROLE_ID,
        "Secret Payroll Agent",
        "owner@example.com",
        "Confidential Research Agent",
        "Do not retain me",
    ):
        assert forbidden not in encoded
    assert all(call["method"] == "GET" for call in transport.calls)
    assert all(call["json_body"] is None for call in transport.calls)
    assert all(call["headers"]["Authorization"] == "Bearer super-secret-token" for call in transport.calls)


def test_entra_pagination_rebuilds_only_the_fixed_path_and_cursor():
    identity_calls = 0

    def handler(call):
        nonlocal identity_calls
        parsed = urlsplit(call["url"])
        query = parse_qs(parsed.query)
        if parsed.path == "/v1.0/servicePrincipals":
            identity_calls += 1
            if "$skiptoken" not in query:
                next_link = (
                    "https://graph.microsoft.com/v1.0/servicePrincipals?"
                    "$select=id,accountEnabled,servicePrincipalType,"
                    "appRoleAssignmentRequired&$top=100&$skiptoken=page-2"
                )
                return _response(call, {"value": [], "@odata.nextLink": next_link})
            assert query["$skiptoken"] == ["page-2"]
            return _response(call, {"value": []})
        raise AssertionError("unexpected path")

    adapter = EntraIdentityGovernanceAdapter(
        _entra_config(),
        transport=RecordingTransport(handler),
        secret_resolver=lambda _reference: "token",
        sleep=lambda _seconds: None,
    )
    assert adapter.collect().identities == ()
    assert identity_calls == 2


def test_entra_rejects_cross_origin_pagination_and_cursor_replay():
    calls = 0

    def cross_origin(call):
        return _response(
            call,
            {
                "value": [],
                "@odata.nextLink": (
                    "https://evil.test/v1.0/servicePrincipals?"
                    "$skiptoken=stolen"
                ),
            },
        )

    adapter = EntraIdentityGovernanceAdapter(
        _entra_config(),
        transport=RecordingTransport(cross_origin),
        secret_resolver=lambda _reference: "token",
    )
    with pytest.raises(IdentityGovernanceProtocolError, match="scope"):
        adapter.collect()

    def replay(call):
        nonlocal calls
        calls += 1
        next_link = (
            "https://graph.microsoft.com/v1.0/servicePrincipals?"
            "$select=id,accountEnabled,servicePrincipalType,"
            "appRoleAssignmentRequired&$top=100&$skiptoken=same"
        )
        return _response(call, {"value": [], "@odata.nextLink": next_link})

    adapter = EntraIdentityGovernanceAdapter(
        _entra_config(),
        transport=RecordingTransport(replay),
        secret_resolver=lambda _reference: "token",
    )
    with pytest.raises(IdentityGovernanceProtocolError, match="cycle"):
        adapter.collect()
    assert calls == 2


def test_redirects_and_followed_redirects_are_rejected():
    def redirect(call):
        return _response(call, {}, status=302)

    adapter = EntraIdentityGovernanceAdapter(
        _entra_config(),
        transport=RecordingTransport(redirect),
        secret_resolver=lambda _reference: "token",
    )
    with pytest.raises(IdentityGovernanceProtocolError, match="redirect"):
        adapter.collect()

    def followed(call):
        return _response(call, {"value": []}, final_url="https://evil.test/stolen")

    adapter = EntraIdentityGovernanceAdapter(
        _entra_config(),
        transport=RecordingTransport(followed),
        secret_resolver=lambda _reference: "token",
    )
    with pytest.raises(IdentityGovernanceProtocolError, match="redirect"):
        adapter.collect()


def test_response_and_record_bounds_fail_closed():
    limits = ConnectorLimits(max_response_bytes=1_024, max_records=1, max_pages=5)

    def oversized(call):
        return _response(call, b"{" + b" " * 1_024 + b"}")

    adapter = EntraIdentityGovernanceAdapter(
        _entra_config(limits=limits),
        transport=RecordingTransport(oversized),
        secret_resolver=lambda _reference: "token",
    )
    with pytest.raises(IdentityGovernanceLimitError, match="too_large"):
        adapter.collect()

    def too_many(call):
        return _response(
            call,
            {
                "value": [
                    {
                        "id": SP_ID,
                        "accountEnabled": True,
                        "servicePrincipalType": "Application",
                        "appRoleAssignmentRequired": False,
                    },
                    {
                        "id": AGENT_ID,
                        "accountEnabled": True,
                        "servicePrincipalType": "ServiceIdentity",
                        "appRoleAssignmentRequired": False,
                    },
                ]
            },
        )

    adapter = EntraIdentityGovernanceAdapter(
        _entra_config(limits=limits),
        transport=RecordingTransport(too_many),
        secret_resolver=lambda _reference: "token",
    )
    with pytest.raises(IdentityGovernanceLimitError, match="record"):
        adapter.collect()


def test_retry_classification_and_retry_budget_are_closed():
    assert retry_classification(200) == "success"
    assert retry_classification(302) == "redirect_rejected"
    assert retry_classification(429) == "retryable"
    assert retry_classification(403) == "terminal"
    calls = 0

    def retry_once(call):
        nonlocal calls
        calls += 1
        if calls == 1:
            return _response(call, {}, status=503)
        return _response(call, {"value": []})

    adapter = EntraIdentityGovernanceAdapter(
        _entra_config(),
        transport=RecordingTransport(retry_once),
        secret_resolver=lambda _reference: "token",
        sleep=lambda _seconds: None,
    )
    assert adapter.collect().identities == ()
    assert calls == 2

    def terminal(call):
        return _response(call, {}, status=401)

    adapter = EntraIdentityGovernanceAdapter(
        _entra_config(),
        transport=RecordingTransport(terminal),
        secret_resolver=lambda _reference: "token",
    )
    with pytest.raises(IdentityGovernanceTransportError) as failure:
        adapter.collect()
    assert failure.value.retryable is False


def test_secret_failures_and_provider_errors_do_not_echo_secret_values():
    secret = "do-not-leak-this-token"

    def exploding(_call):
        raise RuntimeError(secret)

    adapter = EntraIdentityGovernanceAdapter(
        _entra_config(),
        transport=RecordingTransport(exploding),
        secret_resolver=lambda _reference: secret,
        sleep=lambda _seconds: None,
    )
    with pytest.raises(IdentityGovernanceTransportError) as failure:
        adapter.collect()
    assert secret not in str(failure.value)
    assert failure.value.__cause__ is None
    assert secret not in repr(adapter)


@pytest.mark.parametrize(
    "row",
    [
        {
            "id": "not-a-guid",
            "accountEnabled": True,
            "servicePrincipalType": "Application",
            "appRoleAssignmentRequired": False,
        },
        {
            "id": SP_ID,
            "accountEnabled": "yes",
            "servicePrincipalType": "Application",
            "appRoleAssignmentRequired": False,
        },
        {
            "id": SP_ID,
            "accountEnabled": True,
            "servicePrincipalType": "FutureUnknownType",
            "appRoleAssignmentRequired": False,
        },
    ],
)
def test_malformed_entra_identity_is_not_partially_normalized(row):
    transport = RecordingTransport(lambda call: _response(call, {"value": [row]}))
    adapter = EntraIdentityGovernanceAdapter(
        _entra_config(),
        transport=transport,
        secret_resolver=lambda _reference: "token",
    )
    with pytest.raises(IdentityGovernanceProtocolError):
        adapter.collect()


def test_okta_normalizes_apps_and_assignments_without_profiles_or_names():
    app_id = "0oa123456789ABCD"
    user_id = "00u123456789ABCD"

    def handler(call):
        path = urlsplit(call["url"]).path
        if path == "/api/v1/apps":
            return _response(
                call,
                [
                    {
                        "id": app_id,
                        "status": "ACTIVE",
                        "label": "Secret HR App",
                    }
                ],
            )
        if path == f"/api/v1/apps/{app_id}/users":
            return _response(
                call,
                [
                    {
                        "id": user_id,
                        "scope": "USER",
                        "profile": {
                            "email": "private@example.com",
                            "displayName": "Private Person",
                        },
                    }
                ],
            )
        raise AssertionError("unexpected path")

    transport = RecordingTransport(handler)
    snapshot = OktaIdentityGovernanceAdapter(
        _okta_config(),
        transport=transport,
        secret_resolver=lambda reference: (
            "okta-secret" if reference == "OKTA_DISCOVERY_TOKEN" else None
        ),
        clock=lambda: 1,
    ).collect()

    assert snapshot.identities[0].identity_kind == "application"
    assert snapshot.grants[0].grant_kind == "application_assignment"
    encoded = json.dumps(asdict(snapshot), sort_keys=True)
    for forbidden in (
        app_id,
        user_id,
        "Secret HR App",
        "private@example.com",
        "Private Person",
        "okta-secret",
        "OKTA_DISCOVERY_TOKEN",
    ):
        assert forbidden not in encoded
    assert all(call["method"] == "GET" for call in transport.calls)
    assert all(call["headers"]["Authorization"] == "SSWS okta-secret" for call in transport.calls)


def test_okta_link_pagination_is_scoped_and_replay_guarded():
    app_id = "0oa123456789ABCD"
    calls = 0

    def malicious(call):
        return _response(
            call,
            [],
            headers={
                "Link": '<https://metadata.local/latest>; rel="next"',
            },
        )

    adapter = OktaIdentityGovernanceAdapter(
        _okta_config(),
        transport=RecordingTransport(malicious),
        secret_resolver=lambda _reference: "token",
    )
    with pytest.raises(IdentityGovernanceProtocolError, match="scope"):
        adapter.collect()

    def replay(call):
        nonlocal calls
        calls += 1
        path = urlsplit(call["url"]).path
        if path == "/api/v1/apps":
            return _response(
                call,
                [] if calls > 1 else [{"id": app_id, "status": "ACTIVE"}],
                headers={
                    "Link": (
                        '<https://tenant.okta.com/api/v1/apps?limit=100&after=same>'
                        '; rel="next"'
                    )
                },
            )
        return _response(call, [])

    adapter = OktaIdentityGovernanceAdapter(
        _okta_config(),
        transport=RecordingTransport(replay),
        secret_resolver=lambda _reference: "token",
    )
    with pytest.raises(IdentityGovernanceProtocolError, match="cycle"):
        adapter.collect()


def test_purview_uses_documented_read_only_search_and_discards_raw_asset_data():
    bodies = []

    def handler(call):
        bodies.append(call["json_body"])
        if len(bodies) == 1:
            return _response(
                call,
                {
                    "continuationToken": "next-page",
                    "value": [
                        {
                            "id": PURVIEW_ID,
                            "qualifiedName": (
                                "https://private.blob.core.windows.net/payroll.csv"
                            ),
                            "name": "payroll.csv",
                            "owner": "owner@example.com",
                            "entityType": "azure_blob_path",
                            "classification": ["MICROSOFT.PERSONAL.EMAIL"],
                            "label": ["Highly.Confidential"],
                        }
                    ],
                },
            )
        return _response(call, {"value": []})

    transport = RecordingTransport(handler)
    snapshot = PurviewGovernanceAdapter(
        _purview_config(),
        transport=transport,
        secret_resolver=lambda reference: (
            "purview-secret" if reference == "PURVIEW_DISCOVERY_TOKEN" else None
        ),
        clock=lambda: 2,
    ).collect()

    assert len(snapshot.data_classifications) == 1
    row = snapshot.data_classifications[0]
    assert row.entity_type == "azure_blob_path"
    assert row.classification_codes == ("MICROSOFT.PERSONAL.EMAIL",)
    assert bodies == [
        {"keywords": None, "limit": 100},
        {"keywords": None, "limit": 100, "continuationToken": "next-page"},
    ]
    assert all(call["method"] == "POST" for call in transport.calls)
    assert all(
        urlsplit(call["url"]).path == "/datamap/api/search/query"
        for call in transport.calls
    )
    encoded = json.dumps(asdict(snapshot), sort_keys=True)
    for forbidden in (
        PURVIEW_ID,
        "payroll.csv",
        "private.blob.core.windows.net",
        "owner@example.com",
        "purview-secret",
        "PURVIEW_DISCOVERY_TOKEN",
        "next-page",
    ):
        assert forbidden not in encoded


def test_purview_rejects_unclosed_classification_and_cursor_replay():
    def bad_classification(call):
        return _response(
            call,
            {
                "value": [
                    {
                        "id": PURVIEW_ID,
                        "entityType": "azure_blob_path",
                        "classification": ["person@example.com"],
                        "label": [],
                    }
                ]
            },
        )

    adapter = PurviewGovernanceAdapter(
        _purview_config(),
        transport=RecordingTransport(bad_classification),
        secret_resolver=lambda _reference: "token",
    )
    with pytest.raises(IdentityGovernanceProtocolError):
        adapter.collect()

    def replay(call):
        return _response(call, {"value": [], "continuationToken": "same"})

    adapter = PurviewGovernanceAdapter(
        _purview_config(),
        transport=RecordingTransport(replay),
        secret_resolver=lambda _reference: "token",
    )
    with pytest.raises(IdentityGovernanceProtocolError, match="cycle"):
        adapter.collect()


def test_duplicate_json_keys_and_malformed_provider_shapes_fail_closed():
    def duplicates(call):
        return _response(call, b'{"value":[],"value":[]}')

    adapter = EntraIdentityGovernanceAdapter(
        _entra_config(),
        transport=RecordingTransport(duplicates),
        secret_resolver=lambda _reference: "token",
    )
    with pytest.raises(IdentityGovernanceProtocolError, match="duplicate"):
        adapter.collect()

    def malformed(call):
        return _response(call, {"value": {"not": "an array"}})

    adapter = PurviewGovernanceAdapter(
        _purview_config(),
        transport=RecordingTransport(malformed),
        secret_resolver=lambda _reference: "token",
    )
    with pytest.raises(IdentityGovernanceProtocolError):
        adapter.collect()


def test_configuration_digest_is_exact_and_tenant_scoped_but_not_reversible():
    first = _entra_config()
    same = _entra_config()
    other_tenant = _entra_config(tenant_id="other-tenant")
    other_reference = _entra_config(credential_secret_ref="OTHER_TOKEN_REF")
    assert first.configuration_sha256 == same.configuration_sha256
    assert first.configuration_sha256 != other_tenant.configuration_sha256
    assert first.configuration_sha256 != other_reference.configuration_sha256
    assert first.tenant_sha256 != other_tenant.tenant_sha256
    assert first.tenant_id not in first.tenant_sha256
    assert first.credential_secret_ref not in first.configuration_sha256


def test_configured_connectors_is_strict_and_requires_injected_transport():
    section = {
        "enable": True,
        "entra": {
            "enable": True,
            "tenant_id": "tenant",
            "base_url": "https://graph.microsoft.com",
            "credential_secret_ref": "ENTRA_TOKEN_REF",
        },
    }
    with pytest.raises(IdentityGovernanceUnsupportedError):
        configured_connectors(section, transports={}, secret_resolver=lambda _ref: "x")
    with pytest.raises(IdentityGovernanceConfigError, match="key"):
        configured_connectors(
            {"enable": True, "caller_url": "https://evil.test"},
            transports={},
            secret_resolver=lambda _ref: "x",
        )

    transport = RecordingTransport(lambda call: _response(call, {"value": []}))
    connectors = configured_connectors(
        section,
        transports={"entra": transport},
        secret_resolver=lambda _ref: "x",
    )
    assert len(connectors) == 1
    assert isinstance(connectors[0], EntraIdentityGovernanceAdapter)
    assert not any(
        hasattr(connectors[0], operation)
        for operation in ("create", "update", "delete", "patch", "mutate")
    )
