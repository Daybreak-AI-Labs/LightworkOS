"""Provider wire checks are HTTP fakes, explicitly not live acceptance."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Event

import httpx
import maverick.vendor_onboarding_adapters as adapters
import pytest
from maverick import connections, doc_discovery, enterprise
from maverick.governed_operations import ServiceContext
from maverick.paths import current_tenant_id_strict, tenant_scope
from maverick.tools import _ssrf
from maverick.vendor_onboarding_adapters import (
    ADAPTER_CONTRACT_FIELDS,
    ADAPTER_CONTRACT_MATRIX,
    GOOGLE_DOC_MIME,
    JIRA_FIELD_COMPARISONS,
    JIRA_VERIFICATION_RECEIPT_FIELDS,
    MAX_PDF_BYTES,
    MAX_TEXT_BYTES,
    CredentialAuthorityChanged,
    FakeJiraTickets,
    GoogleDriveEvidence,
    JiraTickets,
    ProviderMultipleMatches,
    ProviderReadUnavailable,
    ProviderWriteIndeterminate,
    jira_body,
    resolve_connection,
)


@pytest.fixture
def credential(monkeypatch):
    ctx = ServiceContext("customer-a", "reviewer", "procurement", "credential-admin", "jira-a", "drive-a", True)
    records = {
        "jira-a": {"name": "jira-a", "connector": "jira", "owner": "credential-admin",
                   "allowed_principals": ["reviewer"], "access": "owner", "revision": "jira-v1",
                   "base_url": "https://example.atlassian.net", "token": "synthetic-jira-token"},
        "drive-a": {"name": "drive-a", "connector": "gdrive", "owner": "credential-admin",
                    "allowed_principals": ["reviewer"], "access": "owner", "revision": "drive-v1",
                    "base_url": "https://www.googleapis.com", "token": "synthetic-drive-token"},
    }
    monkeypatch.setattr(connections, "enabled", lambda: True)
    monkeypatch.setattr(connections, "get_connection", lambda name: records.get(name))
    monkeypatch.setattr(enterprise, "enterprise_egress_denial", lambda *a, **kw: None)
    return ctx, records


def payload():
    return {"project": "VEND", "summary": "Reviewed synthetic vendor",
            "description": "Exact accepted assessment digest and evidence reference",
            "marker": "lightwork-vop-" + "1" * 32}


def test_jira_create_readback_search_uses_exact_payload_and_named_credential(credential, monkeypatch):
    ctx, _ = credential
    calls = []

    def transport(request):
        calls.append(request)
        assert current_tenant_id_strict() == ctx.tenant
        assert request.headers["authorization"] == "Bearer synthetic-jira-token"
        if request.method == "POST" and request.url.path == "/rest/api/3/issue":
            assert json.loads(request.content) == jira_body(payload())
            return httpx.Response(201, json={"key": "VEND-1"})
        if request.url.path.endswith("/search/jql"):
            body = json.loads(request.content)
            assert payload()["marker"] in body["jql"]
            return httpx.Response(200, json={"issues": [{"key": "VEND-1"}]})
        fields = jira_body(payload())["fields"]
        return httpx.Response(200, json={"key": "VEND-1", "fields": dict(fields, updated="2026-09-04T00:00:00Z")})

    monkeypatch.setattr(_ssrf, "safe_client", lambda *a, **kw: httpx.Client(transport=httpx.MockTransport(transport)))
    jira = JiraTickets()
    receipt = jira.create(ctx, payload(), "VOP-" + "1" * 32)
    assert receipt["key"] == "VEND-1"
    assert jira.verify(ctx, receipt["key"], payload())["verified"] is True
    assert jira.find(ctx, payload()) == ["VEND-1"]
    assert len(calls) == 3


def test_jira_search_continuation_is_typed_as_at_least_multiple_matches(
    credential, monkeypatch,
):
    ctx, _ = credential
    calls = []

    def transport(request):
        calls.append(request)
        return httpx.Response(200, json={
            "issues": [{"key": "VEND-1"}, {"key": "VEND-2"}],
            "nextPageToken": "opaque-provider-cursor",
        })

    monkeypatch.setattr(
        _ssrf,
        "safe_client",
        lambda *args, **kwargs: httpx.Client(transport=httpx.MockTransport(transport)),
    )
    with pytest.raises(ProviderMultipleMatches) as error:
        JiraTickets().find(ctx, payload())
    assert error.value.minimum == 3
    assert len(calls) == 1


def test_jira_search_does_not_count_duplicate_provider_rows_as_distinct_matches(
    credential, monkeypatch,
):
    ctx, _ = credential

    def transport(request):
        return httpx.Response(200, json={
            "issues": [{"key": "VEND-1"}, {"key": "VEND-1"}],
            "nextPageToken": "opaque-provider-cursor",
        })

    monkeypatch.setattr(
        _ssrf,
        "safe_client",
        lambda *args, **kwargs: httpx.Client(transport=httpx.MockTransport(transport)),
    )
    with pytest.raises(ProviderReadUnavailable, match="duplicate"):
        JiraTickets().find(ctx, payload())


def test_adapter_contract_declares_bounded_reads_and_non_replayed_write():
    assert set(ADAPTER_CONTRACT_MATRIX) == {
        "drive.search", "drive.fetch", "jira.create", "jira.verify", "jira.find",
    }
    assert all(
        set(contract) == ADAPTER_CONTRACT_FIELDS
        for contract in ADAPTER_CONTRACT_MATRIX.values()
    )
    assert ADAPTER_CONTRACT_MATRIX["drive.search"]["pagination"].startswith("one bounded page")
    assert "bounded" in ADAPTER_CONTRACT_MATRIX["jira.verify"]["retry"]
    assert ADAPTER_CONTRACT_MATRIX["jira.create"]["effect"] == "non-idempotent write"
    assert "never automatic" in ADAPTER_CONTRACT_MATRIX["jira.create"]["retry"]
    for operation, contract in ADAPTER_CONTRACT_MATRIX.items():
        assert all(isinstance(value, str) and value for value in contract.values()), operation
        assert "permission" in contract and "rate_limit" in contract
        assert "timeout" in contract and "errors" in contract


def test_jira_safe_read_retries_429_and_timeout_within_cap(credential, monkeypatch):
    ctx, _ = credential
    calls = []
    delays = []
    fields = jira_body(payload())["fields"]

    def transport(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(429, headers={"Retry-After": "99"})
        if len(calls) == 2:
            raise httpx.ReadTimeout("synthetic timeout", request=request)
        return httpx.Response(
            200,
            json={
                "key": "VEND-1",
                "fields": dict(fields, updated="2026-09-04T00:00:00Z"),
            },
        )

    monkeypatch.setattr(
        _ssrf,
        "safe_client",
        lambda *args, **kwargs: httpx.Client(transport=httpx.MockTransport(transport)),
    )
    receipt = JiraTickets(
        safe_read_attempts=3,
        safe_read_backoff_seconds=0,
        sleeper=delays.append,
        clock=lambda: 123.0,
    ).verify(ctx, "VEND-1", payload())
    assert len(calls) == 3
    assert delays == [2.0]
    assert receipt["verified"] is True
    assert receipt["target"] == {"provider": "jira", "issue_key": "VEND-1"}
    assert receipt["observed_at"] == 123.0
    assert all(receipt["field_comparisons"].values())


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(429, headers={"Retry-After": "0"}),
        httpx.Response(201, content=b"not-json"),
        httpx.Response(201, json={}),
        httpx.Response(201, json={"key": "invalid-key"}),
    ],
)
def test_jira_non_idempotent_write_is_never_replayed_when_outcome_is_uncertain(
    credential, monkeypatch, response,
):
    ctx, _ = credential
    calls = []

    def transport(request):
        calls.append(request)
        return response

    monkeypatch.setattr(
        _ssrf,
        "safe_client",
        lambda *args, **kwargs: httpx.Client(transport=httpx.MockTransport(transport)),
    )
    with pytest.raises(ProviderWriteIndeterminate, match="reconcile before retrying"):
        JiraTickets(
            safe_read_attempts=5,
            safe_read_backoff_seconds=0,
            sleeper=lambda _delay: None,
        ).create(ctx, payload(), "VOP-" + "1" * 32)
    assert len(calls) == 1


@pytest.mark.parametrize("change", ["rotate", "revoke"])
def test_drive_retry_rechecks_current_authority_before_each_provider_dispatch(
    credential, monkeypatch, change,
):
    ctx, records = credential
    dispatch_tokens = []

    def metadata(_url, token, _params):
        dispatch_tokens.append(token)
        return 429, {"private": "discarded transient response"}

    def change_authority(_delay):
        if change == "rotate":
            records["drive-a"] = dict(
                records["drive-a"], revision="drive-v2", token="rotated-drive-token",
            )
        else:
            del records["drive-a"]

    monkeypatch.setattr(doc_discovery, "_get", metadata)
    with pytest.raises(CredentialAuthorityChanged, match="generation changed"):
        GoogleDriveEvidence(
            safe_read_attempts=3,
            safe_read_backoff_seconds=0.01,
            sleeper=change_authority,
        ).head(ctx, "doc")
    assert dispatch_tokens == ["synthetic-drive-token"]


def test_fake_jira_verification_uses_the_same_closed_receipt_contract():
    ctx = ServiceContext(
        "customer-a", "reviewer", "procurement", "credential-admin", "jira-a",
        human=True,
    )
    jira = FakeJiraTickets(clock=lambda: 123.0)
    created = jira.create(ctx, payload(), "VOP-" + "1" * 32)
    receipt = jira.verify(ctx, created["key"], payload())
    assert set(receipt) == JIRA_VERIFICATION_RECEIPT_FIELDS
    assert set(receipt["field_comparisons"]) == JIRA_FIELD_COMPARISONS
    assert receipt["schema"] == "lightwork.jira-verification-receipt.v1"
    assert receipt["target"] == {"provider": "jira", "issue_key": created["key"]}
    assert receipt["observed_at"] == 123.0
    assert receipt["unresolved_ambiguity"] is False
    assert all(receipt["field_comparisons"].values())


def test_jira_revoked_read_is_terminal_and_exposes_no_provider_body(credential, monkeypatch):
    ctx, _ = credential
    calls = []

    def transport(request):
        calls.append(request)
        return httpx.Response(403, text="private-provider-detail")

    monkeypatch.setattr(
        _ssrf,
        "safe_client",
        lambda *args, **kwargs: httpx.Client(transport=httpx.MockTransport(transport)),
    )
    with pytest.raises(PermissionError) as denied:
        JiraTickets(
            safe_read_attempts=5,
            safe_read_backoff_seconds=0,
            sleeper=lambda _delay: None,
        ).verify(ctx, "VEND-1", payload())
    assert len(calls) == 1
    assert "private-provider-detail" not in str(denied.value)


def test_drive_safe_read_retry_cap_denial_and_malformed_response(credential, monkeypatch):
    ctx, _ = credential
    attempts = []
    responses = iter([
        (429, {"private": "discard"}),
        (503, {"private": "discard"}),
        (200, {
            "id": "doc",
            "version": "42",
            "mimeType": "text/plain",
            "modifiedTime": "2026-09-01T12:00:00Z",
            "trashed": False,
        }),
    ])

    def metadata(*_args, **_kwargs):
        attempts.append(1)
        return next(responses)

    monkeypatch.setattr(doc_discovery, "_get", metadata)
    drive = GoogleDriveEvidence(
        safe_read_attempts=3,
        safe_read_backoff_seconds=0,
        sleeper=lambda _delay: None,
    )
    assert drive.head(ctx, "doc")["version"] == "42"
    assert len(attempts) == 3

    attempts.clear()
    monkeypatch.setattr(
        doc_discovery,
        "_get",
        lambda *_args, **_kwargs: (403, {"private": "must-not-escape"}),
    )
    with pytest.raises(PermissionError) as denied:
        drive.head(ctx, "doc")
    assert "must-not-escape" not in str(denied.value)

    monkeypatch.setattr(doc_discovery, "_get", lambda *_args, **_kwargs: (200, []))
    with pytest.raises(ProviderReadUnavailable, match="malformed"):
        drive.head(ctx, "doc")


def test_drive_read_discards_data_when_local_credential_rotates(credential, monkeypatch):
    ctx, records = credential

    def metadata(*_args, **_kwargs):
        records["drive-a"] = dict(
            records["drive-a"], revision="drive-v2", token="rotated-token"
        )
        return 200, {
            "id": "doc",
            "version": "42",
            "mimeType": "text/plain",
            "modifiedTime": "2026-09-01T12:00:00Z",
            "trashed": False,
        }

    monkeypatch.setattr(doc_discovery, "_get", metadata)
    with pytest.raises(PermissionError, match="credential changed"):
        GoogleDriveEvidence(
            safe_read_attempts=3,
            safe_read_backoff_seconds=0,
            sleeper=lambda _delay: None,
        ).head(ctx, "doc")


@pytest.mark.parametrize("change", ["rotate", "revoke"])
def test_jira_connection_change_before_effect_fence_never_dispatches_old_bearer(
    credential, monkeypatch, change,
):
    ctx, records = credential
    preflight_read = Event()
    rotation_done = Event()
    original_resolve = adapters.resolve_connection
    dispatches = []

    def pause_after_preflight(context, *, document=False, refresh=True):
        resolved = original_resolve(context, document=document, refresh=refresh)
        if refresh:
            preflight_read.set()
            assert rotation_done.wait(10), "credential rotation did not finish"
        return resolved

    def rotate():
        assert preflight_read.wait(10), "Jira preflight did not finish"
        with connections._mutation_lock():
            if change == "rotate":
                records["jira-a"] = dict(
                    records["jira-a"],
                    revision="jira-v2",
                    token="synthetic-rotated-jira-token",
                )
            else:
                del records["jira-a"]
        rotation_done.set()

    def forbidden_dispatch(*args, **kwargs):
        dispatches.append((args, kwargs))
        raise AssertionError("stale Jira bearer reached the provider boundary")

    monkeypatch.setattr(adapters, "resolve_connection", pause_after_preflight)
    monkeypatch.setattr(_ssrf, "safe_client", forbidden_dispatch)
    with ThreadPoolExecutor(max_workers=1) as workers:
        rotating = workers.submit(rotate)
        with pytest.raises(CredentialAuthorityChanged, match="generation changed"):
            JiraTickets().create(
                ctx,
                payload(),
                "VOP-" + "1" * 32,
                expected_credential_version="jira-v1",
            )
        rotating.result(timeout=10)
    assert dispatches == []
    assert (records.get("jira-a") or {}).get("revision") == (
        "jira-v2" if change == "rotate" else None
    )


def test_jira_effect_fence_serializes_rotation_through_dispatch(
    credential, monkeypatch,
):
    ctx, records = credential
    request_started = Event()
    release_request = Event()
    rotation_started = Event()
    rotation_done = Event()
    authorizations = []

    def transport(request):
        authorizations.append(request.headers["authorization"])
        request_started.set()
        assert release_request.wait(10), "test did not release Jira response"
        return httpx.Response(201, json={"key": "VEND-1"})

    def rotate():
        rotation_started.set()
        with connections._mutation_lock():
            records["jira-a"] = dict(
                records["jira-a"],
                revision="jira-v2",
                token="synthetic-rotated-jira-token",
            )
        rotation_done.set()

    monkeypatch.setattr(
        _ssrf,
        "safe_client",
        lambda *args, **kwargs: httpx.Client(
            transport=httpx.MockTransport(transport)
        ),
    )
    with ThreadPoolExecutor(max_workers=2) as workers:
        creating = workers.submit(
            JiraTickets().create,
            ctx,
            payload(),
            "VOP-" + "1" * 32,
            expected_credential_version="jira-v1",
        )
        try:
            assert request_started.wait(10), "Jira request did not start"
            lock_was_free = connections._lock.acquire(blocking=False)
            if lock_was_free:
                connections._lock.release()
            assert lock_was_free is False
            rotating = workers.submit(rotate)
            assert rotation_started.wait(10), "credential rotation did not start"
            assert rotation_done.is_set() is False
        finally:
            release_request.set()
        assert creating.result(timeout=10)["key"] == "VEND-1"
        rotating.result(timeout=10)
    assert authorizations == ["Bearer synthetic-jira-token"]
    assert records["jira-a"]["revision"] == "jira-v2"


def test_jira_readback_compares_content_and_rejects_redirects(credential, monkeypatch):
    ctx, _ = credential
    fields = jira_body(payload())["fields"]
    fields["summary"] = "Unexpected external change"
    monkeypatch.setattr(_ssrf, "safe_client", lambda *a, **kw: httpx.Client(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, json={"key": "VEND-1", "fields": fields}))))
    jira = JiraTickets()
    assert jira.verify(ctx, "VEND-1", payload())["verified"] is False
    monkeypatch.setattr(_ssrf, "safe_client", lambda *a, **kw: httpx.Client(transport=httpx.MockTransport(
        lambda req: httpx.Response(302, headers={"Location": "https://untrusted.example"}))))
    with pytest.raises(RuntimeError, match="HTTP 302"):
        jira.create(ctx, payload(), "VOP-" + "1" * 32)


def test_jira_search_cannot_interpolate_unvalidated_payload(credential):
    ctx, _ = credential
    with pytest.raises(ValueError, match="unsupported Jira"):
        JiraTickets().find(ctx, dict(payload(), project='VEND" OR project = "OTHER'))


def test_drive_brackets_complete_bounded_text_download_with_provider_versions(credential, monkeypatch):
    ctx, _ = credential
    versions = iter(["42", "42"])

    def metadata(url, token, params):
        assert token == "synthetic-drive-token"
        assert url.endswith("/files/doc%2Fid")
        assert "version" in params["fields"]
        return 200, {"id": "doc/id", "version": next(versions), "mimeType": "text/plain",
                     "modifiedTime": "2026-09-01T12:00:00Z", "trashed": False}

    def download(base, token, ref, doc_id, max_bytes):
        assert current_tenant_id_strict() == ctx.tenant
        assert max_bytes == MAX_TEXT_BYTES
        return b"Internally authored synthetic evidence", "text/plain"

    monkeypatch.setattr(doc_discovery, "_get", metadata)
    monkeypatch.setattr(doc_discovery, "_fetch_gdrive", download)
    doc = GoogleDriveEvidence().fetch(ctx, "doc/id")
    assert doc.version == "42"
    assert doc.content == b"Internally authored synthetic evidence"


@pytest.mark.parametrize("changed", [False, True])
def test_native_google_docs_uses_bounded_export_and_brackets_source_version(credential, monkeypatch, changed):
    ctx, _ = credential
    versions = iter(["42", "43" if changed else "42"])
    monkeypatch.setattr(doc_discovery, "_get", lambda *a, **kw: (200, {
        "id": "native/doc", "version": next(versions), "mimeType": GOOGLE_DOC_MIME,
        "modifiedTime": "2026-09-01T12:00:00Z",
    }))
    calls = []

    def download(url, token, max_bytes):
        calls.append(url)
        assert url == "https://www.googleapis.com/drive/v3/files/native%2Fdoc/export?mimeType=text%2Fplain"
        assert token == "synthetic-drive-token"
        assert max_bytes == MAX_TEXT_BYTES
        return b"Native document exported as text", "text/plain"

    monkeypatch.setattr(doc_discovery, "_download", download)
    if changed:
        with pytest.raises(ValueError, match="changed during download"):
            GoogleDriveEvidence().fetch(ctx, "native/doc")
    else:
        document = GoogleDriveEvidence().fetch(ctx, "native/doc")
        assert document.mime == GOOGLE_DOC_MIME
        assert document.export_mime == "text/plain"
        assert document.identity()["mime"] == GOOGLE_DOC_MIME
    assert len(calls) == 1


def test_drive_pdf_download_has_separate_bound_and_credential_rotation_guard(credential, monkeypatch):
    ctx, records = credential
    monkeypatch.setattr(doc_discovery, "_get", lambda *a, **kw: (200, {
        "id": "pdf", "version": "42", "mimeType": "application/pdf",
        "modifiedTime": "2026-09-01T12:00:00Z",
    }))

    def download(base, token, ref, doc_id, max_bytes):
        assert max_bytes == MAX_PDF_BYTES
        records["drive-a"]["revision"] = "rotated"
        return b"%PDF-", "application/pdf"

    monkeypatch.setattr(doc_discovery, "_fetch_gdrive", download)
    with pytest.raises(PermissionError, match="credential changed"):
        GoogleDriveEvidence().fetch(ctx, "pdf")


def test_drive_picker_escapes_query_and_limits_results_to_supported_types(credential, monkeypatch):
    ctx, _ = credential

    def search(url, token, params):
        assert url == "https://www.googleapis.com/drive/v3/files"
        assert "name contains 'Alice\\'s\\\\paper'" in params["q"]
        assert params["pageSize"] == 20
        assert GOOGLE_DOC_MIME in params["q"]
        return 200, {"files": [{"id": "doc", "name": "Policy", "mimeType": GOOGLE_DOC_MIME},
                                {"id": "exe", "mimeType": "application/octet-stream"}], "nextPageToken": "more"}

    monkeypatch.setattr(doc_discovery, "_get", search)
    result = GoogleDriveEvidence().search(ctx, "Alice's\\paper")
    assert result == {"documents": [{"id": "doc", "name": "Policy", "mime": GOOGLE_DOC_MIME}], "has_more": True}


def test_drive_changed_version_during_download_is_not_evidence(credential, monkeypatch):
    ctx, _ = credential
    versions = iter(["42", "43"])
    monkeypatch.setattr(doc_discovery, "_get", lambda *a, **kw: (200, {
        "id": "doc", "version": next(versions), "mimeType": "text/plain",
        "modifiedTime": "2026-09-01T12:00:00Z",
    }))
    monkeypatch.setattr(doc_discovery, "_fetch_gdrive", lambda *a: (b"text", "text/plain"))
    with pytest.raises(ValueError, match="changed during download"):
        GoogleDriveEvidence().fetch(ctx, "doc")


@pytest.mark.parametrize("change", ["owner", "principal", "reference", "connector", "missing_revision", "http"])
def test_credential_authority_and_enrollment_fail_closed(credential, change):
    ctx, records = credential
    if change == "owner":
        ctx = replace(ctx, credential_authority="somebody-else")
    elif change == "principal":
        ctx = replace(ctx, actor="unauthorized")
    elif change == "reference":
        ctx = replace(ctx, credential_ref="other-credential")
    elif change == "connector":
        records["jira-a"]["connector"] = "salesforce"
    elif change == "missing_revision":
        records["jira-a"]["revision"] = ""
    else:
        records["jira-a"]["base_url"] = "http://example.atlassian.net"
    with pytest.raises(PermissionError):
        resolve_connection(ctx)


def test_explicit_credential_resolution_does_not_inherit_ambient_tenant(credential, monkeypatch):
    ctx, records = credential
    observed = []

    def get(name):
        observed.append(current_tenant_id_strict())
        return records[name]

    monkeypatch.setattr(connections, "get_connection", get)
    with tenant_scope(tenant="ambient-customer-b"):
        resolve_connection(ctx)
        assert current_tenant_id_strict() == "ambient-customer-b"
    assert observed == ["customer-a"]
