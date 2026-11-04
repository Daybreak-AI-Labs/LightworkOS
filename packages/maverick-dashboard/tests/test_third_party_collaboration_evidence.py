"""Evidence files on the supplier portal are measured by the server, never declared.

These tests drive the external API against the real collaboration store: the
supplier's page sends a file's bytes, the server computes its fingerprint, size
and type, and a draft or final answer is accepted only with exactly those
values.  Every check runs before the body is read, against the invitation's own
limits.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from maverick import third_party_collaboration as collaboration
from maverick.third_party_lifecycle import ThirdPartyLifecycleStore
from maverick_dashboard import third_party_collaboration_api as api

EXTERNAL = "/api/v1/external/third-party-collaboration"
PORTAL = "portal_ref_1234567890"
DAY = 24 * 60 * 60
PDF = b"%PDF-1.7\n" + b"supplier certificate " * 40


def _questions() -> list[dict[str, object]]:
    return [
        {
            "question_id": "security_control",
            "domain": "security",
            "prompt_ref": "Do-you-encrypt-data",
            "response_type": "boolean",
            "required": True,
            "options": [],
            "condition": None,
            "risk_rules": [],
        }
    ]


class _Principal:
    value = "author"

    def __call__(self) -> str:
        return self.value


def _stores(tmp_path: Path, *, maximum_artifacts: int = 3) -> tuple[Any, dict[str, str]]:
    principal = _Principal()
    lifecycle_path = tmp_path / "private" / "lifecycle.sqlite3"
    lifecycle = ThirdPartyLifecycleStore(
        lifecycle_path,
        config_gate=lambda: None,
        principal_resolver=principal,
        clock=lambda: 2_000_000_000.0,
    )
    lifecycle.create_template_version(
        "tenant-a",
        "standard",
        title_ref="title.standard",
        questions=_questions(),
        mitigation_rules=[],
        expected_latest_version=0,
        idempotency_key="template-create",
    )
    principal.value = "reviewer"
    lifecycle.approve_template_version(
        "tenant-a", "standard", 1, expected_revision=1, idempotency_key="template-approve"
    )
    principal.value = "creator"
    lifecycle.create_assessment(
        "tenant-a",
        "assessment-1",
        vendor_ref="vendor-1",
        template_id="standard",
        template_version=1,
        owner_ref="owner",
        respondent_assignments={"security_control": "vendor-respondent"},
        retention_seconds=DAY * 10,
        idempotency_key="assessment-create",
    )
    principal.value = "portal-admin"
    store = collaboration.ThirdPartyCollaborationStore(
        tmp_path / "private" / "collaboration.sqlite3",
        lifecycle_path=lifecycle_path,
        config_gate=lambda: None,
        principal_resolver=principal,
        clock=lambda: 2_000_000_000.0,
    )
    tokens: dict[str, str] = {}
    for invitation_id, artifacts in (("with-files", maximum_artifacts), ("no-files", 0)):
        issued = store.issue_invitation(
            "tenant-a",
            invitation_id,
            assessment_id="assessment-1",
            respondent_ref="vendor-respondent",
            allowed_question_ids=["security_control"],
            notice_ref="notice.vendor-assessment",
            notice_sha256="a" * 64,
            artifact_policy={
                "allowed_kinds": ["certification"] if artifacts else [],
                "maximum_artifacts": artifacts,
                "maximum_total_bytes": 4_096 if artifacts else 0,
            },
            expires_in_seconds=DAY,
            retention_seconds=DAY * 2,
            idempotency_key=f"issue-{invitation_id}",
        )
        tokens[invitation_id] = str(issued.token)
    return store, tokens


class _SpyStore:
    """Forward to the real store while recording which operations ran."""

    def __init__(self, store: Any) -> None:
        self._store = store
        self.calls: list[str] = []

    def __getattr__(self, name: str) -> Any:
        target = getattr(self._store, name)
        if not callable(target):
            return target

        def call(*args: Any, **kwargs: Any) -> Any:
            self.calls.append(name)
            return target(*args, **kwargs)

        return call


@pytest.fixture()
def portal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(collaboration, "enabled", lambda *_args: True)
    monkeypatch.setattr(collaboration, "require_enabled", lambda: None)
    store, tokens = _stores(tmp_path)
    spy = _SpyStore(store)
    rate: list[str] = []

    def limiter(_credential_sha256: str, action: str) -> None:
        rate.append(action)
        if action == "evidence" and rate.count("evidence") > 50:
            raise HTTPException(status_code=429, detail="rate limited")

    dependencies = api.ThirdPartyCollaborationDependencies(
        portal_resolver=lambda _ref, _request: api.ExternalPortalAuthority(
            tenant_id="tenant-a", store=spy
        ),
        external_rate_limit=limiter,
    )
    app = FastAPI()
    app.include_router(api.create_external_third_party_collaboration_router(dependencies))
    return TestClient(app, base_url="http://127.0.0.1"), spy, tokens, rate


def _upload(client: TestClient, token: str, content: bytes, **headers: str):
    return client.post(
        f"{EXTERNAL}/{PORTAL}/evidence",
        content=content,
        headers={
            "Authorization": f"ThirdPartyInvitation {token}",
            "Content-Type": "application/octet-stream",
            **headers,
        },
    )


def _draft(client: TestClient, token: str, artifacts: list[dict[str, Any]], key: str):
    ids = [str(item["artifact_id"]) for item in artifacts]
    return client.put(
        f"{EXTERNAL}/{PORTAL}/draft",
        headers={"Authorization": f"ThirdPartyInvitation {token}"},
        json={
            "answers": {"security_control": {"value": True, "artifact_ids": ids}},
            "artifacts": artifacts,
            "expected_revision": 0,
            "idempotency_key": key,
        },
    )


def test_the_server_computes_fingerprint_size_and_type_from_the_file_bytes(portal) -> None:
    client, spy, tokens, rate = portal
    response = _upload(
        client, tokens["with-files"], PDF, **{"X-Evidence-File-Extension": "pdf"}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["content_sha256"] == hashlib.sha256(PDF).hexdigest()
    assert body["size_bytes"] == len(PDF)
    assert body["media_type_ref"] == "application.pdf"
    assert body["invitation_id"] == "with-files"
    assert body["idempotent_replay"] is False
    assert "tenant_id" not in body
    assert response.headers["cache-control"] == "no-store, private"
    assert rate[-1] == "evidence"
    assert spy.calls == ["contract_for_token", "measure_evidence"]

    # A misleading name never changes what the content is.
    picture = _upload(
        client,
        tokens["with-files"],
        b"\x89PNG\r\n\x1a\n" + bytes(64),
        **{"X-Evidence-File-Extension": "pdf"},
    )
    assert picture.status_code == 200
    assert picture.json()["media_type_ref"] == "image.png"


def test_declared_sizes_and_fingerprints_are_never_trusted(portal) -> None:
    client, _spy, tokens, _rate = portal
    token = tokens["with-files"]
    measured = _upload(client, token, PDF).json()
    manifest = {
        "artifact_id": measured["artifact_id"],
        "kind": "certification",
        "content_sha256": measured["content_sha256"],
        "size_bytes": measured["size_bytes"],
        "media_type_ref": measured["media_type_ref"],
    }
    never_uploaded = {**manifest, "artifact_id": "made-up-file"}
    assert _draft(client, token, [never_uploaded], "declared-only").status_code == 422
    for field, forged in (
        ("size_bytes", 12),
        ("content_sha256", "b" * 64),
        ("media_type_ref", "image.png"),
    ):
        rejected = _draft(client, token, [{**manifest, field: forged}], f"forged-{field}")
        assert rejected.status_code == 422, field
        final = client.post(
            f"{EXTERNAL}/{PORTAL}/finalize",
            headers={"Authorization": f"ThirdPartyInvitation {token}"},
            json={
                "answers": {
                    "security_control": {"value": True, "artifact_ids": [manifest["artifact_id"]]}
                },
                "artifacts": [{**manifest, field: forged}],
                "attested": True,
                "expected_draft_revision": 0,
                "idempotency_key": f"forged-final-{field}",
            },
        )
        assert final.status_code == 422, field
    accepted = _draft(client, token, [manifest], "measured")
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["artifact_count"] == 1


def test_upload_checks_run_before_any_file_bytes_are_read(portal) -> None:
    client, spy, tokens, _rate = portal
    token = tokens["with-files"]
    no_credential = client.post(
        f"{EXTERNAL}/{PORTAL}/evidence",
        content=PDF,
        headers={"Content-Type": "application/octet-stream"},
    )
    assert no_credential.status_code == 404
    wrong_credential = _upload(client, "tpc1." + "Z" * 43, PDF)
    assert wrong_credential.status_code == 404
    query = client.post(
        f"{EXTERNAL}/{PORTAL}/evidence?tenant_id=tenant-b",
        content=PDF,
        headers={
            "Authorization": f"ThirdPartyInvitation {token}",
            "Content-Type": "application/octet-stream",
        },
    )
    assert query.status_code == 404
    assert _upload(client, token, PDF, Origin="https://attacker.example").status_code == 403
    assert _upload(client, token, PDF, **{"Content-Type": "multipart/form-data"}).status_code == 415
    assert (
        _upload(client, token, PDF, **{"X-Evidence-File-Extension": "../pdf"}).status_code == 422
    )
    too_large = _upload(client, token, b"%PDF-" + b"x" * 5_000)
    assert too_large.status_code == 413
    assert _upload(client, tokens["no-files"], PDF).status_code == 403
    assert _upload(client, token, b"").status_code == 422

    def lengthless():
        yield PDF

    chunked = client.post(
        f"{EXTERNAL}/{PORTAL}/evidence",
        content=lengthless(),
        headers={
            "Authorization": f"ThirdPartyInvitation {token}",
            "Content-Type": "application/octet-stream",
        },
    )
    assert chunked.status_code == 411
    assert "measure_evidence" not in spy.calls
    assert _upload(client, token, PDF, Origin="http://127.0.0.1").status_code == 200


class _Stream:
    def __init__(self, declared: int, chunks: list[bytes]) -> None:
        self._chunks = chunks
        self.headers = {"content-length": str(declared)}

    async def stream(self):
        for chunk in self._chunks:
            yield chunk


@pytest.mark.asyncio
async def test_the_body_must_match_its_declared_size_exactly() -> None:
    policy = {"maximum_artifacts": 1, "maximum_total_bytes": 100}
    assert await api._read_evidence(_Stream(4, [b"ab", b"cd"]), 4, policy) == b"abcd"  # noqa: SLF001
    with pytest.raises(HTTPException) as short:
        await api._read_evidence(_Stream(5, [b"ab"]), 5, policy)  # noqa: SLF001
    assert short.value.status_code == 400
    with pytest.raises(HTTPException) as long:
        await api._read_evidence(_Stream(2, [b"ab", b"cd"]), 2, policy)  # noqa: SLF001
    assert long.value.status_code == 413
    with pytest.raises(HTTPException) as over_bound:
        await api._read_evidence(_Stream(101, []), 101, policy)  # noqa: SLF001
    assert over_bound.value.status_code == 413


def test_a_store_without_measurement_support_does_not_accept_files(portal) -> None:
    client, spy, tokens, _rate = portal

    class _Legacy:
        def __init__(self, store: Any) -> None:
            self.contract_for_token = store.contract_for_token
            self.save_draft = store.save_draft
            self.finalize_submission = store.finalize_submission

    legacy = _Legacy(spy)
    client.app.state.third_party_collaboration_portal_resolver = (
        lambda _ref, _request: api.ExternalPortalAuthority(tenant_id="tenant-a", store=legacy)
    )
    client.app.state.third_party_collaboration_rate_limit = lambda *_args: None
    assert _upload(client, tokens["with-files"], PDF).status_code == 404
