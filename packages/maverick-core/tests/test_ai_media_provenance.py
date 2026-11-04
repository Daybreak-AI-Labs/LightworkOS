"""Focused contracts for the digest-only C2PA media provenance control plane."""
from __future__ import annotations

import hashlib
import json

import pytest
from maverick import ai_media_provenance as provenance
from maverick.governed_records import GovernedRecordStore
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict

NOW = 1_800_000_000.0
ASSET = "MAA-0123456789abcdef0123456789abcdef"
DEPLOYMENT = "production-east"
CONTEXT = "public-release-v1"


def _hex(label: str | bytes) -> str:
    value = label if isinstance(label, bytes) else label.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def _canonical_sha(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class ManualClock:
    def __init__(self) -> None:
        self.value = NOW

    def __call__(self) -> float:
        return self.value


class Authorities:
    def __init__(self) -> None:
        self.asset_revision = 1
        self.asset_digest = _hex("asset-v1")
        self.deployment_revision = 1
        self.deployment_digest = self.asset_digest
        self.context_revision = 1
        self.context_digest = _hex("context-v1")

    def asset(self, asset_id: str):
        if asset_id != ASSET:
            return None
        return {
            "asset_id": ASSET,
            "revision": self.asset_revision,
            "version_digest": self.asset_digest,
        }

    def deployment(self, deployment_id: str):
        if deployment_id != DEPLOYMENT:
            return None
        return {
            "deployment_id": DEPLOYMENT,
            "revision": self.deployment_revision,
            "artifact_digest": self.deployment_digest,
            "asset_id": ASSET,
            "status": "deployed",
        }

    def context(self, context_id: str):
        if context_id != CONTEXT:
            return None
        return {
            "context_id": CONTEXT,
            "revision": self.context_revision,
            "context_digest": self.context_digest,
            "deployment_id": DEPLOYMENT,
            "status": "active",
        }

    def change_asset(self) -> None:
        self.asset_revision += 1
        self.asset_digest = _hex(f"asset-v{self.asset_revision}")

    def redeploy(self) -> None:
        self.deployment_revision += 1
        self.deployment_digest = self.asset_digest

    def change_context(self) -> None:
        self.context_revision += 1
        self.context_digest = _hex(f"context-v{self.context_revision}")


class FakeC2PAAdapter:
    """Test double for the explicit adapter boundary; not a C2PA implementation."""

    adapter_id = "test.c2pa.adapter"
    adapter_version = "1.0-test"

    def __init__(self, *, available: bool = True) -> None:
        self.available = available
        self.attested = 0

    def is_available(self) -> bool:
        return self.available

    def _receipt(
        self,
        binding: provenance.C2PABinding,
        *,
        operation: str,
        content_sha256: str,
        receipt_id: str,
        assertion_codes=("c2pa.actions", "c2pa.hash.data"),
    ):
        payload = {
            "schema": provenance.ADAPTER_RECEIPT_SCHEMA,
            "operation": operation,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "standard": "c2pa/2.2",
            "receipt_id": receipt_id,
            "observed_at": NOW,
            "media_kind": binding.media_kind,
            "source_content_sha256": binding.source_content_sha256,
            "content_sha256": content_sha256,
            "asset_id": binding.asset_id,
            "asset_revision": binding.asset_revision,
            "asset_version_digest": binding.asset_version_digest,
            "deployment_id": binding.deployment_id,
            "deployment_revision": binding.deployment_revision,
            "deployment_artifact_digest": binding.deployment_artifact_digest,
            "context_id": binding.context_id,
            "context_revision": binding.context_revision,
            "context_digest": binding.context_digest,
            "manifest_sha256": _hex(f"manifest:{receipt_id}"),
            "claim_generator": "Fake adapter boundary for tests",
            "signing_time": NOW - 60,
            "validation_state": "valid",
            "assertion_codes": list(assertion_codes),
            "trust_chain_state": "trusted",
        }
        return {**payload, "receipt_sha256": _canonical_sha(payload)}

    def verify(self, media: bytes, *, binding: provenance.C2PABinding):
        return self._receipt(
            binding,
            operation="verification",
            content_sha256=_hex(media),
            receipt_id=f"verify-{_hex(media)[:16]}",
        )

    def sign(self, media: bytes, *, binding, assertion_codes):
        signed = media + b"|test-c2pa-output"
        receipt = self._receipt(
            binding,
            operation="signing",
            content_sha256=_hex(signed),
            receipt_id=f"sign-{_hex(media)[:16]}",
            assertion_codes=assertion_codes,
        )
        return signed, receipt

    def attest_receipt(self, receipt, *, binding):
        self.attested += 1
        return dict(receipt)


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import audit, config

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    (tmp_path / "config.toml").write_text(
        "[ai_media_provenance]\nenable = true\n", encoding="utf-8"
    )
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _store(label: str) -> GovernedRecordStore:
    return GovernedRecordStore(
        f"test_ai_media_provenance_{label}", "AMP", "test_ai_media_provenance"
    )


def _service(
    label: str = "main",
    *,
    adapter: FakeC2PAAdapter | None = None,
):
    authorities = Authorities()
    clock = ManualClock()
    store = _store(label)
    service = provenance.MediaProvenanceService(
        records=store,
        verifier=adapter,
        signer=adapter,
        asset_lookup=authorities.asset,
        deployment_lookup=authorities.deployment,
        context_lookup=authorities.context,
        clock=clock,
    )
    return service, authorities, clock, store


def _system():
    return provenance.MediaProvenanceActor(
        "system", "system:c2pa-ingestion-worker"
    )


def _human(name: str):
    return provenance.MediaProvenanceActor("human", f"user:{name}@example.test")


def _verify(service, data=b"private-image-pixels", media_kind="image"):
    return service.verify_media(
        data,
        media_kind=media_kind,
        asset_id=ASSET,
        deployment_id=DEPLOYMENT,
        context_id=CONTEXT,
        actor=_system(),
    )


def _detached_receipt(adapter, authorities, *, receipt_id="external-001"):
    binding = provenance.C2PABinding(
        media_kind="image",
        source_content_sha256=_hex(b"detached-media"),
        asset_id=ASSET,
        asset_revision=authorities.asset_revision,
        asset_version_digest=authorities.asset_digest,
        deployment_id=DEPLOYMENT,
        deployment_revision=authorities.deployment_revision,
        deployment_artifact_digest=authorities.deployment_digest,
        context_id=CONTEXT,
        context_revision=authorities.context_revision,
        context_digest=authorities.context_digest,
    )
    return adapter._receipt(
        binding,
        operation="verification",
        content_sha256=binding.source_content_sha256,
        receipt_id=receipt_id,
    )


def _rehash(receipt):
    payload = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    return {**payload, "receipt_sha256": _canonical_sha(payload)}


def test_default_is_off_and_never_pretends_c2pa_support(_isolate):
    from maverick import config

    (_isolate / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    assert provenance.enabled() is False
    status = provenance.default_service.capability_status()
    assert status["enabled"] is False
    assert status["verification"]["status"] == "unsupported"
    assert status["signing"]["status"] == "unsupported"
    assert status["verification"]["adapter_id"] is None
    assert status["signing"]["adapter_id"] is None

    (_isolate / "config.toml").write_text(
        "[ai_media_provenance]\nenable = true\n", encoding="utf-8"
    )
    config.reset_config_cache()
    assert provenance.configured_media_provenance() is provenance.default_service
    service, *_ = _service("unsupported")
    with tenant_scope(tenant="acme"):
        with pytest.raises(provenance.MediaProvenanceUnavailable, match="unsupported"):
            _verify(service)


def test_configured_but_unavailable_adapter_is_reported_not_simulated():
    service, *_ = _service(
        "unavailable", adapter=FakeC2PAAdapter(available=False)
    )
    assert service.capability_status()["verification"]["status"] == "unavailable"
    assert service.capability_status()["verification"]["adapter_id"] == (
        "test.c2pa.adapter"
    )
    assert service.capability_status()["verification"]["adapter_version"] is None
    with tenant_scope(tenant="acme"):
        with pytest.raises(provenance.MediaProvenanceUnavailable, match="unavailable"):
            _verify(service)


def test_factory_requires_explicit_c2patool_verification_selection(
    _isolate, monkeypatch
):
    from maverick import ai_media_provenance_c2pa, config

    adapter = FakeC2PAAdapter()
    constructed = 0

    def factory(**kwargs):
        nonlocal constructed
        constructed += 1
        assert kwargs == {"expected_executable_sha256": "a" * 64}
        return adapter

    monkeypatch.setattr(ai_media_provenance_c2pa, "C2PAToolVerifier", factory)
    (_isolate / "config.toml").write_text(
        "[ai_media_provenance]\n"
        "enable = true\n"
        'verification_adapter = "c2patool"\n'
        f'c2patool_executable_sha256 = "{"a" * 64}"\n',
        encoding="utf-8",
    )
    config.reset_config_cache()

    service = provenance.configured_media_provenance()
    status = service.capability_status()

    assert constructed == 1
    assert service is not provenance.default_service
    assert status["verification"] == {
        "configured": True,
        "available": True,
        "status": "available",
        "adapter_id": "test.c2pa.adapter",
        "adapter_version": "1.0-test",
    }
    assert status["signing"] == {
        "configured": False,
        "available": False,
        "status": "unsupported",
        "adapter_id": None,
        "adapter_version": None,
    }


def test_factory_reports_selected_but_missing_c2patool_as_unavailable(
    _isolate, monkeypatch
):
    from maverick import ai_media_provenance_c2pa, config

    monkeypatch.setattr(
        ai_media_provenance_c2pa,
        "C2PAToolVerifier",
        lambda **_kwargs: FakeC2PAAdapter(available=False),
    )
    (_isolate / "config.toml").write_text(
        "[ai_media_provenance]\n"
        "enable = true\n"
        'verification_adapter = "c2patool"\n'
        f'c2patool_executable_sha256 = "{"a" * 64}"\n',
        encoding="utf-8",
    )
    config.reset_config_cache()

    status = provenance.configured_media_provenance().capability_status()

    assert status["verification"]["configured"] is True
    assert status["verification"]["available"] is False
    assert status["verification"]["status"] == "unavailable"
    assert status["verification"]["adapter_id"] == "test.c2pa.adapter"
    assert status["verification"]["adapter_version"] is None
    assert status["signing"]["status"] == "unsupported"


@pytest.mark.parametrize(
    "digest_line",
    ["", 'c2patool_executable_sha256 = "not-a-digest"\n'],
)
def test_factory_rejects_selected_c2patool_without_exact_digest(
    _isolate,
    digest_line,
):
    from maverick import config

    (_isolate / "config.toml").write_text(
        "[ai_media_provenance]\n"
        "enable = true\n"
        'verification_adapter = "c2patool"\n'
        f"{digest_line}",
        encoding="utf-8",
    )
    config.reset_config_cache()

    with pytest.raises(
        provenance.MediaProvenanceConfigError,
        match="c2patool_executable_sha256",
    ):
        provenance.configured_media_provenance()


@pytest.mark.parametrize(
    "selection",
    ['"other"', '"C2PATool"', "true", "17"],
)
def test_factory_rejects_unknown_or_untyped_verification_adapter(
    _isolate, selection
):
    from maverick import config

    (_isolate / "config.toml").write_text(
        "[ai_media_provenance]\n"
        "enable = true\n"
        f"verification_adapter = {selection}\n",
        encoding="utf-8",
    )
    config.reset_config_cache()

    with pytest.raises(
        provenance.MediaProvenanceConfigError,
        match="verification_adapter must be exactly c2patool",
    ):
        provenance.configured_media_provenance()


def test_factory_does_not_autodiscover_c2patool_without_selector(
    _isolate, monkeypatch
):
    from maverick import ai_media_provenance_c2pa, config

    def forbidden_factory():
        raise AssertionError("c2patool must not be auto-selected")

    monkeypatch.setattr(
        ai_media_provenance_c2pa,
        "C2PAToolVerifier",
        forbidden_factory,
    )
    (_isolate / "config.toml").write_text(
        "[ai_media_provenance]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()

    service = provenance.configured_media_provenance()

    assert service is provenance.default_service
    assert service.capability_status()["verification"]["status"] == "unsupported"


@pytest.mark.parametrize("media_kind", ["image", "audio", "video"])
def test_real_adapter_boundary_records_only_digests_for_all_media_kinds(media_kind):
    adapter = FakeC2PAAdapter()
    service, _, _, store = _service(f"kind_{media_kind}", adapter=adapter)
    secret_bytes = f"raw-{media_kind}-media-do-not-persist".encode()
    with tenant_scope(tenant="acme"):
        result = _verify(service, secret_bytes, media_kind)
        stored = store.list()

    assert result["media_kind"] == media_kind
    assert result["content_sha256"] == _hex(secret_bytes)
    assert result["adapter_reported_validation_state"] == "valid"
    assert result["adapter_reported_trust_chain_state"] == "trusted"
    assert result["coverage"]["media_bytes_persisted"] is False
    assert result["certification_claim"] is False
    assert secret_bytes.decode() not in json.dumps(stored, sort_keys=True)
    assert "media" not in stored[0]


def test_detached_receipt_requires_adapter_attestation_and_rejects_tamper_or_raw_data():
    adapter = FakeC2PAAdapter()
    service, authorities, _, _ = _service("detached", adapter=adapter)
    receipt = _detached_receipt(adapter, authorities)
    with tenant_scope(tenant="acme"):
        admitted = service.ingest_verification_receipt(receipt, actor=_system())
        assert adapter.attested == 1
        assert admitted["receipt_sha256"] == receipt["receipt_sha256"]

        tampered = dict(receipt)
        tampered["manifest_sha256"] = _hex("substituted-manifest")
        with pytest.raises(ValueError, match="digest"):
            service.ingest_verification_receipt(tampered, actor=_system())

        with_raw = {**receipt, "media_bytes": "raw-private-media"}
        with pytest.raises(ValueError, match="unexpected"):
            service.ingest_verification_receipt(with_raw, actor=_system())

        raw_assertion = dict(receipt)
        raw_assertion["assertion_codes"] = [
            {"code": "c2pa.actions", "raw": "private assertion payload"}
        ]
        with pytest.raises(ValueError, match="text"):
            service.ingest_verification_receipt(
                _rehash(raw_assertion), actor=_system()
            )


def test_exact_current_asset_deployment_and_context_binding_is_required():
    adapter = FakeC2PAAdapter()
    service, authorities, _, _ = _service("binding", adapter=adapter)
    stale = _detached_receipt(adapter, authorities)
    authorities.change_context()
    with tenant_scope(tenant="acme"):
        with pytest.raises(provenance.MediaProvenanceBindingError, match="authority"):
            service.ingest_verification_receipt(stale, actor=_system())

    authorities.context_revision = 1
    authorities.context_digest = _hex("context-v1")
    authorities.change_asset()
    with tenant_scope(tenant="acme"):
        with pytest.raises(
            provenance.MediaProvenanceBindingError,
            match="current asset version",
        ):
            service.ingest_verification_receipt(stale, actor=_system())


def test_receipt_replay_is_idempotent_but_identity_conflict_fails_closed():
    adapter = FakeC2PAAdapter()
    service, authorities, _, _ = _service("replay", adapter=adapter)
    receipt = _detached_receipt(adapter, authorities)
    conflict = dict(receipt)
    conflict["manifest_sha256"] = _hex("other-real-manifest")
    conflict = _rehash(conflict)

    with tenant_scope(tenant="acme"):
        first = service.ingest_verification_receipt(receipt, actor=_system())
        replay = service.ingest_verification_receipt(receipt, actor=_system())
        assert replay["provenance_id"] == first["provenance_id"]
        assert replay["revision"] == first["revision"] == 1
        with pytest.raises(provenance.MediaProvenanceIdempotencyConflict):
            service.ingest_verification_receipt(conflict, actor=_system())


def test_release_is_two_human_four_eyes_and_cas_governed():
    service, _, _, _ = _service("release", adapter=FakeC2PAAdapter())
    with tenant_scope(tenant="acme"):
        observed = _verify(service)
        prepared = service.prepare_release_record(
            observed["provenance_id"],
            expected_revision=1,
            purpose_code="public.release",
            evidence_sha256=_hex("preparation-evidence"),
            actor=_human("preparer"),
        )
        assert prepared["status"] == "release_pending"
        assert prepared["revision"] == 2
        with pytest.raises(provenance.MediaProvenanceStateError, match="four-eyes"):
            service.review_release_record(
                observed["provenance_id"],
                expected_revision=2,
                outcome="approved",
                evidence_sha256=_hex("review-evidence"),
                actor=_human("preparer"),
            )
        with pytest.raises(RecordConflict):
            service.review_release_record(
                observed["provenance_id"],
                expected_revision=1,
                outcome="rejected",
                evidence_sha256=_hex("stale-cas-review"),
                actor=_human("third"),
            )
        approved = service.review_release_record(
            observed["provenance_id"],
            expected_revision=2,
            outcome="approved",
            evidence_sha256=_hex("review-evidence"),
            actor=_human("reviewer"),
        )
        assert approved["status"] == "release_approved"
        assert approved["release"]["outcome"] == "approved"
        assert approved["release"]["prepared_by_ref"].startswith("ACT-")
        assert approved["release"]["reviewed_by_ref"].startswith("ACT-")


def test_stale_asset_or_context_blocks_release_and_is_visible_in_safe_export():
    service, authorities, _, _ = _service("stale", adapter=FakeC2PAAdapter())
    with tenant_scope(tenant="acme"):
        observed = _verify(service)
        authorities.change_asset()
        stale = service.export_record(observed["provenance_id"])
        assert stale["binding_current"] is False
        assert set(stale["stale_reasons"]) >= {
            "asset_revision_changed",
            "asset_version_digest_changed",
        }
        with pytest.raises(provenance.MediaProvenanceStateError, match="stale"):
            service.prepare_release_record(
                observed["provenance_id"],
                expected_revision=1,
                purpose_code="public.release",
                evidence_sha256=_hex("evidence"),
                actor=_human("preparer"),
            )


def test_signing_returns_bytes_transiently_but_persists_only_receipt_digests():
    adapter = FakeC2PAAdapter()
    service, _, _, store = _service("sign", adapter=adapter)
    source = b"source-video-bytes-are-transient"
    with tenant_scope(tenant="acme"):
        result = service.sign_media(
            source,
            media_kind="video",
            asset_id=ASSET,
            deployment_id=DEPLOYMENT,
            context_id=CONTEXT,
            assertion_codes=["c2pa.actions"],
            actor=_system(),
        )
        stored = store.list()

    assert result.media == source + b"|test-c2pa-output"
    assert result.record["operation"] == "signing"
    assert result.record["source_content_sha256"] == _hex(source)
    assert result.record["content_sha256"] == _hex(result.media)
    serialized = json.dumps(stored, sort_keys=True)
    assert source.decode() not in serialized
    assert "test-c2pa-output" not in serialized


def test_assertion_bounds_and_closed_schema_are_enforced():
    adapter = FakeC2PAAdapter()
    service, _, _, _ = _service("bounds", adapter=adapter)
    with tenant_scope(tenant="acme"):
        with pytest.raises(ValueError, match="1 through 64"):
            service.sign_media(
                b"media",
                media_kind="image",
                asset_id=ASSET,
                deployment_id=DEPLOYMENT,
                context_id=CONTEXT,
                assertion_codes=[f"assertion.{index}" for index in range(65)],
                actor=_system(),
            )


def test_tenant_isolation_uses_distinct_receipt_identity_and_namespace():
    adapter = FakeC2PAAdapter()
    service, authorities, _, _ = _service("tenants", adapter=adapter)
    receipt = _detached_receipt(adapter, authorities)
    with tenant_scope(tenant="acme"):
        acme = service.ingest_verification_receipt(receipt, actor=_system())
    with tenant_scope(tenant="beta"):
        assert service.get_record(acme["provenance_id"]) is None
        beta = service.ingest_verification_receipt(receipt, actor=_system())
        assert beta["provenance_id"] != acme["provenance_id"]


def test_safe_export_is_explicit_about_coverage_trust_and_no_certification():
    service, _, _, _ = _service("export", adapter=FakeC2PAAdapter())
    with tenant_scope(tenant="acme"):
        observed = _verify(service)
        exported = service.export_record(observed["provenance_id"])

    assert exported["schema"] == provenance.SAFE_EXPORT_SCHEMA
    assert exported["coverage"]["assertion_codes"]
    assert exported["adapter_reported_validation_state"] == "valid"
    assert exported["adapter_reported_trust_chain_state"] == "trusted"
    assert exported["certification_claim"] is False
    assert len(exported["limitations"]) == 4
    assert any("not C2PA" in text for text in exported["limitations"])
    assert "receipt_id" not in exported


def test_explicit_tenant_is_required():
    service, *_ = _service("tenant-required", adapter=FakeC2PAAdapter())
    with pytest.raises(provenance.MediaProvenanceStateError, match="explicit tenant"):
        _verify(service)


class _TwoReleaseAuthorities(Authorities):
    def context(self, context_id: str):
        if context_id not in {CONTEXT, "spring-campaign-2026"}:
            return None
        return {
            "context_id": context_id,
            "revision": self.context_revision,
            "context_digest": self.context_digest,
            "deployment_id": DEPLOYMENT,
            "status": "active",
        }


class _SteppedAdapter(FakeC2PAAdapter):
    """Each receipt is observed a little later than the one before."""

    def __init__(self) -> None:
        super().__init__()
        self.step = 0

    def _receipt(self, binding, **kwargs):
        self.step += 1
        receipt = super()._receipt(binding, **kwargs)
        return _rehash({**receipt, "observed_at": NOW - 100 + self.step})


def test_release_references_list_the_workspace_releases_newest_first():
    authorities = _TwoReleaseAuthorities()
    service = provenance.MediaProvenanceService(
        records=_store("release_refs"),
        verifier=_SteppedAdapter(),
        asset_lookup=authorities.asset,
        deployment_lookup=authorities.deployment,
        context_lookup=authorities.context,
        clock=ManualClock(),
    )

    def check(data: bytes, context_id: str):
        return service.verify_media(
            data,
            media_kind="image",
            asset_id=ASSET,
            deployment_id=DEPLOYMENT,
            context_id=context_id,
            actor=_system(),
        )

    with tenant_scope(tenant="acme"):
        assert service.release_references() == []
        check(b"first", CONTEXT)
        check(b"second", "spring-campaign-2026")
        check(b"third", CONTEXT)
        listed = service.release_references()
        assert service.release_references(limit=1) == listed[:1]
        with pytest.raises(ValueError, match="limit"):
            service.release_references(limit=0)

    assert [row["context_id"] for row in listed] == [CONTEXT, "spring-campaign-2026"]
    assert listed[0] == {
        "context_id": CONTEXT,
        "last_used_at": NOW - 97,
        "deployment_ids": [DEPLOYMENT],
        "record_count": 2,
    }
    # Another workspace never sees these releases.
    with tenant_scope(tenant="beta"):
        assert service.release_references() == []


def test_release_references_need_an_explicit_tenant():
    service, *_ = _service("release-refs-tenant", adapter=FakeC2PAAdapter())
    with pytest.raises(provenance.MediaProvenanceStateError, match="explicit tenant"):
        service.release_references()
