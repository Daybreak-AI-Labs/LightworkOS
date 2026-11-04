from __future__ import annotations

import hashlib
import json
from dataclasses import fields, replace
from typing import Any

import pytest
from maverick.unified_audit import (
    GENESIS_SHA256,
    SourceAuthority,
    SourcePage,
    SourceVerification,
    UnifiedAuditRegistry,
    build_source_page,
    build_source_record,
)
from maverick_dashboard.unified_audit_sources import (
    SOURCE_IDS,
    AuthoritativeAuditPage,
    UnifiedAuditSourceAdapterError,
    build_unified_audit_source_composition,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class _Reader:
    def __init__(
        self,
        source_id: str,
        *,
        total: int = 3,
        action: str = "record_updated",
    ) -> None:
        self.source_id = source_id
        self.total = total
        self.action = action
        self.authority_value = SourceAuthority(
            tenant_id="tenant-a",
            source_id=source_id,
            suite_id=source_id,
            authority_revision=7,
            authority_sha256=_sha(f"authority:{source_id}"),
            source_schema_version=3,
        )
        self.calls: list[dict[str, Any]] = []
        self.page_reads = 0
        self.drift_after_read = False
        self.read_error: BaseException | None = None
        self.transform = lambda page: page
        self.force_nonterminal_count: int | None = None

    def resolve_authority(self, **kwargs: Any) -> SourceAuthority:
        self.calls.append({"operation": "authority", **kwargs})
        if self.drift_after_read and self.page_reads:
            return replace(
                self.authority_value,
                authority_revision=self.authority_value.authority_revision + 1,
                authority_sha256=_sha("changed-authority"),
            )
        return self.authority_value

    def read_history_page(self, **kwargs: Any) -> AuthoritativeAuditPage:
        self.calls.append({"operation": "page", **kwargs})
        self.page_reads += 1
        if self.read_error is not None:
            raise self.read_error
        after = kwargs["after_sequence"]
        limit = kwargs["limit"]
        remaining = max(0, self.total - after)
        count = min(remaining, limit)
        if self.force_nonterminal_count is not None:
            count = self.force_nonterminal_count
        records = []
        previous = kwargs["prior_sha256"]
        for sequence in range(after + 1, after + count + 1):
            record = build_source_record(
                sequence=sequence,
                occurred_at=1_800_000_000.0 + sequence,
                action=self.action,
                actor_sha256=_sha(f"actor:{sequence}"),
                resource_sha256=_sha(f"resource:{sequence}"),
                payload_sha256=_sha(f"payload:{sequence}"),
                previous_sha256=previous,
            )
            records.append(record)
            previous = record.record_sha256
        terminal = after + count >= self.total
        truncated = not terminal
        complete = terminal
        limitations = () if complete else ("page_limit_reached",)
        core_page = build_source_page(
            self.authority_value,
            after_sequence=after,
            prior_sha256=kwargs["prior_sha256"],
            previous_page_sha256=kwargs["previous_page_sha256"],
            records=records,
            terminal=terminal,
            complete=complete,
            truncated=truncated,
            watermark=1_800_001_000.0,
            limitations=limitations,
        )
        page = AuthoritativeAuditPage(
            **{
                field.name: getattr(core_page, field.name)
                for field in fields(AuthoritativeAuditPage)
            }
        )
        return self.transform(page)


class _Verifier:
    def __init__(self, source_id: str) -> None:
        self.source_id = source_id
        self.calls = 0
        self._identity = _sha(f"verifier:{source_id}")

    @property
    def verifier_identity_sha256(self) -> str:
        return self._identity

    def verify_page(
        self,
        *,
        authority: SourceAuthority,
        page: SourcePage,
    ) -> SourceVerification:
        self.calls += 1
        return SourceVerification(
            tenant_id=authority.tenant_id,
            source_id=authority.source_id,
            authority_revision=authority.authority_revision,
            authority_sha256=authority.authority_sha256,
            source_schema_version=authority.source_schema_version,
            page_sha256=page.page_sha256,
            verified_at=page.watermark + 1,
            assurance_level="signed_anchored",
            verifier_identity_sha256=self._identity,
            trust_root_revision=1,
            key_id_sha256=_sha(f"key:{self.source_id}"),
            anchor_sha256=_sha(f"anchor:{page.page_sha256}"),
            snapshot_head_sha256=page.head_sha256,
            snapshot_record_count=page.last_sequence,
            retention_complete=True,
        )


def _verified_composition(
    readers: dict[str, _Reader],
    *,
    max_page_records: int = 500,
):
    verifiers = {source_id: _Verifier(source_id) for source_id in readers}
    composition = build_unified_audit_source_composition(
        tenant_id="tenant-a",
        readers=readers,
        verifiers=verifiers,
        max_page_records=max_page_records,
    )
    return composition, verifiers


def test_fixed_six_sources_and_missing_readers_are_explicitly_incomplete() -> None:
    composition = build_unified_audit_source_composition(
        tenant_id="tenant-a",
        readers={},
    )

    assert SOURCE_IDS == (
        "ai_governance",
        "consent_preferences",
        "data_use_governance",
        "privacy_automation",
        "tech_risk_compliance",
        "third_party_management",
    )
    assert composition.sources == {}
    assert composition.verifiers == {}
    status = composition.status()
    assert status["complete"] is False
    assert status["source_count"] == 0
    assert [item["source_id"] for item in status["sources"]] == list(SOURCE_IDS)
    assert all(item["complete"] is False for item in status["sources"])
    assert all(item["reader_available"] is False for item in status["sources"])
    assert all(item["verifier_available"] is False for item in status["sources"])
    assert all(
        item["limitations"]
        == ("authoritative_history_reader_unavailable", "source_integrity_unverified")
        for item in status["sources"]
    )
    assert status["network_io"] is False
    assert status["private_store_tables_read"] is False
    assert "tenant-a" not in json.dumps(status, sort_keys=True)


def test_tenant_bound_two_page_source_rebuilds_every_commitment() -> None:
    reader = _Reader("ai_governance")
    composition, verifiers = _verified_composition(
        {"ai_governance": reader},
        max_page_records=2,
    )
    source = composition.sources["ai_governance"]

    registry = UnifiedAuditRegistry("tenant-a")
    registry.register(
        source,
        verifier=composition.verifiers["ai_governance"],
    )
    assert registry.get("ai_governance") is source

    authority = source.authority()
    assert authority.tenant_id == "tenant-a"
    first = source.read_page(
        after_sequence=0,
        prior_sha256=GENESIS_SHA256,
        previous_page_sha256=GENESIS_SHA256,
        limit=2,
    )
    assert isinstance(first, SourcePage)
    assert (first.first_sequence, first.last_sequence, first.record_count) == (1, 2, 2)
    assert first.prior_sha256 == GENESIS_SHA256
    assert first.head_sha256 == first.records[-1].record_sha256
    assert first.terminal is False
    assert first.complete is False
    assert first.truncated is True
    assert first.limitations == ("page_limit_reached",)

    second = source.read_page(
        after_sequence=first.last_sequence,
        prior_sha256=first.head_sha256,
        previous_page_sha256=first.page_sha256,
        limit=2,
    )
    assert (second.first_sequence, second.last_sequence, second.record_count) == (3, 3, 1)
    assert second.prior_sha256 == first.head_sha256
    assert second.previous_page_sha256 == first.page_sha256
    assert second.terminal is True
    assert second.complete is True
    assert second.truncated is False
    assert second.limitations == ()

    status = source.status()
    assert status.authority_revision == 7
    assert status.authority_sha256 == authority.authority_sha256
    assert status.source_schema_version == 3
    assert status.pages_read == 2
    assert status.record_count == 1
    assert status.first_sequence == 3
    assert status.last_sequence == 3
    assert status.prior_sha256 == first.head_sha256
    assert status.head_sha256 == second.head_sha256
    assert status.previous_page_sha256 == first.page_sha256
    assert status.page_sha256 == second.page_sha256
    assert status.page_contract_validated is True
    assert status.source_page_complete is True
    assert status.independently_verified is False
    assert status.complete is False
    assert composition.status()["complete"] is False  # Five sources are still absent.
    assert verifiers["ai_governance"].calls == 0
    assert all(call["tenant_id"] == "tenant-a" for call in reader.calls)
    assert "actor:1" not in repr(first)
    assert "resource:1" not in repr(first)
    assert "payload:1" not in repr(first)


def test_all_six_source_pages_can_complete_without_claiming_independent_proof() -> None:
    readers = {source_id: _Reader(source_id, total=0) for source_id in SOURCE_IDS}
    composition, verifiers = _verified_composition(
        readers,
        max_page_records=5,
    )
    assert composition.status()["complete"] is False

    for source in composition.sources.values():
        page = source.read_page(
            after_sequence=0,
            prior_sha256=GENESIS_SHA256,
            previous_page_sha256=GENESIS_SHA256,
            limit=5,
        )
        assert page.record_count == 0
        assert page.first_sequence == 0
        assert page.last_sequence == 0
        assert page.head_sha256 == GENESIS_SHA256
        assert page.complete is True

    status = composition.status()
    assert status["source_pages_complete"] is True
    assert status["independent_verification_accepted"] is False
    assert status["complete"] is False
    assert status["source_count"] == 6
    assert all(item["page_sha256"] != GENESIS_SHA256 for item in status["sources"])
    assert all(item["source_page_complete"] is True for item in status["sources"])
    assert all(item["independently_verified"] is False for item in status["sources"])
    assert all(item["complete"] is False for item in status["sources"])
    assert all(verifier.calls == 0 for verifier in verifiers.values())


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        (lambda page: replace(page, record_count=page.record_count + 1), "source_page_invalid"),
        (lambda page: replace(page, first_sequence=99), "source_page_invalid"),
        (lambda page: replace(page, head_sha256=_sha("wrong-head")), "source_page_invalid"),
        (lambda page: replace(page, page_sha256=_sha("wrong-page")), "source_page_invalid"),
        (
            lambda page: replace(page, limitations=("free_form_customer_name",)),
            "source_page_invalid",
        ),
    ],
)
def test_source_owned_page_metadata_is_recomputed_and_fail_closed(
    mutation,
    expected_code: str,
) -> None:
    reader = _Reader("privacy_automation", total=1)
    reader.transform = mutation
    composition, _ = _verified_composition({"privacy_automation": reader})
    source = composition.sources["privacy_automation"]

    with pytest.raises(UnifiedAuditSourceAdapterError, match=expected_code):
        source.read_page(
            after_sequence=0,
            prior_sha256=GENESIS_SHA256,
            previous_page_sha256=GENESIS_SHA256,
            limit=2,
        )
    assert source.status().complete is False
    assert source.status().limitations == (expected_code,)


def test_free_form_action_underfilled_page_and_authority_drift_fail_closed() -> None:
    action_reader = _Reader("consent_preferences", total=1)

    def _free_form_action(page: AuthoritativeAuditPage) -> AuthoritativeAuditPage:
        object.__setattr__(page.records[0], "action", "customer_alice")
        return page

    action_reader.transform = _free_form_action
    action_composition, _ = _verified_composition(
        {"consent_preferences": action_reader}
    )
    action_source = action_composition.sources["consent_preferences"]
    with pytest.raises(UnifiedAuditSourceAdapterError, match="source_page_invalid"):
        action_source.read_page(
            after_sequence=0,
            prior_sha256=GENESIS_SHA256,
            previous_page_sha256=GENESIS_SHA256,
            limit=2,
        )

    short_reader = _Reader("tech_risk_compliance", total=5)
    short_reader.force_nonterminal_count = 1
    short_composition, _ = _verified_composition(
        {"tech_risk_compliance": short_reader}
    )
    short_source = short_composition.sources["tech_risk_compliance"]
    with pytest.raises(UnifiedAuditSourceAdapterError, match="source_page_invalid"):
        short_source.read_page(
            after_sequence=0,
            prior_sha256=GENESIS_SHA256,
            previous_page_sha256=GENESIS_SHA256,
            limit=2,
        )

    drift_reader = _Reader("third_party_management", total=1)
    drift_reader.drift_after_read = True
    drift_composition, _ = _verified_composition(
        {"third_party_management": drift_reader}
    )
    drift_source = drift_composition.sources["third_party_management"]
    with pytest.raises(UnifiedAuditSourceAdapterError, match="source_authority_changed"):
        drift_source.read_page(
            after_sequence=0,
            prior_sha256=GENESIS_SHA256,
            previous_page_sha256=GENESIS_SHA256,
            limit=2,
        )
    assert drift_source.status().limitations == ("source_authority_changed",)


def test_reader_error_limit_and_unknown_source_never_become_green() -> None:
    reader = _Reader("data_use_governance")
    reader.read_error = RuntimeError("raw-secret-and-customer-name")
    composition, _ = _verified_composition(
        {"data_use_governance": reader},
        max_page_records=2,
    )
    source = composition.sources["data_use_governance"]
    with pytest.raises(UnifiedAuditSourceAdapterError, match="source_history_unavailable") as error:
        source.read_page(
            after_sequence=0,
            prior_sha256=GENESIS_SHA256,
            previous_page_sha256=GENESIS_SHA256,
            limit=2,
        )
    assert "raw-secret" not in str(error.value)
    assert source.status().complete is False
    assert source.status().limitations == ("source_history_unavailable",)

    reads = reader.page_reads
    with pytest.raises(UnifiedAuditSourceAdapterError, match="source_page_limit_invalid"):
        source.read_page(
            after_sequence=0,
            prior_sha256=GENESIS_SHA256,
            previous_page_sha256=GENESIS_SHA256,
            limit=3,
        )
    assert reader.page_reads == reads

    with pytest.raises(UnifiedAuditSourceAdapterError, match="source_id_invalid"):
        build_unified_audit_source_composition(
            tenant_id="tenant-a",
            readers={"caller_selected_source": reader},
        )


def test_reader_authority_is_exactly_tenant_and_source_bound() -> None:
    reader = _Reader("ai_governance")
    reader.authority_value = SourceAuthority(
        tenant_id="tenant-b",
        source_id="ai_governance",
        suite_id="ai_governance",
        authority_revision=1,
        authority_sha256=_sha("other-tenant"),
    )
    composition, _ = _verified_composition({"ai_governance": reader})
    source = composition.sources["ai_governance"]

    with pytest.raises(UnifiedAuditSourceAdapterError, match="source_authority_invalid"):
        source.authority()
    assert source.status().complete is False
    assert source.status().limitations == ("source_authority_invalid",)


def test_reader_and_independent_verifier_presence_are_distinct_fail_closed_seams() -> None:
    reader = _Reader("ai_governance")
    verifier = _Verifier("ai_governance")

    reader_only = build_unified_audit_source_composition(
        tenant_id="tenant-a",
        readers={"ai_governance": reader},
    )
    assert reader_only.sources == {}
    assert reader_only.verifiers == {}
    reader_only_status = reader_only.status()
    ai_status = reader_only_status["sources"][0]
    assert ai_status["reader_available"] is True
    assert ai_status["verifier_available"] is False
    assert ai_status["available"] is False
    assert ai_status["limitations"] == ("source_integrity_unverified",)
    assert reader_only_status["complete"] is False

    verifier_only = build_unified_audit_source_composition(
        tenant_id="tenant-a",
        readers={},
        verifiers={"ai_governance": verifier},
    )
    assert verifier_only.sources == {}
    assert verifier_only.verifiers == {}
    verifier_only_status = verifier_only.status()
    ai_status = verifier_only_status["sources"][0]
    assert ai_status["reader_available"] is False
    assert ai_status["verifier_available"] is True
    assert ai_status["available"] is False
    assert ai_status["limitations"] == ("authoritative_history_reader_unavailable",)
    assert verifier_only_status["complete"] is False


def test_invalid_verifier_is_rejected_before_source_exposure() -> None:
    reader = _Reader("ai_governance")
    with pytest.raises(UnifiedAuditSourceAdapterError, match="source_verifier_invalid"):
        build_unified_audit_source_composition(
            tenant_id="tenant-a",
            readers={"ai_governance": reader},
            verifiers={"ai_governance": object()},  # type: ignore[dict-item]
        )
